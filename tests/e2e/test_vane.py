#!/usr/bin/env python3
"""
Vane E2E Integration Test Suite.
Uses strictly the Python standard library (no pip dependencies required).
"""

import asyncio
import base64
import hashlib
import os
import signal
import socket
import struct
import subprocess
import sys
import time
import unittest

def build_client_hello(server_name: str) -> bytes:
    """Builds a minimal valid TLS 1.2/1.3 ClientHello containing the SNI extension."""
    server_name_bytes = server_name.encode("utf-8")
    
    # SNI extension: type 0x0000, length, list length, type 0x00 (host_name), name length, name
    sni_content = struct.pack("!B H", 0, len(server_name_bytes)) + server_name_bytes
    sni_list = struct.pack("!H", len(sni_content)) + sni_content
    ext_data = struct.pack("!H H", 0x0000, len(sni_list)) + sni_list
    
    # Handshake body: version (0x0303 = TLS 1.2), 32 bytes random, session id len 0, cipher suites, compression, extensions
    random_bytes = b"\x01" * 32
    cipher_suites = struct.pack("!H H", 2, 0x1301)  # 1 cipher suite (TLS_AES_128_GCM_SHA256)
    compression = b"\x01\x00"
    extensions_block = struct.pack("!H", len(ext_data)) + ext_data
    
    handshake_body = struct.pack("!H", 0x0303) + random_bytes + b"\x00" + cipher_suites + compression + extensions_block
    # Handshake header: type 1 (ClientHello), 3-byte length
    handshake = b"\x01" + len(handshake_body).to_bytes(3, "big") + handshake_body
    
    # Record header: type 22 (Handshake), version 0x0301 (TLS 1.0), 2-byte length
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


class MockRealityServer:
    """Mock L4 raw backend (e.g. Xray Reality). Verifies raw TCP passthrough without PROXY headers."""
    def __init__(self, host="127.0.0.1", port=19443):
        self.host = host
        self.port = port
        self.server = None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        data = await reader.read(4096)
        if data.startswith(b"\x16\x03\x01"):
            writer.write(b"REALITY_RAW_OK\n")
        else:
            writer.write(b"REALITY_RAW_ERR\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class MockPpv2Server:
    """Mock L4/L7 backend expecting PROXY protocol v2 (e.g. Caddy / Nginx)."""
    def __init__(self, host="127.0.0.1", port=19444):
        self.host = host
        self.port = port
        self.server = None

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        data = await reader.read(4096)
        # PROXY protocol v2 signature: \r\n\r\n\0\r\nQUIT\n
        ppv2_sig = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"
        if data.startswith(ppv2_sig):
            # Parse IPv4 source address (bytes 16..20)
            src_ip_bytes = data[16:20]
            src_ip = socket.inet_ntoa(src_ip_bytes)
            writer.write(f"PPV2_VERIFIED_OK:{src_ip}\n".encode("utf-8"))
        else:
            writer.write(b"PPV2_MISSING_HEADER\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class VaneE2ETestCase(unittest.TestCase):
    vane_process = None
    reality_server = None
    ppv2_server = None
    loop = None

    @classmethod
    def setUpClass(cls):
        # 1. Build release binary if not built yet
        vane_bin = os.path.join(os.path.dirname(__file__), "../../target/debug/vane")
        if not os.path.exists(vane_bin):
            vane_bin = os.path.join(os.path.dirname(__file__), "../../target/release/vane")
        if not os.path.exists(vane_bin):
            print("[E2E] Building vane binary with cargo build...")
            subprocess.run(["cargo", "build"], check=True)
            vane_bin = os.path.join(os.path.dirname(__file__), "../../target/debug/vane")
        
        cls.vane_bin = os.path.abspath(vane_bin)
        cls.config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "config.ci.toml"))

        # 2. Start mock background servers in a separate thread/event loop
        import threading
        cls.loop = asyncio.new_event_loop()
        cls.reality_server = MockRealityServer()
        cls.ppv2_server = MockPpv2Server()

        async def start_mocks():
            await cls.reality_server.start()
            await cls.ppv2_server.start()

        cls.loop.run_until_complete(start_mocks())
        cls.server_thread = threading.Thread(target=cls.loop.run_forever, daemon=True)
        cls.server_thread.start()

        # 3. Start Vane binary process
        cls.vane_process = subprocess.Popen(
            [cls.vane_bin, "--config", cls.config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for Vane to bind to port 18443
        time.sleep(0.8)
        if cls.vane_process.poll() is not None:
            stdout, stderr = cls.vane_process.communicate()
            raise RuntimeError(f"Vane failed to start:\nStdout: {stdout.decode()}\nStderr: {stderr.decode()}")

    @classmethod
    def tearDownClass(cls):
        if cls.vane_process:
            cls.vane_process.terminate()
            try:
                cls.vane_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                cls.vane_process.kill()

        if cls.loop:
            async def stop_mocks():
                await cls.reality_server.stop()
                await cls.ppv2_server.stop()
            cls.loop.call_soon_threadsafe(cls.loop.stop)

    def test_01_sni_routing_to_reality_raw(self):
        """SNI 'reality.test.local' routes to reality_raw backend without PROXY protocol."""
        s = socket.create_connection(("127.0.0.1", 18443), timeout=3)
        client_hello = build_client_hello("reality.test.local")
        s.sendall(client_hello)
        response = s.recv(1024)
        s.close()
        self.assertEqual(response.strip(), b"REALITY_RAW_OK")

    def test_02_sni_routing_to_caddy_with_ppv2(self):
        """SNI 'caddy.test.local' routes to caddy_upstream and injects PROXY protocol v2."""
        s = socket.create_connection(("127.0.0.1", 18443), timeout=3)
        client_hello = build_client_hello("caddy.test.local")
        s.sendall(client_hello)
        response = s.recv(1024)
        s.close()
        self.assertEqual(response.strip(), b"PPV2_VERIFIED_OK:127.0.0.1")

    def test_03_default_backend_fallback_on_unmatched_sni(self):
        """Unmatched SNI falls back to default_backend (caddy_upstream) with PROXY protocol v2."""
        s = socket.create_connection(("127.0.0.1", 18443), timeout=3)
        client_hello = build_client_hello("unmatched.random.com")
        s.sendall(client_hello)
        response = s.recv(1024)
        s.close()
        self.assertEqual(response.strip(), b"PPV2_VERIFIED_OK:127.0.0.1")

    def test_04_default_backend_fallback_on_non_tls_data(self):
        """Non-TLS payload falls back to default_backend with PROXY protocol v2."""
        s = socket.create_connection(("127.0.0.1", 18443), timeout=3)
        s.sendall(b"PLAIN_TCP_PAYLOAD_DATA\n")
        response = s.recv(1024)
        s.close()
        self.assertEqual(response.strip(), b"PPV2_VERIFIED_OK:127.0.0.1")

    def test_05_http_port_80_redirect_to_https(self):
        """HTTP port 18080 sends 301 Moved Permanently redirect to https preserving URI."""
        s = socket.create_connection(("127.0.0.1", 18080), timeout=3)
        s.sendall(b"GET /api/v1/feed?filter=recent HTTP/1.1\r\nHost: myapp.test.local\r\nConnection: close\r\n\r\n")
        response = s.recv(4096).decode("utf-8", errors="replace")
        s.close()
        self.assertIn("301 Moved Permanently", response)
        self.assertIn("Location: https://myapp.test.local/api/v1/feed?filter=recent", response)

    def test_06_zero_downtime_sighup_reload(self):
        """Sending SIGHUP reloads configuration without terminating process or dropping ports."""
        self.vane_process.send_signal(signal.SIGHUP)
        time.sleep(0.3)
        self.assertIsNone(self.vane_process.poll(), "Vane process must not crash on SIGHUP")
        
        # Verify it still handles requests immediately after reload
        s = socket.create_connection(("127.0.0.1", 18443), timeout=3)
        client_hello = build_client_hello("reality.test.local")
        s.sendall(client_hello)
        response = s.recv(1024)
        s.close()
        self.assertEqual(response.strip(), b"REALITY_RAW_OK")


if __name__ == "__main__":
    unittest.main(verbosity=2)
