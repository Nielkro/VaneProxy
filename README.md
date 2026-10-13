<p align="center">
  <img src="assets/vane-logo.svg" alt="Vane Logo" width="220" />
</p>

<h1 align="center">Vane</h1>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.75%2B-orange.svg" alt="Rust 1.75+" /></a>
  <a href="https://www.kernel.org/"><img src="https://img.shields.io/badge/Platform-Linux-lightgrey.svg" alt="Platform: Linux" /></a>
  <a href="https://github.com/Nielkro/VaneProxy/pulls"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs Welcome" /></a>
</p>

**Vane** is a high-performance, asynchronous hybrid **Layer-4 (L4) SNI Multiplexer** and **Layer-7 (L7) Reverse Proxy** written in safe Rust.

It allows you to serve multiple web services, static websites, and VPN protocols (such as **Xray Reality / VLESS**) on a **single public port (`:443`)** with automatic SSL certificates, zero-downtime hot reloads, and PROXY protocol v2 support.

---

## ⚡ Architecture & Flow

```
                      Client Request (Port 443)
                                  │
                                  ▼
                         [ Vane L4 Listener ]
                                  │
                 (Non-terminating TLS ClientHello Sniff)
                                  │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
    SNI: vpn.domain.com   SNI: caddy.domain.com   SNI: app.domain.com
            │                     │                     │
            ▼                     ▼                     ▼
    [ Raw TCP Splice ]    [ PROXY Protocol v2 ]   [ Vane L7 Engine ]
            │                     │                     │
       (No decrypt)          (No decrypt)         (TLS Terminated)
            │                     │               (Auto-SSL ACME v2)
            ▼                     ▼                     │
    Xray Reality (:8443)    Caddy / Nginx (:8444)       ├── Static Files
                                                        ├── Reverse Proxy
                                                        └── WebSockets (101)
```

---

## 🌟 Key Features

* **Dual-Mode Hybrid Engine:**
  * **L4 Raw Passthrough:** Forwards encrypted TLS streams directly to backends (e.g., Xray Reality) without decryption using zero-copy TCP splicing.
  * **L4 with PROXY Protocol v2:** Injects binary PPv2 headers for downstream proxies (e.g. Caddy/Nginx) so real client IPv4/IPv6 addresses are preserved.
  * **Native L7 Reverse Proxy:** Full HTTP/1.1 and HTTP/2 proxying with seamless WebSocket upgrades (`101 Switching Protocols`) and static file hosting.
* **Automated ACME v2 SSL (Let's Encrypt):**
  * **DNS-01 (Cloudflare):** Supports wildcard certificates (`*.domain.com`) with automated RFC 6125 multi-SAN consolidation.
  * **TLS-ALPN-01 (RFC 8737):** Ephemeral challenge responder for instant certificate issuance without opening port 80.
  * **Smart Renewal & Expiry Tracking:** Native X.509 ASN.1 `notAfter` parser automatically checks and renews certificates before expiration.
* **Zero-Downtime Hot Reload:**
  * Atomically reloads configurations and sites upon receiving `SIGHUP` or via filesystem events (`inotify`) with debouncing.
* **Caddyfile-Inspired Site Configuration:**
  * Clean, human-readable site block syntax in `sites-enabled/`.
* **Hardened Security & Performance:**
  * Single static binary running as unprivileged user with `CAP_NET_BIND_SERVICE`.
  * Dual-stack IPv4/IPv6 support with `IPV6_V6ONLY` socket flags.
  * Internet scanner noise suppression (quiet error logs by default).

---

## 📦 Installation & Build

### Prerequisites
* Rust toolchain (1.75 or later)
* Linux kernel (2.6.32+)

### Building from Source

```bash
git clone https://github.com/Nielkro/VaneProxy.git
cd VaneProxy
cargo build --release
```

The compiled binary will be located at `target/release/vane`.

---

## ⚙️ Configuration

Vane uses a two-tier configuration structure:
1. `/etc/vane/config.toml` — Master daemon settings, L4 routing, and ACME credentials.
2. `/etc/vane/sites-enabled/*.caddy` — L7 virtual hosts and reverse proxy directives.

### 1. Master Configuration (`config.toml`)

```toml
# Listen sockets (dual-stack IPv4 and IPv6)
listen = ["0.0.0.0:443", "[::]:443"]
strict_listen = true
default_backend = "caddy_l7"

# Logging: quiet 'error' level in production suppresses scanner noise
log_level = "error"
access_log = false

# L7 Sites Directory & HTTP-to-HTTPS redirect
sites_dir = "/etc/vane/sites-enabled"
http_listen = "0.0.0.0:80"

# Automated Let's Encrypt TLS
[tls]
email = "admin@yourdomain.com"
storage_dir = "/var/lib/vane/certs"
cloudflare_credentials = "/etc/vane/cloudflare.ini" # Required for DNS-01 wildcards
staging = false
renewal_interval_secs = 43200 # 12 hours check interval

# L4 Backend Definitions
[backends.reality_raw]
addr = "127.0.0.1:8443"
send_proxy_protocol = false

[backends.caddy_l7]
addr = "127.0.0.1:8444"
send_proxy_protocol = true

# L4 SNI Routes (direct matching without TLS termination)
[[routes]]
sni = "vpn.yourdomain.com"
backend = "reality_raw"

[[routes]]
sni = "caddy.yourdomain.com"
backend = "caddy_l7"
```

### 2. Virtual Hosts (`sites-enabled/app.caddy`)

Virtual hosts use Caddyfile syntax:

```caddy
# Reverse proxy with WebSocket upgrade support
messenger.yourdomain.com {
    reverse_proxy 127.0.0.1:3000
}

# Static file hosting with path traversal protection
static.yourdomain.com {
    root * /var/www/landing
    file_server
}
```

---

## 🚀 Running as a Systemd Service

1. Copy binary and configuration:
   ```bash
   sudo cp target/release/vane /usr/local/bin/
   sudo mkdir -p /etc/vane /var/lib/vane/certs
   sudo useradd -r -s /bin/false vane
   sudo chown -R vane:vane /var/lib/vane
   ```

2. Install and enable the systemd unit:
   ```bash
   sudo cp vane.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now vane
   ```

3. Reload configuration without dropping active connections:
   ```bash
   sudo systemctl reload vane
   # or
   sudo kill -HUP $(pidof vane)
   ```

---

### Manual Certificates & Third-Party Domains

For domains whose DNS zone is not managed in Cloudflare (such as external registries or third-party DNS):
- **Exact domains:** Vane automatically falls back to **TLS-ALPN-01** validation over port 443.
- **Wildcard or manual domains:** Place certificate and private key files directly in `storage_dir` (e.g. `/var/lib/vane/certs`):
  - `<domain>.fullchain.pem`
  - `<domain>.privkey.pem`
  Vane loads and serves these certificates immediately on startup or hot reload without invoking ACME orders.

---

## 🧪 Testing & Verification

Run the built-in test suite:

```bash
cargo test
```

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
