//! Per-connection relay: sniff SNI, pick backend, splice the stream.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::Config;
use crate::proxy_proto::encode_ppv2;
use crate::sni::parse_sni;

/// Handle one inbound client connection until close.
pub async fn handle_conn(inbound: TcpStream, cfg: Arc<Config>) {
    let start = Instant::now();
    let peer = inbound.peer_addr().ok();
    let local = inbound.local_addr().ok();

    let mut inbound = inbound;
    let hello_timeout = Duration::from_millis(cfg.client_hello_timeout_ms);
    let max_bytes = cfg.max_client_hello_bytes;

    // Read the first TLS record (or whatever the client sent) with a deadline.
    let mut buf = Vec::with_capacity(2048);
    let read_ok =
        tokio::time::timeout(hello_timeout, read_hello(&mut inbound, &mut buf, max_bytes))
            .await
            .is_ok();

    if buf.is_empty() {
        debug!(?peer, read_ok, "empty preface, closing");
        return;
    }

    let sni = parse_sni(&buf);
    let backend_name = cfg.route(sni.as_deref()).to_string();
    let backend = cfg.backend(&backend_name).clone();

    // Connect to the chosen backend.
    let connect_timeout = Duration::from_millis(cfg.backend_connect_timeout_ms);
    let mut upstream =
        match tokio::time::timeout(connect_timeout, TcpStream::connect(backend.addr)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                warn!(?peer, backend = %backend_name, error = %e, "backend connect failed");
                return;
            }
            Err(_) => {
                warn!(?peer, backend = %backend_name, "backend connect timed out");
                return;
            }
        };
    let _ = upstream.set_nodelay(true);

    // Preface: optional PROXY v2 header, then the bytes already read.
    if backend.send_proxy_protocol {
        if let (Some(p), Some(l)) = (peer, local) {
            let hdr = encode_ppv2(p, l);
            if let Err(e) = upstream.write_all(&hdr).await {
                warn!(?peer, backend = %backend_name, error = %e, "ppv2 write failed");
                return;
            }
        } else if let Err(e) = upstream.write_all(&local_header()).await {
            warn!(?peer, backend = %backend_name, error = %e, "ppv2 local write failed");
            return;
        }
    }
    if let Err(e) = upstream.write_all(&buf).await {
        warn!(?peer, backend = %backend_name, error = %e, "preface write failed");
        return;
    }

    // Bidirectional splice until EOF or error.
    match tokio::io::copy_bidirectional(&mut inbound, &mut upstream).await {
        Ok((up, down)) => {
            if cfg.access_log {
                tracing::info!(
                    peer = peer.map(sock_str).unwrap_or_else(|| "-".into()),
                    sni = sni.as_deref().unwrap_or("-"),
                    backend = %backend_name,
                    ms = start.elapsed().as_millis(),
                    up, down, "proxied"
                );
            } else {
                debug!(
                    ?peer,
                    sni = sni.as_deref().unwrap_or("-"),
                    backend = %backend_name,
                    up, down, "closed"
                );
            }
        }
        Err(e) => {
            warn!(?peer, backend = %backend_name, error = %e, "relay failed");
        }
    }
}

/// Minimal LOCAL header used when socket addresses are unavailable.
fn local_header() -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(b"\r\n\r\n\x00\r\nQUIT\n");
    out.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
    out
}

fn sock_str(a: SocketAddr) -> String {
    a.to_string()
}

/// Read-loop for the first flight of client bytes.
///
/// - Returns as soon as `buf[0] != 0x16` (non-TLS fast path, no waiting).
/// - For TLS, waits for the 6th byte (handshake type) and then for the
///   full first record (`5 + record_len`), capped by `max_bytes`.
/// - Never fails: partial data just means the caller routes by default.
async fn read_hello(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> std::io::Result<()> {
    let mut tmp = [0u8; 4096];
    loop {
        // Check whether we already have a decision.
        if !buf.is_empty() && buf[0] != 0x16 {
            return Ok(());
        }
        if buf.len() >= 6 {
            if buf[5] != 0x01 {
                return Ok(()); // Not a ClientHello.
            }
            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if record_len == 0 {
                return Ok(());
            }
            let want = 5usize.saturating_add(record_len).min(max_bytes);
            if buf.len() >= want {
                return Ok(());
            }
            if buf.len() >= max_bytes {
                return Ok(());
            }
        } else if buf.len() >= max_bytes {
            return Ok(());
        }

        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(()); // EOF: route with what we have.
        }
        let room = max_bytes.saturating_sub(buf.len());
        if room == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n.min(room)]);
        // If the cap truncated the record, stop and route by default.
        if buf.len() >= max_bytes {
            return Ok(());
        }
    }
}
