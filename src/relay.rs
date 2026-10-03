//! Per-connection relay: sniff SNI, pick backend, splice the stream.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use tracing::{debug, warn};

use crate::config::{BackendAddr, Config};
use crate::proxy_proto::encode_ppv2;
use crate::sni::parse_sni;

/// Upstream connection: TCP socket or Unix domain socket.
///
/// Both halves implement `AsyncRead + AsyncWrite`, so the relay
/// (preface writes + `copy_bidirectional`) is transport-agnostic.
enum Upstream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl AsyncRead for Upstream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Upstream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Upstream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Upstream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Upstream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Upstream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Upstream::Tcp(s) => Pin::new(s).poll_flush(cx),
            Upstream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Upstream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Upstream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Open the upstream connection with a deadline.
async fn connect_backend(addr: &BackendAddr, timeout_d: Duration) -> std::io::Result<Upstream> {
    let timed_out =
        || std::io::Error::new(std::io::ErrorKind::TimedOut, "backend connect timed out");
    match addr {
        BackendAddr::Tcp(a) => {
            let s = tokio::time::timeout(timeout_d, TcpStream::connect(*a))
                .await
                .map_err(|_| timed_out())??;
            let _ = s.set_nodelay(true);
            Ok(Upstream::Tcp(s))
        }
        BackendAddr::Unix(p) => {
            let s = tokio::time::timeout(timeout_d, UnixStream::connect(p))
                .await
                .map_err(|_| timed_out())??;
            Ok(Upstream::Unix(s))
        }
    }
}

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

    // Connect to the chosen backend (TCP or Unix socket).
    let connect_timeout = Duration::from_millis(cfg.backend_connect_timeout_ms);
    let mut upstream = match connect_backend(&backend.addr, connect_timeout).await {
        Ok(s) => s,
        Err(e) => {
            warn!(?peer, backend = %backend_name, error = %e, "backend connect failed");
            return;
        }
    };

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
/// Linear flow: read a chunk, then decide. Never waits for more data once
/// a decision is possible:
///
/// - first byte != 0x16 -> non-TLS, return immediately;
/// - 6th byte != 0x01 -> not a ClientHello, return immediately;
/// - full first record (`5 + record_len`, capped by `max_bytes`) -> return.
///
/// Never fails: partial data just means the caller routes by default.
/// A silent client is bounded by the caller's `hello_timeout`.
async fn read_hello(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> std::io::Result<()> {
    let mut tmp = [0u8; 4096];
    while buf.len() < max_bytes {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Ok(()); // EOF: route with what we have.
        }

        let to_take = n.min(max_bytes - buf.len());
        buf.extend_from_slice(&tmp[..to_take]);

        // Non-TLS: decide on the very first byte, no further waiting.
        if buf[0] != 0x16 {
            return Ok(());
        }

        // Need the handshake type (6th byte) before deciding more.
        if buf.len() >= 6 {
            if buf[5] != 0x01 {
                return Ok(()); // Not a ClientHello (alert, other handshake).
            }
            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if record_len == 0 {
                return Ok(());
            }
            let want = 5usize.saturating_add(record_len).min(max_bytes);
            if buf.len() >= want {
                return Ok(()); // Full first record buffered.
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, UnixListener};

    /// Minimal ClientHello carrying `sni`, as raw record bytes.
    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut list = vec![0x00];
        list.extend_from_slice(&(name.len() as u16).to_be_bytes());
        list.extend_from_slice(name);
        let mut ext = (list.len() as u16).to_be_bytes().to_vec();
        ext.extend_from_slice(&list);
        let mut exts = vec![0x00, 0x00];
        exts.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x55u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![
            0x01,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// Full path via a Unix-socket backend: PPv2 header + intact hello
    /// must arrive, and the client must get the backend reply.
    #[tokio::test]
    async fn relays_to_unix_backend_with_ppv2() {
        let sock_path =
            std::env::temp_dir().join(format!("penik-proxy-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock_path);
        let unix_lis = UnixListener::bind(&sock_path).unwrap();

        // Echo backend: read until EOF, record everything, reply with a marker.
        let backend_task = tokio::spawn(async move {
            let (mut conn, _) = unix_lis.accept().await.unwrap();
            let mut got = Vec::new();
            loop {
                let n = conn.read_buf(&mut got).await.unwrap();
                if n == 0 {
                    break;
                }
            }
            conn.write_all(b"BACKEND:unix").await.unwrap();
            conn.shutdown().await.unwrap();
            got
        });

        let text = format!(
            r#"
listen = ["127.0.0.1:0"]
default_backend = "caddy"

[backends.caddy]
addr = "unix://{}"
send_proxy_protocol = true
"#,
            sock_path.display()
        );
        let cfg = Arc::new(Config::parse(&text).unwrap());

        // TCP loopback pair: client <-> proxy inbound.
        let tcp_lis = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = tcp_lis.local_addr().unwrap();
        let proxy_task = tokio::spawn({
            let cfg = cfg.clone();
            async move {
                let (inbound, _) = tcp_lis.accept().await.unwrap();
                handle_conn(inbound, cfg).await;
            }
        });

        let hello = client_hello("penik.ru");
        let mut client = TcpStream::connect(listen_addr).await.unwrap();
        // Fragmented send: 2 bytes now, the rest later.
        client.write_all(&hello[..2]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        client.write_all(&hello[2..]).await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_buf(&mut reply).await.unwrap();

        proxy_task.await.unwrap();
        let got = backend_task.await.unwrap();
        let _ = std::fs::remove_file(&sock_path);

        assert_eq!(reply, b"BACKEND:unix");
        // 12-byte PPv2 signature, then the untouched ClientHello.
        assert_eq!(&got[..12], b"\r\n\r\n\x00\r\nQUIT\n");
        assert_eq!(got[12], 0x21);
        assert_eq!(got[13], 0x11);
        assert_eq!(&got[28..], &hello);
    }
}
