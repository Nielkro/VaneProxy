//! Per-connection relay: sniff SNI, pick backend, splice the stream.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use tracing::{debug, warn};

use crate::acme::alpn_challenge::AlpnChallengeRegistry;
use crate::caddyfile::cluster::matches_site_address;
use crate::caddyfile::model::SiteBlock;
use crate::config::{BackendAddr, Config};
use crate::l7::serve_l7_stream;
use crate::proxy_proto::encode_ppv2;
use crate::sni::parse_client_hello;

/// Unified runtime state holding active config, sites, ALPN registry, and TLS acceptor.
pub struct RuntimeState {
    config: ArcSwap<Config>,
    sites: ArcSwap<Vec<SiteBlock>>,
    pub alpn_registry: Arc<AlpnChallengeRegistry>,
    pub tls_acceptor: ArcSwap<Option<tokio_rustls::TlsAcceptor>>,
}

impl RuntimeState {
    pub fn new(
        config: Arc<Config>,
        sites: Arc<Vec<SiteBlock>>,
        alpn_registry: Arc<AlpnChallengeRegistry>,
        tls_acceptor: Option<tokio_rustls::TlsAcceptor>,
    ) -> Self {
        Self {
            config: ArcSwap::from(config),
            sites: ArcSwap::from(sites),
            alpn_registry,
            tls_acceptor: ArcSwap::from_pointee(tls_acceptor),
        }
    }

    pub fn config(&self) -> Arc<Config> {
        self.config.load_full()
    }

    pub fn sites(&self) -> Arc<Vec<SiteBlock>> {
        self.sites.load_full()
    }

    pub fn update_config(&self, new_config: Arc<Config>) {
        self.config.store(new_config);
    }

    pub fn update_sites(&self, new_sites: Arc<Vec<SiteBlock>>) {
        self.sites.store(new_sites);
    }

    pub fn update_tls_acceptor(&self, acceptor: Option<tokio_rustls::TlsAcceptor>) {
        self.tls_acceptor.store(Arc::new(acceptor));
    }
}

/// Stream wrapping an initial buffered memory slice before delegating to the underlying socket.
pub struct PrefixedStream<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pos = self.prefix.position() as usize;
        let data = self.prefix.get_ref();
        if pos < data.len() {
            let to_copy = (data.len() - pos).min(buf.remaining());
            buf.put_slice(&data[pos..pos + to_copy]);
            self.prefix.set_position((pos + to_copy) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Upstream connection: TCP socket or Unix domain socket.
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
pub async fn handle_conn(inbound: TcpStream, state: Arc<RuntimeState>) {
    let start = Instant::now();
    let peer = inbound.peer_addr().ok();
    let local = inbound.local_addr().ok();

    let cfg = state.config();
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

    let hello_info = parse_client_hello(&buf);
    let is_alpn = hello_info.is_acme_tls_alpn();
    let sni = hello_info.sni;

    // 0. Check ACME TLS-ALPN-01 challenge probe
    if is_alpn {
        if let Some(sni_name) = sni.as_deref() {
            if state.alpn_registry.get_challenge(sni_name).is_some() {
                debug!(sni = %sni_name, "handling ACME TLS-ALPN-01 probe");
                if let Some(acceptor) = state.tls_acceptor.load().as_ref() {
                    let prefixed = PrefixedStream::new(buf, inbound);
                    let acceptor = acceptor.clone();
                    let sni_owned = sni_name.to_string();
                    tokio::spawn(async move {
                        match acceptor.accept(prefixed).await {
                            Ok(mut stream) => {
                                let _ = stream.shutdown().await;
                            }
                            Err(e) => {
                                warn!(sni = %sni_owned, error = %e, "TLS-ALPN-01 handshake failed");
                            }
                        }
                    });
                    return;
                }
            }
        }
    }

    // 1. Check L4 passthrough routes in config.toml
    let l4_backend_name = sni.as_deref().and_then(|s| cfg.routes.get(s));

    if l4_backend_name.is_none() {
        // 2. Check L7 sites in sites-enabled/
        if let Some(sni_name) = sni.as_deref() {
            let sites = state.sites();
            let matched_site = sites.iter().find(|site| {
                site.addresses
                    .iter()
                    .any(|addr| matches_site_address(addr, sni_name))
            });

            if let Some(site) = matched_site {
                let acceptor_opt = state.tls_acceptor.load();
                if let Some(acceptor) = acceptor_opt.as_ref() {
                    let prefixed = PrefixedStream::new(buf, inbound);
                    let acceptor = acceptor.clone();
                    let site_arc = Arc::new(site.clone());
                    let peer_addr = peer.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
                    let sni_owned = sni_name.to_string();
                    tokio::spawn(async move {
                        match acceptor.accept(prefixed).await {
                            Ok(tls_stream) => {
                                serve_l7_stream(tls_stream, site_arc, peer_addr).await;
                            }
                            Err(e) => {
                                let err_str = e.to_string();
                                if err_str.contains("unexpected-eof")
                                    || err_str.contains("close_notify")
                                    || err_str.contains("NoCipherSuitesInCommon")
                                    || err_str.contains("Tls12NotOffered")
                                    || err_str.contains("tls handshake eof")
                                {
                                    debug!(sni = %sni_owned, error = %e, "TLS handshake closed or incompatible scanner probe");
                                } else {
                                    warn!(sni = %sni_owned, error = %e, "TLS handshake failed for L7 site");
                                }
                            }
                        }
                    });
                    return;
                }
            }
        }
    }

    // 3. Fallback: route to L4 backend or default_backend
    let backend_name = l4_backend_name
        .map(|s| s.as_str())
        .unwrap_or_else(|| &cfg.default_backend)
        .to_string();
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
                return Ok(());
            }
        }
    }
    Ok(())
}
