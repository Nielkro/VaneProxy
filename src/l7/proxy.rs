//! High-performance reverse proxy forwarder with WebSocket tunneling and HTTPS upstream support.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::{
    header::{self, HeaderName, HeaderValue},
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::error;

use crate::caddyfile::model::{HeaderOp, Upstream};
use crate::caddyfile::placeholders::{replace_placeholders, PlaceholderContext};

enum TransportStream {
    Tcp(TcpStream),
    Unix(UnixStream),
    Tls(TlsStream<TcpStream>),
}

impl AsyncRead for TransportStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TransportStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::Unix(s) => Pin::new(s).poll_read(cx, buf),
            TransportStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TransportStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            TransportStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::Unix(s) => Pin::new(s).poll_write(cx, buf),
            TransportStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TransportStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            TransportStream::Unix(s) => Pin::new(s).poll_flush(cx),
            TransportStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TransportStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::Unix(s) => Pin::new(s).poll_shutdown(cx),
            TransportStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// No-op server certificate verifier for loopback tls_insecure_skip_verify.
#[derive(Debug)]
struct NoVerifyServerCert;

impl ServerCertVerifier for NoVerifyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// Forwards an HTTP request to the designated upstream with header operations and WebSocket upgrade support.
pub async fn forward_request(
    mut req: Request<hyper::body::Incoming>,
    upstream: &Upstream,
    peer_addr: SocketAddr,
    header_ops_up: &[HeaderOp],
    header_ops_down: &[HeaderOp],
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let is_upgrade = req
        .headers()
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);

    let host_header = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_default();

    // In HTTP/1.1 forward proxies or HTTP/2 downstreams, the URI can be absolute;
    // strict upstreams reject with 400.
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_string());
    if let Ok(origin_uri) = path_and_query.parse::<hyper::Uri>() {
        *req.uri_mut() = origin_uri;
    }

    let method_str = req.method().as_str().to_string();
    let path_str = req.uri().path().to_string();
    let placeholder_ctx = PlaceholderContext::new(
        &method_str,
        &path_str,
        &host_header,
        peer_addr,
        req.headers(),
    );

    // Inject standard reverse proxy headers
    let headers = req.headers_mut();
    if !host_header.is_empty() && !headers.contains_key(header::HOST) {
        if let Ok(host_val) = HeaderValue::from_str(&host_header) {
            headers.insert(header::HOST, host_val);
        }
    }
    headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&peer_addr.ip().to_string()).unwrap(),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    headers.insert(
        HeaderName::from_static("x-real-ip"),
        HeaderValue::from_str(&peer_addr.ip().to_string()).unwrap(),
    );
    if !host_header.is_empty() {
        headers.insert(
            HeaderName::from_static("x-forwarded-host"),
            HeaderValue::from_str(&host_header).unwrap(),
        );
    }

    // Apply custom header_up operations with placeholder substitution
    for op in header_ops_up {
        match op {
            HeaderOp::Set(k, v) => {
                let expanded = replace_placeholders(v, &placeholder_ctx).unwrap_or_else(|_| v.clone());
                if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&expanded)) {
                    headers.insert(name, val);
                }
            }
            HeaderOp::Add(k, v) => {
                let expanded = replace_placeholders(v, &placeholder_ctx).unwrap_or_else(|_| v.clone());
                if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&expanded)) {
                    headers.append(name, val);
                }
            }
            HeaderOp::Delete(k) => {
                if let Ok(name) = HeaderName::from_bytes(k.as_bytes()) {
                    headers.remove(name);
                }
            }
        }
    }

    // Connect to upstream target
    let transport = match upstream {
        Upstream::Tcp(addr_str) => match TcpStream::connect(addr_str).await {
            Ok(s) => {
                let _ = s.set_nodelay(true);
                TransportStream::Tcp(s)
            }
            Err(e) => {
                error!(upstream = %addr_str, error = %e, "failed to connect to TCP upstream");
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(crate::l7::full_box(Bytes::from("502 Bad Gateway: connection failed")))
                    .unwrap());
            }
        },
        Upstream::Unix(socket_path) => match UnixStream::connect(socket_path).await {
            Ok(s) => TransportStream::Unix(s),
            Err(e) => {
                error!(socket = %socket_path.display(), error = %e, "failed to connect to Unix socket upstream");
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(crate::l7::full_box(Bytes::from("502 Bad Gateway: socket connection failed")))
                    .unwrap());
            }
        },
        Upstream::Tls(tls_cfg) => {
            // TCP connect to destination
            let tcp_stream = match TcpStream::connect(&tls_cfg.addr).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    s
                }
                Err(e) => {
                    error!(upstream = %tls_cfg.addr, error = %e, "failed to connect to TLS upstream TCP socket");
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(crate::l7::full_box(Bytes::from("502 Bad Gateway: TLS upstream connect failed")))
                        .unwrap());
                }
            };

            // Setup TLS client config
            let client_config = if tls_cfg.insecure {
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerifyServerCert))
                    .with_no_client_auth()
            } else {
                let mut root_store = rustls::RootCertStore::empty();
                let native_certs = rustls_native_certs::load_native_certs();
                for cert in native_certs.certs {
                    let _ = root_store.add(cert);
                }
                ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth()
            };

            let connector = TlsConnector::from(Arc::new(client_config));
            let server_name = match ServerName::try_from(tls_cfg.sni.clone()) {
                Ok(name) => name,
                Err(_) => {
                    error!(sni = %tls_cfg.sni, "invalid SNI for TLS upstream");
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(crate::l7::full_box(Bytes::from("502 Bad Gateway: invalid upstream SNI")))
                        .unwrap());
                }
            };

            match connector.connect(server_name, tcp_stream).await {
                Ok(tls_stream) => TransportStream::Tls(tls_stream),
                Err(e) => {
                    error!(upstream = %tls_cfg.addr, sni = %tls_cfg.sni, error = %e, "TLS handshake with upstream failed");
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(crate::l7::full_box(Bytes::from("502 Bad Gateway: upstream TLS handshake failed")))
                        .unwrap());
                }
            }
        }
    };

    let io = TokioIo::new(transport);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    if is_upgrade {
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                error!(error = %e, "upstream connection error during upgrade");
            }
        });

        let on_upgrade = hyper::upgrade::on(&mut req);
        let resp = sender.send_request(req).await?;

        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let (mut parts, _) = resp.into_parts();
            let upstream_upgrade = hyper::upgrade::on(Response::from_parts(parts.clone(), ()));
            tokio::spawn(async move {
                match (on_upgrade.await, upstream_upgrade.await) {
                    (Ok(downstream), Ok(upstream)) => {
                        let mut down_io = TokioIo::new(downstream);
                        let mut up_io = TokioIo::new(upstream);
                        let _ = copy_bidirectional(&mut down_io, &mut up_io).await;
                    }
                    (Err(e), _) => error!(error = %e, "downstream upgrade failed"),
                    (_, Err(e)) => error!(error = %e, "upstream upgrade failed"),
                }
            });

            // Ensure standard upgrade headers are present in downstream response
            parts.headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
            parts.headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));

            return Ok(Response::from_parts(parts, crate::l7::empty_box()));
        }

        let (parts, body) = resp.into_parts();
        return Ok(Response::from_parts(parts, body.boxed()));
    }

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            error!(error = %e, "upstream connection error");
        }
    });

    let resp = sender.send_request(req).await?;
    let (mut parts, body) = resp.into_parts();

    // Build context with upstream response headers for header_down placeholder expansions
    let resp_headers = parts.headers.clone();
    let resp_ctx = placeholder_ctx.with_upstream_headers(&resp_headers);

    // Apply custom header_down operations with placeholder substitution
    for op in header_ops_down {
        match op {
            HeaderOp::Set(k, v) => {
                let expanded = replace_placeholders(v, &resp_ctx).unwrap_or_else(|_| v.clone());
                if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&expanded)) {
                    parts.headers.insert(name, val);
                }
            }
            HeaderOp::Add(k, v) => {
                let expanded = replace_placeholders(v, &resp_ctx).unwrap_or_else(|_| v.clone());
                if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(&expanded)) {
                    parts.headers.append(name, val);
                }
            }
            HeaderOp::Delete(k) => {
                if let Ok(name) = HeaderName::from_bytes(k.as_bytes()) {
                    parts.headers.remove(name);
                }
            }
        }
    }

    Ok(Response::from_parts(parts, body.boxed()))
}
