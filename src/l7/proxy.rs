//! High-performance reverse proxy forwarder with WebSocket tunneling.

use std::net::SocketAddr;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    header::{self, HeaderName, HeaderValue},
    upgrade::OnUpgrade,
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpStream, UnixStream};
use tracing::{error, info};

use crate::caddyfile::model::{HeaderOp, Upstream};

/// Forwards an HTTP request to an upstream target, supporting WebSockets and proxy headers.
pub async fn forward_request(
    mut req: Request<hyper::body::Incoming>,
    upstream: &Upstream,
    peer_addr: SocketAddr,
    header_ops_up: &[HeaderOp],
    header_ops_down: &[HeaderOp],
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let host_header = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Detect if this is a WebSocket upgrade request
    let is_upgrade = req
        .headers()
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);

    // Inject standard reverse proxy headers
    let headers = req.headers_mut();
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

    // Apply custom header_up operations
    for op in header_ops_up {
        match op {
            HeaderOp::Set(k, v) => {
                if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
                    headers.insert(name, val);
                }
            }
            HeaderOp::Add(k, v) => {
                if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
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
    let (mut sender, conn) = match upstream {
        Upstream::Tcp(addr_str) => {
            let stream = match TcpStream::connect(addr_str).await {
                Ok(s) => s,
                Err(e) => {
                    error!(upstream = %addr_str, error = %e, "failed to connect to TCP upstream");
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from("502 Bad Gateway: connection failed")).boxed())
                        .unwrap());
                }
            };
            let io = TokioIo::new(stream);
            hyper::client::conn::http1::handshake(io).await?
        }
        Upstream::Unix(socket_path) => {
            let stream = match UnixStream::connect(socket_path).await {
                Ok(s) => s,
                Err(e) => {
                    error!(socket = %socket_path.display(), error = %e, "failed to connect to Unix socket upstream");
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from("502 Bad Gateway: socket connection failed")).boxed())
                        .unwrap());
                }
            };
            let io = TokioIo::new(stream);
            hyper::client::conn::http1::handshake(io).await?
        }
    };

    if is_upgrade {
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                error!(error = %e, "upstream connection error during upgrade");
            }
        });

        let on_upgrade = hyper::upgrade::on(&mut req);
        let resp = sender.send_request(req).await?;

        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            let upstream_upgrade = hyper::upgrade::on(resp);
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

            return Ok(Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header(header::UPGRADE, "websocket")
                .header(header::CONNECTION, "Upgrade")
                .body(Empty::new().boxed())
                .unwrap());
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

    // Apply custom header_down operations
    for op in header_ops_down {
        match op {
            HeaderOp::Set(k, v) => {
                if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
                    parts.headers.insert(name, val);
                }
            }
            HeaderOp::Add(k, v) => {
                if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(k.as_bytes()), HeaderValue::from_str(v)) {
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
