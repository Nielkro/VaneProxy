//! Layer-7 reverse proxy and static asset HTTP server.

pub mod proxy;
pub mod service;
pub mod static_files;

use std::net::SocketAddr;
use std::sync::Arc;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::error;

use crate::caddyfile::model::SiteBlock;
pub use service::{extract_request_host, handle_site_request, resolve_site_for_request};

/// Serves an established decrypted TLS stream as an HTTP/1.1 or HTTP/2 connection.
///
/// Dispatches each request to the matching SiteBlock based on the request's `Host` / `:authority` header,
/// preventing cross-talk and connection coalescing conflicts across multi-SAN HTTP/2 sessions.
pub async fn serve_l7_stream<S>(
    stream: S,
    sites: Arc<Vec<SiteBlock>>,
    default_site: Arc<SiteBlock>,
    peer_addr: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let builder = Builder::new(TokioExecutor::new());

    let service = service_fn(move |req| {
        let sites_ref = Arc::clone(&sites);
        let default_site_ref = Arc::clone(&default_site);
        async move {
            let host = extract_request_host(&req);
            let site = resolve_site_for_request(&sites_ref, &host, &default_site_ref);
            handle_site_request(req, site, peer_addr).await
        }
    });

    let conn = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(conn);
    if let Err(e) = conn.as_mut().await {
        let err_str = e.to_string();
        if err_str.contains("unexpected-eof") || err_str.contains("close_notify") {
            tracing::debug!(peer = %peer_addr, error = %e, "client closed connection without close_notify");
        } else {
            error!(peer = %peer_addr, error = %e, "L7 connection serving error");
        }
    }
}

/// Converts a Bytes buffer into a BoxBody with hyper::Error.
pub fn full_box(bytes: bytes::Bytes) -> http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error> {
    use http_body_util::{BodyExt, Full};
    Full::new(bytes)
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed()
}

/// Converts an empty buffer into a BoxBody with hyper::Error.
pub fn empty_box() -> http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error> {
    use http_body_util::{BodyExt, Empty};
    Empty::new()
        .map_err(|never: std::convert::Infallible| match never {})
        .boxed()
}
