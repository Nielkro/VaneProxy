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
use crate::l7::service::handle_site_request;

/// Serves an established decrypted TLS stream as an HTTP/1.1 or HTTP/2 connection.
pub async fn serve_l7_stream<S>(stream: S, site: Arc<SiteBlock>, peer_addr: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let builder = Builder::new(TokioExecutor::new());

    let service = service_fn(move |req| {
        let site_ref = Arc::clone(&site);
        async move { handle_site_request(req, &site_ref, peer_addr).await }
    });

    if let Err(e) = builder.serve_connection(io, service).await {
        error!(peer = %peer_addr, error = %e, "L7 connection serving error");
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
