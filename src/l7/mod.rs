//! Layer-7 reverse proxy and static asset HTTP server.

pub mod proxy;
pub mod service;
pub mod static_files;

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
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
    default_site_index: usize,
    peer_addr: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let builder = Builder::new(TokioExecutor::new());

    let service = service_fn(move |req| {
        let sites_ref = Arc::clone(&sites);
        async move {
            let host = extract_request_host(&req);
            let default_site = &sites_ref[default_site_index];
            let site = resolve_site_for_request(&sites_ref, &host, default_site);
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

/// Chunk size used when streaming a static file from disk.
const FILE_CHUNK_SIZE: usize = 64 * 1024;

/// Streaming HTTP body backed by a file, avoiding loading whole files into memory.
struct FileBody {
    file: File,
    buf: Vec<u8>,
    remaining: u64,
}

impl FileBody {
    fn new(file: File, len: u64) -> Self {
        Self {
            file,
            buf: vec![0u8; FILE_CHUNK_SIZE],
            remaining: len,
        }
    }
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        if this.remaining == 0 {
            return Poll::Ready(None);
        }

        let want = this.buf.len().min(this.remaining as usize);
        let mut read_buf = ReadBuf::new(&mut this.buf[..want]);
        match Pin::new(&mut this.file).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    // File shrank under us: end the stream.
                    this.remaining = 0;
                    return Poll::Ready(None);
                }
                this.remaining -= n as u64;
                let data = Bytes::copy_from_slice(read_buf.filled());
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            Poll::Ready(Err(e)) => {
                // hyper::Error cannot be constructed from io::Error; end the
                // stream and let hyper close the connection on length mismatch.
                tracing::warn!(error = %e, "static file read error");
                this.remaining = 0;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }
}

/// Wraps an opened file into a streaming boxed body.
pub fn file_box(file: File, len: u64) -> BoxBody<Bytes, hyper::Error> {
    FileBody::new(file, len).boxed()
}
