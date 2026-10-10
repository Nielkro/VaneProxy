//! Static asset streaming with MIME detection and path traversal protection.

use std::path::Path;
use bytes::Bytes;
use hyper::{header, Response, StatusCode};
use tokio::fs;

/// Attempts to serve a static file from the document root.
///
/// Returns:
/// - `Some(Response)` if a static file was found or an access error occurred (403).
/// - `None` if the file was not found (allowing fallthrough to reverse proxy via `try_files` or handlers).
pub async fn serve_static_file(
    root: &Path,
    req_path: &str,
    is_head: bool,
) -> Option<Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>>> {
    // Sanitize path against directory traversal
    let clean_path = req_path.trim_start_matches('/');
    let target = root.join(clean_path);

    // Canonicalize root and target to ensure target stays within root
    let canonical_root = match root.canonicalize() {
        Ok(r) => r,
        Err(_) => return None,
    };

    let canonical_target = match target.canonicalize() {
        Ok(t) => t,
        Err(_) => {
            // Check if directory with index.html exists
            let index_target = target.join("index.html");
            if let Ok(canon_index) = index_target.canonicalize() {
                canon_index
            } else {
                return None;
            }
        }
    };

    if !canonical_target.starts_with(&canonical_root) {
        // Forbidden directory traversal attempt
        return Some(
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(crate::l7::full_box(Bytes::from("403 Forbidden")))
                .unwrap(),
        );
    }

    let meta = match fs::metadata(&canonical_target).await {
        Ok(m) => m,
        Err(_) => return None,
    };

    let file_path = if meta.is_dir() {
        let index = canonical_target.join("index.html");
        if index.exists() {
            index
        } else {
            return None;
        }
    } else {
        canonical_target
    };

    let content_type = mime_guess::from_path(&file_path)
        .first_or_octet_stream()
        .to_string();

    let body_bytes = if is_head {
        Bytes::new()
    } else {
        match fs::read(&file_path).await {
            Ok(bytes) => Bytes::from(bytes),
            Err(_) => return None,
        }
    };

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, meta.len().to_string())
        .body(crate::l7::full_box(body_bytes))
        .unwrap();

    Some(response)
}
