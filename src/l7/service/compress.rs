use super::*;

/// Compresses a response body with gzip if content type is compressible.
pub(super) async fn maybe_compress_gzip(
    resp: Response<BoxBody<Bytes, hyper::Error>>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    // Range responses (206 Partial Content) must not be compressed as slices are identity-based
    if resp.status() == StatusCode::PARTIAL_CONTENT {
        return resp;
    }

    let (mut parts, body) = resp.into_parts();

    // Do not re-compress if Content-Encoding is already present
    if parts.headers.contains_key(header::CONTENT_ENCODING) {
        return Response::from_parts(parts, body);
    }

    // Check Content-Type for compressible types
    let is_compressible = parts.headers.get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            ct.starts_with("text/")
                || ct.contains("json")
                || ct.contains("javascript")
                || ct.contains("xml")
                || ct.contains("svg")
        })
        .unwrap_or(false);

    if !is_compressible {
        return Response::from_parts(parts, body);
    }

    // Collect body bytes and compress using flate2.
    use http_body_util::BodyExt;
    let bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return Response::from_parts(parts, crate::l7::empty_box()),
    };

    // Compression of tiny bodies costs more than it saves.
    const MIN_GZIP_BYTES: usize = 1024;
    if bytes.len() < MIN_GZIP_BYTES {
        return Response::from_parts(parts, crate::l7::full_box(bytes));
    }

    // gzip is CPU-bound: keep it off the async worker threads.
    let original = bytes.clone();
    let compressed = tokio::task::spawn_blocking(move || -> Option<Vec<u8>> {
        use std::io::Write;
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut encoder =
            GzEncoder::new(Vec::with_capacity(bytes.len() / 2), Compression::default());
        encoder.write_all(&bytes).ok()?;
        encoder.finish().ok()
    })
    .await
    .ok()
    .flatten();

    let compressed = match compressed {
        Some(c) => c,
        None => return Response::from_parts(parts, crate::l7::full_box(original)),
    };

    parts.headers.insert(header::CONTENT_ENCODING, header::HeaderValue::from_static("gzip"));
    parts.headers.insert(header::CONTENT_LENGTH, header::HeaderValue::from_str(&compressed.len().to_string()).unwrap());

    Response::from_parts(parts, crate::l7::full_box(Bytes::from(compressed)))
}
