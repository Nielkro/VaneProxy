//! Static asset streaming with MIME detection, path traversal protection,
//! ETag / Last-Modified conditional caching (304), and byte range requests (206/416).

use std::path::Path;
use std::time::UNIX_EPOCH;
use bytes::Bytes;
use hyper::{header, HeaderMap, Method, Response, StatusCode};
use tokio::fs;

/// Checks whether a static file exists relative to the document root (for `file` matcher and `try_files`).
pub fn check_file_exists(root: &Path, req_path: &str) -> bool {
    let clean_path = req_path.trim_start_matches('/');
    let target = root.join(clean_path);
    if let (Ok(canon_root), Ok(canon_target)) = (root.canonicalize(), target.canonicalize()) {
        canon_target.starts_with(&canon_root) && canon_target.exists()
    } else {
        // Also check if directory contains index.html
        let index_target = target.join("index.html");
        if let (Ok(canon_root), Ok(canon_index)) = (root.canonicalize(), index_target.canonicalize()) {
            canon_index.starts_with(&canon_root) && canon_index.exists()
        } else {
            false
        }
    }
}

/// Formats a UNIX timestamp as IMF-fixdate (e.g. `Sun, 06 Nov 1994 08:49:37 GMT`).
pub fn format_imf_fixdate(secs: u64) -> String {
    // Breakdown UNIX seconds into day of week, day, month, year, hour, min, sec
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hour = time_of_day / 3600;
    let min = (time_of_day % 3600) / 60;
    let sec = time_of_day % 60;

    // 1970-01-01 was Thursday (index 4: 0=Sun, 1=Mon, ..., 4=Thu)
    let day_of_week = match (days_since_epoch + 4) % 7 {
        0 => "Sun",
        1 => "Mon",
        2 => "Tue",
        3 => "Wed",
        4 => "Thu",
        5 => "Fri",
        _ => "Sat",
    };

    // Calculate calendar year, month, day from days_since_epoch
    let mut days = days_since_epoch as i64;
    let mut year = 1970;

    loop {
        let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        let days_in_year = if is_leap { 366 } else { 365 };
        if days >= days_in_year {
            days -= days_in_year;
            year += 1;
        } else {
            break;
        }
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let mut month = 0;
    for (m, &dim) in days_in_months.iter().enumerate() {
        if days >= dim {
            days -= dim;
        } else {
            month = m;
            break;
        }
    }

    let day = days + 1;
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        day_of_week, day, month_names[month], year, hour, min, sec
    )
}

/// Parses an IMF-fixdate HTTP date into UNIX timestamp seconds.
pub fn parse_imf_fixdate(s: &str) -> Option<u64> {
    // Format: "Sun, 06 Nov 1994 08:49:37 GMT"
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    let day = parts[1].parse::<u64>().ok()?;
    let month = match parts[2] {
        "Jan" => 0,
        "Feb" => 1,
        "Mar" => 2,
        "Apr" => 3,
        "May" => 4,
        "Jun" => 5,
        "Jul" => 6,
        "Aug" => 7,
        "Sep" => 8,
        "Oct" => 9,
        "Nov" => 10,
        "Dec" => 11,
        _ => return None,
    };
    let year = parts[3].parse::<i64>().ok()?;
    let time_parts: Vec<&str> = parts[4].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour = time_parts[0].parse::<u64>().ok()?;
    let min = time_parts[1].parse::<u64>().ok()?;
    let sec = time_parts[2].parse::<u64>().ok()?;

    if year < 1970 {
        return None;
    }

    let mut total_days: i64 = 0;
    for y in 1970..year {
        let is_leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        total_days += if is_leap { 366 } else { 365 };
    }

    let is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
    let days_in_months = [
        31,
        if is_leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];

    for &dim in days_in_months.iter().take(month) {
        total_days += dim;
    }
    total_days += (day as i64) - 1;

    let total_secs = (total_days as u64) * 86400 + hour * 3600 + min * 60 + sec;
    Some(total_secs)
}

/// Parsed HTTP byte range specifier.
#[derive(Debug, PartialEq, Eq)]
enum RangeSpec {
    /// Exact range `bytes=start-end` inclusive
    Exact(u64, u64),
    /// Open-ended range `bytes=start-`
    From(u64),
    /// Suffix range `bytes=-suffix`
    Suffix(u64),
}

fn parse_single_range(header_val: &str) -> Option<RangeSpec> {
    let s = header_val.trim();
    if !s.starts_with("bytes=") {
        return None;
    }
    let range_part = &s["bytes=".len()..].trim();
    if range_part.contains(',') {
        // Multi-range not supported for 206 slice, fallback to 200 full
        return None;
    }
    let (start_str, end_str) = range_part.split_once('-')?;
    let start_str = start_str.trim();
    let end_str = end_str.trim();

    if start_str.is_empty() {
        if end_str.is_empty() {
            None
        } else {
            let suffix = end_str.parse::<u64>().ok()?;
            Some(RangeSpec::Suffix(suffix))
        }
    } else {
        let start = start_str.parse::<u64>().ok()?;
        if end_str.is_empty() {
            Some(RangeSpec::From(start))
        } else {
            let end = end_str.parse::<u64>().ok()?;
            Some(RangeSpec::Exact(start, end))
        }
    }
}

/// Attempts to serve a static file from the document root.
///
/// Implements:
/// - Path traversal protection and index.html directory resolution
/// - ETag (`"<mtime_hex>-<size_hex>"`) and Last-Modified (IMF-fixdate)
/// - Conditional requests: `If-None-Match` and `If-Modified-Since` (RFC 9110 §13.2.2 -> 304)
/// - Range requests: `Accept-Ranges: bytes`, `Range: bytes=...`, `If-Range` -> 206 / 416
///
/// Returns:
/// - `Some(Response)` if a static file was found or an access error occurred (403/416).
/// - `None` if the file was not found (allowing fallthrough to reverse proxy via `try_files` or handlers).
pub async fn serve_static_file(
    root: &Path,
    req_path: &str,
    req_method: &Method,
    req_headers: &HeaderMap,
    hide_patterns: &[String],
) -> Option<Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>>> {
    // Check hide patterns against the path
    for pat in hide_patterns {
        if req_path.ends_with(pat) || req_path.contains(pat) {
            return None;
        }
    }
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

    let meta = match fs::metadata(&file_path).await {
        Ok(m) => m,
        Err(_) => return None,
    };

    let file_len = meta.len();
    let mtime_unix = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let etag = format!("\"{mtime_unix:x}-{file_len:x}\"");
    let last_modified = format_imf_fixdate(mtime_unix);

    let is_head = req_method == Method::HEAD;
    let is_get = req_method == Method::GET;

    // RFC 9110 §13.2.2: Evaluate conditional headers for GET / HEAD
    if is_get || is_head {
        let mut not_modified = false;

        if let Some(inm) = req_headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
            let inm_trimmed = inm.trim();
            if inm_trimmed == "*" || inm_trimmed.split(',').any(|part| part.trim() == etag) {
                not_modified = true;
            }
        } else if let Some(ims) = req_headers.get(header::IF_MODIFIED_SINCE).and_then(|v| v.to_str().ok()) {
            if let Some(ims_secs) = parse_imf_fixdate(ims.trim()) {
                if mtime_unix <= ims_secs {
                    not_modified = true;
                }
            }
        }

        if not_modified {
            let resp = Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header(header::ETAG, etag)
                .header(header::LAST_MODIFIED, last_modified)
                .header(header::ACCEPT_RANGES, "bytes")
                .body(crate::l7::empty_box())
                .unwrap();
            return Some(resp);
        }
    }

    let content_type = mime_guess::from_path(&file_path)
        .first_or_octet_stream()
        .to_string();

    // Range requests handling (only applicable for GET requests)
    if is_get {
        if let Some(range_header) = req_headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
            // Check If-Range if present (can match ETag or Last-Modified)
            let mut if_range_matched = true;
            if let Some(if_range) = req_headers.get(header::IF_RANGE).and_then(|v| v.to_str().ok()) {
                let ir = if_range.trim();
                if ir.starts_with('"') {
                    if ir != etag {
                        if_range_matched = false;
                    }
                } else if let Some(ir_secs) = parse_imf_fixdate(ir) {
                    if mtime_unix > ir_secs {
                        if_range_matched = false;
                    }
                } else {
                    if_range_matched = false;
                }
            }

            if if_range_matched {
                if let Some(range_spec) = parse_single_range(range_header) {
                    let range_bounds = match range_spec {
                        RangeSpec::Exact(start, end) => {
                            if start <= end && start < file_len {
                                let valid_end = end.min(file_len - 1);
                                Some((start, valid_end))
                            } else {
                                None
                            }
                        }
                        RangeSpec::From(start) => {
                            if start < file_len {
                                Some((start, file_len - 1))
                            } else {
                                None
                            }
                        }
                        RangeSpec::Suffix(suffix) => {
                            if suffix == 0 {
                                None
                            } else {
                                let start = file_len.saturating_sub(suffix);
                                Some((start, file_len - 1))
                            }
                        }
                    };

                    match range_bounds {
                        Some((start, end)) => {
                            let range_len = (end - start + 1) as usize;
                            let full_bytes = match fs::read(&file_path).await {
                                Ok(b) => b,
                                Err(_) => return None,
                            };
                            let slice = full_bytes
                                .get(start as usize..=end as usize)
                                .unwrap_or_default()
                                .to_vec();

                            let content_range = format!("bytes {start}-{end}/{file_len}");
                            let resp = Response::builder()
                                .status(StatusCode::PARTIAL_CONTENT)
                                .header(header::CONTENT_TYPE, content_type)
                                .header(header::CONTENT_LENGTH, range_len.to_string())
                                .header(header::CONTENT_RANGE, content_range)
                                .header(header::ACCEPT_RANGES, "bytes")
                                .header(header::ETAG, etag)
                                .header(header::LAST_MODIFIED, last_modified)
                                .body(crate::l7::full_box(Bytes::from(slice)))
                                .unwrap();
                            return Some(resp);
                        }
                        None => {
                            // Unsatisfiable range (416)
                            let resp = Response::builder()
                                .status(StatusCode::RANGE_NOT_SATISFIABLE)
                                .header(header::CONTENT_RANGE, format!("bytes */{file_len}"))
                                .header(header::ACCEPT_RANGES, "bytes")
                                .body(crate::l7::full_box(Bytes::from("416 Range Not Satisfiable")))
                                .unwrap();
                            return Some(resp);
                        }
                    }
                }
            }
        }
    }

    // Standard 200 OK response
    let body_bytes = if is_head {
        Bytes::new()
    } else {
        match fs::read(&file_path).await {
            Ok(bytes) => Bytes::from(bytes),
            Err(_) => return None,
        }
    };

    let content_len = if is_head {
        file_len
    } else {
        body_bytes.len() as u64
    };

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, content_len.to_string())
        .header(header::ETAG, etag)
        .header(header::LAST_MODIFIED, last_modified)
        .header(header::ACCEPT_RANGES, "bytes")
        .body(crate::l7::full_box(body_bytes))
        .unwrap();

    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_imf_fixdate_format_and_parse() {
        let secs = 784111777; // Sun, 06 Nov 1994 08:49:37 GMT
        let formatted = format_imf_fixdate(secs);
        assert_eq!(formatted, "Sun, 06 Nov 1994 08:49:37 GMT");
        let parsed = parse_imf_fixdate(&formatted).expect("parsed date");
        assert_eq!(parsed, secs);
    }

    #[test]
    fn test_parse_single_range() {
        assert_eq!(
            parse_single_range("bytes=0-499"),
            Some(RangeSpec::Exact(0, 499))
        );
        assert_eq!(
            parse_single_range("bytes=500-"),
            Some(RangeSpec::From(500))
        );
        assert_eq!(
            parse_single_range("bytes=-500"),
            Some(RangeSpec::Suffix(500))
        );
        assert_eq!(parse_single_range("bytes=0-0, 50-100"), None);
        assert_eq!(parse_single_range("items=1-5"), None);
    }

    #[tokio::test]
    async fn test_serve_static_file_etag_and_range() {
        let temp_dir = std::env::temp_dir().join(format!("vane_test_static_{}", std::process::id()));
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();
        let file_path = temp_dir.join("test.txt");
        tokio::fs::write(&file_path, b"Hello, World! Vane Static Test").await.unwrap();

        let dummy_headers = HeaderMap::new();

        // 1. Initial 200 OK request
        let resp = serve_static_file(&temp_dir, "/test.txt", &Method::GET, &dummy_headers, &[])
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::ACCEPT_RANGES).unwrap(), "bytes");
        let etag = resp.headers().get(header::ETAG).unwrap().to_str().unwrap().to_string();
        let last_modified = resp.headers().get(header::LAST_MODIFIED).unwrap().to_str().unwrap().to_string();

        // 2. Conditional request with matching If-None-Match -> 304 Not Modified
        let mut inm_headers = HeaderMap::new();
        inm_headers.insert(header::IF_NONE_MATCH, etag.parse().unwrap());
        let resp304 = serve_static_file(&temp_dir, "/test.txt", &Method::GET, &inm_headers, &[])
            .await
            .expect("304 response");
        assert_eq!(resp304.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(resp304.headers().get(header::ETAG).unwrap(), etag.as_str());

        // 3. Conditional request with matching If-Modified-Since -> 304 Not Modified
        let mut ims_headers = HeaderMap::new();
        ims_headers.insert(header::IF_MODIFIED_SINCE, last_modified.parse().unwrap());
        let resp304_ims = serve_static_file(&temp_dir, "/test.txt", &Method::GET, &ims_headers, &[])
            .await
            .expect("304 response ims");
        assert_eq!(resp304_ims.status(), StatusCode::NOT_MODIFIED);

        // 4. Valid byte range request -> 206 Partial Content
        let mut range_headers = HeaderMap::new();
        range_headers.insert(header::RANGE, "bytes=0-4".parse().unwrap());
        let resp206 = serve_static_file(&temp_dir, "/test.txt", &Method::GET, &range_headers, &[])
            .await
            .expect("206 response");
        assert_eq!(resp206.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp206.headers().get(header::CONTENT_RANGE).unwrap(), "bytes 0-4/30");
        assert_eq!(resp206.headers().get(header::CONTENT_LENGTH).unwrap(), "5");

        // 5. Out of bounds byte range request -> 416 Range Not Satisfiable
        let mut oob_headers = HeaderMap::new();
        oob_headers.insert(header::RANGE, "bytes=500-600".parse().unwrap());
        let resp416 = serve_static_file(&temp_dir, "/test.txt", &Method::GET, &oob_headers, &[])
            .await
            .expect("416 response");
        assert_eq!(resp416.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(resp416.headers().get(header::CONTENT_RANGE).unwrap(), "bytes */30");

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }
}
