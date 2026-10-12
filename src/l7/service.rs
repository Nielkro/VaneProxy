//! HTTP request router dispatching directives within a SiteBlock.
//!
//! Evaluates directives according to plan/07 Phase 3:
//! 1. Request body limit check (rejects 413 Payload Too Large if Content-Length exceeds limit).
//! 2. Top-level redir / rewrite directives.
//! 3. Ordered handle blocks evaluation (first matching block wins; catch-all fallback).
//!    Supports `handle_path <prefix>` with prefix stripping.
//! 4. Within the winning block (or top level if no handle blocks exist):
//!    `uri strip_prefix` -> `root` / `file_server` (with `hide` support) / `try_files` ->
//!    `reverse_proxy` (with `X-Accel-Redirect` intercept) -> `respond`.
//! 5. Post-response header directives (`header [@matcher] [+|-]Name [value]`).
//! 6. Error interception via `handle_errors` block on 4xx/5xx responses.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::{header, HeaderMap, Method, Request, Response, StatusCode, Uri};
use tracing::warn;

use crate::caddyfile::model::{
    Directive, HeaderOp, MatcherDef, MatcherRule, SiteBlock,
};
use crate::caddyfile::placeholders::{replace_placeholders, PlaceholderContext};
use crate::l7::proxy::forward_request;
use crate::l7::static_files::{check_file_exists, serve_static_file};

/// Handles an incoming HTTP request for a resolved site.
pub async fn handle_site_request<B>(
    mut req: Request<B>,
    site: &SiteBlock,
    peer_addr: SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error> + Send + Unpin + 'static,
{
    // Collect named matchers defined at site level
    let mut matchers: HashMap<String, &MatcherDef> = HashMap::new();
    for dir in &site.directives {
        if let Directive::Matcher(m) = dir {
            matchers.insert(m.name.clone(), m);
        }
    }

    // 1. Check request body size limit (default 250 MB if unspecified)
    let body_limit = site.directives.iter().find_map(|d| match d {
        Directive::RequestBodyLimit(lim) => Some(*lim),
        _ => None,
    }).unwrap_or(250 * 1024 * 1024);

    if let Some(content_len_val) = req.headers().get(header::CONTENT_LENGTH) {
        if let Ok(len_str) = content_len_val.to_str() {
            if let Ok(len) = len_str.parse::<u64>() {
                if len > body_limit {
                    return Ok(Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(crate::l7::full_box(Bytes::from("413 Payload Too Large")))
                        .unwrap());
                }
            }
        }
    }

    // Capture initial request context details
    let mut host_header = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if host_header.is_empty() {
        if let Some(auth) = req.uri().authority() {
            host_header = auth.as_str().to_string();
        }
    }

    let method_str = req.method().as_str().to_string();
    let initial_path = req.uri().path().to_string();
    let client_accepts_gzip = req
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|enc| enc.contains("gzip"))
        .unwrap_or(false);

    let initial_ctx = PlaceholderContext::new(
        &method_str,
        &initial_path,
        &host_header,
        peer_addr,
        req.headers(),
    );

    // 2. Top-level redirects
    for dir in &site.directives {
        if let Directive::Redir(cfg) = dir {
            let matched = match &cfg.matcher {
                Some(m) => evaluate_matcher_ref(m, &matchers, &req, None),
                None => true,
            };
            if matched {
                let status = StatusCode::from_u16(cfg.code).unwrap_or(StatusCode::FOUND);
                let target = replace_placeholders(&cfg.target, &initial_ctx).unwrap_or_else(|_| cfg.target.clone());
                return Ok(Response::builder()
                    .status(status)
                    .header(header::LOCATION, &target)
                    .body(crate::l7::full_box(Bytes::from(format!("Redirecting to {}", target))))
                    .unwrap());
            }
        }
    }

    // Top-level rewrites
    for dir in &site.directives {
        if let Directive::Rewrite(cfg) = dir {
            let matched = match &cfg.matcher {
                Some(m) => evaluate_matcher_ref(m, &matchers, &req, None),
                None => true,
            };
            if matched {
                let target = replace_placeholders(&cfg.target, &initial_ctx).unwrap_or_else(|_| cfg.target.clone());
                if let Ok(new_uri) = target.parse::<Uri>() {
                    *req.uri_mut() = new_uri;
                }
            }
        }
    }

    // 3. Find matching handle block (by file order)
    let mut chosen_directives: Option<Vec<Directive>> = None;
    let top_root = site.directives.iter().find_map(|d| match d {
        Directive::Root(p) => Some(PathBuf::from(p)),
        _ => None,
    });

    for dir in &site.directives {
        match dir {
            Directive::Handle(hb) => {
                let matched = match &hb.matcher {
                    Some(m) => evaluate_matcher_ref(m, &matchers, &req, top_root.as_deref()),
                    None => true, // catch-all handle
                };
                if matched {
                    chosen_directives = Some(hb.directives.clone());
                    break;
                }
            }
            Directive::HandlePath(hp) => {
                let req_path = req.uri().path();
                let prefix_clean = hp.prefix.trim_end_matches('*');
                if req_path.starts_with(prefix_clean) {
                    // Strip prefix from URI
                    let stripped = req_path.strip_prefix(prefix_clean).unwrap_or(req_path);
                    let new_path = if stripped.starts_with('/') {
                        stripped.to_string()
                    } else {
                        format!("/{}", stripped)
                    };
                    let query = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
                    if let Ok(new_uri) = format!("{}{}", new_path, query).parse::<Uri>() {
                        *req.uri_mut() = new_uri;
                    }
                    chosen_directives = Some(hp.directives.clone());
                    break;
                }
            }
            _ => {}
        }
    }

    // Directives to execute for this request
    let active_directives = chosen_directives.unwrap_or_else(|| site.directives.clone());

    // Execute the active block pipeline
    let mut resp = execute_directive_pipeline(req, &active_directives, &matchers, peer_addr, &host_header).await?;

    // Apply response headers defined at site or block level
    let placeholder_ctx = PlaceholderContext::new(
        &method_str,
        &initial_path,
        &host_header,
        peer_addr,
        &HeaderMap::new(),
    ).with_upstream_headers(resp.headers());

    apply_response_headers(&mut resp, &site.directives, &matchers, &placeholder_ctx);
    if active_directives != site.directives {
        apply_response_headers(&mut resp, &active_directives, &matchers, &placeholder_ctx);
    }

    // 6. Handle errors if status is 4xx or 5xx and handle_errors is declared
    let status_code = resp.status().as_u16();
    if status_code >= 400 {
        if let Some(err_directives) = site.directives.iter().find_map(|d| match d {
            Directive::HandleErrors(inner) => Some(inner),
            _ => None,
        }) {
            if let Some(err_resp) = execute_handle_errors(
                err_directives,
                status_code,
                &matchers,
                &placeholder_ctx,
                top_root.as_deref(),
            ).await {
                resp = err_resp;
            }
        }
    }

    // 7. Gzip compression if site has `encode` directive and client accepts gzip
    let has_encode_gzip = site.directives.iter().chain(active_directives.iter()).any(|d| match d {
        Directive::Encode(encs) => encs.iter().any(|e| e == "gzip" || e == "zstd"),
        _ => false,
    });

    if has_encode_gzip && client_accepts_gzip {
        resp = maybe_compress_gzip(resp).await;
    }

    Ok(resp)
}

/// Compresses a response body with gzip if content type is compressible.
async fn maybe_compress_gzip(
    resp: Response<BoxBody<Bytes, hyper::Error>>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
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

    // Collect body bytes and compress using flate2
    use http_body_util::BodyExt;
    let bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return Response::from_parts(parts, crate::l7::empty_box()),
    };

    use std::io::Write;
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    if encoder.write_all(&bytes).is_err() {
        return Response::from_parts(parts, crate::l7::full_box(bytes));
    }
    let compressed = match encoder.finish() {
        Ok(c) => c,
        Err(_) => return Response::from_parts(parts, crate::l7::full_box(bytes)),
    };

    parts.headers.insert(header::CONTENT_ENCODING, header::HeaderValue::from_static("gzip"));
    parts.headers.insert(header::CONTENT_LENGTH, header::HeaderValue::from_str(&compressed.len().to_string()).unwrap());

    Response::from_parts(parts, crate::l7::full_box(Bytes::from(compressed)))
}

/// Executes the core request handling pipeline within a set of directives.
async fn execute_directive_pipeline<B>(
    mut req: Request<B>,
    directives: &[Directive],
    matchers: &HashMap<String, &MatcherDef>,
    peer_addr: SocketAddr,
    host_header: &str,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error> + Send + Unpin + 'static,
{
    let mut req_path = req.uri().path().to_string();

    // 1. Process `uri strip_prefix`
    for dir in directives {
        if let Directive::UriStripPrefix(prefix) = dir {
            let prefix_clean = prefix.trim_end_matches('*');
            if req_path.starts_with(prefix_clean) {
                let stripped = req_path.strip_prefix(prefix_clean).unwrap_or(&req_path);
                let new_path = if stripped.starts_with('/') {
                    stripped.to_string()
                } else {
                    format!("/{}", stripped)
                };
                let query = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
                if let Ok(new_uri) = format!("{}{}", new_path, query).parse::<Uri>() {
                    *req.uri_mut() = new_uri;
                    req_path = new_path;
                }
            }
        }
    }

    // 2. Determine root path for static file lookups
    let root_path = directives.iter().find_map(|d| match d {
        Directive::Root(p) => Some(PathBuf::from(p)),
        _ => None,
    });

    let placeholder_ctx = PlaceholderContext::new(
        req.method().as_str(),
        &req_path,
        host_header,
        peer_addr,
        req.headers(),
    );

    // 3. Process respond directives
    for dir in directives {
        if let Directive::Respond(cfg) = dir {
            let matched = match &cfg.matcher {
                Some(m) => evaluate_matcher_ref(m, matchers, &req, root_path.as_deref()),
                None => true,
            };
            if matched {
                let status = StatusCode::from_u16(cfg.status).unwrap_or(StatusCode::OK);
                let body_str = match &cfg.body {
                    Some(b) => replace_placeholders(b, &placeholder_ctx).unwrap_or_else(|_| b.clone()),
                    None => String::new(),
                };
                return Ok(Response::builder()
                    .status(status)
                    .body(crate::l7::full_box(Bytes::from(body_str)))
                    .unwrap());
            }
        }
    }

    // 4. Process try_files
    for dir in directives {
        if let Directive::TryFiles(files) = dir {
            if let Some(root) = root_path.as_ref() {
                for candidate in files {
                    if candidate.starts_with('/') {
                        // Check if file exists on disk
                        if check_file_exists(root, candidate) {
                            let is_head = req.method() == Method::HEAD;
                            if let Some(resp) = serve_static_file(root, candidate, is_head, &[]).await {
                                return Ok(resp);
                            }
                        }
                    }
                }
                // Fallback to last try_files entry (e.g. rewrite to /index.html)
                if let Some(fallback) = files.last() {
                    if fallback.starts_with('/') {
                        let is_head = req.method() == Method::HEAD;
                        if let Some(resp) = serve_static_file(root, fallback, is_head, &[]).await {
                            return Ok(resp);
                        }
                    }
                }
            }
        }
    }

    // 5. Process static files if file_server is enabled
    let file_server_cfg = directives.iter().find_map(|d| match d {
        Directive::FileServer(cfg) => Some(cfg),
        _ => None,
    });

    if let (Some(root), Some(fs_cfg)) = (root_path.as_ref(), file_server_cfg) {
        let is_head = req.method() == Method::HEAD;
        if let Some(resp) = serve_static_file(root, &req_path, is_head, &fs_cfg.hide).await {
            return Ok(resp);
        }
    }

    // 6. Process reverse_proxy
    for dir in directives {
        if let Directive::ReverseProxy(cfg) = dir {
            return forward_request(req, cfg, peer_addr).await;
        }
    }

    // Default 404 Not Found
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(crate::l7::full_box(Bytes::from("404 Not Found")))
        .unwrap())
}

/// Applies configured response headers to an outgoing response.
fn apply_response_headers(
    resp: &mut Response<BoxBody<Bytes, hyper::Error>>,
    directives: &[Directive],
    matchers: &HashMap<String, &MatcherDef>,
    placeholder_ctx: &PlaceholderContext,
) {
    for dir in directives {
        if let Directive::ResponseHeader(cfg) = dir {
            let matched = match &cfg.matcher {
                Some(m) => evaluate_matcher_for_response(m, matchers, resp.headers()),
                None => true,
            };
            if matched {
                match &cfg.op {
                    HeaderOp::Set(k, v) => {
                        let expanded = replace_placeholders(v, placeholder_ctx).unwrap_or_else(|_| v.clone());
                        if let (Ok(name), Ok(val)) = (header::HeaderName::from_bytes(k.as_bytes()), header::HeaderValue::from_str(&expanded)) {
                            resp.headers_mut().insert(name, val);
                        }
                    }
                    HeaderOp::Add(k, v) => {
                        let expanded = replace_placeholders(v, placeholder_ctx).unwrap_or_else(|_| v.clone());
                        if let (Ok(name), Ok(val)) = (header::HeaderName::from_bytes(k.as_bytes()), header::HeaderValue::from_str(&expanded)) {
                            resp.headers_mut().append(name, val);
                        }
                    }
                    HeaderOp::Delete(k) => {
                        if let Ok(name) = header::HeaderName::from_bytes(k.as_bytes()) {
                            resp.headers_mut().remove(name);
                        }
                    }
                }
            }
        }
    }
}

/// Evaluates handle_errors block directives on 4xx/5xx status codes.
async fn execute_handle_errors(
    directives: &[Directive],
    status_code: u16,
    _matchers: &HashMap<String, &MatcherDef>,
    placeholder_ctx: &PlaceholderContext,
    root_path: Option<&Path>,
) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
    let err_ctx = placeholder_ctx.with_status_code(status_code);
    for dir in directives {
        match dir {
            Directive::Respond(cfg) => {
                let status = StatusCode::from_u16(cfg.status).unwrap_or(StatusCode::from_u16(status_code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
                let body_str = match &cfg.body {
                    Some(b) => replace_placeholders(b, &err_ctx).unwrap_or_else(|_| b.clone()),
                    None => format!("Error {}", status_code),
                };
                return Some(Response::builder()
                    .status(status)
                    .body(crate::l7::full_box(Bytes::from(body_str)))
                    .unwrap());
            }
            Directive::Rewrite(cfg) => {
                if let Some(root) = root_path {
                    let path = replace_placeholders(&cfg.target, &err_ctx).unwrap_or_else(|_| cfg.target.clone());
                    if let Some(resp) = serve_static_file(root, &path, false, &[]).await {
                        // Preserve the original error status code
                        let (mut parts, body) = resp.into_parts();
                        parts.status = StatusCode::from_u16(status_code).unwrap_or(parts.status);
                        return Some(Response::from_parts(parts, body));
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Evaluates a matcher reference (e.g. `@name` or `/path/*`) against an incoming request.
fn evaluate_matcher_ref<B>(
    matcher_str: &str,
    matchers: &HashMap<String, &MatcherDef>,
    req: &Request<B>,
    root: Option<&Path>,
) -> bool {
    if let Some(named) = matcher_str.strip_prefix('@') {
        if let Some(def) = matchers.get(named) {
            return evaluate_matcher_def(def, req, root);
        }
        warn!(matcher = %named, "named matcher referenced but not defined");
        return false;
    }

    // Path prefix matcher: `/api/*` or `/join`
    let path = req.uri().path();
    if matcher_str.ends_with('*') {
        path.starts_with(matcher_str.trim_end_matches('*'))
    } else {
        path == matcher_str || path.starts_with(matcher_str)
    }
}

/// Evaluates a named MatcherDef against a request.
fn evaluate_matcher_def<B>(
    def: &MatcherDef,
    req: &Request<B>,
    root: Option<&Path>,
) -> bool {
    // All rules within a matcher must match (AND semantics)
    for rule in &def.matchers {
        match rule {
            MatcherRule::Path(prefixes) => {
                let path = req.uri().path();
                let any_match = prefixes.iter().any(|p| {
                    if p.ends_with('*') {
                        path.starts_with(p.trim_end_matches('*'))
                    } else {
                        path == p
                    }
                });
                if !any_match {
                    return false;
                }
            }
            MatcherRule::PathRegexp(pattern) => {
                let path = req.uri().path();
                if let Ok(re) = regex_lite_match(pattern, path) {
                    if !re {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            MatcherRule::Method(methods) => {
                let req_method = req.method().as_str();
                if !methods.iter().any(|m| m.eq_ignore_ascii_case(req_method)) {
                    return false;
                }
            }
            MatcherRule::Header { name, value, negated } => {
                let header_val = req.headers().get(name).and_then(|v| v.to_str().ok());
                let matches = match (header_val, value) {
                    (Some(_), None) => true,
                    (Some(v), Some(expected)) => {
                        if expected == "*" {
                            true
                        } else {
                            v == expected
                        }
                    }
                    (None, _) => false,
                };
                if *negated && matches {
                    return false;
                }
                if !negated && !matches {
                    return false;
                }
            }
            MatcherRule::File => {
                if let Some(r) = root {
                    if !check_file_exists(r, req.uri().path()) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            MatcherRule::StatusExpr(_) => {
                // Status conditions apply only in handle_errors / response context
            }
        }
    }
    true
}

/// Evaluates matcher for response headers (e.g. `@matcher` checking headers).
fn evaluate_matcher_for_response(
    matcher_str: &str,
    matchers: &HashMap<String, &MatcherDef>,
    resp_headers: &HeaderMap,
) -> bool {
    if let Some(named) = matcher_str.strip_prefix('@') {
        if let Some(def) = matchers.get(named) {
            for rule in &def.matchers {
                if let MatcherRule::Header { name, value, negated } = rule {
                    let has_header = resp_headers.get(name).and_then(|v| v.to_str().ok());
                    let matches = match (has_header, value) {
                        (Some(_), None) => true,
                        (Some(v), Some(expected)) => expected == "*" || v == expected,
                        (None, _) => false,
                    };
                    if *negated && matches {
                        return false;
                    }
                    if !negated && !matches {
                        return false;
                    }
                }
            }
            return true;
        }
    }
    true
}

/// Evaluates simple regex patterns without pulling full heavyweight regex engine if simple.
fn regex_lite_match(pattern: &str, text: &str) -> Result<bool, ()> {
    // Check if pattern is a file extension match: e.g. \.(mp3|wav|ogg)$
    let clean = pattern.trim_start_matches('^').trim_end_matches('$');
    if clean.starts_with(r"\.(") && clean.ends_with(')') {
        let exts = &clean[3..clean.len() - 1];
        for ext in exts.split('|') {
            if text.ends_with(&format!(".{}", ext)) {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    // Fallback simple substring
    Ok(text.contains(clean))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caddyfile::parser::parse_caddyfile;
    use http_body_util::combinators::BoxBody;
    use http_body_util::{BodyExt, Empty};

    fn make_request(method: &str, uri: &str, headers: &[(&str, &str)]) -> Request<BoxBody<Bytes, hyper::Error>> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let empty_body = Empty::new().map_err(|never: std::convert::Infallible| match never {}).boxed();
        builder.body(empty_body).unwrap()
    }

    #[tokio::test]
    async fn test_dispatcher_request_body_limit_413() {
        let caddyfile = r#"
            example.com {
                request_body {
                    max_size 100
                }
                respond "OK" 200
            }
        "#;
        let sites = parse_caddyfile(caddyfile, None).unwrap();
        let site = &sites[0];
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // 150 bytes Content-Length > 100 limit => 413
        let req = make_request("POST", "/", &[("content-length", "150")]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // 50 bytes Content-Length <= 100 limit => 200
        let req = make_request("POST", "/", &[("content-length", "50")]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_dispatcher_handle_order_and_named_matchers() {
        let caddyfile = r#"
            example.com {
                @options method OPTIONS
                handle @options {
                    respond 204
                }

                handle /api/* {
                    respond "API endpoint: {path}" 200
                }

                handle {
                    respond "Fallback handler" 200
                }
            }
        "#;
        let sites = parse_caddyfile(caddyfile, None).unwrap();
        let site = &sites[0];
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // Test OPTIONS => 204
        let req = make_request("OPTIONS", "/api/users", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Test /api/users => "API endpoint: /api/users"
        let req = make_request("GET", "/api/users", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "API endpoint: /api/users");

        // Test catch-all fallback
        let req = make_request("GET", "/other", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "Fallback handler");
    }

    #[tokio::test]
    async fn test_dispatcher_handle_path_strip() {
        let caddyfile = r#"
            example.com {
                handle_path /v1/* {
                    respond "Path after strip: {path}" 200
                }
            }
        "#;
        let sites = parse_caddyfile(caddyfile, None).unwrap();
        let site = &sites[0];
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let req = make_request("GET", "/v1/items/123", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "Path after strip: /items/123");
    }

    #[tokio::test]
    async fn test_dispatcher_response_headers_and_placeholders() {
        let caddyfile = r#"
            example.com {
                header Access-Control-Allow-Origin *
                header X-Client-IP {client_ip}
                respond "Hello" 200
            }
        "#;
        let sites = parse_caddyfile(caddyfile, None).unwrap();
        let site = &sites[0];
        let peer: SocketAddr = "10.0.0.42:54321".parse().unwrap();

        let req = make_request("GET", "/", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("access-control-allow-origin").unwrap(), "*");
        assert_eq!(resp.headers().get("x-client-ip").unwrap(), "10.0.0.42");
    }

    #[tokio::test]
    async fn test_dispatcher_handle_errors() {
        let caddyfile = r#"
            example.com {
                handle_errors {
                    respond "Custom Error: {http.error.status_code}" 500
                }
                respond "Not Found" 404
            }
        "#;
        let sites = parse_caddyfile(caddyfile, None).unwrap();
        let site = &sites[0];
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let req = make_request("GET", "/nonexistent", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes, "Custom Error: 404");
    }

    #[tokio::test]
    async fn test_dispatcher_encode_gzip() {
        use std::io::Read;
        use flate2::read::GzDecoder;

        let caddyfile = r#"
            example.com {
                encode gzip
                header Content-Type "text/html; charset=utf-8"
                respond "<html><body>Hello Compressible World!</body></html>" 200
            }
        "#;
        let sites = parse_caddyfile(caddyfile, None).unwrap();
        let site = &sites[0];
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // 1. Client with Accept-Encoding: gzip receives compressed body
        let req = make_request("GET", "/", &[("accept-encoding", "gzip, deflate")]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("content-encoding").unwrap(), "gzip");

        let compressed_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let mut decoder = GzDecoder::new(&compressed_bytes[..]);
        let mut decompressed_str = String::new();
        decoder.read_to_string(&mut decompressed_str).unwrap();
        assert_eq!(decompressed_str, "<html><body>Hello Compressible World!</body></html>");

        // 2. Client without Accept-Encoding receives plain body
        let req = make_request("GET", "/", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!resp.headers().contains_key("content-encoding"));
        let plain_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(plain_bytes, "<html><body>Hello Compressible World!</body></html>");
    }
}
