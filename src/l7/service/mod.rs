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

use crate::caddyfile::cluster::SiteIndex;
use crate::caddyfile::model::{
    Directive, HeaderOp, MatcherDef, MatcherRule, SiteBlock, StatusOp,
};
use crate::caddyfile::placeholders::{replace_placeholders, PlaceholderContext};
use crate::l7::proxy::forward_request;
use crate::l7::static_files::{check_file_exists, serve_static_file};

mod compress;
mod dispatch;
mod errors;
mod headers;
mod matchers;

use compress::maybe_compress_gzip;
use dispatch::execute_directive_pipeline;
use errors::execute_handle_errors;
use headers::apply_response_headers;
use matchers::{collect_named_matchers, evaluate_matcher_ref};

/// Extracts the Host or :authority header value from an incoming HTTP request.
pub fn extract_request_host<B>(req: &Request<B>) -> String {
    if let Some(host_val) = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()) {
        if !host_val.is_empty() {
            return host_val.to_string();
        }
    }
    if let Some(auth) = req.uri().authority() {
        return auth.as_str().to_string();
    }
    String::new()
}

/// Resolves the target SiteBlock for an incoming request based on its Host or :authority header.
///
/// Looks up matches against all configured site addresses:
/// 1. Exact matches (case-insensitive) take precedence.
/// 2. Wildcard pattern matches (via `matches_site_address`) are checked second.
/// 3. If no match is found, falls back to `default_site` (e.g. SNI site from TLS handshake).
pub fn resolve_site_for_request<'a>(
    sites: &'a [SiteBlock],
    index: &SiteIndex,
    host: &str,
    default_site: &'a SiteBlock,
) -> &'a SiteBlock {
    match index.lookup(host) {
        Some(idx) => sites.get(idx).unwrap_or(default_site),
        None => default_site,
    }
}

/// Handles an incoming HTTP request for a resolved site.
pub async fn handle_site_request<B>(
    mut req: Request<B>,
    site: &SiteBlock,
    peer_addr: SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error>
where
    B: hyper::body::Body<Data = Bytes, Error = hyper::Error> + Send + Unpin + 'static,
{
    // Collect named matchers defined at site level and inside blocks
    let mut matchers: HashMap<String, &MatcherDef> = HashMap::new();
    collect_named_matchers(&site.directives, &mut matchers);

    let start_instant = std::time::Instant::now();

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
    let host_header = extract_request_host(&req);

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
                    .header(header::CONTENT_LENGTH, "0")
                    .body(crate::l7::empty_box())
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
    let mut chosen_directives: Option<&[Directive]> = None;
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
                    chosen_directives = Some(&hb.directives);
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
                    chosen_directives = Some(&hp.directives);
                    break;
                }
            }
            _ => {}
        }
    }

    // Directives to execute for this request
    let active_directives: &[Directive] = chosen_directives.unwrap_or(&site.directives);

    // Execute the active block pipeline
    let mut resp = execute_directive_pipeline(req, active_directives, &matchers, peer_addr, &host_header, top_root.as_deref()).await?;

    // Apply response headers defined at site or block level
    let placeholder_ctx = initial_ctx.with_upstream_headers(resp.headers());

    apply_response_headers(&mut resp, &site.directives, &matchers, &placeholder_ctx);
    if active_directives != site.directives.as_slice() {
        apply_response_headers(&mut resp, active_directives, &matchers, &placeholder_ctx);
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

    let elapsed = start_instant.elapsed();
    let resp_status = resp.status().as_u16();
    let content_len = resp
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-");

    tracing::info!(
        method = %method_str,
        host = %host_header,
        path = %initial_path,
        status = resp_status,
        size = %content_len,
        duration_ms = elapsed.as_millis(),
        peer = %peer_addr,
        "L7 request completed"
    );

    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
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

        // Above the minimum compression threshold.
        let payload = "Hello Compressible World! ".repeat(100);
        let caddyfile = format!(
            r#"
            example.com {{
                encode gzip
                header Content-Type "text/html; charset=utf-8"
                respond "{payload}" 200
            }}
        "#
        );
        let sites = parse_caddyfile(&caddyfile, None).unwrap();
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
        assert_eq!(decompressed_str, payload);

        // 2. Client without Accept-Encoding receives plain body
        let req = make_request("GET", "/", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!resp.headers().contains_key("content-encoding"));
        let plain_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&plain_bytes[..], payload.as_bytes());
    }

    #[tokio::test]
    async fn test_dispatcher_header_block_and_expression() {
        let caddyfile = r#"
            example.com {
                header {
                    X-Frame-Options DENY
                    -Server
                    +X-Custom-Add "test"
                }

                @not_found {
                    expression {http.error.status_code} == 404
                }
                handle_errors {
                    respond @not_found "Not Found Page" 404
                    respond "Server Error Page" 500
                }

                respond "OK" 200
            }
        "#;
        let sites = parse_caddyfile(caddyfile, None).unwrap();
        let site = &sites[0];
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let req = make_request("GET", "/", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
        assert_eq!(resp.headers().get("x-custom-add").unwrap(), "test");
    }

    #[tokio::test]
    async fn test_dispatcher_handle_errors_status_matchers() {
        let caddyfile = r#"
            example.com {
                handle_errors {
                    @404 expression {http.error.status_code} == 404
                    respond @404 "Page Not Found Custom" 404
                    @5xx expression {http.error.status_code} >= 500 && {http.error.status_code} < 600
                    respond @5xx "Server Error Custom" 500
                    respond @nonexistent "Should Not Match" 503
                }

                respond @trigger_500 "fail" 502
                @trigger_500 path /fail
                respond "Not Found" 404
            }
        "#;
        let sites = parse_caddyfile(caddyfile, None).unwrap();
        let site = &sites[0];
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // 1. Request /fail triggers 502, handled by @5xx
        let req = make_request("GET", "/fail", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Server Error Custom");

        // 2. Request /any triggers 404, handled by @404
        let req = make_request("GET", "/any", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "Page Not Found Custom");
    }

    #[tokio::test]
    async fn test_dispatcher_redir_empty_body() {
        let caddyfile = r#"
            status.example.com {
                redir /status/slav 302
            }
        "#;
        let sites = parse_caddyfile(caddyfile, None).unwrap();
        let site = &sites[0];
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let req = make_request("GET", "/", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(resp.headers().get("location").unwrap(), "/status/slav");
        assert_eq!(resp.headers().get("content-length").unwrap(), "0");

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty(), "redirect response body must be empty (0 bytes)");
    }

    #[tokio::test]
    async fn test_dispatcher_try_files_with_placeholders() {
        let temp_dir = std::env::temp_dir().join(format!("vane_test_try_files_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let sw_file = temp_dir.join("sw.js");
        let index_file = temp_dir.join("index.html");
        std::fs::write(&sw_file, "console.log('service worker');").unwrap();
        std::fs::write(&index_file, "<html>SPA Fallback</html>").unwrap();

        let caddyfile = format!(
            r#"
            spa.example.com {{
                root * "{}"
                try_files {{path}} /index.html
                file_server
            }}
            "#,
            temp_dir.display()
        );

        let sites = parse_caddyfile(&caddyfile, None).unwrap();
        let site = &sites[0];
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // 1. Existing file /sw.js should be served directly
        let req = make_request("GET", "/sw.js", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "console.log('service worker');");

        // 2. Non-existent SPA route should fallback to /index.html
        let req = make_request("GET", "/dashboard/settings", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "<html>SPA Fallback</html>");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_resolve_site_for_request() {
        let caddyfile = r#"
            site-a.example.com {
                respond "Site A" 200
            }

            site-b.example.com, alt-b.example.com {
                respond "Site B" 200
            }

            *.example.org {
                respond "Wildcard Org" 200
            }

            exact.example.org {
                respond "Exact Org" 200
            }

            fallback.example.net {
                respond "Fallback" 200
            }
        "#;
        let sites = parse_caddyfile(caddyfile, None).unwrap();
        let index = SiteIndex::build(&sites);
        let fallback_site = sites.iter().find(|s| s.addresses.contains(&"fallback.example.net".to_string())).unwrap();

        // 1. Exact match on primary domain
        let resolved = resolve_site_for_request(&sites, &index, "site-a.example.com", fallback_site);
        assert_eq!(resolved.addresses, vec!["site-a.example.com"]);

        // 2. Exact match with port stripped
        let resolved = resolve_site_for_request(&sites, &index, "site-a.example.com:443", fallback_site);
        assert_eq!(resolved.addresses, vec!["site-a.example.com"]);

        // 3. Exact match on secondary domain
        let resolved = resolve_site_for_request(&sites, &index, "alt-b.example.com:8443", fallback_site);
        assert_eq!(resolved.addresses, vec!["site-b.example.com", "alt-b.example.com"]);

        // 4. Case-insensitive exact match
        let resolved = resolve_site_for_request(&sites, &index, "SITE-B.EXAMPLE.COM", fallback_site);
        assert_eq!(resolved.addresses, vec!["site-b.example.com", "alt-b.example.com"]);

        // 5. Precedence: exact match over wildcard match
        let resolved = resolve_site_for_request(&sites, &index, "exact.example.org", fallback_site);
        assert_eq!(resolved.addresses, vec!["exact.example.org"]);

        // 6. Wildcard match
        let resolved = resolve_site_for_request(&sites, &index, "other.example.org", fallback_site);
        assert_eq!(resolved.addresses, vec!["*.example.org"]);

        // 7. Unknown host falls back to default_site
        let resolved = resolve_site_for_request(&sites, &index, "unknown.example.com", fallback_site);
        assert_eq!(resolved.addresses, vec!["fallback.example.net"]);

        // 8. Empty host falls back to default_site
        let resolved = resolve_site_for_request(&sites, &index, "", fallback_site);
        assert_eq!(resolved.addresses, vec!["fallback.example.net"]);
    }

    #[tokio::test]
    async fn test_serve_l7_stream_multiplexed_coalescing() {
        use hyper_util::rt::TokioIo;
        use http_body_util::Empty;

        let caddyfile = r#"
            site-a.example.com {
                respond "I am Site A" 200
            }

            site-b.example.com {
                respond "I am Site B" 200
            }
        "#;
        let sites = parse_caddyfile(caddyfile, None).unwrap();
        let site_a = sites.iter().find(|s| s.addresses.contains(&"site-a.example.com".to_string())).unwrap().clone();
        let site_b = sites.iter().find(|s| s.addresses.contains(&"site-b.example.com".to_string())).unwrap().clone();

        let sites_vec = vec![site_a, site_b];
        let site_index = Arc::new(SiteIndex::build(&sites_vec));
        let sites_arc = Arc::new(sites_vec);
        let default_site_index = 0usize;

        let (client_io, server_io) = tokio::io::duplex(8192);
        let peer_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();

        tokio::spawn(crate::l7::serve_l7_stream(
            server_io,
            sites_arc,
            site_index,
            default_site_index,
            peer_addr,
        ));

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io)).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // 1. Request to site A over connection
        let req_a = Request::builder()
            .header("host", "site-a.example.com")
            .uri("/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp_a = sender.send_request(req_a).await.unwrap();
        assert_eq!(resp_a.status(), StatusCode::OK);
        let body_a = resp_a.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_a, "I am Site A");

        // 2. Request to site B over the SAME connection (coalescing)
        let req_b = Request::builder()
            .header("host", "site-b.example.com")
            .uri("/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp_b = sender.send_request(req_b).await.unwrap();
        assert_eq!(resp_b.status(), StatusCode::OK);
        let body_b = resp_b.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_b, "I am Site B");

        // 3. Subsequent request to site A over the SAME connection
        let req_a2 = Request::builder()
            .header("host", "site-a.example.com")
            .uri("/")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp_a2 = sender.send_request(req_a2).await.unwrap();
        assert_eq!(resp_a2.status(), StatusCode::OK);
        let body_a2 = resp_a2.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_a2, "I am Site A");
    }

    #[tokio::test]
    async fn test_response_header_matcher_path_and_revalidate() {
        let caddyfile = r#"
            example.com {
                @static {
                    path /assets/* /favicon.ico
                }
                @revalidate {
                    path /index.html
                }

                header @static Cache-Control "public, max-age=31536000, immutable"
                header @revalidate Cache-Control "no-cache"
                header /images/* X-Asset-Category "images"

                respond /assets/bundle.js "bundle content" 200
                respond /favicon.ico "icon content" 200
                respond /index.html "html content" 200
                respond /images/logo.png "logo content" 200
                respond /api/data "api content" 200
            }
        "#;
        let sites = parse_caddyfile(caddyfile, None).unwrap();
        let site = &sites[0];
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        // 1. /assets/bundle.js must match @static (immutable), NOT @revalidate (no-cache)
        let req = make_request("GET", "/assets/bundle.js", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "public, max-age=31536000, immutable"
        );

        // 2. /favicon.ico must match @static (immutable)
        let req = make_request("GET", "/favicon.ico", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "public, max-age=31536000, immutable"
        );

        // 3. /index.html must match @revalidate (no-cache), NOT @static
        let req = make_request("GET", "/index.html", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "no-cache"
        );

        // 4. /images/logo.png must match inline path matcher /images/*
        let req = make_request("GET", "/images/logo.png", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("x-asset-category").unwrap(),
            "images"
        );
        assert!(!resp.headers().contains_key("cache-control"));

        // 5. /api/data must match neither @static nor @revalidate
        let req = make_request("GET", "/api/data", &[]);
        let resp = handle_site_request(req, site, peer).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!resp.headers().contains_key("cache-control"));
        assert!(!resp.headers().contains_key("x-asset-category"));
    }
}
