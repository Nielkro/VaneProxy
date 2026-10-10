//! HTTP request router dispatching directives within a SiteBlock.

use std::net::SocketAddr;
use std::path::PathBuf;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    header, Method, Request, Response, StatusCode, Uri,
};

use crate::caddyfile::model::{Directive, SiteBlock};
use crate::l7::proxy::forward_request;
use crate::l7::static_files::serve_static_file;

/// Handles an incoming HTTP request for a resolved site.
pub async fn handle_site_request(
    mut req: Request<hyper::body::Incoming>,
    site: &SiteBlock,
    peer_addr: SocketAddr,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let req_path = req.uri().path().to_string();

    // 1. Process redirects
    for dir in &site.directives {
        if let Directive::Redir(cfg) = dir {
            let matched = match &cfg.matcher {
                Some(m) if m.starts_with('/') => req_path.starts_with(m),
                _ => true,
            };
            if matched {
                let status = StatusCode::from_u16(cfg.code).unwrap_or(StatusCode::FOUND);
                return Ok(Response::builder()
                    .status(status)
                    .header(header::LOCATION, &cfg.target)
                    .body(Full::new(Bytes::from(format!("Redirecting to {}", cfg.target))).boxed())
                    .unwrap());
            }
        }
    }

    // 2. Process rewrites
    for dir in &site.directives {
        if let Directive::Rewrite(cfg) = dir {
            let matched = match &cfg.matcher {
                Some(m) if m.starts_with('/') => req_path.starts_with(m),
                _ => true,
            };
            if matched {
                if let Ok(new_uri) = cfg.target.parse::<Uri>() {
                    *req.uri_mut() = new_uri;
                }
            }
        }
    }

    // 3. Process static files if root and file_server are configured
    let root_path = site.directives.iter().find_map(|d| match d {
        Directive::Root(p) => Some(PathBuf::from(p)),
        _ => None,
    });

    let has_file_server = site.directives.iter().any(|d| matches!(d, Directive::FileServer(_)));

    if let (Some(root), true) = (root_path.as_ref(), has_file_server) {
        let is_head = req.method() == Method::HEAD;
        if let Some(resp) = serve_static_file(root, &req_path, is_head).await {
            let (parts, body) = resp.into_parts();
            return Ok(Response::from_parts(parts, body.boxed()));
        }
    }

    // 4. Process reverse_proxy
    for dir in &site.directives {
        if let Directive::ReverseProxy(cfg) = dir {
            if let Some(upstream) = cfg.upstreams.first() {
                return forward_request(
                    req,
                    upstream,
                    peer_addr,
                    &cfg.header_up,
                    &cfg.header_down,
                )
                .await;
            }
        }
    }

    // Default 404 Not Found
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from("404 Not Found")).boxed())
        .unwrap())
}
