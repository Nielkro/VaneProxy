use super::*;

/// Executes the core request handling pipeline within a set of directives.
pub(super) async fn execute_directive_pipeline<B>(
    mut req: Request<B>,
    directives: &[Directive],
    matchers: &HashMap<String, &MatcherDef>,
    peer_addr: SocketAddr,
    host_header: &str,
    site_root: Option<&Path>,
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

    // 2. Determine root path for static file lookups (local block root overrides site-level root)
    let root_path = directives
        .iter()
        .find_map(|d| match d {
            Directive::Root(p) => Some(PathBuf::from(p)),
            _ => None,
        })
        .or_else(|| site_root.map(PathBuf::from));

    let placeholder_ctx = PlaceholderContext::new(
        req.method().as_str(),
        &req_path,
        host_header,
        peer_addr,
        req.headers(),
    );

    // 3. Process redir directives within block
    for dir in directives {
        if let Directive::Redir(cfg) = dir {
            let matched = match &cfg.matcher {
                Some(m) => evaluate_matcher_ref(m, matchers, &req, root_path.as_deref()),
                None => true,
            };
            if matched {
                let status = StatusCode::from_u16(cfg.code).unwrap_or(StatusCode::FOUND);
                let target = replace_placeholders(&cfg.target, &placeholder_ctx).unwrap_or_else(|_| cfg.target.clone());
                return Ok(Response::builder()
                    .status(status)
                    .header(header::LOCATION, &target)
                    .header(header::CONTENT_LENGTH, "0")
                    .body(crate::l7::empty_box())
                    .unwrap());
            }
        }
    }

    // 4. Process respond directives
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
                    let resolved = replace_placeholders(candidate, &placeholder_ctx)
                        .unwrap_or_else(|_| candidate.clone());
                    if resolved.starts_with('/') {
                        // Check if file exists on disk
                        if check_file_exists(root, &resolved) {
                            if let Some(resp) = serve_static_file(root, &resolved, req.method(), req.headers(), &[]).await {
                                return Ok(resp);
                            }
                        }
                    }
                }
                // Fallback to last try_files entry (e.g. rewrite to /index.html)
                if let Some(fallback) = files.last() {
                    let resolved_fallback = replace_placeholders(fallback, &placeholder_ctx)
                        .unwrap_or_else(|_| fallback.clone());
                    if resolved_fallback.starts_with('/') {
                        if let Some(resp) = serve_static_file(root, &resolved_fallback, req.method(), req.headers(), &[]).await {
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
        if let Some(resp) = serve_static_file(root, &req_path, req.method(), req.headers(), &fs_cfg.hide).await {
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
