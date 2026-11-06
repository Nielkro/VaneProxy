use super::*;
use super::matchers::evaluate_status_matcher;

/// Evaluates handle_errors block directives on 4xx/5xx status codes.
pub(super) async fn execute_handle_errors(
    directives: &[Directive],
    status_code: u16,
    matchers: &HashMap<String, &MatcherDef>,
    placeholder_ctx: &PlaceholderContext,
    site_root: Option<&Path>,
) -> Option<Response<BoxBody<Bytes, hyper::Error>>> {
    let err_ctx = placeholder_ctx.with_status_code(status_code);

    // If handle_errors has its own local `root`, it overrides site_root
    let effective_root = directives
        .iter()
        .find_map(|d| match d {
            Directive::Root(p) => Some(Path::new(p)),
            _ => None,
        })
        .or(site_root);

    for dir in directives {
        match dir {
            Directive::Respond(cfg) => {
                let matched = match &cfg.matcher {
                    Some(m) => evaluate_status_matcher(m, matchers, status_code),
                    None => true,
                };
                if !matched {
                    continue;
                }
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
                let matched = match &cfg.matcher {
                    Some(m) => evaluate_status_matcher(m, matchers, status_code),
                    None => true,
                };
                if !matched {
                    continue;
                }
                if let Some(root) = effective_root {
                    let path = replace_placeholders(&cfg.target, &err_ctx).unwrap_or_else(|_| cfg.target.clone());
                    let dummy_headers = hyper::HeaderMap::new();
                    if let Some(resp) = serve_static_file(root, &path, &Method::GET, &dummy_headers, &[]).await {
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
