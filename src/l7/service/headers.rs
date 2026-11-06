use super::*;
use super::matchers::evaluate_matcher_for_response;

/// Applies configured response headers to an outgoing response.
pub(super) fn apply_response_headers(
    resp: &mut Response<BoxBody<Bytes, hyper::Error>>,
    directives: &[Directive],
    matchers: &HashMap<String, &MatcherDef>,
    placeholder_ctx: &PlaceholderContext,
) {
    let status_code = resp.status().as_u16();
    for dir in directives {
        match dir {
            Directive::ResponseHeader(cfg) => {
                apply_single_response_header(resp, cfg, matchers, placeholder_ctx, status_code);
            }
            Directive::ResponseHeaders(configs) => {
                for cfg in configs {
                    apply_single_response_header(resp, cfg, matchers, placeholder_ctx, status_code);
                }
            }
            _ => {}
        }
    }
}

fn apply_single_response_header(
    resp: &mut Response<BoxBody<Bytes, hyper::Error>>,
    cfg: &crate::caddyfile::model::ResponseHeaderConfig,
    matchers: &HashMap<String, &MatcherDef>,
    placeholder_ctx: &PlaceholderContext,
    status_code: u16,
) {
    let matched = match &cfg.matcher {
        Some(m) => evaluate_matcher_for_response(m, matchers, resp.headers(), placeholder_ctx, status_code),
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
