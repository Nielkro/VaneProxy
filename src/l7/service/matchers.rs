use super::*;

/// Evaluates status code conditions in handle_errors matchers.
pub(super) fn evaluate_status_matcher(
    matcher_str: &str,
    matchers: &HashMap<String, &MatcherDef>,
    status_code: u16,
) -> bool {
    if let Some(named) = matcher_str.strip_prefix('@') {
        if let Some(def) = matchers.get(named) {
            for rule in &def.matchers {
                if let MatcherRule::StatusExpr(cond) = rule {
                    return match cond.op {
                        StatusOp::Eq => status_code == cond.code,
                        StatusOp::Neq => status_code != cond.code,
                        StatusOp::Gte => status_code >= cond.code,
                        StatusOp::Lte => status_code <= cond.code,
                        StatusOp::Gt => status_code > cond.code,
                        StatusOp::Lt => status_code < cond.code,
                    };
                }
            }
            return true;
        }
        warn!(matcher = %named, "named matcher referenced in handle_errors but not defined");
        return false;
    }
    true
}

/// Evaluates a matcher reference (e.g. `@name` or `/path/*`) against an incoming request.
pub(super) fn evaluate_matcher_ref<B>(
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
    evaluate_path_matcher(matcher_str, req.uri().path())
}

/// Evaluates a path matcher string (e.g. `/api/*`, `/static`) against a path.
fn evaluate_path_matcher(matcher_str: &str, path: &str) -> bool {
    if matcher_str == "*" {
        return true;
    }
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

/// Evaluates matcher for response headers against request context and response headers.
pub(super) fn evaluate_matcher_for_response(
    matcher_str: &str,
    matchers: &HashMap<String, &MatcherDef>,
    resp_headers: &HeaderMap,
    placeholder_ctx: &PlaceholderContext,
    status_code: u16,
) -> bool {
    let m = matcher_str.trim();
    if m == "*" {
        return true;
    }
    if m.starts_with('/') {
        return evaluate_path_matcher(m, &placeholder_ctx.path);
    }
    if let Some(named) = m.strip_prefix('@') {
        let Some(def) = matchers.get(named) else {
            warn!(matcher = %named, "named matcher not found for response header; rejecting");
            return false;
        };

        for rule in &def.matchers {
            match rule {
                MatcherRule::Path(prefixes) => {
                    let path = &placeholder_ctx.path;
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
                    let path = &placeholder_ctx.path;
                    if let Ok(re) = regex_lite_match(pattern, path) {
                        if !re {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                MatcherRule::Method(methods) => {
                    let req_method = &placeholder_ctx.method;
                    if !methods.iter().any(|m| m.eq_ignore_ascii_case(req_method)) {
                        return false;
                    }
                }
                MatcherRule::Header { name, value, negated } => {
                    // Check response header first; fall back to request header
                    let header_val = resp_headers
                        .get(name)
                        .or_else(|| placeholder_ctx.request_headers.get(name))
                        .and_then(|v| v.to_str().ok());
                    let matches = match (header_val, value) {
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
                MatcherRule::StatusExpr(cond) => {
                    let matches = match cond.op {
                        StatusOp::Eq => status_code == cond.code,
                        StatusOp::Neq => status_code != cond.code,
                        StatusOp::Gt => status_code > cond.code,
                        StatusOp::Gte => status_code >= cond.code,
                        StatusOp::Lt => status_code < cond.code,
                        StatusOp::Lte => status_code <= cond.code,
                    };
                    if !matches {
                        return false;
                    }
                }
                MatcherRule::File => {
                    warn!(matcher = %named, "file matcher rule is unsupported in response header context; rejecting");
                    return false;
                }
            }
        }
        return true;
    }

    warn!(matcher = %matcher_str, "unsupported matcher syntax for response header; rejecting");
    false
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

/// Recursively collects named matcher definitions from site-level and block directives.
pub(super) fn collect_named_matchers<'a>(
    directives: &'a [Directive],
    map: &mut HashMap<String, &'a MatcherDef>,
) {
    for dir in directives {
        match dir {
            Directive::Matcher(m) => {
                map.insert(m.name.clone(), m);
            }
            Directive::Handle(h) => {
                collect_named_matchers(&h.directives, map);
            }
            Directive::HandlePath(hp) => {
                collect_named_matchers(&hp.directives, map);
            }
            Directive::HandleErrors(errs) => {
                collect_named_matchers(errs, map);
            }
            _ => {}
        }
    }
}
