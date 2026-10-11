//! Caddyfile string placeholder replacement engine.
//!
//! Replaces placeholders like `{host}`, `{client_ip}`, `{remote}`, `{method}`, `{path}`,
//! `{scheme}`, `{http.request.header.<name>}`, `{rp.header.<name>}`, `{http.error.status_code}`.

use std::net::SocketAddr;
use hyper::header::HeaderMap;

/// Context containing request and response metadata for placeholder expansion.
#[derive(Debug, Clone)]
pub struct PlaceholderContext {
    pub method: String,
    pub path: String,
    pub host: String,
    pub client_ip: String,
    pub remote: String,
    pub scheme: String,
    pub request_headers: HeaderMap,
    pub upstream_headers: Option<HeaderMap>,
    pub status_code: Option<u16>,
}

impl PlaceholderContext {
    /// Builds a placeholder context from request properties and peer address.
    pub fn new(
        method: &str,
        path: &str,
        host: &str,
        peer_addr: SocketAddr,
        request_headers: &HeaderMap,
    ) -> Self {
        let clean_host = host.split(':').next().unwrap_or(host).to_string();
        Self {
            method: method.to_string(),
            path: path.to_string(),
            host: clean_host,
            client_ip: peer_addr.ip().to_string(),
            remote: peer_addr.to_string(),
            scheme: "https".to_string(),
            request_headers: request_headers.clone(),
            upstream_headers: None,
            status_code: None,
        }
    }

    /// Extends context with upstream response headers (for `rp.header.*` expansions).
    pub fn with_upstream_headers(&self, headers: &HeaderMap) -> Self {
        let mut clone = self.clone();
        clone.upstream_headers = Some(headers.clone());
        clone
    }

    /// Extends context with response status code (for `http.error.status_code` expansions).
    pub fn with_status_code(&self, code: u16) -> Self {
        let mut clone = self.clone();
        clone.status_code = Some(code);
        clone
    }
}

/// Evaluates a string template replacing known `{placeholder}` tokens.
/// Unknown placeholders return an error to prevent passing raw templates upstream.
pub fn replace_placeholders(template: &str, ctx: &PlaceholderContext) -> Result<String, String> {
    if !template.contains('{') {
        return Ok(template.to_string());
    }

    let mut result = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '{' {
            let mut key = String::new();
            let mut closed = false;

            for next_c in chars.by_ref() {
                if next_c == '}' {
                    closed = true;
                    break;
                }
                key.push(next_c);
            }

            if !closed {
                return Err(format!("unclosed placeholder in template: '{template}'"));
            }

            let key_trimmed = key.trim();
            if let Some(val) = resolve_placeholder(key_trimmed, ctx)? {
                result.push_str(&val);
            }
        } else {
            result.push(c);
        }
    }

    Ok(result)
}

fn resolve_placeholder(key: &str, ctx: &PlaceholderContext) -> Result<Option<String>, String> {
    match key {
        "method" | "http.request.method" => Ok(Some(ctx.method.clone())),
        "path" | "uri" | "http.request.uri.path" => Ok(Some(ctx.path.clone())),
        "host" | "http.request.host" => Ok(Some(ctx.host.clone())),
        "client_ip" => Ok(Some(ctx.client_ip.clone())),
        "remote" | "client" => Ok(Some(ctx.remote.clone())),
        "scheme" | "http.request.scheme" => Ok(Some(ctx.scheme.clone())),
        "http.error.status_code" => {
            if let Some(code) = ctx.status_code {
                Ok(Some(code.to_string()))
            } else {
                Ok(Some(String::new()))
            }
        }
        _ if key.starts_with("http.request.header.") => {
            let header_name = &key["http.request.header.".len()..];
            let val = ctx
                .request_headers
                .get(header_name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            Ok(Some(val.to_string()))
        }
        _ if key.starts_with("rp.header.") => {
            let header_name = &key["rp.header.".len()..];
            let val = ctx
                .upstream_headers
                .as_ref()
                .and_then(|h| h.get(header_name))
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            Ok(Some(val.to_string()))
        }
        unknown => Err(format!("unknown placeholder '{{{unknown}}}'")),
    }
}

/// Validates placeholder syntax at parse time without runtime values.
pub fn validate_placeholders(template: &str) -> Result<(), String> {
    if !template.contains('{') {
        return Ok(());
    }

    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '{' {
            let mut key = String::new();
            let mut closed = false;

            for next_c in chars.by_ref() {
                if next_c == '}' {
                    closed = true;
                    break;
                }
                key.push(next_c);
            }

            if !closed {
                return Err(format!("unclosed placeholder in template: '{template}'"));
            }

            let key_trimmed = key.trim();
            match key_trimmed {
                "method"
                | "http.request.method"
                | "path"
                | "uri"
                | "http.request.uri.path"
                | "host"
                | "http.request.host"
                | "client_ip"
                | "remote"
                | "client"
                | "scheme"
                | "http.request.scheme"
                | "http.error.status_code" => {}
                _ if key_trimmed.starts_with("http.request.header.") => {}
                _ if key_trimmed.starts_with("rp.header.") => {}
                unknown => return Err(format!("unsupported placeholder '{{{unknown}}}'")),
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_placeholder_validation() {
        assert!(validate_placeholders("{host}").is_ok());
        assert!(validate_placeholders("prefix/{path}/suffix").is_ok());
        assert!(validate_placeholders("{http.request.header.X-Forwarded-For}").is_ok());
        assert!(validate_placeholders("{rp.header.X-Accel-Redirect}").is_ok());
        assert!(validate_placeholders("{unknown_foo}").is_err());
        assert!(validate_placeholders("unclosed_{host").is_err());
    }

    #[test]
    fn test_placeholder_replacement() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom-test", "HelloWorld".parse().unwrap());

        let peer: SocketAddr = "192.168.1.50:54321".parse().unwrap();
        let ctx = PlaceholderContext::new("GET", "/api/v1/feed", "slavchat.ru", peer, &headers);

        let replaced = replace_placeholders("Hello {host} from {client_ip} on {method} {path}!", &ctx).unwrap();
        assert_eq!(replaced, "Hello slavchat.ru from 192.168.1.50 on GET /api/v1/feed!");

        let custom_hdr = replace_placeholders("Header is {http.request.header.x-custom-test}", &ctx).unwrap();
        assert_eq!(custom_hdr, "Header is HelloWorld");
    }
}
