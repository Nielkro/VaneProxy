//! AST parser for Caddyfile tokens with fail-fast validation.

use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::caddyfile::lexer::{tokenize, LexerError, Token};
use crate::caddyfile::model::{
    Directive, FileServerConfig, HandleBlock, HandlePathBlock, HeaderOp, MatcherDef, MatcherRule,
    RedirConfig, RespondConfig, ResponseHeaderConfig, ReverseProxyConfig, RewriteConfig,
    SiteBlock, StatusCond, StatusOp, TlsUpstream, Upstream,
};
use crate::caddyfile::placeholders::validate_placeholders;

/// Parser error with detailed location information.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParserError {
    #[error("lexer error: {0}")]
    Lexer(#[from] LexerError),

    #[error("unexpected end of file: expected '{expected}'")]
    UnexpectedEof { expected: &'static str },

    #[error("unexpected token '{found}' at line {line}, column {col}: expected '{expected}'")]
    UnexpectedToken {
        found: String,
        expected: &'static str,
        line: usize,
        col: usize,
    },

    #[error("unknown directive '{directive}' at line {line}, column {col}")]
    UnknownDirective {
        directive: String,
        line: usize,
        col: usize,
    },

    #[error("missing required argument for directive '{directive}' at line {line}, column {col}")]
    MissingArgument {
        directive: String,
        line: usize,
        col: usize,
    },

    #[error("invalid status code '{found}' at line {line}, column {col}")]
    InvalidStatusCode {
        found: String,
        line: usize,
        col: usize,
    },

    #[error("invalid placeholder '{message}' at line {line}, column {col}")]
    InvalidPlaceholder {
        message: String,
        line: usize,
        col: usize,
    },

    #[error("insecure TLS upstream is only allowed for loopback addresses, but '{addr}' was configured at line {line}, column {col}")]
    InsecureTlsNotLoopback {
        addr: String,
        line: usize,
        col: usize,
    },
}

/// Parses an entire Caddyfile string into a list of `SiteBlock`s.
pub fn parse_caddyfile(input: &str, file_path: Option<&Path>) -> Result<Vec<SiteBlock>, ParserError> {
    let tokens = tokenize(input)?;
    let mut cursor = Cursor::new(&tokens);
    let mut sites = Vec::new();

    while !cursor.is_eof() {
        sites.push(parse_site_block(&mut cursor, file_path)?);
    }

    Ok(sites)
}

struct Cursor<'a> {
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(tokens: &'a [Token]) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&'a Token> {
        self.tokens.get(self.pos)
    }

    fn peek_nth(&self, n: usize) -> Option<&'a Token> {
        self.tokens.get(self.pos + n)
    }

    fn next(&mut self) -> Option<&'a Token> {
        let tok = self.tokens.get(self.pos);
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn expect(&mut self, expected: &'static str) -> Result<&'a Token, ParserError> {
        match self.next() {
            Some(tok) if tok.text == expected => Ok(tok),
            Some(tok) => Err(ParserError::UnexpectedToken {
                found: tok.text.clone(),
                expected,
                line: tok.line,
                col: tok.col,
            }),
            None => Err(ParserError::UnexpectedEof { expected }),
        }
    }
}

fn parse_site_block(cursor: &mut Cursor<'_>, file_path: Option<&Path>) -> Result<SiteBlock, ParserError> {
    let mut addresses = Vec::new();
    let start_line = cursor.peek().map(|t| t.line).unwrap_or(1);

    while let Some(tok) = cursor.peek() {
        if tok.text == "{" {
            cursor.next();
            break;
        }
        let addr_tok = cursor.next().unwrap();
        let clean = addr_tok.text.trim_end_matches(',').trim().to_string();
        if !clean.is_empty() {
            addresses.push(clean);
        }
    }

    if addresses.is_empty() {
        let line = cursor.peek().map(|t| t.line).unwrap_or(1);
        let col = cursor.peek().map(|t| t.col).unwrap_or(1);
        return Err(ParserError::MissingArgument {
            directive: "site address".to_string(),
            line,
            col,
        });
    }

    let mut directives = Vec::new();
    while let Some(tok) = cursor.peek() {
        if tok.text == "}" {
            cursor.next();
            break;
        }
        directives.push(parse_directive(cursor)?);
    }

    Ok(SiteBlock {
        addresses,
        directives,
        source_file: file_path.map(PathBuf::from),
        line: start_line,
    })
}

fn parse_directive(cursor: &mut Cursor<'_>) -> Result<Directive, ParserError> {
    let tok = cursor.next().ok_or(ParserError::UnexpectedEof {
        expected: "directive",
    })?;
    let dir_name = tok.text.as_str();
    let line = tok.line;
    let col = tok.col;

    // Check if directive is a named matcher definition (starts with '@')
    if let Some(matcher_name) = dir_name.strip_prefix('@') {
        let matcher_def = parse_named_matcher(cursor, matcher_name, line, col)?;
        return Ok(Directive::Matcher(matcher_def));
    }

    match dir_name {
        "reverse_proxy" => {
            let mut upstreams = Vec::new();
            let mut header_up = Vec::new();
            let mut header_down = Vec::new();
            let mut insecure_tls = false;
            let mut intercept_accel = false;
            let mut accel_prefix = "/static-internal".to_string();
            let mut accel_root = PathBuf::from(".");

            // Collect arguments until '{' or next directive / matcher
            while cursor.peek().is_some() {
                if is_arg_boundary(cursor) {
                    break;
                }
                let raw_arg = cursor.next().unwrap();
                upstreams.push(parse_upstream(&raw_arg.text, raw_arg.line, raw_arg.col)?);
            }

            // Check if there is a subblock '{'
            if let Some(sub) = cursor.peek() {
                if sub.text == "{" {
                    cursor.next(); // consume '{'
                    while let Some(sub_tok) = cursor.peek() {
                        if sub_tok.text == "}" {
                            cursor.next();
                            break;
                        }
                        let sub_name = cursor.next().unwrap().text.clone();
                        if let Some(m_name) = sub_name.strip_prefix('@') {
                            // Local matcher definition inside reverse_proxy (e.g. @accel header X-Accel-Redirect *)
                            let _ = parse_named_matcher(cursor, m_name, sub_tok.line, sub_tok.col)?;
                            continue;
                        }
                        match sub_name.as_str() {
                            "header_up" => header_up.push(parse_header_op(cursor, "header_up")?),
                            "header_down" => {
                                header_down.push(parse_header_op(cursor, "header_down")?)
                            }
                            "transport" => {
                                // transport http { tls_insecure_skip_verify }
                                let transport_proto = cursor.next().map(|t| t.text.clone()).unwrap_or_default();
                                if transport_proto != "http" {
                                    return Err(ParserError::UnknownDirective {
                                        directive: format!("transport {transport_proto}"),
                                        line: sub_tok.line,
                                        col: sub_tok.col,
                                    });
                                }
                                cursor.expect("{")?;
                                while let Some(opt_tok) = cursor.peek() {
                                    if opt_tok.text == "}" {
                                        cursor.next();
                                        break;
                                    }
                                    let opt = cursor.next().unwrap().text.clone();
                                    if opt == "tls_insecure_skip_verify" {
                                        insecure_tls = true;
                                    } else {
                                        return Err(ParserError::UnknownDirective {
                                            directive: opt,
                                            line: opt_tok.line,
                                            col: opt_tok.col,
                                        });
                                    }
                                }
                            }
                            "flush_interval" => {
                                // Ignore flush_interval with silent acceptance (SSE streams without buffer by default)
                                let _ = cursor.next();
                            }
                            "handle_response" => {
                                // handle_response [@matcher] { ... }
                                // Specifically supports: @accel { rewrite * {rp.header.X-Accel-Redirect} } or root / accel_prefix
                                let mut _resp_matcher = None;
                                if let Some(m_tok) = cursor.peek() {
                                    if m_tok.text.starts_with('@') {
                                        _resp_matcher = Some(cursor.next().unwrap().text.clone());
                                    }
                                }
                                cursor.expect("{")?;
                                intercept_accel = true;
                                while let Some(resp_tok) = cursor.peek() {
                                    if resp_tok.text == "}" {
                                        cursor.next();
                                        break;
                                    }
                                    let sub_d = cursor.next().unwrap().text.clone();
                                    match sub_d.as_str() {
                                        "root" => {
                                            let _ = cursor.peek().map(|t| if t.text == "*" { cursor.next(); });
                                            if let Some(r_tok) = cursor.next() {
                                                accel_root = PathBuf::from(r_tok.text.clone());
                                            }
                                        }
                                        "rewrite" => {
                                            // consume rewrite * {rp.header.X-Accel-Redirect} or target
                                            while let Some(t) = cursor.peek() {
                                                if t.text == "}" || is_directive_keyword(&t.text) {
                                                    break;
                                                }
                                                let rw_arg = cursor.next().unwrap().text.clone();
                                                if rw_arg.starts_with('/') {
                                                    accel_prefix = rw_arg;
                                                }
                                            }
                                        }
                                        _ => {
                                            // Skip any other inner directive tokens until end of line / block
                                            while let Some(t) = cursor.peek() {
                                                if t.text == "}" || is_directive_keyword(&t.text) {
                                                    break;
                                                }
                                                cursor.next();
                                            }
                                        }
                                    }
                                }
                            }
                            other => {
                                return Err(ParserError::UnknownDirective {
                                    directive: other.to_string(),
                                    line: sub_tok.line,
                                    col: sub_tok.col,
                                    });
                            }
                        }
                    }
                }
            }

            if upstreams.is_empty() {
                return Err(ParserError::MissingArgument {
                    directive: "reverse_proxy".to_string(),
                    line,
                    col,
                });
            }

            // Apply insecure_tls flag to any TLS upstreams and enforce loopback guard
            for up in &mut upstreams {
                if let Upstream::Tls(tls) = up {
                    if insecure_tls {
                        tls.insecure = true;
                    }
                    if tls.insecure && !is_loopback_addr(&tls.addr) {
                        return Err(ParserError::InsecureTlsNotLoopback {
                            addr: tls.addr.clone(),
                            line,
                            col,
                        });
                    }
                }
            }

            Ok(Directive::ReverseProxy(ReverseProxyConfig {
                upstreams,
                header_up,
                header_down,
                insecure_tls,
                intercept_accel,
                accel_prefix,
                accel_root,
            }))
        }

        "root" => {
            let arg1 = cursor.next().ok_or(ParserError::MissingArgument {
                directive: "root".to_string(),
                line,
                col,
            })?;
            let path = if arg1.text == "*" {
                let arg2 = cursor.next().ok_or(ParserError::MissingArgument {
                    directive: "root".to_string(),
                    line: arg1.line,
                    col: arg1.col,
                })?;
                arg2.text.clone()
            } else {
                arg1.text.clone()
            };
            Ok(Directive::Root(path))
        }

        "file_server" => {
            let mut browse = false;
            let mut hide = Vec::new();

            while cursor.peek().is_some() {
                if is_arg_boundary(cursor) {
                    break;
                }
                let token = cursor.next().unwrap();
                if token.text == "browse" {
                    browse = true;
                }
            }

            if let Some(sub) = cursor.peek() {
                if sub.text == "{" {
                    cursor.next(); // consume '{'
                    while let Some(sub_tok) = cursor.peek() {
                        if sub_tok.text == "}" {
                            cursor.next();
                            break;
                        }
                        let opt = cursor.next().unwrap().text.clone();
                        if opt == "hide" {
                            while cursor.peek().is_some() {
                                if is_arg_boundary(cursor) {
                                    break;
                                }
                                hide.push(cursor.next().unwrap().text.clone());
                            }
                        } else if opt == "browse" {
                            browse = true;
                        }
                    }
                }
            }

            Ok(Directive::FileServer(FileServerConfig { browse, hide }))
        }

        "try_files" => {
            let mut files = Vec::new();
            while cursor.peek().is_some() {
                if is_arg_boundary(cursor) {
                    break;
                }
                files.push(cursor.next().unwrap().text.clone());
            }
            if files.is_empty() {
                return Err(ParserError::MissingArgument {
                    directive: "try_files".to_string(),
                    line,
                    col,
                });
            }
            Ok(Directive::TryFiles(files))
        }

        "redir" => {
            let mut args = Vec::new();
            while cursor.peek().is_some() {
                if is_arg_boundary(cursor) {
                    break;
                }
                args.push(cursor.next().unwrap());
            }

            let config = match args.len() {
                1 => {
                    validate_placeholders(&args[0].text).map_err(|e| ParserError::InvalidPlaceholder {
                        message: e,
                        line: args[0].line,
                        col: args[0].col,
                    })?;
                    RedirConfig {
                        matcher: None,
                        target: args[0].text.clone(),
                        code: 302,
                    }
                }
                2 => {
                    if let Ok(code) = args[1].text.parse::<u16>() {
                        validate_placeholders(&args[0].text).map_err(|e| ParserError::InvalidPlaceholder {
                            message: e,
                            line: args[0].line,
                            col: args[0].col,
                        })?;
                        RedirConfig {
                            matcher: None,
                            target: args[0].text.clone(),
                            code,
                        }
                    } else {
                        validate_placeholders(&args[1].text).map_err(|e| ParserError::InvalidPlaceholder {
                            message: e,
                            line: args[1].line,
                            col: args[1].col,
                        })?;
                        RedirConfig {
                            matcher: Some(args[0].text.clone()),
                            target: args[1].text.clone(),
                            code: 302,
                        }
                    }
                }
                3 => {
                    let code = args[2]
                        .text
                        .parse::<u16>()
                        .map_err(|_| ParserError::InvalidStatusCode {
                            found: args[2].text.clone(),
                            line: args[2].line,
                            col: args[2].col,
                        })?;
                    validate_placeholders(&args[1].text).map_err(|e| ParserError::InvalidPlaceholder {
                        message: e,
                        line: args[1].line,
                        col: args[1].col,
                    })?;
                    RedirConfig {
                        matcher: Some(args[0].text.clone()),
                        target: args[1].text.clone(),
                        code,
                    }
                }
                _ => {
                    return Err(ParserError::MissingArgument {
                        directive: "redir".to_string(),
                        line,
                        col,
                    });
                }
            };
            Ok(Directive::Redir(config))
        }

        "rewrite" => {
            let mut args = Vec::new();
            while cursor.peek().is_some() {
                if is_arg_boundary(cursor) {
                    break;
                }
                args.push(cursor.next().unwrap().text.clone());
            }
            let config = match args.len() {
                1 => {
                    validate_placeholders(&args[0]).map_err(|e| ParserError::InvalidPlaceholder {
                        message: e,
                        line,
                        col,
                    })?;
                    RewriteConfig {
                        matcher: None,
                        target: args[0].clone(),
                    }
                }
                2 => {
                    validate_placeholders(&args[1]).map_err(|e| ParserError::InvalidPlaceholder {
                        message: e,
                        line,
                        col,
                    })?;
                    RewriteConfig {
                        matcher: Some(args[0].clone()),
                        target: args[1].clone(),
                    }
                }
                _ => {
                    return Err(ParserError::MissingArgument {
                        directive: "rewrite".to_string(),
                        line,
                        col,
                    });
                }
            };
            Ok(Directive::Rewrite(config))
        }

        "respond" => {
            // Syntax: respond [@matcher] [body] [status_code]
            let mut args = Vec::new();
            while cursor.peek().is_some() {
                if is_arg_boundary(cursor) {
                    break;
                }
                args.push(cursor.next().unwrap());
            }

            if args.is_empty() {
                return Err(ParserError::MissingArgument {
                    directive: "respond".to_string(),
                    line,
                    col,
                });
            }

            let mut matcher = None;
            let mut body = None;
            let mut status = 200;

            let mut idx = 0;
            if args[idx].text.starts_with('@') || args[idx].text.starts_with('/') {
                matcher = Some(args[idx].text.clone());
                idx += 1;
            }

            if idx < args.len() {
                if let Ok(code) = args[idx].text.parse::<u16>() {
                    status = code;
                } else {
                    body = Some(args[idx].text.clone());
                    validate_placeholders(&args[idx].text).map_err(|e| ParserError::InvalidPlaceholder {
                        message: e,
                        line: args[idx].line,
                        col: args[idx].col,
                    })?;
                    idx += 1;
                    if idx < args.len() {
                        status = args[idx].text.parse::<u16>().map_err(|_| ParserError::InvalidStatusCode {
                            found: args[idx].text.clone(),
                            line: args[idx].line,
                            col: args[idx].col,
                        })?;
                    }
                }
            }

            Ok(Directive::Respond(RespondConfig {
                matcher,
                body,
                status,
            }))
        }

        "header" => {
            // Syntax:
            //   Single: header [@matcher] [+|-]Header-Name [value]
            //   Block:  header [@matcher] {
            //               [+|-]Header-Name [value]
            //               ...
            //           }
            let mut matcher = None;
            if let Some(first) = cursor.peek() {
                if first.text.starts_with('@') {
                    matcher = Some(cursor.next().unwrap().text.clone());
                }
            }

            if let Some(tok) = cursor.peek() {
                if tok.text == "{" {
                    cursor.next(); // consume '{'
                    let mut configs = Vec::new();
                    while let Some(sub_tok) = cursor.peek() {
                        if sub_tok.text == "}" {
                            cursor.next();
                            break;
                        }
                        let op = parse_header_op(cursor, "header")?;
                        configs.push(ResponseHeaderConfig {
                            matcher: matcher.clone(),
                            op,
                        });
                    }
                    return Ok(Directive::ResponseHeaders(configs));
                }
            }

            let op = parse_header_op(cursor, "header")?;
            Ok(Directive::ResponseHeader(ResponseHeaderConfig { matcher, op }))
        }

        "uri" => {
            // Syntax: uri strip_prefix <prefix>
            let op_name = cursor.next().ok_or(ParserError::MissingArgument {
                directive: "uri".to_string(),
                line,
                col,
            })?;
            if op_name.text != "strip_prefix" {
                return Err(ParserError::UnknownDirective {
                    directive: format!("uri {}", op_name.text),
                    line: op_name.line,
                    col: op_name.col,
                });
            }
            let prefix = cursor.next().ok_or(ParserError::MissingArgument {
                directive: "uri strip_prefix".to_string(),
                line: op_name.line,
                col: op_name.col,
            })?;
            Ok(Directive::UriStripPrefix(prefix.text.clone()))
        }

        "handle" => {
            let mut matcher = None;
            if let Some(tok) = cursor.peek() {
                if tok.text != "{" {
                    matcher = Some(cursor.next().unwrap().text.clone());
                }
            }
            cursor.expect("{")?;
            let mut inner_directives = Vec::new();
            while let Some(tok) = cursor.peek() {
                if tok.text == "}" {
                    cursor.next();
                    break;
                }
                inner_directives.push(parse_directive(cursor)?);
            }
            Ok(Directive::Handle(HandleBlock {
                matcher,
                directives: inner_directives,
            }))
        }

        "handle_path" => {
            let prefix_tok = cursor.next().ok_or(ParserError::MissingArgument {
                directive: "handle_path".to_string(),
                line,
                col,
            })?;
            cursor.expect("{")?;
            let mut inner_directives = Vec::new();
            while let Some(tok) = cursor.peek() {
                if tok.text == "}" {
                    cursor.next();
                    break;
                }
                inner_directives.push(parse_directive(cursor)?);
            }
            Ok(Directive::HandlePath(HandlePathBlock {
                prefix: prefix_tok.text.clone(),
                directives: inner_directives,
            }))
        }

        "handle_errors" => {
            cursor.expect("{")?;
            let mut inner_directives = Vec::new();
            while let Some(tok) = cursor.peek() {
                if tok.text == "}" {
                    cursor.next();
                    break;
                }
                inner_directives.push(parse_directive(cursor)?);
            }
            Ok(Directive::HandleErrors(inner_directives))
        }

        "request_body" => {
            let mut max_bytes = 250 * 1024 * 1024; // default 250MB
            if let Some(next_tok) = cursor.peek() {
                if next_tok.text == "{" {
                    cursor.next(); // consume '{'
                    while let Some(tok) = cursor.peek() {
                        if tok.text == "}" {
                            cursor.next();
                            break;
                        }
                        let opt = cursor.next().unwrap().text.clone();
                        if opt == "max_size" {
                            let size_tok = cursor.next().ok_or(ParserError::MissingArgument {
                                directive: "request_body max_size".to_string(),
                                line,
                                col,
                            })?;
                            max_bytes = parse_byte_size(&size_tok.text).ok_or(ParserError::MissingArgument {
                                directive: format!("invalid size '{}'", size_tok.text),
                                line: size_tok.line,
                                col: size_tok.col,
                            })?;
                        }
                    }
                } else if next_tok.text == "max_size" {
                    cursor.next();
                    let size_tok = cursor.next().ok_or(ParserError::MissingArgument {
                        directive: "request_body max_size".to_string(),
                        line,
                        col,
                    })?;
                    max_bytes = parse_byte_size(&size_tok.text).ok_or(ParserError::MissingArgument {
                        directive: format!("invalid size '{}'", size_tok.text),
                        line: size_tok.line,
                        col: size_tok.col,
                    })?;
                }
            }
            Ok(Directive::RequestBodyLimit(max_bytes))
        }

        "header_up" => Ok(Directive::HeaderUp(parse_header_op(cursor, "header_up")?)),
        "header_down" => Ok(Directive::HeaderDown(parse_header_op(
            cursor,
            "header_down",
        )?)),
        "encode" => {
            let mut encodings = Vec::new();
            while cursor.peek().is_some() {
                if is_arg_boundary(cursor) {
                    break;
                }
                encodings.push(cursor.next().unwrap().text.clone());
            }
            if encodings.is_empty() {
                encodings.push("gzip".to_string());
            }
            Ok(Directive::Encode(encodings))
        }

        unknown => Err(ParserError::UnknownDirective {
            directive: unknown.to_string(),
            line,
            col,
        }),
    }
}

fn parse_named_matcher(
    cursor: &mut Cursor<'_>,
    name: &str,
    line: usize,
    col: usize,
) -> Result<MatcherDef, ParserError> {
    let mut rules = Vec::new();
    let next_tok = cursor.peek().ok_or(ParserError::MissingArgument {
        directive: format!("@{name}"),
        line,
        col,
    })?;

    if next_tok.text == "{" {
        cursor.next(); // consume '{'
        while let Some(tok) = cursor.peek() {
            if tok.text == "}" {
                cursor.next();
                break;
            }
            rules.push(parse_matcher_rule(cursor)?);
        }
    } else {
        // Inline matcher rule: `@name method OPTIONS` or `@name path /api/*`
        rules.push(parse_matcher_rule(cursor)?);
    }

    Ok(MatcherDef {
        name: name.to_string(),
        matchers: rules,
    })
}

fn parse_matcher_rule(cursor: &mut Cursor<'_>) -> Result<MatcherRule, ParserError> {
    let rule_tok = cursor.next().ok_or(ParserError::UnexpectedEof {
        expected: "matcher rule",
    })?;

    match rule_tok.text.as_str() {
        "path" => {
            let mut paths = Vec::new();
            while let Some(tok) = cursor.peek() {
                if is_arg_boundary(cursor) || is_matcher_keyword(&tok.text) {
                    break;
                }
                paths.push(cursor.next().unwrap().text.clone());
            }
            if paths.is_empty() {
                return Err(ParserError::MissingArgument {
                    directive: "path matcher".to_string(),
                    line: rule_tok.line,
                    col: rule_tok.col,
                });
            }
            Ok(MatcherRule::Path(paths))
        }
        "path_regexp" => {
            let regex_tok = cursor.next().ok_or(ParserError::MissingArgument {
                directive: "path_regexp".to_string(),
                line: rule_tok.line,
                col: rule_tok.col,
            })?;
            // If two args, e.g. `path_regexp my_name <regex>`, pick the last one
            let final_regex = if let Some(peek_tok) = cursor.peek() {
                if !peek_tok.text.starts_with('{') && !is_matcher_keyword(&peek_tok.text) && !is_arg_boundary(cursor) {
                    cursor.next().unwrap().text.clone()
                } else {
                    regex_tok.text.clone()
                }
            } else {
                regex_tok.text.clone()
            };
            Ok(MatcherRule::PathRegexp(final_regex))
        }
        "method" => {
            let mut methods = Vec::new();
            while let Some(tok) = cursor.peek() {
                if is_arg_boundary(cursor) || is_matcher_keyword(&tok.text) {
                    break;
                }
                methods.push(cursor.next().unwrap().text.clone());
            }
            if methods.is_empty() {
                return Err(ParserError::MissingArgument {
                    directive: "method matcher".to_string(),
                    line: rule_tok.line,
                    col: rule_tok.col,
                });
            }
            Ok(MatcherRule::Method(methods))
        }
        "header" => {
            let mut name_tok = cursor.next().ok_or(ParserError::MissingArgument {
                directive: "header matcher".to_string(),
                line: rule_tok.line,
                col: rule_tok.col,
            })?.text.clone();

            let negated = name_tok.starts_with('!');
            if negated {
                name_tok = name_tok[1..].to_string();
            }

            let mut val = None;
            if let Some(tok) = cursor.peek() {
                if !is_arg_boundary(cursor) && !is_matcher_keyword(&tok.text) {
                    val = Some(cursor.next().unwrap().text.clone());
                }
            }

            Ok(MatcherRule::Header {
                name: name_tok,
                value: val,
                negated,
            })
        }
        "file" => Ok(MatcherRule::File),
        "expression" => {
            // Status code expression parsing:
            //   expression {http.error.status_code} == 404
            //   expression {http.error.status_code} >= 500 && {http.error.status_code} < 600
            let mut expr_tokens = Vec::new();
            while let Some(tok) = cursor.peek() {
                if is_arg_boundary(cursor) || is_matcher_keyword(&tok.text) {
                    break;
                }
                expr_tokens.push(cursor.next().unwrap().text.clone());
            }

            if expr_tokens.is_empty() {
                return Err(ParserError::MissingArgument {
                    directive: "expression".to_string(),
                    line: rule_tok.line,
                    col: rule_tok.col,
                });
            }

            let full_expr = expr_tokens.join(" ");
            let (op, code) = parse_status_expression(&full_expr);
            Ok(MatcherRule::StatusExpr(StatusCond { op, code }))
        }
        other => Err(ParserError::UnknownDirective {
            directive: format!("matcher {other}"),
            line: rule_tok.line,
            col: rule_tok.col,
        }),
    }
}

fn parse_upstream(raw: &str, _line: usize, _col: usize) -> Result<Upstream, ParserError> {
    if let Some(https_target) = raw.strip_prefix("https://") {
        let (sni, port) = if let Some((host_part, port_part)) = https_target.split_once(':') {
            (host_part.to_string(), port_part.to_string())
        } else {
            (https_target.to_string(), "443".to_string())
        };

        let addr = format!("{sni}:{port}");
        Ok(Upstream::Tls(TlsUpstream {
            addr,
            sni,
            insecure: false,
        }))
    } else if let Some(path) = raw.strip_prefix("unix///") {
        Ok(Upstream::Unix(PathBuf::from(format!("/{}", path))))
    } else if let Some(path) = raw.strip_prefix("unix//") {
        Ok(Upstream::Unix(PathBuf::from(format!("/{}", path))))
    } else {
        Ok(Upstream::Tcp(raw.to_string()))
    }
}

fn parse_header_op(cursor: &mut Cursor<'_>, directive: &'static str) -> Result<HeaderOp, ParserError> {
    let name_tok = cursor.next().ok_or(ParserError::MissingArgument {
        directive: directive.to_string(),
        line: 0,
        col: 0,
    })?;

    let name = &name_tok.text;
    if let Some(to_delete) = name.strip_prefix('-') {
        return Ok(HeaderOp::Delete(to_delete.to_string()));
    }

    let val_tok = cursor.next().ok_or(ParserError::MissingArgument {
        directive: directive.to_string(),
        line: name_tok.line,
        col: name_tok.col,
    })?;

    validate_placeholders(&val_tok.text).map_err(|e| ParserError::InvalidPlaceholder {
        message: e,
        line: val_tok.line,
        col: val_tok.col,
    })?;

    if let Some(to_add) = name.strip_prefix('+') {
        Ok(HeaderOp::Add(to_add.to_string(), val_tok.text.clone()))
    } else {
        Ok(HeaderOp::Set(name.to_string(), val_tok.text.clone()))
    }
}

fn parse_status_expression(expr: &str) -> (StatusOp, u16) {
    let s = expr.trim();
    // Try to find comparison operator: ==, !=, >=, <=, >, <
    let (op, rest) = if let Some(idx) = s.find("==") {
        (StatusOp::Eq, &s[idx + 2..])
    } else if let Some(idx) = s.find("!=") {
        (StatusOp::Neq, &s[idx + 2..])
    } else if let Some(idx) = s.find(">=") {
        (StatusOp::Gte, &s[idx + 2..])
    } else if let Some(idx) = s.find("<=") {
        (StatusOp::Lte, &s[idx + 2..])
    } else if let Some(idx) = s.find('>') {
        (StatusOp::Gt, &s[idx + 1..])
    } else if let Some(idx) = s.find('<') {
        (StatusOp::Lt, &s[idx + 1..])
    } else {
        (StatusOp::Eq, s)
    };

    // Extract first numeric status code token from rest
    let code = rest
        .split_whitespace()
        .find_map(|tok| tok.trim_matches(|c: char| !c.is_ascii_digit()).parse::<u16>().ok())
        .unwrap_or(404);

    (op, code)
}

fn parse_byte_size(s: &str) -> Option<u64> {
    let s = s.trim().to_uppercase();
    if let Some(n) = s.strip_suffix("MB") {
        n.trim().parse::<u64>().ok().map(|v| v * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("KB") {
        n.trim().parse::<u64>().ok().map(|v| v * 1024)
    } else if let Some(n) = s.strip_suffix("GB") {
        n.trim().parse::<u64>().ok().map(|v| v * 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('M') {
        n.trim().parse::<u64>().ok().map(|v| v * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('K') {
        n.trim().parse::<u64>().ok().map(|v| v * 1024)
    } else {
        s.parse::<u64>().ok()
    }
}

fn is_loopback_addr(addr: &str) -> bool {
    let host = addr.split(':').next().unwrap_or(addr);
    host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host.starts_with("127.")
}

fn is_matcher_keyword(word: &str) -> bool {
    matches!(
        word,
        "path" | "path_regexp" | "method" | "header" | "file" | "expression"
    )
}

fn is_directive_keyword(word: &str) -> bool {
    matches!(
        word,
        "reverse_proxy"
            | "root"
            | "file_server"
            | "try_files"
            | "redir"
            | "rewrite"
            | "respond"
            | "header"
            | "uri"
            | "handle"
            | "handle_path"
            | "handle_errors"
            | "request_body"
            | "header_up"
            | "header_down"
            | "encode"
    )
}

fn is_matcher_definition(cursor: &Cursor<'_>) -> bool {
    if let Some(tok) = cursor.peek() {
        if tok.text.starts_with('@') && tok.text.len() > 1 {
            if let Some(next) = cursor.peek_nth(1) {
                return next.text == "{" || is_matcher_keyword(&next.text);
            }
        }
    }
    false
}

fn is_arg_boundary(cursor: &Cursor<'_>) -> bool {
    if let Some(tok) = cursor.peek() {
        if tok.text == "{" || tok.text == "}" || is_directive_keyword(&tok.text) || is_matcher_definition(cursor) {
            return true;
        }
    }
    false
}

