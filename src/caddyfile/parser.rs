//! AST parser for Caddyfile tokens with fail-fast validation.

use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::caddyfile::lexer::{tokenize, LexerError, Token};
use crate::caddyfile::model::{
    Directive, FileServerConfig, HandleBlock, HeaderOp, RedirConfig, ReverseProxyConfig,
    RewriteConfig, SiteBlock, Upstream,
};

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

fn parse_site_block(
    cursor: &mut Cursor<'_>,
    file_path: Option<&Path>,
) -> Result<SiteBlock, ParserError> {
    let mut addresses = Vec::new();
    let start_line = cursor.peek().map(|t| t.line).unwrap_or(1);

    // Consume addresses until we hit '{'
    while let Some(tok) = cursor.peek() {
        if tok.text == "{" {
            break;
        }
        let raw = cursor.next().unwrap();
        let cleaned = raw.text.trim_end_matches(',').trim();
        if !cleaned.is_empty() {
            addresses.push(cleaned.to_string());
        }
    }

    if addresses.is_empty() {
        return Err(match cursor.peek() {
            Some(t) => ParserError::UnexpectedToken {
                found: t.text.clone(),
                expected: "site address",
                line: t.line,
                col: t.col,
            },
            None => ParserError::UnexpectedEof {
                expected: "site address",
            },
        });
    }

    cursor.expect("{")?;

    let mut directives = Vec::new();
    while let Some(tok) = cursor.peek() {
        if tok.text == "}" {
            cursor.next(); // consume '}'
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

    match dir_name {
        "reverse_proxy" => {
            let mut upstreams = Vec::new();
            let mut header_up = Vec::new();
            let mut header_down = Vec::new();

            // Collect arguments until '{' or end of directive
            while let Some(arg) = cursor.peek() {
                if arg.text == "{" || arg.text == "}" || is_directive_keyword(&arg.text) {
                    break;
                }
                let raw_arg = cursor.next().unwrap();
                upstreams.push(parse_upstream(&raw_arg.text));
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
                        match sub_name.as_str() {
                            "header_up" => header_up.push(parse_header_op(cursor, "header_up")?),
                            "header_down" => {
                                header_down.push(parse_header_op(cursor, "header_down")?)
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

            Ok(Directive::ReverseProxy(ReverseProxyConfig {
                upstreams,
                header_up,
                header_down,
            }))
        }

        "root" => {
            let arg1 = cursor.next().ok_or(ParserError::MissingArgument {
                directive: "root".to_string(),
                line,
                col,
            })?;
            // If argument is matcher (e.g. `root * /path`)
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
            if let Some(arg) = cursor.peek() {
                if arg.text == "browse" {
                    cursor.next();
                    browse = true;
                }
            }
            Ok(Directive::FileServer(FileServerConfig { browse }))
        }

        "try_files" => {
            let mut files = Vec::new();
            while let Some(arg) = cursor.peek() {
                if arg.text == "{" || arg.text == "}" || is_directive_keyword(&arg.text) {
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
            while let Some(arg) = cursor.peek() {
                if arg.text == "{" || arg.text == "}" || is_directive_keyword(&arg.text) {
                    break;
                }
                args.push(cursor.next().unwrap());
            }

            let config = match args.len() {
                1 => RedirConfig {
                    matcher: None,
                    target: args[0].text.clone(),
                    code: 302,
                },
                2 => {
                    if let Ok(code) = args[1].text.parse::<u16>() {
                        RedirConfig {
                            matcher: None,
                            target: args[0].text.clone(),
                            code,
                        }
                    } else {
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
            while let Some(arg) = cursor.peek() {
                if arg.text == "{" || arg.text == "}" || is_directive_keyword(&arg.text) {
                    break;
                }
                args.push(cursor.next().unwrap().text.clone());
            }
            let config = match args.len() {
                1 => RewriteConfig {
                    matcher: None,
                    target: args[0].clone(),
                },
                2 => RewriteConfig {
                    matcher: Some(args[0].clone()),
                    target: args[1].clone(),
                },
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

        "header_up" => Ok(Directive::HeaderUp(parse_header_op(cursor, "header_up")?)),
        "header_down" => Ok(Directive::HeaderDown(parse_header_op(
            cursor,
            "header_down",
        )?)),

        unknown => Err(ParserError::UnknownDirective {
            directive: unknown.to_string(),
            line,
            col,
        }),
    }
}

fn parse_upstream(raw: &str) -> Upstream {
    // Standardize Caddy unix//path and URI unix:///path formats
    if let Some(path) = raw.strip_prefix("unix///") {
        Upstream::Unix(PathBuf::from(format!("/{}", path)))
    } else if let Some(path) = raw.strip_prefix("unix//") {
        Upstream::Unix(PathBuf::from(format!("/{}", path)))
    } else {
        Upstream::Tcp(raw.to_string())
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

    if let Some(to_add) = name.strip_prefix('+') {
        Ok(HeaderOp::Add(to_add.to_string(), val_tok.text.clone()))
    } else {
        Ok(HeaderOp::Set(name.to_string(), val_tok.text.clone()))
    }
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
            | "handle"
            | "header_up"
            | "header_down"
    )
}
