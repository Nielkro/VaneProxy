//! Caddyfile lexical analyzer with precise line/column tracking.

use thiserror::Error;

/// Error encountered during lexical analysis.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LexerError {
    #[error("unterminated quoted string starting at line {line}, column {col}")]
    UnterminatedString { line: usize, col: usize },
}

/// A lexical token with its position in source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// Token text content.
    pub text: String,
    /// Line number (1-indexed).
    pub line: usize,
    /// Column number (1-indexed).
    pub col: usize,
}

/// Tokenizes a Caddyfile string into tokens.
pub fn tokenize(input: &str) -> Result<Vec<Token>, LexerError> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    let mut line = 1;
    let mut col = 1;

    while let Some(&ch) = chars.peek() {
        // Handle line breaks
        if ch == '\n' {
            chars.next();
            line += 1;
            col = 1;
            continue;
        }

        // Handle whitespace
        if ch.is_whitespace() {
            chars.next();
            col += 1;
            continue;
        }

        // Handle comments: # or //
        if ch == '#' || (ch == '/' && chars.clone().nth(1) == Some('/')) {
            // Consume until newline
            while let Some(&c) = chars.peek() {
                if c == '\n' {
                    break;
                }
                chars.next();
                col += 1;
            }
            continue;
        }

        // Handle single character delimiters { and }
        if ch == '{' || ch == '}' {
            let token_col = col;
            chars.next();
            col += 1;
            tokens.push(Token {
                text: ch.to_string(),
                line,
                col: token_col,
            });
            continue;
        }

        // Handle quoted string
        if ch == '"' || ch == '\'' {
            let quote_char = ch;
            let start_line = line;
            let start_col = col;
            chars.next(); // consume opening quote
            col += 1;

            let mut string_buf = String::new();
            let mut closed = false;

            while let Some(c) = chars.next() {
                col += 1;
                if c == quote_char {
                    closed = true;
                    break;
                }
                if c == '\\' {
                    if let Some(escaped) = chars.next() {
                        col += 1;
                        match escaped {
                            'n' => string_buf.push('\n'),
                            't' => string_buf.push('\t'),
                            'r' => string_buf.push('\r'),
                            '\\' => string_buf.push('\\'),
                            '"' => string_buf.push('"'),
                            '\'' => string_buf.push('\''),
                            other => {
                                string_buf.push('\\');
                                string_buf.push(other);
                            }
                        }
                    } else {
                        return Err(LexerError::UnterminatedString {
                            line: start_line,
                            col: start_col,
                        });
                    }
                } else if c == '\n' {
                    line += 1;
                    col = 1;
                    string_buf.push('\n');
                } else {
                    string_buf.push(c);
                }
            }

            if !closed {
                return Err(LexerError::UnterminatedString {
                    line: start_line,
                    col: start_col,
                });
            }

            tokens.push(Token {
                text: string_buf,
                line: start_line,
                col: start_col,
            });
            continue;
        }

        // Handle bare token / identifier
        let start_col = col;
        let mut token_buf = String::new();

        while let Some(&c) = chars.peek() {
            if c.is_whitespace() || c == '{' || c == '}' || c == '#' {
                break;
            }
            if c == '/' && chars.clone().nth(1) == Some('/') {
                break;
            }
            token_buf.push(c);
            chars.next();
            col += 1;
        }

        tokens.push(Token {
            text: token_buf,
            line,
            col: start_col,
        });
    }

    Ok(tokens)
}
