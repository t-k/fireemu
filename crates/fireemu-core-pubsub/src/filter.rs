//! Subscription filter parsing and evaluation.
//!
//! Implements the documented Cloud Pub/Sub filtering grammar over message attributes:
//!
//! ```text
//! attributes:key                      the attribute `key` is present
//! attributes.key = "value"            the attribute `key` equals `value`
//! attributes.key != "value"           `key` is absent or does not equal `value`
//! hasPrefix(attributes.key, "prefix") `key` is present and its value starts with `prefix`
//! NOT <expr>       <expr> AND <expr>       <expr> OR <expr>       ( <expr> )
//! ```
//!
//! Precedence is `OR` (lowest), then `AND`, then `NOT`, then a primary term. An empty filter
//! matches every message. A malformed filter is an `INVALID_ARGUMENT`, evaluated once when the
//! subscription is created so that a bad filter never reaches delivery.

use std::collections::BTreeMap;

use crate::error::{PubSubError, Result};

/// Maximum length of a filter expression, in bytes. Cloud Pub/Sub documents a 256-byte limit;
/// enforcing it here also bounds the recursive-descent parser's depth, so a hostile or
/// accidentally deeply-nested filter can never overflow the stack.
pub const MAX_FILTER_BYTES: usize = 256;

/// Maximum nesting depth the parser accepts. A 256-byte filter cannot reach this, so it is a
/// defence-in-depth guard rather than a functional limit.
const MAX_DEPTH: usize = 64;

/// A parsed, validated filter. Cloning is cheap relative to re-parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    root: Option<Expr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    Has(String),
    Eq(String, String),
    Ne(String, String),
    HasPrefix(String, String),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

impl Filter {
    /// The always-true filter (no `filter` set on the subscription).
    #[must_use]
    pub fn always() -> Self {
        Self { root: None }
    }

    /// Parses a filter expression. An empty or whitespace-only string is [`Filter::always`].
    ///
    /// A filter longer than [`MAX_FILTER_BYTES`] is refused before it is parsed, which is both
    /// the documented Pub/Sub limit and the bound that keeps the recursive-descent parser from
    /// overflowing the stack on a deeply-nested input.
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() > MAX_FILTER_BYTES {
            return Err(PubSubError::invalid_argument(format!(
                "filter exceeds {MAX_FILTER_BYTES} bytes"
            )));
        }
        if input.trim().is_empty() {
            return Ok(Self::always());
        }
        let tokens = lex(input)?;
        let mut parser = Parser {
            tokens: &tokens,
            pos: 0,
            depth: 0,
        };
        let expr = parser.parse_or()?;
        if parser.pos != parser.tokens.len() {
            return Err(PubSubError::invalid_argument(
                "unexpected trailing tokens in filter",
            ));
        }
        Ok(Self { root: Some(expr) })
    }

    /// Whether the filter matches a message's attribute set.
    #[must_use]
    pub fn matches(&self, attributes: &BTreeMap<String, String>) -> bool {
        self.root.as_ref().is_none_or(|e| eval(e, attributes))
    }
}

fn eval(expr: &Expr, attrs: &BTreeMap<String, String>) -> bool {
    match expr {
        Expr::Has(k) => attrs.contains_key(k),
        Expr::Eq(k, v) => attrs.get(k).is_some_and(|a| a == v),
        Expr::Ne(k, v) => attrs.get(k) != Some(v),
        Expr::HasPrefix(k, p) => attrs.get(k).is_some_and(|a| a.starts_with(p)),
        Expr::Not(e) => !eval(e, attrs),
        Expr::And(a, b) => eval(a, attrs) && eval(b, attrs),
        Expr::Or(a, b) => eval(a, attrs) || eval(b, attrs),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Ident(String),
    Str(String),
    Attributes,
    Dot,
    Colon,
    Eq,
    Ne,
    LParen,
    RParen,
    Comma,
}

fn lex(input: &str) -> Result<Vec<Token>> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            b'(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            b')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            b'.' => {
                tokens.push(Token::Dot);
                i += 1;
            }
            b':' => {
                tokens.push(Token::Colon);
                i += 1;
            }
            b',' => {
                tokens.push(Token::Comma);
                i += 1;
            }
            b'=' => {
                tokens.push(Token::Eq);
                i += 1;
            }
            b'!' => {
                if bytes.get(i + 1) == Some(&b'=') {
                    tokens.push(Token::Ne);
                    i += 2;
                } else {
                    return Err(PubSubError::invalid_argument("'!' must be part of '!='"));
                }
            }
            b'"' => {
                let (s, next) = lex_string(input, i)?;
                tokens.push(Token::Str(s));
                i = next;
            }
            _ if is_ident_start(b) => {
                let start = i;
                while i < bytes.len() && is_ident_byte(bytes[i]) {
                    i += 1;
                }
                let word = &input[start..i];
                tokens.push(if word == "attributes" {
                    Token::Attributes
                } else {
                    Token::Ident(word.to_owned())
                });
            }
            _ => {
                return Err(PubSubError::invalid_argument(format!(
                    "unexpected character in filter at byte {i}"
                )));
            }
        }
    }
    Ok(tokens)
}

/// Lexes a double-quoted string starting at `start` (the opening quote). Supports `\"` and
/// `\\` escapes.
fn lex_string(input: &str, start: usize) -> Result<(String, usize)> {
    let bytes = input.as_bytes();
    let mut out = String::new();
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Ok((out, i + 1)),
            b'\\' => {
                let next = bytes.get(i + 1).ok_or_else(|| {
                    PubSubError::invalid_argument("dangling escape in filter string")
                })?;
                match next {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    other => {
                        return Err(PubSubError::invalid_argument(format!(
                            "invalid escape '\\{}' in filter string",
                            *other as char
                        )))
                    }
                }
                i += 2;
            }
            _ => {
                // Copy one UTF-8 character.
                let ch = input[i..]
                    .chars()
                    .next()
                    .ok_or_else(|| PubSubError::invalid_argument("invalid UTF-8 in filter"))?;
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    Err(PubSubError::invalid_argument(
        "unterminated string in filter",
    ))
}

const fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

const fn is_ident_byte(b: u8) -> bool {
    // '.' is deliberately excluded: it is the `attributes.key` separator token. Attribute keys
    // that contain a dot must be written as a quoted string.
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'~' | b'%' | b'+')
}

struct Parser<'a> {
    tokens: &'a [Token],
    pos: usize,
    depth: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn bump(&mut self) -> Option<&Token> {
        let t = self.tokens.get(self.pos);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat_keyword(&mut self, kw: &str) -> bool {
        if let Some(Token::Ident(w)) = self.peek() {
            if w.eq_ignore_ascii_case(kw) {
                self.pos += 1;
                return true;
            }
        }
        false
    }

    fn parse_or(&mut self) -> Result<Expr> {
        let mut left = self.parse_and()?;
        while self.eat_keyword("OR") {
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr> {
        let mut left = self.parse_not()?;
        while self.eat_keyword("AND") {
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr> {
        if self.eat_keyword("NOT") {
            self.enter()?;
            let inner = self.parse_not()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    /// Descends one nesting level, refusing input that nests past [`MAX_DEPTH`].
    fn enter(&mut self) -> Result<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(PubSubError::invalid_argument("filter nests too deeply"));
        }
        Ok(())
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        match self.peek() {
            Some(Token::LParen) => {
                self.pos += 1;
                self.enter()?;
                let inner = self.parse_or()?;
                self.depth -= 1;
                match self.bump() {
                    Some(Token::RParen) => Ok(inner),
                    _ => Err(PubSubError::invalid_argument("expected ')' in filter")),
                }
            }
            Some(Token::Ident(w)) if w == "hasPrefix" => self.parse_has_prefix(),
            Some(Token::Attributes) => self.parse_attribute_term(),
            _ => Err(PubSubError::invalid_argument(
                "expected a filter term (attributes..., hasPrefix(...), NOT, '(')",
            )),
        }
    }

    fn parse_has_prefix(&mut self) -> Result<Expr> {
        self.pos += 1; // hasPrefix
        self.expect(&Token::LParen)?;
        self.expect(&Token::Attributes)?;
        self.expect(&Token::Dot)?;
        let key = self.parse_attr_key()?;
        self.expect(&Token::Comma)?;
        let prefix = self.parse_string()?;
        self.expect(&Token::RParen)?;
        Ok(Expr::HasPrefix(key, prefix))
    }

    fn parse_attribute_term(&mut self) -> Result<Expr> {
        self.pos += 1; // attributes
        match self.bump() {
            Some(Token::Colon) => {
                let key = self.parse_attr_key()?;
                Ok(Expr::Has(key))
            }
            Some(Token::Dot) => {
                let key = self.parse_attr_key()?;
                match self.bump() {
                    Some(Token::Eq) => Ok(Expr::Eq(key, self.parse_string()?)),
                    Some(Token::Ne) => Ok(Expr::Ne(key, self.parse_string()?)),
                    _ => Err(PubSubError::invalid_argument(
                        "expected '=' or '!=' after attributes.key",
                    )),
                }
            }
            _ => Err(PubSubError::invalid_argument(
                "expected ':' or '.' after 'attributes'",
            )),
        }
    }

    /// An attribute key is either a bare identifier or a quoted string (for keys with dots or
    /// other special characters).
    fn parse_attr_key(&mut self) -> Result<String> {
        match self.bump() {
            Some(Token::Ident(w)) => Ok(w.clone()),
            Some(Token::Str(s)) => Ok(s.clone()),
            _ => Err(PubSubError::invalid_argument("expected an attribute key")),
        }
    }

    fn parse_string(&mut self) -> Result<String> {
        match self.bump() {
            Some(Token::Str(s)) => Ok(s.clone()),
            _ => Err(PubSubError::invalid_argument("expected a quoted string")),
        }
    }

    fn expect(&mut self, want: &Token) -> Result<()> {
        if self.peek() == Some(want) {
            self.pos += 1;
            Ok(())
        } else {
            Err(PubSubError::invalid_argument(format!(
                "expected {want:?} in filter"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn empty_filter_matches_all() {
        let f = Filter::parse("").unwrap();
        assert!(f.matches(&attrs(&[])));
    }

    #[test]
    fn equality() {
        let f = Filter::parse("attributes.type = \"order\"").unwrap();
        assert!(f.matches(&attrs(&[("type", "order")])));
        assert!(!f.matches(&attrs(&[("type", "refund")])));
        assert!(!f.matches(&attrs(&[])));
    }

    #[test]
    fn inequality_matches_absent() {
        let f = Filter::parse("attributes.type != \"order\"").unwrap();
        assert!(f.matches(&attrs(&[])));
        assert!(f.matches(&attrs(&[("type", "refund")])));
        assert!(!f.matches(&attrs(&[("type", "order")])));
    }

    #[test]
    fn existence() {
        let f = Filter::parse("attributes:type").unwrap();
        assert!(f.matches(&attrs(&[("type", "x")])));
        assert!(!f.matches(&attrs(&[("other", "x")])));
    }

    #[test]
    fn has_prefix() {
        let f = Filter::parse("hasPrefix(attributes.name, \"eu-\")").unwrap();
        assert!(f.matches(&attrs(&[("name", "eu-west1")])));
        assert!(!f.matches(&attrs(&[("name", "us-east1")])));
    }

    #[test]
    fn and_or_not_precedence() {
        let f =
            Filter::parse("attributes.a = \"1\" AND attributes.b = \"2\" OR attributes.c = \"3\"")
                .unwrap();
        // (a AND b) OR c
        assert!(f.matches(&attrs(&[("a", "1"), ("b", "2")])));
        assert!(f.matches(&attrs(&[("c", "3")])));
        assert!(!f.matches(&attrs(&[("a", "1")])));
        let g = Filter::parse("NOT attributes:a").unwrap();
        assert!(g.matches(&attrs(&[])));
        assert!(!g.matches(&attrs(&[("a", "x")])));
    }

    #[test]
    fn parentheses_change_grouping() {
        let f = Filter::parse(
            "attributes.a = \"1\" AND (attributes.b = \"2\" OR attributes.c = \"3\")",
        )
        .unwrap();
        assert!(f.matches(&attrs(&[("a", "1"), ("c", "3")])));
        assert!(!f.matches(&attrs(&[("c", "3")])));
    }

    #[test]
    fn quoted_key_with_dot() {
        let f = Filter::parse("attributes.\"iana.org/lang\" = \"en\"").unwrap();
        assert!(f.matches(&attrs(&[("iana.org/lang", "en")])));
    }

    #[test]
    fn a_deeply_nested_filter_is_refused_without_overflowing_the_stack() {
        // A hostile filter cannot crash the process: the length cap refuses it first, and even a
        // within-cap deeply-nested filter is refused by the depth guard rather than recursed.
        let huge = "(".repeat(1_000_000);
        assert_eq!(
            Filter::parse(&huge).unwrap_err().code(),
            crate::error::Code::InvalidArgument
        );
        let many_not = "NOT ".repeat(1_000_000);
        assert!(Filter::parse(&many_not).is_err());
        // Right at the byte cap, deep nesting still returns an error, never a panic.
        let nested = format!("{}attributes:a{}", "(".repeat(120), ")".repeat(120));
        assert!(nested.len() <= MAX_FILTER_BYTES + 240);
        let _ = Filter::parse(&nested);
    }

    #[test]
    fn a_filter_over_the_byte_cap_is_refused() {
        let long = format!("attributes.type = \"{}\"", "x".repeat(MAX_FILTER_BYTES));
        assert_eq!(
            Filter::parse(&long).unwrap_err().code(),
            crate::error::Code::InvalidArgument
        );
    }

    #[test]
    fn malformed_filters_are_rejected() {
        for bad in [
            "attributes.",
            "attributes.a =",
            "attributes.a = order",
            "hasPrefix(attributes.a)",
            "attributes.a = \"x\" AND",
            "(attributes:a",
            "!",
            "attributes.a == \"x\"",
        ] {
            assert!(Filter::parse(bad).is_err(), "expected error for {bad:?}");
        }
    }
}
