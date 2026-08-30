//! Minimal std-only JSON value and parser for core crates (tokens, claims, control payloads).
//!
//! This is not a general serializer; adapters use `serde_json`. The parser enforces a nesting
//! depth budget and rejects control characters inside strings (RFC 8259).

use core::fmt;
use std::collections::BTreeMap;

/// Maximum nesting depth accepted by [`parse`].
pub const MAX_DEPTH: usize = 64;

/// JSON value with canonical (sorted) object keys.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// `null`
    Null,
    /// Boolean.
    Bool(bool),
    /// Integer that fits in `i64` and was written without fraction or exponent.
    Int(i64),
    /// Any other number.
    Float(f64),
    /// String.
    String(String),
    /// Array.
    Array(Vec<JsonValue>),
    /// Object.
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    /// Object member lookup.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            Self::Object(m) => m.get(key),
            _ => None,
        }
    }

    /// String content.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// Integer content.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Boolean content.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }
}

/// Parse error with byte offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    /// Byte offset.
    pub offset: usize,
    /// What was expected.
    pub expected: &'static str,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid JSON at byte {}: expected {}",
            self.offset, self.expected
        )
    }
}

impl std::error::Error for JsonError {}

struct Parser<'a> {
    src: &'a [u8],
    pos: usize,
}

/// Parses a complete JSON document.
pub fn parse(text: &str) -> Result<JsonValue, JsonError> {
    let mut p = Parser {
        src: text.as_bytes(),
        pos: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.pos != p.src.len() {
        return Err(p.err("end of input"));
    }
    Ok(v)
}

impl Parser<'_> {
    fn err(&self, expected: &'static str) -> JsonError {
        JsonError {
            offset: self.pos,
            expected,
        }
    }

    fn ws(&mut self) {
        while let Some(b) = self.src.get(self.pos) {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, b: u8, expected: &'static str) -> Result<(), JsonError> {
        if self.src.get(self.pos) == Some(&b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.err(expected))
        }
    }

    fn value(&mut self, depth: usize) -> Result<JsonValue, JsonError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting within the depth budget"));
        }
        match self.src.get(self.pos) {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b't') => self.literal("true", JsonValue::Bool(true)),
            Some(b'f') => self.literal("false", JsonValue::Bool(false)),
            Some(b'n') => self.literal("null", JsonValue::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.err("a value")),
        }
    }

    fn literal(&mut self, word: &'static str, v: JsonValue) -> Result<JsonValue, JsonError> {
        if self.src[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(v)
        } else {
            Err(self.err("a literal"))
        }
    }

    fn number(&mut self) -> Result<JsonValue, JsonError> {
        let start = self.pos;
        let mut is_int = true;
        if self.src.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while matches!(self.src.get(self.pos), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.pos == digits_start {
            return Err(self.err("a digit"));
        }
        // RFC 8259: no leading zeros ("01" is invalid, "0" and "0.5" are fine).
        if self.pos - digits_start > 1 && self.src[digits_start] == b'0' {
            return Err(JsonError {
                offset: digits_start,
                expected: "no leading zero",
            });
        }
        if self.src.get(self.pos) == Some(&b'.') {
            is_int = false;
            self.pos += 1;
            let s = self.pos;
            while matches!(self.src.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == s {
                return Err(self.err("fraction digits"));
            }
        }
        if matches!(self.src.get(self.pos), Some(b'e' | b'E')) {
            is_int = false;
            self.pos += 1;
            if matches!(self.src.get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let s = self.pos;
            while matches!(self.src.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == s {
                return Err(self.err("exponent digits"));
            }
        }
        let text =
            core::str::from_utf8(&self.src[start..self.pos]).map_err(|_| self.err("a number"))?;
        if is_int {
            if let Ok(i) = text.parse::<i64>() {
                return Ok(JsonValue::Int(i));
            }
        }
        text.parse::<f64>()
            .map(JsonValue::Float)
            .map_err(|_| self.err("a number"))
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let slice = self
            .src
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.err("4 hex digits"))?;
        let text = core::str::from_utf8(slice).map_err(|_| self.err("4 hex digits"))?;
        let v = u32::from_str_radix(text, 16).map_err(|_| self.err("4 hex digits"))?;
        self.pos += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.expect(b'"', "'\"'")?;
        let mut out = String::new();
        loop {
            let b = *self
                .src
                .get(self.pos)
                .ok_or_else(|| self.err("closing '\"'"))?;
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let e = *self.src.get(self.pos).ok_or_else(|| self.err("escape"))?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let c = if (0xD800..0xDC00).contains(&hi) {
                                if self.src.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                    return Err(self.err("low surrogate"));
                                }
                                self.pos += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err("low surrogate"));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            out.push(char::from_u32(c).ok_or_else(|| self.err("a scalar value"))?);
                        }
                        _ => return Err(self.err("a valid escape")),
                    }
                }
                0x00..=0x1F => return Err(self.err("no control characters in strings")),
                _ => {
                    // Copy one UTF-8 scalar.
                    let rest = core::str::from_utf8(&self.src[self.pos..])
                        .map_err(|_| self.err("valid UTF-8"))?;
                    let c = rest.chars().next().ok_or_else(|| self.err("a character"))?;
                    out.push(c);
                    self.pos += c.len_utf8();
                }
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<JsonValue, JsonError> {
        self.expect(b'[', "'['")?;
        let mut items = Vec::new();
        self.ws();
        if self.src.get(self.pos) == Some(&b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.src.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(self.err("',' or ']'")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<JsonValue, JsonError> {
        self.expect(b'{', "'{'")?;
        let mut entries = BTreeMap::new();
        self.ws();
        if self.src.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(entries));
        }
        loop {
            self.ws();
            let key = self.string()?;
            self.ws();
            self.expect(b':', "':'")?;
            self.ws();
            let value = self.value(depth + 1)?;
            entries.insert(key, value);
            self.ws();
            match self.src.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(entries));
                }
                _ => return Err(self.err("',' or '}'")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_documents_and_escapes() {
        let v =
            parse(r#"{"a":[1,2.5,-3,true,null,"x\u00e9\ud83d\ude00\n"],"b":{"c":{}}}"#).unwrap();
        assert_eq!(
            v.get("a").and_then(|a| match a {
                JsonValue::Array(items) => Some(items.len()),
                _ => None,
            }),
            Some(6)
        );
        match v.get("a") {
            Some(JsonValue::Array(items)) => {
                assert_eq!(items[0], JsonValue::Int(1));
                assert_eq!(items[1], JsonValue::Float(2.5));
                assert_eq!(items[5], JsonValue::String("x\u{e9}\u{1F600}\n".to_owned()));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":}",
            "\"\u{1}\"",
            "01",
            "1.",
            "tru",
            "{\"a\":1}x",
            "\"\\x\"",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
        assert!(parse(&deep).is_err());
    }
}
