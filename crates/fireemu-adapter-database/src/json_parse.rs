//! A JSON parser for request bodies.
//!
//! It reads numbers exactly (an integer that fits an i64 stays an integer; any other number is
//! the correctly rounded double of its text) and records where every object key starts, so
//! a refused key can be reported by line and column as the official emulator reports it.

use std::collections::BTreeMap;

use fireemu_core_database::{Json, Number};

/// A body that is not one JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError;

/// An object key and where it starts: the 1-based line and column of its opening quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAt {
    /// The decoded key.
    pub key: String,
    /// The line.
    pub line: usize,
    /// The column, in characters.
    pub column: usize,
    /// How many objects and arrays enclose the key's object (0 for the outermost).
    pub depth: usize,
}

/// The deepest nesting read; deeper bodies are refused rather than exhausting the stack.
const MAX_NESTING: usize = 512;

/// Parses one JSON value and lists its object keys in document order.
pub fn parse_with_keys(text: &str) -> Result<(Json, Vec<KeyAt>), ParseError> {
    let mut parser = Parser::new(text, true);
    let value = parser.whole()?;
    Ok((value, parser.keys))
}

/// Parses one JSON value without recording key positions (the common path).
pub fn parse(text: &str) -> Result<Json, ParseError> {
    Parser::new(text, false).whole()
}

/// Parses the JSON value at the start of `text` (after whitespace) and returns it with the
/// byte index just after it.
pub fn parse_prefix(text: &str) -> Result<(Json, usize), ParseError> {
    let mut parser = Parser::new(text, false);
    parser.skip_whitespace();
    let value = parser.value(0)?;
    Ok((value, parser.at))
}

struct Parser<'a> {
    text: &'a str,
    at: usize,
    /// Whether to record where each key starts.
    record_keys: bool,
    keys: Vec<KeyAt>,
    /// The last position computed: byte index, line and column. Positions are asked for in
    /// increasing order, so each is computed from the previous one in linear total time.
    mark: (usize, usize, usize),
}

impl<'a> Parser<'a> {
    fn new(text: &'a str, record_keys: bool) -> Self {
        Self {
            text,
            at: 0,
            record_keys,
            keys: Vec::new(),
            mark: (0, 1, 1),
        }
    }

    fn whole(&mut self) -> Result<Json, ParseError> {
        self.skip_whitespace();
        let value = self.value(0)?;
        self.skip_whitespace();
        if self.at != self.text.len() {
            return Err(ParseError);
        }
        Ok(value)
    }

    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, literal: &str) -> Result<(), ParseError> {
        if self.text[self.at..].starts_with(literal) {
            self.at += literal.len();
            Ok(())
        } else {
            Err(ParseError)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, ParseError> {
        if depth > MAX_NESTING {
            return Err(ParseError);
        }
        match self.peek().ok_or(ParseError)? {
            b'n' => self.expect("null").map(|()| Json::Null),
            b't' => self.expect("true").map(|()| Json::Bool(true)),
            b'f' => self.expect("false").map(|()| Json::Bool(false)),
            b'"' => self.string().map(Json::String),
            b'[' => self.array(depth),
            b'{' => self.object(depth),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(ParseError),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.at += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(ParseError),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, ParseError> {
        self.at += 1;
        let mut map = BTreeMap::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(ParseError);
            }
            let position = self.record_keys.then(|| self.position());
            let key = self.string()?;
            if let Some((line, column)) = position {
                self.keys.push(KeyAt {
                    key: key.clone(),
                    line,
                    column,
                    depth,
                });
            }
            self.skip_whitespace();
            self.expect(":")?;
            self.skip_whitespace();
            let value = self.value(depth + 1)?;
            // A repeated key keeps its last value.
            map.insert(key, value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Object(map));
                }
                _ => return Err(ParseError),
            }
        }
    }

    fn position(&mut self) -> (usize, usize) {
        let (from, mut line, mut column) = self.mark;
        for c in self.text[from..self.at].chars() {
            if c == '\n' {
                line += 1;
                column = 1;
            } else {
                column += 1;
            }
        }
        self.mark = (self.at, line, column);
        (line, column)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let rest = &self.text[self.at..];
            let mut chars = rest.chars();
            let c = chars.next().ok_or(ParseError)?;
            self.at += c.len_utf8();
            match c {
                '"' => return Ok(out),
                '\\' => out.push(self.escape()?),
                '\u{0}'..='\u{1f}' => return Err(ParseError),
                c => out.push(c),
            }
        }
    }

    fn escape(&mut self) -> Result<char, ParseError> {
        let c = self.peek().ok_or(ParseError)?;
        self.at += 1;
        Ok(match c {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let first = self.hex4()?;
                if (0xD800..0xDC00).contains(&first) {
                    self.expect("\\u")?;
                    let second = self.hex4()?;
                    if !(0xDC00..0xE000).contains(&second) {
                        return Err(ParseError);
                    }
                    let code = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
                    char::from_u32(code).ok_or(ParseError)?
                } else {
                    char::from_u32(first).ok_or(ParseError)?
                }
            }
            _ => return Err(ParseError),
        })
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let digits = self.text.get(self.at..self.at + 4).ok_or(ParseError)?;
        if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ParseError);
        }
        self.at += 4;
        u32::from_str_radix(digits, 16).map_err(|_| ParseError)
    }

    fn number(&mut self) -> Result<Json, ParseError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(ParseError),
        }
        let mut integral = true;
        if self.peek() == Some(b'.') {
            integral = false;
            self.at += 1;
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(ParseError);
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            integral = false;
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(ParseError);
            }
            self.digits();
        }
        let text = &self.text[start..self.at];
        if integral {
            if let Ok(int) = text.parse::<i64>() {
                return Ok(Json::Number(Number::Int(int)));
            }
        }
        // Beyond the i64 range an integer is a double, as the server stores it. Beyond the
        // double range the official emulator stores the string "Infinity" or "-Infinity".
        let double: f64 = text.parse().map_err(|_| ParseError)?;
        Ok(match Number::from_f64(double) {
            Some(number) => Json::Number(number),
            None if double < 0.0 => Json::string("-Infinity"),
            None => Json::string("Infinity"),
        })
    }

    fn digits(&mut self) {
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.at += 1;
        }
    }
}
