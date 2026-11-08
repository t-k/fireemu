//! A JSON parser for request bodies.
//!
//! It reads numbers exactly (an integer that fits an i64 stays an integer; any other number is
//! the correctly rounded double of its text) and records where every object key starts, so
//! a refused key can be reported by line and column as the official emulator reports it.

use std::collections::BTreeMap;

use fireemu_core_database::node::{Assembly, Built};
use fireemu_core_database::{Json, Leaf, Limits, Node, Number};

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

/// How a lone surrogate escape (`"\ud83d"` without its pair) in a string is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lone {
    /// The text is refused.
    Refuse,
    /// In a string value, the character given (the official emulator stores `?`); a key is still refused.
    Replace(char),
    /// In any string, key or value, the character given (a copy of text made only to be checked).
    ReplaceAll(char),
    /// A WebSocket frame: `?` in a value, as the official emulator stores it, and [`INVALID`] in a key and in the
    /// path of the message (`d.b.p`). No key or path may hold that character (it is a control character, which
    /// every key and path check refuses), so a path or a key that held a lone surrogate never reads as any valid
    /// one, `.priority` included. A lone surrogate in the `authvar` of the message (`d.b.authvar`) is refused as the
    /// whole message was before this reading existed.
    Frame,
}

/// What a lone surrogate in a key or in the path of a frame is read as: a control character, which no key and no
/// path may hold, and which has no meaning of its own (the dot of `.priority` has one).
pub const INVALID: char = '\u{0}';

/// One step of the location of the value being read: an object member, or an array item.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Key(String),
    Index,
}

/// [`parse_with_keys`] for a body the emulator profile accepts as the official emulator does: a lone
/// surrogate escape in a string value (`"a\ud83d"`) is `with`, one for each lone unit, and the last
/// answer says whether any was. A key holding one is still refused.
pub fn parse_with_keys_replacing(
    text: &str,
    with: char,
) -> Result<(Json, Vec<KeyAt>, bool), ParseError> {
    let mut parser = Parser::new(text, true);
    parser.lone = Lone::Replace(with);
    let value = parser.whole()?;
    Ok((value, parser.keys, parser.replaced))
}

/// [`parse_with_keys_replacing`] for a WebSocket frame (see [`Lone::Frame`]).
pub fn parse_frame_with_keys(text: &str) -> Result<(Json, Vec<KeyAt>, bool), ParseError> {
    let mut parser = Parser::new(text, true);
    parser.lone = Lone::Frame;
    parser.track(3);
    let value = parser.whole()?;
    Ok((value, parser.keys, parser.replaced))
}

/// [`parse`] with a lone surrogate in a string value read as `with`, as [`parse_with_keys_replacing`] does.
pub fn parse_replacing(text: &str, with: char) -> Result<(Json, bool), ParseError> {
    let mut parser = Parser::new(text, false);
    parser.lone = Lone::Replace(with);
    let value = parser.whole()?;
    Ok((value, parser.replaced))
}

/// [`parse_replacing`] that reads a lone surrogate in a key as `with` too.
pub fn parse_replacing_all(text: &str, with: char) -> Result<(Json, bool), ParseError> {
    let mut parser = Parser::new(text, false);
    parser.lone = Lone::ReplaceAll(with);
    let value = parser.whole()?;
    Ok((value, parser.replaced))
}

/// [`parse_replacing`] for a WebSocket frame (see [`Lone::Frame`]).
pub fn parse_frame(text: &str) -> Result<(Json, bool), ParseError> {
    let mut parser = Parser::new(text, false);
    parser.lone = Lone::Frame;
    parser.track(3);
    let value = parser.whole()?;
    Ok((value, parser.replaced))
}

/// [`parse_prefix`] with a lone surrogate in a string value read as `with`.
pub fn parse_prefix_replacing(text: &str, with: char) -> Result<(Json, usize), ParseError> {
    let mut parser = Parser::new(text, false);
    parser.lone = Lone::Replace(with);
    parser.skip_whitespace();
    let value = parser.value(0)?;
    Ok((value, parser.at))
}

/// What [`parse_node`] made of a file.
#[derive(Debug, PartialEq)]
pub enum Read {
    /// The tree the file describes (none for a file that describes nothing).
    Tree(Option<Node>),
    /// A file to read the long way: with server values, or one the tree may refuse. Nothing is said of
    /// whether it parses.
    Declined,
}

/// Reads a file straight into the tree [`Node::from_json_owned`] builds from the parsed value (against
/// `limits`, at the root), so no parsed value is held next to the tree. A lone surrogate escape in a string
/// value is read as `lone_surrogate` where given and refuses the file otherwise (a key that holds one is
/// refused either way), as [`parse_replacing`] and [`parse`] read it.
///
/// A file that does not parse is an error, unless the file is declined first: the reading stops at the first
/// member it would not build the same way, and the caller reads the file again as a value.
pub fn parse_node(
    text: &str,
    limits: &Limits,
    lone_surrogate: Option<char>,
) -> Result<Read, ParseError> {
    let mut parser = Parser::new(text, false);
    if let Some(with) = lone_surrogate {
        parser.lone = Lone::Replace(with);
    }
    parser.skip_whitespace();
    let built = match parser.node(0, 0, limits) {
        Ok(built) => built,
        Err(Halt::Declined) => return Ok(Read::Declined),
        Err(Halt::Syntax) => return Err(ParseError),
    };
    parser.skip_whitespace();
    if parser.at != text.len() {
        return Err(ParseError);
    }
    Ok(Read::Tree(built.into_node()))
}

/// Why [`Parser::node`] stopped.
enum Halt {
    /// The text is not JSON.
    Syntax,
    /// The tree may not be built from what was read so far.
    Declined,
}

impl From<ParseError> for Halt {
    fn from(_: ParseError) -> Self {
        Self::Syntax
    }
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
    /// How a lone surrogate escape is read.
    lone: Lone,
    /// Whether one was.
    replaced: bool,
    /// The location of the value being read, as far as `track` keeps it, and the levels deeper than that.
    path: Vec<Step>,
    skipped: usize,
    limit: usize,
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
            lone: Lone::Refuse,
            replaced: false,
            path: Vec::new(),
            skipped: 0,
            limit: 0,
            keys: Vec::new(),
            mark: (0, 1, 1),
        }
    }

    /// Keeps the location of values down to `limit` levels.
    fn track(&mut self, limit: usize) {
        self.limit = limit;
    }

    fn enter(&mut self, step: impl FnOnce() -> Step) {
        if self.skipped > 0 || self.path.len() >= self.limit {
            self.skipped += 1;
        } else {
            self.path.push(step());
        }
    }

    fn leave(&mut self) {
        if self.skipped > 0 {
            self.skipped -= 1;
        } else {
            self.path.pop();
        }
    }

    /// Whether the value being read is the path of a frame (`d.b.p`).
    fn at_frame_path(&self) -> bool {
        self.skipped == 0
            && matches!(
                self.path.as_slice(),
                [Step::Key(d), Step::Key(b), Step::Key(p)] if d == "d" && b == "b" && p == "p"
            )
    }

    /// Whether the value or key being read is inside `d.b.authvar` of a frame.
    fn in_authvar(&self) -> bool {
        matches!(
            self.path.as_slice(),
            [Step::Key(d), Step::Key(b), Step::Key(a)] if d == "d" && b == "b" && a == "authvar"
        )
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
            b'"' => self.string(false).map(Json::String),
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
            self.enter(|| Step::Index);
            let item = self.value(depth + 1);
            self.leave();
            items.push(item?);
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
            let key = self.string(true)?;
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
            self.enter(|| Step::Key(key.clone()));
            let value = self.value(depth + 1);
            self.leave();
            let value = value?;
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

    /// [`Parser::value`] building the node of the value at `depth` keys below the root, whose path is
    /// `bytes` bytes long, as [`Node::from_json_owned`] would. The syntax it accepts is `value`'s.
    fn node(&mut self, depth: usize, bytes: usize, limits: &Limits) -> Result<Built, Halt> {
        // The tree holds even a `null` to the depth limit.
        if depth > limits.max_depth {
            return Err(Halt::Declined);
        }
        match self.peek().ok_or(Halt::Syntax)? {
            b'n' => self
                .expect("null")
                .map(|()| Built::null())
                .map_err(Halt::from),
            b't' => self
                .expect("true")
                .map_err(Halt::from)
                .and_then(|()| leaf(Leaf::Bool(true), limits)),
            b'f' => self
                .expect("false")
                .map_err(Halt::from)
                .and_then(|()| leaf(Leaf::Bool(false), limits)),
            b'"' => {
                let text = self.string(false)?;
                leaf(Leaf::String(text), limits)
            }
            b'[' => self.node_array(depth, bytes, limits),
            b'{' => self.node_object(depth, bytes, limits),
            b'-' | b'0'..=b'9' => match self.number()? {
                Json::Number(number) => leaf(Leaf::Number(number), limits),
                Json::String(text) => leaf(Leaf::String(text), limits),
                _ => Err(Halt::Syntax),
            },
            _ => Err(Halt::Syntax),
        }
    }

    fn node_array(&mut self, depth: usize, bytes: usize, limits: &Limits) -> Result<Built, Halt> {
        self.at += 1;
        let mut items = Assembly::array(depth, bytes);
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return items.finish().ok_or(Halt::Declined);
        }
        loop {
            self.skip_whitespace();
            let (item_depth, item_bytes) = items.item(limits).ok_or(Halt::Declined)?;
            let item = self.node(item_depth, item_bytes, limits)?;
            items.push(item);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return items.finish().ok_or(Halt::Declined);
                }
                _ => return Err(Halt::Syntax),
            }
        }
    }

    fn node_object(&mut self, depth: usize, bytes: usize, limits: &Limits) -> Result<Built, Halt> {
        self.at += 1;
        let mut members = Assembly::object(depth, bytes);
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return members.finish().ok_or(Halt::Declined);
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(Halt::Syntax);
            }
            let key = self.string(true)?;
            self.skip_whitespace();
            self.expect(":")?;
            self.skip_whitespace();
            let (member_depth, member_bytes) =
                members.member(&key, limits).ok_or(Halt::Declined)?;
            let value = self.node(member_depth, member_bytes, limits)?;
            // A repeated key keeps its last value.
            members.put(key, value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return members.finish().ok_or(Halt::Declined);
                }
                _ => return Err(Halt::Syntax),
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

    /// How a lone surrogate is read in a string: in a key or in a value.
    fn mode(&self, key: bool) -> Lone {
        match (self.lone, key) {
            (Lone::Frame, true) => Lone::ReplaceAll(INVALID),
            (Lone::ReplaceAll(_), _) | (_, false) => self.lone,
            (_, true) => Lone::Refuse,
        }
    }

    fn string(&mut self, key: bool) -> Result<String, ParseError> {
        let mode = self.mode(key);
        self.at += 1;
        let mut out = String::new();
        loop {
            let rest = &self.text[self.at..];
            let mut chars = rest.chars();
            let c = chars.next().ok_or(ParseError)?;
            self.at += c.len_utf8();
            let decoded = match c {
                '"' => {
                    return Ok(out);
                }
                '\\' => self.escape()?,
                '\u{0}'..='\u{1f}' => return Err(ParseError),
                c => Decoded::Char(c),
            };
            match decoded {
                Decoded::Char(c) => out.push(c),
                Decoded::Lone if self.lone == Lone::Frame && self.in_authvar() => {
                    return Err(ParseError)
                }
                Decoded::Lone => match mode {
                    Lone::Refuse => return Err(ParseError),
                    Lone::Replace(with) | Lone::ReplaceAll(with) => {
                        self.replaced = true;
                        out.push(with);
                    }
                    Lone::Frame => {
                        self.replaced = true;
                        out.push(if !key && self.at_frame_path() {
                            INVALID
                        } else {
                            '?'
                        });
                    }
                },
            }
        }
    }

    /// What an escape stands for.
    fn escape(&mut self) -> Result<Decoded, ParseError> {
        let c = self.peek().ok_or(ParseError)?;
        self.at += 1;
        let simple = |c: char| Ok(Decoded::Char(c));
        match c {
            b'"' => simple('"'),
            b'\\' => simple('\\'),
            b'/' => simple('/'),
            b'b' => simple('\u{8}'),
            b'f' => simple('\u{c}'),
            b'n' => simple('\n'),
            b'r' => simple('\r'),
            b't' => simple('\t'),
            b'u' => {
                let first = self.hex4()?;
                if (0xD800..0xDC00).contains(&first) {
                    let after_first = self.at;
                    let second = self
                        .expect("\\u")
                        .and_then(|()| self.hex4())
                        .ok()
                        .filter(|second| (0xDC00..0xE000).contains(second));
                    let Some(second) = second else {
                        // A high surrogate without its low one; what follows is read afresh.
                        self.at = after_first;
                        return Ok(Decoded::Lone);
                    };
                    let code = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
                    Ok(Decoded::Char(char::from_u32(code).ok_or(ParseError)?))
                } else if (0xDC00..0xE000).contains(&first) {
                    Ok(Decoded::Lone)
                } else {
                    Ok(Decoded::Char(char::from_u32(first).ok_or(ParseError)?))
                }
            }
            _ => Err(ParseError),
        }
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

fn leaf(leaf: Leaf, limits: &Limits) -> Result<Built, Halt> {
    Built::leaf(leaf, limits).ok_or(Halt::Declined)
}

/// What a character or an escape of a string stands for.
enum Decoded {
    Char(char),
    /// A surrogate unit with no partner.
    Lone,
}
