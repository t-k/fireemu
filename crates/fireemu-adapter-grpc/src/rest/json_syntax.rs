//! The JSON grammar of production's REST front end (the protobuf `JsonStreamParser` that the
//! Extensible Service Proxy's transcoder runs over a request body), and its refusal texts.
//!
//! It is more lenient than RFC 8259: object keys may be bare words (`{structuredQuery: {}}`,
//! `{nullValue: 0}`, but not a reserved word alone), strings may be single-quoted, a comma may
//! trail the last member of an object or array, control characters may appear raw in a string,
//! `\v` is a vertical tab and any other escaped character stands for itself. These follow the
//! legacy parser whose refusal texts production answers with; the leniencies themselves are
//! unrecorded (follow-ups). Its refusals name what it expected and quote up to 20 bytes either side of where it
//! stopped, with a caret under that byte. It reads a body in two passes: the first stops without
//! an error where it would need more input (an unknown character, or a token that runs to the
//! end), and the second, "finishing", pass resumes from there and quotes only from that point
//! on. Recorded rows: FS-QUERY-INDEX request-shape/rest (`body-not-json`, `body-truncated`,
//! `body-trailing-comma`) and the production matrix row `errors/rest-shapes#not-json`.

use serde_json::{Map, Number, Value};

/// How many bytes of context the refusal quotes on each side of the failure.
const CONTEXT: usize = 20;
/// How deeply objects and arrays may nest.
const MAX_DEPTH: usize = 100;

/// The source order of the keys of each object of a body with two or more keys, by the object's
/// JSON pointer (RFC 6901). An object that repeats a key has no entry (its order is unknown).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyOrder(std::collections::BTreeMap<String, Vec<String>>);

impl KeyOrder {
    /// The keys of the object at `pointer` in source order, when it has two or more and none
    /// repeats.
    #[must_use]
    pub fn keys(&self, pointer: &str) -> Option<&[String]> {
        self.0.get(pointer).map(Vec::as_slice)
    }

    /// Every recorded object's keys in source order.
    pub fn objects(&self) -> impl Iterator<Item = &[String]> {
        self.0.values().map(Vec::as_slice)
    }

    /// The order of the objects under `from`, with their pointers moved under `to` (an object
    /// of a larger document seen as a body of its own).
    #[must_use]
    pub fn rebased(&self, from: &str, to: &str) -> Self {
        Self(
            self.0
                .iter()
                .filter_map(|(pointer, keys)| {
                    let rest = pointer.strip_prefix(from)?;
                    (rest.is_empty() || rest.starts_with('/'))
                        .then(|| (format!("{to}{rest}"), keys.clone()))
                })
                .collect(),
        )
    }
}

/// `key` as a JSON pointer segment (RFC 6901: `~` is `~0`, `/` is `~1`).
#[must_use]
pub fn pointer_segment(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// A body the parser refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxError {
    message: String,
    /// Byte offset of the failure, and where the quoted context may start.
    position: Option<(usize, usize)>,
}

impl SyntaxError {
    /// The refusal text, as production words it.
    #[must_use]
    pub fn render(&self, body: &[u8]) -> String {
        let Some((position, context_start)) = self.position else {
            return format!("Invalid JSON payload received. {}", self.message);
        };
        let begin = position.saturating_sub(CONTEXT).max(context_start);
        let end = position.saturating_add(CONTEXT).min(body.len());
        format!(
            "Invalid JSON payload received. {}\n{}\n{}^",
            self.message,
            String::from_utf8_lossy(&body[begin.min(end)..end]),
            " ".repeat(position - begin.min(position)),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Token {
    /// The end of the body, or a character no token starts with.
    Unknown,
    String,
    Number,
    True,
    False,
    Null,
    BeginObject,
    EndObject,
    BeginArray,
    EndArray,
    Colon,
    Comma,
    /// A bare word, which is a key and never a value.
    Key,
}

#[derive(Clone, Copy)]
enum Location {
    Root,
    Writes,
    Write(usize),
    Update(usize),
    Fields(usize),
    Other,
}

impl Location {
    fn member(self, key: &str) -> Self {
        match (self, key) {
            (Self::Root, "writes") => Self::Writes,
            (Self::Write(at), "update") => Self::Update(at),
            (Self::Update(at), "fields") => Self::Fields(at),
            _ => Self::Other,
        }
    }

    const fn element(self, at: usize) -> Self {
        match self {
            Self::Writes => Self::Write(at),
            _ => Self::Other,
        }
    }
}

struct Parser<'a> {
    body: &'a [u8],
    at: usize,
    /// Whether the first pass stopped; from then on nothing waits for more input.
    finishing: bool,
    /// Where the second pass started: its refusals quote from here on.
    leftover: usize,
    batch_field_order: Vec<Vec<String>>,
    /// The pointer of the value being read and the key order found so far, when the caller
    /// asked for the key order.
    key_order: Option<(String, KeyOrder)>,
}

const fn is_letter(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$'
}

const fn is_alphanumeric(byte: u8) -> bool {
    is_letter(byte) || byte.is_ascii_digit()
}

/// `ascii_isspace`: space, tab, newline, vertical tab, form feed and carriage return.
const fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

impl Parser<'_> {
    fn remaining(&self) -> &[u8] {
        &self.body[self.at..]
    }

    fn fail(&self, message: impl Into<String>, at: usize) -> SyntaxError {
        SyntaxError {
            message: message.into(),
            position: Some((at, if self.finishing { self.leftover } else { 0 })),
        }
    }

    /// The first pass stops here; the second resumes at the same place.
    fn stop_first_pass(&mut self, at: usize) {
        if !self.finishing {
            self.finishing = true;
            self.leftover = at;
        }
    }

    /// `ReportUnknown`: at the end of the body the message says so.
    fn unknown(&mut self, message: &str) -> SyntaxError {
        self.stop_first_pass(self.at);
        if self.at == self.body.len() {
            self.fail(format!("Unexpected end of string. {message}"), self.at)
        } else {
            self.fail(message, self.at)
        }
    }

    fn next_token(&mut self) -> Token {
        while self.at < self.body.len() && is_space(self.body[self.at]) {
            self.at += 1;
        }
        let rest = self.remaining();
        let Some(&first) = rest.first() else {
            return Token::Unknown;
        };
        match first {
            b'"' | b'\'' => Token::String,
            b'-' | b'0'..=b'9' => Token::Number,
            _ if rest.starts_with(b"true") => Token::True,
            _ if rest.starts_with(b"false") => Token::False,
            _ if rest.starts_with(b"null") => Token::Null,
            b'{' => Token::BeginObject,
            b'}' => Token::EndObject,
            b'[' => Token::BeginArray,
            b']' => Token::EndArray,
            b':' => Token::Colon,
            b',' => Token::Comma,
            _ if is_letter(first) => Token::Key,
            _ => Token::Unknown,
        }
    }

    fn value(&mut self, depth: usize, key: &str, location: Location) -> Result<Value, SyntaxError> {
        match self.next_token() {
            Token::Unknown => Err(self.unknown("Expected a value.")),
            Token::BeginObject | Token::BeginArray if depth >= MAX_DEPTH => Err(SyntaxError {
                message: format!(
                    "Message too deep. Max recursion depth reached for key '{}'",
                    super::transcode::echo(&key)
                ),
                position: None,
            }),
            Token::BeginObject => {
                self.at += 1;
                self.object(depth + 1, location)
            }
            Token::BeginArray => {
                self.at += 1;
                self.array(depth + 1, key, location)
            }
            Token::String => self.string().map(Value::String),
            Token::Number => self.number(),
            Token::True => {
                self.at += 4;
                Ok(Value::Bool(true))
            }
            Token::False => {
                self.at += 5;
                Ok(Value::Bool(false))
            }
            Token::Null => {
                self.at += 4;
                Ok(Value::Null)
            }
            Token::EndObject | Token::EndArray | Token::Colon | Token::Comma | Token::Key => {
                // A short tail might still become a keyword: the first pass waits for it.
                if self.remaining().len() < "false".len() {
                    self.stop_first_pass(self.at);
                }
                Err(self.fail("Unexpected token.", self.at))
            }
        }
    }

    fn object(&mut self, depth: usize, location: Location) -> Result<Value, SyntaxError> {
        if let Location::Fields(at) = location {
            if self.batch_field_order.len() <= at {
                self.batch_field_order.resize_with(at + 1, Vec::new);
            }
            self.batch_field_order[at].clear();
        }
        let mut out = Map::new();
        // The keys in source order, and whether one repeated.
        let mut keys: Vec<String> = Vec::new();
        let mut repeated = false;
        loop {
            let key = match self.next_token() {
                Token::Unknown => return Err(self.unknown("Expected an object key or }.")),
                // A comma may trail the last member.
                Token::EndObject => {
                    self.at += 1;
                    self.record_keys(keys, repeated);
                    return Ok(Value::Object(out));
                }
                Token::String => self.string()?,
                Token::Key => self.bare_key(),
                // A bare key may begin with a reserved word (`nullValue`); the word alone is
                // no key.
                Token::True | Token::False | Token::Null => {
                    let key = self.bare_key();
                    if matches!(key.as_str(), "true" | "false" | "null") {
                        return Err(self.fail("Expected an object key or }.", self.at));
                    }
                    key
                }
                _ => return Err(self.fail("Expected an object key or }.", self.at)),
            };
            match self.next_token() {
                Token::Unknown => return Err(self.unknown("Expected : between key:value pair.")),
                Token::Colon => self.at += 1,
                _ => return Err(self.fail("Expected : between key:value pair.", self.at)),
            }
            let value = self.member_value(depth, &key, location)?;
            if self.key_order.is_some() {
                if keys.contains(&key) {
                    repeated = true;
                } else {
                    keys.push(key.clone());
                }
            }
            if let Location::Fields(at) = location {
                let order = &mut self.batch_field_order[at];
                if !out.contains_key(&key) {
                    order.push(key.clone());
                }
            }
            out.insert(key, value);
            match self.next_token() {
                Token::Unknown => {
                    return Err(self.unknown("Expected , or } after key:value pair."));
                }
                Token::EndObject => {
                    self.at += 1;
                    self.record_keys(keys, repeated);
                    return Ok(Value::Object(out));
                }
                Token::Comma => self.at += 1,
                _ => return Err(self.fail("Expected , or } after key:value pair.", self.at)),
            }
        }
    }

    fn array(&mut self, depth: usize, key: &str, location: Location) -> Result<Value, SyntaxError> {
        if matches!(location, Location::Writes) {
            self.batch_field_order.clear();
        }
        let mut out = Vec::new();
        loop {
            match self.next_token() {
                Token::Unknown => {
                    return Err(self.unknown("Expected a value or ] within an array."));
                }
                // A comma may trail the last element.
                Token::EndArray => {
                    self.at += 1;
                    return Ok(Value::Array(out));
                }
                _ => {
                    let element = self.element_value(depth, key, location, out.len())?;
                    out.push(element);
                }
            }
            match self.next_token() {
                Token::Unknown => return Err(self.unknown("Expected , or ] after array value.")),
                Token::EndArray => {
                    self.at += 1;
                    return Ok(Value::Array(out));
                }
                Token::Comma => self.at += 1,
                _ => return Err(self.fail("Expected , or ] after array value.", self.at)),
            }
        }
    }

    /// Reads a member's value with its pointer pushed.
    fn member_value(
        &mut self,
        depth: usize,
        key: &str,
        location: Location,
    ) -> Result<Value, SyntaxError> {
        let len = self.push_pointer(&pointer_segment(key));
        let value = self.value(depth, key, location.member(key));
        self.pop_pointer(len);
        value
    }

    /// Reads an array element with its pointer pushed.
    fn element_value(
        &mut self,
        depth: usize,
        key: &str,
        location: Location,
        at: usize,
    ) -> Result<Value, SyntaxError> {
        let len = self.push_pointer(&at.to_string());
        let value = self.value(depth, key, location.element(at));
        self.pop_pointer(len);
        value
    }

    /// Appends a segment to the current pointer and returns its previous length.
    fn push_pointer(&mut self, segment: &str) -> usize {
        match &mut self.key_order {
            Some((pointer, _)) => {
                let len = pointer.len();
                pointer.push('/');
                pointer.push_str(segment);
                len
            }
            None => 0,
        }
    }

    fn pop_pointer(&mut self, len: usize) {
        if let Some((pointer, _)) = &mut self.key_order {
            pointer.truncate(len);
        }
    }

    /// Keeps the key order of the object just read, when it has two or more keys.
    fn record_keys(&mut self, keys: Vec<String>, repeated: bool) {
        if let Some((pointer, order)) = &mut self.key_order {
            if !repeated && keys.len() > 1 {
                order.0.insert(pointer.clone(), keys);
            }
        }
    }

    fn bare_key(&mut self) -> String {
        let start = self.at;
        while self.at < self.body.len() && is_alphanumeric(self.body[self.at]) {
            self.at += 1;
        }
        if self.at == self.body.len() {
            self.stop_first_pass(start);
        }
        // Letters, digits, `_` and `$` only.
        String::from_utf8_lossy(&self.body[start..self.at]).into_owned()
    }

    fn string(&mut self) -> Result<String, SyntaxError> {
        let start = self.at;
        let quote = self.body[start];
        let mut out: Vec<u8> = Vec::new();
        let mut i = start + 1;
        loop {
            let Some(&byte) = self.body.get(i) else {
                self.stop_first_pass(start);
                return Err(self.fail("Closing quote expected in string.", start));
            };
            if byte == quote {
                self.at = i + 1;
                break;
            }
            if byte != b'\\' {
                out.push(byte);
                i += 1;
                continue;
            }
            let Some(&escaped) = self.body.get(i + 1) else {
                self.stop_first_pass(start);
                return Err(self.fail("Closing quote expected in string.", start));
            };
            if escaped == b'u' {
                let (code, consumed) = self.unicode_escape(i, start)?;
                let mut buffer = [0u8; 4];
                out.extend_from_slice(code.encode_utf8(&mut buffer).as_bytes());
                i += consumed;
                continue;
            }
            out.push(match escaped {
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'v' => 0x0b,
                // Any other escaped character stands for itself (`\q` is `q`).
                other => other,
            });
            i += 2;
        }
        String::from_utf8(out).map_err(|_| SyntaxError {
            message: "Encountered non UTF-8 code points.".to_owned(),
            position: None,
        })
    }

    fn hex4(&self, at: usize) -> Option<u32> {
        let digits = std::str::from_utf8(self.body.get(at..at + 4)?).ok()?;
        match fireemu_core_types::codec::hex_decode(digits)?.as_slice() {
            [high, low] => Some((u32::from(*high) << 8) | u32::from(*low)),
            _ => None,
        }
    }

    /// The code point of the `\uXXXX` escape (a surrogate pair included) at `at`, and how many
    /// bytes it took.
    fn unicode_escape(&mut self, at: usize, start: usize) -> Result<(char, usize), SyntaxError> {
        if self.body.len() - at < 6 {
            self.stop_first_pass(start);
            return Err(self.fail("Illegal hex string.", at));
        }
        let Some(code) = self.hex4(at + 2) else {
            return Err(self.fail("Invalid escape sequence.", at));
        };
        if (0xD800..=0xDBFF).contains(&code) {
            if self.body.len() - at < 12 {
                self.stop_first_pass(start);
                return Err(self.fail("Missing low surrogate.", at));
            }
            if self.body[at + 6] != b'\\' || self.body[at + 7] != b'u' {
                return Err(self.fail("Missing low surrogate.", at));
            }
            let Some(low) = self.hex4(at + 8) else {
                return Err(self.fail("Invalid escape sequence.", at));
            };
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(self.fail("Invalid low surrogate.", at));
            }
            let combined = (((code & 0x3FF) << 10) | (low & 0x3FF)) + 0x1_0000;
            return char::from_u32(combined)
                .map(|c| (c, 12))
                .ok_or_else(|| self.fail("Invalid unicode code point.", at));
        }
        char::from_u32(code)
            .map(|c| (c, 6))
            .ok_or_else(|| self.fail("Invalid unicode code point.", at))
    }

    fn number(&mut self) -> Result<Value, SyntaxError> {
        let start = self.at;
        let mut end = start;
        let mut floating = false;
        while let Some(&byte) = self.body.get(end) {
            match byte {
                b'0'..=b'9' | b'+' | b'-' | b'x' => {}
                b'.' | b'e' | b'E' => floating = true,
                _ => break,
            }
            end += 1;
        }
        if end == self.body.len() {
            self.stop_first_pass(start);
        }
        let text = std::str::from_utf8(&self.body[start..end]).unwrap_or_default();
        let negative = text.starts_with('-');
        let octal = if negative {
            text.len() >= 3 && text.as_bytes()[1] == b'0'
        } else {
            text.len() >= 2 && text.as_bytes()[0] == b'0'
        };
        let parsed = if floating {
            self.double(text, start)?
        } else if octal {
            return Err(self.fail("Octal/hex numbers are not valid JSON values.", start));
        } else if negative {
            match text.parse::<i64>() {
                Ok(n) => Value::Number(n.into()),
                Err(_) => self.double(text, start)?,
            }
        } else {
            match text.parse::<u64>() {
                Ok(n) => Value::Number(n.into()),
                Err(_) => self.double(text, start)?,
            }
        };
        self.at = end;
        Ok(parsed)
    }

    fn double(&self, text: &str, start: usize) -> Result<Value, SyntaxError> {
        let value: f64 = text
            .parse()
            .map_err(|_| self.fail("Unable to parse number.", start))?;
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| self.fail("Number exceeds the range of double.", start))
    }
}

/// Parses a request body as production's front end does.
pub fn parse(body: &[u8]) -> Result<Value, SyntaxError> {
    parse_internal(body, false, false).map(|(value, _, _)| value)
}

/// Parses a request and retains the source order of top-level `BatchWrite` document fields.
pub fn parse_with_batch_field_order(body: &[u8]) -> Result<(Value, Vec<Vec<String>>), SyntaxError> {
    parse_internal(body, true, false).map(|(value, order, _)| (value, order))
}

/// Parses a request and retains the source order of the keys of every object (the wire order
/// of a pipeline's maps, which production's answers can depend on).
pub fn parse_with_key_order(body: &[u8]) -> Result<(Value, KeyOrder), SyntaxError> {
    parse_internal(body, false, true).map(|(value, _, order)| (value, order))
}

fn parse_internal(
    body: &[u8],
    collect_batch_order: bool,
    collect_key_order: bool,
) -> Result<(Value, Vec<Vec<String>>, KeyOrder), SyntaxError> {
    let mut parser = Parser {
        body,
        at: 0,
        finishing: false,
        leftover: 0,
        batch_field_order: Vec::new(),
        key_order: collect_key_order.then(|| (String::new(), KeyOrder::default())),
    };
    let location = if collect_batch_order {
        Location::Root
    } else {
        Location::Other
    };
    let value = parser.value(0, "", location)?;
    while parser.at < body.len() && is_space(body[parser.at]) {
        parser.at += 1;
    }
    if parser.at < body.len() {
        return Err(parser.fail("Parsing terminated before end of input.", parser.at));
    }
    let key_order = parser.key_order.map(|(_, order)| order).unwrap_or_default();
    Ok((value, parser.batch_field_order, key_order))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn key_order_names_each_object_of_two_or_more_keys_by_its_pointer() {
        let (body, order) = super::parse_with_key_order(
            br#"{"b": 1, "a": {"y/x": [{"z": 1, "~": 2}], "only": {"k": 1}}, c: 'x'}"#,
        )
        .unwrap();
        assert_eq!(
            body,
            super::parse(
                br#"{"b": 1, "a": {"y/x": [{"z": 1, "~": 2}], "only": {"k": 1}}, c: 'x'}"#
            )
            .unwrap()
        );
        assert_eq!(
            order.keys(""),
            Some(&["b".to_owned(), "a".to_owned(), "c".to_owned()][..])
        );
        assert_eq!(
            order.keys("/a"),
            Some(&["y/x".to_owned(), "only".to_owned()][..])
        );
        assert_eq!(
            order.keys("/a/y~1x/0"),
            Some(&["z".to_owned(), "~".to_owned()][..])
        );
        // One key has no order to keep.
        assert_eq!(order.keys("/a/only"), None);
        assert_eq!(
            order.rebased("/a", "/q").keys("/q/y~1x/0"),
            Some(&["z".to_owned(), "~".to_owned()][..])
        );
        assert_eq!(order.rebased("/a/y", "").keys(""), None);
    }

    #[test]
    fn a_repeated_key_leaves_its_object_without_an_order() {
        let (_, order) = super::parse_with_key_order(
            br#"{"m": {"a": 1, "b": 2, "a": 3}, "n": {"a": 1, "b": 2}}"#,
        )
        .unwrap();
        assert_eq!(order.keys("/m"), None);
        assert_eq!(
            order.keys("/n"),
            Some(&["a".to_owned(), "b".to_owned()][..])
        );
        assert_eq!(
            super::parse_with_batch_field_order(br#"{"a": 1, "b": 2}"#)
                .unwrap()
                .1,
            Vec::<Vec<String>>::new()
        );
    }

    proptest::proptest! {
        /// Keys come back in the order they were written, at any depth.
        #[test]
        fn key_order_is_the_written_order(keys in proptest::collection::vec("[a-z/~]{1,3}", 2..6)) {
            let mut unique = Vec::new();
            for key in keys {
                if !unique.contains(&key) {
                    unique.push(key);
                }
            }
            let members: Vec<String> = unique.iter().map(|k| format!("{}: {{\"x\": [1, {{\"p\": 1, \"q\": 2}}]}}", serde_json::to_string(k).unwrap())).collect();
            let text = format!("{{\"outer\": {{{}}}}}", members.join(", "));
            let (_, order) = super::parse_with_key_order(text.as_bytes()).unwrap();
            if unique.len() > 1 {
                proptest::prop_assert_eq!(order.keys("/outer"), Some(&unique[..]));
            } else {
                proptest::prop_assert_eq!(order.keys("/outer"), None);
            }
            for key in &unique {
                let pointer = format!("/outer/{}/x/1", super::pointer_segment(key));
                proptest::prop_assert_eq!(order.keys(&pointer), Some(&["p".to_owned(), "q".to_owned()][..]));
            }
        }
    }

    #[test]
    fn batch_field_order_uses_decoded_keys_and_last_duplicate_map() {
        let (body, order) = super::parse_with_batch_field_order(
            br"{writes:[{update:{fields:{old:{stringValue:'old'}},fields:{'\u007a':{stringValue:'z'},a:{stringValue:'a'},'\u007a':{stringValue:'last'}}}}]}",
        )
        .unwrap();
        assert_eq!(order, vec![vec!["z".to_owned(), "a".to_owned()]]);
        assert!(body["writes"][0]["update"]["fields"].get("old").is_none());
        assert_eq!(
            body["writes"][0]["update"]["fields"]["z"]["stringValue"],
            "last"
        );
    }

    use super::*;

    fn refusal(body: &str) -> String {
        parse(body.as_bytes()).unwrap_err().render(body.as_bytes())
    }

    #[test]
    fn recorded_refusals_are_worded_as_production_words_them() {
        // FS-QUERY-INDEX request-shape/rest#body-not-json.
        assert_eq!(
            refusal("not json"),
            "Invalid JSON payload received. Unexpected token.\nnot json\n^"
        );
        // Production matrix errors/rest-shapes#not-json: the bare word is a key.
        assert_eq!(
            refusal("{not json"),
            "Invalid JSON payload received. Expected : between key:value pair.\n{not json\n     ^"
        );
        // FS-QUERY-INDEX request-shape/rest#body-truncated.
        assert_eq!(
            refusal("{\"structuredQuery\":"),
            "Invalid JSON payload received. Unexpected end of string. Expected a value.\n\n^"
        );
    }

    #[test]
    fn the_lenient_grammar_is_accepted() {
        assert_eq!(
            parse(br#"{"a": [1, 2,], "b": {"c": 1,},}"#).unwrap(),
            json!({"a": [1, 2], "b": {"c": 1}})
        );
        assert_eq!(
            parse(
                b"{structuredQuery: {limit: 3}, nullValue: 'it\\'s', trueish: 1, $k_1: \"a\tb\"}"
            )
            .unwrap(),
            json!({"structuredQuery": {"limit": 3}, "nullValue": "it's", "trueish": 1, "$k_1": "a\tb"})
        );
        assert_eq!(parse(br#"["c\q", "\v"]"#).unwrap(), json!(["cq", "\u{b}"]));
        assert_eq!(
            parse(br#"["\u00e9\ud83d\ude00\n", -0, -12, 18446744073709551615, 1e2, 1.5]"#).unwrap(),
            json!([
                "\u{e9}\u{1f600}\n",
                0,
                -12,
                18_446_744_073_709_551_615_u64,
                100.0,
                1.5
            ])
        );
    }

    #[test]
    fn refusals_quote_twenty_bytes_either_side() {
        let body = format!("{{\"k\": {}, x}}", "1".repeat(40));
        assert_eq!(
            refusal(&body),
            format!(
                "Invalid JSON payload received. Expected : between key:value pair.\n{}, x}}\n{}^",
                "1".repeat(17),
                " ".repeat(20)
            )
        );
        // A refusal of the second pass quotes from where the first stopped.
        assert_eq!(
            refusal("[,]"),
            "Invalid JSON payload received. Unexpected token.\n,]\n^"
        );
        assert_eq!(
            refusal("{\"a\": #1}"),
            "Invalid JSON payload received. Expected a value.\n#1}\n^"
        );
        assert_eq!(
            refusal("[1"),
            "Invalid JSON payload received. Unexpected end of string. Expected , or ] after array value.\n1\n ^"
        );
        let long = format!("{{\"a\": \"{}", "x".repeat(10_000));
        assert_eq!(
            refusal(&long),
            format!(
                "Invalid JSON payload received. Closing quote expected in string.\n\"{}\n^",
                "x".repeat(19)
            )
        );
    }

    #[test]
    fn every_state_names_what_it_expected() {
        let cases = [
            ("{,}", "Expected an object key or }.\n{,}\n ^"),
            (
                "{true: 1}",
                "Expected an object key or }.\n{true: 1}\n     ^",
            ),
            (
                "{\"a\" 1}",
                "Expected : between key:value pair.\n{\"a\" 1}\n     ^",
            ),
            (
                "{\"a\": 1 2}",
                "Expected , or } after key:value pair.\n{\"a\": 1 2}\n        ^",
            ),
            ("[1 2]", "Expected , or ] after array value.\n[1 2]\n   ^"),
            (
                "{} x",
                "Parsing terminated before end of input.\n{} x\n   ^",
            ),
            (
                "[01]",
                "Octal/hex numbers are not valid JSON values.\n[01]\n ^",
            ),
            (
                "[-01]",
                "Octal/hex numbers are not valid JSON values.\n[-01]\n ^",
            ),
            ("[1-2]", "Unable to parse number.\n[1-2]\n ^"),
            (
                "[1e999]",
                "Number exceeds the range of double.\n[1e999]\n ^",
            ),
            (
                "[\"\\uzzzz\"]",
                "Invalid escape sequence.\n[\"\\uzzzz\"]\n  ^",
            ),
            (
                "[\"\\ud800x\"]",
                "Missing low surrogate.\n\"\\ud800x\"]\n ^",
            ),
            (
                "[\"\\udc00\"]",
                "Invalid unicode code point.\n[\"\\udc00\"]\n  ^",
            ),
            (
                "{",
                "Unexpected end of string. Expected an object key or }.\n\n^",
            ),
            (
                "{\"a\"",
                "Unexpected end of string. Expected : between key:value pair.\n\n^",
            ),
        ];
        for (body, expected) in cases {
            assert_eq!(
                refusal(body),
                format!("Invalid JSON payload received. {expected}"),
                "{body}"
            );
        }
    }

    #[test]
    fn nesting_and_encoding_are_bounded() {
        let deep = "[".repeat(MAX_DEPTH + 1);
        assert_eq!(
            refusal(&deep),
            "Invalid JSON payload received. Message too deep. Max recursion depth reached for key ''"
        );
        // The key a depth refusal names is echoed only in part.
        let key = "k".repeat(1 << 20);
        let body = format!("{}{{\"{key}\": [1]}}", "[".repeat(MAX_DEPTH - 1));
        assert!(refusal(&body).len() < 2048, "{}", refusal(&body).len());
        assert!(parse(&[b'[', b'"', 0xff, b'"', b']']).is_err());
        assert!(parse(&[b'[', b'"', 0xff, b'"', b',', b']']).is_err());
    }
}
