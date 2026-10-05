//! A JSON reader that keeps the order of an object's members.
//!
//! `serde_json::Value` sorts the members of an object, and the strict Eventarc surface reports the
//! first problem it finds in the order the request wrote them (and the position of an attribute in its
//! map). Leaves are decoded by `serde_json`; this module only walks the structure, with a depth bound.

use serde_json::Number;

/// The deepest nesting accepted.
const MAX_DEPTH: usize = 64;

/// A parsed JSON value whose objects keep their members in the order they were written.
#[derive(Debug, Clone, PartialEq)]
pub enum Ordered {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number.
    Number(Number),
    /// A string, escapes decoded.
    String(String),
    /// An array.
    Array(Vec<Ordered>),
    /// An object, members in the order they were written.
    Object(Vec<(String, Ordered)>),
}

impl Ordered {
    /// The same value as a `serde_json::Value` (objects sorted by name, as `serde_json` keeps them).
    #[must_use]
    pub fn to_value(&self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(value) => serde_json::Value::Bool(*value),
            Self::Number(value) => serde_json::Value::Number(value.clone()),
            Self::String(value) => serde_json::Value::String(value.clone()),
            Self::Array(items) => {
                serde_json::Value::Array(items.iter().map(Self::to_value).collect())
            }
            Self::Object(members) => serde_json::Value::Object(
                members
                    .iter()
                    .map(|(name, value)| (name.clone(), value.to_value()))
                    .collect(),
            ),
        }
    }

    /// The members of an object.
    #[must_use]
    pub fn members(&self) -> Option<&[(String, Self)]> {
        match self {
            Self::Object(members) => Some(members),
            _ => None,
        }
    }
}

/// Parses one JSON document, or says why it is not one.
pub fn parse(bytes: &[u8]) -> Result<Ordered, String> {
    let mut reader = Reader { bytes, at: 0 };
    reader.skip_space();
    let value = reader.value(0)?;
    reader.skip_space();
    if reader.at != bytes.len() {
        return Err("unexpected trailing characters".to_owned());
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn skip_space(&mut self) {
        while matches!(self.bytes.get(self.at), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(format!("expected '{}'", char::from(byte)))
        }
    }

    fn literal(&mut self, text: &str, value: Ordered) -> Result<Ordered, String> {
        if self.bytes[self.at..].starts_with(text.as_bytes()) {
            self.at += text.len();
            Ok(value)
        } else {
            Err("unexpected token".to_owned())
        }
    }

    fn value(&mut self, depth: usize) -> Result<Ordered, String> {
        if depth > MAX_DEPTH {
            return Err("nesting is too deep".to_owned());
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Ordered::String),
            Some(b't') => self.literal("true", Ordered::Bool(true)),
            Some(b'f') => self.literal("false", Ordered::Bool(false)),
            Some(b'n') => self.literal("null", Ordered::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err("unexpected token".to_owned()),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Ordered, String> {
        self.expect(b'{')?;
        let mut members = Vec::new();
        self.skip_space();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Ordered::Object(members));
        }
        loop {
            self.skip_space();
            let name = self.string()?;
            self.skip_space();
            self.expect(b':')?;
            self.skip_space();
            members.push((name, self.value(depth + 1)?));
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Ordered::Object(members));
                }
                _ => return Err("expected ',' or '}'".to_owned()),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Ordered, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_space();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Ordered::Array(items));
        }
        loop {
            self.skip_space();
            items.push(self.value(depth + 1)?);
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Ordered::Array(items));
                }
                _ => return Err("expected ',' or ']'".to_owned()),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        let start = self.at;
        self.expect(b'"')?;
        loop {
            match self.peek() {
                None => return Err("unterminated string".to_owned()),
                Some(b'"') => {
                    self.at += 1;
                    break;
                }
                Some(b'\\') => self.at += 2,
                Some(_) => self.at += 1,
            }
        }
        let token = self
            .bytes
            .get(start..self.at)
            .ok_or("unterminated string")?;
        serde_json::from_slice::<String>(token).map_err(|error| error.to_string())
    }

    fn number(&mut self) -> Result<Ordered, String> {
        let start = self.at;
        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.at += 1;
        }
        let token = &self.bytes[start..self.at];
        serde_json::from_slice::<Number>(token)
            .map(Ordered::Number)
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{parse, Ordered};

    fn names(value: &Ordered) -> Vec<&str> {
        value
            .members()
            .expect("an object")
            .iter()
            .map(|(name, _)| name.as_str())
            .collect()
    }

    #[test]
    fn members_keep_the_order_they_were_written_in() {
        let value = parse(br#"{"b":1,"a":{"z":null,"y":[true,false]},"c":"x"}"#).unwrap();
        assert_eq!(names(&value), ["b", "a", "c"]);
        let inner = &value.members().unwrap()[1].1;
        assert_eq!(names(inner), ["z", "y"]);
        assert_eq!(
            value.to_value().to_string(),
            r#"{"a":{"y":[true,false],"z":null},"b":1,"c":"x"}"#,
            "the Value form is sorted"
        );
    }

    #[test]
    fn strings_decode_escapes_and_numbers_keep_their_kind() {
        let value =
            parse(b" {\"k\\u00e9\\n\":\"\\ud83d\\ude00 \\\"q\\\"\", \"n\":-12.5e1 , \"i\":7}\n")
                .unwrap();
        let members = value.members().unwrap();
        assert_eq!(members[0].0, "k\u{e9}\n");
        assert_eq!(members[0].1, Ordered::String("\u{1f600} \"q\"".to_owned()));
        assert_eq!(members[1].1.to_value(), serde_json::json!(-125.0));
        assert_eq!(members[2].1.to_value(), serde_json::json!(7));
    }

    #[test]
    fn what_is_not_json_is_refused() {
        for text in [
            "",
            "{",
            "[1,]",
            "{\"a\"}",
            "{\"a\":1,}",
            "tru",
            "\"x",
            "{\"a\":1} x",
            "[1 2]",
            "-",
            "01x",
            "{\"a\":\"\\x\"}",
            "nul",
            "{1:2}",
        ] {
            assert!(parse(text.as_bytes()).is_err(), "{text:?}");
        }
        let deep = format!("{}{}", "[".repeat(80), "]".repeat(80));
        assert_eq!(parse(deep.as_bytes()).unwrap_err(), "nesting is too deep");
        let fine = format!("{}{}", "[".repeat(60), "]".repeat(60));
        assert!(parse(fine.as_bytes()).is_ok());
    }

    #[test]
    fn nesting_is_bounded_at_exactly_sixty_five_levels_for_arrays_and_for_objects() {
        let arrays = |levels: usize| format!("{}{}", "[".repeat(levels), "]".repeat(levels));
        assert!(parse(arrays(65).as_bytes()).is_ok());
        assert_eq!(
            parse(arrays(66).as_bytes()).unwrap_err(),
            "nesting is too deep"
        );
        let objects =
            |levels: usize| format!("{}null{}", "{\"a\":".repeat(levels), "}".repeat(levels));
        assert!(parse(objects(64).as_bytes()).is_ok());
        assert_eq!(
            parse(objects(66).as_bytes()).unwrap_err(),
            "nesting is too deep"
        );
        assert_eq!(
            parse(objects(200).as_bytes()).unwrap_err(),
            "nesting is too deep"
        );
    }

    #[test]
    fn empty_containers_and_whitespace_are_fine() {
        assert_eq!(parse(b" { } ").unwrap(), Ordered::Object(vec![]));
        assert_eq!(parse(b"[ ]").unwrap(), Ordered::Array(vec![]));
        assert_eq!(parse(b"null").unwrap(), Ordered::Null);
        assert_eq!(
            parse(b"[1,\n2]").unwrap(),
            Ordered::Array(vec![Ordered::Number(1.into()), Ordered::Number(2.into())])
        );
    }
}
