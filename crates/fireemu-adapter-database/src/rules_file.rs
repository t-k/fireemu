//! Reading a Realtime Database rules file (`database.rules.json`, or the body of
//! `PUT /.settings/rules.json`) into the rules tree, with the official emulator's error texts
//! and places (firebase-database-emulator v4.11.2).
//!
//! The file is JSON with `//` and `/* */` comments and trailing commas allowed. Its one
//! property is `rules`; each level holds `.read`, `.write`, `.validate` (`true`, `false` or an
//! expression string), `.indexOn` (a string or an array of strings) and child levels, of which
//! at most one is a `$wildcard`. Every expression keeps the line and column of each of its
//! characters, so an error in it names the place in the file.

use fireemu_core_database::rules::{RuleSource, RuleSpec, Rules, RulesError, SourceExpr};

/// Reads and compiles a rules file.
///
/// Reading and checking recurse once per level of nesting, which the bounds allow to reach
/// about a thousand; they run on a thread of their own with room for that, so the caller's
/// stack (a server worker's) never decides whether a file loads.
pub fn compile(text: &str) -> Result<Rules, RulesError> {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("rules-compile".to_owned())
            .stack_size(COMPILE_STACK_BYTES)
            .spawn_scoped(scope, || Rules::compile(&read(text)?))
            .map_err(|error| RulesError {
                line: 1,
                column: 1,
                message: format!("Could not start reading the rules: {error}"),
            })?
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

/// The stack of the thread that reads and checks a rules file.
const COMPILE_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Reads a rules file into its tree, without checking the expressions.
pub fn read(text: &str) -> Result<RuleSpec, RulesError> {
    let mut reader = Reader::new(text);
    reader.space()?;
    if reader.peek() != Some('{') {
        reader.literal()?;
        return Err(reader.error_here("Expected '{'."));
    }
    reader.bump();
    reader.space()?;
    let key_at = reader.position();
    let key = match reader.peek() {
        Some('"') => reader.string()?.0,
        _ => String::new(),
    };
    if key != "rules" {
        return Err(Reader::error_at(key_at, "Expected 'rules' property."));
    }
    reader.colon()?;
    let spec = reader.level()?;
    reader.space()?;
    match reader.peek() {
        Some('}') => reader.bump(),
        Some(',') => {
            reader.bump();
            reader.space()?;
            if reader.peek() == Some('}') {
                reader.bump();
            } else {
                return Err(reader.error_here("Expected '}'."));
            }
        }
        None => return Err(reader.error_here("Unexpected EOF.")),
        _ => return Err(reader.error_here("Expected '}'.")),
    }
    reader.space()?;
    if reader.peek().is_some() {
        return Err(reader.error_here("Parse error."));
    }
    Ok(spec)
}

/// A place in the file: character index, line and column (both from 1).
#[derive(Debug, Clone, Copy)]
struct Place {
    line: usize,
    column: usize,
}

/// The deepest nesting of rule levels, `rules` included. The official emulator loads 1,000
/// levels below `rules` (and stops answering at 3,000); past this bound fireemu refuses the
/// file, so a deep file never exhausts the stack. The text is provisional.
const MAX_LEVEL_DEPTH: usize = 1001;

struct Reader {
    chars: Vec<char>,
    at: usize,
    line: usize,
    column: usize,
    /// How many levels the one being read is nested in.
    depth: usize,
}

impl Reader {
    fn new(text: &str) -> Self {
        Self {
            chars: text.chars().collect(),
            at: 0,
            line: 1,
            column: 1,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn bump(&mut self) {
        if let Some(c) = self.peek() {
            self.at += 1;
            if c == '\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
        }
    }

    fn position(&self) -> Place {
        Place {
            line: self.line,
            column: self.column,
        }
    }

    fn error_at(place: Place, message: &str) -> RulesError {
        RulesError {
            line: place.line,
            column: place.column,
            message: message.to_owned(),
        }
    }

    fn error_here(&self, message: &str) -> RulesError {
        Self::error_at(self.position(), message)
    }

    /// Skips white space and comments.
    fn space(&mut self) -> Result<(), RulesError> {
        loop {
            match self.peek() {
                Some(c) if c.is_whitespace() => self.bump(),
                Some('/') if self.chars.get(self.at + 1) == Some(&'/') => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                }
                Some('/') if self.chars.get(self.at + 1) != Some(&'*') => {
                    self.bump();
                    return Err(self.error_here("Expected '/' or '*'."));
                }
                Some('/') => {
                    self.bump();
                    self.bump();
                    loop {
                        match self.peek() {
                            None => return Err(self.error_here("Unexpected EOF.")),
                            Some('*') if self.chars.get(self.at + 1) == Some(&'/') => {
                                self.bump();
                                self.bump();
                                break;
                            }
                            Some(_) => self.bump(),
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    /// At the start of a file that is not an object: a word must spell `true`, `false` or
    /// `null` (by its first letter), or it is refused where it stops matching; the place stays
    /// at the start for what follows.
    fn literal(&self) -> Result<(), RulesError> {
        let Some(first) = self.peek().filter(char::is_ascii_alphabetic) else {
            return Ok(());
        };
        let Some(word) = ["true", "false", "null"]
            .into_iter()
            .find(|w| w.starts_with(first))
        else {
            return Err(self.error_here("Parse error."));
        };
        for (i, expected) in word.chars().enumerate() {
            let message = match self.chars.get(self.at + i) {
                Some(c) if *c == expected => continue,
                Some(_) => "Parse error.",
                None => "Unexpected EOF.",
            };
            return Err(RulesError {
                line: self.line,
                column: self.column + i,
                message: message.to_owned(),
            });
        }
        Ok(())
    }

    fn colon(&mut self) -> Result<(), RulesError> {
        self.space()?;
        match self.peek() {
            Some(':') => {
                self.bump();
                self.space()
            }
            _ => Err(self.error_here("Expected ':'.")),
        }
    }

    /// A JSON string, with the place of each decoded character (and of the closing quote).
    fn string(&mut self) -> Result<(String, Vec<(usize, usize)>), RulesError> {
        self.bump();
        let mut text = String::new();
        let mut places = Vec::new();
        loop {
            let place = self.position();
            match self.peek() {
                None => return Err(self.error_here("Unexpected EOF.")),
                Some('"') => {
                    places.push((place.line, place.column));
                    self.bump();
                    return Ok((text, places));
                }
                Some('\\') => {
                    self.bump();
                    // An escaped character is placed where its escape ends.
                    let mut place = self.position();
                    let decoded = match self.peek() {
                        None => return Err(self.error_here("Unexpected EOF.")),
                        Some('n') => '\n',
                        Some('t') => '\t',
                        Some('r') => '\r',
                        Some('b') => '\u{8}',
                        Some('f') => '\u{c}',
                        Some('u') => {
                            let mut code = 0u32;
                            for _ in 0..4 {
                                self.bump();
                                let digit = self
                                    .peek()
                                    .and_then(|c| c.to_digit(16))
                                    .ok_or_else(|| self.error_here("Parse error."))?;
                                code = code * 16 + digit;
                            }
                            place = self.position();
                            char::from_u32(code).unwrap_or('\u{fffd}')
                        }
                        Some(other) => other,
                    };
                    self.bump();
                    text.push(decoded);
                    places.push((place.line, place.column));
                }
                Some(c) => {
                    self.bump();
                    text.push(c);
                    places.push((place.line, place.column));
                }
            }
        }
    }

    /// A rule value: `true`, `false` or an expression string. Anything else is refused at
    /// its start, without reading it; a word is refused where it stops spelling `true`,
    /// `false` or `null`.
    fn rule_value(&mut self) -> Result<RuleSource, RulesError> {
        let start = self.position();
        let invalid = || {
            Self::error_at(
                start,
                "Invalid rule expression.  Expected 'true', 'false', or an expression string.",
            )
        };
        let word = match self.peek() {
            Some('"') => {
                let (text, positions) = self.string()?;
                return Ok(RuleSource::Expr(SourceExpr { text, positions }));
            }
            Some('t') => "true",
            Some('f') => "false",
            Some('n') => "null",
            Some('}' | ',') => return Err(self.error_here("Missing value.")),
            None => return Err(self.error_here("Unexpected EOF.")),
            Some(_) => return Err(invalid()),
        };
        for expected in word.chars() {
            match self.peek() {
                Some(c) if c == expected => self.bump(),
                Some(_) => return Err(self.error_here("Parse error.")),
                None => return Err(self.error_here("Unexpected EOF.")),
            }
        }
        match word {
            "true" => Ok(RuleSource::Bool(true)),
            "false" => Ok(RuleSource::Bool(false)),
            _ => Err(invalid()),
        }
    }

    /// `.indexOn`: a string, or an array of strings.
    fn index_on(&mut self) -> Result<Vec<String>, RulesError> {
        let start = self.position();
        match self.peek() {
            Some('"') => Ok(vec![self.string()?.0]),
            Some('[') => {
                self.bump();
                let mut names = Vec::new();
                loop {
                    self.space()?;
                    match self.peek() {
                        Some(']') => {
                            self.bump();
                            return Ok(names);
                        }
                        Some(',') => self.bump(),
                        Some('"') => names.push(self.string()?.0),
                        None => return Err(self.error_here("Unexpected EOF.")),
                        _ => {
                            return Err(self.error_here("Invalid indexOn expression. Expected ']'"))
                        }
                    }
                }
            }
            _ => Err(Self::error_at(
                start,
                "Invalid indexOn expression. Must be either a string or an array of strings",
            )),
        }
    }

    /// One level of the rules: an object.
    fn level(&mut self) -> Result<RuleSpec, RulesError> {
        self.depth += 1;
        let level = if self.depth > MAX_LEVEL_DEPTH {
            Err(self.error_here("Parse error."))
        } else {
            self.level_body()
        };
        self.depth -= 1;
        level
    }

    fn level_body(&mut self) -> Result<RuleSpec, RulesError> {
        if self.peek() != Some('{') {
            return Err(match self.peek() {
                None => self.error_here("Unexpected EOF."),
                _ => self.error_here("Expected '{'."),
            });
        }
        self.bump();
        let mut spec = RuleSpec::default();
        let mut wildcard: Option<String> = None;
        loop {
            self.space()?;
            match self.peek() {
                None => return Err(self.error_here("Unexpected EOF.")),
                Some('}') => {
                    self.bump();
                    return Ok(spec);
                }
                Some(',') => {
                    self.bump();
                    continue;
                }
                Some('"') => {}
                Some(_) => return Err(self.error_here("Parse error.")),
            }
            let key_at = self.position();
            let (key, _) = self.string()?;
            if key.is_empty() {
                return Err(Self::error_at(key_at, "Unexpected empty string."));
            }
            self.colon()?;
            match key.as_str() {
                ".read" | ".write" | ".validate" => {
                    let rule = self.rule_value()?;
                    match key.as_str() {
                        ".read" => spec.read = Some(rule),
                        ".write" => spec.write = Some(rule),
                        _ => spec.validate = Some(rule),
                    }
                }
                ".indexOn" => spec.index_on = self.index_on()?,
                _ => {
                    let child = self.level()?;
                    // The key is checked once its level is read, at its closing brace.
                    let end = Place {
                        line: self.line,
                        column: self.column - 1,
                    };
                    if let Some(name) = key.strip_prefix('$') {
                        if !valid_key(name) {
                            return Err(Self::error_at(end, INVALID_KEY));
                        }
                        if let Some(other) = &wildcard {
                            return Err(Self::error_at(
                                end,
                                &format!(
                                    "Cannot have multiple default rules ('{other}' and '{key}')."
                                ),
                            ));
                        }
                        wildcard = Some(key.clone());
                    } else if !valid_key(&key) {
                        return Err(Self::error_at(end, INVALID_KEY));
                    }
                    spec.children.insert(key, child);
                }
            }
            // A member is followed by a comma or the closing brace.
            self.space()?;
            match self.peek() {
                Some(',' | '}') => {}
                None => return Err(self.error_here("Unexpected EOF.")),
                Some(_) => return Err(self.error_here("Expected ',' or '}'.")),
            }
        }
    }
}

const INVALID_KEY: &str = r##"String can't contain ".", "#", "$", "/", "[", or "]""##;

fn valid_key(key: &str) -> bool {
    !key.is_empty() && !key.contains(['.', '#', '$', '/', '[', ']'])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers of firebase-database-emulator v4.11.2 to the same files.
    #[test]
    fn structural_errors_are_named_and_placed_as_the_official_emulator_does() {
        let mut wrong = Vec::new();
        for (text, expected) in [
            ("{}", "1:2: Expected 'rules' property."),
            (r#"{"x":1}"#, "1:2: Expected 'rules' property."),
            (r#"{"rules":"#, "1:10: Unexpected EOF."),
            ("not json", "1:2: Parse error."),
            ("[1]", "1:1: Expected '{'."),
            (r#"{"rules":true}"#, "1:10: Expected '{'."),
            (r#"{"rules":{"a":1}}"#, "1:15: Expected '{'."),
            (r#"{"rules":{".read":1}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":null}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":"true","t":{".foo":true}}}"#, "1:38: Expected '{'."),
            (r#"{"rules":{".indexOn":[1]}}"#, "1:23: Invalid indexOn expression. Expected ']'"),
            (r#"{"rules":{".indexOn":{}}}"#, "1:22: Invalid indexOn expression. Must be either a string or an array of strings"),
            (r#"{"rules":{"t":{"$a":{},"$b":{}}}}"#, "1:30: Cannot have multiple default rules ('$a' and '$b')."),
            (r#"{"rules":{"$a":{".read":true},"$a2":{".read":true}}}"#, "1:50: Cannot have multiple default rules ('$a' and '$a2')."),
            (r#"{"rules":{"t":{"$a":{"x":{}},"$b":{"y":{}}}}}"#, "1:42: Cannot have multiple default rules ('$a' and '$b')."),
            ("{\n  \"rules\": {\n    \"$a\": {},\n    \"$b\": {\n      \".read\": true\n    }\n  }\n}", "6:5: Cannot have multiple default rules ('$a' and '$b')."),
            (r#"{"rules":{".read":true},"x":1}"#, "1:25: Expected '}'."),
            (r#"{"rules":{".read":true}}x"#, "1:25: Parse error."),
            ("{\"rules\":{\n\".read\":true,\n\"a\":5}}", "3:5: Expected '{'."),
            (r#"{"rules":{"a":{".foo":{}}}}"#, r##"1:24: String can't contain ".", "#", "$", "/", "[", or "]""##),
            (r#"{"rules":{"a.b":{}}}"#, r##"1:18: String can't contain ".", "#", "$", "/", "[", or "]""##),
            (r#"{"rules":{".value":{}}}"#, r##"1:21: String can't contain ".", "#", "$", "/", "[", or "]""##),
            (r#"{"rules":{"":{}}}"#, "1:11: Unexpected empty string."),
            (r#"{"rules":{".read":"\"a\" == 1 +"}}"#, "1:32: Unexpected end of expression"),
            (r#"{"rules":{".read":"'é' == 1 +"}}"#, "1:30: Unexpected end of expression"),
            ("{\"rules\":{\n  \".read\":\n    \"auth.x ===\"\n}}", "3:16: Unexpected end of expression"),
            // Recorded 2026-10-20: comments, literals, values and escapes.
            (r#"{ /x "rules": {} }"#, "1:4: Expected '/' or '*'."),
            (r#"{"rules": {}} /"#, "1:16: Expected '/' or '*'."),
            (r#"{"rules": {} /"#, "1:15: Expected '/' or '*'."),
            (r#"{"rules": /* open"#, "1:18: Unexpected EOF."),
            ("tru", "1:4: Unexpected EOF."),
            ("trux", "1:4: Parse error."),
            ("nul", "1:4: Unexpected EOF."),
            ("nulx", "1:4: Parse error."),
            ("fx", "1:2: Parse error."),
            ("x", "1:1: Parse error."),
            ("true", "1:1: Expected '{'."),
            ("null", "1:1: Expected '{'."),
            ("false", "1:1: Expected '{'."),
            ("  tru", "1:6: Unexpected EOF."),
            ("t", "1:2: Unexpected EOF."),
            ("falsy", "1:5: Parse error."),
            ("  x", "1:3: Parse error."),
            ("1", "1:1: Expected '{'."),
            (r#""s""#, "1:1: Expected '{'."),
            (r#"{"rules""#, "1:9: Expected ':'."),
            (r#"{"rules" "#, "1:10: Expected ':'."),
            (r#"{"rules":{".read": }}"#, "1:20: Missing value."),
            (r#"{"rules":{".read":"#, "1:19: Unexpected EOF."),
            (r#"{"rules":{".read":"\u0074ru"}}"#, "1:25: Unknown variable 'tru'."),
            (r#"{"rules":{".read":"\u0061uth.x("}}"#, "1:32: Unexpected end of expression"),
            (r#"{"rules":{".read":true,"x":[1,{"a":1},"s"]}}"#, "1:28: Expected '{'."),
            (r#"{"rules":{"x":[1,2"#, "1:15: Expected '{'."),
            (r#"{"rules":{"x":[}}"#, "1:15: Expected '{'."),
            (r#"{"rules":{"x":[1 2]}}"#, "1:15: Expected '{'."),
            (r#"{"rules":{"x":[,]}}"#, "1:15: Expected '{'."),
            (r#"{"rules":{"x":[{"a":}]}}"#, "1:15: Expected '{'."),
            (r#"{"rules":{".indexOn":["a""#, "1:26: Unexpected EOF."),
            (r#"{"rules":{".indexOn":["a","#, "1:27: Unexpected EOF."),
            (r#"{"rules":{}"#, "1:12: Unexpected EOF."),
            (r#"{"rules":{".read":true}"#, "1:24: Unexpected EOF."),
            (r#"{"rules":{"x":"s"}}"#, "1:15: Expected '{'."),
            (r#"{"rules":{"x":[]}}"#, "1:15: Expected '{'."),
            (r#"{"rules":{".read":[1,2]}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":[1"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":[}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":[{"a":1}]}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":[1 2]}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":{"a":1}}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":{}}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":[{"a":}]}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":tru}}"#, "1:22: Parse error."),
            (r#"{"rules":{".read":-1}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":[,]}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":[[1]]}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":["#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":["a",]}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":[x]}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":[{"a":1}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
            (r#"{"rules":{".read":truex}}"#, "1:23: Expected ',' or '}'."),
            (r#"{"rules":{".read":nul}}"#, "1:22: Parse error."),
            (r#"{"rules":{".read":[ ]}}"#, "1:19: Invalid rule expression.  Expected 'true', 'false', or an expression string."),
        ] {
            let got = compile(text).map_err(|e| e.to_string());
            if got.as_ref().err().map(String::as_str) != Some(expected) {
                wrong.push(format!("{text}: {got:?}, expected {expected}"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    #[test]
    fn comments_trailing_commas_and_index_names_are_accepted() {
        for text in [
            r#"{"rules":{".read":true,}}"#,
            "// c\n{\"rules\":{\".read\":true}}",
            r#"{"rules":{".read":true /* c */}}"#,
            r#"{"rules":{".read":"true"/*c*/,".write":false}}"#,
            r#"{"rules":{".indexOn":"n"}}"#,
            r#"{"rules":{".indexOn":["n","m"]}}"#,
            r#"{"rules":{".validate":true,".indexOn":["a",".value"]}}"#,
            r#"{"rules":{"$a":{"$b":{".read":"$a == $b"}}}}"#,
            "{\"rules\":{\".read\":\"true\"}} ",
            r#"{"rules": {".read": true} } // c"#,
            r#"{"rules":{".read":"\u0074rue"}}"#,
            r#"{"rules":{".read":true /* a * b */}}"#,
            r#"{"rules":{".read":true /** c **/}}"#,
            r#"/* x */{"rules":{}}"#,
        ] {
            assert!(compile(text).is_ok(), "{text}");
        }
        // Depth counts nesting, not width: 1,100 sibling levels below a 900-deep one load.
        let deep = format!("{}{{}}{}", r#"{"a":"#.repeat(900), "}".repeat(900));
        let siblings: Vec<String> = (0..1100).map(|i| format!(r#""k{i}":{{}}"#)).collect();
        let wide = format!(r#"{{"rules":{{"d":{deep},{}}}}}"#, siblings.join(","));
        assert!(compile(&wide).is_ok());
        let spec = read(r#"{"rules":{"q":{".indexOn":["n","m"]}}}"#).unwrap();
        assert_eq!(
            spec.children["q"].index_on,
            vec!["n".to_owned(), "m".to_owned()]
        );
    }
}
