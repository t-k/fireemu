//! The expression language of Realtime Database rules: tokens and syntax.
//!
//! It is a small subset of JavaScript expressions: literals (numbers, strings, `true`,
//! `false`, `null`, regular expressions), names, member access (`a.b`, `a['b']`), calls,
//! the unary operators `!` and `-`, the binary arithmetic, comparison and logical
//! operators, and `?:`. An array literal is read only so that `hasChildren([...])` can take
//! one. Positions are character offsets into the expression text; the caller maps them to
//! the line and column of the rules file.

use super::java_chars;

/// A syntax or type error, at a character offset of the expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExprError {
    /// Where the error is, in characters from the start of the expression.
    pub at: usize,
    /// The official emulator's text for it.
    pub message: String,
}

impl ExprError {
    pub(crate) fn new(at: usize, message: impl Into<String>) -> Self {
        Self {
            at,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Number(f64),
    Str(String),
    Regex(String, String),
    Name(String),
    Punct(&'static str),
    End,
}

const PUNCTUATION: [&str; 28] = [
    "===", "!==", "--", "++", "==", "!=", "<=", ">=", "&&", "||", "(", ")", "[", "]", "{", "}",
    ".", ",", ";", "?", ":", "!", "+", "-", "*", "/", "%", "<",
];

/// A binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `%`
    Rem,
    /// `==` and `===` (the rules language has one equality)
    Eq,
    /// `!=` and `!==`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `&&`
    And,
    /// `||`
    Or,
}

impl BinaryOp {
    /// The operator as the official emulator names it in a type error.
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Sub => "-",
            Self::Mul => "*",
            Self::Div => "/",
            Self::Rem => "%",
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::And => "&&",
            Self::Or => "||",
        }
    }
}

/// An expression, with the character offset where it starts. Its depth is bounded when it
/// is parsed, and it is dropped without recursion.
#[derive(Debug, Clone, PartialEq)]
pub struct Expr {
    /// Where it starts.
    pub at: usize,
    /// What it is.
    pub kind: ExprKind,
}

/// The kinds of expression.
#[derive(Debug, Clone, PartialEq)]
pub enum ExprKind {
    /// `true` / `false`
    Bool(bool),
    /// A number literal.
    Number(f64),
    /// A string literal.
    Str(String),
    /// `null`
    Null,
    /// `/pattern/flags`, compiled when the rules load.
    Regex(super::pattern::Pattern),
    /// `[a, b]`, only as an argument of `hasChildren`.
    Array(Vec<Expr>),
    /// A variable.
    Name(String),
    /// `object.name`, or `object['name']` with a string literal.
    Member(Box<Expr>, String),
    /// `object[index]` with any other index.
    Index(Box<Expr>, Box<Expr>),
    /// `callee(arguments)`.
    Call(Box<Expr>, Vec<Expr>),
    /// `!operand`
    Not(Box<Expr>),
    /// `-operand`
    Neg(Box<Expr>),
    /// `left op right`
    Binary(BinaryOp, Box<Expr>, Box<Expr>),
    /// `a && b && …`, `a || b || …` or `a + b + …`: a chain of one associative operator,
    /// read left to right, kept flat so its length is no depth.
    Chain(BinaryOp, Vec<Expr>),
    /// `condition ? then : otherwise`
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
}

impl ExprKind {
    /// The sub-expressions, by reference.
    fn children(&self) -> Vec<&Expr> {
        match self {
            Self::Bool(_)
            | Self::Number(_)
            | Self::Str(_)
            | Self::Null
            | Self::Regex(_)
            | Self::Name(_) => Vec::new(),
            Self::Member(object, _) | Self::Not(object) | Self::Neg(object) => vec![object],
            Self::Index(a, b) | Self::Binary(_, a, b) => vec![a, b],
            Self::Ternary(a, b, c) => vec![a, b, c],
            Self::Call(callee, items) => std::iter::once(&**callee).chain(items).collect(),
            Self::Array(items) | Self::Chain(_, items) => items.iter().collect(),
        }
    }

    /// The sub-expressions, taken out.
    fn into_children(self) -> Vec<Expr> {
        match self {
            Self::Bool(_)
            | Self::Number(_)
            | Self::Str(_)
            | Self::Null
            | Self::Regex(_)
            | Self::Name(_) => Vec::new(),
            Self::Member(object, _) | Self::Not(object) | Self::Neg(object) => vec![*object],
            Self::Index(a, b) | Self::Binary(_, a, b) => vec![*a, *b],
            Self::Ternary(a, b, c) => vec![*a, *b, *c],
            Self::Call(callee, mut items) => {
                items.push(*callee);
                items
            }
            Self::Array(items) | Self::Chain(_, items) => items,
        }
    }
}

impl Expr {
    /// The depth of the tree (a leaf is 1): how deep the checker and the evaluator recurse.
    pub(crate) fn depth(&self) -> usize {
        let mut deepest = 0;
        let mut pending = vec![(self, 1)];
        while let Some((expr, depth)) = pending.pop() {
            deepest = deepest.max(depth);
            pending.extend(
                expr.kind
                    .children()
                    .into_iter()
                    .map(|child| (child, depth + 1)),
            );
        }
        deepest
    }
}

impl Drop for Expr {
    /// Takes the tree apart level by level, so dropping a deep one never recurses.
    fn drop(&mut self) {
        let mut pending = std::mem::replace(&mut self.kind, ExprKind::Null).into_children();
        while let Some(mut expr) = pending.pop() {
            pending.extend(std::mem::replace(&mut expr.kind, ExprKind::Null).into_children());
        }
    }
}

struct Lexer<'a> {
    chars: &'a [char],
    at: usize,
}

impl Lexer<'_> {
    /// Skips the format characters at the reader's place (see [`is_format`]).
    fn skip_format(&mut self) {
        while self.chars.get(self.at).copied().is_some_and(is_format) {
            self.at += 1;
        }
    }

    /// Skips white space (see [`is_space`]) and comments, which JavaScript reads anywhere: `//` to the end of
    /// the line and `/* … */`. A `/` followed by `/` or `*` never starts a regular expression.
    fn skip_space(&mut self) -> Result<(), ExprError> {
        loop {
            let Some(&c) = self.chars.get(self.at) else {
                return Ok(());
            };
            if is_space(c) {
                self.at += 1;
                continue;
            }
            // The reader skips format characters while it reads `//`, `/*` and `*/` too
            // (review r8 M20).
            let second = self.past_format(self.at + 1);
            match (c, self.chars.get(second)) {
                ('/', Some('/')) => {
                    self.at = second;
                    while self
                        .chars
                        .get(self.at)
                        .is_some_and(|&c| !is_line_terminator(c))
                    {
                        self.at += 1;
                    }
                }
                ('/', Some('*')) => {
                    let mut i = second + 1;
                    loop {
                        match self.chars.get(i) {
                            None => {
                                return Err(ExprError::new(
                                    self.chars.len(),
                                    "unterminated comment",
                                ));
                            }
                            Some('*') => {
                                let after = self.past_format(i + 1);
                                if self.chars.get(after) == Some(&'/') {
                                    self.at = after + 1;
                                    break;
                                }
                                i += 1;
                            }
                            Some(_) => i += 1,
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    /// The first index from `i` on that holds no format character.
    fn past_format(&self, mut i: usize) -> usize {
        while self.chars.get(i).copied().is_some_and(is_format) {
            i += 1;
        }
        i
    }

    /// The next token and where it starts. `regex_allowed` is true where an operand is
    /// expected, so a `/` starts a regular expression there and divides elsewhere.
    fn next(&mut self, regex_allowed: bool) -> Result<(usize, Token), ExprError> {
        self.skip_space()?;
        let start = self.at;
        let Some(&c) = self.chars.get(self.at) else {
            return Ok((start, Token::End));
        };
        if c.is_ascii_digit() || (c == '.' && self.peek_digit(1)) {
            return self.number(start);
        }
        if c == '\'' || c == '"' {
            return self.string(start, c);
        }
        if c == '/' && regex_allowed {
            return self.regex(start);
        }
        // Names follow Java's identifier classes, as the reader there reads them (review r8
        // M18); a character outside the Basic Multilingual Plane is never one.
        if java_chars::is_identifier_start(c) {
            let mut name = String::new();
            while let Some(&c) = self.chars.get(self.at) {
                if is_format(c) {
                    // Dropped from the name (`tr\u{200b}ue` is `true`).
                    self.at += 1;
                } else if c != '\u{feff}' && java_chars::is_identifier_part(c) {
                    // (U+FEFF is white space to the reader, so it ends the name.)
                    name.push(c);
                    self.at += 1;
                } else {
                    break;
                }
            }
            return Ok((start, Token::Name(name)));
        }
        // A format character inside an operator is skipped, as there (review r7 S19).
        for punct in PUNCTUATION.iter().chain(&[">"]) {
            let mut at = self.at;
            // (The first character is never one: the space before a token was skipped.)
            let matched = punct.chars().all(|expected| {
                while self.chars.get(at).copied().is_some_and(is_format) {
                    at += 1;
                }
                let found = self.chars.get(at) == Some(&expected);
                at += 1;
                found
            });
            if matched {
                self.at = at;
                return Ok((start, Token::Punct(punct)));
            }
        }
        Err(ExprError::new(start, "Unsupported javascript syntax."))
    }

    /// Whether the character `ahead` places on, format characters skipped, is a digit.
    fn peek_digit(&self, ahead: usize) -> bool {
        let mut at = self.at + ahead;
        while self.chars.get(at).copied().is_some_and(is_format) {
            at += 1;
        }
        self.chars.get(at).is_some_and(char::is_ascii_digit)
    }

    /// Where the JavaScript parser of the official emulator stands after a token that ends
    /// at `end` and needed a character of lookahead to end: one past it, unless that is the
    /// end of the text.
    fn after_lookahead(&self, end: usize) -> usize {
        if end < self.chars.len() {
            end + 1
        } else {
            end
        }
    }

    /// A number: decimal (`1`, `1.5`, `.5`, `1.`, `1e3`), hexadecimal (`0x10`) or legacy
    /// octal (`010`, as JavaScript reads it).
    fn number(&mut self, start: usize) -> Result<(usize, Token), ExprError> {
        // A format character inside a number is skipped, as there (review r7 S19).
        let digits = |lexer: &mut Self, radix: u32| {
            let mut text = String::new();
            loop {
                let saved = lexer.at;
                lexer.skip_format();
                match lexer.chars.get(lexer.at) {
                    Some(c) if c.is_digit(radix) => {
                        text.push(*c);
                        lexer.at += 1;
                    }
                    _ => {
                        lexer.at = saved;
                        return text;
                    }
                }
            }
        };
        let next_is = |lexer: &mut Self, accept: &dyn Fn(char) -> bool| {
            let saved = lexer.at;
            lexer.skip_format();
            match lexer.chars.get(lexer.at) {
                Some(&c) if accept(c) => {
                    lexer.at += 1;
                    Some(c)
                }
                _ => {
                    lexer.at = saved;
                    None
                }
            }
        };
        if self.chars[self.at] == '0' {
            let saved = self.at;
            self.at += 1;
            if next_is(self, &|c| matches!(c, 'x' | 'X')).is_some() {
                // Read into a double, as there: any length, and `0x` alone is NaN (review r8
                // S21; recorded 2026-10-21).
                let hex = digits(self, 16);
                let value = if hex.is_empty() {
                    f64::NAN
                } else {
                    radix_value(&hex, 16)
                };
                return Ok((start, Token::Number(value)));
            }
            let octal = digits(self, 10);
            if let Some(bad) = octal.chars().find(|c| matches!(c, '8' | '9')) {
                // The official emulator refuses what its reader only warns about.
                return Err(ExprError::new(
                    self.at,
                    format!(
                        "illegal octal literal digit {bad}; interpreting it as a decimal digit"
                    ),
                ));
            }
            if !octal.is_empty() {
                return Ok((start, Token::Number(radix_value(&octal, 8))));
            }
            self.at = saved;
        }
        let mut text = digits(self, 10);
        if next_is(self, &|c| c == '.').is_some() {
            text.push('.');
            text.push_str(&digits(self, 10));
        }
        if next_is(self, &|c| matches!(c, 'e' | 'E')).is_some() {
            text.push('e');
            if let Some(sign) = next_is(self, &|c| matches!(c, '+' | '-')) {
                text.push(sign);
            }
            let exponent = digits(self, 10);
            if exponent.is_empty() {
                return Err(ExprError::new(
                    self.after_lookahead(self.at),
                    "missing exponent",
                ));
            }
            text.push_str(&exponent);
        }
        text.parse::<f64>()
            .map(|n| (start, Token::Number(n)))
            .map_err(|_| ExprError::new(start, "Unsupported javascript syntax."))
    }

    /// A string literal, with its escapes read as the official emulator's JavaScript reads
    /// them: `\n \t \r \b \f \v`, `\xXX`, `\uXXXX` (a pair of escaped surrogates is one
    /// character), legacy octal (`\101`, `\0`), and any other escaped character standing for
    /// itself (so an incomplete `\u004` is `u004`). An escaped surrogate that pairs with
    /// nothing has no counterpart in this text and is refused.
    fn string(&mut self, start: usize, quote: char) -> Result<(usize, Token), ExprError> {
        self.at += 1;
        let mut text = String::new();
        let mut units: Vec<u16> = Vec::new();
        loop {
            let Some(&c) = self.chars.get(self.at) else {
                return Err(ExprError::new(start, "Unterminated string literal."));
            };
            self.at += 1;
            if c == quote {
                Self::flush_units(start, &mut units, &mut text)?;
                return Ok((start, Token::Str(text)));
            }
            if is_line_terminator(c) {
                // A line ends the literal there (review r7 M17).
                return Err(ExprError::new(self.at - 1, "unterminated string literal"));
            }
            if c != '\\' {
                // A format character in the body is kept, as there.
                Self::flush_units(start, &mut units, &mut text)?;
                text.push(c);
                continue;
            }
            // After `\` the reader skips format characters, as it does everywhere but the
            // body of a string (review r7 M15).
            self.skip_format();
            let Some(&escaped) = self.chars.get(self.at) else {
                return Err(ExprError::new(start, "Unterminated string literal."));
            };
            self.at += 1;
            if is_line_terminator(escaped) {
                // A line continuation adds nothing; `\r\n` is one (review r7 M16).
                if escaped == '\r' {
                    self.skip_format();
                    if self.chars.get(self.at) == Some(&'\n') {
                        self.at += 1;
                    }
                }
                // The reader takes the next character past format characters too
                // (recorded 2026-10-21: `'a\<LF><U+200B>b'` is `ab`).
                self.skip_format();
                continue;
            }
            // `n` hex digits, each read past format characters. Short of them, the escape
            // stands for its letter and the digits read, and the reader goes on at the
            // character that is no digit; the format characters before it are gone.
            let hex = |lexer: &mut Self, n: usize| -> Result<u32, String> {
                let mut digits = String::with_capacity(n);
                for _ in 0..n {
                    lexer.skip_format();
                    match lexer.chars.get(lexer.at) {
                        Some(d) if d.is_ascii_hexdigit() => {
                            digits.push(*d);
                            lexer.at += 1;
                        }
                        _ => return Err(digits),
                    }
                }
                u32::from_str_radix(&digits, 16).map_err(|_| digits)
            };
            let code = match escaped {
                'n' => u32::from('\n'),
                't' => u32::from('\t'),
                'r' => u32::from('\r'),
                'b' => 0x8,
                'f' => 0xC,
                'v' => 0xB,
                'u' | 'x' => match hex(self, if escaped == 'u' { 4 } else { 2 }) {
                    Ok(code) => code,
                    Err(digits) => {
                        Self::flush_units(start, &mut units, &mut text)?;
                        text.push(escaped);
                        text.push_str(&digits);
                        continue;
                    }
                },
                '0'..='7' => {
                    // Up to three octal digits, at most \377.
                    let longest = if escaped <= '3' { 3 } else { 2 };
                    let mut value = escaped.to_digit(8).unwrap_or(0);
                    let mut taken = 1;
                    // The reader looks one character past the escape, so format characters
                    // after it are gone too.
                    loop {
                        self.skip_format();
                        match self.chars.get(self.at).and_then(|d| d.to_digit(8)) {
                            Some(digit) if taken < longest => {
                                value = value * 8 + digit;
                                self.at += 1;
                                taken += 1;
                            }
                            _ => break,
                        }
                    }
                    value
                }
                other => u32::from(other),
            };
            if let Ok(unit) = u16::try_from(code) {
                units.push(unit);
            } else {
                Self::flush_units(start, &mut units, &mut text)?;
                text.extend(char::from_u32(code));
            }
        }
    }

    /// Decodes the UTF-16 units read from escapes; a surrogate without its pair is refused.
    fn flush_units(start: usize, units: &mut Vec<u16>, text: &mut String) -> Result<(), ExprError> {
        for decoded in char::decode_utf16(units.drain(..)) {
            let c = decoded.map_err(|_| ExprError::new(start, "Unsupported javascript syntax."))?;
            text.push(c);
        }
        Ok(())
    }

    fn regex(&mut self, start: usize) -> Result<(usize, Token), ExprError> {
        self.at += 1;
        let mut pattern = String::new();
        let mut in_class = false;
        loop {
            let Some(&c) = self.chars.get(self.at) else {
                return Err(ExprError::new(
                    self.chars.len(),
                    "unterminated regular expression literal",
                ));
            };
            self.at += 1;
            if is_format(c) {
                // Dropped from the pattern, as there.
                continue;
            }
            if is_line_terminator(c) {
                // A line ends the literal there (review r8 M21).
                return Err(ExprError::new(
                    self.at - 1,
                    "unterminated regular expression literal",
                ));
            }
            match c {
                '\\' => {
                    pattern.push(c);
                    while self.chars.get(self.at).copied().is_some_and(is_format) {
                        self.at += 1;
                    }
                    let Some(&next) = self.chars.get(self.at) else {
                        return Err(ExprError::new(
                            self.chars.len(),
                            "unterminated regular expression literal",
                        ));
                    };
                    pattern.push(next);
                    self.at += 1;
                    // The reader reads CR LF as one line terminator (a LF).
                    if next == '\r' && self.chars.get(self.at) == Some(&'\n') {
                        pattern.pop();
                        pattern.push('\n');
                        self.at += 1;
                    }
                }
                '[' => {
                    in_class = true;
                    pattern.push(c);
                }
                ']' => {
                    in_class = false;
                    pattern.push(c);
                }
                '/' if !in_class => break,
                other => pattern.push(other),
            }
        }
        // Flags, a format character among them skipped (review r7 S19).
        let mut flags = String::new();
        loop {
            let saved = self.at;
            self.skip_format();
            match self.chars.get(self.at) {
                Some(&c) if c.is_ascii_alphabetic() => {
                    flags.push(c);
                    self.at += 1;
                }
                _ => {
                    self.at = saved;
                    break;
                }
            }
        }
        check_anchors(&pattern).map_err(|message| ExprError::new(start, message))?;
        check_groups_and_counts(&pattern).map_err(|message| ExprError::new(start, message))?;
        Ok((start, Token::Regex(pattern, flags)))
    }
}

/// The value of `digits` in `radix`, accumulated in a double as the JavaScript reader does.
fn radix_value(digits: &str, radix: u32) -> f64 {
    digits.chars().fold(0.0, |value, digit| {
        value * f64::from(radix) + f64::from(digit.to_digit(radix).unwrap_or(0))
    })
}

/// The official emulator's refusal of `--` or `++` (`op`) on `operand`: a name or member
/// is a valid operand that the rules forbid, anything else an invalid one.
fn update_refusal(op: &str, operand: &Expr, at: usize) -> ExprError {
    let assignable = matches!(
        operand.kind,
        ExprKind::Name(_) | ExprKind::Member(..) | ExprKind::Index(..)
    );
    let message = match (assignable, op) {
        (true, _) => format!("Rule expressions may not contain '{op}' operator."),
        (false, "--") => "Invalid decrement operand.".to_owned(),
        (false, _) => "Invalid increment operand.".to_owned(),
    };
    ExprError::new(at, message)
}

/// Whether `c` ends a line (and so a string literal or a `//` comment) there.
fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// Whether `c` separates tokens as on the official emulator's JavaScript reader (Rhino on
/// Java 21): tab, vertical tab, form feed, space, U+00A0, U+FEFF and Java's space separators;
/// the line terminators; and the format characters it skips (see [`is_format`]). U+0085 is
/// none of these there (it is part of a name).
fn is_space(c: char) -> bool {
    matches!(c, '\t' | '\u{b}' | '\u{c}' | ' ' | '\u{a0}' | '\u{feff}')
        || java_chars::is_space_separator(c)
        || is_line_terminator(c)
        || is_format(c)
}

/// The format characters the official emulator's reader drops from names and
/// regular-expression literals and skips between tokens: Java's FORMAT characters above
/// U+007F, U+FEFF aside (white space there). A string literal keeps them. The reader works on
/// UTF-16 units, so no character outside the Basic Multilingual Plane is one.
fn is_format(c: char) -> bool {
    u32::from(c) > 0x7F && c != '\u{feff}' && java_chars::is_format(c)
}

/// The groups and counted repetitions of a pattern, as the official emulator checks them. It
/// reads the pattern wrapped as it searches with it (`.*` before an unanchored start and after
/// an unanchored end), and its positions count in that text: an unclosed group is "expected
/// ')' at position <end>", a `)` without its group "end-of-string expected", and a `{` must
/// open `{n}`, `{n,}` or `{n,m}` ("integer expected" or "expected '}'" where it stops). An
/// escape such as `\p` is one character, so `\p{L}` is a count without its integer.
fn check_groups_and_counts(pattern: &str) -> Result<(), String> {
    regex_shape(pattern).map(|_| ())
}

/// Reads a pattern as the official emulator's grammar does (see [`check_groups_and_counts`])
/// and answers whether an alternative starts with `|`, `)`, `*`, `+`, `?` or `{`, which that
/// grammar reads as a literal character: `(a|))` is a group of `a` or `)`, and `(|a)` a group
/// of `|a`. The scan keeps its own stack, so nesting costs no recursion.
pub(crate) fn regex_shape(pattern: &str) -> Result<bool, String> {
    let (start, body) = match pattern.strip_prefix('^') {
        Some(body) => ("", body),
        None => (".*", pattern),
    };
    let (body, end) = match body.strip_suffix('$') {
        Some(body) => (body, ""),
        None => (body, ".*"),
    };
    let chars: Vec<char> = format!("{start}{body}{end}").chars().collect();
    if chars.is_empty() {
        // `^$`: the empty string.
        return Ok(false);
    }
    let illegal = |what: String| Err(format!("Illegal regular expression, {what}"));
    let mut literal_operator = false;
    // `\s` and `\S` as the grammar reads them (in a class, `\\\s` is `\` then `s`): the
    // automaton has no whitespace class, which fails once the grammar has read the pattern.
    let mut whitespace_class = false;
    let names_whitespace = |chars: &[char], i: usize| {
        chars.get(i) == Some(&'\\') && matches!(chars.get(i + 1), Some('s' | 'S'))
    };
    let mut depth = 0usize;
    let mut i = 0;
    // Whether the next character starts an alternative (and so is read as an atom whatever it
    // is), as at the start and after `(` and `|`.
    let mut alternative_start = true;
    loop {
        // One atom.
        match chars.get(i) {
            None => return illegal("unexpected end-of-string".to_owned()),
            Some('[') => {
                i += 1;
                if chars.get(i) == Some(&'^') {
                    i += 1;
                }
                loop {
                    whitespace_class |= names_whitespace(&chars, i);
                    i = class_member_end(&chars, i)?;
                    if chars.get(i).is_none_or(|c| *c == ']') {
                        break;
                    }
                }
                if i >= chars.len() {
                    return illegal(format!("expected ']' at position {i}"));
                }
                i += 1;
            }
            Some('(') if chars.get(i + 1) == Some(&')') => i += 2,
            Some('(') => {
                depth += 1;
                i += 1;
                alternative_start = true;
                continue;
            }
            Some('\\') => {
                if i + 1 >= chars.len() {
                    return illegal("unexpected end-of-string".to_owned());
                }
                whitespace_class |= names_whitespace(&chars, i);
                i += 2;
            }
            Some(c) => {
                if alternative_start && matches!(c, '|' | ')' | '*' | '+' | '?' | '{') {
                    literal_operator = true;
                }
                i += 1;
            }
        }
        alternative_start = false;
        // Its repetitions, then what follows: more of the concatenation, another alternative,
        // the group's end (the group is an atom: its repetitions follow) or the pattern's.
        loop {
            i = repetitions_end(&chars, i)?;
            match chars.get(i) {
                None if depth == 0 && whitespace_class => {
                    return illegal("'whitespacechar' not found".to_owned());
                }
                None if depth == 0 => return Ok(literal_operator),
                None => return illegal(format!("expected ')' at position {i}")),
                Some('|') => {
                    i += 1;
                    alternative_start = true;
                }
                Some(')') if depth == 0 => return illegal("end-of-string expected".to_owned()),
                Some(')') => {
                    depth -= 1;
                    i += 1;
                    continue;
                }
                Some(_) => {}
            }
            break;
        }
    }
}

/// The end of the repetitions (`*`, `+`, `?`, `{n}`, `{n,}`, `{n,m}`) at `chars[i]`.
fn repetitions_end(chars: &[char], mut i: usize) -> Result<usize, String> {
    let digits = |from: usize| {
        let mut to = from;
        while chars.get(to).is_some_and(char::is_ascii_digit) {
            to += 1;
        }
        to
    };
    while let Some(c) = chars.get(i) {
        match c {
            '*' | '+' | '?' => i += 1,
            '{' => {
                let after = digits(i + 1);
                if after == i + 1 {
                    return Err(format!(
                        "Illegal regular expression, integer expected at position {}",
                        i + 1
                    ));
                }
                let mut at = after;
                if chars.get(at) == Some(&',') {
                    at = digits(at + 1);
                }
                if chars.get(at) != Some(&'}') {
                    return Err(format!(
                        "Illegal regular expression, expected '}}' at position {at}"
                    ));
                }
                i = at + 1;
            }
            _ => break,
        }
    }
    Ok(i)
}

/// The end of the class member at `chars[i]`, as the official emulator reads one: after a
/// `\`, `d`, `s`, `w`, `D`, `S` or `W` names a class; otherwise one character follows, itself
/// optionally escaped, so `\\]` is the character `]` there and does not close the class.
/// `-` and a second character make a range, unless `]` follows the `-`.
fn class_member_end(chars: &[char], mut i: usize) -> Result<usize, String> {
    if chars.get(i) == Some(&'\\') {
        i += 1;
        if chars
            .get(i)
            .is_some_and(|c| matches!(c, 'd' | 's' | 'w' | 'D' | 'S' | 'W'))
        {
            return Ok(i + 1);
        }
    }
    i = class_char_end(chars, i)?;
    if chars.get(i) == Some(&'-') {
        i += 1;
        if chars.get(i) != Some(&']') {
            i = class_char_end(chars, i)?;
        }
    }
    Ok(i)
}

/// The end of one character of a class, which an optional `\` escapes.
fn class_char_end(chars: &[char], mut i: usize) -> Result<usize, String> {
    if chars.get(i) == Some(&'\\') {
        i += 1;
    }
    if i >= chars.len() {
        return Err("Illegal regular expression, unexpected end-of-string".to_owned());
    }
    Ok(i + 1)
}

/// The anchors of a pattern, as the official emulator checks them: a final `$` is the end
/// anchor (escaped or not, so `/a\$/` leaves a dangling escape), and otherwise `^` may stand
/// only first and `$` nowhere, outside a character class.
fn check_anchors(pattern: &str) -> Result<(), &'static str> {
    let body = pattern.strip_suffix('$').unwrap_or(pattern);
    let trailing_escapes = body.chars().rev().take_while(|c| *c == '\\').count();
    if trailing_escapes % 2 == 1 {
        return Err("Illegal regular expression, unexpected end-of-string");
    }
    let mut chars = body.chars().enumerate();
    let mut in_class = false;
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '[' => in_class = true,
            ']' => in_class = false,
            '^' if !in_class && i > 0 => {
                return Err("Illegal regular expression, unescaped ^, ^ can only appear at the end of regular expressions")
            }
            '$' if !in_class => {
                return Err("Illegal regular expression, unescaped ^, ^ can only appear at the end of regular expressions")
            }
            _ => {}
        }
    }
    Ok(())
}

/// Parses one rule expression. An optional trailing `;` is allowed; a second expression
/// after it is not.
pub fn parse(text: &str) -> Result<Expr, ExprError> {
    let expr = parse_text(text, MAX_EXPRESSION_DEPTH).0?;
    // The counter above bounds the parser's own recursion; the tree it built is measured
    // too, since an operand read early can land deep (`1 - (…) - 0 - 0 …`, review r3 M6c).
    if expr.depth() > MAX_EXPRESSION_DEPTH {
        return Err(ExprError::new(0, "Rule expression may not be empty."));
    }
    Ok(expr)
}

/// Parses with the parser's own recursion bounded at `limit`; also answers the deepest it
/// reached.
fn parse_text(text: &str, limit: usize) -> (Result<Expr, ExprError>, usize) {
    let chars: Vec<char> = text.chars().collect();
    let mut parser = Parser {
        lexer: Lexer {
            chars: &chars,
            at: 0,
        },
        peeked: None,
        regex_next: true,
        depth: 0,
        limit,
        deepest: 0,
    };
    let parsed = parser.statement();
    (parsed, parser.deepest)
}

impl Parser<'_> {
    fn statement(&mut self) -> Result<Expr, ExprError> {
        let expr = self.ternary()?;
        let (at, token) = self.next()?;
        match token {
            Token::End => Ok(expr),
            Token::Punct(";") => {
                let (at, token) = self.next()?;
                if token == Token::End {
                    Ok(expr)
                } else {
                    Err(ExprError::new(
                        at,
                        "Rule expressions may not contain multiple expressions.",
                    ))
                }
            }
            token @ Token::Punct(")" | "]") => {
                Err(ExprError::new(self.rhino_end(at, &token), "syntax error"))
            }
            token => Err(ExprError::new(
                self.rhino_end(at, &token),
                "missing ; before statement",
            )),
        }
    }
}

/// The deepest an expression may nest: every level the checker and the evaluator recurse
/// through counts (a group, a unary operator, a member, index or call step, a conditional
/// branch, an operator that is not `&&`, `||` or `+`, and the innermost operand), so a rule
/// that loads is evaluated within this many levels. `&&`, `||` and `+` chains are one level
/// however long they are, as the official emulator loads chains of thousands. Past the bound
/// the expression is refused with "Rule expression may not be empty.", the official
/// emulator's text for 562 nested groups. 600 is a local safety budget: the official emulator
/// loads 561 groups and dies past 2,000 to 4,000 levels; fireemu evaluates on its 8 MiB
/// server workers.
pub(crate) const MAX_EXPRESSION_DEPTH: usize = 600;

struct Parser<'a> {
    lexer: Lexer<'a>,
    peeked: Option<(usize, Token)>,
    /// Whether a `/` at the next token starts a regular expression.
    regex_next: bool,
    /// How deep the operand being read is nested.
    depth: usize,
    /// The bound on `depth` (`MAX_EXPRESSION_DEPTH`).
    limit: usize,
    /// The deepest `depth` reached.
    deepest: usize,
}

impl Parser<'_> {
    fn peek(&mut self) -> Result<&(usize, Token), ExprError> {
        if self.peeked.is_none() {
            let token = self.lexer.next(self.regex_next)?;
            self.peeked = Some(token);
        }
        Ok(self.peeked.as_ref().unwrap_or(&(0, Token::End)))
    }

    fn next(&mut self) -> Result<(usize, Token), ExprError> {
        let token = match self.peeked.take() {
            Some(token) => token,
            None => self.lexer.next(self.regex_next)?,
        };
        // After an operand a `/` divides; after an operator or `(` it starts a regex.
        self.regex_next = !matches!(
            token.1,
            Token::Number(_)
                | Token::Str(_)
                | Token::Regex(..)
                | Token::Name(_)
                | Token::Punct(")" | "]")
        );
        Ok(token)
    }

    fn eat(&mut self, punct: &str) -> Result<bool, ExprError> {
        if matches!(self.peek()?, (_, Token::Punct(p)) if *p == punct) {
            self.next()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Where the official emulator's JavaScript parser reports an error at `token`, which
    /// starts at `at`: its end, one further after a token that needs lookahead to end.
    fn rhino_end(&self, at: usize, token: &Token) -> usize {
        let chars = self.lexer.chars;
        match token {
            Token::End => at,
            Token::Punct(p @ ("(" | ")" | "[" | "]" | "{" | "}" | "," | ";" | "?" | ":")) => {
                at + p.len()
            }
            Token::Punct(p) => self.lexer.after_lookahead(at + p.len()),
            Token::Str(_) => {
                // The closing quote ends it.
                let quote = chars[at];
                let mut end = at + 1;
                while end < chars.len() && chars[end] != quote {
                    end += if chars[end] == '\\' { 2 } else { 1 };
                }
                (end + 1).min(chars.len())
            }
            Token::Number(_) | Token::Name(_) | Token::Regex(..) => {
                // A number runs over its digits, point and exponent; a name stops at a `.`.
                let number = matches!(token, Token::Number(_));
                let mut end = at + 1;
                while end < chars.len()
                    && (java_chars::is_identifier_part(chars[end]) || (number && chars[end] == '.'))
                {
                    end += 1;
                }
                self.lexer.after_lookahead(end)
            }
        }
    }

    /// The closing `)` or `]` of a group, call or array, refused with the official
    /// emulator's text when something else stands there.
    fn close(&mut self, closer: &str, message: &str) -> Result<(), ExprError> {
        let (at, token) = self.next()?;
        match token {
            Token::Punct(p) if p == closer => Ok(()),
            token => Err(ExprError::new(self.rhino_end(at, &token), message)),
        }
    }

    fn ternary(&mut self) -> Result<Expr, ExprError> {
        let condition = self.binary(0)?;
        if !self.eat("?")? {
            return Ok(condition);
        }
        self.deeper()?;
        let then = self.ternary()?;
        if !self.eat(":")? {
            let (at, _) = self.peek()?.clone();
            return Err(ExprError::new(at, "Unexpected end of expression"));
        }
        let otherwise = self.ternary()?;
        self.depth -= 1;
        Ok(Expr {
            at: condition.at,
            kind: ExprKind::Ternary(Box::new(condition), Box::new(then), Box::new(otherwise)),
        })
    }

    fn binary(&mut self, min_level: u8) -> Result<Expr, ExprError> {
        let mut left = self.unary()?;
        // The levels this chain of operators adds, given back when it ends.
        let mut nested = 0;
        let result = loop {
            let (op, level) = match self.peek()? {
                (_, Token::Punct(p)) => match *p {
                    "||" => (BinaryOp::Or, 1),
                    "&&" => (BinaryOp::And, 2),
                    "==" | "===" => (BinaryOp::Eq, 3),
                    "!=" | "!==" => (BinaryOp::Ne, 3),
                    "<" => (BinaryOp::Lt, 4),
                    "<=" => (BinaryOp::Le, 4),
                    ">" => (BinaryOp::Gt, 4),
                    ">=" => (BinaryOp::Ge, 4),
                    "+" => (BinaryOp::Add, 5),
                    "-" => (BinaryOp::Sub, 5),
                    "*" => (BinaryOp::Mul, 6),
                    "/" => (BinaryOp::Div, 6),
                    "%" => (BinaryOp::Rem, 6),
                    _ => break Ok(left),
                },
                (_, Token::Name(name)) if name == "in" => {
                    let at = left.at;
                    break Err(ExprError::new(
                        at,
                        "Rule expressions may not contain 'in' operator.",
                    ));
                }
                _ => break Ok(left),
            };
            if level <= min_level {
                break Ok(left);
            }
            self.next()?;
            let right = self.binary(level)?;
            let associative = matches!(op, BinaryOp::And | BinaryOp::Or | BinaryOp::Add);
            if associative {
                if let ExprKind::Chain(chained, operands) = &mut left.kind {
                    if *chained == op {
                        operands.push(right);
                        continue;
                    }
                }
            }
            self.deeper()?;
            nested += 1;
            let at = left.at;
            left = Expr {
                at,
                kind: if associative {
                    ExprKind::Chain(op, vec![left, right])
                } else {
                    ExprKind::Binary(op, Box::new(left), Box::new(right))
                },
            };
        };
        self.depth -= nested;
        result
    }

    /// One level deeper, refused past the bound.
    fn deeper(&mut self) -> Result<(), ExprError> {
        self.depth += 1;
        self.deepest = self.deepest.max(self.depth);
        if self.depth > self.limit {
            return Err(ExprError::new(0, "Rule expression may not be empty."));
        }
        Ok(())
    }

    fn unary(&mut self) -> Result<Expr, ExprError> {
        self.depth += 1;
        self.deepest = self.deepest.max(self.depth);
        let operand = if self.depth > self.limit {
            Err(ExprError::new(0, "Rule expression may not be empty."))
        } else {
            self.unary_operand()
        };
        self.depth -= 1;
        operand
    }

    fn unary_operand(&mut self) -> Result<Expr, ExprError> {
        let (at, token) = self.peek()?.clone();
        match token {
            Token::Punct("!") => {
                self.next()?;
                let operand = self.unary()?;
                Ok(Expr {
                    at,
                    kind: ExprKind::Not(Box::new(operand)),
                })
            }
            Token::Punct("-") => {
                self.next()?;
                let operand = self.unary()?;
                Ok(Expr {
                    at,
                    kind: ExprKind::Neg(Box::new(operand)),
                })
            }
            Token::Punct(op @ ("--" | "++")) => {
                // The JavaScript reader parses a prefix decrement or increment; the rules
                // refuse it (review r8 M19).
                self.next()?;
                let operand = self.unary()?;
                Err(update_refusal(op, &operand, at))
            }
            Token::Name(name) if name == "typeof" => Err(ExprError::new(
                at,
                "Rule expressions may not contain 'typeof' operator.",
            )),
            _ => self.postfix(),
        }
    }

    fn postfix(&mut self) -> Result<Expr, ExprError> {
        let mut expr = self.primary()?;
        // Each step (member, index, call) is a level the evaluator recurses through.
        let mut steps = 0;
        loop {
            let step = matches!(self.peek()?, (_, Token::Punct("." | "[" | "(")));
            if step {
                self.deeper()?;
                steps += 1;
            }
            if self.eat(".")? {
                let (at, token) = self.next()?;
                let Token::Name(name) = token else {
                    return Err(ExprError::new(at, "missing name after . operator"));
                };
                expr = Expr {
                    at: expr.at,
                    kind: ExprKind::Member(Box::new(expr), name),
                };
            } else if self.eat("[")? {
                let index = self.ternary()?;
                self.close("]", "missing ] in index expression")?;
                let mut index = index;
                expr = match std::mem::replace(&mut index.kind, ExprKind::Null) {
                    ExprKind::Str(name) => Expr {
                        at: expr.at,
                        kind: ExprKind::Member(Box::new(expr), name),
                    },
                    kind => {
                        index.kind = kind;
                        Expr {
                            at: expr.at,
                            kind: ExprKind::Index(Box::new(expr), Box::new(index)),
                        }
                    }
                };
            } else if self.eat("(")? {
                let mut arguments = Vec::new();
                if !self.eat(")")? {
                    loop {
                        arguments.push(self.ternary()?);
                        if !self.eat(",")? {
                            self.close(")", "missing ) after argument list")?;
                            break;
                        }
                    }
                }
                expr = Expr {
                    at: expr.at,
                    kind: ExprKind::Call(Box::new(expr), arguments),
                };
            } else {
                self.depth -= steps;
                // A postfix decrement or increment, refused as there; after a call the
                // reader ends the statement instead, which the caller then refuses.
                if let (at, Token::Punct(op @ ("--" | "++"))) = self.peek()?.clone() {
                    if !matches!(expr.kind, ExprKind::Call(..)) {
                        return Err(update_refusal(op, &expr, at));
                    }
                }
                return Ok(expr);
            }
        }
    }

    fn primary(&mut self) -> Result<Expr, ExprError> {
        let (at, token) = self.next()?;
        let kind = match token {
            Token::Number(n) => ExprKind::Number(n),
            Token::Str(s) => ExprKind::Str(s),
            Token::Regex(pattern, flags) => {
                ExprKind::Regex(super::pattern::Pattern::new(pattern, flags))
            }
            Token::Name(name) => match name.as_str() {
                "true" => ExprKind::Bool(true),
                "false" => ExprKind::Bool(false),
                "null" => ExprKind::Null,
                _ => ExprKind::Name(name),
            },
            Token::Punct("(") => {
                let inner = self.ternary()?;
                self.close(")", "missing ) in parenthetical")?;
                return Ok(inner);
            }
            Token::Punct("[") => {
                let mut items = Vec::new();
                while !self.eat("]")? {
                    if let (end, Token::End) = self.peek()?.clone() {
                        return Err(ExprError::new(end, "missing ] after element list"));
                    }
                    items.push(self.ternary()?);
                    if !self.eat(",")? {
                        self.close("]", "missing ] after element list")?;
                        break;
                    }
                }
                ExprKind::Array(items)
            }
            Token::Punct("{" | "}") => {
                return Err(ExprError::new(at, "Unsupported javascript syntax."))
            }
            Token::End => return Err(ExprError::new(at, "Unexpected end of expression")),
            token @ Token::Punct(_) => {
                return Err(ExprError::new(self.rhino_end(at, &token), "syntax error"))
            }
        };
        Ok(Expr { at, kind })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The depth measured by recursion, to check the iterative measure against.
    fn recursive_depth(expr: &Expr) -> usize {
        1 + expr
            .kind
            .children()
            .into_iter()
            .map(recursive_depth)
            .max()
            .unwrap_or(0)
    }

    fn on_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(512 * 1024 * 1024)
            .spawn(f)
            .unwrap()
            .join()
            .unwrap()
    }

    /// A numeric expression built from every way an operand can nest, `n` times each.
    fn composed() -> impl Strategy<Value = String> {
        Just("1".to_owned()).prop_recursive(5, 64, 1, |inner| {
            (inner, 0usize..5, 0usize..400).prop_map(|(e, shape, n)| match shape {
                0 => format!("1 - ({e}){}", " - 0".repeat(n)),
                1 => format!("{}({e}){}", "-(".repeat(n % 50), ")".repeat(n % 50)),
                2 => format!(
                    "{}({e}){}",
                    "(true ? ".repeat(n % 100),
                    " : 1)".repeat(n % 100)
                ),
                3 => format!("root.child('a' + ({e})){}.val()", ".parent()".repeat(n / 2)),
                _ => format!(
                    "auth[({e}) == null ? 'a' : 'b']{} == null ? 1 : 2",
                    ".y".repeat(n)
                ),
            })
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Whatever the composition, an expression that parses is at most the bound deep,
        /// as the tree is measured, and the measure is the tree's real depth.
        #[test]
        fn a_parsed_expression_is_never_deeper_than_the_bound(text in composed()) {
            let rule = format!("{text} < 0");
            let measured = on_big_stack(move || {
                parse(&rule).ok().map(|expr| (expr.depth(), recursive_depth(&expr)))
            });
            if let Some((depth, real)) = measured {
                prop_assert_eq!(depth, real);
                prop_assert!(depth <= MAX_EXPRESSION_DEPTH, "{}", depth);
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// And conversely: an expression is refused exactly when its tree is deeper than the
        /// bound or the parser itself had to go deeper (groups and unary operators count there
        /// without being nodes).
        #[test]
        fn an_expression_within_the_bound_parses(text in composed()) {
            let rule = format!("{text} < 0");
            let (accepted, measured) = on_big_stack(move || {
                let accepted = parse(&rule).is_ok();
                let (tree, deepest) = parse_text(&rule, usize::MAX);
                (accepted, tree.ok().map(|tree| (tree.depth(), deepest)))
            });
            if let Some((depth, deepest)) = measured {
                prop_assert_eq!(
                    accepted,
                    depth <= MAX_EXPRESSION_DEPTH && deepest <= MAX_EXPRESSION_DEPTH,
                    "tree {} parser {}", depth, deepest
                );
            }
        }
    }

    #[test]
    fn a_deep_tree_is_dropped_without_recursion() {
        // Built by hand past any bound, it is dropped on an ordinary stack.
        let mut expr = Expr {
            at: 0,
            kind: ExprKind::Number(1.0),
        };
        for _ in 0..1_000_000 {
            expr = Expr {
                at: 0,
                kind: ExprKind::Not(Box::new(expr)),
            };
        }
        std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || drop(expr))
            .unwrap()
            .join()
            .unwrap();
    }
}
