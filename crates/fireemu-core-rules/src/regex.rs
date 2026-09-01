//! A small RE2-style regular expression engine for `string.matches()` / `string.replace()`.
//!
//! Supported syntax: literals, `.`, character classes (`[abc]`, `[^a-z]`, `\d \w \s` and
//! their negations, POSIX classes `[[:alpha:]]` and Unicode classes `\p{L}`, also inside
//! classes), anchors `^` `$`, capturing groups `( )` and non-capturing `(?: )`, the inline
//! flags `(?i)` / `(?s)` / `(?m)`, alternation `|`, quantifiers `* + ? {n} {n,} {n,m}` with
//! lazy variants, `\0` / zero-prefixed octal escapes, and `\xHH` / `\x{H...}` escapes. RE2
//! has no backreferences and no lookarounds, and neither does this: both are compile errors,
//! which is what the official runtime reports for the same patterns.
//!
//! Matching is backtracking over chars with a step budget, so pathological patterns fail
//! closed instead of hanging (`matches()` is a full match, as in the Rules language).
//! `replace()` expands `$0` / `$1` ... and `$$` in the replacement, as the official
//! runtime does.

use core::cell::{Cell, RefCell};
use core::fmt;

/// Compilation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegexError(pub String);

impl fmt::Display for RegexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid regular expression: {}", self.0)
    }
}

impl std::error::Error for RegexError {}

pub(crate) fn escape_diagnostic_text(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            escaped.extend(character.escape_debug());
        } else if character.is_ascii() {
            escaped.push(character);
        } else {
            escaped.extend(character.escape_default());
        }
    }
    escaped
}

/// Runtime failure while executing a compiled regular expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegexRuntimeError {
    /// The matcher consumed more backtracking steps than its safety limit permits.
    StepBudgetExceeded {
        /// Steps observed when the limit was detected.
        current: u64,
        /// Maximum permitted steps.
        maximum: u64,
    },
    /// Recursive matcher frames exceeded the stack-safety limit.
    DepthBudgetExceeded {
        /// Logical matcher depth observed when the limit was detected.
        current: u64,
        /// Maximum permitted logical matcher depth.
        maximum: u64,
    },
}

impl fmt::Display for RegexRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StepBudgetExceeded { current, maximum } => {
                write!(
                    f,
                    "regular expression step budget exceeded: {current} > {maximum}"
                )
            }
            Self::DepthBudgetExceeded { current, maximum } => {
                write!(
                    f,
                    "regular expression depth budget exceeded: {current} > {maximum}"
                )
            }
        }
    }
}

impl std::error::Error for RegexRuntimeError {}

/// Maximum backtracking steps per match attempt.
const STEP_BUDGET: u64 = 200_000;

/// Maximum simultaneously active matcher functions. This bounds native stack use even when
/// a linear match consumes a long subject without exhausting the step budget.
const DEPTH_BUDGET: u64 = 32;

#[derive(Debug, Clone, PartialEq)]
enum Node {
    Char(char),
    Any,
    Class {
        negated: bool,
        items: Vec<ClassItem>,
    },
    Start,
    End,
    /// `Some(i)`: the `i`-th capturing group (1-based); `None`: `(?: )`.
    Group(Option<usize>, Box<Node>),
    Alt(Vec<Node>),
    Seq(Vec<Node>),
    Repeat {
        node: Box<Node>,
        min: usize,
        max: Option<usize>,
        greedy: bool,
    },
}

#[derive(Debug, Clone, PartialEq)]
enum ClassItem {
    Range(char, char),
    Digit(bool),
    Word(bool),
    Space(bool),
    /// A POSIX class (`[:alpha:]`) or a Unicode class (`\p{L}`), with `false` for the
    /// negated form.
    Named(NamedClass, bool),
}

/// The named character classes both `[[:name:]]` and `\p{Name}` resolve to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamedClass {
    /// `[:alpha:]`, `\p{L}`, `\p{Alpha}`
    Alpha,
    /// `[:digit:]`, `\p{Nd}`
    Digit,
    /// `[:alnum:]`, `\p{Alnum}`
    Alnum,
    /// `[:space:]`, `\p{Zs}`, `\p{Space}`
    Space,
    /// `[:upper:]`, `\p{Lu}`
    Upper,
    /// `[:lower:]`, `\p{Ll}`
    Lower,
    /// `[:punct:]`, `\p{P}`
    Punct,
    /// `[:xdigit:]`
    HexDigit,
    /// `[:word:]`, `\p{N}` is folded into `Number`
    Word,
    /// `\p{N}`
    Number,
    /// `[:ascii:]`
    Ascii,
    /// `[:cntrl:]`
    Control,
    /// `[:print:]`
    Print,
    /// `[:graph:]`
    Graph,
    /// `[:blank:]`
    Blank,
}

impl NamedClass {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "alpha" | "Alpha" | "L" | "Letter" => Self::Alpha,
            "digit" | "Nd" => Self::Digit,
            "alnum" | "Alnum" => Self::Alnum,
            "space" | "Space" | "Zs" | "White_Space" => Self::Space,
            "upper" | "Upper" | "Lu" => Self::Upper,
            "lower" | "Lower" | "Ll" => Self::Lower,
            "punct" | "Punct" | "P" => Self::Punct,
            "xdigit" | "XDigit" => Self::HexDigit,
            "word" | "Word" => Self::Word,
            "N" | "Number" => Self::Number,
            "ascii" | "ASCII" => Self::Ascii,
            "cntrl" | "Cc" => Self::Control,
            "print" | "Print" => Self::Print,
            "graph" | "Graph" => Self::Graph,
            "blank" | "Blank" => Self::Blank,
            _ => return None,
        })
    }

    fn contains(self, c: char) -> bool {
        match self {
            Self::Alpha => c.is_alphabetic(),
            Self::Digit => c.is_numeric() && c.is_ascii_digit(),
            Self::Alnum => c.is_alphanumeric(),
            Self::Space => c.is_whitespace(),
            Self::Upper => c.is_uppercase(),
            Self::Lower => c.is_lowercase(),
            Self::Punct => c.is_ascii_punctuation(),
            Self::HexDigit => c.is_ascii_hexdigit(),
            Self::Word => c.is_alphanumeric() || c == '_',
            Self::Number => c.is_numeric(),
            Self::Ascii => c.is_ascii(),
            Self::Control => c.is_control(),
            Self::Print => !c.is_control(),
            Self::Graph => !c.is_control() && !c.is_whitespace(),
            Self::Blank => c == ' ' || c == '\t',
        }
    }
}

/// Pattern-wide flags set by an inline `(?flags)` group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Flags {
    /// `i`: ASCII and Unicode case folding on literals and classes.
    case_insensitive: bool,
    /// `s`: `.` also matches a newline.
    dot_all: bool,
    /// `m`: `^` and `$` match at line boundaries. Accepted and, because `matches()` is a
    /// whole-string match, without effect on the answer.
    multi_line: bool,
}

/// The span of each capturing group in the current match attempt, indexed 1-based.
type Captures = Vec<Option<(usize, usize)>>;

/// A compiled pattern.
#[derive(Debug, Clone, PartialEq)]
pub struct Regex {
    node: Node,
    flags: Flags,
    groups: usize,
}

struct Parser<'a> {
    chars: Vec<char>,
    pos: usize,
    flags: Flags,
    groups: usize,
    _src: &'a str,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        self.pos += 1;
        c
    }

    fn parse_alt(&mut self) -> Result<Node, RegexError> {
        let mut branches = vec![self.parse_seq()?];
        while self.peek() == Some('|') {
            self.pos += 1;
            branches.push(self.parse_seq()?);
        }
        Ok(if branches.len() == 1 {
            branches.remove(0)
        } else {
            Node::Alt(branches)
        })
    }

    fn parse_seq(&mut self) -> Result<Node, RegexError> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.parse_atom()?;
            items.push(self.parse_quantifier(atom)?);
        }
        Ok(Node::Seq(items))
    }

    fn parse_quantifier(&mut self, atom: Node) -> Result<Node, RegexError> {
        let (min, max) = match self.peek() {
            Some('*') => (0, None),
            Some('+') => (1, None),
            Some('?') => (0, Some(1)),
            Some('{') => {
                let save = self.pos;
                self.pos += 1;
                let mut digits = String::new();
                while let Some(d) = self.peek().filter(char::is_ascii_digit) {
                    digits.push(d);
                    self.pos += 1;
                }
                if digits.is_empty() {
                    self.pos = save;
                    return Ok(atom);
                }
                let min: usize = digits
                    .parse()
                    .map_err(|_| RegexError("bad repeat".into()))?;
                let max = if self.peek() == Some(',') {
                    self.pos += 1;
                    let mut more = String::new();
                    while let Some(d) = self.peek().filter(char::is_ascii_digit) {
                        more.push(d);
                        self.pos += 1;
                    }
                    if more.is_empty() {
                        None
                    } else {
                        Some(more.parse().map_err(|_| RegexError("bad repeat".into()))?)
                    }
                } else {
                    Some(min)
                };
                if self.peek() != Some('}') {
                    return Err(RegexError("unterminated repeat".into()));
                }
                if max.is_some_and(|m| m < min) || min > 1000 || max.is_some_and(|m| m > 1000) {
                    return Err(RegexError("repeat out of range".into()));
                }
                (min, max)
            }
            _ => return Ok(atom),
        };
        self.pos += 1;
        let greedy = if self.peek() == Some('?') {
            self.pos += 1;
            false
        } else {
            true
        };
        Ok(Node::Repeat {
            node: Box::new(atom),
            min,
            max,
            greedy,
        })
    }

    fn parse_atom(&mut self) -> Result<Node, RegexError> {
        let c = self
            .bump()
            .ok_or_else(|| RegexError("unexpected end".into()))?;
        Ok(match c {
            '.' => Node::Any,
            '^' => Node::Start,
            '$' => Node::End,
            '(' => {
                let mut index = Some(0);
                if self.peek() == Some('?') {
                    self.pos += 1;
                    index = None;
                    match self.peek() {
                        Some(':') => {
                            self.pos += 1;
                        }
                        // RE2 has neither lookaround nor named backreferences.
                        Some('=' | '!' | '<' | '>' | 'P') => {
                            return Err(RegexError("lookarounds are not supported".into()))
                        }
                        Some(_) => {
                            // `(?flags)` sets them for the pattern, `(?flags:...)` opens a
                            // non-capturing group. fireemu applies either to the whole
                            // pattern, which is what every practical Rules pattern means.
                            let mut negate = false;
                            loop {
                                match self.bump() {
                                    Some('i') => self.flags.case_insensitive = !negate,
                                    Some('s') => self.flags.dot_all = !negate,
                                    Some('m') => self.flags.multi_line = !negate,
                                    Some('U') => {}
                                    Some('-') => negate = true,
                                    Some(':') => break,
                                    Some(')') => {
                                        // `(?i)` on its own: no group, no atom.
                                        return Ok(Node::Seq(Vec::new()));
                                    }
                                    _ => return Err(RegexError("bad group flags".into())),
                                }
                            }
                        }
                        None => return Err(RegexError("bad group".into())),
                    }
                }
                if index.is_some() {
                    self.groups += 1;
                    index = Some(self.groups);
                }
                let inner = self.parse_alt()?;
                if self.bump() != Some(')') {
                    return Err(RegexError("unterminated group".into()));
                }
                Node::Group(index, Box::new(inner))
            }
            ')' => return Err(RegexError("unmatched )".into())),
            '[' => self.parse_class()?,
            '\\' => self.parse_escape(false)?,
            '*' | '+' | '?' => return Err(RegexError(format!("nothing to repeat before {c}"))),
            other => Node::Char(other),
        })
    }

    fn parse_escape(&mut self, in_class: bool) -> Result<Node, RegexError> {
        let e = self
            .bump()
            .ok_or_else(|| RegexError("dangling escape".into()))?;
        Ok(match e {
            'd' => Node::Class {
                negated: false,
                items: vec![ClassItem::Digit(true)],
            },
            'D' => Node::Class {
                negated: false,
                items: vec![ClassItem::Digit(false)],
            },
            'w' => Node::Class {
                negated: false,
                items: vec![ClassItem::Word(true)],
            },
            'W' => Node::Class {
                negated: false,
                items: vec![ClassItem::Word(false)],
            },
            's' => Node::Class {
                negated: false,
                items: vec![ClassItem::Space(true)],
            },
            'S' => Node::Class {
                negated: false,
                items: vec![ClassItem::Space(false)],
            },
            'n' => Node::Char('\n'),
            't' => Node::Char('\t'),
            'r' => Node::Char('\r'),
            'f' => Node::Char('\u{c}'),
            'v' => Node::Char('\u{b}'),
            'a' => Node::Char('\u{7}'),
            'x' => Node::Char(self.parse_hex_escape()?),
            'p' | 'P' => Node::Class {
                negated: false,
                items: vec![ClassItem::Named(self.parse_unicode_class()?, e == 'p')],
            },
            '0' => Node::Char(self.parse_zero_prefixed_octal_escape()?),
            // A digit after a backslash is a backreference, which RE2 does not have.
            '1'..='9' => return Err(RegexError("backreferences are not supported".into())),
            'b' | 'B' | 'A' | 'z' => {
                if in_class {
                    return Err(RegexError("invalid escape in class".into()));
                }
                return Err(RegexError("word boundaries are not supported".into()));
            }
            other if other.is_ascii_punctuation() || other == ' ' => Node::Char(other),
            other => return Err(RegexError(format!("unknown escape \\{other}"))),
        })
    }

    /// `\0`, followed by up to two octal digits. A following `8` or `9` begins the next
    /// literal atom, as in the official RE2 runtime.
    fn parse_zero_prefixed_octal_escape(&mut self) -> Result<char, RegexError> {
        let mut value = 0;
        for _ in 0..2 {
            let Some(digit) = self
                .peek()
                .filter(|character| matches!(character, '0'..='7'))
            else {
                break;
            };
            let _ = self.bump();
            value = value * 8 + digit.to_digit(8).unwrap_or(0);
        }
        char::from_u32(value).ok_or_else(|| RegexError("octal escape names no character".into()))
    }

    /// `\xHH` or `\x{H...}`.
    fn parse_hex_escape(&mut self) -> Result<char, RegexError> {
        let mut digits = String::new();
        if self.peek() == Some('{') {
            self.pos += 1;
            while let Some(c) = self.peek().filter(char::is_ascii_hexdigit) {
                digits.push(c);
                self.pos += 1;
            }
            if self.bump() != Some('}') {
                return Err(RegexError("unterminated \\x{...}".into()));
            }
        } else {
            for _ in 0..2 {
                match self.peek().filter(char::is_ascii_hexdigit) {
                    Some(c) => {
                        digits.push(c);
                        self.pos += 1;
                    }
                    None => return Err(RegexError("\\x needs two hex digits".into())),
                }
            }
        }
        u32::from_str_radix(&digits, 16)
            .ok()
            .and_then(char::from_u32)
            .ok_or_else(|| RegexError("\\x names no character".into()))
    }

    /// `\p{Name}` or the one-letter `\pL`.
    fn parse_unicode_class(&mut self) -> Result<NamedClass, RegexError> {
        let mut name = String::new();
        if self.peek() == Some('{') {
            self.pos += 1;
            while let Some(c) = self.peek().filter(|c| *c != '}') {
                name.push(c);
                self.pos += 1;
            }
            if self.bump() != Some('}') {
                return Err(RegexError("unterminated \\p{...}".into()));
            }
        } else {
            name.push(
                self.bump()
                    .ok_or_else(|| RegexError("dangling \\p".into()))?,
            );
        }
        NamedClass::parse(&name).ok_or_else(|| RegexError(format!("unknown class \\p{{{name}}}")))
    }

    fn parse_class(&mut self) -> Result<Node, RegexError> {
        let negated = if self.peek() == Some('^') {
            self.pos += 1;
            true
        } else {
            false
        };
        let mut items = Vec::new();
        let mut first = true;
        loop {
            // `[:name:]` is only a POSIX class inside a class, and only in that exact form.
            if self.peek() == Some('[') && self.chars.get(self.pos + 1) == Some(&':') {
                let save = self.pos;
                self.pos += 2;
                let negated_item = if self.peek() == Some('^') {
                    self.pos += 1;
                    true
                } else {
                    false
                };
                let mut name = String::new();
                while let Some(c) = self.peek().filter(char::is_ascii_alphanumeric) {
                    name.push(c);
                    self.pos += 1;
                }
                if self.peek() == Some(':') && self.chars.get(self.pos + 1) == Some(&']') {
                    self.pos += 2;
                    let class = NamedClass::parse(&name)
                        .ok_or_else(|| RegexError(format!("unknown POSIX class [:{name}:]")))?;
                    items.push(ClassItem::Named(class, !negated_item));
                    first = false;
                    continue;
                }
                self.pos = save;
            }
            let c = self
                .bump()
                .ok_or_else(|| RegexError("unterminated class".into()))?;
            if c == ']' && !first {
                break;
            }
            first = false;
            let lo = if c == '\\' {
                match self.parse_escape(true)? {
                    Node::Char(ch) => ch,
                    Node::Class { items: sub, .. } => {
                        items.extend(sub);
                        continue;
                    }
                    _ => return Err(RegexError("bad class escape".into())),
                }
            } else {
                c
            };
            if self.peek() == Some('-') && self.chars.get(self.pos + 1).is_some_and(|n| *n != ']') {
                self.pos += 1;
                let hi = self
                    .bump()
                    .ok_or_else(|| RegexError("unterminated range".into()))?;
                let hi = if hi == '\\' {
                    match self.parse_escape(true)? {
                        Node::Char(ch) => ch,
                        _ => return Err(RegexError("bad range end".into())),
                    }
                } else {
                    hi
                };
                if hi < lo {
                    return Err(RegexError("invalid range".into()));
                }
                items.push(ClassItem::Range(lo, hi));
            } else {
                items.push(ClassItem::Range(lo, lo));
            }
        }
        Ok(Node::Class { negated, items })
    }
}

impl Regex {
    /// Compiles a pattern.
    pub fn new(pattern: &str) -> Result<Self, RegexError> {
        if pattern.len() > 2048 {
            return Err(RegexError("pattern too long".into()));
        }
        let mut p = Parser {
            chars: pattern.chars().collect(),
            pos: 0,
            flags: Flags::default(),
            groups: 0,
            _src: pattern,
        };
        let node = p.parse_alt()?;
        if p.pos < p.chars.len() {
            return Err(RegexError("unexpected )".into()));
        }
        Ok(Self {
            node,
            flags: p.flags,
            groups: p.groups,
        })
    }

    /// Whether the whole of `text` matches (Rules `matches()` semantics).
    pub fn is_full_match(&self, text: &str) -> Result<bool, RegexRuntimeError> {
        let chars: Vec<char> = text.chars().collect();
        let steps = Cell::new(0);
        let depth = Cell::new(0);
        let caps = RefCell::new(vec![None; self.groups + 1]);
        let ctx = MatchContext {
            chars: &chars,
            steps: &steps,
            depth: &depth,
            caps: &caps,
            flags: self.flags,
        };
        match_node(&self.node, &ctx, 0, &mut |end| Ok(end == chars.len()))
    }

    /// Replaces every non-overlapping match, expanding `$0` / `$1` ... and `$$` in
    /// `replacement`, as the official runtime's `replace()` does.
    pub fn replace_all(&self, text: &str, replacement: &str) -> Result<String, RegexRuntimeError> {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::new();
        let mut i = 0;
        let steps = Cell::new(0);
        let depth = Cell::new(0);
        while i <= chars.len() {
            let caps = RefCell::new(vec![None; self.groups + 1]);
            let ctx = MatchContext {
                chars: &chars,
                steps: &steps,
                depth: &depth,
                caps: &caps,
                flags: self.flags,
            };
            let mut best: Option<(usize, Captures)> = None;
            let found = match_node(&self.node, &ctx, i, &mut |end| {
                best = Some((end, caps.borrow().clone()));
                Ok(true)
            })?;
            match (found, best) {
                (true, Some((end, groups))) if end > i => {
                    out.push_str(&expand(replacement, &chars, i, end, &groups));
                    i = end;
                }
                (true, Some((end, groups))) => {
                    // Empty match: emit the replacement and advance one char.
                    out.push_str(&expand(replacement, &chars, i, end, &groups));
                    if i < chars.len() {
                        out.push(chars[i]);
                    }
                    i += 1;
                }
                _ => {
                    if i < chars.len() {
                        out.push(chars[i]);
                    }
                    i += 1;
                }
            }
        }
        Ok(out)
    }
}

/// Expands `$0` (the whole match), `$1` .. `$9` (groups) and `$$` (a literal `$`).
fn expand(
    replacement: &str,
    chars: &[char],
    start: usize,
    end: usize,
    groups: &[Option<(usize, usize)>],
) -> String {
    let slice = |lo: usize, hi: usize| chars[lo..hi].iter().collect::<String>();
    let mut out = String::new();
    let mut it = replacement.chars().peekable();
    while let Some(c) = it.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match it.peek().copied() {
            Some('$') => {
                it.next();
                out.push('$');
            }
            Some(d) if d.is_ascii_digit() => {
                let mut n = 0usize;
                while let Some(d) = it.peek().copied().filter(char::is_ascii_digit) {
                    n = n * 10 + (d as usize - '0' as usize);
                    it.next();
                }
                if n == 0 {
                    out.push_str(&slice(start, end));
                } else if let Some(Some((lo, hi))) = groups.get(n) {
                    out.push_str(&slice(*lo, *hi));
                }
            }
            _ => out.push('$'),
        }
    }
    out
}

/// Everything one match attempt needs: the subject, the step budget, the capture slots and
/// the pattern-wide flags.
struct MatchContext<'a> {
    chars: &'a [char],
    steps: &'a Cell<u64>,
    depth: &'a Cell<u64>,
    caps: &'a RefCell<Captures>,
    flags: Flags,
}

type MatchResult = Result<bool, RegexRuntimeError>;

struct MatchDepthGuard<'a>(&'a Cell<u64>);

impl Drop for MatchDepthGuard<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

fn enter_match<'a>(ctx: &MatchContext<'a>) -> Result<MatchDepthGuard<'a>, RegexRuntimeError> {
    let current = ctx.depth.get().saturating_add(1);
    if current > DEPTH_BUDGET {
        return Err(RegexRuntimeError::DepthBudgetExceeded {
            current,
            maximum: DEPTH_BUDGET,
        });
    }
    ctx.depth.set(current);
    Ok(MatchDepthGuard(ctx.depth))
}

fn charge_step(ctx: &MatchContext<'_>) -> Result<(), RegexRuntimeError> {
    let current = ctx.steps.get().saturating_add(1);
    ctx.steps.set(current);
    if current > STEP_BUDGET {
        return Err(RegexRuntimeError::StepBudgetExceeded {
            current,
            maximum: STEP_BUDGET,
        });
    }
    Ok(())
}

fn class_matches(negated: bool, items: &[ClassItem], c: char, flags: Flags) -> bool {
    let hit = |c: char| {
        items.iter().any(|item| match item {
            ClassItem::Range(lo, hi) => (*lo..=*hi).contains(&c),
            ClassItem::Digit(yes) => c.is_ascii_digit() == *yes,
            ClassItem::Word(yes) => (c.is_ascii_alphanumeric() || c == '_') == *yes,
            ClassItem::Space(yes) => {
                matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0B' | '\x0C') == *yes
            }
            ClassItem::Named(class, yes) => class.contains(c) == *yes,
        })
    };
    let found = if flags.case_insensitive {
        hit(c) || c.to_lowercase().any(hit) || c.to_uppercase().any(hit)
    } else {
        hit(c)
    };
    found != negated
}

fn chars_equal(a: char, b: char, flags: Flags) -> bool {
    a == b
        || (flags.case_insensitive
            && a.to_lowercase().eq(b.to_lowercase())
            && a.to_lowercase().count() == b.to_lowercase().count())
}

fn atomic_end(node: &Node, ctx: &MatchContext<'_>, pos: usize) -> Option<usize> {
    match node {
        Node::Char(expected) => ctx
            .chars
            .get(pos)
            .is_some_and(|actual| chars_equal(*actual, *expected, ctx.flags))
            .then_some(pos + 1),
        Node::Any => ctx
            .chars
            .get(pos)
            .is_some_and(|character| ctx.flags.dot_all || *character != '\n')
            .then_some(pos + 1),
        Node::Class { negated, items } => ctx
            .chars
            .get(pos)
            .is_some_and(|character| class_matches(*negated, items, *character, ctx.flags))
            .then_some(pos + 1),
        _ => None,
    }
}

fn is_deterministic(node: &Node) -> bool {
    let mut pending = vec![node];
    while let Some(node) = pending.pop() {
        match node {
            Node::Char(_) | Node::Any | Node::Class { .. } | Node::Start | Node::End => {}
            Node::Group(_, inner) => pending.push(inner),
            Node::Seq(items) => pending.extend(items),
            Node::Alt(_) | Node::Repeat { .. } => return false,
        }
    }
    true
}

enum DeterministicTask<'a> {
    Match(&'a Node),
    CloseGroup { index: usize, start: usize },
}

fn deterministic_end(
    node: &Node,
    ctx: &MatchContext<'_>,
    pos: usize,
) -> Result<Option<usize>, RegexRuntimeError> {
    let original_captures = ctx.caps.borrow().clone();
    let mut end = pos;
    let mut pending = vec![DeterministicTask::Match(node)];
    while let Some(task) = pending.pop() {
        match task {
            DeterministicTask::Match(node) => {
                charge_step(ctx)?;
                match node {
                    Node::Char(_) | Node::Any | Node::Class { .. } => {
                        let Some(next) = atomic_end(node, ctx, end) else {
                            *ctx.caps.borrow_mut() = original_captures;
                            return Ok(None);
                        };
                        end = next;
                    }
                    Node::Start if end == 0 => {}
                    Node::End if end == ctx.chars.len() => {}
                    Node::Start | Node::End => {
                        *ctx.caps.borrow_mut() = original_captures;
                        return Ok(None);
                    }
                    Node::Group(index, inner) => {
                        if let Some(index) = index {
                            pending.push(DeterministicTask::CloseGroup {
                                index: *index,
                                start: end,
                            });
                        }
                        pending.push(DeterministicTask::Match(inner));
                    }
                    Node::Seq(items) => {
                        pending.extend(items.iter().rev().map(DeterministicTask::Match));
                    }
                    Node::Alt(_) | Node::Repeat { .. } => {
                        unreachable!("deterministic nodes contain no alternatives or repeats")
                    }
                }
            }
            DeterministicTask::CloseGroup { index, start } => {
                if let Some(slot) = ctx.caps.borrow_mut().get_mut(index) {
                    *slot = Some((start, end));
                }
            }
        }
    }
    Ok(Some(end))
}

/// Backtracking matcher in continuation-passing style: `k(end)` is called for every way
/// `node` can match starting at `pos`; returns `true` as soon as `k` accepts.
fn match_node(
    node: &Node,
    ctx: &MatchContext,
    pos: usize,
    k: &mut dyn FnMut(usize) -> MatchResult,
) -> MatchResult {
    let _depth = enter_match(ctx)?;
    charge_step(ctx)?;
    match node {
        Node::Char(_) | Node::Any | Node::Class { .. } => {
            atomic_end(node, ctx, pos).map_or_else(|| Ok(false), k)
        }
        Node::Start => {
            if pos == 0 {
                k(pos)
            } else {
                Ok(false)
            }
        }
        Node::End => {
            if pos == ctx.chars.len() {
                k(pos)
            } else {
                Ok(false)
            }
        }
        Node::Group(None, inner) => match_node(inner, ctx, pos, k),
        Node::Group(Some(index), inner) => {
            let index = *index;
            match_node(inner, ctx, pos, &mut |end| {
                let previous = ctx.caps.borrow().get(index).copied().flatten();
                if let Some(slot) = ctx.caps.borrow_mut().get_mut(index) {
                    *slot = Some((pos, end));
                }
                match k(end) {
                    Ok(true) => return Ok(true),
                    Ok(false) => {}
                    Err(error) => return Err(error),
                }
                if let Some(slot) = ctx.caps.borrow_mut().get_mut(index) {
                    *slot = previous;
                }
                Ok(false)
            })
        }
        Node::Alt(branches) => {
            for branch in branches {
                if match_node(branch, ctx, pos, k)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Node::Seq(items) => match_seq(items, ctx, pos, k),
        Node::Repeat {
            node,
            min,
            max,
            greedy,
        } => match_repeat(node, *min, *max, *greedy, ctx, pos, 0, k),
    }
}

fn match_seq(
    items: &[Node],
    ctx: &MatchContext,
    pos: usize,
    k: &mut dyn FnMut(usize) -> MatchResult,
) -> MatchResult {
    let _depth = enter_match(ctx)?;
    let original_captures = ctx.caps.borrow().clone();
    let mut remaining = items;
    let mut end = pos;
    while let Some((first, rest)) = remaining.split_first() {
        if !is_deterministic(first) {
            break;
        }
        let next = match deterministic_end(first, ctx, end) {
            Ok(Some(next)) => next,
            Ok(None) => {
                *ctx.caps.borrow_mut() = original_captures;
                return Ok(false);
            }
            Err(error) => {
                *ctx.caps.borrow_mut() = original_captures;
                return Err(error);
            }
        };
        end = next;
        remaining = rest;
    }
    let result = match remaining.split_first() {
        None => k(end),
        Some((first, rest)) => {
            match_node(first, ctx, end, &mut |next| match_seq(rest, ctx, next, k))
        }
    };
    if !matches!(result, Ok(true)) {
        *ctx.caps.borrow_mut() = original_captures;
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn match_repeat(
    node: &Node,
    min: usize,
    max: Option<usize>,
    greedy: bool,
    ctx: &MatchContext,
    pos: usize,
    count: usize,
    k: &mut dyn FnMut(usize) -> MatchResult,
) -> MatchResult {
    let _depth = enter_match(ctx)?;
    charge_step(ctx)?;
    if is_deterministic(node) {
        return match_deterministic_repeat(node, min, max, greedy, ctx, pos, count, k);
    }
    let can_stop = count >= min;
    let can_more = max.is_none_or(|m| count < m);
    let try_more = |k: &mut dyn FnMut(usize) -> MatchResult| -> MatchResult {
        if can_more {
            match_node(node, ctx, pos, &mut |end| {
                // An empty iteration would loop forever; require progress.
                if end > pos {
                    match_repeat(node, min, max, greedy, ctx, end, count + 1, k)
                } else {
                    Ok(false)
                }
            })
        } else {
            Ok(false)
        }
    };
    if greedy {
        if try_more(k)? {
            Ok(true)
        } else if can_stop {
            k(pos)
        } else {
            Ok(false)
        }
    } else {
        if can_stop && k(pos)? {
            Ok(true)
        } else {
            try_more(k)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn match_deterministic_repeat(
    node: &Node,
    min: usize,
    max: Option<usize>,
    greedy: bool,
    ctx: &MatchContext,
    pos: usize,
    count: usize,
    k: &mut dyn FnMut(usize) -> MatchResult,
) -> MatchResult {
    let original_captures = ctx.caps.borrow().clone();
    if !greedy {
        let mut end = pos;
        let mut current_count = count;
        loop {
            let candidate_captures = ctx.caps.borrow().clone();
            if current_count >= min {
                match k(end) {
                    Ok(true) => return Ok(true),
                    Ok(false) => *ctx.caps.borrow_mut() = candidate_captures,
                    Err(error) => return Err(error),
                }
            }
            if max.is_some_and(|maximum| current_count >= maximum) {
                break;
            }
            let Some(next) = deterministic_end(node, ctx, end)? else {
                break;
            };
            if next <= end {
                break;
            }
            end = next;
            current_count += 1;
        }
        *ctx.caps.borrow_mut() = original_captures;
        return Ok(false);
    }

    let mut candidates = vec![(pos, original_captures.clone())];
    while max.is_none_or(|maximum| count + candidates.len() - 1 < maximum) {
        let current = candidates.last().map_or(pos, |(end, _)| *end);
        let Some(end) = deterministic_end(node, ctx, current)? else {
            break;
        };
        if end <= current {
            break;
        }
        candidates.push((end, ctx.caps.borrow().clone()));
    }
    for (added, (end, captures)) in candidates.into_iter().enumerate().rev() {
        if count + added < min {
            continue;
        }
        *ctx.caps.borrow_mut() = captures;
        if k(end)? {
            return Ok(true);
        }
    }
    *ctx.caps.borrow_mut() = original_captures;
    Ok(false)
}
