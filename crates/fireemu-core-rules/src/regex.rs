//! A small RE2-style regular expression engine for `string.matches()` / `string.replace()`.
//!
//! Supported syntax: literals, `.`, character classes (`[abc]`, `[^a-z]`, `\d \w \s` and
//! their negations, also inside classes), anchors `^` `$`, groups `( )` and non-capturing
//! `(?: )`, alternation `|`, quantifiers `* + ? {n} {n,} {n,m}` with lazy variants, escapes.
//! Matching is backtracking over chars with a step budget, so pathological patterns fail
//! closed instead of hanging (`matches()` is a full match, as in the Rules language).

use core::cell::Cell;
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

/// Maximum backtracking steps per match attempt.
const STEP_BUDGET: usize = 200_000;

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
    Group(Box<Node>),
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
}

/// A compiled pattern.
#[derive(Debug, Clone, PartialEq)]
pub struct Regex {
    node: Node,
}

struct Parser<'a> {
    chars: Vec<char>,
    pos: usize,
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
                if self.peek() == Some('?') {
                    self.pos += 1;
                    match self.bump() {
                        Some(':') => {}
                        Some('i' | 'm' | 's' | 'U' | 'P' | '<' | '=' | '!') => {
                            return Err(RegexError(
                                "group flags and lookarounds are not supported".into(),
                            ))
                        }
                        _ => return Err(RegexError("bad group".into())),
                    }
                }
                let inner = self.parse_alt()?;
                if self.bump() != Some(')') {
                    return Err(RegexError("unterminated group".into()));
                }
                Node::Group(Box::new(inner))
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
            _src: pattern,
        };
        let node = p.parse_alt()?;
        if p.pos < p.chars.len() {
            return Err(RegexError("unexpected )".into()));
        }
        Ok(Self { node })
    }

    /// Whether the whole of `text` matches (Rules `matches()` semantics).
    #[must_use]
    pub fn is_full_match(&self, text: &str) -> bool {
        let chars: Vec<char> = text.chars().collect();
        let steps = Cell::new(0usize);
        match_node(&self.node, &chars, 0, &steps, &mut |end| end == chars.len())
    }

    /// Replaces every non-overlapping match with `replacement` (a literal).
    #[must_use]
    pub fn replace_all(&self, text: &str, replacement: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let mut out = String::new();
        let mut i = 0;
        while i <= chars.len() {
            let steps = Cell::new(0usize);
            let mut best: Option<usize> = None;
            let found = match_node(&self.node, &chars, i, &steps, &mut |end| {
                best = Some(end);
                true
            });
            match (found, best) {
                (true, Some(end)) if end > i => {
                    out.push_str(replacement);
                    i = end;
                }
                (true, Some(_)) => {
                    // Empty match: emit the replacement and advance one char.
                    out.push_str(replacement);
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
        out
    }
}

fn class_matches(negated: bool, items: &[ClassItem], c: char) -> bool {
    let hit = items.iter().any(|item| match item {
        ClassItem::Range(lo, hi) => (*lo..=*hi).contains(&c),
        ClassItem::Digit(yes) => c.is_ascii_digit() == *yes,
        ClassItem::Word(yes) => (c.is_ascii_alphanumeric() || c == '_') == *yes,
        ClassItem::Space(yes) => matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0B' | '\x0C') == *yes,
    });
    hit != negated
}

/// Backtracking matcher in continuation-passing style: `k(end)` is called for every way
/// `node` can match starting at `pos`; returns `true` as soon as `k` accepts.
fn match_node(
    node: &Node,
    chars: &[char],
    pos: usize,
    steps: &Cell<usize>,
    k: &mut dyn FnMut(usize) -> bool,
) -> bool {
    steps.set(steps.get() + 1);
    if steps.get() > STEP_BUDGET {
        return false;
    }
    match node {
        Node::Char(c) => chars.get(pos) == Some(c) && k(pos + 1),
        Node::Any => chars.get(pos).is_some_and(|c| *c != '\n') && k(pos + 1),
        Node::Class { negated, items } => {
            chars
                .get(pos)
                .is_some_and(|c| class_matches(*negated, items, *c))
                && k(pos + 1)
        }
        Node::Start => pos == 0 && k(pos),
        Node::End => pos == chars.len() && k(pos),
        Node::Group(inner) => match_node(inner, chars, pos, steps, k),
        Node::Alt(branches) => branches.iter().any(|b| match_node(b, chars, pos, steps, k)),
        Node::Seq(items) => match_seq(items, chars, pos, steps, k),
        Node::Repeat {
            node,
            min,
            max,
            greedy,
        } => match_repeat(node, *min, *max, *greedy, chars, pos, 0, steps, k),
    }
}

fn match_seq(
    items: &[Node],
    chars: &[char],
    pos: usize,
    steps: &Cell<usize>,
    k: &mut dyn FnMut(usize) -> bool,
) -> bool {
    match items.split_first() {
        None => k(pos),
        Some((first, rest)) => match_node(first, chars, pos, steps, &mut |end| {
            match_seq(rest, chars, end, steps, k)
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn match_repeat(
    node: &Node,
    min: usize,
    max: Option<usize>,
    greedy: bool,
    chars: &[char],
    pos: usize,
    count: usize,
    steps: &Cell<usize>,
    k: &mut dyn FnMut(usize) -> bool,
) -> bool {
    steps.set(steps.get() + 1);
    if steps.get() > STEP_BUDGET {
        return false;
    }
    let can_stop = count >= min;
    let can_more = max.is_none_or(|m| count < m);
    let try_more = |k: &mut dyn FnMut(usize) -> bool| -> bool {
        can_more
            && match_node(node, chars, pos, steps, &mut |end| {
                // An empty iteration would loop forever; require progress.
                end > pos && match_repeat(node, min, max, greedy, chars, end, count + 1, steps, k)
            })
    };
    if greedy {
        try_more(k) || (can_stop && k(pos))
    } else {
        (can_stop && k(pos)) || try_more(k)
    }
}
