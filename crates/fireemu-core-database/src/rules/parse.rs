//! The expression language of Realtime Database rules: tokens and syntax.
//!
//! It is a small subset of JavaScript expressions: literals (numbers, strings, `true`,
//! `false`, `null`, regular expressions), names, member access (`a.b`, `a['b']`), calls,
//! the unary operators `!` and `-`, the binary arithmetic, comparison and logical
//! operators, and `?:`. An array literal is read only so that `hasChildren([...])` can take
//! one. Positions are character offsets into the expression text; the caller maps them to
//! the line and column of the rules file.

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

const PUNCTUATION: [&str; 26] = [
    "===", "!==", "==", "!=", "<=", ">=", "&&", "||", "(", ")", "[", "]", "{", "}", ".", ",", ";",
    "?", ":", "!", "+", "-", "*", "/", "%", "<",
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

/// An expression, with the character offset where it starts.
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

struct Lexer<'a> {
    chars: &'a [char],
    at: usize,
}

impl Lexer<'_> {
    fn skip_space(&mut self) {
        while self.at < self.chars.len() && self.chars[self.at].is_whitespace() {
            self.at += 1;
        }
    }

    /// The next token and where it starts. `regex_allowed` is true where an operand is
    /// expected, so a `/` starts a regular expression there and divides elsewhere.
    fn next(&mut self, regex_allowed: bool) -> Result<(usize, Token), ExprError> {
        self.skip_space();
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
        if c.is_alphabetic() || c == '_' || c == '$' {
            let mut name = String::new();
            while let Some(&c) = self.chars.get(self.at) {
                if c.is_alphanumeric() || c == '_' || c == '$' {
                    name.push(c);
                    self.at += 1;
                } else {
                    break;
                }
            }
            return Ok((start, Token::Name(name)));
        }
        for punct in PUNCTUATION.iter().chain(&[">"]) {
            let len = punct.chars().count();
            if self.chars.len() >= self.at + len
                && self.chars[self.at..self.at + len]
                    .iter()
                    .copied()
                    .eq(punct.chars())
            {
                self.at += len;
                return Ok((start, Token::Punct(punct)));
            }
        }
        Err(ExprError::new(start, "Unsupported javascript syntax."))
    }

    fn peek_digit(&self, ahead: usize) -> bool {
        self.chars
            .get(self.at + ahead)
            .is_some_and(char::is_ascii_digit)
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
        let digits = |lexer: &mut Self, radix: u32| {
            let from = lexer.at;
            while lexer.chars.get(lexer.at).is_some_and(|c| c.is_digit(radix)) {
                lexer.at += 1;
            }
            lexer.chars[from..lexer.at].iter().collect::<String>()
        };
        if self.chars[self.at] == '0' {
            if matches!(self.chars.get(self.at + 1), Some('x' | 'X')) {
                self.at += 2;
                let hex = digits(self, 16);
                #[allow(clippy::cast_precision_loss)]
                return u64::from_str_radix(&hex, 16)
                    .map(|n| (start, Token::Number(n as f64)))
                    .map_err(|_| ExprError::new(start, "Unsupported javascript syntax."));
            }
            let mut end = self.at + 1;
            while self.chars.get(end).is_some_and(char::is_ascii_digit) {
                end += 1;
            }
            let octal: String = self.chars[self.at + 1..end].iter().collect();
            if !octal.is_empty() && octal.chars().all(|c| c.is_digit(8)) {
                self.at = end;
                #[allow(clippy::cast_precision_loss)]
                return u64::from_str_radix(&octal, 8)
                    .map(|n| (start, Token::Number(n as f64)))
                    .map_err(|_| ExprError::new(start, "Unsupported javascript syntax."));
            }
        }
        let mut text = digits(self, 10);
        if self.chars.get(self.at) == Some(&'.') {
            self.at += 1;
            text.push('.');
            text.push_str(&digits(self, 10));
        }
        if matches!(self.chars.get(self.at), Some('e' | 'E')) {
            self.at += 1;
            text.push('e');
            if let Some(&sign @ ('+' | '-')) = self.chars.get(self.at) {
                self.at += 1;
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

    fn string(&mut self, start: usize, quote: char) -> Result<(usize, Token), ExprError> {
        self.at += 1;
        let mut text = String::new();
        loop {
            let Some(&c) = self.chars.get(self.at) else {
                return Err(ExprError::new(start, "Unterminated string literal."));
            };
            self.at += 1;
            if c == quote {
                return Ok((start, Token::Str(text)));
            }
            if c == '\\' {
                let Some(&escaped) = self.chars.get(self.at) else {
                    return Err(ExprError::new(start, "Unterminated string literal."));
                };
                self.at += 1;
                text.push(match escaped {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    '0' => '\0',
                    other => other,
                });
            } else {
                text.push(c);
            }
        }
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
            match c {
                '\\' => {
                    pattern.push(c);
                    let Some(&next) = self.chars.get(self.at) else {
                        return Err(ExprError::new(
                            self.chars.len(),
                            "unterminated regular expression literal",
                        ));
                    };
                    pattern.push(next);
                    self.at += 1;
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
        let mut flags = String::new();
        while let Some(&c) = self.chars.get(self.at) {
            if c.is_ascii_alphabetic() {
                flags.push(c);
                self.at += 1;
            } else {
                break;
            }
        }
        check_anchors(&pattern).map_err(|message| ExprError::new(start, message))?;
        check_groups_and_counts(&pattern).map_err(|message| ExprError::new(start, message))?;
        Ok((start, Token::Regex(pattern, flags)))
    }
}

/// The groups and counted repetitions of a pattern, as the official emulator checks them. It
/// reads the pattern wrapped as it searches with it (`.*` before an unanchored start and after
/// an unanchored end), and its positions count in that text: an unclosed group is "expected
/// ')' at position <end>", a `)` without its group "end-of-string expected", and a `{` must
/// open `{n}`, `{n,}` or `{n,m}` ("integer expected" or "expected '}'" where it stops). An
/// escape such as `\p` is one character, so `\p{L}` is a count without its integer.
fn check_groups_and_counts(pattern: &str) -> Result<(), String> {
    let (start, body) = match pattern.strip_prefix('^') {
        Some(body) => ("", body),
        None => (".*", pattern),
    };
    let (body, end) = match body.strip_suffix('$') {
        Some(body) => (body, ""),
        None => (body, ".*"),
    };
    let wrapped: Vec<char> = format!("{start}{body}{end}").chars().collect();
    let illegal = |what: String| Err(format!("Illegal regular expression, {what}"));
    let mut depth = 0usize;
    let mut i = 0;
    while i < wrapped.len() {
        match wrapped[i] {
            '\\' => i += 1,
            '[' => {
                // A class ends at the first `]` after its first member.
                i += 2;
                while i < wrapped.len() && wrapped[i] != ']' {
                    if wrapped[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            '(' => depth += 1,
            ')' if depth == 0 => return illegal("end-of-string expected".to_owned()),
            ')' => depth -= 1,
            '{' => {
                let digits = |from: usize| {
                    let mut to = from;
                    while wrapped.get(to).is_some_and(char::is_ascii_digit) {
                        to += 1;
                    }
                    to
                };
                let after = digits(i + 1);
                if after == i + 1 {
                    return illegal(format!("integer expected at position {}", i + 1));
                }
                let mut at = after;
                if wrapped.get(at) == Some(&',') {
                    at = digits(at + 1);
                }
                if wrapped.get(at) != Some(&'}') {
                    return illegal(format!("expected '}}' at position {at}"));
                }
                i = at;
            }
            _ => {}
        }
        i += 1;
    }
    if depth > 0 {
        return illegal(format!("expected ')' at position {}", wrapped.len()));
    }
    Ok(())
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
    let chars: Vec<char> = text.chars().collect();
    let mut parser = Parser {
        lexer: Lexer {
            chars: &chars,
            at: 0,
        },
        peeked: None,
        regex_next: true,
        depth: 0,
    };
    let expr = parser.ternary()?;
    let (at, token) = parser.next()?;
    match token {
        Token::End => Ok(expr),
        Token::Punct(";") => {
            let (at, token) = parser.next()?;
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
            Err(ExprError::new(parser.rhino_end(at, &token), "syntax error"))
        }
        token => Err(ExprError::new(
            parser.rhino_end(at, &token),
            "missing ; before statement",
        )),
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
                    && (chars[end].is_alphanumeric()
                        || matches!(chars[end], '_' | '$')
                        || (number && chars[end] == '.'))
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
        if self.depth > MAX_EXPRESSION_DEPTH {
            return Err(ExprError::new(0, "Rule expression may not be empty."));
        }
        Ok(())
    }

    fn unary(&mut self) -> Result<Expr, ExprError> {
        self.depth += 1;
        let operand = if self.depth > MAX_EXPRESSION_DEPTH {
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
                expr = match index.kind {
                    ExprKind::Str(name) => Expr {
                        at: expr.at,
                        kind: ExprKind::Member(Box::new(expr), name),
                    },
                    _ => Expr {
                        at: expr.at,
                        kind: ExprKind::Index(Box::new(expr), Box::new(index)),
                    },
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
