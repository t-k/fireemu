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
    /// `/pattern/flags`
    Regex(String, String),
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

    fn number(&mut self, start: usize) -> Result<(usize, Token), ExprError> {
        let mut text = String::new();
        while let Some(&c) = self.chars.get(self.at) {
            let exponent_sign = (c == '+' || c == '-') && text.ends_with(['e', 'E']);
            if c.is_ascii_digit() || c == '.' || c == 'e' || c == 'E' || exponent_sign {
                text.push(c);
                self.at += 1;
            } else {
                break;
            }
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
                return Err(ExprError::new(start, "Unterminated regular expression."));
            };
            self.at += 1;
            match c {
                '\\' => {
                    pattern.push(c);
                    if let Some(&next) = self.chars.get(self.at) {
                        pattern.push(next);
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
        let mut flags = String::new();
        while let Some(&c) = self.chars.get(self.at) {
            if c.is_ascii_alphabetic() {
                flags.push(c);
                self.at += 1;
            } else {
                break;
            }
        }
        Ok((start, Token::Regex(pattern, flags)))
    }
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
        _ => Err(ExprError::new(at, "Unexpected token.")),
    }
}

struct Parser<'a> {
    lexer: Lexer<'a>,
    peeked: Option<(usize, Token)>,
    /// Whether a `/` at the next token starts a regular expression.
    regex_next: bool,
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

    fn ternary(&mut self) -> Result<Expr, ExprError> {
        let condition = self.binary(0)?;
        if !self.eat("?")? {
            return Ok(condition);
        }
        let then = self.ternary()?;
        if !self.eat(":")? {
            let (at, _) = self.peek()?.clone();
            return Err(ExprError::new(at, "Unexpected end of expression"));
        }
        let otherwise = self.ternary()?;
        Ok(Expr {
            at: condition.at,
            kind: ExprKind::Ternary(Box::new(condition), Box::new(then), Box::new(otherwise)),
        })
    }

    fn binary(&mut self, min_level: u8) -> Result<Expr, ExprError> {
        let mut left = self.unary()?;
        loop {
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
                    _ => return Ok(left),
                },
                (_, Token::Name(name)) if name == "in" => {
                    let at = left.at;
                    return Err(ExprError::new(
                        at,
                        "Rule expressions may not contain 'in' operator.",
                    ));
                }
                _ => return Ok(left),
            };
            if level <= min_level {
                return Ok(left);
            }
            self.next()?;
            let right = self.binary(level)?;
            left = Expr {
                at: left.at,
                kind: ExprKind::Binary(op, Box::new(left), Box::new(right)),
            };
        }
    }

    fn unary(&mut self) -> Result<Expr, ExprError> {
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
        loop {
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
                self.expect("]")?;
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
                        if self.eat(")")? {
                            break;
                        }
                        self.expect(",")?;
                    }
                }
                expr = Expr {
                    at: expr.at,
                    kind: ExprKind::Call(Box::new(expr), arguments),
                };
            } else {
                return Ok(expr);
            }
        }
    }

    fn expect(&mut self, punct: &str) -> Result<(), ExprError> {
        let (at, token) = self.next()?;
        match token {
            Token::Punct(p) if p == punct => Ok(()),
            Token::End => Err(ExprError::new(at, "Unexpected end of expression")),
            _ => Err(ExprError::new(at, "Unexpected token.")),
        }
    }

    fn primary(&mut self) -> Result<Expr, ExprError> {
        let (at, token) = self.next()?;
        let kind = match token {
            Token::Number(n) => ExprKind::Number(n),
            Token::Str(s) => ExprKind::Str(s),
            Token::Regex(pattern, flags) => ExprKind::Regex(pattern, flags),
            Token::Name(name) => match name.as_str() {
                "true" => ExprKind::Bool(true),
                "false" => ExprKind::Bool(false),
                "null" => ExprKind::Null,
                _ => ExprKind::Name(name),
            },
            Token::Punct("(") => {
                let inner = self.ternary()?;
                self.expect(")")?;
                return Ok(inner);
            }
            Token::Punct("[") => {
                let mut items = Vec::new();
                if !self.eat("]")? {
                    loop {
                        items.push(self.ternary()?);
                        if self.eat("]")? {
                            break;
                        }
                        self.expect(",")?;
                    }
                }
                ExprKind::Array(items)
            }
            Token::Punct("{" | "}") => {
                return Err(ExprError::new(at, "Unsupported javascript syntax."))
            }
            Token::End => return Err(ExprError::new(at, "Unexpected end of expression")),
            Token::Punct(_) => return Err(ExprError::new(at, "Unexpected token.")),
        };
        Ok(Expr { at, kind })
    }
}
