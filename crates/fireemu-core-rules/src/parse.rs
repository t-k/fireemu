//! Recursive-descent parser for the Rules native subset.
//!
//! The scanner is driven by the parser because `/` is both the division operator and the start
//! of a path literal; the parser knows which one it expects. Input budgets (spec 33.3): the
//! source is capped, control characters other than tab / newline / carriage return are
//! rejected, and expression nesting is bounded.

use core::fmt;

use crate::ast::{
    Allow, BinaryOp, Expr, ExprKind, FunctionDecl, Item, LetBinding, Literal, MatchBlock, Method,
    PathSegment, Ruleset, Service, Span, UnaryOp,
};

/// Maximum accepted source size for parsing (well above the 256 KiB ruleset limit so that
/// over-limit sources still produce size diagnostics).
pub const MAX_PARSE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum expression nesting depth. The recursive-descent parser and the evaluator spend
/// several stack frames per level, so this stays well below what an 8 MiB stack holds in a
/// debug build (a hostile ruleset must be refused, never overflow the stack); real rulesets
/// nest a handful of levels.
pub const MAX_EXPR_DEPTH: u32 = 32;
/// Maximum `match` nesting depth accepted by the parser (the limit itself is 10; the parser
/// allows more so that the linter can report the exact excess).
pub const MAX_MATCH_NESTING: u32 = 64;

/// Parse error with position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Description.
    pub message: String,
    /// 1-based line.
    pub line: u32,
    /// 1-based column.
    pub column: u32,
    /// Byte offset.
    pub offset: usize,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.column, self.message)
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    /// Widened to `i128` so that `-9223372036854775808` -- which the official compiler
    /// accepts and which no `i64` literal can hold before its sign is applied -- reaches
    /// the parser instead of dying in the lexer.
    Int(i128),
    Float(f64),
    Str(String),
    Punct(&'static str),
    Eof,
}

impl Token {
    fn describe(&self) -> String {
        match self {
            Self::Ident(s) => format!("identifier `{s}`"),
            Self::Int(_) | Self::Float(_) => "number".to_owned(),
            Self::Str(_) => "string".to_owned(),
            Self::Punct(p) => format!("`{p}`"),
            Self::Eof => "end of input".to_owned(),
        }
    }
}

const PUNCTS: &[&str] = &[
    "==", "!=", "<=", ">=", "&&", "||", "$(", "{", "}", "(", ")", "[", "]", ",", ";", ":", ".",
    "?", "/", "=", "<", ">", "!", "+", "-", "*", "%",
];

struct Parser<'a> {
    src: &'a str,
    pos: usize,
    expr_depth: u32,
}

/// Parses a complete ruleset.
pub fn parse_ruleset(src: &str) -> Result<Ruleset, ParseError> {
    if src.len() > MAX_PARSE_BYTES {
        return Err(ParseError {
            message: format!("source exceeds the {MAX_PARSE_BYTES} byte parse budget"),
            line: 1,
            column: 1,
            offset: 0,
        });
    }
    if let Some((offset, _)) = src
        .char_indices()
        .find(|(_, c)| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        let p = Parser {
            src,
            pos: offset,
            expr_depth: 0,
        };
        return Err(p.error("control character in source"));
    }
    let mut p = Parser {
        src,
        pos: 0,
        expr_depth: 0,
    };
    let ruleset = p.ruleset()?;
    check_literal_patterns(&ruleset)?;
    Ok(ruleset)
}

/// The official compiler compiles every literal `matches()` / `replace()` pattern while it
/// compiles the file, and rejects the file when one of them is not a valid RE2 pattern --
/// a lookahead, a backreference or an unterminated class never reaches the runtime. This
/// walk reproduces that, so an unusable pattern is a load failure on both sides.
fn check_literal_patterns(ruleset: &Ruleset) -> Result<(), ParseError> {
    // Both walks are worklists rather than recursion: a left-nested `&&` chain is as deep
    // as it is long, and a recursive visitor would overflow the stack on a source the
    // parser itself accepts.
    let mut exprs: Vec<&Expr> = Vec::new();
    let mut items: Vec<&Item> = ruleset.services.iter().flat_map(|s| &s.items).collect();
    while let Some(item) = items.pop() {
        match item {
            Item::Match(m) => {
                items.extend(&m.items);
                exprs.extend(m.allows.iter().filter_map(|a| a.condition.as_ref()));
                exprs.extend(m.path.iter().filter_map(|s| match s {
                    PathSegment::Binding(e) => Some(e),
                    _ => None,
                }));
            }
            Item::Function(f) => {
                exprs.extend(f.lets.iter().map(|b| &b.value));
                exprs.push(&f.body);
            }
        }
    }
    while let Some(e) = exprs.pop() {
        let span = e.span;
        match e.kind() {
            ExprKind::Call { callee, args } => {
                if let ExprKind::Member { name, .. } = callee.kind() {
                    if matches!(name.as_str(), "matches" | "replace") {
                        if let Some(ExprKind::Literal(Literal::Str(pattern))) =
                            args.first().map(Expr::kind)
                        {
                            if crate::regex::Regex::new(pattern).is_err() {
                                return Err(ParseError {
                                    message: format!(
                                        "Invalid regular expression pattern. Pattern: {pattern}."
                                    ),
                                    line: span.line,
                                    column: span.column,
                                    offset: span.offset,
                                });
                            }
                        }
                    }
                }
                exprs.push(callee);
                exprs.extend(args);
            }
            _ => exprs.extend(e.children()),
        }
    }
    Ok(())
}

impl<'a> Parser<'a> {
    fn span_at(&self, offset: usize) -> Span {
        let mut line = 1u32;
        let mut column = 1u32;
        for (i, c) in self.src.char_indices() {
            if i >= offset {
                break;
            }
            if c == '\n' {
                line += 1;
                column = 1;
            } else {
                column += 1;
            }
        }
        Span {
            line,
            column,
            offset,
        }
    }

    fn error(&self, message: impl Into<String>) -> ParseError {
        let span = self.span_at(self.pos.min(self.src.len()));
        ParseError {
            message: message.into(),
            line: span.line,
            column: span.column,
            offset: span.offset,
        }
    }

    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    fn skip_trivia(&mut self) -> Result<(), ParseError> {
        loop {
            let rest = self.rest();
            if rest.starts_with("//") {
                match rest.find('\n') {
                    Some(n) => self.pos += n + 1,
                    None => self.pos = self.src.len(),
                }
            } else if let Some(body) = rest.strip_prefix("/*") {
                match body.find("*/") {
                    Some(n) => self.pos += n + 4,
                    None => return Err(self.error("unterminated block comment")),
                }
            } else if let Some(c) = rest.chars().next() {
                if c.is_whitespace() {
                    self.pos += c.len_utf8();
                } else {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }
    }

    fn peek(&mut self) -> Result<Token, ParseError> {
        let save = self.pos;
        let t = self.next()?;
        self.pos = save;
        Ok(t)
    }

    fn next(&mut self) -> Result<Token, ParseError> {
        self.skip_trivia()?;
        let rest = self.rest();
        let Some(c) = rest.chars().next() else {
            return Ok(Token::Eof);
        };
        if c.is_ascii_alphabetic() || c == '_' {
            let end = rest
                .char_indices()
                .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
                .map_or(rest.len(), |(i, _)| i);
            self.pos += end;
            return Ok(Token::Ident(rest[..end].to_owned()));
        }
        if c.is_ascii_digit() {
            return self.number();
        }
        if c == '\'' || c == '"' {
            return self.string(c);
        }
        for p in PUNCTS {
            if rest.starts_with(p) {
                self.pos += p.len();
                return Ok(Token::Punct(p));
            }
        }
        Err(self.error(format!("unexpected character `{c}`")))
    }

    fn number(&mut self) -> Result<Token, ParseError> {
        let rest = self.rest();
        let mut end = 0;
        let mut is_float = false;
        for (i, c) in rest.char_indices() {
            if c.is_ascii_digit() {
                end = i + 1;
            } else if c == '.'
                && !is_float
                && rest[i + 1..].starts_with(|d: char| d.is_ascii_digit())
            {
                is_float = true;
                end = i + 1;
            } else {
                break;
            }
        }
        let text = &rest[..end];
        self.pos += end;
        // An integer literal is never a receiver: the official lexer reads the `.` of
        // `0.hasAny` as the start of a decimal part and rejects the file, so `0.join(x)` is
        // a compile error rather than a runtime one. A float has already consumed its
        // point, so `1.5.toMillis()` parses and raises at evaluation time instead --
        // both measured (`conformance/rules-matrix.json`, generated area).
        if !is_float && self.rest().starts_with('.') {
            return Err(self.error("an integer literal cannot be followed by `.`"));
        }
        if is_float {
            text.parse::<f64>()
                .map(Token::Float)
                .map_err(|_| self.error("invalid float"))
        } else {
            text.parse::<i128>()
                .ok()
                .filter(|v| *v <= -i128::from(i64::MIN))
                .map(Token::Int)
                .ok_or_else(|| self.error("integer out of range"))
        }
    }

    fn string(&mut self, quote: char) -> Result<Token, ParseError> {
        let start = self.pos;
        self.pos += 1;
        let mut out = String::new();
        loop {
            let Some(c) = self.rest().chars().next() else {
                self.pos = start;
                return Err(self.error("unterminated string"));
            };
            self.pos += c.len_utf8();
            match c {
                '\\' => {
                    let Some(e) = self.rest().chars().next() else {
                        return Err(self.error("unterminated escape"));
                    };
                    self.pos += e.len_utf8();
                    out.push(match e {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        '0' => '\0',
                        'u' | 'x' | 'U' => self.unicode_escape(e)?,
                        '\\' | '\'' | '"' | '/' => e,
                        _ => return Err(self.error(format!("invalid escape `\\{e}`"))),
                    });
                }
                '\n' => {
                    return Err(self.error("newline in string"));
                }
                c if c == quote => return Ok(Token::Str(out)),
                c => out.push(c),
            }
        }
    }

    /// `\xHH`, `\uHHHH` and `\UHHHHHHHH` inside a string literal.
    fn unicode_escape(&mut self, kind: char) -> Result<char, ParseError> {
        let width = match kind {
            'x' => 2,
            'u' => 4,
            _ => 8,
        };
        let mut digits = String::new();
        for _ in 0..width {
            match self.rest().chars().next().filter(char::is_ascii_hexdigit) {
                Some(c) => {
                    digits.push(c);
                    self.pos += c.len_utf8();
                }
                None => return Err(self.error(format!("`\\{kind}` needs {width} hex digits"))),
            }
        }
        u32::from_str_radix(&digits, 16)
            .ok()
            .and_then(char::from_u32)
            .ok_or_else(|| self.error(format!("`\\{kind}{digits}` names no character")))
    }

    fn expect_punct(&mut self, p: &'static str) -> Result<(), ParseError> {
        let save = self.pos;
        let t = self.next()?;
        if t == Token::Punct(p) {
            Ok(())
        } else {
            self.pos = save;
            self.skip_trivia()?;
            Err(self.error(format!("expected `{p}`, found {}", t.describe())))
        }
    }

    fn expect_ident(&mut self, what: &str) -> Result<(String, Span), ParseError> {
        self.skip_trivia()?;
        let at = self.pos;
        match self.next()? {
            Token::Ident(s) => Ok((s, self.span_at(at))),
            t => {
                self.pos = at;
                Err(self.error(format!("expected {what}, found {}", t.describe())))
            }
        }
    }

    fn eat_ident(&mut self, word: &str) -> Result<bool, ParseError> {
        let save = self.pos;
        if let Token::Ident(s) = self.next()? {
            if s == word {
                return Ok(true);
            }
        }
        self.pos = save;
        Ok(false)
    }

    fn ruleset(&mut self) -> Result<Ruleset, ParseError> {
        let mut version = None;
        if self.eat_ident("rules_version")? {
            self.expect_punct("=")?;
            match self.next()? {
                Token::Str(s) => version = Some(s),
                t => {
                    return Err(
                        self.error(format!("expected version string, found {}", t.describe()))
                    )
                }
            }
            self.expect_punct(";")?;
        }
        let mut services = Vec::new();
        loop {
            self.skip_trivia()?;
            if self.pos >= self.src.len() {
                break;
            }
            let at = self.pos;
            if !self.eat_ident("service")? {
                return Err(self.error("expected `service`"));
            }
            let (first, _) = self.expect_ident("service name")?;
            let mut name = first;
            while self.rest().starts_with('.') {
                self.pos += 1;
                let (part, _) = self.expect_ident("service name segment")?;
                name.push('.');
                name.push_str(&part);
            }
            self.expect_punct("{")?;
            let (items, allows) = self.body(0)?;
            if let Some(a) = allows.first() {
                return Err(ParseError {
                    message: "`allow` is only valid inside a `match` block".to_owned(),
                    line: a.span.line,
                    column: a.span.column,
                    offset: a.span.offset,
                });
            }
            services.push(Service {
                name,
                items,
                span: self.span_at(at),
            });
        }
        if services.is_empty() {
            return Err(self.error("expected at least one `service` block"));
        }
        Ok(Ruleset { version, services })
    }

    /// Parses items until the closing `}` (consumed).
    fn body(&mut self, nesting: u32) -> Result<(Vec<Item>, Vec<Allow>), ParseError> {
        let mut items = Vec::new();
        let mut allows = Vec::new();
        loop {
            self.skip_trivia()?;
            let at = self.pos;
            match self.next()? {
                Token::Punct("}") => return Ok((items, allows)),
                Token::Ident(w) if w == "match" => {
                    if nesting >= MAX_MATCH_NESTING {
                        self.pos = at;
                        return Err(self.error("match nesting exceeds the parser budget"));
                    }
                    items.push(Item::Match(self.match_block(at, nesting + 1)?));
                }
                Token::Ident(w) if w == "function" => {
                    items.push(Item::Function(self.function(at)?));
                }
                Token::Ident(w) if w == "allow" => allows.push(self.allow(at)?),
                Token::Eof => {
                    self.pos = at;
                    return Err(self.error("expected `}` before end of input"));
                }
                t => {
                    self.pos = at;
                    return Err(self.error(format!(
                        "expected `match`, `function`, `allow` or `}}`, found {}",
                        t.describe()
                    )));
                }
            }
        }
    }

    fn match_block(&mut self, at: usize, nesting: u32) -> Result<MatchBlock, ParseError> {
        let path = self.path(true)?;
        self.expect_punct("{")?;
        let (items, allows) = self.body(nesting)?;
        Ok(MatchBlock {
            path,
            items,
            allows,
            span: self.span_at(at),
        })
    }

    /// Parses `/seg/seg...`. In `match` headers literal segments end at whitespace or `{`; in
    /// path literals they also end at expression punctuation.
    fn path(&mut self, header: bool) -> Result<Vec<PathSegment>, ParseError> {
        let mut segments = Vec::new();
        self.skip_trivia()?;
        if !self.rest().starts_with('/') {
            return Err(self.error("expected path starting with `/`"));
        }
        while self.rest().starts_with('/') {
            self.pos += 1;
            let at = self.pos;
            let rest = self.rest();
            if rest.starts_with("$(") {
                if header {
                    return Err(self.error("bindings are not allowed in match paths"));
                }
                self.pos += 2;
                let expr = self.expr()?;
                self.expect_punct(")")?;
                segments.push(PathSegment::Binding(expr));
            } else if rest.starts_with('{') {
                self.pos += 1;
                let (name, span) = self.expect_ident("capture name")?;
                self.skip_trivia()?;
                if self.rest().starts_with("=**") {
                    self.pos += 3;
                    self.expect_punct("}")?;
                    segments.push(PathSegment::RecursiveWildcard { name, span });
                } else {
                    self.expect_punct("}")?;
                    segments.push(PathSegment::Capture { name, span });
                }
            } else {
                // `(default)`: a parenthesised literal segment (Storage rules address the
                // Firestore database that way); otherwise the segment ends at a delimiter.
                let end = if rest.starts_with('(') {
                    rest.find(')').map_or(0, |close| close + 1)
                } else {
                    rest.char_indices()
                        .find(|(_, c)| {
                            c.is_whitespace()
                                || matches!(c, '/' | '{' | '}' | '(' | ')' | ',' | ';' | '[' | ']')
                        })
                        .map_or(rest.len(), |(i, _)| i)
                };
                if end == 0 {
                    self.pos = at;
                    return Err(self.error("empty path segment"));
                }
                segments.push(PathSegment::Literal(rest[..end].to_owned()));
                self.pos += end;
            }
        }
        Ok(segments)
    }

    fn allow(&mut self, at: usize) -> Result<Allow, ParseError> {
        let mut methods = Vec::new();
        loop {
            let (word, span) = self.expect_ident("access method")?;
            match Method::parse(&word) {
                Some(m) => methods.push(m),
                None => {
                    return Err(ParseError {
                        message: format!("unknown access method `{word}`"),
                        line: span.line,
                        column: span.column,
                        offset: span.offset,
                    })
                }
            }
            let save = self.pos;
            if self.next()? == Token::Punct(",") {
                continue;
            }
            self.pos = save;
            break;
        }
        let save = self.pos;
        let condition = if self.next()? == Token::Punct(":") {
            if !self.eat_ident("if")? {
                return Err(self.error("expected `if`"));
            }
            Some(self.expr()?)
        } else {
            self.pos = save;
            None
        };
        self.expect_punct(";")?;
        Ok(Allow {
            methods,
            condition,
            span: self.span_at(at),
        })
    }

    fn function(&mut self, at: usize) -> Result<FunctionDecl, ParseError> {
        let (name, _) = self.expect_ident("function name")?;
        self.expect_punct("(")?;
        let mut params = Vec::new();
        if self.peek()? != Token::Punct(")") {
            loop {
                let (p, _) = self.expect_ident("parameter name")?;
                params.push(p);
                let save = self.pos;
                if self.next()? == Token::Punct(",") {
                    continue;
                }
                self.pos = save;
                break;
            }
        }
        self.expect_punct(")")?;
        self.expect_punct("{")?;
        let mut lets = Vec::new();
        loop {
            self.skip_trivia()?;
            let stmt_at = self.pos;
            if self.eat_ident("let")? {
                let (name, _) = self.expect_ident("binding name")?;
                self.expect_punct("=")?;
                let value = self.expr()?;
                self.expect_punct(";")?;
                lets.push(LetBinding {
                    name,
                    value,
                    span: self.span_at(stmt_at),
                });
            } else if self.eat_ident("return")? {
                let body = self.expr()?;
                self.expect_punct(";")?;
                self.expect_punct("}")?;
                return Ok(FunctionDecl {
                    name,
                    params,
                    lets,
                    body,
                    span: self.span_at(at),
                });
            } else {
                return Err(self.error("expected `let` or `return`"));
            }
        }
    }

    fn enter(&mut self) -> Result<(), ParseError> {
        self.expr_depth += 1;
        if self.expr_depth > MAX_EXPR_DEPTH {
            return Err(self.error("expression nesting exceeds the parser budget"));
        }
        Ok(())
    }

    fn expr(&mut self) -> Result<Expr, ParseError> {
        self.enter()?;
        let r = self.ternary();
        self.expr_depth -= 1;
        r
    }

    fn ternary(&mut self) -> Result<Expr, ParseError> {
        let cond = self.binary(0)?;
        let save = self.pos;
        if self.next()? == Token::Punct("?") {
            let then = self.expr()?;
            self.expect_punct(":")?;
            let otherwise = self.expr()?;
            let span = cond.span;
            let end = otherwise.end;
            return Ok(Expr::new(
                ExprKind::Ternary {
                    cond,
                    then,
                    otherwise,
                },
                span,
                end,
            ));
        }
        self.pos = save;
        Ok(cond)
    }

    /// Precedence levels, lowest first.
    const LEVELS: &'static [&'static [(&'static str, BinaryOp)]] = &[
        &[("||", BinaryOp::Or)],
        &[("&&", BinaryOp::And)],
        &[("==", BinaryOp::Eq), ("!=", BinaryOp::Ne)],
        &[
            ("<=", BinaryOp::Le),
            (">=", BinaryOp::Ge),
            ("<", BinaryOp::Lt),
            (">", BinaryOp::Gt),
        ],
        &[("+", BinaryOp::Add), ("-", BinaryOp::Sub)],
        &[
            ("*", BinaryOp::Mul),
            ("/", BinaryOp::Div),
            ("%", BinaryOp::Mod),
        ],
    ];

    fn binary(&mut self, level: usize) -> Result<Expr, ParseError> {
        if level >= Self::LEVELS.len() {
            return self.unary();
        }
        let mut left = self.binary(level + 1)?;
        loop {
            let save = self.pos;
            let tok = self.next()?;
            let mut matched = None;
            for (p, op) in Self::LEVELS[level] {
                if tok == Token::Punct(p) {
                    matched = Some(*op);
                }
            }
            // `in` and `is` sit at the comparison level.
            if level == 3 {
                if let Token::Ident(w) = &tok {
                    if w == "in" {
                        matched = Some(BinaryOp::In);
                    } else if w == "is" {
                        let at = {
                            self.skip_trivia()?;
                            self.pos
                        };
                        let (type_name, _) = self.expect_ident("type name")?;
                        if !crate::ast::IS_TYPE_NAMES.contains(&type_name.as_str()) {
                            self.pos = at;
                            return Err(self.error(format!(
                                "An unsupported type identifier was used with the 'is' operator. Received {type_name}. Expected one of [{}]",
                                crate::ast::IS_TYPE_NAMES.join(", ")
                            )));
                        }
                        let span = left.span;
                        let end = self.pos;
                        left = Expr::new(
                            ExprKind::Is {
                                expr: left,
                                type_name,
                            },
                            span,
                            end,
                        );
                        continue;
                    }
                }
            }
            let Some(op) = matched else {
                self.pos = save;
                return Ok(left);
            };
            let right = self.binary(level + 1)?;
            let span = left.span;
            let end = right.end;
            left = Expr::new(ExprKind::Binary { op, left, right }, span, end);
        }
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        self.skip_trivia()?;
        let save = self.pos;
        match self.next()? {
            Token::Punct("!") => {
                self.enter()?;
                let e = self.unary();
                self.expr_depth -= 1;
                let expr = e?;
                let end = expr.end;
                Ok(Expr::new(
                    ExprKind::Unary {
                        op: UnaryOp::Not,
                        expr,
                    },
                    self.span_at(save),
                    end,
                ))
            }
            Token::Punct("-") => {
                // `-9223372036854775808` is one literal to the official compiler, not a
                // negation of a literal that no `i64` can hold. Folding it here is the only
                // way to accept it, and it is folded only for that exact value.
                let after_minus = self.pos;
                if let Token::Int(v) = self.peek()? {
                    if v == -i128::from(i64::MIN) {
                        self.pos = after_minus;
                        let _ = self.next()?;
                        return Ok(Expr::new(
                            ExprKind::Literal(Literal::Int(i64::MIN)),
                            self.span_at(save),
                            self.pos,
                        ));
                    }
                }
                self.enter()?;
                let e = self.unary();
                self.expr_depth -= 1;
                let expr = e?;
                let end = expr.end;
                Ok(Expr::new(
                    ExprKind::Unary {
                        op: UnaryOp::Neg,
                        expr,
                    },
                    self.span_at(save),
                    end,
                ))
            }
            _ => {
                self.pos = save;
                self.postfix()
            }
        }
    }

    fn postfix(&mut self) -> Result<Expr, ParseError> {
        let mut e = self.primary()?;
        loop {
            let save = self.pos;
            match self.next()? {
                Token::Punct(".") => {
                    let (name, _) = self.expect_ident("member name")?;
                    let span = e.span;
                    e = Expr::new(ExprKind::Member { object: e, name }, span, self.pos);
                }
                Token::Punct("[") => {
                    let index = self.expr()?;
                    let after_index = self.pos;
                    if self.next()? == Token::Punct(":") {
                        let end = self.expr()?;
                        self.expect_punct("]")?;
                        let span = e.span;
                        e = Expr::new(
                            ExprKind::Slice {
                                object: e,
                                start: index,
                                end,
                            },
                            span,
                            self.pos,
                        );
                    } else {
                        self.pos = after_index;
                        self.expect_punct("]")?;
                        let span = e.span;
                        e = Expr::new(ExprKind::Index { object: e, index }, span, self.pos);
                    }
                }
                Token::Punct("(") => {
                    let mut args = Vec::new();
                    if self.peek()? != Token::Punct(")") {
                        loop {
                            args.push(self.expr()?);
                            let s = self.pos;
                            if self.next()? == Token::Punct(",") {
                                continue;
                            }
                            self.pos = s;
                            break;
                        }
                    }
                    self.expect_punct(")")?;
                    let span = e.span;
                    e = Expr::new(ExprKind::Call { callee: e, args }, span, self.pos);
                }
                _ => {
                    self.pos = save;
                    return Ok(e);
                }
            }
        }
    }

    fn primary(&mut self) -> Result<Expr, ParseError> {
        self.skip_trivia()?;
        let at = self.pos;
        // Every arm below builds its node through this, so a node's extent is always the
        // text the parser actually consumed for it.
        macro_rules! node {
            ($kind:expr) => {
                Expr::new($kind, self.span_at(at), self.pos)
            };
        }
        if self.rest().starts_with('/') {
            let segments = self.path(false)?;
            return Ok(node!(ExprKind::Path(segments)));
        }
        match self.next()? {
            Token::Int(i) => {
                if let Ok(i) = i64::try_from(i) {
                    Ok(node!(ExprKind::Literal(Literal::Int(i))))
                } else {
                    self.pos = at;
                    Err(self.error("integer out of range"))
                }
            }
            Token::Float(f) => Ok(node!(ExprKind::Literal(Literal::Float(f)))),
            Token::Str(s) => Ok(node!(ExprKind::Literal(Literal::Str(s)))),
            Token::Ident(w) => Ok(match w.as_str() {
                "true" => node!(ExprKind::Literal(Literal::Bool(true))),
                "false" => node!(ExprKind::Literal(Literal::Bool(false))),
                "null" => node!(ExprKind::Literal(Literal::Null)),
                _ => node!(ExprKind::Ident(w)),
            }),
            Token::Punct("(") => {
                let e = self.expr()?;
                self.expect_punct(")")?;
                Ok(e)
            }
            Token::Punct("[") => {
                let mut items = Vec::new();
                if self.peek()? != Token::Punct("]") {
                    loop {
                        items.push(self.expr()?);
                        let s = self.pos;
                        if self.next()? == Token::Punct(",") {
                            continue;
                        }
                        self.pos = s;
                        break;
                    }
                }
                self.expect_punct("]")?;
                Ok(node!(ExprKind::List(items)))
            }
            Token::Punct("{") => {
                let mut entries = Vec::new();
                if self.peek()? != Token::Punct("}") {
                    loop {
                        let key = match self.next()? {
                            Token::Str(s) | Token::Ident(s) => s,
                            t => {
                                return Err(
                                    self.error(format!("expected map key, found {}", t.describe()))
                                )
                            }
                        };
                        self.expect_punct(":")?;
                        let value = self.expr()?;
                        entries.push((key, value));
                        let s = self.pos;
                        if self.next()? == Token::Punct(",") {
                            continue;
                        }
                        self.pos = s;
                        break;
                    }
                }
                self.expect_punct("}")?;
                Ok(node!(ExprKind::Map(entries)))
            }
            t => {
                self.pos = at;
                Err(self.error(format!("expected expression, found {}", t.describe())))
            }
        }
    }
}
