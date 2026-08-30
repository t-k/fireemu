//! Security Rules AST (native subset, spec 13.3).

/// Source position (1-based line and column, 0-based byte offset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Span {
    /// 1-based line.
    pub line: u32,
    /// 1-based column (in characters).
    pub column: u32,
    /// Byte offset.
    pub offset: usize,
}

/// A parsed ruleset.
#[derive(Debug, Clone, PartialEq)]
pub struct Ruleset {
    /// `rules_version` if declared.
    pub version: Option<String>,
    /// Services.
    pub services: Vec<Service>,
}

/// `service <name> { ... }`.
#[derive(Debug, Clone, PartialEq)]
pub struct Service {
    /// Service name such as `cloud.firestore`.
    pub name: String,
    /// Items.
    pub items: Vec<Item>,
    /// Position.
    pub span: Span,
}

/// A service or match body item.
#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    /// `match` block.
    Match(MatchBlock),
    /// `function` declaration.
    Function(FunctionDecl),
}

/// Path segment in `match` headers and path literals.
#[derive(Debug, Clone, PartialEq)]
pub enum PathSegment {
    /// Literal segment.
    Literal(String),
    /// `{name}` single-segment capture.
    Capture {
        /// Variable name.
        name: String,
        /// Position.
        span: Span,
    },
    /// `{name=**}` recursive wildcard.
    RecursiveWildcard {
        /// Variable name.
        name: String,
        /// Position.
        span: Span,
    },
    /// `$(expr)` binding inside a path literal.
    Binding(Expr),
}

/// `match /path { ... }`.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchBlock {
    /// Path.
    pub path: Vec<PathSegment>,
    /// Nested items.
    pub items: Vec<Item>,
    /// `allow` statements.
    pub allows: Vec<Allow>,
    /// Position.
    pub span: Span,
}

/// Access methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// `read`
    Read,
    /// `write`
    Write,
    /// `get`
    Get,
    /// `list`
    List,
    /// `create`
    Create,
    /// `update`
    Update,
    /// `delete`
    Delete,
}

impl Method {
    /// Parses a method keyword.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "read" => Self::Read,
            "write" => Self::Write,
            "get" => Self::Get,
            "list" => Self::List,
            "create" => Self::Create,
            "update" => Self::Update,
            "delete" => Self::Delete,
            _ => return None,
        })
    }
}

/// `allow methods: if condition;`
#[derive(Debug, Clone, PartialEq)]
pub struct Allow {
    /// Methods.
    pub methods: Vec<Method>,
    /// Condition; `None` means unconditional allow.
    pub condition: Option<Expr>,
    /// Position.
    pub span: Span,
}

/// `let name = expr;`
#[derive(Debug, Clone, PartialEq)]
pub struct LetBinding {
    /// Name.
    pub name: String,
    /// Value.
    pub value: Expr,
    /// Position.
    pub span: Span,
}

/// `function name(params) { lets; return expr; }`
#[derive(Debug, Clone, PartialEq)]
pub struct FunctionDecl {
    /// Name.
    pub name: String,
    /// Parameters.
    pub params: Vec<String>,
    /// `let` bindings.
    pub lets: Vec<LetBinding>,
    /// Return expression.
    pub body: Expr,
    /// Position.
    pub span: Span,
}

/// Literal values.
#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    /// `null`
    Null,
    /// Boolean.
    Bool(bool),
    /// Integer.
    Int(i64),
    /// Float.
    Float(f64),
    /// String.
    Str(String),
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    /// `!`
    Not,
    /// `-`
    Neg,
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOp {
    /// `||`
    Or,
    /// `&&`
    And,
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `in`
    In,
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `%`
    Mod,
}

/// Expressions.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Literal.
    Literal(Literal),
    /// Identifier.
    Ident(String),
    /// `object.name`
    Member {
        /// Object.
        object: Box<Expr>,
        /// Member name.
        name: String,
    },
    /// `object[index]`
    Index {
        /// Object.
        object: Box<Expr>,
        /// Index expression.
        index: Box<Expr>,
    },
    /// `object[start:end]`: the range index of a list or a string.
    Slice {
        /// Object.
        object: Box<Expr>,
        /// First index, included.
        start: Box<Expr>,
        /// Last index, excluded.
        end: Box<Expr>,
    },
    /// `callee(args)`
    Call {
        /// Callee.
        callee: Box<Expr>,
        /// Arguments.
        args: Vec<Expr>,
        /// Position of the call.
        span: Span,
    },
    /// Unary operation.
    Unary {
        /// Operator.
        op: UnaryOp,
        /// Operand.
        expr: Box<Expr>,
    },
    /// Binary operation.
    Binary {
        /// Operator.
        op: BinaryOp,
        /// Left operand.
        left: Box<Expr>,
        /// Right operand.
        right: Box<Expr>,
    },
    /// `cond ? then : otherwise`
    Ternary {
        /// Condition.
        cond: Box<Expr>,
        /// Then branch.
        then: Box<Expr>,
        /// Else branch.
        otherwise: Box<Expr>,
    },
    /// `[a, b]`
    List(Vec<Expr>),
    /// `{'k': v}`
    Map(Vec<(String, Expr)>),
    /// `/a/$(b)/c` path literal.
    Path(Vec<PathSegment>),
    /// `expr is type`
    Is {
        /// Expression.
        expr: Box<Expr>,
        /// Type name.
        type_name: String,
    },
}

/// The type names the `is` operator accepts. The official compiler rejects anything else
/// with "An unsupported type identifier was used with the 'is' operator", which is a
/// compile error rather than a `false` answer.
pub const IS_TYPE_NAMES: &[&str] = &[
    "bool",
    "bytes",
    "duration",
    "float",
    "int",
    "latlng",
    "list",
    "map",
    "number",
    "path",
    "set",
    "string",
    "timestamp",
];
