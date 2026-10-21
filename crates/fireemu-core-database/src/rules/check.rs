//! The static check the official emulator runs when rules are loaded: names, members,
//! argument counts and types, and operand types, each refused with its own text.
//!
//! Types are sets, as there (review r9 M26): a ternary has the union of its branches' types,
//! and each check asks either whether a set holds an allowed type (operands of `==`, `<`,
//! `+`, `-`, method arguments, members), or whether it is exactly one type (`!`, `&&`, `||`,
//! a ternary's condition and the rule itself). `auth` and its members may be any JSON value;
//! `val()`, `getPriority()` and the query bounds are values known only at run time. A wrong
//! type found at run time makes the rule false.

use std::collections::BTreeSet;

use super::parse::{BinaryOp, Expr, ExprError, ExprKind};
use crate::path::Path;

/// Which rule an expression is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// `.read`
    Read,
    /// `.write`
    Write,
    /// `.validate`
    Validate,
}

/// One member of a static type: what a value may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Str,
    Num,
    Bool,
    Null,
    /// A JSON object or array, only through `auth`.
    Json,
    /// The sentinel `auth` may also be.
    EmptyObject,
    /// "A snapshot value that is an object", from `val()`.
    Sentinel,
    /// A snapshot (`root`, `data`, `newData`, `child()`, `parent()`).
    Data,
    Regex,
    /// The `query` object.
    Query,
    /// An ordering (`query.orderByChild`).
    OrderBy,
    /// A method not yet called (`data.child`).
    Method(&'static str),
}

/// A static type: the set of what a value may be, in the order it was built (a call takes
/// the first method in it).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Types(Vec<Tok>);

impl Types {
    fn one(tok: Tok) -> Self {
        Self(vec![tok])
    }

    fn of(toks: &[Tok]) -> Self {
        Self(toks.to_vec())
    }

    fn is(&self, tok: Tok) -> bool {
        self.0 == [tok]
    }

    fn has(&self, tok: Tok) -> bool {
        self.0.contains(&tok)
    }

    fn meets(&self, allowed: &[Tok]) -> bool {
        self.0.iter().any(|tok| allowed.contains(tok))
    }

    fn union(mut self, other: Self) -> Self {
        for tok in other.0 {
            if !self.0.contains(&tok) {
                self.0.push(tok);
            }
        }
        self
    }

    fn method(&self) -> Option<&'static str> {
        self.0.iter().find_map(|tok| match tok {
            Tok::Method(name) => Some(*name),
            _ => None,
        })
    }
}

/// `auth` and any member of it.
const AUTH: [Tok; 5] = [Tok::Str, Tok::Num, Tok::Bool, Tok::Json, Tok::EmptyObject];
/// `val()` and the query bounds.
const DATA_VALUE: [Tok; 5] = [Tok::Str, Tok::Num, Tok::Bool, Tok::Sentinel, Tok::Null];

/// Checks a whole rule expression, which must be a boolean. An equality against an
/// ordering compares a string literal on the other side as a path, so that literal is
/// replaced by the ordering it names.
pub fn check(
    expr: &mut Expr,
    kind: RuleKind,
    wildcards: &BTreeSet<String>,
) -> Result<(), ExprError> {
    let checker = Checker { kind, wildcards };
    if checker.ty(expr)?.is(Tok::Bool) {
        Ok(())
    } else {
        Err(ExprError::new(
            expr.at,
            "Expression must evaluate to a boolean.",
        ))
    }
}

struct Checker<'a> {
    kind: RuleKind,
    wildcards: &'a BTreeSet<String>,
}

const SNAPSHOT_METHODS: [&str; 10] = [
    "val",
    "child",
    "parent",
    "hasChild",
    "hasChildren",
    "exists",
    "getPriority",
    "isNumber",
    "isString",
    "isBoolean",
];

const STRING_METHODS: [&str; 7] = [
    "contains",
    "beginsWith",
    "endsWith",
    "replace",
    "toLowerCase",
    "toUpperCase",
    "matches",
];

fn method_name(names: &[&'static str], name: &str) -> Option<&'static str> {
    names.iter().copied().find(|known| *known == name)
}

fn no_such(at: usize, name: &str) -> ExprError {
    ExprError::new(at, format!("No such method/property '{name}'."))
}

fn not_an_object(at: usize) -> ExprError {
    ExprError::new(at, "Invalid property access: target is not an object.")
}

/// Whether an operand may stand on the other side of an ordering: an ordering, the literal
/// `null`, or a string literal naming a valid path. A string literal is replaced by the
/// ordering it names.
fn ordering_operand(expr: &mut Expr, types: &Types) -> bool {
    if types.is(Tok::OrderBy) || matches!(expr.kind, ExprKind::Null) {
        return true;
    }
    let ExprKind::Str(text) = &expr.kind else {
        return false;
    };
    // As the official emulator reads such a path: segments between slashes, empty ones
    // dropped, each a valid key.
    let joined: Vec<&str> = text.split('/').filter(|s| !s.is_empty()).collect();
    let Ok(path) = Path::parse(&joined.join("/"), &crate::limits::Limits::default()) else {
        return false;
    };
    if path.is_priority() || path.is_info() {
        return false;
    }
    expr.kind = ExprKind::Ordering(path.keys().to_vec());
    true
}

impl Checker<'_> {
    fn ty(&self, expr: &mut Expr) -> Result<Types, ExprError> {
        let at = expr.at;
        match &mut expr.kind {
            ExprKind::Bool(_) => Ok(Types::one(Tok::Bool)),
            ExprKind::Number(_) => Ok(Types::one(Tok::Num)),
            ExprKind::Str(_) => Ok(Types::one(Tok::Str)),
            ExprKind::Null => Ok(Types::one(Tok::Null)),
            ExprKind::Regex(..) => Ok(Types::one(Tok::Regex)),
            ExprKind::Ordering(_) => Ok(Types::one(Tok::OrderBy)),
            ExprKind::Array(_) => Err(ExprError::new(at, "Unexpected array literal.")),
            ExprKind::Name(name) => self.variable(at, name),
            ExprKind::Member(object, name) => {
                let object = self.ty(object)?;
                Self::member(at, &object, name)
            }
            ExprKind::Index(object, index) => {
                let object = self.ty(object)?;
                let index = self.ty(index)?;
                if !object.has(Tok::Json) {
                    return Err(ExprError::new(at, "Invalid property access."));
                }
                if !index.meets(&[Tok::Num, Tok::Str]) {
                    return Err(ExprError::new(
                        at,
                        "Invalid property access on 'auth' object.",
                    ));
                }
                Ok(Types::of(&AUTH))
            }
            ExprKind::Call(callee, arguments) => self.call(at, callee, arguments),
            ExprKind::Not(operand) => {
                if self.ty(operand)?.is(Tok::Bool) {
                    Ok(Types::one(Tok::Bool))
                } else {
                    Err(ExprError::new(at, "! only operates on booleans."))
                }
            }
            ExprKind::Neg(operand) => {
                if self.ty(operand)?.meets(&[Tok::Num]) {
                    Ok(Types::one(Tok::Num))
                } else {
                    Err(ExprError::new(at, "- only operates on numbers."))
                }
            }
            ExprKind::Binary(op, left, right) => {
                let op = *op;
                let l = self.ty(left)?;
                let r = self.ty(right)?;
                if op == BinaryOp::Eq && (l.is(Tok::OrderBy) || r.is(Tok::OrderBy)) {
                    for (side, operand, types) in [("left", left, &l), ("right", right, &r)] {
                        if !ordering_operand(operand, types) {
                            return Err(ExprError::new(
                                at,
                                format!("Invalid == expression: {side} operand must be an ordering or string literal when comparing against an ordering."),
                            ));
                        }
                    }
                    return Ok(Types::one(Tok::Bool));
                }
                Self::binary(at, op, &l, &r)
            }
            // A chain is checked as the left-nested operators it stands for.
            ExprKind::Chain(op, operands) => {
                let op = *op;
                let mut operands = operands.iter_mut();
                let Some(first) = operands.next() else {
                    return Ok(Types::one(Tok::Bool));
                };
                let mut l = self.ty(first)?;
                for operand in operands {
                    let r = self.ty(operand)?;
                    l = Self::binary(at, op, &l, &r)?;
                }
                Ok(l)
            }
            ExprKind::Ternary(condition, then, otherwise) => {
                let condition = self.ty(condition)?;
                let then = self.ty(then)?;
                let otherwise = self.ty(otherwise)?;
                if !condition.is(Tok::Bool) {
                    return Err(ExprError::new(at, "condition of ? must be boolean."));
                }
                Ok(then.union(otherwise))
            }
        }
    }

    fn variable(&self, at: usize, name: &str) -> Result<Types, ExprError> {
        match name {
            "auth" => Ok(Types::of(&AUTH)),
            "now" => Ok(Types::one(Tok::Num)),
            "newData" if self.kind == RuleKind::Read => Err(ExprError::new(
                at,
                "newData is invalid in .read expressions.",
            )),
            "root" | "data" | "newData" => Ok(Types::one(Tok::Data)),
            "query" => Ok(Types::one(Tok::Query)),
            _ if self.wildcards.contains(name) => Ok(Types::one(Tok::Str)),
            _ => Err(ExprError::new(at, format!("Unknown variable '{name}'."))),
        }
    }

    /// The member `name` of a value of type `object`. Any type that may be `auth` takes any
    /// member; a snapshot's methods need exactly a snapshot; a string's members need a set
    /// that may be a string.
    fn member(at: usize, object: &Types, name: &str) -> Result<Types, ExprError> {
        if object.has(Tok::Json) {
            let mut types = AUTH.to_vec();
            if name == "length" {
                types.push(Tok::Num);
            } else if let Some(method) = method_name(&STRING_METHODS, name) {
                types.push(Tok::Method(method));
            }
            return Ok(Types(types));
        }
        if object.is(Tok::Data) {
            return method_name(&SNAPSHOT_METHODS, name)
                .map(|method| Types::one(Tok::Method(method)))
                .ok_or_else(|| no_such(at, name));
        }
        if object.has(Tok::Str) {
            if name == "length" {
                return Ok(Types::one(Tok::Num));
            }
            return method_name(&STRING_METHODS, name)
                .map(|method| Types::one(Tok::Method(method)))
                .ok_or_else(|| no_such(at, name));
        }
        if object.has(Tok::Query) {
            // As the official emulator types them; `orderBy`, `endBefore` and
            // `isOrderByChild` are not served here, so a rule naming them is refused.
            return match name {
                "orderByChild" => Ok(Types::one(Tok::OrderBy)),
                "orderByKey" | "orderByValue" | "orderByPriority" => Ok(Types::one(Tok::Bool)),
                "limitToFirst" | "limitToLast" => Ok(Types::one(Tok::Num)),
                "startAt" | "endAt" | "equalTo" => Ok(Types::of(&DATA_VALUE)),
                _ => Err(no_such(at, name)),
            };
        }
        Err(not_an_object(at))
    }

    fn call(
        &self,
        at: usize,
        callee: &mut Expr,
        arguments: &mut [Expr],
    ) -> Result<Types, ExprError> {
        if !matches!(callee.kind, ExprKind::Member(..)) {
            self.ty(callee)?;
            return Err(ExprError::new(
                at,
                "Type error: function call on a non-function.",
            ));
        }
        let Some(method) = self.ty(callee)?.method() else {
            return Err(ExprError::new(
                at,
                "Type error: Function call on target that is not a function.",
            ));
        };
        let site = CallSite {
            checker: self,
            at,
            name: method,
            arguments,
        };
        site.check()
    }

    fn binary(at: usize, op: BinaryOp, l: &Types, r: &Types) -> Result<Types, ExprError> {
        let symbol = op.symbol();
        let operand = |types: &Types, allowed: &[Tok], message: String| {
            if types.meets(allowed) {
                Ok(())
            } else {
                Err(ExprError::new(at, message))
            }
        };
        match op {
            BinaryOp::And | BinaryOp::Or => {
                if !l.is(Tok::Bool) {
                    return Err(ExprError::new(
                        at,
                        format!("Left operand of {symbol} must be boolean."),
                    ));
                }
                if !r.is(Tok::Bool) {
                    return Err(ExprError::new(
                        at,
                        format!("Right operand of {symbol} must be boolean."),
                    ));
                }
                Ok(Types::one(Tok::Bool))
            }
            BinaryOp::Eq => {
                let allowed = [Tok::Num, Tok::Bool, Tok::Str, Tok::Null];
                operand(
                    l,
                    &allowed,
                    "Invalid == expression: left operand is not a number, boolean, string, null."
                        .to_owned(),
                )?;
                operand(
                    r,
                    &allowed,
                    "Invalid == expression: right operand is not a number, boolean, string, or null."
                        .to_owned(),
                )?;
                Ok(Types::one(Tok::Bool))
            }
            BinaryOp::Ne => {
                let allowed = [Tok::Num, Tok::Bool, Tok::Str, Tok::OrderBy, Tok::Null];
                for side in ["left", "right"] {
                    operand(
                        if side == "left" { l } else { r },
                        &allowed,
                        format!("Invalid != expression: {side} operand is not a number, boolean, string, or null."),
                    )?;
                }
                Ok(Types::one(Tok::Bool))
            }
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                for side in ["left", "right"] {
                    operand(
                        if side == "left" { l } else { r },
                        &[Tok::Num, Tok::Str],
                        format!("Invalid {symbol} expression: {side} operand must be a number or string."),
                    )?;
                }
                Ok(Types::one(Tok::Bool))
            }
            BinaryOp::Add => {
                for side in ["left", "right"] {
                    operand(
                        if side == "left" { l } else { r },
                        &[Tok::Num, Tok::Str],
                        format!("Invalid + expression: {side} operand is not a number or string."),
                    )?;
                }
                // A sum is a string when one side is surely one, otherwise a number or a
                // string.
                Ok(if l.is(Tok::Str) || r.is(Tok::Str) {
                    Types::one(Tok::Str)
                } else {
                    Types::of(&[Tok::Num, Tok::Str])
                })
            }
            BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem => {
                for side in ["left", "right"] {
                    operand(
                        if side == "left" { l } else { r },
                        &[Tok::Num],
                        format!("Invalid {symbol} expression: {side} operand is not a number."),
                    )?;
                }
                Ok(Types::one(Tok::Num))
            }
        }
    }
}

/// A method call being checked: where it is, the method, and its arguments. The arguments
/// are checked only once their count is right.
struct CallSite<'a, 'b> {
    checker: &'a Checker<'b>,
    at: usize,
    name: &'static str,
    arguments: &'a mut [Expr],
}

impl CallSite<'_, '_> {
    fn arity(&self, n: usize) -> Result<(), ExprError> {
        if self.arguments.len() == n {
            return Ok(());
        }
        let count = match n {
            0 => "no arguments",
            1 => "1 argument",
            _ => "two arguments",
        };
        Err(ExprError::new(
            self.at,
            format!("{}() expects {count}.", self.name),
        ))
    }

    /// Argument `i` must be able to be a string.
    fn string_argument(&mut self, i: usize, message: &str) -> Result<(), ExprError> {
        let argument = &mut self.arguments[i];
        if self.checker.ty(argument)?.has(Tok::Str) {
            Ok(())
        } else {
            Err(ExprError::new(argument.at, message))
        }
    }

    fn check(mut self) -> Result<Types, ExprError> {
        let name = self.name;
        let expects_string = format!("{name}() expects a string argument.");
        match name {
            "child" | "hasChild" => {
                self.arity(1)?;
                self.string_argument(0, &expects_string)?;
                Ok(Types::one(if name == "child" {
                    Tok::Data
                } else {
                    Tok::Bool
                }))
            }
            "hasChildren" => {
                if let Some(second) = self.arguments.get(1) {
                    return Err(ExprError::new(
                        second.at,
                        "hasChildren() expects only a single argument (containing an array of child names).",
                    ));
                }
                if let Some(argument) = self.arguments.first_mut() {
                    let at = argument.at;
                    let ExprKind::Array(items) = &mut argument.kind else {
                        return Err(ExprError::new(
                            at,
                            "hasChildren() expects an array of child names.",
                        ));
                    };
                    for item in items {
                        if !self.checker.ty(item)?.meets(&[Tok::Str]) {
                            return Err(ExprError::new(
                                item.at,
                                "hasChildren() expects an array of strings.",
                            ));
                        }
                    }
                }
                Ok(Types::one(Tok::Bool))
            }
            "parent" => self.arity(0).map(|()| Types::one(Tok::Data)),
            "val" => self.arity(0).map(|()| Types::of(&DATA_VALUE)),
            "getPriority" => self
                .arity(0)
                .map(|()| Types::of(&[Tok::Str, Tok::Num, Tok::Null])),
            "exists" | "isNumber" | "isString" | "isBoolean" => {
                self.arity(0).map(|()| Types::one(Tok::Bool))
            }
            "contains" | "beginsWith" | "endsWith" => {
                self.arity(1)?;
                self.string_argument(0, &expects_string)?;
                Ok(Types::one(Tok::Bool))
            }
            "replace" => {
                self.arity(2)?;
                self.string_argument(0, "Argument 1 of replace() must be a string.")?;
                self.string_argument(1, "Argument 2 of replace() must be a string.")?;
                Ok(Types::one(Tok::Str))
            }
            "toLowerCase" | "toUpperCase" => self.arity(0).map(|()| Types::one(Tok::Str)),
            _ => {
                if self.arguments.len() != 1 {
                    return Err(ExprError::new(
                        self.at,
                        "matches() expects 1 regular expression literal argument.",
                    ));
                }
                let argument = &mut self.arguments[0];
                if self.checker.ty(argument)?.has(Tok::Regex) {
                    Ok(Types::one(Tok::Bool))
                } else {
                    Err(ExprError::new(
                        argument.at,
                        "matches() expects a regular expression literal argument.",
                    ))
                }
            }
        }
    }
}
