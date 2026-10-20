//! The static check the official emulator runs when rules are loaded: names, members,
//! argument counts and types, and operand types, each refused with its own text.
//!
//! Values whose type is known only at run time are checked when the rule runs, where a wrong
//! type makes the rule false. `auth` and its members (`Json`) take any member; `val()`,
//! `getPriority()`, the query bounds and a sum without a string (`Any`) take the members of a
//! string. Neither is a boolean: `&&`, `||`, `!`, `?:` and the rule itself need one.

use std::collections::BTreeSet;

use super::parse::{BinaryOp, Expr, ExprError, ExprKind};

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

/// A static type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    Bool,
    Num,
    Str,
    Null,
    Any,
    Snapshot,
    Query,
    Regex,
    Array,
    /// `auth` and its members: a JSON value known only at run time, with any member.
    Json,
}

impl Ty {
    fn is(self, allowed: &[Ty]) -> bool {
        matches!(self, Ty::Any | Ty::Json) || allowed.contains(&self)
    }
}

/// Checks a whole rule expression: it must be a boolean.
pub fn check(expr: &Expr, kind: RuleKind, wildcards: &BTreeSet<String>) -> Result<(), ExprError> {
    let checker = Checker { kind, wildcards };
    // A value known only at run time is not enough here: the rule must be a boolean.
    if checker.ty(expr)? == Ty::Bool {
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

const QUERY_MEMBERS: [&str; 9] = [
    "orderByKey",
    "orderByChild",
    "orderByValue",
    "orderByPriority",
    "startAt",
    "endAt",
    "equalTo",
    "limitToFirst",
    "limitToLast",
];

fn no_such(at: usize, name: &str) -> ExprError {
    ExprError::new(at, format!("No such method/property '{name}'."))
}

impl Checker<'_> {
    fn ty(&self, expr: &Expr) -> Result<Ty, ExprError> {
        match &expr.kind {
            ExprKind::Bool(_) => Ok(Ty::Bool),
            ExprKind::Number(_) => Ok(Ty::Num),
            ExprKind::Str(_) => Ok(Ty::Str),
            ExprKind::Null => Ok(Ty::Null),
            ExprKind::Regex(..) => Ok(Ty::Regex),
            ExprKind::Array(_) => Err(ExprError::new(expr.at, "Unexpected array literal.")),
            ExprKind::Name(name) => self.variable(expr.at, name),
            ExprKind::Member(object, name) => self.member(expr.at, object, name),
            ExprKind::Index(object, index) => {
                let object = self.ty(object)?;
                self.ty(index)?;
                match object {
                    Ty::Any | Ty::Json => Ok(object),
                    _ => Err(ExprError::new(
                        expr.at,
                        "Invalid property access: target is not an object.",
                    )),
                }
            }
            ExprKind::Call(callee, arguments) => self.call(expr, callee, arguments),
            ExprKind::Not(operand) => {
                if self.ty(operand)? == Ty::Bool {
                    Ok(Ty::Bool)
                } else {
                    Err(ExprError::new(expr.at, "! only operates on booleans."))
                }
            }
            ExprKind::Neg(operand) => {
                if self.ty(operand)?.is(&[Ty::Num]) {
                    Ok(Ty::Num)
                } else {
                    Err(ExprError::new(expr.at, "- only operates on numbers."))
                }
            }
            ExprKind::Binary(op, left, right) => {
                let l = self.ty(left)?;
                let r = self.ty(right)?;
                Self::binary(expr.at, *op, l, r)
            }
            // A chain is checked as the left-nested operators it stands for.
            ExprKind::Chain(op, operands) => {
                let mut types = operands.iter().map(|operand| self.ty(operand));
                let mut l = types.next().unwrap_or(Ok(Ty::Any))?;
                for r in types {
                    l = Self::binary(expr.at, *op, l, r?)?;
                }
                Ok(l)
            }
            ExprKind::Ternary(condition, then, otherwise) => {
                if self.ty(condition)? != Ty::Bool {
                    return Err(ExprError::new(expr.at, "condition of ? must be boolean."));
                }
                let then = self.ty(then)?;
                let otherwise = self.ty(otherwise)?;
                Ok(if then == otherwise {
                    then
                } else if then == Ty::Json || otherwise == Ty::Json {
                    Ty::Json
                } else {
                    Ty::Any
                })
            }
        }
    }

    fn variable(&self, at: usize, name: &str) -> Result<Ty, ExprError> {
        match name {
            "auth" => Ok(Ty::Json),
            "now" => Ok(Ty::Num),
            "newData" if self.kind == RuleKind::Read => Err(ExprError::new(
                at,
                "newData is invalid in .read expressions.",
            )),
            "root" | "data" | "newData" => Ok(Ty::Snapshot),
            "query" => Ok(Ty::Query),
            _ if self.wildcards.contains(name) => Ok(Ty::Str),
            _ => Err(ExprError::new(at, format!("Unknown variable '{name}'."))),
        }
    }

    fn member(&self, at: usize, object: &Expr, name: &str) -> Result<Ty, ExprError> {
        match self.ty(object)? {
            Ty::Json => Ok(Ty::Json),
            Ty::Str | Ty::Any if name == "length" => Ok(Ty::Num),
            Ty::Num | Ty::Bool | Ty::Null | Ty::Regex | Ty::Array => Err(ExprError::new(
                at,
                "Invalid property access: target is not an object.",
            )),
            // As the official emulator types them: `orderByChild` as null, the limits as
            // numbers, the bounds as values known at run time.
            Ty::Query if QUERY_MEMBERS.contains(&name) => Ok(match name {
                "orderByKey" | "orderByValue" | "orderByPriority" => Ty::Bool,
                "orderByChild" => Ty::Null,
                "limitToFirst" | "limitToLast" => Ty::Num,
                _ => Ty::Any,
            }),
            // Methods are read only through a call.
            _ => Err(no_such(at, name)),
        }
    }

    fn call(&self, call: &Expr, callee: &Expr, arguments: &[Expr]) -> Result<Ty, ExprError> {
        let ExprKind::Member(object, name) = &callee.kind else {
            self.ty(callee)?;
            return Err(ExprError::new(
                call.at,
                "Type error: function call on a non-function.",
            ));
        };
        let object_ty = self.ty(object)?;
        let site = CallSite {
            at: call.at,
            name,
            arguments,
            types: self.argument_types(arguments)?,
        };
        match object_ty {
            Ty::Snapshot if SNAPSHOT_METHODS.contains(&name.as_str()) => site.snapshot_method(),
            Ty::Str | Ty::Any | Ty::Json if STRING_METHODS.contains(&name.as_str()) => {
                site.string_method()
            }
            Ty::Json => Err(ExprError::new(
                call.at,
                "Type error: Function call on target that is not a function.",
            )),
            Ty::Num | Ty::Bool | Ty::Null | Ty::Regex | Ty::Array => Err(ExprError::new(
                call.at,
                "Invalid property access: target is not an object.",
            )),
            // A value known only at run time has only the string methods.
            _ => Err(no_such(call.at, name)),
        }
    }

    /// The types of call arguments; an array literal (only `hasChildren` takes one) must
    /// hold strings.
    fn argument_types(&self, arguments: &[Expr]) -> Result<Vec<Ty>, ExprError> {
        arguments
            .iter()
            .map(|a| match &a.kind {
                ExprKind::Array(items) => {
                    for item in items {
                        if !self.ty(item)?.is(&[Ty::Str]) {
                            return Err(ExprError::new(
                                item.at,
                                "hasChildren() expects an array of strings.",
                            ));
                        }
                    }
                    Ok(Ty::Array)
                }
                _ => self.ty(a),
            })
            .collect()
    }

    fn binary(at: usize, op: BinaryOp, l: Ty, r: Ty) -> Result<Ty, ExprError> {
        let symbol = op.symbol();
        let operand = |ty: Ty, side: &str, allowed: &[Ty], what: &str| {
            if ty.is(allowed) {
                Ok(())
            } else {
                Err(ExprError::new(
                    at,
                    format!("Invalid {symbol} expression: {side} operand {what}."),
                ))
            }
        };
        match op {
            BinaryOp::And | BinaryOp::Or => {
                if l != Ty::Bool {
                    return Err(ExprError::new(
                        at,
                        format!("Left operand of {symbol} must be boolean."),
                    ));
                }
                if r != Ty::Bool {
                    return Err(ExprError::new(
                        at,
                        format!("Right operand of {symbol} must be boolean."),
                    ));
                }
                Ok(Ty::Bool)
            }
            BinaryOp::Eq | BinaryOp::Ne => {
                let allowed = [Ty::Num, Ty::Bool, Ty::Str, Ty::Null];
                let what = "is not a number, boolean, string, null";
                operand(l, "left", &allowed, what)?;
                operand(r, "right", &allowed, what)?;
                Ok(Ty::Bool)
            }
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                let allowed = [Ty::Num, Ty::Str];
                operand(l, "left", &allowed, "must be a number or string")?;
                operand(r, "right", &allowed, "must be a number or string")?;
                Ok(Ty::Bool)
            }
            BinaryOp::Add => {
                let allowed = [Ty::Num, Ty::Str];
                operand(l, "left", &allowed, "is not a number or string")?;
                operand(r, "right", &allowed, "is not a number or string")?;
                // A sum is a string, or, without a string operand, a number or a string.
                Ok(if l == Ty::Str || r == Ty::Str {
                    Ty::Str
                } else {
                    Ty::Any
                })
            }
            BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem => {
                operand(l, "left", &[Ty::Num], "is not a number")?;
                operand(r, "right", &[Ty::Num], "is not a number")?;
                Ok(Ty::Num)
            }
        }
    }
}

/// A method call being checked: where it is, the method, and its arguments with their types.
struct CallSite<'a> {
    at: usize,
    name: &'a str,
    arguments: &'a [Expr],
    types: Vec<Ty>,
}

impl CallSite<'_> {
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

    fn string_arguments(&self) -> Result<(), ExprError> {
        for (argument, ty) in self.arguments.iter().zip(&self.types) {
            if !ty.is(&[Ty::Str]) {
                return Err(ExprError::new(
                    argument.at,
                    format!("{}() expects a string argument.", self.name),
                ));
            }
        }
        Ok(())
    }

    fn snapshot_method(&self) -> Result<Ty, ExprError> {
        match self.name {
            "child" | "hasChild" => {
                self.arity(1)?;
                self.string_arguments()?;
                Ok(if self.name == "child" {
                    Ty::Snapshot
                } else {
                    Ty::Bool
                })
            }
            "hasChildren" => {
                if self.arguments.len() > 1 {
                    return Err(ExprError::new(
                        self.at,
                        "hasChildren() expects 0 or 1 arguments.",
                    ));
                }
                if let (Some(argument), Some(ty)) = (self.arguments.first(), self.types.first()) {
                    if !ty.is(&[Ty::Array]) {
                        return Err(ExprError::new(
                            argument.at,
                            "hasChildren() expects an array of child names.",
                        ));
                    }
                }
                Ok(Ty::Bool)
            }
            "parent" => self.arity(0).map(|()| Ty::Snapshot),
            "val" | "getPriority" => self.arity(0).map(|()| Ty::Any),
            _ => self.arity(0).map(|()| Ty::Bool),
        }
    }

    fn string_method(&self) -> Result<Ty, ExprError> {
        match self.name {
            "contains" | "beginsWith" | "endsWith" => {
                self.arity(1)?;
                self.string_arguments()?;
                Ok(Ty::Bool)
            }
            "replace" => {
                self.arity(2)?;
                self.string_arguments()?;
                Ok(Ty::Str)
            }
            "toLowerCase" | "toUpperCase" => self.arity(0).map(|()| Ty::Str),
            _ => {
                self.arity(1)?;
                if self.types[0].is(&[Ty::Regex]) {
                    Ok(Ty::Bool)
                } else {
                    Err(ExprError::new(
                        self.arguments[0].at,
                        "matches() expects a regular expression literal argument.",
                    ))
                }
            }
        }
    }
}
