//! Native Rules evaluator subset (`RULES-1` core, spec 13.3, 13.8).
//!
//! Semantics implemented:
//!
//! - deny by default; a request is allowed when at least one applicable `allow` covering the
//!   method evaluates to `true`;
//! - `match` paths with `{capture}` and `{capture=**}`, nested blocks, lexically scoped
//!   functions with `let` bindings;
//! - expression budget (`RULES-EXPRESSIONS-PER-REQUEST`) and call depth
//!   (`RULES-FUNCTION-CALL-DEPTH`) from the catalog, checked arithmetic, short-circuit
//!   evaluation is not charged for skipped branches;
//! - type / missing-member errors make a condition false (as on the backend); unsupported
//!   built-ins (`get`, `exists`, `getAfter`, regex) make the request deny with an explicit
//!   reason (fail closed, ADR-005).

use std::collections::BTreeMap;

use ftd_core_limits::catalogs::FIREBASE_RULES_2026_08_25;
use ftd_core_limits::model::LimitMaximum;

use crate::ast::{
    Allow, BinaryOp, Expr, FunctionDecl, Item, Literal, MatchBlock, Method as AstMethod,
    PathSegment, Ruleset, UnaryOp,
};
use crate::value::{AuthContext, RulesValue};

/// Request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Single document read.
    Get,
    /// Query.
    List,
    /// Create.
    Create,
    /// Update.
    Update,
    /// Delete.
    Delete,
}

impl Method {
    fn covered_by(self, m: AstMethod) -> bool {
        match m {
            AstMethod::Read => matches!(self, Self::Get | Self::List),
            AstMethod::Write => matches!(self, Self::Create | Self::Update | Self::Delete),
            AstMethod::Get => self == Self::Get,
            AstMethod::List => self == Self::List,
            AstMethod::Create => self == Self::Create,
            AstMethod::Update => self == Self::Update,
            AstMethod::Delete => self == Self::Delete,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::List => "list",
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

/// Request being authorized.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestContext {
    /// Method.
    pub method: Method,
    /// Path relative to the service root, e.g. `/databases/(default)/documents/users/u1`.
    pub path: String,
    /// Verified identity, `None` when unauthenticated.
    pub auth: Option<AuthContext>,
    /// Existing document (`resource`), as a map with `data`.
    pub resource: Option<RulesValue>,
    /// Incoming document (`request.resource`), as a map with `data`.
    pub request_resource: Option<RulesValue>,
    /// `request.time` in Unix seconds.
    pub time_unix_seconds: i64,
}

/// Why a request was denied.
#[derive(Debug, Clone, PartialEq)]
pub enum DenyReason {
    /// No `match` block covers the path.
    NoMatchingRule,
    /// Match blocks exist but no `allow` covering the method evaluated to true.
    NoMatchingAllow,
    /// A condition used a feature this evaluator does not implement.
    Unsupported(String),
    /// A runtime budget was exceeded.
    BudgetExceeded {
        /// Limit ID.
        limit_id: &'static str,
        /// Observed.
        current: u64,
        /// Maximum.
        maximum: u64,
    },
}

/// Decision.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// Allowed.
    Allow,
    /// Denied.
    Deny(DenyReason),
}

/// Evaluation report with budget observations (spec 13.10).
#[derive(Debug, Clone, PartialEq)]
pub struct EvaluationReport {
    /// Decision.
    pub decision: Decision,
    /// Expressions charged to the request.
    pub expressions_evaluated: u64,
    /// Deepest function call chain observed.
    pub max_call_depth: u16,
}

#[derive(Debug)]
enum EvalError {
    /// Condition is false because of a type / missing member error. The message is kept for
    /// the `rules explain` output (Milestone H); it does not influence the decision.
    #[allow(dead_code)]
    Soft(String),
    /// Fail closed.
    Unsupported(String),
    /// Budget exceeded.
    Budget {
        limit_id: &'static str,
        current: u64,
        maximum: u64,
    },
}

fn limit_max(id: &str) -> u64 {
    match FIREBASE_RULES_2026_08_25.find(id).map(|l| l.maximum) {
        Some(LimitMaximum::Fixed(v)) => v,
        _ => u64::MAX,
    }
}

struct Budget {
    expressions: u64,
    expression_max: u64,
    depth: u16,
    max_depth_seen: u16,
    depth_max: u64,
}

impl Budget {
    fn charge(&mut self) -> Result<(), EvalError> {
        self.expressions = self.expressions.saturating_add(1);
        if self.expressions > self.expression_max {
            return Err(EvalError::Budget {
                limit_id: "RULES-EXPRESSIONS-PER-REQUEST",
                current: self.expressions,
                maximum: self.expression_max,
            });
        }
        Ok(())
    }

    fn enter_call(&mut self) -> Result<(), EvalError> {
        self.depth = self.depth.saturating_add(1);
        self.max_depth_seen = self.max_depth_seen.max(self.depth);
        if u64::from(self.depth) > self.depth_max {
            return Err(EvalError::Budget {
                limit_id: "RULES-FUNCTION-CALL-DEPTH",
                current: u64::from(self.depth),
                maximum: self.depth_max,
            });
        }
        Ok(())
    }

    fn leave_call(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

struct Scope<'a> {
    functions: Vec<&'a FunctionDecl>,
    bindings: Vec<(String, RulesValue)>,
}

struct Evaluator<'a> {
    request: RulesValue,
    resource: RulesValue,
    budget: Budget,
    scope: Scope<'a>,
}

/// Evaluates a request against a ruleset.
#[must_use]
pub fn evaluate_request(ruleset: &Ruleset, ctx: &RequestContext) -> EvaluationReport {
    let mut budget = Budget {
        expressions: 0,
        expression_max: limit_max("RULES-EXPRESSIONS-PER-REQUEST"),
        depth: 0,
        max_depth_seen: 0,
        depth_max: limit_max("RULES-FUNCTION-CALL-DEPTH"),
    };
    let segments: Vec<String> = ctx
        .path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let mut matched_any = false;
    let mut unsupported: Option<String> = None;
    for service in &ruleset.services {
        if service.name != "cloud.firestore" {
            continue;
        }
        let mut scope = Scope {
            functions: Vec::new(),
            bindings: Vec::new(),
        };
        for item in &service.items {
            if let Item::Function(f) = item {
                scope.functions.push(f);
            }
        }
        let request_value = build_request(ctx);
        let resource_value = ctx.resource.clone().unwrap_or(RulesValue::Null);
        let mut ev = Evaluator {
            request: request_value,
            resource: resource_value,
            budget,
            scope,
        };
        let outcome = walk_items(&service.items, &segments, ctx, &mut ev, &mut matched_any);
        budget = ev.budget;
        match outcome {
            Ok(true) => {
                return EvaluationReport {
                    decision: Decision::Allow,
                    expressions_evaluated: budget.expressions,
                    max_call_depth: budget.max_depth_seen,
                }
            }
            Ok(false) | Err(EvalError::Soft(_)) => {}
            Err(EvalError::Budget {
                limit_id,
                current,
                maximum,
            }) => {
                return EvaluationReport {
                    decision: Decision::Deny(DenyReason::BudgetExceeded {
                        limit_id,
                        current,
                        maximum,
                    }),
                    expressions_evaluated: budget.expressions,
                    max_call_depth: budget.max_depth_seen,
                }
            }
            Err(EvalError::Unsupported(m)) => unsupported = Some(m),
        }
    }
    let decision = if let Some(m) = unsupported {
        Decision::Deny(DenyReason::Unsupported(m))
    } else if matched_any {
        Decision::Deny(DenyReason::NoMatchingAllow)
    } else {
        Decision::Deny(DenyReason::NoMatchingRule)
    };
    EvaluationReport {
        decision,
        expressions_evaluated: budget.expressions,
        max_call_depth: budget.max_depth_seen,
    }
}

fn build_request(ctx: &RequestContext) -> RulesValue {
    let mut m = BTreeMap::new();
    m.insert(
        "auth".to_owned(),
        ctx.auth
            .as_ref()
            .map_or(RulesValue::Null, AuthContext::to_value),
    );
    m.insert(
        "method".to_owned(),
        RulesValue::String(ctx.method.name().to_owned()),
    );
    m.insert(
        "path".to_owned(),
        RulesValue::Path(
            ctx.path
                .trim_start_matches('/')
                .split('/')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
        ),
    );
    m.insert(
        "time".to_owned(),
        RulesValue::Timestamp(ctx.time_unix_seconds),
    );
    m.insert(
        "resource".to_owned(),
        ctx.request_resource.clone().unwrap_or(RulesValue::Null),
    );
    RulesValue::Map(m)
}

/// Walks items; returns `Ok(true)` as soon as an allow succeeds. Unsupported errors are
/// remembered by the caller; soft errors only make that allow false.
fn walk_items<'a>(
    items: &'a [Item],
    remaining: &[String],
    ctx: &RequestContext,
    ev: &mut Evaluator<'a>,
    matched_any: &mut bool,
) -> Result<bool, EvalError> {
    let mut deferred_unsupported: Option<EvalError> = None;
    for item in items {
        if let Item::Match(block) = item {
            match walk_match(block, remaining, ctx, ev, matched_any) {
                Ok(true) => return Ok(true),
                Ok(false) | Err(EvalError::Soft(_)) => {}
                Err(EvalError::Budget {
                    limit_id,
                    current,
                    maximum,
                }) => {
                    return Err(EvalError::Budget {
                        limit_id,
                        current,
                        maximum,
                    })
                }
                Err(e @ EvalError::Unsupported(_)) => deferred_unsupported = Some(e),
            }
        }
    }
    match deferred_unsupported {
        Some(e) => Err(e),
        None => Ok(false),
    }
}

fn walk_match<'a>(
    block: &'a MatchBlock,
    remaining: &[String],
    ctx: &RequestContext,
    ev: &mut Evaluator<'a>,
    matched_any: &mut bool,
) -> Result<bool, EvalError> {
    let Some((rest, captures)) = match_path(&block.path, remaining) else {
        return Ok(false);
    };
    let functions_before = ev.scope.functions.len();
    let bindings_before = ev.scope.bindings.len();
    for item in &block.items {
        if let Item::Function(f) = item {
            ev.scope.functions.push(f);
        }
    }
    ev.scope.bindings.extend(captures);
    let mut result: Result<bool, EvalError> = Ok(false);
    if rest.is_empty() {
        *matched_any = true;
        result = evaluate_allows(&block.allows, ctx, ev);
    }
    if !matches!(result, Ok(true)) {
        let nested = walk_items(&block.items, &rest, ctx, ev, matched_any);
        result = match (result, nested) {
            (_, Ok(true)) => Ok(true),
            (Err(e), Ok(false)) | (Ok(false) | Err(_), Err(e)) => Err(e),
            (Ok(false), Ok(false)) => Ok(false),
            (Ok(true), r) => r,
        };
    }
    ev.scope.functions.truncate(functions_before);
    ev.scope.bindings.truncate(bindings_before);
    result
}

/// Unmatched remainder and captured bindings of a path match.
type PathMatch = (Vec<String>, Vec<(String, RulesValue)>);

/// Matches `pattern` against the start of `segments`; returns the unmatched remainder and
/// the captured bindings.
fn match_path(pattern: &[PathSegment], segments: &[String]) -> Option<PathMatch> {
    let mut captures = Vec::new();
    let mut i = 0;
    for seg in pattern {
        match seg {
            PathSegment::Literal(l) => {
                if segments.get(i)? != l {
                    return None;
                }
                i += 1;
            }
            PathSegment::Capture { name, .. } => {
                let v = segments.get(i)?;
                captures.push((name.clone(), RulesValue::String(v.clone())));
                i += 1;
            }
            PathSegment::RecursiveWildcard { name, .. } => {
                let rest: Vec<String> = segments[i..].to_vec();
                captures.push((name.clone(), RulesValue::Path(rest)));
                i = segments.len();
            }
            PathSegment::Binding(_) => return None,
        }
    }
    Some((segments[i..].to_vec(), captures))
}

fn evaluate_allows<'a>(
    allows: &'a [Allow],
    ctx: &RequestContext,
    ev: &mut Evaluator<'a>,
) -> Result<bool, EvalError> {
    let mut deferred: Option<EvalError> = None;
    for allow in allows {
        if !allow.methods.iter().any(|m| ctx.method.covered_by(*m)) {
            continue;
        }
        let Some(cond) = &allow.condition else {
            return Ok(true);
        };
        match ev.eval(cond) {
            Ok(RulesValue::Bool(true)) => return Ok(true),
            Ok(_) | Err(EvalError::Soft(_)) => {}
            Err(e @ EvalError::Budget { .. }) => return Err(e),
            Err(e @ EvalError::Unsupported(_)) => deferred = Some(e),
        }
    }
    match deferred {
        Some(e) => Err(e),
        None => Ok(false),
    }
}

fn soft(msg: impl Into<String>) -> EvalError {
    EvalError::Soft(msg.into())
}

fn truthy(v: &RulesValue) -> Result<bool, EvalError> {
    match v {
        RulesValue::Bool(b) => Ok(*b),
        other => Err(soft(format!("expected bool, got {}", other.type_name()))),
    }
}

impl<'a> Evaluator<'a> {
    fn lookup(&self, name: &str) -> Option<RulesValue> {
        if let Some((_, v)) = self.scope.bindings.iter().rev().find(|(n, _)| n == name) {
            return Some(v.clone());
        }
        match name {
            "request" => Some(self.request.clone()),
            "resource" => Some(self.resource.clone()),
            _ => None,
        }
    }

    fn function(&self, name: &str) -> Option<&'a FunctionDecl> {
        self.scope
            .functions
            .iter()
            .rev()
            .find(|f| f.name == name)
            .copied()
    }

    #[allow(clippy::too_many_lines)]
    fn eval(&mut self, expr: &Expr) -> Result<RulesValue, EvalError> {
        self.budget.charge()?;
        match expr {
            Expr::Literal(l) => Ok(match l {
                Literal::Null => RulesValue::Null,
                Literal::Bool(b) => RulesValue::Bool(*b),
                Literal::Int(i) => RulesValue::Int(*i),
                Literal::Float(f) => RulesValue::Float(*f),
                Literal::Str(s) => RulesValue::String(s.clone()),
            }),
            Expr::Ident(name) => self
                .lookup(name)
                .ok_or_else(|| soft(format!("unknown identifier {name}"))),
            Expr::Member { object, name } => {
                let obj = self.eval(object)?;
                match obj {
                    RulesValue::Map(m) => m
                        .get(name)
                        .cloned()
                        .ok_or_else(|| soft(format!("missing member {name}"))),
                    RulesValue::Null => Err(soft(format!("member {name} of null"))),
                    other => Err(soft(format!("member {name} of {}", other.type_name()))),
                }
            }
            Expr::Index { object, index } => {
                let obj = self.eval(object)?;
                let idx = self.eval(index)?;
                match (obj, idx) {
                    (RulesValue::Map(m), RulesValue::String(k)) => m
                        .get(&k)
                        .cloned()
                        .ok_or_else(|| soft(format!("missing key {k}"))),
                    (RulesValue::List(items), RulesValue::Int(i)) => usize::try_from(i)
                        .ok()
                        .and_then(|i| items.get(i).cloned())
                        .ok_or_else(|| soft("list index out of range")),
                    (RulesValue::Path(segments), RulesValue::Int(i)) => usize::try_from(i)
                        .ok()
                        .and_then(|i| segments.get(i).cloned())
                        .map(RulesValue::String)
                        .ok_or_else(|| soft("path index out of range")),
                    (RulesValue::String(s), RulesValue::Int(i)) => usize::try_from(i)
                        .ok()
                        .and_then(|i| s.chars().nth(i))
                        .map(|c| RulesValue::String(c.to_string()))
                        .ok_or_else(|| soft("string index out of range")),
                    (o, i) => Err(soft(format!(
                        "cannot index {} with {}",
                        o.type_name(),
                        i.type_name()
                    ))),
                }
            }
            Expr::Call { callee, args, .. } => self.call(callee, args),
            Expr::Unary { op, expr } => {
                let v = self.eval(expr)?;
                match (op, v) {
                    (UnaryOp::Not, RulesValue::Bool(b)) => Ok(RulesValue::Bool(!b)),
                    (UnaryOp::Neg, RulesValue::Int(i)) => i
                        .checked_neg()
                        .map(RulesValue::Int)
                        .ok_or_else(|| soft("integer overflow")),
                    (UnaryOp::Neg, RulesValue::Float(f)) => Ok(RulesValue::Float(-f)),
                    (_, v) => Err(soft(format!("unary operator on {}", v.type_name()))),
                }
            }
            Expr::Binary { op, left, right } => self.binary(*op, left, right),
            Expr::Ternary {
                cond,
                then,
                otherwise,
            } => {
                let c = self.eval(cond)?;
                if truthy(&c)? {
                    self.eval(then)
                } else {
                    self.eval(otherwise)
                }
            }
            Expr::List(items) => Ok(RulesValue::List(
                items
                    .iter()
                    .map(|i| self.eval(i))
                    .collect::<Result<_, _>>()?,
            )),
            Expr::Map(entries) => {
                let mut m = BTreeMap::new();
                for (k, v) in entries {
                    m.insert(k.clone(), self.eval(v)?);
                }
                Ok(RulesValue::Map(m))
            }
            Expr::Path(segments) => {
                let mut out = Vec::new();
                for s in segments {
                    match s {
                        PathSegment::Literal(l) => out.push(l.clone()),
                        PathSegment::Binding(e) => match self.eval(e)? {
                            RulesValue::String(s) => out.push(s),
                            RulesValue::Path(p) => out.extend(p),
                            RulesValue::Int(i) => out.push(i.to_string()),
                            other => {
                                return Err(soft(format!("path binding of {}", other.type_name())))
                            }
                        },
                        PathSegment::Capture { .. } | PathSegment::RecursiveWildcard { .. } => {
                            return Err(soft("captures are not allowed in path literals"))
                        }
                    }
                }
                Ok(RulesValue::Path(out))
            }
            Expr::Is { expr, type_name } => {
                let v = self.eval(expr)?;
                let matches = match type_name.as_str() {
                    "number" => matches!(v, RulesValue::Int(_) | RulesValue::Float(_)),
                    "latlng" | "bytes" | "duration" => {
                        return Err(EvalError::Unsupported(format!(
                            "`is {type_name}` is not implemented"
                        )))
                    }
                    t => v.type_name() == t,
                };
                Ok(RulesValue::Bool(matches))
            }
        }
    }

    #[allow(clippy::many_single_char_names)]
    fn binary(&mut self, op: BinaryOp, left: &Expr, right: &Expr) -> Result<RulesValue, EvalError> {
        use RulesValue as V;
        // Short-circuit operators charge only the operands they evaluate. Long chains parse
        // left-nested; they are flattened here so that evaluation depth stays bounded.
        if matches!(op, BinaryOp::And | BinaryOp::Or) {
            let mut operands: Vec<&Expr> = vec![right];
            let mut cursor = left;
            while let Expr::Binary {
                op: inner,
                left: l,
                right: r,
            } = cursor
            {
                if *inner != op {
                    break;
                }
                // Each nested node is one expression evaluation.
                self.budget.charge()?;
                operands.push(r);
                cursor = l;
            }
            operands.push(cursor);
            let stop_on = matches!(op, BinaryOp::Or);
            for operand in operands.into_iter().rev() {
                let v = self.eval(operand)?;
                if truthy(&v)? == stop_on {
                    return Ok(RulesValue::Bool(stop_on));
                }
            }
            return Ok(RulesValue::Bool(!stop_on));
        }
        let l = self.eval(left)?;
        let r = self.eval(right)?;
        Ok(match (op, &l, &r) {
            (BinaryOp::Eq, a, b) => V::Bool(values_equal(a, b)),
            (BinaryOp::Ne, a, b) => V::Bool(!values_equal(a, b)),
            (BinaryOp::In, item, V::List(items)) => {
                V::Bool(items.iter().any(|x| values_equal(x, item)))
            }
            (BinaryOp::In, V::String(k), V::Map(m)) => V::Bool(m.contains_key(k)),
            (BinaryOp::In, _, other) => return Err(soft(format!("`in` on {}", other.type_name()))),
            (BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge, a, b) => {
                let ord = compare(a, b)?;
                V::Bool(match op {
                    BinaryOp::Lt => ord.is_lt(),
                    BinaryOp::Le => ord.is_le(),
                    BinaryOp::Gt => ord.is_gt(),
                    _ => ord.is_ge(),
                })
            }
            (BinaryOp::Add, V::String(a), V::String(b)) => V::String(format!("{a}{b}")),
            (BinaryOp::Add, V::List(a), V::List(b)) => {
                V::List(a.iter().chain(b).cloned().collect())
            }
            (
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod,
                V::Int(a),
                V::Int(b),
            ) => {
                let r = match op {
                    BinaryOp::Add => a.checked_add(*b),
                    BinaryOp::Sub => a.checked_sub(*b),
                    BinaryOp::Mul => a.checked_mul(*b),
                    BinaryOp::Div => a.checked_div(*b),
                    _ => a.checked_rem(*b),
                };
                V::Int(r.ok_or_else(|| soft("integer overflow or division by zero"))?)
            }
            (
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod,
                a,
                b,
            ) => {
                let (x, y) = (as_float(a)?, as_float(b)?);
                V::Float(match op {
                    BinaryOp::Add => x + y,
                    BinaryOp::Sub => x - y,
                    BinaryOp::Mul => x * y,
                    BinaryOp::Div => x / y,
                    _ => x % y,
                })
            }
            (BinaryOp::And | BinaryOp::Or, _, _) => unreachable!("handled above"),
        })
    }

    fn call(&mut self, callee: &Expr, args: &[Expr]) -> Result<RulesValue, EvalError> {
        match callee {
            Expr::Ident(name) => {
                if let Some(f) = self.function(name) {
                    let values = args
                        .iter()
                        .map(|a| self.eval(a))
                        .collect::<Result<Vec<_>, _>>()?;
                    return self.call_user(f, values);
                }
                match name.as_str() {
                    "get" | "exists" | "getAfter" => Err(EvalError::Unsupported(format!(
                        "{name}() document access is not implemented in this evaluator"
                    ))),
                    "debug" => match args {
                        [a] => self.eval(a),
                        _ => Err(soft("debug() takes one argument")),
                    },
                    "int" | "string" | "float" | "path" => {
                        let [a] = args else {
                            return Err(soft(format!("{name}() takes one argument")));
                        };
                        let v = self.eval(a)?;
                        convert(name, v)
                    }
                    "timestamp" | "duration" | "latlng" | "math" | "hashing" => Err(
                        EvalError::Unsupported(format!("{name} namespace is not implemented")),
                    ),
                    _ => Err(soft(format!("unknown function {name}"))),
                }
            }
            Expr::Member { object, name } => {
                let receiver = self.eval(object)?;
                let values = args
                    .iter()
                    .map(|a| self.eval(a))
                    .collect::<Result<Vec<_>, _>>()?;
                method_call(&receiver, name, &values)
            }
            _ => Err(soft("call target is not callable")),
        }
    }

    fn call_user(
        &mut self,
        f: &'a FunctionDecl,
        values: Vec<RulesValue>,
    ) -> Result<RulesValue, EvalError> {
        if values.len() != f.params.len() {
            return Err(soft(format!(
                "{} expects {} arguments",
                f.name,
                f.params.len()
            )));
        }
        self.budget.enter_call()?;
        let bindings_before = self.scope.bindings.len();
        for (p, v) in f.params.iter().zip(values) {
            self.scope.bindings.push((p.clone(), v));
        }
        let result = (|| {
            for l in &f.lets {
                let v = self.eval(&l.value)?;
                self.scope.bindings.push((l.name.clone(), v));
            }
            self.eval(&f.body)
        })();
        self.scope.bindings.truncate(bindings_before);
        self.budget.leave_call();
        result
    }
}

// Int / float equality follows the Rules language (numeric comparison), so the widening cast
// and the exact float comparison are intentional.
#[allow(clippy::cast_precision_loss, clippy::float_cmp)]
fn values_equal(a: &RulesValue, b: &RulesValue) -> bool {
    match (a, b) {
        (RulesValue::Int(x), RulesValue::Float(y)) | (RulesValue::Float(y), RulesValue::Int(x)) => {
            (*x as f64) == *y
        }
        _ => a == b,
    }
}

#[allow(clippy::cast_precision_loss)]
fn as_float(v: &RulesValue) -> Result<f64, EvalError> {
    match v {
        RulesValue::Int(i) => Ok(*i as f64),
        RulesValue::Float(f) => Ok(*f),
        other => Err(soft(format!("arithmetic on {}", other.type_name()))),
    }
}

fn compare(a: &RulesValue, b: &RulesValue) -> Result<core::cmp::Ordering, EvalError> {
    use RulesValue as V;
    match (a, b) {
        (V::Int(x), V::Int(y)) | (V::Timestamp(x), V::Timestamp(y)) => Ok(x.cmp(y)),
        (V::String(x), V::String(y)) => Ok(x.cmp(y)),
        (V::Int(_) | V::Float(_), V::Int(_) | V::Float(_)) => as_float(a)?
            .partial_cmp(&as_float(b)?)
            .ok_or_else(|| soft("NaN comparison")),
        _ => Err(soft(format!(
            "cannot compare {} with {}",
            a.type_name(),
            b.type_name()
        ))),
    }
}

#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn convert(name: &str, v: RulesValue) -> Result<RulesValue, EvalError> {
    use RulesValue as V;
    Ok(match (name, v) {
        ("int", V::Int(i)) => V::Int(i),
        ("int", V::String(s)) => V::Int(
            s.trim()
                .parse()
                .map_err(|_| soft("int() of non-numeric string"))?,
        ),
        ("int", V::Float(f)) if f.is_finite() && f.fract() == 0.0 => V::Int(f as i64),
        ("float", V::Int(i)) => V::Float(i as f64),
        ("float", V::Float(f)) => V::Float(f),
        ("float", V::String(s)) => V::Float(
            s.trim()
                .parse()
                .map_err(|_| soft("float() of non-numeric string"))?,
        ),
        ("string", V::String(s)) => V::String(s),
        ("string", V::Int(i)) => V::String(i.to_string()),
        ("string", V::Bool(b)) => V::String(b.to_string()),
        ("path", V::String(s)) => V::Path(
            s.trim_start_matches('/')
                .split('/')
                .filter(|x| !x.is_empty())
                .map(str::to_owned)
                .collect(),
        ),
        (_, other) => return Err(soft(format!("{name}() of {}", other.type_name()))),
    })
}

#[allow(clippy::too_many_lines)]
fn method_call(
    receiver: &RulesValue,
    name: &str,
    args: &[RulesValue],
) -> Result<RulesValue, EvalError> {
    use RulesValue as V;
    let arity = |n: usize| -> Result<(), EvalError> {
        if args.len() == n {
            Ok(())
        } else {
            Err(soft(format!("{name}() takes {n} argument(s)")))
        }
    };
    let list_arg = |a: &RulesValue| -> Result<Vec<RulesValue>, EvalError> {
        match a {
            V::List(items) => Ok(items.clone()),
            other => Err(soft(format!(
                "{name}() expects a list, got {}",
                other.type_name()
            ))),
        }
    };
    Ok(match (receiver, name) {
        (V::String(s), "size") => {
            arity(0)?;
            V::Int(i64::try_from(s.chars().count()).unwrap_or(i64::MAX))
        }
        (V::String(s), "lower") => {
            arity(0)?;
            V::String(s.to_lowercase())
        }
        (V::String(s), "upper") => {
            arity(0)?;
            V::String(s.to_uppercase())
        }
        (V::String(s), "trim") => {
            arity(0)?;
            V::String(s.trim().to_owned())
        }
        (V::String(s), "split") => {
            arity(1)?;
            match &args[0] {
                V::String(sep) => V::List(
                    s.split(sep.as_str())
                        .map(|p| V::String(p.to_owned()))
                        .collect(),
                ),
                _ => return Err(soft("split() expects a string")),
            }
        }
        (V::String(_), "matches" | "replace") => {
            return Err(EvalError::Unsupported(format!(
                "string.{name}() (regular expressions) is not implemented"
            )))
        }
        (V::List(items), "size") => {
            arity(0)?;
            V::Int(i64::try_from(items.len()).unwrap_or(i64::MAX))
        }
        (V::List(items), "hasAll") => {
            arity(1)?;
            let wanted = list_arg(&args[0])?;
            V::Bool(
                wanted
                    .iter()
                    .all(|w| items.iter().any(|i| values_equal(i, w))),
            )
        }
        (V::List(items), "hasAny") => {
            arity(1)?;
            let wanted = list_arg(&args[0])?;
            V::Bool(
                wanted
                    .iter()
                    .any(|w| items.iter().any(|i| values_equal(i, w))),
            )
        }
        (V::List(items), "hasOnly") => {
            arity(1)?;
            let allowed = list_arg(&args[0])?;
            V::Bool(
                items
                    .iter()
                    .all(|i| allowed.iter().any(|a| values_equal(i, a))),
            )
        }
        (V::List(items), "join") => {
            arity(1)?;
            match &args[0] {
                V::String(sep) => {
                    let parts: Result<Vec<String>, EvalError> = items
                        .iter()
                        .map(|i| match i {
                            V::String(s) => Ok(s.clone()),
                            other => Err(soft(format!(
                                "join() on list containing {}",
                                other.type_name()
                            ))),
                        })
                        .collect();
                    V::String(parts?.join(sep))
                }
                _ => return Err(soft("join() expects a string")),
            }
        }
        (V::List(items), "concat") => {
            arity(1)?;
            V::List(items.iter().cloned().chain(list_arg(&args[0])?).collect())
        }
        (V::Map(m), "keys") => {
            arity(0)?;
            V::List(m.keys().cloned().map(V::String).collect())
        }
        (V::Map(m), "values") => {
            arity(0)?;
            V::List(m.values().cloned().collect())
        }
        (V::Map(m), "size") => {
            arity(0)?;
            V::Int(i64::try_from(m.len()).unwrap_or(i64::MAX))
        }
        (V::Map(m), "get") => {
            arity(2)?;
            match &args[0] {
                V::String(k) => m.get(k).cloned().unwrap_or_else(|| args[1].clone()),
                _ => return Err(soft("get() expects a string key")),
            }
        }
        (V::Map(_), "diff") => {
            return Err(EvalError::Unsupported(
                "map.diff() is not implemented".into(),
            ))
        }
        (V::Path(p), "size") => {
            arity(0)?;
            V::Int(i64::try_from(p.len()).unwrap_or(i64::MAX))
        }
        (V::Timestamp(t), "toMillis") => {
            arity(0)?;
            V::Int(t.saturating_mul(1_000))
        }
        (V::Timestamp(_), _) => {
            return Err(EvalError::Unsupported(format!(
                "timestamp.{name}() is not implemented"
            )))
        }
        (other, _) => {
            return Err(soft(format!(
                "unknown method {name} on {}",
                other.type_name()
            )))
        }
    })
}
