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
//! - type / missing-member errors make a condition false (as on the backend); a feature
//!   this evaluator does not implement makes the request deny with an explicit reason (fail
//!   closed, ADR-005);
//! - `get()` / `exists()` / `getAfter()` through a [`DocumentAccess`], the `timestamp`,
//!   `duration`, `latlng`, `math` and `hashing` namespaces, `map.diff()`, and the
//!   `firestore.get()` / `firestore.exists()` namespace of Storage rules.

use std::collections::BTreeMap;

use fireemu_core_limits::catalogs::FIREBASE_RULES_2026_08_25;
use fireemu_core_limits::model::LimitMaximum;

use crate::ast::{
    Allow, BinaryOp, Expr, ExprKind, FunctionDecl, Item, Literal, MatchBlock, Method as AstMethod,
    PathSegment, Ruleset, UnaryOp,
};
use crate::coverage::{Coverage, ExprValue, UndefinedCause};
use crate::value::{AuthContext, MapDiff, RulesValue, ValueRange};

/// Namespaces callable as `namespace.function(...)` unless shadowed by a binding.
const NAMESPACES: [&str; 6] = [
    "timestamp",
    "duration",
    "latlng",
    "math",
    "hashing",
    "firestore",
];

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

/// Path segment that stands for "any document" in a query proof (see
/// `RequestContext::abstract_path`); captures binding it are undetermined and no literal
/// segment equals it.
pub const ABSTRACT_SEGMENT: &str = "fireemu-placeholder";

/// Path segment that stands for "any ancestor prefix, of any depth" (collection-group
/// proofs); only a recursive wildcard can consume it.
pub const ABSTRACT_PREFIX: &str = "fireemu-any-prefix";

fn is_abstract_segment(s: &str) -> bool {
    s == ABSTRACT_SEGMENT || s == ABSTRACT_PREFIX
}

/// Which `service` block of the ruleset applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RulesService {
    /// `service cloud.firestore`.
    #[default]
    Firestore,
    /// `service firebase.storage`.
    Storage,
}

impl RulesService {
    /// Name as written in the ruleset.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Firestore => "cloud.firestore",
            Self::Storage => "firebase.storage",
        }
    }
}

/// Request being authorized.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestContext {
    /// Service block to evaluate.
    pub service: RulesService,
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
    /// `request.time` in Unix nanoseconds.
    pub time_unix_nanos: i128,
    /// Query proof mode: path captures and `request.path` are undetermined (the request
    /// stands for every potential result).
    pub abstract_path: bool,
    /// `request.query` (`limit`, `offset`, `orderBy`) of a list request; `None` elsewhere.
    pub request_query: Option<RulesValue>,
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
    /// `resource` was read while the request carried no existing document. A `list`
    /// evaluation over an empty result set uses this to tell "denied by the rule" from
    /// "undecidable without a document" (spec RULES-LIST-APPROX).
    pub absent_resource_used: bool,
}

#[derive(Debug, Clone)]
enum EvalError {
    /// Condition is false because of a type / missing member error. The message is kept for
    /// the `rules explain` output (Milestone H); it does not influence the decision.
    Soft(String),
    /// The value is not determined by the request (query proofs); the condition cannot be
    /// proven and the allow does not apply.
    Unknown,
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

    /// One more frame. The budget counts *calls* rather than frames, as the official
    /// compiler does: a chain of 21 functions is 20 calls and is within a maximum of 20.
    fn enter_call(&mut self) -> Result<(), EvalError> {
        self.depth = self.depth.saturating_add(1);
        self.max_depth_seen = self.max_depth_seen.max(self.depth);
        let calls = u64::from(self.depth).saturating_sub(1);
        if calls > self.depth_max {
            return Err(EvalError::Budget {
                limit_id: "RULES-FUNCTION-CALL-DEPTH",
                current: calls,
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
    bindings: Vec<Binding<'a>>,
}

struct Binding<'a> {
    name: String,
    visible_before: usize,
    state: BindingState<'a>,
}

enum BindingState<'a> {
    Value(RulesValue),
    Lazy(&'a Expr),
    Evaluating,
    Resolved(Result<RulesValue, EvalError>),
}

impl Binding<'_> {
    fn value(name: String, value: RulesValue) -> Self {
        Self {
            name,
            visible_before: 0,
            state: BindingState::Value(value),
        }
    }
}

/// Reads other documents for `get()` / `exists()`. `segments` is the rules path after the
/// leading slash (`["databases", db, "documents", ...]`); `None` means the document does not
/// exist. Implementations decide the consistency (a commit's staged state, a snapshot).
pub trait DocumentAccess {
    /// The document as a `resource`-shaped value (`data`, `id`, `__name__`), if it exists.
    fn get(&self, segments: &[String]) -> Option<RulesValue>;

    /// `getAfter()`: the document as it will be once the current write (every write of the
    /// batch or transaction) has completed. `None` = not available (reads, query proofs:
    /// `getAfter()` then fails closed); `Some(None)` = it will not exist.
    fn get_after(&self, _segments: &[String]) -> Option<Option<RulesValue>> {
        None
    }
}

/// No document access: `get()` / `exists()` are unsupported.
pub struct NoDocumentAccess;

impl DocumentAccess for NoDocumentAccess {
    fn get(&self, _: &[String]) -> Option<RulesValue> {
        None
    }
}

struct Evaluator<'a> {
    /// Current `eval` recursion depth.
    nesting: u32,
    request: RulesValue,
    resource: RulesValue,
    /// `get()` / `exists()` provider (`None` = unsupported).
    access: Option<&'a dyn DocumentAccess>,
    /// Documents read so far, keyed by (`getAfter`?, path): a path is charged once per
    /// request and kind, as in production.
    doc_cache: BTreeMap<(bool, Vec<String>), Option<RulesValue>>,
    doc_reads_max: u64,
    /// `rules_version = '2'`: `**` matches zero or more segments.
    wildcard_zero_or_more: bool,
    resource_absent: bool,
    absent_resource_used: core::cell::Cell<bool>,
    budget: Budget,
    scope: Scope<'a>,
    /// Where every evaluated expression's value is recorded, when a trace was asked for.
    coverage: Option<&'a core::cell::RefCell<Coverage>>,
    /// The innermost expression that raised while the current error propagates, so an
    /// `undefined` value names the cause rather than the outermost node.
    cause: Option<UndefinedCause>,
}

/// Evaluates a request against a ruleset without document access (`get()` / `exists()` are
/// unsupported and fail closed).
#[must_use]
pub fn evaluate_request(ruleset: &Ruleset, ctx: &RequestContext) -> EvaluationReport {
    evaluate_request_with(ruleset, ctx, None)
}

/// Evaluates a request and records what every expression evaluated to, which is what a
/// coverage report and a request trace are built from (`RULES-PARITY-04`).
#[must_use]
pub fn evaluate_request_traced(
    ruleset: &Ruleset,
    ctx: &RequestContext,
    access: Option<&dyn DocumentAccess>,
) -> (EvaluationReport, Coverage) {
    let coverage = core::cell::RefCell::new(Coverage::default());
    let report = evaluate_with_coverage(ruleset, ctx, access, Some(&coverage));
    (report, coverage.into_inner())
}

/// Evaluates a request against a ruleset; `access` serves `get()` / `exists()` within the
/// Maximum `eval` recursion depth (stack safety; parenthesised nesting is bounded by the
/// parser, left-nested operator chains are bounded here).
pub const MAX_EVAL_NESTING: u32 = 64;

/// `RULES-DOC-ACCESS-SINGLE` budget.
#[must_use]
pub fn evaluate_request_with(
    ruleset: &Ruleset,
    ctx: &RequestContext,
    access: Option<&dyn DocumentAccess>,
) -> EvaluationReport {
    evaluate_with_coverage(ruleset, ctx, access, None)
}

fn evaluate_with_coverage(
    ruleset: &Ruleset,
    ctx: &RequestContext,
    access: Option<&dyn DocumentAccess>,
    coverage: Option<&core::cell::RefCell<Coverage>>,
) -> EvaluationReport {
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
    let mut absent_resource_used = false;
    for service in &ruleset.services {
        if service.name != ctx.service.name() {
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
            nesting: 0,
            request: request_value,
            resource: resource_value,
            access,
            doc_cache: BTreeMap::new(),
            doc_reads_max: limit_max(match ctx.service {
                RulesService::Firestore => "RULES-DOC-ACCESS-SINGLE",
                // Storage rules may call firestore.get() / exists() twice per request.
                RulesService::Storage => "STORAGE-RULES-FIRESTORE-ACCESS",
            }),
            wildcard_zero_or_more: ruleset.version.as_deref() == Some("2"),
            resource_absent: ctx.resource.is_none(),
            absent_resource_used: core::cell::Cell::new(false),
            budget,
            scope,
            coverage,
            cause: None,
        };
        let outcome = walk_items(&service.items, &segments, ctx, &mut ev, &mut matched_any);
        absent_resource_used |= ev.absent_resource_used.get();
        budget = ev.budget;
        match outcome {
            Ok(true) => {
                return EvaluationReport {
                    decision: Decision::Allow,
                    expressions_evaluated: budget.expressions,
                    max_call_depth: budget.max_depth_seen,
                    absent_resource_used,
                }
            }
            Ok(false) | Err(EvalError::Soft(_) | EvalError::Unknown) => {}
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
                    absent_resource_used,
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
        absent_resource_used,
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
        if ctx.abstract_path {
            RulesValue::Unknown
        } else {
            RulesValue::Path(
                ctx.path
                    .trim_start_matches('/')
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect(),
            )
        },
    );
    m.insert(
        "time".to_owned(),
        RulesValue::Timestamp(ctx.time_unix_nanos),
    );
    // `request.resource` and `request.query` are absent, not null, when the request has no
    // such thing: reading either on a `get` is a missing-member error in the official
    // runtime, and `request.keys()` does not list them (recorded, area `detail`).
    if let Some(resource) = ctx.request_resource.clone() {
        m.insert("resource".to_owned(), resource);
    }
    if let Some(query) = ctx.request_query.clone() {
        m.insert("query".to_owned(), query);
    }
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
                Ok(false) | Err(EvalError::Soft(_) | EvalError::Unknown) => {}
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
    // Every way the pattern can consume the path is tried (`**` backtracks).
    let mut outcome: Result<bool, EvalError> = Ok(false);
    for (rest, captures) in match_path(&block.path, remaining, ev.wildcard_zero_or_more) {
        // In a query proof only the segments standing for potential results are
        // undetermined; the database and any concrete ancestor segments stay known.
        let captures: Vec<(String, RulesValue)> = if ctx.abstract_path {
            captures
                .into_iter()
                .map(|(n, v)| {
                    let placeholder = match &v {
                        RulesValue::String(s) => s == ABSTRACT_SEGMENT,
                        RulesValue::Path(p) => p.iter().any(|s| s == ABSTRACT_SEGMENT),
                        _ => false,
                    };
                    (n, if placeholder { RulesValue::Unknown } else { v })
                })
                .collect()
        } else {
            captures
        };
        let functions_before = ev.scope.functions.len();
        let bindings_before = ev.scope.bindings.len();
        for item in &block.items {
            if let Item::Function(f) = item {
                ev.scope.functions.push(f);
            }
        }
        ev.scope.bindings.extend(
            captures
                .into_iter()
                .map(|(name, value)| Binding::value(name, value)),
        );
        let mut result: Result<bool, EvalError> = Ok(false);
        if rest.is_empty() {
            *matched_any = true;
            result = evaluate_allows(&block.allows, ctx, ev);
        }
        if !matches!(result, Ok(true) | Err(EvalError::Budget { .. })) {
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
        match result {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(e @ EvalError::Budget { .. }) => return Err(e),
            Err(e) => {
                if matches!(outcome, Ok(false)) {
                    outcome = Err(e);
                }
            }
        }
    }
    outcome
}

/// Unmatched remainder and captured bindings of a path match.
type PathMatch = (Vec<String>, Vec<(String, RulesValue)>);

/// Every way `pattern` matches the start of `segments` (a recursive wildcard consumes zero or
/// more segments under rules version 2, one or more under version 1), each with its
/// unmatched remainder and captured bindings.
fn match_path(pattern: &[PathSegment], segments: &[String], zero_or_more: bool) -> Vec<PathMatch> {
    fn go(
        pattern: &[PathSegment],
        segments: &[String],
        zero_or_more: bool,
        captures: &mut Vec<(String, RulesValue)>,
        out: &mut Vec<PathMatch>,
    ) {
        let Some((seg, tail)) = pattern.split_first() else {
            out.push((segments.to_vec(), captures.clone()));
            return;
        };
        match seg {
            PathSegment::Literal(l) => {
                // An undetermined segment is never equal to a literal.
                if segments.first() == Some(l) && !is_abstract_segment(l) {
                    go(tail, &segments[1..], zero_or_more, captures, out);
                }
            }
            PathSegment::Capture { name, .. } => {
                // The "any prefix" marker stands for zero or more segments: only `**` fits.
                if let Some(v) = segments.first().filter(|v| v.as_str() != ABSTRACT_PREFIX) {
                    captures.push((name.clone(), RulesValue::String(v.clone())));
                    go(tail, &segments[1..], zero_or_more, captures, out);
                    captures.pop();
                }
            }
            PathSegment::RecursiveWildcard { name, .. } => {
                let min = usize::from(!zero_or_more);
                for take in min..=segments.len() {
                    // A prefix marker must be consumed whole by the wildcard.
                    if segments[take..]
                        .first()
                        .is_some_and(|s| s == ABSTRACT_PREFIX)
                    {
                        continue;
                    }
                    captures.push((name.clone(), RulesValue::Path(segments[..take].to_vec())));
                    go(tail, &segments[take..], zero_or_more, captures, out);
                    captures.pop();
                }
            }
            PathSegment::Binding(_) => {}
        }
    }
    let mut out = Vec::new();
    go(pattern, segments, zero_or_more, &mut Vec::new(), &mut out);
    out
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
            Ok(_) | Err(EvalError::Soft(_) | EvalError::Unknown) => {}
            Err(e @ EvalError::Budget { .. }) => return Err(e),
            Err(e @ EvalError::Unsupported(_)) => deferred = Some(e),
        }
    }
    match deferred {
        Some(e) => Err(e),
        None => Ok(false),
    }
}

/// One line of why an expression is undefined, for a trace.
fn describe(e: &EvalError) -> String {
    match e {
        EvalError::Soft(m) | EvalError::Unsupported(m) => m.clone(),
        EvalError::Unknown => "the request does not determine this value".to_owned(),
        EvalError::Budget {
            limit_id,
            current,
            maximum,
        } => format!("{limit_id}: {current} exceeds {maximum}"),
    }
}

fn soft(msg: impl Into<String>) -> EvalError {
    EvalError::Soft(msg.into())
}

fn regex_runtime_error(error: crate::regex::RegexRuntimeError) -> EvalError {
    match error {
        crate::regex::RegexRuntimeError::StepBudgetExceeded { current, maximum } => {
            EvalError::Budget {
                limit_id: "FIREEMU-REGEX-STEPS-PER-MATCH",
                current,
                maximum,
            }
        }
        crate::regex::RegexRuntimeError::DepthBudgetExceeded { current, maximum } => {
            EvalError::Budget {
                limit_id: "FIREEMU-REGEX-DEPTH-PER-MATCH",
                current,
                maximum,
            }
        }
    }
}

fn truthy(v: &RulesValue) -> Result<bool, EvalError> {
    match v {
        RulesValue::Bool(b) => Ok(*b),
        RulesValue::Unknown => Err(EvalError::Unknown),
        other => Err(soft(format!("expected bool, got {}", other.type_name()))),
    }
}

/// Values whose identity is not determined (query proofs) make most operations undecidable.
/// Undetermined at any depth: a container holding an undetermined member cannot be compared,
/// searched or iterated with a definite result.
fn undetermined(v: &RulesValue) -> bool {
    match v {
        RulesValue::Unknown
        | RulesValue::PartialMap(_)
        | RulesValue::PartialList(_)
        | RulesValue::PartialListAny(_)
        | RulesValue::Range(_)
        | RulesValue::OneOf(_)
        | RulesValue::NotOneOf(_) => true,
        RulesValue::List(items) | RulesValue::Set(items) => items.iter().any(undetermined),
        RulesValue::Map(m) => m.values().any(undetermined),
        _ => false,
    }
}

impl<'a> Evaluator<'a> {
    fn lookup(&mut self, name: &str) -> Result<Option<RulesValue>, EvalError> {
        if let Some(index) = self
            .scope
            .bindings
            .iter()
            .rposition(|binding| binding.name == name)
        {
            return self.resolve_binding(index).map(Some);
        }
        Ok(match name {
            "request" => Some(self.request.clone()),
            "resource" => {
                if self.resource_absent {
                    self.absent_resource_used.set(true);
                }
                Some(self.resource.clone())
            }
            _ => None,
        })
    }

    fn has_binding(&self, name: &str) -> bool {
        self.scope
            .bindings
            .iter()
            .rev()
            .any(|binding| binding.name == name)
    }

    fn resolve_binding(&mut self, index: usize) -> Result<RulesValue, EvalError> {
        let state = core::mem::replace(
            &mut self.scope.bindings[index].state,
            BindingState::Evaluating,
        );
        match state {
            BindingState::Value(value) => {
                self.scope.bindings[index].state = BindingState::Value(value.clone());
                Ok(value)
            }
            BindingState::Resolved(result) => {
                self.scope.bindings[index].state = BindingState::Resolved(result.clone());
                result
            }
            BindingState::Evaluating => {
                self.scope.bindings[index].state = BindingState::Evaluating;
                Err(soft("cyclic let binding"))
            }
            BindingState::Lazy(expr) => {
                let visible_before = self.scope.bindings[index].visible_before;
                let mut hidden = self.scope.bindings.split_off(visible_before);
                let result = self.eval(expr);
                hidden[index - visible_before].state = BindingState::Resolved(result.clone());
                self.scope.bindings.extend(hidden);
                result
            }
        }
    }

    /// Reads a document through the access provider (`after`: `getAfter()`), charging the
    /// budget once per path and kind.
    fn read_document(
        &mut self,
        path: Vec<String>,
        after: bool,
    ) -> Result<Option<RulesValue>, EvalError> {
        let key = (after, path);
        if let Some(cached) = self.doc_cache.get(&key) {
            return Ok(cached.clone());
        }
        let Some(access) = self.access else {
            return Err(EvalError::Unsupported(
                "get()/exists()/getAfter() document access is not available for this request"
                    .into(),
            ));
        };
        let reads = self.doc_cache.len() as u64 + 1;
        if reads > self.doc_reads_max {
            return Err(EvalError::Budget {
                limit_id: "RULES-DOC-ACCESS-SINGLE",
                current: reads,
                maximum: self.doc_reads_max,
            });
        }
        let doc = if after {
            access.get_after(&key.1).ok_or_else(|| {
                EvalError::Unsupported(
                    "getAfter() is only available while a write is authorized".into(),
                )
            })?
        } else {
            access.get(&key.1)
        };
        self.doc_cache.insert(key, doc.clone());
        Ok(doc)
    }

    /// `get()` / `exists()` / `getAfter()` with the evaluated path argument.
    fn document_call(&mut self, name: &str, args: &[RulesValue]) -> Result<RulesValue, EvalError> {
        let [a] = args else {
            return Err(soft(format!("{name}() takes one path")));
        };
        let path = match a {
            RulesValue::Path(p) => p.clone(),
            v if undetermined(v) => return Err(EvalError::Unknown),
            other => {
                return Err(soft(format!(
                    "{name}() expects a path, got {}",
                    other.type_name()
                )))
            }
        };
        let doc = self.read_document(path, name == "getAfter")?;
        Ok(match (name, doc) {
            ("exists", d) => RulesValue::Bool(d.is_some()),
            (_, Some(d)) => d,
            (_, None) => return Err(soft(format!("{name}() of a missing document"))),
        })
    }

    /// `namespace.function(args)` for the built-in namespaces.
    #[allow(clippy::too_many_lines)]
    fn namespace_call(
        &mut self,
        namespace: &str,
        name: &str,
        args: &[RulesValue],
    ) -> Result<RulesValue, EvalError> {
        use RulesValue as V;
        if args.iter().any(undetermined) {
            return Err(EvalError::Unknown);
        }
        let arity = |n: usize| -> Result<(), EvalError> {
            if args.len() == n {
                Ok(())
            } else {
                Err(soft(format!("{namespace}.{name}() takes {n} argument(s)")))
            }
        };
        let int_arg = |i: usize| -> Result<i64, EvalError> {
            match &args[i] {
                V::Int(v) => Ok(*v),
                other => Err(soft(format!(
                    "{namespace}.{name}() expects an int, got {}",
                    other.type_name()
                ))),
            }
        };
        let float_arg = |i: usize| -> Result<f64, EvalError> { as_float(&args[i]) };
        Ok(match (namespace, name) {
            ("firestore", "get" | "exists") => return self.document_call(name, args),
            ("timestamp", "date") => {
                arity(3)?;
                let (y, m, d) = (int_arg(0)?, int_arg(1)?, int_arg(2)?);
                if !crate::civil::is_valid_date(y, m, d) || !(1..=9999).contains(&y) {
                    return Err(soft("timestamp.date(): not a valid date"));
                }
                V::Timestamp(i128::from(crate::civil::days_from_civil(y, m, d)) * NANOS_PER_DAY)
            }
            ("timestamp", "value") => {
                arity(1)?;
                V::Timestamp(i128::from(int_arg(0)?) * 1_000_000)
            }
            ("duration", "value") => {
                arity(2)?;
                let magnitude = i128::from(int_arg(0)?);
                let V::String(unit) = &args[1] else {
                    return Err(soft("duration.value() expects a unit string"));
                };
                let per_unit: i128 = match unit.as_str() {
                    "w" => 7 * NANOS_PER_DAY,
                    "d" => NANOS_PER_DAY,
                    "h" => 3_600_000_000_000,
                    "m" => 60_000_000_000,
                    "s" => 1_000_000_000,
                    "ms" => 1_000_000,
                    "ns" => 1,
                    other => return Err(soft(format!("duration.value(): unknown unit {other:?}"))),
                };
                V::Duration(magnitude * per_unit)
            }
            ("duration", "time") => {
                arity(4)?;
                let (h, m, s, ns) = (int_arg(0)?, int_arg(1)?, int_arg(2)?, int_arg(3)?);
                V::Duration(
                    i128::from(h) * 3_600_000_000_000
                        + i128::from(m) * 60_000_000_000
                        + i128::from(s) * 1_000_000_000
                        + i128::from(ns),
                )
            }
            ("duration", "abs") => {
                arity(1)?;
                match &args[0] {
                    V::Duration(d) => V::Duration(d.abs()),
                    other => return Err(soft(format!("duration.abs() of {}", other.type_name()))),
                }
            }
            ("latlng", "value") => {
                arity(2)?;
                let (latitude, longitude) = (float_arg(0)?, float_arg(1)?);
                if !(-90.0..=90.0).contains(&latitude) || !(-180.0..=180.0).contains(&longitude) {
                    return Err(soft("latlng.value(): out of range"));
                }
                V::LatLng {
                    latitude,
                    longitude,
                }
            }
            ("math", "abs") => {
                arity(1)?;
                match &args[0] {
                    V::Int(i) => V::Int(i.checked_abs().ok_or_else(|| soft("integer overflow"))?),
                    other => V::Float(as_float(other)?.abs()),
                }
            }
            ("math", "ceil" | "floor" | "sqrt") => {
                arity(1)?;
                let x = float_arg(0)?;
                V::Float(match name {
                    "ceil" => x.ceil(),
                    "floor" => x.floor(),
                    _ => x.sqrt(),
                })
            }
            // Alone among them, `round` answers an int, and it rounds a half towards
            // positive infinity: `math.round(-1.5)` is -1, recorded.
            ("math", "round") => {
                arity(1)?;
                let rounded = (float_arg(0)? + 0.5).floor();
                if !rounded.is_finite() || rounded < -(2f64.powi(63)) || rounded >= 2f64.powi(63) {
                    return Err(soft("math.round() out of the int range"));
                }
                #[allow(clippy::cast_possible_truncation)]
                V::Int(rounded as i64)
            }
            ("math", "pow") => {
                arity(2)?;
                V::Float(float_arg(0)?.powf(float_arg(1)?))
            }
            ("math", "isNaN") => {
                arity(1)?;
                V::Bool(float_arg(0)?.is_nan())
            }
            ("hashing", "crc32" | "crc32c" | "md5" | "sha256") => {
                arity(1)?;
                let input: Vec<u8> = match &args[0] {
                    V::Bytes(b) => b.clone(),
                    V::String(s) => s.as_bytes().to_vec(),
                    other => {
                        return Err(soft(format!(
                            "hashing.{name}() expects bytes or a string, got {}",
                            other.type_name()
                        )))
                    }
                };
                V::Bytes(match name {
                    // The checksums come back little-endian: `hashing.crc32('abc')` prints
                    // as `C2412435` where the checksum itself is `0x352441C2`, recorded.
                    "crc32" => crate::hash::crc32(&input).to_le_bytes().to_vec(),
                    "crc32c" => crate::hash::crc32c(&input).to_le_bytes().to_vec(),
                    "md5" => crate::hash::md5(&input).to_vec(),
                    _ => crate::hash::sha256(&input).to_vec(),
                })
            }
            _ => return Err(soft(format!("unknown function {namespace}.{name}()"))),
        })
    }

    fn function(&self, name: &str) -> Option<&'a FunctionDecl> {
        self.scope
            .functions
            .iter()
            .rev()
            .find(|f| f.name == name)
            .copied()
    }

    /// Evaluates `expr` behind a recursion guard: a tree deeper than
    /// [`MAX_EVAL_NESTING`] (left-nested chains are not flattened, unlike `&&` / `||`) is
    /// refused instead of exhausting the stack.
    fn eval(&mut self, expr: &Expr) -> Result<RulesValue, EvalError> {
        if self.nesting >= MAX_EVAL_NESTING {
            return Err(soft("expression nesting exceeds the evaluator budget"));
        }
        self.nesting += 1;
        let result = self.eval_inner(expr);
        self.nesting -= 1;
        if self.coverage.is_some() {
            self.record(expr, &result);
        }
        result
    }

    /// Records one evaluation of `expr`. A success is recorded as its value; a failure as
    /// `undefined`, carrying the innermost expression that actually raised.
    fn record(&mut self, expr: &Expr, result: &Result<RulesValue, EvalError>) {
        let value = match result {
            Ok(v) => {
                self.cause = None;
                ExprValue::of(v)
            }
            Err(e) => {
                if self.cause.is_none() {
                    self.cause = Some(UndefinedCause {
                        span: expr.span,
                        end: expr.end,
                        message: describe(e),
                    });
                }
                ExprValue::Undefined(self.cause.clone().unwrap_or_else(|| UndefinedCause {
                    span: expr.span,
                    end: expr.end,
                    message: describe(e),
                }))
            }
        };
        if let Some(coverage) = self.coverage {
            if let Ok(mut c) = coverage.try_borrow_mut() {
                c.record(expr.span, expr.end, value);
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn eval_inner(&mut self, expr: &Expr) -> Result<RulesValue, EvalError> {
        self.budget.charge()?;
        match expr.kind() {
            ExprKind::Literal(l) => Ok(match l {
                Literal::Null => RulesValue::Null,
                Literal::Bool(b) => RulesValue::Bool(*b),
                Literal::Int(i) => RulesValue::Int(*i),
                Literal::Float(f) => RulesValue::Float(*f),
                Literal::Str(s) => RulesValue::String(s.clone()),
            }),
            ExprKind::Ident(name) => self
                .lookup(name)?
                .ok_or_else(|| soft(format!("unknown identifier {name}"))),
            ExprKind::Member { object, name } => {
                let obj = self.eval(object)?;
                match obj {
                    RulesValue::Map(m) => m
                        .get(name)
                        .cloned()
                        .ok_or_else(|| soft(format!("missing member {name}"))),
                    // A key the query does not constrain may or may not exist.
                    RulesValue::PartialMap(m) => {
                        Ok(m.get(name).cloned().unwrap_or(RulesValue::Unknown))
                    }
                    RulesValue::Unknown => Err(EvalError::Unknown),
                    RulesValue::Null => Err(soft(format!("member {name} of null"))),
                    other => Err(soft(format!("member {name} of {}", other.type_name()))),
                }
            }
            ExprKind::Index { object, index } => {
                let obj = self.eval(object)?;
                let idx = self.eval(index)?;
                match (obj, idx) {
                    (RulesValue::Map(m), RulesValue::String(k)) => m
                        .get(&k)
                        .cloned()
                        .ok_or_else(|| soft(format!("missing key {k}"))),
                    (RulesValue::PartialMap(m), RulesValue::String(k)) => {
                        Ok(m.get(&k).cloned().unwrap_or(RulesValue::Unknown))
                    }
                    (o, i) if undetermined(&o) || undetermined(&i) => Err(EvalError::Unknown),
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
            ExprKind::Slice { object, start, end } => {
                let obj = self.eval(object)?;
                let lo = self.eval(start)?;
                let hi = self.eval(end)?;
                slice(&obj, &lo, &hi)
            }
            ExprKind::Call { callee, args } => self.call(callee, args),
            ExprKind::Unary { op, expr } => {
                let v = self.eval(expr)?;
                match (op, v) {
                    (_, v) if undetermined(&v) => Err(EvalError::Unknown),
                    (UnaryOp::Not, RulesValue::Bool(b)) => Ok(RulesValue::Bool(!b)),
                    (UnaryOp::Neg, RulesValue::Int(i)) => i
                        .checked_neg()
                        .map(RulesValue::Int)
                        .ok_or_else(|| soft("integer overflow")),
                    (UnaryOp::Neg, RulesValue::Float(f)) => Ok(RulesValue::Float(-f)),
                    (_, v) => Err(soft(format!("unary operator on {}", v.type_name()))),
                }
            }
            ExprKind::Binary { op, left, right } => self.binary(*op, left, right),
            ExprKind::Ternary {
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
            ExprKind::List(items) => Ok(RulesValue::List(
                items
                    .iter()
                    .map(|i| self.eval(i))
                    .collect::<Result<_, _>>()?,
            )),
            ExprKind::Map(entries) => {
                let mut m = BTreeMap::new();
                for (k, v) in entries {
                    m.insert(k.clone(), self.eval(v)?);
                }
                Ok(RulesValue::Map(m))
            }
            ExprKind::Path(segments) => {
                let mut out = Vec::new();
                for s in segments {
                    match s {
                        PathSegment::Literal(l) => out.push(l.clone()),
                        PathSegment::Binding(e) => match self.eval(e)? {
                            v if undetermined(&v) => return Err(EvalError::Unknown),
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
            ExprKind::Is { expr, type_name } => {
                let v = self.eval(expr)?;
                if matches!(v, RulesValue::Unknown) {
                    return Err(EvalError::Unknown);
                }
                if let RulesValue::Range(r) = &v {
                    // Every member shares the range's class; `int` vs `float` stays open.
                    let class = r.class().ok_or(EvalError::Unknown)?;
                    return match type_name.as_str() {
                        "int" | "float" if class == "number" => Err(EvalError::Unknown),
                        t => Ok(RulesValue::Bool(t == class)),
                    };
                }
                if let RulesValue::OneOf(members) = &v {
                    // Decided when every member answers the same.
                    let answers: Vec<bool> =
                        members.iter().map(|m| is_type(m, type_name)).collect();
                    return match (answers.iter().all(|a| *a), answers.iter().any(|a| *a)) {
                        (true, _) => Ok(RulesValue::Bool(true)),
                        (false, false) => Ok(RulesValue::Bool(false)),
                        _ => Err(EvalError::Unknown),
                    };
                }
                if matches!(
                    v,
                    RulesValue::NotOneOf(_)
                        | RulesValue::PartialMap(_)
                        | RulesValue::PartialList(_)
                        | RulesValue::PartialListAny(_)
                ) {
                    return match type_name.as_str() {
                        // A partially known container is at least a container of its kind.
                        "map" if matches!(v, RulesValue::PartialMap(_)) => {
                            Ok(RulesValue::Bool(true))
                        }
                        "list"
                            if matches!(
                                v,
                                RulesValue::PartialList(_) | RulesValue::PartialListAny(_)
                            ) =>
                        {
                            Ok(RulesValue::Bool(true))
                        }
                        _ => Err(EvalError::Unknown),
                    };
                }
                Ok(RulesValue::Bool(is_type(&v, type_name)))
            }
        }
    }

    #[allow(clippy::many_single_char_names, clippy::too_many_lines)]
    fn binary(&mut self, op: BinaryOp, left: &Expr, right: &Expr) -> Result<RulesValue, EvalError> {
        use RulesValue as V;
        // Short-circuit operators charge only the operands they evaluate. Long chains parse
        // left-nested; they are flattened here so that evaluation depth stays bounded.
        if matches!(op, BinaryOp::And | BinaryOp::Or) {
            let mut operands: Vec<&Expr> = vec![right];
            let mut cursor = left;
            while let ExprKind::Binary {
                op: inner,
                left: l,
                right: r,
            } = cursor.kind()
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
            // Three-valued: a deciding operand (`false` for `&&`, `true` for `||`) wins
            // even when another operand is undetermined; otherwise an undetermined operand
            // makes the whole expression undetermined.
            // Left to right, as in production: an operand that decides the result ends the
            // evaluation; an undetermined operand (which may be a runtime error for some
            // potential document) makes the whole expression undetermined.
            let stop_on = matches!(op, BinaryOp::Or);
            // The official runtime absorbs a raised operand: `error || true` is true and
            // `error && false` is false, because the deciding operand settles the answer
            // whatever the other one did. A raised operand is therefore remembered rather
            // than propagated, and only surfaces when nothing decides.
            //
            // A budget exhaustion and an unsupported construct are not absorbed: the first
            // ends the request, and the second is fireemu admitting it cannot evaluate the
            // operand, which must never be allowed to read as a permissive answer.
            let mut deferred: Option<EvalError> = None;
            for operand in operands.into_iter().rev() {
                match self.eval(operand).and_then(|v| truthy(&v)) {
                    Ok(b) if b == stop_on => return Ok(RulesValue::Bool(stop_on)),
                    Ok(_) => {}
                    Err(e @ (EvalError::Budget { .. } | EvalError::Unsupported(_))) => {
                        return Err(e)
                    }
                    Err(e) => deferred = Some(deferred.map_or(e, |first| first)),
                }
            }
            return match deferred {
                Some(e) => Err(e),
                None => Ok(RulesValue::Bool(!stop_on)),
            };
        }
        let l = self.eval(left)?;
        let r = self.eval(right)?;
        Ok(match (op, &l, &r) {
            // Membership in a partially known container is provable only positively.
            (BinaryOp::In, item, V::PartialList(known)) if !undetermined(item) => {
                if known.iter().any(|x| values_equal(x, item)) {
                    V::Bool(true)
                } else {
                    return Err(EvalError::Unknown);
                }
            }
            // At least one candidate is present: membership is certain only when every
            // candidate is the item.
            (BinaryOp::In, item, V::PartialListAny(candidates)) if !undetermined(item) => {
                if !candidates.is_empty() && candidates.iter().all(|c| values_equal(c, item)) {
                    V::Bool(true)
                } else {
                    return Err(EvalError::Unknown);
                }
            }
            (BinaryOp::In, V::String(k), V::PartialMap(m)) => {
                if m.contains_key(k) {
                    V::Bool(true)
                } else {
                    return Err(EvalError::Unknown);
                }
            }
            // A range against a concrete value: decided when every member agrees.
            (
                BinaryOp::Eq
                | BinaryOp::Ne
                | BinaryOp::Lt
                | BinaryOp::Le
                | BinaryOp::Gt
                | BinaryOp::Ge,
                V::Range(r),
                c,
            ) if !undetermined(c) => V::Bool(range_relation(r, op, c)?),
            (
                BinaryOp::Eq
                | BinaryOp::Ne
                | BinaryOp::Lt
                | BinaryOp::Le
                | BinaryOp::Gt
                | BinaryOp::Ge,
                c,
                V::Range(r),
            ) if !undetermined(c) => {
                let mirrored = match op {
                    BinaryOp::Lt => BinaryOp::Gt,
                    BinaryOp::Le => BinaryOp::Ge,
                    BinaryOp::Gt => BinaryOp::Lt,
                    BinaryOp::Ge => BinaryOp::Le,
                    other => other,
                };
                V::Bool(range_relation(r, mirrored, c)?)
            }
            // A set of candidates: decided when every candidate answers the same.
            (_, V::OneOf(members), c) if !undetermined(c) => V::Bool(unanimous(
                members.iter().map(|m| binary_concrete(op, m, c)),
            )?),
            (_, c, V::OneOf(members)) if !undetermined(c) => V::Bool(unanimous(
                members.iter().map(|m| binary_concrete(op, c, m)),
            )?),
            // A value known to differ from some values: only equality is ever decided.
            (BinaryOp::Eq | BinaryOp::Ne, V::NotOneOf(excluded), c)
            | (BinaryOp::Eq | BinaryOp::Ne, c, V::NotOneOf(excluded))
                if !undetermined(c) =>
            {
                if excluded.iter().any(|e| values_equal(e, c)) {
                    V::Bool(op == BinaryOp::Ne)
                } else {
                    return Err(EvalError::Unknown);
                }
            }
            (BinaryOp::In, V::NotOneOf(excluded), V::List(items)) if !undetermined(&r) => {
                if items
                    .iter()
                    .all(|i| excluded.iter().any(|e| values_equal(e, i)))
                {
                    V::Bool(false)
                } else {
                    return Err(EvalError::Unknown);
                }
            }
            (_, a, b) if undetermined(a) || undetermined(b) => return Err(EvalError::Unknown),
            (BinaryOp::Eq, a, b) => V::Bool(values_equal(a, b)),
            (BinaryOp::Ne, a, b) => V::Bool(!values_equal(a, b)),
            (BinaryOp::In, item, V::List(items) | V::Set(items)) => {
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
            (BinaryOp::Add, V::Timestamp(t), V::Duration(d))
            | (BinaryOp::Add, V::Duration(d), V::Timestamp(t)) => V::Timestamp(t + d),
            (BinaryOp::Sub, V::Timestamp(t), V::Duration(d)) => V::Timestamp(t - d),
            (BinaryOp::Sub, V::Timestamp(a), V::Timestamp(b))
            | (BinaryOp::Sub, V::Duration(a), V::Duration(b)) => V::Duration(a - b),
            (BinaryOp::Add, V::Duration(a), V::Duration(b)) => V::Duration(a + b),
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
        match callee.kind() {
            ExprKind::Ident(name) => {
                if let Some(f) = self.function(name) {
                    let values = args
                        .iter()
                        .map(|a| self.eval(a))
                        .collect::<Result<Vec<_>, _>>()?;
                    return self.call_user(f, values);
                }
                match name.as_str() {
                    "get" | "exists" | "getAfter" => {
                        let values = args
                            .iter()
                            .map(|a| self.eval(a))
                            .collect::<Result<Vec<_>, _>>()?;
                        self.document_call(name, &values)
                    }
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
                    _ => Err(soft(format!("unknown function {name}"))),
                }
            }
            ExprKind::Member { object, name } => {
                if let ExprKind::Ident(ns) = object.kind() {
                    if NAMESPACES.contains(&ns.as_str()) && !self.has_binding(ns.as_str()) {
                        let values = args
                            .iter()
                            .map(|a| self.eval(a))
                            .collect::<Result<Vec<_>, _>>()?;
                        return self.namespace_call(ns.as_str(), name, &values);
                    }
                }
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
            self.scope.bindings.push(Binding::value(p.clone(), v));
        }
        let result = {
            for l in &f.lets {
                let visible_before = self.scope.bindings.len();
                self.scope.bindings.push(Binding {
                    name: l.name.clone(),
                    visible_before,
                    state: BindingState::Lazy(&l.value),
                });
            }
            self.eval(&f.body)
        };
        self.scope.bindings.truncate(bindings_before);
        self.budget.leave_call();
        result
    }
}

// Int / float equality follows the Rules language (numeric comparison), so the widening cast
// and the exact float comparison are intentional.
#[allow(clippy::cast_precision_loss, clippy::float_cmp)]
fn values_equal(a: &RulesValue, b: &RulesValue) -> bool {
    debug_assert!(
        !undetermined(a) && !undetermined(b),
        "undetermined values never compare"
    );
    match (a, b) {
        (RulesValue::Int(x), RulesValue::Float(y)) | (RulesValue::Float(y), RulesValue::Int(x)) => {
            !y.is_nan() && cmp_int_double(*x, *y) == core::cmp::Ordering::Equal
        }
        // Two sets are equal when they hold the same members, in whatever order; a set is
        // never equal to a list.
        (RulesValue::Set(x), RulesValue::Set(y)) => {
            x.len() == y.len() && x.iter().all(|i| y.iter().any(|j| values_equal(i, j)))
        }
        _ => a == b,
    }
}

/// Exact ordering of an `i64` against a non-NaN `f64` (no conversion of the integer to a
/// double, which loses precision above 2^53).
fn cmp_int_double(i: i64, d: f64) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    if d.is_infinite() {
        return if d > 0.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    // 2^63 exactly: every i64 is below it.
    if d >= 9_223_372_036_854_775_808.0 {
        return Ordering::Less;
    }
    if d < -9_223_372_036_854_775_808.0 {
        return Ordering::Greater;
    }
    #[allow(clippy::cast_possible_truncation)]
    let t = d.trunc() as i64;
    match i.cmp(&t) {
        Ordering::Equal => {
            let frac = d - d.trunc();
            if frac > 0.0 {
                Ordering::Less
            } else if frac < 0.0 {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        }
        o => o,
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

/// `range <op> c` for every member of the range: `Ok(true)` / `Ok(false)` when all members
/// agree, `Unknown` otherwise. A concrete value of another class never equals a member and
/// cannot be ordered against one (an error for every member, hence for the proof).
fn range_relation(r: &ValueRange, op: BinaryOp, c: &RulesValue) -> Result<bool, EvalError> {
    use core::cmp::Ordering::{Equal, Greater, Less};
    let class = r.class().ok_or(EvalError::Unknown)?;
    if c.compare_class() != class {
        return match op {
            BinaryOp::Eq => Ok(false),
            BinaryOp::Ne => Ok(true),
            _ => Err(soft(format!(
                "cannot compare {class} with {}",
                c.type_name()
            ))),
        };
    }
    // Position of `c` relative to each end: `Less` = below the whole range, `Greater` =
    // above it, `Equal` = on the bound (its inclusivity decides).
    let lower = r
        .lower
        .as_ref()
        .map(|b| compare(c, &b.value).map(|o| (o, b.inclusive)))
        .transpose()?;
    let upper = r
        .upper
        .as_ref()
        .map(|b| compare(c, &b.value).map(|o| (o, b.inclusive)))
        .transpose()?;
    // `c` is below every member / above every member.
    let below_all = matches!(lower, Some((Less, _) | (Equal, false)));
    let above_all = matches!(upper, Some((Greater, _) | (Equal, false)));
    // `c` is at or below every member (`<=`) / at or above every member (`>=`).
    let at_or_below_all = below_all || matches!(lower, Some((Equal, true)));
    let at_or_above_all = above_all || matches!(upper, Some((Equal, true)));
    let outside = below_all || above_all;
    let pinned = matches!((lower, upper), (Some((Equal, true)), Some((Equal, true))));
    match op {
        BinaryOp::Eq if outside => Ok(false),
        BinaryOp::Eq if pinned => Ok(true),
        BinaryOp::Ne if outside => Ok(true),
        BinaryOp::Ne if pinned => Ok(false),
        // member < c: true when c is above every member, false when c is at or below all.
        BinaryOp::Lt if above_all => Ok(true),
        BinaryOp::Lt if at_or_below_all => Ok(false),
        BinaryOp::Le if at_or_above_all => Ok(true),
        BinaryOp::Le if below_all => Ok(false),
        BinaryOp::Gt if below_all => Ok(true),
        BinaryOp::Gt if at_or_above_all => Ok(false),
        BinaryOp::Ge if at_or_below_all => Ok(true),
        BinaryOp::Ge if above_all => Ok(false),
        _ => Err(EvalError::Unknown),
    }
}

/// Orders two concrete values of one comparable class; `None` when they do not compare
/// (different classes, NaN).
#[must_use]
pub fn try_compare(a: &RulesValue, b: &RulesValue) -> Option<core::cmp::Ordering> {
    compare(a, b).ok()
}

fn compare(a: &RulesValue, b: &RulesValue) -> Result<core::cmp::Ordering, EvalError> {
    use RulesValue as V;
    match (a, b) {
        (V::Int(x), V::Int(y)) => Ok(x.cmp(y)),
        (V::Timestamp(x), V::Timestamp(y)) | (V::Duration(x), V::Duration(y)) => Ok(x.cmp(y)),
        (V::String(x), V::String(y)) => Ok(x.cmp(y)),
        (V::Bytes(x), V::Bytes(y)) => Ok(x.cmp(y)),
        (V::Float(x), V::Float(y)) => x.partial_cmp(y).ok_or_else(|| soft("NaN comparison")),
        (V::Int(i), V::Float(d)) if !d.is_nan() => Ok(cmp_int_double(*i, *d)),
        (V::Float(d), V::Int(i)) if !d.is_nan() => Ok(cmp_int_double(*i, *d).reverse()),
        (V::Int(_) | V::Float(_), V::Int(_) | V::Float(_)) => Err(soft("NaN comparison")),
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
        // No trimming: the official runtime raises on `int(' 12 ')` and on `int('12abc')`,
        // and it truncates a float rather than requiring a whole one.
        ("int", V::String(s)) => {
            V::Int(s.parse().map_err(|_| soft("int() of non-numeric string"))?)
        }
        ("int", V::Float(f)) if f.is_finite() && f.trunc().abs() < 2f64.powi(63) => {
            V::Int(f.trunc() as i64)
        }
        ("float", V::Int(i)) => V::Float(i as f64),
        ("float", V::Float(f)) => V::Float(f),
        ("float", V::String(s)) => V::Float(
            s.parse()
                .map_err(|_| soft("float() of non-numeric string"))?,
        ),
        ("string", V::String(s)) => V::String(s),
        ("string", V::Int(i)) => V::String(i.to_string()),
        ("string", V::Bool(b)) => V::String(b.to_string()),
        ("string", V::Null) => V::String("null".to_owned()),
        ("string", V::Float(f)) => V::String(format_float(f)),
        ("string", V::Path(p)) => V::String(format!("/{}", p.join("/"))),
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
    // An exact list / map holding an undetermined member, or an undetermined argument,
    // cannot be searched, joined or compared with a definite result (query proofs). The
    // partially known containers have their own arms below.
    //
    // `keys()` and `size()` of a map are the exception: both read the key set, which an
    // undetermined *value* leaves fully known. `request.keys()` depends on it, because
    // `request.auth` is undetermined while a query is being proven.
    let shape_only = matches!(receiver, V::Map(_)) && matches!(name, "keys" | "size");
    if (!shape_only
        && matches!(receiver, V::List(_) | V::Set(_) | V::Map(_))
        && undetermined(receiver))
        || args.iter().any(undetermined)
    {
        return Err(EvalError::Unknown);
    }
    let arity = |n: usize| -> Result<(), EvalError> {
        if args.len() == n {
            Ok(())
        } else {
            Err(soft(format!("{name}() takes {n} argument(s)")))
        }
    };
    let list_arg = |a: &RulesValue| -> Result<Vec<RulesValue>, EvalError> {
        match a {
            V::List(items) if !items.iter().any(undetermined) => Ok(items.clone()),
            V::List(_) | V::PartialList(_) | V::Unknown => Err(EvalError::Unknown),
            other => Err(soft(format!(
                "{name}() expects a list, got {}",
                other.type_name()
            ))),
        }
    };
    Ok(match (receiver, name) {
        (V::PartialList(known), "hasAny") => {
            arity(1)?;
            let wanted = list_arg(&args[0])?;
            if wanted
                .iter()
                .any(|w| known.iter().any(|i| values_equal(i, w)))
            {
                V::Bool(true)
            } else {
                return Err(EvalError::Unknown);
            }
        }
        (V::PartialListAny(candidates), "hasAny") => {
            arity(1)?;
            let wanted = list_arg(&args[0])?;
            // Whichever candidate the document holds, it is among `wanted`.
            if !candidates.is_empty()
                && candidates
                    .iter()
                    .all(|c| wanted.iter().any(|w| values_equal(c, w)))
            {
                V::Bool(true)
            } else {
                return Err(EvalError::Unknown);
            }
        }
        (V::PartialList(known), "hasAll") => {
            arity(1)?;
            let wanted = list_arg(&args[0])?;
            if wanted
                .iter()
                .all(|w| known.iter().any(|i| values_equal(i, w)))
            {
                V::Bool(true)
            } else {
                return Err(EvalError::Unknown);
            }
        }
        (V::PartialMap(m), "get") => {
            arity(2)?;
            match &args[0] {
                V::String(k) => match m.get(k) {
                    Some(v) => v.clone(),
                    None => return Err(EvalError::Unknown),
                },
                _ => return Err(soft("get() expects a string key")),
            }
        }
        (V::Unknown | V::PartialList(_) | V::PartialListAny(_) | V::PartialMap(_), _) => {
            return Err(EvalError::Unknown)
        }
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
        (V::String(s), "matches") => {
            arity(1)?;
            let V::String(pattern) = &args[0] else {
                return Err(soft("matches() expects a string pattern"));
            };
            let re = crate::regex::Regex::new(pattern).map_err(|error| {
                EvalError::Unsupported(crate::regex::escape_diagnostic_text(&error.to_string()))
            })?;
            V::Bool(re.is_full_match(s).map_err(regex_runtime_error)?)
        }
        (V::String(s), "replace") => {
            arity(2)?;
            let (V::String(pattern), V::String(replacement)) = (&args[0], &args[1]) else {
                return Err(soft("replace() expects a pattern and a replacement"));
            };
            let re = crate::regex::Regex::new(pattern).map_err(|error| {
                EvalError::Unsupported(crate::regex::escape_diagnostic_text(&error.to_string()))
            })?;
            V::String(
                re.replace_all(s, replacement)
                    .map_err(regex_runtime_error)?,
            )
        }
        (V::List(items) | V::Set(items), "size") => {
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
                    // The official runtime stringifies members rather than requiring
                    // strings: `[1, 2].join(',')` is `'1,2'`, recorded.
                    let parts: Result<Vec<String>, EvalError> = items
                        .iter()
                        .map(|i| match convert("string", i.clone()) {
                            Ok(V::String(s)) => Ok(s),
                            _ => Err(soft(format!("join() on list containing {}", i.type_name()))),
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
        (V::List(items), "removeAll") => {
            arity(1)?;
            let removed = list_arg(&args[0])?;
            V::List(
                items
                    .iter()
                    .filter(|i| !removed.iter().any(|r| values_equal(i, r)))
                    .cloned()
                    .collect(),
            )
        }
        (V::List(items), "toSet") => {
            arity(0)?;
            make_set(items.iter().cloned())
        }
        // A `set` is its own type: it compares unordered, `is` never recognises it, and its
        // operations take another set rather than a list.
        (V::Set(items), "union" | "intersection" | "difference") => {
            arity(1)?;
            let V::Set(other) = &args[0] else {
                return Err(soft(format!(
                    "{name}() expects a set, got {}",
                    args[0].type_name()
                )));
            };
            let member = |xs: &[RulesValue], v: &RulesValue| xs.iter().any(|x| values_equal(x, v));
            match name {
                "union" => make_set(items.iter().chain(other).cloned()),
                "intersection" => make_set(
                    items
                        .iter()
                        .filter(|v| member(other, v))
                        .cloned()
                        .collect::<Vec<_>>(),
                ),
                _ => make_set(
                    items
                        .iter()
                        .filter(|v| !member(other, v))
                        .cloned()
                        .collect::<Vec<_>>(),
                ),
            }
        }
        (V::Set(items), "hasAll" | "hasAny" | "hasOnly") => {
            arity(1)?;
            let other = match &args[0] {
                V::Set(xs) => xs.clone(),
                _ => list_arg(&args[0])?,
            };
            let member = |xs: &[RulesValue], v: &RulesValue| xs.iter().any(|x| values_equal(x, v));
            V::Bool(match name {
                "hasAll" => other.iter().all(|w| member(items, w)),
                "hasAny" => other.iter().any(|w| member(items, w)),
                _ => items.iter().all(|i| member(&other, i)),
            })
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
                // A list key walks nested maps: `{'a': {'b': 1}}.get(['a', 'b'], 0)` is 1.
                V::List(path) => {
                    let mut current = receiver.clone();
                    for step in path {
                        let V::String(k) = step else {
                            return Err(soft("get() expects string keys in a key path"));
                        };
                        match current {
                            V::Map(ref inner) => match inner.get(k) {
                                Some(v) => current = v.clone(),
                                None => return Ok(args[1].clone()),
                            },
                            _ => return Ok(args[1].clone()),
                        }
                    }
                    current
                }
                _ => return Err(soft("get() expects a string key")),
            }
        }
        // `path.bind()` fills the `{name}` placeholders of a path literal. Every binding has
        // to be used: the official runtime raises on one the path does not name, and it has
        // no `size()` on a path at all.
        (V::Path(p), "bind") => {
            arity(1)?;
            let V::Map(bindings) = &args[0] else {
                return Err(soft(format!(
                    "bind() expects a map, got {}",
                    args[0].type_name()
                )));
            };
            let mut used: Vec<&String> = Vec::new();
            let mut out = Vec::new();
            for segment in p {
                match segment
                    .strip_prefix('{')
                    .and_then(|s| s.strip_suffix('}'))
                    .filter(|s| !s.is_empty())
                {
                    Some(placeholder) => {
                        let Some((key, value)) = bindings.get_key_value(placeholder) else {
                            return Err(soft(format!("bind() has no value for {{{placeholder}}}")));
                        };
                        used.push(key);
                        out.push(match value {
                            V::String(s) => s.clone(),
                            V::Int(i) => i.to_string(),
                            other => {
                                return Err(soft(format!(
                                    "bind() cannot put a {} in a path",
                                    other.type_name()
                                )))
                            }
                        });
                    }
                    None => out.push(segment.clone()),
                }
            }
            if used.len() != bindings.len() {
                return Err(soft("bind() was given a name the path does not use"));
            }
            V::Path(out)
        }
        (V::Timestamp(t), "toMillis") => {
            arity(0)?;
            V::Int(i64::try_from(t.div_euclid(1_000_000)).unwrap_or(i64::MAX))
        }
        (V::Timestamp(t), "year" | "month" | "day" | "dayOfWeek" | "dayOfYear") => {
            arity(0)?;
            let days = i64::try_from(t.div_euclid(NANOS_PER_DAY)).unwrap_or(0);
            let (y, m, d) = crate::civil::civil_from_days(days);
            V::Int(match name {
                "year" => y,
                "month" => m,
                "day" => d,
                "dayOfWeek" => crate::civil::iso_weekday(days),
                _ => crate::civil::day_of_year(days),
            })
        }
        (V::Timestamp(t), "hours" | "minutes") => {
            arity(0)?;
            let of_day = t.rem_euclid(NANOS_PER_DAY);
            V::Int(
                i64::try_from(match name {
                    "hours" => of_day / 3_600_000_000_000,
                    _ => of_day / 60_000_000_000 % 60,
                })
                .unwrap_or(0),
            )
        }
        (V::Timestamp(t), "date") => {
            arity(0)?;
            V::Timestamp(t - t.rem_euclid(NANOS_PER_DAY))
        }
        (V::Timestamp(t), "time") => {
            arity(0)?;
            V::Duration(t.rem_euclid(NANOS_PER_DAY))
        }
        (V::Duration(d), "seconds") => {
            arity(0)?;
            V::Int(i64::try_from(d.div_euclid(1_000_000_000)).unwrap_or(i64::MAX))
        }
        (V::Duration(d), "nanos") => {
            arity(0)?;
            V::Int(i64::try_from(d.rem_euclid(1_000_000_000)).unwrap_or(0))
        }
        (V::Bytes(b), "toBase64") => {
            arity(0)?;
            V::String(crate::hash::base64(b))
        }
        (V::Bytes(b), "toHexString") => {
            arity(0)?;
            V::String(crate::hash::hex(b))
        }
        (V::String(s), "toUtf8") => {
            arity(0)?;
            V::Bytes(s.as_bytes().to_vec())
        }
        (
            V::LatLng {
                latitude,
                longitude,
            },
            "distance",
        ) => {
            arity(1)?;
            let V::LatLng {
                latitude: lat2,
                longitude: lng2,
            } = &args[0]
            else {
                return Err(soft("distance() expects a latlng"));
            };
            V::Float(haversine_metres(*latitude, *longitude, *lat2, *lng2))
        }
        (V::Map(m), "diff") => {
            arity(1)?;
            let V::Map(other) = &args[0] else {
                return Err(soft("diff() expects a map"));
            };
            let mut diff = MapDiff {
                added: Vec::new(),
                removed: Vec::new(),
                changed: Vec::new(),
                unchanged: Vec::new(),
            };
            for (k, v) in m {
                match other.get(k) {
                    None => diff.added.push(k.clone()),
                    Some(o) if values_equal(v, o) => diff.unchanged.push(k.clone()),
                    Some(_) => diff.changed.push(k.clone()),
                }
            }
            for k in other.keys() {
                if !m.contains_key(k) {
                    diff.removed.push(k.clone());
                }
            }
            V::MapDiff(diff)
        }
        (
            V::MapDiff(d),
            "addedKeys" | "removedKeys" | "changedKeys" | "unchangedKeys" | "affectedKeys",
        ) => {
            arity(0)?;
            let keys: Vec<String> = match name {
                "addedKeys" => d.added.clone(),
                "removedKeys" => d.removed.clone(),
                "changedKeys" => d.changed.clone(),
                "unchangedKeys" => d.unchanged.clone(),
                _ => {
                    let mut all: Vec<String> = d
                        .added
                        .iter()
                        .chain(&d.removed)
                        .chain(&d.changed)
                        .cloned()
                        .collect();
                    all.sort();
                    all
                }
            };
            // Every one of these is a `set` in the official runtime, not a list.
            make_set(keys.into_iter().map(V::String))
        }
        (V::Timestamp(t), "seconds") => {
            arity(0)?;
            V::Int(i64::try_from(t.div_euclid(1_000_000_000)).unwrap_or(i64::MAX))
        }
        (V::Timestamp(t), "nanos") => {
            arity(0)?;
            V::Int(i64::try_from(t.rem_euclid(1_000_000_000)).unwrap_or(0))
        }
        (V::Bytes(b), "size") => {
            arity(0)?;
            V::Int(i64::try_from(b.len()).unwrap_or(i64::MAX))
        }
        (V::LatLng { latitude, .. }, "latitude") => {
            arity(0)?;
            V::Float(*latitude)
        }
        (V::LatLng { longitude, .. }, "longitude") => {
            arity(0)?;
            V::Float(*longitude)
        }
        (other, _) => {
            return Err(soft(format!(
                "unknown method {name} on {}",
                other.type_name()
            )))
        }
    })
}

/// `receiver[start:end]` over a list or a string.
///
/// The bounds the official runtime accepts are asymmetric, and measured rather than
/// guessed (`conformance/rules-matrix.json`, area `slice`): `start` has to be a valid
/// index, `0 <= start < len`, while `end` has to be a valid *position after* one,
/// `0 < end <= len`, and `start <= end`. So `[1, 2, 3][1:1]` is the empty list while
/// `[1, 2, 3][0:0]`, `[1, 2, 3][3:3]` and `[][0:0]` all raise.
fn slice(
    receiver: &RulesValue,
    start: &RulesValue,
    end: &RulesValue,
) -> Result<RulesValue, EvalError> {
    use RulesValue as V;
    if undetermined(receiver) || undetermined(start) || undetermined(end) {
        return Err(EvalError::Unknown);
    }
    let (V::Int(lo), V::Int(hi)) = (start, end) else {
        return Err(soft(format!(
            "a range index takes two ints, got {} and {}",
            start.type_name(),
            end.type_name()
        )));
    };
    let len = match receiver {
        V::List(items) => items.len(),
        V::String(s) => s.chars().count(),
        other => {
            return Err(soft(format!(
                "{} cannot be range indexed",
                other.type_name()
            )))
        }
    };
    let len = i64::try_from(len).unwrap_or(i64::MAX);
    if *lo < 0 || *lo >= len || *hi <= 0 || *hi > len || lo > hi {
        return Err(soft(format!("range index [{lo}:{hi}] is out of range")));
    }
    let (lo, hi) = (
        usize::try_from(*lo).unwrap_or(0),
        usize::try_from(*hi).unwrap_or(0),
    );
    Ok(match receiver {
        V::List(items) => V::List(items[lo..hi].to_vec()),
        V::String(s) => V::String(s.chars().skip(lo).take(hi - lo).collect()),
        _ => unreachable!("the length arm already rejected every other receiver"),
    })
}

/// Nanoseconds per day.
const NANOS_PER_DAY: i128 = 86_400_000_000_000;

/// `v is type_name` for a concrete value.
///
/// A `set` answers `false` to every type name, `set` included -- measured, not assumed:
/// `[1, 2].toSet() is set`, `is list` and `is map` are all false in the official runtime.
fn is_type(v: &RulesValue, type_name: &str) -> bool {
    if matches!(v, RulesValue::Set(_)) {
        return false;
    }
    match type_name {
        "number" => matches!(v, RulesValue::Int(_) | RulesValue::Float(_)),
        t => v.type_name() == t,
    }
}

/// A set with each member kept once, in first-seen order.
fn make_set(items: impl IntoIterator<Item = RulesValue>) -> RulesValue {
    let mut out: Vec<RulesValue> = Vec::new();
    for item in items {
        if !out.iter().any(|x| values_equal(x, &item)) {
            out.push(item);
        }
    }
    RulesValue::Set(out)
}

/// `string(float)`: a whole float still prints with no decimal part, as the runtime does
/// for `string(1.5)` and for the members `join()` stringifies.
fn format_float(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e15 {
        format!("{f:.1}")
            .strip_suffix(".0")
            .map_or_else(|| f.to_string(), str::to_owned)
    } else {
        f.to_string()
    }
}

/// Applies a comparison / membership operator to two concrete values; an error for
/// operators that do not apply (arithmetic never reaches here).
fn binary_concrete(op: BinaryOp, a: &RulesValue, b: &RulesValue) -> Result<bool, EvalError> {
    use RulesValue as V;
    match op {
        BinaryOp::Eq => Ok(values_equal(a, b)),
        BinaryOp::Ne => Ok(!values_equal(a, b)),
        BinaryOp::In => match b {
            V::List(items) => Ok(items.iter().any(|x| values_equal(x, a))),
            V::Map(m) => match a {
                V::String(k) => Ok(m.contains_key(k)),
                _ => Err(soft("`in` needs a string key")),
            },
            other => Err(soft(format!("`in` on {}", other.type_name()))),
        },
        BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
            let ord = compare(a, b)?;
            Ok(match op {
                BinaryOp::Lt => ord.is_lt(),
                BinaryOp::Le => ord.is_le(),
                BinaryOp::Gt => ord.is_gt(),
                _ => ord.is_ge(),
            })
        }
        _ => Err(EvalError::Unknown),
    }
}

/// The common answer of every candidate; undetermined when they disagree. A candidate
/// that errors (type mismatch) makes the whole condition an error for that potential
/// document, hence undetermined for the proof.
fn unanimous(answers: impl Iterator<Item = Result<bool, EvalError>>) -> Result<bool, EvalError> {
    let mut agreed: Option<bool> = None;
    for a in answers {
        let a = a.map_err(|_| EvalError::Unknown)?;
        match agreed {
            None => agreed = Some(a),
            Some(prev) if prev == a => {}
            Some(_) => return Err(EvalError::Unknown),
        }
    }
    agreed.ok_or(EvalError::Unknown)
}

/// Great-circle distance in kilometres (`latlng.distance()`).
fn haversine_metres(lat1: f64, lng1: f64, lat2: f64, lng2: f64) -> f64 {
    // `latlng.distance()` answers metres: one degree of latitude measures more than
    // 111 000 of them and less than 112 000, which is what the official runtime records.
    const EARTH_RADIUS_KM: f64 = 6_371_000.0;
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let (dp, dl) = ((lat2 - lat1).to_radians(), (lng2 - lng1).to_radians());
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_KM * a.sqrt().asin()
}
