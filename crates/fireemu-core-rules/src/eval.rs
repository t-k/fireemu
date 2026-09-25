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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
    /// Request-local regular expression compilation and cache observations.
    pub regex: RegexEvaluationDiagnostics,
    /// Member chains projected directly from shared request roots without cloning containers.
    pub projected_member_reads: u64,
}

/// Request-local observations for compiled regular expression reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegexEvaluationDiagnostics {
    /// Dynamic patterns compiled during this evaluation.
    pub runtime_compiles: u64,
    /// Dynamic patterns served from the request-local cache.
    pub cache_hits: u64,
    /// Greatest number of dynamic patterns retained at once.
    pub peak_cache_entries: usize,
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
    /// One node, plus one evaluation for each pair of parentheses around it: production
    /// counts a parenthesised expression as an expression of its own (FS-RULES 2026-09-24).
    fn charge_node(&mut self, expr: &Expr) -> Result<(), EvalError> {
        for _ in 0..=expr.parens {
            self.charge()?;
        }
        Ok(())
    }

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
    /// Functions visible from each declaration's lexical scope. The active `functions` stack
    /// tracks the call site, while this map restores the declaration environment for a call.
    /// Environments are shared by declarations in the same lexical scope so the static table
    /// does not retain a separate copy for every function.
    function_scopes: BTreeMap<usize, Arc<FunctionEnvironment<'a>>>,
    /// Value bindings captured at each declaration site. Match captures are dynamic values, so
    /// this is populated while walking the matching block and restored for every call. Functions
    /// declared in one block share the immutable request-local table.
    function_bindings: BTreeMap<usize, FunctionBindings>,
    bindings: Vec<Binding<'a>>,
    /// The lexical function environment of the function currently being evaluated. `None`
    /// means that resolution follows the active match/call-site stack in `functions`.
    lexical_functions: Option<Arc<FunctionEnvironment<'a>>>,
}

type FunctionBindings = Arc<Vec<(String, RulesValue)>>;
type QueryFloatZeroProvenance = (bool, bool);
type QueryFloatZeroFunctionCache = BTreeMap<(usize, Vec<QueryFloatZeroProvenance>), bool>;
type QueryStringificationProvenance = (bool, bool);
type QueryStringificationFunctionCache =
    BTreeMap<(usize, Vec<QueryStringificationProvenance>), bool>;
type QueryNumericSourceFunctionCache = BTreeMap<(usize, Vec<bool>), bool>;
type QueryNumericErrorFunctionCache = BTreeMap<usize, bool>;

/// Immutable lexical function declarations for one scope. Parent environments are linked rather
/// than flattened so nested scopes do not copy all ancestor declarations.
struct FunctionEnvironment<'a> {
    parent: Option<Arc<FunctionEnvironment<'a>>>,
    own: Vec<&'a FunctionDecl>,
}

#[allow(clippy::struct_excessive_bools)]
struct Binding<'a> {
    name: String,
    visible_before: usize,
    query_derived: bool,
    /// The value may be a numeric result whose representation still depends on the
    /// integer/double encoding accepted by a query equality filter. This is distinct from
    /// `query_derived`: `int()`/`float()` canonicalize ordinary Rules arithmetic, but a later
    /// string conversion can still observe the original representation.
    query_numeric_source: bool,
    /// The value may still change unary numeric success/error based on query representation.
    query_numeric_error_source: bool,
    query_float_zero_ambiguous: bool,
    query_numeric_stringification_sensitive: bool,
    state: BindingState<'a>,
}

enum BindingState<'a> {
    Value(RulesValue),
    Lazy(&'a Expr),
    Evaluating,
    Resolved {
        result: Result<RulesValue, EvalError>,
        cause: Option<UndefinedCause>,
    },
}

impl Binding<'_> {
    fn value(name: String, value: RulesValue) -> Self {
        Self {
            name,
            visible_before: 0,
            query_derived: false,
            query_numeric_source: false,
            query_numeric_error_source: false,
            query_float_zero_ambiguous: false,
            query_numeric_stringification_sensitive: false,
            state: BindingState::Value(value),
        }
    }

    #[allow(clippy::fn_params_excessive_bools)]
    fn with_provenance(
        name: String,
        value: RulesValue,
        query_derived: bool,
        query_numeric_source: bool,
        query_numeric_error_source: bool,
        query_float_zero_ambiguous: bool,
        query_numeric_stringification_sensitive: bool,
    ) -> Self {
        Self {
            name,
            visible_before: 0,
            query_derived,
            query_numeric_source,
            query_numeric_error_source,
            query_float_zero_ambiguous,
            query_numeric_stringification_sensitive,
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
    /// batch or transaction) has completed. `None` = no write applies (reads, query proofs):
    /// Firestore rules then read the current state, Storage rules refuse the call;
    /// `Some(None)` = it will not exist.
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
    request: Arc<RulesValue>,
    resource: Arc<RulesValue>,
    /// Abstract resources are query proofs: equality filters preserve Firestore's numeric
    /// equivalence even after a nested member is projected to a concrete Rules value.
    query_proof: bool,
    /// `get()` / `exists()` provider (`None` = unsupported).
    access: Option<&'a dyn DocumentAccess>,
    /// The service: in Firestore rules the FS-RULES observations (a missing document is null,
    /// `getAfter()` in a read is the current state) apply; Storage rules keep their answers.
    service: RulesService,
    /// Documents read so far, keyed by (`getAfter`?, path): a path is charged once per
    /// request and kind, as in production.
    doc_cache: BTreeMap<(bool, Vec<String>), Option<RulesValue>>,
    /// Successful and failed dynamic pattern compilations retained only for this request.
    regex_cache: BTreeMap<String, Result<Arc<crate::regex::Regex>, crate::regex::RegexError>>,
    regex_diagnostics: RegexEvaluationDiagnostics,
    /// Matches in this request that exhausted the regex step budget (see
    /// [`REGEX_EXHAUSTIONS_PER_REQUEST_MAX`]).
    regex_exhaustions: u64,
    projected_member_reads: u64,
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
    /// Path matcher work is bounded independently from expression evaluation.
    match_path_work: Arc<AtomicU64>,
    /// Reachability prefilter work is bounded independently from the matcher. Exhaustion keeps
    /// the candidate conservative and lets the bounded matcher make the final decision.
    match_prefilter_work: Arc<AtomicU64>,
    /// Reachability results shared by structurally equivalent match paths in one request.
    pattern_reachability_cache: BTreeMap<(String, Vec<String>, bool), Vec<bool>>,
    /// Query-provenance results are static for one ruleset evaluation and can be reused across
    /// repeated references to the same declaration.
    query_derived_function_cache: core::cell::RefCell<BTreeMap<usize, bool>>,
    /// Bound the work spent deriving query provenance. Exhaustion is conservative: the
    /// expression is treated as query-derived rather than allowing an unproven result.
    query_derived_analysis_work: core::cell::Cell<u64>,
    /// Signed-zero provenance is also memoized by declaration and argument provenance so the
    /// arithmetic guard cannot re-expand the same function graph.
    query_float_zero_function_cache: core::cell::RefCell<QueryFloatZeroFunctionCache>,
    query_float_zero_analysis_work: core::cell::Cell<u64>,
    /// Stringification provenance is memoized by declaration and argument provenance so
    /// wrappers such as `string(float(value))` do not rescan a function graph.
    query_stringification_function_cache: core::cell::RefCell<QueryStringificationFunctionCache>,
    query_stringification_analysis_work: core::cell::Cell<u64>,
    /// Numeric-source analysis is also memoized by declaration and argument provenance so a
    /// repeated function DAG remains linear in the number of distinct contexts.
    query_numeric_source_function_cache: core::cell::RefCell<QueryNumericSourceFunctionCache>,
    /// Bound the numeric-source graph walk independently from the other provenance analyses.
    /// Exhaustion is conservative: a value is treated as representation-sensitive rather than
    /// allowing an unproven query result.
    query_numeric_source_analysis_work: core::cell::Cell<u64>,
    /// Canonical numeric return analysis for unary error provenance.
    query_numeric_error_function_cache: core::cell::RefCell<QueryNumericErrorFunctionCache>,
    query_numeric_error_analysis_work: core::cell::Cell<u64>,
}

const DYNAMIC_REGEX_CACHE_CAPACITY: usize = 16;

/// Maximum path-matcher steps charged to one request. Recursive wildcards are valid and may
/// backtrack, but their work must be bounded independently from expression evaluation so a
/// deeply nested set cannot allocate or recurse without limit. This is an evaluator safety
/// bound, not a Firebase compatibility claim.
const MATCH_PATH_WORK_MAX: u64 = 65_536;
/// Maximum structural reachability transitions charged to one request. If this conservative
/// prefilter bound is exhausted, the candidate is treated as unknown and evaluated by the
/// bounded matcher instead of being rejected solely by the prefilter.
const MATCH_PATH_PREFILTER_WORK_MAX: u64 = 1_000_000;
/// A request-local reachability cache must not grow without bound when a ruleset contains many
/// distinct path shapes. Once full, the evaluator simply recomputes the bounded prefilter.
const MATCH_PATH_REACHABILITY_CACHE_MAX_ENTRIES: usize = 4_096;
/// Maximum function-body declarations visited while deriving query provenance for one request.
const QUERY_DERIVED_ANALYSIS_WORK_MAX: u64 = 100_000;

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

/// Evaluates an owned request while moving its potentially large document values into the
/// evaluator instead of cloning them.
#[must_use]
pub fn evaluate_request_traced_owned(
    ruleset: &Ruleset,
    mut ctx: RequestContext,
    access: Option<&dyn DocumentAccess>,
) -> (EvaluationReport, Coverage) {
    let coverage = core::cell::RefCell::new(Coverage::default());
    let resource_absent = ctx.resource.is_none();
    let resource = Arc::new(ctx.resource.take().unwrap_or(RulesValue::Null));
    let request_resource = ctx.request_resource.take();
    let request = Arc::new(build_request_with_resource(&ctx, request_resource));
    let report = evaluate_prepared(
        ruleset,
        &ctx,
        access,
        Some(&coverage),
        &request,
        &resource,
        resource_absent,
    );
    (report, coverage.into_inner())
}

/// Evaluates a request against a ruleset; `access` serves `get()` / `exists()` within the
/// Maximum `eval` recursion depth: a stack-safety bound of fireemu's, not production's.
/// Production evaluates every expression it compiles (99 levels, see
/// `parse::MAX_COMPILED_EXPR_DEPTH`, and up to 20 nested calls); an evaluation deeper than
/// this is an error here, which makes its condition false (fails closed). The daemon gives its
/// request threads a stack that holds this depth in a debug build.
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

#[allow(clippy::too_many_lines)]
fn evaluate_with_coverage(
    ruleset: &Ruleset,
    ctx: &RequestContext,
    access: Option<&dyn DocumentAccess>,
    coverage: Option<&core::cell::RefCell<Coverage>>,
) -> EvaluationReport {
    let request = Arc::new(build_request(ctx));
    let resource_absent = ctx.resource.is_none();
    let resource = Arc::new(ctx.resource.clone().unwrap_or(RulesValue::Null));
    evaluate_prepared(
        ruleset,
        ctx,
        access,
        coverage,
        &request,
        &resource,
        resource_absent,
    )
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn evaluate_prepared(
    ruleset: &Ruleset,
    ctx: &RequestContext,
    access: Option<&dyn DocumentAccess>,
    coverage: Option<&core::cell::RefCell<Coverage>>,
    request: &Arc<RulesValue>,
    resource: &Arc<RulesValue>,
    resource_absent: bool,
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
    let mut regex_diagnostics = RegexEvaluationDiagnostics::default();
    let mut projected_member_reads = 0u64;
    for service in &ruleset.services {
        if service.name != ctx.service.name() {
            continue;
        }
        let mut function_scopes = BTreeMap::new();
        collect_function_scopes(&service.items, None, &mut function_scopes);
        let mut function_bindings = BTreeMap::new();
        initialize_function_bindings(&service.items, &mut function_bindings);
        let functions = service
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Function(function) => Some(function),
                Item::Match(_) => None,
            })
            .collect();
        let scope = Scope {
            functions,
            function_scopes,
            function_bindings,
            bindings: Vec::new(),
            lexical_functions: None,
        };
        let mut ev = Evaluator {
            nesting: 0,
            request: Arc::clone(request),
            resource: Arc::clone(resource),
            query_proof: ctx.abstract_path,
            access,
            service: ctx.service,
            doc_cache: BTreeMap::new(),
            regex_cache: BTreeMap::new(),
            regex_exhaustions: 0,
            regex_diagnostics: RegexEvaluationDiagnostics::default(),
            projected_member_reads: 0,
            doc_reads_max: limit_max(match ctx.service {
                // A query's rule may read as many documents as a multi-document request
                // (20: production and the official emulator allow 20 and refuse 21, FS-RULES).
                RulesService::Firestore if ctx.method == Method::List => {
                    "RULES-DOC-ACCESS-MULTI-TOTAL"
                }
                RulesService::Firestore => "RULES-DOC-ACCESS-SINGLE",
                // Storage rules may call firestore.get() / exists() twice per request.
                RulesService::Storage => "STORAGE-RULES-FIRESTORE-ACCESS",
            }),
            wildcard_zero_or_more: ruleset.version.as_deref() == Some("2"),
            resource_absent,
            absent_resource_used: core::cell::Cell::new(false),
            budget,
            scope,
            coverage,
            cause: None,
            match_path_work: Arc::new(AtomicU64::new(0)),
            match_prefilter_work: Arc::new(AtomicU64::new(0)),
            pattern_reachability_cache: BTreeMap::new(),
            query_derived_function_cache: core::cell::RefCell::new(BTreeMap::new()),
            query_derived_analysis_work: core::cell::Cell::new(0),
            query_float_zero_function_cache: core::cell::RefCell::new(BTreeMap::new()),
            query_float_zero_analysis_work: core::cell::Cell::new(0),
            query_stringification_function_cache: core::cell::RefCell::new(BTreeMap::new()),
            query_stringification_analysis_work: core::cell::Cell::new(0),
            query_numeric_source_function_cache: core::cell::RefCell::new(BTreeMap::new()),
            query_numeric_source_analysis_work: core::cell::Cell::new(0),
            query_numeric_error_function_cache: core::cell::RefCell::new(BTreeMap::new()),
            query_numeric_error_analysis_work: core::cell::Cell::new(0),
        };
        let outcome = walk_items(&service.items, &segments, ctx, &mut ev, &mut matched_any);
        absent_resource_used |= ev.absent_resource_used.get();
        budget = ev.budget;
        regex_diagnostics.runtime_compiles = regex_diagnostics
            .runtime_compiles
            .saturating_add(ev.regex_diagnostics.runtime_compiles);
        regex_diagnostics.cache_hits = regex_diagnostics
            .cache_hits
            .saturating_add(ev.regex_diagnostics.cache_hits);
        regex_diagnostics.peak_cache_entries = regex_diagnostics
            .peak_cache_entries
            .max(ev.regex_diagnostics.peak_cache_entries);
        projected_member_reads = projected_member_reads.saturating_add(ev.projected_member_reads);
        match outcome {
            Ok(true) => {
                return EvaluationReport {
                    decision: Decision::Allow,
                    expressions_evaluated: budget.expressions,
                    max_call_depth: budget.max_depth_seen,
                    absent_resource_used,
                    regex: regex_diagnostics,
                    projected_member_reads,
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
                    regex: regex_diagnostics,
                    projected_member_reads,
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
        regex: regex_diagnostics,
        projected_member_reads,
    }
}

fn build_request(ctx: &RequestContext) -> RulesValue {
    build_request_with_resource(ctx, ctx.request_resource.clone())
}

fn build_request_with_resource(
    ctx: &RequestContext,
    request_resource: Option<RulesValue>,
) -> RulesValue {
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
    if let Some(resource) = request_resource {
        m.insert("resource".to_owned(), resource);
    } else if ctx.method == Method::Delete && ctx.service == RulesService::Firestore {
        // A delete has no incoming document; production presents it as null (FS-RULES).
        m.insert("resource".to_owned(), RulesValue::Null);
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
    let mut raised = None;
    for item in items {
        if let Item::Match(block) = item {
            match walk_match(block, remaining, ctx, ev, matched_any) {
                Ok(true) => return Ok(true),
                Ok(false) | Err(EvalError::Soft(_) | EvalError::Unknown) => {}
                // A request-wide budget stops the walk: nothing after it is known.
                Err(e) if stops_request(&e) => return Err(e),
                Err(e @ (EvalError::Budget { .. } | EvalError::Unsupported(_))) => {
                    raised.get_or_insert(e);
                }
            }
        }
    }
    raised.map_or(Ok(false), Err)
}

fn function_key(function: &FunctionDecl) -> usize {
    std::ptr::from_ref(function) as usize
}

fn collect_function_scopes<'a>(
    items: &'a [Item],
    parent: Option<Arc<FunctionEnvironment<'a>>>,
    scopes: &mut BTreeMap<usize, Arc<FunctionEnvironment<'a>>>,
) {
    let own: Vec<&'a FunctionDecl> = items
        .iter()
        .filter_map(|item| match item {
            Item::Function(function) => Some(function),
            Item::Match(_) => None,
        })
        .collect();
    let visible = Arc::new(FunctionEnvironment { parent, own });
    for function in &visible.own {
        scopes.insert(function_key(function), Arc::clone(&visible));
    }
    for item in items {
        if let Item::Match(block) = item {
            collect_function_scopes(&block.items, Some(Arc::clone(&visible)), scopes);
        }
    }
}

/// Returns every segment offset that `match_path` can reach after consuming `pattern`.
///
/// This is a rejection-only filter: every transition mirrors the corresponding transition in
/// `match_path`, so an empty result never skips a potentially matching rule. The offsets are
/// retained so a parent can prove that one of its descendants consumes the complete request,
/// instead of treating every prefix-capable parent as a candidate.
fn pattern_reachable_offsets(
    pattern: &[PathSegment],
    segments: &[String],
    zero_or_more: bool,
    work: &AtomicU64,
    cache: &mut BTreeMap<(String, Vec<String>, bool), Vec<bool>>,
) -> Option<Vec<bool>> {
    let shape = pattern
        .iter()
        .map(|segment| match segment {
            PathSegment::Literal(value) => Some(format!("l:{value}")),
            PathSegment::Capture { .. } => Some("c".to_owned()),
            PathSegment::RecursiveWildcard { .. } => Some("r".to_owned()),
            PathSegment::Binding(_) => None,
        })
        .collect::<Option<Vec<_>>>()
        .map(|parts| parts.join("/"));
    if let Some(shape) = shape {
        let key = (shape, segments.to_vec(), zero_or_more);
        if let Some(cached) = cache.get(&key) {
            return Some(cached.clone());
        }
        let result = pattern_reachable_offsets_uncached(pattern, segments, zero_or_more, work);
        if let Some(reachable) = &result {
            if cache.len() >= MATCH_PATH_REACHABILITY_CACHE_MAX_ENTRIES {
                return result;
            }
            cache.insert(key, reachable.clone());
        }
        return result;
    }
    pattern_reachable_offsets_uncached(pattern, segments, zero_or_more, work)
}

fn pattern_reachable_offsets_uncached(
    pattern: &[PathSegment],
    segments: &[String],
    zero_or_more: bool,
    work: &AtomicU64,
) -> Option<Vec<bool>> {
    let mut reachable = vec![false; segments.len() + 1];
    reachable[0] = true;

    for segment in pattern {
        let mut next = vec![false; segments.len() + 1];
        for (offset, reachable) in reachable.iter().enumerate() {
            if !reachable {
                continue;
            }
            let current = work.fetch_add(1, Ordering::Relaxed).saturating_add(1);
            if current > MATCH_PATH_PREFILTER_WORK_MAX {
                return None;
            }
            match segment {
                PathSegment::Literal(literal) => {
                    if segments
                        .get(offset)
                        .is_some_and(|candidate| candidate == literal)
                        && !is_abstract_segment(literal)
                    {
                        next[offset + 1] = true;
                    }
                }
                PathSegment::Capture { .. } => {
                    if segments
                        .get(offset)
                        .is_some_and(|candidate| candidate != ABSTRACT_PREFIX)
                    {
                        next[offset + 1] = true;
                    }
                }
                PathSegment::RecursiveWildcard { .. } => {
                    let minimum = usize::from(!zero_or_more);
                    for (target, next) in next
                        .iter_mut()
                        .enumerate()
                        .skip(offset.saturating_add(minimum))
                    {
                        let current = work.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                        if current > MATCH_PATH_PREFILTER_WORK_MAX {
                            return None;
                        }
                        if segments
                            .get(target)
                            .is_none_or(|candidate| candidate != ABSTRACT_PREFIX)
                        {
                            *next = true;
                        }
                    }
                }
                // Match headers do not permit bindings. Preserve the runtime matcher behavior
                // for manually constructed ASTs by treating one as unreachable here as well.
                PathSegment::Binding(_) => {}
            }
        }
        reachable = next;
    }

    Some(reachable)
}

struct BlockReachability {
    /// The block or a descendant has a structurally reachable complete allow path.
    can_reach_allow: bool,
    /// The block's own path can consume the complete request, regardless of its items.
    covers_path: bool,
    /// Offsets after the block path where an allow in this block's subtree can consume the rest.
    /// Parent matchers use this to avoid exploring wildcard splits that cannot reach a complete
    /// descendant path.
    complete_offsets: Vec<bool>,
}

/// Returns whether a match block or one of its descendants can consume the complete request.
///
/// A block with direct `allow` statements needs a complete path match. A block with nested
/// matches may consume a prefix, but only when a child subtree can consume the remainder. This
/// avoids spending the bounded matcher budget on parent branches that can never reach an
/// applicable allow, while preserving partial matching for valid parent/child rules.
fn block_reachability(
    block: &MatchBlock,
    segments: &[String],
    zero_or_more: bool,
    work: &AtomicU64,
    cache: &mut BTreeMap<(String, Vec<String>, bool), Vec<bool>>,
) -> Option<BlockReachability> {
    let reachable =
        pattern_reachable_offsets(block.path.as_slice(), segments, zero_or_more, work, cache)?;
    let covers_path = reachable.get(segments.len()).copied().unwrap_or(false);
    let mut complete_offsets = vec![false; segments.len() + 1];
    if !block.allows.is_empty() && covers_path {
        complete_offsets[segments.len()] = true;
    }

    for item in &block.items {
        let Item::Match(child) = item else {
            continue;
        };
        for (offset, can_reach) in reachable.iter().copied().enumerate() {
            if can_reach {
                let child_reachability =
                    block_reachability(child, &segments[offset..], zero_or_more, work, cache)?;
                if child_reachability.can_reach_allow {
                    complete_offsets[offset] = true;
                }
            }
            if can_reach && work.load(Ordering::Relaxed) > MATCH_PATH_PREFILTER_WORK_MAX {
                return None;
            }
        }
    }
    let can_reach_allow = complete_offsets.iter().copied().any(|reachable| reachable);
    Some(BlockReachability {
        can_reach_allow,
        covers_path,
        complete_offsets,
    })
}

#[allow(clippy::too_many_lines)]
fn walk_match<'a>(
    block: &'a MatchBlock,
    remaining: &[String],
    ctx: &RequestContext,
    ev: &mut Evaluator<'a>,
    matched_any: &mut bool,
) -> Result<bool, EvalError> {
    let reachability = block_reachability(
        block,
        remaining,
        ev.wildcard_zero_or_more,
        &ev.match_prefilter_work,
        &mut ev.pattern_reachability_cache,
    );
    if let Some(ref reachability) = reachability {
        if !reachability.can_reach_allow {
            if reachability.covers_path {
                // Preserve the distinction between a covered path with no successful allow and a
                // path for which no match block applies, even when its subtree is pruned.
                *matched_any = true;
            }
            return Ok(false);
        }
    }
    let endpoint_mask = reachability.as_ref().and_then(|reachability| {
        block
            .items
            .iter()
            .any(|item| matches!(item, Item::Match(_)))
            .then_some(reachability.complete_offsets.as_slice())
    });
    let mut outcome: Result<bool, EvalError> = Ok(false);
    let mut raised: Option<EvalError> = None;
    let zero_or_more = ev.wildcard_zero_or_more;
    let match_work = Arc::clone(&ev.match_path_work);
    let prefilter_work = Arc::clone(&ev.match_prefilter_work);
    let mut visit = |rest: Vec<String>, captures: Vec<(String, RulesValue)>| {
        // In a query proof only the segments standing for potential results are
        // undetermined; the database and any concrete ancestor segments stay known.
        let captures: Vec<(String, RulesValue)> = if ctx.abstract_path {
            captures
                .into_iter()
                .map(|(n, v)| {
                    let placeholder = match &v {
                        RulesValue::String(s) => is_abstract_segment(s),
                        RulesValue::Path(p) => p.iter().any(|s| is_abstract_segment(s)),
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
        let captured_bindings: FunctionBindings = Arc::new(
            ev.scope
                .bindings
                .iter()
                .filter_map(|binding| match &binding.state {
                    BindingState::Value(value)
                    | BindingState::Resolved {
                        result: Ok(value), ..
                    } => Some((binding.name.clone(), value.clone())),
                    BindingState::Lazy(_)
                    | BindingState::Evaluating
                    | BindingState::Resolved { .. } => None,
                })
                .collect(),
        );
        bind_function_captures(
            &block.items,
            &captured_bindings,
            &mut ev.scope.function_bindings,
        );
        let mut result: Result<bool, EvalError> = Ok(false);
        if rest.is_empty() {
            *matched_any = true;
            result = evaluate_allows(&block.allows, ctx, ev);
        }
        // An allow that holds decides; otherwise the nested blocks may still allow, and only
        // when nothing does is a raised error the answer.
        if !matches!(result, Ok(true)) && !result.as_ref().is_err_and(stops_request) {
            let nested = walk_items(&block.items, &rest, ctx, ev, matched_any);
            result = either(result, nested);
        }
        ev.scope.functions.truncate(functions_before);
        ev.scope.bindings.truncate(bindings_before);
        match result {
            Ok(true) => {
                outcome = Ok(true);
                Ok(true)
            }
            Ok(false) => Ok(false),
            // A request-wide budget stops enumerating paths; a rule's own error only decides
            // when no other path allows.
            Err(e) if stops_request(&e) => Err(e),
            Err(e @ (EvalError::Budget { .. } | EvalError::Unsupported(_))) => {
                raised.get_or_insert(e);
                Ok(false)
            }
            Err(e) => {
                if matches!(outcome, Ok(false)) {
                    outcome = Err(e);
                }
                Ok(false)
            }
        }
    };
    let matched = match_path(
        &block.path,
        remaining,
        zero_or_more,
        &match_work,
        endpoint_mask,
        &prefilter_work,
        &mut visit,
    )?;
    if matched {
        Ok(true)
    } else if let Some(e) = raised {
        Err(e)
    } else {
        outcome
    }
}

/// Computes, for every pattern position and input offset, whether the suffix can reach one of
/// the complete offsets supplied by the subtree prefilter. This is a bounded dynamic program;
/// recursive wildcards use suffix aggregation instead of enumerating every split.
fn endpoint_reachability(
    pattern: &[PathSegment],
    segments: &[String],
    zero_or_more: bool,
    endpoints: &[bool],
    work: &AtomicU64,
) -> Option<Vec<Vec<bool>>> {
    let segment_count = segments.len();
    let mut table = vec![vec![false; segment_count + 1]; pattern.len() + 1];
    for (offset, allowed) in endpoints
        .iter()
        .copied()
        .enumerate()
        .take(segment_count + 1)
    {
        table[pattern.len()][offset] = allowed;
    }

    for (index, segment) in pattern.iter().enumerate().rev() {
        let next_row = table[index + 1].clone();
        match segment {
            PathSegment::RecursiveWildcard { .. } => {
                let mut eligible = vec![false; segment_count + 1];
                for offset in (0..=segment_count).rev() {
                    let current = work.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                    if current > MATCH_PATH_PREFILTER_WORK_MAX {
                        return None;
                    }
                    eligible[offset] = next_row[offset]
                        && (offset == segment_count || segments[offset] != ABSTRACT_PREFIX);
                }
                let mut suffix_any = vec![false; segment_count + 2];
                for offset in (0..=segment_count).rev() {
                    suffix_any[offset] = eligible[offset] || suffix_any[offset + 1];
                }
                let minimum = usize::from(!zero_or_more);
                for (offset, value) in table[index].iter_mut().enumerate() {
                    let target = offset.saturating_add(minimum);
                    *value = target <= segment_count && suffix_any[target];
                }
            }
            PathSegment::Literal(literal) => {
                for offset in (0..=segment_count).rev() {
                    let current = work.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                    if current > MATCH_PATH_PREFILTER_WORK_MAX {
                        return None;
                    }
                    table[index][offset] = offset < segment_count
                        && segments[offset] == *literal
                        && !is_abstract_segment(literal)
                        && next_row[offset + 1];
                }
            }
            PathSegment::Capture { .. } => {
                for offset in (0..=segment_count).rev() {
                    let current = work.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                    if current > MATCH_PATH_PREFILTER_WORK_MAX {
                        return None;
                    }
                    table[index][offset] = segments
                        .get(offset)
                        .is_some_and(|candidate| candidate != ABSTRACT_PREFIX)
                        && offset < segment_count
                        && next_row[offset + 1];
                }
            }
            PathSegment::Binding(_) => {
                for offset in (0..=segment_count).rev() {
                    let current = work.fetch_add(1, Ordering::Relaxed).saturating_add(1);
                    if current > MATCH_PATH_PREFILTER_WORK_MAX {
                        return None;
                    }
                    table[index][offset] = false;
                }
            }
        }
    }
    Some(table)
}

/// Every way `pattern` matches the start of `segments` (a recursive wildcard consumes zero or
/// more segments under rules version 2, one or more under version 1), each with its
/// unmatched remainder and captured bindings.
#[allow(clippy::too_many_lines)]
fn match_path(
    pattern: &[PathSegment],
    segments: &[String],
    zero_or_more: bool,
    work: &AtomicU64,
    endpoints: Option<&[bool]>,
    prefilter_work: &AtomicU64,
    visit: &mut impl FnMut(Vec<String>, Vec<(String, RulesValue)>) -> Result<bool, EvalError>,
) -> Result<bool, EvalError> {
    #[allow(clippy::too_many_arguments)]
    fn go(
        pattern: &[PathSegment],
        segments: &[String],
        zero_or_more: bool,
        captures: &mut Vec<(String, RulesValue)>,
        pattern_index: usize,
        consumed: usize,
        endpoint_table: Option<&[Vec<bool>]>,
        work: &AtomicU64,
        visit: &mut impl FnMut(Vec<String>, Vec<(String, RulesValue)>) -> Result<bool, EvalError>,
    ) -> Result<bool, EvalError> {
        if endpoint_table.is_some_and(|table| !table[pattern_index][consumed]) {
            return Ok(false);
        }
        let current = work.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        if current > MATCH_PATH_WORK_MAX {
            return Err(EvalError::Budget {
                limit_id: "FIREEMU-RULES-MATCH-WORK",
                current,
                maximum: MATCH_PATH_WORK_MAX,
            });
        }
        let Some((seg, tail)) = pattern.split_first() else {
            return visit(segments.to_vec(), captures.clone());
        };
        match seg {
            PathSegment::Literal(l) => {
                // An undetermined segment is never equal to a literal.
                if segments.first() == Some(l) && !is_abstract_segment(l) {
                    return go(
                        tail,
                        &segments[1..],
                        zero_or_more,
                        captures,
                        pattern_index + 1,
                        consumed + 1,
                        endpoint_table,
                        work,
                        visit,
                    );
                }
            }
            PathSegment::Capture { name, .. } => {
                // The "any prefix" marker stands for zero or more segments: only `**` fits.
                if let Some(v) = segments.first().filter(|v| v.as_str() != ABSTRACT_PREFIX) {
                    captures.push((name.clone(), RulesValue::String(v.clone())));
                    let result = go(
                        tail,
                        &segments[1..],
                        zero_or_more,
                        captures,
                        pattern_index + 1,
                        consumed + 1,
                        endpoint_table,
                        work,
                        visit,
                    );
                    captures.pop();
                    return result;
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
                    let next_consumed = consumed + take;
                    if endpoint_table.is_some_and(|table| !table[pattern_index + 1][next_consumed])
                    {
                        continue;
                    }
                    captures.push((name.clone(), RulesValue::Path(segments[..take].to_vec())));
                    let stop = go(
                        tail,
                        &segments[take..],
                        zero_or_more,
                        captures,
                        pattern_index + 1,
                        next_consumed,
                        endpoint_table,
                        work,
                        visit,
                    )?;
                    captures.pop();
                    if stop {
                        return Ok(true);
                    }
                }
            }
            PathSegment::Binding(_) => {}
        }
        Ok(false)
    }
    let endpoint_table = endpoints.and_then(|endpoints| {
        endpoint_reachability(pattern, segments, zero_or_more, endpoints, prefilter_work)
    });
    go(
        pattern,
        segments,
        zero_or_more,
        &mut Vec::new(),
        0,
        0,
        endpoint_table.as_deref(),
        work,
        visit,
    )
}

fn evaluate_allows<'a>(
    allows: &'a [Allow],
    ctx: &RequestContext,
    ev: &mut Evaluator<'a>,
) -> Result<bool, EvalError> {
    // Allow statements are alternatives: the first that holds allows the request whatever the
    // others raise (production and the official emulator, FS-RULES 2026-09-24). A budget or
    // unsupported error only decides when nothing holds.
    let mut raised = None;
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
            Err(e) if stops_request(&e) => return Err(e),
            Err(e @ (EvalError::Budget { .. } | EvalError::Unsupported(_))) => {
                raised.get_or_insert(e);
            }
        }
    }
    raised.map_or(Ok(false), Err)
}

/// A block's own allows together with its nested blocks: one that holds decides; otherwise a
/// budget or unsupported error outranks an ordinary one, which outranks `false`.
fn either(
    own: Result<bool, EvalError>,
    nested: Result<bool, EvalError>,
) -> Result<bool, EvalError> {
    for result in [&own, &nested] {
        if let Err(e) = result {
            if stops_request(e) {
                return Err(e.clone());
            }
        }
    }
    if matches!(own, Ok(true)) || matches!(nested, Ok(true)) {
        return Ok(true);
    }
    match (own, nested) {
        (Err(a), Err(b)) => Err(if is_hard(&a) || !is_hard(&b) { a } else { b }),
        (Err(e), Ok(_)) | (Ok(_), Err(e)) => Err(e),
        (Ok(_), Ok(_)) => Ok(false),
    }
}

/// Regex matches per request that may exhaust the step budget before the request stops. An
/// exhausted match no longer ends the request (another allow may hold), so without a cap a
/// ruleset of many regex allows would multiply the work one request may cost.
const REGEX_EXHAUSTIONS_PER_REQUEST_MAX: u64 = 4;

/// A budget that ends the whole request, whatever other allows would say: production treats
/// running out of the per-request expression budget as fatal (FS-RULES: `terms-500-then-true`
/// is denied), and fireemu's own matcher-work and regex-exhaustion caps bound the request.
fn stops_request(error: &EvalError) -> bool {
    matches!(
        error,
        EvalError::Budget {
            limit_id: "RULES-EXPRESSIONS-PER-REQUEST"
                | "FIREEMU-RULES-MATCH-WORK"
                | "FIREEMU-REGEX-EXHAUSTIONS-PER-REQUEST",
            ..
        }
    )
}

/// A budget or unsupported error: it decides a request when no alternative allows it.
const fn is_hard(error: &EvalError) -> bool {
    matches!(error, EvalError::Budget { .. } | EvalError::Unsupported(_))
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
        | RulesValue::PartialMapExcluding { .. }
        | RulesValue::PartialList(_)
        | RulesValue::PartialListAny(_)
        | RulesValue::Range(_)
        | RulesValue::RangeExcluding { .. }
        | RulesValue::OneOf(_)
        | RulesValue::NotOneOf(_) => true,
        RulesValue::List(items) | RulesValue::Set(items) => items.iter().any(undetermined),
        RulesValue::Map(m) => m.values().any(undetermined),
        _ => false,
    }
}

fn member_access_chain<'a>(
    expression: &'a Expr,
    members: &mut Vec<(&'a Expr, &'a str)>,
) -> Option<(&'a Expr, &'a str)> {
    match expression.kind() {
        ExprKind::Ident(name) => Some((expression, name)),
        ExprKind::Member { object, name } => {
            let root = member_access_chain(object, members)?;
            members.push((expression, name));
            Some(root)
        }
        _ => None,
    }
}

fn expression_root_identifier(expression: &Expr) -> Option<&str> {
    match expression.kind() {
        ExprKind::Ident(name) => Some(name.as_str()),
        ExprKind::Member { object, .. }
        | ExprKind::Index { object, .. }
        | ExprKind::Slice { object, .. } => expression_root_identifier(object),
        _ => None,
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
            "request" => Some(self.request.as_ref().clone()),
            "resource" => {
                if self.resource_absent {
                    self.absent_resource_used.set(true);
                }
                Some(self.resource.as_ref().clone())
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

    fn query_derived_expression(&self, expr: &Expr) -> bool {
        let mut visiting = Vec::new();
        self.query_derived_expression_with(expr, &mut visiting)
    }

    fn query_float_zero_ambiguous(&self, expr: &Expr, value: &RulesValue) -> bool {
        if !self.query_proof || !matches!(value, RulesValue::Float(f) if *f == 0.0) {
            return false;
        }
        let mut visiting = Vec::new();
        self.query_float_zero_ambiguous_with(expr, &mut visiting)
    }

    fn query_float_zero_source(&self, expr: &Expr) -> bool {
        if !self.query_proof {
            return false;
        }
        let mut visiting = Vec::new();
        self.query_float_zero_ambiguous_with(expr, &mut visiting)
    }

    /// Reports whether evaluating `expr` can expose a query-derived number through a
    /// representation-sensitive string operation. Firestore equality treats integer and double
    /// encodings as equivalent, while Rules stringification preserves their distinct textual
    /// forms. A query proof cannot use such a string as a unique representative for a later
    /// numeric conversion or length calculation.
    fn query_numeric_stringification_sensitive(&self, expr: &Expr) -> bool {
        if !self.query_proof {
            return false;
        }
        self.query_numeric_stringification_sensitive_with(expr)
    }

    /// A query-derived container can carry a numeric member even when the expression itself is
    /// not a numeric expression. `join()` stringifies those members, so preserve the same
    /// representation uncertainty as an explicit `string()` call.
    fn query_container_numeric_stringification_sensitive(&self, expr: &Expr) -> bool {
        self.query_derived_expression(expr)
            && self.query_static_value(expr).is_some_and(|value| {
                matches!(
                    value,
                    RulesValue::List(_)
                        | RulesValue::Set(_)
                        | RulesValue::Map(_)
                        | RulesValue::PartialList(_)
                        | RulesValue::PartialListAny(_)
                        | RulesValue::PartialMap(_)
                        | RulesValue::PartialMapExcluding { .. }
                ) && contains_nested_numeric(&value)
            })
    }

    /// Resolves the statically known portion of a query-proof expression without evaluating it
    /// or charging the request budget. This is used only to distinguish a known string query
    /// value from a numeric value that may have an equivalent integer/double representation.
    fn query_static_value(&self, expr: &Expr) -> Option<RulesValue> {
        self.query_static_value_with_limit(expr, self.scope.bindings.len())
    }

    /// Resolve static values using only bindings visible at the expression's declaration site.
    /// In particular, a lazy `let value = value` must see an earlier parameter/capture rather
    /// than recursively resolving the let binding currently being defined.
    fn query_static_value_with_limit(
        &self,
        expr: &Expr,
        visible_limit: usize,
    ) -> Option<RulesValue> {
        let visible_limit = visible_limit.min(self.scope.bindings.len());
        match expr.kind() {
            ExprKind::Ident(name) => {
                if let Some(index) = self
                    .scope
                    .bindings
                    .get(..visible_limit)?
                    .iter()
                    .rposition(|binding| binding.name == *name)
                {
                    match &self.scope.bindings[index].state {
                        BindingState::Lazy(source) => self.query_static_value_with_limit(
                            source,
                            self.scope.bindings[index].visible_before.min(visible_limit),
                        ),
                        BindingState::Value(value)
                        | BindingState::Resolved {
                            result: Ok(value), ..
                        } => Some(value.clone()),
                        BindingState::Evaluating | BindingState::Resolved { .. } => None,
                    }
                } else {
                    match name.as_str() {
                        "resource" => Some(self.resource.as_ref().clone()),
                        "request" => Some(self.request.as_ref().clone()),
                        _ => None,
                    }
                }
            }
            ExprKind::Member { object, name } => {
                let value = self.query_static_value_with_limit(object, visible_limit)?;
                match value {
                    RulesValue::Map(fields) | RulesValue::PartialMap(fields) => {
                        fields.get(name).cloned()
                    }
                    RulesValue::PartialMapExcluding { fields, .. } => fields.get(name).cloned(),
                    _ => None,
                }
            }
            ExprKind::Index { object, index } => {
                let value = self.query_static_value_with_limit(object, visible_limit)?;
                let RulesValue::String(key) =
                    self.query_static_value_with_limit(index, visible_limit)?
                else {
                    return None;
                };
                match value {
                    RulesValue::Map(fields) | RulesValue::PartialMap(fields) => {
                        fields.get(&key).cloned()
                    }
                    RulesValue::PartialMapExcluding { fields, .. } => fields.get(&key).cloned(),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Returns whether an expression can evaluate to a query-derived number. This is deliberately
    /// separate from `query_derived_expression`: `int()`/`float()` canonicalize a number for most
    /// Rules operations, but a subsequent string conversion can still observe its representation.
    #[allow(clippy::too_many_lines)]
    fn query_numeric_expression_source(&self, expr: &Expr) -> bool {
        match expr.kind() {
            ExprKind::Ident(_) => {
                if let ExprKind::Ident(name) = expr.kind() {
                    if let Some(binding) = self
                        .scope
                        .bindings
                        .iter()
                        .rfind(|binding| binding.name == *name)
                    {
                        if binding.query_numeric_source {
                            return true;
                        }
                    }
                }
                match self.query_static_value(expr) {
                    Some(RulesValue::Int(_) | RulesValue::Float(_)) => {
                        self.query_derived_expression(expr)
                    }
                    Some(_) => false,
                    None => self.query_derived_expression(expr),
                }
            }
            ExprKind::Member { object, .. } => {
                self.query_numeric_expression_source(object)
                    || match self.query_static_value(expr) {
                        Some(RulesValue::Int(_) | RulesValue::Float(_)) => {
                            self.query_derived_expression(expr)
                        }
                        Some(_) => false,
                        None => self.query_derived_expression(expr),
                    }
            }
            ExprKind::Index { object, index } => {
                self.query_numeric_expression_source(object)
                    || self.query_numeric_expression_source(index)
                    || match self.query_static_value(expr) {
                        Some(RulesValue::Int(_) | RulesValue::Float(_)) => {
                            self.query_derived_expression(expr)
                        }
                        Some(_) => false,
                        None => self.query_derived_expression(expr),
                    }
            }
            ExprKind::Slice { object, start, end } => {
                self.query_numeric_expression_source(object)
                    || self.query_numeric_expression_source(start)
                    || self.query_numeric_expression_source(end)
            }
            ExprKind::List(items) => items
                .iter()
                .any(|item| self.query_numeric_expression_source(item)),
            ExprKind::Map(entries) => entries
                .iter()
                .any(|(_, value)| self.query_numeric_expression_source(value)),
            ExprKind::Path(segments) => segments.iter().any(|segment| match segment {
                PathSegment::Binding(expression) => {
                    self.query_numeric_expression_source(expression)
                }
                PathSegment::Literal(_)
                | PathSegment::Capture { .. }
                | PathSegment::RecursiveWildcard { .. } => false,
            }),
            ExprKind::Unary { expr, .. } => self.query_numeric_expression_source(expr),
            ExprKind::Binary { left, right, .. } => {
                self.query_derived_expression(expr)
                    || self.query_numeric_expression_source(left)
                    || self.query_numeric_expression_source(right)
            }
            ExprKind::Ternary {
                cond,
                then,
                otherwise,
            } => {
                self.query_derived_expression(expr)
                    || self.query_numeric_expression_source(cond)
                    || self.query_numeric_expression_source(then)
                    || self.query_numeric_expression_source(otherwise)
            }
            ExprKind::Call { callee, args, .. } => match callee.kind() {
                ExprKind::Ident(name)
                    if name == "float" && args.len() == 1 && self.function(name).is_none() =>
                {
                    self.query_derived_expression(&args[0])
                        || self.query_numeric_expression_source(&args[0])
                }
                ExprKind::Ident(name)
                    if name == "int" && args.len() == 1 && self.function(name).is_none() =>
                {
                    self.query_numeric_stringification_sensitive_with(&args[0])
                }
                ExprKind::Ident(name)
                    if name == "string" && args.len() == 1 && self.function(name).is_none() =>
                {
                    false
                }
                ExprKind::Ident(name)
                    if name == "debug" && args.len() == 1 && self.function(name).is_none() =>
                {
                    self.query_derived_expression(&args[0])
                        || self.query_numeric_expression_source(&args[0])
                }
                ExprKind::Member { name, .. } if name == "size" => false,
                ExprKind::Member { object, name } if name == "join" => {
                    self.query_numeric_expression_source(object)
                        || self.query_numeric_stringification_sensitive_with(object)
                }
                ExprKind::Ident(name) if self.function(name).is_some() => {
                    let argument_provenance = args
                        .iter()
                        .map(|argument| self.query_numeric_expression_source(argument))
                        .collect::<Vec<_>>();
                    self.function(name).is_some_and(|function| {
                        self.function_body_query_numeric_source(
                            function,
                            &argument_provenance,
                            &mut Vec::new(),
                        )
                    })
                }
                _ => self.query_derived_expression(expr),
            },
            _ => false,
        }
    }

    /// Reports whether a query-derived numeric expression can still change the success or error
    /// result of unary negation. Explicit numeric conversions establish the runtime type, while
    /// the broader numeric-source analysis remains representation-sensitive for stringification.
    fn query_numeric_error_source(&self, expr: &Expr) -> bool {
        match expr.kind() {
            ExprKind::Ident(name) => self
                .scope
                .bindings
                .iter()
                .rposition(|binding| binding.name == *name)
                .map_or_else(
                    || self.query_numeric_expression_source(expr),
                    |index| self.scope.bindings[index].query_numeric_error_source,
                ),
            ExprKind::Call { callee, args, .. } => match callee.kind() {
                ExprKind::Ident(name)
                    if matches!(name.as_str(), "int" | "float")
                        && args.len() == 1
                        && self.function(name).is_none() =>
                {
                    false
                }
                ExprKind::Ident(name)
                    if name == "debug" && args.len() == 1 && self.function(name).is_none() =>
                {
                    self.query_numeric_error_source(&args[0])
                }
                ExprKind::Ident(name) if self.function(name).is_some() => {
                    self.function(name).is_none_or(|function| {
                        !self.function_returns_canonical_numeric(function, &mut Vec::new())
                    }) && self.query_numeric_expression_source(expr)
                }
                _ => self.query_numeric_expression_source(expr),
            },
            _ => self.query_numeric_expression_source(expr),
        }
    }

    fn function_returns_canonical_numeric(
        &self,
        function: &FunctionDecl,
        visiting: &mut Vec<usize>,
    ) -> bool {
        let key = function_key(function);
        if visiting.contains(&key) {
            return false;
        }
        if let Some(cached) = self.query_numeric_error_function_cache.borrow().get(&key) {
            return *cached;
        }
        if self.query_numeric_error_analysis_work.get() >= QUERY_DERIVED_ANALYSIS_WORK_MAX {
            return false;
        }
        self.query_numeric_error_analysis_work.set(
            self.query_numeric_error_analysis_work
                .get()
                .saturating_add(1),
        );
        let Some(environment) = self.scope.function_scopes.get(&key).map(Arc::as_ref) else {
            return false;
        };
        visiting.push(key);
        let mut locals = BTreeMap::new();
        for parameter in &function.params {
            locals.insert(parameter.as_str(), false);
        }
        for binding in &function.lets {
            let canonical = self.expression_returns_canonical_numeric(
                &binding.value,
                &locals,
                environment,
                visiting,
            );
            locals.insert(binding.name.as_str(), canonical);
        }
        let result = self.expression_returns_canonical_numeric(
            &function.body,
            &locals,
            environment,
            visiting,
        );
        visiting.pop();
        self.query_numeric_error_function_cache
            .borrow_mut()
            .insert(key, result);
        result
    }

    fn expression_returns_canonical_numeric(
        &self,
        expr: &Expr,
        locals: &BTreeMap<&str, bool>,
        environment: &FunctionEnvironment<'a>,
        visiting: &mut Vec<usize>,
    ) -> bool {
        match expr.kind() {
            ExprKind::Ident(name) => locals.get(name.as_str()).copied().unwrap_or(false),
            ExprKind::Call { callee, args, .. } => match callee.kind() {
                ExprKind::Ident(name)
                    if matches!(name.as_str(), "int" | "float")
                        && args.len() == 1
                        && function_in_environment(environment, name).is_none() =>
                {
                    true
                }
                ExprKind::Ident(name)
                    if name == "debug"
                        && args.len() == 1
                        && function_in_environment(environment, name).is_none() =>
                {
                    self.expression_returns_canonical_numeric(
                        &args[0],
                        locals,
                        environment,
                        visiting,
                    )
                }
                ExprKind::Ident(name) => {
                    function_in_environment(environment, name).is_some_and(|function| {
                        self.function_returns_canonical_numeric(function, visiting)
                    })
                }
                _ => false,
            },
            _ => false,
        }
    }

    /// Reports whether a user function can return a query-derived numeric value. This analysis
    /// keeps numeric provenance separate from the broader query-derived flag, because a function
    /// parameter may carry a known query-derived string while another call carries a canonical
    /// integer/double value whose representation remains relevant to stringification.
    fn function_body_query_numeric_source(
        &self,
        function: &FunctionDecl,
        parameter_provenance: &[bool],
        visiting: &mut Vec<usize>,
    ) -> bool {
        let key = function_key(function);
        if visiting.contains(&key) {
            return true;
        }
        let cache_key = (key, parameter_provenance.to_vec());
        if let Some(cached) = self
            .query_numeric_source_function_cache
            .borrow()
            .get(&cache_key)
        {
            return *cached;
        }
        if self.query_numeric_source_analysis_work.get() >= QUERY_DERIVED_ANALYSIS_WORK_MAX {
            return true;
        }
        self.query_numeric_source_analysis_work.set(
            self.query_numeric_source_analysis_work
                .get()
                .saturating_add(1),
        );
        let Some(environment) = self.scope.function_scopes.get(&key).map(Arc::as_ref) else {
            return true;
        };
        visiting.push(key);
        let mut numeric_locals = BTreeMap::new();
        for (index, parameter) in function.params.iter().enumerate() {
            numeric_locals.insert(
                parameter.as_str(),
                parameter_provenance.get(index).copied().unwrap_or(true),
            );
        }
        for binding in &function.lets {
            let source = self.function_expression_query_numeric_source_only(
                &binding.value,
                &numeric_locals,
                environment,
                visiting,
            );
            numeric_locals.insert(binding.name.as_str(), source);
        }
        let result = self.function_expression_query_numeric_source_only(
            &function.body,
            &numeric_locals,
            environment,
            visiting,
        );
        visiting.pop();
        self.query_numeric_source_function_cache
            .borrow_mut()
            .insert(cache_key, result);
        result
    }

    #[allow(clippy::too_many_lines)]
    fn function_expression_query_numeric_source_only(
        &self,
        expr: &Expr,
        numeric_locals: &BTreeMap<&str, bool>,
        environment: &FunctionEnvironment<'a>,
        visiting: &mut Vec<usize>,
    ) -> bool {
        match expr.kind() {
            ExprKind::Ident(name) => numeric_locals
                .get(name.as_str())
                .copied()
                .unwrap_or(name == "resource"),
            ExprKind::Member { object, .. } => {
                let source = self.function_expression_query_numeric_source_only(
                    object,
                    numeric_locals,
                    environment,
                    visiting,
                );
                if !source
                    || expression_root_identifier(object)
                        .is_some_and(|name| numeric_locals.contains_key(name))
                {
                    return source;
                }
                // Resolve only evaluator globals here. The function-specific analysis is
                // independent of the caller's runtime bindings; using the full binding stack
                // would let a caller parameter named `resource` or `request` shadow the global
                // value referenced by this callee.
                match self.query_static_value_with_limit(expr, 0) {
                    Some(
                        RulesValue::Int(_)
                        | RulesValue::Float(_)
                        | RulesValue::Map(_)
                        | RulesValue::PartialMap(_)
                        | RulesValue::PartialMapExcluding { .. }
                        | RulesValue::List(_)
                        | RulesValue::Set(_)
                        | RulesValue::PartialList(_)
                        | RulesValue::PartialListAny(_),
                    )
                    | None => source,
                    Some(_) => false,
                }
            }
            ExprKind::Index { object, index } => {
                let source = self.function_expression_query_numeric_source_only(
                    object,
                    numeric_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_numeric_source_only(
                    index,
                    numeric_locals,
                    environment,
                    visiting,
                );
                if !source
                    || expression_root_identifier(object)
                        .is_some_and(|name| numeric_locals.contains_key(name))
                {
                    return source;
                }
                match self.query_static_value_with_limit(expr, 0) {
                    Some(
                        RulesValue::Int(_)
                        | RulesValue::Float(_)
                        | RulesValue::Map(_)
                        | RulesValue::PartialMap(_)
                        | RulesValue::PartialMapExcluding { .. }
                        | RulesValue::List(_)
                        | RulesValue::Set(_)
                        | RulesValue::PartialList(_)
                        | RulesValue::PartialListAny(_),
                    )
                    | None => source,
                    Some(_) => false,
                }
            }
            ExprKind::Slice { object, start, end } => {
                self.function_expression_query_numeric_source_only(
                    object,
                    numeric_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_numeric_source_only(
                    start,
                    numeric_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_numeric_source_only(
                    end,
                    numeric_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::List(items) => items.iter().any(|item| {
                self.function_expression_query_numeric_source_only(
                    item,
                    numeric_locals,
                    environment,
                    visiting,
                )
            }),
            ExprKind::Map(entries) => entries.iter().any(|(_, value)| {
                self.function_expression_query_numeric_source_only(
                    value,
                    numeric_locals,
                    environment,
                    visiting,
                )
            }),
            ExprKind::Path(segments) => segments.iter().any(|segment| match segment {
                PathSegment::Binding(expression) => self
                    .function_expression_query_numeric_source_only(
                        expression,
                        numeric_locals,
                        environment,
                        visiting,
                    ),
                PathSegment::Literal(_)
                | PathSegment::Capture { .. }
                | PathSegment::RecursiveWildcard { .. } => false,
            }),
            ExprKind::Unary { expr, .. } => self.function_expression_query_numeric_source_only(
                expr,
                numeric_locals,
                environment,
                visiting,
            ),
            ExprKind::Binary { left, right, .. } => {
                self.function_expression_query_numeric_source_only(
                    left,
                    numeric_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_numeric_source_only(
                    right,
                    numeric_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::Ternary {
                cond,
                then,
                otherwise,
            } => {
                self.function_expression_query_numeric_source_only(
                    cond,
                    numeric_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_numeric_source_only(
                    then,
                    numeric_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_numeric_source_only(
                    otherwise,
                    numeric_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::Call { callee, args, .. } => match callee.kind() {
                ExprKind::Ident(name)
                    if name == "string"
                        && args.len() == 1
                        && function_in_environment(environment, name).is_none() =>
                {
                    false
                }
                ExprKind::Ident(name)
                    if matches!(name.as_str(), "int" | "float" | "debug")
                        && args.len() == 1
                        && function_in_environment(environment, name).is_none() =>
                {
                    if name == "int" {
                        false
                    } else {
                        self.function_expression_query_numeric_source_only(
                            &args[0],
                            numeric_locals,
                            environment,
                            visiting,
                        )
                    }
                }
                ExprKind::Member { name, .. } if name == "size" => false,
                ExprKind::Member { object, name } if name == "join" => self
                    .function_expression_query_numeric_source_only(
                        object,
                        numeric_locals,
                        environment,
                        visiting,
                    ),
                ExprKind::Ident(name) => {
                    let argument_provenance = args
                        .iter()
                        .map(|argument| {
                            self.function_expression_query_numeric_source_only(
                                argument,
                                numeric_locals,
                                environment,
                                visiting,
                            )
                        })
                        .collect::<Vec<_>>();
                    function_in_environment(environment, name).is_some_and(|function| {
                        self.function_body_query_numeric_source(
                            function,
                            &argument_provenance,
                            visiting,
                        )
                    })
                }
                _ => args.iter().any(|argument| {
                    self.function_expression_query_numeric_source_only(
                        argument,
                        numeric_locals,
                        environment,
                        visiting,
                    )
                }),
            },
            _ => false,
        }
    }

    fn function_body_query_stringification_sensitive(
        &self,
        function: &FunctionDecl,
        parameter_provenance: &[QueryStringificationProvenance],
        visiting: &mut Vec<usize>,
    ) -> bool {
        let key = function_key(function);
        if visiting.contains(&key) {
            return true;
        }
        let cache_key = (key, parameter_provenance.to_vec());
        if let Some(cached) = self
            .query_stringification_function_cache
            .borrow()
            .get(&cache_key)
        {
            return *cached;
        }
        if self.query_stringification_analysis_work.get() >= QUERY_DERIVED_ANALYSIS_WORK_MAX {
            return true;
        }
        self.query_stringification_analysis_work.set(
            self.query_stringification_analysis_work
                .get()
                .saturating_add(1),
        );
        let Some(environment) = self.scope.function_scopes.get(&key).map(Arc::as_ref) else {
            return true;
        };
        visiting.push(key);
        let mut query_locals = BTreeMap::new();
        let mut sensitive_locals = BTreeMap::new();
        for (index, parameter) in function.params.iter().enumerate() {
            let (derived, sensitive) = parameter_provenance
                .get(index)
                .copied()
                .unwrap_or((true, true));
            query_locals.insert(parameter.as_str(), derived);
            sensitive_locals.insert(parameter.as_str(), sensitive);
        }
        for binding in &function.lets {
            // A canonical numeric conversion (float()/int()) is not query-derived for ordinary
            // Rules arithmetic, but its result can still expose the query's integer/double
            // representation when passed to string(). Keep that provenance in the local map used
            // by this stringification analysis without changing the arithmetic query proof.
            let derived = self.function_expression_query_derived(
                &binding.value,
                &query_locals,
                environment,
                visiting,
            ) || self.function_expression_query_numeric_source(
                &binding.value,
                &query_locals,
                &sensitive_locals,
                environment,
                visiting,
            );
            let sensitive = self.function_expression_query_stringification_sensitive(
                &binding.value,
                &query_locals,
                &sensitive_locals,
                environment,
                visiting,
            );
            query_locals.insert(binding.name.as_str(), derived);
            sensitive_locals.insert(binding.name.as_str(), sensitive);
        }
        let result = self.function_expression_query_stringification_sensitive(
            &function.body,
            &query_locals,
            &sensitive_locals,
            environment,
            visiting,
        );
        visiting.pop();
        self.query_stringification_function_cache
            .borrow_mut()
            .insert(cache_key, result);
        result
    }

    #[allow(clippy::too_many_lines)]
    fn function_expression_query_stringification_sensitive(
        &self,
        expr: &Expr,
        query_locals: &BTreeMap<&str, bool>,
        sensitive_locals: &BTreeMap<&str, bool>,
        environment: &FunctionEnvironment<'a>,
        visiting: &mut Vec<usize>,
    ) -> bool {
        match expr.kind() {
            ExprKind::Ident(name) => sensitive_locals
                .get(name.as_str())
                .copied()
                .unwrap_or(false),
            ExprKind::Member { object, .. } => self
                .function_expression_query_stringification_sensitive(
                    object,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                ),
            ExprKind::Index { object, index } => {
                self.function_expression_query_stringification_sensitive(
                    object,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_stringification_sensitive(
                    index,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::Slice { object, start, end } => {
                self.function_expression_query_stringification_sensitive(
                    object,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_stringification_sensitive(
                    start,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_stringification_sensitive(
                    end,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::List(items) => items.iter().any(|item| {
                self.function_expression_query_stringification_sensitive(
                    item,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                )
            }),
            ExprKind::Map(entries) => entries.iter().any(|(_, value)| {
                self.function_expression_query_stringification_sensitive(
                    value,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                )
            }),
            ExprKind::Path(segments) => segments.iter().any(|segment| match segment {
                PathSegment::Binding(expression) => self
                    .function_expression_query_stringification_sensitive(
                        expression,
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    ),
                PathSegment::Literal(_)
                | PathSegment::Capture { .. }
                | PathSegment::RecursiveWildcard { .. } => false,
            }),
            ExprKind::Unary { expr, .. } => self
                .function_expression_query_stringification_sensitive(
                    expr,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                ),
            ExprKind::Binary { left, right, .. } => {
                self.function_expression_query_stringification_sensitive(
                    left,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_stringification_sensitive(
                    right,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::Ternary {
                cond,
                then,
                otherwise,
            } => {
                self.function_expression_query_stringification_sensitive(
                    cond,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_stringification_sensitive(
                    then,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_stringification_sensitive(
                    otherwise,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::Call { callee, args, .. } => match callee.kind() {
                ExprKind::Ident(name)
                    if name == "string"
                        && args.len() == 1
                        && function_in_environment(environment, name).is_none() =>
                {
                    let derived = match args[0].kind() {
                        ExprKind::Ident(local) => query_locals
                            .get(local.as_str())
                            .copied()
                            .unwrap_or(self.function_expression_query_derived(
                                &args[0],
                                query_locals,
                                environment,
                                visiting,
                            )),
                        _ => self.function_expression_query_derived(
                            &args[0],
                            query_locals,
                            environment,
                            visiting,
                        ),
                    };
                    derived
                        || self.function_expression_query_numeric_source(
                            &args[0],
                            query_locals,
                            sensitive_locals,
                            environment,
                            visiting,
                        )
                        || self.function_expression_query_stringification_sensitive(
                            &args[0],
                            query_locals,
                            sensitive_locals,
                            environment,
                            visiting,
                        )
                }
                ExprKind::Ident(name)
                    if matches!(name.as_str(), "int" | "float")
                        && args.len() == 1
                        && function_in_environment(environment, name).is_none() =>
                {
                    self.function_expression_query_stringification_sensitive(
                        &args[0],
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    )
                }
                ExprKind::Ident(name)
                    if name == "debug"
                        && args.len() == 1
                        && function_in_environment(environment, name).is_none() =>
                {
                    self.function_expression_query_numeric_source(
                        &args[0],
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    ) || self.function_expression_query_stringification_sensitive(
                        &args[0],
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    )
                }
                ExprKind::Member { object, name } if name == "size" => self
                    .function_expression_query_stringification_sensitive(
                        object,
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    ),
                ExprKind::Member { object, name } if name == "join" => {
                    self.function_expression_query_numeric_source(
                        object,
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    ) || self.function_expression_query_stringification_sensitive(
                        object,
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    )
                }
                ExprKind::Ident(name) => {
                    let argument_provenance = args
                        .iter()
                        .map(|argument| {
                            (
                                self.function_expression_query_derived(
                                    argument,
                                    query_locals,
                                    environment,
                                    visiting,
                                ) || self.function_expression_query_numeric_source(
                                    argument,
                                    query_locals,
                                    sensitive_locals,
                                    environment,
                                    visiting,
                                ),
                                self.function_expression_query_stringification_sensitive(
                                    argument,
                                    query_locals,
                                    sensitive_locals,
                                    environment,
                                    visiting,
                                ),
                            )
                        })
                        .collect::<Vec<_>>();
                    function_in_environment(environment, name).is_some_and(|function| {
                        self.function_body_query_stringification_sensitive(
                            function,
                            &argument_provenance,
                            visiting,
                        )
                    })
                }
                _ => {
                    self.function_expression_query_stringification_sensitive(
                        callee,
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    ) || args.iter().any(|argument| {
                        self.function_expression_query_stringification_sensitive(
                            argument,
                            query_locals,
                            sensitive_locals,
                            environment,
                            visiting,
                        )
                    })
                }
            },
            _ => false,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn function_expression_query_numeric_source(
        &self,
        expr: &Expr,
        query_locals: &BTreeMap<&str, bool>,
        sensitive_locals: &BTreeMap<&str, bool>,
        environment: &FunctionEnvironment<'a>,
        visiting: &mut Vec<usize>,
    ) -> bool {
        match expr.kind() {
            ExprKind::Ident(name) => query_locals
                .get(name.as_str())
                .copied()
                .unwrap_or(name == "resource"),
            ExprKind::Member { object, .. } => self.function_expression_query_numeric_source(
                object,
                query_locals,
                sensitive_locals,
                environment,
                visiting,
            ),
            ExprKind::Index { object, index } => {
                self.function_expression_query_numeric_source(
                    object,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_numeric_source(
                    index,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::Slice { object, start, end } => {
                self.function_expression_query_numeric_source(
                    object,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_numeric_source(
                    start,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_numeric_source(
                    end,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::List(items) => items.iter().any(|item| {
                self.function_expression_query_numeric_source(
                    item,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                )
            }),
            ExprKind::Map(entries) => entries.iter().any(|(_, value)| {
                self.function_expression_query_numeric_source(
                    value,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                )
            }),
            ExprKind::Path(segments) => segments.iter().any(|segment| match segment {
                PathSegment::Binding(expression) => self.function_expression_query_numeric_source(
                    expression,
                    query_locals,
                    sensitive_locals,
                    environment,
                    visiting,
                ),
                PathSegment::Literal(_)
                | PathSegment::Capture { .. }
                | PathSegment::RecursiveWildcard { .. } => false,
            }),
            ExprKind::Unary { expr, .. } => self.function_expression_query_numeric_source(
                expr,
                query_locals,
                sensitive_locals,
                environment,
                visiting,
            ),
            ExprKind::Binary { left, right, .. } => {
                self.function_expression_query_derived(expr, query_locals, environment, visiting)
                    || self.function_expression_query_numeric_source(
                        left,
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    )
                    || self.function_expression_query_numeric_source(
                        right,
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    )
            }
            ExprKind::Ternary {
                cond,
                then,
                otherwise,
            } => {
                self.function_expression_query_derived(expr, query_locals, environment, visiting)
                    || self.function_expression_query_numeric_source(
                        cond,
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    )
                    || self.function_expression_query_numeric_source(
                        then,
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    )
                    || self.function_expression_query_numeric_source(
                        otherwise,
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    )
            }
            ExprKind::Call { callee, args, .. } => match callee.kind() {
                ExprKind::Ident(name)
                    if name == "float"
                        && args.len() == 1
                        && function_in_environment(environment, name).is_none() =>
                {
                    self.function_expression_query_derived(
                        &args[0],
                        query_locals,
                        environment,
                        visiting,
                    ) || self.function_expression_query_numeric_source(
                        &args[0],
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    )
                }
                ExprKind::Ident(name)
                    if name == "int"
                        && args.len() == 1
                        && function_in_environment(environment, name).is_none() =>
                {
                    self.function_expression_query_stringification_sensitive(
                        &args[0],
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    )
                }
                ExprKind::Ident(name)
                    if name == "string"
                        && args.len() == 1
                        && function_in_environment(environment, name).is_none() =>
                {
                    false
                }
                ExprKind::Member { object, name } if name == "size" => false,
                ExprKind::Member { object, name } if name == "join" => {
                    self.function_expression_query_numeric_source(
                        object,
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    ) || self.function_expression_query_stringification_sensitive(
                        object,
                        query_locals,
                        sensitive_locals,
                        environment,
                        visiting,
                    )
                }
                ExprKind::Ident(name) => {
                    let argument_provenance = args
                        .iter()
                        .map(|argument| {
                            self.function_expression_query_numeric_source(
                                argument,
                                query_locals,
                                sensitive_locals,
                                environment,
                                visiting,
                            )
                        })
                        .collect::<Vec<_>>();
                    function_in_environment(environment, name).is_some_and(|function| {
                        self.function_body_query_numeric_source(
                            function,
                            &argument_provenance,
                            visiting,
                        )
                    })
                }
                _ => self.function_expression_query_derived(
                    expr,
                    query_locals,
                    environment,
                    visiting,
                ),
            },
            _ => false,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn query_numeric_stringification_sensitive_with(&self, expr: &Expr) -> bool {
        match expr.kind() {
            ExprKind::Ident(name) => {
                let Some(index) = self
                    .scope
                    .bindings
                    .iter()
                    .rposition(|binding| binding.name == *name)
                else {
                    return false;
                };
                let binding = &self.scope.bindings[index];
                match &binding.state {
                    BindingState::Lazy(_)
                    | BindingState::Value(_)
                    | BindingState::Resolved { .. }
                    | BindingState::Evaluating => binding.query_numeric_stringification_sensitive,
                }
            }
            ExprKind::Member { object, .. } => {
                self.query_numeric_stringification_sensitive_with(object)
            }
            ExprKind::Index { object, index } => {
                self.query_numeric_stringification_sensitive_with(object)
                    || self.query_numeric_stringification_sensitive_with(index)
            }
            ExprKind::Slice { object, start, end } => {
                self.query_numeric_stringification_sensitive_with(object)
                    || self.query_numeric_stringification_sensitive_with(start)
                    || self.query_numeric_stringification_sensitive_with(end)
            }
            ExprKind::List(items) => items
                .iter()
                .any(|item| self.query_numeric_stringification_sensitive_with(item)),
            ExprKind::Map(entries) => entries
                .iter()
                .any(|(_, value)| self.query_numeric_stringification_sensitive_with(value)),
            ExprKind::Path(segments) => segments.iter().any(|segment| match segment {
                PathSegment::Binding(expression) => {
                    self.query_numeric_stringification_sensitive_with(expression)
                }
                PathSegment::Literal(_)
                | PathSegment::Capture { .. }
                | PathSegment::RecursiveWildcard { .. } => false,
            }),
            ExprKind::Unary { expr, .. } => self.query_numeric_stringification_sensitive_with(expr),
            ExprKind::Binary { left, right, .. } => {
                self.query_numeric_stringification_sensitive_with(left)
                    || self.query_numeric_stringification_sensitive_with(right)
            }
            ExprKind::Ternary {
                cond,
                then,
                otherwise,
            } => {
                self.query_numeric_stringification_sensitive_with(cond)
                    || self.query_numeric_stringification_sensitive_with(then)
                    || self.query_numeric_stringification_sensitive_with(otherwise)
            }
            ExprKind::Call { callee, args, .. } => match callee.kind() {
                ExprKind::Ident(name)
                    if name == "string" && args.len() == 1 && self.function(name).is_none() =>
                {
                    self.query_numeric_expression_source(&args[0])
                        || self.query_numeric_stringification_sensitive_with(&args[0])
                }
                // int()/float() canonicalize a numeric value. They do not erase uncertainty
                // introduced by an earlier string conversion, so preserve that provenance.
                ExprKind::Ident(name)
                    if matches!(name.as_str(), "int" | "float")
                        && args.len() == 1
                        && self.function(name).is_none() =>
                {
                    self.query_numeric_stringification_sensitive_with(&args[0])
                }
                ExprKind::Ident(name)
                    if name == "debug" && args.len() == 1 && self.function(name).is_none() =>
                {
                    self.query_numeric_expression_source(&args[0])
                        || self.query_numeric_stringification_sensitive_with(&args[0])
                }
                ExprKind::Ident(name) if self.function(name).is_some() => {
                    let argument_provenance = args
                        .iter()
                        .map(|argument| {
                            (
                                self.query_derived_expression(argument)
                                    || self.query_numeric_expression_source(argument),
                                self.query_numeric_stringification_sensitive_with(argument),
                            )
                        })
                        .collect::<Vec<_>>();
                    self.function(name).is_some_and(|function| {
                        self.function_body_query_stringification_sensitive(
                            function,
                            &argument_provenance,
                            &mut Vec::new(),
                        )
                    })
                }
                // A size() call on a string whose contents came from numeric stringification is
                // representation-sensitive. Collection shape remains independent of element
                // values, so list/map literals are handled conservatively by their caller.
                ExprKind::Member { object, name } if name == "size" => {
                    self.query_numeric_stringification_sensitive_with(object)
                }
                ExprKind::Member { object, name } if name == "join" => {
                    self.query_numeric_expression_source(object)
                        || self.query_numeric_stringification_sensitive_with(object)
                        || self.query_container_numeric_stringification_sensitive(object)
                        || args.iter().any(|argument| {
                            self.query_numeric_stringification_sensitive_with(argument)
                        })
                }
                // Map/list lookup itself does not stringify numeric values. If the selected
                // value is later converted to text, the enclosing string() branch will inspect
                // its numeric source directly; do not taint a known string returned by get().
                ExprKind::Member { object, name } if name == "get" => {
                    self.query_numeric_stringification_sensitive_with(object)
                        || args.iter().any(|argument| {
                            self.query_numeric_stringification_sensitive_with(argument)
                        })
                }
                ExprKind::Member { object, name }
                    if matches!(
                        name.as_str(),
                        "hasAny"
                            | "hasAll"
                            | "hasOnly"
                            | "removeAll"
                            | "toSet"
                            | "union"
                            | "intersection"
                            | "difference"
                            | "bind"
                            | "matches"
                            | "replace"
                    ) =>
                {
                    self.query_numeric_stringification_sensitive_with(object)
                        || args.iter().any(|argument| {
                            self.query_numeric_stringification_sensitive_with(argument)
                        })
                }
                // Unknown methods and user functions may preserve or inspect their arguments;
                // a query-derived argument therefore cannot be treated as one representation.
                _ => {
                    self.query_derived_expression(expr)
                        || self.query_numeric_stringification_sensitive_with(callee)
                        || args.iter().any(|argument| {
                            self.query_numeric_stringification_sensitive_with(argument)
                        })
                }
            },
            _ => false,
        }
    }

    /// Like `query_numeric_stringification_sensitive`, but only for an expression used as the
    /// receiver of `.size()`. A list/map's cardinality is shape-only even when an element was
    /// derived from a query value; strings and methods that preserve their contents remain
    /// sensitive.
    fn query_size_stringification_sensitive(&self, expr: &Expr) -> bool {
        if !self.query_proof {
            return false;
        }
        match expr.kind() {
            ExprKind::Ident(name) => {
                let Some(index) = self
                    .scope
                    .bindings
                    .iter()
                    .rposition(|binding| binding.name == *name)
                else {
                    return false;
                };
                let binding = &self.scope.bindings[index];
                match &binding.state {
                    BindingState::Lazy(_) => binding.query_numeric_stringification_sensitive,
                    BindingState::Value(value)
                    | BindingState::Resolved {
                        result: Ok(value), ..
                    } => {
                        binding.query_numeric_stringification_sensitive
                            && matches!(value, RulesValue::String(_))
                    }
                    BindingState::Resolved { .. } | BindingState::Evaluating => {
                        binding.query_derived
                    }
                }
            }
            ExprKind::Call { callee, args, .. } => match callee.kind() {
                ExprKind::Ident(name)
                    if name == "string" && args.len() == 1 && self.function(name).is_none() =>
                {
                    self.query_numeric_expression_source(&args[0])
                        || self.query_numeric_stringification_sensitive_with(&args[0])
                }
                ExprKind::Ident(name)
                    if name == "debug" && args.len() == 1 && self.function(name).is_none() =>
                {
                    self.query_numeric_expression_source(&args[0])
                        || self.query_size_stringification_sensitive(&args[0])
                }
                ExprKind::Member { object, name } if name == "join" => {
                    self.query_numeric_expression_source(object)
                        || self.query_numeric_stringification_sensitive_with(object)
                        || self.query_container_numeric_stringification_sensitive(object)
                        || args.iter().any(|argument| {
                            self.query_numeric_stringification_sensitive_with(argument)
                        })
                }
                ExprKind::Member { object, .. } => {
                    self.query_size_stringification_sensitive(object)
                }
                _ => self.query_numeric_stringification_sensitive(expr),
            },
            ExprKind::Member { object, .. } => self.query_size_stringification_sensitive(object),
            ExprKind::List(_) | ExprKind::Map(_) => false,
            _ => self.query_numeric_stringification_sensitive(expr),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn query_float_zero_ambiguous_with(&self, expr: &Expr, visiting: &mut Vec<usize>) -> bool {
        match expr.kind() {
            ExprKind::Ident(name) => {
                let Some(index) = self
                    .scope
                    .bindings
                    .iter()
                    .rposition(|binding| binding.name == *name)
                else {
                    return name == "resource";
                };
                let binding = &self.scope.bindings[index];
                if binding.query_float_zero_ambiguous {
                    return true;
                }
                if !binding.query_derived {
                    return false;
                }
                match &binding.state {
                    // Preserve the source expression through lazy aliases such as
                    // `let value = float(resource.data.value)`.
                    BindingState::Lazy(_) => binding.query_float_zero_ambiguous,
                    // A resolved query-derived value has no retained expression. The caller
                    // already observed a float zero, so the missing sign information is unsafe
                    // to treat as canonical.
                    BindingState::Value(_)
                    | BindingState::Resolved { .. }
                    | BindingState::Evaluating => true,
                }
            }
            ExprKind::Member { object, .. } => {
                self.query_float_zero_ambiguous_with(object, visiting)
            }
            ExprKind::Index { object, index } => {
                self.query_float_zero_ambiguous_with(object, visiting)
                    || self.query_derived_expression(index)
            }
            ExprKind::Slice { object, start, end } => {
                self.query_float_zero_ambiguous_with(object, visiting)
                    || self.query_derived_expression(start)
                    || self.query_derived_expression(end)
            }
            ExprKind::List(items) => items
                .iter()
                .any(|item| self.query_float_zero_ambiguous_with(item, visiting)),
            ExprKind::Map(entries) => entries
                .iter()
                .any(|(_, value)| self.query_float_zero_ambiguous_with(value, visiting)),
            ExprKind::Path(segments) => segments.iter().any(|segment| match segment {
                PathSegment::Binding(expression) => {
                    self.query_float_zero_ambiguous_with(expression, visiting)
                }
                PathSegment::Literal(_)
                | PathSegment::Capture { .. }
                | PathSegment::RecursiveWildcard { .. } => false,
            }),
            ExprKind::Unary { expr, .. } => self.query_float_zero_ambiguous_with(expr, visiting),
            ExprKind::Binary { left, right, .. } => {
                self.query_float_zero_ambiguous_with(left, visiting)
                    || self.query_float_zero_ambiguous_with(right, visiting)
            }
            ExprKind::Ternary {
                cond,
                then,
                otherwise,
            } => {
                self.query_float_zero_ambiguous_with(cond, visiting)
                    || self.query_float_zero_ambiguous_with(then, visiting)
                    || self.query_float_zero_ambiguous_with(otherwise, visiting)
            }
            ExprKind::Call { callee, args, .. } => match callee.kind() {
                ExprKind::Ident(name)
                    if name == "float" && args.len() == 1 && self.function("float").is_none() =>
                {
                    self.query_float_zero_ambiguous_with(&args[0], visiting)
                }
                ExprKind::Ident(name)
                    if name == "int" && args.len() == 1 && self.function("int").is_none() =>
                {
                    // int() canonicalizes an equivalent integer/double value, including zero;
                    // unlike float() it cannot preserve a signed-zero distinction.
                    false
                }
                ExprKind::Member { name, .. } if name == "size" => false,
                ExprKind::Ident(name) => {
                    self.function(name).is_some_and(|function| {
                        let argument_provenance = args
                            .iter()
                            .map(|argument| {
                                (
                                    self.query_derived_expression(argument),
                                    self.query_float_zero_ambiguous_with(argument, visiting),
                                )
                            })
                            .collect::<Vec<_>>();
                        self.function_body_query_float_zero_ambiguous(
                            function,
                            &argument_provenance,
                            visiting,
                        )
                    }) || args
                        .iter()
                        .any(|argument| self.query_float_zero_ambiguous_with(argument, visiting))
                }
                _ => {
                    self.query_float_zero_ambiguous_with(callee, visiting)
                        || args.iter().any(|argument| {
                            self.query_float_zero_ambiguous_with(argument, visiting)
                        })
                }
            },
            _ => false,
        }
    }

    fn function_body_query_float_zero_ambiguous(
        &self,
        function: &FunctionDecl,
        parameter_provenance: &[(bool, bool)],
        visiting: &mut Vec<usize>,
    ) -> bool {
        let key = function_key(function);
        if visiting.contains(&key) {
            // A recursive back-edge may eventually reach a query-derived value. Returning
            // false here and caching the parent result would make the answer depend on which
            // declaration happened to be visited first. Fail closed for the proof instead.
            return true;
        }
        let cache_key = (key, parameter_provenance.to_vec());
        if let Some(cached) = self
            .query_float_zero_function_cache
            .borrow()
            .get(&cache_key)
        {
            return *cached;
        }
        if self.query_float_zero_analysis_work.get() >= QUERY_DERIVED_ANALYSIS_WORK_MAX {
            return true;
        }
        self.query_float_zero_analysis_work
            .set(self.query_float_zero_analysis_work.get().saturating_add(1));
        let Some(environment) = self.scope.function_scopes.get(&key).map(Arc::as_ref) else {
            return false;
        };
        visiting.push(key);
        let mut query_locals = BTreeMap::new();
        let mut float_locals = BTreeMap::new();
        for (index, parameter) in function.params.iter().enumerate() {
            let (derived, ambiguous) = parameter_provenance
                .get(index)
                .copied()
                .unwrap_or((true, true));
            query_locals.insert(parameter.as_str(), derived);
            float_locals.insert(parameter.as_str(), derived || ambiguous);
        }
        for binding in &function.lets {
            let derived = self.function_expression_query_derived(
                &binding.value,
                &query_locals,
                environment,
                visiting,
            );
            let ambiguous = self.function_expression_query_float_zero_ambiguous(
                &binding.value,
                &query_locals,
                &float_locals,
                environment,
                visiting,
            );
            query_locals.insert(binding.name.as_str(), derived);
            // A query-derived local whose concrete result is a float zero may have either sign;
            // keep that uncertainty available through later aliases.
            float_locals.insert(binding.name.as_str(), derived || ambiguous);
        }
        let result = self.function_expression_query_float_zero_ambiguous(
            &function.body,
            &query_locals,
            &float_locals,
            environment,
            visiting,
        );
        visiting.pop();
        self.query_float_zero_function_cache
            .borrow_mut()
            .insert(cache_key, result);
        result
    }

    #[allow(clippy::too_many_lines)]
    fn function_expression_query_float_zero_ambiguous(
        &self,
        expr: &Expr,
        query_locals: &BTreeMap<&str, bool>,
        float_locals: &BTreeMap<&str, bool>,
        environment: &FunctionEnvironment<'a>,
        visiting: &mut Vec<usize>,
    ) -> bool {
        match expr.kind() {
            ExprKind::Ident(name) => float_locals
                .get(name.as_str())
                .copied()
                .unwrap_or(name == "resource"),
            ExprKind::Member { object, .. } => self.function_expression_query_float_zero_ambiguous(
                object,
                query_locals,
                float_locals,
                environment,
                visiting,
            ),
            ExprKind::Index { object, index } => {
                self.function_expression_query_float_zero_ambiguous(
                    object,
                    query_locals,
                    float_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_derived(
                    index,
                    query_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::Slice { object, start, end } => {
                self.function_expression_query_float_zero_ambiguous(
                    object,
                    query_locals,
                    float_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_derived(
                    start,
                    query_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_derived(
                    end,
                    query_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::List(items) => items.iter().any(|item| {
                self.function_expression_query_float_zero_ambiguous(
                    item,
                    query_locals,
                    float_locals,
                    environment,
                    visiting,
                )
            }),
            ExprKind::Map(entries) => entries.iter().any(|(_, value)| {
                self.function_expression_query_float_zero_ambiguous(
                    value,
                    query_locals,
                    float_locals,
                    environment,
                    visiting,
                )
            }),
            ExprKind::Path(segments) => segments.iter().any(|segment| match segment {
                PathSegment::Binding(expression) => self
                    .function_expression_query_float_zero_ambiguous(
                        expression,
                        query_locals,
                        float_locals,
                        environment,
                        visiting,
                    ),
                PathSegment::Literal(_)
                | PathSegment::Capture { .. }
                | PathSegment::RecursiveWildcard { .. } => false,
            }),
            ExprKind::Unary { expr, .. } => self.function_expression_query_float_zero_ambiguous(
                expr,
                query_locals,
                float_locals,
                environment,
                visiting,
            ),
            ExprKind::Ternary {
                cond,
                then,
                otherwise,
            } => {
                self.function_expression_query_float_zero_ambiguous(
                    cond,
                    query_locals,
                    float_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_float_zero_ambiguous(
                    then,
                    query_locals,
                    float_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_float_zero_ambiguous(
                    otherwise,
                    query_locals,
                    float_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::Binary { left, right, .. } => {
                self.function_expression_query_float_zero_ambiguous(
                    left,
                    query_locals,
                    float_locals,
                    environment,
                    visiting,
                ) || self.function_expression_query_float_zero_ambiguous(
                    right,
                    query_locals,
                    float_locals,
                    environment,
                    visiting,
                )
            }
            ExprKind::Call { callee, args, .. } => match callee.kind() {
                ExprKind::Ident(name)
                    if name == "float"
                        && args.len() == 1
                        && function_in_environment(environment, name).is_none() =>
                {
                    self.function_expression_query_float_zero_ambiguous(
                        &args[0],
                        query_locals,
                        float_locals,
                        environment,
                        visiting,
                    )
                }
                ExprKind::Ident(name)
                    if name == "int"
                        && args.len() == 1
                        && function_in_environment(environment, name).is_none() =>
                {
                    // int() canonicalizes an equivalent integer/double value, including zero.
                    false
                }
                ExprKind::Member { name, .. } if name == "size" => false,
                ExprKind::Ident(name) => {
                    function_in_environment(environment, name).is_some_and(|function| {
                        let argument_provenance = args
                            .iter()
                            .map(|argument| {
                                (
                                    self.function_expression_query_derived(
                                        argument,
                                        query_locals,
                                        environment,
                                        visiting,
                                    ),
                                    self.function_expression_query_float_zero_ambiguous(
                                        argument,
                                        query_locals,
                                        float_locals,
                                        environment,
                                        visiting,
                                    ),
                                )
                            })
                            .collect::<Vec<_>>();
                        self.function_body_query_float_zero_ambiguous(
                            function,
                            &argument_provenance,
                            visiting,
                        )
                    }) || args.iter().any(|argument| {
                        self.function_expression_query_float_zero_ambiguous(
                            argument,
                            query_locals,
                            float_locals,
                            environment,
                            visiting,
                        )
                    })
                }
                _ => {
                    self.function_expression_query_float_zero_ambiguous(
                        callee,
                        query_locals,
                        float_locals,
                        environment,
                        visiting,
                    ) || args.iter().any(|argument| {
                        self.function_expression_query_float_zero_ambiguous(
                            argument,
                            query_locals,
                            float_locals,
                            environment,
                            visiting,
                        )
                    })
                }
            },
            _ => false,
        }
    }

    fn query_derived_expression_with(&self, expr: &Expr, visiting: &mut Vec<usize>) -> bool {
        if !self.query_proof {
            return false;
        }
        match expr.kind() {
            ExprKind::Ident(name) => self
                .scope
                .bindings
                .iter()
                .rposition(|binding| binding.name == *name)
                .map_or(name == "resource", |index| {
                    self.scope.bindings[index].query_derived
                }),
            ExprKind::Member { object, .. } => self.query_derived_expression_with(object, visiting),
            ExprKind::Index { object, index } => {
                self.query_derived_expression_with(object, visiting)
                    || self.query_derived_expression_with(index, visiting)
            }
            ExprKind::Slice { object, start, end } => {
                self.query_derived_expression_with(object, visiting)
                    || self.query_derived_expression_with(start, visiting)
                    || self.query_derived_expression_with(end, visiting)
            }
            ExprKind::List(items) => items
                .iter()
                .any(|item| self.query_derived_expression_with(item, visiting)),
            ExprKind::Map(entries) => entries
                .iter()
                .any(|(_, value)| self.query_derived_expression_with(value, visiting)),
            ExprKind::Path(segments) => segments.iter().any(|segment| match segment {
                PathSegment::Binding(expression) => {
                    self.query_derived_expression_with(expression, visiting)
                }
                PathSegment::Literal(_)
                | PathSegment::Capture { .. }
                | PathSegment::RecursiveWildcard { .. } => false,
            }),
            ExprKind::Unary { expr, .. } => self.query_derived_expression_with(expr, visiting),
            ExprKind::Binary { left, right, .. } => {
                self.query_derived_expression_with(left, visiting)
                    || self.query_derived_expression_with(right, visiting)
            }
            ExprKind::Ternary {
                cond,
                then,
                otherwise,
            } => {
                self.query_derived_expression_with(cond, visiting)
                    || self.query_derived_expression_with(then, visiting)
                    || self.query_derived_expression_with(otherwise, visiting)
            }
            ExprKind::Call { callee, args, .. } => match callee.kind() {
                // These built-ins canonicalize the numeric representation, so an equality
                // query's integer/double ambiguity does not survive the call.
                ExprKind::Ident(name)
                    if matches!(name.as_str(), "int" | "float")
                        && self.function(name).is_none() =>
                {
                    false
                }
                // Collection/string size is determined by the shape, not numeric encoding.
                ExprKind::Member { name, .. } if name == "size" => false,
                _ => {
                    self.query_derived_expression_with(callee, visiting)
                        || args
                            .iter()
                            .any(|argument| self.query_derived_expression_with(argument, visiting))
                        || matches!(callee.kind(), ExprKind::Ident(name) if self
                            .function(name)
                            .is_some_and(|function| self.function_body_query_derived(function, visiting)))
                }
            },
            _ => false,
        }
    }

    fn function_body_query_derived(
        &self,
        function: &FunctionDecl,
        visiting: &mut Vec<usize>,
    ) -> bool {
        let key = function_key(function);
        if visiting.contains(&key) {
            // See the analogous float-zero analysis above: an in-progress declaration is not a
            // completed, context-independent `false` result.
            return true;
        }
        if let Some(cached) = self.query_derived_function_cache.borrow().get(&key) {
            return *cached;
        }
        if self.query_derived_analysis_work.get() >= QUERY_DERIVED_ANALYSIS_WORK_MAX {
            return true;
        }
        self.query_derived_analysis_work
            .set(self.query_derived_analysis_work.get().saturating_add(1));
        let Some(environment) = self.scope.function_scopes.get(&key).map(Arc::as_ref) else {
            return true;
        };
        visiting.push(key);
        let mut locals = BTreeMap::new();
        for parameter in &function.params {
            locals.insert(parameter.as_str(), false);
        }
        for binding in &function.lets {
            let derived = self.function_expression_query_derived(
                &binding.value,
                &locals,
                environment,
                visiting,
            );
            locals.insert(binding.name.as_str(), derived);
        }
        let derived =
            self.function_expression_query_derived(&function.body, &locals, environment, visiting);
        visiting.pop();
        self.query_derived_function_cache
            .borrow_mut()
            .insert(key, derived);
        derived
    }

    fn function_expression_query_derived(
        &self,
        expr: &Expr,
        locals: &BTreeMap<&str, bool>,
        environment: &FunctionEnvironment<'a>,
        visiting: &mut Vec<usize>,
    ) -> bool {
        match expr.kind() {
            ExprKind::Ident(name) => locals
                .get(name.as_str())
                .copied()
                .unwrap_or(name == "resource"),
            ExprKind::Member { object, .. } => {
                self.function_expression_query_derived(object, locals, environment, visiting)
            }
            ExprKind::Index { object, index } => {
                self.function_expression_query_derived(object, locals, environment, visiting)
                    || self.function_expression_query_derived(index, locals, environment, visiting)
            }
            ExprKind::Slice { object, start, end } => {
                self.function_expression_query_derived(object, locals, environment, visiting)
                    || self.function_expression_query_derived(start, locals, environment, visiting)
                    || self.function_expression_query_derived(end, locals, environment, visiting)
            }
            ExprKind::List(items) => items.iter().any(|item| {
                self.function_expression_query_derived(item, locals, environment, visiting)
            }),
            ExprKind::Map(entries) => entries.iter().any(|(_, value)| {
                self.function_expression_query_derived(value, locals, environment, visiting)
            }),
            ExprKind::Path(segments) => segments.iter().any(|segment| match segment {
                PathSegment::Binding(expression) => self.function_expression_query_derived(
                    expression,
                    locals,
                    environment,
                    visiting,
                ),
                PathSegment::Literal(_)
                | PathSegment::Capture { .. }
                | PathSegment::RecursiveWildcard { .. } => false,
            }),
            ExprKind::Unary { expr, .. } => {
                self.function_expression_query_derived(expr, locals, environment, visiting)
            }
            ExprKind::Binary { left, right, .. } => {
                self.function_expression_query_derived(left, locals, environment, visiting)
                    || self.function_expression_query_derived(right, locals, environment, visiting)
            }
            ExprKind::Ternary {
                cond,
                then,
                otherwise,
            } => {
                self.function_expression_query_derived(cond, locals, environment, visiting)
                    || self.function_expression_query_derived(then, locals, environment, visiting)
                    || self.function_expression_query_derived(
                        otherwise,
                        locals,
                        environment,
                        visiting,
                    )
            }
            ExprKind::Call { callee, args, .. } => match callee.kind() {
                ExprKind::Ident(name)
                    if matches!(name.as_str(), "int" | "float")
                        && function_in_environment(environment, name).is_none() =>
                {
                    false
                }
                ExprKind::Member { name, .. } if name == "size" => false,
                _ => {
                    self.function_expression_query_derived(callee, locals, environment, visiting)
                        || args.iter().any(|argument| {
                            self.function_expression_query_derived(
                                argument,
                                locals,
                                environment,
                                visiting,
                            )
                        })
                        || matches!(callee.kind(), ExprKind::Ident(name) if function_in_environment(environment, name)
                            .is_some_and(|function| self.function_body_query_derived(function, visiting)))
                }
            },
            _ => false,
        }
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
            BindingState::Resolved { result, cause } => {
                self.cause.clone_from(&cause);
                self.scope.bindings[index].state = BindingState::Resolved {
                    result: result.clone(),
                    cause,
                };
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
                hidden[index - visible_before].state = BindingState::Resolved {
                    result: result.clone(),
                    cause: self.cause.clone(),
                };
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
        // The budget counts documents, not calls: get() and getAfter() of one path are one
        // access, as production counts them (FS-RULES, 2026-09-24).
        let reads = self
            .doc_cache
            .keys()
            .map(|(_, cached)| cached)
            .chain(core::iter::once(&key.1))
            .collect::<BTreeSet<_>>()
            .len() as u64;
        if reads > self.doc_reads_max {
            return Err(EvalError::Budget {
                limit_id: "RULES-DOC-ACCESS-SINGLE",
                current: reads,
                maximum: self.doc_reads_max,
            });
        }
        // In a Firestore read no write is applied, so the state after it is the current state.
        // Storage rules have no write to apply either and do not offer it.
        let doc = if after {
            match access.get_after(&key.1) {
                Some(doc) => doc,
                None if self.service == RulesService::Firestore => access.get(&key.1),
                None => {
                    return Err(EvalError::Unsupported(
                        "getAfter()/existsAfter() are only available in Firestore rules".into(),
                    ))
                }
            }
        } else {
            access.get(&key.1)
        };
        self.doc_cache.insert(key, doc.clone());
        Ok(doc)
    }

    /// `get()` / `exists()` / `getAfter()` / `existsAfter()` with the evaluated path argument.
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
        let doc = self.read_document(path, matches!(name, "getAfter" | "existsAfter"))?;
        Ok(match (name, doc) {
            ("exists" | "existsAfter", d) => RulesValue::Bool(d.is_some()),
            (_, Some(d)) => d,
            // Production Firestore answers null for a missing document (FS-RULES, 2026-09-24);
            // reading a member of it is the error. Storage rules keep the error.
            (_, None) if self.service == RulesService::Firestore => RulesValue::Null,
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
        if let Some(functions) = &self.scope.lexical_functions {
            function_in_environment(functions, name)
        } else {
            self.scope
                .functions
                .iter()
                .rev()
                .find(|f| f.name == name)
                .copied()
        }
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

    fn record_success(&mut self, expr: &Expr, value: &RulesValue) {
        self.cause = None;
        if let Some(coverage) = self.coverage {
            if let Ok(mut coverage) = coverage.try_borrow_mut() {
                coverage.record(expr.span, expr.end, ExprValue::of(value));
            }
        }
    }

    fn project_member_chain(&mut self, expr: &Expr) -> Option<Result<RulesValue, EvalError>> {
        let mut members = Vec::new();
        let (root_expr, root_name) = member_access_chain(expr, &mut members)?;
        if self.has_binding(root_name) {
            return None;
        }
        let root = match root_name {
            "request" => Arc::clone(&self.request),
            "resource" => Arc::clone(&self.resource),
            _ => return None,
        };
        let mut values = vec![root.as_ref()];
        for (_, name) in &members {
            let RulesValue::Map(map) = values.last().copied()? else {
                return None;
            };
            values.push(map.get(*name)?);
        }
        let projected = values.last().copied()?;
        if matches!(
            projected,
            RulesValue::Map(_)
                | RulesValue::List(_)
                | RulesValue::Set(_)
                | RulesValue::PartialMap(_)
                | RulesValue::PartialMapExcluding { .. }
                | RulesValue::PartialList(_)
                | RulesValue::PartialListAny(_)
                | RulesValue::OneOf(_)
                | RulesValue::NotOneOf(_)
                | RulesValue::Range(_)
                | RulesValue::RangeExcluding { .. }
        ) {
            return None;
        }
        let charges = u64::try_from(members.len().saturating_add(1)).unwrap_or(u64::MAX);
        for _ in 0..charges {
            if let Err(error) = self.budget.charge() {
                return Some(Err(error));
            }
        }
        self.projected_member_reads = self.projected_member_reads.saturating_add(1);
        self.record_success(root_expr, values[0]);
        for ((member_expr, _), value) in members
            .iter()
            .zip(values.iter().skip(1))
            .take(members.len().saturating_sub(1))
        {
            self.record_success(member_expr, value);
        }
        Some(Ok(projected.clone()))
    }

    #[allow(clippy::too_many_lines)]
    fn eval_inner(&mut self, expr: &Expr) -> Result<RulesValue, EvalError> {
        if matches!(expr.kind(), ExprKind::Member { .. }) {
            if let Some(result) = self.project_member_chain(expr) {
                return result;
            }
        }
        self.budget.charge_node(expr)?;
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
                    RulesValue::PartialMapExcluding { fields, .. } => {
                        Ok(fields.get(name).cloned().unwrap_or(RulesValue::Unknown))
                    }
                    RulesValue::Unknown => Err(EvalError::Unknown),
                    RulesValue::Null => Err(soft(format!("member {name} of null"))),
                    other => Err(soft(format!("member {name} of {}", other.type_name()))),
                }
            }
            ExprKind::Index { object, index } => {
                let obj = self.eval(object)?;
                let idx = self.eval(index)?;
                if self.query_proof && self.query_numeric_stringification_sensitive(index) {
                    // A numeric value converted to a string can select a different map entry
                    // for an equivalent integer/double query representation (for example `0`
                    // versus `-0`). Such a lookup is not a sound query proof.
                    return Err(EvalError::Unknown);
                }
                if self.query_proof
                    && self.query_derived_expression(index)
                    && matches!(idx, RulesValue::Int(_) | RulesValue::Float(_))
                {
                    return Err(EvalError::Unknown);
                }
                match (obj, idx) {
                    (RulesValue::Map(m), RulesValue::String(k)) => m
                        .get(&k)
                        .cloned()
                        .ok_or_else(|| soft(format!("missing key {k}"))),
                    (RulesValue::PartialMap(m), RulesValue::String(k)) => {
                        Ok(m.get(&k).cloned().unwrap_or(RulesValue::Unknown))
                    }
                    (RulesValue::PartialMapExcluding { fields, .. }, RulesValue::String(k)) => {
                        Ok(fields.get(&k).cloned().unwrap_or(RulesValue::Unknown))
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
                if self.query_proof
                    && ((self.query_derived_expression(start)
                        && matches!(lo, RulesValue::Int(_) | RulesValue::Float(_)))
                        || (self.query_derived_expression(end)
                            && matches!(hi, RulesValue::Int(_) | RulesValue::Float(_))))
                {
                    return Err(EvalError::Unknown);
                }
                slice(&obj, &lo, &hi)
            }
            ExprKind::Call {
                callee,
                args,
                compiled_regex,
            } => self.call(callee, args, compiled_regex.as_ref()),
            ExprKind::Unary { op, expr } => {
                let v = self.eval(expr)?;
                let negation_boundary = matches!(v, RulesValue::Int(i) if i == i64::MIN)
                    || matches!(v, RulesValue::Float(f) if f.to_bits() == (-(2f64.powi(63))).to_bits());
                if self.query_proof
                    && *op == UnaryOp::Neg
                    && negation_boundary
                    && self.query_numeric_error_source(expr)
                {
                    // `-i64::MIN` raises, while the equivalent double representative can be
                    // negated successfully. Do not authorize from either representative.
                    return Err(EvalError::Unknown);
                }
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
                        PathSegment::Binding(e) => {
                            let value = self.eval(e)?;
                            if self.query_proof
                                && (self.query_numeric_stringification_sensitive(e)
                                    || (self.query_derived_expression(e)
                                        && matches!(
                                            value,
                                            RulesValue::Int(_) | RulesValue::Float(_)
                                        )))
                            {
                                return Err(EvalError::Unknown);
                            }
                            match value {
                                v if undetermined(&v) => return Err(EvalError::Unknown),
                                RulesValue::String(s) => out.push(s),
                                RulesValue::Path(p) => out.extend(p),
                                RulesValue::Int(i) => out.push(i.to_string()),
                                other => {
                                    return Err(soft(format!(
                                        "path binding of {}",
                                        other.type_name()
                                    )))
                                }
                            }
                        }
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
                let query_resource_value = self.query_derived_expression(expr);
                if query_resource_value
                    && matches!(type_name.as_str(), "int" | "float")
                    && matches!(v, RulesValue::Int(_) | RulesValue::Float(_))
                {
                    // Firestore equality is numeric across integer and double encodings. An
                    // exact query value therefore cannot establish its Rules representation.
                    return Err(EvalError::Unknown);
                }
                if let RulesValue::Range(r) | RulesValue::RangeExcluding { range: r, .. } = &v {
                    // Every member shares the range's class; `int` vs `float` stays open.
                    let class = r.class().ok_or(EvalError::Unknown)?;
                    return match type_name.as_str() {
                        "int" | "float" if class == "number" => Err(EvalError::Unknown),
                        t => Ok(RulesValue::Bool(t == class)),
                    };
                }
                if let RulesValue::OneOf(members) = &v {
                    if query_resource_value
                        && matches!(type_name.as_str(), "int" | "float")
                        && members
                            .iter()
                            .any(|m| matches!(m, RulesValue::Int(_) | RulesValue::Float(_)))
                    {
                        return Err(EvalError::Unknown);
                    }
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
                        | RulesValue::RangeExcluding { .. }
                        | RulesValue::PartialMap(_)
                        | RulesValue::PartialMapExcluding { .. }
                        | RulesValue::PartialList(_)
                        | RulesValue::PartialListAny(_)
                ) {
                    return match type_name.as_str() {
                        // A partially known container is at least a container of its kind.
                        "map"
                            if matches!(
                                v,
                                RulesValue::PartialMap(_) | RulesValue::PartialMapExcluding { .. }
                            ) =>
                        {
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
                // Each nested node is one expression evaluation (and one per parentheses).
                self.budget.charge_node(cursor)?;
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
        let query_derived_left = self.query_derived_expression(left);
        let query_derived_right = self.query_derived_expression(right);
        let query_resource_value = query_derived_left || query_derived_right;
        if self.query_proof
            && matches!(
                op,
                BinaryOp::Eq
                    | BinaryOp::Ne
                    | BinaryOp::Lt
                    | BinaryOp::Le
                    | BinaryOp::Gt
                    | BinaryOp::Ge
            )
            && (self.query_numeric_stringification_sensitive(left)
                || self.query_numeric_stringification_sensitive(right))
        {
            // A string produced from a query-derived number may differ for an equivalent integer
            // and double representation. Do not prove a comparison from that one text value.
            return Err(EvalError::Unknown);
        }
        if self.query_proof
            && op == BinaryOp::In
            && (self.query_numeric_stringification_sensitive(left)
                || self.query_numeric_stringification_sensitive(right))
        {
            // Membership observes stringified numeric representations just like a map lookup.
            // A single integer/double representative cannot establish membership for every
            // document accepted by the equality filter.
            return Err(EvalError::Unknown);
        }
        if matches!(
            op,
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod
        ) && ((query_derived_left && numeric_value(&l))
            || (query_derived_right && numeric_value(&r))
            || self.query_float_zero_ambiguous(left, &l)
            || self.query_float_zero_ambiguous(right, &r))
        {
            // Equality filters preserve Firestore's numeric equivalence, but Rules arithmetic
            // distinguishes integer and floating-point operands. A query representative cannot
            // therefore establish an arithmetic result for every matching document.
            return Err(EvalError::Unknown);
        }
        Ok(match (op, &l, &r) {
            // Membership in a partially known container is provable only positively.
            (BinaryOp::In, item, V::PartialList(known)) if !undetermined(item) => {
                if query_membership_result(known, item).is_ok_and(|matches| matches) {
                    V::Bool(true)
                } else {
                    return Err(EvalError::Unknown);
                }
            }
            // At least one candidate is present: membership is certain only when every
            // candidate is the item.
            (BinaryOp::In, item, V::PartialListAny(candidates)) if !undetermined(item) => {
                if !candidates.is_empty() && query_all_equal_result(candidates, item).is_ok() {
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
            (BinaryOp::In, V::String(k), V::PartialMapExcluding { fields, .. }) => {
                if fields.contains_key(k) {
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
            (
                BinaryOp::Eq
                | BinaryOp::Ne
                | BinaryOp::Lt
                | BinaryOp::Le
                | BinaryOp::Gt
                | BinaryOp::Ge,
                V::RangeExcluding { range, excluded },
                c,
            ) if !undetermined(c) => {
                if matches!(op, BinaryOp::Eq | BinaryOp::Ne)
                    && excluded.iter().any(|e| values_equal(e, c))
                {
                    V::Bool(op == BinaryOp::Ne)
                } else {
                    V::Bool(range_relation(range, op, c)?)
                }
            }
            (
                BinaryOp::Eq
                | BinaryOp::Ne
                | BinaryOp::Lt
                | BinaryOp::Le
                | BinaryOp::Gt
                | BinaryOp::Ge,
                c,
                V::RangeExcluding { range, excluded },
            ) if !undetermined(c) => {
                if matches!(op, BinaryOp::Eq | BinaryOp::Ne)
                    && excluded.iter().any(|e| values_equal(e, c))
                {
                    V::Bool(op == BinaryOp::Ne)
                } else {
                    let mirrored = match op {
                        BinaryOp::Lt => BinaryOp::Gt,
                        BinaryOp::Le => BinaryOp::Ge,
                        BinaryOp::Gt => BinaryOp::Lt,
                        BinaryOp::Ge => BinaryOp::Le,
                        other => other,
                    };
                    V::Bool(range_relation(range, mirrored, c)?)
                }
            }
            // A set of candidates: decided when every candidate answers the same.
            (_, V::OneOf(members), c) if !undetermined(c) => {
                V::Bool(unanimous(members.iter().map(|m| {
                    binary_concrete_query(op, m, c, query_resource_value)
                }))?)
            }
            (_, c, V::OneOf(members)) if !undetermined(c) => {
                V::Bool(unanimous(members.iter().map(|m| {
                    binary_concrete_query(op, c, m, query_resource_value)
                }))?)
            }
            // A value known to differ from some values: only equality is ever decided.
            (BinaryOp::Eq | BinaryOp::Ne, V::NotOneOf(excluded), c)
            | (BinaryOp::Eq | BinaryOp::Ne, c, V::NotOneOf(excluded))
                if !undetermined(c) =>
            {
                if excluded.iter().any(|e| query_values_equal(e, c)) {
                    V::Bool(op == BinaryOp::Ne)
                } else {
                    return Err(EvalError::Unknown);
                }
            }
            (BinaryOp::Eq | BinaryOp::Ne, V::PartialMap(fields), c) if !undetermined(c) => {
                V::Bool(partial_map_relation(op, fields, c)?)
            }
            (BinaryOp::Eq | BinaryOp::Ne, V::PartialMapExcluding { fields, excluded }, c)
                if !undetermined(c) =>
            {
                if excluded
                    .iter()
                    .any(|excluded| query_values_equal(excluded, c))
                {
                    V::Bool(op == BinaryOp::Ne)
                } else {
                    V::Bool(partial_map_relation(op, fields, c)?)
                }
            }
            (BinaryOp::Eq | BinaryOp::Ne, c, V::PartialMap(fields)) if !undetermined(c) => {
                V::Bool(partial_map_relation(op, fields, c)?)
            }
            (BinaryOp::Eq | BinaryOp::Ne, c, V::PartialMapExcluding { fields, excluded })
                if !undetermined(c) =>
            {
                if excluded
                    .iter()
                    .any(|excluded| query_values_equal(excluded, c))
                {
                    V::Bool(op == BinaryOp::Ne)
                } else {
                    V::Bool(partial_map_relation(op, fields, c)?)
                }
            }
            (BinaryOp::In, V::NotOneOf(excluded), V::List(items)) if !undetermined(&r) => {
                if items
                    .iter()
                    .all(|i| excluded.iter().any(|e| query_values_equal(e, i)))
                {
                    V::Bool(false)
                } else {
                    return Err(EvalError::Unknown);
                }
            }
            (BinaryOp::In, V::RangeExcluding { excluded, .. }, V::List(items))
                if !undetermined(&r) =>
            {
                if items
                    .iter()
                    .all(|i| excluded.iter().any(|e| query_values_equal(e, i)))
                {
                    V::Bool(false)
                } else {
                    return Err(EvalError::Unknown);
                }
            }
            (_, a, b) if undetermined(a) || undetermined(b) => return Err(EvalError::Unknown),
            (BinaryOp::Eq, a, b) => V::Bool(if query_resource_value {
                query_equality_result(BinaryOp::Eq, a, b)?
            } else {
                values_equal(a, b)
            }),
            (BinaryOp::Ne, a, b) => V::Bool(if query_resource_value {
                query_equality_result(BinaryOp::Ne, a, b)?
            } else {
                !values_equal(a, b)
            }),
            (BinaryOp::In, item, V::List(items) | V::Set(items)) => {
                V::Bool(if query_resource_value {
                    query_membership_result(items, item)?
                } else {
                    items.iter().any(|x| values_equal(x, item))
                })
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

    #[allow(clippy::too_many_lines)]
    fn call(
        &mut self,
        callee: &Expr,
        args: &[Expr],
        compiled_regex: Option<&Arc<crate::regex::Regex>>,
    ) -> Result<RulesValue, EvalError> {
        match callee.kind() {
            ExprKind::Ident(name) => {
                if let Some(f) = self.function(name) {
                    let values = args
                        .iter()
                        .map(|a| self.eval(a))
                        .collect::<Result<Vec<_>, _>>()?;
                    let query_provenance = args
                        .iter()
                        .map(|argument| {
                            (
                                self.query_derived_expression(argument),
                                self.query_float_zero_source(argument),
                            )
                        })
                        .collect();
                    let stringification_provenance = args
                        .iter()
                        .map(|argument| self.query_numeric_stringification_sensitive(argument))
                        .collect();
                    let numeric_source_provenance = args
                        .iter()
                        .map(|argument| self.query_numeric_expression_source(argument))
                        .collect();
                    let numeric_error_provenance = args
                        .iter()
                        .map(|argument| self.query_numeric_error_source(argument))
                        .collect();
                    return self.call_user(
                        f,
                        values,
                        query_provenance,
                        stringification_provenance,
                        numeric_source_provenance,
                        numeric_error_provenance,
                    );
                }
                match name.as_str() {
                    "get" | "exists" | "getAfter" | "existsAfter" => {
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
                        let query_derived = self.query_derived_expression(a);
                        if self.query_proof
                            && name == "path"
                            && self.query_numeric_stringification_sensitive(a)
                        {
                            return Err(EvalError::Unknown);
                        }
                        let v = self.eval(a)?;
                        let converted = convert(name, v)?;
                        if self.query_proof
                            && name == "int"
                            && query_derived
                            && (matches!(converted, RulesValue::Int(i64::MIN))
                                || self.query_numeric_stringification_sensitive(a))
                        {
                            // Equality filters treat integer and double encodings as one
                            // numeric value, but converting an equivalent double at the i64
                            // boundary or after a representation-sensitive string conversion
                            // can fail. Keep the query proof conservative after every accepted
                            // representation, including a string conversion.
                            return Err(EvalError::Unknown);
                        }
                        Ok(converted)
                    }
                    _ => Err(soft(format!("unknown function {name}"))),
                }
            }
            ExprKind::Member { object, name } => {
                if let ExprKind::Ident(ns) = object.kind() {
                    if NAMESPACES.contains(&ns.as_str()) && !self.has_binding(ns.as_str()) {
                        let integer_only_argument = match (ns.as_str(), name.as_str()) {
                            ("timestamp", "date") => Some([0, 1, 2].as_slice()),
                            ("timestamp" | "duration", "value") => Some([0].as_slice()),
                            ("duration", "time") => Some([0, 1, 2, 3].as_slice()),
                            _ => None,
                        };
                        if self.query_proof
                            && integer_only_argument.is_some_and(|indices| {
                                indices.iter().any(|&index| {
                                    args.get(index).is_some_and(|argument| {
                                        self.query_numeric_error_source(argument)
                                    })
                                })
                            })
                        {
                            // These built-ins require an integer at runtime. A query equality
                            // representative may be a double with the same numeric value, which
                            // would raise instead of succeeding with the integer representative.
                            return Err(EvalError::Unknown);
                        }
                        if self.query_proof
                            && ns == "math"
                            && args.iter().any(|argument| {
                                self.query_numeric_expression_source(argument)
                                    || self.query_float_zero_source(argument)
                            })
                        {
                            // Namespace math operations can expose integer/double differences
                            // that are not represented by the ordinary Rules comparison guard
                            // (for example pow(-0, -1) changes the sign of infinity).
                            return Err(EvalError::Unknown);
                        }
                        let values = args
                            .iter()
                            .map(|a| self.eval(a))
                            .collect::<Result<Vec<_>, _>>()?;
                        return self.namespace_call(ns.as_str(), name, &values);
                    }
                }
                let receiver = self.eval(object)?;
                if self.query_proof
                    && name == "size"
                    && self.query_size_stringification_sensitive(object)
                {
                    // A numeric query value converted to text can have a different length for
                    // an equivalent integer/double representation (for example `0` vs `-0`).
                    // Do not let the shape-only size exemption turn that uncertainty into a
                    // query authorization proof.
                    return Err(EvalError::Unknown);
                }
                if self.query_proof
                    && matches!(receiver, RulesValue::String(_))
                    && self.query_numeric_stringification_sensitive(object)
                {
                    // String methods can inspect the representation (matches, replace, case
                    // conversion, and trimming included), so their result is not proof-safe.
                    return Err(EvalError::Unknown);
                }
                if self.query_proof {
                    let receiver_is_representation_sensitive =
                        self.query_numeric_stringification_sensitive(object);
                    let argument_is_representation_sensitive = args
                        .iter()
                        .any(|argument| self.query_numeric_stringification_sensitive(argument));
                    let lookup_or_membership = matches!(
                        name.as_str(),
                        "get"
                            | "hasAny"
                            | "hasAll"
                            | "hasOnly"
                            | "removeAll"
                            | "toSet"
                            | "union"
                            | "intersection"
                            | "difference"
                            | "bind"
                            | "matches"
                            | "replace"
                    );
                    if lookup_or_membership
                        && (receiver_is_representation_sensitive
                            || argument_is_representation_sensitive)
                    {
                        // Map lookups and collection membership observe stringified numeric
                        // representations. A representative key/member is not unique across
                        // equivalent integer/double query encodings.
                        return Err(EvalError::Unknown);
                    }
                }
                let values = args
                    .iter()
                    .map(|a| self.eval(a))
                    .collect::<Result<Vec<_>, _>>()?;
                if matches!(receiver, RulesValue::String(_))
                    && matches!(name.as_str(), "matches" | "replace")
                {
                    self.string_regex_call(&receiver, name, &values, compiled_regex)
                } else {
                    let query_derived_receiver = self.query_derived_expression(object);
                    let query_derived = query_derived_receiver
                        || args
                            .iter()
                            .any(|argument| self.query_derived_expression(argument));
                    let query_join_stringification_sensitive = self.query_proof
                        && name == "join"
                        && (self.query_numeric_stringification_sensitive(object)
                            || args.iter().any(|argument| {
                                self.query_numeric_stringification_sensitive(argument)
                            })
                            || (query_derived_receiver && contains_nested_numeric(&receiver)));
                    method_call(
                        &receiver,
                        name,
                        &values,
                        query_derived,
                        query_join_stringification_sensitive,
                    )
                }
            }
            _ => Err(soft("call target is not callable")),
        }
    }

    fn regex_for(
        &mut self,
        pattern: &str,
        compiled_regex: Option<&Arc<crate::regex::Regex>>,
    ) -> Result<Arc<crate::regex::Regex>, EvalError> {
        if let Some(regex) = compiled_regex {
            return Ok(Arc::clone(regex));
        }
        if let Some(cached) = self.regex_cache.get(pattern) {
            self.regex_diagnostics.cache_hits = self.regex_diagnostics.cache_hits.saturating_add(1);
            return cached.clone().map_err(|error| {
                EvalError::Unsupported(crate::regex::escape_diagnostic_text(&error.to_string()))
            });
        }
        self.regex_diagnostics.runtime_compiles =
            self.regex_diagnostics.runtime_compiles.saturating_add(1);
        let compiled = crate::regex::Regex::new(pattern).map(Arc::new);
        if self.regex_cache.len() < DYNAMIC_REGEX_CACHE_CAPACITY {
            self.regex_cache
                .insert(pattern.to_owned(), compiled.clone());
            self.regex_diagnostics.peak_cache_entries = self
                .regex_diagnostics
                .peak_cache_entries
                .max(self.regex_cache.len());
        }
        compiled.map_err(|error| {
            EvalError::Unsupported(crate::regex::escape_diagnostic_text(&error.to_string()))
        })
    }

    /// A failed match: a step-budget exhaustion counts toward the request's cap, and past it the
    /// request stops.
    fn regex_failure(&mut self, error: crate::regex::RegexRuntimeError) -> EvalError {
        if matches!(
            error,
            crate::regex::RegexRuntimeError::StepBudgetExceeded { .. }
        ) {
            self.regex_exhaustions = self.regex_exhaustions.saturating_add(1);
            if self.regex_exhaustions > REGEX_EXHAUSTIONS_PER_REQUEST_MAX {
                return EvalError::Budget {
                    limit_id: "FIREEMU-REGEX-EXHAUSTIONS-PER-REQUEST",
                    current: self.regex_exhaustions,
                    maximum: REGEX_EXHAUSTIONS_PER_REQUEST_MAX,
                };
            }
        }
        regex_runtime_error(error)
    }

    fn string_regex_call(
        &mut self,
        receiver: &RulesValue,
        name: &str,
        args: &[RulesValue],
        compiled_regex: Option<&Arc<crate::regex::Regex>>,
    ) -> Result<RulesValue, EvalError> {
        let RulesValue::String(subject) = receiver else {
            unreachable!("the caller checks the receiver type")
        };
        match (name, args) {
            ("matches", [RulesValue::String(pattern)]) => {
                let regex = self.regex_for(pattern, compiled_regex)?;
                let matched = regex.is_full_match(subject);
                Ok(RulesValue::Bool(
                    matched.map_err(|e| self.regex_failure(e))?,
                ))
            }
            ("matches", [_]) => Err(soft("matches() expects a string pattern")),
            ("matches", _) => Err(soft("matches() takes 1 argument(s)")),
            ("replace", [RulesValue::String(pattern), RulesValue::String(replacement)]) => {
                let regex = self.regex_for(pattern, compiled_regex)?;
                let replaced = regex.replace_all(subject, replacement);
                Ok(RulesValue::String(
                    replaced.map_err(|e| self.regex_failure(e))?,
                ))
            }
            ("replace", [_, _]) => Err(soft("replace() expects a pattern and a replacement")),
            ("replace", _) => Err(soft("replace() takes 2 argument(s)")),
            _ => unreachable!("the caller checks the method name"),
        }
    }

    fn call_user(
        &mut self,
        f: &'a FunctionDecl,
        values: Vec<RulesValue>,
        query_provenance: Vec<QueryFloatZeroProvenance>,
        stringification_provenance: Vec<bool>,
        numeric_source_provenance: Vec<bool>,
        numeric_error_provenance: Vec<bool>,
    ) -> Result<RulesValue, EvalError> {
        if values.len() != f.params.len() {
            return Err(soft(format!(
                "{} expects {} arguments",
                f.name,
                f.params.len()
            )));
        }
        let definition_functions = required_function_scope(&self.scope.function_scopes, f)?;
        let Some(definition_bindings) = self.scope.function_bindings.get(&function_key(f)).cloned()
        else {
            return Err(EvalError::Unsupported(
                "function declaration bindings metadata missing".to_owned(),
            ));
        };
        self.budget.enter_call()?;
        let caller_lexical_functions = self.scope.lexical_functions.take();
        self.scope.lexical_functions = Some(definition_functions);
        let caller_bindings = std::mem::take(&mut self.scope.bindings);
        self.scope.bindings = definition_bindings
            .iter()
            .map(|(name, value)| Binding::value(name.clone(), value.clone()))
            .collect();
        for (
            (
                (((p, v), (query_derived, float_zero_ambiguous)), stringification_sensitive),
                numeric_source,
            ),
            numeric_error_source,
        ) in f
            .params
            .iter()
            .zip(values)
            .zip(query_provenance)
            .zip(stringification_provenance)
            .zip(numeric_source_provenance)
            .zip(numeric_error_provenance)
        {
            self.scope.bindings.push(Binding::with_provenance(
                p.clone(),
                v,
                query_derived,
                numeric_source,
                numeric_error_source,
                float_zero_ambiguous,
                stringification_sensitive,
            ));
        }
        let result = {
            for l in &f.lets {
                let visible_before = self.scope.bindings.len();
                let query_derived = self.query_derived_expression(&l.value);
                let query_float_zero_ambiguous = if self.query_proof {
                    let mut visiting = Vec::new();
                    self.query_float_zero_ambiguous_with(&l.value, &mut visiting)
                } else {
                    false
                };
                let query_numeric_stringification_sensitive =
                    self.query_numeric_stringification_sensitive(&l.value);
                let query_numeric_source = self.query_numeric_expression_source(&l.value);
                let query_numeric_error_source = self.query_numeric_error_source(&l.value);
                self.scope.bindings.push(Binding {
                    name: l.name.clone(),
                    visible_before,
                    query_derived,
                    query_numeric_source,
                    query_numeric_error_source,
                    query_float_zero_ambiguous,
                    query_numeric_stringification_sensitive,
                    state: BindingState::Lazy(&l.value),
                });
            }
            self.eval(&f.body)
        };
        self.scope.bindings = caller_bindings;
        self.scope.lexical_functions = caller_lexical_functions;
        self.budget.leave_call();
        result
    }
}

fn function_in_environment<'a>(
    environment: &FunctionEnvironment<'a>,
    name: &str,
) -> Option<&'a FunctionDecl> {
    environment
        .own
        .iter()
        .rev()
        .find(|function| function.name == name)
        .copied()
        .or_else(|| {
            environment
                .parent
                .as_deref()
                .and_then(|parent| function_in_environment(parent, name))
        })
}

fn required_function_scope<'a>(
    scopes: &BTreeMap<usize, Arc<FunctionEnvironment<'a>>>,
    function: &FunctionDecl,
) -> Result<Arc<FunctionEnvironment<'a>>, EvalError> {
    scopes.get(&function_key(function)).cloned().ok_or_else(|| {
        EvalError::Unsupported("function declaration scope metadata missing".to_owned())
    })
}

fn bind_function_captures(
    items: &[Item],
    captures: &FunctionBindings,
    bindings: &mut BTreeMap<usize, FunctionBindings>,
) {
    for item in items {
        if let Item::Function(function) = item {
            bindings.insert(function_key(function), Arc::clone(captures));
        }
    }
}

fn initialize_function_bindings(items: &[Item], bindings: &mut BTreeMap<usize, FunctionBindings>) {
    let empty = Arc::new(Vec::new());
    initialize_function_bindings_with_empty(items, bindings, &empty);
}

fn initialize_function_bindings_with_empty(
    items: &[Item],
    bindings: &mut BTreeMap<usize, FunctionBindings>,
    empty: &FunctionBindings,
) {
    for item in items {
        match item {
            Item::Function(function) => {
                bindings.insert(function_key(function), Arc::clone(empty));
            }
            Item::Match(block) => {
                initialize_function_bindings_with_empty(&block.items, bindings, empty);
            }
        }
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

/// Equality used when proving a query constraint. Firestore query values use the same numeric
/// equivalence recursively through arrays and maps, so a representation-only integer/float
/// difference cannot prove that every matching document differs from a Rules literal. Concrete
/// Rules evaluation continues to use [`values_equal`] so this proof-specific widening does not
/// alter the language evaluator's semantics.
#[allow(clippy::cast_precision_loss, clippy::float_cmp)]
fn query_values_equal(a: &RulesValue, b: &RulesValue) -> bool {
    match (a, b) {
        (RulesValue::Int(x), RulesValue::Float(y)) | (RulesValue::Float(y), RulesValue::Int(x)) => {
            !y.is_nan() && cmp_int_double(*x, *y) == core::cmp::Ordering::Equal
        }
        (RulesValue::List(x), RulesValue::List(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y)
                    .all(|(left, right)| query_values_equal(left, right))
        }
        (RulesValue::Map(x), RulesValue::Map(y)) => {
            x.len() == y.len()
                && x.iter().all(|(key, left)| {
                    y.get(key)
                        .is_some_and(|right| query_values_equal(left, right))
                })
        }
        (RulesValue::Set(x), RulesValue::Set(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|left| y.iter().any(|right| query_values_equal(left, right)))
        }
        _ => values_equal(a, b),
    }
}

/// Compares a partially known map with a concrete value. A missing required key (or a known
/// concrete value that differs) proves inequality; otherwise the unknown remainder keeps the
/// equality undecidable.
fn partial_map_relation(
    op: BinaryOp,
    fields: &BTreeMap<String, RulesValue>,
    candidate: &RulesValue,
) -> Result<bool, EvalError> {
    let RulesValue::Map(candidate) = candidate else {
        return Ok(op == BinaryOp::Ne);
    };
    let definitely_different = fields.iter().any(|(key, expected)| {
        let Some(actual) = candidate.get(key) else {
            return true;
        };
        partial_value_definitely_differs(expected, actual)
    });
    if definitely_different {
        Ok(op == BinaryOp::Ne)
    } else {
        Err(EvalError::Unknown)
    }
}

fn partial_value_definitely_differs(expected: &RulesValue, actual: &RulesValue) -> bool {
    if undetermined(actual) {
        return false;
    }
    match expected {
        RulesValue::Range(range) => {
            range_relation(range, BinaryOp::Eq, actual).is_ok_and(|equal| !equal)
        }
        RulesValue::RangeExcluding { range, excluded } => {
            excluded
                .iter()
                .any(|member| !undetermined(member) && query_values_equal(member, actual))
                || range_relation(range, BinaryOp::Eq, actual).is_ok_and(|equal| !equal)
        }
        RulesValue::OneOf(members) => members
            .iter()
            .all(|member| !undetermined(member) && !query_values_equal(member, actual)),
        RulesValue::NotOneOf(excluded) => excluded
            .iter()
            .any(|member| !undetermined(member) && query_values_equal(member, actual)),
        RulesValue::PartialMap(fields) => {
            matches!(
                partial_map_relation(BinaryOp::Eq, fields, actual),
                Ok(false)
            )
        }
        RulesValue::PartialMapExcluding { fields, excluded } => {
            if excluded
                .iter()
                .any(|member| !undetermined(member) && query_values_equal(member, actual))
            {
                true
            } else {
                matches!(
                    partial_map_relation(BinaryOp::Eq, fields, actual),
                    Ok(false)
                )
            }
        }
        value if undetermined(value) => false,
        value => !query_values_equal(value, actual),
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

fn numeric_value(v: &RulesValue) -> bool {
    matches!(v, RulesValue::Int(_) | RulesValue::Float(_))
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
    query_derived: bool,
    query_join_stringification_sensitive: bool,
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
                .any(|w| query_membership_result(known, w).is_ok_and(|matches| matches))
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
                    .all(|c| query_membership_result(&wanted, c).is_ok_and(|matches| matches))
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
                .all(|w| query_membership_result(known, w).is_ok_and(|matches| matches))
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
        (V::PartialMapExcluding { fields, .. }, "get") => {
            arity(2)?;
            match &args[0] {
                V::String(k) => match fields.get(k) {
                    Some(v) => v.clone(),
                    None => return Err(EvalError::Unknown),
                },
                _ => return Err(soft("get() expects a string key")),
            }
        }
        (
            V::Unknown
            | V::PartialList(_)
            | V::PartialListAny(_)
            | V::PartialMap(_)
            | V::PartialMapExcluding { .. },
            _,
        ) => return Err(EvalError::Unknown),
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
        (V::List(items) | V::Set(items), "size") => {
            arity(0)?;
            V::Int(i64::try_from(items.len()).unwrap_or(i64::MAX))
        }
        (V::List(items), "hasAll") => {
            arity(1)?;
            let wanted = list_arg(&args[0])?;
            V::Bool(all_members_present(items, &wanted, query_derived)?)
        }
        (V::List(items), "hasAny") => {
            arity(1)?;
            let wanted = list_arg(&args[0])?;
            V::Bool(membership_any(items, &wanted, query_derived)?)
        }
        (V::List(items), "hasOnly") => {
            arity(1)?;
            let allowed = list_arg(&args[0])?;
            V::Bool(all_values_allowed(items, &allowed, query_derived)?)
        }
        (V::List(items), "join") => {
            arity(1)?;
            if query_join_stringification_sensitive {
                return Err(EvalError::Unknown);
            }
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
            if query_derived
                && (items.iter().any(contains_nested_numeric)
                    || removed.iter().any(contains_nested_numeric))
            {
                return Err(EvalError::Unknown);
            }
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
            if query_derived && items.iter().any(contains_nested_numeric) {
                return Err(EvalError::Unknown);
            }
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
            if query_derived
                && (items.iter().any(contains_nested_numeric)
                    || other.iter().any(contains_nested_numeric))
            {
                return Err(EvalError::Unknown);
            }
            match name {
                "union" => make_set(items.iter().chain(other).cloned()),
                "intersection" => make_set(
                    items
                        .iter()
                        .filter(|v| other.iter().any(|x| values_equal(x, v)))
                        .cloned()
                        .collect::<Vec<_>>(),
                ),
                _ => make_set(
                    items
                        .iter()
                        .filter(|v| !other.iter().any(|x| values_equal(x, v)))
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
            V::Bool(match name {
                "hasAll" => all_members_present(items, &other, query_derived)?,
                "hasAny" => membership_any(items, &other, query_derived)?,
                _ => all_values_allowed(items, &other, query_derived)?,
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
                        if query_derived && matches!(value, V::Int(_) | V::Float(_)) {
                            return Err(EvalError::Unknown);
                        }
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
            if query_derived
                && (m.values().any(contains_nested_numeric)
                    || other.values().any(contains_nested_numeric))
            {
                // Nested map/list equality is representation-sensitive in Rules while a query
                // may widen an integer/float representation. Do not materialize a changed-key
                // set from one representative and let its size become a proof.
                return Err(EvalError::Unknown);
            }
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

fn binary_concrete_query(
    op: BinaryOp,
    a: &RulesValue,
    b: &RulesValue,
    query_resource_value: bool,
) -> Result<bool, EvalError> {
    if query_resource_value {
        return match op {
            BinaryOp::Eq | BinaryOp::Ne => query_equality_result(op, a, b),
            BinaryOp::In => match b {
                RulesValue::List(items) | RulesValue::Set(items) => {
                    query_membership_result(items, a)
                }
                _ => binary_concrete(op, a, b),
            },
            _ => binary_concrete(op, a, b),
        };
    }
    binary_concrete(op, a, b)
}

fn query_equality_result(op: BinaryOp, a: &RulesValue, b: &RulesValue) -> Result<bool, EvalError> {
    // Query equality can widen numeric equivalence inside containers. That proves neither
    // branch of the Rules comparison when the concrete Rules result is representation-sensitive.
    let query_equal = query_values_equal(a, b);
    let rules_equal = values_equal(a, b);
    if query_equal != rules_equal
        || (query_equal && contains_nested_numeric(a) && contains_nested_numeric(b))
    {
        return Err(EvalError::Unknown);
    }
    Ok(if op == BinaryOp::Eq {
        rules_equal
    } else {
        !rules_equal
    })
}

fn query_membership_result(items: &[RulesValue], item: &RulesValue) -> Result<bool, EvalError> {
    let mut uncertain = false;
    for candidate in items {
        match query_equality_result(BinaryOp::Eq, candidate, item) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(EvalError::Unknown) => uncertain = true,
            Err(error) => return Err(error),
        }
    }
    if uncertain {
        Err(EvalError::Unknown)
    } else {
        Ok(false)
    }
}

fn membership_any(
    items: &[RulesValue],
    wanted: &[RulesValue],
    query_derived: bool,
) -> Result<bool, EvalError> {
    if query_derived {
        let mut uncertain = false;
        for item in wanted {
            match query_membership_result(items, item) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(EvalError::Unknown) => uncertain = true,
                Err(error) => return Err(error),
            }
        }
        return if uncertain {
            Err(EvalError::Unknown)
        } else {
            Ok(false)
        };
    }
    Ok(wanted
        .iter()
        .any(|item| items.iter().any(|candidate| values_equal(candidate, item))))
}

fn all_members_present(
    items: &[RulesValue],
    wanted: &[RulesValue],
    query_derived: bool,
) -> Result<bool, EvalError> {
    let mut uncertain = false;
    for item in wanted {
        match membership_any(items, std::slice::from_ref(item), query_derived) {
            Ok(true) => {}
            Ok(false) => return Ok(false),
            Err(EvalError::Unknown) => uncertain = true,
            Err(error) => return Err(error),
        }
    }
    if uncertain {
        Err(EvalError::Unknown)
    } else {
        Ok(true)
    }
}

fn all_values_allowed(
    items: &[RulesValue],
    allowed: &[RulesValue],
    query_derived: bool,
) -> Result<bool, EvalError> {
    all_members_present(allowed, items, query_derived)
}

fn query_all_equal_result(candidates: &[RulesValue], item: &RulesValue) -> Result<(), EvalError> {
    for candidate in candidates {
        if !query_equality_result(BinaryOp::Eq, candidate, item).is_ok_and(|equal| equal) {
            return Err(EvalError::Unknown);
        }
    }
    Ok(())
}

fn contains_nested_numeric(value: &RulesValue) -> bool {
    match value {
        RulesValue::List(items) | RulesValue::Set(items) => items.iter().any(|item| {
            matches!(item, RulesValue::Int(_) | RulesValue::Float(_))
                || contains_nested_numeric(item)
        }),
        RulesValue::Map(fields) => fields.values().any(|item| {
            matches!(item, RulesValue::Int(_) | RulesValue::Float(_))
                || contains_nested_numeric(item)
        }),
        RulesValue::PartialMap(fields) => fields.values().any(|item| {
            matches!(item, RulesValue::Int(_) | RulesValue::Float(_))
                || contains_nested_numeric(item)
        }),
        RulesValue::PartialMapExcluding { fields, excluded } => {
            fields.values().any(|item| {
                matches!(item, RulesValue::Int(_) | RulesValue::Float(_))
                    || contains_nested_numeric(item)
            }) || excluded.iter().any(|item| {
                matches!(item, RulesValue::Int(_) | RulesValue::Float(_))
                    || contains_nested_numeric(item)
            })
        }
        RulesValue::PartialList(items) | RulesValue::PartialListAny(items) => {
            items.iter().any(|item| {
                matches!(item, RulesValue::Int(_) | RulesValue::Float(_))
                    || contains_nested_numeric(item)
            })
        }
        _ => false,
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

#[cfg(test)]
mod tests {
    use super::{
        bind_function_captures, collect_function_scopes, contains_nested_numeric, evaluate_request,
        function_key, partial_value_definitely_differs, pattern_reachable_offsets,
        required_function_scope, Decision, EvalError, FunctionBindings,
        MATCH_PATH_REACHABILITY_CACHE_MAX_ENTRIES,
    };
    use crate::ast::PathSegment;
    use crate::eval::{Method, RequestContext, RulesService};
    use crate::parse::parse_ruleset;
    use crate::value::{RangeBound, RulesValue, ValueRange};
    use std::collections::BTreeMap;
    use std::fmt::Write as _;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[test]
    fn declarations_in_one_lexical_scope_share_their_function_environment() {
        let mut source = String::from("rules_version = '2';\nservice cloud.firestore {\n");
        for index in 0..256 {
            let _ = writeln!(source, "  function helper{index}() {{ return false; }}");
        }
        source.push_str(
            "  match /databases/{db}/documents/{document=**} { allow read: if false; }\n}",
        );
        let ruleset = parse_ruleset(&source).expect("generated rules should parse");
        let service = &ruleset.services[0];
        let mut scopes = BTreeMap::new();
        collect_function_scopes(service.items.as_slice(), None, &mut scopes);

        assert_eq!(scopes.len(), 256);
        let first = scopes
            .values()
            .next()
            .expect("generated declarations should be indexed");
        assert!(scopes.values().all(|scope| Arc::ptr_eq(scope, first)));
        assert!(service
            .items
            .iter()
            .filter_map(|item| match item {
                crate::ast::Item::Function(function) => Some(function),
                crate::ast::Item::Match(_) => None,
            })
            .all(|function| scopes.contains_key(&function_key(function))));
    }

    #[test]
    fn declarations_in_one_match_share_their_request_capture_table() {
        let mut source = String::from(
            "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents/{owner} {\n",
        );
        for index in 0..256 {
            let _ = writeln!(source, "    function helper{index}() {{ return false; }}");
        }
        source.push_str("    allow read: if true;\n  }\n}");
        let ruleset = parse_ruleset(&source).expect("generated rules should parse");
        let service = &ruleset.services[0];
        let crate::ast::Item::Match(block) = &service.items[0] else {
            panic!("generated scope should be a match block");
        };
        let captures: FunctionBindings = Arc::new(vec![(
            "owner".to_owned(),
            crate::value::RulesValue::String("alice".to_owned()),
        )]);
        let mut bindings = BTreeMap::new();
        bind_function_captures(block.items.as_slice(), &captures, &mut bindings);

        assert_eq!(bindings.len(), 256);
        assert!(bindings.values().all(|table| Arc::ptr_eq(table, &captures)));
    }

    #[test]
    fn missing_function_scope_metadata_is_fail_closed() {
        let ruleset = parse_ruleset(
            "service cloud.firestore { function helper() { return true; } match /databases/{db}/documents { allow read: if helper(); } }",
        )
        .expect("rules should parse");
        let service = &ruleset.services[0];
        let crate::ast::Item::Function(function) = &service.items[0] else {
            panic!("generated declaration should be a function");
        };
        let mut scopes = BTreeMap::new();
        collect_function_scopes(service.items.as_slice(), None, &mut scopes);
        scopes.clear();

        assert!(matches!(
            required_function_scope(&scopes, function),
            Err(EvalError::Unsupported(message)) if message == "function declaration scope metadata missing"
        ));
    }

    #[test]
    fn path_reachability_cache_has_a_request_local_entry_cap() {
        let mut cache = BTreeMap::new();
        let work = AtomicU64::new(0);
        for index in 0..(MATCH_PATH_REACHABILITY_CACHE_MAX_ENTRIES + 512) {
            let pattern = [PathSegment::Literal(format!("segment-{index}"))];
            let reachable = pattern_reachable_offsets(
                &pattern,
                &["target".to_owned()],
                true,
                &work,
                &mut cache,
            )
            .expect("literal reachability should remain decidable");
            assert_eq!(reachable.len(), 2);
        }
        assert_eq!(cache.len(), MATCH_PATH_REACHABILITY_CACHE_MAX_ENTRIES);
        assert!(work.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn range_excluding_proves_difference_for_an_excluded_concrete_value() {
        let constrained = RulesValue::RangeExcluding {
            range: ValueRange {
                lower: Some(RangeBound {
                    value: Box::new(RulesValue::Int(10)),
                    inclusive: false,
                }),
                upper: None,
            },
            excluded: vec![RulesValue::Int(20)],
        };

        assert!(partial_value_definitely_differs(
            &constrained,
            &RulesValue::Int(20)
        ));
        assert!(!partial_value_definitely_differs(
            &constrained,
            &RulesValue::Int(15)
        ));
    }

    #[test]
    fn partial_map_does_not_prove_nested_numeric_container_difference() {
        let expected = RulesValue::PartialMap(BTreeMap::from([(
            "payload".to_owned(),
            RulesValue::List(vec![RulesValue::Int(1)]),
        )]));
        let actual = RulesValue::Map(BTreeMap::from([(
            "payload".to_owned(),
            RulesValue::List(vec![RulesValue::Float(1.0)]),
        )]));

        assert!(!partial_value_definitely_differs(&expected, &actual));

        let nested_expected = RulesValue::PartialMap(BTreeMap::from([(
            "payload".to_owned(),
            RulesValue::Map(BTreeMap::from([("score".to_owned(), RulesValue::Int(1))])),
        )]));
        let nested_actual = RulesValue::Map(BTreeMap::from([(
            "payload".to_owned(),
            RulesValue::Map(BTreeMap::from([(
                "score".to_owned(),
                RulesValue::Float(1.0),
            )])),
        )]));
        assert!(!partial_value_definitely_differs(
            &nested_expected,
            &nested_actual
        ));
        let different_actual = RulesValue::Map(BTreeMap::from([(
            "payload".to_owned(),
            RulesValue::List(vec![RulesValue::Float(2.0)]),
        )]));
        assert!(partial_value_definitely_differs(
            &expected,
            &different_actual
        ));
    }

    #[test]
    fn nested_partial_containers_are_representation_sensitive_for_query_proofs() {
        let nested_partial_map = RulesValue::Map(BTreeMap::from([(
            "payload".to_owned(),
            RulesValue::PartialMap(BTreeMap::from([("score".to_owned(), RulesValue::Int(1))])),
        )]));
        assert!(contains_nested_numeric(&nested_partial_map));

        let nested_partial_list = RulesValue::Map(BTreeMap::from([(
            "payload".to_owned(),
            RulesValue::PartialList(vec![RulesValue::Float(1.0)]),
        )]));
        assert!(contains_nested_numeric(&nested_partial_list));

        let nested_partial_map_excluding = RulesValue::Map(BTreeMap::from([(
            "payload".to_owned(),
            RulesValue::PartialMapExcluding {
                fields: BTreeMap::new(),
                excluded: vec![RulesValue::Int(1)],
            },
        )]));
        assert!(contains_nested_numeric(&nested_partial_map_excluding));

        let nested_partial_list_any = RulesValue::Map(BTreeMap::from([(
            "payload".to_owned(),
            RulesValue::PartialListAny(vec![RulesValue::Float(1.0)]),
        )]));
        assert!(contains_nested_numeric(&nested_partial_list_any));
    }

    #[test]
    fn query_map_diff_does_not_authorize_from_representation_sensitive_changed_keys() {
        let ruleset = parse_ruleset(
            "rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    function canRead() {
      let changed = resource.data.meta.diff({payload: [1.0]}).changedKeys();
      return timestamp.date(changed.size(), 1, 1) is timestamp;
    }

    match /records/{id} {
      allow get: if canRead();
    }
  }
}",
        )
        .expect("map diff rules should parse");

        let map_with_payload = |payload| {
            let payload = RulesValue::List(vec![payload]);
            let meta = RulesValue::Map(BTreeMap::from([("payload".to_owned(), payload)]));
            let data = RulesValue::Map(BTreeMap::from([("meta".to_owned(), meta)]));
            RulesValue::Map(BTreeMap::from([("data".to_owned(), data)]))
        };
        let context = |resource, abstract_path| RequestContext {
            service: RulesService::Firestore,
            method: Method::Get,
            path: "/databases/(default)/documents/records/numeric".to_owned(),
            auth: None,
            resource: Some(resource),
            request_resource: None,
            time_unix_nanos: 0,
            abstract_path,
            request_query: None,
        };

        // Firestore query equality treats integer 1 and double 1.0 as equivalent. The
        // abstract query resource therefore uses the integer representative, while the
        // concrete document uses the stored double. `map.diff()` must not turn that one
        // representative into a definite changed-key set whose size authorizes the query.
        let query_report = evaluate_request(
            &ruleset,
            &context(map_with_payload(RulesValue::Int(1)), true),
        );
        assert!(matches!(query_report.decision, Decision::Deny(_)));

        let concrete_report = evaluate_request(
            &ruleset,
            &context(map_with_payload(RulesValue::Float(1.0)), false),
        );
        assert!(matches!(concrete_report.decision, Decision::Deny(_)));
    }
}
