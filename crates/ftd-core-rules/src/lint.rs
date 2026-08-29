//! Static Rules linter (`RULES-LINT-1`, spec 13.4 - 13.7).
//!
//! Every limit value comes from the `firebase-rules-2026-08-25` catalog through
//! `ftd_core_limits::evaluate`; no literal limit lives in this module.

use std::collections::{BTreeMap, BTreeSet};

use ftd_core_limits::catalogs::FIREBASE_RULES_2026_08_25;
use ftd_core_limits::evaluate::{
    evaluate, LimitDisposition, WarningSeverity, WarningThreshold, DEFAULT_THRESHOLDS,
};
use ftd_core_limits::model::{EnforcementPrecision, LimitDefinition};
use ftd_core_limits::plan::FirestorePlanProfile;

use crate::ast::{Expr, FunctionDecl, Item, MatchBlock, PathSegment, Ruleset, Span};
use crate::parse::{parse_ruleset, ParseError};

/// Linter options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintOptions {
    /// Warning thresholds applied to every limit.
    pub thresholds: Vec<WarningThreshold>,
}

impl Default for LintOptions {
    fn default() -> Self {
        Self {
            thresholds: DEFAULT_THRESHOLDS.to_vec(),
        }
    }
}

/// Diagnostic level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DiagnosticLevel {
    /// Near-limit warning; the ruleset still activates.
    Warning(WarningSeverity),
    /// Compile error; the ruleset must not activate.
    Error,
}

/// One diagnostic.
#[derive(Debug, Clone, PartialEq)]
pub struct Diagnostic {
    /// Stable limit or rule ID.
    pub limit_id: &'static str,
    /// Level.
    pub level: DiagnosticLevel,
    /// Observed value.
    pub current: u64,
    /// Maximum (0 when the rule has no numeric maximum).
    pub maximum: u64,
    /// Source position.
    pub span: Option<Span>,
    /// Function or match path the diagnostic refers to.
    pub subject: Option<String>,
    /// Human-readable message (not a compatibility contract).
    pub message: String,
    /// Precision of the measurement.
    pub precision: EnforcementPrecision,
}

/// Ruleset source size (spec 13.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesSourceSize {
    /// UTF-8 bytes of the source content.
    pub content_utf8_bytes: u64,
    /// Serialized size sent to the Rules Management API. For a single file this equals the
    /// content size; multi-file framing overhead is a conformance item.
    pub serialized_bytes: u64,
    /// Exclusive maximum from the catalog.
    pub maximum_exclusive: u64,
    /// Precision.
    pub precision: EnforcementPrecision,
}

/// Lint report.
#[derive(Debug, Clone, PartialEq)]
pub struct LintReport {
    /// Diagnostics in deterministic order.
    pub diagnostics: Vec<Diagnostic>,
    /// Source size.
    pub source_size: RulesSourceSize,
    /// Parse error, if the source did not parse.
    pub parse_error: Option<ParseError>,
    /// Parsed ruleset, when parsing succeeded.
    pub ruleset: Option<Ruleset>,
}

impl LintReport {
    /// Whether the ruleset may be activated: it parsed and no diagnostic is an error.
    #[must_use]
    pub fn is_activatable(&self) -> bool {
        self.parse_error.is_none()
            && self
                .diagnostics
                .iter()
                .all(|d| d.level != DiagnosticLevel::Error)
    }
}

fn limit(id: &str) -> &'static LimitDefinition {
    FIREBASE_RULES_2026_08_25
        .find(id)
        .unwrap_or_else(|| unreachable!("catalog entry {id} is checked by the catalog tests"))
}

struct Ctx<'a> {
    options: &'a LintOptions,
    diagnostics: Vec<Diagnostic>,
}

impl Ctx<'_> {
    fn check(
        &mut self,
        id: &'static str,
        current: u64,
        span: Option<Span>,
        subject: Option<String>,
        what: &str,
    ) {
        let def = limit(id);
        let plan = FirestorePlanProfile::default();
        let (level, maximum) = match evaluate(def, current, &plan, &self.options.thresholds) {
            LimitDisposition::Allow => return,
            LimitDisposition::AllowWithWarnings(ws) => (
                DiagnosticLevel::Warning(ws[0].severity),
                ws[0].maximum.value(),
            ),
            LimitDisposition::Reject(v) | LimitDisposition::ObservedOverLimit(v) => {
                (DiagnosticLevel::Error, v.maximum.value())
            }
        };
        self.diagnostics.push(Diagnostic {
            limit_id: id,
            level,
            current,
            maximum,
            span,
            subject,
            message: format!("{what}: {current} / {maximum}"),
            precision: def.precision,
        });
    }
}

/// Lints a source text. Size diagnostics are produced even when the source does not parse.
#[must_use]
pub fn lint_source(src: &str, options: &LintOptions) -> LintReport {
    let mut ctx = Ctx {
        options,
        diagnostics: Vec::new(),
    };
    let content_utf8_bytes = src.len() as u64;
    let size_def = limit("RULES-SOURCE-SIZE");
    let maximum_exclusive = match size_def.maximum {
        ftd_core_limits::model::LimitMaximum::Fixed(v) => v,
        _ => 0,
    };
    ctx.check(
        "RULES-SOURCE-SIZE",
        content_utf8_bytes,
        None,
        None,
        "serialized ruleset source bytes",
    );
    let source_size = RulesSourceSize {
        content_utf8_bytes,
        serialized_bytes: content_utf8_bytes,
        maximum_exclusive,
        precision: EnforcementPrecision::BoundaryConformance,
    };

    let (ruleset, parse_error) = match parse_ruleset(src) {
        Ok(r) => (Some(r), None),
        Err(e) => (None, Some(e)),
    };
    if let Some(r) = &ruleset {
        lint_ruleset(r, &mut ctx);
    }
    let mut diagnostics = ctx.diagnostics;
    diagnostics.sort_by(|a, b| {
        a.span
            .cmp(&b.span)
            .then_with(|| a.limit_id.cmp(b.limit_id))
            .then_with(|| a.subject.cmp(&b.subject))
    });
    LintReport {
        diagnostics,
        source_size,
        parse_error,
        ruleset,
    }
}

/// Function declaration with its lexical scope path.
struct DeclaredFunction<'a> {
    decl: &'a FunctionDecl,
    /// Nesting path of the block declaring it (empty for the service body).
    scope: Vec<usize>,
}

/// A call site: callee name, argument count, position, and the scope it occurs in.
struct CallSite {
    callee: String,
    args: u64,
    span: Span,
    scope: Vec<usize>,
    /// Function the call occurs in (`None` for allow conditions).
    from: Option<usize>,
}

fn lint_ruleset(ruleset: &Ruleset, ctx: &mut Ctx<'_>) {
    for service in &ruleset.services {
        let mut functions: Vec<DeclaredFunction<'_>> = Vec::new();
        let mut calls: Vec<CallSite> = Vec::new();
        let mut walker = Walker {
            functions: &mut functions,
            calls: &mut calls,
            worst: BTreeMap::new(),
        };
        walker.items(&service.items, &mut Vec::new(), 0, 0, 0);
        let worst = std::mem::take(&mut walker.worst);
        for (id, (current, span, subject)) in worst {
            ctx.check(
                id,
                current,
                Some(span),
                Some(subject),
                match id {
                    "RULES-MATCH-DEPTH" => "nested match depth",
                    "RULES-MATCH-PATH-SEGMENTS" => "accumulated match path segments",
                    _ => "accumulated path capture variables",
                },
            );
        }
        // Collect calls inside function bodies (done after all functions are known so that
        // calls can be attributed to their declaring function index).
        for (index, f) in functions.iter().enumerate() {
            let mut inner = Vec::new();
            for l in &f.decl.lets {
                collect_calls(&l.value, &f.scope, Some(index), &mut inner);
            }
            collect_calls(&f.decl.body, &f.scope, Some(index), &mut inner);
            calls.extend(inner);
        }
        lint_functions(&functions, &calls, ctx);
    }
}

struct Walker<'w, 'a> {
    functions: &'w mut Vec<DeclaredFunction<'a>>,
    calls: &'w mut Vec<CallSite>,
    /// Worst observed value per accumulated match limit: (current, span, subject).
    worst: BTreeMap<&'static str, (u64, Span, String)>,
}

impl<'a> Walker<'_, 'a> {
    fn items(
        &mut self,
        items: &'a [Item],
        scope: &mut Vec<usize>,
        depth: u64,
        segments: u64,
        captures: u64,
    ) {
        for (i, item) in items.iter().enumerate() {
            match item {
                Item::Function(f) => {
                    self.functions.push(DeclaredFunction {
                        decl: f,
                        scope: scope.clone(),
                    });
                }
                Item::Match(m) => {
                    scope.push(i);
                    self.match_block(m, scope, depth + 1, segments, captures);
                    scope.pop();
                }
            }
        }
    }

    fn match_block(
        &mut self,
        m: &'a MatchBlock,
        scope: &mut Vec<usize>,
        depth: u64,
        segments: u64,
        captures: u64,
    ) {
        let own_segments = m.path.len() as u64;
        let own_captures = m
            .path
            .iter()
            .filter(|s| {
                matches!(
                    s,
                    PathSegment::Capture { .. } | PathSegment::RecursiveWildcard { .. }
                )
            })
            .count() as u64;
        let segments = segments + own_segments;
        let captures = captures + own_captures;
        let subject = describe_path(&m.path);
        for (id, current) in [
            ("RULES-MATCH-DEPTH", depth),
            ("RULES-MATCH-PATH-SEGMENTS", segments),
            ("RULES-PATH-CAPTURES", captures),
        ] {
            let entry = self.worst.entry(id).or_insert((0, m.span, subject.clone()));
            if current > entry.0 {
                *entry = (current, m.span, subject.clone());
            }
        }
        for allow in &m.allows {
            if let Some(cond) = &allow.condition {
                collect_calls(cond, scope, None, self.calls);
            }
        }
        self.items(&m.items, scope, depth, segments, captures);
    }
}

fn describe_path(path: &[PathSegment]) -> String {
    let parts: Vec<String> = path
        .iter()
        .map(|s| match s {
            PathSegment::Literal(l) => l.clone(),
            PathSegment::Capture { name, .. } => format!("{{{name}}}"),
            PathSegment::RecursiveWildcard { name, .. } => format!("{{{name}=**}}"),
            PathSegment::Binding(_) => "$(...)".to_owned(),
        })
        .collect();
    format!("/{}", parts.join("/"))
}

fn collect_calls(expr: &Expr, scope: &[usize], from: Option<usize>, out: &mut Vec<CallSite>) {
    match expr {
        Expr::Call { callee, args, span } => {
            if let Expr::Ident(name) = callee.as_ref() {
                out.push(CallSite {
                    callee: name.clone(),
                    args: args.len() as u64,
                    span: *span,
                    scope: scope.to_vec(),
                    from,
                });
            } else {
                collect_calls(callee, scope, from, out);
            }
            for a in args {
                collect_calls(a, scope, from, out);
            }
        }
        Expr::Member { object, .. } => collect_calls(object, scope, from, out),
        Expr::Index { object, index } => {
            collect_calls(object, scope, from, out);
            collect_calls(index, scope, from, out);
        }
        Expr::Unary { expr, .. } | Expr::Is { expr, .. } => collect_calls(expr, scope, from, out),
        Expr::Binary { left, right, .. } => {
            collect_calls(left, scope, from, out);
            collect_calls(right, scope, from, out);
        }
        Expr::Ternary {
            cond,
            then,
            otherwise,
        } => {
            collect_calls(cond, scope, from, out);
            collect_calls(then, scope, from, out);
            collect_calls(otherwise, scope, from, out);
        }
        Expr::List(items) => {
            for i in items {
                collect_calls(i, scope, from, out);
            }
        }
        Expr::Map(entries) => {
            for (_, v) in entries {
                collect_calls(v, scope, from, out);
            }
        }
        Expr::Path(segments) => {
            for s in segments {
                if let PathSegment::Binding(e) = s {
                    collect_calls(e, scope, from, out);
                }
            }
        }
        Expr::Literal(_) | Expr::Ident(_) => {}
    }
}

/// Resolves a call to the innermost declared function whose scope encloses the call.
fn resolve(functions: &[DeclaredFunction<'_>], call: &CallSite) -> Option<usize> {
    functions
        .iter()
        .enumerate()
        .filter(|(_, f)| f.decl.name == call.callee && call.scope.starts_with(&f.scope))
        .max_by_key(|(_, f)| f.scope.len())
        .map(|(i, _)| i)
}

#[allow(clippy::too_many_lines)]
fn lint_functions(functions: &[DeclaredFunction<'_>], calls: &[CallSite], ctx: &mut Ctx<'_>) {
    // Declaration-level limits.
    for f in functions {
        ctx.check(
            "RULES-FUNCTION-ARGUMENTS",
            f.decl.params.len() as u64,
            Some(f.decl.span),
            Some(f.decl.name.clone()),
            "function parameters",
        );
        ctx.check(
            "RULES-LET-BINDINGS",
            f.decl.lets.len() as u64,
            Some(f.decl.span),
            Some(f.decl.name.clone()),
            "let bindings",
        );
    }

    // Call sites: arity against the declaration, argument count against the limit.
    let mut edges: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); functions.len()];
    let mut roots: BTreeSet<usize> = BTreeSet::new();
    let mut called: BTreeSet<usize> = BTreeSet::new();
    for call in calls {
        let Some(target) = resolve(functions, call) else {
            // Built-ins (get, exists, string methods, ...) are not user functions; their
            // argument count is still subject to the limit.
            ctx.check(
                "RULES-FUNCTION-ARGUMENTS",
                call.args,
                Some(call.span),
                Some(call.callee.clone()),
                "call arguments",
            );
            continue;
        };
        called.insert(target);
        let params = functions[target].decl.params.len() as u64;
        if call.args != params {
            ctx.diagnostics.push(Diagnostic {
                limit_id: "RULES-CALL-ARITY-MISMATCH",
                level: DiagnosticLevel::Error,
                current: call.args,
                maximum: params,
                span: Some(call.span),
                subject: Some(call.callee.clone()),
                message: format!(
                    "{} expects {params} arguments, called with {}",
                    call.callee, call.args
                ),
                precision: EnforcementPrecision::Exact,
            });
            ctx.check(
                "RULES-FUNCTION-ARGUMENTS",
                call.args,
                Some(call.span),
                Some(call.callee.clone()),
                "call arguments",
            );
        }
        match call.from {
            Some(from) => {
                edges[from].insert(target);
            }
            None => {
                roots.insert(target);
            }
        }
    }

    // Unused functions.
    for (i, f) in functions.iter().enumerate() {
        if !called.contains(&i) {
            ctx.diagnostics.push(Diagnostic {
                limit_id: "RULES-UNUSED-FUNCTION",
                level: DiagnosticLevel::Warning(WarningSeverity::Notice),
                current: 0,
                maximum: 0,
                span: Some(f.decl.span),
                subject: Some(f.decl.name.clone()),
                message: format!("function {} is never called", f.decl.name),
                precision: EnforcementPrecision::Exact,
            });
        }
    }

    // Recursion: functions that belong to a cycle (including self loops).
    let cyclic = functions_in_cycles(&edges);
    if !cyclic.is_empty() {
        let names: Vec<&str> = cyclic
            .iter()
            .map(|i| functions[*i].decl.name.as_str())
            .collect();
        let first = *cyclic.iter().next().unwrap_or(&0);
        ctx.check(
            "RULES-RECURSION",
            cyclic.len() as u64,
            Some(functions[first].decl.span),
            Some(names.join(", ")),
            "functions participating in recursive calls",
        );
        return;
    }

    // Call depth: longest chain of frames reachable from an allow condition.
    let mut memo: Vec<Option<u64>> = vec![None; functions.len()];
    let mut deepest = 0u64;
    let mut deepest_root: Option<usize> = None;
    for root in roots {
        let d = depth_of(root, &edges, &mut memo);
        if d > deepest {
            deepest = d;
            deepest_root = Some(root);
        }
    }
    if let Some(root) = deepest_root {
        ctx.check(
            "RULES-FUNCTION-CALL-DEPTH",
            deepest,
            Some(functions[root].decl.span),
            Some(functions[root].decl.name.clone()),
            "function call depth",
        );
    }
}

fn depth_of(node: usize, edges: &[BTreeSet<usize>], memo: &mut Vec<Option<u64>>) -> u64 {
    if let Some(d) = memo[node] {
        return d;
    }
    let mut best = 0;
    for next in &edges[node] {
        best = best.max(depth_of(*next, edges, memo));
    }
    let d = best + 1;
    memo[node] = Some(d);
    d
}

/// Tarjan's strongly connected components; returns every node in a non-trivial SCC or with
/// a self loop.
fn functions_in_cycles(edges: &[BTreeSet<usize>]) -> BTreeSet<usize> {
    struct State<'e> {
        edges: &'e [BTreeSet<usize>],
        index: Vec<Option<usize>>,
        low: Vec<usize>,
        on_stack: Vec<bool>,
        stack: Vec<usize>,
        next: usize,
        cyclic: BTreeSet<usize>,
    }
    fn visit(s: &mut State<'_>, v: usize) {
        s.index[v] = Some(s.next);
        s.low[v] = s.next;
        s.next += 1;
        s.stack.push(v);
        s.on_stack[v] = true;
        for w in s.edges[v].iter().copied().collect::<Vec<_>>() {
            if s.index[w].is_none() {
                visit(s, w);
                s.low[v] = s.low[v].min(s.low[w]);
            } else if s.on_stack[w] {
                s.low[v] = s.low[v].min(s.index[w].unwrap_or(usize::MAX));
            }
        }
        if s.index[v] == Some(s.low[v]) {
            let mut component = Vec::new();
            while let Some(w) = s.stack.pop() {
                s.on_stack[w] = false;
                component.push(w);
                if w == v {
                    break;
                }
            }
            if component.len() > 1 || s.edges[v].contains(&v) {
                s.cyclic.extend(component);
            }
        }
    }
    let n = edges.len();
    let mut s = State {
        edges,
        index: vec![None; n],
        low: vec![0; n],
        on_stack: vec![false; n],
        stack: Vec::new(),
        next: 0,
        cyclic: BTreeSet::new(),
    };
    for v in 0..n {
        if s.index[v].is_none() {
            visit(&mut s, v);
        }
    }
    s.cyclic
}
