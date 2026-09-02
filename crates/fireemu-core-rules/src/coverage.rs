//! Per-expression evaluation coverage (`RULES-PARITY-04`).
//!
//! The official Firestore emulator answers `GET /emulator/v1/projects/{p}:ruleCoverage` with
//! the ruleset it has loaded plus a `report`: one tree per top-level expression, each node
//! naming its source extent (`line`, `column`, `currentOffset`, `endOffset`) and the values
//! it took, with a count per distinct value. An expression that raised contributes an
//! `undefined` value carrying the position and message of the cause; an expression that was
//! never evaluated has children but no values at all.
//!
//! This module records exactly that. It stores nothing but positions, counts and the values
//! the evaluator produced, and it is keyed by extent, so two evaluations of the same
//! expression accumulate into one node whatever request they came from.

use std::collections::{BTreeMap, VecDeque};

use crate::ast::{Allow, Expr, Item, Ruleset, Span};
use crate::value::RulesValue;

/// A value an expression took, in the shape a report can print.
#[derive(Debug, Clone, PartialEq)]
pub enum ExprValue {
    /// `null`
    Null,
    /// Boolean.
    Bool(bool),
    /// Integer.
    Int(i64),
    /// Float.
    Float(f64),
    /// String.
    String(String),
    /// The expression raised; the cause names where and why.
    Undefined(UndefinedCause),
    /// A value with no scalar rendering (a list, a map, a timestamp, ...); the type name is
    /// kept so a report still shows that the expression produced something.
    Composite(&'static str),
}

/// Why an expression is undefined: the innermost expression that raised, and its message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndefinedCause {
    /// Position of the expression that raised.
    pub span: Span,
    /// Byte offset just past it.
    pub end: usize,
    /// What went wrong, in fireemu's words.
    pub message: String,
}

impl ExprValue {
    /// The value of a successful evaluation.
    #[must_use]
    pub fn of(value: &RulesValue) -> Self {
        match value {
            RulesValue::Null => Self::Null,
            RulesValue::Bool(b) => Self::Bool(*b),
            RulesValue::Int(i) => Self::Int(*i),
            RulesValue::Float(f) => Self::Float(*f),
            RulesValue::String(s) => Self::String(s.clone()),
            other => Self::Composite(other.type_name()),
        }
    }
}

/// One expression's observed values, in first-seen order.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CoverageEntry {
    /// Position of the expression.
    pub span: Span,
    /// Byte offset just past it.
    pub end: usize,
    /// Distinct values with how often each was produced.
    pub values: Vec<(ExprValue, u64)>,
}

/// Accumulated coverage, keyed by source extent.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Coverage {
    entries: BTreeMap<(usize, usize), CoverageEntry>,
}

impl Coverage {
    /// Records one evaluation of the expression at `span ..= end`.
    pub fn record(&mut self, span: Span, end: usize, value: ExprValue) {
        let entry = self
            .entries
            .entry((span.offset, end))
            .or_insert_with(|| CoverageEntry {
                span,
                end,
                values: Vec::new(),
            });
        // Distinct values stay in first-seen order, which keeps a report stable across runs
        // that evaluate the same expressions in the same order.
        if let Some(slot) = entry.values.iter_mut().find(|(v, _)| *v == value) {
            slot.1 += 1;
        } else {
            entry.values.push((value, 1));
        }
    }

    /// Folds another recording into this one.
    pub fn merge(&mut self, other: &Self) {
        for entry in other.entries.values() {
            let target = self
                .entries
                .entry((entry.span.offset, entry.end))
                .or_insert_with(|| CoverageEntry {
                    span: entry.span,
                    end: entry.end,
                    values: Vec::new(),
                });
            for (value, count) in &entry.values {
                if let Some((_, target_count)) =
                    target.values.iter_mut().find(|(seen, _)| seen == value)
                {
                    *target_count = target_count.saturating_add(*count);
                } else {
                    target.values.push((value.clone(), *count));
                }
            }
        }
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every recorded expression, ordered by position.
    #[must_use]
    pub fn entries(&self) -> Vec<&CoverageEntry> {
        self.entries.values().collect()
    }

    /// The values recorded for one extent, if any.
    #[must_use]
    fn values_at(&self, span: Span, end: usize) -> Option<&[(ExprValue, u64)]> {
        self.entries
            .get(&(span.offset, end))
            .map(|e| e.values.as_slice())
    }
}

/// One node of a coverage report.
#[derive(Debug, Clone, PartialEq)]
pub struct CoverageNode {
    /// Position of the expression.
    pub span: Span,
    /// Byte offset just past it.
    pub end: usize,
    /// Values the expression took; empty when it was never evaluated.
    pub values: Vec<(ExprValue, u64)>,
    /// Sub-expressions, in source order.
    pub children: Vec<CoverageNode>,
}

/// Builds the report of `ruleset` from `coverage`: one tree per `allow` condition and per
/// function body, in source order, whether or not it was ever evaluated.
#[must_use]
pub fn report(ruleset: &Ruleset, coverage: &Coverage) -> Vec<CoverageNode> {
    let mut roots: Vec<&Expr> = Vec::new();
    let mut items: Vec<&Item> = ruleset.services.iter().flat_map(|s| &s.items).collect();
    while let Some(item) = items.pop() {
        match item {
            Item::Match(m) => {
                items.extend(&m.items);
                roots.extend(m.allows.iter().filter_map(|a: &Allow| a.condition.as_ref()));
            }
            Item::Function(f) => {
                roots.extend(f.lets.iter().map(|b| &b.value));
                roots.push(&f.body);
            }
        }
    }
    roots.sort_by_key(|e| (e.span.offset, e.end));
    roots.iter().map(|e| node(e, coverage)).collect()
}

fn node(expr: &Expr, coverage: &Coverage) -> CoverageNode {
    CoverageNode {
        span: expr.span,
        end: expr.end,
        values: coverage
            .values_at(expr.span, expr.end)
            .map(<[(ExprValue, u64)]>::to_vec)
            .unwrap_or_default(),
        children: expr
            .children()
            .into_iter()
            .map(|c| node(c, coverage))
            .collect(),
    }
}

/// How many decided requests the diagnostics keep. A ring rather than a log: the route is
/// a debugging aid, not an audit trail, and a long-running session must not grow without
/// bound.
pub const REQUEST_TRACE_CAPACITY: usize = 100;

/// One decided request, with what every expression of the ruleset evaluated to while it was
/// being decided.
#[derive(Debug, Clone)]
pub struct RequestTrace {
    /// Monotonic sequence number within the session; the newest request has the largest.
    pub sequence: u64,
    /// `get`, `list`, `create`, `update` or `delete`.
    pub method: &'static str,
    /// Document or collection the request named, relative to the database.
    pub path: String,
    /// Whether Security Rules allowed it.
    pub allowed: bool,
    /// Why it was denied, in fireemu's words; empty when it was allowed.
    pub reason: String,
    /// The caller's `request.auth.uid`, if any. No token, and no claim other than the
    /// subject, ever reaches this structure.
    pub uid: Option<String>,
    /// Every expression evaluated while deciding, with the values it took.
    pub expressions: Vec<CoverageEntry>,
}

/// Rules diagnostics for one session: coverage accumulated over every request, and the last
/// [`REQUEST_TRACE_CAPACITY`] requests with their traces.
#[derive(Debug, Default)]
pub struct RulesDiagnostics {
    coverage: Coverage,
    requests: VecDeque<RequestTrace>,
    next_sequence: u64,
    request_traces_enabled: bool,
}

impl RulesDiagnostics {
    /// Coverage accumulated since the ruleset was loaded.
    #[must_use]
    pub const fn coverage(&self) -> &Coverage {
        &self.coverage
    }

    /// The recorded requests, newest first.
    #[must_use]
    pub fn requests(&self) -> Vec<&RequestTrace> {
        self.requests.iter().rev().collect()
    }

    /// Enables the fireemu-specific request trace ring for subsequent decisions.
    pub fn enable_request_traces(&mut self) {
        self.request_traces_enabled = true;
    }

    /// Whether a client has requested fireemu-specific request traces.
    #[must_use]
    pub const fn request_traces_enabled(&self) -> bool {
        self.request_traces_enabled
    }

    /// Drops everything, which is what loading a new ruleset has to do: the recorded
    /// positions describe source that no longer exists.
    pub fn clear(&mut self) {
        self.coverage = Coverage::default();
        self.requests.clear();
    }

    /// Folds one decided request into the session's diagnostics.
    pub fn push(&mut self, coverage: &Coverage, trace: impl FnOnce(u64) -> RequestTrace) {
        self.coverage.merge(coverage);
        if !self.request_traces_enabled {
            return;
        }
        self.next_sequence += 1;
        let sequence = self.next_sequence;
        if self.requests.len() >= REQUEST_TRACE_CAPACITY {
            self.requests.pop_front();
        }
        self.requests.push_back(trace(sequence));
    }

    /// Folds coverage without constructing a fireemu-specific request trace.
    pub fn merge_coverage(&mut self, coverage: &Coverage) {
        self.coverage.merge(coverage);
    }
}
