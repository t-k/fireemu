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

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::hash::{Hash, Hasher};

use crate::ast::{Allow, Expr, Item, Ruleset, Span};
use crate::value::RulesValue;

/// Distinct values one expression keeps. A later new value is only counted (see
/// [`CoverageNode::omitted`]), so a rule such as `id != 'secret'` cannot make a long-running
/// daemon retain every document id a client ever asked about. Coverage is a diagnostic: no
/// Rules decision reads it, so the bound changes what a report lists, never what is allowed.
pub const COVERAGE_VALUES_PER_EXPRESSION: usize = 64;

/// Bytes of a string value (or of an undefined cause's message) coverage keeps. A longer one
/// is cut at the last character boundary at or before this length, so a kept value never
/// pins more than this many string bytes.
pub const COVERAGE_STRING_BYTES_PER_VALUE: usize = 1024;

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
            RulesValue::String(s) => Self::String(s[..kept_len(s)].to_owned()),
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
#[derive(Debug, Clone, Default)]
pub struct Coverage {
    entries: BTreeMap<(usize, usize), CoverageEntry>,
    indexes: BTreeMap<(usize, usize), ValueIndex>,
    /// Observations, per extent, of values that were not kept because the expression already
    /// held [`COVERAGE_VALUES_PER_EXPRESSION`] distinct values.
    omitted: BTreeMap<(usize, usize), u64>,
}

impl PartialEq for Coverage {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries && self.omitted == other.omitted
    }
}

/// Fingerprints narrow the candidates; exact equality remains authoritative, including collisions.
#[derive(Debug, Clone, Default)]
struct ValueIndex {
    buckets: HashMap<u64, Vec<usize>>,
    #[cfg(test)]
    comparisons: usize,
}

impl ValueIndex {
    fn find(
        &mut self,
        values: &[(ExprValue, u64)],
        value: &ExprValue,
        fingerprint: u64,
    ) -> Option<usize> {
        self.buckets
            .get(&fingerprint)?
            .iter()
            .copied()
            .find(|&position| {
                #[cfg(test)]
                {
                    self.comparisons += 1;
                }
                values[position].0 == *value
            })
    }
}

fn fingerprint(value: &ExprValue) -> Option<u64> {
    let mut hash = std::collections::hash_map::DefaultHasher::new();
    std::mem::discriminant(value).hash(&mut hash);
    match value {
        ExprValue::Null => {}
        ExprValue::Bool(value) => value.hash(&mut hash),
        ExprValue::Int(value) => value.hash(&mut hash),
        // PartialEq coalesces signed zero but never NaNs; retain its original scan path.
        ExprValue::Float(_) => return None,
        ExprValue::String(value) => value.hash(&mut hash),
        ExprValue::Composite(value) => value.hash(&mut hash),
        ExprValue::Undefined(cause) => {
            cause.span.hash(&mut hash);
            cause.end.hash(&mut hash);
            cause.message.hash(&mut hash);
        }
    }
    Some(hash.finish())
}

/// The byte length of the longest prefix of `text` coverage keeps: all of it up to
/// [`COVERAGE_STRING_BYTES_PER_VALUE`], otherwise the last character boundary at or before it.
fn kept_len(text: &str) -> usize {
    if text.len() <= COVERAGE_STRING_BYTES_PER_VALUE {
        return text.len();
    }
    let mut end = COVERAGE_STRING_BYTES_PER_VALUE;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

/// `value` as coverage keeps it: a string, or an undefined cause's message, cut to
/// [`kept_len`]. Lookups use the cut form too, so a long value matches what was kept of it.
fn bounded(value: Cow<'_, ExprValue>) -> Cow<'_, ExprValue> {
    let long = match &*value {
        ExprValue::String(text) => kept_len(text) < text.len(),
        ExprValue::Undefined(cause) => kept_len(&cause.message) < cause.message.len(),
        _ => false,
    };
    if !long {
        return value;
    }
    let cut = |text: &str| text[..kept_len(text)].to_owned();
    Cow::Owned(match &*value {
        ExprValue::String(text) => ExprValue::String(cut(text)),
        ExprValue::Undefined(cause) => ExprValue::Undefined(UndefinedCause {
            span: cause.span,
            end: cause.end,
            message: cut(&cause.message),
        }),
        other => other.clone(),
    })
}

/// Adds `count` observations of `value` to `entry`. A value the entry does not hold yet is
/// kept only while it holds fewer than [`COVERAGE_VALUES_PER_EXPRESSION`] values; otherwise
/// the observations are added to `omitted`. A kept value is never evicted, so every kept
/// count is the exact number of times that value was observed.
fn observe(
    entry: &mut CoverageEntry,
    index: &mut ValueIndex,
    omitted: &mut u64,
    value: Cow<'_, ExprValue>,
    count: u64,
    merge: bool,
) {
    const INDEX_THRESHOLD: usize = 32;
    let value = bounded(value);
    if index.buckets.is_empty() && entry.values.len() >= INDEX_THRESHOLD {
        for (position, (seen, _)) in entry.values.iter().enumerate() {
            if let Some(hash) = fingerprint(seen) {
                index.buckets.entry(hash).or_default().push(position);
            }
        }
    }
    let hash = if index.buckets.is_empty() {
        None
    } else {
        fingerprint(&value)
    };
    let position = if let Some(hash) = hash {
        index.find(&entry.values, &value, hash)
    } else {
        entry.values.iter().position(|(seen, _)| *seen == *value)
    };
    if let Some(position) = position {
        let seen = &mut entry.values[position].1;
        if merge {
            *seen = seen.saturating_add(count);
        } else {
            *seen += count;
        }
    } else if entry.values.len() >= COVERAGE_VALUES_PER_EXPRESSION {
        *omitted = omitted.saturating_add(count);
    } else {
        if !index.buckets.is_empty() {
            if let Some(hash) = hash {
                index
                    .buckets
                    .entry(hash)
                    .or_default()
                    .push(entry.values.len());
            }
        }
        entry.values.push((value.into_owned(), count));
    }
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
        // The report keeps first-seen order; the auxiliary index only selects candidate positions.
        let mut scratch = ValueIndex::default();
        let index = if entry.values.len() >= 32 {
            self.indexes.entry((span.offset, end)).or_default()
        } else {
            &mut scratch
        };
        let omitted = self.omitted.entry((span.offset, end)).or_default();
        observe(entry, index, omitted, Cow::Owned(value), 1, false);
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
                let mut scratch = ValueIndex::default();
                let index = if target.values.len() >= 32 {
                    self.indexes
                        .entry((entry.span.offset, entry.end))
                        .or_default()
                } else {
                    &mut scratch
                };
                let omitted = self
                    .omitted
                    .entry((entry.span.offset, entry.end))
                    .or_default();
                observe(target, index, omitted, Cow::Borrowed(value), *count, true);
            }
        }
        for (key, count) in &other.omitted {
            let omitted = self.omitted.entry(*key).or_default();
            *omitted = omitted.saturating_add(*count);
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

    /// How many observations of the expression at `span ..= end` were counted but not kept,
    /// because it already held [`COVERAGE_VALUES_PER_EXPRESSION`] distinct values.
    #[must_use]
    pub fn omitted_at(&self, span: Span, end: usize) -> u64 {
        self.omitted.get(&(span.offset, end)).copied().unwrap_or(0)
    }

    /// The values recorded for one extent, if any.
    #[must_use]
    fn values_at(&self, span: Span, end: usize) -> Option<&[(ExprValue, u64)]> {
        self.entries
            .get(&(span.offset, end))
            .map(|e| e.values.as_slice())
    }
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

impl Coverage {
    fn statistics(&self) -> (u64, u64, u64, u64) {
        let mut distinct = 0u64;
        let mut observations = 0u64;
        let mut bytes = count(self.entries.len())
            .saturating_mul(count(std::mem::size_of::<((usize, usize), CoverageEntry)>()));
        for entry in self.entries.values() {
            distinct = distinct.saturating_add(count(entry.values.len()));
            bytes = bytes.saturating_add(
                count(entry.values.capacity())
                    .saturating_mul(count(std::mem::size_of::<(ExprValue, u64)>())),
            );
            for (value, seen) in &entry.values {
                observations = observations.saturating_add(*seen);
                bytes = bytes.saturating_add(match value {
                    ExprValue::String(value) => count(value.capacity()),
                    ExprValue::Undefined(cause) => count(cause.message.capacity()),
                    _ => 0,
                });
            }
        }
        for omitted in self.omitted.values() {
            observations = observations.saturating_add(*omitted);
        }
        bytes = bytes.saturating_add(
            count(self.omitted.len())
                .saturating_mul(count(std::mem::size_of::<((usize, usize), u64)>())),
        );
        bytes = bytes.saturating_add(
            count(self.indexes.len())
                .saturating_mul(count(std::mem::size_of::<((usize, usize), ValueIndex)>())),
        );
        for index in self.indexes.values() {
            bytes = bytes.saturating_add(
                count(index.buckets.capacity())
                    .saturating_mul(count(std::mem::size_of::<(u64, Vec<usize>)>())),
            );
            for positions in index.buckets.values() {
                bytes = bytes.saturating_add(
                    count(positions.capacity()).saturating_mul(count(std::mem::size_of::<usize>())),
                );
            }
        }
        (count(self.entries.len()), distinct, observations, bytes)
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
    /// Observations of further distinct values that were counted but not kept (see
    /// [`COVERAGE_VALUES_PER_EXPRESSION`]).
    pub omitted: u64,
    /// Sub-expressions, in source order.
    pub children: Vec<CoverageNode>,
}

impl CoverageNode {
    /// Every evaluation of the expression: the kept values' counts plus the omitted ones.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.values
            .iter()
            .fold(self.omitted, |total, (_, seen)| total.saturating_add(*seen))
    }
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

/// The `allow` conditions `coverage` (one request's) evaluated, in source order, with the values
/// each took: the conditions a denial diagnostic names. A function body is not among them; the
/// condition that called it is.
#[must_use]
pub fn decided_conditions(ruleset: &Ruleset, coverage: &Coverage) -> Vec<CoverageEntry> {
    let mut decided = Vec::new();
    let mut items: Vec<&Item> = ruleset.services.iter().flat_map(|s| &s.items).collect();
    while let Some(item) = items.pop() {
        if let Item::Match(m) = item {
            items.extend(&m.items);
            for condition in m.allows.iter().filter_map(|a: &Allow| a.condition.as_ref()) {
                if let Some(values) = coverage.values_at(condition.span, condition.end) {
                    decided.push(CoverageEntry {
                        span: condition.span,
                        end: condition.end,
                        values: values.to_vec(),
                    });
                }
            }
        }
    }
    decided.sort_by_key(|entry| (entry.span.offset, entry.end));
    decided
}

fn node(expr: &Expr, coverage: &Coverage) -> CoverageNode {
    CoverageNode {
        span: expr.span,
        end: expr.end,
        values: coverage
            .values_at(expr.span, expr.end)
            .map(<[(ExprValue, u64)]>::to_vec)
            .unwrap_or_default(),
        omitted: coverage.omitted_at(expr.span, expr.end),
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
    interval_epoch: u64,
    coverage: Coverage,
    requests: VecDeque<RequestTrace>,
    next_sequence: u64,
    request_traces_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DiagnosticsStatistics {
    pub(crate) interval_epoch: u64,
    pub(crate) expression_count: u64,
    pub(crate) distinct_value_count: u64,
    pub(crate) observation_count: u64,
    pub(crate) estimated_coverage_bytes: u64,
    pub(crate) request_trace_count: u64,
    pub(crate) request_trace_capacity: u64,
    pub(crate) request_traces_enabled: bool,
}

impl RulesDiagnostics {
    pub(crate) const fn interval_epoch(&self) -> u64 {
        self.interval_epoch
    }

    pub(crate) fn statistics(&self) -> DiagnosticsStatistics {
        let (expression_count, distinct_value_count, observation_count, estimated_coverage_bytes) =
            self.coverage.statistics();
        DiagnosticsStatistics {
            interval_epoch: self.interval_epoch,
            expression_count,
            distinct_value_count,
            observation_count,
            estimated_coverage_bytes,
            request_trace_count: count(self.requests.len()),
            request_trace_capacity: count(REQUEST_TRACE_CAPACITY),
            request_traces_enabled: self.request_traces_enabled,
        }
    }

    /// Starts an explicit diagnostic interval; exhaustion leaves every observation intact.
    pub(crate) fn reset_interval(&mut self) -> Option<u64> {
        let next = self.interval_epoch.checked_add(1)?;
        self.clear();
        self.interval_epoch = next;
        Some(next)
    }

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

#[cfg(test)]
mod index_tests {
    use super::*;

    /// The reference the indexed path must agree with: a linear scan, bounded the same way.
    fn linear_record(values: &mut Vec<(ExprValue, u64)>, value: ExprValue, count: u64) {
        if let Some((_, seen)) = values.iter_mut().find(|(seen, _)| *seen == value) {
            *seen = seen.saturating_add(count);
        } else if values.len() < COVERAGE_VALUES_PER_EXPRESSION {
            values.push((value, count));
        }
    }

    #[test]
    fn high_cardinality_coverage_uses_exact_index_and_preserves_order() {
        let mut coverage = Coverage::default();
        let mut expected = Vec::new();
        for value in (0..1000).chain(0..1000) {
            let value = ExprValue::String(format!("uid-{value}"));
            linear_record(&mut expected, value.clone(), 1);
            coverage.record(Span::default(), 1, value);
        }
        assert_eq!(coverage.entries()[0].values, expected);
        assert!(coverage.indexes[&(0, 1)].comparisons < 3000);
        let mut cloned = coverage.clone();
        cloned.merge(&coverage);
        for (_, count) in &mut expected {
            *count *= 2;
        }
        assert_eq!(cloned.entries()[0].values, expected);
        assert!(Coverage::default().is_empty());
    }

    #[test]
    fn coverage_fingerprint_collisions_are_resolved_by_exact_equality() {
        let values = vec![
            (ExprValue::String("first".into()), 1),
            (ExprValue::String("second".into()), 2),
        ];
        let mut index = ValueIndex::default();
        index.buckets.insert(7, vec![0, 1]);
        assert_eq!(
            index.find(&values, &ExprValue::String("second".into()), 7),
            Some(1)
        );
        assert_eq!(
            index.find(&values, &ExprValue::String("third".into()), 7),
            None
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(256))]
        #[test]
        fn indexed_record_merge_agrees_with_linear_reference(steps in proptest::collection::vec((0u8..8, -60i16..60), 0..400)) {
            let mut coverage = Coverage::default();
            let mut expected = Vec::new();
            for chunk in steps.chunks(13) {
                let mut part = Coverage::default();
                for &(kind, number) in chunk {
                    let value = match kind {
                        0 => ExprValue::Null,
                        1 => ExprValue::Bool(number % 2 == 0),
                        2 => ExprValue::Int(i64::from(number)),
                        3 => ExprValue::Float(f64::from(number)),
                        4 => ExprValue::Float(if number % 2 == 0 { 0.0 } else { -0.0 }),
                        5 => ExprValue::Undefined(UndefinedCause { span: Span { offset: usize::from(number.unsigned_abs()), ..Span::default() }, end: 7, message: format!("error-{number}") }),
                        6 => ExprValue::Composite("map"),
                        _ => ExprValue::String(number.to_string()),
                    };
                    linear_record(&mut expected, value.clone(), 1);
                    part.record(Span::default(), 1, value);
                }
                coverage.merge(&part);
                proptest::prop_assert_eq!(&coverage.entries()[0].values, &expected);
            }
        }
    }

    #[test]
    fn coverage_float_fallback_retains_nan_and_signed_zero_semantics() {
        let mut coverage = Coverage::default();
        for number in 0..40 {
            coverage.record(Span::default(), 1, ExprValue::Int(number));
        }
        for value in [0.0, -0.0, f64::NAN, f64::NAN] {
            coverage.record(Span::default(), 1, ExprValue::Float(value));
        }
        let values = &coverage.entries()[0].values;
        assert_eq!(values.len(), 43);
        assert_eq!(values[40], (ExprValue::Float(0.0), 2));
        assert!(matches!(values[41], (ExprValue::Float(value), 1) if value.is_nan()));
        let cause = |message: &str| {
            ExprValue::Undefined(UndefinedCause {
                span: Span::default(),
                end: 1,
                message: message.into(),
            })
        };
        for value in [cause("first"), cause("second"), cause("first")] {
            coverage.record(Span::default(), 1, value);
        }
        assert_eq!(coverage.entries()[0].values[43].1, 2);
        assert_eq!(coverage.entries()[0].values[44].1, 1);
    }
    #[test]
    fn indexed_merge_saturates_counts_and_preserves_first_extent_span() {
        let span = Span {
            line: 1,
            column: 2,
            offset: 0,
        };
        let mut coverage = Coverage::default();
        for i in 0..40 {
            coverage.record(span, 1, ExprValue::Int(i));
        }
        coverage.entries.get_mut(&(0, 1)).unwrap().values[0].1 = u64::MAX - 1;
        let mut other = Coverage::default();
        other.record(
            Span {
                line: 9,
                column: 9,
                offset: 0,
            },
            1,
            ExprValue::Int(0),
        );
        other.record(Span::default(), 1, ExprValue::Int(0));
        coverage.merge(&other);
        assert_eq!(coverage.entries()[0].span, span);
        assert_eq!(coverage.entries()[0].values[0].1, u64::MAX);
    }

    #[test]
    #[ignore = "bounded release coverage measurement"]
    fn bounded_high_cardinality_coverage_measurement() {
        for size in [1usize, 1000, 10_000, 100_000] {
            for repetition in 0..3 {
                let mut coverage = Coverage::default();
                let start = std::time::Instant::now();
                for i in 0..size {
                    coverage.record(Span::default(), 1, ExprValue::String(format!("uid-{i}")));
                }
                let record_elapsed = start.elapsed();
                let start = std::time::Instant::now();
                let snapshot = coverage.clone();
                coverage.merge(&snapshot);
                let merge_elapsed = start.elapsed();
                assert_eq!(
                    coverage.entries()[0].values.len(),
                    size.min(COVERAGE_VALUES_PER_EXPRESSION)
                );
                assert!(coverage.entries()[0]
                    .values
                    .iter()
                    .all(|(_, count)| *count == 2));
                let values = &coverage.entries()[0].values;
                let vec_bytes = values.capacity() * std::mem::size_of::<(ExprValue, u64)>()
                    + values
                        .iter()
                        .map(|(value, _)| match value {
                            ExprValue::String(value) => value.capacity(),
                            _ => 0,
                        })
                        .sum::<usize>();
                let index_capacity: usize = coverage
                    .indexes
                    .values()
                    .map(|index| index.buckets.capacity())
                    .sum();
                let index_positions: usize = coverage
                    .indexes
                    .values()
                    .flat_map(|index| index.buckets.values())
                    .map(Vec::capacity)
                    .sum();
                let estimated = coverage.statistics().3;
                println!("coverage size={size} repetition={repetition} estimated_coverage_bytes={estimated} record={record_elapsed:?} clone_merge={merge_elapsed:?} report_retained_bytes={vec_bytes} index_bucket_capacity={index_capacity} index_position_capacity={index_positions}");
            }
        }
    }
    #[test]
    fn diagnostic_interval_statistics_and_reset_release_the_auxiliary_index() {
        let mut diagnostics = RulesDiagnostics::default();
        let mut coverage = Coverage::default();
        for i in 0..1000 {
            coverage.record(Span::default(), 1, ExprValue::String(format!("uid-{i}")));
        }
        diagnostics.merge_coverage(&coverage);
        diagnostics.merge_coverage(&coverage);
        let stats = diagnostics.statistics();
        assert_eq!(
            (
                stats.expression_count,
                stats.distinct_value_count,
                stats.observation_count
            ),
            (1, count(COVERAGE_VALUES_PER_EXPRESSION), 2000)
        );
        assert!(stats.estimated_coverage_bytes > 1000);
        assert!(!diagnostics.coverage.indexes.is_empty());
        assert_eq!(diagnostics.reset_interval(), Some(1));
        let empty = diagnostics.statistics();
        assert_eq!(
            (
                empty.expression_count,
                empty.distinct_value_count,
                empty.observation_count,
                empty.estimated_coverage_bytes
            ),
            (0, 0, 0, 0)
        );
        assert!(diagnostics.coverage.indexes.is_empty());
        diagnostics.interval_epoch = u64::MAX;
        diagnostics.merge_coverage(&coverage);
        let before = diagnostics.statistics();
        assert_eq!(diagnostics.reset_interval(), None);
        assert_eq!(diagnostics.statistics(), before);
    }
    #[test]
    fn interval_exhaustion_refuses_the_public_clear_without_data_loss() {
        let mut diagnostics = RulesDiagnostics {
            interval_epoch: u64::MAX,
            ..RulesDiagnostics::default()
        };
        diagnostics
            .coverage
            .record(Span::default(), 1, ExprValue::Int(1));
        let loaded = crate::runtime::LoadedRules {
            diagnostics: std::sync::Arc::new(std::sync::Mutex::new(diagnostics)),
            ..crate::runtime::LoadedRules::default()
        };
        let slot = crate::runtime::RulesetSlot::new(loaded);
        let before = slot.diagnostics_snapshot().unwrap();
        assert_eq!(
            slot.clear_diagnostics(0, u64::MAX),
            Err(crate::runtime::RulesDiagnosticsError::IntervalExhausted)
        );
        assert_eq!(slot.diagnostics_snapshot().unwrap(), before);
    }

    #[test]
    #[ignore = "bounded release diagnostic reset/index retention measurement"]
    fn bounded_diagnostic_reset_releases_index_and_value_storage() {
        for size in [1usize, 1000, 100_000] {
            let slot = crate::runtime::RulesetSlot::default();
            let snapshot = slot.snapshot().unwrap();
            {
                let mut diagnostics = snapshot.diagnostics.lock().unwrap();
                for i in 0..size {
                    diagnostics.coverage.record(
                        Span::default(),
                        1,
                        ExprValue::String(format!("uid-{i}")),
                    );
                }
                assert_eq!(!diagnostics.coverage.indexes.is_empty(), size >= 32);
            }
            let before = slot.diagnostics_snapshot().unwrap();
            assert_eq!(
                (before.distinct_value_count, before.observation_count),
                (count(size.min(COVERAGE_VALUES_PER_EXPRESSION)), count(size))
            );
            let start = std::time::Instant::now();
            let after = slot.clear_diagnostics(0, 0).unwrap();
            let elapsed = start.elapsed();
            assert_eq!(
                (
                    after.interval_epoch,
                    after.expression_count,
                    after.distinct_value_count,
                    after.observation_count,
                    after.estimated_coverage_bytes
                ),
                (1, 0, 0, 0, 0)
            );
            let diagnostics = snapshot.diagnostics.lock().unwrap();
            assert!(diagnostics.coverage.entries.is_empty());
            assert!(diagnostics.coverage.indexes.is_empty());
            println!("diagnostics_reset size={size} estimated_before={} estimated_after={} elapsed={elapsed:?}", before.estimated_coverage_bytes, after.estimated_coverage_bytes);
        }
    }
    #[test]
    fn diagnostic_observation_totals_saturate_without_merging_distinct_variants() {
        let mut diagnostics = RulesDiagnostics::default();
        diagnostics
            .coverage
            .record(Span::default(), 1, ExprValue::Int(1));
        diagnostics
            .coverage
            .record(Span::default(), 1, ExprValue::Float(1.0));
        diagnostics
            .coverage
            .entries
            .get_mut(&(0, 1))
            .unwrap()
            .values[0]
            .1 = u64::MAX;
        let stats = diagnostics.statistics();
        assert_eq!(
            (
                stats.expression_count,
                stats.distinct_value_count,
                stats.observation_count
            ),
            (1, 2, u64::MAX)
        );
    }
    #[test]
    fn diagnostic_byte_estimate_includes_the_auxiliary_index_payload() {
        let mut coverage = Coverage::default();
        for i in 0..1000 {
            coverage.record(Span::default(), 1, ExprValue::String(format!("uid-{i}")));
        }
        let indexed = coverage.statistics().3;
        let positions: usize = coverage
            .indexes
            .values()
            .flat_map(|index| index.buckets.values())
            .map(Vec::capacity)
            .sum();
        let mut without_index = coverage.clone();
        without_index.indexes.clear();
        assert_eq!(coverage, without_index);
        assert!(
            indexed
                >= without_index.statistics().3.saturating_add(
                    count(positions).saturating_mul(count(std::mem::size_of::<usize>()))
                )
        );
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;
    use crate::eval::{evaluate_request_traced, Decision, Method, RequestContext, RulesService};
    use crate::parse::parse_ruleset;

    const LIMIT: usize = COVERAGE_VALUES_PER_EXPRESSION;
    const BYTES: usize = COVERAGE_STRING_BYTES_PER_VALUE;

    const RULES: &str = "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /notes/{id} {\n      allow get: if id != 'secret';\n    }\n  }\n}\n";

    fn get(id: &str) -> RequestContext {
        RequestContext {
            service: RulesService::Firestore,
            method: Method::Get,
            path: format!("/databases/(default)/documents/notes/{id}"),
            auth: None,
            resource: None,
            request_resource: None,
            time_unix_nanos: 1_788_004_860_i128 * 1_000_000_000,
            abstract_path: false,
            request_query: None,
        }
    }

    fn find(nodes: &[CoverageNode], offset: usize, end: usize) -> Option<&CoverageNode> {
        nodes.iter().find_map(|node| {
            if node.span.offset == offset && node.end == end {
                Some(node)
            } else {
                find(&node.children, offset, end)
            }
        })
    }

    fn string(index: usize) -> ExprValue {
        ExprValue::String(format!("uid-{index}"))
    }

    #[test]
    fn ten_thousand_distinct_ids_keep_the_limit_and_count_the_rest() {
        let ruleset = parse_ruleset(RULES).unwrap();
        let mut diagnostics = RulesDiagnostics::default();
        for index in 0..10_000 {
            let (decided, one) =
                evaluate_request_traced(&ruleset, &get(&format!("doc-{index}")), None);
            assert!(matches!(decided.decision, Decision::Allow), "{index}");
            diagnostics.merge_coverage(&one);
        }
        // Coverage is a diagnostic: the decision past the bound is the decision before it.
        let (decided, one) = evaluate_request_traced(&ruleset, &get("secret"), None);
        assert!(!matches!(decided.decision, Decision::Allow));
        diagnostics.merge_coverage(&one);

        let nodes = report(&ruleset, diagnostics.coverage());
        let id_at = RULES.find("id != 'secret'").unwrap();
        let id = find(&nodes, id_at, id_at + 2).expect("the `id` operand is in the report");
        assert_eq!(id.values.len(), LIMIT);
        assert_eq!(id.values[0], (ExprValue::String("doc-0".into()), 1));
        assert_eq!(id.omitted, 10_001 - 64);
        assert_eq!(id.total(), 10_001);
        // The condition took two values only, so nothing of it is omitted.
        let condition = find(&nodes, id_at, id_at + "id != 'secret'".len()).unwrap();
        assert_eq!(
            condition.values,
            vec![(ExprValue::Bool(true), 10_000), (ExprValue::Bool(false), 1)]
        );
        assert_eq!((condition.omitted, condition.total()), (0, 10_001));

        let stats = diagnostics.statistics();
        assert!(stats.distinct_value_count <= 3 * 64, "{stats:?}");
        // Every evaluation is still counted: `id`, the literal and the condition each 10,001.
        assert_eq!(stats.observation_count, 3 * 10_001, "{stats:?}");
    }

    #[test]
    fn exactly_the_limit_is_kept_and_one_beyond_is_only_counted() {
        let mut coverage = Coverage::default();
        for index in 0..LIMIT {
            coverage.record(Span::default(), 1, string(index));
        }
        assert_eq!(coverage.entries()[0].values.len(), LIMIT);
        assert_eq!(coverage.omitted_at(Span::default(), 1), 0);

        coverage.record(Span::default(), 1, string(LIMIT));
        assert_eq!(coverage.entries()[0].values.len(), LIMIT);
        assert_eq!(coverage.omitted_at(Span::default(), 1), 1);
        assert!(!coverage.entries()[0]
            .values
            .iter()
            .any(|(value, _)| *value == string(LIMIT)));

        // A kept value still accumulates exactly; the omitted one stays omitted.
        coverage.record(Span::default(), 1, string(0));
        coverage.record(Span::default(), 1, string(LIMIT));
        assert_eq!(coverage.entries()[0].values[0], (string(0), 2));
        assert_eq!(coverage.omitted_at(Span::default(), 1), 2);
        // An unrelated extent has its own bound.
        assert_eq!(coverage.omitted_at(Span::default(), 2), 0);
    }

    #[test]
    fn merge_carries_omitted_counts_and_bounds_the_union() {
        let mut first = Coverage::default();
        let mut second = Coverage::default();
        for index in 0..LIMIT + 10 {
            first.record(Span::default(), 1, string(index));
            second.record(Span::default(), 1, string(index + 1000));
        }
        let mut merged = first.clone();
        merged.merge(&second);
        assert_eq!(merged.entries()[0].values, first.entries()[0].values);
        // first omitted 10, second kept 64 that no longer fit and omitted 10.
        assert_eq!(merged.omitted_at(Span::default(), 1), 10 + 64 + 10);
        assert_eq!(merged.statistics().2, 2 * count(LIMIT + 10));
    }

    #[test]
    fn coverages_that_differ_only_in_what_they_omitted_are_unequal() {
        let mut first = Coverage::default();
        for index in 0..=LIMIT {
            first.record(Span::default(), 1, string(index));
        }
        let mut second = first.clone();
        assert_eq!(first, second);
        // Same kept values, one more omitted observation.
        second.record(Span::default(), 1, string(LIMIT + 1));
        assert_eq!(first.entries(), second.entries());
        assert_ne!(first, second);
        // Same omitted counts, different kept values.
        let mut third = Coverage::default();
        for index in 1..=LIMIT + 1 {
            third.record(Span::default(), 1, string(index));
        }
        assert_eq!(
            third.omitted_at(Span::default(), 1),
            first.omitted_at(Span::default(), 1)
        );
        assert_ne!(first, third);
    }

    #[test]
    fn a_long_string_is_cut_on_a_character_boundary() {
        // `a` then two-byte characters: byte `BYTES` falls inside a character.
        let long = format!("a{}", "é".repeat(BYTES));
        assert!(!long.is_char_boundary(BYTES));
        let mut coverage = Coverage::default();
        coverage.record(Span::default(), 1, ExprValue::String(long.clone()));
        let ExprValue::String(kept) = &coverage.entries()[0].values[0].0 else {
            panic!("a string value");
        };
        assert_eq!(kept.len(), BYTES - 1);
        assert!(long.starts_with(kept.as_str()));

        // Exactly the limit is kept whole; one byte more is cut to it.
        let exact = "x".repeat(BYTES);
        let beyond = "y".repeat(BYTES + 1);
        coverage.record(Span::default(), 2, ExprValue::String(exact.clone()));
        coverage.record(Span::default(), 2, ExprValue::String(beyond));
        assert_eq!(
            coverage.entries()[1].values,
            vec![
                (ExprValue::String(exact), 1),
                (ExprValue::String("y".repeat(BYTES)), 1)
            ]
        );

        // Values that agree on the kept prefix are one value, counted together.
        coverage.record(Span::default(), 2, ExprValue::String("y".repeat(BYTES + 9)));
        assert_eq!(coverage.entries()[1].values[1].1, 2);

        // An undefined cause's message is cut the same way.
        let message = format!("no field {}", "ü".repeat(BYTES));
        coverage.record(
            Span::default(),
            3,
            ExprValue::Undefined(UndefinedCause {
                span: Span::default(),
                end: 3,
                message: message.clone(),
            }),
        );
        let ExprValue::Undefined(cause) = &coverage.entries()[2].values[0].0 else {
            panic!("an undefined value");
        };
        assert!(cause.message.len() <= BYTES && cause.message.len() > BYTES - 4);
        assert!(message.starts_with(cause.message.as_str()));
        // `ExprValue::of` does not copy more than it keeps either.
        let ExprValue::String(of) = ExprValue::of(&RulesValue::String(long.clone())) else {
            panic!("a string value");
        };
        assert_eq!(of.len(), BYTES - 1);
    }

    fn observation(kind: u8, number: u8) -> ExprValue {
        match kind {
            0 => ExprValue::Int(i64::from(number)),
            1 => ExprValue::Bool(number % 2 == 0),
            _ => ExprValue::String(format!("v{number}")),
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(256))]
        /// Recording in parts and merging the parts in any order gives every expression the
        /// same total and keeps `min(distinct, limit)` values. A kept count never exceeds the
        /// value's true count; it can be lower only when another part had to omit that value,
        /// and those observations are in the omitted count, so kept plus omitted is exact.
        #[test]
        fn merging_parts_in_any_order_gives_the_same_counts(
            steps in proptest::collection::vec((0usize..3, 0u8..3, 0u8..120), 0..600),
            parts in 1usize..8,
            order in proptest::collection::vec(proptest::num::usize::ANY, 0..8),
        ) {
            let mut reference: BTreeMap<usize, Vec<(ExprValue, u64)>> = BTreeMap::new();
            let mut pieces = vec![Coverage::default(); parts];
            for (position, &(expr, kind, number)) in steps.iter().enumerate() {
                let value = observation(kind, number);
                let values = reference.entry(expr).or_default();
                match values.iter_mut().find(|(seen, _)| *seen == value) {
                    Some((_, seen)) => *seen += 1,
                    None => values.push((value.clone(), 1)),
                }
                pieces[position % parts].record(Span { offset: expr, ..Span::default() }, expr + 1, value);
            }
            let mut permutation: Vec<usize> = (0..parts).collect();
            for (index, pick) in order.iter().enumerate().take(parts) {
                permutation.swap(index, index + pick % (parts - index));
            }
            let mut forward = Coverage::default();
            for piece in &pieces {
                forward.merge(piece);
            }
            let mut permuted = Coverage::default();
            for &index in &permutation {
                permuted.merge(&pieces[index]);
            }
            for merged in [&forward, &permuted] {
                for (&expr, values) in &reference {
                    let span = Span { offset: expr, ..Span::default() };
                    let kept = merged.values_at(span, expr + 1).unwrap();
                    let total: u64 = values.iter().map(|(_, seen)| seen).sum();
                    let kept_sum: u64 = kept.iter().map(|(_, seen)| seen).sum();
                    proptest::prop_assert_eq!(kept_sum + merged.omitted_at(span, expr + 1), total);
                    proptest::prop_assert_eq!(kept.len(), values.len().min(LIMIT));
                    for (value, seen) in kept {
                        let exact = values.iter().find(|(v, _)| v == value).map(|(_, c)| *c);
                        proptest::prop_assert!(exact.is_some_and(|exact| *seen <= exact));
                    }
                }
                proptest::prop_assert_eq!(merged.statistics().2, count(steps.len()));
            }
            // Below the bound nothing depends on the order but the listing order.
            for (&expr, values) in &reference {
                if values.len() <= LIMIT {
                    let span = Span { offset: expr, ..Span::default() };
                    let mut a = forward.values_at(span, expr + 1).unwrap().to_vec();
                    let mut b = permuted.values_at(span, expr + 1).unwrap().to_vec();
                    let key = |entry: &(ExprValue, u64)| format!("{entry:?}");
                    a.sort_by_key(key);
                    b.sort_by_key(key);
                    proptest::prop_assert_eq!(a, b);
                }
            }
        }
    }
}
