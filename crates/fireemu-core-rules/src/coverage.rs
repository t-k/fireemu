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
#[derive(Debug, Clone, Default)]
pub struct Coverage {
    entries: BTreeMap<(usize, usize), CoverageEntry>,
    indexes: BTreeMap<(usize, usize), ValueIndex>,
}

impl PartialEq for Coverage {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
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

fn observe(
    entry: &mut CoverageEntry,
    index: &mut ValueIndex,
    value: Cow<'_, ExprValue>,
    count: u64,
    merge: bool,
) {
    const INDEX_THRESHOLD: usize = 32;
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
        observe(entry, index, Cow::Owned(value), 1, false);
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
                observe(target, index, Cow::Borrowed(value), *count, true);
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

    fn linear_record(values: &mut Vec<(ExprValue, u64)>, value: ExprValue, count: u64) {
        if let Some((_, seen)) = values.iter_mut().find(|(seen, _)| *seen == value) {
            *seen = seen.saturating_add(count);
        } else {
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
        for size in [1usize, 1000, 100_000] {
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
                assert_eq!(coverage.entries()[0].values.len(), size);
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
                println!("coverage size={size} repetition={repetition} record={record_elapsed:?} clone_merge={merge_elapsed:?} report_retained_bytes={vec_bytes} index_bucket_capacity={index_capacity} index_position_capacity={index_positions}");
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
            (1, 1000, 2000)
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
                (count(size), count(size))
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
