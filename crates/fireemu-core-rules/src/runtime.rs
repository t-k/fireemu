//! Loaded ruleset shared between adapters (hot-reloadable through the control API).

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, Mutex, RwLock};

use crate::ast::{Item, PathSegment, Ruleset, Span};
use crate::coverage::RulesDiagnostics;
use crate::lint::{lint_parsed, DiagnosticLevel, LintOptions};
use crate::parse::{parse_ruleset, ParseError};

/// The currently loaded rules: source text plus its parsed form. `None` means no rules are
/// configured; adapters then allow every request (the runtime prints a warning at start).
///
/// The diagnostics travel with the ruleset rather than beside it, because every position
/// they hold is an offset into *this* source. Replacing the slot therefore replaces the
/// coverage and the request traces too, which is the only correct behaviour and needs no
/// separate reset.
#[derive(Debug, Default)]
pub struct LoadedRules {
    /// Source text as loaded.
    pub source: Option<String>,
    /// Shared immutable parsed ruleset.
    pub ruleset: Option<Arc<Ruleset>>,
    /// Coverage and request traces recorded against this ruleset (`RULES-PARITY-04`).
    pub diagnostics: Arc<Mutex<RulesDiagnostics>>,
}

/// Two loaded rulesets are the same when they hold the same source and the same tree; what
/// has been observed about them is not part of their identity.
impl PartialEq for LoadedRules {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.ruleset == other.ruleset
    }
}

/// A clone is a separate ruleset -- a snapshot, or a copy handed to another surface -- and
/// starts with nothing observed, so a restored snapshot never inherits another run's
/// coverage.
impl Clone for LoadedRules {
    fn clone(&self) -> Self {
        Self {
            source: self.source.clone(),
            ruleset: self.ruleset.clone(),
            diagnostics: Arc::new(Mutex::new(RulesDiagnostics::default())),
        }
    }
}

impl LoadedRules {
    /// A conservative, saturating estimate of heap bytes retained by a snapshot.
    ///
    /// The parsed tree is linear in the accepted source. Multiplying the source allocation
    /// by 32 deliberately over-counts node, vector and compiled-regex allocations so the
    /// admission budget fails on the safe side without walking the full tree on every capture.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        self.source.as_ref().map_or(0, |source| {
            u64::try_from(source.capacity())
                .unwrap_or(u64::MAX)
                .saturating_mul(32)
        })
    }

    /// Parses `source` and returns the loaded rules.
    ///
    /// Two call-graph rules are compile errors rather than runtime ones, which is where the
    /// official compiler puts them: a recursive or cyclical call, and a call chain deeper
    /// than the catalog's maximum. Both were measured against the pinned emulator
    /// (`conformance/rules-programs.json`, `recursion-self-call` and
    /// `recursion-depth-chain-21-calls`), and the messages are its messages.
    pub fn from_source(source: &str) -> Result<Self, ParseError> {
        let ruleset = parse_ruleset(source)?;
        validate_ruleset(&ruleset)?;
        let (diagnostics, _) = lint_parsed(source, &ruleset, &LintOptions::default());
        for diagnostic in &diagnostics {
            if diagnostic.level != DiagnosticLevel::Error {
                continue;
            }
            let message = match diagnostic.limit_id {
                "RULES-RECURSION" => "Recursive call is not allowed.".to_owned(),
                "RULES-FUNCTION-CALL-DEPTH" => format!(
                    "Maximum allowed call depth of {} is reached for [{}]",
                    diagnostic.maximum,
                    diagnostic.subject.as_deref().unwrap_or("the call chain")
                ),
                _ => format!("{}: {}", diagnostic.limit_id, diagnostic.message),
            };
            let span = diagnostic.span.unwrap_or_default();
            return Err(ParseError {
                message,
                line: span.line.max(1),
                column: span.column.max(1),
                offset: span.offset,
            });
        }
        Ok(Self {
            source: Some(source.to_owned()),
            ruleset: Some(Arc::new(ruleset)),
            diagnostics: Arc::new(Mutex::new(RulesDiagnostics::default())),
        })
    }

    /// Whether rules are configured.
    #[must_use]
    pub const fn is_loaded(&self) -> bool {
        self.ruleset.is_some()
    }
}

/// Startup-scoped compilation reuse by exact source, with fresh diagnostics for every load.
#[derive(Default)]
pub struct RulesCompilationCache {
    compiled: HashMap<String, LoadedRules>,
    #[cfg(test)]
    compilations: usize,
}

impl RulesCompilationCache {
    /// Compiles a source once while this cache lives, sharing only its immutable parsed tree.
    pub fn load(&mut self, source: &str) -> Result<LoadedRules, ParseError> {
        if let Some(loaded) = self.compiled.get(source) {
            return Ok(loaded.clone());
        }
        #[cfg(test)]
        {
            self.compilations += 1;
        }
        let loaded = LoadedRules::from_source(source)?;
        self.compiled.insert(source.to_owned(), loaded.clone());
        Ok(loaded)
    }
}

fn validation_error(span: Span, message: impl Into<String>) -> ParseError {
    ParseError {
        message: message.into(),
        line: span.line.max(1),
        column: span.column.max(1),
        offset: span.offset,
    }
}

fn validate_ruleset(ruleset: &Ruleset) -> Result<(), ParseError> {
    if let Some(version) = ruleset.version.as_deref() {
        if !matches!(version, "1" | "2") {
            return Err(validation_error(
                Span::default(),
                format!("unsupported rules_version `{version}`"),
            ));
        }
    }
    let version = ruleset.version.as_deref();
    for service in &ruleset.services {
        validate_items(&service.items, version)?;
    }
    Ok(())
}

fn validate_items(items: &[Item], version: Option<&str>) -> Result<(), ParseError> {
    for item in items {
        let Item::Match(block) = item else {
            continue;
        };
        let recursive = block
            .path
            .iter()
            .filter_map(|segment| match segment {
                PathSegment::RecursiveWildcard { span, .. } => Some(*span),
                _ => None,
            })
            .collect::<Vec<_>>();
        if let Some(span) = recursive.get(1) {
            return Err(validation_error(
                *span,
                "a match may contain at most one recursive wildcard",
            ));
        }
        if version != Some("2") {
            if let Some((_, span)) =
                block
                    .path
                    .iter()
                    .enumerate()
                    .find_map(|(index, segment)| match segment {
                        PathSegment::RecursiveWildcard { span, .. }
                            if index + 1 != block.path.len() =>
                        {
                            Some((index, *span))
                        }
                        _ => None,
                    })
            {
                return Err(validation_error(
                    span,
                    "in rules_version 1 a recursive wildcard must be the final path segment",
                ));
            }
        }
        validate_items(&block.items, version)?;
    }
    Ok(())
}

#[derive(Debug)]
struct ActiveRules {
    generation: u64,
    loaded: Arc<LoadedRules>,
}

/// One immutable ruleset generation retained by an admitted authorization evaluation.
#[derive(Clone, Debug)]
pub struct RulesetSnapshot(Arc<ActiveRules>);

impl RulesetSnapshot {
    /// Monotonic generation assigned at atomic publication.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.0.generation
    }

    /// The immutable loaded rules and generation-local diagnostics.
    #[must_use]
    pub fn loaded(&self) -> Arc<LoadedRules> {
        Arc::clone(&self.0.loaded)
    }
}

impl Deref for RulesetSnapshot {
    type Target = LoadedRules;

    fn deref(&self) -> &Self::Target {
        &self.0.loaded
    }
}

/// One atomic inspection of the active source generation and its explicit diagnostic interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulesDiagnosticsSnapshot {
    /// Whether the active source contains configured rules.
    pub loaded: bool,
    /// The authorization source generation; diagnostic clears do not change it.
    pub generation: u64,
    /// Explicit diagnostic interval within this source generation.
    pub interval_epoch: u64,
    /// Retained expression extents.
    pub expression_count: u64,
    /// Distinct retained value slots, including each non-reflexive NaN observation.
    pub distinct_value_count: u64,
    /// Saturating sum of the retained per-value observation counts.
    pub observation_count: u64,
    /// Estimated coverage payload and auxiliary index capacity bytes. Excludes source/AST, trace payloads, allocator/BTree/hash control metadata, mutex/Arc overhead and RSS.
    pub estimated_coverage_bytes: u64,
    /// Retained request traces.
    pub request_trace_count: u64,
    /// Maximum retained request traces.
    pub request_trace_capacity: u64,
    /// Whether subsequent decisions collect request traces.
    pub request_traces_enabled: bool,
}

impl RulesDiagnosticsSnapshot {
    fn from_diagnostics(active: &ActiveRules, diagnostics: &RulesDiagnostics) -> Self {
        let stats = diagnostics.statistics();
        Self {
            loaded: active.loaded.is_loaded(),
            generation: active.generation,
            interval_epoch: stats.interval_epoch,
            expression_count: stats.expression_count,
            distinct_value_count: stats.distinct_value_count,
            observation_count: stats.observation_count,
            estimated_coverage_bytes: stats.estimated_coverage_bytes,
            request_trace_count: stats.request_trace_count,
            request_trace_capacity: stats.request_trace_capacity,
            request_traces_enabled: stats.request_traces_enabled,
        }
    }
}

/// A guarded diagnostic inspection or explicit clear could not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesDiagnosticsError {
    /// A newer source generation is active.
    StaleGeneration {
        /// Generation supplied by the caller.
        expected: u64,
        /// Active generation.
        actual: u64,
    },
    /// The diagnostic interval has already changed.
    StaleInterval {
        /// Interval supplied by the caller.
        expected: u64,
        /// Active interval.
        actual: u64,
    },
    /// The next interval cannot be represented; nothing was cleared.
    IntervalExhausted,
    /// The source publication lock is poisoned.
    SlotPoisoned,
    /// The active generation's diagnostics lock is poisoned.
    DiagnosticsPoisoned,
}

impl std::fmt::Display for RulesDiagnosticsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StaleGeneration { expected, actual } => write!(
                f,
                "stale rules generation: expected {expected}, active {actual}"
            ),
            Self::StaleInterval { expected, actual } => write!(
                f,
                "stale diagnostic interval: expected {expected}, active {actual}"
            ),
            Self::IntervalExhausted => f.write_str("diagnostic interval is exhausted"),
            Self::SlotPoisoned => f.write_str("ruleset slot is poisoned"),
            Self::DiagnosticsPoisoned => f.write_str("rules diagnostics are poisoned"),
        }
    }
}

impl std::error::Error for RulesDiagnosticsError {}

/// Atomically published rulesets with immutable authorization-evaluation snapshots.
#[derive(Debug)]
pub struct RulesetSlot {
    active: RwLock<Arc<ActiveRules>>,
}

impl RulesetSlot {
    /// Creates generation zero from the initial loaded rules.
    #[must_use]
    pub fn new(loaded: LoadedRules) -> Self {
        Self {
            active: RwLock::new(Arc::new(ActiveRules {
                generation: 0,
                loaded: Arc::new(loaded),
            })),
        }
    }

    /// Captures one immutable generation for a complete logical evaluation.
    pub fn snapshot(&self) -> Result<RulesetSnapshot, String> {
        self.active
            .read()
            .map(|active| RulesetSnapshot(Arc::clone(&active)))
            .map_err(|_| "ruleset slot is poisoned".to_owned())
    }

    /// Inspects one active source/interval atomically, retaining the source read guard through the diagnostics lock.
    pub fn diagnostics_snapshot(&self) -> Result<RulesDiagnosticsSnapshot, RulesDiagnosticsError> {
        let active = self
            .active
            .read()
            .map_err(|_| RulesDiagnosticsError::SlotPoisoned)?;
        let diagnostics = active
            .loaded
            .diagnostics
            .lock()
            .map_err(|_| RulesDiagnosticsError::DiagnosticsPoisoned)?;
        Ok(RulesDiagnosticsSnapshot::from_diagnostics(
            &active,
            &diagnostics,
        ))
    }

    /// Explicitly clears coverage, its auxiliary indexes and request traces while preserving tracing enablement and request sequence. Merges completed before this lock boundary are erased; merges completed afterwards belong to the new interval even if their evaluations started earlier.
    pub fn clear_diagnostics(
        &self,
        expected_generation: u64,
        expected_interval_epoch: u64,
    ) -> Result<RulesDiagnosticsSnapshot, RulesDiagnosticsError> {
        let active = self
            .active
            .read()
            .map_err(|_| RulesDiagnosticsError::SlotPoisoned)?;
        if active.generation != expected_generation {
            return Err(RulesDiagnosticsError::StaleGeneration {
                expected: expected_generation,
                actual: active.generation,
            });
        }
        let mut diagnostics = active
            .loaded
            .diagnostics
            .lock()
            .map_err(|_| RulesDiagnosticsError::DiagnosticsPoisoned)?;
        let actual = diagnostics.interval_epoch();
        if actual != expected_interval_epoch {
            return Err(RulesDiagnosticsError::StaleInterval {
                expected: expected_interval_epoch,
                actual,
            });
        }
        diagnostics
            .reset_interval()
            .ok_or(RulesDiagnosticsError::IntervalExhausted)?;
        Ok(RulesDiagnosticsSnapshot::from_diagnostics(
            &active,
            &diagnostics,
        ))
    }

    /// Publishes a fully checked candidate and returns its fresh generation.
    pub fn replace_loaded(&self, loaded: LoadedRules) -> Result<u64, String> {
        let mut active = self
            .active
            .write()
            .map_err(|_| "ruleset slot is poisoned".to_owned())?;
        let generation = active
            .generation
            .checked_add(1)
            .ok_or_else(|| "ruleset generation is exhausted".to_owned())?;
        *active = Arc::new(ActiveRules {
            generation,
            loaded: Arc::new(loaded),
        });
        Ok(generation)
    }

    /// Checks a source completely before publishing it.
    pub fn replace_source(&self, source: &str) -> Result<u64, String> {
        let loaded = LoadedRules::from_source(source).map_err(|error| error.to_string())?;
        self.replace_loaded(loaded)
    }

    /// Publishes an empty rules generation.
    pub fn clear(&self) -> Result<u64, String> {
        self.replace_loaded(LoadedRules::default())
    }
}

impl Default for RulesetSlot {
    fn default() -> Self {
        Self::new(LoadedRules::default())
    }
}

#[cfg(test)]
mod tests {
    use super::{LoadedRules, RulesetSlot};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::Arc;

    const V1: &str = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if false; } } }";
    const V2: &str = "service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read: if true; } } }";

    #[test]
    fn cloned_rules_keep_diagnostics_and_publications_independent() {
        let loaded = LoadedRules::from_source(V1).unwrap();
        let mut coverage = crate::coverage::Coverage::default();
        coverage.record(
            crate::ast::Span::default(),
            1,
            crate::coverage::ExprValue::Bool(false),
        );
        {
            let mut diagnostics = loaded.diagnostics.lock().unwrap();
            diagnostics.merge_coverage(&coverage);
            diagnostics.enable_request_traces();
        }
        let cloned = loaded.clone();
        assert_eq!(loaded, cloned);
        assert!(!Arc::ptr_eq(&loaded.diagnostics, &cloned.diagnostics));
        {
            let diagnostics = cloned.diagnostics.lock().unwrap();
            assert_eq!(
                diagnostics.coverage(),
                &crate::coverage::Coverage::default()
            );
            assert!(!diagnostics.request_traces_enabled());
        }
        let first = RulesetSlot::new(loaded);
        let second = RulesetSlot::new(cloned);
        assert_eq!(first.replace_source(V2).unwrap(), 1);
        let unchanged = second.snapshot().unwrap();
        assert_eq!(unchanged.source.as_deref(), Some(V1));
        assert_eq!(unchanged.generation(), 0);
    }

    #[test]
    fn cloned_rules_share_the_parsed_tree() {
        let loaded = LoadedRules::from_source(V1).unwrap();
        let cloned = loaded.clone();
        assert!(Arc::ptr_eq(
            loaded.ruleset.as_ref().unwrap(),
            cloned.ruleset.as_ref().unwrap(),
        ));
    }

    #[test]
    fn startup_cache_retains_one_compilation_for_identical_sources() {
        for count in [1, 4, 16] {
            let mut cache = super::RulesCompilationCache::default();
            let loaded: Vec<_> = (0..count).map(|_| cache.load(V1).unwrap()).collect();
            assert_eq!(cache.compiled.len(), 1);
            assert_eq!(cache.compilations, 1);
            for copy in &loaded {
                assert!(Arc::ptr_eq(
                    loaded[0].ruleset.as_ref().unwrap(),
                    copy.ruleset.as_ref().unwrap(),
                ));
            }
            if count > 1 {
                assert!(!Arc::ptr_eq(&loaded[0].diagnostics, &loaded[1].diagnostics));
            }
            let other = cache.load(V2).unwrap();
            assert_eq!(cache.compiled.len(), 2);
            assert_ne!(loaded[0], other);
            let whitespace = cache.load(&format!("{V1}\n")).unwrap();
            assert_eq!(cache.compiled.len(), 3);
            assert_eq!(cache.compilations, 3);
            assert_ne!(loaded[0], whitespace);
            drop(cache);
            assert_eq!(loaded[0].source.as_deref(), Some(V1));
        }
    }

    #[test]
    fn startup_cache_preserves_parse_validation_and_lint_errors() {
        let mut cache = super::RulesCompilationCache::default();
        cache.load(V1).unwrap();
        for source in [
            "invalid rules".to_owned(),
            format!("rules_version = '3'; {V1}"),
            "service cloud.firestore { function f() { return f(); } }".to_owned(),
        ] {
            assert_eq!(
                cache.load(&source).unwrap_err().to_string(),
                LoadedRules::from_source(&source).unwrap_err().to_string(),
            );
            assert_eq!(cache.compiled.len(), 1);
        }
    }

    #[test]
    fn generation_exhaustion_preserves_the_active_arc() {
        let slot = RulesetSlot::new(LoadedRules::from_source(V1).unwrap());
        {
            let mut active = slot.active.write().unwrap();
            *active = Arc::new(super::ActiveRules {
                generation: u64::MAX,
                loaded: active.loaded.clone(),
            });
        }
        let before = slot.snapshot().unwrap();

        let error = slot
            .replace_source(V2)
            .expect_err("generation must be exhausted");

        assert!(error.contains("exhausted"));
        let after = slot.snapshot().unwrap();
        assert_eq!(after.generation(), u64::MAX);
        assert_eq!(after.source.as_deref(), Some(V1));
        assert!(Arc::ptr_eq(&before.0, &after.0));
    }

    #[test]
    fn poisoned_slot_refuses_reads_and_publications() {
        let slot = RulesetSlot::new(LoadedRules::from_source(V1).unwrap());
        let retained = slot.snapshot().unwrap();
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _guard = slot.active.write().unwrap();
            panic!("poison ruleset slot for fail-closed coverage");
        }));
        assert!(poisoned.is_err());

        assert!(slot.snapshot().is_err());
        assert!(slot.replace_source(V2).is_err());
        assert_eq!(retained.source.as_deref(), Some(V1));
        assert_eq!(retained.generation(), 0);
    }

    #[test]
    fn source_and_parsed_tree_contribute_to_the_snapshot_estimate() {
        let empty = LoadedRules::default();
        let loaded = LoadedRules::from_source(V1).expect("valid rules");

        assert!(loaded.retained_bytes() > empty.retained_bytes());
        assert!(loaded.retained_bytes() >= V1.len() as u64);
    }
    #[test]
    fn distinct_source_load_parses_once_and_keeps_validation_precedence() {
        crate::parse::PARSE_CALLS.with(|calls| calls.set(0));
        LoadedRules::from_source(V1).unwrap();
        assert_eq!(crate::parse::PARSE_CALLS.with(core::cell::Cell::get), 1);
        let error = LoadedRules::from_source(
            "rules_version = '3'; service cloud.firestore { function f() { return f(); } }",
        )
        .unwrap_err();
        assert_eq!(error.message, "unsupported rules_version `3`");
    }

    #[test]
    #[ignore = "bounded release load phase measurement"]
    fn bounded_load_phase_measurement() {
        fn expression(leaves: usize) -> String {
            if leaves == 1 {
                return "true".into();
            }
            format!(
                "({} && {})",
                expression(leaves / 2),
                expression(leaves - leaves / 2)
            )
        }
        for bytes in [1024usize, 10_240, 102_400] {
            let source = format!(
                "service cloud.firestore {{ match /{{id}} {{ allow get: if {}; }} }}",
                expression(bytes / 10)
            );
            let mut parse_time = std::time::Duration::ZERO;
            let mut validate_time = std::time::Duration::ZERO;
            let mut lint_time = std::time::Duration::ZERO;
            for _ in 0..30 {
                let start = std::time::Instant::now();
                let tree = crate::parse::parse_ruleset(&source).unwrap();
                parse_time += start.elapsed();
                let start = std::time::Instant::now();
                super::validate_ruleset(&tree).unwrap();
                validate_time += start.elapsed();
                let start = std::time::Instant::now();
                std::hint::black_box(crate::lint::lint_parsed(
                    &source,
                    &tree,
                    &crate::lint::LintOptions::default(),
                ));
                lint_time += start.elapsed();
            }
            println!("load bytes={} iterations=30 parse={parse_time:?} validate={validate_time:?} lint={lint_time:?}", source.len());
        }
    }
    #[test]
    fn diagnostic_snapshot_and_guarded_clear_preserve_the_authorization_generation() {
        let slot = RulesetSlot::default();
        let before = slot.diagnostics_snapshot().unwrap();
        assert!(!before.loaded);
        assert_eq!(
            (
                before.generation,
                before.interval_epoch,
                before.distinct_value_count,
                before.estimated_coverage_bytes
            ),
            (0, 0, 0, 0)
        );
        let after = slot.clear_diagnostics(0, 0).unwrap();
        assert_eq!((after.generation, after.interval_epoch), (0, 1));
        assert_eq!(slot.snapshot().unwrap().generation(), 0);
        assert!(matches!(
            slot.clear_diagnostics(0, 0),
            Err(super::RulesDiagnosticsError::StaleInterval {
                expected: 0,
                actual: 1
            })
        ));
        assert!(matches!(
            slot.clear_diagnostics(1, 1),
            Err(super::RulesDiagnosticsError::StaleGeneration {
                expected: 1,
                actual: 0
            })
        ));
    }
    #[test]
    fn diagnostic_clear_retains_its_source_guard_until_the_reset_completes() {
        let slot = Arc::new(RulesetSlot::default());
        let admitted = slot.snapshot().unwrap();
        let diagnostics = admitted.diagnostics.lock().unwrap();
        let operation = {
            let slot = Arc::clone(&slot);
            std::thread::spawn(move || slot.clear_diagnostics(0, 0))
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match slot.active.try_write() {
                Err(std::sync::TryLockError::WouldBlock) => break,
                Ok(guard) => drop(guard),
                Err(error) => panic!("unexpected source lock failure: {error}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "clear never held the source read guard while waiting for diagnostics"
            );
            std::thread::yield_now();
        }
        let publisher = {
            let slot = Arc::clone(&slot);
            std::thread::spawn(move || slot.replace_loaded(LoadedRules::default()))
        };
        drop(diagnostics);
        let result = operation.join().unwrap().unwrap();
        assert_eq!((result.generation, result.interval_epoch), (0, 1));
        assert_eq!(publisher.join().unwrap().unwrap(), 1);
        let active = slot.diagnostics_snapshot().unwrap();
        assert_eq!(
            (
                active.generation,
                active.interval_epoch,
                active.observation_count
            ),
            (1, 0, 0)
        );
    }

    #[test]
    fn diagnostic_operations_report_poisoned_locks_and_check_generation_first() {
        let slot = RulesetSlot::default();
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _guard = slot.active.write().unwrap();
            panic!("source poison control");
        }));
        assert!(poisoned.is_err());
        assert_eq!(
            slot.diagnostics_snapshot(),
            Err(super::RulesDiagnosticsError::SlotPoisoned)
        );
        assert_eq!(
            slot.clear_diagnostics(0, 0),
            Err(super::RulesDiagnosticsError::SlotPoisoned)
        );

        let slot = RulesetSlot::default();
        let snapshot = slot.snapshot().unwrap();
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _guard = snapshot.diagnostics.lock().unwrap();
            panic!("diagnostics poison control");
        }));
        assert!(poisoned.is_err());
        assert_eq!(
            slot.diagnostics_snapshot(),
            Err(super::RulesDiagnosticsError::DiagnosticsPoisoned)
        );
        assert_eq!(
            slot.clear_diagnostics(0, 0),
            Err(super::RulesDiagnosticsError::DiagnosticsPoisoned)
        );
        assert_eq!(
            slot.clear_diagnostics(1, 0),
            Err(super::RulesDiagnosticsError::StaleGeneration {
                expected: 1,
                actual: 0
            })
        );
    }
}
