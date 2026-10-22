//! Explicit diagnostics intervals preserve generation isolation and completion-order recording.

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

use fireemu_core_rules::ast::Span;
use fireemu_core_rules::coverage::{Coverage, ExprValue, RequestTrace, REQUEST_TRACE_CAPACITY};
use fireemu_core_rules::runtime::{LoadedRules, RulesDiagnosticsError, RulesetSlot};

fn recording(value: u16) -> Coverage {
    let mut coverage = Coverage::default();
    coverage.record(
        Span::default(),
        1,
        ExprValue::String(format!("uid-{value}")),
    );
    coverage
}

fn trace(sequence: u64) -> RequestTrace {
    RequestTrace {
        sequence,
        method: "get",
        path: "/one".into(),
        allowed: true,
        reason: String::new(),
        uid: None,
        expressions: Vec::new(),
    }
}

#[test]
fn explicit_clear_preserves_trace_enable_and_sequence_and_uses_merge_completion_order() {
    let slot = RulesetSlot::default();
    let admitted = slot.snapshot().unwrap();
    {
        let mut diagnostics = admitted.diagnostics.lock().unwrap();
        diagnostics.enable_request_traces();
        diagnostics.push(&recording(1), trace);
    }
    let before = slot.diagnostics_snapshot().unwrap();
    assert_eq!(
        (before.request_trace_count, before.observation_count),
        (1, 1)
    );
    let empty = slot.clear_diagnostics(0, 0).unwrap();
    assert!(empty.request_traces_enabled);
    assert_eq!(
        (
            empty.interval_epoch,
            empty.request_trace_count,
            empty.observation_count,
            empty.estimated_coverage_bytes
        ),
        (1, 0, 0, 0)
    );
    // This admitted request completes after the explicit clear, so it belongs to interval one.
    admitted
        .diagnostics
        .lock()
        .unwrap()
        .push(&recording(2), trace);
    let after = slot.diagnostics_snapshot().unwrap();
    assert_eq!(
        (
            after.interval_epoch,
            after.observation_count,
            after.request_trace_count
        ),
        (1, 1, 1)
    );
    assert_eq!(
        admitted.diagnostics.lock().unwrap().requests()[0].sequence,
        2
    );
}

#[test]
fn concurrent_clears_have_one_winner_and_one_stale_interval_without_changing_source() {
    for _ in 0..16 {
        let slot = Arc::new(RulesetSlot::default());
        let start = Arc::new(Barrier::new(3));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let slot = Arc::clone(&slot);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    slot.clear_diagnostics(0, 0)
                })
            })
            .collect();
        start.wait();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(
                    result,
                    Err(RulesDiagnosticsError::StaleInterval {
                        expected: 0,
                        actual: 1
                    })
                ))
                .count(),
            1
        );
        assert_eq!(slot.snapshot().unwrap().generation(), 0);
    }
}

#[test]
fn late_old_generation_merges_and_stale_clears_cannot_modify_the_active_generation() {
    let slot = RulesetSlot::default();
    let admitted = slot.snapshot().unwrap();
    admitted
        .diagnostics
        .lock()
        .unwrap()
        .merge_coverage(&recording(1));
    slot.replace_loaded(LoadedRules::default()).unwrap();
    admitted
        .diagnostics
        .lock()
        .unwrap()
        .merge_coverage(&recording(2));
    assert!(matches!(
        slot.clear_diagnostics(0, 0),
        Err(RulesDiagnosticsError::StaleGeneration {
            expected: 0,
            actual: 1
        })
    ));
    let active = slot.diagnostics_snapshot().unwrap();
    assert_eq!(
        (
            active.generation,
            active.interval_epoch,
            active.observation_count
        ),
        (1, 0, 0)
    );
    assert_eq!(
        admitted.diagnostics.lock().unwrap().coverage().entries()[0]
            .values
            .len(),
        2
    );
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(128))]
    #[test]
    fn diagnostic_interval_transitions_match_an_independent_reference(operations in proptest::collection::vec((0u8..7, 0u16..64), 0..80)) {
        let slot = RulesetSlot::default();
        let mut generation = 0u64;
        let mut interval = 0u64;
        let mut values = BTreeMap::<u16, u64>::new();
        let mut enabled = false;
        let mut sequences = Vec::new();
        let mut next_sequence = 0u64;
        let mut old = Vec::new();
        for (operation, value) in operations {
            match operation {
                0 | 1 => {
                    slot.snapshot().unwrap().diagnostics.lock().unwrap().push(&recording(value), trace);
                    *values.entry(value).or_default() += 1;
                    if enabled {
                        next_sequence += 1;
                        sequences.push(next_sequence);
                        if sequences.len() > REQUEST_TRACE_CAPACITY { sequences.remove(0); }
                    }
                }
                2 => { slot.snapshot().unwrap().diagnostics.lock().unwrap().enable_request_traces(); enabled = true; }
                3 => {
                    slot.clear_diagnostics(generation, interval).unwrap();
                    interval += 1; values.clear(); sequences.clear();
                }
                4 => {
                    let stale = slot.clear_diagnostics(generation.saturating_add(1), interval);
                    proptest::prop_assert!(matches!(stale, Err(RulesDiagnosticsError::StaleGeneration { .. })), "stale generation must be refused");
                }
                5 => {
                    old.push(slot.snapshot().unwrap());
                    slot.replace_loaded(LoadedRules::default()).unwrap();
                    generation += 1; interval = 0; values.clear(); sequences.clear(); next_sequence = 0; enabled = false;
                }
                _ => {
                    if let Some(old) = old.last() { old.diagnostics.lock().unwrap().merge_coverage(&recording(value)); }
                    let stale = slot.clear_diagnostics(generation, interval.saturating_add(1));
                    proptest::prop_assert!(matches!(stale, Err(RulesDiagnosticsError::StaleInterval { .. })), "stale interval must be refused");
                }
            }
            let actual = slot.diagnostics_snapshot().unwrap();
            proptest::prop_assert_eq!((actual.generation, actual.interval_epoch), (generation, interval));
            proptest::prop_assert_eq!(actual.expression_count, u64::from(!values.is_empty()));
            proptest::prop_assert_eq!(actual.distinct_value_count, u64::try_from(values.len()).unwrap());
            proptest::prop_assert_eq!(actual.observation_count, values.values().sum::<u64>());
            proptest::prop_assert_eq!(actual.request_trace_count, u64::try_from(sequences.len()).unwrap());
            proptest::prop_assert_eq!(actual.request_traces_enabled, enabled);
            if values.is_empty() { proptest::prop_assert_eq!(actual.estimated_coverage_bytes, 0); }
            let snapshot = slot.snapshot().unwrap();
            let diagnostics = snapshot.diagnostics.lock().unwrap();
            let actual_sequences: Vec<_> = diagnostics.requests().iter().rev().map(|request| request.sequence).collect();
            proptest::prop_assert_eq!(&actual_sequences, &sequences);
        }
    }
}
