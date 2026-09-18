//! Fault plans: nth-occurrence matching, per-operation counters, history.

use fireemu_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule, FaultState};

fn rule(
    operation: &str,
    nth: Option<u64>,
    function: Option<&str>,
    action: FaultAction,
) -> FaultRule {
    FaultRule {
        matches: FaultMatch {
            operation: operation.to_owned(),
            nth,
            function: function.map(str::to_owned),
            event_type: None,
        },
        action,
    }
}

#[test]
fn rules_match_the_nth_occurrence_or_every_one_and_are_counted_per_operation() {
    let mut state = FaultState::default();
    assert!(state.decide("firestore.commit", None, None).is_empty());
    assert!(
        state.counters().is_empty(),
        "nothing counted without a plan"
    );
    state.install(FaultPlan {
        seed: 1,
        rules: vec![
            rule(
                "firestore.commit",
                Some(2),
                None,
                FaultAction::ReturnError {
                    code: "ABORTED".into(),
                },
            ),
            rule(
                "functions.invoke",
                None,
                Some("flaky"),
                FaultAction::Timeout,
            ),
            rule(
                "functions.deliver",
                Some(1),
                None,
                FaultAction::Duplicate { count: 2 },
            ),
        ],
    });
    assert!(state.decide("firestore.commit", None, None).is_empty());
    assert_eq!(
        state.decide("firestore.commit", None, None),
        vec![FaultAction::ReturnError {
            code: "ABORTED".into()
        }]
    );
    assert!(state.decide("firestore.commit", None, None).is_empty());
    // Function filter.
    assert!(state
        .decide("functions.invoke", Some("steady"), None)
        .is_empty());
    assert_eq!(
        state.decide("functions.invoke", Some("flaky"), None),
        vec![FaultAction::Timeout]
    );
    assert_eq!(
        state.decide("functions.invoke", Some("flaky"), None),
        vec![FaultAction::Timeout]
    );
    // Counters are per operation; the delivery rule fires once.
    assert_eq!(
        state.decide("functions.deliver", None, None),
        vec![FaultAction::Duplicate { count: 2 }]
    );
    assert!(state.decide("functions.deliver", None, None).is_empty());
    assert_eq!(state.counters()["firestore.commit"], 3);
    assert_eq!(state.counters()["functions.invoke"], 3);
    assert_eq!(state.counters()["functions.invoke|flaky"], 2);
    let fired = state.fired();
    assert_eq!(fired.len(), 4);
    assert_eq!(fired[0].occurrence, 2);
    assert_eq!(fired[1].function.as_deref(), Some("flaky"));
    // Clearing forgets the plan, the counters and the history.
    state.clear();
    assert!(state.plan().is_none());
    assert!(state.decide("firestore.commit", None, None).is_empty());
    assert!(state.fired().is_empty());
    // Reinstalling restarts the counters.
    state.install(FaultPlan {
        seed: 2,
        rules: vec![rule(
            "firestore.commit",
            Some(1),
            None,
            FaultAction::TransactionConflict,
        )],
    });
    assert_eq!(
        state.decide("firestore.commit", None, None),
        vec![FaultAction::TransactionConflict]
    );
    assert_eq!(
        FaultAction::Duplicate { count: 2 }.to_string(),
        "duplicate x2"
    );
    // With a function filter, nth counts that function's occurrences.
    state.install(FaultPlan {
        seed: 3,
        rules: vec![rule(
            "functions.invoke",
            Some(1),
            Some("b"),
            FaultAction::CrashRunner,
        )],
    });
    assert!(state.decide("functions.invoke", Some("a"), None).is_empty());
    assert_eq!(
        state.decide("functions.invoke", Some("b"), None),
        vec![FaultAction::CrashRunner]
    );
    assert!(state.decide("functions.invoke", Some("b"), None).is_empty());
}

/// FAULTH-1: a rule with no `nth` fires on every matching operation, so the history of a plan
/// left installed under load is a bounded ring. The records that fall out are counted, and the
/// snapshot estimate of the state stops growing with them.
#[test]
fn the_fired_history_is_a_bounded_ring_that_counts_what_it_drops() {
    use fireemu_core_session::fault::MAX_FIRED_RECORDS;

    let mut state = FaultState::default();
    state.install(FaultPlan {
        seed: 1,
        rules: vec![rule(
            "firestore.commit",
            None,
            None,
            FaultAction::TransactionConflict,
        )],
    });
    assert_eq!(state.dropped_fired(), 0);

    for _ in 0..MAX_FIRED_RECORDS {
        assert_eq!(
            state.decide("firestore.commit", None, None),
            vec![FaultAction::TransactionConflict]
        );
    }
    assert_eq!(state.fired().len(), MAX_FIRED_RECORDS);
    assert_eq!(state.dropped_fired(), 0);
    assert_eq!(state.fired()[0].occurrence, 1, "the oldest record is first");
    let bounded = state.retained_bytes();

    let overflow = 9_000;
    for _ in 0..overflow {
        assert_eq!(
            state.decide("firestore.commit", None, None),
            vec![FaultAction::TransactionConflict]
        );
    }
    assert_eq!(
        state.fired().len(),
        MAX_FIRED_RECORDS,
        "the ring is bounded"
    );
    assert_eq!(state.dropped_fired(), overflow as u64);
    let occurrences: Vec<u64> = state.fired().iter().map(|r| r.occurrence).collect();
    assert_eq!(
        occurrences.first().copied(),
        Some((overflow + 1) as u64),
        "the oldest retained record is the newest {MAX_FIRED_RECORDS} minus one"
    );
    assert_eq!(
        occurrences.last().copied(),
        Some((MAX_FIRED_RECORDS + overflow) as u64),
        "the newest record is the last operation"
    );
    assert!(
        state.retained_bytes() <= bounded.saturating_mul(2),
        "the snapshot estimate stays bounded"
    );

    // The counters still count every occurrence: the ring bounds the history, not the plan.
    assert_eq!(
        state.counters()["firestore.commit"],
        (MAX_FIRED_RECORDS + overflow) as u64
    );

    // Installing or clearing a plan forgets the history and the dropped count together.
    state.clear();
    assert!(state.fired().is_empty());
    assert_eq!(state.dropped_fired(), 0);
}
