//! Event state machine (spec 10.2): terminal states never regress (INV-EVENT-001), retries
//! are bounded, stale-epoch work is discarded.

use fireemu_core_events::event::{EventSource, EventType, LogicalEvent};
use fireemu_core_events::retry::RetryPolicy;
use fireemu_core_events::state::{EventRecord, EventState, EventTransitionError, FailureOutcome};
use fireemu_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

fn event(epoch: Epoch) -> LogicalEvent {
    LogicalEvent {
        event_id: EventId::new(1),
        session_id: SessionId::new(1),
        epoch,
        source: EventSource::Firestore,
        event_type: EventType::try_new("google.cloud.firestore.document.v1.created").unwrap(),
        subject: "documents/users/alice".to_owned(),
        logical_time: LogicalInstant::UNIX_EPOCH,
        causation_id: None,
        correlation_id: CorrelationId::new(1),
        payload: Vec::new(),
    }
}

fn policy() -> RetryPolicy {
    RetryPolicy::try_new(
        3,
        LogicalDuration::from_seconds(1),
        LogicalDuration::from_seconds(60),
    )
    .unwrap()
}

#[test]
fn happy_path_pending_leased_running_succeeded() {
    let mut r = EventRecord::new(event(Epoch::initial()));
    assert_eq!(r.state(), &EventState::Pending);
    assert_eq!(r.attempt(), 0);
    r.lease().unwrap();
    assert_eq!(r.state(), &EventState::Leased);
    r.start().unwrap();
    assert_eq!(r.state(), &EventState::Running);
    assert_eq!(r.attempt(), 1);
    r.succeed().unwrap();
    assert_eq!(r.state(), &EventState::Succeeded);
    assert!(r.is_terminal());
}

#[test]
fn failure_retries_with_backoff_until_max_attempts_then_dead_letters() {
    let mut r = EventRecord::new(event(Epoch::initial()));
    let now = LogicalInstant::from_unix_seconds(100);
    // attempt 1 fails -> retry at now + 1s
    r.lease().unwrap();
    r.start().unwrap();
    assert_eq!(
        r.fail(&policy(), now).unwrap(),
        FailureOutcome::RetryScheduled {
            retry_at: LogicalInstant::from_unix_seconds(101)
        }
    );
    assert_eq!(
        r.state(),
        &EventState::RetryWaiting {
            retry_at: LogicalInstant::from_unix_seconds(101)
        }
    );
    assert_eq!(
        r.retry_due(LogicalInstant::from_unix_seconds(100)),
        Err(EventTransitionError::RetryNotDue)
    );
    r.retry_due(LogicalInstant::from_unix_seconds(101)).unwrap();
    assert_eq!(r.state(), &EventState::Pending);
    // attempt 2 fails -> retry at now + 2s
    r.lease().unwrap();
    r.start().unwrap();
    assert_eq!(r.attempt(), 2);
    assert_eq!(
        r.fail(&policy(), now).unwrap(),
        FailureOutcome::RetryScheduled {
            retry_at: LogicalInstant::from_unix_seconds(102)
        }
    );
    r.retry_due(LogicalInstant::from_unix_seconds(102)).unwrap();
    // attempt 3 fails -> dead letter (max_attempts = 3)
    r.lease().unwrap();
    r.start().unwrap();
    assert_eq!(r.attempt(), 3);
    assert_eq!(
        r.fail(&policy(), now).unwrap(),
        FailureOutcome::DeadLettered
    );
    assert!(matches!(r.state(), EventState::DeadLettered { .. }));
    assert!(r.is_terminal());
}

#[test]
fn backoff_is_capped_and_never_overflows() {
    let p = RetryPolicy::try_new(
        u32::MAX,
        LogicalDuration::from_seconds(1),
        LogicalDuration::from_seconds(60),
    )
    .unwrap();
    assert_eq!(p.backoff_for_attempt(1), LogicalDuration::from_seconds(1));
    assert_eq!(p.backoff_for_attempt(6), LogicalDuration::from_seconds(32));
    assert_eq!(p.backoff_for_attempt(7), LogicalDuration::from_seconds(60));
    assert_eq!(
        p.backoff_for_attempt(200),
        LogicalDuration::from_seconds(60)
    );
}

#[test]
fn terminal_states_never_regress() {
    for terminal in [
        |r: &mut EventRecord| {
            r.lease().unwrap();
            r.start().unwrap();
            r.succeed().unwrap();
        },
        |r: &mut EventRecord| {
            r.cancel().unwrap();
        },
        |r: &mut EventRecord| {
            r.discard_stale(Epoch::new(5)).unwrap();
        },
    ] {
        let mut r = EventRecord::new(event(Epoch::initial()));
        terminal(&mut r);
        assert!(r.is_terminal());
        let before = r.state().clone();
        assert!(matches!(
            r.lease(),
            Err(EventTransitionError::Terminal { .. })
        ));
        assert!(matches!(
            r.start(),
            Err(EventTransitionError::Terminal { .. })
        ));
        assert!(matches!(
            r.succeed(),
            Err(EventTransitionError::Terminal { .. })
        ));
        assert!(matches!(
            r.fail(&policy(), LogicalInstant::UNIX_EPOCH),
            Err(EventTransitionError::Terminal { .. })
        ));
        assert!(matches!(
            r.cancel(),
            Err(EventTransitionError::Terminal { .. })
        ));
        assert!(matches!(
            r.retry_due(LogicalInstant::MAX),
            Err(EventTransitionError::Terminal { .. })
        ));
        assert_eq!(r.state(), &before);
    }
}

#[test]
fn invalid_non_terminal_transitions_are_rejected() {
    let mut r = EventRecord::new(event(Epoch::initial()));
    assert!(matches!(
        r.start(),
        Err(EventTransitionError::InvalidTransition { .. })
    ));
    assert!(matches!(
        r.succeed(),
        Err(EventTransitionError::InvalidTransition { .. })
    ));
    r.lease().unwrap();
    assert!(matches!(
        r.lease(),
        Err(EventTransitionError::InvalidTransition { .. })
    ));
    assert_eq!(r.state(), &EventState::Leased);
}

#[test]
fn stale_epoch_discard_only_applies_to_older_epochs() {
    let mut r = EventRecord::new(event(Epoch::new(3)));
    assert_eq!(
        r.discard_stale(Epoch::new(3)),
        Err(EventTransitionError::EpochIsCurrent)
    );
    assert_eq!(r.state(), &EventState::Pending);
    r.discard_stale(Epoch::new(4)).unwrap();
    assert_eq!(r.state(), &EventState::DiscardedStaleEpoch);
}

#[test]
fn event_type_rejects_empty_and_control_characters() {
    assert!(EventType::try_new("").is_err());
    assert!(EventType::try_new("a\u{0}b").is_err());
    assert!(EventType::try_new("a b").is_err());
    assert!(EventType::try_new("google.cloud.storage.object.v1.finalized").is_ok());
}

#[test]
fn retry_instant_overflow_is_a_typed_error_that_leaves_the_record_running() {
    let mut r = EventRecord::new(event(Epoch::initial()));
    r.lease().unwrap();
    r.start().unwrap();
    let result = r.fail(&policy(), LogicalInstant::MAX);
    assert_eq!(result, Err(EventTransitionError::RetryInstantOverflow));
    assert_eq!(r.state(), &EventState::Running);
}

#[test]
fn retry_policy_rejects_zero_attempts_negative_and_inverted_backoffs() {
    use fireemu_core_events::retry::RetryPolicyError;
    let one = LogicalDuration::from_seconds(1);
    assert_eq!(
        RetryPolicy::try_new(0, one, one),
        Err(RetryPolicyError::ZeroAttempts)
    );
    assert_eq!(
        RetryPolicy::try_new(1, LogicalDuration::from_seconds(-1), one),
        Err(RetryPolicyError::NegativeBackoff)
    );
    assert_eq!(
        RetryPolicy::try_new(1, LogicalDuration::from_seconds(2), one),
        Err(RetryPolicyError::BaseExceedsMax)
    );
    // One attempt: the first failure dead-letters immediately (matches the TLA+ bound).
    let no_retry = RetryPolicy::try_new(1, one, one).unwrap();
    let mut r = EventRecord::new(event(Epoch::initial()));
    r.lease().unwrap();
    r.start().unwrap();
    assert_eq!(
        r.fail(&no_retry, LogicalInstant::UNIX_EPOCH).unwrap(),
        FailureOutcome::DeadLettered
    );
    assert_eq!(r.state(), &EventState::DeadLettered { attempts: 1 });
}

#[test]
fn event_type_accessors_length_boundary_and_names() {
    let t = EventType::try_new("a.b").unwrap();
    assert_eq!(t.as_str(), "a.b");
    assert_eq!(t.to_string(), "a.b");
    assert!(EventType::try_new("x".repeat(256)).is_ok());
    assert!(EventType::try_new("x".repeat(257)).is_err());
    assert!(EventType::try_new("a\u{0}b")
        .unwrap_err()
        .to_string()
        .contains("invalid character"));
    assert!(EventType::try_new("")
        .unwrap_err()
        .to_string()
        .contains("empty"));
    assert_eq!(EventState::Pending.name(), "Pending");
    assert_eq!(
        EventState::RetryWaiting {
            retry_at: LogicalInstant::UNIX_EPOCH
        }
        .name(),
        "RetryWaiting"
    );
    assert_eq!(
        EventState::DeadLettered { attempts: 3 }.name(),
        "DeadLettered"
    );
    let err = EventTransitionError::InvalidTransition {
        from: "Pending",
        action: "start",
    };
    assert!(err.to_string().contains("Pending") && err.to_string().contains("start"));
    assert!(EventTransitionError::RetryNotDue
        .to_string()
        .contains("due"));
}

#[test]
fn retry_policy_accessors_and_edge_values() {
    use fireemu_core_events::retry::RetryPolicyError;
    let one = LogicalDuration::from_seconds(1);
    let p = RetryPolicy::try_new(3, one, LogicalDuration::from_seconds(60)).unwrap();
    assert_eq!(p.max_attempts(), 3);
    assert_eq!(p.base_backoff(), one);
    assert_eq!(p.max_backoff(), LogicalDuration::from_seconds(60));
    assert!(
        RetryPolicy::try_new(1, one, one).is_ok(),
        "base == max is allowed"
    );
    assert!(RetryPolicy::try_new(1, LogicalDuration::ZERO, LogicalDuration::ZERO).is_ok());
    assert_eq!(
        RetryPolicy::try_new(1, one, LogicalDuration::from_seconds(-1)),
        Err(RetryPolicyError::NegativeBackoff)
    );
    assert!(RetryPolicyError::ZeroAttempts.to_string().contains('1'));
    assert!(p.allows_retry_after(2));
    assert!(!p.allows_retry_after(3));
}
