//! Event state machine (spec 10.2): terminal states never regress (INV-EVENT-001), retries
//! are bounded, stale-epoch work is discarded.

use ftd_core_events::event::{EventSource, EventType, LogicalEvent};
use ftd_core_events::retry::RetryPolicy;
use ftd_core_events::state::{EventRecord, EventState, EventTransitionError, FailureOutcome};
use ftd_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
use ftd_core_types::time::{LogicalDuration, LogicalInstant};

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
    RetryPolicy {
        max_attempts: 3,
        base_backoff: LogicalDuration::from_seconds(1),
        max_backoff: LogicalDuration::from_seconds(60),
    }
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
    let p = RetryPolicy {
        max_attempts: u32::MAX,
        base_backoff: LogicalDuration::from_seconds(1),
        max_backoff: LogicalDuration::from_seconds(60),
    };
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
