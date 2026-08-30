//! Property artifact for INV-EVENT-001 (spec 10.2).

use ftd_core_events::event::{EventSource, EventType, LogicalEvent};
use ftd_core_events::retry::RetryPolicy;
use ftd_core_events::state::{EventRecord, EventState, EventTransitionError};
use ftd_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
use ftd_core_types::time::{LogicalDuration, LogicalInstant};
use proptest::prelude::*;

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

/// Drives a fresh record into one of the four terminal states.
fn terminal(kind: u8) -> EventRecord {
    let epoch = Epoch::initial();
    let mut record = EventRecord::new(event(epoch));
    let policy = RetryPolicy::try_new(
        1,
        LogicalDuration::from_seconds(1),
        LogicalDuration::from_seconds(60),
    )
    .unwrap();
    match kind % 4 {
        0 => {
            record.lease().unwrap();
            record.start().unwrap();
            record.succeed().unwrap();
        }
        1 => {
            record.lease().unwrap();
            record.start().unwrap();
            record.fail(&policy, LogicalInstant::UNIX_EPOCH).unwrap();
        }
        2 => record.cancel().unwrap(),
        _ => record.discard_stale(epoch.next().unwrap()).unwrap(),
    }
    assert!(record.is_terminal());
    record
}

proptest! {
    /// INV-EVENT-001: every transition out of a terminal state is refused with `Terminal`, and
    /// the record (state and attempt counter) is left exactly as it was.
    #[test]
    fn prop_terminal_states_are_absorbing(kind in 0u8..4, action in 0u8..8, now in 0i64..1_000_000) {
        let policy = RetryPolicy::try_new(
            3,
            LogicalDuration::from_seconds(1),
            LogicalDuration::from_seconds(60),
        )
        .unwrap();
        let mut record = terminal(kind);
        let before = record.clone();
        let expected = EventTransitionError::Terminal { state: record.state().name() };
        let at = LogicalInstant::from_unix_seconds(now);
        let result = match action {
            0 => record.lease(),
            1 => record.start(),
            2 => record.succeed(),
            3 => record.fail(&policy, at).map(|_| ()),
            4 => record.interrupt(),
            5 => record.retry_due(at),
            6 => record.cancel(),
            _ => record.discard_stale(Epoch::new(u64::MAX)),
        };
        prop_assert_eq!(result, Err(expected));
        prop_assert_eq!(record.state(), before.state());
        prop_assert_eq!(record.attempt(), before.attempt());
        prop_assert!(record.is_terminal());
        let non_terminal = matches!(
            record.state(),
            EventState::Pending
                | EventState::Leased
                | EventState::Running
                | EventState::RetryWaiting { .. }
        );
        prop_assert!(!non_terminal);
    }
}
