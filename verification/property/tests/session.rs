//! Property artifacts for INV-EPOCH-001, INV-TIME-001 and INV-IDLE-001 (spec 7.4, 8.2, 12).

use fireemu_core_events::event::{EventSource, EventType, LogicalEvent};
use fireemu_core_events::retry::RetryPolicy;
use fireemu_core_events::state::EventRecord;
use fireemu_core_session::clock::{ClockError, VirtualClock};
use fireemu_core_session::idle::{AwaitIdleOptions, IdleVerdict, WorkKind, WorkLedger};
use fireemu_core_session::session::{Session, WorkResult};
use fireemu_core_types::determinism::Clock;
use fireemu_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
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

proptest! {
    /// INV-EPOCH-001: the guard of an active session proceeds for exactly the current epoch,
    /// whatever number of resets produced it, and discards every other epoch as stale.
    #[test]
    fn prop_epoch_guard_rejects_non_current(seed: u64, resets in 0u8..8, claimed in 0u64..32) {
        let mut session = Session::create(SessionId::new(1), seed, LogicalInstant::UNIX_EPOCH);
        session.activate().unwrap();
        for _ in 0..resets {
            session.begin_reset().unwrap();
            session.complete_reset().unwrap();
        }
        let current = session.epoch();
        let result = session.check_work_epoch(Epoch::new(claimed));
        if claimed == current.value() {
            prop_assert_eq!(result, WorkResult::Proceed);
        } else {
            prop_assert_eq!(result, WorkResult::DiscardedStaleEpoch);
        }
    }

    /// INV-TIME-001: `advance` never moves the clock backwards. A negative duration is refused
    /// and leaves the clock exactly where it was; every accepted step is non-decreasing.
    #[test]
    fn prop_clock_advance_is_monotonic(
        start in -1_000_000_000_000i128..1_000_000_000_000,
        steps in prop::collection::vec(-1_000_000i128..1_000_000, 0..32),
    ) {
        let mut clock = VirtualClock::new(LogicalInstant::from_nanos(start));
        for nanos in steps {
            let before = clock.now();
            let result = clock.advance(LogicalDuration::from_nanos(nanos));
            if nanos < 0 {
                prop_assert_eq!(result, Err(ClockError::NegativeDuration));
                prop_assert_eq!(clock.now(), before);
            } else {
                prop_assert_eq!(result.unwrap(), clock.now());
            }
            prop_assert!(clock.now() >= before);
            // Moving to an earlier instant is refused by the default policy.
            let current = clock.now();
            if let Some(earlier) = current.checked_add(LogicalDuration::from_nanos(-1)) {
                prop_assert!(clock.advance_to(earlier).is_err());
                prop_assert_eq!(clock.now(), current);
            }
        }
        prop_assert_eq!(clock.backwards_sets(), 0);
    }

    /// INV-IDLE-001: the ledger reports Idle only when every event registered in it has reached
    /// a terminal state. Each non-terminal event holds an `EventDispatch` registration.
    #[test]
    fn prop_idle_implies_all_terminal(plan in prop::collection::vec(0u8..6, 0..16)) {
        let epoch = Epoch::initial();
        let newer = epoch.next().unwrap();
        let policy = RetryPolicy::try_new(
            1,
            LogicalDuration::from_seconds(1),
            LogicalDuration::from_seconds(60),
        )
        .unwrap();
        let mut ledger = WorkLedger::new(epoch);
        let mut records = Vec::new();
        for step in plan {
            let mut record = EventRecord::new(event(epoch));
            let token = ledger.begin(WorkKind::EventDispatch, epoch).unwrap();
            match step {
                0 => {
                    record.lease().unwrap();
                    record.start().unwrap();
                    record.succeed().unwrap();
                }
                1 => record.cancel().unwrap(),
                2 => {
                    record.lease().unwrap();
                    record.start().unwrap();
                    record.fail(&policy, LogicalInstant::UNIX_EPOCH).unwrap();
                }
                3 => record.discard_stale(newer).unwrap(),
                4 => {
                    record.lease().unwrap();
                    record.start().unwrap();
                }
                _ => {}
            }
            // Work is only released once the event can no longer be dispatched again.
            if record.is_terminal() {
                ledger.end(token).unwrap();
            }
            records.push(record);
        }
        let all_terminal = records.iter().all(EventRecord::is_terminal);
        let verdict = ledger.verdict(&AwaitIdleOptions::default());
        prop_assert_eq!(verdict == IdleVerdict::Idle, all_terminal);
        if all_terminal {
            prop_assert_eq!(ledger.active_total(), 0);
        }
    }
}
