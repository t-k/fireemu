//! Outbox: deterministic dispatch order and duplicate rejection.

use ftd_core_events::event::{EventSource, EventType, LogicalEvent};
use ftd_core_events::outbox::{Outbox, OutboxError};
use ftd_core_events::state::EventState;
use ftd_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
use ftd_core_types::time::LogicalInstant;

fn event(id: u128, t: i64) -> LogicalEvent {
    LogicalEvent {
        event_id: EventId::new(id),
        session_id: SessionId::new(1),
        epoch: Epoch::initial(),
        source: EventSource::Storage,
        event_type: EventType::try_new("google.cloud.storage.object.v1.finalized").unwrap(),
        subject: format!("objects/{id}"),
        logical_time: LogicalInstant::from_unix_seconds(t),
        causation_id: None,
        correlation_id: CorrelationId::new(id),
        payload: Vec::new(),
    }
}

#[test]
fn dispatch_order_is_logical_time_then_event_id() {
    let mut outbox = Outbox::new();
    outbox.enqueue(event(30, 2)).unwrap();
    outbox.enqueue(event(10, 2)).unwrap();
    outbox.enqueue(event(20, 1)).unwrap();
    let order: Vec<u128> = outbox.dispatchable().map(|e| e.event_id.value()).collect();
    assert_eq!(order, vec![20, 10, 30]);
}

#[test]
fn duplicate_event_ids_are_rejected_without_changing_state() {
    let mut outbox = Outbox::new();
    outbox.enqueue(event(1, 0)).unwrap();
    assert_eq!(
        outbox.enqueue(event(1, 5)),
        Err(OutboxError::DuplicateEventId(EventId::new(1)))
    );
    assert_eq!(outbox.len(), 1);
}

#[test]
fn only_pending_events_are_dispatchable() {
    let mut outbox = Outbox::new();
    outbox.enqueue(event(1, 0)).unwrap();
    outbox.enqueue(event(2, 0)).unwrap();
    outbox.record_mut(EventId::new(1)).unwrap().lease().unwrap();
    let ids: Vec<u128> = outbox.dispatchable().map(|e| e.event_id.value()).collect();
    assert_eq!(ids, vec![2]);
    assert_eq!(
        outbox.record(EventId::new(1)).unwrap().state(),
        &EventState::Leased
    );
}

#[test]
fn reset_discards_every_non_terminal_event_from_old_epochs() {
    let mut outbox = Outbox::new();
    outbox.enqueue(event(1, 0)).unwrap();
    outbox.enqueue(event(2, 0)).unwrap();
    outbox
        .record_mut(EventId::new(2))
        .unwrap()
        .cancel()
        .unwrap();
    let discarded = outbox.discard_stale(Epoch::new(1));
    assert_eq!(discarded, 1);
    assert_eq!(
        outbox.record(EventId::new(1)).unwrap().state(),
        &EventState::DiscardedStaleEpoch
    );
    assert!(outbox.dispatchable().next().is_none());
}
