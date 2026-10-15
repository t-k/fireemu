//! Outbox: deterministic dispatch order and duplicate rejection.

use fireemu_core_events::event::{EventSource, EventType, LogicalEvent};
use fireemu_core_events::outbox::{Outbox, OutboxError};
use fireemu_core_events::state::{EventRecord, EventState};
use fireemu_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
use fireemu_core_types::time::LogicalInstant;

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
    outbox
        .update(EventId::new(1), EventRecord::lease)
        .unwrap()
        .unwrap();
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
        .update(EventId::new(2), EventRecord::cancel)
        .unwrap()
        .unwrap();
    let discarded = outbox.discard_stale(Epoch::new(1));
    assert_eq!(discarded, 1);
    assert_eq!(
        outbox.record(EventId::new(1)).unwrap().state(),
        &EventState::DiscardedStaleEpoch
    );
    assert!(outbox.dispatchable().next().is_none());
}

#[test]
fn len_is_empty_has_active_and_retries_due() {
    use fireemu_core_events::retry::RetryPolicy;
    use fireemu_core_types::time::LogicalDuration;
    let mut outbox = Outbox::new();
    assert!(outbox.is_empty());
    assert_eq!(outbox.len(), 0);
    assert!(!outbox.has_active());
    outbox.enqueue(event(1, 0)).unwrap();
    outbox.enqueue(event(2, 0)).unwrap();
    assert!(!outbox.is_empty());
    assert_eq!(outbox.len(), 2);
    assert!(outbox.has_active());
    let policy = RetryPolicy::try_new(
        3,
        LogicalDuration::from_seconds(10),
        LogicalDuration::from_seconds(10),
    )
    .unwrap();
    for id in [1, 2] {
        outbox
            .update(EventId::new(id), |r| {
                r.lease().unwrap();
                r.start().unwrap();
                r.fail(
                    &policy,
                    LogicalInstant::from_unix_seconds(100 + i64::try_from(id).unwrap()),
                )
                .unwrap();
            })
            .unwrap();
    }
    // Failures happen at 101 / 102 with a 10 s backoff: retry_at = 111 for event 1, 112 for 2.
    assert!(outbox
        .retries_due(LogicalInstant::from_unix_seconds(110))
        .is_empty());
    assert_eq!(
        outbox.retries_due(LogicalInstant::from_unix_seconds(111)),
        vec![EventId::new(1)]
    );
    assert_eq!(
        outbox.retries_due(LogicalInstant::from_unix_seconds(112)),
        vec![EventId::new(1), EventId::new(2)]
    );
    outbox
        .update(EventId::new(1), EventRecord::cancel)
        .unwrap()
        .unwrap();
    outbox
        .update(EventId::new(2), EventRecord::cancel)
        .unwrap()
        .unwrap();
    assert!(!outbox.has_active());
    assert_eq!(
        outbox.enqueue(event(1, 0)).unwrap_err().to_string(),
        "duplicate event id 1"
    );
    assert!(outbox
        .update(EventId::new(9), EventRecord::cancel)
        .unwrap_err()
        .to_string()
        .contains("unknown"));
}

#[test]
fn terminal_records_are_evicted_and_dispatch_follows_the_active_work() {
    // FN-RET-01 / 02: completing twice the retention budget leaves the retained window bounded
    // and in the order the records were retired, while a dispatch pass keeps visiting only the
    // pending records however many events have finished.
    let mut outbox = Outbox::with_terminal_retention(8);
    assert_eq!(outbox.terminal_retention(), 8);
    for id in 1..=16u128 {
        outbox.enqueue(event(id, 0)).unwrap();
        outbox
            .update(EventId::new(id), |r| {
                r.lease().unwrap();
                r.start().unwrap();
                r.succeed().unwrap();
            })
            .unwrap();
    }
    assert_eq!(outbox.len(), 8, "the retained window is bounded");
    assert_eq!(outbox.evicted(), 8);
    assert!(!outbox.has_active());
    // Oldest first within the window: 1..=8 were dropped, 9..=16 kept.
    for id in 1..=8u128 {
        assert!(outbox.record(EventId::new(id)).is_none(), "{id} evicted");
    }
    for id in 9..=16u128 {
        assert_eq!(
            outbox.record(EventId::new(id)).unwrap().state(),
            &EventState::Succeeded,
            "{id} retained"
        );
    }

    // One pending event among many terminal ones: dispatch visits it alone.
    outbox.enqueue(event(100, 0)).unwrap();
    assert_eq!(outbox.dispatch_visits(), 1);
    assert_eq!(
        outbox
            .dispatchable()
            .map(|e| e.event_id.value())
            .collect::<Vec<_>>(),
        vec![100]
    );
    assert!(outbox.has_active());
    // A retry-waiting record leaves the pending index but stays active.
    outbox
        .update(EventId::new(100), |r| {
            r.lease().unwrap();
            r.start().unwrap();
        })
        .unwrap();
    assert_eq!(outbox.dispatch_visits(), 0);
    assert!(outbox.has_active());
    outbox
        .update(EventId::new(100), EventRecord::cancel)
        .unwrap()
        .unwrap();
    assert!(!outbox.has_active());
    assert_eq!(outbox.len(), 8, "the window did not grow");
}

#[test]
fn eviction_leaves_dispatch_order_and_retry_eligibility_unchanged() {
    // FN-RET-03: retiring more records than the window holds must not disturb the events that
    // are still active, whatever order they were enqueued in.
    use fireemu_core_events::retry::RetryPolicy;
    use fireemu_core_types::time::LogicalDuration;
    let policy = RetryPolicy::try_new(
        3,
        LogicalDuration::from_seconds(10),
        LogicalDuration::from_seconds(10),
    )
    .unwrap();
    let mut outbox = Outbox::with_terminal_retention(2);
    // Three pending events out of dispatch order, and one that will be retry-waiting.
    outbox.enqueue(event(30, 2)).unwrap();
    outbox.enqueue(event(10, 2)).unwrap();
    outbox.enqueue(event(20, 1)).unwrap();
    outbox.enqueue(event(40, 0)).unwrap();
    outbox
        .update(EventId::new(40), |r| {
            r.lease().unwrap();
            r.start().unwrap();
            r.fail(&policy, LogicalInstant::from_unix_seconds(100))
                .unwrap();
        })
        .unwrap();
    // Retire far more records than the window holds.
    for id in 1000..1020u128 {
        outbox.enqueue(event(id, 5)).unwrap();
        outbox
            .update(EventId::new(id), EventRecord::cancel)
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        outbox
            .dispatchable()
            .map(|e| e.event_id.value())
            .collect::<Vec<_>>(),
        vec![20, 10, 30],
        "dispatch order survives eviction"
    );
    assert_eq!(
        outbox.retries_due(LogicalInstant::from_unix_seconds(110)),
        vec![EventId::new(40)],
        "retry eligibility survives eviction"
    );
    assert_eq!(outbox.evicted(), 18);
    assert!(outbox.has_active());
    // A reset still discards every non-terminal record, and does it over the active index.
    assert_eq!(outbox.discard_stale(Epoch::new(1)), 4);
    assert!(!outbox.has_active());
    assert!(outbox.dispatchable().next().is_none());
    assert!(outbox
        .retries_due(LogicalInstant::from_unix_seconds(200))
        .is_empty());
}

#[test]
fn retry_sweep_visits_only_the_due_prefix() {
    use fireemu_core_events::retry::RetryPolicy;
    use fireemu_core_types::time::LogicalDuration;

    let policy = RetryPolicy::try_new(
        3,
        LogicalDuration::from_seconds(10),
        LogicalDuration::from_seconds(10),
    )
    .unwrap();
    let mut outbox = Outbox::new();
    for id in 1..=1_000u128 {
        outbox.enqueue(event(id, 0)).unwrap();
        outbox
            .update(EventId::new(id), |record| {
                record.lease().unwrap();
                record.start().unwrap();
                record
                    .fail(
                        &policy,
                        LogicalInstant::from_unix_seconds(i64::try_from(id).unwrap()),
                    )
                    .unwrap();
            })
            .unwrap();
    }

    let now = LogicalInstant::from_unix_seconds(11);
    assert_eq!(outbox.retries_due(now), vec![EventId::new(1)]);
    assert_eq!(outbox.retry_sweep_visits(now), 1);
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config { cases: 128, failure_persistence: None, ..Default::default() })]
    #[test]
    fn queue_heads_match_linear_dispatch_after_state_transitions(
        steps in proptest::collection::vec((1u128..32, 0u8..10, -5i64..15, 0u8..4), 1..150),
        capacities in proptest::collection::vec(0usize..4, 4),
        held in proptest::collection::btree_set(1u128..32, 0..12),
    ) {
        use fireemu_core_events::retry::RetryPolicy;
        use fireemu_core_types::time::LogicalDuration;
        use std::collections::{BTreeMap, BTreeSet};

        let mut indexed = Outbox::with_terminal_retention(4);
        let mut linear = Outbox::with_terminal_retention(4);
        let mut queues = BTreeMap::new();
        let policy = RetryPolicy::try_new(3, LogicalDuration::from_seconds(1), LogicalDuration::from_seconds(4)).unwrap();
        let mut epoch = Epoch::initial();
        for (id, action, time, queue) in steps {
            let id = EventId::new(id);
            let now = LogicalInstant::from_unix_seconds(time);
            if action == 0 {
                let mut event = event(id.value(), time);
                event.epoch = epoch;
                let result = linear.enqueue(event.clone());
                proptest::prop_assert_eq!(indexed.enqueue_in_queue(event, &queue.to_string()), result);
                if result.is_ok() { queues.insert(id, queue.to_string()); }
            } else if action == 8 {
                epoch = epoch.next().unwrap();
                proptest::prop_assert_eq!(indexed.discard_stale(epoch), linear.discard_stale(epoch));
            } else {
                for outbox in [&mut indexed, &mut linear] {
                    let _ = outbox.update(id, |record| match action {
                        1 => record.lease(),
                        2 => record.start(),
                        3 => record.succeed(),
                        4 => record.fail(&policy, now).map(|_| ()),
                        5 => record.interrupt(),
                        6 => record.retry_due(now),
                        _ => record.cancel(),
                    });
                }
            }
            proptest::prop_assert_eq!(indexed.len(), linear.len());
            proptest::prop_assert_eq!(indexed.retries_due(now), linear.retries_due(now));
            let mut room = capacities.clone();
            let expected = linear.dispatchable().filter_map(|event| {
                let queue: usize = queues[&event.event_id].parse().unwrap();
                if room[queue] == 0 || held.contains(&event.event_id.value()) { return None; }
                room[queue] -= 1;
                Some(event.event_id)
            }).collect::<Vec<_>>();
            let mut heads = indexed.dispatchable_queue_heads().map(|(queue, key)| (key, queue.to_owned())).collect::<BTreeSet<_>>();
            let mut actual = Vec::new();
            let mut room = capacities.clone();
            while let Some((key, queue)) = heads.pop_first() {
                let index: usize = queue.parse().unwrap();
                if room[index] == 0 { continue; }
                if !held.contains(&key.1.value()) {
                    actual.push(key.1);
                    room[index] -= 1;
                }
                if let Some(next) = indexed.next_dispatchable_in_queue(&queue, key) {
                    heads.insert((next, queue));
                }
            }
            proptest::prop_assert_eq!(actual, expected);
            proptest::prop_assert_eq!(indexed.dispatchable().collect::<Vec<_>>(), linear.dispatchable().collect::<Vec<_>>());
        }
    }
}
