//! Conformance boundary tests for the Quint event-delivery driver.

use std::collections::BTreeMap;

use fireemu_verification_quint::event_delivery::{
    EventDeliveryDriver, EventDeliveryState, EventLifecycle, MODELED_ACTIONS,
};

fn one_event_state(
    lifecycle: EventLifecycle,
    attempts: u32,
    current_epoch: u64,
) -> EventDeliveryState {
    let terminal = matches!(
        &lifecycle,
        EventLifecycle::Succeeded
            | EventLifecycle::DeadLettered
            | EventLifecycle::Cancelled
            | EventLifecycle::DiscardedStaleEpoch
    );
    let cancelled = lifecycle == EventLifecycle::Cancelled;
    let stale = lifecycle == EventLifecycle::DiscardedStaleEpoch;
    EventDeliveryState {
        state: BTreeMap::from([("e1".to_owned(), lifecycle)]),
        attempts: BTreeMap::from([("e1".to_owned(), attempts)]),
        max_attempts: 2,
        captured_epoch: BTreeMap::from([("e1".to_owned(), 0)]),
        current_epoch,
        terminal: BTreeMap::from([("e1".to_owned(), terminal)]),
        cancelled: BTreeMap::from([("e1".to_owned(), cancelled)]),
        stale: BTreeMap::from([("e1".to_owned(), stale)]),
    }
}

fn driver() -> EventDeliveryDriver {
    EventDeliveryDriver::try_new(vec!["e1".to_owned()], 2).expect("valid driver")
}

#[test]
fn project_real_event_record_lifecycle() {
    let mut driver = driver();
    driver.init().expect("initialize event record");
    assert_eq!(
        driver.project().expect("project pending"),
        one_event_state(EventLifecycle::Pending, 0, 0)
    );

    driver.lease("e1").expect("lease");
    assert_eq!(
        driver.project().expect("project leased"),
        one_event_state(EventLifecycle::Leased, 0, 0)
    );

    driver.start("e1").expect("start");
    assert_eq!(
        driver.project().expect("project running"),
        one_event_state(EventLifecycle::Running, 1, 0)
    );

    driver.fail("e1").expect("schedule retry");
    assert_eq!(
        driver.project().expect("project retry wait"),
        one_event_state(EventLifecycle::RetryWaiting, 1, 0)
    );

    driver.retry_due("e1").expect("release retry");
    assert_eq!(
        driver.project().expect("project pending retry"),
        one_event_state(EventLifecycle::Pending, 1, 0)
    );

    driver.lease("e1").expect("lease second attempt");
    driver.start("e1").expect("start second attempt");
    driver.fail("e1").expect("exhaust retries");
    assert_eq!(
        driver.project().expect("project dead letter"),
        one_event_state(EventLifecycle::DeadLettered, 2, 0)
    );
}

#[test]
fn project_success_cancel_and_stale_terminals() {
    let mut succeeded = driver();
    succeeded.init().expect("initialize success record");
    succeeded.lease("e1").expect("lease success record");
    succeeded.start("e1").expect("start success record");
    succeeded.succeed("e1").expect("succeed record");
    assert_eq!(
        succeeded.project().expect("project success"),
        one_event_state(EventLifecycle::Succeeded, 1, 0)
    );

    let mut cancelled = driver();
    cancelled.init().expect("initialize cancellation record");
    cancelled.cancel("e1").expect("cancel record");
    assert_eq!(
        cancelled.project().expect("project cancellation"),
        one_event_state(EventLifecycle::Cancelled, 0, 0)
    );

    let mut stale = driver();
    stale.init().expect("initialize stale record");
    stale.reset().expect("advance epoch");
    stale.discard_stale("e1").expect("discard stale record");
    assert_eq!(
        stale.project().expect("project stale discard"),
        one_event_state(EventLifecycle::DiscardedStaleEpoch, 0, 1)
    );
}

#[test]
fn modeled_actions_exclude_the_rust_only_interrupt_transition() {
    assert_eq!(
        MODELED_ACTIONS,
        [
            "Lease",
            "Start",
            "Succeed",
            "Fail",
            "RetryDue",
            "Cancel",
            "Reset",
            "DiscardStale",
        ]
    );
}
