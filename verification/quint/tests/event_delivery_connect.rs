//! Conformance boundary tests for the Quint event-delivery driver.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::event_delivery::{
    EventDeliveryDriver, EventDeliveryState, EventLifecycle, MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, TestConfig};

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

fn absolute_spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/EventDelivery.qnt")
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

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));

    for scenario in ["success", "retryExhaustion", "staleDiscard", "cancel"] {
        let driver = driver().with_action_recorder(Arc::clone(&recorded));
        let config = RunnerConfig {
            test_name: format!("EventDelivery scenario {scenario}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("EventDeliveryScenarios".to_owned()),
                test: scenario.to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        run_test(driver, config)
            .unwrap_or_else(|error| panic!("scenario {scenario} failed: {error:#}"));
    }

    let actual = recorded.lock().expect("action recorder lock").clone();
    let expected = MODELED_ACTIONS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
}
