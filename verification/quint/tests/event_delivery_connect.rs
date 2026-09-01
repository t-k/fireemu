//! Conformance boundary tests for the Quint event-delivery driver.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use fireemu_verification_quint::event_delivery::{
    EventDeliveryConnectDriver, EventDeliveryDriver, EventDeliveryState, EventLifecycle,
    ProjectionFault, GENERATED_TRACE_SEEDS, MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

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

const PROJECTION_FAULTS: [ProjectionFault; 8] = [
    ProjectionFault::State,
    ProjectionFault::Attempts,
    ProjectionFault::MaxAttempts,
    ProjectionFault::CapturedEpoch,
    ProjectionFault::CurrentEpoch,
    ProjectionFault::Terminal,
    ProjectionFault::Cancelled,
    ProjectionFault::Stale,
];

#[test]
fn projection_fault_changes_exactly_one_field() {
    for fault in PROJECTION_FAULTS {
        let mut driver = driver();
        driver.init().expect("initialize projection fixture");
        let baseline = driver.project().expect("baseline projection");
        driver.set_projection_fault(fault);
        let perturbed = driver.project().expect("perturbed projection");

        let changed = [
            ("state", baseline.state != perturbed.state),
            ("attempts", baseline.attempts != perturbed.attempts),
            (
                "maxAttempts",
                baseline.max_attempts != perturbed.max_attempts,
            ),
            (
                "capturedEpoch",
                baseline.captured_epoch != perturbed.captured_epoch,
            ),
            (
                "currentEpoch",
                baseline.current_epoch != perturbed.current_epoch,
            ),
            ("terminal", baseline.terminal != perturbed.terminal),
            ("cancelled", baseline.cancelled != perturbed.cancelled),
            ("stale", baseline.stale != perturbed.stale),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect::<Vec<_>>();

        assert_eq!(changed, vec![fault.field_name()], "fault {fault:?}");
    }
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn each_projection_field_detects_drift() {
    for fault in PROJECTION_FAULTS {
        let driver = driver().with_projection_fault(fault);
        let config = RunnerConfig {
            test_name: format!("EventDelivery projection fault {fault:?}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("EventDeliveryScenarios".to_owned()),
                test: "success".to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        let error = run_test(driver, config)
            .expect_err("a perturbed projection must fail Quint Connect comparison");
        assert!(
            error.to_string().contains("State invariant failed"),
            "scenario success, seed 0x1, fault {fault:?}: {error:#}"
        );
    }

    let temporary = OwnedDirectory::create("fireemu-quint-malformed")
        .expect("create owned malformed-spec directory");
    let source = fs::read_to_string(absolute_spec_path()).expect("read EventDelivery spec");
    let malformed = source
        .replace("maxAttempts: int,", "maxAttempts: str,")
        .replace("maxAttempts: MAX_ATTEMPTS,", "maxAttempts: \"invalid\",")
        .replace(
            "observable.maxAttempts == MAX_ATTEMPTS",
            "observable.maxAttempts == \"invalid\"",
        )
        .replace(
            "previousObservable.maxAttempts == MAX_ATTEMPTS",
            "previousObservable.maxAttempts == \"invalid\"",
        );
    assert_ne!(malformed, source, "malformed fixture mutation must apply");
    let malformed_path = temporary.path().join("EventDelivery.qnt");
    fs::write(&malformed_path, malformed).expect("write malformed EventDelivery spec");

    let config = RunnerConfig {
        test_name: "EventDelivery malformed maxAttempts projection".to_owned(),
        gen_config: TestConfig {
            spec: malformed_path.to_string_lossy().into_owned(),
            main: Some("EventDeliveryScenarios".to_owned()),
            test: "success".to_owned(),
            max_samples: Some(1),
            seed: "0x1".to_owned(),
        },
    };
    let error = run_test(driver(), config)
        .expect_err("an incompatible ITF field type must fail Quint Connect decoding");
    assert!(
        format!("{error:#}").contains("Failed to deserialize specification's state"),
        "scenario success, seed 0x1, malformed maxAttempts: {error:#}"
    );
    temporary
        .close()
        .expect("remove owned malformed-spec directory");
}

struct OwnedDirectory {
    path: PathBuf,
    closed: bool,
}

impl OwnedDirectory {
    fn create(prefix: &str) -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self {
            path,
            closed: false,
        })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn close(mut self) -> io::Result<()> {
        fs::remove_dir_all(&self.path)?;
        self.closed = true;
        Ok(())
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        if !self.closed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn run_generated(
    seed: &str,
    driver: EventDeliveryConnectDriver,
    max_samples: usize,
) -> Result<(), String> {
    let config = RunnerConfig {
        test_name: format!("EventDelivery generated seed {seed}"),
        gen_config: RunConfig {
            spec: absolute_spec_path().to_string_lossy().into_owned(),
            main: Some("EventDeliveryConnect".to_owned()),
            init: Some("init".to_owned()),
            step: Some("step".to_owned()),
            max_samples: Some(max_samples),
            max_steps: Some(20),
            seed: seed.to_owned(),
        },
    };
    run_test(driver, config).map_err(|error| format!("seed {seed}: {error:#}"))
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn generated_traces_match_rust() {
    for seed in GENERATED_TRACE_SEEDS {
        let driver = EventDeliveryConnectDriver::try_new().expect("valid generated-trace driver");
        run_generated(seed, driver, 100)
            .unwrap_or_else(|diagnostic| panic!("generated campaign failed: {diagnostic}"));
    }

    let seed = GENERATED_TRACE_SEEDS[0];
    let driver = EventDeliveryConnectDriver::try_new()
        .expect("valid faulted generated-trace driver")
        .with_projection_fault(ProjectionFault::MaxAttempts);
    let diagnostic = run_generated(seed, driver, 1)
        .expect_err("faulted generated campaign must report a reproducible mismatch");
    assert!(
        diagnostic.contains("State invariant failed"),
        "{diagnostic}"
    );
    assert!(diagnostic.contains(seed), "{diagnostic}");
}
