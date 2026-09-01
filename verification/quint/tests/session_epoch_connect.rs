//! Conformance boundary tests for the production session lifecycle and epoch guard.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::session_epoch::{
    ProjectionFault, SessionEpochConnectDriver, SessionEpochDriver, SessionEpochState,
    GENERATED_TRACE_SEEDS, MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

fn absolute_spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/SessionEpoch.qnt")
}

fn initialized_driver() -> SessionEpochDriver {
    let mut driver = SessionEpochDriver::new();
    driver.init().expect("initialize session epoch driver");
    driver
}

#[test]
fn real_session_lifecycle_and_current_epoch_guard_are_connected() {
    let mut driver = initialized_driver();
    assert_eq!(
        driver.project().expect("creating projection"),
        SessionEpochState {
            state: "Creating".to_owned(),
            epoch: 0,
            work_epoch_result: "NotChecked".to_owned(),
        }
    );
    driver.activate().expect("activate session");
    driver.capture_work("w1").expect("capture current work");
    driver.apply_work("w1").expect("apply current work");
    assert_eq!(
        driver
            .project()
            .expect("applied projection")
            .work_epoch_result,
        "Proceed"
    );
}

#[test]
fn stale_work_is_discarded_through_the_real_guard() {
    let mut driver = initialized_driver();
    driver.activate().expect("activate session");
    driver.capture_work("w1").expect("capture epoch zero work");
    driver.begin_reset().expect("advance to epoch one");
    driver.complete_reset().expect("publish epoch one");
    driver.discard_work("w1").expect("discard stale work");
    assert_eq!(
        driver.project().expect("discard projection"),
        SessionEpochState {
            state: "Active".to_owned(),
            epoch: 1,
            work_epoch_result: "DiscardedStaleEpoch".to_owned(),
        }
    );
}

#[test]
fn real_session_can_close_while_reset_is_incomplete() {
    let mut driver = initialized_driver();
    driver.activate().expect("activate session");
    driver.begin_reset().expect("begin reset");
    driver.begin_close().expect("close from resetting");
    driver.complete_close().expect("complete close");
    assert_eq!(driver.project().expect("closed projection").state, "Closed");
}

#[test]
fn disabled_actions_preserve_every_production_field() {
    let mut driver = initialized_driver();
    let before = driver.project().expect("initial projection");
    assert!(driver.begin_reset().is_err());
    assert!(driver.complete_reset().is_err());
    assert!(driver.capture_work("w1").is_err());
    assert!(driver.apply_work("w1").is_err());
    assert!(driver.discard_work("w1").is_err());
    assert_eq!(
        driver.project().expect("projection after rejection"),
        before
    );
}

#[test]
fn modeled_action_inventory_is_exact() {
    assert_eq!(
        MODELED_ACTIONS,
        [
            "Activate",
            "BeginReset",
            "CompleteReset",
            "BeginClose",
            "CompleteClose",
            "CaptureWork",
            "ApplyWork",
            "DiscardWork",
        ]
    );
}

const PROJECTION_FAULTS: [ProjectionFault; 3] = [
    ProjectionFault::State,
    ProjectionFault::Epoch,
    ProjectionFault::WorkEpochResult,
];

#[test]
fn projection_fault_changes_exactly_one_production_field() {
    for fault in PROJECTION_FAULTS {
        let mut driver = initialized_driver();
        let baseline = driver.project().expect("baseline projection");
        driver.set_projection_fault(fault);
        let perturbed = driver.project().expect("faulted projection");
        let changed = [
            ("state", baseline.state != perturbed.state),
            ("epoch", baseline.epoch != perturbed.epoch),
            (
                "workEpochResult",
                baseline.work_epoch_result != perturbed.work_epoch_result,
            ),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()], "fault {fault:?}");
    }
}

const SCENARIOS: [&str; 5] = [
    "activateScenario",
    "applyCurrent",
    "resetScenario",
    "closeScenario",
    "discardStale",
];

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for scenario in SCENARIOS {
        let driver = SessionEpochDriver::new().with_action_recorder(Arc::clone(&recorded));
        let config = RunnerConfig {
            test_name: format!("SessionEpoch scenario {scenario}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("SessionEpochScenarios".to_owned()),
                test: scenario.to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        run_test(driver, config)
            .unwrap_or_else(|error| panic!("scenario {scenario} failed: {error:#}"));
    }
    assert_eq!(
        recorded.lock().expect("action recorder lock").clone(),
        MODELED_ACTIONS.into_iter().map(str::to_owned).collect()
    );
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn every_production_projection_field_detects_drift() {
    for fault in PROJECTION_FAULTS {
        let driver = SessionEpochDriver::new().with_projection_fault(fault);
        let config = RunnerConfig {
            test_name: format!("SessionEpoch projection fault {fault:?}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("SessionEpochScenarios".to_owned()),
                test: "activateScenario".to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        let error = run_test(driver, config)
            .expect_err("a perturbed projection must fail Quint Connect comparison");
        assert!(error.to_string().contains("State invariant failed"));
    }
}

fn run_generated(seed: &str, driver: SessionEpochConnectDriver) -> Result<(), String> {
    let config = RunnerConfig {
        test_name: format!("SessionEpoch generated seed {seed}"),
        gen_config: RunConfig {
            spec: absolute_spec_path().to_string_lossy().into_owned(),
            main: Some("SessionEpochConnect".to_owned()),
            init: Some("init".to_owned()),
            step: Some("step".to_owned()),
            max_samples: Some(100),
            max_steps: Some(20),
            seed: seed.to_owned(),
        },
    };
    run_test(driver, config).map_err(|error| format!("seed {seed}: {error:#}"))
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn generated_traces_match_the_real_session() {
    for seed in GENERATED_TRACE_SEEDS {
        run_generated(seed, SessionEpochConnectDriver::new())
            .unwrap_or_else(|error| panic!("generated campaign failed: {error}"));
    }
}
