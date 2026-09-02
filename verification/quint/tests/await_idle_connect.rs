//! Conformance boundary tests for the causal await-idle fence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::await_idle::{
    AwaitIdleConnectDriver, AwaitIdleDriver, AwaitIdleState, ProjectionFault,
    GENERATED_TRACE_SEEDS, MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

fn absolute_spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/AwaitIdle.qnt")
}

fn initialized_driver(ignore_text_index: bool) -> AwaitIdleDriver {
    let mut driver = AwaitIdleDriver::new(ignore_text_index);
    driver.init().expect("initialize await-idle driver");
    driver
}

#[test]
fn reservation_handoff_never_projects_false_idle() {
    let mut driver = initialized_driver(false);
    driver
        .begin_external("i1", "invocation")
        .expect("begin parent");
    driver.request_fence().expect("request fence");
    driver
        .complete_with_reservation("i1")
        .expect("reserve child");
    assert_eq!(
        driver.project().expect("reserved projection").reservations,
        BTreeSet::from(["i1".to_owned()])
    );
    assert!(driver.return_idle().is_err());
    driver
        .enqueue_child("i1", "i2", "event")
        .expect("handoff child");
    assert!(driver.return_idle().is_err());
    driver.complete_leaf("i2").expect("complete child");
    driver.return_idle().expect("return after drain");
    assert!(driver.project().expect("returned projection").returned);
}

#[test]
fn fence_rejects_new_external_work_but_explicitly_ignored_text_index_does_not_block() {
    let mut driver = initialized_driver(true);
    driver
        .begin_external("i1", "textIndexBuild")
        .expect("begin build");
    driver.request_fence().expect("request fence");
    assert!(driver.begin_external("i2", "commit").is_err());
    driver.return_idle().expect("ignored build permits return");
    assert_eq!(
        driver.project().expect("projection"),
        AwaitIdleState {
            fence: "returned".to_owned(),
            in_flight: BTreeMap::from([
                ("i1".to_owned(), "textIndexBuild".to_owned()),
                ("i2".to_owned(), String::new()),
                ("i3".to_owned(), String::new()),
            ]),
            reservations: BTreeSet::new(),
            returned: true,
        }
    );
}

#[test]
fn work_identity_cannot_be_reused() {
    let mut driver = initialized_driver(false);
    driver.begin_external("i1", "commit").expect("begin work");
    driver.complete_leaf("i1").expect("complete work");
    assert!(driver.begin_external("i1", "event").is_err());
}

#[test]
fn modeled_action_inventory_is_exact() {
    assert_eq!(
        MODELED_ACTIONS,
        [
            "BeginExternal",
            "CompleteLeaf",
            "CompleteWithReservation",
            "EnqueueChild",
            "RequestFence",
            "ReturnIdle"
        ]
    );
}

const PROJECTION_FAULTS: [ProjectionFault; 4] = [
    ProjectionFault::Fence,
    ProjectionFault::InFlight,
    ProjectionFault::Reservations,
    ProjectionFault::Returned,
];

#[test]
fn projection_fault_changes_exactly_one_production_field() {
    for fault in PROJECTION_FAULTS {
        let mut driver = initialized_driver(false);
        let baseline = driver.project().expect("baseline projection");
        driver.set_projection_fault(fault);
        let perturbed = driver.project().expect("faulted projection");
        let changed = [
            ("fence", baseline.fence != perturbed.fence),
            ("inFlight", baseline.in_flight != perturbed.in_flight),
            (
                "reservations",
                baseline.reservations != perturbed.reservations,
            ),
            ("returned", baseline.returned != perturbed.returned),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()], "fault {fault:?}");
    }
}

const SCENARIOS: [&str; 4] = ["leaf", "reservation", "fence", "ignoreTextIndex"];

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for scenario in SCENARIOS {
        let driver = AwaitIdleDriver::new(false).with_action_recorder(Arc::clone(&recorded));
        let config = RunnerConfig {
            test_name: format!("AwaitIdle scenario {scenario}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("AwaitIdleScenarios".to_owned()),
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
        let driver = AwaitIdleDriver::new(false).with_projection_fault(fault);
        let config = RunnerConfig {
            test_name: format!("AwaitIdle projection fault {fault:?}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("AwaitIdleScenarios".to_owned()),
                test: "reservation".to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        let error =
            run_test(driver, config).expect_err("perturbed projection must fail comparison");
        assert!(error.to_string().contains("State invariant failed"));
    }
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn generated_traces_match_the_real_work_ledger() {
    for seed in GENERATED_TRACE_SEEDS {
        let config = RunnerConfig {
            test_name: format!("AwaitIdle generated seed {seed}"),
            gen_config: RunConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("AwaitIdleConnect".to_owned()),
                init: Some("init".to_owned()),
                step: Some("step".to_owned()),
                max_samples: Some(100),
                max_steps: Some(14),
                seed: seed.to_owned(),
            },
        };
        run_test(AwaitIdleConnectDriver::new(), config)
            .unwrap_or_else(|error| panic!("seed {seed} failed: {error:#}"));
    }
}
