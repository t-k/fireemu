//! Production conformance tests for bounded linear repeated alternatives.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::regex_linear_repeat::{
    ProjectionFault, RegexLinearRepeatDriver, RegexLinearRepeatState, GENERATED_TRACE_SEEDS,
    MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

fn spec() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/RegexLinearRepeat.qnt")
}
fn driver() -> RegexLinearRepeatDriver {
    let mut driver = RegexLinearRepeatDriver::new();
    driver.init().unwrap();
    driver
}

#[test]
fn production_diagnostics_distinguish_branch_charges_depth_and_failure() {
    for (case, outcome, work, depth) in [
        ("atomicFirst", "Matched", "FirstBranch", "Constant"),
        ("atomicThird", "Matched", "ThirdBranch", "Constant"),
        ("forbidden", "NotMatched", "Rejected", "Constant"),
        ("nonAtomic", "Matched", "Fallback", "Nested"),
        ("exhausted", "Exhausted", "Exhausted", "Constant"),
    ] {
        let mut driver = driver();
        driver.evaluate(case).unwrap();
        assert_eq!(
            driver.project().unwrap(),
            RegexLinearRepeatState {
                last_case: case.to_owned(),
                outcome: outcome.to_owned(),
                work_class: work.to_owned(),
                depth_class: depth.to_owned(),
                probe_accounting: "Charged".to_owned(),
            },
            "case {case}"
        );
    }
}

#[test]
fn projection_faults_change_their_declared_field() {
    for fault in [
        ProjectionFault::Outcome,
        ProjectionFault::WorkClass,
        ProjectionFault::DepthClass,
        ProjectionFault::ProbeAccounting,
    ] {
        let mut driver = driver();
        driver.evaluate("atomicFirst").unwrap();
        let before = driver.project().unwrap();
        driver.set_projection_fault(fault);
        let after = driver.project().unwrap();
        let changed = [
            ("outcome", before.outcome != after.outcome),
            ("workClass", before.work_class != after.work_class),
            ("depthClass", before.depth_class != after.depth_class),
            (
                "probeAccounting",
                before.probe_accounting != after.probe_accounting,
            ),
        ]
        .into_iter()
        .filter_map(|(field, changed)| changed.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()]);
    }
}

const SCENARIOS: [&str; 5] = [
    "atomicFirst",
    "atomicThird",
    "forbidden",
    "nonAtomic",
    "exhausted",
];

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for scenario in SCENARIOS {
        let driver = RegexLinearRepeatDriver::new().with_action_recorder(Arc::clone(&recorded));
        run_test(
            driver,
            RunnerConfig {
                test_name: format!("RegexLinearRepeat {scenario}"),
                gen_config: TestConfig {
                    spec: spec().to_string_lossy().into_owned(),
                    main: Some("RegexLinearRepeatScenarios".to_owned()),
                    test: scenario.to_owned(),
                    max_samples: Some(1),
                    seed: "0x1".to_owned(),
                },
            },
        )
        .unwrap();
    }
    assert_eq!(
        recorded.lock().unwrap().clone(),
        MODELED_ACTIONS.into_iter().map(str::to_owned).collect()
    );
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn every_projection_field_detects_drift() {
    for fault in [
        ProjectionFault::Outcome,
        ProjectionFault::WorkClass,
        ProjectionFault::DepthClass,
        ProjectionFault::ProbeAccounting,
    ] {
        let driver = RegexLinearRepeatDriver::new().with_projection_fault(fault);
        let error = run_test(
            driver,
            RunnerConfig {
                test_name: format!("RegexLinearRepeat fault {fault:?}"),
                gen_config: TestConfig {
                    spec: spec().to_string_lossy().into_owned(),
                    main: Some("RegexLinearRepeatScenarios".to_owned()),
                    test: "atomicFirst".to_owned(),
                    max_samples: Some(1),
                    seed: "0x1".to_owned(),
                },
            },
        )
        .expect_err("fault must be detected");
        assert!(error.to_string().contains("State invariant failed"));
    }
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn generated_traces_match_production() {
    for seed in GENERATED_TRACE_SEEDS {
        run_test(
            RegexLinearRepeatDriver::new(),
            RunnerConfig {
                test_name: format!("RegexLinearRepeat seed {seed}"),
                gen_config: RunConfig {
                    spec: spec().to_string_lossy().into_owned(),
                    main: Some("RegexLinearRepeatConnect".to_owned()),
                    init: Some("init".to_owned()),
                    step: Some("step".to_owned()),
                    max_samples: Some(100),
                    max_steps: Some(2),
                    seed: seed.to_owned(),
                },
            },
        )
        .unwrap();
    }
}
