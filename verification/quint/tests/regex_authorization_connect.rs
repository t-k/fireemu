//! Conformance boundary tests for the real rules evaluator and regex budgets.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::regex_authorization::{
    ProjectionFault, RegexAuthorizationConnectDriver, RegexAuthorizationDriver,
    RegexAuthorizationState, GENERATED_TRACE_SEEDS, MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

const CASES: [(&str, &str, &str); 6] = [
    ("matched", "Allow", "None"),
    ("notMatched", "Deny", "RuleMismatch"),
    ("stepExhausted", "Deny", "FIREEMU-REGEX-STEPS-PER-MATCH"),
    ("depthExhausted", "Deny", "FIREEMU-REGEX-DEPTH-PER-MATCH"),
    ("parentNegated", "Deny", "RuleMismatch"),
    ("nestedNegated", "Allow", "None"),
];

fn absolute_spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/RegexAuthorization.qnt")
}

fn initialized_driver() -> RegexAuthorizationDriver {
    let mut driver = RegexAuthorizationDriver::new();
    driver
        .init()
        .expect("initialize regex authorization driver");
    driver
}

#[test]
fn real_evaluator_covers_matches_negations_and_both_budget_limits() {
    for (case, decision, denial_class) in CASES {
        let mut driver = initialized_driver();
        driver
            .evaluate(case)
            .unwrap_or_else(|error| panic!("evaluate {case}: {error:#}"));
        assert_eq!(
            driver.project().expect("project evaluation"),
            RegexAuthorizationState {
                last_case: case.to_owned(),
                decision: decision.to_owned(),
                denial_class: denial_class.to_owned(),
            },
            "case {case}"
        );
    }
}

#[test]
fn disabled_evaluation_preserves_the_production_projection() {
    let mut driver = initialized_driver();
    driver.evaluate("matched").expect("first evaluation");
    let before = driver.project().expect("projection before disabled action");
    assert!(driver.evaluate("notMatched").is_err());
    assert_eq!(
        driver.project().expect("projection after rejection"),
        before
    );
}

#[test]
fn modeled_action_inventory_is_exact() {
    assert_eq!(MODELED_ACTIONS, ["Evaluate"]);
}

const PROJECTION_FAULTS: [ProjectionFault; 2] =
    [ProjectionFault::Decision, ProjectionFault::DenialClass];

#[test]
fn projection_fault_changes_exactly_one_production_field() {
    for fault in PROJECTION_FAULTS {
        let mut driver = initialized_driver();
        driver.evaluate("matched").expect("matched evaluation");
        let baseline = driver.project().expect("baseline projection");
        driver.set_projection_fault(fault);
        let perturbed = driver.project().expect("faulted projection");
        let changed = [
            ("decision", baseline.decision != perturbed.decision),
            (
                "denialClass",
                baseline.denial_class != perturbed.denial_class,
            ),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()], "fault {fault:?}");
    }
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_every_real_evaluator_class() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for (scenario, _, _) in CASES {
        let driver = RegexAuthorizationDriver::new().with_action_recorder(Arc::clone(&recorded));
        let config = RunnerConfig {
            test_name: format!("RegexAuthorization scenario {scenario}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("RegexAuthorizationScenarios".to_owned()),
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
        BTreeSet::from(["Evaluate".to_owned()])
    );
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn each_production_projection_field_detects_drift() {
    for fault in PROJECTION_FAULTS {
        let driver = RegexAuthorizationDriver::new().with_projection_fault(fault);
        let config = RunnerConfig {
            test_name: format!("RegexAuthorization projection fault {fault:?}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("RegexAuthorizationScenarios".to_owned()),
                test: "matched".to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        let error = run_test(driver, config)
            .expect_err("a perturbed production projection must fail Quint Connect");
        assert!(
            error.to_string().contains("State invariant failed"),
            "fault {fault:?}: {error:#}"
        );
    }
}

fn run_generated(seed: &str, driver: RegexAuthorizationConnectDriver) -> Result<(), String> {
    let config = RunnerConfig {
        test_name: format!("RegexAuthorization generated seed {seed}"),
        gen_config: RunConfig {
            spec: absolute_spec_path().to_string_lossy().into_owned(),
            main: Some("RegexAuthorizationConnect".to_owned()),
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
fn generated_traces_match_the_real_evaluator() {
    for seed in GENERATED_TRACE_SEEDS {
        run_generated(seed, RegexAuthorizationConnectDriver::new())
            .unwrap_or_else(|error| panic!("generated campaign failed: {error}"));
    }
}
