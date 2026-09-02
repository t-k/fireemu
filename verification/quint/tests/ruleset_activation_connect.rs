//! Conformance boundary tests for ruleset publication and request snapshots.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::ruleset_activation::{
    ProjectionFault, RulesetActivationConnectDriver, RulesetActivationDriver,
    RulesetActivationState, GENERATED_TRACE_SEEDS, MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

fn absolute_spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/RulesetActivation.qnt")
}

fn initialized_driver() -> RulesetActivationDriver {
    let mut driver = RulesetActivationDriver::new();
    driver.init().expect("initialize ruleset activation driver");
    driver
}

fn initial_state() -> RulesetActivationState {
    RulesetActivationState {
        active_version: "v1".to_owned(),
        generation: 0,
        request_version: BTreeMap::from([
            ("r1".to_owned(), "v1".to_owned()),
            ("r2".to_owned(), "v1".to_owned()),
        ]),
        request_generation: BTreeMap::from([("r1".to_owned(), 0), ("r2".to_owned(), 0)]),
    }
}

#[test]
fn checked_candidate_is_published_as_one_fresh_generation() {
    let mut driver = initialized_driver();
    driver.create().expect("create candidate");
    driver.parse().expect("parse candidate");
    driver.compile().expect("compile candidate");
    assert_eq!(
        driver.project().expect("pre-check projection"),
        initial_state()
    );
    driver.check().expect("check candidate");
    assert_eq!(
        driver.project().expect("pre-activation projection"),
        initial_state()
    );

    driver.activate().expect("activate candidate");
    assert_eq!(
        driver.project().expect("active projection"),
        RulesetActivationState {
            active_version: "v2".to_owned(),
            generation: 1,
            request_version: initial_state().request_version,
            request_generation: initial_state().request_generation,
        }
    );
}

#[test]
fn rejected_candidate_and_disabled_activation_preserve_production_state() {
    let mut driver = initialized_driver();
    assert!(driver.activate().is_err());
    assert_eq!(
        driver.project().expect("disabled projection"),
        initial_state()
    );

    driver.create().expect("create candidate");
    driver.parse().expect("parse candidate");
    driver.reject().expect("reject candidate");
    assert!(driver.activate().is_err());
    assert_eq!(
        driver.project().expect("rejected projection"),
        initial_state()
    );
}

#[test]
fn running_request_retains_v1_across_v2_publication() {
    let mut driver = initialized_driver();
    driver.start_request("r1").expect("start request on v1");
    driver.create().expect("create candidate");
    driver.parse().expect("parse candidate");
    driver.compile().expect("compile candidate");
    driver.check().expect("check candidate");
    driver.activate().expect("activate v2");
    driver
        .progress_request("r1")
        .expect("progress retained v1 request");

    let during = driver.project().expect("running projection");
    assert_eq!(
        (during.active_version.as_str(), during.generation),
        ("v2", 1)
    );
    assert_eq!(
        during.request_version.get("r1").map(String::as_str),
        Some("v1")
    );

    driver
        .finish_request("r1")
        .expect("finish retained request");
    assert_eq!(
        driver
            .project()
            .expect("finished projection")
            .request_version
            .get("r1")
            .map(String::as_str),
        Some("v1")
    );
    driver.start_request("r2").expect("start request on v2");
    assert_eq!(
        driver
            .project()
            .expect("new request projection")
            .request_version
            .get("r2")
            .map(String::as_str),
        Some("v2")
    );
}

#[test]
fn running_request_retains_exact_generation_across_same_source_republication() {
    let mut driver = initialized_driver();
    driver.create().expect("create candidate");
    driver.parse().expect("parse candidate");
    driver.compile().expect("compile candidate");
    driver.check().expect("check candidate");
    driver.activate().expect("activate v2 generation one");
    driver.start_request("r1").expect("start on generation one");
    driver.republish().expect("republish v2 as generation two");
    driver
        .progress_request("r1")
        .expect("progress retained generation one request");
    driver
        .finish_request("r1")
        .expect("finish retained request");

    let projected = driver.project().expect("republished projection");
    assert_eq!(
        (projected.active_version.as_str(), projected.generation),
        ("v2", 2)
    );
    assert_eq!(
        projected.request_version.get("r1").map(String::as_str),
        Some("v2")
    );
    assert_eq!(projected.request_generation.get("r1"), Some(&1));
}

#[test]
fn modeled_action_inventory_is_exact() {
    assert_eq!(
        MODELED_ACTIONS,
        [
            "Create",
            "Parse",
            "Compile",
            "Check",
            "Reject",
            "Activate",
            "Republish",
            "StartRequest",
            "ProgressRequest",
            "FinishRequest",
        ]
    );
}

const PROJECTION_FAULTS: [ProjectionFault; 4] = [
    ProjectionFault::ActiveVersion,
    ProjectionFault::Generation,
    ProjectionFault::RequestVersion,
    ProjectionFault::RequestGeneration,
];

#[test]
fn projection_fault_changes_exactly_one_production_field() {
    for fault in PROJECTION_FAULTS {
        let mut driver = initialized_driver();
        let baseline = driver.project().expect("baseline projection");
        driver.set_projection_fault(fault);
        let perturbed = driver.project().expect("faulted projection");
        let changed = [
            (
                "activeVersion",
                baseline.active_version != perturbed.active_version,
            ),
            ("generation", baseline.generation != perturbed.generation),
            (
                "requestVersion",
                baseline.request_version != perturbed.request_version,
            ),
            (
                "requestGeneration",
                baseline.request_generation != perturbed.request_generation,
            ),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()], "fault {fault:?}");
    }
}

const SCENARIOS: [&str; 4] = ["activate", "reject", "pinRequest", "pinGeneration"];

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for scenario in SCENARIOS {
        let driver = RulesetActivationDriver::new().with_action_recorder(Arc::clone(&recorded));
        let config = RunnerConfig {
            test_name: format!("RulesetActivation scenario {scenario}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("RulesetActivationScenarios".to_owned()),
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
        let driver = RulesetActivationDriver::new().with_projection_fault(fault);
        let config = RunnerConfig {
            test_name: format!("RulesetActivation projection fault {fault:?}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("RulesetActivationScenarios".to_owned()),
                test: "activate".to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        let error = run_test(driver, config)
            .expect_err("a perturbed projection must fail Quint Connect comparison");
        assert!(error.to_string().contains("State invariant failed"));
    }
}

fn run_generated(seed: &str, driver: RulesetActivationConnectDriver) -> Result<(), String> {
    let config = RunnerConfig {
        test_name: format!("RulesetActivation generated seed {seed}"),
        gen_config: RunConfig {
            spec: absolute_spec_path().to_string_lossy().into_owned(),
            main: Some("RulesetActivationConnect".to_owned()),
            init: Some("init".to_owned()),
            step: Some("step".to_owned()),
            max_samples: Some(100),
            max_steps: Some(14),
            seed: seed.to_owned(),
        },
    };
    run_test(driver, config).map_err(|error| format!("seed {seed}: {error:#}"))
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn generated_traces_match_the_real_ruleset_slot() {
    for seed in GENERATED_TRACE_SEEDS {
        run_generated(seed, RulesetActivationConnectDriver::new())
            .unwrap_or_else(|error| panic!("generated campaign failed: {error}"));
    }
}
