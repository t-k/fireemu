//! Conformance boundary tests for owner-only atomic export publication.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::atomic_export_publication::{
    AtomicExportPublicationConnectDriver, AtomicExportPublicationDriver,
    AtomicExportPublicationState, ProjectionFault, GENERATED_TRACE_SEEDS, MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

fn absolute_spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/AtomicExportPublication.qnt")
}

fn initialized_driver() -> AtomicExportPublicationDriver {
    let mut driver = AtomicExportPublicationDriver::new();
    driver.init().expect("initialize export publication driver");
    driver
}

#[test]
fn partial_stage_is_private_and_invisible_until_real_publish() {
    let mut driver = initialized_driver();
    driver.create().expect("create stage");
    driver.write().expect("write partial stage");
    let partial = driver.project().expect("partial projection");
    assert_eq!(partial.stage_state, "Partial");
    assert_eq!(partial.public_artifact, "Old");
    assert!(partial.stage_private);

    driver.complete().expect("complete stage");
    driver.publish().expect("publish complete stage");
    assert_eq!(
        driver.project().expect("published projection"),
        AtomicExportPublicationState {
            stage_state: "Absent".to_owned(),
            stage_identity: "Absent".to_owned(),
            target_identity: "Original".to_owned(),
            public_artifact: "New".to_owned(),
            stage_private: true,
            public_private: true,
            last_result: "Published".to_owned(),
        }
    );
}

#[test]
fn changed_stage_is_refused_and_never_published_by_the_real_capability() {
    let mut driver = initialized_driver();
    driver.create().expect("create stage");
    driver.write().expect("write stage");
    driver.complete().expect("complete stage");
    driver.swap_stage().expect("replace stage identity");
    assert_eq!(
        driver
            .project()
            .expect("changed stage projection")
            .stage_identity,
        "Changed"
    );

    driver.refuse().expect("refuse changed stage");

    let refused = driver.project().expect("refused projection");
    assert_eq!(refused.stage_identity, "Changed");
    assert_eq!(refused.public_artifact, "Old");
    assert_eq!(refused.last_result, "Refused");
}

#[test]
fn repeated_changed_stage_refusals_preserve_each_replacement() {
    let mut driver = initialized_driver();
    for _ in 0..2 {
        driver.create().expect("create stage");
        driver.write().expect("write stage");
        driver.complete().expect("complete stage");
        driver.swap_stage().expect("replace stage identity");
        driver.refuse().expect("refuse changed stage");
        let refused = driver.project().expect("refused projection");
        assert_eq!(refused.stage_identity, "Changed");
        assert_eq!(refused.public_artifact, "Old");
    }
}

#[test]
fn changed_target_is_refused_and_preserved_by_the_real_capability() {
    let mut driver = initialized_driver();
    driver.create().expect("create stage");
    driver.write().expect("write stage");
    driver.complete().expect("complete stage");
    driver.swap().expect("replace target identity");
    driver.refuse().expect("refuse changed target");
    let refused = driver.project().expect("refused projection");
    assert_eq!(refused.target_identity, "Changed");
    assert_eq!(refused.public_artifact, "Old");
    assert_eq!(refused.last_result, "Refused");
}

#[test]
fn disabled_actions_preserve_every_projected_field() {
    let mut driver = initialized_driver();
    let initial = driver.project().expect("initial projection");
    assert!(driver.write().is_err());
    assert!(driver.complete().is_err());
    assert!(driver.swap().is_err());
    assert!(driver.swap_stage().is_err());
    assert!(driver.refuse().is_err());
    assert!(driver.publish().is_err());
    assert_eq!(driver.project().expect("unchanged projection"), initial);
}

#[test]
fn modeled_action_inventory_is_exact() {
    assert_eq!(
        MODELED_ACTIONS,
        [
            "Create",
            "Write",
            "Complete",
            "Swap",
            "SwapStage",
            "Refuse",
            "Publish"
        ]
    );
}

const PROJECTION_FAULTS: [ProjectionFault; 7] = [
    ProjectionFault::StageState,
    ProjectionFault::StageIdentity,
    ProjectionFault::TargetIdentity,
    ProjectionFault::PublicArtifact,
    ProjectionFault::StagePrivate,
    ProjectionFault::PublicPrivate,
    ProjectionFault::LastResult,
];

#[test]
fn projection_fault_changes_exactly_one_field() {
    for fault in PROJECTION_FAULTS {
        let mut driver = initialized_driver();
        let baseline = driver.project().expect("baseline projection");
        driver.set_projection_fault(fault);
        let perturbed = driver.project().expect("faulted projection");
        let changed = [
            ("stageState", baseline.stage_state != perturbed.stage_state),
            (
                "stageIdentity",
                baseline.stage_identity != perturbed.stage_identity,
            ),
            (
                "targetIdentity",
                baseline.target_identity != perturbed.target_identity,
            ),
            (
                "publicArtifact",
                baseline.public_artifact != perturbed.public_artifact,
            ),
            (
                "stagePrivate",
                baseline.stage_private != perturbed.stage_private,
            ),
            (
                "publicPrivate",
                baseline.public_private != perturbed.public_private,
            ),
            ("lastResult", baseline.last_result != perturbed.last_result),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()], "fault {fault:?}");
    }
}

const SCENARIOS: [&str; 4] = ["publish", "refuse", "replace", "stageReplace"];

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for scenario in SCENARIOS {
        let driver =
            AtomicExportPublicationDriver::new().with_action_recorder(Arc::clone(&recorded));
        let config = RunnerConfig {
            test_name: format!("AtomicExportPublication scenario {scenario}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("AtomicExportPublicationScenarios".to_owned()),
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
fn every_projection_field_detects_drift() {
    for fault in PROJECTION_FAULTS {
        let driver = AtomicExportPublicationDriver::new().with_projection_fault(fault);
        let config = RunnerConfig {
            test_name: format!("AtomicExportPublication projection fault {fault:?}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("AtomicExportPublicationScenarios".to_owned()),
                test: "refuse".to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        let error = run_test(driver, config)
            .expect_err("a perturbed projection must fail Quint Connect comparison");
        assert!(error.to_string().contains("State invariant failed"));
    }
}

fn run_generated(seed: &str, driver: AtomicExportPublicationConnectDriver) -> Result<(), String> {
    let config = RunnerConfig {
        test_name: format!("AtomicExportPublication generated seed {seed}"),
        gen_config: RunConfig {
            spec: absolute_spec_path().to_string_lossy().into_owned(),
            main: Some("AtomicExportPublicationConnect".to_owned()),
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
fn generated_traces_match_the_real_publication_capability() {
    for seed in GENERATED_TRACE_SEEDS {
        run_generated(seed, AtomicExportPublicationConnectDriver::new())
            .unwrap_or_else(|error| panic!("generated campaign failed: {error}"));
    }
}
