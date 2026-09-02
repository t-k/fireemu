//! Production conformance tests for compatibility selection.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::compatibility_selection::{
    CompatibilitySelectionDriver, CompatibilitySelectionState, ProjectionFault,
    GENERATED_TRACE_SEEDS, MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

fn spec() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/CompatibilitySelection.qnt")
}
fn driver() -> CompatibilitySelectionDriver {
    let mut driver = CompatibilitySelectionDriver::new();
    driver.init().unwrap();
    driver
}

#[test]
fn auth_routing_and_node_precedence_use_production_paths() {
    for (case, auth, automatic) in [
        ("default", "default", "node22new"),
        ("unique", "worker-a", "node22new"),
        ("ambiguous", "deny", "node22new"),
        ("concurrentMove", "worker-b", "node22new"),
        ("alias", "default", "node22new"),
        ("capability", "default", "node22new"),
        ("runtime", "default", "node20new"),
        ("engine", "default", "node22new"),
        ("explicit", "default", "node22new"),
    ] {
        let mut driver = driver();
        driver.evaluate(case).unwrap();
        assert_eq!(
            driver.project().unwrap(),
            CompatibilitySelectionState {
                last_case: case.to_owned(),
                auth_decision: auth.to_owned(),
                automatic_node: automatic.to_owned(),
                explicit_node: "node22old".to_owned(),
                store_aliases: false,
            }
        );
    }
}

#[test]
fn projection_faults_change_their_declared_field() {
    for fault in [
        ProjectionFault::AuthDecision,
        ProjectionFault::AutomaticNode,
        ProjectionFault::ExplicitNode,
        ProjectionFault::StoreAliases,
    ] {
        let mut driver = driver();
        driver.evaluate("unique").unwrap();
        let before = driver.project().unwrap();
        driver.set_projection_fault(fault);
        let after = driver.project().unwrap();
        let changed = [
            ("authDecision", before.auth_decision != after.auth_decision),
            (
                "automaticNode",
                before.automatic_node != after.automatic_node,
            ),
            ("explicitNode", before.explicit_node != after.explicit_node),
            ("storeAliases", before.store_aliases != after.store_aliases),
        ]
        .into_iter()
        .filter_map(|(field, changed)| changed.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()]);
    }
}

const SCENARIOS: [&str; 9] = [
    "default",
    "unique",
    "ambiguous",
    "concurrentMove",
    "alias",
    "capability",
    "runtime",
    "engine",
    "explicit",
];

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for scenario in SCENARIOS {
        let driver =
            CompatibilitySelectionDriver::new().with_action_recorder(Arc::clone(&recorded));
        run_test(
            driver,
            RunnerConfig {
                test_name: format!("CompatibilitySelection {scenario}"),
                gen_config: TestConfig {
                    spec: spec().to_string_lossy().into_owned(),
                    main: Some("CompatibilitySelectionScenarios".to_owned()),
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
        ProjectionFault::AuthDecision,
        ProjectionFault::AutomaticNode,
        ProjectionFault::ExplicitNode,
        ProjectionFault::StoreAliases,
    ] {
        let driver = CompatibilitySelectionDriver::new().with_projection_fault(fault);
        let error = run_test(
            driver,
            RunnerConfig {
                test_name: format!("CompatibilitySelection fault {fault:?}"),
                gen_config: TestConfig {
                    spec: spec().to_string_lossy().into_owned(),
                    main: Some("CompatibilitySelectionScenarios".to_owned()),
                    test: "unique".to_owned(),
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
            CompatibilitySelectionDriver::new(),
            RunnerConfig {
                test_name: format!("CompatibilitySelection seed {seed}"),
                gen_config: RunConfig {
                    spec: spec().to_string_lossy().into_owned(),
                    main: Some("CompatibilitySelectionConnect".to_owned()),
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
