//! Conformance boundary tests for atomic Firestore publication and commit changes.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::atomic_commit_outbox::{
    AtomicCommitOutboxConnectDriver, AtomicCommitOutboxDriver, AtomicCommitOutboxState,
    ProjectionFault, GENERATED_TRACE_SEEDS, MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

fn absolute_spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/AtomicCommitOutbox.qnt")
}

fn initialized_driver() -> AtomicCommitOutboxDriver {
    let mut driver = AtomicCommitOutboxDriver::new();
    driver.init().expect("initialize commit driver");
    driver
}

#[test]
fn staging_is_invisible_until_one_real_atomic_commit() {
    let mut driver = initialized_driver();
    driver.begin().expect("begin staging");
    driver.stage_write("d1").expect("stage d1");
    driver.stage_outbox("d1").expect("stage d1 change");
    driver.stage_write("d2").expect("stage d2");
    driver.stage_outbox("d2").expect("stage d2 change");
    assert_eq!(
        driver.project().expect("staged projection"),
        AtomicCommitOutboxState {
            documents: BTreeMap::from([("d1".to_owned(), 0), ("d2".to_owned(), 0)]),
            outbox: BTreeSet::new(),
            transaction_state: "Staging".to_owned(),
        }
    );

    driver.commit().expect("commit staged writes");
    assert_eq!(
        driver.project().expect("committed projection"),
        AtomicCommitOutboxState {
            documents: BTreeMap::from([("d1".to_owned(), 1), ("d2".to_owned(), 1)]),
            outbox: BTreeSet::from(["d1".to_owned(), "d2".to_owned()]),
            transaction_state: "Committed".to_owned(),
        }
    );
}

#[test]
fn real_multi_write_rejection_publishes_neither_documents_nor_changes() {
    let mut driver = initialized_driver();
    driver.begin().expect("begin staging");
    driver.stage_write("d1").expect("stage d1");
    driver.stage_outbox("d1").expect("stage d1 change");
    driver.stage_write("d2").expect("stage d2");
    driver.stage_outbox("d2").expect("stage d2 change");
    driver.detect_conflict().expect("detect conflict");
    driver.abort().expect("abort real rejected batch");
    assert_eq!(
        driver.project().expect("aborted projection"),
        AtomicCommitOutboxState {
            documents: BTreeMap::from([("d1".to_owned(), 0), ("d2".to_owned(), 0)]),
            outbox: BTreeSet::new(),
            transaction_state: "Aborted".to_owned(),
        }
    );
}

#[test]
fn disabled_actions_preserve_every_projected_field() {
    let mut driver = initialized_driver();
    let initial = driver.project().expect("initial projection");
    assert!(driver.stage_write("d1").is_err());
    assert!(driver.stage_outbox("d1").is_err());
    assert!(driver.detect_conflict().is_err());
    assert!(driver.commit().is_err());
    assert!(driver.abort().is_err());
    assert_eq!(driver.project().expect("unchanged projection"), initial);
}

#[test]
fn modeled_action_inventory_is_exact() {
    assert_eq!(
        MODELED_ACTIONS,
        [
            "Begin",
            "StageWrite",
            "StageOutbox",
            "DetectConflict",
            "Commit",
            "Abort",
        ]
    );
}

const PROJECTION_FAULTS: [ProjectionFault; 3] = [
    ProjectionFault::Documents,
    ProjectionFault::Outbox,
    ProjectionFault::TransactionState,
];

#[test]
fn projection_fault_changes_exactly_one_field() {
    for fault in PROJECTION_FAULTS {
        let mut driver = initialized_driver();
        let baseline = driver.project().expect("baseline projection");
        driver.set_projection_fault(fault);
        let perturbed = driver.project().expect("faulted projection");
        let changed = [
            ("documents", baseline.documents != perturbed.documents),
            ("outbox", baseline.outbox != perturbed.outbox),
            (
                "transactionState",
                baseline.transaction_state != perturbed.transaction_state,
            ),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()], "fault {fault:?}");
    }
}

const SCENARIOS: [&str; 3] = ["commit", "conflict", "abort"];

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for scenario in SCENARIOS {
        let driver = AtomicCommitOutboxDriver::new().with_action_recorder(Arc::clone(&recorded));
        let config = RunnerConfig {
            test_name: format!("AtomicCommitOutbox scenario {scenario}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("AtomicCommitOutboxScenarios".to_owned()),
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
        let driver = AtomicCommitOutboxDriver::new().with_projection_fault(fault);
        let config = RunnerConfig {
            test_name: format!("AtomicCommitOutbox projection fault {fault:?}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("AtomicCommitOutboxScenarios".to_owned()),
                test: "abort".to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        let error = run_test(driver, config)
            .expect_err("a perturbed projection must fail Quint Connect comparison");
        assert!(error.to_string().contains("State invariant failed"));
    }
}

fn run_generated(seed: &str, driver: AtomicCommitOutboxConnectDriver) -> Result<(), String> {
    let config = RunnerConfig {
        test_name: format!("AtomicCommitOutbox generated seed {seed}"),
        gen_config: RunConfig {
            spec: absolute_spec_path().to_string_lossy().into_owned(),
            main: Some("AtomicCommitOutboxConnect".to_owned()),
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
fn generated_traces_match_the_real_firestore_state() {
    for seed in GENERATED_TRACE_SEEDS {
        run_generated(seed, AtomicCommitOutboxConnectDriver::new())
            .unwrap_or_else(|error| panic!("generated campaign failed: {error}"));
    }
}
