//! Conformance boundary tests for optimistic transaction retries around a conditional lock.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::transaction_conditional_lock::{
    ProjectionFault, TransactionConditionalLockConnectDriver, TransactionConditionalLockDriver,
    TransactionConditionalLockState, GENERATED_TRACE_SEEDS, MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

fn absolute_spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/TransactionConditionalLock.qnt")
}

fn initial_state() -> TransactionConditionalLockState {
    TransactionConditionalLockState {
        phase: BTreeMap::from([
            ("c1".to_owned(), "Ready".to_owned()),
            ("c2".to_owned(), "Ready".to_owned()),
        ]),
        locked: false,
        observations: BTreeMap::from([
            ("c1".to_owned(), Vec::new()),
            ("c2".to_owned(), Vec::new()),
        ]),
        acted: BTreeSet::new(),
    }
}

fn read_both(driver: &mut TransactionConditionalLockDriver) {
    driver.read_unlocked("c1").expect("c1 reads unlocked");
    driver.read_unlocked("c2").expect("c2 reads unlocked");
}

fn reject_loser(driver: &mut TransactionConditionalLockDriver, loser: &str) {
    driver.abort_stale(loser).expect("stale commit aborts");
    driver
        .retry(loser)
        .expect("retry begins from aborted lineage");
    driver
        .reject_locked(loser)
        .expect("retry observes committed lock");
}

#[test]
fn stale_commit_aborts_and_retry_reads_the_committed_lock() {
    let mut driver = TransactionConditionalLockDriver::new();
    assert_eq!(
        driver.project().expect("initial projection"),
        initial_state()
    );
    read_both(&mut driver);
    driver.commit("c1").expect("c1 commits lock");
    reject_loser(&mut driver, "c2");

    let projected = driver.project().expect("rejected projection");
    assert!(projected.locked);
    assert_eq!(projected.observations["c1"], [false]);
    assert_eq!(projected.observations["c2"], [false, true]);
    assert_eq!(projected.phase["c1"], "Committed");
    assert_eq!(projected.phase["c2"], "Rejected");
}

#[test]
fn protected_action_and_release_wait_for_the_losing_retry() {
    let mut driver = TransactionConditionalLockDriver::new();
    read_both(&mut driver);
    driver.commit("c1").expect("c1 commits lock");
    driver
        .run_protected_action("c1")
        .expect("winner runs protected action");
    assert!(driver.release("c1").is_err());
    assert!(driver.project().expect("held lock").locked);

    reject_loser(&mut driver, "c2");
    driver.release("c1").expect("release after loser rejects");
    let projected = driver.project().expect("released projection");
    assert!(!projected.locked);
    assert_eq!(projected.acted, BTreeSet::from(["c1".to_owned()]));
}

#[test]
fn either_client_can_be_the_single_winner() {
    for (winner, loser) in [("c1", "c2"), ("c2", "c1")] {
        let mut driver = TransactionConditionalLockDriver::new();
        read_both(&mut driver);
        driver.commit(winner).expect("winner commits lock");
        reject_loser(&mut driver, loser);
        driver
            .run_protected_action(winner)
            .expect("winner runs protected action");
        assert!(driver.run_protected_action(loser).is_err());
        assert_eq!(
            driver.project().expect("winner projection").acted,
            BTreeSet::from([winner.to_owned()])
        );
    }
}

#[test]
fn disabled_actions_preserve_every_projected_field() {
    let mut driver = TransactionConditionalLockDriver::new();
    let initial = driver.project().expect("initial projection");
    assert!(driver.commit("c1").is_err());
    assert!(driver.abort_stale("c1").is_err());
    assert!(driver.retry("c1").is_err());
    assert!(driver.reject_locked("c1").is_err());
    assert!(driver.run_protected_action("c1").is_err());
    assert!(driver.release("c1").is_err());
    assert_eq!(driver.project().expect("unchanged projection"), initial);
}

#[test]
fn modeled_action_inventory_is_exact() {
    assert_eq!(
        MODELED_ACTIONS,
        [
            "ReadUnlocked",
            "Commit",
            "AbortStale",
            "Retry",
            "RejectLocked",
            "RunProtectedAction",
            "Release",
        ]
    );
}

const PROJECTION_FAULTS: [ProjectionFault; 4] = [
    ProjectionFault::Phase,
    ProjectionFault::Locked,
    ProjectionFault::Observations,
    ProjectionFault::Acted,
];

#[test]
fn projection_fault_changes_exactly_one_field() {
    for fault in PROJECTION_FAULTS {
        let mut driver = TransactionConditionalLockDriver::new();
        let baseline = driver.project().expect("baseline projection");
        driver.set_projection_fault(fault);
        let perturbed = driver.project().expect("faulted projection");
        let changed = [
            ("phase", baseline.phase != perturbed.phase),
            ("locked", baseline.locked != perturbed.locked),
            (
                "observations",
                baseline.observations != perturbed.observations,
            ),
            ("acted", baseline.acted != perturbed.acted),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()], "fault {fault:?}");
    }
}

const SCENARIOS: [&str; 3] = [
    "firstClientWins",
    "secondClientWins",
    "retrySeesCommittedLock",
];

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for scenario in SCENARIOS {
        let driver =
            TransactionConditionalLockDriver::new().with_action_recorder(Arc::clone(&recorded));
        let config = RunnerConfig {
            test_name: format!("TransactionConditionalLock scenario {scenario}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("TransactionConditionalLockScenarios".to_owned()),
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
        let driver = TransactionConditionalLockDriver::new().with_projection_fault(fault);
        let config = RunnerConfig {
            test_name: format!("TransactionConditionalLock projection fault {fault:?}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("TransactionConditionalLockScenarios".to_owned()),
                test: "retrySeesCommittedLock".to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        let error = run_test(driver, config)
            .expect_err("a perturbed projection must fail Quint Connect comparison");
        assert!(error.to_string().contains("State invariant failed"));
    }
}

fn run_generated(seed: &str) -> Result<(), String> {
    let config = RunnerConfig {
        test_name: format!("TransactionConditionalLock generated seed {seed}"),
        gen_config: RunConfig {
            spec: absolute_spec_path().to_string_lossy().into_owned(),
            main: Some("TransactionConditionalLockConnect".to_owned()),
            init: Some("init".to_owned()),
            step: Some("step".to_owned()),
            max_samples: Some(100),
            max_steps: Some(20),
            seed: seed.to_owned(),
        },
    };
    run_test(TransactionConditionalLockConnectDriver::new(), config)
        .map_err(|error| format!("seed {seed}: {error:#}"))
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn generated_traces_match_the_real_firestore_state() {
    for seed in GENERATED_TRACE_SEEDS {
        run_generated(seed).unwrap_or_else(|error| panic!("generated campaign failed: {error}"));
    }
}
