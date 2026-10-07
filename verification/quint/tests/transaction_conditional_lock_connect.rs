//! Conformance boundary tests for transaction retries around a conditional lock under
//! production's pessimistic locking.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::{gateway::Gateway, local::LocalBackend};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
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
        age: BTreeMap::from([("c1".to_owned(), 0), ("c2".to_owned(), 0)]),
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

// The read guard closure returns tonic::Status, which clippy calls a large error.
#[allow(clippy::result_large_err)]
#[test]
fn local_contract_idle_expired_lineage_can_retry_with_or_without_a_touch_first() {
    // Pins the local handler ordering of an idle expiry, a Rollback and a retry; production recorded the retry accepted in both orders (P13b, REST).
    for touch_before_rollback in [false, true] {
        let start = 1_788_004_860;
        let clock = Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(start),
        )));
        let backend = LocalBackend::new(
            Gateway {
                enforce_limits: true,
                ctx: PlanningContext {
                    edition: FirestoreEdition::Standard,
                    api_mode: FirestoreApiMode::Native,
                    policy: IndexValidationPolicy::Production,
                },
                indexes: IndexSet::default(),
            },
            Arc::clone(&clock),
            7,
        );
        let database = "projects/demo-local-contract/databases/(default)";
        let transaction = backend
            .begin_transaction(&pb::BeginTransactionRequest {
                database: database.to_owned(),
                options: None,
                ..Default::default()
            })
            .expect("begin local read-write transaction");
        // Advance directly: no compaction or other RPC precedes the first expired call.
        clock
            .lock()
            .expect("clock lock")
            .advance_to(LogicalInstant::from_unix_seconds(start + 125))
            .expect("advance beyond the 120 s strict idle deadline");
        if touch_before_rollback {
            let error = backend
                .get_document(
                    &pb::GetDocumentRequest {
                        name: format!("{database}/documents/controls/missing"),
                        consistency_selector: Some(
                            pb::get_document_request::ConsistencySelector::Transaction(
                                transaction.clone(),
                            ),
                        ),
                        ..Default::default()
                    },
                    &|_, _, _| Ok(()),
                )
                .expect_err("transaction use first expires its lineage");
            assert_eq!(error.code(), tonic::Code::Aborted);
            assert_eq!(
                error.message(),
                "The referenced transaction has expired or is no longer valid."
            );
        }
        backend
            .rollback(&pb::RollbackRequest {
                database: database.to_owned(),
                transaction: transaction.clone(),
                ..Default::default()
            })
            .expect("idle rollback is an idempotent local success");
        let retry = backend.begin_transaction(&pb::BeginTransactionRequest {
            database: database.to_owned(),
            options: Some(pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadWrite(
                    pb::transaction_options::ReadWrite {
                        retry_transaction: transaction.clone(),
                        ..Default::default()
                    },
                )),
            }),
            ..Default::default()
        });
        // Production recorded two orders over REST (P13b, two recordings): no request at all and then the retry (RT-2), and a Rollback and then the retry
        // (RT-3). The order here with `touch_before_rollback` (a read that noticed the expiry, then the Rollback, then the retry) is not recorded in production
        // and this test runs over gRPC. The official emulator accepted it over gRPC (firebase-tools 15.28.2: read, Rollback, retry all answered as accepted
        // or expired and the retry 0), and the gRPC retry of an idle-expired token is a candidate row of the next FS-TRANSACTION packet.
        let next = retry.expect("an idle-expired lineage can retry");
        assert!(!next.is_empty());
        assert_ne!(next, transaction);
        backend
            .rollback(&pb::RollbackRequest {
                database: database.to_owned(),
                transaction: next,
                ..Default::default()
            })
            .expect("release local retry transaction");
    }
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
    // Held back by c2's read lock: not committed, and the protected action cannot run yet.
    assert_eq!(driver.project().expect("held commit").phase["c1"], "Held");
    assert!(!driver.project().expect("held commit").locked);
    assert!(driver.run_protected_action("c1").is_err());
    driver
        .abort_stale("c2")
        .expect("the deadlock victim aborts");
    assert_eq!(
        driver.project().expect("completed commit").phase["c1"],
        "Committed"
    );
    driver
        .run_protected_action("c1")
        .expect("winner runs protected action");
    assert!(driver.release("c1").is_err());
    assert!(driver.project().expect("held lock").locked);

    driver
        .retry("c2")
        .expect("retry begins from aborted lineage");
    driver
        .reject_locked("c2")
        .expect("retry observes committed lock");
    driver.release("c1").expect("release after loser rejects");
    let projected = driver.project().expect("released projection");
    assert!(!projected.locked);
    assert_eq!(projected.acted, BTreeSet::from(["c1".to_owned()]));
}

#[test]
fn either_client_can_be_the_single_winner() {
    for (winner, loser) in [("c1", "c2"), ("c2", "c1")] {
        let mut driver = TransactionConditionalLockDriver::new();
        driver.read_unlocked(winner).unwrap();
        driver.read_unlocked(loser).unwrap();
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

const PROJECTION_FAULTS: [ProjectionFault; 5] = [
    ProjectionFault::Phase,
    ProjectionFault::Age,
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
            ("age", baseline.age != perturbed.age),
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

const SCENARIOS: [&str; 4] = [
    "firstClientWins",
    "secondClientWins",
    "youngerWaitsThenLoses",
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

#[test]
fn older_requester_wins_after_a_younger_commit_waits() {
    let mut driver = TransactionConditionalLockDriver::new();
    read_both(&mut driver);
    driver.commit("c2").expect("younger client waits");
    assert_eq!(driver.project().unwrap().phase["c2"], "Held");
    driver
        .abort_stale("c1")
        .expect("older requester resolves deadlock");
    let projected = driver.project().unwrap();
    assert_eq!(projected.phase["c1"], "Committed");
    assert_eq!(projected.phase["c2"], "Aborted");
    driver.retry("c2").unwrap();
    driver.reject_locked("c2").unwrap();
}
