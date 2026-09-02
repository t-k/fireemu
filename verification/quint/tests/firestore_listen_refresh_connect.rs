//! Production conformance tests for Firestore Listen incremental refresh boundaries.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::firestore_listen_refresh::{
    FirestoreListenRefreshConnectDriver, FirestoreListenRefreshDriver, FirestoreListenRefreshState,
    ProjectionFault, GENERATED_TRACE_SEEDS, MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

fn absolute_spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/FirestoreListenRefresh.qnt")
}

fn initialized_driver() -> FirestoreListenRefreshDriver {
    let mut driver = FirestoreListenRefreshDriver::new();
    driver.init().expect("initialize Firestore Listen driver");
    driver
}

#[test]
fn contiguous_notifications_union_paths_and_match_the_full_projection() {
    let mut driver = initialized_driver();
    driver
        .queue_contiguous("items/a")
        .expect("queue first commit");
    driver
        .queue_contiguous("items/b")
        .expect("queue second commit");
    driver
        .queue_contiguous("items/a")
        .expect("deduplicate repeated path");

    let queued = driver.project().expect("queued projection");
    assert_eq!(queued.through_version, 4);
    assert_eq!(queued.refresh_mode, "Delta");
    assert_eq!(
        queued.changed_paths,
        BTreeSet::from(["items/a".to_owned(), "items/b".to_owned()])
    );

    driver.refresh().expect("execute delta refresh");
    let refreshed = driver.project().expect("refreshed projection");
    assert_eq!(refreshed.last_version, 4);
    assert!(refreshed.incremental_used);
    assert!(refreshed.projection_equivalent);
    assert_eq!(refreshed.examined_count, 2);
}

#[test]
fn gaps_resets_and_unsafe_page_boundaries_fall_back_to_full_queries() {
    let mut gap = initialized_driver();
    gap.queue_gap().expect("queue version gap");
    gap.refresh().expect("refresh version gap");
    assert_full_fallback(&gap.project().expect("gap projection"), 3);

    let mut reset = initialized_driver();
    reset.queue_reset().expect("queue reset");
    let invalidated = reset.project().expect("invalidated reset projection");
    assert_eq!(invalidated.generation, 2);
    assert!(!invalidated.target_current);
    assert!(invalidated.reset_pending);
    reset.refresh().expect("refresh reset");
    let replayed = reset.project().expect("reset projection");
    assert_full_fallback(&replayed, 1);
    assert!(replayed.target_current);
    assert!(!replayed.reset_pending);
    assert_eq!(replayed.replay_count, 1);

    let mut unsafe_query = initialized_driver();
    unsafe_query
        .mark_unsafe()
        .expect("mark limited query unsafe");
    unsafe_query
        .queue_contiguous("items/a")
        .expect("queue commit for limited query");
    unsafe_query.refresh().expect("refresh limited query");
    let projected = unsafe_query.project().expect("unsafe projection");
    assert!(!projected.safe_query);
    assert_full_fallback(&projected, 2);

    unsafe_query
        .queue_contiguous("items/b")
        .expect("queue later commit for still-limited query");
    unsafe_query.refresh().expect("refresh still-limited query");
    assert_full_fallback(&unsafe_query.project().expect("later unsafe projection"), 3);
}

#[test]
fn fifty_targets_examine_one_changed_document_each() {
    let mut driver = initialized_driver();
    driver
        .set_fifty_targets()
        .expect("install bounded target population");
    driver
        .queue_contiguous("items/a")
        .expect("queue one changed document");
    driver.refresh().expect("refresh fifty targets");

    let projected = driver.project().expect("fifty-target projection");
    assert_eq!(projected.target_count, 50);
    assert_eq!(projected.examined_count, 50);
    assert!(projected.incremental_used);
    assert!(projected.projection_equivalent);
}

fn assert_full_fallback(state: &FirestoreListenRefreshState, expected_version: u64) {
    assert_eq!(state.last_version, expected_version);
    assert_eq!(state.refresh_mode, "Idle");
    assert_eq!(state.last_reason, "full");
    assert!(!state.incremental_used);
    assert_eq!(state.examined_count, 0);
    assert!(state.projection_equivalent);
}

const PROJECTION_FAULTS: [ProjectionFault; 14] = [
    ProjectionFault::Generation,
    ProjectionFault::LastVersion,
    ProjectionFault::ThroughVersion,
    ProjectionFault::RefreshMode,
    ProjectionFault::ChangedPaths,
    ProjectionFault::SafeQuery,
    ProjectionFault::TargetCount,
    ProjectionFault::ExaminedCount,
    ProjectionFault::ProjectionEquivalent,
    ProjectionFault::IncrementalUsed,
    ProjectionFault::TargetCurrent,
    ProjectionFault::ResetPending,
    ProjectionFault::ReplayCount,
    ProjectionFault::LastReason,
];

#[test]
fn projection_faults_change_exactly_their_declared_field() {
    for fault in PROJECTION_FAULTS {
        let mut driver = initialized_driver();
        driver
            .queue_contiguous("items/a")
            .expect("queue projection fixture");
        driver.refresh().expect("refresh projection fixture");
        let before = driver.project().expect("baseline projection");
        driver.set_projection_fault(fault);
        let after = driver.project().expect("faulted projection");
        let changed = [
            ("generation", before.generation != after.generation),
            ("lastVersion", before.last_version != after.last_version),
            (
                "throughVersion",
                before.through_version != after.through_version,
            ),
            ("refreshMode", before.refresh_mode != after.refresh_mode),
            ("changedPaths", before.changed_paths != after.changed_paths),
            ("safeQuery", before.safe_query != after.safe_query),
            ("targetCount", before.target_count != after.target_count),
            (
                "examinedCount",
                before.examined_count != after.examined_count,
            ),
            (
                "projectionEquivalent",
                before.projection_equivalent != after.projection_equivalent,
            ),
            (
                "incrementalUsed",
                before.incremental_used != after.incremental_used,
            ),
            (
                "targetCurrent",
                before.target_current != after.target_current,
            ),
            ("resetPending", before.reset_pending != after.reset_pending),
            ("replayCount", before.replay_count != after.replay_count),
            ("lastReason", before.last_reason != after.last_reason),
        ]
        .into_iter()
        .filter_map(|(field, changed)| changed.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()], "fault {fault:?}");
    }
}

const SCENARIOS: [&str; 7] = [
    "contiguous",
    "pathUnion",
    "gap",
    "reset",
    "generationReset",
    "unsafe",
    "fiftyTargets",
];

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for scenario in SCENARIOS {
        let driver =
            FirestoreListenRefreshDriver::new().with_action_recorder(Arc::clone(&recorded));
        run_test(
            driver,
            RunnerConfig {
                test_name: format!("FirestoreListenRefresh scenario {scenario}"),
                gen_config: TestConfig {
                    spec: absolute_spec_path().to_string_lossy().into_owned(),
                    main: Some("FirestoreListenRefreshScenarios".to_owned()),
                    test: scenario.to_owned(),
                    max_samples: Some(1),
                    seed: "0x1".to_owned(),
                },
            },
        )
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
        let driver = FirestoreListenRefreshDriver::new().with_projection_fault(fault);
        let error = run_test(
            driver,
            RunnerConfig {
                test_name: format!("FirestoreListenRefresh projection fault {fault:?}"),
                gen_config: TestConfig {
                    spec: absolute_spec_path().to_string_lossy().into_owned(),
                    main: Some("FirestoreListenRefreshScenarios".to_owned()),
                    test: "contiguous".to_owned(),
                    max_samples: Some(1),
                    seed: "0x1".to_owned(),
                },
            },
        )
        .expect_err("a perturbed projection must fail Quint Connect comparison");
        assert!(error.to_string().contains("State invariant failed"));
    }
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn generated_traces_match_production_query_execution() {
    for seed in GENERATED_TRACE_SEEDS {
        run_test(
            FirestoreListenRefreshConnectDriver::new(),
            RunnerConfig {
                test_name: format!("FirestoreListenRefresh generated seed {seed}"),
                gen_config: RunConfig {
                    spec: absolute_spec_path().to_string_lossy().into_owned(),
                    main: Some("FirestoreListenRefreshConnect".to_owned()),
                    init: Some("init".to_owned()),
                    step: Some("step".to_owned()),
                    max_samples: Some(100),
                    max_steps: Some(20),
                    seed: seed.to_owned(),
                },
            },
        )
        .unwrap_or_else(|error| panic!("generated campaign failed for seed {seed}: {error:#}"));
    }
}
