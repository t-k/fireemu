//! Real commit and event-publication checks for the bounded limit rejection model.

use fireemu_verification_quint::limit_rejection::LimitRejectionDriver;

#[test]
fn failed_second_write_preserves_preexisting_documents_and_real_event_accounting() {
    for seeded in [false, true] {
        for kind in ["size", "transforms"] {
            let mut driver = LimitRejectionDriver::new();
            driver.init().unwrap();
            if seeded {
                driver.seed().unwrap();
            }
            assert!(
                driver.configured_index_count() > 0,
                "the catalog preservation check must be non-vacuous"
            );
            let before = driver.project().unwrap();
            driver.begin().unwrap();
            driver.stage("d1").unwrap();
            driver.stage("d2").unwrap();
            driver.attempt(kind).unwrap();
            let after = driver.project().unwrap();
            assert_eq!(after.documents, before.documents);
            assert_eq!(after.outbox, before.outbox);
            assert_eq!(after.reserved_events, before.reserved_events);
            assert_eq!(after.published_events, before.published_events);
            assert_eq!(after.event_generation, before.event_generation);
            assert_eq!(after.transaction_state, "Aborted");
        }
    }
}

#[test]
fn valid_commit_changes_real_document_and_event_projections() {
    let mut driver = LimitRejectionDriver::new();
    driver.init().unwrap();
    driver.begin().unwrap();
    driver.stage("d1").unwrap();
    driver.stage("d2").unwrap();
    driver.attempt("valid").unwrap();
    let after = driver.project().unwrap();
    assert_eq!(
        after.documents.values().copied().collect::<Vec<_>>(),
        vec![1, 1]
    );
    assert_eq!(after.outbox.len(), 2);
    assert!(after.published_events > 0);
    assert_eq!(after.reserved_events, 0);
}

fn spec_path() -> String {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("specs/LimitRejection.qnt")
        .to_string_lossy()
        .into_owned()
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    use fireemu_verification_quint::limit_rejection::MODELED_ACTIONS;
    use quint_connect::runner::{run_test, Config, TestConfig};
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for scenario in ["sizeEmpty", "sizeSeeded", "transformsSeeded", "valid"] {
        run_test(
            LimitRejectionDriver::new().with_action_recorder(Arc::clone(&recorded)),
            Config {
                test_name: format!("LimitRejection {scenario}"),
                gen_config: TestConfig {
                    spec: spec_path(),
                    main: Some("LimitRejectionScenarios".to_owned()),
                    test: scenario.to_owned(),
                    max_samples: Some(1),
                    seed: "0x1".to_owned(),
                },
            },
        )
        .unwrap_or_else(|error| panic!("{scenario}: {error:#}"));
    }
    assert_eq!(
        *recorded.lock().unwrap(),
        MODELED_ACTIONS.into_iter().map(str::to_owned).collect()
    );
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn every_production_projection_field_detects_drift() {
    use fireemu_verification_quint::atomic_commit_outbox::ProjectionFault;
    use quint_connect::runner::{run_test, Config, TestConfig};
    for fault in [
        ProjectionFault::Documents,
        ProjectionFault::Outbox,
        ProjectionFault::TransactionState,
        ProjectionFault::ReservedEvents,
        ProjectionFault::PublishedEvents,
        ProjectionFault::EventGeneration,
    ] {
        let error = run_test(
            LimitRejectionDriver::new().with_projection_fault(fault),
            Config {
                test_name: format!("LimitRejection fault {fault:?}"),
                gen_config: TestConfig {
                    spec: spec_path(),
                    main: Some("LimitRejectionScenarios".to_owned()),
                    test: "sizeSeeded".to_owned(),
                    max_samples: Some(1),
                    seed: "0x1".to_owned(),
                },
            },
        )
        .expect_err("projection perturbation must be detected");
        assert!(
            error.to_string().contains("State invariant failed"),
            "{error:#}"
        );
    }
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn generated_traces_match_actual_limit_refusals() {
    use fireemu_verification_quint::limit_rejection::LimitRejectionConnectDriver;
    use quint_connect::runner::{run_test, Config, RunConfig};
    for seed in ["0x1", "0x2", "0x3", "0x4"] {
        run_test(
            LimitRejectionConnectDriver::default(),
            Config {
                test_name: format!("LimitRejection generated {seed}"),
                gen_config: RunConfig {
                    spec: spec_path(),
                    main: Some("LimitRejectionConnect".to_owned()),
                    init: Some("init".to_owned()),
                    step: Some("step".to_owned()),
                    max_samples: Some(100),
                    max_steps: Some(14),
                    seed: seed.to_owned(),
                },
            },
        )
        .unwrap_or_else(|error| panic!("{seed}: {error:#}"));
    }
}

#[test]
fn seeded_valid_commit_exposes_the_real_publication_delta() {
    let mut driver = LimitRejectionDriver::new();
    driver.init().unwrap();
    driver.seed().unwrap();
    driver.begin().unwrap();
    driver.stage("d1").unwrap();
    driver.stage("d2").unwrap();
    driver.attempt("valid").unwrap();
    let after = driver.project().unwrap();
    assert_eq!(
        after.documents.values().copied().collect::<Vec<_>>(),
        vec![2, 2]
    );
    assert_eq!(after.outbox.len(), 2);
    assert_eq!(after.published_events, 5);
    driver.reset().unwrap();
    let reset = driver.project().unwrap();
    assert_eq!(
        reset.documents.values().copied().collect::<Vec<_>>(),
        vec![0, 0]
    );
    assert_eq!(reset.event_generation, 0);
    assert_eq!(reset.published_events, 0);
}
