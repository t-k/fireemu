//! Production conformance tests for request-local regular expression compilation reuse.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::regex_evaluation_cache::{
    ProjectionFault, RegexEvaluationCacheDriver, RegexEvaluationCacheState, GENERATED_TRACE_SEEDS,
    MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

const CASES: [(&str, u64, u64, usize); 4] = [
    ("literal", 0, 0, 0),
    ("dynamicRepeated", 1, 2, 1),
    ("capacity", 17, 1, 16),
    ("separateEvaluations", 1, 2, 1),
];

fn spec() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/RegexEvaluationCache.qnt")
}

fn driver() -> RegexEvaluationCacheDriver {
    let mut driver = RegexEvaluationCacheDriver::new();
    driver.init().expect("initialize regex cache driver");
    driver
}

#[test]
fn real_evaluator_reports_literal_dynamic_capacity_and_isolation_contracts() {
    for (case, runtime_compiles, cache_hits, peak_cache_entries) in CASES {
        let mut driver = driver();
        driver
            .evaluate(case)
            .unwrap_or_else(|error| panic!("evaluate {case}: {error:#}"));
        assert_eq!(
            driver.project().expect("project regex cache state"),
            RegexEvaluationCacheState {
                last_case: case.to_owned(),
                decision: "Allow".to_owned(),
                runtime_compiles,
                cache_hits,
                peak_cache_entries,
                evaluation_isolation: true,
            },
            "case {case}"
        );
    }
}

#[test]
fn a_second_action_is_rejected_without_changing_the_projection() {
    let mut driver = driver();
    driver.evaluate("literal").expect("first evaluation");
    let before = driver.project().expect("projection before rejection");
    assert!(driver.evaluate("dynamicRepeated").is_err());
    assert_eq!(
        driver.project().expect("projection after rejection"),
        before
    );
}

#[test]
fn projection_faults_change_exactly_their_declared_production_field() {
    for fault in ProjectionFault::ALL {
        let mut driver = driver();
        driver
            .evaluate("dynamicRepeated")
            .expect("dynamic evaluation");
        let before = driver.project().expect("baseline projection");
        driver.set_projection_fault(fault);
        let after = driver.project().expect("perturbed projection");
        let changed = [
            ("decision", before.decision != after.decision),
            (
                "runtimeCompiles",
                before.runtime_compiles != after.runtime_compiles,
            ),
            ("cacheHits", before.cache_hits != after.cache_hits),
            (
                "peakCacheEntries",
                before.peak_cache_entries != after.peak_cache_entries,
            ),
            (
                "evaluationIsolation",
                before.evaluation_isolation != after.evaluation_isolation,
            ),
        ]
        .into_iter()
        .filter_map(|(field, changed)| changed.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()], "fault {fault:?}");
    }
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_the_production_evaluation_action() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for (scenario, _, _, _) in CASES {
        let driver = RegexEvaluationCacheDriver::new().with_action_recorder(Arc::clone(&recorded));
        run_test(
            driver,
            RunnerConfig {
                test_name: format!("RegexEvaluationCache {scenario}"),
                gen_config: TestConfig {
                    spec: spec().to_string_lossy().into_owned(),
                    main: Some("RegexEvaluationCacheScenarios".to_owned()),
                    test: scenario.to_owned(),
                    max_samples: Some(1),
                    seed: "0x1".to_owned(),
                },
            },
        )
        .unwrap_or_else(|error| panic!("scenario {scenario}: {error:#}"));
    }
    assert_eq!(
        recorded.lock().expect("action recorder lock").clone(),
        MODELED_ACTIONS.into_iter().map(str::to_owned).collect()
    );
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn every_production_projection_field_detects_drift() {
    for fault in ProjectionFault::ALL {
        let driver = RegexEvaluationCacheDriver::new().with_projection_fault(fault);
        let error = run_test(
            driver,
            RunnerConfig {
                test_name: format!("RegexEvaluationCache fault {fault:?}"),
                gen_config: TestConfig {
                    spec: spec().to_string_lossy().into_owned(),
                    main: Some("RegexEvaluationCacheScenarios".to_owned()),
                    test: "dynamicRepeated".to_owned(),
                    max_samples: Some(1),
                    seed: "0x1".to_owned(),
                },
            },
        )
        .expect_err("projection fault must fail conformance");
        assert!(error.to_string().contains("State invariant failed"));
    }
}

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn generated_traces_match_the_production_evaluator() {
    for seed in GENERATED_TRACE_SEEDS {
        run_test(
            RegexEvaluationCacheDriver::new(),
            RunnerConfig {
                test_name: format!("RegexEvaluationCache seed {seed}"),
                gen_config: RunConfig {
                    spec: spec().to_string_lossy().into_owned(),
                    main: Some("RegexEvaluationCacheConnect".to_owned()),
                    init: Some("init".to_owned()),
                    step: Some("step".to_owned()),
                    max_samples: Some(100),
                    max_steps: Some(2),
                    seed: seed.to_owned(),
                },
            },
        )
        .unwrap_or_else(|error| panic!("seed {seed}: {error:#}"));
    }
}
