//! Conformance boundary tests for production TOTP enrollment and verification.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use fireemu_verification_quint::auth_totp::{
    AuthTotpConnectDriver, AuthTotpDriver, AuthTotpState, ProjectionFault, GENERATED_TRACE_SEEDS,
    MODELED_ACTIONS,
};
use quint_connect::runner::{run_test, Config as RunnerConfig, RunConfig, TestConfig};

fn absolute_spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("specs/AuthTotp.qnt")
}

fn initialized_driver() -> AuthTotpDriver {
    let mut driver = AuthTotpDriver::new();
    driver.init().expect("initialize TOTP driver");
    driver
}

#[test]
fn real_store_accepts_enrollment_at_exact_ttl_and_rejects_ttl_plus_one() {
    let mut at_ttl = initialized_driver();
    at_ttl.start_enrollment().expect("start enrollment");
    at_ttl.advance_seconds(60).expect("advance to exact TTL");
    at_ttl
        .finalize_enrollment(2)
        .expect("finalize at exact TTL");
    assert_eq!(
        at_ttl.project().expect("exact TTL projection").last_result,
        "EnrollmentAccepted"
    );

    let mut after_ttl = initialized_driver();
    after_ttl.start_enrollment().expect("start enrollment");
    after_ttl
        .advance_seconds(61)
        .expect("advance past exact TTL");
    after_ttl
        .expire_enrollment()
        .expect("observe expired enrollment");
    assert_eq!(
        after_ttl.project().expect("expired projection"),
        AuthTotpState {
            factor_count: 0,
            pending_count: 0,
            last_accepted_step: 5,
            last_result: "EnrollmentExpired".to_owned(),
            second_factor_claim: "None".to_owned(),
        }
    );
}

#[test]
fn adjacent_window_codes_are_accepted_and_outside_codes_are_rejected() {
    for (code_step, expected) in [
        (0, "VerificationInvalid"),
        (1, "VerificationAccepted"),
        (2, "VerificationAccepted"),
        (3, "VerificationAccepted"),
        (4, "VerificationInvalid"),
    ] {
        let mut driver = initialized_driver();
        driver.start_enrollment().expect("start enrollment");
        driver.finalize_enrollment(0).expect("finalize enrollment");
        driver.advance_seconds(60).expect("advance to step two");
        driver.verify(code_step).expect("attempt verification");
        assert_eq!(
            driver.project().expect("window projection").last_result,
            expected,
            "code step {code_step}"
        );
    }
}

#[test]
fn replay_older_step_and_factorless_verification_are_rejected() {
    let mut driver = initialized_driver();
    driver.verify(0).expect("factorless verification attempt");
    assert_eq!(
        driver.project().expect("factorless projection").last_result,
        "NoEnrolledFactor"
    );

    driver.start_enrollment().expect("start enrollment");
    driver.finalize_enrollment(0).expect("finalize enrollment");
    driver.advance_seconds(60).expect("advance to step two");
    driver.verify(2).expect("accept current step");
    assert_eq!(
        driver
            .project()
            .expect("accepted projection")
            .second_factor_claim,
        "ValidTotp"
    );
    driver.verify(2).expect("reject replay");
    let replay = driver.project().expect("replay projection");
    assert_eq!(replay.last_result, "VerificationReplayed");
    assert_eq!(replay.second_factor_claim, "None");
    driver.verify(1).expect("reject older step");
    assert_eq!(
        driver.project().expect("older projection").last_result,
        "VerificationReplayed"
    );
}

#[test]
fn debug_and_projection_output_never_expose_totp_material() {
    let mut driver = initialized_driver();
    driver.start_enrollment().expect("start enrollment");
    let diagnostic = driver.redacted_diagnostic().expect("redacted diagnostic");
    assert!(driver.redaction_holds_for_test().expect("redaction check"));
    assert!(diagnostic.contains("[redacted]"));
}

#[test]
fn disabled_actions_preserve_every_production_field() {
    let mut driver = initialized_driver();
    let before = driver.project().expect("initial projection");
    assert!(driver.finalize_enrollment(0).is_err());
    assert!(driver.expire_enrollment().is_err());
    assert_eq!(
        driver.project().expect("projection after rejection"),
        before
    );
}

#[test]
fn modeled_action_inventory_is_exact() {
    assert_eq!(
        MODELED_ACTIONS,
        [
            "Tick",
            "StartEnrollment",
            "FinalizeEnrollment",
            "ExpireEnrollment",
            "Verify",
        ]
    );
}

const PROJECTION_FAULTS: [ProjectionFault; 5] = [
    ProjectionFault::FactorCount,
    ProjectionFault::PendingCount,
    ProjectionFault::LastAcceptedStep,
    ProjectionFault::LastResult,
    ProjectionFault::SecondFactorClaim,
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
                "factorCount",
                baseline.factor_count != perturbed.factor_count,
            ),
            (
                "pendingCount",
                baseline.pending_count != perturbed.pending_count,
            ),
            (
                "lastAcceptedStep",
                baseline.last_accepted_step != perturbed.last_accepted_step,
            ),
            ("lastResult", baseline.last_result != perturbed.last_result),
            (
                "secondFactorClaim",
                baseline.second_factor_claim != perturbed.second_factor_claim,
            ),
        ]
        .into_iter()
        .filter_map(|(field, differs)| differs.then_some(field))
        .collect::<Vec<_>>();
        assert_eq!(changed, vec![fault.field_name()], "fault {fault:?}");
    }
}

const SCENARIOS: [&str; 6] = [
    "enrollAtTtl",
    "expireAfterTtl",
    "verifyAdjacent",
    "rejectOutsideWindow",
    "rejectReplay",
    "rejectWithoutFactor",
];

#[test]
#[ignore = "requires the pinned local Quint CLI"]
fn deterministic_scenarios_cover_all_actions() {
    let recorded = Arc::new(Mutex::new(BTreeSet::new()));
    for scenario in SCENARIOS {
        let driver = AuthTotpDriver::new().with_action_recorder(Arc::clone(&recorded));
        let config = RunnerConfig {
            test_name: format!("AuthTotp scenario {scenario}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("AuthTotpScenarios".to_owned()),
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
        let driver = AuthTotpDriver::new().with_projection_fault(fault);
        let config = RunnerConfig {
            test_name: format!("AuthTotp projection fault {fault:?}"),
            gen_config: TestConfig {
                spec: absolute_spec_path().to_string_lossy().into_owned(),
                main: Some("AuthTotpScenarios".to_owned()),
                test: "rejectWithoutFactor".to_owned(),
                max_samples: Some(1),
                seed: "0x1".to_owned(),
            },
        };
        let error = run_test(driver, config)
            .expect_err("a perturbed projection must fail Quint Connect comparison");
        assert!(error.to_string().contains("State invariant failed"));
    }
}

fn run_generated(seed: &str, driver: AuthTotpConnectDriver) -> Result<(), String> {
    let config = RunnerConfig {
        test_name: format!("AuthTotp generated seed {seed}"),
        gen_config: RunConfig {
            spec: absolute_spec_path().to_string_lossy().into_owned(),
            main: Some("AuthTotpConnect".to_owned()),
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
fn generated_traces_match_the_real_auth_store() {
    for seed in GENERATED_TRACE_SEEDS {
        run_generated(seed, AuthTotpConnectDriver::new())
            .unwrap_or_else(|error| panic!("generated campaign failed: {error}"));
    }
}
