//! The verdict the Admin SDK instrumentation asks for (HTTP Functions, `verifyToken`).
//!
//! The strict policy must agree with the callable boundary's `classify` on every snapshot;
//! the one production-parity switch (`D3`, a future `iat`) may only relax that one check and
//! never mask an epoch, signature, expiry, claim or app fault. `D2` (an unknown or disabled app)
//! is refused under every policy.

mod support;

use std::sync::{Arc, RwLock};

use fireemu_core_app_check::admin::{
    admin_rejection_for, admin_verdict, AdminPolicy, AdminRejection, AdminVerdict,
};
use fireemu_core_app_check::admission::AppCheckGate;
use fireemu_core_app_check::claims::{issuer_for, AppCheckClaims};
use fireemu_core_app_check::header::HeaderClassification;
use fireemu_core_app_check::jwt::encode;
use fireemu_core_app_check::observe::{CredentialCategory, FUNCTIONS_SERVICE};
use fireemu_core_app_check::registry::{AppCheckRegistry, AppRegistration};
use fireemu_core_app_check::verify::{
    classify, AppCheckCredentialState, AppCheckFailure, BaselineMode,
};
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;
use support::{fixture_registry, seeded_epoch, TestSigner, DEMO_APP_ID, OTHER_APP_ID};

const START: i64 = 1_788_004_860;

fn now(offset: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(START + offset)
}

fn issue(registry: &AppCheckRegistry, signer: &TestSigner, project: &str, app: &str) -> String {
    let claims = registry
        .issue_claims(project, app, now(0))
        .expect("the fixture app is registered and enabled");
    encode(&claims, signer)
}

fn claims_of(registry: &AppCheckRegistry, sub: &str, iat: i64, exp: i64) -> AppCheckClaims {
    AppCheckClaims {
        iss: issuer_for("1234567890"),
        sub: sub.to_owned(),
        aud: vec![
            "projects/1234567890".to_owned(),
            "projects/demo-app".to_owned(),
        ],
        iat,
        exp,
        jti: "manual-1".to_owned(),
        fireemu_epoch: registry.project_epoch("demo-app").unwrap().claim_text(),
    }
}

const STRICT: AdminPolicy = AdminPolicy::STRICT;
const RULED: AdminPolicy = AdminPolicy::OWNER_RULINGS;

fn verdict(
    registry: &AppCheckRegistry,
    signer: &TestSigner,
    token: &str,
    p: AdminPolicy,
) -> AdminVerdict {
    admin_verdict(token, registry, "demo-app", signer, now(0), p)
}

fn reject(r: AdminRejection) -> AdminVerdict {
    AdminVerdict::Reject(r)
}

#[test]
fn every_failure_maps_to_exactly_one_wire_reason_and_back() {
    use AppCheckFailure::*;
    let table = [
        (Malformed, AdminRejection::Malformed),
        (UnsupportedAlgorithm, AdminRejection::Malformed),
        (UnknownKeyId, AdminRejection::NoMatchingKid),
        (WrongEpoch, AdminRejection::NoMatchingKid),
        (BadSignature, AdminRejection::InvalidSignature),
        (Expired, AdminRejection::TokenExpired),
        (NotYetValid, AdminRejection::NotYetValid),
        (WrongIssuer, AdminRejection::Claims),
        (WrongAudience, AdminRejection::Claims),
        (WrongProject, AdminRejection::Claims),
        (UnknownApp, AdminRejection::UnknownApp),
        (AppDisabled, AdminRejection::UnknownApp),
    ];
    for (failure, expected) in table {
        assert_eq!(admin_rejection_for(failure), expected, "{failure:?}");
    }
    let wires: Vec<&str> = AdminRejection::ALL.iter().map(|r| r.wire()).collect();
    let mut unique = wires.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        AdminRejection::ALL.len(),
        "wire names are distinct"
    );
    for rejection in AdminRejection::ALL {
        assert_eq!(
            AdminRejection::parse_wire(rejection.wire()),
            Some(rejection)
        );
    }
    assert_eq!(AdminRejection::parse_wire("accept"), None);
    assert_eq!(AdminRejection::parse_wire(""), None);
}

#[test]
fn a_current_token_is_accepted_and_every_fault_is_refused_under_the_strict_policy() {
    let mut registry = fixture_registry();
    let signer = TestSigner::new(1);
    let token = issue(&registry, &signer, "demo-app", DEMO_APP_ID);
    assert_eq!(
        verdict(&registry, &signer, &token, STRICT),
        AdminVerdict::Accept
    );

    // Forged signature and another instance's key.
    let mut forged = token.clone();
    forged.push('A');
    assert_eq!(
        verdict(&registry, &signer, &forged, STRICT),
        reject(AdminRejection::InvalidSignature)
    );
    let foreign = TestSigner::new(2);
    assert_eq!(
        verdict(&registry, &foreign, &token, STRICT),
        reject(AdminRejection::NoMatchingKid)
    );

    // Expired and future.
    assert_eq!(
        admin_verdict(&token, &registry, "demo-app", &signer, now(3600), STRICT),
        reject(AdminRejection::TokenExpired)
    );
    let future = encode(
        &claims_of(&registry, DEMO_APP_ID, START + 60, START + 3660),
        &signer,
    );
    assert_eq!(
        verdict(&registry, &signer, &future, STRICT),
        reject(AdminRejection::NotYetValid)
    );

    // Another project's token and an unknown app.
    let other = issue(&registry, &signer, "demo-other", OTHER_APP_ID);
    assert_eq!(
        verdict(&registry, &signer, &other, STRICT),
        reject(AdminRejection::Claims)
    );
    let ghost = encode(
        &claims_of(&registry, "1:1234567890:web:ghost", START, START + 3600),
        &signer,
    );
    assert_eq!(
        verdict(&registry, &signer, &ghost, STRICT),
        reject(AdminRejection::UnknownApp)
    );

    // A reset of the project, and then of another project only.
    registry.set_project_epoch("demo-other", seeded_epoch(70));
    assert_eq!(
        verdict(&registry, &signer, &token, STRICT),
        AdminVerdict::Accept
    );
    registry.set_project_epoch("demo-app", seeded_epoch(71));
    assert_eq!(
        verdict(&registry, &signer, &token, STRICT),
        reject(AdminRejection::NoMatchingKid)
    );
}

#[test]
fn an_unknown_or_disabled_app_is_refused_under_every_policy() {
    let mut registry = AppCheckRegistry::new(3600).unwrap();
    registry
        .register_app(AppRegistration {
            project_id: "demo-app".to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: DEMO_APP_ID.to_owned(),
            enabled: false,
            debug_token_digests: Vec::new(),
        })
        .unwrap();
    registry.set_project_epoch("demo-app", seeded_epoch(3));
    let signer = TestSigner::new(1);
    for sub in [DEMO_APP_ID, "1:1234567890:web:ghost"] {
        let token = encode(&claims_of(&registry, sub, START, START + 3600), &signer);
        for policy in [STRICT, RULED] {
            assert_eq!(
                verdict(&registry, &signer, &token, policy),
                reject(AdminRejection::UnknownApp),
                "{sub} under {policy:?}"
            );
        }
    }
}

#[test]
fn the_future_iat_ruling_never_masks_an_epoch_signature_expiry_or_claim_fault() {
    let mut registry = fixture_registry();
    let signer = TestSigner::new(1);
    // A future token is accepted under the ruling and refused under the strict policy ...
    let future = encode(
        &claims_of(&registry, DEMO_APP_ID, START + 60, START + 3660),
        &signer,
    );
    assert_eq!(
        verdict(&registry, &signer, &future, RULED),
        AdminVerdict::Accept
    );
    assert_eq!(
        verdict(&registry, &signer, &future, STRICT),
        reject(AdminRejection::NotYetValid)
    );
    // ... a future token for an unknown app is still an unknown app ...
    let future_ghost = encode(
        &claims_of(
            &registry,
            "1:1234567890:web:ghost",
            START + 60,
            START + 3660,
        ),
        &signer,
    );
    assert_eq!(
        verdict(&registry, &signer, &future_ghost, RULED),
        reject(AdminRejection::UnknownApp)
    );
    // ... and once the project is reset the epoch fault is reported, not the iat.
    registry.set_project_epoch("demo-app", seeded_epoch(90));
    assert_eq!(
        verdict(&registry, &signer, &future, RULED),
        reject(AdminRejection::NoMatchingKid)
    );
    // Bad signature, wrong key and expiry still refuse.
    let fresh = encode(
        &claims_of(&registry, DEMO_APP_ID, START, START + 3600),
        &signer,
    );
    assert_eq!(
        verdict(&registry, &signer, &fresh, RULED),
        AdminVerdict::Accept
    );
    let mut forged = fresh.clone();
    forged.push('A');
    assert_eq!(
        verdict(&registry, &signer, &forged, RULED),
        reject(AdminRejection::InvalidSignature)
    );
    assert_eq!(
        admin_verdict(&fresh, &registry, "demo-app", &signer, now(3600), RULED),
        reject(AdminRejection::TokenExpired)
    );
    // The ruling does not reach another project's token.
    let other = issue(&registry, &signer, "demo-other", OTHER_APP_ID);
    assert_eq!(
        verdict(&registry, &signer, &other, RULED),
        reject(AdminRejection::Claims)
    );
}

/// D2 and D3 are decided in `AdminPolicy::OWNER_RULINGS` alone (owner rulings 1795 and 1796).
#[test]
fn the_owner_rulings_are_isolated_in_one_constant() {
    // D3: a future iat verifies, as in production. D2 has no switch at all.
    assert_eq!(
        AdminPolicy::OWNER_RULINGS,
        AdminPolicy {
            accept_future_iat: true
        }
    );
    assert_eq!(
        AdminPolicy::STRICT,
        AdminPolicy {
            accept_future_iat: false
        }
    );
}

#[test]
fn the_gate_records_one_secret_free_observation_and_ignores_other_projects() {
    let gate = AppCheckGate::new(
        Arc::new(RwLock::new(fixture_registry())),
        Arc::new(TestSigner::new(1)),
    );
    let signer = TestSigner::new(1);
    let token = {
        let registry = gate.registry().read().unwrap();
        issue(&registry, &signer, "demo-app", DEMO_APP_ID)
    };
    let generation = || {
        gate.registry()
            .read()
            .unwrap()
            .policy_generation("demo-app")
    };
    let first_generation = generation();
    assert_eq!(
        gate.verify_for_admin("demo-app", &token, now(0), STRICT),
        AdminVerdict::Accept
    );
    // Another project's reset changes nothing for this project.
    gate.set_epochs(&[("demo-other".to_owned(), seeded_epoch(55))]);
    assert_eq!(
        gate.verify_for_admin("demo-app", &token, now(0), STRICT),
        AdminVerdict::Accept
    );
    assert_eq!(
        generation(),
        first_generation,
        "another project's reset does not bump this one's generation"
    );
    gate.set_epochs(&[("demo-app".to_owned(), seeded_epoch(56))]);
    assert_eq!(
        gate.verify_for_admin("demo-app", &token, now(0), STRICT),
        reject(AdminRejection::NoMatchingKid)
    );
    let observations = gate.registry().read().unwrap().observations("demo-app");
    assert_eq!(observations.len(), 3);
    assert!(observations
        .iter()
        .all(|o| o.service == FUNCTIONS_SERVICE && o.operation == "verifyToken"));
    assert!(observations
        .iter()
        .all(|o| o.mode == BaselineMode::Unenforced && o.transport == "http"));
    assert_eq!(observations[0].category, CredentialCategory::Valid);
    assert_eq!(observations[0].app_id, DEMO_APP_ID);
    assert_eq!(observations[2].category, CredentialCategory::Invalid);
    assert_eq!(observations[2].failure, Some(AppCheckFailure::WrongEpoch));
    assert_eq!(
        observations.iter().map(|o| o.admitted).collect::<Vec<_>>(),
        [true, true, false],
        "an observation is admitted exactly when the verdict accepted"
    );
    assert_eq!(
        observations
            .iter()
            .map(|o| o.policy_generation)
            .collect::<Vec<_>>(),
        [first_generation, first_generation, generation()],
        "each observation carries the policy generation it was decided under"
    );
    assert_ne!(generation(), first_generation);
    for observation in &observations {
        assert!(!format!("{observation:?}").contains(&token));
    }
    // The other project saw nothing.
    assert!(gate
        .registry()
        .read()
        .unwrap()
        .observations("demo-other")
        .is_empty());
}

#[test]
fn the_gate_applies_the_policy_it_is_given() {
    let gate = AppCheckGate::new(
        Arc::new(RwLock::new(fixture_registry())),
        Arc::new(TestSigner::new(1)),
    );
    let signer = TestSigner::new(1);
    let future = {
        let registry = gate.registry().read().unwrap();
        encode(
            &claims_of(&registry, DEMO_APP_ID, START + 60, START + 3660),
            &signer,
        )
    };
    assert_eq!(
        gate.verify_for_admin("demo-app", &future, now(0), RULED),
        AdminVerdict::Accept
    );
    assert_eq!(
        gate.verify_for_admin("demo-app", &future, now(0), STRICT),
        reject(AdminRejection::NotYetValid)
    );
}

#[derive(Debug, Clone)]
enum Step {
    Reset(bool),
    Disable,
    Advance(i64),
}

fn mutate(token: &str, flips: &[(usize, u8)]) -> String {
    let mut bytes = token.as_bytes().to_vec();
    for (at, byte) in flips {
        if bytes.is_empty() {
            break;
        }
        let i = at % bytes.len();
        bytes[i] = *byte;
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The strict admin verdict is the callable boundary's verdict, mapped, on every snapshot
    /// reached by random resets of either project, app disablement, time travel and byte flips.
    #[test]
    fn the_strict_verdict_is_the_callable_verdict_mapped(
        steps in proptest::collection::vec(prop_oneof![
            any::<bool>().prop_map(Step::Reset),
            Just(Step::Disable),
            (-4000i64..4000).prop_map(Step::Advance),
        ], 0..8),
        flips in proptest::collection::vec((0usize..400, 33u8..127), 0..3),
        project_other in any::<bool>(),
    ) {
        let signer = TestSigner::new(1);
        let mut registry = fixture_registry();
        let token_a = issue(&registry, &signer, "demo-app", DEMO_APP_ID);
        let token_b = issue(&registry, &signer, "demo-other", OTHER_APP_ID);
        let mut clock = 0i64;
        let mut seed = 1000u64;
        for step in steps {
            match step {
                Step::Reset(first) => {
                    seed += 1;
                    registry.set_project_epoch(if first { "demo-app" } else { "demo-other" }, seeded_epoch(seed));
                }
                Step::Disable => {
                    let mut disabled = AppCheckRegistry::new(3600).unwrap();
                    for app in registry.apps() {
                        disabled.register_app(AppRegistration {
                            project_id: app.project_id().to_owned(),
                            project_number: app.project_number().to_owned(),
                            app_id: app.app_id().to_owned(),
                            enabled: app.project_id() != "demo-app",
                            debug_token_digests: Vec::new(),
                        }).unwrap();
                    }
                    for project in ["demo-app", "demo-other"] {
                        disabled.set_project_epoch(project, registry.project_epoch(project).unwrap());
                    }
                    registry = disabled;
                }
                Step::Advance(delta) => clock += delta,
            }
        }
        let token = mutate(if project_other { &token_b } else { &token_a }, &flips);
        let at = now(clock);
        let classified = classify(&HeaderClassification::Present(token.clone()), &registry, "demo-app", &signer, at);
        let expected = match classified {
            AppCheckCredentialState::Valid(_) => AdminVerdict::Accept,
            AppCheckCredentialState::Invalid(failure) => AdminVerdict::Reject(admin_rejection_for(failure)),
            other => panic!("unexpected {other:?}"),
        };
        prop_assert_eq!(admin_verdict(&token, &registry, "demo-app", &signer, at, STRICT), expected);
    }

    /// The future-iat ruling changes exactly one verdict: `NotYetValid` becomes whatever the
    /// remaining checks say (never `NotYetValid` again); every other verdict is unchanged.
    #[test]
    fn the_ruling_only_changes_the_not_yet_valid_verdict(
        steps in proptest::collection::vec(any::<bool>(), 0..4),
        flips in proptest::collection::vec((0usize..400, 33u8..127), 0..3),
        clock in -4000i64..4000,
        ghost in any::<bool>(),
    ) {
        let signer = TestSigner::new(1);
        let mut registry = fixture_registry();
        let base = if ghost {
            encode(&claims_of(&registry, "1:1234567890:web:ghost", START, START + 3600), &signer)
        } else {
            issue(&registry, &signer, "demo-app", DEMO_APP_ID)
        };
        let mut seed = 5000u64;
        for reset in steps {
            if reset {
                seed += 1;
                registry.set_project_epoch("demo-app", seeded_epoch(seed));
            }
        }
        let token = mutate(&base, &flips);
        let at = now(clock);
        let strict = admin_verdict(&token, &registry, "demo-app", &signer, at, STRICT);
        let ruled = admin_verdict(&token, &registry, "demo-app", &signer, at, RULED);
        match strict {
            AdminVerdict::Reject(AdminRejection::NotYetValid) => {
                prop_assert_ne!(ruled, AdminVerdict::Reject(AdminRejection::NotYetValid));
            }
            other => prop_assert_eq!(ruled, other),
        }
    }
}
