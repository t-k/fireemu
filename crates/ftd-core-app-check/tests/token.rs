//! Token issuance and verification (specification section 11, scenarios 3-7, 9 and 11).

mod support;

use ftd_core_app_check::claims::{issuer_for, AppCheckClaims};
use ftd_core_app_check::jwt::{base64url_encode, encode};
use ftd_core_app_check::registry::{AppCheckRegistry, AppRegistration, ProjectEpoch};
use ftd_core_app_check::verify::{
    verify_token, AdmissionDecision, AppCheckCredentialState, AppCheckFailure, BaselineMode,
};
use ftd_core_types::time::LogicalInstant;
use support::{
    digest_of, fixture_registry, seeded_epoch, TestSigner, DEMO_APP_ID, DEMO_SECRET, OTHER_APP_ID,
};

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

#[test]
fn a_locally_issued_token_verifies_against_its_own_project() {
    let registry = fixture_registry();
    let signer = TestSigner::new(1);
    let token = issue(&registry, &signer, "demo-app", DEMO_APP_ID);
    let identity = verify_token(&token, &registry, "demo-app", &signer, now(0)).unwrap();
    assert_eq!(identity.app_id, DEMO_APP_ID);
    assert_eq!(identity.project_id, "demo-app");
    assert_eq!(identity.project_number, "1234567890");
    assert_eq!(identity.issued_at, now(0));
    assert_eq!(identity.expires_at, now(3600));
    assert!(!identity.token_id.is_empty());
}

#[test]
fn a_token_expires_exactly_when_the_virtual_clock_reaches_exp() {
    let registry = fixture_registry();
    let signer = TestSigner::new(1);
    let token = issue(&registry, &signer, "demo-app", DEMO_APP_ID);
    assert!(verify_token(&token, &registry, "demo-app", &signer, now(3599)).is_ok());
    assert_eq!(
        verify_token(&token, &registry, "demo-app", &signer, now(3600)),
        Err(AppCheckFailure::Expired),
        "now == exp is expired, never valid"
    );
    assert_eq!(
        verify_token(&token, &registry, "demo-app", &signer, now(3601)),
        Err(AppCheckFailure::Expired)
    );
}

#[test]
fn a_token_issued_in_the_future_is_rejected() {
    let registry = fixture_registry();
    let signer = TestSigner::new(1);
    let claims = registry
        .issue_claims("demo-app", DEMO_APP_ID, now(60))
        .unwrap();
    let token = encode(&claims, &signer);
    assert_eq!(
        verify_token(&token, &registry, "demo-app", &signer, now(59)),
        Err(AppCheckFailure::NotYetValid)
    );
    assert!(verify_token(&token, &registry, "demo-app", &signer, now(60)).is_ok());
}

#[test]
fn a_valid_signature_with_another_project_audience_is_rejected() {
    let registry = fixture_registry();
    let signer = TestSigner::new(1);
    let token = issue(&registry, &signer, "demo-other", OTHER_APP_ID);
    // The signature is this instance's, but the token belongs to the other project.
    assert_eq!(
        verify_token(&token, &registry, "demo-app", &signer, now(0)),
        Err(AppCheckFailure::WrongProject)
    );
    assert!(verify_token(&token, &registry, "demo-other", &signer, now(0)).is_ok());
}

#[test]
fn an_audience_that_names_only_one_of_the_two_project_forms_is_rejected() {
    let registry = fixture_registry();
    let signer = TestSigner::new(1);
    let mut claims = registry
        .issue_claims("demo-app", DEMO_APP_ID, now(0))
        .unwrap();
    claims.aud = vec!["projects/1234567890".to_owned()];
    assert_eq!(
        verify_token(
            &encode(&claims, &signer),
            &registry,
            "demo-app",
            &signer,
            now(0)
        ),
        Err(AppCheckFailure::WrongAudience)
    );
    let mut claims = registry
        .issue_claims("demo-app", DEMO_APP_ID, now(0))
        .unwrap();
    claims.aud = vec!["projects/demo-app".to_owned()];
    assert_eq!(
        verify_token(
            &encode(&claims, &signer),
            &registry,
            "demo-app",
            &signer,
            now(0)
        ),
        Err(AppCheckFailure::WrongAudience)
    );
}

#[test]
fn issuer_prefix_and_suffix_confusion_cannot_satisfy_exact_issuer_validation() {
    let registry = fixture_registry();
    let signer = TestSigner::new(1);
    let exact = issuer_for("1234567890");
    for forged in [
        format!("{exact}/"),
        format!("{exact}0"),
        format!("{exact}?x=1"),
        format!("{exact}#demo"),
        format!("x{exact}"),
        exact.replace("https", "http"),
        "https://firebaseappcheck.googleapis.com.evil.example/1234567890".to_owned(),
        "https://firebaseappcheck.googleapis.com/1234567890/../1234567890".to_owned(),
    ] {
        let mut claims = registry
            .issue_claims("demo-app", DEMO_APP_ID, now(0))
            .unwrap();
        claims.iss = forged.clone();
        let result = verify_token(
            &encode(&claims, &signer),
            &registry,
            "demo-app",
            &signer,
            now(0),
        );
        assert!(
            matches!(
                result,
                Err(AppCheckFailure::WrongIssuer | AppCheckFailure::WrongProject)
            ),
            "{forged} must not satisfy exact issuer validation, got {result:?}"
        );
    }
}

#[test]
fn a_registered_app_from_another_session_cannot_authorize_this_session() {
    // Two daemons, two registries, two epochs: the app registration is identical, the epoch
    // is not, so neither accepts the other's tokens.
    let signer = TestSigner::new(1);
    let mut first = fixture_registry();
    let mut second = fixture_registry();
    first.set_project_epoch("demo-app", seeded_epoch(11));
    second.set_project_epoch("demo-app", seeded_epoch(12));
    let token = issue(&first, &signer, "demo-app", DEMO_APP_ID);
    assert!(verify_token(&token, &first, "demo-app", &signer, now(0)).is_ok());
    assert_eq!(
        verify_token(&token, &second, "demo-app", &signer, now(0)),
        Err(AppCheckFailure::WrongEpoch)
    );
}

#[test]
fn reset_invalidates_every_token_from_the_previous_epoch() {
    let mut registry = fixture_registry();
    let signer = TestSigner::new(1);
    let before = issue(&registry, &signer, "demo-app", DEMO_APP_ID);
    assert!(verify_token(&before, &registry, "demo-app", &signer, now(0)).is_ok());
    let generation = registry.policy_generation("demo-app");

    registry.set_project_epoch("demo-app", seeded_epoch(99));
    assert_eq!(
        verify_token(&before, &registry, "demo-app", &signer, now(0)),
        Err(AppCheckFailure::WrongEpoch)
    );
    assert_eq!(registry.policy_generation("demo-app"), generation + 1);
    // The counter restarts, but the epoch prefix makes the token IDs disjoint anyway.
    let after = issue(&registry, &signer, "demo-app", DEMO_APP_ID);
    assert!(verify_token(&after, &registry, "demo-app", &signer, now(0)).is_ok());
    assert_ne!(before, after);
}

#[test]
fn a_forged_signature_a_foreign_key_and_an_unknown_key_id_are_all_refused() {
    let registry = fixture_registry();
    let signer = TestSigner::new(1);
    let foreign = TestSigner::new(2);
    let token = issue(&registry, &signer, "demo-app", DEMO_APP_ID);

    // Another instance's key: the key ID does not even name this instance's key.
    assert_eq!(
        verify_token(&token, &registry, "demo-app", &foreign, now(0)),
        Err(AppCheckFailure::UnknownKeyId)
    );
    // A token forged with the foreign key but relabelled with this instance's key ID.
    let claims = registry
        .issue_claims("demo-app", DEMO_APP_ID, now(0))
        .unwrap();
    let header = format!(
        r#"{{"alg":"RS256","kid":"{}","typ":"JWT"}}"#,
        <TestSigner as ftd_core_app_check::crypto::AppCheckSigner>::kid(&signer)
    );
    let signing_input = format!(
        "{}.{}",
        base64url_encode(header.as_bytes()),
        base64url_encode(claims.canonical_json().as_bytes())
    );
    let forged = format!(
        "{signing_input}.{}",
        base64url_encode(&ftd_core_app_check::crypto::AppCheckSigner::sign(
            &foreign,
            signing_input.as_bytes()
        ))
    );
    assert_eq!(
        verify_token(&forged, &registry, "demo-app", &signer, now(0)),
        Err(AppCheckFailure::BadSignature)
    );
    // A payload edited after signing.
    let (head, _) = token.rsplit_once('.').unwrap();
    let tampered = format!("{head}.{}", base64url_encode(b"not-a-signature"));
    assert_eq!(
        verify_token(&tampered, &registry, "demo-app", &signer, now(0)),
        Err(AppCheckFailure::BadSignature)
    );
}

#[test]
fn an_unsigned_or_differently_signed_token_never_verifies() {
    let registry = fixture_registry();
    let signer = TestSigner::new(1);
    let claims = registry
        .issue_claims("demo-app", DEMO_APP_ID, now(0))
        .unwrap();
    let payload = base64url_encode(claims.canonical_json().as_bytes());

    let none = format!(
        "{}.{payload}.",
        base64url_encode(br#"{"alg":"none","typ":"JWT"}"#)
    );
    assert_eq!(
        verify_token(&none, &registry, "demo-app", &signer, now(0)),
        Err(AppCheckFailure::Malformed),
        "an empty signature segment is not a token at all"
    );
    let hs256 = format!(
        "{}.{payload}.{}",
        base64url_encode(br#"{"alg":"HS256","kid":"x","typ":"JWT"}"#),
        base64url_encode(b"tag")
    );
    assert_eq!(
        verify_token(&hs256, &registry, "demo-app", &signer, now(0)),
        Err(AppCheckFailure::UnsupportedAlgorithm)
    );
    let wrong_typ = format!(
        "{}.{payload}.{}",
        base64url_encode(br#"{"alg":"RS256","kid":"x","typ":"at+jwt"}"#),
        base64url_encode(b"tag")
    );
    assert_eq!(
        verify_token(&wrong_typ, &registry, "demo-app", &signer, now(0)),
        Err(AppCheckFailure::UnsupportedAlgorithm)
    );
}

#[test]
fn an_unknown_and_a_disabled_app_are_distinguished_only_internally() {
    let mut registry = AppCheckRegistry::new(3600).unwrap();
    registry
        .register_app(AppRegistration {
            project_id: "demo-app".to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: DEMO_APP_ID.to_owned(),
            enabled: false,
            debug_token_digests: vec![digest_of(DEMO_SECRET)],
        })
        .unwrap();
    registry.set_project_epoch("demo-app", seeded_epoch(3));
    let signer = TestSigner::new(1);

    // A disabled app cannot even be issued a token.
    assert!(registry
        .issue_claims("demo-app", DEMO_APP_ID, now(0))
        .is_err());

    // A token minted for it (as if issued before it was disabled) stops verifying.
    let epoch = registry.project_epoch("demo-app").unwrap();
    let claims = AppCheckClaims {
        iss: issuer_for("1234567890"),
        sub: DEMO_APP_ID.to_owned(),
        aud: vec![
            "projects/1234567890".to_owned(),
            "projects/demo-app".to_owned(),
        ],
        iat: START,
        exp: START + 3600,
        jti: "manual-1".to_owned(),
        ftd_epoch: epoch.claim_text(),
    };
    assert_eq!(
        verify_token(
            &encode(&claims, &signer),
            &registry,
            "demo-app",
            &signer,
            now(0)
        ),
        Err(AppCheckFailure::AppDisabled)
    );

    let mut unknown = claims;
    unknown.sub = "1:1234567890:web:never-registered".to_owned();
    assert_eq!(
        verify_token(
            &encode(&unknown, &signer),
            &registry,
            "demo-app",
            &signer,
            now(0)
        ),
        Err(AppCheckFailure::UnknownApp)
    );
    assert_eq!(
        AppCheckFailure::UnknownApp.code(),
        AppCheckFailure::AppDisabled.code(),
        "the public reason code does not distinguish them"
    );
}

#[test]
fn concurrent_exchanges_produce_unique_token_ids() {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    let registry = Arc::new(fixture_registry());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let registry = registry.clone();
        handles.push(std::thread::spawn(move || {
            (0..64)
                .map(|_| registry.next_token_id("demo-app").expect("a live epoch"))
                .collect::<Vec<_>>()
        }));
    }
    let mut ids = BTreeSet::new();
    let mut total = 0usize;
    for handle in handles {
        for id in handle.join().expect("the issuing thread finished") {
            total += 1;
            assert!(ids.insert(id), "a token ID was reused");
        }
    }
    assert_eq!(total, 8 * 64);
    assert_eq!(ids.len(), total);
    // Every ID carries the epoch, so IDs from different epochs cannot collide either.
    let epoch = registry.project_epoch("demo-app").unwrap().claim_text();
    assert!(ids.iter().all(|id| id.starts_with(&epoch)));
}

#[test]
fn a_token_that_is_not_three_base64url_segments_is_malformed() {
    let registry = fixture_registry();
    let signer = TestSigner::new(1);
    for bad in [
        "",
        ".",
        "..",
        "a.b",
        "a.b.c.d",
        "a..c",
        ".b.c",
        "a.b.",
        "a.b.c",
        "!!!.b.c",
        "YQ.YQ.YQ=",
    ] {
        assert!(
            verify_token(bad, &registry, "demo-app", &signer, now(0)).is_err(),
            "{bad:?} must not verify"
        );
    }
    let oversized = "a".repeat(16 * 1024 + 1);
    assert_eq!(
        verify_token(&oversized, &registry, "demo-app", &signer, now(0)),
        Err(AppCheckFailure::Malformed)
    );
}

#[test]
fn the_baseline_modes_decide_exactly_as_the_matrix_says() {
    let registry = fixture_registry();
    let signer = TestSigner::new(1);
    let token = issue(&registry, &signer, "demo-app", DEMO_APP_ID);
    let valid = AppCheckCredentialState::Valid(
        verify_token(&token, &registry, "demo-app", &signer, now(0)).unwrap(),
    );
    let states = [
        AppCheckCredentialState::Bypass,
        AppCheckCredentialState::Missing,
        valid,
        AppCheckCredentialState::Invalid(AppCheckFailure::BadSignature),
    ];
    for mode in [BaselineMode::Off, BaselineMode::Unenforced] {
        for state in &states {
            let decision = AdmissionDecision::decide(mode, state.clone());
            assert!(decision.allowed, "{mode} never denies");
        }
    }
    let denied: Vec<bool> = states
        .iter()
        .map(|s| AdmissionDecision::decide(BaselineMode::Enforced, s.clone()).allowed)
        .collect();
    assert_eq!(denied, vec![true, false, true, false]);
    // An invalid credential never becomes an anonymous valid app, in any mode.
    for mode in [
        BaselineMode::Off,
        BaselineMode::Unenforced,
        BaselineMode::Enforced,
    ] {
        let decision = AdmissionDecision::decide(
            mode,
            AppCheckCredentialState::Invalid(AppCheckFailure::Malformed),
        );
        assert!(decision.identity().is_none());
        let decision = AdmissionDecision::decide(mode, AppCheckCredentialState::Missing);
        assert!(decision.identity().is_none());
    }
}

#[test]
fn a_project_without_an_epoch_can_neither_issue_nor_verify() {
    let mut registry = AppCheckRegistry::new(3600).unwrap();
    registry
        .register_app(AppRegistration {
            project_id: "demo-app".to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: DEMO_APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: vec![digest_of(DEMO_SECRET)],
        })
        .unwrap();
    let signer = TestSigner::new(1);
    assert!(registry
        .issue_claims("demo-app", DEMO_APP_ID, now(0))
        .is_err());
    registry.set_project_epoch("demo-app", ProjectEpoch::new(1));
    let token = issue(&registry, &signer, "demo-app", DEMO_APP_ID);
    assert!(verify_token(&token, &registry, "demo-app", &signer, now(0)).is_ok());
}
