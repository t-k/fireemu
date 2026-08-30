//! The debug-token exchange decision (specification section 10.1, scenarios 1, 2, 8 and 10).

mod support;

use fireemu_core_app_check::exchange::{
    canonical_debug_token, exchange, ExchangeOutcome, ExchangeRequest,
};
use fireemu_core_app_check::registry::{AppCheckRegistry, AppRegistration};
use fireemu_core_app_check::verify::verify_token;
use fireemu_core_types::time::LogicalInstant;
use support::{
    digest_of, fixture_registry, seeded_epoch, TestEq, TestHasher, TestSigner, DEMO_APP_ID,
    DEMO_SECRET, OTHER_APP_ID, OTHER_SECRET,
};

const START: i64 = 1_788_004_860;

fn now() -> LogicalInstant {
    LogicalInstant::from_unix_seconds(START)
}

fn request<'a>(project: &'a str, app: &'a str, secret: &'a str) -> ExchangeRequest<'a> {
    ExchangeRequest {
        project_selector: project,
        app_id: app,
        debug_token: secret,
        limited_use: false,
    }
}

fn run(registry: &AppCheckRegistry, request: &ExchangeRequest<'_>) -> ExchangeOutcome {
    exchange(registry, request, &TestHasher, &TestEq, now())
}

#[test]
fn a_registered_debug_token_exchanges_for_a_project_bound_rs256_session_token() {
    let registry = fixture_registry();
    let signer = TestSigner::new(1);
    let ExchangeOutcome::Issued(claims) =
        run(&registry, &request("demo-app", DEMO_APP_ID, DEMO_SECRET))
    else {
        panic!("the registered secret must exchange");
    };
    assert_eq!(claims.sub, DEMO_APP_ID);
    assert_eq!(
        claims.iss,
        "https://firebaseappcheck.googleapis.com/1234567890"
    );
    assert_eq!(
        claims.aud,
        vec![
            "projects/1234567890".to_owned(),
            "projects/demo-app".to_owned()
        ]
    );
    assert_eq!(claims.ttl_seconds(), 3600);

    let token = fireemu_core_app_check::jwt::encode(&claims, &signer);
    let identity = verify_token(&token, &registry, "demo-app", &signer, now()).unwrap();
    assert_eq!(identity.app_id, DEMO_APP_ID);

    // The project number selects the same project as the project ID.
    assert!(matches!(
        run(&registry, &request("1234567890", DEMO_APP_ID, DEMO_SECRET)),
        ExchangeOutcome::Issued(_)
    ));
}

#[test]
fn an_unknown_debug_token_and_an_unknown_app_produce_indistinguishable_public_errors() {
    let registry = fixture_registry();
    let unknown_secret = "22222222-2222-4222-a222-222222222222";
    let outcomes = [
        // Registered app, unregistered secret.
        run(&registry, &request("demo-app", DEMO_APP_ID, unknown_secret)),
        // Registered project, unregistered app.
        run(
            &registry,
            &request("demo-app", "1:1234567890:web:nope", DEMO_SECRET),
        ),
        // Unregistered project.
        run(&registry, &request("demo-nope", DEMO_APP_ID, DEMO_SECRET)),
        // Unregistered project number.
        run(&registry, &request("5555555555", DEMO_APP_ID, DEMO_SECRET)),
        // A secret registered for another project's app.
        run(&registry, &request("demo-app", DEMO_APP_ID, OTHER_SECRET)),
        // The right secret, but the app of the other project.
        run(&registry, &request("demo-app", OTHER_APP_ID, OTHER_SECRET)),
        // Not even a UUID.
        run(&registry, &request("demo-app", DEMO_APP_ID, "not-a-uuid")),
    ];
    for outcome in &outcomes {
        assert_eq!(
            *outcome,
            ExchangeOutcome::AttestationFailed,
            "every failure mode is the same public outcome"
        );
    }
}

#[test]
fn uppercase_uuid_input_exchanges_against_its_canonical_registered_digest() {
    let registry = fixture_registry();
    let upper = DEMO_SECRET.to_uppercase();
    assert_ne!(upper, DEMO_SECRET);
    assert_eq!(
        canonical_debug_token(&upper).as_deref(),
        Some(DEMO_SECRET),
        "hexadecimal case never changes the credential"
    );
    assert!(matches!(
        run(&registry, &request("demo-app", DEMO_APP_ID, &upper)),
        ExchangeOutcome::Issued(_)
    ));
}

#[test]
fn only_a_canonical_uuid_v4_is_accepted_as_debug_token_text() {
    assert!(canonical_debug_token(DEMO_SECRET).is_some());
    for bad in [
        "",
        "00000000-0000-4000-8000-00000000000", // one character short
        "00000000-0000-4000-8000-0000000000000", // one character too long
        "00000000000040008000000000000000",    // no hyphens
        "00000000-0000-4000-8000_000000000000", // wrong separator
        "00000000-0000-1000-8000-000000000000", // version 1
        "00000000-0000-4000-c000-000000000000", // wrong variant
        "0000000g-0000-4000-8000-000000000000", // not hexadecimal
        " 00000000-0000-4000-8000-000000000000",
    ] {
        assert_eq!(
            canonical_debug_token(bad),
            None,
            "{bad:?} is not a debug token"
        );
    }
}

#[test]
fn limited_use_exchange_fails_closed_while_replay_protection_is_unsupported() {
    let registry = fixture_registry();
    let limited = ExchangeRequest {
        limited_use: true,
        ..request("demo-app", DEMO_APP_ID, DEMO_SECRET)
    };
    assert_eq!(run(&registry, &limited), ExchangeOutcome::ReplayUnsupported);
    // Even an otherwise failing request fails as unsupported, never as a reusable token.
    let limited_unknown = ExchangeRequest {
        limited_use: true,
        ..request(
            "demo-app",
            DEMO_APP_ID,
            "22222222-2222-4222-a222-222222222222",
        )
    };
    assert_eq!(
        run(&registry, &limited_unknown),
        ExchangeOutcome::ReplayUnsupported
    );
}

#[test]
fn a_disabled_app_cannot_exchange_even_with_the_right_secret() {
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
    registry.set_project_epoch("demo-app", seeded_epoch(4));
    assert_eq!(
        run(&registry, &request("demo-app", DEMO_APP_ID, DEMO_SECRET)),
        ExchangeOutcome::AttestationFailed
    );
}

#[test]
fn a_dynamically_registered_debug_token_exchanges_and_stops_after_deletion() {
    let mut registry = fixture_registry();
    let dynamic_secret = "33333333-3333-4333-b333-333333333333";
    let record = registry
        .add_debug_token(
            "demo-app",
            DEMO_APP_ID,
            "ci runner",
            digest_of(dynamic_secret),
            now(),
        )
        .unwrap();
    assert_eq!(record.display_name, "ci runner");
    assert!(matches!(
        run(&registry, &request("demo-app", DEMO_APP_ID, dynamic_secret)),
        ExchangeOutcome::Issued(_)
    ));
    // The static digest still works alongside it.
    assert!(matches!(
        run(&registry, &request("demo-app", DEMO_APP_ID, DEMO_SECRET)),
        ExchangeOutcome::Issued(_)
    ));

    registry
        .delete_debug_token("demo-app", DEMO_APP_ID, &record.id)
        .unwrap();
    assert_eq!(
        run(&registry, &request("demo-app", DEMO_APP_ID, dynamic_secret)),
        ExchangeOutcome::AttestationFailed
    );
    assert!(registry
        .delete_debug_token("demo-app", DEMO_APP_ID, &record.id)
        .is_err());
}

#[test]
fn a_full_digest_set_still_matches_its_last_entry_without_an_early_exit() {
    // The scan runs to the fixed capacity, so a match in the last slot is found and a set that
    // is full refuses one more registration.
    let mut registry = AppCheckRegistry::new(3600).unwrap();
    let secrets: Vec<String> = (0..128)
        .map(|i| format!("44444444-4444-4444-8444-{i:012}"))
        .map(|s| {
            // Fix the version nibble; the loop above only varies the tail.
            let mut s = s;
            s.replace_range(14..15, "4");
            s
        })
        .collect();
    registry
        .register_app(AppRegistration {
            project_id: "demo-app".to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: DEMO_APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: secrets.iter().map(|s| digest_of(s)).collect(),
        })
        .unwrap();
    registry.set_project_epoch("demo-app", seeded_epoch(5));
    assert!(matches!(
        run(&registry, &request("demo-app", DEMO_APP_ID, &secrets[127])),
        ExchangeOutcome::Issued(_)
    ));
    assert!(registry
        .add_debug_token(
            "demo-app",
            DEMO_APP_ID,
            "one too many",
            digest_of(DEMO_SECRET),
            now()
        )
        .is_err());
}
