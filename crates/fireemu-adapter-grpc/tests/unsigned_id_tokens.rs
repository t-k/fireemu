//! `auth.allowUnsignedIdTokens` on the Firestore Security Rules surface (owner ledger 1393):
//! the strict profile admits `@firebase/rules-unit-testing`'s unsigned mock token when the
//! setting is on, refuses it exactly as before when it is off, and refuses a token that claims a
//! signature that does not verify either way. The emulator profile is unchanged.

// `tonic::Status` is the error type the enforcer's API dictates.
#![allow(clippy::result_large_err)]

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::{RestRequest, RestState};
use fireemu_adapter_grpc::rules::{
    Principal, RulesEnforcer, TokenSemantics, EXPIRED_CREDENTIALS_MESSAGE,
    PERMISSION_DENIED_MESSAGE,
};
use fireemu_core_auth::jwt::{base64url_encode, TokenAcceptance};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};
use tonic::Code;

const PROJECT: &str = "demo-app";
const DOCS: &str = "/v1/projects/demo-app/databases/(default)/documents";
const OWNER_RULES: &str = "rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /owned/{uid} { allow read, write: if request.auth != null && request.auth.uid == uid; } } }";

fn token(header: &str, payload: &str, signature: &str) -> String {
    format!(
        "{}.{}.{signature}",
        base64url_encode(header.as_bytes()),
        base64url_encode(payload.as_bytes())
    )
}

fn mock_payload(sub: &str, project: &str) -> String {
    format!(
        r#"{{"iss":"https://securetoken.google.com/{project}","aud":"{project}","iat":0,"exp":3600,"auth_time":0,"sub":"{sub}","user_id":"{sub}","firebase":{{"sign_in_provider":"custom","identities":{{}}}}}}"#
    )
}

/// What `createMockUserToken` (`@firebase/util`) sends for `authenticatedContext(sub)`.
fn mock_user_token(sub: &str) -> String {
    token(
        r#"{"alg":"none","type":"JWT"}"#,
        &mock_payload(sub, PROJECT),
        "",
    )
}

fn tampered_rs256(sub: &str) -> String {
    token(
        r#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#,
        &mock_payload(sub, PROJECT),
        &base64url_encode(b"not a signature"),
    )
}

/// The Firestore enforcer as the daemon builds it; `unsigned` is the setting, `None` leaves
/// the profile's default.
fn enforcer(acceptance: TokenAcceptance, unsigned: Option<bool>) -> RulesEnforcer {
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let auth = Arc::new(Mutex::new(AuthStore::new(
        PROJECT,
        SplitMix64::new(3),
        TotpPolicy::default(),
    )));
    let loaded = Arc::new(RulesetSlot::new(
        LoadedRules::from_source(OWNER_RULES).unwrap(),
    ));
    let enforcer = RulesEnforcer::new(loaded, auth, clock)
        .with_token_semantics(TokenSemantics::Firestore)
        .with_token_acceptance(acceptance);
    match unsigned {
        Some(allow) => enforcer.with_unsigned_id_tokens(allow),
        None => enforcer,
    }
}

fn uid_of(principal: &Principal) -> Option<String> {
    match principal {
        Principal::User(ctx) => Some(ctx.uid.clone()),
        _ => None,
    }
}

fn resolve(enforcer: &RulesEnforcer, credential: &str) -> Result<Principal, tonic::Status> {
    enforcer
        .principal_from_authorization_for_project(Some(&format!("Bearer {credential}")), PROJECT)
}

#[test]
fn strict_with_the_setting_admits_the_mock_token_as_its_subject() {
    let strict = enforcer(TokenAcceptance::Verified, Some(true));
    let principal = resolve(&strict, &mock_user_token("alice")).unwrap();
    assert_eq!(uid_of(&principal).as_deref(), Some("alice"));
    let principal = strict
        .principal_from_authorization(Some(&format!("Bearer {}", mock_user_token("alice"))))
        .unwrap();
    assert_eq!(uid_of(&principal).as_deref(), Some("alice"));
}

#[test]
fn strict_without_the_setting_refuses_with_todays_status() {
    for unsigned in [None, Some(false)] {
        let strict = enforcer(TokenAcceptance::Verified, unsigned);
        let refused = resolve(&strict, &mock_user_token("alice")).unwrap_err();
        assert_eq!(refused.code(), Code::Unauthenticated, "{unsigned:?}");
        assert_eq!(
            refused.message(),
            EXPIRED_CREDENTIALS_MESSAGE,
            "{unsigned:?}"
        );
    }
}

#[test]
fn a_tampered_rs256_token_is_refused_whatever_the_setting() {
    for unsigned in [None, Some(false), Some(true)] {
        let strict = enforcer(TokenAcceptance::Verified, unsigned);
        let refused = resolve(&strict, &tampered_rs256("alice")).unwrap_err();
        assert_eq!(refused.code(), Code::PermissionDenied, "{unsigned:?}");
        assert_eq!(refused.message(), PERMISSION_DENIED_MESSAGE, "{unsigned:?}");
        let emulator = enforcer(TokenAcceptance::EmulatorMock, unsigned);
        let refused = resolve(&emulator, &tampered_rs256("alice")).unwrap_err();
        assert_eq!(refused.code(), Code::Unauthenticated, "{unsigned:?}");
    }
}

#[test]
fn a_mock_token_of_another_project_stays_refused_under_strict() {
    let strict = enforcer(TokenAcceptance::Verified, Some(true));
    let foreign = token(
        r#"{"alg":"none","type":"JWT"}"#,
        &mock_payload("alice", "demo-other"),
        "",
    );
    let refused = resolve(&strict, &foreign).unwrap_err();
    assert_eq!(refused.code(), Code::PermissionDenied);
    assert_eq!(refused.message(), PERMISSION_DENIED_MESSAGE);
}

#[test]
fn the_emulator_profile_is_unchanged_and_the_setting_can_refuse() {
    for unsigned in [None, Some(true)] {
        let emulator = enforcer(TokenAcceptance::EmulatorMock, unsigned);
        let principal = resolve(&emulator, &mock_user_token("alice")).unwrap();
        assert_eq!(uid_of(&principal).as_deref(), Some("alice"), "{unsigned:?}");
    }
    let emulator = enforcer(TokenAcceptance::EmulatorMock, Some(false));
    let refused = resolve(&emulator, &mock_user_token("alice")).unwrap_err();
    assert_eq!(refused.code(), Code::Unauthenticated);
    assert_eq!(refused.message(), "invalid ID token: token expired");
}

/// The setting is about the caller's token only: the profile's other answers stay. A strict
/// enforcer with the setting still refuses an empty bearer value in production's shape.
#[test]
fn the_setting_does_not_change_the_profiles_other_answers() {
    let strict = enforcer(TokenAcceptance::Verified, Some(true));
    let refused = strict
        .principal_from_authorization(Some("Bearer "))
        .unwrap_err();
    assert_eq!(refused.code(), Code::PermissionDenied);
    assert!(matches!(
        strict.principal_from_authorization(Some("Bearer owner")),
        Ok(Principal::Owner)
    ));
    let mock = resolve(&strict, &mock_user_token("alice")).unwrap();
    assert!(strict.check_audience(&mock, "demo-other").is_err());
    assert!(strict.check_audience(&mock, PROJECT).is_ok());
}

fn rest(acceptance: TokenAcceptance, unsigned: Option<bool>) -> RestState {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let local = Arc::new(LocalBackend::new(gateway.clone(), clock, 7));
    RestState {
        local,
        gateway: Arc::new(gateway),
        rules: Some(Arc::new(enforcer(acceptance, unsigned))),
        app_check: None,
        control_token: None,
    }
}

fn patch(state: &RestState, path: &str, authorization: &str) -> (u16, Value) {
    let response = state.handle(&RestRequest {
        method: "PATCH".to_owned(),
        path: path.to_owned(),
        query: String::new(),
        authorization: Some(authorization.to_owned()),
        app_check: Vec::new(),
        body: json!({"fields": {"v": {"integerValue": "1"}}}),
        batch_field_order: Vec::new(),
        origin: None,
        remote_peer: false,
        browser_metadata: false,
    });
    (response.status, response.body)
}

/// End to end on the REST surface: the rule sees `request.auth.uid` from the mock token's
/// claims, so another subject's document is still denied by the rule.
#[test]
fn strict_rest_evaluates_rules_with_the_mock_tokens_claims() {
    let bearer = format!("Bearer {}", mock_user_token("alice"));
    let strict = rest(TokenAcceptance::Verified, Some(true));
    let (status, body) = patch(&strict, &format!("{DOCS}/owned/alice"), &bearer);
    assert_eq!(status, 200, "{body}");
    let (status, body) = patch(&strict, &format!("{DOCS}/owned/bob"), &bearer);
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        body["error"]["message"], PERMISSION_DENIED_MESSAGE,
        "{body}"
    );

    let refusing = rest(TokenAcceptance::Verified, Some(false));
    let (status, body) = patch(&refusing, &format!("{DOCS}/owned/alice"), &bearer);
    assert_eq!(status, 401, "{body}");
    assert_eq!(
        body["error"]["message"], EXPIRED_CREDENTIALS_MESSAGE,
        "{body}"
    );
}

/// Tokens next to the unsigned shape that count as signed: under strict each one gets the same
/// refusal with the setting on as with it off.
fn near_misses() -> Vec<(&'static str, String)> {
    let payload = mock_payload("alice", PROJECT);
    let padded_header = format!("{}=", base64url_encode(br#"{"alg":"none","type":"JWT"}"#));
    vec![
        (
            "alg None",
            token(r#"{"alg":"None","type":"JWT"}"#, &payload, ""),
        ),
        ("alg NONE", token(r#"{"alg":"NONE"}"#, &payload, "")),
        (
            "none with a signature",
            token(r#"{"alg":"none","type":"JWT"}"#, &payload, "c2ln"),
        ),
        (
            "RS256 without a signature",
            token(r#"{"alg":"RS256"}"#, &payload, ""),
        ),
        ("no alg", token(r#"{"type":"JWT"}"#, &payload, "")),
        ("header not an object", token(r#""none""#, &payload, "")),
        (
            "padded header",
            format!("{padded_header}.{}.", base64url_encode(payload.as_bytes())),
        ),
        ("four segments", format!("{}.", mock_user_token("alice"))),
    ]
}

#[test]
fn strict_near_misses_get_the_same_refusal_whatever_the_setting() {
    let allowing = enforcer(TokenAcceptance::Verified, Some(true));
    let refusing = enforcer(TokenAcceptance::Verified, Some(false));
    for (name, candidate) in near_misses() {
        let with = resolve(&allowing, &candidate).expect_err(name);
        let without = resolve(&refusing, &candidate).expect_err(name);
        assert_eq!(with.code(), without.code(), "{name}");
        assert_eq!(with.message(), without.message(), "{name}");
    }
}
