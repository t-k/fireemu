//! `auth.allowUnsignedIdTokens` on the Storage Security Rules surface (owner ledger 1393):
//! the strict profile admits `@firebase/rules-unit-testing`'s unsigned mock token when the
//! setting is on, refuses it exactly as before when it is off, and refuses a token that claims a
//! signature that does not verify either way. The emulator profile is unchanged.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fireemu_adapter_http::storage::{handle, StorageRequest, StorageRulesRegistry, StorageState};
use fireemu_core_auth::jwt::{base64url_encode, TokenAcceptance};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::store::StorageState as ObjectStore;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const PROJECT: &str = "demo-app";
const BUCKET: &str = "demo-app.appspot.com";
/// Each user reads only under their own uid, so the decision depends on the token's claims.
const OWNER_RULES: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /users/{uid}/{path=**} { allow read: if request.auth != null && request.auth.uid == uid; } } }";

fn state(acceptance: TokenAcceptance, allow_unsigned_id_tokens: bool) -> StorageState {
    StorageState {
        store: Mutex::new(ObjectStore::new(9)),
        clock: Arc::new(Mutex::new(VirtualClock::new(START))),
        auth: Arc::new(fireemu_core_auth::store::AuthRegistry::new(
            PROJECT,
            Arc::new(Mutex::new(AuthStore::new(
                PROJECT,
                SplitMix64::new(3),
                TotpPolicy::default(),
            ))),
        )),
        tenancy: None,
        rules: Arc::new(StorageRulesRegistry::global(Arc::new(RulesetSlot::new(
            LoadedRules::from_source(OWNER_RULES).unwrap(),
        )))),
        project: PROJECT.to_owned(),
        events: None,
        barrier: None,
        firestore: None,
        faults: None,
        clock_observer: None,
        app_check_policy: None,
        admin_capability: None,
        token_acceptance: acceptance,
        allow_unsigned_id_tokens,
        control_token: None,
    }
}

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

/// A metadata read of a missing object under `users/<owner>/`: 404 when the rule admits the
/// caller, 403 when it does not, 401 when the credential is refused.
fn read(s: &StorageState, owner: &str, authorization: &str) -> (u16, Vec<u8>) {
    let response = handle(
        s,
        StorageRequest {
            method: "GET".to_owned(),
            path: format!("/v0/b/{BUCKET}/o/users%2F{owner}%2Fa.txt"),
            query: String::new(),
            host: Some("127.0.0.1:9199".to_owned()),
            headers: BTreeMap::from([("authorization".to_owned(), authorization.to_owned())]),
            app_check: Vec::new(),
            body: Vec::new(),
        },
    );
    (response.status, response.body.to_vec())
}

#[test]
fn strict_with_the_setting_admits_the_mock_token_on_both_schemes() {
    let strict = state(TokenAcceptance::Verified, true);
    for scheme in ["Firebase", "Bearer"] {
        let credential = format!("{scheme} {}", mock_user_token("alice"));
        assert_eq!(read(&strict, "alice", &credential).0, 404, "{scheme}");
        // Still an identity: another user's path is denied by the rule, in production's bytes.
        let (status, body) = read(&strict, "bob", &credential);
        assert_eq!(status, 403, "{scheme}");
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "{\n  \"error\": {\n    \"code\": 403,\n    \"message\": \"Permission denied.\"\n  }\n}",
            "{scheme}"
        );
    }
}

#[test]
fn strict_without_the_setting_refuses_with_todays_response() {
    let refusing = state(TokenAcceptance::Verified, false);
    let credential = format!("Firebase {}", mock_user_token("alice"));
    let (status, body) = read(&refusing, "alice", &credential);
    assert_eq!(status, 401);
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "{\n  \"error\": {\n    \"code\": 401,\n    \"message\": \"invalid ID token: token expired\",\n    \"status\": \"UNAUTHENTICATED\"\n  }\n}"
    );
}

#[test]
fn a_tampered_rs256_token_is_refused_whatever_the_setting() {
    for allow in [false, true] {
        let strict = state(TokenAcceptance::Verified, allow);
        let (status, _) = read(
            &strict,
            "alice",
            &format!("Firebase {}", tampered_rs256("alice")),
        );
        assert_eq!(status, 401, "strict, setting {allow}");
        // The emulator profile treats a token it cannot verify as an anonymous caller, never
        // as the user it claims to be.
        let emulator = state(TokenAcceptance::EmulatorMock, allow);
        let (status, _) = read(
            &emulator,
            "alice",
            &format!("Firebase {}", tampered_rs256("alice")),
        );
        assert_eq!(status, 403, "emulator, setting {allow}");
    }
}

/// A mock token minted for another project keeps production's 403 under strict: the foreign
/// audience is refused before the token is verified.
#[test]
fn a_mock_token_of_another_project_keeps_the_strict_refusal() {
    let strict = state(TokenAcceptance::Verified, true);
    let foreign = token(
        r#"{"alg":"none","type":"JWT"}"#,
        &mock_payload("alice", "demo-other"),
        "",
    );
    let (status, body) = read(&strict, "alice", &format!("Firebase {foreign}"));
    assert_eq!(status, 403);
    assert!(
        String::from_utf8(body)
            .unwrap()
            .contains("Permission denied."),
        "production's foreign-audience answer"
    );
}

#[test]
fn the_emulator_profile_is_unchanged_and_the_setting_can_refuse() {
    let emulator = state(TokenAcceptance::EmulatorMock, true);
    let credential = format!("Firebase {}", mock_user_token("alice"));
    assert_eq!(read(&emulator, "alice", &credential).0, 404);
    assert_eq!(read(&emulator, "bob", &credential).0, 403);
    let refusing = state(TokenAcceptance::EmulatorMock, false);
    assert_eq!(read(&refusing, "alice", &credential).0, 401);
}
