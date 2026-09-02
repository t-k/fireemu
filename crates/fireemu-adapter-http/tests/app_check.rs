//! App Check over HTTP: debug-token exchange, JWKS and privileged debug-token management
//! (specification sections 9 and 10, scenarios 1, 2, 8, 10 and 12).
//!
//! The signer here is the real `rsa` / `sha2` implementation the daemon uses, so these tests
//! also cover the shell side of the core's cryptographic seams. RSA key generation is slow in
//! a debug build, so the fixtures share one instance key and only the isolation scenario
//! generates a second one.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use fireemu_adapter_http::app_check::{AppCheckState, RawRequest};
use fireemu_adapter_http::identity_toolkit::{AuthState, JsonResponse, RequestHeaders};
use fireemu_adapter_http::signing::{
    AppCheckKeySource, AppCheckRsaSigner, OsDebugSecrets, Sha256DebugTokenHasher,
    SubtleConstantTimeEq,
};
use fireemu_core_app_check::crypto::DebugTokenHasher;
use fireemu_core_app_check::registry::{
    AppCheckRegistry, AppRegistration, DebugTokenDigest, ProjectEpoch,
};
use fireemu_core_app_check::verify::verify_token;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const START: i64 = 1_788_004_860;
const CONTROL_TOKEN: &str = "test-control-token";
const APP_ID: &str = "1:1234567890:web:local-test-app";
const OTHER_APP_ID: &str = "1:9876543210:web:other-test-app";
const SECRET: &str = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
const OTHER_SECRET: &str = "11111111-1111-4111-9111-111111111111";
const EXCHANGE: &str =
    "/v1/projects/demo-app/apps/1:1234567890:web:local-test-app:exchangeDebugToken";

/// One RSA key per seed, generated once for the whole test binary.
fn signer(seed: u64) -> Arc<AppCheckRsaSigner> {
    static KEYS: OnceLock<Mutex<BTreeMap<u64, Arc<AppCheckRsaSigner>>>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut keys = keys.lock().expect("the key cache is not poisoned");
    keys.entry(seed)
        .or_insert_with(|| {
            AppCheckRsaSigner::generate(AppCheckKeySource::Seed(seed)).expect("key generation")
        })
        .clone()
}

fn digest_of(secret: &str) -> DebugTokenDigest {
    let canonical = fireemu_core_app_check::exchange::canonical_debug_token(secret)
        .expect("the fixture secret is a canonical UUIDv4");
    DebugTokenDigest::from_bytes(Sha256DebugTokenHasher.sha256(canonical.as_bytes()))
}

fn registry() -> AppCheckRegistry {
    let mut registry = AppCheckRegistry::new(3600).expect("3600s is inside the TTL range");
    registry
        .register_app(AppRegistration {
            project_id: "demo-app".to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: vec![digest_of(SECRET)],
        })
        .unwrap();
    registry
        .register_app(AppRegistration {
            project_id: "demo-other".to_owned(),
            project_number: "9876543210".to_owned(),
            app_id: OTHER_APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: vec![digest_of(OTHER_SECRET)],
        })
        .unwrap();
    registry.set_project_epoch("demo-app", ProjectEpoch::new(0x0123_4567_89AB_CDEF));
    registry.set_project_epoch("demo-other", ProjectEpoch::new(0xFEDC_BA98_7654_3210));
    registry
}

fn clock() -> Arc<Mutex<VirtualClock>> {
    Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(START),
    )))
}

fn app_check_state(seed: u64) -> Arc<AppCheckState> {
    Arc::new(AppCheckState {
        registry: Arc::new(RwLock::new(registry())),
        signer: signer(seed),
        clock: clock(),
        control_token: CONTROL_TOKEN.to_owned(),
        hasher: Arc::new(Sha256DebugTokenHasher),
        constant_time: Arc::new(SubtleConstantTimeEq),
        secrets: Arc::new(OsDebugSecrets),
        barrier: None,
    })
}

fn auth_state(app_check: Option<Arc<AppCheckState>>) -> Arc<AuthState> {
    Arc::new(AuthState {
        store: Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(5),
            TotpPolicy::default(),
        ))),
        clock: clock(),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: Some(CONTROL_TOKEN.to_owned()),
        registry: None,
        allow_routed_projects: false,
        app_check_policy: None,
        tenancy: None,
        app_check,
    })
}

fn call(state: &AppCheckState, method: &str, path: &str, body: &str) -> JsonResponse {
    call_with(state, method, path, body, &RequestHeaders::default())
}

fn call_with(
    state: &AppCheckState,
    method: &str,
    path: &str,
    body: &str,
    headers: &RequestHeaders,
) -> JsonResponse {
    fireemu_adapter_http::app_check::handle_raw(
        state,
        &RawRequest {
            method,
            path,
            headers,
            body: body.as_bytes(),
        },
    )
}

fn control() -> RequestHeaders {
    RequestHeaders {
        authorization: Some(format!("Bearer {CONTROL_TOKEN}")),
        ..RequestHeaders::default()
    }
}

fn exchange_body(secret: &str) -> String {
    json!({"debugToken": secret, "limitedUse": false}).to_string()
}

// ------------------------------------------------------------------------------------------
// Exchange
// ------------------------------------------------------------------------------------------

#[test]
fn a_registered_debug_token_exchanges_for_a_verifiable_session_token() {
    let state = app_check_state(1);
    let r = call(&state, "POST", EXCHANGE, &exchange_body(SECRET));
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.body["ttl"], "3600s");
    let token = r.body["token"].as_str().expect("a token");

    let registry = state.registry.read().unwrap();
    let identity = verify_token(
        token,
        &registry,
        "demo-app",
        state.signer.as_ref(),
        LogicalInstant::from_unix_seconds(START),
    )
    .expect("the issued token verifies against the instance key");
    assert_eq!(identity.app_id, APP_ID);
    assert_eq!(identity.project_number, "1234567890");
    // The header names this instance's dedicated App Check key, never the Auth key.
    assert!(state.signer.kid().starts_with("fireemu-app-check-"));
    assert!(
        token.contains(&fireemu_core_app_check::jwt::base64url_encode(
            format!(
                r#"{{"alg":"RS256","kid":"{}","typ":"JWT"}}"#,
                state.signer.kid()
            )
            .as_bytes()
        ))
    );
}

#[test]
fn the_project_number_and_the_v1beta_twin_reach_the_same_app() {
    let state = app_check_state(1);
    for path in [
        EXCHANGE,
        "/v1beta/projects/demo-app/apps/1:1234567890:web:local-test-app:exchangeDebugToken",
        "/v1/projects/1234567890/apps/1:1234567890:web:local-test-app:exchangeDebugToken",
        "/v1beta/projects/1234567890/apps/1:1234567890:web:local-test-app:exchangeDebugToken",
        // The API key is accepted and ignored.
        "/v1/projects/demo-app/apps/1:1234567890:web:local-test-app:exchangeDebugToken?key=AIzaFake",
        // A percent-encoded app ID resolves to the same app.
        "/v1/projects/demo-app/apps/1%3A1234567890%3Aweb%3Alocal-test-app:exchangeDebugToken",
    ] {
        let r = call(&state, "POST", path, &exchange_body(SECRET));
        assert_eq!(r.status, 200, "{path}: {}", r.body);
    }
}

#[test]
fn an_unknown_app_project_and_secret_are_byte_for_byte_indistinguishable() {
    let state = app_check_state(1);
    let mut bodies = Vec::new();
    for (path, secret) in [
        (EXCHANGE, "22222222-2222-4222-a222-222222222222"),
        (
            "/v1/projects/demo-app/apps/1:1234567890:web:never-registered:exchangeDebugToken",
            SECRET,
        ),
        (
            "/v1/projects/demo-nope/apps/1:1234567890:web:local-test-app:exchangeDebugToken",
            SECRET,
        ),
        (
            "/v1/projects/5555555555/apps/1:1234567890:web:local-test-app:exchangeDebugToken",
            SECRET,
        ),
        (EXCHANGE, OTHER_SECRET),
        (EXCHANGE, "not-a-uuid"),
    ] {
        let r = call(&state, "POST", path, &exchange_body(secret));
        assert_eq!(r.status, 403, "{path}: {}", r.body);
        assert_eq!(r.body["error"]["message"], "App attestation failed.");
        bodies.push(r.body.to_string());
    }
    assert_eq!(
        bodies
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        1,
        "every failure renders exactly the same body: {bodies:?}"
    );
}

#[test]
fn a_limited_use_exchange_fails_closed_with_the_replay_code() {
    let state = app_check_state(1);
    let r = call(
        &state,
        "POST",
        EXCHANGE,
        &json!({"debugToken": SECRET, "limitedUse": true}).to_string(),
    );
    assert_eq!(r.status, 501, "{}", r.body);
    assert_eq!(r.body["error"]["status"], "UNIMPLEMENTED");
    assert_eq!(r.body["error"]["reason"], "APP_CHECK_REPLAY_UNSUPPORTED");
    assert!(
        r.body.get("token").is_none(),
        "a limited-use request never returns a reusable session token"
    );
}

#[test]
fn malformed_exchange_requests_are_invalid_argument_and_never_attestation_failures() {
    let state = app_check_state(1);
    let oversized = json!({"debugToken": "x".repeat(17 * 1024)}).to_string();
    for body in [
        "",
        "not json",
        "[]",
        "\"string\"",
        // A trailing JSON value after a complete object.
        &format!("{} {{}}", exchange_body(SECRET)),
        // Unknown members fail closed.
        &json!({"debugToken": SECRET, "consumeAppCheckToken": true}).to_string(),
        // Wrong types.
        &json!({"debugToken": 1}).to_string(),
        &json!({"debugToken": SECRET, "limitedUse": "false"}).to_string(),
        &json!({}).to_string(),
        &oversized,
    ] {
        let r = call(&state, "POST", EXCHANGE, body);
        assert_eq!(r.status, 400, "{body}: {}", r.body);
        assert_eq!(r.body["error"]["status"], "INVALID_ARGUMENT");
    }
    // The verb is POST only.
    assert_eq!(call(&state, "GET", EXCHANGE, "").status, 405);
}

// ------------------------------------------------------------------------------------------
// JWKS
// ------------------------------------------------------------------------------------------

#[test]
fn the_jwks_publishes_the_public_key_and_no_private_material() {
    let state = app_check_state(1);
    for path in ["/v1/jwks", "/v1beta/jwks"] {
        let r = call(&state, "GET", path, "");
        assert_eq!(r.status, 200, "{path}");
        let keys = r.body["keys"].as_array().expect("a JWK set");
        assert_eq!(keys.len(), 1, "only this instance's App Check key");
        let key = &keys[0];
        assert_eq!(key["kty"], "RSA");
        assert_eq!(key["alg"], "RS256");
        assert_eq!(key["use"], "sig");
        assert_eq!(key["kid"], state.signer.kid());
        // Public modulus and exponent only: no private CRT parameters.
        let rendered = r.body.to_string();
        for private in ["\"d\"", "\"p\"", "\"q\"", "\"dp\"", "\"dq\"", "\"qi\""] {
            assert!(!rendered.contains(private), "{path} leaks {private}");
        }
    }
    assert_eq!(call(&state, "POST", "/v1/jwks", "").status, 405);
}

#[test]
fn two_daemon_instances_reject_each_others_locally_issued_tokens() {
    // Two independently keyed instances with identical project configuration.
    let first = app_check_state(1);
    let second = app_check_state(2);
    assert_ne!(first.signer.kid(), second.signer.kid());

    let r = call(&first, "POST", EXCHANGE, &exchange_body(SECRET));
    assert_eq!(r.status, 200, "{}", r.body);
    let token = r.body["token"].as_str().unwrap().to_owned();

    let at = LogicalInstant::from_unix_seconds(START);
    let own = first.registry.read().unwrap();
    assert!(verify_token(&token, &own, "demo-app", first.signer.as_ref(), at).is_ok());
    let foreign = second.registry.read().unwrap();
    assert_eq!(
        verify_token(&token, &foreign, "demo-app", second.signer.as_ref(), at),
        Err(fireemu_core_app_check::verify::AppCheckFailure::UnknownKeyId),
        "the other instance does not even know this key"
    );
    // Relabelling the header with the other instance's key ID does not help either: the
    // signature was made with a different private key.
    let (_, rest) = token.split_once('.').unwrap();
    let relabelled = format!(
        "{}.{rest}",
        fireemu_core_app_check::jwt::base64url_encode(
            format!(
                r#"{{"alg":"RS256","kid":"{}","typ":"JWT"}}"#,
                second.signer.kid()
            )
            .as_bytes()
        )
    );
    assert_eq!(
        verify_token(
            &relabelled,
            &foreign,
            "demo-app",
            second.signer.as_ref(),
            at
        ),
        Err(fireemu_core_app_check::verify::AppCheckFailure::BadSignature)
    );
}

// ------------------------------------------------------------------------------------------
// Privileged debug-token management
// ------------------------------------------------------------------------------------------

const TOKENS: &str =
    "/emulator/v1/projects/demo-app/apps/1:1234567890:web:local-test-app/debugTokens";

#[test]
fn debug_token_management_requires_the_control_token_without_an_origin_header() {
    let state = app_check_state(1);
    let wrong = RequestHeaders {
        authorization: Some("Bearer not-the-control-token".to_owned()),
        ..RequestHeaders::default()
    };
    let owner = RequestHeaders {
        authorization: Some("Bearer owner".to_owned()),
        ..RequestHeaders::default()
    };
    let loopback_origin = RequestHeaders {
        origin: Some("http://localhost:4000".to_owned()),
        ..RequestHeaders::default()
    };
    for (method, path) in [
        ("GET", TOKENS),
        ("POST", TOKENS),
        ("DELETE", &format!("{TOKENS}/dbg-1")),
    ] {
        for headers in [&RequestHeaders::default(), &wrong, &owner, &loopback_origin] {
            let r = call_with(&state, method, path, "{}", headers);
            assert_eq!(
                r.status, 403,
                "{method} {path} must need the control token: {}",
                r.body
            );
            assert!(r.body["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("CONTROL_TOKEN_REQUIRED"));
        }
        // The same request with the control token gets past the guard.
        let r = call_with(&state, method, path, "{}", &control());
        assert_ne!(r.status, 403, "{method} {path} with the control token");
    }
}

#[test]
fn a_created_debug_token_returns_its_secret_once_and_then_only_a_digest_prefix() {
    let state = app_check_state(1);
    let created = call_with(
        &state,
        "POST",
        TOKENS,
        &json!({"displayName": "ci runner", "generate": true}).to_string(),
        &control(),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    let secret = created.body["debugToken"]
        .as_str()
        .expect("the raw secret is returned exactly once")
        .to_owned();
    let token_id = created.body["tokenId"].as_str().unwrap().to_owned();
    assert!(fireemu_core_app_check::exchange::canonical_debug_token(&secret).is_some());

    // The generated secret exchanges.
    let exchanged = call(&state, "POST", EXCHANGE, &exchange_body(&secret));
    assert_eq!(exchanged.status, 200, "{}", exchanged.body);

    // The list never shows the secret again, nor the full digest.
    let listed = call_with(&state, "GET", TOKENS, "", &control());
    assert_eq!(listed.status, 200, "{}", listed.body);
    let rendered = listed.body.to_string();
    assert!(
        !rendered.contains(&secret),
        "the raw secret must never reappear"
    );
    let entry = &listed.body["debugTokens"][0];
    assert_eq!(entry["tokenId"], token_id.as_str());
    assert_eq!(entry["displayName"], "ci runner");
    assert_eq!(entry["digestPrefix"].as_str().unwrap().len(), 8);
    assert!(entry["createdAt"].as_str().unwrap().starts_with("2026-"));
    assert!(entry.get("digest").is_none());

    // Deletion stops future exchanges.
    let deleted = call_with(
        &state,
        "DELETE",
        &format!("{TOKENS}/{token_id}"),
        "",
        &control(),
    );
    assert_eq!(deleted.status, 200, "{}", deleted.body);
    assert_eq!(
        call(&state, "POST", EXCHANGE, &exchange_body(&secret)).status,
        403
    );
    assert_eq!(
        call_with(
            &state,
            "DELETE",
            &format!("{TOKENS}/{token_id}"),
            "",
            &control()
        )
        .status,
        404
    );
    // The statically configured secret is unaffected.
    assert_eq!(
        call(&state, "POST", EXCHANGE, &exchange_body(SECRET)).status,
        200
    );
}

#[test]
fn a_supplied_uuid_is_canonicalized_and_a_malformed_creation_is_refused() {
    let state = app_check_state(1);
    let supplied = "33333333-3333-4333-B333-333333333333";
    let created = call_with(
        &state,
        "POST",
        TOKENS,
        &json!({"displayName": "manual", "debugToken": supplied}).to_string(),
        &control(),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    assert_eq!(
        created.body["debugToken"],
        supplied.to_lowercase(),
        "the stored credential is the canonical lowercase form"
    );
    // Exchanging with either case works, because both canonicalize to the same digest.
    for text in [supplied, &supplied.to_lowercase()] {
        assert_eq!(
            call(&state, "POST", EXCHANGE, &exchange_body(text)).status,
            200
        );
    }

    for body in [
        json!({"debugToken": "not-a-uuid"}).to_string(),
        json!({"debugToken": SECRET, "generate": true}).to_string(),
        json!({"displayName": "x"}).to_string(),
        json!({"generate": true, "unknown": 1}).to_string(),
        json!({"generate": true, "displayName": ""}).to_string(),
        json!({"generate": true, "displayName": "n".repeat(129)}).to_string(),
    ] {
        let r = call_with(&state, "POST", TOKENS, &body, &control());
        assert_eq!(r.status, 400, "{body}: {}", r.body);
    }
}

#[test]
fn an_unconfigured_app_reads_exactly_like_an_unknown_project() {
    let state = app_check_state(1);
    let unknown_app =
        "/emulator/v1/projects/demo-app/apps/1:1234567890:web:never-registered/debugTokens";
    let unknown_project =
        "/emulator/v1/projects/demo-nope/apps/1:1234567890:web:local-test-app/debugTokens";
    let a = call_with(&state, "GET", unknown_app, "", &control());
    let b = call_with(&state, "GET", unknown_project, "", &control());
    assert_eq!(a.status, 404);
    assert_eq!(a.status, b.status);
    assert_eq!(a.body, b.body);
}

// ------------------------------------------------------------------------------------------
// Observations
// ------------------------------------------------------------------------------------------

#[test]
fn every_exchange_is_observed_without_a_secret_a_token_or_an_epoch() {
    let state = app_check_state(1);
    call(&state, "POST", EXCHANGE, &exchange_body(SECRET));
    call(&state, "POST", EXCHANGE, &exchange_body(OTHER_SECRET));
    let registry = state.registry.read().unwrap();
    let observations = registry.observations("demo-app");
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].category.as_str(), "valid");
    assert_eq!(observations[0].app_id, APP_ID);
    assert!(observations[0].admitted);
    assert_eq!(observations[1].category.as_str(), "invalid");
    assert_eq!(observations[1].app_id, "unknown");
    assert!(!observations[1].admitted);

    let epoch = registry.project_epoch("demo-app").unwrap().claim_text();
    let rendered = format!("{observations:?}");
    for secret in [SECRET, OTHER_SECRET, epoch.as_str()] {
        assert!(!rendered.contains(secret), "an observation leaked {secret}");
    }
    assert!(
        !rendered.contains("eyJ"),
        "no observation carries a raw JWT"
    );
}

// ------------------------------------------------------------------------------------------
// Over a real socket
// ------------------------------------------------------------------------------------------

async fn raw(addr: std::net::SocketAddr, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).into_owned()
}

fn body_of(response: &str) -> Value {
    let start = response.find("\r\n\r\n").expect("a header/body split") + 4;
    serde_json::from_str(&response[start..]).expect("a JSON body")
}

#[tokio::test]
async fn the_exchange_and_the_jwks_are_served_over_a_real_socket_and_never_cached() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = auth_state(Some(app_check_state(1)));
    let server = tokio::spawn(fireemu_adapter_http::server::serve(listener, state));

    let body = exchange_body(SECRET);
    let response = raw(
        addr,
        &format!(
            "POST {EXCHANGE} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(
        response.to_lowercase().contains("cache-control: no-store"),
        "the exchange response must never be cached: {response}"
    );
    assert!(body_of(&response)["token"].is_string());

    let jwks = raw(
        addr,
        "GET /v1/jwks HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(jwks.starts_with("HTTP/1.1 200"), "{jwks}");
    assert!(jwks.to_lowercase().contains("cache-control: no-store"));
    assert_eq!(body_of(&jwks)["keys"].as_array().unwrap().len(), 1);

    // A browser origin reaches the exchange without the control token: it is a bootstrap
    // route, not a control route, even though it lives under /v1/.
    let from_browser = raw(
        addr,
        &format!(
            "POST {EXCHANGE} HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost:5173\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert!(from_browser.starts_with("HTTP/1.1 200"), "{from_browser}");

    // The management route, on the same listener, still needs the control token.
    let management = raw(
        addr,
        &format!("GET {TOKENS} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(management.starts_with("HTTP/1.1 403"), "{management}");
    assert!(management
        .to_lowercase()
        .contains("cache-control: no-store"));
    let authorized = raw(
        addr,
        &format!("GET {TOKENS} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {CONTROL_TOKEN}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(authorized.starts_with("HTTP/1.1 200"), "{authorized}");

    server.abort();
}

#[tokio::test]
async fn every_app_check_route_is_not_found_while_the_section_is_disabled() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(fireemu_adapter_http::server::serve(
        listener,
        auth_state(None),
    ));

    for (method, path) in [("GET", "/v1/jwks"), ("GET", TOKENS), ("POST", EXCHANGE)] {
        let response = raw(
            addr,
            &format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 404"),
            "{method} {path}: {response}"
        );
        assert!(body_of(&response)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("appCheck.enabled"));
    }
    server.abort();
}
