//! App Check enforcement for Firebase Authentication (specification sections 12, 13.3, 17 and
//! 19; obligations `AC-AUTH-001`, `AC-BOUNDARY-001` and `AC-HEADER-001`).
//!
//! The scenarios of the Authentication list are all here: an enforced sign-up creates no user,
//! an enforced refresh rotates no credential, an enforced MFA finalize consumes no assertion,
//! and Admin account management follows the explicit bypass. The full mode x credential matrix
//! runs over `accounts:signUp`, which is the route with the most visible side effect.

mod app_check_support;

use std::sync::{Arc, Mutex};

use app_check_support as fixture;
use fireemu_adapter_http::identity_toolkit::{
    handle_with, AuthState, JsonResponse, RequestHeaders,
};
use fireemu_core_app_check::verify::BaselineMode;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_auth::totp::{totp_at, TotpParams};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";
const ADMIN: &str = "/identitytoolkit.googleapis.com/v1/projects/demo-app";
const REFRESH: &str = "/securetoken.googleapis.com/v1/token";

/// One Auth listener with an App Check policy of the given baseline mode.
struct Harness {
    auth: Arc<AuthState>,
    app_check: Arc<fireemu_adapter_http::app_check::AppCheckState>,
}

fn harness(mode: BaselineMode) -> Harness {
    let clock = fixture::clock();
    let app_check = fixture::app_check_state(1, clock.clone());
    let auth = Arc::new(AuthState {
        store: Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(5),
            TotpPolicy::default(),
        ))),
        clock,
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: Some(fixture::CONTROL_TOKEN.to_owned()),
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: true,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        app_check: Some(app_check.clone()),
        app_check_policy: fixture::policy(&app_check, "auth", mode),
        tenancy: None,
    });
    Harness { auth, app_check }
}

fn harness_with_totp_extension(mode: BaselineMode) -> Harness {
    let mut harness = harness(mode);
    Arc::get_mut(&mut harness.auth)
        .expect("the harness is the sole AuthState owner")
        .totp_extension_enabled = true;
    harness
}

impl Harness {
    /// A request carrying exactly the App Check field values given.
    fn call(&self, method: &str, path: &str, body: &Value, app_check: &[&str]) -> JsonResponse {
        handle_with(
            &self.auth,
            method,
            path,
            &RequestHeaders {
                app_check: app_check.iter().map(|v| (*v).to_owned()).collect(),
                ..RequestHeaders::default()
            },
            body,
        )
    }

    fn post(&self, path: &str, body: &Value, app_check: &[&str]) -> JsonResponse {
        self.call("POST", path, body, app_check)
    }

    fn valid_token(&self) -> String {
        fixture::token(&self.app_check, "demo-app", fixture::APP_ID)
    }

    fn user_count(&self) -> usize {
        self.auth
            .store
            .lock()
            .expect("the store is not poisoned")
            .users_by_creation()
            .len()
    }
}

fn sign_up_body(email: &str) -> Value {
    json!({"email": email, "password": "hunter22", "returnSecureToken": true})
}

// ------------------------------------------------------------------------------------------
// Scenario 1: an enforced sign-up without App Check creates no user
// ------------------------------------------------------------------------------------------

#[test]
fn an_enforced_sign_up_without_app_check_creates_no_user() {
    let h = harness(BaselineMode::Enforced);
    let denied = h.post(
        &format!("{V1}/accounts:signUp"),
        &sign_up_body("a@example.com"),
        &[],
    );
    assert_eq!(denied.status, 403, "{}", denied.body);
    assert_eq!(denied.body["error"]["status"], "PERMISSION_DENIED");
    assert_eq!(denied.body["error"]["reason"], "APP_CHECK_REQUIRED");
    assert_eq!(h.user_count(), 0, "a denied sign-up creates no user");

    let admitted = h.post(
        &format!("{V1}/accounts:signUp"),
        &sign_up_body("a@example.com"),
        &[&h.valid_token()],
    );
    assert_eq!(admitted.status, 200, "{}", admitted.body);
    assert_eq!(h.user_count(), 1);
}

// ------------------------------------------------------------------------------------------
// Scenario 2: an enforced refresh without App Check does not rotate credentials
// ------------------------------------------------------------------------------------------

#[test]
fn an_enforced_refresh_without_app_check_does_not_rotate_credentials() {
    let h = harness(BaselineMode::Enforced);
    let token = h.valid_token();
    let signed_up = h.post(
        &format!("{V1}/accounts:signUp"),
        &sign_up_body("b@example.com"),
        &[&token],
    );
    assert_eq!(signed_up.status, 200, "{}", signed_up.body);
    let refresh_token = signed_up.body["refreshToken"]
        .as_str()
        .expect("sign-up returns a refresh token")
        .to_owned();

    let denied = h.post(
        REFRESH,
        &json!({"grant_type": "refresh_token", "refresh_token": refresh_token}),
        &[],
    );
    assert_eq!(denied.status, 403, "{}", denied.body);

    // The refresh token still works, so nothing was consumed or rotated by the denial.
    let admitted = h.post(
        REFRESH,
        &json!({"grant_type": "refresh_token", "refresh_token": refresh_token}),
        &[&token],
    );
    assert_eq!(admitted.status, 200, "{}", admitted.body);
    assert!(admitted.body["id_token"].as_str().is_some());
}

// ------------------------------------------------------------------------------------------
// Scenario 3: an enforced MFA finalize without App Check does not consume the assertion
// ------------------------------------------------------------------------------------------

#[test]
fn an_enforced_mfa_finalize_without_app_check_does_not_consume_the_assertion() {
    let h = harness_with_totp_extension(BaselineMode::Enforced);
    let token = h.valid_token();
    let signed_up = h.post(
        &format!("{V1}/accounts:signUp"),
        &sign_up_body("c@example.com"),
        &[&token],
    );
    let id_token = signed_up.body["idToken"]
        .as_str()
        .expect("sign-up returns an ID token")
        .to_owned();

    let started = h.post(
        &format!("{V2}/accounts/mfaEnrollment:start"),
        &json!({"idToken": id_token, "totpEnrollmentInfo": {}}),
        &[&token],
    );
    assert_eq!(started.status, 200, "{}", started.body);
    let info = &started.body["totpSessionInfo"];
    let secret = info["sharedSecretKey"]
        .as_str()
        .expect("the enrollment returns a shared secret")
        .to_owned();
    let session = info["sessionInfo"]
        .as_str()
        .expect("the enrollment returns a session")
        .to_owned();

    let at = LogicalInstant::from_unix_seconds(fixture::START);
    let params = TotpParams {
        period_seconds: 30,
        digits: 6,
    };
    let key = fireemu_core_auth::base32::decode(&secret).expect("the shared secret is base32");
    let code = totp_at(&key, &params, at);
    let finalize = json!({
        "idToken": id_token,
        "totpVerificationInfo": {"sessionInfo": session, "verificationCode": format!("{code:06}")},
    });

    let denied = h.post(
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &finalize,
        &[],
    );
    assert_eq!(denied.status, 403, "{}", denied.body);

    // The very same assertion still finalizes, so the denial consumed nothing.
    let admitted = h.post(
        &format!("{V2}/accounts/mfaEnrollment:finalize"),
        &finalize,
        &[&token],
    );
    assert_eq!(admitted.status, 200, "{}", admitted.body);
}

// ------------------------------------------------------------------------------------------
// Scenario 4: Admin account management follows the explicit bypass
// ------------------------------------------------------------------------------------------

#[test]
fn admin_account_management_follows_the_explicit_bypass() {
    let h = harness(BaselineMode::Enforced);
    let owner = RequestHeaders {
        authorization: Some("Bearer owner".to_owned()),
        content_type: Some("application/json".to_owned()),
        ..RequestHeaders::default()
    };
    let created = handle_with(
        &h.auth,
        "POST",
        &format!("{ADMIN}/accounts"),
        &owner,
        &json!({"email": "admin@example.com", "password": "password1"}),
    );
    assert_eq!(
        created.status, 200,
        "the verified owner credential bypasses App Check: {}",
        created.body
    );
    assert_eq!(h.user_count(), 1);
}

/// The bypass is the owner credential, not the path: an Admin-shaped path without it is an
/// ordinary end-user request and is refused before `admin_guard` reports anything.
#[test]
fn an_admin_path_without_the_owner_credential_does_not_bypass_app_check() {
    let h = harness(BaselineMode::Enforced);
    let denied = handle_with(
        &h.auth,
        "POST",
        &format!("{ADMIN}/accounts"),
        &RequestHeaders {
            authorization: Some("Bearer not-the-owner".to_owned()),
            content_type: Some("application/json".to_owned()),
            ..RequestHeaders::default()
        },
        &json!({"email": "nope@example.com", "password": "password1"}),
    );
    assert_eq!(denied.status, 403, "{}", denied.body);
    assert_eq!(denied.body["error"]["reason"], "APP_CHECK_REQUIRED");
    assert_eq!(h.user_count(), 0);
}

/// The emulator inspection routes are privileged local administration, so they are outside
/// end-user enforcement (section 13.3) -- for a caller that presents the control token.
#[test]
fn emulator_inspection_routes_follow_the_explicit_bypass() {
    let h = harness(BaselineMode::Enforced);
    let listed = handle_with(
        &h.auth,
        "GET",
        "/emulator/v1/projects/demo-app/oobCodes",
        &RequestHeaders {
            authorization: Some(format!("Bearer {}", fixture::CONTROL_TOKEN)),
            ..RequestHeaders::default()
        },
        &json!({}),
    );
    assert_eq!(listed.status, 200, "{}", listed.body);
}

/// Section 12.2 grants the emulator-route bypass because those routes have "a separate
/// control-token guard", and that guard only challenges browser requests. A command-line
/// caller therefore has to present the control token to the App Check path itself, or the
/// route is an ordinary end-user request -- otherwise an enforced Auth service would let an
/// unauthenticated `Origin`-less request read action codes or wipe every account.
#[test]
fn emulator_inspection_routes_without_the_control_token_do_not_bypass() {
    let h = harness(BaselineMode::Enforced);
    let token = h.valid_token();
    let signed_up = h.post(
        &format!("{V1}/accounts:signUp"),
        &sign_up_body("victim@example.com"),
        &[&token],
    );
    assert_eq!(signed_up.status, 200, "{}", signed_up.body);

    for (method, path) in [
        ("GET", "/emulator/v1/projects/demo-app/oobCodes"),
        ("GET", "/emulator/v1/projects/demo-app/verificationCodes"),
        ("DELETE", "/emulator/v1/projects/demo-app/accounts"),
    ] {
        for (name, authorization) in [
            ("no credential at all", None),
            (
                "a wrong control token",
                Some("Bearer not-the-control-token"),
            ),
        ] {
            let denied = handle_with(
                &h.auth,
                method,
                path,
                &RequestHeaders {
                    authorization: authorization.map(str::to_owned),
                    ..RequestHeaders::default()
                },
                &json!({}),
            );
            assert_eq!(
                denied.status, 403,
                "{method} {path} with {name}: {}",
                denied.body
            );
            assert_eq!(denied.body["error"]["reason"], "APP_CHECK_REQUIRED");
        }
    }
    assert_eq!(h.user_count(), 1, "no denied request wiped the accounts");
}

/// The Auth JWKS is public-key discovery, not an end-user operation.
#[test]
fn the_auth_jwks_follows_the_explicit_bypass() {
    let h = harness(BaselineMode::Enforced);
    let keys = h.call("GET", "/.well-known/jwks.json", &json!({}), &[]);
    assert_eq!(keys.status, 200, "{}", keys.body);
}

// ------------------------------------------------------------------------------------------
// The enforcement matrix: mode x credential state (section 19)
// ------------------------------------------------------------------------------------------

#[test]
fn the_auth_enforcement_matrix_holds_for_every_mode_and_credential_state() {
    for (mode, denies) in [
        (BaselineMode::Off, false),
        (BaselineMode::Unenforced, false),
        (BaselineMode::Enforced, true),
    ] {
        let h = harness(mode);
        for (index, (name, value)) in fixture::credential_states(&h.app_check)
            .into_iter()
            .enumerate()
        {
            let values: Vec<&str> = value.iter().map(String::as_str).collect();
            let response = h.post(
                &format!("{V1}/accounts:signUp"),
                &sign_up_body(&format!("m{index}@example.com")),
                &values,
            );
            let expected_denial = denies && name != "valid";
            if expected_denial {
                assert_eq!(
                    response.status, 403,
                    "{mode} must deny {name}: {}",
                    response.body
                );
                assert_eq!(
                    response.body["error"]["reason"],
                    if name == "missing" {
                        "APP_CHECK_REQUIRED"
                    } else {
                        "APP_CHECK_INVALID"
                    },
                    "{mode}/{name} renders the public code only"
                );
            } else {
                assert_eq!(
                    response.status, 200,
                    "{mode} must admit {name}: {}",
                    response.body
                );
            }
        }
    }
}

/// A detailed failure reason never reaches the caller: every invalid credential renders the
/// same public body, whatever went wrong (section 17).
#[test]
fn a_denial_never_names_the_detailed_failure_reason() {
    let h = harness(BaselineMode::Enforced);
    let mut bodies = Vec::new();
    for (name, value) in fixture::credential_states(&h.app_check) {
        if name == "valid" || name == "missing" {
            continue;
        }
        let values: Vec<&str> = value.iter().map(String::as_str).collect();
        let response = h.post(
            &format!("{V1}/accounts:signUp"),
            &sign_up_body("x@e.com"),
            &values,
        );
        assert_eq!(response.status, 403);
        bodies.push(response.body.to_string());
    }
    assert!(
        bodies.windows(2).all(|w| w[0] == w[1]),
        "every invalid credential renders one body: {bodies:?}"
    );
    let rendered = bodies.join(" ");
    for internal in [
        "APP_CHECK_BAD_SIGNATURE",
        "APP_CHECK_EXPIRED",
        "APP_CHECK_WRONG_PROJECT",
        "APP_CHECK_UNKNOWN_APP",
        "APP_CHECK_MALFORMED",
    ] {
        assert!(
            !rendered.contains(internal),
            "{internal} is a privileged reason and must not be public"
        );
    }
}

// ------------------------------------------------------------------------------------------
// The header contract on this transport (AC-HEADER-001)
// ------------------------------------------------------------------------------------------

#[test]
fn the_auth_transport_refuses_duplicate_folded_empty_and_oversized_app_check_fields() {
    let h = harness(BaselineMode::Enforced);
    let valid = h.valid_token();
    let folded = format!("{valid},{valid}");
    let oversized = "a".repeat(16 * 1024 + 1);
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("duplicate", vec![valid.as_str(), valid.as_str()]),
        (
            "duplicate with a second, invalid value",
            vec![valid.as_str(), "junk"],
        ),
        ("folded", vec![folded.as_str()]),
        ("empty", vec![""]),
        ("whitespace", vec![" "]),
        ("oversized", vec![oversized.as_str()]),
    ];
    for (name, values) in cases {
        let response = h.post(
            &format!("{V1}/accounts:signUp"),
            &sign_up_body("h@e.com"),
            &values,
        );
        assert_eq!(response.status, 403, "{name} must never be admitted");
        assert_eq!(response.body["error"]["reason"], "APP_CHECK_INVALID");
    }
    assert_eq!(h.user_count(), 0, "no ambiguous header ever created a user");
}

/// The field name is matched case-insensitively, and a single well-formed value is admitted.
#[test]
fn one_well_formed_app_check_field_is_admitted() {
    let h = harness(BaselineMode::Enforced);
    let response = h.post(
        &format!("{V1}/accounts:signUp"),
        &sign_up_body("ok@example.com"),
        &[&h.valid_token()],
    );
    assert_eq!(response.status, 200, "{}", response.body);
}

// ------------------------------------------------------------------------------------------
// Observations (AC-OBS-001)
// ------------------------------------------------------------------------------------------

#[test]
fn an_off_service_records_nothing_and_an_unenforced_one_records_every_request() {
    let off = harness(BaselineMode::Off);
    let _ = off.post(
        &format!("{V1}/accounts:signUp"),
        &sign_up_body("o@e.com"),
        &["junk"],
    );
    assert!(
        off.app_check
            .registry
            .read()
            .expect("readable")
            .observed_projects()
            .is_empty(),
        "off does no token work at all"
    );

    let unenforced = harness(BaselineMode::Unenforced);
    let _ = unenforced.post(
        &format!("{V1}/accounts:signUp"),
        &sign_up_body("u@e.com"),
        &["junk"],
    );
    let observed = unenforced
        .app_check
        .registry
        .read()
        .expect("readable")
        .observations("demo-app");
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].service, "auth");
    assert_eq!(observed[0].transport, "http");
    assert_eq!(observed[0].operation, "accounts:signUp");
    assert_eq!(observed[0].app_id, "unknown");
    assert!(observed[0].admitted, "unenforced admits and records");
}

/// Section 15: an unrecognised path never becomes a metric label of its own.
#[test]
fn an_unknown_path_does_not_create_an_unbounded_operation_label() {
    let h = harness(BaselineMode::Unenforced);
    let _ = h.post(
        "/identitytoolkit.googleapis.com/v1/accounts:notARoute",
        &json!({}),
        &["junk"],
    );
    let observed = h
        .app_check
        .registry
        .read()
        .expect("readable")
        .observations("demo-app");
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].operation, "unknown");
}

// ------------------------------------------------------------------------------------------
// Over a real socket: the header contract must survive the HTTP stack (AC-HEADER-001)
// ------------------------------------------------------------------------------------------

async fn raw(addr: std::net::SocketAddr, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write the request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read the response");
    String::from_utf8_lossy(&response).into_owned()
}

/// Two `X-Firebase-AppCheck` field instances reach the daemon as two values, not as one
/// folded value the classifier would accept: the HTTP stack must not let a duplicate become a
/// credential (`INV-APPCHECK-009`).
#[tokio::test]
async fn duplicate_app_check_fields_over_a_real_socket_are_never_admitted() {
    let h = harness(BaselineMode::Enforced);
    let token = h.valid_token();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("a local address");
    let server = tokio::spawn(fireemu_adapter_http::server::serve(
        listener,
        h.auth.clone(),
    ));

    let body = sign_up_body("socket@example.com").to_string();
    let one = raw(
        addr,
        &format!(
            "POST {V1}/accounts:signUp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nX-Firebase-AppCheck: {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert!(one.starts_with("HTTP/1.1 200"), "{one}");

    // Mixed case on the second instance, so the case-insensitive match is exercised too.
    let body = sign_up_body("socket2@example.com").to_string();
    let two = raw(
        addr,
        &format!(
            "POST {V1}/accounts:signUp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nX-Firebase-AppCheck: {token}\r\nx-firebase-AppCheck: {token}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert!(two.starts_with("HTTP/1.1 403"), "{two}");
    assert!(two.contains("APP_CHECK_INVALID"), "{two}");
    assert_eq!(
        h.user_count(),
        1,
        "only the unambiguous request created a user"
    );
    server.abort();
}

/// The Auth preflight advertises the App Check request header so a browser SDK may send it.
#[tokio::test]
async fn the_auth_preflight_allows_the_app_check_request_header() {
    let h = harness(BaselineMode::Enforced);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("a local address");
    let server = tokio::spawn(fireemu_adapter_http::server::serve(
        listener,
        h.auth.clone(),
    ));
    let response = raw(
        addr,
        &format!("OPTIONS {V1}/accounts:signUp HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost:5173\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(response.starts_with("HTTP/1.1 204"), "{response}");
    assert!(
        response.to_lowercase().contains("x-firebase-appcheck"),
        "{response}"
    );
    server.abort();
}
