//! The emulator profile answers the requests below as the official emulator does (firebase-tools
//! 15.28.2). Every expected answer was probed in-process against the pinned `createApp("demo-app")`
//! and the case tables compare the official answer with fireemu's. Two families:
//!
//! - an ID token the operation does not read (`createAuthUri`, `sendOobCode PASSWORD_RESET` and
//!   `EMAIL_SIGNIN`, `resetPassword`, `signInWithCustomToken`) is not parsed, so a tenant it
//!   names that was just made does not make the request `USER_NOT_FOUND`
//!   (`operations.js` calls `parseIdToken` only in the operations listed in the tests);
//! - an Admin request on a project path with a body `tenantId` runs in that tenant of the path's
//!   project (`server.js:395-414`), for the default project and any other project alike.

#![allow(dead_code)] // the helpers are shared with the other tenant test files

use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthQueryLimits, AuthState, ClientApiKeyPolicy, FakeCustomTokenExpiry,
    IdpContinuationPolicy, RequestHeaders,
};
use fireemu_core_auth::jwt::decode_unsigned;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";
const KEY: &str = "fake-api-key";
const SECURE_TOKEN: &str = "/securetoken.googleapis.com/v1/token";
fn emulator_state() -> AuthState {
    AuthState {
        store: Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(5),
            TotpPolicy::default(),
        ))),
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        notices: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: true,
        idp_continuations: IdpContinuationPolicy::Disabled,
        query_limits: AuthQueryLimits::EmulatorUnbounded,
        client_api_key: ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry: FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
        idp_assertions: fireemu_adapter_http::identity_toolkit::IdpAssertionPolicy::Fixture,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    }
}

fn strict_state() -> AuthState {
    AuthState {
        idp_continuations: IdpContinuationPolicy::LocalBounded,
        query_limits: AuthQueryLimits::ProductionBounded,
        stateless_refresh_tokens: false,
        client_api_key: ClientApiKeyPolicy::Required,
        fake_custom_token_expiry: FakeCustomTokenExpiry::Reject,
        custom_token_trust: None,
        idp_assertions: fireemu_adapter_http::identity_toolkit::IdpAssertionPolicy::Fixture,
        ..emulator_state()
    }
}

fn owner() -> RequestHeaders {
    RequestHeaders {
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        content_type: Some("application/json".to_owned()),
        host: Some("127.0.0.1:9099".to_owned()),
        app_check: Vec::new(),
        peer_ip: None,
    }
}

fn admin(state: &AuthState, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let r = handle_with(state, method, path, &owner(), body);
    (r.status, r.body)
}

fn enable_tenants(state: &AuthState, project: &str) {
    let path = format!("/identitytoolkit.googleapis.com/admin/v2/projects/{project}/config?updateMask=multiTenant.allowTenants");
    let (status, body) = admin(
        state,
        "PATCH",
        &path,
        &json!({"multiTenant": {"allowTenants": true}}),
    );
    assert_eq!(status, 200, "{project}: {body}");
}

fn claims(id_token: &str) -> Value {
    serde_json::from_str(&decode_unsigned(id_token).unwrap().payload_json).unwrap()
}

fn client(state: &AuthState, route: &str, body: &Value) -> (u16, Value) {
    let r = handle(state, "POST", &format!("{route}?key={KEY}"), body);
    (r.status, r.body)
}

/// The two profiles over one project, with the project itself registered.
fn profiles() -> Vec<(&'static str, AuthState, Arc<AuthRegistry>)> {
    [("emulator", emulator_state()), ("strict", strict_state())]
        .into_iter()
        .map(|(label, mut state)| {
            let registry = Arc::new(AuthRegistry::new("demo-app", state.store.clone()));
            state.registry = Some(registry.clone());
            enable_tenants(&state, "demo-app");
            (label, state, registry)
        })
        .collect()
}

fn emulator() -> (AuthState, Arc<AuthRegistry>) {
    let (_, state, registry) = profiles().into_iter().next().unwrap();
    (state, registry)
}

fn tenant_names(state: &AuthState, project: &str) -> Vec<String> {
    let (status, body) = admin(
        state,
        "GET",
        &format!("{V2}/projects/{project}/tenants"),
        &json!({}),
    );
    assert_eq!(status, 200, "{body}");
    let mut names: Vec<String> = body["tenants"]
        .as_array()
        .map(|all| {
            all.iter()
                .filter_map(|t| t["name"].as_str())
                .filter_map(|name| name.rsplit('/').next().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn routed_state() -> (AuthState, Arc<AuthRegistry>) {
    let (mut state, registry) = emulator();
    state.allow_routed_projects = true;
    (state, registry)
}

fn alg_none(claims: &Value) -> String {
    use fireemu_core_auth::jwt::base64url_encode;
    format!(
        "{}.{}.",
        base64url_encode(br#"{"alg":"none","typ":"JWT"}"#),
        base64url_encode(claims.to_string().as_bytes())
    )
}

fn own_token(user: &str, tenant: &str) -> String {
    alg_none(&json!({
        "aud": "demo-app", "iss": "https://securetoken.google.com/demo-app",
        "sub": user, "user_id": user, "iat": 1_788_004_860, "exp": 1_788_008_400,
        "auth_time": 1_788_004_860,
        "firebase": {"sign_in_provider": "password", "identities": {}, "tenant": tenant}
    }))
}

/// The message of an answer, `-` for a success.
fn message_of(body: &Value) -> String {
    body["error"]["message"].as_str().unwrap_or("-").to_owned()
}

/// A client request with an ID token of `tenant` (a tenant that does not exist yet, so the
/// request makes it on the way) and the same tenant in the body: what the official emulator
/// answers, then what fireemu answers.
///
/// Rows: (case, route, body without tenant and token, official status, official message).
/// The official column was probed with `probe2.cjs` against the pinned emulator.
#[test]
#[allow(clippy::too_many_lines)]
fn an_id_token_the_operation_does_not_read_is_not_parsed_for_the_tenant_it_names() {
    let rows: Vec<(&str, &str, Value, u16, &str)> = vec![
        (
            "createAuthUri",
            "accounts:createAuthUri",
            json!({"identifier": "x@example.com", "continueUri": "http://localhost"}),
            200,
            "-",
        ),
        (
            "sendOobCode PASSWORD_RESET",
            "accounts:sendOobCode",
            json!({"requestType": "PASSWORD_RESET", "email": "x@example.com"}),
            400,
            "EMAIL_NOT_FOUND",
        ),
        (
            "sendOobCode EMAIL_SIGNIN",
            "accounts:sendOobCode",
            json!({"requestType": "EMAIL_SIGNIN", "email": "x@example.com"}),
            200,
            "-",
        ),
        (
            "resetPassword",
            "accounts:resetPassword",
            json!({"oobCode": "nope", "newPassword": "hunter22"}),
            400,
            "INVALID_OOB_CODE",
        ),
        (
            "signInWithCustomToken",
            "accounts:signInWithCustomToken",
            json!({"token": "{\"uid\":\"c1\"}"}),
            200,
            "-",
        ),
        // The operations that do parse the token keep answering as the official emulator does:
        // the user is not in the tenant that was just made.
        (
            "sendOobCode VERIFY_EMAIL",
            "accounts:sendOobCode",
            json!({"requestType": "VERIFY_EMAIL"}),
            400,
            "USER_NOT_FOUND",
        ),
        (
            "sendOobCode VERIFY_AND_CHANGE_EMAIL",
            "accounts:sendOobCode",
            json!({"requestType": "VERIFY_AND_CHANGE_EMAIL", "newEmail": "n@example.com"}),
            400,
            "USER_NOT_FOUND",
        ),
        (
            "signInWithEmailLink",
            "accounts:signInWithEmailLink",
            json!({"email": "x@example.com", "oobCode": "nope"}),
            400,
            "USER_NOT_FOUND",
        ),
        (
            "update",
            "accounts:update",
            json!({"displayName": "x"}),
            400,
            "USER_NOT_FOUND",
        ),
        (
            "delete",
            "accounts:delete",
            json!({}),
            400,
            "USER_NOT_FOUND",
        ),
        (
            "lookup",
            "accounts:lookup",
            json!({}),
            400,
            "USER_NOT_FOUND",
        ),
        (
            "signUp (an anonymous upgrade)",
            "accounts:signUp",
            json!({"email": "u@example.com", "password": "hunter22"}),
            400,
            "USER_NOT_FOUND",
        ),
    ];
    for (n, (case, route, body, status, message)) in rows.into_iter().enumerate() {
        let (state, registry) = emulator();
        let tenant = format!("tok-{n}");
        let mut body = body;
        body["tenantId"] = json!(tenant);
        body["idToken"] = json!(own_token("u1", &tenant));
        let (got, answered) = client(&state, &format!("{V1}/{route}"), &body);
        assert_eq!(
            (got, message_of(&answered)),
            (status, message.to_owned()),
            "{case}: {answered}"
        );
        // Either way the request named the tenant, so it is there.
        assert!(
            registry.tenant_store("demo-app", &tenant).is_some(),
            "{case}"
        );
    }
}

/// Answers that still differ from the official emulator's on a request carrying an ID token and a
/// tenant, pinned so a fix updates them deliberately (official column from the same probe). Not
/// part of the two over-refusals this file's other tests close; filed in
/// docs.local/issues/open/emulator-tenant-phone-and-idp-operations-differ-from-the-official-emulator.md.
#[test]
fn the_known_differences_for_the_tenant_phone_and_idp_operations_are_pinned() {
    // (case, route, body, fireemu status, fireemu message, official status, official message)
    let rows: Vec<(&str, &str, Value, u16, &str, u16, &str)> = vec![
        (
            "sendVerificationCode",
            "accounts:sendVerificationCode",
            json!({"phoneNumber": "+16505550101"}),
            200,
            "-",
            400,
            "UNSUPPORTED_TENANT_OPERATION",
        ),
        (
            "signInWithPhoneNumber",
            "accounts:signInWithPhoneNumber",
            json!({"sessionInfo": "x", "code": "123456"}),
            400,
            "USER_NOT_FOUND",
            400,
            "UNSUPPORTED_TENANT_OPERATION",
        ),
        (
            "signInWithIdp",
            "accounts:signInWithIdp",
            json!({"requestUri": "http://localhost", "postBody": "providerId=google.com&id_token=x"}),
            400,
            "USER_NOT_FOUND",
            400,
            "(an idp error, not USER_NOT_FOUND)",
        ),
    ];
    for (n, (case, route, body, status, message, _official_status, _official_message)) in
        rows.into_iter().enumerate()
    {
        let (state, _) = emulator();
        let tenant = format!("known-{n}");
        let mut body = body;
        body["tenantId"] = json!(tenant);
        body["idToken"] = json!(own_token("u1", &tenant));
        let (got, answered) = client(&state, &format!("{V1}/{route}"), &body);
        assert_eq!(
            (got, message_of(&answered)),
            (status, message.to_owned()),
            "{case}: {answered}"
        );
    }
}

/// An Admin request on a project path with a body `tenantId` runs in that tenant of the path's
/// project (`server.js:395-414`): the tenant is made there, the operation answers as it does for a
/// tenant path, and nothing is made in another project. Official column probed with `probe2.cjs`
/// for the default project and for another one (`demo-other`).
#[test]
fn an_admin_request_with_a_body_tenant_runs_in_that_tenant_of_the_paths_project() {
    within_a_minute(admin_body_tenant_table);
}

/// Runs `run` on its own thread and fails, rather than hangs, when it does not finish (a routed
/// project's gate held across the tenant's own gate would deadlock the request).
fn within_a_minute(run: fn()) {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        run();
        let _ = done.send(());
    });
    finished
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the requests finished: nothing deadlocked");
}

fn admin_body_tenant_table() {
    // (case, path suffix, body, official status, official message)
    let rows: Vec<(&str, &str, Value, u16, &str)> = vec![
        (
            "lookup",
            "accounts:lookup",
            json!({"localId": ["x"]}),
            200,
            "-",
        ),
        (
            "create",
            "accounts",
            json!({"email": "m@example.com", "password": "hunter22"}),
            200,
            "-",
        ),
        (
            "update",
            "accounts:update",
            json!({"localId": "x", "displayName": "d"}),
            400,
            "USER_NOT_FOUND",
        ),
        (
            "delete",
            "accounts:delete",
            json!({"localId": "x"}),
            400,
            "USER_NOT_FOUND",
        ),
        (
            "batchCreate",
            "accounts:batchCreate",
            json!({"users": [{"localId": "u", "email": "b@example.com"}]}),
            200,
            "-",
        ),
        (
            "batchDelete",
            "accounts:batchDelete",
            json!({"localIds": ["x"], "force": true}),
            200,
            "-",
        ),
        (
            "query",
            "accounts:query",
            json!({"returnUserInfo": false}),
            200,
            "-",
        ),
        (
            "sendOobCode",
            "accounts:sendOobCode",
            json!({"requestType": "PASSWORD_RESET", "email": "x@example.com", "returnOobLink": true}),
            400,
            "EMAIL_NOT_FOUND",
        ),
    ];
    for project in ["demo-other", "demo-app"] {
        for (n, (case, suffix, body, status, message)) in rows.iter().enumerate() {
            let (state, registry) = routed_state();
            let tenant = format!("body-{n}");
            let mut body = body.clone();
            body["tenantId"] = json!(tenant);
            let (got, answered) = admin(
                &state,
                "POST",
                &format!("{V1}/projects/{project}/{suffix}"),
                &body,
            );
            assert_eq!(
                (got, message_of(&answered)),
                (*status, (*message).to_owned()),
                "{project} {case}: {answered}"
            );
            // The tenant is the path's project's, and nothing landed in the other project.
            assert!(
                registry.tenant_store(project, &tenant).is_some(),
                "{project} {case}"
            );
            let other = if project == "demo-app" {
                "demo-other"
            } else {
                "demo-app"
            };
            assert!(
                registry.tenant_store(other, &tenant).is_none(),
                "{project} {case}"
            );
        }
    }
}

/// The body's tenant is a selector only for a request the owner (or control) guard admitted: a
/// caller without the credential is refused as it is for a tenant path, and nothing is served
/// from, or written to, the tenant.
#[test]
fn a_caller_without_the_owner_credential_cannot_pick_a_tenant_through_the_body() {
    let (state, registry) = routed_state();
    // The tenant exists and holds an account.
    let (status, created) = admin(
        &state,
        "POST",
        &format!("{V1}/projects/demo-app/tenants/held/accounts"),
        &json!({"email": "held@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    let garbage = RequestHeaders {
        authorization: Some("Bearer garbage".to_owned()),
        ..owner()
    };
    let keyless = RequestHeaders {
        authorization: None,
        ..owner()
    };
    for headers in [garbage, keyless] {
        for (suffix, body) in [
            (
                "accounts:lookup",
                json!({"tenantId": "held", "email": ["held@example.com"]}),
            ),
            (
                "accounts",
                json!({"tenantId": "held", "email": "x@example.com", "password": "hunter22"}),
            ),
        ] {
            let r = handle_with(
                &state,
                "POST",
                &format!("{V1}/projects/demo-app/{suffix}"),
                &headers,
                &body,
            );
            assert!(
                matches!(r.status, 401 | 403 | 404 | 405),
                "{suffix}: {} {}",
                r.status,
                r.body
            );
        }
    }
    let held = registry.tenant_store("demo-app", "held").unwrap();
    assert_eq!(held.lock().unwrap().user_count(), 1);
    // A refused request on an unknown project makes and installs nothing.
    let r = handle_with(
        &state,
        "POST",
        &format!("{V1}/projects/demo-late/accounts:lookup"),
        &RequestHeaders {
            authorization: Some("Bearer garbage".to_owned()),
            ..owner()
        },
        &json!({"tenantId": "t", "localId": ["x"]}),
    );
    assert_eq!(r.status, 401, "{}", r.body);
    assert!(registry.routed_store_for("demo-late").is_none());
}

/// The tenant of an ID token is checked against the tenant the request names for every operation
/// (`server.js:399-403`, before any operation runs), also for the ones that never read the token:
/// `TENANT_ID_MISMATCH`, and no tenant is made (official column probed).
#[test]
fn a_token_of_another_tenant_is_a_mismatch_for_every_operation() {
    for (n, (route, body)) in [
        (
            "accounts:createAuthUri",
            json!({"identifier": "x@example.com", "continueUri": "http://localhost"}),
        ),
        (
            "accounts:signInWithCustomToken",
            json!({"token": "{\"uid\":\"c1\"}"}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (state, registry) = emulator();
        let mut body = body;
        body["tenantId"] = json!(format!("named-{n}"));
        body["idToken"] = json!(own_token("u1", &format!("token-{n}")));
        let (status, refused) = client(&state, &format!("{V1}/{route}"), &body);
        assert_eq!(status, 400, "{route}: {refused}");
        assert_eq!(message_of(&refused), "TENANT_ID_MISMATCH", "{route}");
        assert!(registry.tenants("demo-app").is_empty(), "{route}");
    }
}
