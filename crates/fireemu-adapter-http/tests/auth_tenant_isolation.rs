//! Tenant isolation matrix (TP-AUTH-E-01, parent AUTH-TENANT-BLOCKING).
//!
//! Rows: (a) a tenant-A credential on a tenant-B route is refused with a typed class and
//! mutates neither tenant; (b) project-level Admin lookup does not see tenant users;
//! (c) tenant settings inherit from the project at creation and tenant patches override
//! them, with a client operation obeying the effective value; (d) provider configurations
//! are namespaced per tenant; (e) deleting a tenant invalidates its credentials and leaves
//! the sibling tenant and the project untouched; (f) every negative row has a same-tenant
//! positive control.
//!
//! The refusal classes asserted here are the classes fireemu returns locally. They are
//! spec-derived hypotheses for Identity Platform, not production observations.

use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthQueryLimits, AuthState, ClientApiKeyPolicy, FakeCustomTokenExpiry,
    IdpContinuationPolicy, RequestHeaders,
};
use fireemu_core_auth::jwt::{base64url_encode, decode_unsigned};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_session::tenancy::Tenancy;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";
const ADMIN_V2: &str = "/identitytoolkit.googleapis.com/v2/projects/demo-app";
const PROJECT_CONFIG: &str = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
const SECURE_TOKEN: &str = "/securetoken.googleapis.com/v1/token";
const EMULATOR: &str = "/emulator/v1/projects/demo-app";
const KEY: &str = "fake-api-key";
const TENANT_A: &str = "tenant-a";
const TENANT_B: &str = "tenant-b";

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
        ..emulator_state()
    }
}

/// Both adapter profiles with two explicit tenants registered under the default project.
fn profiles() -> Vec<(&'static str, AuthState, Arc<AuthRegistry>)> {
    [("emulator", emulator_state()), ("strict", strict_state())]
        .into_iter()
        .map(|(label, mut state)| {
            let registry = Arc::new(AuthRegistry::new("demo-app", state.store.clone()));
            for tenant in [TENANT_A, TENANT_B] {
                registry.ensure_tenant("demo-app", tenant).unwrap();
            }
            state.registry = Some(registry.clone());
            (label, state, registry)
        })
        .collect()
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

fn post(state: &AuthState, path: &str, body: &Value) -> (u16, Value) {
    let path = with_client_key(state, path, KEY);
    let r = handle(state, "POST", &path, body);
    (r.status, r.body)
}

/// Client SDKs always send their API key. Under a profile that refuses keyless client calls,
/// the plain helper adds it to client routes that do not carry one, as an SDK would.
fn with_client_key(state: &AuthState, path: &str, key: &str) -> String {
    let project_scoped = path.contains("/projects/") || path.starts_with("/emulator");
    let keyed = path.contains("key=") || path.contains("apiKey=");
    if state.client_api_key != ClientApiKeyPolicy::Required || project_scoped || keyed {
        return path.to_owned();
    }
    let separator = if path.contains('?') { '&' } else { '?' };
    format!("{path}{separator}key={key}")
}

fn admin(state: &AuthState, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let r = handle_with(state, method, path, &owner(), body);
    (r.status, r.body)
}

fn claims(id_token: &str) -> Value {
    serde_json::from_str(&decode_unsigned(id_token).unwrap().payload_json).unwrap()
}

/// The error class: the message up to the first ` : ` detail separator.
fn class(body: &Value) -> String {
    body["error"]["message"]
        .as_str()
        .unwrap_or_default()
        .split(" : ")
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Client SDK request shape: the API key in the query, the tenant in the body.
fn client(state: &AuthState, route: &str, tenant: &str, body: Value) -> (u16, Value) {
    let mut body = body;
    body["tenantId"] = Value::String(tenant.to_owned());
    post(state, &format!("{route}?key={KEY}"), &body)
}

fn tenant_admin_path(tenant: &str, suffix: &str) -> String {
    format!("{V1}/projects/demo-app/tenants/{tenant}/{suffix}")
}

fn sign_up(state: &AuthState, tenant: &str, email: &str) -> Value {
    let (status, created) = client(
        state,
        &format!("{V1}/accounts:signUp"),
        tenant,
        json!({"email": email, "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{tenant}: {created}");
    assert_eq!(
        created["idToken"].as_str().map(claims).unwrap()["firebase"]["tenant"],
        tenant
    );
    created
}

/// Every account of a namespace as the Admin batchGet route reports it.
fn snapshot(state: &AuthState, tenant: Option<&str>) -> Value {
    let path = match tenant {
        Some(tenant) => tenant_admin_path(tenant, "accounts:batchGet?maxResults=1000"),
        None => format!("{V1}/projects/demo-app/accounts:batchGet?maxResults=1000"),
    };
    let (status, body) = admin(state, "GET", &path, &json!({}));
    assert_eq!(status, 200, "{body}");
    body
}

fn oob_codes(state: &AuthState, tenant: &str) -> Vec<Value> {
    let (status, body) = admin(
        state,
        "GET",
        &format!("{EMULATOR}/tenants/{tenant}/oobCodes"),
        &json!({}),
    );
    assert_eq!(status, 200, "{body}");
    body["oobCodes"].as_array().cloned().unwrap_or_default()
}

fn verification_codes(state: &AuthState, tenant: &str) -> Vec<Value> {
    let (status, body) = admin(
        state,
        "GET",
        &format!("{EMULATOR}/tenants/{tenant}/verificationCodes"),
        &json!({}),
    );
    assert_eq!(status, 200, "{body}");
    body["verificationCodes"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn idp_jwt(payload: &Value) -> String {
    format!(
        "{}.{}.",
        base64url_encode(br#"{"alg":"RS256","typ":"JWT"}"#),
        base64url_encode(payload.to_string().as_bytes())
    )
}

fn google_post_body(sub: &str, email: &str) -> String {
    let payload = json!({"sub": sub, "email": email, "email_verified": true});
    format!("id_token={}&providerId=google.com", idp_jwt(&payload))
}

/// How a client names the destination tenant. The SDK shape carries the API key and the
/// body tenant; the other two shapes are the selector forms the handler accepts as well.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Selector {
    KeyAndBody,
    BodyOnly,
    QueryOnly,
}

impl Selector {
    const ALL: [Self; 3] = [Self::KeyAndBody, Self::BodyOnly, Self::QueryOnly];

    /// The shapes a profile serves. The strict profile refuses a client request without an
    /// API key before any selector is read, as production does, so only the SDK shape reaches
    /// tenant selection there (`strict_keyless_tenant_selectors_are_unregistered_callers`).
    fn admitted(state: &AuthState) -> &'static [Self] {
        if state.client_api_key == ClientApiKeyPolicy::Required {
            &[Self::KeyAndBody]
        } else {
            &Self::ALL
        }
    }

    fn request(self, state: &AuthState, route: &str, tenant: &str, body: Value) -> (u16, Value) {
        let mut body = body;
        match self {
            Self::KeyAndBody => {
                body["tenantId"] = Value::String(tenant.to_owned());
                post(state, &format!("{route}?key={KEY}"), &body)
            }
            Self::BodyOnly => {
                body["tenantId"] = Value::String(tenant.to_owned());
                post(state, route, &body)
            }
            Self::QueryOnly => post(state, &format!("{route}?tenantId={tenant}"), &body),
        }
    }
}

/// The strict profile refuses the fireemu-only keyless selector shapes as production refuses
/// any client call without an API key: 403 before tenant selection, with no state change
/// (sandbox recording 2026-09-23, `auth-account/privilege/credentials`).
#[test]
fn strict_keyless_tenant_selectors_are_unregistered_callers() {
    let (_, state, _registry) = profiles().pop().unwrap();
    assert_eq!(state.client_api_key, ClientApiKeyPolicy::Required);
    let a = sign_up(&state, TENANT_A, "keyless@example.com");
    let before_a = snapshot(&state, Some(TENANT_A));
    let token = a["idToken"].as_str().unwrap();
    let refresh = a["refreshToken"].as_str().unwrap();
    for (route, body) in [
        (format!("{V1}/accounts:lookup"), json!({"idToken": token})),
        (
            SECURE_TOKEN.to_owned(),
            json!({"grant_type": "refresh_token", "refresh_token": refresh}),
        ),
    ] {
        for selector in [Selector::BodyOnly, Selector::QueryOnly] {
            let mut body = body.clone();
            let path = if selector == Selector::BodyOnly {
                body["tenantId"] = Value::String(TENANT_A.to_owned());
                route.clone()
            } else {
                format!("{route}?tenantId={TENANT_A}")
            };
            let refused = handle(&state, "POST", &path, &body);
            assert_eq!(refused.status, 403, "{path} {selector:?}: {}", refused.body);
            assert_eq!(refused.body["error"]["status"], "PERMISSION_DENIED");
        }
    }
    assert_eq!(snapshot(&state, Some(TENANT_A)), before_a);
}

// ---------------------------------------------------------------------------------------
// (a) + (f): a tenant-A ID token on tenant-B routes.
// ---------------------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn a_tenant_id_token_is_refused_on_every_other_tenant_route_without_mutation() {
    for (profile, state, _registry) in profiles() {
        let a = sign_up(&state, TENANT_A, "same@example.com");
        let b = sign_up(&state, TENANT_B, "same@example.com");
        let token_a = a["idToken"].as_str().unwrap().to_owned();
        let token_b = b["idToken"].as_str().unwrap().to_owned();
        let before_a = snapshot(&state, Some(TENANT_A));
        let before_b = snapshot(&state, Some(TENANT_B));
        let before_project = snapshot(&state, None);

        let rows: Vec<(&str, String, Value)> = vec![
            (
                "accounts:lookup",
                format!("{V1}/accounts:lookup"),
                json!({"idToken": token_a}),
            ),
            (
                "accounts:update profile",
                format!("{V1}/accounts:update"),
                json!({"idToken": token_a, "displayName": "crossed"}),
            ),
            (
                "accounts:update password",
                format!("{V1}/accounts:update"),
                json!({"idToken": token_a, "password": "changed-password-1"}),
            ),
            (
                "accounts:delete",
                format!("{V1}/accounts:delete"),
                json!({"idToken": token_a}),
            ),
            (
                "accounts:sendOobCode VERIFY_EMAIL",
                format!("{V1}/accounts:sendOobCode"),
                json!({"idToken": token_a, "requestType": "VERIFY_EMAIL"}),
            ),
            (
                "accounts:signInWithIdp link",
                format!("{V1}/accounts:signInWithIdp"),
                json!({
                    "idToken": token_a,
                    "postBody": google_post_body("g-cross", "same@example.com"),
                    "requestUri": "http://localhost",
                    "returnSecureToken": true,
                }),
            ),
            (
                "mfaEnrollment:start",
                format!("{V2}/accounts/mfaEnrollment:start"),
                json!({
                    "idToken": token_a,
                    "phoneEnrollmentInfo": {"phoneNumber": "+15550001111", "recaptchaToken": "x"},
                }),
            ),
        ];
        for (label, route, body) in &rows {
            for &selector in Selector::admitted(&state) {
                let (status, refused) = selector.request(&state, route, TENANT_B, body.clone());
                assert_eq!(status, 400, "{profile} {label} {selector:?}: {refused}");
                // The class depends on which selector picked the store: the API key routes
                // the request into tenant B, whose verifier rejects the tenant-A token; the
                // bare body or query tenant is compared with the token's tenant first.
                let expected = match selector {
                    Selector::KeyAndBody => "INVALID_ID_TOKEN",
                    Selector::BodyOnly | Selector::QueryOnly => "TENANT_ID_MISMATCH",
                };
                assert_eq!(
                    class(&refused),
                    expected,
                    "{profile} {label} {selector:?}: {refused}"
                );
            }
        }
        assert_eq!(snapshot(&state, Some(TENANT_A)), before_a, "{profile}");
        assert_eq!(snapshot(&state, Some(TENANT_B)), before_b, "{profile}");
        assert_eq!(snapshot(&state, None), before_project, "{profile}");
        assert!(oob_codes(&state, TENANT_A).is_empty(), "{profile}");
        assert!(oob_codes(&state, TENANT_B).is_empty(), "{profile}");
        assert!(verification_codes(&state, TENANT_A).is_empty(), "{profile}");
        assert!(verification_codes(&state, TENANT_B).is_empty(), "{profile}");

        // Positive controls: the same rows succeed in the token's own tenant.
        for (token, tenant) in [(&token_a, TENANT_A), (&token_b, TENANT_B)] {
            let (status, found) = client(
                &state,
                &format!("{V1}/accounts:lookup"),
                tenant,
                json!({"idToken": token}),
            );
            assert_eq!(status, 200, "{profile} {tenant}: {found}");
            assert_eq!(found["users"][0]["tenantId"], tenant);
            assert_eq!(found["users"][0]["email"], "same@example.com");
        }
        let (status, updated) = client(
            &state,
            &format!("{V1}/accounts:update"),
            TENANT_A,
            json!({"idToken": token_a, "displayName": "own tenant"}),
        );
        assert_eq!(status, 200, "{profile}: {updated}");
        assert_eq!(updated["displayName"], "own tenant");
        let (status, sent) = client(
            &state,
            &format!("{V1}/accounts:sendOobCode"),
            TENANT_A,
            json!({"idToken": token_a, "requestType": "VERIFY_EMAIL"}),
        );
        assert_eq!(status, 200, "{profile}: {sent}");
        assert_eq!(oob_codes(&state, TENANT_A).len(), 1, "{profile}");
        assert!(oob_codes(&state, TENANT_B).is_empty(), "{profile}");
        let (status, linked) = client(
            &state,
            &format!("{V1}/accounts:signInWithIdp"),
            TENANT_A,
            json!({
                "idToken": token_a,
                "postBody": google_post_body("g-own", "same@example.com"),
                "requestUri": "http://localhost",
                "returnSecureToken": true,
            }),
        );
        assert_eq!(status, 200, "{profile}: {linked}");
        assert_eq!(linked["localId"], a["localId"]);
        assert_eq!(
            claims(linked["idToken"].as_str().unwrap())["firebase"]["tenant"],
            TENANT_A
        );
        // Tenant B still has exactly its own password user; the link landed in A only.
        assert_eq!(snapshot(&state, Some(TENANT_B)), before_b, "{profile}");
        let (status, deleted) = client(
            &state,
            &format!("{V1}/accounts:delete"),
            TENANT_B,
            json!({"idToken": token_b}),
        );
        assert_eq!(status, 200, "{profile}: {deleted}");
        assert!(snapshot(&state, Some(TENANT_B))["users"]
            .as_array()
            .is_none_or(Vec::is_empty));
        assert_eq!(
            snapshot(&state, Some(TENANT_A))["users"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
}

// ---------------------------------------------------------------------------------------
// (a) + (f): a tenant-A refresh token on tenant-B token exchanges.
// ---------------------------------------------------------------------------------------

#[test]
fn a_tenant_refresh_token_is_refused_by_the_other_tenant_without_rotating_the_session() {
    for (profile, state, _registry) in profiles() {
        let a = sign_up(&state, TENANT_A, "a@example.com");
        let b = sign_up(&state, TENANT_B, "b@example.com");
        let refresh_a = a["refreshToken"].as_str().unwrap().to_owned();
        let refresh_b = b["refreshToken"].as_str().unwrap().to_owned();
        let before_a = snapshot(&state, Some(TENANT_A));
        let before_b = snapshot(&state, Some(TENANT_B));

        for (refresh, destination) in [(&refresh_a, TENANT_B), (&refresh_b, TENANT_A)] {
            for &selector in Selector::admitted(&state) {
                let (status, refused) = selector.request(
                    &state,
                    SECURE_TOKEN,
                    destination,
                    json!({"grant_type": "refresh_token", "refresh_token": refresh}),
                );
                assert_eq!(
                    status, 400,
                    "{profile} {destination} {selector:?}: {refused}"
                );
                let expected = match selector {
                    Selector::KeyAndBody => "INVALID_REFRESH_TOKEN",
                    Selector::BodyOnly | Selector::QueryOnly => "TENANT_ID_MISMATCH",
                };
                assert_eq!(
                    class(&refused),
                    expected,
                    "{profile} {destination} {selector:?}: {refused}"
                );
            }
        }
        assert_eq!(snapshot(&state, Some(TENANT_A)), before_a, "{profile}");
        assert_eq!(snapshot(&state, Some(TENANT_B)), before_b, "{profile}");

        // Positive control: the refused attempts did not revoke or rotate either session.
        // Every selector shape that names the token's own tenant renews it.
        for (refresh, tenant) in [(&refresh_a, TENANT_A), (&refresh_b, TENANT_B)] {
            for &selector in Selector::admitted(&state) {
                let (status, renewed) = selector.request(
                    &state,
                    SECURE_TOKEN,
                    tenant,
                    json!({"grant_type": "refresh_token", "refresh_token": refresh}),
                );
                assert_eq!(status, 200, "{profile} {tenant} {selector:?}: {renewed}");
                assert_eq!(
                    claims(renewed["id_token"].as_str().unwrap())["firebase"]["tenant"],
                    tenant
                );
                assert_eq!(renewed["refresh_token"], *refresh);
            }
        }
    }
}

/// Regression (TP-AUTH-E-01 defect, fixed): the pinned `@firebase/auth` 1.13.5
/// `requestStsToken` posts `grant_type=refresh_token&refresh_token=...` to
/// `/v1/token?key=<apiKey>` without a `tenantId`, for tenant users as well (the securetoken
/// API has no tenant parameter). The refresh token names its namespace
/// (`rt1.<plen>.<tlen>.<project><tenant>.<entropy>`), so the API-key branch of `select_store`
/// must route the exchange to the issuing tenant store instead of the project store. Covered
/// with no tenancy and with the daemon's default empty `Tenancy`, in both profiles.
#[test]
fn sdk_shaped_refresh_without_a_tenant_selector_renews_a_tenant_session() {
    for (profile, mut state, _registry) in profiles() {
        for tenancy in [None, Some(Tenancy::new("demo-app"))] {
            let tenancy_label = if tenancy.is_some() { "empty" } else { "none" };
            state.tenancy = tenancy.map(|tenancy| Arc::new(RwLock::new(tenancy)));
            let a = sign_up(&state, TENANT_A, &format!("{tenancy_label}@example.com"));
            let refresh_a = a["refreshToken"].as_str().unwrap().to_owned();
            let (status, renewed) = post(
                &state,
                &format!("{SECURE_TOKEN}?key={KEY}"),
                &json!({"grant_type": "refresh_token", "refresh_token": refresh_a}),
            );
            assert_eq!(status, 200, "{profile} tenancy={tenancy_label}: {renewed}");
            assert_eq!(
                claims(renewed["id_token"].as_str().unwrap())["firebase"]["tenant"],
                TENANT_A,
                "{profile} tenancy={tenancy_label}"
            );
            assert_eq!(renewed["user_id"], a["localId"]);
        }
    }
}

/// The SDK-shaped exchange routes by the token's namespace only. A project user's refresh
/// stays on the project store, every contradicting explicit selector keeps its refusal
/// class from the matrix above, a refusal mutates no namespace, and the renewed tenant
/// session keeps `auth_time` while `iat`/`exp` advance.
#[test]
fn sdk_shaped_refresh_keeps_project_refresh_and_contradicting_selectors_unchanged() {
    for (profile, mut state, _registry) in profiles() {
        for tenancy in [None, Some(Tenancy::new("demo-app"))] {
            let tenancy_label = if tenancy.is_some() { "empty" } else { "none" };
            state.tenancy = tenancy.map(|tenancy| Arc::new(RwLock::new(tenancy)));
            let a = sign_up(&state, TENANT_A, &format!("a-{tenancy_label}@example.com"));
            let (status, project_user) = post(
                &state,
                &format!("{V1}/accounts:signUp?key={KEY}"),
                &json!({"email": format!("p-{tenancy_label}@example.com"), "password": "hunter22"}),
            );
            assert_eq!(status, 200, "{profile}: {project_user}");
            let refresh_a = a["refreshToken"].as_str().unwrap().to_owned();
            let refresh_project = project_user["refreshToken"].as_str().unwrap().to_owned();
            let issued_at = claims(a["idToken"].as_str().unwrap())["iat"]
                .as_i64()
                .unwrap();
            let before_a = snapshot(&state, Some(TENANT_A));
            let before_b = snapshot(&state, Some(TENANT_B));
            let before_project = snapshot(&state, None);

            // A project user's SDK-shaped refresh is unchanged: project store, no tenant claim.
            let (status, renewed) = post(
                &state,
                &format!("{SECURE_TOKEN}?key={KEY}"),
                &json!({"grant_type": "refresh_token", "refresh_token": refresh_project}),
            );
            assert_eq!(status, 200, "{profile} tenancy={tenancy_label}: {renewed}");
            let renewed_claims = claims(renewed["id_token"].as_str().unwrap());
            assert_eq!(renewed_claims["firebase"]["tenant"], Value::Null);
            assert_eq!(renewed_claims["aud"], "demo-app");
            assert_eq!(renewed["user_id"], project_user["localId"]);

            // An explicit selector that contradicts the token's namespace keeps its class.
            for (query, body_tenant, expected) in [
                (
                    format!("?key={KEY}"),
                    Some(TENANT_B),
                    "INVALID_REFRESH_TOKEN",
                ),
                (
                    format!("?key={KEY}&tenantId={TENANT_B}"),
                    None,
                    "TENANT_ID_MISMATCH",
                ),
                (format!("?tenantId={TENANT_B}"), None, "TENANT_ID_MISMATCH"),
                (String::new(), Some(TENANT_B), "TENANT_ID_MISMATCH"),
            ] {
                let mut body = json!({"grant_type": "refresh_token", "refresh_token": refresh_a});
                if let Some(tenant) = body_tenant {
                    body["tenantId"] = Value::String(tenant.to_owned());
                }
                let response = handle(&state, "POST", &format!("{SECURE_TOKEN}{query}"), &body);
                let (status, refused) = (response.status, response.body);
                if state.client_api_key == ClientApiKeyPolicy::Required && !query.contains("key=") {
                    // Production refuses a keyless client call before reading any selector.
                    assert_eq!(status, 403, "{profile} {query}: {refused}");
                    assert_eq!(refused["error"]["status"], "PERMISSION_DENIED");
                    continue;
                }
                assert_eq!(
                    status, 400,
                    "{profile} tenancy={tenancy_label} {query} body_tenant={body_tenant:?}: {refused}"
                );
                assert_eq!(
                    class(&refused),
                    expected,
                    "{profile} tenancy={tenancy_label} {query} body_tenant={body_tenant:?}: {refused}"
                );
            }
            assert_eq!(snapshot(&state, Some(TENANT_A)), before_a, "{profile}");
            assert_eq!(snapshot(&state, Some(TENANT_B)), before_b, "{profile}");
            assert_eq!(snapshot(&state, None), before_project, "{profile}");

            // The refusals did not rotate the tenant session; the SDK-shaped renewal keeps
            // the sign-in time and advances the issue and expiry times.
            state
                .clock
                .lock()
                .unwrap()
                .advance(LogicalDuration::from_seconds(7))
                .unwrap();
            let (status, renewed) = post(
                &state,
                &format!("{SECURE_TOKEN}?key={KEY}"),
                &json!({"grant_type": "refresh_token", "refresh_token": refresh_a}),
            );
            assert_eq!(status, 200, "{profile} tenancy={tenancy_label}: {renewed}");
            let renewed_claims = claims(renewed["id_token"].as_str().unwrap());
            assert_eq!(renewed_claims["firebase"]["tenant"], TENANT_A);
            assert_eq!(renewed_claims["auth_time"], issued_at);
            let renewed_iat = renewed_claims["iat"].as_i64().unwrap();
            assert!(
                renewed_iat > issued_at,
                "{profile}: iat {renewed_iat} <= {issued_at}"
            );
            assert_eq!(renewed_claims["exp"], renewed_iat + 3600);
            assert_eq!(renewed["refresh_token"], refresh_a);
            assert_eq!(renewed["user_id"], a["localId"]);
        }
    }
}

/// The API key names the project. A tenant token minted under another registered session
/// project is not renewed by a key of a different project, even though its namespace
/// prefix resolves; the key's own project renews it and the tenant claim survives.
#[test]
fn sdk_shaped_refresh_of_a_tenant_token_from_another_project_is_refused() {
    for (profile, mut state, registry) in profiles() {
        let mut tenancy = Tenancy::new("demo-app");
        for (project, key) in [("worker-alpha", "alpha-key"), ("worker-beta", "beta-key")] {
            assert!(registry.register(
                project,
                AuthStore::new(project, SplitMix64::new(11), TotpPolicy::default()),
            ));
            registry.ensure_tenant(project, "customer-a").unwrap();
            tenancy.register(project, &[], &[key.to_owned()]).unwrap();
        }
        state.tenancy = Some(Arc::new(RwLock::new(tenancy)));
        let (status, alpha_user) = post(
            &state,
            &format!("{V1}/accounts:signUp?key=alpha-key"),
            &json!({"tenantId": "customer-a", "email": "alpha@example.com", "password": "hunter22"}),
        );
        assert_eq!(status, 200, "{profile}: {alpha_user}");
        let refresh_alpha = alpha_user["refreshToken"].as_str().unwrap().to_owned();
        let alpha_snapshot = || {
            let (status, body) = admin(
                &state,
                "GET",
                &format!("{V1}/projects/worker-alpha/tenants/customer-a/accounts:batchGet?maxResults=1000"),
                &json!({}),
            );
            assert_eq!(status, 200, "{body}");
            body
        };
        let before_alpha = alpha_snapshot();

        let (status, refused) = post(
            &state,
            &format!("{SECURE_TOKEN}?key=beta-key"),
            &json!({"grant_type": "refresh_token", "refresh_token": refresh_alpha}),
        );
        assert_eq!(status, 400, "{profile}: {refused}");
        assert_eq!(
            class(&refused),
            "INVALID_REFRESH_TOKEN",
            "{profile}: {refused}"
        );
        assert_eq!(alpha_snapshot(), before_alpha, "{profile}");

        let (status, renewed) = post(
            &state,
            &format!("{SECURE_TOKEN}?key=alpha-key"),
            &json!({"grant_type": "refresh_token", "refresh_token": refresh_alpha}),
        );
        assert_eq!(status, 200, "{profile}: {renewed}");
        let renewed_claims = claims(renewed["id_token"].as_str().unwrap());
        assert_eq!(renewed_claims["firebase"]["tenant"], "customer-a");
        assert_eq!(renewed_claims["aud"], "worker-alpha");
        assert_eq!(renewed["user_id"], alpha_user["localId"]);
    }
}

// ---------------------------------------------------------------------------------------
// (a) + (f): a tenant-A pending MFA credential on tenant-B second-factor routes.
// ---------------------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn a_tenant_mfa_pending_credential_is_refused_by_the_other_tenant() {
    for (profile, state, _registry) in profiles() {
        let (status, created) = admin(
            &state,
            "POST",
            &tenant_admin_path(TENANT_A, "accounts"),
            &json!({
                "email": "mfa@example.com",
                "password": "hunter22",
                "emailVerified": true,
                "mfaInfo": [{"phoneInfo": "+15559876543", "displayName": "phone"}],
            }),
        );
        assert_eq!(status, 200, "{profile}: {created}");
        let (status, found) = admin(
            &state,
            "POST",
            &tenant_admin_path(TENANT_A, "accounts:lookup"),
            &json!({"localId": [created["localId"]]}),
        );
        assert_eq!(status, 200, "{profile}: {found}");
        let enrollment_id = found["users"][0]["mfaInfo"][0]["mfaEnrollmentId"]
            .as_str()
            .unwrap()
            .to_owned();
        sign_up(&state, TENANT_B, "b@example.com");
        let before_a = snapshot(&state, Some(TENANT_A));
        let before_b = snapshot(&state, Some(TENANT_B));

        let (status, pending) = client(
            &state,
            &format!("{V1}/accounts:signInWithPassword"),
            TENANT_A,
            json!({"email": "mfa@example.com", "password": "hunter22"}),
        );
        assert_eq!(status, 200, "{profile}: {pending}");
        assert!(pending.get("idToken").is_none(), "{profile}: {pending}");
        let credential = pending["mfaPendingCredential"].as_str().unwrap().to_owned();

        let start_body = json!({
            "mfaPendingCredential": credential,
            "mfaEnrollmentId": enrollment_id,
            "phoneSignInInfo": {"recaptchaToken": "x"},
        });
        for &selector in Selector::admitted(&state) {
            let (status, refused) = selector.request(
                &state,
                &format!("{V2}/accounts/mfaSignIn:start"),
                TENANT_B,
                start_body.clone(),
            );
            assert_eq!(status, 400, "{profile} start {selector:?}: {refused}");
            assert_eq!(
                class(&refused),
                "INVALID_MFA_PENDING_CREDENTIAL",
                "{profile} start {selector:?}: {refused}"
            );
        }
        assert!(verification_codes(&state, TENANT_A).is_empty(), "{profile}");
        assert!(verification_codes(&state, TENANT_B).is_empty(), "{profile}");

        // Positive control: start in tenant A issues exactly one code, in tenant A.
        let (status, started) = client(
            &state,
            &format!("{V2}/accounts/mfaSignIn:start"),
            TENANT_A,
            start_body.clone(),
        );
        assert_eq!(status, 200, "{profile}: {started}");
        let session = started["phoneResponseInfo"]["sessionInfo"]
            .as_str()
            .unwrap()
            .to_owned();
        let codes = verification_codes(&state, TENANT_A);
        assert_eq!(codes.len(), 1, "{profile}");
        assert!(verification_codes(&state, TENANT_B).is_empty(), "{profile}");
        let code = codes[0]["code"].as_str().unwrap().to_owned();

        let finalize_body = json!({
            "mfaPendingCredential": credential,
            "phoneVerificationInfo": {"sessionInfo": session, "code": code},
        });
        // The phone finalize path checks the verification session before the pending
        // credential, so tenant B reports the missing session; the TOTP-shaped finalize
        // reaches the pending-credential check first. Both are typed refusals.
        let totp_shaped = json!({
            "mfaPendingCredential": credential,
            "mfaEnrollmentId": enrollment_id,
            "totpVerificationInfo": {"verificationCode": "123456"},
        });
        for (shape, body, expected) in [
            ("phone", &finalize_body, "INVALID_SESSION_INFO"),
            ("totp", &totp_shaped, "INVALID_MFA_PENDING_CREDENTIAL"),
        ] {
            for &selector in Selector::admitted(&state) {
                let (status, refused) = selector.request(
                    &state,
                    &format!("{V2}/accounts/mfaSignIn:finalize"),
                    TENANT_B,
                    body.clone(),
                );
                assert_eq!(
                    status, 400,
                    "{profile} finalize {shape} {selector:?}: {refused}"
                );
                assert_eq!(
                    class(&refused),
                    expected,
                    "{profile} finalize {shape} {selector:?}: {refused}"
                );
            }
        }
        // The refused finalize consumed neither the pending sign-in nor the code.
        assert_eq!(verification_codes(&state, TENANT_A).len(), 1, "{profile}");
        assert_eq!(snapshot(&state, Some(TENANT_B)), before_b, "{profile}");

        let (status, signed) = client(
            &state,
            &format!("{V2}/accounts/mfaSignIn:finalize"),
            TENANT_A,
            finalize_body,
        );
        assert_eq!(status, 200, "{profile}: {signed}");
        let signed_claims = claims(signed["idToken"].as_str().unwrap());
        assert_eq!(signed_claims["firebase"]["tenant"], TENANT_A);
        assert_eq!(signed_claims["firebase"]["sign_in_second_factor"], "phone");
        assert_eq!(signed_claims["sub"], created["localId"]);
        assert_eq!(
            snapshot(&state, Some(TENANT_A))["users"]
                .as_array()
                .unwrap()
                .len(),
            before_a["users"].as_array().unwrap().len(),
            "{profile}"
        );
    }
}

// ---------------------------------------------------------------------------------------
// (a) + (f): action codes and password reset never cross tenants.
// ---------------------------------------------------------------------------------------

#[test]
fn a_tenant_oob_code_is_refused_by_the_other_tenant_and_stays_consumable() {
    for (profile, state, _registry) in profiles() {
        sign_up(&state, TENANT_A, "reset@example.com");
        sign_up(&state, TENANT_B, "other@example.com");
        let before_b = snapshot(&state, Some(TENANT_B));

        // A password reset request for a tenant-A address addressed to tenant B finds no
        // account there and mints no code anywhere.
        let (status, refused) = client(
            &state,
            &format!("{V1}/accounts:sendOobCode"),
            TENANT_B,
            json!({"requestType": "PASSWORD_RESET", "email": "reset@example.com"}),
        );
        assert_eq!(status, 400, "{profile}: {refused}");
        assert_eq!(class(&refused), "EMAIL_NOT_FOUND", "{profile}: {refused}");
        assert!(oob_codes(&state, TENANT_A).is_empty(), "{profile}");
        assert!(oob_codes(&state, TENANT_B).is_empty(), "{profile}");

        let (status, sent) = client(
            &state,
            &format!("{V1}/accounts:sendOobCode"),
            TENANT_A,
            json!({"requestType": "PASSWORD_RESET", "email": "reset@example.com"}),
        );
        assert_eq!(status, 200, "{profile}: {sent}");
        let codes = oob_codes(&state, TENANT_A);
        assert_eq!(codes.len(), 1, "{profile}");
        assert!(oob_codes(&state, TENANT_B).is_empty(), "{profile}");
        let oob_code = codes[0]["oobCode"].as_str().unwrap().to_owned();

        for &selector in Selector::admitted(&state) {
            let (status, refused) = selector.request(
                &state,
                &format!("{V1}/accounts:resetPassword"),
                TENANT_B,
                json!({"oobCode": oob_code, "newPassword": "changed-password-1"}),
            );
            assert_eq!(status, 400, "{profile} {selector:?}: {refused}");
            assert_eq!(
                class(&refused),
                "INVALID_OOB_CODE",
                "{profile} {selector:?}: {refused}"
            );
        }
        // The code is still outstanding and the old password still works in tenant A.
        assert_eq!(oob_codes(&state, TENANT_A).len(), 1, "{profile}");
        assert_eq!(snapshot(&state, Some(TENANT_B)), before_b, "{profile}");
        let (status, signed) = client(
            &state,
            &format!("{V1}/accounts:signInWithPassword"),
            TENANT_A,
            json!({"email": "reset@example.com", "password": "hunter22"}),
        );
        assert_eq!(status, 200, "{profile}: {signed}");

        // Positive control: the same code resets the password in its own tenant, once.
        let (status, reset) = client(
            &state,
            &format!("{V1}/accounts:resetPassword"),
            TENANT_A,
            json!({"oobCode": oob_code, "newPassword": "changed-password-1"}),
        );
        assert_eq!(status, 200, "{profile}: {reset}");
        assert!(oob_codes(&state, TENANT_A).is_empty(), "{profile}");
        let (status, signed) = client(
            &state,
            &format!("{V1}/accounts:signInWithPassword"),
            TENANT_A,
            json!({"email": "reset@example.com", "password": "changed-password-1"}),
        );
        assert_eq!(status, 200, "{profile}: {signed}");
        let (status, stale) = client(
            &state,
            &format!("{V1}/accounts:signInWithPassword"),
            TENANT_B,
            json!({"email": "reset@example.com", "password": "changed-password-1"}),
        );
        assert_eq!(status, 400, "{profile}: {stale}");
        assert_eq!(class(&stale), "EMAIL_NOT_FOUND", "{profile}: {stale}");
    }
}

// ---------------------------------------------------------------------------------------
// (a) + (f): federated sign-in creates and links only in the selected tenant.
// ---------------------------------------------------------------------------------------

#[test]
fn federated_sign_in_creates_separate_accounts_per_tenant() {
    for (profile, state, _registry) in profiles() {
        let body = json!({
            "postBody": google_post_body("g-shared", "fed@example.com"),
            "requestUri": "http://localhost",
            "returnSecureToken": true,
        });
        let (status, in_a) = client(
            &state,
            &format!("{V1}/accounts:signInWithIdp"),
            TENANT_A,
            body.clone(),
        );
        assert_eq!(status, 200, "{profile}: {in_a}");
        assert_eq!(in_a["isNewUser"], true);
        assert_eq!(
            claims(in_a["idToken"].as_str().unwrap())["firebase"]["tenant"],
            TENANT_A
        );
        assert!(snapshot(&state, Some(TENANT_B))["users"]
            .as_array()
            .is_none_or(Vec::is_empty));
        assert!(snapshot(&state, None)["users"]
            .as_array()
            .is_none_or(Vec::is_empty));

        // The same federated identity in tenant B is a different, new account.
        let (status, in_b) = client(
            &state,
            &format!("{V1}/accounts:signInWithIdp"),
            TENANT_B,
            body.clone(),
        );
        assert_eq!(status, 200, "{profile}: {in_b}");
        assert_eq!(in_b["isNewUser"], true);
        assert_ne!(in_b["localId"], in_a["localId"]);
        assert_eq!(
            claims(in_b["idToken"].as_str().unwrap())["firebase"]["tenant"],
            TENANT_B
        );

        // Repeating in A is a returning sign-in for the A account only.
        let (status, again) = client(
            &state,
            &format!("{V1}/accounts:signInWithIdp"),
            TENANT_A,
            body,
        );
        assert_eq!(status, 200, "{profile}: {again}");
        assert_eq!(again["isNewUser"], false);
        assert_eq!(again["localId"], in_a["localId"]);
        assert_eq!(
            snapshot(&state, Some(TENANT_A))["users"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            snapshot(&state, Some(TENANT_B))["users"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
}

// ---------------------------------------------------------------------------------------
// (b): project-level Admin lookup does not see tenant users.
// ---------------------------------------------------------------------------------------

/// Identity Platform scopes tenant users to their tenant: the Admin SDK reaches them only
/// through `tenantManager().authForTenant(tenantId)`, which posts to the
/// `/projects/{p}/tenants/{t}/accounts:*` routes; the project-level routes address the
/// project's own users (multi-tenancy docs, "Managing users" for tenants). Spec-derived.
#[test]
fn project_level_admin_lookup_does_not_find_tenant_users() {
    for (profile, state, _registry) in profiles() {
        let (status, in_a) = admin(
            &state,
            "POST",
            &tenant_admin_path(TENANT_A, "accounts"),
            &json!({"localId": "shared-uid", "email": "a@example.com", "phoneNumber": "+15550000001"}),
        );
        assert_eq!(status, 200, "{profile}: {in_a}");
        let (status, in_project) = admin(
            &state,
            "POST",
            &format!("{V1}/projects/demo-app/accounts"),
            &json!({"localId": "project-uid", "email": "p@example.com"}),
        );
        assert_eq!(status, 200, "{profile}: {in_project}");

        for (label, selector) in [
            ("localId", json!({"localId": ["shared-uid"]})),
            ("email", json!({"email": ["a@example.com"]})),
            ("phoneNumber", json!({"phoneNumber": ["+15550000001"]})),
            (
                "federatedUserId",
                json!({"federatedUserId": [{"providerId": "phone", "rawId": "+15550000001"}]}),
            ),
        ] {
            let (status, found) = admin(
                &state,
                "POST",
                &format!("{V1}/projects/demo-app/accounts:lookup"),
                &selector,
            );
            assert_eq!(status, 200, "{profile} {label}: {found}");
            assert!(
                found["users"].as_array().is_none_or(Vec::is_empty),
                "{profile} {label}: project lookup must not see tenant users: {found}"
            );
            let (status, found) = admin(
                &state,
                "POST",
                &tenant_admin_path(TENANT_B, "accounts:lookup"),
                &selector,
            );
            assert_eq!(status, 200, "{profile} {label}: {found}");
            assert!(
                found["users"].as_array().is_none_or(Vec::is_empty),
                "{profile} {label}: sibling tenant lookup must not see tenant-A users: {found}"
            );
        }
        // Positive control: the tenant route finds it, with the tenant recorded on the row.
        let (status, found) = admin(
            &state,
            "POST",
            &tenant_admin_path(TENANT_A, "accounts:lookup"),
            &json!({"localId": ["shared-uid"]}),
        );
        assert_eq!(status, 200, "{profile}: {found}");
        assert_eq!(found["users"][0]["localId"], "shared-uid");
        assert_eq!(found["users"][0]["tenantId"], TENANT_A);

        // The project-level lookup route never accepts a body tenant as a redirection into a
        // tenant namespace: the request is refused rather than silently rerouted.
        let (status, refused) = admin(
            &state,
            "POST",
            &format!("{V1}/projects/demo-app/accounts:lookup"),
            &json!({"localId": ["shared-uid"], "tenantId": TENANT_A}),
        );
        assert_eq!(status, 400, "{profile}: {refused}");
        assert_eq!(
            class(&refused),
            "TENANT_ID_MISMATCH",
            "{profile}: {refused}"
        );

        // Listing and query are project-scoped as well.
        let listed = snapshot(&state, None);
        assert_eq!(
            listed["users"].as_array().unwrap().len(),
            1,
            "{profile}: {listed}"
        );
        assert_eq!(listed["users"][0]["localId"], "project-uid");
        let (status, counted) = admin(
            &state,
            "POST",
            &format!("{V1}/projects/demo-app/accounts:query"),
            &json!({}),
        );
        assert_eq!(status, 200, "{profile}: {counted}");
        assert_eq!(counted["recordsCount"], "1", "{profile}: {counted}");
    }
}

// ---------------------------------------------------------------------------------------
// (c): inheritance at creation, override by tenant PATCH, and the client obeys.
// ---------------------------------------------------------------------------------------

fn tenant_id_of(created: &Value) -> String {
    created["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned()
}

fn read_tenant(state: &AuthState, tenant: &str) -> Value {
    let (status, body) = admin(
        state,
        "GET",
        &format!("{ADMIN_V2}/tenants/{tenant}"),
        &json!({}),
    );
    assert_eq!(status, 200, "{body}");
    body
}

fn min_password_length(config: &Value) -> Value {
    config["passwordPolicyConfig"]["passwordPolicyVersions"][0]["customStrengthOptions"]
        ["minPasswordLength"]
        .clone()
}

fn create_tenant(state: &AuthState, body: &Value) -> Value {
    let (status, created) = admin(state, "POST", &format!("{ADMIN_V2}/tenants"), body);
    assert_eq!(status, 200, "{created}");
    created
}

fn sign_up_status(state: &AuthState, tenant: &str, body: Value) -> (u16, String) {
    let (status, body) = client(state, &format!("{V1}/accounts:signUp"), tenant, body);
    (status, class(&body))
}

fn unknown_email_sign_in_class(state: &AuthState, tenant: Option<&str>) -> String {
    let body = json!({"email": "missing@example.com", "password": "twelve-chars-ok"});
    let (status, refused) = match tenant {
        Some(tenant) => client(
            state,
            &format!("{V1}/accounts:signInWithPassword"),
            tenant,
            body,
        ),
        None => post(
            state,
            &format!("{V1}/accounts:signInWithPassword?key={KEY}"),
            &body,
        ),
    };
    assert_eq!(status, 400, "{refused}");
    class(&refused)
}

/// Local default model, recorded for the bounded production observation: an explicitly
/// created tenant carries the Identity Platform `Tenant` proto defaults for its sign-in
/// methods (`false` when omitted, as the Admin SDK's `createTenant` documents), and the
/// client is refused until a PATCH enables them. Only implicit (config-declared) tenants
/// default every method to enabled. The false-by-default behaviour is a spec-derived
/// hypothesis until observed.
#[test]
fn explicit_tenant_creation_defaults_sign_in_methods_off_until_patched() {
    for (profile, state, _registry) in profiles() {
        let created = create_tenant(&state, &json!({"displayName": "Minimal"}));
        let tenant = tenant_id_of(&created);
        assert_eq!(
            created["allowPasswordSignup"], false,
            "{profile}: {created}"
        );
        assert_eq!(
            created["enableEmailLinkSignin"], false,
            "{profile}: {created}"
        );
        assert_eq!(
            created["enableAnonymousUser"], false,
            "{profile}: {created}"
        );
        assert_eq!(created["disableAuth"], false, "{profile}: {created}");

        let password = json!({"email": "off@example.com", "password": "hunter22"});
        assert_eq!(
            sign_up_status(&state, &tenant, password.clone()),
            (400, "OPERATION_NOT_ALLOWED".to_owned()),
            "{profile}"
        );
        assert_eq!(
            sign_up_status(&state, &tenant, json!({})),
            (400, "OPERATION_NOT_ALLOWED".to_owned()),
            "{profile}"
        );
        let (status, refused) = client(
            &state,
            &format!("{V1}/accounts:sendOobCode"),
            &tenant,
            json!({"requestType": "EMAIL_SIGNIN", "email": "off@example.com", "continueUrl": "http://localhost/"}),
        );
        assert_eq!(status, 400, "{profile}: {refused}");
        assert_eq!(
            class(&refused),
            "OPERATION_NOT_ALLOWED",
            "{profile}: {refused}"
        );
        assert!(snapshot(&state, Some(&tenant))["users"]
            .as_array()
            .is_none_or(Vec::is_empty));

        let (status, patched) = admin(
            &state,
            "PATCH",
            &format!(
                "{ADMIN_V2}/tenants/{tenant}?updateMask=allowPasswordSignup,enableAnonymousUser"
            ),
            &json!({"allowPasswordSignup": true, "enableAnonymousUser": true}),
        );
        assert_eq!(status, 200, "{profile}: {patched}");
        assert_eq!(
            sign_up_status(&state, &tenant, password).0,
            200,
            "{profile}"
        );
        assert_eq!(
            sign_up_status(&state, &tenant, json!({})).0,
            200,
            "{profile}"
        );
        assert_eq!(
            snapshot(&state, Some(&tenant))["users"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }
}

/// Local inheritance model, recorded for the bounded production observation:
/// `client.permissions` and `emailPrivacyConfig` are copied from the project when a tenant
/// is created and follow later project `PATCH`es unless the tenant overrode the field;
/// `passwordPolicyConfig` is never copied from the project (a new tenant starts from the
/// default policy) and never follows it; the sign-in method flags are tenant-only;
/// `mfaConfig` is a constant `DISABLED` projection that refuses PATCH. Identity Platform's
/// `Tenant.inheritance` covers only `emailSendingConfig`, so the copied and propagated
/// fields are spec-derived hypotheses until observed.
#[test]
#[allow(clippy::too_many_lines)]
fn tenant_settings_inherit_at_creation_and_tenant_patches_override_them() {
    for (profile, state, registry) in profiles() {
        // Project: an enforced 8-character minimum and email enumeration protection.
        let (status, project) = admin(
            &state,
            "PATCH",
            &format!("{PROJECT_CONFIG}?updateMask=passwordPolicyConfig,emailPrivacyConfig.enableImprovedEmailPrivacy"),
            &json!({
                "passwordPolicyConfig": {
                    "passwordPolicyEnforcementState": "ENFORCE",
                    "passwordPolicyVersions": [{"customStrengthOptions": {"minPasswordLength": 8}}]
                },
                "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true},
            }),
        );
        assert_eq!(status, 200, "{profile}: {project}");
        assert_eq!(
            project["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
            true
        );

        let enabled = json!({
            "allowPasswordSignup": true,
            "enableAnonymousUser": true,
            "enableEmailLinkSignin": true,
        });
        let mut overridden_body = enabled.clone();
        overridden_body["displayName"] = json!("Overridden");
        let created = create_tenant(&state, &overridden_body);
        let overridden = tenant_id_of(&created);
        let mut untouched_body = enabled;
        untouched_body["displayName"] = json!("Untouched");
        let untouched = tenant_id_of(&create_tenant(&state, &untouched_body));

        // The projection at creation: privacy and client permissions copied, the password
        // policy not copied, MFA constant.
        assert_eq!(created["allowPasswordSignup"], true);
        assert_eq!(created["enableAnonymousUser"], true);
        assert_eq!(
            created["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
            true
        );
        assert_eq!(
            created["client"]["permissions"]["disabledUserSignup"],
            false
        );
        assert_eq!(min_password_length(&created), 6, "{profile}: {created}");
        assert_eq!(
            created["passwordPolicyConfig"]["passwordPolicyEnforcementState"],
            "OFF"
        );
        assert_eq!(
            created["mfaConfig"],
            json!({"state": "DISABLED", "enabledProviders": []})
        );

        // The client obeys the effective values: the tenant accepts a 7-character password
        // (its own default policy) while the project enforces 8; both hide unknown emails.
        assert_eq!(
            sign_up_status(
                &state,
                &overridden,
                json!({"email": "seven@example.com", "password": "seven77"})
            )
            .0,
            200,
            "{profile}"
        );
        let (status, weak) = post(
            &state,
            &format!("{V1}/accounts:signUp?key={KEY}"),
            &json!({"email": "seven@example.com", "password": "seven77"}),
        );
        assert_eq!(status, 400, "{profile}: {weak}");
        assert_eq!(class(&weak), "PASSWORD_DOES_NOT_MEET_REQUIREMENTS");
        assert_eq!(
            unknown_email_sign_in_class(&state, Some(&overridden)),
            "INVALID_LOGIN_CREDENTIALS",
            "{profile}"
        );
        assert_eq!(
            unknown_email_sign_in_class(&state, None),
            "INVALID_LOGIN_CREDENTIALS",
            "{profile}"
        );
        assert_eq!(
            sign_up_status(&state, &overridden, json!({})).0,
            200,
            "{profile}"
        );

        // Tenant override: no anonymous or password sign-in, a 12-character minimum, and
        // privacy off, while the project keeps its own values.
        let (status, patched) = admin(
            &state,
            "PATCH",
            &format!("{ADMIN_V2}/tenants/{overridden}?updateMask=enableAnonymousUser,allowPasswordSignup,passwordPolicyConfig,emailPrivacyConfig.enableImprovedEmailPrivacy"),
            &json!({
                "enableAnonymousUser": false,
                "allowPasswordSignup": false,
                "passwordPolicyConfig": {
                    "passwordPolicyEnforcementState": "ENFORCE",
                    "passwordPolicyVersions": [{"customStrengthOptions": {"minPasswordLength": 12}}]
                },
                "emailPrivacyConfig": {"enableImprovedEmailPrivacy": false},
            }),
        );
        assert_eq!(status, 200, "{profile}: {patched}");
        assert_eq!(patched["enableAnonymousUser"], false);
        assert_eq!(patched["allowPasswordSignup"], false);
        assert_eq!(min_password_length(&patched), 12);
        assert_eq!(
            patched["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
            false
        );
        let (status, mfa_patch) = admin(
            &state,
            "PATCH",
            &format!("{ADMIN_V2}/tenants/{overridden}?updateMask=mfaConfig"),
            &json!({"mfaConfig": {"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}}),
        );
        assert_eq!(status, 400, "{profile}: {mfa_patch}");
        assert_eq!(class(&mfa_patch), "INVALID_ARGUMENT");
        assert_eq!(
            read_tenant(&state, &overridden)["mfaConfig"]["state"],
            "DISABLED"
        );

        let (status, project_now) = admin(&state, "GET", PROJECT_CONFIG, &json!({}));
        assert_eq!(status, 200, "{profile}: {project_now}");
        assert_eq!(min_password_length(&project_now), 8);
        assert_eq!(
            project_now["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
            true
        );

        // The client obeys the override in the tenant and the project values on the project.
        assert_eq!(
            sign_up_status(&state, &overridden, json!({})),
            (400, "OPERATION_NOT_ALLOWED".to_owned()),
            "{profile}"
        );
        assert_eq!(
            sign_up_status(
                &state,
                &overridden,
                json!({"email": "twelve@example.com", "password": "twelve-chars-ok"})
            ),
            (400, "OPERATION_NOT_ALLOWED".to_owned()),
            "{profile}"
        );
        let (status, refused) = client(
            &state,
            &format!("{V1}/accounts:signInWithPassword"),
            &overridden,
            json!({"email": "seven@example.com", "password": "seven77"}),
        );
        assert_eq!(status, 400, "{profile}: {refused}");
        assert_eq!(
            class(&refused),
            "OPERATION_NOT_ALLOWED",
            "{profile}: {refused}"
        );
        let (status, anonymous) = post(
            &state,
            &format!("{V1}/accounts:signUp?key={KEY}"),
            &json!({}),
        );
        assert_eq!(status, 200, "{profile}: {anonymous}");
        let (status, ok) = post(
            &state,
            &format!("{V1}/accounts:signUp?key={KEY}"),
            &json!({"email": "project8@example.com", "password": "eight888"}),
        );
        assert_eq!(status, 200, "{profile}: {ok}");
        assert_eq!(
            unknown_email_sign_in_class(&state, None),
            "INVALID_LOGIN_CREDENTIALS",
            "{profile}"
        );
        assert_eq!(
            unknown_email_sign_in_class(&state, Some(&untouched)),
            "INVALID_LOGIN_CREDENTIALS",
            "{profile}"
        );

        // Re-enable password sign-in: the tenant's own 12-character policy applies, not the
        // project's 8, and the tenant now reveals unknown addresses (privacy override).
        let (status, patched) = admin(
            &state,
            "PATCH",
            &format!("{ADMIN_V2}/tenants/{overridden}?updateMask=allowPasswordSignup"),
            &json!({"allowPasswordSignup": true}),
        );
        assert_eq!(status, 200, "{profile}: {patched}");
        assert_eq!(
            sign_up_status(
                &state,
                &overridden,
                json!({"email": "eleven@example.com", "password": "eleven-char"})
            ),
            (400, "PASSWORD_DOES_NOT_MEET_REQUIREMENTS".to_owned()),
            "{profile}"
        );
        assert_eq!(
            sign_up_status(
                &state,
                &overridden,
                json!({"email": "twelve@example.com", "password": "twelve-chars-ok"})
            )
            .0,
            200,
            "{profile}"
        );
        assert_eq!(
            unknown_email_sign_in_class(&state, Some(&overridden)),
            "EMAIL_NOT_FOUND",
            "{profile}"
        );

        // Later project changes: copied client config follows on the untouched tenant, the
        // overridden field stays overridden, and the password policy never follows.
        let (status, project) = admin(
            &state,
            "PATCH",
            &format!("{PROJECT_CONFIG}?updateMask=passwordPolicyConfig,emailPrivacyConfig.enableImprovedEmailPrivacy,client.permissions.disabledUserSignup"),
            &json!({
                "passwordPolicyConfig": {
                    "passwordPolicyEnforcementState": "ENFORCE",
                    "passwordPolicyVersions": [{"customStrengthOptions": {"minPasswordLength": 10}}]
                },
                "emailPrivacyConfig": {"enableImprovedEmailPrivacy": false},
                "client": {"permissions": {"disabledUserSignup": true}},
            }),
        );
        assert_eq!(status, 200, "{profile}: {project}");
        let (status, project) = admin(
            &state,
            "PATCH",
            &format!("{PROJECT_CONFIG}?updateMask=emailPrivacyConfig.enableImprovedEmailPrivacy"),
            &json!({"emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}}),
        );
        assert_eq!(status, 200, "{profile}: {project}");
        let overridden_now = read_tenant(&state, &overridden);
        assert_eq!(
            min_password_length(&overridden_now),
            12,
            "{profile}: {overridden_now}"
        );
        assert_eq!(
            overridden_now["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
            false
        );
        assert_eq!(
            overridden_now["client"]["permissions"]["disabledUserSignup"],
            true
        );
        let untouched_now = read_tenant(&state, &untouched);
        assert_eq!(
            min_password_length(&untouched_now),
            6,
            "{profile}: {untouched_now}"
        );
        assert_eq!(
            untouched_now["emailPrivacyConfig"]["enableImprovedEmailPrivacy"],
            true
        );
        assert_eq!(
            untouched_now["client"]["permissions"]["disabledUserSignup"],
            true
        );
        // The propagated permission is enforced by both tenant stores, not only projected,
        // and each tenant's effective privacy decides what the client learns.
        for tenant in [&overridden, &untouched] {
            assert_eq!(
                sign_up_status(
                    &state,
                    tenant,
                    json!({"email": "blocked@example.com", "password": "twelve-chars-ok"})
                ),
                (400, "ADMIN_ONLY_OPERATION".to_owned()),
                "{profile} {tenant}"
            );
            assert!(
                registry
                    .tenant_store("demo-app", tenant)
                    .unwrap()
                    .lock()
                    .unwrap()
                    .config()
                    .disabled_user_signup
            );
        }
        assert_eq!(
            unknown_email_sign_in_class(&state, Some(&overridden)),
            "EMAIL_NOT_FOUND",
            "{profile}"
        );
        assert_eq!(
            unknown_email_sign_in_class(&state, Some(&untouched)),
            "INVALID_LOGIN_CREDENTIALS",
            "{profile}"
        );
        assert_eq!(
            unknown_email_sign_in_class(&state, None),
            "INVALID_LOGIN_CREDENTIALS",
            "{profile}"
        );
        // The project's own policy moved to 10 without touching either tenant: an existing
        // project user cannot pick a 9-character password (end-user sign-up is disabled on
        // the project now, so the check goes through a password change).
        let (status, weak) = post(
            &state,
            &format!("{V1}/accounts:update?key={KEY}"),
            &json!({"idToken": ok["idToken"], "password": "nine-char"}),
        );
        assert_eq!(status, 400, "{profile}: {weak}");
        assert_eq!(class(&weak), "PASSWORD_DOES_NOT_MEET_REQUIREMENTS");
        let (status, changed) = post(
            &state,
            &format!("{V1}/accounts:update?key={KEY}"),
            &json!({"idToken": ok["idToken"], "password": "ten-chars!"}),
        );
        assert_eq!(status, 200, "{profile}: {changed}");
    }
}

// ---------------------------------------------------------------------------------------
// (d): provider configurations are namespaced per tenant.
// ---------------------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn provider_configs_created_in_one_tenant_are_invisible_to_the_other_tenant_and_the_project() {
    for (profile, state, _registry) in profiles() {
        let oidc = json!({
            "clientId": "acme-client",
            "issuer": "https://issuer.acme.example",
            "displayName": "Acme OIDC",
            "enabled": true,
            "responseType": {"idToken": true}
        });
        let saml = json!({
            "idpConfig": {
                "idpEntityId": "https://idp.acme.example/entity",
                "ssoUrl": "https://idp.acme.example/sso",
                "idpCertificates": [{"x509Certificate": "MIIC"}],
                "signRequest": false
            },
            "spConfig": {
                "spEntityId": "https://sp.acme.example/entity",
                "callbackUri": "https://sp.acme.example/__/auth/handler"
            },
            "displayName": "Acme SAML",
            "enabled": true
        });
        let (status, created) = admin(
            &state,
            "POST",
            &format!("{ADMIN_V2}/tenants/{TENANT_A}/oauthIdpConfigs?oauthIdpConfigId=oidc.acme"),
            &oidc,
        );
        assert_eq!(status, 200, "{profile}: {created}");
        assert_eq!(
            created["name"],
            format!("projects/demo-app/tenants/{TENANT_A}/oauthIdpConfigs/oidc.acme")
        );
        let (status, created) = admin(
            &state,
            "POST",
            &format!(
                "{ADMIN_V2}/tenants/{TENANT_A}/inboundSamlConfigs?inboundSamlConfigId=saml.acme"
            ),
            &saml,
        );
        assert_eq!(status, 200, "{profile}: {created}");

        for (label, collection) in [
            ("tenant B", format!("{ADMIN_V2}/tenants/{TENANT_B}")),
            ("project", ADMIN_V2.to_owned()),
        ] {
            for (kind, id) in [
                ("oauthIdpConfigs", "oidc.acme"),
                ("inboundSamlConfigs", "saml.acme"),
            ] {
                let (status, missing) = admin(
                    &state,
                    "GET",
                    &format!("{collection}/{kind}/{id}"),
                    &json!({}),
                );
                assert_eq!(status, 404, "{profile} {label} {kind}: {missing}");
                let (status, listed) =
                    admin(&state, "GET", &format!("{collection}/{kind}"), &json!({}));
                assert_eq!(status, 200, "{profile} {label} {kind}: {listed}");
                assert!(
                    listed[kind].as_array().is_none_or(Vec::is_empty),
                    "{profile} {label} {kind}: {listed}"
                );
                let (status, refused) = admin(
                    &state,
                    "PATCH",
                    &format!("{collection}/{kind}/{id}?updateMask=displayName"),
                    &json!({"displayName": "crossed"}),
                );
                assert_eq!(status, 404, "{profile} {label} {kind}: {refused}");
                let (status, refused) = admin(
                    &state,
                    "DELETE",
                    &format!("{collection}/{kind}/{id}"),
                    &json!({}),
                );
                assert_eq!(status, 404, "{profile} {label} {kind}: {refused}");
            }
        }
        // Positive control: tenant A still reads both, unchanged by the refused PATCH/DELETE.
        let (status, own) = admin(
            &state,
            "GET",
            &format!("{ADMIN_V2}/tenants/{TENANT_A}/oauthIdpConfigs/oidc.acme"),
            &json!({}),
        );
        assert_eq!(status, 200, "{profile}: {own}");
        assert_eq!(own["displayName"], "Acme OIDC");
        assert_eq!(own["clientId"], "acme-client");
        let (status, own) = admin(
            &state,
            "GET",
            &format!("{ADMIN_V2}/tenants/{TENANT_A}/inboundSamlConfigs/saml.acme"),
            &json!({}),
        );
        assert_eq!(status, 200, "{profile}: {own}");
        assert_eq!(own["displayName"], "Acme SAML");

        // The same ID in the project and in tenant B are independent configurations.
        let (status, project_created) = admin(
            &state,
            "POST",
            &format!("{ADMIN_V2}/oauthIdpConfigs?oauthIdpConfigId=oidc.acme"),
            &json!({"clientId": "project-client", "issuer": "https://issuer.project.example"}),
        );
        assert_eq!(status, 200, "{profile}: {project_created}");
        let (status, b_created) = admin(
            &state,
            "POST",
            &format!("{ADMIN_V2}/tenants/{TENANT_B}/oauthIdpConfigs?oauthIdpConfigId=oidc.acme"),
            &json!({"clientId": "b-client", "issuer": "https://issuer.b.example"}),
        );
        assert_eq!(status, 200, "{profile}: {b_created}");
        let (status, deleted) = admin(
            &state,
            "DELETE",
            &format!("{ADMIN_V2}/tenants/{TENANT_A}/oauthIdpConfigs/oidc.acme"),
            &json!({}),
        );
        assert_eq!(status, 200, "{profile}: {deleted}");
        let (status, project_still) = admin(
            &state,
            "GET",
            &format!("{ADMIN_V2}/oauthIdpConfigs/oidc.acme"),
            &json!({}),
        );
        assert_eq!(status, 200, "{profile}: {project_still}");
        assert_eq!(project_still["clientId"], "project-client");
        let (status, b_still) = admin(
            &state,
            "GET",
            &format!("{ADMIN_V2}/tenants/{TENANT_B}/oauthIdpConfigs/oidc.acme"),
            &json!({}),
        );
        assert_eq!(status, 200, "{profile}: {b_still}");
        assert_eq!(b_still["clientId"], "b-client");
        let (status, gone) = admin(
            &state,
            "GET",
            &format!("{ADMIN_V2}/tenants/{TENANT_A}/oauthIdpConfigs/oidc.acme"),
            &json!({}),
        );
        assert_eq!(status, 404, "{profile}: {gone}");
    }
}

// ---------------------------------------------------------------------------------------
// (e): deleting a tenant invalidates its credentials and leaves everything else alone.
// ---------------------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn deleting_a_tenant_invalidates_its_credentials_and_leaves_the_sibling_and_project_untouched() {
    for (profile, state, registry) in profiles() {
        let a = sign_up(&state, TENANT_A, "a@example.com");
        let b = sign_up(&state, TENANT_B, "b@example.com");
        let (status, project_user) = post(
            &state,
            &format!("{V1}/accounts:signUp?key={KEY}"),
            &json!({"email": "p@example.com", "password": "hunter22"}),
        );
        assert_eq!(status, 200, "{profile}: {project_user}");
        let (status, created) = admin(
            &state,
            "POST",
            &format!("{ADMIN_V2}/tenants/{TENANT_A}/oauthIdpConfigs?oauthIdpConfigId=oidc.acme"),
            &json!({"clientId": "acme", "issuer": "https://issuer.acme.example"}),
        );
        assert_eq!(status, 200, "{profile}: {created}");
        let token_a = a["idToken"].as_str().unwrap().to_owned();
        let refresh_a = a["refreshToken"].as_str().unwrap().to_owned();
        let token_b = b["idToken"].as_str().unwrap().to_owned();
        let refresh_b = b["refreshToken"].as_str().unwrap().to_owned();
        let project_token = project_user["idToken"].as_str().unwrap().to_owned();
        let before_b = snapshot(&state, Some(TENANT_B));
        let before_project = snapshot(&state, None);

        let (status, deleted) = admin(
            &state,
            "DELETE",
            &format!("{ADMIN_V2}/tenants/{TENANT_A}"),
            &json!({}),
        );
        assert_eq!(status, 200, "{profile}: {deleted}");
        let (status, again) = admin(
            &state,
            "DELETE",
            &format!("{ADMIN_V2}/tenants/{TENANT_A}"),
            &json!({}),
        );
        assert_eq!(status, 404, "{profile}: {again}");
        assert_eq!(class(&again), "TENANT_NOT_FOUND");

        // The store, metadata, listing, provider configs and Admin routes are gone.
        assert!(
            registry.tenant_store("demo-app", TENANT_A).is_none(),
            "{profile}"
        );
        assert!(
            registry.tenant_metadata("demo-app", TENANT_A).is_none(),
            "{profile}"
        );
        assert_eq!(
            registry.tenants("demo-app"),
            vec![TENANT_B.to_owned()],
            "{profile}"
        );
        let (status, listed) = admin(&state, "GET", &format!("{ADMIN_V2}/tenants"), &json!({}));
        assert_eq!(status, 200, "{profile}: {listed}");
        assert_eq!(listed["tenants"].as_array().unwrap().len(), 1);
        assert_eq!(
            listed["tenants"][0]["name"],
            format!("projects/demo-app/tenants/{TENANT_B}")
        );
        let (status, missing) = admin(
            &state,
            "GET",
            &format!("{ADMIN_V2}/tenants/{TENANT_A}"),
            &json!({}),
        );
        assert_eq!(status, 404, "{profile}: {missing}");
        assert_eq!(class(&missing), "TENANT_NOT_FOUND");
        let (status, missing) = admin(
            &state,
            "GET",
            &format!("{ADMIN_V2}/tenants/{TENANT_A}/oauthIdpConfigs/oidc.acme"),
            &json!({}),
        );
        assert_eq!(status, 404, "{profile}: {missing}");
        let (status, missing) = admin(
            &state,
            "GET",
            &tenant_admin_path(TENANT_A, "accounts:batchGet?maxResults=1000"),
            &json!({}),
        );
        assert_eq!(status, 404, "{profile}: {missing}");
        assert_eq!(class(&missing), "TENANT_NOT_FOUND");

        // Issued credentials of the deleted tenant no longer authenticate anywhere. The
        // class depends on the selector: the API key resolves the named tenant and finds
        // none; a bare body tenant is compared with the store the token still selects (the
        // parent project, the only remaining namespace the token can name), and a bare
        // query tenant matches the token's tenant and then the token fails verification
        // against that parent store. Every shape is a refusal without fallback.
        for (selector, lookup_status, lookup_class, refresh_status, refresh_class) in [
            (
                Selector::KeyAndBody,
                404,
                "TENANT_NOT_FOUND",
                404,
                "TENANT_NOT_FOUND",
            ),
            (
                Selector::BodyOnly,
                400,
                "TENANT_ID_MISMATCH",
                400,
                "TENANT_NOT_FOUND",
            ),
            (
                Selector::QueryOnly,
                400,
                "INVALID_ID_TOKEN",
                404,
                "TENANT_NOT_FOUND",
            ),
        ]
        .into_iter()
        .filter(|row| Selector::admitted(&state).contains(&row.0))
        {
            let (status, refused) = selector.request(
                &state,
                &format!("{V1}/accounts:lookup"),
                TENANT_A,
                json!({"idToken": token_a}),
            );
            assert_eq!(
                status, lookup_status,
                "{profile} lookup {selector:?}: {refused}"
            );
            assert_eq!(
                class(&refused),
                lookup_class,
                "{profile} lookup {selector:?}: {refused}"
            );
            let (status, refused) = selector.request(
                &state,
                SECURE_TOKEN,
                TENANT_A,
                json!({"grant_type": "refresh_token", "refresh_token": refresh_a}),
            );
            assert_eq!(
                status, refresh_status,
                "{profile} refresh {selector:?}: {refused}"
            );
            assert_eq!(
                class(&refused),
                refresh_class,
                "{profile} refresh {selector:?}: {refused}"
            );
        }
        // Without a tenant selector the token still names the deleted tenant and cannot fall
        // back to the project or to the sibling.
        let (status, refused) = post(
            &state,
            &format!("{V1}/accounts:lookup?key={KEY}"),
            &json!({"idToken": token_a}),
        );
        assert_eq!(status, 400, "{profile}: {refused}");
        assert_eq!(class(&refused), "INVALID_ID_TOKEN", "{profile}: {refused}");
        let (status, refused) = post(
            &state,
            &format!("{SECURE_TOKEN}?key={KEY}"),
            &json!({"grant_type": "refresh_token", "refresh_token": refresh_a}),
        );
        assert_eq!(status, 400, "{profile}: {refused}");
        assert_eq!(
            class(&refused),
            "INVALID_REFRESH_TOKEN",
            "{profile}: {refused}"
        );
        let (status, refused) = client(
            &state,
            &format!("{V1}/accounts:lookup"),
            TENANT_B,
            json!({"idToken": token_a}),
        );
        assert_eq!(status, 400, "{profile}: {refused}");
        assert_eq!(class(&refused), "INVALID_ID_TOKEN", "{profile}: {refused}");

        // The sibling tenant and the project are untouched and their credentials still work.
        assert_eq!(snapshot(&state, Some(TENANT_B)), before_b, "{profile}");
        assert_eq!(snapshot(&state, None), before_project, "{profile}");
        let (status, found) = client(
            &state,
            &format!("{V1}/accounts:lookup"),
            TENANT_B,
            json!({"idToken": token_b}),
        );
        assert_eq!(status, 200, "{profile}: {found}");
        assert_eq!(found["users"][0]["tenantId"], TENANT_B);
        let (status, renewed) = client(
            &state,
            SECURE_TOKEN,
            TENANT_B,
            json!({"grant_type": "refresh_token", "refresh_token": refresh_b}),
        );
        assert_eq!(status, 200, "{profile}: {renewed}");
        let (status, found) = post(
            &state,
            &format!("{V1}/accounts:lookup?key={KEY}"),
            &json!({"idToken": project_token}),
        );
        assert_eq!(status, 200, "{profile}: {found}");
        assert!(
            found["users"][0].get("tenantId").is_none(),
            "{profile}: {found}"
        );

        // A namespace re-created under the same ID starts empty: the old credentials do not
        // revive (the token's tenant now matches but its subject does not exist) and the new
        // tenant has no users and no provider configs.
        registry.ensure_tenant("demo-app", TENANT_A).unwrap();
        assert!(snapshot(&state, Some(TENANT_A))["users"]
            .as_array()
            .is_none_or(Vec::is_empty));
        let (status, refused) = client(
            &state,
            &format!("{V1}/accounts:lookup"),
            TENANT_A,
            json!({"idToken": token_a}),
        );
        assert_eq!(status, 400, "{profile}: {refused}");
        assert_eq!(class(&refused), "USER_NOT_FOUND", "{profile}: {refused}");
        let (status, refused) = client(
            &state,
            SECURE_TOKEN,
            TENANT_A,
            json!({"grant_type": "refresh_token", "refresh_token": refresh_a}),
        );
        assert_eq!(status, 400, "{profile}: {refused}");
        assert_eq!(
            class(&refused),
            "INVALID_REFRESH_TOKEN",
            "{profile}: {refused}"
        );
        let (status, missing) = admin(
            &state,
            "GET",
            &format!("{ADMIN_V2}/tenants/{TENANT_A}/oauthIdpConfigs/oidc.acme"),
            &json!({}),
        );
        assert_eq!(status, 404, "{profile}: {missing}");
        assert!(snapshot(&state, Some(TENANT_A))["users"]
            .as_array()
            .is_none_or(Vec::is_empty));
    }
}
