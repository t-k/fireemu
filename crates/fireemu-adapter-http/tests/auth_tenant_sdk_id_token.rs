//! Web SDK calls that carry a tenant user's ID token and no tenant selector.
//!
//! `@firebase/auth` (firebase 12.18.0) adds `tenantId` only to some requests. `accounts:lookup`
//! (after every sign-in and on `reload()`), `accounts:delete` (`user.delete()`) and the
//! `accounts:update` forms of `updateProfile` and linking go out with the API key and the ID
//! token alone. Web SDK tenant sign-in works in production, so these calls are taken to reach
//! the token's tenant there. That is inferred, not observed: the AUTH-FS-CROSS stage-2
//! production recording signs two tenant clients in through the Web SDK and checks it.
//!
//! Everything else keeps its current answer: a body tenant that contradicts the token, a
//! deleted tenant's token, a tenant token of another project under a foreign key, a tenant
//! claim naming no tenant, and the project user's path.

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
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
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

/// Both profiles with two tenants of the default project, each with no tenancy map and with
/// the daemon's default empty one.
fn cases() -> Vec<(String, AuthState, Arc<AuthRegistry>)> {
    let mut out = Vec::new();
    for (label, make) in [
        ("emulator", emulator_state as fn() -> AuthState),
        ("strict", strict_state),
    ] {
        for empty_tenancy in [false, true] {
            let mut state = make();
            let registry = Arc::new(AuthRegistry::new("demo-app", state.store.clone()));
            for tenant in [TENANT_A, TENANT_B] {
                registry.ensure_tenant("demo-app", tenant).unwrap();
            }
            state.registry = Some(registry.clone());
            if empty_tenancy {
                state.tenancy = Some(Arc::new(RwLock::new(Tenancy::new("demo-app"))));
            }
            let tenancy = if empty_tenancy { "empty" } else { "none" };
            out.push((format!("{label} tenancy={tenancy}"), state, registry));
        }
    }
    out
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
    let r = handle(state, "POST", path, body);
    (r.status, r.body)
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

/// A tenant sign-up in the SDK's shape (the key in the query, the tenant in the body).
fn sign_up(state: &AuthState, key: &str, tenant: &str, email: &str) -> Value {
    let (status, created) = post(
        state,
        &format!("{V1}/accounts:signUp?key={key}"),
        &json!({"tenantId": tenant, "email": email, "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{tenant}: {created}");
    assert_eq!(
        claims(created["idToken"].as_str().unwrap())["firebase"]["tenant"],
        tenant
    );
    created
}

fn tenant_accounts(state: &AuthState, project: &str, tenant: &str) -> Value {
    let (status, body) = admin(
        state,
        "GET",
        &format!("{V1}/projects/{project}/tenants/{tenant}/accounts:batchGet?maxResults=1000"),
        &json!({}),
    );
    assert_eq!(status, 200, "{body}");
    body
}

/// A call in the Web SDK's shape: the API key in the query, the ID token in the body, no
/// tenant selector anywhere.
fn sdk_call(state: &AuthState, route: &str, body: &Value) -> (u16, Value) {
    post(state, &format!("{V1}/{route}?key={KEY}"), body)
}

#[test]
fn sdk_shaped_lookup_update_and_delete_reach_the_tokens_tenant() {
    for (case, state, _registry) in cases() {
        let a = sign_up(&state, KEY, TENANT_A, "a@example.com");
        let id_token = a["idToken"].as_str().unwrap().to_owned();
        let uid = a["localId"].as_str().unwrap().to_owned();

        let (status, found) = sdk_call(&state, "accounts:lookup", &json!({"idToken": id_token}));
        assert_eq!(status, 200, "{case} lookup: {found}");
        assert_eq!(found["users"][0]["localId"], uid, "{case}");
        assert_eq!(found["users"][0]["tenantId"], TENANT_A, "{case}");

        let (status, updated) = sdk_call(
            &state,
            "accounts:update",
            &json!({"idToken": id_token, "displayName": "Tenant A", "returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{case} update: {updated}");
        let accounts = tenant_accounts(&state, "demo-app", TENANT_A);
        assert_eq!(accounts["users"][0]["displayName"], "Tenant A", "{case}");

        let (status, deleted) = sdk_call(&state, "accounts:delete", &json!({"idToken": id_token}));
        assert_eq!(status, 200, "{case} delete: {deleted}");
        let accounts = tenant_accounts(&state, "demo-app", TENANT_A);
        assert!(
            accounts["users"].as_array().is_none_or(Vec::is_empty),
            "{case}: {accounts}"
        );
    }
}

/// The project user's calls keep the project store.
#[test]
fn sdk_shaped_calls_of_a_project_user_are_unchanged() {
    for (case, state, _registry) in cases() {
        let (status, user) = post(
            &state,
            &format!("{V1}/accounts:signUp?key={KEY}"),
            &json!({"email": "p@example.com", "password": "hunter22", "returnSecureToken": true}),
        );
        assert_eq!(status, 200, "{case}: {user}");
        let (status, found) = sdk_call(
            &state,
            "accounts:lookup",
            &json!({"idToken": user["idToken"]}),
        );
        assert_eq!(status, 200, "{case}: {found}");
        assert_eq!(found["users"][0]["localId"], user["localId"], "{case}");
        assert_eq!(found["users"][0]["tenantId"], Value::Null, "{case}");
    }
}

/// A body tenant that contradicts the token keeps its refusal, and changes nothing.
#[test]
fn a_contradicting_body_tenant_keeps_its_refusal() {
    for (case, state, _registry) in cases() {
        let a = sign_up(&state, KEY, TENANT_A, "a@example.com");
        let before = tenant_accounts(&state, "demo-app", TENANT_A);
        for route in ["accounts:lookup", "accounts:update", "accounts:delete"] {
            let (status, refused) = sdk_call(
                &state,
                route,
                &json!({"idToken": a["idToken"], "tenantId": TENANT_B, "displayName": "x"}),
            );
            assert_eq!(status, 400, "{case} {route}: {refused}");
            assert_eq!(
                class(&refused),
                "INVALID_ID_TOKEN",
                "{case} {route}: {refused}"
            );
        }
        assert_eq!(
            tenant_accounts(&state, "demo-app", TENANT_A),
            before,
            "{case}"
        );
    }
}

/// A deleted tenant's token names no store any more: it is refused as before.
#[test]
fn a_deleted_tenants_token_keeps_its_refusal() {
    for (case, state, registry) in cases() {
        let a = sign_up(&state, KEY, TENANT_A, "a@example.com");
        assert!(registry.delete_tenant("demo-app", TENANT_A), "{case}");
        for route in ["accounts:lookup", "accounts:update", "accounts:delete"] {
            let (status, refused) = sdk_call(
                &state,
                route,
                &json!({"idToken": a["idToken"], "displayName": "x"}),
            );
            assert_eq!(status, 400, "{case} {route}: {refused}");
            assert_eq!(
                class(&refused),
                "INVALID_ID_TOKEN",
                "{case} {route}: {refused}"
            );
        }
    }
}

/// A tenant claim naming no tenant of the project is refused as before. The token is the
/// tenant user's own with its tenant claim replaced, so it also fails its signature where
/// signatures are checked; either way no tenant store is chosen for it.
#[test]
fn a_tenant_claim_naming_no_tenant_keeps_its_refusal() {
    for (case, state, _registry) in cases() {
        let a = sign_up(&state, KEY, TENANT_A, "a@example.com");
        let token = a["idToken"].as_str().unwrap();
        let mut payload = claims(token);
        payload["firebase"]["tenant"] = json!("tenant-missing");
        let mut parts = token.split('.');
        let header = parts.next().unwrap();
        let signature = parts.nth(1).unwrap();
        let forged = format!(
            "{header}.{}.{signature}",
            base64url_encode(payload.to_string().as_bytes())
        );
        for route in ["accounts:lookup", "accounts:update", "accounts:delete"] {
            let (status, refused) = sdk_call(
                &state,
                route,
                &json!({"idToken": forged, "displayName": "x"}),
            );
            assert_eq!(status, 400, "{case} {route}: {refused}");
            assert_eq!(
                class(&refused),
                "INVALID_ID_TOKEN",
                "{case} {route}: {refused}"
            );
        }
        let accounts = tenant_accounts(&state, "demo-app", TENANT_A);
        assert_eq!(accounts["users"][0]["displayName"], Value::Null, "{case}");
    }
}

/// The API key names the project: a tenant token of another registered project is refused
/// under a foreign key, and reaches its tenant under its own project's key.
#[test]
fn a_tenant_token_of_another_project_is_refused_under_a_foreign_key() {
    for (case, mut state, registry) in cases() {
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
        let alpha = sign_up(&state, "alpha-key", "customer-a", "alpha@example.com");
        let before = tenant_accounts(&state, "worker-alpha", "customer-a");

        for route in ["accounts:lookup", "accounts:update", "accounts:delete"] {
            let (status, refused) = post(
                &state,
                &format!("{V1}/{route}?key=beta-key"),
                &json!({"idToken": alpha["idToken"], "displayName": "x"}),
            );
            assert_eq!(status, 400, "{case} {route}: {refused}");
            assert_eq!(
                class(&refused),
                "INVALID_ID_TOKEN",
                "{case} {route}: {refused}"
            );
        }
        assert_eq!(
            tenant_accounts(&state, "worker-alpha", "customer-a"),
            before,
            "{case}"
        );

        let (status, found) = post(
            &state,
            &format!("{V1}/accounts:lookup?key=alpha-key"),
            &json!({"idToken": alpha["idToken"]}),
        );
        assert_eq!(status, 200, "{case}: {found}");
        assert_eq!(found["users"][0]["localId"], alpha["localId"], "{case}");
    }
}
