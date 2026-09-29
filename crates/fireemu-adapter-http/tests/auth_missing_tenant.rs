//! A request that names a tenant that does not exist. The official Auth emulator (firebase-tools
//! 15.28.2, `server.js` `getProjectStateById`, `state.js` `getTenantProject`) creates the tenant on
//! the way, with defaults, wherever an operation's target tenant comes from the path, the body's
//! `tenantId`, the ID token's `firebase.tenant` or (for `accounts:batchGet`) the query. The
//! emulator profile does the same. The strict profile refuses and creates nothing, as production
//! does.

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

/// The members of the tenant the official emulator creates for a name it has not seen
/// (`state.js` `getTenantProject`) that the emulator profile's tenant document has too:
/// password sign-up, anonymous users and email-link sign-in on, authentication not disabled (a
/// switch appears only when on) and multi-factor enabled for `PHONE_SMS`. The document keeps the
/// profile's own shape for every tenant (no `tenantId`, a `name` by project number when known,
/// `inheritance`), which this test does not change.
fn assert_official_default_tenant(document: &Value, project: &str, tenant: &str) {
    assert_eq!(
        document["name"],
        format!("projects/{project}/tenants/{tenant}"),
        "{document}"
    );
    assert_eq!(document["allowPasswordSignup"], true, "{document}");
    assert_eq!(document["enableAnonymousUser"], true, "{document}");
    assert_eq!(document["enableEmailLinkSignin"], true, "{document}");
    assert!(document.get("disableAuth").is_none(), "{document}");
    assert!(document.get("displayName").is_none(), "{document}");
    assert_eq!(
        document["mfaConfig"],
        json!({"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}),
        "{document}"
    );
}

#[test]
fn a_client_request_naming_a_new_tenant_creates_it_with_the_official_defaults() {
    let (state, registry) = emulator();
    assert!(registry.tenant_store("demo-app", "brand-new").is_none());
    let (status, created) = client(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "a@example.com", "password": "hunter22", "tenantId": "brand-new"}),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(
        claims(created["idToken"].as_str().unwrap())["firebase"]["tenant"],
        "brand-new"
    );
    assert!(registry.tenant_store("demo-app", "brand-new").is_some());
    assert_eq!(tenant_names(&state, "demo-app"), ["brand-new"]);
    let (status, document) = admin(
        &state,
        "GET",
        &format!("{V2}/projects/demo-app/tenants/brand-new"),
        &json!({}),
    );
    assert_eq!(status, 200, "{document}");
    assert_official_default_tenant(&document, "demo-app", "brand-new");
    let (status, listed) = admin(
        &state,
        "GET",
        &format!("{V2}/projects/demo-app/tenants"),
        &json!({}),
    );
    assert_eq!(status, 200, "{listed}");
    assert_eq!(
        listed["tenants"].as_array().map(Vec::len),
        Some(1),
        "{listed}"
    );
    assert_official_default_tenant(&listed["tenants"][0], "demo-app", "brand-new");
}

/// Each request family the official emulator reads a target tenant from creates it: the path
/// (client-style resource paths, tenant management, emulator routes), the body's `tenantId`, and
/// the query of `accounts:batchGet`.
#[test]
fn every_way_of_naming_a_tenant_creates_it_in_the_emulator_profile() {
    let cases: Vec<(&str, String, &str, Value)> = vec![
        (
            "body tenantId",
            format!("{V1}/accounts:lookup?key={KEY}"),
            "POST",
            json!({"tenantId": "t-body", "idToken": "x"}),
        ),
        (
            "body tenantId, sign in",
            format!("{V1}/accounts:signInWithPassword?key={KEY}"),
            "POST",
            json!({"tenantId": "t-signin", "email": "a@example.com", "password": "p"}),
        ),
        (
            "path, admin create",
            format!("{V1}/projects/demo-app/tenants/t-path/accounts"),
            "POST",
            json!({"email": "a@example.com", "password": "hunter22"}),
        ),
        (
            "path, admin batchGet",
            format!("{V1}/projects/demo-app/tenants/t-batch/accounts:batchGet"),
            "GET",
            json!({}),
        ),
        (
            "query, batchGet",
            format!("{V1}/projects/demo-app/accounts:batchGet?tenantId=t-query"),
            "GET",
            json!({}),
        ),
        (
            "tenant document read",
            format!("{V2}/projects/demo-app/tenants/t-get"),
            "GET",
            json!({}),
        ),
        (
            "tenant document update",
            format!("{V2}/projects/demo-app/tenants/t-patch?updateMask=displayName"),
            "PATCH",
            json!({"displayName": "x"}),
        ),
        (
            "emulator route",
            "/emulator/v1/projects/demo-app/tenants/t-emulator/oobCodes".to_string(),
            "GET",
            json!({}),
        ),
    ];
    for (case, path, method, body) in cases {
        let (state, registry) = emulator();
        let tenant = case_tenant(&path, &body);
        assert!(
            registry.tenant_store("demo-app", &tenant).is_none(),
            "{case}"
        );
        let r = handle_with(&state, method, &path, &owner(), &body);
        assert!(
            registry.tenant_store("demo-app", &tenant).is_some(),
            "{case}: the tenant was not created (answer {} {})",
            r.status,
            r.body
        );
        assert_eq!(
            tenant_names(&state, "demo-app"),
            [tenant.as_str()],
            "{case}"
        );
    }
}

fn case_tenant(path: &str, body: &Value) -> String {
    if let Some(tenant) = body["tenantId"].as_str() {
        return tenant.to_owned();
    }
    if let Some(rest) = path.split("tenantId=").nth(1) {
        return rest.split('&').next().unwrap().to_owned();
    }
    let after = path.split("/tenants/").nth(1).unwrap();
    after.split(['/', '?', ':']).next().unwrap().to_owned()
}

/// A tenant management request for a tenant that does not exist finds one made on the way: the
/// read answers the defaults and the delete removes what it made.
#[test]
fn tenant_management_requests_act_on_the_tenant_made_on_the_way() {
    let (state, registry) = emulator();
    let (status, deleted) = admin(
        &state,
        "DELETE",
        &format!("{V2}/projects/demo-app/tenants/ghost"),
        &json!({}),
    );
    assert_eq!((status, deleted), (200, json!({})));
    assert!(registry.tenant_store("demo-app", "ghost").is_none());
    let (status, updated) = admin(
        &state,
        "PATCH",
        &format!("{V2}/projects/demo-app/tenants/ghost2?updateMask=displayName"),
        &json!({"displayName": "renamed"}),
    );
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["displayName"], "renamed", "{updated}");
    assert_eq!(updated["allowPasswordSignup"], true, "{updated}");
    assert_eq!(updated["enableAnonymousUser"], true, "{updated}");
}

#[test]
fn a_request_with_a_token_of_a_deleted_tenant_finds_no_user_and_the_tenant_exists_again() {
    let (state, registry) = emulator();
    let (status, created) = client(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "a@example.com", "password": "hunter22", "tenantId": "gone"}),
    );
    assert_eq!(status, 200, "{created}");
    assert!(registry.delete_tenant("demo-app", "gone"));
    let (status, refused) = client(
        &state,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": created["idToken"]}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "USER_NOT_FOUND");
    // The official emulator made the tenant on the way, empty.
    assert!(registry.tenant_store("demo-app", "gone").is_some());
    assert_eq!(tenant_names(&state, "demo-app"), ["gone"]);
}

/// The requests the official emulator does not serve a tenant for create none.
#[test]
fn what_names_no_servable_tenant_creates_nothing() {
    let (state, registry) = emulator();
    // A path tenant and a body tenant that differ, an empty name, a name that is not a string,
    // and a route that does not exist.
    let attempts: Vec<(&str, String, &str, Value)> = vec![
        (
            "mismatch",
            format!("{V1}/projects/demo-app/tenants/one/accounts:batchGet"),
            "GET",
            json!({"tenantId": "two"}),
        ),
        (
            "empty",
            format!("{V1}/accounts:lookup?key={KEY}"),
            "POST",
            json!({"tenantId": "", "idToken": "x"}),
        ),
        (
            "not a string",
            format!("{V1}/accounts:lookup?key={KEY}"),
            "POST",
            json!({"tenantId": 7, "idToken": "x"}),
        ),
        (
            "unknown route",
            format!("{V1}/projects/demo-app/tenants/three/nothing"),
            "GET",
            json!({}),
        ),
        (
            "slash",
            format!("{V1}/accounts:lookup?key={KEY}"),
            "POST",
            json!({"tenantId": "a/b", "idToken": "x"}),
        ),
    ];
    for (case, path, method, body) in attempts {
        let _ = handle_with(&state, method, &path, &owner(), &body);
        for tenant in ["one", "two", "three", "a/b"] {
            assert!(
                registry.tenant_store("demo-app", tenant).is_none(),
                "{case}: {tenant}"
            );
        }
        assert_eq!(
            tenant_names(&state, "demo-app"),
            Vec::<String>::new(),
            "{case}"
        );
    }
}

/// A token of another project is not a tenant of this one: the request keeps its refusal and no
/// tenant is made (the emulator profile's exception, AUTH-FS-CROSS closure).
#[test]
fn a_token_of_another_project_creates_no_tenant() {
    let (state, registry) = emulator();
    let other = AuthState {
        store: Arc::new(Mutex::new(AuthStore::new(
            "other-app",
            SplitMix64::new(9),
            TotpPolicy::default(),
        ))),
        registry: None,
        ..emulator_state()
    };
    let (status, created) = client(
        &other,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    // A tenant-scoped token of the other project, with a tenant this project lacks.
    let (status, tenant_token) = {
        let registry = Arc::new(AuthRegistry::new("other-app", other.store.clone()));
        let mut with_tenants = AuthState {
            registry: Some(registry),
            ..emulator_state()
        };
        with_tenants.store = other.store.clone();
        client(
            &with_tenants,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "b@example.com", "password": "hunter22", "tenantId": "elsewhere"}),
        )
    };
    assert_eq!(status, 200, "{tenant_token}");
    let (_, _) = client(
        &state,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": tenant_token["idToken"]}),
    );
    assert!(registry.tenant_store("demo-app", "elsewhere").is_none());
}

/// The strict profile refuses a tenant that does not exist and creates nothing, as production.
#[test]
fn the_strict_profile_creates_nothing() {
    let (_, state, registry) = profiles().into_iter().nth(1).unwrap();
    let (status, refused) = client(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "a@example.com", "password": "hunter22", "tenantId": "brand-new"}),
    );
    assert_eq!(status, 400, "{refused}");
    for (method, path) in [
        ("GET", format!("{V2}/projects/demo-app/tenants/ghost")),
        (
            "GET",
            format!("{V1}/projects/demo-app/tenants/ghost2/accounts:batchGet"),
        ),
        (
            "GET",
            format!("{V1}/projects/demo-app/accounts:batchGet?tenantId=ghost3"),
        ),
    ] {
        let _ = handle_with(&state, method, &path, &owner(), &json!({}));
    }
    for tenant in ["brand-new", "ghost", "ghost2", "ghost3"] {
        assert!(
            registry.tenant_store("demo-app", tenant).is_none(),
            "{tenant}"
        );
    }
    assert_eq!(tenant_names(&state, "demo-app"), Vec::<String>::new());
}

/// The emulator keeps one state per project (`getProjectStateById`), so the tenant is made in the
/// project the request names, and nowhere else.
#[test]
fn the_tenant_is_made_in_the_project_the_request_names() {
    let (state, registry) = emulator();
    let second = AuthStore::new("demo-second", SplitMix64::new(11), TotpPolicy::default());
    assert!(registry.register_session("demo-second", second));
    let (status, created) = admin(
        &state,
        "POST",
        &format!("{V1}/projects/demo-second/tenants/only-here/accounts"),
        &json!({"email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    assert!(registry.tenant_store("demo-second", "only-here").is_some());
    assert!(registry.tenant_store("demo-app", "only-here").is_none());
    assert_eq!(tenant_names(&state, "demo-second"), ["only-here"]);
    assert_eq!(tenant_names(&state, "demo-app"), Vec::<String>::new());
}
