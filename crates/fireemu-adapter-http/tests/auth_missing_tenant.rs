//! A request that names a tenant that does not exist. The official Auth emulator (firebase-tools
//! 15.28.2, `server.js` `getProjectStateById`, `state.js` `getTenantProject`) creates the tenant on
//! the way, with defaults, wherever an operation's target tenant comes from the path, the body's
//! `tenantId`, the ID token's `firebase.tenant` or (for `accounts:batchGet`) the query. The
//! emulator profile does the same. The strict profile refuses and creates nothing, as production
//! does.

use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthQueryLimits, AuthState, ClientApiKeyPolicy, FakeCustomTokenExpiry,
    IdpContinuationPolicy, RequestHeaders,
};
use fireemu_core_auth::jwt::decode_unsigned;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_session::tenancy::Tenancy;
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
    // A path tenant and a body tenant that differ, an empty name, a name that is a boolean, an
    // object or an array (a number is read as its string, `a_numeric_tenant_id_names_its_string`),
    // and a route that does not exist.
    let attempts: Vec<(&str, String, &str, Value)> = vec![
        (
            "mismatch",
            format!("{V1}/projects/demo-app/tenants/one/accounts"),
            "POST",
            json!({"tenantId": "two", "email": "a@example.com", "password": "hunter22"}),
        ),
        (
            "empty",
            format!("{V1}/accounts:lookup?key={KEY}"),
            "POST",
            json!({"tenantId": "", "idToken": "x"}),
        ),
        (
            "a boolean",
            format!("{V1}/accounts:lookup?key={KEY}"),
            "POST",
            json!({"tenantId": true, "idToken": "x"}),
        ),
        (
            "an object",
            format!("{V1}/accounts:lookup?key={KEY}"),
            "POST",
            json!({"tenantId": {"name": "one"}, "idToken": "x"}),
        ),
        (
            "an array",
            format!("{V1}/accounts:lookup?key={KEY}"),
            "POST",
            json!({"tenantId": ["one"], "idToken": "x"}),
        ),
        (
            "unknown route",
            format!("{V1}/projects/demo-app/tenants/three/nothing"),
            "GET",
            json!({}),
        ),
        (
            "unknown route with a body tenant",
            format!("{V1}/nothing-here?key={KEY}"),
            "POST",
            json!({"tenantId": "four"}),
        ),
    ];
    for (case, path, method, body) in attempts {
        let _ = handle_with(&state, method, &path, &owner(), &body);
        for tenant in ["one", "two", "three", "four"] {
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
    let (status, refused) = client(
        &state,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": tenant_token["idToken"]}),
    );
    assert_eq!(status, 400, "{refused}");
    assert!(registry.tenant_store("demo-app", "elsewhere").is_none());
    // The token's tenant still has to agree with the tenant the body names, as the official
    // emulator asserts before it looks a tenant up: a mismatch makes nothing.
    let (status, refused) = client(
        &state,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": tenant_token["idToken"], "tenantId": "named-anyway"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_ID_MISMATCH");
    assert!(registry.tenant_store("demo-app", "named-anyway").is_none());
    assert!(registry.tenant_store("demo-app", "elsewhere").is_none());
    // The same through the path, and a credential the guard refuses is still refused first.
    let path = format!("{V1}/projects/demo-app/tenants/named-by-path/accounts:lookup");
    let r = handle_with(
        &state,
        "POST",
        &path,
        &owner(),
        &json!({"idToken": tenant_token["idToken"]}),
    );
    assert_eq!(r.status, 400, "{}", r.body);
    assert_eq!(r.body["error"]["message"], "TENANT_ID_MISMATCH");
    let garbage = RequestHeaders {
        authorization: Some("Bearer garbage".to_owned()),
        ..owner()
    };
    let r = handle_with(
        &state,
        "POST",
        &path,
        &garbage,
        &json!({"idToken": tenant_token["idToken"]}),
    );
    assert_eq!(r.status, 401, "{}", r.body);
    assert!(registry.tenant_store("demo-app", "named-by-path").is_none());
    // An agreeing body tenant is the target, and is made.
    let _ = client(
        &state,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": tenant_token["idToken"], "tenantId": "elsewhere"}),
    );
    assert!(registry.tenant_store("demo-app", "elsewhere").is_some());
}

/// A body the official schema check rejects still makes the tenant it names: Fireemu validates in
/// each handler, after the tenant is made (a recorded divergence).
#[test]
fn a_body_the_official_schema_rejects_still_makes_the_tenant() {
    let (state, registry) = emulator();
    let (status, refused) = client(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"tenantId": "t-badbody", "email": {"x": 1}}),
    );
    assert_eq!(status, 400, "{refused}");
    assert!(registry.tenant_store("demo-app", "t-badbody").is_some());
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

/// An empty `tenantId` is no tenant to the official emulator (JavaScript falsiness): a path
/// tenant beside it is the target, and is made.
#[test]
fn an_empty_body_tenant_leaves_the_path_tenant_as_the_target() {
    let (state, registry) = emulator();
    // (The answer to the request itself is a separate matter: the account API still reads a path
    // tenant beside an empty body tenant as a mismatch.)
    let _ = admin(
        &state,
        "POST",
        &format!("{V1}/projects/demo-app/tenants/t-empty/accounts"),
        &json!({"tenantId": "", "email": "a@example.com", "password": "hunter22"}),
    );
    assert!(registry.tenant_store("demo-app", "t-empty").is_some());
}

/// The tenant made on the way holds the official default multi-factor config in its own store, and
/// shows it as written; a tenant made by a create request does not get it.
#[test]
fn the_tenant_made_on_the_way_carries_the_default_mfa_config_in_its_store() {
    use fireemu_core_auth::mfa_config::MfaConfigState;
    let (state, registry) = emulator();
    let (status, _) = admin(
        &state,
        "GET",
        &format!("{V2}/projects/demo-app/tenants/on-the-way"),
        &json!({}),
    );
    assert_eq!(status, 200);
    let store = registry.tenant_store("demo-app", "on-the-way").unwrap();
    let config = store.lock().unwrap().mfa_config().clone();
    assert_eq!(config.state, MfaConfigState::Enabled);
    assert!(config.phone_sms);
    assert!(!config.totp_enabled());
    let (status, created) = admin(
        &state,
        "POST",
        &format!("{V2}/projects/demo-app/tenants"),
        &json!({"displayName": "explicit"}),
    );
    assert_eq!(status, 200, "{created}");
    assert!(created.get("mfaConfig").is_none(), "{created}");
    let id = created["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap();
    let store = registry.tenant_store("demo-app", id).unwrap();
    assert_eq!(
        *store.lock().unwrap().mfa_config(),
        fireemu_core_auth::mfa_config::MfaProjectConfig::default()
    );
}

fn no_tenant(registry: &AuthRegistry, projects: &[&str], tenants: &[&str], case: &str) {
    for project in projects {
        for tenant in tenants {
            assert!(
                registry.tenant_store(project, tenant).is_none(),
                "{case}: {project}/{tenant}"
            );
        }
    }
}

/// Only a request this daemon would serve makes a tenant: one that a guard refuses gets the
/// refusal, and nothing is made. The official emulator answers an unauthorised request before it
/// looks a tenant up.
#[test]
fn a_request_a_guard_refuses_makes_no_tenant() {
    let (mut state, registry) = emulator();
    state.control_token = Some("control-token".to_owned());
    let tenants = ["guarded"];
    let garbage = RequestHeaders {
        authorization: Some("Bearer garbage".to_owned()),
        ..owner()
    };
    // An Admin route with a credential that is not the owner's, on every tenant-scoped shape.
    for (method, path) in [
        ("GET", format!("{V2}/projects/demo-app/tenants/guarded")),
        ("DELETE", format!("{V2}/projects/demo-app/tenants/guarded")),
        (
            "POST",
            format!("{V1}/projects/demo-app/tenants/guarded/accounts"),
        ),
        (
            "GET",
            format!("{V1}/projects/demo-app/tenants/guarded/accounts:batchGet"),
        ),
        (
            "GET",
            format!("{V1}/projects/demo-app/accounts:batchGet?tenantId=guarded"),
        ),
    ] {
        let r = handle_with(&state, method, &path, &garbage, &json!({}));
        assert_eq!(r.status, 401, "{method} {path}: {}", r.body);
        no_tenant(
            &registry,
            &["demo-app"],
            &tenants,
            &format!("{method} {path}"),
        );
    }
    // An emulator route from a local page without the control token.
    let browser = RequestHeaders {
        origin: Some("http://localhost:3000".to_owned()),
        authorization: None,
        ..owner()
    };
    let r = handle_with(
        &state,
        "GET",
        "/emulator/v1/projects/demo-app/tenants/guarded/oobCodes",
        &browser,
        &json!({}),
    );
    assert_eq!(r.status, 403, "{}", r.body);
    no_tenant(
        &registry,
        &["demo-app"],
        &tenants,
        "browser without the token",
    );
    // The same request with the token, and an owner credential on the Admin route, is served and
    // makes the tenant.
    let with_token = RequestHeaders {
        authorization: Some("Bearer control-token".to_owned()),
        ..browser
    };
    let r = handle_with(
        &state,
        "GET",
        "/emulator/v1/projects/demo-app/tenants/guarded/oobCodes",
        &with_token,
        &json!({}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(registry.tenant_store("demo-app", "guarded").is_some());
    // A project the daemon does not serve makes nothing, in it or in the default project.
    let r = handle_with(
        &state,
        "GET",
        "/emulator/v1/projects/other-app/tenants/elsewhere/oobCodes",
        &with_token,
        &json!({}),
    );
    assert_eq!(r.status, 404, "{}", r.body);
    no_tenant(
        &registry,
        &["demo-app", "other-app"],
        &["elsewhere"],
        "wrong project",
    );
}

/// A key no project owns is refused, and the tenant its body names is made in no project: the
/// default project's namespace is not written on behalf of a caller that belongs to none.
#[test]
fn an_unknown_api_key_makes_no_tenant_in_any_project() {
    let (mut state, registry) = emulator();
    let alpha = AuthStore::new("worker-alpha", SplitMix64::new(11), TotpPolicy::default());
    assert!(registry.register_session("worker-alpha", alpha));
    let mut tenancy = Tenancy::new("demo-app");
    tenancy
        .register("worker-alpha", &[], &["alpha-key".to_owned()])
        .unwrap();
    state.tenancy = Some(Arc::new(RwLock::new(tenancy)));
    let r = handle(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=unknown-key",
        &json!({"email": "a@example.com", "password": "hunter22", "tenantId": "stray"}),
    );
    assert_eq!(r.status, 400, "{}", r.body);
    assert_eq!(
        r.body["error"]["details"][0]["reason"], "API_KEY_INVALID",
        "{}",
        r.body
    );
    no_tenant(
        &registry,
        &["demo-app", "worker-alpha"],
        &["stray"],
        "unknown key",
    );
    // The project's own key is served: the tenant is made in its project.
    let r = handle(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=alpha-key",
        &json!({"email": "a@example.com", "password": "hunter22", "tenantId": "owned"}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(registry.tenant_store("worker-alpha", "owned").is_some());
    assert!(registry.tenant_store("demo-app", "owned").is_none());
}

/// A malformed query `tenantId` on a route that never reads it (the official emulator ignores it
/// there) does not hide the API key: the request is served from the key's project, and an unknown
/// key still makes no tenant. Probed against the official emulator: `signUp?key=fake&tenantId=a&
/// tenantId=b` with a body tenant answers 200 in the body's tenant.
#[test]
fn a_malformed_query_tenant_on_a_route_that_ignores_it_keeps_the_api_keys_project() {
    for (n, malformed) in ["&tenantId=a&tenantId=b", "&tenantId", "&tenantId="]
        .into_iter()
        .enumerate()
    {
        let (mut state, registry) = emulator();
        let alpha = AuthStore::new("worker-alpha", SplitMix64::new(11), TotpPolicy::default());
        assert!(registry.register_session("worker-alpha", alpha));
        let mut tenancy = Tenancy::new("demo-app");
        tenancy
            .register("worker-alpha", &[], &["alpha-key".to_owned()])
            .unwrap();
        state.tenancy = Some(Arc::new(RwLock::new(tenancy)));
        let sign_up = |key: &str, body: Value| {
            handle(
                &state,
                "POST",
                &format!("/identitytoolkit.googleapis.com/v1/accounts:signUp?key={key}{malformed}"),
                &body,
            )
        };
        // The project's own key, with a body tenant: served, and the tenant is the key's project's.
        let r = sign_up(
            "alpha-key",
            json!({"email": "a@example.com", "password": "hunter22", "tenantId": "owned"}),
        );
        assert_eq!(r.status, 200, "{malformed}: {}", r.body);
        assert!(registry.tenant_store("worker-alpha", "owned").is_some());
        assert!(registry.tenant_store("demo-app", "owned").is_none());
        // Without a body tenant: served from the key's project, not the default one.
        let r = sign_up(
            "alpha-key",
            json!({"email": format!("b{n}@example.com"), "password": "hunter22"}),
        );
        assert_eq!(r.status, 200, "{malformed}: {}", r.body);
        assert_eq!(
            r.body["localId"].as_str().map(|id| registry
                .store_for("worker-alpha")
                .is_some_and(|store| store.lock().unwrap().user_count() == 1)
                && id.len() > 3),
            Some(true)
        );
        // An unknown key: refused, and the body's tenant is made in no project.
        let r = sign_up(
            "unknown-key",
            json!({"email": "c@example.com", "password": "hunter22", "tenantId": "stray"}),
        );
        assert_eq!(r.status, 400, "{malformed}: {}", r.body);
        assert_eq!(
            r.body["error"]["details"][0]["reason"], "API_KEY_INVALID",
            "{malformed}: {}",
            r.body
        );
        no_tenant(
            &registry,
            &["demo-app", "worker-alpha"],
            &["stray"],
            "unknown key",
        );
    }
}

/// The emulator profile with a second project, `worker-alpha`, that owns `alpha-key`.
fn alpha_state() -> (AuthState, Arc<AuthRegistry>) {
    let (mut state, registry) = emulator();
    let alpha = AuthStore::new("worker-alpha", SplitMix64::new(11), TotpPolicy::default());
    assert!(registry.register_session("worker-alpha", alpha));
    let mut tenancy = Tenancy::new("demo-app");
    tenancy
        .register("worker-alpha", &[], &["alpha-key".to_owned()])
        .unwrap();
    state.tenancy = Some(Arc::new(RwLock::new(tenancy)));
    (state, registry)
}

/// A query that does not parse (a repeated, empty, bare or percent-malformed key, or a malformed
/// tenant on a route that reads it) makes nothing: the request is refused by the store selection,
/// which reads the query the same way, and no tenant is made for it in the default project or in
/// the key's. The official emulator answers 403 for a repeated, empty or bare key and makes
/// nothing, and reads `key=%ZZ` literally (200); fireemu refuses that one too, a recorded
/// divergence (`emulator-malformed-api-key-is-refused-where-the-official-emulator-ignores-it`).
#[test]
fn a_query_that_does_not_parse_makes_no_tenant() {
    let (state, registry) = alpha_state();
    for (n, query) in [
        "key=alpha-key&key=alpha-key",
        "key=",
        "key",
        "key=%ZZ",
        "key=unknown-key&key=unknown-key",
        "key=alpha-key&apiKey=alpha-key",
    ]
    .into_iter()
    .enumerate()
    {
        let tenant = format!("stray-{n}");
        let r = handle(
            &state,
            "POST",
            &format!("/identitytoolkit.googleapis.com/v1/accounts:signUp?{query}"),
            &json!({"email": "a@example.com", "password": "hunter22", "tenantId": tenant}),
        );
        assert_eq!(r.status, 400, "{query}: {}", r.body);
        no_tenant(&registry, &["demo-app", "worker-alpha"], &[&tenant], query);
    }
    // The routes that keep reading the query tenant: a malformed tenant beside a body tenant, an
    // unknown key or the project's own.
    for (n, route) in ["passwordPolicy", "recaptchaConfig"]
        .into_iter()
        .enumerate()
    {
        for (m, query) in [
            "key=unknown-key&tenantId=a&tenantId=b",
            "key=alpha-key&tenantId=",
        ]
        .into_iter()
        .enumerate()
        {
            let tenant = format!("keep-{n}-{m}");
            let r = handle_with(
                &state,
                "GET",
                &format!("/identitytoolkit.googleapis.com/v2/{route}?{query}"),
                &owner(),
                &json!({"tenantId": tenant}),
            );
            assert_eq!(r.status, 400, "{route}?{query}: {}", r.body);
            no_tenant(
                &registry,
                &["demo-app", "worker-alpha"],
                &[&tenant],
                &format!("{route}?{query}"),
            );
        }
    }
}

/// An ID token of a deleted tenant of the key's project, with a malformed query tenant on a route
/// that ignores it, finds no user: the key still names its project, so the token's audience is the
/// request's project and the tenant that no longer exists is looked for there.
#[test]
fn a_deleted_tenants_token_beside_a_malformed_query_tenant_finds_no_user_in_the_keys_project() {
    let (state, registry) = alpha_state();
    let up = handle(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=alpha-key",
        &json!({"email": "g@example.com", "password": "hunter22", "tenantId": "gone"}),
    );
    assert_eq!(up.status, 200, "{}", up.body);
    for (route, body) in [
        (
            "accounts:sendOobCode",
            json!({"requestType": "VERIFY_EMAIL"}),
        ),
        ("accounts:update", json!({"displayName": "x"})),
        ("accounts:lookup", json!({})),
        ("accounts:delete", json!({})),
    ] {
        assert!(registry.delete_tenant("worker-alpha", "gone"));
        let mut body = body;
        body["idToken"] = up.body["idToken"].clone();
        let r = handle(
            &state,
            "POST",
            &format!("{V1}/{route}?key=alpha-key&tenantId=a&tenantId=b"),
            &body,
        );
        assert_eq!(r.status, 400, "{route}: {}", r.body);
        assert_eq!(
            r.body["error"]["message"], "USER_NOT_FOUND",
            "{route}: {}",
            r.body
        );
    }
}

/// The refresh token is the fourth place a target tenant comes from, and it is decoded before the
/// tenant is looked up (`server.js` `toExegesisOperation`).
#[test]
fn the_tenant_of_a_refresh_token_is_read_and_checked_before_a_tenant_is_made() {
    let (state, registry) = emulator();
    let sign_up = |tenant: &str| {
        let (status, created) = client(
            &state,
            &format!("{V1}/accounts:signUp"),
            &json!({"email": "a@example.com", "password": "hunter22", "tenantId": tenant}),
        );
        assert_eq!(status, 200, "{created}");
        created["refreshToken"].as_str().unwrap().to_owned()
    };
    let refresh = |body: Value| {
        let mut body = body;
        body["grant_type"] = json!("refresh_token");
        let r = handle(&state, "POST", &format!("{SECURE_TOKEN}?key={KEY}"), &body);
        (
            r.status,
            r.body["error"]["message"].as_str().unwrap_or("").to_owned(),
        )
    };
    let token_a = sign_up("tenant-a");
    // A body tenant with a refresh token that does not decode: INVALID_REFRESH_TOKEN, nothing made.
    let (status, message) = refresh(json!({"refresh_token": "garbage", "tenantId": "tenant-b"}));
    assert_eq!((status, message.as_str()), (400, "INVALID_REFRESH_TOKEN"));
    no_tenant(&registry, &["demo-app"], &["tenant-b"], "undecodable token");
    // A token of tenant A with a body tenant B that does not exist: a mismatch, nothing made.
    let (status, message) = refresh(json!({"refresh_token": token_a, "tenantId": "tenant-b"}));
    assert_eq!(status, 400);
    assert_eq!(
        message,
        "TENANT_ID_MISMATCH: ((Refresh token tenant ID does not match target tenant ID.))"
    );
    no_tenant(&registry, &["demo-app"], &["tenant-b"], "mismatched token");
    // The token's own tenant, deleted, is the target when nothing else names one: it is made, and
    // the token is not one of its sessions.
    assert!(registry.delete_tenant("demo-app", "tenant-a"));
    let (status, message) = refresh(json!({"refresh_token": token_a}));
    assert_eq!((status, message.as_str()), (400, "INVALID_REFRESH_TOKEN"));
    assert!(registry.tenant_store("demo-app", "tenant-a").is_some());
}

/// The action link reads its tenant from the query, and makes it; without the parameters the
/// official handler refuses first, and makes nothing.
#[test]
fn an_action_link_naming_a_tenant_makes_it() {
    let (state, registry) = emulator();
    let link = |query: &str| {
        handle_with(
            &state,
            "GET",
            &format!("/emulator/action?{query}"),
            &owner(),
            &json!({}),
        )
    };
    let _ = link("mode=verifyEmail&oobCode=nope&tenantId=t-link");
    assert!(registry.tenant_store("demo-app", "t-link").is_none());
    let _ = link(&format!(
        "mode=verifyEmail&oobCode=nope&apiKey={KEY}&tenantId=t-link"
    ));
    assert!(registry.tenant_store("demo-app", "t-link").is_some());
    let _ = link(&format!("mode=verifyEmail&apiKey={KEY}&tenantId=t-no-code"));
    let _ = link("mode=verifyEmail&oobCode=nope&apiKey=&tenantId=t-empty-key");
    assert!(registry.tenant_store("demo-app", "t-empty-key").is_none());
    let _ = link(&format!(
        "mode=verifyEmail&oobCode=&apiKey={KEY}&tenantId=t-empty-code"
    ));
    assert!(registry.tenant_store("demo-app", "t-empty-code").is_none());
    assert!(registry.tenant_store("demo-app", "t-no-code").is_none());
}

/// The tenant IdP-config routes are stubs in the official emulator (`501`, no tenant), so a
/// missing tenant is refused as before and not made.
#[test]
fn the_tenant_idp_config_routes_make_no_tenant() {
    let (state, registry) = emulator();
    for collection in [
        "oauthIdpConfigs",
        "inboundSamlConfigs",
        "defaultSupportedIdpConfigs",
    ] {
        let (status, refused) = admin(
            &state,
            "GET",
            &format!("{V2}/projects/demo-app/tenants/no-idp/{collection}"),
            &json!({}),
        );
        assert_eq!(status, 404, "{collection}: {refused}");
    }
    no_tenant(&registry, &["demo-app"], &["no-idp"], "idp configs");
}

/// A number in the string-typed `tenantId` is read as its string (the official body validation
/// converts it), so the tenant `"7"` is made and the request runs in it.
#[test]
fn a_numeric_tenant_id_names_its_string() {
    let (state, registry) = emulator();
    let (status, created) = client(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "a@example.com", "password": "hunter22", "tenantId": 7}),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(
        claims(created["idToken"].as_str().unwrap())["firebase"]["tenant"],
        "7"
    );
    assert!(registry.tenant_store("demo-app", "7").is_some());
    assert_eq!(tenant_names(&state, "demo-app"), ["7"]);
}

/// A tenant name with a slash is a divergence: the official emulator makes it, and Fireemu keeps
/// a tenant id out of a resource path's separators. It is refused as an unknown tenant, `TENANT_NOT_FOUND`.
#[test]
fn a_tenant_name_with_a_slash_makes_no_tenant() {
    let (state, registry) = emulator();
    for name in ["a/b", "a\\b"] {
        let (status, refused) = client(
            &state,
            &format!("{V1}/accounts:lookup"),
            &json!({"tenantId": name, "idToken": "x"}),
        );
        assert_eq!(status, 404, "{name}: {refused}");
        assert_eq!(refused["error"]["message"], "TENANT_NOT_FOUND", "{name}");
        no_tenant(&registry, &["demo-app"], &[name], name);
    }
    assert_eq!(tenant_names(&state, "demo-app"), Vec::<String>::new());
}

/// `tenants:create` makes the tenant it creates and no tenant its body names (the official
/// emulator makes the named one and then refuses).
#[test]
fn tenants_create_makes_no_tenant_the_body_names() {
    let (state, registry) = emulator();
    let (status, created) = admin(
        &state,
        "POST",
        &format!("{V2}/projects/demo-app/tenants"),
        &json!({"displayName": "explicit", "tenantId": "named-in-body"}),
    );
    // Fireemu's own answer to a body tenant on the create route, unchanged.
    assert_eq!(status, 400, "{created}");
    assert!(registry.tenant_store("demo-app", "named-in-body").is_none());
    assert!(tenant_names(&state, "demo-app").is_empty());
}

/// An ID token this daemon cannot verify (another algorithm, another key, a production token) is
/// read as the official emulator reads it, without verification, for the agreement with the named
/// tenant only: it is never the target, and a disagreement makes nothing.
#[test]
fn an_unverifiable_id_tokens_tenant_has_to_agree_with_the_named_tenant() {
    use fireemu_core_auth::jwt::base64url_encode;
    let (state, registry) = emulator();
    let token = |claims: &Value| {
        format!(
            "{}.{}.{}",
            base64url_encode(br#"{"alg":"RS256","kid":"other","typ":"JWT"}"#),
            base64url_encode(claims.to_string().as_bytes()),
            base64url_encode(b"signature")
        )
    };
    let with_tenant = token(&json!({"aud": "demo-app", "firebase": {"tenant": "t-x"}}));
    let (status, refused) = client(
        &state,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": with_tenant, "tenantId": "t-y"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_ID_MISMATCH");
    // Alone it is no target either, and agreeing it changes nothing about who is made.
    let _ = client(
        &state,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": with_tenant}),
    );
    assert!(registry.tenant_store("demo-app", "t-x").is_none());
    let _ = client(
        &state,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": with_tenant, "tenantId": "t-x"}),
    );
    assert!(registry.tenant_store("demo-app", "t-x").is_some());
    // A token with no tenant claim names none.
    let without = token(&json!({"aud": "demo-app"}));
    let _ = client(
        &state,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": without, "tenantId": "t-z"}),
    );
    assert!(registry.tenant_store("demo-app", "t-z").is_some());
}

#[test]
fn an_empty_or_unreadable_token_tenant_names_no_tenant() {
    use fireemu_core_auth::jwt::base64url_encode;
    let (state, registry) = emulator();
    let token = |claims: &Value| {
        format!(
            "{}.{}.{}",
            base64url_encode(br#"{"alg":"RS256","kid":"other","typ":"JWT"}"#),
            base64url_encode(claims.to_string().as_bytes()),
            base64url_encode(b"signature")
        )
    };
    // An empty tenant claim is no tenant, as it is falsy in the official emulator's check: the
    // body tenant is made on a route that does not parse the token.
    let empty = token(&json!({"aud": "demo-app", "firebase": {"tenant": ""}}));
    let (status, answered) = client(
        &state,
        &format!("{V1}/accounts:createAuthUri"),
        &json!({"identifier": "x@example.com", "continueUri": "http://localhost", "tenantId": "t-e", "idToken": empty}),
    );
    assert_ne!(
        answered["error"]["message"], "TENANT_ID_MISMATCH",
        "{status} {answered}"
    );
    assert!(registry.tenant_store("demo-app", "t-e").is_some());
    // The same for a token this daemon verifies (unsigned, in a daemon without a signer).
    let verified_empty = format!(
        "{}.{}.",
        base64url_encode(br#"{"alg":"none","typ":"JWT"}"#),
        base64url_encode(
            json!({"aud": "demo-app", "firebase": {"tenant": ""}})
                .to_string()
                .as_bytes()
        )
    );
    let (status, answered) = client(
        &state,
        &format!("{V1}/accounts:createAuthUri"),
        &json!({"identifier": "x@example.com", "continueUri": "http://localhost", "tenantId": "t-v", "idToken": verified_empty}),
    );
    assert_ne!(
        answered["error"]["message"], "TENANT_ID_MISMATCH",
        "{status} {answered}"
    );
    assert!(registry.tenant_store("demo-app", "t-v").is_some());
    // A signature segment outside base64url makes the official decoder read nothing, so the
    // token's tenant does not take part in the agreement.
    for (n, signature) in ["c2ln!", "c2ln+/==", "a b"].into_iter().enumerate() {
        let bad = format!(
            "{}.{}.{signature}",
            base64url_encode(br#"{"alg":"RS256","kid":"other","typ":"JWT"}"#),
            base64url_encode(
                json!({"aud": "demo-app", "firebase": {"tenant": "t-x"}})
                    .to_string()
                    .as_bytes()
            )
        );
        let name = format!("t-sig{n}");
        let (status, answered) = client(
            &state,
            &format!("{V1}/accounts:createAuthUri"),
            &json!({"identifier": "x@example.com", "continueUri": "http://localhost", "tenantId": name, "idToken": bad}),
        );
        assert_ne!(
            answered["error"]["message"], "TENANT_ID_MISMATCH",
            "{signature}: {status} {answered}"
        );
        assert!(
            registry.tenant_store("demo-app", &name).is_some(),
            "{signature}"
        );
    }
    // A tenant claim that is not a string is a recorded divergence: the official emulator asserts
    // it against the body's tenant, and here it names none.
    let number = token(&json!({"aud": "demo-app", "firebase": {"tenant": 5}}));
    let _ = client(
        &state,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": number, "tenantId": "t-n"}),
    );
    assert!(registry.tenant_store("demo-app", "t-n").is_some());
    // A token that is no JWT at all is not read.
    let _ = client(
        &state,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": "not.a.token", "tenantId": "t-w"}),
    );
    assert!(registry.tenant_store("demo-app", "t-w").is_some());
}

/// A keyed request for a project other than the default: an ID token naming a tenant that was
/// deleted finds no user, and the tenant is made again in that project, never in the default one.
#[test]
fn a_deleted_tenants_token_of_a_non_default_project_makes_the_tenant_in_that_project() {
    let (mut state, registry) = emulator();
    let alpha = AuthStore::new("worker-alpha", SplitMix64::new(11), TotpPolicy::default());
    assert!(registry.register_session("worker-alpha", alpha));
    let mut tenancy = Tenancy::new("demo-app");
    tenancy
        .register("worker-alpha", &[], &["alpha-key".to_owned()])
        .unwrap();
    state.tenancy = Some(Arc::new(RwLock::new(tenancy)));
    let sign_up = handle(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=alpha-key",
        &json!({"email": "a@example.com", "password": "hunter22", "tenantId": "gone"}),
    );
    assert_eq!(sign_up.status, 200, "{}", sign_up.body);
    assert!(registry.delete_tenant("worker-alpha", "gone"));
    no_tenant(
        &registry,
        &["worker-alpha", "demo-app"],
        &["gone"],
        "after the delete",
    );
    let lookup = handle(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v1/accounts:lookup?key=alpha-key",
        &json!({"idToken": sign_up.body["idToken"]}),
    );
    assert_eq!(lookup.status, 400, "{}", lookup.body);
    assert_eq!(lookup.body["error"]["message"], "USER_NOT_FOUND");
    assert!(registry.tenant_store("worker-alpha", "gone").is_some());
    assert!(registry.tenant_store("demo-app", "gone").is_none());
}
