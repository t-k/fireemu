//! Tenants in a compatibility-routed project (the emulator profile's namespace for a project id
//! the daemon was not told about): the official emulator creates a project and a tenant on demand
//! for any project id, so the emulator profile makes the routed project when a request writes a
//! tenant (creating one, or naming one that does not exist yet), never for a read alone, and never
//! for a request its guards refuse. The strict profile is unchanged.

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

fn routed_state() -> (AuthState, Arc<AuthRegistry>) {
    let (mut state, registry) = emulator();
    state.allow_routed_projects = true;
    (state, registry)
}

const ROUTED_TENANTS: &str = "/identitytoolkit.googleapis.com/v2/projects/demo-routed/tenants";

#[test]
fn creating_a_tenant_on_an_unknown_project_installs_the_project_and_makes_the_tenant() {
    let (state, registry) = routed_state();
    assert!(registry.routed_store_for("demo-routed").is_none());
    let (status, created) = admin(&state, "POST", ROUTED_TENANTS, &json!({"displayName": "x"}));
    assert_eq!(status, 200, "{created}");
    assert!(registry.routed_store_for("demo-routed").is_some());
    let id = created["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(registry.tenants("demo-routed"), [id.clone()]);
    let (status, listed) = admin(&state, "GET", ROUTED_TENANTS, &json!({}));
    assert_eq!(status, 200, "{listed}");
    assert_eq!(
        listed["tenants"].as_array().map(Vec::len),
        Some(1),
        "{listed}"
    );
    let (status, read) = admin(&state, "GET", &format!("{ROUTED_TENANTS}/{id}"), &json!({}));
    assert_eq!(status, 200, "{read}");
    assert_eq!(read["displayName"], "x");
    // Nothing reached the default project.
    assert!(registry.tenants("demo-app").is_empty());
}

#[test]
fn naming_a_tenant_on_an_unknown_project_makes_both_as_the_official_emulator_does() {
    let (state, registry) = routed_state();
    for (n, (method, path, body)) in [
        ("GET", format!("{ROUTED_TENANTS}/one"), json!({})),
        (
            "POST",
            format!("{V1}/projects/demo-routed/tenants/two/accounts"),
            json!({"email": "a@example.com", "password": "hunter22"}),
        ),
        ("DELETE", format!("{ROUTED_TENANTS}/three"), json!({})),
    ]
    .into_iter()
    .enumerate()
    {
        let (status, answer) = admin(&state, method, &path, &body);
        assert_eq!(status, 200, "{n} {method} {path}: {answer}");
    }
    assert!(registry.routed_store_for("demo-routed").is_some());
    let mut made = registry.tenants("demo-routed");
    made.sort();
    // (the delete removes what its request made, as for the default project)
    assert_eq!(made, ["one", "two"]);
    let store = registry.tenant_store("demo-routed", "two").unwrap();
    assert_eq!(store.lock().unwrap().project_id(), "demo-routed");
    assert!(registry.tenants("demo-app").is_empty());
}

#[test]
fn a_read_of_an_unknown_project_leaves_nothing_behind() {
    let (state, registry) = routed_state();
    let (status, listed) = admin(&state, "GET", ROUTED_TENANTS, &json!({}));
    assert_eq!((status, listed), (200, json!({})));
    assert!(registry.routed_store_for("demo-routed").is_none());
}

#[test]
fn a_refused_request_installs_no_project() {
    let (mut state, registry) = routed_state();
    state.control_token = Some("control-token".to_owned());
    let garbage = RequestHeaders {
        authorization: Some("Bearer garbage".to_owned()),
        ..owner()
    };
    for (method, path) in [
        ("POST", ROUTED_TENANTS.to_owned()),
        ("GET", format!("{ROUTED_TENANTS}/named")),
        (
            "POST",
            format!("{V1}/projects/demo-routed/tenants/named/accounts"),
        ),
    ] {
        let r = handle_with(
            &state,
            method,
            &path,
            &garbage,
            &json!({"displayName": "x"}),
        );
        assert_eq!(r.status, 401, "{method} {path}: {}", r.body);
    }
    // A local page without the control token, on an emulator route.
    let browser = RequestHeaders {
        origin: Some("http://localhost:3000".to_owned()),
        authorization: None,
        ..owner()
    };
    let r = handle_with(
        &state,
        "GET",
        "/emulator/v1/projects/demo-routed/tenants/named/oobCodes",
        &browser,
        &json!({}),
    );
    assert_eq!(r.status, 403, "{}", r.body);
    // A project id that is no project id.
    let (status, refused) = admin(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v2/projects/Bad_Project/tenants",
        &json!({"displayName": "x"}),
    );
    assert_eq!(status, 400, "{refused}");
    assert!(registry.routed_store_for("demo-routed").is_none());
    assert!(registry.routed_store_for("Bad_Project").is_none());
    assert!(registry.tenants("demo-routed").is_empty());
}

#[test]
fn two_routed_projects_do_not_share_a_tenant_id() {
    let (state, registry) = routed_state();
    for project in ["demo-routed", "demo-second"] {
        let (status, made) = admin(
            &state,
            "GET",
            &format!("/identitytoolkit.googleapis.com/v2/projects/{project}/tenants/shared"),
            &json!({}),
        );
        assert_eq!(status, 200, "{project}: {made}");
    }
    let one = registry.tenant_store("demo-routed", "shared").unwrap();
    let two = registry.tenant_store("demo-second", "shared").unwrap();
    assert!(!Arc::ptr_eq(&one, &two));
    assert_eq!(one.lock().unwrap().project_id(), "demo-routed");
    assert_eq!(two.lock().unwrap().project_id(), "demo-second");
}

#[test]
fn the_strict_profile_still_serves_no_project_it_was_not_told_about() {
    let (mut state, registry) = profiles()
        .into_iter()
        .nth(1)
        .map(|(_, s, r)| (s, r))
        .unwrap();
    state.allow_routed_projects = false;
    let (status, refused) = admin(&state, "POST", ROUTED_TENANTS, &json!({"displayName": "x"}));
    assert_eq!(status, 400, "{refused}");
    let (status, refused) = admin(
        &state,
        "GET",
        &format!("{ROUTED_TENANTS}/named"),
        &json!({}),
    );
    assert!(status >= 400, "{refused}");
    assert!(registry.routed_store_for("demo-routed").is_none());
    assert!(registry.tenants("demo-routed").is_empty());
}

fn declared() -> Vec<Value> {
    vec![
        json!({
            "tenantId": "acme-x7k2q",
            "displayName": "acme",
            "allowPasswordSignup": true,
            "mfaConfig": {"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}
        }),
        json!({"tenantId": "beta-a1b2c", "displayName": "beta"}),
    ]
}

/// The declaration (the configuration file's tenants) is what a routed project starts with, and
/// the tenant the installing request made on the way is kept beside it.
#[test]
fn a_routed_project_is_seeded_with_the_declared_tenants_when_a_request_installs_it() {
    use fireemu_adapter_http::identity_toolkit::{prepare_tenant_seeds, TenantSeeding};
    let (state, registry) = routed_state();
    let seeds = prepare_tenant_seeds(&declared(), true, None).unwrap();
    registry.set_new_project_tenant_seed(Arc::new(TenantSeeding::new(Some(true), seeds)));
    // A read installs nothing, so nothing is seeded.
    let (status, listed) = admin(&state, "GET", ROUTED_TENANTS, &json!({}));
    assert_eq!((status, listed), (200, json!({})));
    assert!(registry.tenants("demo-routed").is_empty());
    // A tenant the request names installs the project, and the declaration comes with it.
    let (status, made) = admin(
        &state,
        "GET",
        &format!("{ROUTED_TENANTS}/on-the-way"),
        &json!({}),
    );
    assert_eq!(status, 200, "{made}");
    let mut tenants = registry.tenants("demo-routed");
    tenants.sort();
    assert_eq!(tenants, ["acme-x7k2q", "beta-a1b2c", "on-the-way"]);
    // The declared tenant has its declared settings, not the on-the-way defaults.
    let (status, acme) = admin(
        &state,
        "GET",
        &format!("{ROUTED_TENANTS}/acme-x7k2q"),
        &json!({}),
    );
    assert_eq!(status, 200, "{acme}");
    assert_eq!(acme["allowPasswordSignup"], true, "{acme}");
    let (_, beta) = admin(
        &state,
        "GET",
        &format!("{ROUTED_TENANTS}/beta-a1b2c"),
        &json!({}),
    );
    assert!(beta.get("allowPasswordSignup").is_none(), "{beta}");
    // The switch is the declared one, and the default project is not touched.
    let store = registry.routed_store_for("demo-routed").unwrap();
    assert!(store.lock().unwrap().allows_tenants());
    assert!(registry.tenants("demo-app").is_empty());
    // The next project is seeded on its own; a request to the installed one seeds nothing again.
    let (status, created) = admin(
        &state,
        "POST",
        "/identitytoolkit.googleapis.com/v2/projects/demo-second/tenants",
        &json!({"displayName": "second"}),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(registry.tenants("demo-second").len(), 3);
    let (status, _) = admin(
        &state,
        "GET",
        &format!("{ROUTED_TENANTS}/again"),
        &json!({}),
    );
    assert_eq!(status, 200);
    assert_eq!(registry.tenants("demo-routed").len(), 4);
}

/// A declaration that names a tenant the installing request creates itself is not an error: the
/// installing request's own tenant is kept and the declared one is not made twice.
#[test]
fn a_request_naming_a_declared_tenant_first_keeps_one_tenant_of_that_id() {
    use fireemu_adapter_http::identity_toolkit::{prepare_tenant_seeds, TenantSeeding};
    let (state, registry) = routed_state();
    let seeds = prepare_tenant_seeds(&declared(), true, None).unwrap();
    registry.set_new_project_tenant_seed(Arc::new(TenantSeeding::new(None, seeds)));
    let (status, made) = admin(
        &state,
        "GET",
        &format!("{ROUTED_TENANTS}/acme-x7k2q"),
        &json!({}),
    );
    assert_eq!(status, 200, "{made}");
    let mut tenants = registry.tenants("demo-routed");
    tenants.sort();
    assert_eq!(tenants, ["acme-x7k2q", "beta-a1b2c"]);
}

/// Requests that install the same new project at once, through the real gate flow: the project is
/// installed once, the declaration is applied once, every request is served and nothing deadlocks.
#[test]
fn concurrent_requests_naming_a_new_project_install_and_seed_it_once() {
    use fireemu_adapter_http::identity_toolkit::{prepare_tenant_seeds, TenantSeeding};
    let (state, registry) = routed_state();
    let seeds = prepare_tenant_seeds(&declared(), true, None).unwrap();
    registry.set_new_project_tenant_seed(Arc::new(TenantSeeding::new(Some(true), seeds)));
    let state = Arc::new(state);
    let (done, finished) = std::sync::mpsc::channel();
    for n in 0..8 {
        let (state, done) = (state.clone(), done.clone());
        std::thread::spawn(move || {
            let r = handle_with(
                &state,
                "GET",
                &format!("{ROUTED_TENANTS}/racer-{n}"),
                &owner(),
                &json!({}),
            );
            let _ = done.send((r.status, r.body));
        });
    }
    for _ in 0..8 {
        let (status, body) = finished
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("every request finished: nothing deadlocked");
        assert_eq!(status, 200, "{body}");
    }
    let mut tenants = registry.tenants("demo-routed");
    tenants.sort();
    let mut expected = vec!["acme-x7k2q".to_owned(), "beta-a1b2c".to_owned()];
    expected.extend((0..8).map(|n| format!("racer-{n}")));
    expected.sort();
    assert_eq!(tenants, expected);
}
