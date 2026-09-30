//! Tenants in a compatibility-routed project (the emulator profile's namespace for a project id
//! the daemon was not told about): the official emulator creates a project and a tenant on demand
//! for any project id, so the emulator profile makes the routed project when a request writes a
//! tenant (creating one, or naming one that does not exist yet), never for a read alone, and never
//! for a request its guards refuse. The strict profile is unchanged.

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
    assert_eq!(registry.tenants("demo-routed"), std::slice::from_ref(&id));
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

/// A create the create route would refuse installs nothing: the project is made for a tenant, not
/// for a request.
#[test]
fn a_tenant_create_the_route_refuses_installs_no_project() {
    let (state, registry) = routed_state();
    let (status, refused) = admin(
        &state,
        "POST",
        ROUTED_TENANTS,
        &json!({"displayName": "x", "mfaConfig": {"state": "ON"}}),
    );
    assert_eq!(status, 400, "{refused}");
    assert!(registry.routed_store_for("demo-routed").is_none());
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

/// Runs `request` on its own thread and fails, rather than hangs, when it does not finish: a seed
/// applied under the routed project's gate would deadlock its installing request.
fn within_a_minute<T: Send + 'static>(request: impl FnOnce() -> T + Send + 'static) -> T {
    let (done, finished) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(request());
    });
    finished
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the request finished: nothing deadlocked")
}

fn declaration(documents: &[Value]) -> Arc<fireemu_adapter_http::identity_toolkit::TenantSeeding> {
    use fireemu_adapter_http::identity_toolkit::{prepare_tenant_seeds, TenantSeeding};
    Arc::new(TenantSeeding::new(
        Some(true),
        prepare_tenant_seeds(documents, true, None).unwrap(),
    ))
}

/// Every request that installs a routed project seeds it, and none of them does it under a gate:
/// `tenants:create`, an Admin user create, a provider create.
#[test]
fn every_installing_request_seeds_the_project_and_none_deadlocks() {
    let (state, registry) = routed_state();
    registry.set_new_project_tenant_seed(declaration(&declared()));
    let state = Arc::new(state);
    let call = |method: &'static str, path: String, body: Value| {
        let state = state.clone();
        within_a_minute(move || {
            let r = handle_with(&state, method, &path, &owner(), &body);
            (r.status, r.body)
        })
    };
    let (status, made) = call(
        "POST",
        "/identitytoolkit.googleapis.com/v2/projects/demo-tc/tenants".to_owned(),
        json!({"displayName": "x"}),
    );
    assert_eq!(status, 200, "{made}");
    let (status, made) = call(
        "POST",
        format!("{V1}/projects/demo-user/accounts"),
        json!({"email": "a@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{made}");
    for (project, extra) in [("demo-tc", 1), ("demo-user", 0)] {
        let mut tenants = registry.tenants(project);
        tenants.sort();
        assert_eq!(tenants.len(), 2 + extra, "{project}: {tenants:?}");
        assert!(tenants.contains(&"acme-x7k2q".to_owned()), "{project}");
        assert!(tenants.contains(&"beta-a1b2c".to_owned()), "{project}");
    }
}

/// The declared document is what a declared tenant reads back, whichever request installs the
/// project: also when that request is the one that names the tenant.
#[test]
fn a_declared_tenant_named_by_the_installing_request_keeps_its_declared_settings() {
    let declared = vec![json!({
        "tenantId": "acme-x7k2q",
        "displayName": "acme",
        "allowPasswordSignup": false,
        "enableEmailLinkSignin": false
    })];
    for (project, request) in [("demo-acc", "account create"), ("demo-get", "tenant read")] {
        let (state, registry) = routed_state();
        registry.set_new_project_tenant_seed(declaration(&declared));
        let (status, answered) = if request == "account create" {
            admin(
                &state,
                "POST",
                &format!("{V1}/projects/{project}/tenants/acme-x7k2q/accounts"),
                &json!({"email": "a@example.com", "password": "hunter22"}),
            )
        } else {
            admin(
                &state,
                "GET",
                &format!(
                    "/identitytoolkit.googleapis.com/v2/projects/{project}/tenants/acme-x7k2q"
                ),
                &json!({}),
            )
        };
        assert_eq!(status, 200, "{request}: {answered}");
        let (status, document) = admin(
            &state,
            "GET",
            &format!("/identitytoolkit.googleapis.com/v2/projects/{project}/tenants/acme-x7k2q"),
            &json!({}),
        );
        assert_eq!(status, 200, "{request}: {document}");
        assert_eq!(document["displayName"], "acme", "{request}: {document}");
        assert!(
            document.get("allowPasswordSignup").is_none(),
            "{request}: {document}"
        );
        assert!(
            document.get("enableEmailLinkSignin").is_none(),
            "{request}: {document}"
        );
        assert!(document.get("mfaConfig").is_none(), "{request}: {document}");
    }
}

/// A foreign ID token whose tenant disagrees with the path's, on a project only this request
/// names: `TENANT_ID_MISMATCH`, and nothing is installed.
#[test]
fn a_disagreeing_foreign_token_on_an_unknown_project_is_a_mismatch_that_installs_nothing() {
    use fireemu_core_auth::jwt::base64url_encode;
    let (state, registry) = routed_state();
    let token = format!(
        "{}.{}.{}",
        base64url_encode(br#"{"alg":"RS256","kid":"other","typ":"JWT"}"#),
        base64url_encode(
            json!({"aud": "demo-late", "firebase": {"tenant": "t-x"}})
                .to_string()
                .as_bytes()
        ),
        base64url_encode(b"signature")
    );
    let (status, refused) = admin(
        &state,
        "POST",
        &format!("{V1}/projects/demo-late/tenants/t-y/accounts:lookup"),
        &json!({"idToken": token}),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_ID_MISMATCH");
    assert!(registry.routed_store_for("demo-late").is_none());
    assert!(registry.tenants("demo-late").is_empty());
}

fn with_barrier(
    mut state: AuthState,
) -> (
    Arc<AuthState>,
    Arc<fireemu_core_session::barrier::AdmissionBarrier>,
) {
    let barrier = Arc::new(fireemu_core_session::barrier::AdmissionBarrier::default());
    state.barrier = Some(barrier.clone());
    (Arc::new(state), barrier)
}

fn keyless() -> RequestHeaders {
    RequestHeaders {
        authorization: None,
        ..owner()
    }
}

/// Sends `path` on its own thread, so the test can hold the barrier while it waits.
fn send_on_a_thread(
    state: &Arc<AuthState>,
    headers: RequestHeaders,
    path: &str,
) -> std::sync::mpsc::Receiver<(u16, Value)> {
    let (done, answer) = std::sync::mpsc::channel();
    let (state, path) = (state.clone(), path.to_owned());
    std::thread::spawn(move || {
        let r = handle_with(&state, "GET", &path, &headers, &json!({}));
        let _ = done.send((r.status, r.body));
    });
    answer
}

const SOON: std::time::Duration = std::time::Duration::from_millis(400);
const LONG: std::time::Duration = std::time::Duration::from_secs(60);

/// A request its guards refuse before admission answers at once even while a reset holds the
/// barrier exclusively, in both profiles, when it installed nothing (a request that installs
/// nothing takes no admission for a seed).
#[test]
fn a_refused_request_does_not_wait_for_a_reset_when_nothing_is_pending() {
    for (label, state, registry) in profiles() {
        registry.set_new_project_tenant_seed(declaration(&declared()));
        let (state, barrier) = with_barrier(state);
        let reset = barrier.exclusive();
        let answer = send_on_a_thread(
            &state,
            keyless(),
            &format!("{V2}/projects/demo-app/tenants"),
        );
        let (status, body) = answer
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("{label}: a refusal waited for the reset"));
        assert!(matches!(status, 401 | 403), "{label}: {status} {body}");
        drop(reset);
    }
}

/// A routed project that is installed and not yet seeded is seeded under admission: the next
/// request through the wrapper waits for a reset that holds the barrier, and seeds after it.
#[test]
fn a_pending_seed_is_applied_under_admission() {
    let (state, registry) = routed_state();
    registry.set_new_project_tenant_seed(declaration(&declared()));
    let (state, barrier) = with_barrier(state);
    let candidate = registry.routed_candidate("demo-pend").unwrap();
    assert!(matches!(
        registry.install_routed("demo-pend", Arc::new(Mutex::new(candidate))),
        fireemu_core_auth::store::RoutedStoreInstall::Installed(_)
    ));
    assert!(registry.has_pending_project_seeds());
    let reset = barrier.exclusive();
    let answer = send_on_a_thread(
        &state,
        keyless(),
        &format!("{V2}/projects/demo-app/tenants"),
    );
    assert!(
        answer.recv_timeout(SOON).is_err(),
        "the seed waited for the reset"
    );
    assert!(registry.tenants("demo-pend").is_empty());
    drop(reset);
    let (status, body) = answer.recv_timeout(LONG).unwrap();
    assert!(matches!(status, 401 | 403), "{status} {body}");
    assert_eq!(registry.tenants("demo-pend").len(), 2);
}

/// A request that names a tenant of a new project installs the project, seeds it and makes the
/// tenant in one admitted step: while a reset holds the barrier nothing is installed, so the
/// reset's membership probe stays valid, and after it the request makes all of it.
#[test]
fn an_on_the_way_install_is_admitted_as_one_step_and_survives_a_racing_reset() {
    let (state, registry) = routed_state();
    registry.set_new_project_tenant_seed(declaration(&declared()));
    let (state, barrier) = with_barrier(state);
    let reset = barrier.exclusive();
    let probe = registry.prepare_default_scope_reset().unwrap();
    let answer = send_on_a_thread(
        &state,
        owner(),
        &format!("{V2}/projects/demo-race/tenants/acme-x7k2q"),
    );
    assert!(
        answer.recv_timeout(SOON).is_err(),
        "the request went on under the reset"
    );
    assert!(registry.routed_store_for("demo-race").is_none());
    registry
        .apply_default_scope_reset(&probe)
        .expect("nothing was installed between the probe and the reset");
    drop(reset);
    let (status, body) = answer.recv_timeout(LONG).unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(registry.tenants("demo-race").len(), 2);
}

/// A seed that holds up the first project it is applied to until the test lets it go, or that
/// lets a test act while the seed is applied under its request's admission.
struct ProbedSeed {
    inner: Arc<fireemu_adapter_http::identity_toolkit::TenantSeeding>,
    /// Sent when the seed is entered for `hold_project`; the seed then waits for `release`.
    hold_project: &'static str,
    entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    /// Slows every application, so a concurrent drain lands inside the window.
    delay: std::time::Duration,
    /// Run once, on the first application, before the seed's own work.
    on_first: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl std::fmt::Debug for ProbedSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProbedSeed")
    }
}

impl ProbedSeed {
    fn new(documents: &[Value]) -> Self {
        Self {
            inner: declaration(documents),
            hold_project: "",
            entered: Mutex::new(None),
            release: Mutex::new(None),
            delay: std::time::Duration::ZERO,
            on_first: Mutex::new(None),
        }
    }
}

impl fireemu_core_auth::store::NewProjectSeed for ProbedSeed {
    fn apply(&self, registry: &AuthRegistry, project: &str) -> Result<(), String> {
        if let Some(first) = self.on_first.lock().unwrap().take() {
            first();
        }
        if project == self.hold_project {
            if let Some(entered) = self.entered.lock().unwrap().take() {
                let _ = entered.send(());
                if let Some(release) = self.release.lock().unwrap().take() {
                    let _ = release.recv_timeout(LONG);
                }
            }
        }
        std::thread::sleep(self.delay);
        fireemu_core_auth::store::NewProjectSeed::apply(&*self.inner, registry, project)
    }
}

fn display_name_of(registry: &AuthRegistry, project: &str, tenant: &str) -> Option<String> {
    registry
        .tenant_metadata(project, tenant)
        .and_then(|metadata| metadata.display_name)
}

/// A request naming a declared tenant while its project's seed is in flight (drained, not yet
/// applied) waits for that seed and finds the tenant as declared, instead of making it with the
/// on-the-way defaults that the seed would then keep.
#[test]
fn a_declared_tenant_named_while_the_projects_seed_is_in_flight_keeps_its_declaration() {
    let (state, registry) = routed_state();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let mut seed = ProbedSeed::new(&declared());
    seed.hold_project = "demo-gx";
    seed.entered = Mutex::new(Some(entered_tx));
    seed.release = Mutex::new(Some(release_rx));
    registry.set_new_project_tenant_seed(Arc::new(seed));
    let state = Arc::new(state);
    // The installing request: an Admin user create, whose wrapper drains the seed and is held.
    let installer = {
        let state = state.clone();
        std::thread::spawn(move || {
            handle_with(
                &state,
                "POST",
                &format!("{V1}/projects/demo-gx/accounts"),
                &owner(),
                &json!({"email": "a@example.com", "password": "hunter22"}),
            )
            .status
        })
    };
    entered_rx.recv_timeout(LONG).expect("the seed was entered");
    // Another request names the declared tenant meanwhile: it waits for the seed.
    let named = send_on_a_thread(
        &state,
        owner(),
        &format!("{V2}/projects/demo-gx/tenants/acme-x7k2q"),
    );
    assert!(
        named.recv_timeout(SOON).is_err(),
        "the request went on while the seed was in flight"
    );
    release_tx.send(()).unwrap();
    assert_eq!(installer.join().unwrap(), 200);
    let (status, body) = named.recv_timeout(LONG).unwrap();
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        display_name_of(&registry, "demo-gx", "acme-x7k2q").as_deref(),
        Some("acme")
    );
}

/// The same holds for the installing request itself when other requests drain the pending list
/// at the same time (a bounded stress: it lost the declaration in 4 of 400 before the drain was
/// serialized).
#[test]
fn an_installing_request_keeps_the_declaration_while_other_requests_drain_the_seeds() {
    let (state, registry) = routed_state();
    let mut seed = ProbedSeed::new(&declared());
    seed.delay = std::time::Duration::from_millis(2);
    registry.set_new_project_tenant_seed(Arc::new(seed));
    let state = Arc::new(state);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let drainer = {
        let (registry, stop) = (registry.clone(), stop.clone());
        std::thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = registry.apply_pending_project_seeds();
                std::thread::yield_now();
            }
        })
    };
    let mut lost = Vec::new();
    for n in 0..200 {
        let project = format!("demo-dr{n}");
        let answer = send_on_a_thread(
            &state,
            owner(),
            &format!("{V2}/projects/{project}/tenants/acme-x7k2q"),
        );
        let (status, body) = answer.recv_timeout(LONG).unwrap();
        assert_eq!(status, 200, "{project}: {body}");
        if display_name_of(&registry, &project, "acme-x7k2q").as_deref() != Some("acme") {
            lost.push(project);
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    drainer.join().unwrap();
    assert!(lost.is_empty(), "declared settings lost in {lost:?}");
}

/// The tenant an on-the-way request makes is made inside the same admission as the install and
/// the seed: a reset that starts waiting for the barrier while the seed runs cannot begin (and
/// probe the membership) until the request is done with all three.
#[test]
fn the_on_the_way_tenant_is_made_inside_the_admission_a_reset_waits_on() {
    let (state, registry) = routed_state();
    let (state, barrier) = with_barrier(state);
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let mut seed = ProbedSeed::new(&declared());
    seed.delay = std::time::Duration::from_millis(200);
    {
        let (registry, barrier) = (registry.clone(), barrier.clone());
        *seed.on_first.lock().unwrap() = Some(Box::new(move || {
            std::thread::spawn(move || {
                // A reset: it holds the barrier exclusively across probe and apply.
                let _reset = barrier.exclusive();
                let probe = registry.prepare_default_scope_reset().unwrap();
                std::thread::sleep(std::time::Duration::from_millis(400));
                let _ = result_tx.send(registry.apply_default_scope_reset(&probe));
            });
        }));
    }
    registry.set_new_project_tenant_seed(Arc::new(seed));
    let answer = send_on_a_thread(
        &state,
        owner(),
        &format!("{V2}/projects/demo-seam/tenants/named"),
    );
    // The request is admitted first; the reset queues behind it and runs once it is done.
    let (status, body) = answer.recv_timeout(LONG).unwrap();
    assert!(matches!(status, 200 | 404), "{status} {body}");
    let reset = result_rx.recv_timeout(LONG).unwrap();
    assert!(
        reset.is_ok(),
        "the reset's membership probe changed under it: {reset:?}"
    );
}
