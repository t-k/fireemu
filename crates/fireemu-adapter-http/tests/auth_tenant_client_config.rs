//! The authorized domains the client project configuration (`GET v1/projects`) reports for a
//! tenant-scoped request.
//!
//! Authorized domains belong to the project `Config`, and the JS SDK feeds this list to its
//! origin check (`_validateOrigin`). Production's `GetProjectConfigRequest` has no tenant field
//! and the SDK sends none for a tenant client (`_getProjectConfig` does not add the tenant id),
//! so the answer is the project's. A strict request that still names a tenant (the query
//! `tenantId`, the only form that can reach this route) must therefore report the parent
//! project's live list, the one tenant action links are checked against, never the tenant
//! store's own list (which holds only the project defaults) and never a copy. The emulator
//! profile ignores the query tenant on this route, as the official emulator does (`getProjects`
//! reads no tenant), and keeps its `localhost` until domains are configured.
//!
//! Recorded: the project-scope answers (AUTH-CONFIG-SDK `projects`, `projects-with-domain`).
//! A `tenantId` query on this route is not recorded.

use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthQueryLimits, AuthState, ClientApiKeyPolicy, FakeCustomTokenExpiry,
    IdpContinuationPolicy, RequestHeaders,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;
use serde_json::{json, Value};

const V2: &str = "/identitytoolkit.googleapis.com/v2";
const KEY: &str = "fake-api-key";
const PROJECT: &str = "demo-app";
const TENANT: &str = "tenant-a";
const NUMBER: u64 = 123_456_789_012;

fn emulator_state() -> AuthState {
    AuthState {
        store: Arc::new(Mutex::new(AuthStore::new(
            PROJECT,
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
        allow_unsigned_custom_tokens: true,
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

fn project_config(project: &str) -> String {
    format!("/identitytoolkit.googleapis.com/admin/v2/projects/{project}/config")
}

fn enable_tenants(state: &AuthState, project: &str) {
    let (status, body) = admin(
        state,
        "PATCH",
        &format!(
            "{}?updateMask=multiTenant.allowTenants",
            project_config(project)
        ),
        &json!({"multiTenant": {"allowTenants": true}}),
    );
    assert_eq!(status, 200, "{project}: {body}");
}

/// A state of the named profile with `TENANT` registered under `PROJECT`, whose number is
/// `NUMBER`.
fn world(strict: bool) -> (AuthState, Arc<AuthRegistry>) {
    let mut state = if strict {
        strict_state()
    } else {
        emulator_state()
    };
    state.store.lock().unwrap().set_project_number(Some(NUMBER));
    let registry = Arc::new(AuthRegistry::new(PROJECT, state.store.clone()));
    registry.ensure_tenant(PROJECT, TENANT).unwrap();
    state.registry = Some(registry.clone());
    if strict {
        enable_tenants(&state, PROJECT);
    }
    (state, registry)
}

fn set_domains(state: &AuthState, project: &str, domains: &Value) {
    let (status, body) = admin(
        state,
        "PATCH",
        &format!("{}?updateMask=authorizedDomains", project_config(project)),
        &json!({"authorizedDomains": domains}),
    );
    assert_eq!(status, 200, "{project}: {body}");
}

/// How a client names the tenant on the configuration read.
#[derive(Clone, Copy, Debug)]
enum Selector {
    /// The SDK's request: `?key=` only.
    None,
    /// `?tenantId=` of an existing tenant.
    Query(&'static str),
}

fn client_config(state: &AuthState, selector: Selector) -> (u16, Value) {
    let path = match selector {
        Selector::None => format!("/identitytoolkit.googleapis.com/v1/projects?key={KEY}"),
        Selector::Query(tenant) => {
            format!("/identitytoolkit.googleapis.com/v1/projects?key={KEY}&tenantId={tenant}")
        }
    };
    let r = handle(state, "GET", &path, &Value::Null);
    (r.status, r.body)
}

fn domains_of(answer: &(u16, Value)) -> Value {
    assert_eq!(answer.0, 200, "{}", answer.1);
    answer.1["authorizedDomains"].clone()
}

fn defaults() -> Value {
    json!(["localhost", "demo-app.firebaseapp.com", "demo-app.web.app"])
}

/// PICT table `work+tenant-client-config` (profile x selector x list x timing x tenant's own
/// list). The expected list is the project's at the time of the read: the strict daemon
/// reports it for every selector; the emulator profile reports `localhost` until domains are
/// configured, whichever selector the request carries.
#[test]
fn tenant_client_config_follows_the_project_list_table() {
    let table: [(&str, &str, &str, &str, &str); 12] = [
        ("strict", "query_tenant", "custom", "initial", "default"),
        ("strict", "query_tenant", "custom", "after_patch", "wider"),
        ("strict", "query_tenant", "undeclared", "initial", "default"),
        ("strict", "query_tenant", "empty", "initial", "default"),
        ("strict", "none", "custom", "initial", "default"),
        (
            "emulator",
            "query_tenant",
            "undeclared",
            "initial",
            "default",
        ),
        (
            "emulator",
            "query_tenant",
            "custom",
            "after_patch",
            "default",
        ),
        ("emulator", "none", "undeclared", "after_patch", "wider"),
        ("emulator", "none", "empty", "after_patch", "wider"),
        (
            "strict",
            "query_tenant",
            "undeclared",
            "after_patch",
            "wider",
        ),
        ("strict", "query_tenant", "empty", "after_patch", "wider"),
        ("emulator", "query_tenant", "empty", "initial", "default"),
    ];
    for (profile, selector, list, timing, own) in table {
        let strict = profile == "strict";
        let (state, registry) = world(strict);
        let mut effective = match list {
            "undeclared" => None,
            "custom" => Some(vec!["app.test"]),
            "empty" => Some(vec![]),
            other => panic!("{other}"),
        };
        if let Some(list) = &effective {
            set_domains(&state, PROJECT, &json!(list));
        }
        if own == "wider" {
            registry
                .tenant_store(PROJECT, TENANT)
                .unwrap()
                .lock()
                .unwrap()
                .set_authorized_domains_seed(vec!["evil.test".to_owned(), "app.test".to_owned()])
                .unwrap();
        }
        if timing == "after_patch" {
            effective = Some(vec!["patched.test", "other.test"]);
            set_domains(&state, PROJECT, &json!(effective));
        }
        let selector = match selector {
            "none" => Selector::None,
            _ => Selector::Query(TENANT),
        };
        let expected = match (&effective, strict) {
            (Some(list), _) => json!(list),
            (None, true) => defaults(),
            (None, false) => json!(["localhost"]),
        };
        let answer = client_config(&state, selector);
        let context = format!("{profile} {selector:?} {list} {timing} {own}");
        assert_eq!(domains_of(&answer), expected, "{context}");
        // The configuration names the project by its number in every scope.
        assert_eq!(
            answer.1["projectId"],
            json!(NUMBER.to_string()),
            "{context}"
        );
        // The same read of the project scope agrees with the tenant-scoped one.
        assert_eq!(
            domains_of(&client_config(&state, Selector::None)),
            expected,
            "{context}: the project's own read"
        );
    }
}

/// A tenant cannot widen or shrink what the configuration reports: not through its store's
/// own list, and not through a tenant PATCH naming an authorizedDomains member.
#[test]
fn a_tenant_store_list_never_widens_the_client_config() {
    let (state, registry) = world(true);
    set_domains(&state, PROJECT, &json!(["project.test"]));
    registry
        .tenant_store(PROJECT, TENANT)
        .unwrap()
        .lock()
        .unwrap()
        .set_authorized_domains_seed(vec!["evil.test".to_owned()])
        .unwrap();
    assert_eq!(
        domains_of(&client_config(&state, Selector::Query(TENANT))),
        json!(["project.test"])
    );
    let (_status, _body) = admin(
        &state,
        "PATCH",
        &format!("{V2}/projects/{PROJECT}/tenants/{TENANT}?updateMask=authorizedDomains"),
        &json!({"authorizedDomains": ["evil.test"]}),
    );
    assert_eq!(
        domains_of(&client_config(&state, Selector::Query(TENANT))),
        json!(["project.test"])
    );
    // The project's update applies to the next tenant-scoped read at once, both ways.
    set_domains(&state, PROJECT, &json!([]));
    assert_eq!(
        domains_of(&client_config(&state, Selector::Query(TENANT))),
        json!([])
    );
    set_domains(&state, PROJECT, &json!(["next.test"]));
    assert_eq!(
        domains_of(&client_config(&state, Selector::Query(TENANT))),
        json!(["next.test"])
    );
}

/// A tenant deleted and made again reports the project's list at the time, not a stale one.
#[test]
fn client_config_survives_tenant_recreation() {
    let (state, _registry) = world(true);
    set_domains(&state, PROJECT, &json!(["first.test"]));
    assert_eq!(
        domains_of(&client_config(&state, Selector::Query(TENANT))),
        json!(["first.test"])
    );
    let (status, body) = admin(
        &state,
        "DELETE",
        &format!("{V2}/projects/{PROJECT}/tenants/{TENANT}"),
        &json!({}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, created) = admin(
        &state,
        "POST",
        &format!("{V2}/projects/{PROJECT}/tenants"),
        &json!({"displayName": "again"}),
    );
    assert_eq!(status, 200, "{created}");
    let again = created["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    set_domains(&state, PROJECT, &json!(["second.test"]));
    let path = format!("/identitytoolkit.googleapis.com/v1/projects?key={KEY}&tenantId={again}");
    let r = handle(&state, "GET", &path, &Value::Null);
    assert_eq!(
        domains_of(&(r.status, r.body)),
        json!(["second.test"]),
        "the recreated tenant"
    );
}

/// An unknown tenant keeps the refusal it has today (the route has no recorded tenant
/// reading): it never turns into the project's list or a tenant default list.
#[test]
fn an_unknown_query_tenant_keeps_its_refusal() {
    let (state, _registry) = world(true);
    set_domains(&state, PROJECT, &json!(["project.test"]));
    let r = handle(
        &state,
        "GET",
        &format!("/identitytoolkit.googleapis.com/v1/projects?key={KEY}&tenantId=nobody"),
        &Value::Null,
    );
    assert_eq!(
        (r.status, r.body["error"]["message"].as_str()),
        (404, Some("TENANT_NOT_FOUND")),
        "{}",
        r.body
    );
}

/// The Admin configuration read (which exposes the project's list) is not served for a tenant
/// path, so it cannot be reached with a tenant store.
#[test]
fn the_admin_config_read_cannot_reach_a_tenant_store() {
    let (state, _registry) = world(true);
    set_domains(&state, PROJECT, &json!(["project.test"]));
    let (status, body) = admin(
        &state,
        "GET",
        &format!(
            "/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/tenants/{TENANT}/config"
        ),
        &Value::Null,
    );
    assert_ne!(status, 200, "{body}");
    assert!(body.get("authorizedDomains").is_none(), "{body}");
}

const HOSTS: [&str; 5] = ["a.test", "b.test", "c.test", "localhost", "d.test"];

fn host_subset() -> impl Strategy<Value = Vec<&'static str>> {
    proptest::sample::subsequence(HOSTS.to_vec(), 0..=HOSTS.len())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// Whatever the project's lists and the tenant store's own list hold, a strict
    /// tenant-scoped read equals the project-scoped read of the same moment, and the emulator
    /// profile's equals its own project read.
    #[test]
    fn a_tenant_scoped_read_equals_the_project_read(
        parent in host_subset(),
        patched in host_subset(),
        tenant_own in host_subset(),
        patch_after in any::<bool>(),
    ) {
        for strict in [true, false] {
            let (state, registry) = world(strict);
            set_domains(&state, PROJECT, &json!(parent));
            registry
                .tenant_store(PROJECT, TENANT)
                .unwrap()
                .lock()
                .unwrap()
                .set_authorized_domains_seed(tenant_own.iter().map(|d| (*d).to_owned()).collect())
                .unwrap();
            let effective = if patch_after {
                set_domains(&state, PROJECT, &json!(patched));
                &patched
            } else {
                &parent
            };
            let tenant_scoped = client_config(&state, Selector::Query(TENANT));
            let project_scoped = client_config(&state, Selector::None);
            prop_assert_eq!(&tenant_scoped, &project_scoped);
            if strict {
                prop_assert_eq!(domains_of(&tenant_scoped), json!(effective));
            }
        }
    }
}
