//! The authorized domains that decide a tenant-scoped action link's `continueUrl`.
//!
//! Authorized domains belong to the project `Config`; a `Tenant` resource has no such field.
//! A strict tenant-scoped link therefore checks the host against the parent project's live
//! list, never against the tenant store's own list (which is only the project defaults) and
//! never against a copy made when the tenant was created. The emulator profile adds no
//! refusal, as the official Auth emulator checks no domain.
//!
//! The project-level refusal is recorded (AUTH-ACTION `link-unauthorized-continue-url`,
//! AUTH-CONFIG-SDK `reset-to-removed-domain`). A tenant-scoped `continueUrl` is not recorded;
//! the parent-list lookup follows the resource model and the coordinator's ruling in the
//! issue `tenant-action-links-use-tenant-store-domains`.

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

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";
const KEY: &str = "fake-api-key";
const PROJECT: &str = "demo-app";
const OTHER: &str = "other-app";
const TENANT: &str = "tenant-a";
const REFUSAL: &str = "UNAUTHORIZED_DOMAIN : Domain not allowlisted by project";

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

/// A state of the named profile with `TENANT` registered under `PROJECT`.
fn world(strict: bool) -> (AuthState, Arc<AuthRegistry>) {
    let mut state = if strict {
        strict_state()
    } else {
        emulator_state()
    };
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

fn project_domains(state: &AuthState, project: &str) -> Value {
    let (status, body) = admin(state, "GET", &project_config(project), &Value::Null);
    assert_eq!(status, 200, "{body}");
    body["authorizedDomains"].clone()
}

/// How a caller names the tenant: the Admin tenant path (a link generator) or the SDK shape
/// (API key in the query, tenant in the body).
#[derive(Clone, Copy, Debug)]
enum Route {
    AdminTenantPath,
    ClientBodyTenant,
}

const EMAIL: &str = "reset@example.com";

fn create_user(state: &AuthState, project: &str, tenant: &str) {
    let (status, body) = admin(
        state,
        "POST",
        &format!("{V1}/projects/{project}/tenants/{tenant}/accounts"),
        &json!({"email": EMAIL, "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{project}/{tenant}: {body}");
}

/// A password-reset link whose continue URL is `https://{host}/done`.
fn link(state: &AuthState, route: Route, project: &str, tenant: &str, host: &str) -> (u16, Value) {
    let url = format!("https://{host}/done");
    match route {
        Route::AdminTenantPath => admin(
            state,
            "POST",
            &format!("{V1}/projects/{project}/tenants/{tenant}/accounts:sendOobCode"),
            &json!({"requestType": "PASSWORD_RESET", "email": EMAIL, "continueUrl": url, "returnOobLink": true}),
        ),
        Route::ClientBodyTenant => {
            let r = handle(
                state,
                "POST",
                &format!("{V1}/accounts:sendOobCode?key={KEY}"),
                &json!({"requestType": "PASSWORD_RESET", "email": EMAIL, "continueUrl": url, "tenantId": tenant}),
            );
            (r.status, r.body)
        }
    }
}

/// The decision the strict profile must give: accepted when the host is in `domains`.
fn assert_decision(answer: &(u16, Value), accepted: bool, context: &str) {
    let (status, body) = answer;
    if accepted {
        assert_eq!(*status, 200, "{context}: {body}");
    } else {
        assert_eq!(
            (*status, body["error"]["message"].as_str()),
            (400, Some(REFUSAL)),
            "{context}"
        );
    }
}

fn listed(domains: &[&str], host: &str) -> bool {
    domains.iter().any(|d| d.eq_ignore_ascii_case(host))
}

const TABLE: [(&str, &str, &str, &str, &str); 12] = [
    ("strict", "admin_tenant", "custom", "custom_host", "initial"),
    (
        "strict",
        "admin_tenant",
        "custom",
        "default_host",
        "initial",
    ),
    (
        "strict",
        "client_body_tenant",
        "custom",
        "custom_host",
        "after_patch",
    ),
    (
        "strict",
        "admin_tenant",
        "undeclared",
        "default_host",
        "initial",
    ),
    ("strict", "admin_tenant", "empty", "default_host", "initial"),
    (
        "strict",
        "admin_tenant",
        "custom",
        "other_host",
        "after_patch",
    ),
    (
        "emulator",
        "admin_tenant",
        "custom",
        "other_host",
        "initial",
    ),
    (
        "emulator",
        "client_body_tenant",
        "empty",
        "default_host",
        "after_patch",
    ),
    (
        "strict",
        "client_body_tenant",
        "empty",
        "other_host",
        "initial",
    ),
    (
        "emulator",
        "client_body_tenant",
        "undeclared",
        "custom_host",
        "after_patch",
    ),
    (
        "strict",
        "client_body_tenant",
        "empty",
        "custom_host",
        "after_patch",
    ),
    (
        "strict",
        "admin_tenant",
        "undeclared",
        "other_host",
        "after_patch",
    ),
];

/// PICT table `work+tenant-action-domains` (profile x route x list x host x timing). The
/// list is set by an Admin PATCH after the tenant exists; `after_patch` replaces it again.
#[test]
fn tenant_link_follows_the_project_list_table() {
    let defaults = ["localhost", "demo-app.firebaseapp.com", "demo-app.web.app"];
    for (profile, route, list, host, timing) in TABLE {
        let strict = profile == "strict";
        let (state, _registry) = world(strict);
        create_user(&state, PROJECT, TENANT);
        let mut effective: Vec<&str> = match list {
            "undeclared" => defaults.to_vec(),
            "custom" => vec!["app.test"],
            "empty" => vec![],
            other => panic!("{other}"),
        };
        if list != "undeclared" {
            set_domains(&state, PROJECT, &json!(effective));
        }
        if timing == "after_patch" {
            effective = vec!["patched.test", "other.test"];
            set_domains(&state, PROJECT, &json!(effective));
        }
        let host = match host {
            "custom_host" => "app.test",
            "default_host" => "localhost",
            "other_host" => "other.test",
            other => panic!("{other}"),
        };
        let route = match route {
            "admin_tenant" => Route::AdminTenantPath,
            _ => Route::ClientBodyTenant,
        };
        let answer = link(&state, route, PROJECT, TENANT, host);
        let accepted = !strict || listed(&effective, host);
        assert_decision(
            &answer,
            accepted,
            &format!("{profile} {route:?} {list} {host} {timing}"),
        );
    }
}

/// A host spelled with other letter case is the same host, as at the project scope.
#[test]
fn a_tenant_link_matches_the_project_list_case_insensitively() {
    let (state, _registry) = world(true);
    create_user(&state, PROJECT, TENANT);
    set_domains(&state, PROJECT, &json!(["App.Test"]));
    for host in ["app.test", "APP.TEST", "App.Test"] {
        let answer = link(&state, Route::AdminTenantPath, PROJECT, TENANT, host);
        assert_decision(&answer, true, host);
    }
    let answer = link(&state, Route::AdminTenantPath, PROJECT, TENANT, "xapp.test");
    assert_decision(&answer, false, "a different host");
}

/// The report: a project-authorized host works for the tenant, the removed default does not,
/// and the next project update applies at once, in both directions, without recreating the
/// tenant.
#[test]
fn a_project_list_update_after_tenant_creation_applies_at_once() {
    for route in [Route::AdminTenantPath, Route::ClientBodyTenant] {
        let (state, _registry) = world(true);
        create_user(&state, PROJECT, TENANT);
        // The tenant exists before the list changes.
        set_domains(&state, PROJECT, &json!(["first.test"]));
        assert_decision(
            &link(&state, route, PROJECT, TENANT, "first.test"),
            true,
            "first",
        );
        assert_decision(
            &link(&state, route, PROJECT, TENANT, "localhost"),
            false,
            "removed default",
        );
        set_domains(&state, PROJECT, &json!(["second.test"]));
        assert_decision(
            &link(&state, route, PROJECT, TENANT, "first.test"),
            false,
            "first removed",
        );
        assert_decision(
            &link(&state, route, PROJECT, TENANT, "second.test"),
            true,
            "second",
        );
        set_domains(&state, PROJECT, &json!(["localhost"]));
        assert_decision(
            &link(&state, route, PROJECT, TENANT, "localhost"),
            true,
            "default back",
        );
        assert_decision(
            &link(&state, route, PROJECT, TENANT, "second.test"),
            false,
            "second removed",
        );
        // The project scope is unaffected by the tenant lookup.
        let project_link = admin(
            &state,
            "POST",
            &format!("{V1}/projects/{PROJECT}/accounts"),
            &json!({"email": EMAIL, "password": "hunter22"}),
        );
        assert_eq!(project_link.0, 200, "{}", project_link.1);
        let (status, body) = admin(
            &state,
            "POST",
            &format!("{V1}/projects/{PROJECT}/accounts:sendOobCode"),
            &json!({"requestType": "PASSWORD_RESET", "email": EMAIL, "continueUrl": "https://localhost/done", "returnOobLink": true}),
        );
        assert_eq!(status, 200, "{body}");
        // ... and the project scope still checks its own list.
        let (status, body) = admin(
            &state,
            "POST",
            &format!("{V1}/projects/{PROJECT}/accounts:sendOobCode"),
            &json!({"requestType": "PASSWORD_RESET", "email": EMAIL, "continueUrl": "https://second.test/done", "returnOobLink": true}),
        );
        assert_decision(&(status, body), false, "project scope, host removed");
    }
}

/// Two projects of one registry, each with a tenant of the same id, keep their own lists.
#[test]
fn two_projects_keep_their_tenant_decisions_apart() {
    let (state, registry) = world(true);
    assert!(registry.register(
        OTHER,
        AuthStore::new(OTHER, SplitMix64::new(9), TotpPolicy::default())
    ));
    registry.ensure_tenant(OTHER, TENANT).unwrap();
    enable_tenants(&state, OTHER);
    for project in [PROJECT, OTHER] {
        create_user(&state, project, TENANT);
    }
    set_domains(&state, PROJECT, &json!(["a.test"]));
    set_domains(&state, OTHER, &json!(["b.test"]));
    let route = Route::AdminTenantPath;
    assert_decision(
        &link(&state, route, PROJECT, TENANT, "a.test"),
        true,
        "A on a",
    );
    assert_decision(
        &link(&state, route, PROJECT, TENANT, "b.test"),
        false,
        "A on b",
    );
    assert_decision(
        &link(&state, route, OTHER, TENANT, "b.test"),
        true,
        "B on b",
    );
    assert_decision(
        &link(&state, route, OTHER, TENANT, "a.test"),
        false,
        "B on a",
    );
    // Changing one project leaves the other tenant's decisions alone.
    set_domains(&state, OTHER, &json!(["c.test"]));
    assert_decision(
        &link(&state, route, PROJECT, TENANT, "a.test"),
        true,
        "A after B update",
    );
    assert_decision(
        &link(&state, route, OTHER, TENANT, "b.test"),
        false,
        "B old",
    );
    assert_decision(&link(&state, route, OTHER, TENANT, "c.test"), true, "B new");
}

fn recreate_tenant(state: &AuthState, old: &str) -> String {
    let (status, body) = admin(
        state,
        "DELETE",
        &format!("{V2}/projects/{PROJECT}/tenants/{old}"),
        &json!({}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, created) = admin(
        state,
        "POST",
        &format!("{V2}/projects/{PROJECT}/tenants"),
        &json!({"displayName": "again"}),
    );
    assert_eq!(status, 200, "{created}");
    let tenant = created["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    create_user(state, PROJECT, &tenant);
    tenant
}

/// A declared seed, an explicitly empty seed and an undeclared list keep their existing
/// project reset semantics, and the tenant (recreated or not) follows whatever the project
/// list is at the time.
#[test]
fn seed_empty_and_undeclared_lists_survive_tenant_recreation_and_reset() {
    // (seed, live list after a PATCH, restored list, whether the restore reports a seed)
    type Case = (
        Option<Vec<&'static str>>,
        Vec<&'static str>,
        Vec<&'static str>,
    );
    let defaults = vec!["localhost", "demo-app.firebaseapp.com", "demo-app.web.app"];
    let cases: [Case; 3] = [
        (
            Some(vec!["seed.test"]),
            vec!["live.test"],
            vec!["seed.test"],
        ),
        (Some(vec![]), vec!["live.test"], vec![]),
        // Undeclared: the live list survives a restore.
        (None, vec!["live.test"], vec!["live.test"]),
    ];
    for (seed, live, restored) in cases {
        let (state, registry) = world(true);
        let initial = match &seed {
            Some(seed) => {
                state
                    .store
                    .lock()
                    .unwrap()
                    .set_authorized_domains_seed(seed.iter().map(|d| (*d).to_owned()).collect())
                    .unwrap();
                seed.clone()
            }
            None => defaults.clone(),
        };
        let route = Route::AdminTenantPath;
        create_user(&state, PROJECT, TENANT);
        let probe = |tenant: &str, expected: &[&str], context: &str| {
            for host in ["seed.test", "live.test", "localhost", "demo-app.web.app"] {
                assert_decision(
                    &link(&state, route, PROJECT, tenant, host),
                    listed(expected, host),
                    &format!("{context} {host}"),
                );
            }
        };
        probe(TENANT, &initial, "initial");
        set_domains(&state, PROJECT, &json!(live));
        probe(TENANT, &live, "after the project update");
        let recreated = recreate_tenant(&state, TENANT);
        probe(&recreated, &live, "after tenant recreation");
        let restored_seed = state
            .store
            .lock()
            .unwrap()
            .restore_authorized_domains_seed();
        assert_eq!(restored_seed, seed.is_some());
        assert_eq!(
            project_domains(&state, PROJECT),
            json!(restored),
            "the project's own reset semantics are unchanged"
        );
        probe(&recreated, &restored, "after the project list was restored");
        drop(registry);
    }
}

/// A tenant cannot widen or bypass the project's list: not through its store's own list, and
/// not through a tenant PATCH that names an authorizedDomains member.
#[test]
fn a_tenant_store_list_never_widens_the_project_list() {
    let (state, registry) = world(true);
    create_user(&state, PROJECT, TENANT);
    set_domains(&state, PROJECT, &json!(["project.test"]));
    registry
        .tenant_store(PROJECT, TENANT)
        .unwrap()
        .lock()
        .unwrap()
        .set_authorized_domains_seed(vec!["evil.test".to_owned(), "project.test".to_owned()])
        .unwrap();
    for route in [Route::AdminTenantPath, Route::ClientBodyTenant] {
        assert_decision(
            &link(&state, route, PROJECT, TENANT, "evil.test"),
            false,
            "evil",
        );
        assert_decision(
            &link(&state, route, PROJECT, TENANT, "project.test"),
            true,
            "project",
        );
    }
    // The tenant store's own list does not narrow it either: a project host the tenant store
    // does not list is accepted.
    set_domains(&state, PROJECT, &json!(["only-project.test"]));
    assert_decision(
        &link(
            &state,
            Route::AdminTenantPath,
            PROJECT,
            TENANT,
            "only-project.test",
        ),
        true,
        "project-only host",
    );
    // A tenant update cannot carry a list of its own.
    let (_status, _body) = admin(
        &state,
        "PATCH",
        &format!("{V2}/projects/{PROJECT}/tenants/{TENANT}?updateMask=authorizedDomains"),
        &json!({"authorizedDomains": ["evil.test"]}),
    );
    assert_decision(
        &link(&state, Route::AdminTenantPath, PROJECT, TENANT, "evil.test"),
        false,
        "evil after a tenant PATCH",
    );
    assert_eq!(
        project_domains(&state, PROJECT),
        json!(["only-project.test"]),
        "the project's list is untouched"
    );
}

/// The emulator profile adds no refusal at any scope, as the official emulator checks no
/// domain, whatever the project list holds.
#[test]
fn the_emulator_profile_accepts_any_host_for_a_tenant_link() {
    let (state, _registry) = world(false);
    create_user(&state, PROJECT, TENANT);
    for list in [json!([]), json!(["only.test"])] {
        set_domains(&state, PROJECT, &list);
        for route in [Route::AdminTenantPath, Route::ClientBodyTenant] {
            for host in ["localhost", "only.test", "nowhere.invalid"] {
                assert_decision(&link(&state, route, PROJECT, TENANT, host), true, host);
            }
        }
    }
}

const HOSTS: [&str; 5] = ["a.test", "b.test", "c.test", "localhost", "d.test"];

fn host_subset() -> impl Strategy<Value = Vec<&'static str>> {
    proptest::sample::subsequence(HOSTS.to_vec(), 0..=HOSTS.len())
}

fn spelled() -> impl Strategy<Value = (usize, bool)> {
    (0..HOSTS.len(), any::<bool>())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// A strict tenant-scoped decision is exactly the membership of the host in the parent
    /// project's live list, whatever the tenant store's own list holds and whichever way the
    /// list was reached; the emulator profile accepts every host.
    #[test]
    fn tenant_decision_is_the_membership_in_the_parent_list(
        parent in host_subset(),
        patched in host_subset(),
        tenant_own in host_subset(),
        (host, upper) in spelled(),
        patch_after in any::<bool>(),
    ) {
        let (strict_world, strict_registry) = world(true);
        let (emulator_world, emulator_registry) = world(false);
        let host = if upper { HOSTS[host].to_uppercase() } else { HOSTS[host].to_owned() };
        for (state, registry, strict) in [
            (&strict_world, &strict_registry, true),
            (&emulator_world, &emulator_registry, false),
        ] {
            create_user(state, PROJECT, TENANT);
            set_domains(state, PROJECT, &json!(parent));
            registry
                .tenant_store(PROJECT, TENANT)
                .unwrap()
                .lock()
                .unwrap()
                .set_authorized_domains_seed(tenant_own.iter().map(|d| (*d).to_owned()).collect())
                .unwrap();
            let effective = if patch_after {
                set_domains(state, PROJECT, &json!(patched));
                &patched
            } else {
                &parent
            };
            for route in [Route::AdminTenantPath, Route::ClientBodyTenant] {
                let answer = link(state, route, PROJECT, TENANT, &host);
                assert_decision(&answer, !strict || listed(effective, &host), &format!("{route:?} {host}"));
            }
        }
    }
}
