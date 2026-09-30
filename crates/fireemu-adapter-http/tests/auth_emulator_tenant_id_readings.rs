//! How the emulator profile reads the tenant a request names, against the official emulator
//! (firebase-tools 15.28.2, probed in-process with the pinned `createApp`):
//!
//! - an empty `tenantId` in a body is no tenant (`server.js:395-398`, JavaScript falsiness): a
//!   path tenant beside it is the target, and none is a project request;
//! - a number in the string-typed `tenantId` is read as its string (the body validation's
//!   `validateAndFixRestMappingRequestBody`), `null` and a boolean are refused by the schema;
//! - the query's `tenantId` is read only by `accounts:batchGet` (`operations.js:438`, and only
//!   when no other tenant is named) and by the action link; every other route ignores it.
//!
//! The strict profile follows the production recordings and is unchanged.

#![allow(dead_code)] // helpers shared with the other tenant test files

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

fn project_users(state: &AuthState) -> usize {
    state.store.lock().unwrap().users_by_creation().len()
}

fn sign_up(state: &AuthState, query: &str, body: &Value) -> (u16, Value) {
    let r = handle(
        state,
        "POST",
        &format!("{V1}/accounts:signUp?key={KEY}{query}"),
        body,
    );
    (r.status, r.body)
}

fn account(email: &str) -> Value {
    json!({"email": email, "password": "hunter22"})
}

fn with(mut body: Value, key: &str, value: Value) -> Value {
    body[key] = value;
    body
}

#[test]
fn an_empty_body_tenant_id_is_no_tenant_in_the_emulator_profile() {
    let (state, registry) = emulator();
    // No tenant beside it: a project sign-up.
    let (status, created) = sign_up(
        &state,
        "",
        &with(account("a@example.com"), "tenantId", json!("")),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(project_users(&state), 1);
    assert!(registry.tenants("demo-app").is_empty());
    // A path tenant beside it: the path tenant is the target (and is made), no mismatch.
    let (status, created) = admin(
        &state,
        "POST",
        &format!("{V1}/projects/demo-app/tenants/pt1/accounts"),
        &with(account("b@example.com"), "tenantId", json!("")),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(registry.tenants("demo-app"), ["pt1"]);
    // The same for a token's route: an ID token of the tenant and an empty body tenant.
    let (status, up) = client(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "c@example.com", "password": "hunter22", "tenantId": "pt2"}),
    );
    assert_eq!(status, 200, "{up}");
    let (status, looked) = client(
        &state,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": up["idToken"], "tenantId": ""}),
    );
    assert_eq!(status, 200, "{looked}");
}

#[test]
fn a_number_is_its_string_and_null_and_a_boolean_are_no_tenant_here() {
    let (state, registry) = emulator();
    // A number is its string, as in the official emulator (0 is "0", not falsy).
    let (status, created) = sign_up(
        &state,
        "",
        &with(account("n0@example.com"), "tenantId", json!(0)),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(registry.tenants("demo-app"), ["0"]);
    // A number beside a path tenant that is not its string is a mismatch, as officially.
    let (status, refused) = admin(
        &state,
        "POST",
        &format!("{V1}/projects/demo-app/tenants/pt4/accounts"),
        &with(account("n7@example.com"), "tenantId", json!(7)),
    );
    assert_eq!(status, 400, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_ID_MISMATCH");
    // A recorded divergence: the official emulator's schema refuses `null` and a boolean
    // (`/tenantId must be string`); the emulator profile reads them as no tenant, which accepts
    // more and makes nothing.
    for (n, value) in [json!(null), json!(true)].into_iter().enumerate() {
        let (status, created) = sign_up(
            &state,
            "",
            &with(account(&format!("nb{n}@example.com")), "tenantId", value),
        );
        assert_eq!(status, 200, "{created}");
    }
    assert_eq!(registry.tenants("demo-app"), ["0"]);
}

#[test]
fn the_strict_profile_reads_an_empty_body_tenant_as_before() {
    let (_, state, registry) = profiles().into_iter().nth(1).unwrap();
    let (status, refused) = admin(
        &state,
        "POST",
        &format!("{V1}/projects/demo-app/tenants/pt1/accounts"),
        &with(account("b@example.com"), "tenantId", json!("")),
    );
    assert_eq!(
        (status, refused["error"]["message"].as_str()),
        (400, Some("INVALID_TENANT_ID")),
        "{refused}"
    );
    assert!(registry.tenants("demo-app").is_empty());
}

#[test]
fn the_query_tenant_id_is_ignored_on_every_route_but_batch_get_and_the_action_link() {
    let (state, registry) = emulator();
    // A client sign-up: a project sign-up, the query names no tenant.
    let (status, created) = sign_up(&state, "&tenantId=qt1", &account("q1@example.com"));
    assert_eq!(status, 200, "{created}");
    assert_eq!(project_users(&state), 1);
    // The query beside a body tenant: the body's tenant is the target, no mismatch.
    let (status, created) = sign_up(
        &state,
        "&tenantId=qt2",
        &with(account("q2@example.com"), "tenantId", json!("bt2")),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(registry.tenants("demo-app"), ["bt2"]);
    // Lookup and a token refresh find no user or session; neither asks for a tenant.
    let r = handle(
        &state,
        "POST",
        &format!("{V1}/accounts:lookup?key={KEY}&tenantId=qt3"),
        &json!({"idToken": "x"}),
    );
    assert_eq!(r.body["error"]["message"], "INVALID_ID_TOKEN", "{}", r.body);
    let r = handle(
        &state,
        "POST",
        &format!("{SECURE_TOKEN}?key={KEY}&tenantId=qt4"),
        &json!({"grant_type": "refresh_token", "refresh_token": "x"}),
    );
    assert_eq!(
        r.body["error"]["message"], "INVALID_REFRESH_TOKEN",
        "{}",
        r.body
    );
    // An Admin project-path route reads no query tenant either.
    let (status, looked) = admin(
        &state,
        "POST",
        &format!("{V1}/projects/demo-app/accounts:lookup?tenantId=qt5"),
        &json!({"localId": ["x"]}),
    );
    assert_eq!(status, 200, "{looked}");
    assert_eq!(registry.tenants("demo-app"), ["bt2"]);
}

#[test]
fn batch_get_reads_the_query_tenant_only_when_no_other_tenant_is_named() {
    let (state, registry) = emulator();
    let batch = |path: &str| {
        let r = handle_with(&state, "GET", path, &owner(), &json!({}));
        (r.status, r.body)
    };
    // The query alone: that tenant's accounts (the tenant is made on the way).
    let (status, listed) = batch(&format!(
        "{V1}/projects/demo-app/accounts:batchGet?tenantId=qt3"
    ));
    assert_eq!(status, 200, "{listed}");
    assert_eq!(registry.tenants("demo-app"), ["qt3"]);
    // A path tenant beside a different query tenant: the path tenant, no mismatch.
    let (status, listed) = batch(&format!(
        "{V1}/projects/demo-app/tenants/pt5/accounts:batchGet?tenantId=qt4"
    ));
    assert_eq!(status, 200, "{listed}");
    assert_eq!(registry.tenants("demo-app"), ["pt5", "qt3"]);
    // The query never fills in for or overrides a tenant named elsewhere: the accounts read are
    // the path tenant's.
    let (status, created) = admin(
        &state,
        "POST",
        &format!("{V1}/projects/demo-app/tenants/qt3/accounts"),
        &account("in-qt3@example.com"),
    );
    assert_eq!(status, 200, "{created}");
    let (_, listed) = batch(&format!(
        "{V1}/projects/demo-app/tenants/pt5/accounts:batchGet?tenantId=qt3"
    ));
    assert!(
        listed
            .get("users")
            .is_none_or(|u| u.as_array().is_some_and(Vec::is_empty)),
        "{listed}"
    );
    let (_, listed) = batch(&format!(
        "{V1}/projects/demo-app/accounts:batchGet?tenantId=qt3"
    ));
    assert_eq!(
        listed["users"].as_array().map(Vec::len),
        Some(1),
        "{listed}"
    );
}

#[test]
fn the_strict_profile_reads_the_query_tenant_as_before() {
    let (_, state, registry) = profiles().into_iter().nth(1).unwrap();
    // An unknown tenant in the query of a client route is refused, not ignored.
    let (status, refused) = sign_up(&state, "&tenantId=qt1", &account("q1@example.com"));
    assert_eq!(status, 404, "{refused}");
    assert_eq!(refused["error"]["message"], "TENANT_NOT_FOUND");
    assert!(registry.tenants("demo-app").is_empty());
}

#[test]
fn the_action_link_reads_its_query_tenant_to_find_the_tenants_code() {
    let (state, registry) = emulator();
    let (status, up) = client(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "t@example.com", "password": "hunter22", "tenantId": "pt"}),
    );
    assert_eq!(status, 200, "{up}");
    let (status, sent) = client(
        &state,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "idToken": up["idToken"], "tenantId": "pt"}),
    );
    assert_eq!(status, 200, "{sent}");
    let (status, codes) = admin(
        &state,
        "GET",
        "/emulator/v1/projects/demo-app/tenants/pt/oobCodes",
        &json!({}),
    );
    assert_eq!(status, 200, "{codes}");
    let code = codes["oobCodes"][0]["oobCode"].as_str().unwrap().to_owned();
    let follow = |query: &str| {
        let r = handle_with(
            &state,
            "GET",
            &format!("/emulator/action?mode=verifyEmail&oobCode={code}&apiKey={KEY}{query}"),
            &RequestHeaders {
                authorization: None,
                ..owner()
            },
            &json!({}),
        );
        (r.status, r.body)
    };
    // Without its tenant the project has no such code; with the query's tenant it is found.
    let (status, refused) = follow("");
    assert_eq!(status, 400, "{refused}");
    let (status, done) = follow("&tenantId=pt");
    assert_eq!(status, 200, "{done}");
    assert!(registry.tenant_store("demo-app", "pt").is_some());
}

/// The two GET routes that read a tenant from the query read no body in the official emulator, so
/// a body tenant beside them selects nothing and makes nothing (official column probed: the action
/// link with `?tenantId=pt` and a body tenant answers in `pt`; batchGet with a query tenant and a
/// body tenant answers with the query tenant's users).
#[test]
fn the_get_routes_that_read_the_query_tenant_read_no_body() {
    let (state, registry) = emulator();
    let (status, up) = client(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "t@example.com", "password": "hunter22", "tenantId": "pt"}),
    );
    assert_eq!(status, 200, "{up}");
    let (status, sent) = client(
        &state,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "idToken": up["idToken"], "tenantId": "pt"}),
    );
    assert_eq!(status, 200, "{sent}");
    let (_, codes) = admin(
        &state,
        "GET",
        "/emulator/v1/projects/demo-app/tenants/pt/oobCodes",
        &json!({}),
    );
    let code = codes["oobCodes"][0]["oobCode"].as_str().unwrap().to_owned();
    let follow = |query: &str, body: &Value| {
        let r = handle_with(
            &state,
            "GET",
            &format!("/emulator/action?mode=verifyEmail&oobCode={code}&apiKey={KEY}{query}"),
            &RequestHeaders {
                authorization: None,
                ..owner()
            },
            body,
        );
        (r.status, r.body)
    };
    // Action link: the query's tenant, whatever the body says, and no tenant is made for the body.
    let (status, done) = follow("&tenantId=pt", &json!({"tenantId": "other"}));
    assert_eq!(status, 200, "{done}");
    assert!(registry.tenant_store("demo-app", "other").is_none());
    // No query tenant: the project, where the code is not (a body tenant selects nothing).
    let (status, refused) = follow("", &json!({"tenantId": "pt"}));
    assert_eq!(status, 400, "{refused}");
    // batchGet: the query's tenant's users; a body tenant is not read and makes nothing.
    let batch = |query: &str, body: &Value| {
        let r = handle_with(
            &state,
            "GET",
            &format!("{V1}/projects/demo-app/accounts:batchGet{query}"),
            &owner(),
            body,
        );
        (r.status, r.body)
    };
    let (status, listed) = batch("?tenantId=pt", &json!({"tenantId": "bt"}));
    assert_eq!(status, 200, "{listed}");
    assert_eq!(
        listed["users"].as_array().map(Vec::len),
        Some(1),
        "{listed}"
    );
    assert!(registry.tenant_store("demo-app", "bt").is_none());
    let (status, listed) = batch("", &json!({"tenantId": "pt"}));
    assert_eq!(status, 200, "{listed}");
    assert!(
        listed
            .get("users")
            .is_none_or(|u| u.as_array().is_some_and(Vec::is_empty)),
        "{listed}"
    );
}

/// Routes the official emulator serves ignore the query's tenant (`operations.js:15-86`), so they
/// answer with it as they do without it; the routes it does not serve keep fireemu's reading.
#[test]
fn the_official_routes_ignore_the_query_tenant_and_the_others_keep_it() {
    let (state, registry) = emulator();
    let tenants = format!("{V2}/projects/demo-app/tenants");
    let (status, made) = admin(
        &state,
        "POST",
        &format!("{tenants}?tenantId=unk"),
        &json!({"displayName": "held"}),
    );
    assert_eq!(status, 200, "{made}");
    let held = made["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    // (case, method, path with a query tenant naming a tenant that does not exist or another one,
    // body): the official emulator answers 200 for each.
    let official: Vec<(&str, &str, String, Value)> = vec![
        (
            "getProjects",
            "GET",
            format!("{V1}/projects?key={KEY}&tenantId=unk"),
            json!({}),
        ),
        (
            "recaptchaParams",
            "GET",
            format!("{V1}/recaptchaParams?key={KEY}&tenantId=unk"),
            json!({}),
        ),
        (
            "v2 config get",
            "GET",
            "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?tenantId=unk"
                .to_owned(),
            json!({}),
        ),
        (
            "tenants list",
            "GET",
            format!("{tenants}?tenantId=unk"),
            json!({}),
        ),
        (
            "tenants create",
            "POST",
            format!("{tenants}?tenantId=unk"),
            json!({"displayName": "second"}),
        ),
        (
            "tenants get",
            "GET",
            format!("{tenants}/{held}?tenantId=other"),
            json!({}),
        ),
        (
            "tenants patch",
            "PATCH",
            format!("{tenants}/{held}?tenantId=other&updateMask=displayName"),
            json!({"displayName": "renamed"}),
        ),
    ];
    for (case, method, path, body) in official {
        let (status, answered) = admin(&state, method, &path, &body);
        assert_eq!(status, 200, "{case}: {answered}");
    }
    // Delete last: it removes the tenant the rows above used.
    let (status, deleted) = admin(
        &state,
        "DELETE",
        &format!("{tenants}/{held}?tenantId=other"),
        &json!({}),
    );
    assert_eq!(status, 200, "{deleted}");
    assert!(registry.tenant_store("demo-app", &held).is_none());
    // Routes the official emulator does not serve (501 there) keep fireemu's reading of the query.
    for (case, path) in [
        (
            "passwordPolicy",
            format!("{V2}/passwordPolicy?key={KEY}&tenantId=unk"),
        ),
        (
            "recaptchaConfig",
            format!("{V2}/recaptchaConfig?key={KEY}&tenantId=unk"),
        ),
    ] {
        let (status, refused) = admin(&state, "GET", &path, &json!({}));
        assert!(status >= 400, "{case}: {status} {refused}");
    }
}

/// A deleted tenant's ID token, with an API key and no body tenant, is made the target by the
/// token's tenant and finds no user there: `USER_NOT_FOUND`, as the official emulator answers for
/// every route that reads the token.
#[test]
fn a_deleted_tenants_token_without_a_body_tenant_finds_no_user() {
    let (state, registry) = emulator();
    let (status, up) = client(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "g@example.com", "password": "hunter22", "tenantId": "gone"}),
    );
    assert_eq!(status, 200, "{up}");
    for (route, body) in [
        (
            "accounts:sendOobCode",
            json!({"requestType": "VERIFY_EMAIL"}),
        ),
        ("accounts:update", json!({"displayName": "x"})),
        ("accounts:lookup", json!({})),
        ("accounts:delete", json!({})),
    ] {
        assert!(registry.delete_tenant("demo-app", "gone"));
        let mut body = body;
        body["idToken"] = up["idToken"].clone();
        let (status, refused) = client(&state, &format!("{V1}/{route}"), &body);
        assert_eq!(status, 400, "{route}: {refused}");
        assert_eq!(refused["error"]["message"], "USER_NOT_FOUND", "{route}");
    }
}

/// A `tenantId` the official schema refuses (`/tenantId must be string`) is read as no tenant here:
/// a recorded divergence that accepts more and makes nothing. Strict is unchanged.
#[test]
fn a_tenant_id_of_another_type_is_no_tenant_in_the_emulator_profile() {
    let (state, registry) = emulator();
    for (n, value) in [json!(null), json!(true), json!({}), json!(["one"])]
        .into_iter()
        .enumerate()
    {
        let (status, created) = sign_up(
            &state,
            "",
            &with(account(&format!("types{n}@example.com")), "tenantId", value),
        );
        assert_eq!(status, 200, "{n}: {created}");
    }
    assert!(registry.tenants("demo-app").is_empty());
    assert_eq!(project_users(&state), 4);
}

/// A refresh with a query tenant renews the session in the token's own namespace, whatever tenant
/// the query names (the official emulator ignores it), and rotates nothing in the other tenant.
#[test]
fn a_refresh_ignores_the_query_tenant_and_renews_in_the_tokens_own_namespace() {
    let (state, registry) = emulator();
    let (status, up) = client(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "r@example.com", "password": "hunter22", "tenantId": "tenant-a"}),
    );
    assert_eq!(status, 200, "{up}");
    let (status, other) = client(
        &state,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "o@example.com", "password": "hunter22", "tenantId": "tenant-b"}),
    );
    assert_eq!(status, 200, "{other}");
    let before_b = registry
        .tenant_store("demo-app", "tenant-b")
        .unwrap()
        .lock()
        .unwrap()
        .user_count();
    for query in ["&tenantId=tenant-b", "&tenantId=unknown", "&tenantId="] {
        let r = handle(
            &state,
            "POST",
            &format!("{SECURE_TOKEN}?key={KEY}{query}"),
            &json!({"grant_type": "refresh_token", "refresh_token": up["refreshToken"]}),
        );
        assert_eq!(r.status, 200, "{query}: {}", r.body);
        assert_eq!(r.body["user_id"], up["localId"], "{query}");
        assert!(
            r.body["refresh_token"]
                .as_str()
                .unwrap()
                .contains("tenant-a"),
            "{query}: the renewed session is tenant-a's"
        );
    }
    assert_eq!(
        registry
            .tenant_store("demo-app", "tenant-b")
            .unwrap()
            .lock()
            .unwrap()
            .user_count(),
        before_b
    );
    assert!(registry.tenant_store("demo-app", "unknown").is_none());
}
