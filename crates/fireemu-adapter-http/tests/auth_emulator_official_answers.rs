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
    project_token("demo-app", user, tenant)
}

/// An unsigned ID token of `project` (the emulator profile refuses another project's audience,
/// where the official emulator does not look at it).
fn project_token(project: &str, user: &str, tenant: &str) -> String {
    alg_none(&json!({
        "aud": project, "iss": format!("https://securetoken.google.com/{project}"),
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

#[allow(clippy::too_many_lines)]
fn admin_body_tenant_table() {
    // (case, path suffix, body, official status, official message)
    let rows: Vec<(&str, &str, Value, u16, &str)> = vec![
        (
            "lookup",
            "/accounts:lookup",
            json!({"localId": ["x"]}),
            200,
            "-",
        ),
        (
            "create",
            "/accounts",
            json!({"email": "m@example.com", "password": "hunter22"}),
            200,
            "-",
        ),
        (
            "update",
            "/accounts:update",
            json!({"localId": "x", "displayName": "d"}),
            400,
            "USER_NOT_FOUND",
        ),
        (
            "delete",
            "/accounts:delete",
            json!({"localId": "x"}),
            400,
            "USER_NOT_FOUND",
        ),
        (
            "batchCreate",
            "/accounts:batchCreate",
            json!({"users": [{"localId": "u", "email": "b@example.com"}]}),
            200,
            "-",
        ),
        (
            "batchDelete",
            "/accounts:batchDelete",
            json!({"localIds": ["x"], "force": true}),
            200,
            "-",
        ),
        (
            "query",
            "/accounts:query",
            json!({"returnUserInfo": false}),
            200,
            "-",
        ),
        (
            "sendOobCode",
            "/accounts:sendOobCode",
            json!({"requestType": "PASSWORD_RESET", "email": "x@example.com", "returnOobLink": true}),
            400,
            "EMAIL_NOT_FOUND",
        ),
        (
            "createSessionCookie",
            ":createSessionCookie",
            json!({"validDuration": "3600"}),
            400,
            "USER_NOT_FOUND",
        ),
    ];
    for project in ["demo-other", "demo-app"] {
        for (n, (case, suffix, body, status, message)) in rows.iter().enumerate() {
            let (state, registry) = routed_state();
            let tenant = format!("body-{n}");
            let mut body = body.clone();
            body["tenantId"] = json!(tenant);
            if *case == "createSessionCookie" {
                body["idToken"] = json!(project_token(project, "u1", &tenant));
            }
            let (got, answered) = admin(
                &state,
                "POST",
                &format!("{V1}/projects/{project}{suffix}"),
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
            // A create lands in the tenant, never in the path's project.
            if matches!(*case, "create" | "batchCreate") {
                let users_in = |store: Option<Arc<Mutex<AuthStore>>>| {
                    store.map_or(0, |store| store.lock().unwrap().user_count())
                };
                assert_eq!(
                    users_in(registry.tenant_store(project, &tenant)),
                    1,
                    "{project} {case}: the tenant holds the user"
                );
                let project_store = registry
                    .store_for(project)
                    .or_else(|| registry.routed_store_for(project));
                assert_eq!(
                    users_in(project_store),
                    0,
                    "{project} {case}: the project holds none"
                );
            }
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

/// `sendOobCode` for `VERIFY_EMAIL` asks for the link alone (no ID token read) only when it has
/// `returnOobLink` and no token (`operations.js:678`); a token reads it even with the flag
/// (official column probed, owner credential, no `email` so the two paths answer differently).
#[test]
fn a_verify_email_link_request_reads_the_token_it_carries() {
    let (state, _registry) = emulator();
    let mut body =
        json!({"requestType": "VERIFY_EMAIL", "returnOobLink": true, "tenantId": "link-t"});
    body["idToken"] = json!(own_token("u1", "link-t"));
    let (status, answered) = admin(&state, "POST", &format!("{V1}/accounts:sendOobCode"), &body);
    assert_eq!(
        (status, message_of(&answered)),
        (400, "USER_NOT_FOUND".to_owned()),
        "{answered}"
    );
}

/// The body-tenant scope of the Admin account operations is the emulator profile's alone: under
/// strict only the project-level lookup takes a body tenant as its scope (production's Admin
/// operations on a project path ignore it), so a create or a batch create with one writes to the
/// project, never to the tenant it names.
#[test]
fn the_strict_profile_does_not_scope_admin_writes_by_the_body_tenant() {
    let (_, state, registry) = profiles()
        .into_iter()
        .find(|(label, ..)| *label == "strict")
        .unwrap();
    let (status, created) = admin(
        &state,
        "POST",
        &format!("{V2}/projects/demo-app/tenants"),
        &json!({"displayName": "held"}),
    );
    assert_eq!(status, 200, "{created}");
    let tenant = created["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let held = registry.tenant_store("demo-app", &tenant).unwrap();
    for (suffix, body) in [
        (
            "accounts",
            json!({"email": "m@example.com", "password": "hunter22"}),
        ),
        (
            "accounts:batchCreate",
            json!({"users": [{"localId": "u", "email": "b@example.com"}]}),
        ),
    ] {
        let mut body = body;
        body["tenantId"] = json!(tenant);
        let (_, answered) = admin(
            &state,
            "POST",
            &format!("{V1}/projects/demo-app/{suffix}"),
            &body,
        );
        assert_eq!(held.lock().unwrap().user_count(), 0, "{suffix}: {answered}");
    }
}

/// A body `tenantId` on a tenant-management route selects no tenant store: `tenants:create` on a
/// routed project with one is refused as it was (the official emulator makes the tenant and then
/// refuses), and nothing is made in, or added to, the tenant the body names.
#[test]
fn a_body_tenant_on_a_tenant_route_selects_no_tenant_store() {
    within_a_minute(|| {
        let (state, registry) = routed_state();
        let create = |body: Value| {
            admin(
                &state,
                "POST",
                &format!("{V2}/projects/demo-other/tenants"),
                &body,
            )
        };
        let (status, first) = create(json!({"displayName": "first"}));
        assert_eq!(status, 200, "{first}");
        let named = first["name"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        assert!(registry.tenant_store("demo-other", &named).is_some());
        let (status, second) = create(json!({"displayName": "second", "tenantId": named}));
        assert_eq!(status, 400, "{second}");
        assert_eq!(tenant_names(&state, "demo-other"), vec![named]);
    });
}

/// The Admin create and the Admin update (without an `oobCode`) parse an ID token too
/// (`operations.js:181` and `:832`, privileged requests included): a token of a tenant that was
/// made on the way finds no user there, so the create is refused and creates nothing, in the
/// default project and in a routed one alike (official column probed, owner credential).
#[test]
fn an_admin_create_or_update_with_an_id_token_of_a_new_tenant_finds_no_user() {
    within_a_minute(|| {
        for project in ["demo-app", "demo-other"] {
            // (case, path suffix, body without the token, whether the body names the tenant)
            let rows: Vec<(&str, &str, Value, bool)> = vec![
                (
                    "create in a body tenant",
                    "/accounts",
                    json!({"email": "m@example.com", "password": "hunter22"}),
                    true,
                ),
                (
                    "create with the token's tenant only",
                    "/accounts",
                    json!({"email": "m@example.com", "password": "hunter22"}),
                    false,
                ),
                (
                    "update by localId",
                    "/accounts:update",
                    json!({"localId": "x", "displayName": "d"}),
                    true,
                ),
            ];
            for (n, (case, suffix, body, names_tenant)) in rows.into_iter().enumerate() {
                let (state, registry) = routed_state();
                let tenant = format!("adm-{n}");
                let mut body = body;
                if names_tenant {
                    body["tenantId"] = json!(tenant);
                }
                body["idToken"] = json!(project_token(project, "u1", &tenant));
                let (status, answered) = admin(
                    &state,
                    "POST",
                    &format!("{V1}/projects/{project}{suffix}"),
                    &body,
                );
                assert_eq!(
                    (status, message_of(&answered)),
                    (400, "USER_NOT_FOUND".to_owned()),
                    "{project} {case}: {answered}"
                );
                // Nothing was created: not in the tenant, and not in the project.
                if let Some(store) = registry.tenant_store(project, &tenant) {
                    assert_eq!(store.lock().unwrap().user_count(), 0, "{project} {case}");
                }
                let project_users = if project == "demo-app" {
                    registry.store_for(project)
                } else {
                    registry.routed_store_for(project)
                }
                .map_or(0, |store| store.lock().unwrap().user_count());
                assert_eq!(project_users, 0, "{project} {case}");
            }
        }
    });
}

/// `parseIdToken` does not look at `exp`, so an expired token of a tenant made on the way finds no
/// user there (`USER_NOT_FOUND`), for every operation that reads the token, the Admin ones and the
/// session cookie included; not the expiry's own refusal (official column probed).
#[test]
fn an_expired_token_of_a_new_tenant_finds_no_user_in_the_operations_that_parse_it() {
    for (n, (route, body)) in [
        ("accounts:lookup", json!({})),
        ("accounts:delete", json!({})),
        ("accounts:update", json!({"displayName": "x"})),
    ]
    .into_iter()
    .enumerate()
    {
        let (state, _registry) = emulator();
        let tenant = format!("exp-{n}");
        let mut body = body;
        body["tenantId"] = json!(tenant);
        body["idToken"] = json!(alg_none(&json!({
            "aud": "demo-app", "iss": "https://securetoken.google.com/demo-app",
            "sub": "u1", "user_id": "u1", "iat": 1_787_000_000, "exp": 1_787_003_600,
            "auth_time": 1_787_000_000,
            "firebase": {"sign_in_provider": "password", "identities": {}, "tenant": tenant}
        })));
        let (status, answered) = client(&state, &format!("{V1}/{route}"), &body);
        assert_eq!(
            (status, message_of(&answered)),
            (400, "USER_NOT_FOUND".to_owned()),
            "{route}: {answered}"
        );
    }
}

/// The body-tenant selection of the routed block is the emulator profile's alone: a strict state
/// that is allowed routed projects (an embedding, a test) still serves a body tenant of a routed
/// project's Admin request from the project, never from the tenant it names.
#[test]
fn the_strict_profile_does_not_scope_a_routed_admin_request_by_the_body_tenant() {
    let (emulator_state, registry) = routed_state();
    let (status, created) = admin(
        &emulator_state,
        "POST",
        &format!("{V1}/projects/demo-other/tenants/held/accounts"),
        &json!({"email": "held@example.com", "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    let mut state = strict_state();
    state.registry = Some(registry);
    state.allow_routed_projects = true;
    let (_, answered) = admin(
        &state,
        "POST",
        &format!("{V1}/projects/demo-other/accounts:lookup"),
        &json!({"tenantId": "held", "email": ["held@example.com"]}),
    );
    // The project's own store answers (the body tenant is a scope the routed project's store does
    // not have); the tenant's store would answer that tenants are not enabled in strict.
    assert_eq!(message_of(&answered), "TENANT_ID_MISMATCH", "{answered}");
}

/// The Admin update parses the token (`operations.js:832`) unless it carries an `oobCode`. The
/// pre-check only speaks for a tenant that was made on the way, where the token's user is not
/// there. Rows: (case, body, fireemu's answer, official answer). With no `localId` the official
/// emulator asserts it first (`MISSING_LOCAL_ID`, `operations.js:769`), and fireemu answers
/// `USER_NOT_FOUND` from the pre-check, or `INVALID_OOB_CODE` with an `oobCode` (both recorded);
/// with an `oobCode` neither reads the token.
#[test]
fn an_admin_update_reads_the_token_unless_it_carries_an_oob_code() {
    within_a_minute(|| {
        for project in ["demo-app", "demo-other"] {
            let rows: Vec<(&str, Value, &str, &str)> = vec![
                (
                    "no localId",
                    json!({"displayName": "d"}),
                    "USER_NOT_FOUND",
                    "MISSING_LOCAL_ID",
                ),
                (
                    "an oobCode and no localId",
                    json!({"displayName": "d", "oobCode": "nope"}),
                    "INVALID_OOB_CODE",
                    "MISSING_LOCAL_ID",
                ),
                (
                    "a localId and an oobCode",
                    json!({"localId": "x", "displayName": "d", "oobCode": "nope"}),
                    "INVALID_OOB_CODE",
                    "INVALID_OOB_CODE",
                ),
            ];
            for (n, (case, body, fireemu, official)) in rows.into_iter().enumerate() {
                let (state, _registry) = routed_state();
                let tenant = format!("upd-{n}");
                let mut body = body;
                body["tenantId"] = json!(tenant);
                body["idToken"] = json!(project_token(project, "zz", &tenant));
                let (_, answered) = admin(
                    &state,
                    "POST",
                    &format!("{V1}/projects/{project}/accounts:update"),
                    &body,
                );
                assert_eq!(
                    message_of(&answered),
                    fireemu,
                    "{project} {case}: {answered} (official: {official})"
                );
            }
        }
    });
}

#[test]
fn an_expired_token_of_a_new_tenant_finds_no_user_in_the_admin_operations_that_parse_it() {
    let expired = |tenant: &str| {
        alg_none(&json!({
            "aud": "demo-app", "iss": "https://securetoken.google.com/demo-app",
            "sub": "u1", "user_id": "u1", "iat": 1_787_000_000, "exp": 1_787_003_600,
            "auth_time": 1_787_000_000,
            "firebase": {"sign_in_provider": "password", "identities": {}, "tenant": tenant}
        }))
    };
    for (n, (path, body)) in [
        (
            format!("{V1}/projects/demo-app:createSessionCookie"),
            json!({"validDuration": "3600"}),
        ),
        (
            format!("{V1}/projects/demo-app/accounts"),
            json!({"email": "m@example.com", "password": "hunter22"}),
        ),
        (
            format!("{V1}/projects/demo-app/accounts:update"),
            json!({"localId": "x", "displayName": "d"}),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let (state, _registry) = emulator();
        let tenant = format!("aexp-{n}");
        let mut body = body;
        body["tenantId"] = json!(tenant);
        body["idToken"] = json!(expired(&tenant));
        let (status, answered) = admin(&state, "POST", &path, &body);
        assert_eq!(
            (status, message_of(&answered)),
            (400, "USER_NOT_FOUND".to_owned()),
            "{path}: {answered}"
        );
    }
}

/// The official emulator takes the token's tenant as the third source of an operation's target
/// (`server.js:398-406`), and does not parse the token on an end-user route reached with the owner
/// credential (`operations.js:225`, `:546-551`, `:753`). Official column probed against
/// firebase-tools 15.28.2; owner credential; default and routed project.
///
/// - the Admin update and delete with only an ID token naming an existing tenant run in that tenant
///   (both answered `USER_NOT_FOUND` from the project's store before);
/// - the end-user lookup, delete and update with the owner credential are served by their
///   selectors, with no token read (they answered `USER_NOT_FOUND` before): a lookup with a
///   selector that matches nothing is 200, a delete without a `localId` is `MISSING_LOCAL_ID`;
/// - still different, recorded: the Admin create with a token creates the user (in the token's
///   tenant now; the official emulator answers `USER_NOT_FOUND` when the token's user is missing),
///   and an update with the owner credential and no `localId` answers `INVALID_ID_TOKEN` (the
///   official emulator `MISSING_LOCAL_ID`).
#[test]
fn an_id_token_names_the_target_tenant_of_an_admin_operation_and_the_owner_credential_skips_it() {
    within_a_minute(|| {
        for project in ["demo-app", "demo-other"] {
            let (state, registry) = routed_state();
            let path = |suffix: &str| format!("{V1}/projects/{project}{suffix}");
            // A tenant `tt` that holds the user `l1`, made through the Admin create.
            let (status, made) = admin(
                &state,
                "POST",
                &path("/accounts"),
                &json!({"tenantId": "tt", "localId": "l1", "email": "l1@example.com", "password": "hunter22"}),
            );
            assert_eq!(status, 200, "{project}: {made}");
            let token = project_token(project, "l1", "tt");
            let users_in = |store: Option<Arc<Mutex<AuthStore>>>| {
                store.map_or(0, |store| store.lock().unwrap().user_count())
            };
            let project_store = || {
                registry
                    .store_for(project)
                    .or_else(|| registry.routed_store_for(project))
            };
            // The update and the delete run in the token's tenant.
            let (status, answered) = admin(
                &state,
                "POST",
                &path("/accounts:update"),
                &json!({"localId": "l1", "displayName": "d", "idToken": token}),
            );
            assert_eq!(status, 200, "{project} update: {answered}");
            let (status, answered) = admin(
                &state,
                "POST",
                &path("/accounts:delete"),
                &json!({"localId": "l1", "idToken": token}),
            );
            assert_eq!(status, 200, "{project} delete: {answered}");
            assert_eq!(
                users_in(registry.tenant_store(project, "tt")),
                0,
                "{project}"
            );
            // A create with a token names its tenant too, so the user lands there (the official
            // emulator refuses with USER_NOT_FOUND: the token's user is missing).
            let (status, answered) = admin(
                &state,
                "POST",
                &path("/accounts"),
                &json!({"email": "m@example.com", "password": "hunter22", "idToken": project_token(project, "u9", "tt")}),
            );
            assert_eq!(status, 200, "{project} create: {answered}");
            assert_eq!(
                users_in(registry.tenant_store(project, "tt")),
                1,
                "{project}"
            );
            assert_eq!(users_in(project_store()), 0, "{project}");
        }
        // The end-user routes with the owner credential and a token of a tenant made on the way.
        for (route, body, status, message) in [
            ("lookup", json!({"email": ["nobody@example.com"]}), 200, "-"),
            ("delete", json!({}), 400, "MISSING_LOCAL_ID"),
            (
                "update",
                json!({"localId": "nobody", "displayName": "d"}),
                400,
                "USER_NOT_FOUND",
            ),
            // Official: MISSING_LOCAL_ID.
            (
                "update",
                json!({"displayName": "d"}),
                400,
                "INVALID_ID_TOKEN",
            ),
        ] {
            let (state, _registry) = emulator();
            let mut body = body;
            body["tenantId"] = json!("tc");
            body["idToken"] = json!(own_token("u1", "tc"));
            let (got, answered) = admin(
                &state,
                "POST",
                &format!("{V1}/accounts:{route}?key={KEY}"),
                &body,
            );
            assert_eq!(
                (got, message_of(&answered)),
                (status, message.to_owned()),
                "{route} with Bearer owner: {answered}"
            );
        }
    });
}

/// The token's tenant is the target only for a token of this project, with a tenant claim, in the
/// emulator profile: a token of another project's audience (this daemon refuses it), an empty
/// tenant claim (no tenant, as in the official emulator) and the strict profile all leave the
/// request in the project's store: the delete of the project's own user `p1` succeeds there, and
/// the tenant `tt` (which holds `l1`) is untouched.
#[test]
fn the_tokens_tenant_is_not_the_target_for_another_projects_token_an_empty_claim_or_strict() {
    within_a_minute(|| {
        let with_claim = |project: &str, tenant: &str| {
            alg_none(&json!({
                "aud": project, "iss": format!("https://securetoken.google.com/{project}"),
                "sub": "l1", "user_id": "l1", "iat": 1_788_004_860, "exp": 1_788_008_400,
                "auth_time": 1_788_004_860,
                "firebase": {"sign_in_provider": "password", "identities": {}, "tenant": tenant}
            }))
        };
        // The project holds `p1`, the tenant `tt` holds `l1`.
        let setup = |state: &AuthState, project: &str| {
            for (tenant, id) in [(None, "p1"), (Some("tt"), "l1")] {
                let mut body = json!({
                    "localId": id, "email": format!("{id}@example.com"), "password": "hunter22"
                });
                if let Some(tenant) = tenant {
                    body["tenantId"] = json!(tenant);
                }
                let (status, made) = admin(
                    state,
                    "POST",
                    &format!("{V1}/projects/{project}/accounts"),
                    &body,
                );
                assert_eq!(status, 200, "{project}: {made}");
            }
        };
        let tenant_users = |registry: &AuthRegistry, project: &str| {
            registry
                .tenant_store(project, "tt")
                .map_or(0, |store| store.lock().unwrap().user_count())
        };
        for project in ["demo-app", "demo-other"] {
            // (case, token): none of them selects the tenant `tt`.
            for (case, token) in [
                (
                    "another project's audience",
                    with_claim("demo-elsewhere", "tt"),
                ),
                ("an empty tenant claim", with_claim(project, "")),
            ] {
                let (state, registry) = routed_state();
                setup(&state, project);
                let (status, answered) = admin(
                    &state,
                    "POST",
                    &format!("{V1}/projects/{project}/accounts:delete"),
                    &json!({"localId": "p1", "idToken": token}),
                );
                assert_eq!(status, 200, "{project} {case}: {answered}");
                assert_eq!(tenant_users(&registry, project), 1, "{project} {case}");
            }
        }
        // Strict: the token never picks the tenant of an Admin delete.
        let (mut state, registry) = routed_state();
        setup(&state, "demo-other");
        state.stateless_refresh_tokens = strict_state().stateless_refresh_tokens;
        let (status, answered) = admin(
            &state,
            "POST",
            &format!("{V1}/projects/demo-other/accounts:delete"),
            &json!({"localId": "p1", "idToken": project_token("demo-other", "l1", "tt")}),
        );
        assert_eq!(status, 200, "strict: {answered}");
        assert_eq!(tenant_users(&registry, "demo-other"), 1, "strict");
    });
}
