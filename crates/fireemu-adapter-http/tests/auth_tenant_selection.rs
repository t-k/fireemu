//! Which tenant an account request names, and production's answers when it names none that
//! exists (strict profile; AUTH-TENANT-BLOCKING sandbox recording 2026-09-27, programs
//! `atb/tenant/selection`, `deletion`, `switch-off`, `credentials`).
//!
//! - A non-string `tenantId` is `INVALID_TENANT_ID`; `""` is the project.
//! - An ID token's tenant that differs from the named one is `TENANT_ID_MISMATCH : ...`, before
//!   the named tenant's existence is checked; a tenant ID token without a `tenantId` works in
//!   its own tenant.
//! - A tenant that never existed is `INVALID_TENANT_ID`; one deleted in this run is
//!   `TENANT_DELETED` (a refresh in the Secure Token's v2 shape).

use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::{
    handle_with, AuthQueryLimits, AuthState, ClientApiKeyPolicy, FakeCustomTokenExpiry,
    IdpContinuationPolicy, RequestHeaders,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const TENANTS: &str = "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants";
const TOKEN: &str = "/securetoken.googleapis.com/v1/token";
const KEY: &str = "fake-api-key";
const UNKNOWN: &str = "atb-nosuch-tenant";
const MISMATCH: &str = "TENANT_ID_MISMATCH : Specified tenant ID mismatches with the ID token.";

fn state(strict: bool) -> AuthState {
    let mut store = AuthStore::new("demo-app", SplitMix64::new(5), TotpPolicy::default());
    store.set_project_number(Some(123_456_789_012));
    let store = Arc::new(Mutex::new(store));
    let registry = Arc::new(AuthRegistry::new("demo-app", store.clone()));
    let state = AuthState {
        store,
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
        registry: Some(registry),
        allow_routed_projects: false,
        stateless_refresh_tokens: !strict,
        idp_continuations: if strict {
            IdpContinuationPolicy::LocalBounded
        } else {
            IdpContinuationPolicy::Disabled
        },
        query_limits: if strict {
            AuthQueryLimits::ProductionBounded
        } else {
            AuthQueryLimits::EmulatorUnbounded
        },
        client_api_key: if strict {
            ClientApiKeyPolicy::Required
        } else {
            ClientApiKeyPolicy::Optional
        },
        fake_custom_token_expiry: if strict {
            FakeCustomTokenExpiry::Reject
        } else {
            FakeCustomTokenExpiry::Ignore
        },
        custom_token_trust: None,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };
    if strict {
        let (status, body) = admin(
            &state,
            "PATCH",
            "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=multiTenant.allowTenants",
            &json!({"multiTenant": {"allowTenants": true}}),
        );
        assert_eq!(status, 200, "{body}");
    }
    state
}

fn admin(state: &AuthState, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let headers = RequestHeaders {
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        content_type: Some("application/json".to_owned()),
        host: Some("127.0.0.1:9099".to_owned()),
        app_check: Vec::new(),
        peer_ip: None,
    };
    let r = handle_with(state, method, path, &headers, body);
    (r.status, r.body)
}

fn client(state: &AuthState, route: &str, body: &Value) -> (u16, Value) {
    let r = handle_with(
        state,
        "POST",
        &format!("{route}?key={KEY}"),
        &RequestHeaders::default(),
        body,
    );
    (r.status, r.body)
}

/// A tenant with password sign-in on, and one account in it signed in.
fn tenant_with_user(state: &AuthState, name: &str) -> (String, Value) {
    let (status, created) = admin(
        state,
        "POST",
        TENANTS,
        &json!({"displayName": name, "allowPasswordSignup": true}),
    );
    assert_eq!(status, 200, "{created}");
    let tenant = created["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let (status, user) = admin(
        state,
        "POST",
        &format!("{V1}/projects/demo-app/tenants/{tenant}/accounts"),
        &json!({"email": format!("{name}@example.com"), "password": "password123"}),
    );
    assert_eq!(status, 200, "{user}");
    let (status, signed) = client(
        state,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"tenantId": tenant, "email": format!("{name}@example.com"),
                "password": "password123", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{signed}");
    (tenant, signed)
}

/// Production's v1 error: `code`, `message` and one `errors` entry, no `status`.
fn v1(message: &str) -> Value {
    json!({"error": {"code": 400, "message": message,
                     "errors": [{"message": message, "domain": "global", "reason": "invalid"}]}})
}

#[test]
fn strict_names_a_tenant_as_production_does() {
    let s = state(true);
    let (a, signed) = tenant_with_user(&s, "atb-sel-a");
    let (b, _) = tenant_with_user(&s, "atb-sel-b");
    let sign_in = |tenant: Value| {
        client(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"tenantId": tenant, "email": "atb-sel-a@example.com", "password": "password123"}),
        )
    };
    // selection#sign-in-unknown-tenant, sign-in-number-tenant.
    assert_eq!(sign_in(json!(UNKNOWN)), (400, v1("INVALID_TENANT_ID")));
    assert_eq!(sign_in(json!(7)), (400, v1("INVALID_TENANT_ID")));
    // selection#sign-in-empty-tenant: "" is the project, which has no such account.
    let (status, empty) = sign_in(json!(""));
    let (_, project) = client(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"email": "atb-sel-a@example.com", "password": "password123"}),
    );
    assert_eq!((status, empty), (400, project));
    // selection#admin-lookup-unknown-tenant.
    let (status, body) = admin(
        &s,
        "POST",
        &format!("{V1}/projects/demo-app/tenants/{UNKNOWN}/accounts:lookup"),
        &json!({"localId": ["x"]}),
    );
    assert_eq!((status, body), (400, v1("INVALID_TENANT_ID")));
    // selection#lookup-tenant-b, lookup-unknown-tenant: the token's tenant is checked first.
    let id_token = signed["idToken"].clone();
    for tenant in [b.as_str(), UNKNOWN] {
        let answer = client(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"idToken": id_token, "tenantId": tenant}),
        );
        assert_eq!(answer, (400, v1(MISMATCH)), "{tenant}");
    }
    // selection#lookup-no-tenant: a tenant token works in its own tenant.
    let (status, found) = client(
        &s,
        &format!("{V1}/accounts:lookup"),
        &json!({"idToken": id_token}),
    );
    assert_eq!(status, 200, "{found}");
    assert_eq!(found["users"][0]["tenantId"], json!(a));
}

#[test]
fn strict_answers_a_deleted_tenant_as_deleted() {
    let s = state(true);
    let (d, signed) = tenant_with_user(&s, "atb-del-d");
    let (status, _) = admin(&s, "DELETE", &format!("{TENANTS}/{d}"), &json!({}));
    assert_eq!(status, 200);
    let id_token = signed["idToken"].clone();
    // deletion#lookup-after-delete, lookup-after-delete-no-tenant, sign-in-after-delete.
    for body in [
        json!({"idToken": id_token, "tenantId": d}),
        json!({"idToken": id_token}),
    ] {
        assert_eq!(
            client(&s, &format!("{V1}/accounts:lookup"), &body),
            (400, v1("TENANT_DELETED")),
            "{body}"
        );
    }
    assert_eq!(
        client(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"tenantId": d, "email": "atb-del-d@example.com", "password": "password123"}),
        ),
        (400, v1("TENANT_DELETED"))
    );
    // deletion#admin-lookup-after-delete.
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{V1}/projects/demo-app/tenants/{d}/accounts:lookup"),
            &json!({"localId": ["x"]}),
        ),
        (400, v1("TENANT_DELETED"))
    );
    // deletion#refresh-after-delete, in the Secure Token's shape.
    let (status, refreshed) = client(
        &s,
        TOKEN,
        &json!({"grant_type": "refresh_token", "refresh_token": signed["refreshToken"]}),
    );
    assert_eq!(
        (status, refreshed),
        (
            400,
            json!({"error": {"code": 400, "message": "TENANT_DELETED", "status": "INVALID_ARGUMENT"}})
        )
    );
    // Tenant management still calls it unknown (manage#get-deleted).
    let (status, got) = admin(&s, "GET", &format!("{TENANTS}/{d}"), &json!({}));
    assert_eq!(
        (status, got["error"]["message"].clone()),
        (404, json!("TENANT_NOT_FOUND"))
    );
}

#[test]
fn the_emulator_profile_keeps_its_answers_for_an_unknown_tenant() {
    let s = state(false);
    let (status, body) = client(
        &s,
        &format!("{V1}/accounts:signInWithPassword"),
        &json!({"tenantId": UNKNOWN, "email": "x@example.com", "password": "password123"}),
    );
    assert_ne!(
        body["error"]["message"], "INVALID_TENANT_ID",
        "{status} {body}"
    );
    assert_ne!(
        body["error"]["message"], "TENANT_DELETED",
        "{status} {body}"
    );
}

/// Production's Admin create answer names no tenant, on a tenant path too
/// (selection#create-a1: `kind`, `email`, `localId`).
#[test]
fn strict_admin_create_answers_without_the_tenant() {
    let s = state(true);
    let (status, created) = admin(
        &s,
        "POST",
        TENANTS,
        &json!({"displayName": "atb-sel-c", "allowPasswordSignup": true}),
    );
    assert_eq!(status, 200, "{created}");
    let tenant = created["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    let (status, user) = admin(
        &s,
        "POST",
        &format!("{V1}/projects/demo-app/tenants/{tenant}/accounts"),
        &json!({"email": "c@example.com", "password": "password123"}),
    );
    assert_eq!(status, 200, "{user}");
    let mut keys: Vec<&str> = user
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["email", "kind", "localId"], "{user}");
}

fn patch_tenant(state: &AuthState, tenant: &str, mask: &str, body: &Value) {
    let (status, answer) = admin(
        state,
        "PATCH",
        &format!("{TENANTS}/{tenant}?updateMask={mask}"),
        body,
    );
    assert_eq!(status, 200, "{answer}");
}

/// A tenant's sign-in switches answer as production's (settings program).
#[test]
fn strict_tenant_switches_answer_as_production() {
    let s = state(true);
    let (t, signed) = tenant_with_user(&s, "atb-set-s");
    let email = "atb-set-s@example.com";
    // settings#password-off-sign-in, password-off-reset-mail.
    patch_tenant(
        &s,
        &t,
        "allowPasswordSignup",
        &json!({"allowPasswordSignup": false}),
    );
    assert_eq!(
        client(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"tenantId": t, "email": email, "password": "password123"}),
        ),
        (400, v1("PASSWORD_LOGIN_DISABLED"))
    );
    let (status, mail) = client(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"tenantId": t, "requestType": "PASSWORD_RESET", "email": email}),
    );
    assert_eq!(status, 200, "{mail}");
    patch_tenant(
        &s,
        &t,
        "allowPasswordSignup",
        &json!({"allowPasswordSignup": true}),
    );
    // settings#anonymous-off-sign-up.
    assert_eq!(
        client(
            &s,
            &format!("{V1}/accounts:signUp"),
            &json!({"tenantId": t})
        ),
        (400, v1("ADMIN_ONLY_OPERATION"))
    );
    // settings#auth-off-*: sign-in, admin lookup and refresh are TENANT_DISABLED; a lookup
    // with a token issued before is TOKEN_EXPIRED.
    patch_tenant(&s, &t, "disableAuth", &json!({"disableAuth": true}));
    assert_eq!(
        client(
            &s,
            &format!("{V1}/accounts:signInWithPassword"),
            &json!({"tenantId": t, "email": email, "password": "password123"}),
        ),
        (400, v1("TENANT_DISABLED"))
    );
    assert_eq!(
        admin(
            &s,
            "POST",
            &format!("{V1}/projects/demo-app/tenants/{t}/accounts:lookup"),
            &json!({"email": [email]}),
        ),
        (400, v1("TENANT_DISABLED"))
    );
    assert_eq!(
        client(
            &s,
            TOKEN,
            &json!({"grant_type": "refresh_token", "refresh_token": signed["refreshToken"]}),
        ),
        (
            400,
            json!({"error": {"code": 400, "message": "TENANT_DISABLED", "status": "INVALID_ARGUMENT"}})
        )
    );
    assert_eq!(
        client(
            &s,
            &format!("{V1}/accounts:lookup"),
            &json!({"tenantId": t, "idToken": signed["idToken"]}),
        ),
        (400, v1("TOKEN_EXPIRED"))
    );
    patch_tenant(&s, &t, "disableAuth", &json!({"disableAuth": false}));
    // settings#phone-tenant-number: a tenant's phone code.
    patch_tenant(
        &s,
        &t,
        "testPhoneNumbers",
        &json!({"testPhoneNumbers": {"+16505550102": "123456"}}),
    );
    assert_eq!(
        client(
            &s,
            &format!("{V1}/accounts:sendVerificationCode"),
            &json!({"tenantId": t, "phoneNumber": "+16505550102"}),
        ),
        (400, v1("UNSUPPORTED_TENANT_OPERATION"))
    );
}
