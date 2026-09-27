//! The Identity Platform tenant resource as production answers it (sandbox recording
//! 2026-09-27, `conformance/auth-tenant-blocking-production.json`, programs `atb/tenant/*`;
//! the rules and the rows they come from are in the AUTH-TENANT-BLOCKING spec notes).
//!
//! The shape of the answers is production's under both profiles; the refusals production adds
//! (display-name rules, a patch without an update mask) are the strict profile's only.

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

const TENANTS: &str = "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants";
const PROJECT_NUMBER: u64 = 123_456_789_012;

fn state(strict: bool) -> AuthState {
    let mut store = AuthStore::new("demo-app", SplitMix64::new(5), TotpPolicy::default());
    if strict {
        store.set_project_number(Some(PROJECT_NUMBER));
    }
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

fn profiles() -> [(&'static str, AuthState); 2] {
    [("emulator", state(false)), ("strict", state(true))]
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

fn create(state: &AuthState, body: &Value) -> Value {
    let (status, created) = admin(state, "POST", TENANTS, body);
    assert_eq!(status, 200, "{body} -> {created}");
    created
}

fn id_of(document: &Value) -> String {
    document["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned()
}

fn keys(document: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = document
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

fn project_path(label: &str) -> String {
    if label == "strict" {
        PROJECT_NUMBER.to_string()
    } else {
        "demo-app".to_owned()
    }
}

#[test]
fn a_new_tenant_answers_only_what_was_written() {
    for (label, state) in profiles() {
        // manage#create-minimal, get-minimal.
        let created = create(&state, &json!({"displayName": "atb-man-min"}));
        assert_eq!(
            keys(&created),
            ["displayName", "inheritance", "name"],
            "{label}: {created}"
        );
        assert_eq!(created["displayName"], "atb-man-min");
        assert_eq!(created["inheritance"], json!({}));
        let id = id_of(&created);
        let suffix = id.strip_prefix("atb-man-min-").unwrap_or_default();
        assert!(
            suffix.len() == 5
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
            "{label}: {id}"
        );
        assert_eq!(
            created["name"],
            format!("projects/{}/tenants/{id}", project_path(label)),
            "{label}"
        );
        let (status, got) = admin(&state, "GET", &format!("{TENANTS}/{id}"), &json!({}));
        assert_eq!(status, 200);
        assert_eq!(
            keys(&got),
            ["displayName", "hashConfig", "inheritance", "name"],
            "{label}: {got}"
        );
        let hash = &got["hashConfig"];
        assert_eq!(hash["algorithm"], "SCRYPT");
        assert_eq!(hash["rounds"], 8);
        assert_eq!(hash["memoryCost"], 14);
        assert!(hash["signerKey"].is_string() && hash["saltSeparator"].is_string());
    }
}

#[test]
fn switches_appear_only_when_on_and_written_members_are_echoed() {
    for (label, state) in profiles() {
        // manage#create-open: a false disableAuth is left out.
        let open = create(
            &state,
            &json!({"displayName": "atb-man-open", "allowPasswordSignup": true,
                    "enableEmailLinkSignin": true, "enableAnonymousUser": true, "disableAuth": false}),
        );
        assert_eq!(
            keys(&open),
            [
                "allowPasswordSignup",
                "displayName",
                "enableAnonymousUser",
                "enableEmailLinkSignin",
                "inheritance",
                "name"
            ],
            "{label}: {open}"
        );
        // manage#create-mfa: the MFA config as written, without providers not sent.
        let mfa = create(
            &state,
            &json!({"displayName": "atb-man-mfa", "mfaConfig": {"state": "ENABLED",
                    "enabledProviders": ["PHONE_SMS"],
                    "providerConfigs": [{"state": "ENABLED", "totpProviderConfig": {"adjacentIntervals": 5}}]}}),
        );
        assert_eq!(
            mfa["mfaConfig"],
            json!({"state": "ENABLED", "enabledProviders": ["PHONE_SMS"],
                   "providerConfigs": [{"totpProviderConfig": {"adjacentIntervals": 5}, "state": "ENABLED"}]}),
            "{label}"
        );
        // manage#create-phones: test numbers echoed, an empty repeated field dropped.
        let phones = create(
            &state,
            &json!({"displayName": "atb-man-phones", "testPhoneNumbers": {"+16505550101": "123456"},
                    "smsRegionConfig": {"allowByDefault": {"disallowedRegions": []}}}),
        );
        assert_eq!(
            phones["testPhoneNumbers"],
            json!({"+16505550101": "123456"}),
            "{label}"
        );
        assert_eq!(
            phones["smsRegionConfig"],
            json!({"allowByDefault": {}}),
            "{label}"
        );
        // manage#create-settings: inheritance, monitoring, privacy and permissions echoed;
        // autodeleteAnonymousUsers accepted and not echoed.
        let settings = create(
            &state,
            &json!({"displayName": "atb-man-set", "inheritance": {"emailSendingConfig": true},
                    "monitoring": {"requestLogging": {"enabled": true}},
                    "emailPrivacyConfig": {"enableImprovedEmailPrivacy": true},
                    "client": {"permissions": {"disabledUserSignup": true, "disabledUserDeletion": true}},
                    "autodeleteAnonymousUsers": true}),
        );
        assert_eq!(
            settings["inheritance"],
            json!({"emailSendingConfig": true}),
            "{label}"
        );
        assert_eq!(
            settings["monitoring"],
            json!({"requestLogging": {"enabled": true}})
        );
        assert_eq!(
            settings["emailPrivacyConfig"],
            json!({"enableImprovedEmailPrivacy": true})
        );
        assert_eq!(
            settings["client"],
            json!({"permissions": {"disabledUserSignup": true, "disabledUserDeletion": true}})
        );
        assert!(
            settings.get("autodeleteAnonymousUsers").is_none(),
            "{label}: {settings}"
        );
        // manage#create-bad-type: a bool written as "yes" reads as true.
        let typed = create(
            &state,
            &json!({"displayName": "atb-man-type", "allowPasswordSignup": "yes"}),
        );
        assert_eq!(typed["allowPasswordSignup"], true, "{label}");
        // manage#create-policy: the written policy with its schema version and write time.
        let policy = create(
            &state,
            &json!({"displayName": "atb-man-policy", "passwordPolicyConfig": {
                "passwordPolicyEnforcementState": "ENFORCE",
                "passwordPolicyVersions": [{"customStrengthOptions": {"minPasswordLength": 8}}]}}),
        );
        let written = &policy["passwordPolicyConfig"];
        assert_eq!(
            written["passwordPolicyEnforcementState"], "ENFORCE",
            "{label}: {policy}"
        );
        assert_eq!(
            written["passwordPolicyVersions"],
            json!([{"customStrengthOptions": {"minPasswordLength": 8}, "schemaVersion": 1}]),
            "{label}: {policy}"
        );
        assert!(written["lastUpdateTime"].is_string(), "{label}: {policy}");
    }
}

#[test]
fn an_unknown_member_is_refused_with_production_message() {
    // manage#create-unknown-field.
    let strict = state(true);
    let (status, body) = admin(
        &strict,
        "POST",
        TENANTS,
        &json!({"displayName": "atb-man-x", "notAField": true}),
    );
    assert_eq!(status, 400);
    assert_eq!(
        body["error"]["message"],
        "Invalid JSON payload received. Unknown name \"notAField\" at 'tenant': Cannot find field.",
        "{body}"
    );
    assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
    // The official Auth emulator ignores an unknown member, at any depth; so does the
    // emulator profile (local measurement 2026-09-28).
    let emulator = state(false);
    let created = create(
        &emulator,
        &json!({"displayName": "atb-man-x", "notAField": true,
                "client": {"permissions": {"disabledUserSignup": true, "alsoUnknown": 1}}}),
    );
    assert_eq!(created["displayName"], "atb-man-x");
    assert_eq!(
        created["client"],
        json!({"permissions": {"disabledUserSignup": true}})
    );
    assert!(created.get("notAField").is_none());
}

#[test]
fn strict_refuses_display_names_production_refuses() {
    const INVALID: &str = "INVALID_DISPLAY_NAME : display_name should start with a letter and only consist of letters, digits and hyphens with 4-20 characters.";
    const MISSING: &str = "MISSING_DISPLAY_NAME : Missing tenant with valid display_name.";
    let strict = state(true);
    for name in ["atb", "1atb-name", "atb_name", "atb-abcdefghijklmnopq"] {
        let (status, body) = admin(&strict, "POST", TENANTS, &json!({"displayName": name}));
        assert_eq!(
            (status, body["error"]["message"].clone()),
            (400, json!(INVALID)),
            "{name}"
        );
    }
    let (status, body) = admin(&strict, "POST", TENANTS, &json!({}));
    assert_eq!(
        (status, body["error"]["message"].clone()),
        (400, json!(MISSING))
    );
    for name in ["Atb-Upper", "atbx", "a-bcdefghijklmnopqrs"] {
        let (status, body) = admin(&strict, "POST", TENANTS, &json!({"displayName": name}));
        assert_eq!(status, 200, "{name}: {body}");
    }
    // A patch is held to the same rule (manage#patch-bad-name), and one without an update
    // mask is a whole-resource replacement that needs a display name (manage#patch-no-mask).
    let id = id_of(&create(&strict, &json!({"displayName": "atb-man-min"})));
    let (status, body) = admin(
        &strict,
        "PATCH",
        &format!("{TENANTS}/{id}?updateMask=displayName"),
        &json!({"displayName": "1atb-bad"}),
    );
    assert_eq!(
        (status, body["error"]["message"].clone()),
        (400, json!(INVALID))
    );
    let (status, body) = admin(
        &strict,
        "PATCH",
        &format!("{TENANTS}/{id}"),
        &json!({"allowPasswordSignup": true}),
    );
    assert_eq!(
        (status, body["error"]["message"].clone()),
        (400, json!(MISSING))
    );
    // The emulator profile adds neither refusal.
    let emulator = state(false);
    let (status, _) = admin(&emulator, "POST", TENANTS, &json!({"displayName": "atb"}));
    assert_eq!(status, 200);
}

#[test]
fn a_patch_applies_exactly_its_mask() {
    for (label, state) in profiles() {
        let open = create(
            &state,
            &json!({"displayName": "atb-man-open", "allowPasswordSignup": true,
                    "enableEmailLinkSignin": true, "enableAnonymousUser": true}),
        );
        let id = id_of(&open);
        // manage#patch-mask-omitted-value: a masked member left out of the body is cleared.
        let (status, patched) = admin(
            &state,
            "PATCH",
            &format!("{TENANTS}/{id}?updateMask=enableAnonymousUser"),
            &json!({}),
        );
        assert_eq!(status, 200, "{label}: {patched}");
        assert!(
            patched.get("enableAnonymousUser").is_none(),
            "{label}: {patched}"
        );
        assert!(patched.get("hashConfig").is_none(), "{label}: {patched}");
        assert_eq!(patched["allowPasswordSignup"], true);
        // manage#patch-unknown-mask: an unknown mask path changes nothing and is no error.
        let (status, unchanged) = admin(
            &state,
            "PATCH",
            &format!("{TENANTS}/{id}?updateMask=notAField"),
            &json!({"displayName": "atb-x"}),
        );
        assert_eq!(status, 200, "{label}: {unchanged}");
        assert_eq!(unchanged["displayName"], "atb-man-open");
        // settings#privacy-off: a written message stays, empty, when its switch is cleared.
        let (status, privacy) = admin(
            &state,
            "PATCH",
            &format!("{TENANTS}/{id}?updateMask=emailPrivacyConfig.enableImprovedEmailPrivacy"),
            &json!({"emailPrivacyConfig": {"enableImprovedEmailPrivacy": false}}),
        );
        assert_eq!(status, 200);
        assert_eq!(
            privacy["emailPrivacyConfig"],
            json!({}),
            "{label}: {privacy}"
        );
        // mfa#tenant-m-mfa-off: the mfaConfig mask replaces the whole message.
        let (status, mfa) = admin(
            &state,
            "PATCH",
            &format!("{TENANTS}/{id}?updateMask=mfaConfig"),
            &json!({"mfaConfig": {"state": "DISABLED"}}),
        );
        assert_eq!(status, 200);
        assert_eq!(
            mfa["mfaConfig"],
            json!({"state": "DISABLED"}),
            "{label}: {mfa}"
        );
        // settings#tenant-test-phone: the testPhoneNumbers mask replaces the map.
        let (status, phones) = admin(
            &state,
            "PATCH",
            &format!("{TENANTS}/{id}?updateMask=testPhoneNumbers"),
            &json!({"testPhoneNumbers": {"+16505550102": "123456"}}),
        );
        assert_eq!(status, 200);
        assert_eq!(
            phones["testPhoneNumbers"],
            json!({"+16505550102": "123456"}),
            "{label}"
        );
    }
}

#[test]
fn the_tenant_list_is_ordered_by_id_and_pages_as_production_does() {
    for (label, state) in profiles() {
        // No tenant: an empty answer (manage#list-bad-token has the same shape).
        let (status, empty) = admin(&state, "GET", TENANTS, &json!({}));
        assert_eq!((status, empty.clone()), (200, json!({})), "{label}");
        let mut ids: Vec<String> = ["atb-b", "Atb-Upper", "atb-a", "atb-c"]
            .into_iter()
            .map(|name| id_of(&create(&state, &json!({"displayName": format!("{name}x")}))))
            .collect();
        ids.sort();
        let listed = |query: &str| {
            let (status, body) = admin(&state, "GET", &format!("{TENANTS}{query}"), &json!({}));
            assert_eq!(status, 200, "{label} {query}: {body}");
            body
        };
        let ids_of = |body: &Value| -> Vec<String> {
            body["tenants"]
                .as_array()
                .map(|tenants| tenants.iter().map(id_of).collect())
                .unwrap_or_default()
        };
        // manage#list-size-zero, -negative, -large: every tenant, no next page.
        for query in ["?pageSize=0", "?pageSize=-1", "?pageSize=1001", ""] {
            let body = listed(query);
            assert_eq!(ids_of(&body), ids, "{label} {query}");
            assert!(
                body.get("nextPageToken").is_none(),
                "{label} {query}: {body}"
            );
            assert!(body["tenants"][0].get("hashConfig").is_none());
        }
        // manage#list-page-1, -2.
        let first = listed("?pageSize=2");
        assert_eq!(ids_of(&first), ids[..2]);
        let token = first["nextPageToken"].as_str().unwrap().to_owned();
        let second = listed(&format!("?pageSize=2&pageToken={token}"));
        assert_eq!(ids_of(&second), ids[2..]);
        // manage#list-bad-token.
        assert_eq!(listed("?pageToken=not-a-token"), json!({}), "{label}");
    }
}

/// Tenant management answers in the Admin v2 error shape (`code`, `message`, `status`, no
/// `errors`), and with multi-tenancy off every tenant management call is INVALID_PROJECT_ID,
/// a read of a tenant id included (manage#get-unknown, switch-off#get-unknown-off).
#[test]
fn strict_tenant_management_errors_are_production_v2_errors() {
    let strict = state(true);
    let (status, body) = admin(
        &strict,
        "GET",
        &format!("{TENANTS}/atb-nosuch-tenant"),
        &json!({}),
    );
    assert_eq!(
        (status, body),
        (
            404,
            json!({"error": {"code": 404, "message": "TENANT_NOT_FOUND", "status": "NOT_FOUND"}})
        )
    );
    let id = id_of(&create(&strict, &json!({"displayName": "atb-man-min"})));
    let (status, _) = admin(&strict, "DELETE", &format!("{TENANTS}/{id}"), &json!({}));
    assert_eq!(status, 200);
    let (status, body) = admin(&strict, "DELETE", &format!("{TENANTS}/{id}"), &json!({}));
    assert_eq!(
        (status, body),
        (
            404,
            json!({"error": {"code": 404, "message": "TENANT_NOT_FOUND", "status": "NOT_FOUND"}})
        )
    );
    let (status, _) = admin(
        &strict,
        "PATCH",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=multiTenant.allowTenants",
        &json!({"multiTenant": {"allowTenants": false}}),
    );
    assert_eq!(status, 200);
    let off = json!({"error": {"code": 400, "message": "INVALID_PROJECT_ID", "status": "INVALID_ARGUMENT"}});
    for (method, path, body) in [
        ("GET", TENANTS.to_owned(), json!({})),
        ("GET", format!("{TENANTS}/atb-nosuch-tenant"), json!({})),
        (
            "POST",
            TENANTS.to_owned(),
            json!({"displayName": "atb-off"}),
        ),
    ] {
        let (status, answer) = admin(&strict, method, &path, &body);
        assert_eq!((status, answer), (400, off.clone()), "{method} {path}");
    }
}

/// An OIDC provider config under strict, as production answers it (providers program): the
/// project number in `name`, `responseType` with only its true members, `{}` for an empty
/// list, and CONFIGURATION_NOT_FOUND in the v2 shape for a config outside the addressed scope.
#[test]
fn strict_provider_configs_answer_as_production() {
    let strict = state(true);
    let a = id_of(&create(&strict, &json!({"displayName": "atb-prov-a"})));
    let b = id_of(&create(&strict, &json!({"displayName": "atb-prov-b"})));
    let configs = |tenant: &str| {
        format!(
            "/identitytoolkit.googleapis.com/v2/projects/demo-app/tenants/{tenant}/oauthIdpConfigs"
        )
    };
    let (status, created) = admin(
        &strict,
        "POST",
        &format!("{}?oauthIdpConfigId=oidc.atb-a", configs(&a)),
        &json!({"clientId": "atb-client", "issuer": "https://accounts.google.com",
                "displayName": "atb provider", "enabled": true, "responseType": {"idToken": true}}),
    );
    assert_eq!(status, 200, "{created}");
    let expected = json!({
        "name": format!("projects/{PROJECT_NUMBER}/tenants/{a}/oauthIdpConfigs/oidc.atb-a"),
        "clientId": "atb-client", "issuer": "https://accounts.google.com",
        "displayName": "atb provider", "enabled": true, "responseType": {"idToken": true},
    });
    assert_eq!(created, expected);
    let (status, got) = admin(
        &strict,
        "GET",
        &format!("{}/oidc.atb-a", configs(&a)),
        &json!({}),
    );
    assert_eq!((status, got), (200, expected.clone()));
    let (status, listed) = admin(&strict, "GET", &configs(&a), &json!({}));
    assert_eq!(
        (status, listed),
        (200, json!({"oauthIdpConfigs": [expected]}))
    );
    let (status, empty) = admin(&strict, "GET", &configs(&b), &json!({}));
    assert_eq!((status, empty), (200, json!({})));
    let missing = json!({"error": {"code": 404, "message": "CONFIGURATION_NOT_FOUND", "status": "NOT_FOUND"}});
    for method in ["GET", "DELETE"] {
        let (status, body) = admin(
            &strict,
            method,
            &format!("{}/oidc.atb-a", configs(&b)),
            &json!({}),
        );
        assert_eq!((status, body), (404, missing.clone()), "{method}");
    }
}
