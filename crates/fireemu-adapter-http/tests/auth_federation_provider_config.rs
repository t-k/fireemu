//! Provider configuration management as production answers it (AUTH-FEDERATION record-oidc,
//! run 39209e, `conformance/auth-federation-production.json`, programs
//! `auth-federation/provider-config/*`, `provider-enablement` and `third-party-refusals`).
//!
//! The strict profile answers the Admin v2 provider collections in production's shape: the
//! project named by number, false members left out (proto3 JSON), an empty list as `{}`,
//! v2 errors with production's messages, and the list of supported identity providers. The
//! emulator profile keeps the official emulator's answers.

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

const ADMIN: &str = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app";
const SUPPORTED: &str = "/identitytoolkit.googleapis.com/admin/v2/defaultSupportedIdps";
const PROJECT_NUMBER: u64 = 123_456_789_012;
const ISSUER: &str = "https://issuer.example.test/oidc/run";

fn state(strict: bool) -> AuthState {
    let mut store = AuthStore::new("demo-app", SplitMix64::new(5), TotpPolicy::default());
    if strict {
        store.set_project_number(Some(PROJECT_NUMBER));
    }
    let store = Arc::new(Mutex::new(store));
    let registry = Arc::new(AuthRegistry::new("demo-app", store.clone()));
    AuthState {
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
        idp_continuations: IdpContinuationPolicy::Disabled,
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
        allow_unsigned_custom_tokens: true,
        idp_assertions: fireemu_adapter_http::identity_toolkit::IdpAssertionPolicy::Fixture,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
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
    let r = handle_with(state, method, &format!("{ADMIN}/{path}"), &owner(), body);
    (r.status, r.body)
}

fn v2_error(code: u16, message: &str, status: &str) -> Value {
    json!({"error": {"code": code, "message": message, "status": status}})
}

fn saml_body(enabled: Option<bool>) -> Value {
    let mut body = json!({
        "idpConfig": {
            "idpEntityId": "https://demo-app.web.app/saml/run",
            "ssoUrl": "https://demo-app.web.app/saml/run/sso",
            "idpCertificates": [{"x509Certificate": "CERT"}],
        },
        "spConfig": {
            "spEntityId": "https://demo-app.firebaseapp.com/saml/run",
            "callbackUri": "https://demo-app.firebaseapp.com/__/auth/handler",
        },
    });
    if let Some(enabled) = enabled {
        body["enabled"] = json!(enabled);
    }
    body
}

fn saml_answer(id: &str, enabled: bool) -> Value {
    let mut answer = json!({
        "name": format!("projects/{PROJECT_NUMBER}/inboundSamlConfigs/{id}"),
        "idpConfig": {
            "idpEntityId": "https://demo-app.web.app/saml/run",
            "ssoUrl": "https://demo-app.web.app/saml/run/sso",
            "idpCertificates": [{"x509Certificate": "CERT"}],
        },
        "spConfig": {
            "spEntityId": "https://demo-app.firebaseapp.com/saml/run",
            "callbackUri": "https://demo-app.firebaseapp.com/__/auth/handler",
        },
    });
    if enabled {
        answer["enabled"] = json!(true);
    }
    answer
}

#[test]
fn strict_answers_saml_configs_in_productions_shape() {
    // provider-config/saml#create, create-bad-certificate, get.
    let s = state(true);
    let (status, created) = admin(
        &s,
        "POST",
        "inboundSamlConfigs?inboundSamlConfigId=saml.run-a",
        &saml_body(Some(true)),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(created, saml_answer("saml.run-a", true));
    let (status, disabled) = admin(
        &s,
        "POST",
        "inboundSamlConfigs?inboundSamlConfigId=saml.run-b",
        &saml_body(None),
    );
    assert_eq!(status, 200, "{disabled}");
    assert_eq!(disabled, saml_answer("saml.run-b", false));
    let (status, read) = admin(&s, "GET", "inboundSamlConfigs/saml.run-a", &Value::Null);
    assert_eq!(status, 200, "{read}");
    assert_eq!(read, saml_answer("saml.run-a", true));
    // A true signRequest is answered (provider-config/saml#patch-sign-request); production's SP
    // certificate that comes with it is not implemented.
    let (status, signing) = admin(
        &s,
        "PATCH",
        "inboundSamlConfigs/saml.run-b?updateMask=idpConfig.signRequest",
        &json!({"idpConfig": {"signRequest": true}}),
    );
    assert_eq!(status, 200, "{signing}");
    let mut expected = saml_answer("saml.run-b", false);
    expected["idpConfig"]["signRequest"] = json!(true);
    assert_eq!(signing, expected);
    let (status, unsigned) = admin(
        &s,
        "PATCH",
        "inboundSamlConfigs/saml.run-b?updateMask=idpConfig.signRequest",
        &json!({"idpConfig": {"signRequest": false}}),
    );
    assert_eq!((status, unsigned), (200, saml_answer("saml.run-b", false)));
    // Lists name the project by number too, and an empty one is `{}`, as for OIDC.
    let (status, listed) = admin(&s, "GET", "inboundSamlConfigs", &Value::Null);
    assert_eq!(status, 200, "{listed}");
    assert_eq!(
        listed,
        json!({"inboundSamlConfigs": [saml_answer("saml.run-a", true), saml_answer("saml.run-b", false)]})
    );
    for id in ["saml.run-a", "saml.run-b"] {
        let (status, deleted) = admin(
            &s,
            "DELETE",
            &format!("inboundSamlConfigs/{id}"),
            &Value::Null,
        );
        assert_eq!((status, deleted), (200, json!({})));
    }
    let (status, empty) = admin(&s, "GET", "inboundSamlConfigs", &Value::Null);
    assert_eq!((status, empty), (200, json!({})));
    let (status, missing) = admin(&s, "GET", "inboundSamlConfigs/saml.run-a", &Value::Null);
    assert_eq!(
        (status, missing),
        (404, v2_error(404, "CONFIGURATION_NOT_FOUND", "NOT_FOUND"))
    );
}

#[test]
fn the_emulator_profile_keeps_its_saml_config_answers() {
    let s = state(false);
    let (status, created) = admin(
        &s,
        "POST",
        "inboundSamlConfigs?inboundSamlConfigId=saml.run-b",
        &saml_body(None),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(
        created["name"],
        "projects/demo-app/inboundSamlConfigs/saml.run-b"
    );
    assert_eq!(created["enabled"], false);
    assert_eq!(created["idpConfig"]["signRequest"], false);
}

#[test]
fn strict_answers_default_supported_configs_in_productions_shape() {
    // provider-config/default-supported#list, create, get, patch-enabled, delete, get-deleted.
    let s = state(true);
    let name = format!("projects/{PROJECT_NUMBER}/defaultSupportedIdpConfigs/facebook.com");
    let (status, empty) = admin(&s, "GET", "defaultSupportedIdpConfigs", &Value::Null);
    assert_eq!((status, empty), (200, json!({})));
    let (status, created) = admin(
        &s,
        "POST",
        "defaultSupportedIdpConfigs?idpId=facebook.com",
        &json!({"enabled": false, "clientId": "fireemu-client", "clientSecret": "fireemu-secret"}),
    );
    assert_eq!(status, 200, "{created}");
    let disabled =
        json!({"name": name, "clientId": "fireemu-client", "clientSecret": "fireemu-secret"});
    assert_eq!(created, disabled);
    let (status, read) = admin(
        &s,
        "GET",
        "defaultSupportedIdpConfigs/facebook.com",
        &Value::Null,
    );
    assert_eq!((status, read), (200, disabled));
    let (status, enabled) = admin(
        &s,
        "PATCH",
        "defaultSupportedIdpConfigs/facebook.com?updateMask=enabled",
        &json!({"enabled": true}),
    );
    assert_eq!(status, 200, "{enabled}");
    assert_eq!(
        enabled,
        json!({"name": name, "enabled": true, "clientId": "fireemu-client", "clientSecret": "fireemu-secret"})
    );
    let (status, listed) = admin(&s, "GET", "defaultSupportedIdpConfigs", &Value::Null);
    assert_eq!(
        (status, listed),
        (200, json!({"defaultSupportedIdpConfigs": [enabled]}))
    );
    let (status, deleted) = admin(
        &s,
        "DELETE",
        "defaultSupportedIdpConfigs/facebook.com",
        &Value::Null,
    );
    assert_eq!((status, deleted), (200, json!({})));
    let (status, missing) = admin(
        &s,
        "GET",
        "defaultSupportedIdpConfigs/facebook.com",
        &Value::Null,
    );
    assert_eq!(
        (status, missing),
        (404, v2_error(404, "CONFIGURATION_NOT_FOUND", "NOT_FOUND"))
    );
}

#[test]
fn strict_lists_the_supported_identity_providers() {
    // provider-config/default-supported#list-supported.
    let s = state(true);
    let answer = handle_with(&s, "GET", SUPPORTED, &owner(), &Value::Null);
    assert_eq!(answer.status, 200, "{}", answer.body);
    let ids = [
        "apple.com",
        "facebook.com",
        "gc.apple.com",
        "github.com",
        "google.com",
        "linkedin.com",
        "microsoft.com",
        "playgames.google.com",
        "twitter.com",
        "yahoo.com",
    ];
    assert_eq!(
        answer.body,
        json!({"defaultSupportedIdps": ids.iter().map(|id| json!({"idpId": id})).collect::<Vec<_>>()})
    );
    // An Admin read: without a credential it is refused as the other Admin reads are.
    let anonymous = handle_with(
        &s,
        "GET",
        SUPPORTED,
        &RequestHeaders::default(),
        &Value::Null,
    );
    assert_ne!(anonymous.status, 200, "{}", anonymous.body);
    // The emulator profile does not serve it, as the official emulator does not.
    let emulator = handle_with(&state(false), "GET", SUPPORTED, &owner(), &Value::Null);
    assert_eq!(emulator.status, 404, "{}", emulator.body);
}

#[test]
fn strict_refuses_oidc_configs_with_productions_messages() {
    // provider-config/oidc#create-duplicate, create-without-prefix, create-without-client,
    // create-both-responses, create-code-without-secret, create-http-issuer.
    let s = state(true);
    let create = |id: &str, body: Value| {
        admin(
            &s,
            "POST",
            &format!("oauthIdpConfigs?oauthIdpConfigId={id}"),
            &body,
        )
    };
    let (status, created) = create(
        "oidc.run-a",
        json!({"clientId": "client-a", "issuer": ISSUER}),
    );
    assert_eq!(status, 200, "{created}");
    let invalid = "INVALID_ARGUMENT";
    for (case, id, body, code, message, status) in [
        (
            "duplicate",
            "oidc.run-a",
            json!({"clientId": "client-a", "issuer": ISSUER}),
            409,
            "CONFIGURATION_EXISTS : The OAuthIdpConfig already exists with config_id: oidc.run-a",
            "ALREADY_EXISTS",
        ),
        (
            "without prefix",
            "run-noprefix",
            json!({"clientId": "c", "issuer": ISSUER}),
            400,
            "INVALID_CONFIG_ID : Oauth_idp_config_id must start with 'oidc.' and can only have alphanumeric characters, hyphens, underscores or periods. The part after 'oidc.' must also start with a lowercase letter, end with an alphanumeric character, and have at least 2 characters.",
            invalid,
        ),
        (
            "without client",
            "oidc.run-b",
            json!({"issuer": ISSUER}),
            400,
            "MISSING_OAUTH_CLIENT_ID : Client_id in OAuthIdpConfig cannot be empty.",
            invalid,
        ),
        (
            "both responses",
            "oidc.run-b",
            json!({"clientId": "c", "issuer": ISSUER, "responseType": {"idToken": true, "code": true}}),
            400,
            "INVALID_CONFIG : response_type should have exactly one of 'idToken' and 'code' being true. Setting both types to be true ('{code: true, idToken: true}') is not yet supported.",
            invalid,
        ),
        (
            "code without secret",
            "oidc.run-b",
            json!({"clientId": "c", "issuer": ISSUER, "responseType": {"code": true}}),
            400,
            "INVALID_CONFIG : client_secret cannot be empty for code flow.",
            invalid,
        ),
        (
            "http issuer",
            "oidc.run-b",
            json!({"clientId": "c", "issuer": "http://demo-app.web.app/oidc/run"}),
            400,
            "INVALID_ISSUER : Issuer in OAuthIdpConfig should be a valid URL.",
            invalid,
        ),
    ] {
        let (answered, body) = create(id, body);
        assert_eq!(
            (answered, body),
            (code, v2_error(code, message, status)),
            "{case}"
        );
    }
    // Nothing but the first was created.
    let (status, listed) = admin(&s, "GET", "oauthIdpConfigs", &Value::Null);
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["oauthIdpConfigs"].as_array().map(Vec::len), Some(1));
}

#[test]
fn the_emulator_profile_keeps_its_oidc_create_answers() {
    // No refusal the official emulator lacks: an http issuer is accepted there.
    let s = state(false);
    let (status, created) = admin(
        &s,
        "POST",
        "oauthIdpConfigs?oauthIdpConfigId=oidc.run-b",
        &json!({"clientId": "c", "issuer": "http://demo-app.web.app/oidc/run"}),
    );
    assert_eq!(status, 200, "{created}");
    let (status, duplicate) = admin(
        &s,
        "POST",
        "oauthIdpConfigs?oauthIdpConfigId=oidc.run-b",
        &json!({"clientId": "c", "issuer": ISSUER}),
    );
    assert_eq!(status, 409, "{duplicate}");
    assert_eq!(duplicate["error"]["message"], "ALREADY_EXISTS");
}

#[test]
fn strict_leaves_a_disabled_oidc_config_without_enabled() {
    // provider-enablement#disable, third-party-refusals#create-disabled.
    let s = state(true);
    let (status, created) = admin(
        &s,
        "POST",
        "oauthIdpConfigs?oauthIdpConfigId=oidc.run-off",
        &json!({"clientId": "client-off", "issuer": ISSUER}),
    );
    assert_eq!(status, 200, "{created}");
    assert!(created.get("enabled").is_none(), "{created}");
    let (status, enabled) = admin(
        &s,
        "PATCH",
        "oauthIdpConfigs/oidc.run-off?updateMask=enabled",
        &json!({"enabled": true}),
    );
    assert_eq!(status, 200, "{enabled}");
    assert_eq!(enabled["enabled"], true);
    let (status, disabled) = admin(
        &s,
        "PATCH",
        "oauthIdpConfigs/oidc.run-off?updateMask=enabled",
        &json!({"enabled": false}),
    );
    assert_eq!(status, 200, "{disabled}");
    assert_eq!(
        disabled,
        json!({
            "name": format!("projects/{PROJECT_NUMBER}/oauthIdpConfigs/oidc.run-off"),
            "clientId": "client-off",
            "issuer": ISSUER,
            "responseType": {"idToken": true},
        })
    );
}

#[test]
fn canonical_provider_seeds_have_the_same_acceptance_and_errors_as_admin_create() {
    use fireemu_adapter_http::identity_toolkit::provider_config_seeds;
    for strict in [false, true] {
        let oidc = json!({"clientId":"client", "issuer":"https://issuer.test"});
        let mut cases = vec![
            ("oidc", "oidc.fixture", oidc.clone()),
            ("saml", "saml.fixture", saml_body(Some(true))),
        ];
        for patch in [
            json!({"issuer":"http://issuer.test"}),
            json!({"clientId":""}),
            json!({"enabled":null}),
            json!({"responseType":{"idToken":true,"code":true}}),
            json!({"responseType":{"code":true}}),
            json!({"responseType":{"code":true},"clientSecret":"test-secret"}),
            json!({"responseType":{"token":true}}),
        ] {
            let mut body = oidc.clone();
            for (key, value) in patch.as_object().unwrap() {
                body[key] = value.clone();
            }
            cases.push(("oidc", "oidc.fixture", body));
        }
        cases.extend([
            (
                "oidc",
                "oidc.x&oauthIdpConfigId=oidc.injected",
                oidc.clone(),
            ),
            ("oidc", "wrong.fixture", oidc),
            (
                "saml",
                "saml.fixture",
                json!({"idpConfig":{},"spConfig":{}}),
            ),
        ]);
        for (kind, id, mut body) in cases {
            let s = state(strict);
            let (collection, query) = if kind == "oidc" {
                ("oauthIdpConfigs", "oauthIdpConfigId")
            } else {
                ("inboundSamlConfigs", "inboundSamlConfigId")
            };
            let safe_id = id.replace('&', "%26").replace('=', "%3D");
            let (status, answer) = admin(
                &s,
                "POST",
                &format!("{collection}?{query}={safe_id}"),
                &body,
            );
            body["name"] = json!(id);
            let input = if kind == "oidc" {
                json!({"oidc":[body]})
            } else {
                json!({"saml":[body]})
            };
            let parsed = provider_config_seeds(&input, strict);
            if status == 200 {
                let declaration = parsed.unwrap();
                let store = s.store.lock().unwrap();
                if kind == "oidc" {
                    assert_eq!(
                        declaration.oidc,
                        Some(store.oidc_configs().cloned().collect())
                    );
                } else {
                    assert_eq!(
                        declaration.saml,
                        Some(store.saml_configs().cloned().collect())
                    );
                }
            } else {
                let error = parsed.unwrap_err();
                assert!(
                    error.contains(answer["error"]["message"].as_str().unwrap()),
                    "profile={strict} id={id}: {error} versus {answer}"
                );
            }
        }
    }
}
