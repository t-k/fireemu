//! The strict profile with fixture assertions (`auth.idpAssertions: "fixture"`, the development
//! default) still applies the provider configuration checks production applies before it reads
//! an assertion: an `oidc.*` or `saml.*` provider that has no configuration, or is disabled, is
//! refused with production's recorded answers (AUTH-FEDERATION record-oidc 39209e and
//! record-saml 7789f0). Only the signature check is skipped, which needs no setup to skip. A
//! built-in provider keeps signing in without a console configuration (documented development
//! default), and the emulator profile keeps accepting every provider, as the official emulator
//! does.

use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthQueryLimits, AuthState, ClientApiKeyPolicy, FakeCustomTokenExpiry,
    IdpAssertionPolicy, IdpContinuationPolicy, JsonResponse, RequestHeaders,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{
    AuthRegistry, AuthStore, InboundSamlProviderConfig, OAuthResponseType, OidcProviderConfig,
};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
// Production's refusals (AUTH-FEDERATION record-oidc 39209e, record-saml 7789f0).
const NOT_FOUND: &str = "OPERATION_NOT_ALLOWED : The identity provider configuration is not found.";
const DISABLED: &str = "OPERATION_NOT_ALLOWED : The identity provider configuration is disabled.";

fn state(strict: bool) -> AuthState {
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
        stateless_refresh_tokens: !strict,
        idp_continuations: IdpContinuationPolicy::Disabled,
        query_limits: AuthQueryLimits::EmulatorUnbounded,
        client_api_key: ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry: FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
        allow_unsigned_custom_tokens: true,
        idp_assertions: IdpAssertionPolicy::Fixture,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    }
}

fn add_oidc(state: &AuthState, id: &str, enabled: bool) {
    assert!(state
        .store
        .lock()
        .unwrap()
        .create_oidc_config(OidcProviderConfig {
            id: id.into(),
            display_name: None,
            enabled,
            client_id: "client".into(),
            issuer: "https://issuer.example.test".into(),
            client_secret: None,
            response_type: OAuthResponseType {
                id_token: true,
                code: false,
                token: false,
            },
        }));
}

fn add_saml(state: &AuthState, id: &str, enabled: bool) {
    assert!(state
        .store
        .lock()
        .unwrap()
        .create_saml_config(InboundSamlProviderConfig {
            id: id.into(),
            display_name: None,
            enabled,
            idp_entity_id: "https://idp.example.test".into(),
            sso_url: "https://idp.example.test/sso".into(),
            idp_certificates: Vec::new(),
            sign_request: false,
            sp_entity_id: "sp".into(),
            callback_uri: "https://sp.example.test/callback".into(),
        }));
}

/// The fixture `IdP`'s credential: a JSON ID token, which the official emulator accepts. A
/// JSON `SAMLResponse` rides along for a `saml.*` provider, as the fixture parser requires one.
fn fixture_request(provider: &str) -> Value {
    let saml = if provider.to_ascii_lowercase().starts_with("saml.") {
        "&SAMLResponse={\"assertion\":{\"subject\":{\"nameId\":\"person@saml.example.test\"}}}"
    } else {
        ""
    };
    json!({
        "requestUri": "http://localhost",
        "postBody": format!(
            "providerId={provider}&id_token={}{saml}",
            json!({"sub": "fixture-subject", "email": "fixture@example.test"})
        ),
        "returnSecureToken": true,
    })
}

fn sign_in(state: &AuthState, provider: &str) -> JsonResponse {
    handle(
        state,
        "POST",
        &format!("{V1}/accounts:signInWithIdp"),
        &fixture_request(provider),
    )
}

fn users(state: &AuthState) -> usize {
    state.store.lock().unwrap().user_count()
}

fn assert_refused(state: &AuthState, provider: &str, message: &str) {
    let response = sign_in(state, provider);
    assert_eq!(response.status, 400, "{provider}: {}", response.body);
    assert_eq!(response.body["error"]["message"], message, "{provider}");
    assert!(response.body.get("idToken").is_none(), "{provider}");
    assert_eq!(users(state), 0, "{provider}: a refusal creates no account");
}

#[test]
fn strict_refuses_an_unconfigured_oidc_or_saml_provider_under_fixture_assertions() {
    let s = state(true);
    for provider in ["oidc.typo", "oidc.unconfigured", "saml.unconfigured"] {
        assert_refused(&s, provider, NOT_FOUND);
    }
}

#[test]
fn strict_refuses_a_disabled_oidc_or_saml_provider_under_fixture_assertions() {
    let s = state(true);
    add_oidc(&s, "oidc.off", false);
    add_saml(&s, "saml.off", false);
    for provider in ["oidc.off", "saml.off"] {
        assert_refused(&s, provider, DISABLED);
    }
}

#[test]
fn strict_signs_in_through_a_configured_enabled_provider_with_a_fixture_assertion() {
    let s = state(true);
    add_oidc(&s, "oidc.on", true);
    add_saml(&s, "saml.on", true);
    for provider in ["oidc.on", "saml.on"] {
        let response = sign_in(&s, provider);
        assert_eq!(response.status, 200, "{provider}: {}", response.body);
        assert!(response.body["idToken"].is_string(), "{provider}");
    }
    assert_eq!(users(&s), 2);
}

#[test]
fn a_provider_name_in_another_case_is_not_the_configured_provider() {
    // The credential parser lowercases the provider, so production's configuration lookup, which
    // is case-sensitive, does not find it (the same recorded answer the signed path gives).
    let s = state(true);
    add_oidc(&s, "oidc.on", true);
    add_saml(&s, "saml.on", true);
    for provider in ["OIDC.on", "Oidc.on", "SAML.on", "Saml.on"] {
        assert_refused(&s, provider, NOT_FOUND);
    }
}

#[test]
fn a_configuration_removed_or_disabled_later_refuses_the_next_sign_in() {
    let s = state(true);
    add_oidc(&s, "oidc.live", true);
    assert_eq!(sign_in(&s, "oidc.live").status, 200);
    {
        let mut store = s.store.lock().unwrap();
        assert!(store.delete_oidc_config("oidc.live"));
    }
    let response = sign_in(&s, "oidc.live");
    assert_eq!(response.status, 400);
    assert_eq!(response.body["error"]["message"], NOT_FOUND);
}

#[test]
fn a_built_in_provider_signs_in_without_a_console_configuration() {
    // Documented development default (profiles.md): production needs the provider enabled in the
    // console; a test should not have to say so.
    let s = state(true);
    for provider in [
        "google.com",
        "facebook.com",
        "github.com",
        "apple.com",
        "custom.example",
    ] {
        let response = sign_in(&s, provider);
        assert_eq!(response.status, 200, "{provider}: {}", response.body);
    }
}

#[test]
fn the_emulator_profile_accepts_every_provider_as_the_official_emulator_does() {
    let s = state(false);
    add_oidc(&s, "oidc.off", false);
    for provider in [
        "oidc.unconfigured",
        "oidc.off",
        "saml.unconfigured",
        "google.com",
    ] {
        let response = sign_in(&s, provider);
        assert_eq!(response.status, 200, "{provider}: {}", response.body);
    }
}

fn provider_id() -> impl Strategy<Value = String> {
    (
        prop_oneof![
            Just("oidc."),
            Just("saml."),
            Just("OIDC."),
            Just("Saml."),
            Just("")
        ],
        "[a-z][a-z0-9._-]{0,12}",
    )
        .prop_map(|(prefix, rest)| format!("{prefix}{rest}"))
}

proptest! {
    /// Whatever the provider id, strict refuses exactly the `oidc.*`/`saml.*` ids that are not
    /// configured and enabled with the exact spelling, and creates no account when it refuses.
    #[test]
    fn strict_fixture_sign_in_follows_the_configuration_for_every_provider_id(
        id in provider_id(),
        configured in prop_oneof![Just(None), Just(Some(true)), Just(Some(false))],
    ) {
        let s = state(true);
        let federated = id.to_ascii_lowercase().starts_with("oidc.")
            || id.to_ascii_lowercase().starts_with("saml.");
        if let Some(enabled) = configured {
            if id.starts_with("oidc.") {
                add_oidc(&s, &id, enabled);
            } else if id.starts_with("saml.") {
                add_saml(&s, &id, enabled);
            }
        }
        let exact = id.starts_with("oidc.") || id.starts_with("saml.");
        let expected = if !federated {
            None
        } else if !exact || configured.is_none() {
            Some(NOT_FOUND)
        } else if configured == Some(false) {
            Some(DISABLED)
        } else {
            None
        };
        let response = sign_in(&s, &id);
        match expected {
            Some(message) => {
                prop_assert_eq!(response.status, 400, "{}", response.body);
                prop_assert_eq!(response.body["error"]["message"].as_str(), Some(message));
                prop_assert_eq!(users(&s), 0);
            }
            None => {
                prop_assert_eq!(response.status, 200, "{}", response.body);
            }
        }
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

/// A strict state with a registry, a tenant, and the project allowing tenants.
fn tenant_state() -> (AuthState, Arc<AuthRegistry>, &'static str) {
    const TENANT: &str = "acme-x7k2q";
    let mut s = state(true);
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    registry.ensure_tenant("demo-app", TENANT).unwrap();
    s.registry = Some(registry.clone());
    let r = handle_with(
        &s,
        "PATCH",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=multiTenant.allowTenants",
        &owner(),
        &json!({"multiTenant": {"allowTenants": true}}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    (s, registry, TENANT)
}

fn oidc_config(id: &str, enabled: bool) -> OidcProviderConfig {
    OidcProviderConfig {
        id: id.into(),
        display_name: None,
        enabled,
        client_id: "client".into(),
        issuer: "https://issuer.example.test".into(),
        client_secret: None,
        response_type: OAuthResponseType {
            id_token: true,
            code: false,
            token: false,
        },
    }
}

#[test]
fn a_tenant_sign_in_needs_the_provider_configured_in_the_tenant() {
    let (s, registry, tenant) = tenant_state();
    let tenant_sign_in = |provider: &str| {
        let mut body = fixture_request(provider);
        body["tenantId"] = json!(tenant);
        handle(&s, "POST", &format!("{V1}/accounts:signInWithIdp"), &body)
    };
    // A provider the project has is not the tenant's.
    add_oidc(&s, "oidc.project-only", true);
    let refused = tenant_sign_in("oidc.project-only");
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert_eq!(refused.body["error"]["message"], NOT_FOUND);
    // A provider only the tenant has signs in there and is unknown to the project.
    assert!(registry
        .tenant_store("demo-app", tenant)
        .unwrap()
        .lock()
        .unwrap()
        .create_oidc_config(oidc_config("oidc.tenant-only", true)));
    let accepted = tenant_sign_in("oidc.tenant-only");
    assert_eq!(accepted.status, 200, "{}", accepted.body);
    assert_refused(&s, "oidc.tenant-only", NOT_FOUND);
    // Disabled in the tenant: refused there.
    assert!(registry
        .tenant_store("demo-app", tenant)
        .unwrap()
        .lock()
        .unwrap()
        .replace_oidc_config(oidc_config("oidc.tenant-only", false)));
    let refused = tenant_sign_in("oidc.tenant-only");
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert_eq!(refused.body["error"]["message"], DISABLED);
}

#[test]
fn a_resumed_pending_token_meets_the_provider_as_it_is_now() {
    let mut s = state(true);
    s.idp_continuations = IdpContinuationPolicy::LocalBounded;
    add_oidc(&s, "oidc.live", true);
    let request = fixture_request("oidc.live");
    let first = handle(
        &s,
        "POST",
        &format!("{V1}/accounts:signInWithIdp"),
        &request,
    );
    assert_eq!(first.status, 200, "{}", first.body);
    let token = first.body["pendingToken"]
        .as_str()
        .expect("a strict continuation")
        .to_owned();
    let resume = json!({"requestUri": request["requestUri"], "pendingToken": token, "returnSecureToken": true});
    // Resumed while the provider is as it was: accepted.
    let again = handle(&s, "POST", &format!("{V1}/accounts:signInWithIdp"), &resume);
    assert_eq!(again.status, 200, "{}", again.body);
    let users = users(&s);
    // Disabled since: the check runs on the resumed credential.
    assert!(s
        .store
        .lock()
        .unwrap()
        .replace_oidc_config(oidc_config("oidc.live", false)));
    let refused = handle(&s, "POST", &format!("{V1}/accounts:signInWithIdp"), &resume);
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert_eq!(refused.body["error"]["message"], DISABLED);
    // Deleted since: not found.
    assert!(s.store.lock().unwrap().delete_oidc_config("oidc.live"));
    let refused = handle(&s, "POST", &format!("{V1}/accounts:signInWithIdp"), &resume);
    assert_eq!(refused.status, 400, "{}", refused.body);
    assert_eq!(refused.body["error"]["message"], NOT_FOUND);
    assert_eq!(
        self::users(&s),
        users,
        "a refused resume creates no account"
    );
}

#[test]
fn the_check_and_the_credential_parser_read_the_provider_from_the_same_place() {
    // The parser takes `providerId` from the merged request URI query, post body and fragment;
    // the configuration check must judge the provider the parser will use, whichever carries it.
    let s = state(true);
    add_oidc(&s, "oidc.on", true);
    add_oidc(&s, "oidc.off", false);
    let claims = json!({"sub": "conflict-subject", "email": "conflict@example.test"}).to_string();
    let enc = |text: &str| {
        text.replace('{', "%7B")
            .replace('}', "%7D")
            .replace('"', "%22")
            .replace(' ', "%20")
    };
    let sign_in = |request_uri: &str, post_body: &str| {
        handle(
            &s,
            "POST",
            &format!("{V1}/accounts:signInWithIdp"),
            &json!({"requestUri": request_uri, "postBody": post_body, "returnSecureToken": true}),
        )
    };
    let id_token = format!("id_token={}", enc(&claims));
    for (request_uri, post_body) in [
        // The post body names the disabled provider while the URI names an enabled one, and the
        // reverse, and the fragment form of each.
        (
            "http://localhost?providerId=oidc.on".to_owned(),
            format!("providerId=oidc.off&{id_token}"),
        ),
        (
            "http://localhost?providerId=oidc.on#providerId=oidc.off".to_owned(),
            id_token.clone(),
        ),
    ] {
        let response = sign_in(&request_uri, &post_body);
        let used = response.body["providerId"].as_str().map(str::to_owned);
        match response.status {
            400 => assert_eq!(
                response.body["error"]["message"], DISABLED,
                "{request_uri} {post_body}"
            ),
            200 => assert_eq!(
                used.as_deref(),
                Some("oidc.on"),
                "{request_uri} {post_body}"
            ),
            other => panic!("{other}: {}", response.body),
        }
        // Whatever the parser picked, a sign-in never succeeds through the disabled provider.
        assert_ne!(
            used.as_deref(),
            Some("oidc.off"),
            "{request_uri} {post_body}"
        );
    }
    // And an enabled provider named only in the body still signs in.
    let ok = sign_in(
        "http://localhost",
        &format!("providerId=oidc.on&{id_token}"),
    );
    assert_eq!(ok.status, 200, "{}", ok.body);
}
