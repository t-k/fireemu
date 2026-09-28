//! The strict profile verifies signed OIDC ID tokens with the issuer keys given at startup
//! (`auth.idpSigners`, owner decision O4 of AUTH-FEDERATION) and refuses the unsigned fixture
//! `IdP`; the emulator profile keeps the fixture. No key is fetched from an issuer.
use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthState, IdpAssertionPolicy, IdpContinuationPolicy, IdpSignerTrust,
    JsonResponse, RequestHeaders,
};
use fireemu_adapter_http::signing::RsaSigner;
use fireemu_core_auth::jwt::encode_payload_with;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{
    AuthRegistry, AuthStore, OAuthResponseType, OidcProviderConfig, UserRecord,
};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, OnceLock};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const NOW: i64 = 1_788_004_860;
const ISSUER: &str = "https://issuer.example.test/oidc/run";
const PROVIDER: &str = "oidc.strict";
const CLIENT: &str = "strict-client";
// Production's refusals (AUTH-FEDERATION record-oidc, run 39209e, 2026-09-28).
const SIGNATURE: &str = "INVALID_IDP_RESPONSE : Unable to verify the ID Token signature.";
const UNPARSABLE: &str = "INVALID_IDP_RESPONSE : Unable to parse the ID Token.";
const NOT_FOUND: &str = "OPERATION_NOT_ALLOWED : The identity provider configuration is not found.";
const DISABLED: &str = "OPERATION_NOT_ALLOWED : The identity provider configuration is disabled.";
const UNREACHABLE: &str =
    "INVALID_IDP_RESPONSE : Error connecting to the given credential's issuer.";
const NONCE_MISSING: &str = "MISSING_OR_INVALID_NONCE : Nonce is missing in the request.";
const DUPLICATE: &str =
    "MISSING_OR_INVALID_NONCE : Duplicate credential received. Please try again with a new credential.";
/// Refusals whose production message is unobserved.
const UNOBSERVED: &str = "INVALID_IDP_RESPONSE";

fn stale(iat: i64) -> String {
    format!("INVALID_IDP_RESPONSE : ID Token issued at {iat} is stale to sign-in.")
}

// Public deterministic test fixtures only; these seeds are not deployment signing keys.
fn signer() -> &'static Arc<RsaSigner> {
    static SIGNER: OnceLock<Arc<RsaSigner>> = OnceLock::new();
    SIGNER.get_or_init(|| RsaSigner::from_seed(4401).unwrap())
}
fn other_signer() -> &'static Arc<RsaSigner> {
    static SIGNER: OnceLock<Arc<RsaSigner>> = OnceLock::new();
    SIGNER.get_or_init(|| RsaSigner::from_seed(4402).unwrap())
}

fn signers(issuer: &str, keys: Value) -> Arc<IdpSignerTrust> {
    let mut map = serde_json::Map::new();
    map.insert(issuer.to_owned(), keys);
    Arc::new(IdpSignerTrust::from_jwks(&map).unwrap())
}

fn provider(enabled: bool, issuer: &str) -> OidcProviderConfig {
    OidcProviderConfig {
        id: PROVIDER.into(),
        display_name: None,
        enabled,
        client_id: CLIENT.into(),
        issuer: issuer.into(),
        client_secret: None,
        response_type: OAuthResponseType {
            id_token: true,
            code: false,
            token: false,
        },
    }
}

fn new_store() -> AuthStore {
    AuthStore::new("demo-app", SplitMix64::new(5), TotpPolicy::default())
}

/// A strict daemon state (stateful refresh sessions) with the run issuer's signer configured.
fn strict_state() -> AuthState {
    let s = AuthState {
        store: Arc::new(Mutex::new(new_store())),
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(NOW),
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
        stateless_refresh_tokens: false,
        idp_continuations: IdpContinuationPolicy::Disabled,
        query_limits: fireemu_adapter_http::identity_toolkit::AuthQueryLimits::EmulatorUnbounded,
        client_api_key: fireemu_adapter_http::identity_toolkit::ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
        idp_assertions: IdpAssertionPolicy::SignedOidc(signers(ISSUER, signer().jwks())),
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };
    assert!(s
        .store
        .lock()
        .unwrap()
        .create_oidc_config(provider(true, ISSUER)));
    s
}

fn claims() -> Value {
    json!({"sub": "strict-subject", "iss": ISSUER, "aud": CLIENT, "iat": NOW, "exp": NOW + 60})
}

fn token_by(signer: &RsaSigner, claims: &Value) -> String {
    encode_payload_with(&claims.to_string(), Some(signer))
}

fn token(claims: &Value) -> String {
    token_by(signer(), claims)
}

fn request_for(provider: &str, token: &str) -> Value {
    json!({
        "requestUri": "http://localhost",
        "postBody": format!("providerId={provider}&id_token={token}"),
        "returnSecureToken": true,
    })
}

fn request(token: &str) -> Value {
    request_for(PROVIDER, token)
}

fn sign_in(s: &AuthState, body: &Value) -> JsonResponse {
    handle(s, "POST", &format!("{V1}/accounts:signInWithIdp"), body)
}

fn assert_refused(s: &AuthState, body: &Value, message: &str, case: &str) {
    let response = sign_in(s, body);
    assert_eq!(response.status, 400, "{case}: {}", response.body);
    assert_eq!(response.body["error"]["message"], message, "{case}");
    assert!(response.body.get("idToken").is_none(), "{case}");
    assert!(response.body.get("pendingToken").is_none(), "{case}");
    let store = s.store.lock().unwrap();
    assert_eq!(store.user_count(), 0, "{case}");
    assert_eq!(store.pending_idp_count(), 0, "{case}");
}

/// The fixture `IdP`'s unsigned forms: a JSON credential and an unsigned JWT.
fn fixture_requests(provider: &str) -> Vec<Value> {
    let unsigned = encode_payload_with(&claims().to_string(), None);
    vec![
        request_for(provider, &unsigned),
        json!({
            "requestUri": "http://localhost",
            "postBody": format!(
                "providerId={provider}&id_token={}",
                json!({"sub": "strict-subject", "email": "fixture@example.test"})
            ),
            "returnSecureToken": true,
        }),
    ]
}

#[test]
fn strict_signs_in_with_a_token_the_configured_issuer_key_verifies() {
    let s = strict_state();
    let first = sign_in(&s, &request(&token(&claims())));
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(first.body["isNewUser"], true);
    assert_eq!(first.body["providerId"], PROVIDER);
    let second = sign_in(&s, &request(&token(&claims())));
    assert_eq!(second.status, 200, "{}", second.body);
    // Production leaves `isNewUser` out when it is false (record-oidc 39209e).
    assert!(second.body.get("isNewUser").is_none(), "{}", second.body);
    assert_eq!(second.body["localId"], first.body["localId"]);
    assert!(s
        .store
        .lock()
        .unwrap()
        .user_by_federated(PROVIDER, "strict-subject")
        .is_some());
}

#[test]
fn strict_refuses_the_unsigned_fixture_idp() {
    let s = strict_state();
    let [unsigned, json_credential] = fixture_requests(PROVIDER).try_into().unwrap();
    assert_refused(&s, &unsigned, SIGNATURE, "an unsigned JWT");
    assert_refused(&s, &json_credential, UNPARSABLE, "a JSON credential");
}

#[test]
fn strict_without_signers_refuses_every_idp_sign_in() {
    let mut s = strict_state();
    s.idp_assertions = IdpAssertionPolicy::SignedOidc(Arc::new(IdpSignerTrust::default()));
    assert_refused(
        &s,
        &request(&token(&claims())),
        UNREACHABLE,
        "signed without signers",
    );
    let [unsigned, json_credential] = fixture_requests(PROVIDER).try_into().unwrap();
    assert_refused(&s, &unsigned, UNREACHABLE, "unsigned without signers");
    assert_refused(&s, &json_credential, UNREACHABLE, "JSON without signers");
    // The Emulator UI proxy's entry point is gated the same way.
    let response = handle_with(
        &s,
        "POST",
        &format!("{V1}/accounts:signInWithIdp"),
        &RequestHeaders::default(),
        &request(&token(&claims())),
    );
    assert_eq!(response.status, 400);
    assert_eq!(s.store.lock().unwrap().user_count(), 0);
}

#[test]
fn strict_refuses_tokens_the_configured_keys_do_not_verify() {
    let s = strict_state();
    let mut wrong_iss = claims();
    wrong_iss["iss"] = json!("https://other.example.test/oidc/run");
    let mut wrong_aud = claims();
    wrong_aud["aud"] = json!("other-client");
    let mut expired = claims();
    expired["exp"] = json!(NOW);
    let mut future = claims();
    future["iat"] = json!(NOW + 1);
    future["exp"] = json!(NOW + 61);
    let mut empty_sub = claims();
    empty_sub["sub"] = json!("");
    let mut bad_signature = token(&claims());
    let start = bad_signature.rfind('.').unwrap() + 1;
    let replacement = if &bad_signature[start..=start] == "A" {
        "B"
    } else {
        "A"
    };
    bad_signature.replace_range(start..=start, replacement);
    let cases = [
        (
            "other key",
            request(&token_by(other_signer(), &claims())),
            SIGNATURE.to_owned(),
        ),
        ("bad signature", request(&bad_signature), SIGNATURE.to_owned()),
        (
            "wrong iss",
            request(&token(&wrong_iss)),
            format!("INVALID_IDP_RESPONSE : The issuer in ID Token https://other.example.test/oidc/run does not match the expected one in config: {ISSUER}."),
        ),
        (
            "wrong aud",
            request(&token(&wrong_aud)),
            format!("INVALID_IDP_RESPONSE : The audience in ID Token [other-client] does not match the expected audience {CLIENT}."),
        ),
        ("expired", request(&token(&expired)), stale(NOW)),
        ("issued in the future", request(&token(&future)), stale(NOW + 1)),
        (
            "empty sub",
            request(&token(&empty_sub)),
            format!("INVALID_IDP_RESPONSE : ID Token does not contain user's identity in 'sub' claim: {}", json!({"aud": CLIENT, "exp": NOW + 60, "iat": NOW, "iss": ISSUER, "sub": ""})),
        ),
        (
            "access token alongside",
            json!({
                "requestUri": "http://localhost",
                "postBody": format!(
                    "providerId={PROVIDER}&id_token={}&access_token=at",
                    token(&claims())
                ),
                "returnSecureToken": true,
            }),
            UNOBSERVED.to_owned(),
        ),
        (
            "access token only",
            json!({
                "requestUri": "http://localhost",
                "postBody": format!("providerId={PROVIDER}&access_token=at"),
                "returnSecureToken": true,
            }),
            format!("INVALID_CREDENTIAL_OR_PROVIDER_ID : Invalid IdP response/credential: http://localhost?providerId={PROVIDER}&access_token=at"),
        ),
        (
            "no token",
            json!({
                "requestUri": "http://localhost",
                "postBody": format!("providerId={PROVIDER}"),
                "returnSecureToken": true,
            }),
            format!("INVALID_CREDENTIAL_OR_PROVIDER_ID : Invalid IdP response/credential: http://localhost?providerId={PROVIDER}"),
        ),
        (
            "mixed-case provider",
            request_for("oidc.Strict", &token(&claims())),
            NOT_FOUND.to_owned(),
        ),
    ];
    for (case, body, message) in cases {
        assert_refused(&s, &body, &message, case);
    }
    // Even with a configuration stored under the mixed-case ID: the credential parser
    // lowercases the provider, so the verified provider would not be the one recorded.
    let mut mixed = provider(true, ISSUER);
    mixed.id = "oidc.Strict".into();
    assert!(s.store.lock().unwrap().create_oidc_config(mixed));
    assert_refused(
        &s,
        &request_for("oidc.Strict", &token(&claims())),
        NOT_FOUND,
        "mixed-case provider with a configuration",
    );
}

#[test]
fn strict_selects_the_key_by_kid_and_refuses_a_key_under_the_wrong_kid() {
    // The configured key carries the token's kid but is another key: verification must fail.
    let mut relabelled = other_signer().jwks();
    relabelled["keys"][0]["kid"] = signer().jwks()["keys"][0]["kid"].clone();
    let mut s = strict_state();
    s.idp_assertions = IdpAssertionPolicy::SignedOidc(signers(ISSUER, relabelled));
    assert_refused(&s, &request(&token(&claims())), SIGNATURE, "relabelled key");
    // A kid the issuer does not list.
    s.idp_assertions = IdpAssertionPolicy::SignedOidc(signers(ISSUER, other_signer().jwks()));
    assert_refused(&s, &request(&token(&claims())), SIGNATURE, "unknown kid");
    // Both keys listed: the kid picks the verifying one.
    let mut both = signer().jwks();
    both["keys"]
        .as_array_mut()
        .unwrap()
        .push(other_signer().jwks()["keys"][0].clone());
    s.idp_assertions = IdpAssertionPolicy::SignedOidc(signers(ISSUER, both));
    let response = sign_in(&s, &request(&token(&claims())));
    assert_eq!(response.status, 200, "{}", response.body);
}

#[test]
fn strict_refuses_a_provider_that_is_unconfigured_disabled_or_of_another_issuer() {
    let s = strict_state();
    s.store
        .lock()
        .unwrap()
        .replace_oidc_config(provider(false, ISSUER));
    assert_refused(&s, &request(&token(&claims())), DISABLED, "disabled");
    // The provider points at an issuer without configured keys.
    s.store
        .lock()
        .unwrap()
        .replace_oidc_config(provider(true, "https://unlisted.example.test"));
    let mut claims = claims();
    claims["iss"] = json!("https://unlisted.example.test");
    assert_refused(
        &s,
        &request(&token(&claims)),
        UNREACHABLE,
        "unlisted issuer",
    );
    assert_refused(
        &s,
        &request_for("oidc.unconfigured", &token(&self::claims())),
        NOT_FOUND,
        "unconfigured",
    );
}

#[test]
fn strict_refuses_providers_it_cannot_verify_without_a_network_fetch() {
    let s = strict_state();
    for provider in ["google.com", "facebook.com", "saml.strict"] {
        for body in fixture_requests(provider) {
            assert_refused(&s, &body, NOT_FOUND, provider);
        }
        assert_refused(
            &s,
            &request_for(provider, &token(&claims())),
            NOT_FOUND,
            provider,
        );
    }
}

#[test]
fn strict_keeps_the_request_shape_errors_it_answered_before() {
    let s = strict_state();
    let missing_uri = json!({
        "postBody": format!("providerId={PROVIDER}&id_token={}", token(&claims())),
        "returnSecureToken": true,
    });
    let response = sign_in(&s, &missing_uri);
    assert_eq!(response.status, 400);
    assert_eq!(response.body["error"]["message"], "MISSING_REQUEST_URI");
    let missing_provider = json!({
        "requestUri": "http://localhost",
        "postBody": format!("id_token={}", token(&claims())),
        "returnSecureToken": true,
    });
    let response = sign_in(&s, &missing_provider);
    assert_eq!(response.status, 400);
    assert!(response.body["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("INVALID_CREDENTIAL_OR_PROVIDER_ID"));
    assert_eq!(s.store.lock().unwrap().user_count(), 0);
}

#[test]
fn the_fixture_policy_of_the_emulator_profile_accepts_the_fixture_idp() {
    // The daemon selects this policy for the emulator profile (`idp_assertion_policy`).
    let mut s = strict_state();
    s.stateless_refresh_tokens = true;
    s.idp_assertions = IdpAssertionPolicy::Fixture;
    for body in fixture_requests("google.com") {
        let response = sign_in(&s, &body);
        assert_eq!(response.status, 200, "{}", response.body);
        // The official emulator's answer fields stay.
        assert!(response.body.get("rawId").is_some(), "{}", response.body);
        assert!(response.body.get("context").is_some(), "{}", response.body);
    }
    let response = sign_in(&s, &fixture_requests("oidc.unconfigured")[1]);
    assert_eq!(response.status, 200, "{}", response.body);
}

#[test]
fn strict_verifies_on_the_selected_tenant_with_that_tenants_provider() {
    let mut s = strict_state();
    let registry = Arc::new(AuthRegistry::new("demo-app", s.store.clone()));
    let tenant = registry.ensure_tenant("demo-app", "customer-a").unwrap();
    // The tenant's provider of the same ID names another issuer.
    assert!(tenant
        .lock()
        .unwrap()
        .create_oidc_config(provider(true, "https://tenant.example.test")));
    s.registry = Some(registry);
    let mut body = request(&token(&claims()));
    body["tenantId"] = json!("customer-a");
    let response = sign_in(&s, &body);
    assert_eq!(response.status, 400, "{}", response.body);
    assert_eq!(response.body["error"]["message"], UNREACHABLE);
    assert_eq!(tenant.lock().unwrap().user_count(), 0);
    // With the tenant's provider on the configured issuer, the tenant accepts it.
    tenant
        .lock()
        .unwrap()
        .replace_oidc_config(provider(true, ISSUER));
    let response = sign_in(&s, &body);
    assert_eq!(response.status, 200, "{}", response.body);
    assert_eq!(tenant.lock().unwrap().user_count(), 1);
    assert_eq!(s.store.lock().unwrap().user_count(), 0);
}

fn continuation(value: &Value) -> Value {
    json!({"requestUri": "http://localhost", "pendingToken": value, "returnSecureToken": true})
}

#[test]
fn strict_continuations_are_reverified_and_do_not_cross_with_the_fixture() {
    let mut strict = strict_state();
    strict.idp_continuations = IdpContinuationPolicy::LocalBounded;
    let first = sign_in(&strict, &request(&token(&claims())));
    assert_eq!(first.status, 200, "{}", first.body);
    let pending = first.body["pendingToken"].clone();
    assert!(pending.is_string());
    let resumed = sign_in(&strict, &continuation(&pending));
    assert_eq!(resumed.status, 200, "{}", resumed.body);
    assert_eq!(resumed.body["localId"], first.body["localId"]);

    // The same store under the emulator profile mints a fixture continuation, which strict
    // must not resume, and the emulator must not resume strict's.
    let mut emulator = strict_state();
    emulator.store = strict.store.clone();
    emulator.stateless_refresh_tokens = true;
    emulator.idp_assertions = IdpAssertionPolicy::Fixture;
    emulator.idp_continuations = IdpContinuationPolicy::LocalBounded;
    let fixture = sign_in(&emulator, &fixture_requests("google.com")[1]);
    assert_eq!(fixture.status, 200, "{}", fixture.body);
    let refused = sign_in(&strict, &continuation(&fixture.body["pendingToken"]));
    assert_eq!(refused.status, 400);
    assert_eq!(refused.body["error"]["message"], "INVALID_PENDING_TOKEN");
    let refused = sign_in(&emulator, &continuation(&pending));
    assert_eq!(refused.status, 400);

    // A disabled provider refuses the resume; the original token's expiry is re-checked.
    strict
        .store
        .lock()
        .unwrap()
        .replace_oidc_config(provider(false, ISSUER));
    let refused = sign_in(&strict, &continuation(&pending));
    assert_eq!(refused.body["error"]["message"], DISABLED);
    strict
        .store
        .lock()
        .unwrap()
        .replace_oidc_config(provider(true, ISSUER));
    strict
        .clock
        .lock()
        .unwrap()
        .advance_to(LogicalInstant::from_unix_seconds(NOW + 60))
        .unwrap();
    let refused = sign_in(&strict, &continuation(&pending));
    assert_eq!(refused.body["error"]["message"], stale(NOW));
}

/// A blocking hook that disables the provider while it runs, as a concurrent Admin PATCH
/// would between the first verification and the commit.
struct DisableProviderDuringHook {
    store: Arc<Mutex<AuthStore>>,
}

impl fireemu_adapter_http::identity_toolkit::AuthBlockingHook for DisableProviderDuringHook {
    fn invoke(
        &self,
        _event: fireemu_core_functions::manifest::BlockingAuthEvent,
        _user: &UserRecord,
    ) -> Result<Value, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure> {
        Ok(json!({}))
    }

    fn invoke_for_with_context(
        &self,
        _project: &str,
        _tenant: Option<&str>,
        _event: fireemu_core_functions::manifest::BlockingAuthEvent,
        _user: &UserRecord,
        _context: &fireemu_adapter_http::identity_toolkit::AuthBlockingContext,
    ) -> Result<Option<Value>, fireemu_adapter_http::identity_toolkit::BlockingFunctionFailure>
    {
        self.store
            .lock()
            .unwrap()
            .replace_oidc_config(provider(false, ISSUER));
        Ok(Some(json!({})))
    }
}

#[test]
fn strict_reverifies_when_a_blocking_hook_commits() {
    let mut s = strict_state();
    s.blocking = Some(Arc::new(DisableProviderDuringHook {
        store: s.store.clone(),
    }));
    let response = sign_in(&s, &request(&token(&claims())));
    assert_eq!(response.status, 400, "{}", response.body);
    assert_eq!(response.body["error"]["message"], "INVALID_IDP_RESPONSE");
    assert!(response.body.get("idToken").is_none());
    assert_eq!(s.store.lock().unwrap().user_count(), 0);
}

#[test]
fn strict_accepts_what_production_accepts() {
    // Several audiences without `azp`, and an `nbf` in the future (record-oidc 39209e).
    let s = strict_state();
    let mut several = claims();
    several["aud"] = json!([CLIENT, "other-client"]);
    several["sub"] = json!("several");
    let mut not_yet = claims();
    not_yet["nbf"] = json!(NOW + 3600);
    not_yet["sub"] = json!("not-yet");
    for (case, claims) in [("several audiences", several), ("future nbf", not_yet)] {
        let response = sign_in(&s, &request(&token(&claims)));
        assert_eq!(response.status, 200, "{case}: {}", response.body);
    }
}

fn with_nonce(token: &str, nonce: Option<&str>) -> Value {
    let mut body = request(token);
    if let Some(nonce) = nonce {
        body["postBody"] = json!(format!(
            "{}&nonce={nonce}",
            body["postBody"].as_str().unwrap()
        ));
    }
    body
}

fn hashed(nonce: &str) -> String {
    fireemu_core_types::hash::hex_lower(&fireemu_core_types::hash::sha256(nonce.as_bytes()))
}

#[test]
fn strict_checks_the_nonce_as_production_does() {
    let s = strict_state();
    let mut claimed = claims();
    claimed["nonce"] = json!(hashed("nonce-a"));
    let nonce_token = token(&claimed);
    // The token carries a nonce the request does not.
    assert_refused(
        &s,
        &with_nonce(&nonce_token, None),
        NONCE_MISSING,
        "no request nonce",
    );
    // The request carries a nonce the token does not: accepted.
    let response = sign_in(&s, &with_nonce(&token(&claims()), Some("nonce-a")));
    assert_eq!(response.status, 200, "{}", response.body);
    // A matching nonce signs in once; the same credential again is a duplicate, before the
    // nonce is even compared.
    let s = strict_state();
    let first = sign_in(&s, &with_nonce(&nonce_token, Some("nonce-a")));
    assert_eq!(first.status, 200, "{}", first.body);
    assert_refused_after(&s, &with_nonce(&nonce_token, Some("nonce-a")), DUPLICATE);
    assert_refused_after(&s, &with_nonce(&nonce_token, Some("nonce-b")), DUPLICATE);
    // A new token with the same nonce for the same subject is the same credential.
    let mut reissued = claimed.clone();
    reissued["iat"] = json!(NOW - 1);
    assert_refused_after(
        &s,
        &with_nonce(&token(&reissued), Some("nonce-a")),
        DUPLICATE,
    );
    // Another subject's token with the same nonce is another credential.
    let mut other = claimed.clone();
    other["sub"] = json!("other-subject");
    let response = sign_in(&s, &with_nonce(&token(&other), Some("nonce-a")));
    assert_eq!(response.status, 200, "{}", response.body);
    // A nonce that does not match (production's message for it is unobserved).
    let mut fresh = claims();
    fresh["nonce"] = json!(hashed("nonce-c"));
    fresh["sub"] = json!("fresh-subject");
    assert_refused_after(&s, &with_nonce(&token(&fresh), Some("nonce-d")), UNOBSERVED);
    // Without a nonce, the same token signs in again (production's replay rows).
    let again = sign_in(&s, &request(&token(&claims())));
    assert_eq!(again.status, 200, "{}", again.body);
    let again = sign_in(&s, &request(&token(&claims())));
    assert_eq!(again.status, 200, "{}", again.body);
}

/// A refusal that changes nothing, in a store that already holds accounts.
fn assert_refused_after(s: &AuthState, body: &Value, message: &str) {
    let users = s.store.lock().unwrap().user_count();
    let response = sign_in(s, body);
    assert_eq!(response.status, 400, "{}", response.body);
    assert_eq!(response.body["error"]["message"], message);
    assert_eq!(s.store.lock().unwrap().user_count(), users);
}

#[test]
fn a_refused_or_reset_sign_in_uses_no_nonce() {
    let s = strict_state();
    let mut claimed = claims();
    claimed["nonce"] = json!(hashed("nonce-a"));
    let nonce_token = token(&claimed);
    // A refusal after the nonce check (the provider disabled) records nothing.
    s.store
        .lock()
        .unwrap()
        .replace_oidc_config(provider(false, ISSUER));
    assert_refused(
        &s,
        &with_nonce(&nonce_token, Some("nonce-a")),
        DISABLED,
        "disabled",
    );
    s.store
        .lock()
        .unwrap()
        .replace_oidc_config(provider(true, ISSUER));
    let first = sign_in(&s, &with_nonce(&nonce_token, Some("nonce-a")));
    assert_eq!(first.status, 200, "{}", first.body);
    // Resetting the emulator's accounts forgets the credentials used.
    let reset = handle(
        &s,
        "DELETE",
        "/emulator/v1/projects/demo-app/accounts",
        &Value::Null,
    );
    assert_eq!(reset.status, 200, "{}", reset.body);
    s.store
        .lock()
        .unwrap()
        .replace_oidc_config(provider(true, ISSUER));
    let again = sign_in(&s, &with_nonce(&nonce_token, Some("nonce-a")));
    assert_eq!(again.status, 200, "{}", again.body);
}

fn id_token_claims(response: &JsonResponse) -> Value {
    let payload = response.body["idToken"]
        .as_str()
        .unwrap()
        .split('.')
        .nth(1)
        .unwrap();
    serde_json::from_slice(&fireemu_core_auth::jwt::base64url_decode(payload).unwrap()).unwrap()
}

#[test]
fn strict_answers_a_sign_in_in_productions_shape() {
    // record-oidc 39209e: the federated ID names the provider, the answer carries no context,
    // raw ID or access token for an ID-token credential, `isNewUser` only when true, and the
    // sign-in attributes are the claims beyond the standard ones.
    let s = strict_state();
    let mut rich = claims();
    rich["email"] = json!("rich@example.com");
    rich["email_verified"] = json!(true);
    rich["name"] = json!("Rich User");
    rich["picture"] = json!("https://example.com/p.png");
    rich["department"] = json!("fireemu");
    let first = sign_in(&s, &request(&token(&rich)));
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(
        first.body["federatedId"],
        format!("{PROVIDER}/strict-subject")
    );
    for absent in ["context", "rawId", "oauthAccessToken"] {
        assert!(first.body.get(absent).is_none(), "{absent}: {}", first.body);
    }
    assert_eq!(first.body["isNewUser"], true);
    assert_eq!(
        id_token_claims(&first)["firebase"]["sign_in_attributes"],
        json!({"department": "fireemu"})
    );
    let again = sign_in(&s, &request(&token(&claims())));
    assert_eq!(again.status, 200, "{}", again.body);
    assert!(again.body.get("isNewUser").is_none(), "{}", again.body);
    assert!(
        id_token_claims(&again)["firebase"]
            .get("sign_in_attributes")
            .is_none(),
        "only standard claims: no attributes"
    );
}
