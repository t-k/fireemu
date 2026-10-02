//! Time-claim validation through the Auth adapter using the existing public test RSA key.
//! These tests invoke the real HTTP handler in-process, not a listening server or Google.

use std::sync::{Arc, Mutex, OnceLock, RwLock};

use fireemu_adapter_http::control::{self, ControlState};
use fireemu_adapter_http::identity_toolkit::{
    handle, handle_with, AuthState, RequestHeaders, OWNER_CREDENTIAL,
};
use fireemu_adapter_http::signing::RsaSigner;
use fireemu_core_auth::jwt::{
    base64url_decode, base64url_encode, decode_token, encode_payload_with, verify_rules_token,
    JwtError, TokenAcceptance, IDENTITY_TOOLKIT_EXPIRY_LEEWAY_SECONDS,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::codec::hex_decode;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const NOW: i64 = 1_788_004_860;
const AT: LogicalInstant = LogicalInstant::from_unix_seconds(NOW);
const SIGN_UP: &str = "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=k";
const LOOKUP: &str = "/identitytoolkit.googleapis.com/v1/accounts:lookup?key=k";
const UPDATE: &str = "/identitytoolkit.googleapis.com/v1/accounts:update?key=k";

fn signer() -> Arc<RsaSigner> {
    static SIGNER: OnceLock<Arc<RsaSigner>> = OnceLock::new();
    Arc::clone(SIGNER.get_or_init(|| {
        // Reuse a deliberately public, insecure fixture; never put this key in a release.
        let bytes = include_bytes!("fixtures/INSECURE_TEST_ONLY_RSA_A.der.hex");
        let digits: String = bytes
            .iter()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(|byte| char::from(*byte))
            .collect();
        let der = hex_decode(&digits).expect("existing test key is hexadecimal");
        RsaSigner::from_pkcs8_der(&der).expect("existing test key is PKCS#8")
    }))
}

/// The compatibility profile an [`AuthState`] is wired for, as the daemon wires it: the
/// emulator profile keeps refresh tokens stateless, strict keeps refresh sessions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Strict,
    Emulator,
}

/// The strict profile with session-RSA signing, which the existing refusal tests assume.
fn setup() -> (AuthState, Arc<RsaSigner>, String, String) {
    setup_with(Profile::Strict, true)
}

/// A session of `profile` with one signed-up account. `rsa` installs the RSA signer
/// (`auth.idTokenSigning: session-rsa`); otherwise tokens are unsigned, as with the emulator
/// profile's default `unsigned-emulator`.
fn setup_with(profile: Profile, rsa: bool) -> (AuthState, Arc<RsaSigner>, String, String) {
    let signer = signer();
    let mut store = AuthStore::new("demo-app", SplitMix64::new(11), TotpPolicy::default());
    if rsa {
        store.set_signer(signer.clone());
    }
    let state = AuthState {
        store: Arc::new(Mutex::new(store)),
        clock: Arc::new(Mutex::new(VirtualClock::new(AT))),
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
        stateless_refresh_tokens: profile == Profile::Emulator,
        idp_continuations: fireemu_adapter_http::identity_toolkit::IdpContinuationPolicy::Disabled,
        query_limits: fireemu_adapter_http::identity_toolkit::AuthQueryLimits::EmulatorUnbounded,
        client_api_key: fireemu_adapter_http::identity_toolkit::ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
        idp_assertions: fireemu_adapter_http::identity_toolkit::IdpAssertionPolicy::Fixture,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };
    let response = handle(
        &state,
        "POST",
        SIGN_UP,
        &json!({"email": "temporal@example.invalid", "password": "password1"}),
    );
    assert_eq!(response.status, 200, "signup is the positive route control");
    let token = response.body["idToken"].as_str().unwrap().to_owned();
    let refresh = response.body["refreshToken"].as_str().unwrap().to_owned();
    (state, signer, token, refresh)
}

fn revised_token(original: &str, signer: &RsaSigner, key: &str, value: Option<Value>) -> String {
    let decoded = decode_token(original, Some(signer)).unwrap();
    let mut payload: Value = serde_json::from_str(&decoded.payload_json).unwrap();
    let object = payload.as_object_mut().unwrap();
    match value {
        Some(value) => {
            object.insert(key.to_owned(), value);
        }
        None => {
            object.remove(key);
        }
    }
    let token = encode_payload_with(&payload.to_string(), Some(signer));
    // A temporal rejection must not pass simply because the RSA signature is wrong.
    assert!(decode_token(&token, Some(signer)).is_ok());
    token
}

#[test]
fn signed_bad_time_claims_cannot_change_an_account() {
    let (state, signer, original, _) = setup();
    let before = handle(&state, "POST", LOOKUP, &json!({"idToken": original}));
    assert_eq!(before.status, 200);
    let before_user = before.body["users"][0].clone();
    for (key, value) in [
        ("iat", None),
        ("iat", Some(Value::Null)),
        ("iat", Some(json!(true))),
        ("iat", Some(json!(NOW.to_string()))),
        ("iat", Some(json!(NOW + 600))),
        ("auth_time", Some(json!(NOW + 600))),
    ] {
        let bad = revised_token(&original, signer.as_ref(), key, value);
        let response = handle(
            &state,
            "POST",
            UPDATE,
            &json!({"idToken": bad, "displayName": "must-not-be-committed"}),
        );
        assert_eq!(
            response.status, 400,
            "a well-signed, invalid-time token is refused"
        );
        assert!(response.body.get("idToken").is_none());
        let after = handle(&state, "POST", LOOKUP, &json!({"idToken": original}));
        assert_eq!(
            after.status, 200,
            "the valid token remains usable after refusal"
        );
        assert_eq!(
            after.body["users"][0], before_user,
            "no partial account update"
        );
    }
}

#[test]
fn a_current_second_signed_token_can_update_and_refresh() {
    let (state, signer, original, refresh) = setup();
    let updated = handle(
        &state,
        "POST",
        UPDATE,
        &json!({"idToken": original, "displayName": "valid-change"}),
    );
    assert_eq!(updated.status, 200);
    let looked_up = handle(&state, "POST", LOOKUP, &json!({"idToken": original}));
    assert_eq!(looked_up.status, 200);
    assert_eq!(looked_up.body["users"][0]["displayName"], "valid-change");
    let refreshed = handle(
        &state,
        "POST",
        "/securetoken.googleapis.com/v1/token",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}),
    );
    assert_eq!(refreshed.status, 200);
    let id_token = refreshed.body["id_token"].as_str().unwrap();
    let store = state.store.lock().unwrap();
    assert!(verify_rules_token(id_token, &store, AT, TokenAcceptance::Verified).is_ok());
    assert!(decode_token(id_token, Some(signer.as_ref())).is_ok());
}

/// Security Rules follow the profile's token acceptance (ledger 781): strict (`Verified`)
/// refuses a signed token whose `iat` or `auth_time` is in the future; the emulator profile
/// (`EmulatorMock`) accepts it on the verified path, with its signature still checked, as the
/// official emulators read no time claim. A tampered signature never reaches the mock fallback.
#[test]
fn a_signed_future_dated_token_follows_the_rules_profile_and_never_the_mock_fallback() {
    let (state, signer, original, _) = setup();
    for key in ["iat", "auth_time"] {
        let future = revised_token(&original, signer.as_ref(), key, Some(json!(NOW + 600)));
        let store = state.store.lock().unwrap();
        assert_eq!(
            verify_rules_token(&future, &store, AT, TokenAcceptance::Verified),
            Err(JwtError::Malformed),
            "{key}"
        );
        let accepted = verify_rules_token(&future, &store, AT, TokenAcceptance::EmulatorMock)
            .unwrap_or_else(|e| panic!("{key}: {e:?}"));
        assert_eq!(
            accepted.sub(),
            decode_token(&original, Some(signer.as_ref()))
                .unwrap()
                .sub()
        );
        let mut parts: Vec<String> = future.split('.').map(str::to_owned).collect();
        let mut signature = base64url_decode(&parts[2]).unwrap();
        signature[0] ^= 1;
        parts[2] = base64url_encode(&signature);
        assert_eq!(
            verify_rules_token(&parts.join("."), &store, AT, TokenAcceptance::EmulatorMock),
            Err(JwtError::BadSignature),
            "{key}"
        );
    }
}

#[test]
fn signature_rejection_still_precedes_temporal_rejection() {
    let (state, signer, original, _) = setup();
    let bad_time = revised_token(&original, signer.as_ref(), "iat", Some(json!(NOW + 600)));
    let mut parts: Vec<String> = bad_time.split('.').map(str::to_owned).collect();
    let mut signature = base64url_decode(&parts[2]).unwrap();
    signature[0] ^= 1;
    parts[2] = base64url_encode(&signature);
    let corrupted = parts.join(".");
    assert_eq!(
        decode_token(&corrupted, Some(signer.as_ref())),
        Err(JwtError::BadSignature)
    );
    let store = state.store.lock().unwrap();
    assert_eq!(
        verify_rules_token(&corrupted, &store, AT, TokenAcceptance::Verified),
        Err(JwtError::BadSignature)
    );
}

#[test]
fn session_cookie_creation_refuses_future_time_claims_and_accepts_the_original() {
    let (state, signer, original, _) = setup();
    let headers = RequestHeaders {
        authorization: Some(OWNER_CREDENTIAL.to_owned()),
        ..RequestHeaders::default()
    };
    let route = "/identitytoolkit.googleapis.com/v1/projects/demo-app:createSessionCookie";
    let good = handle_with(
        &state,
        "POST",
        route,
        &headers,
        &json!({"idToken": original, "validDuration": "3600"}),
    );
    assert_eq!(
        good.status, 200,
        "positive control for the same route and credential"
    );
    for key in ["iat", "auth_time"] {
        let bad = revised_token(&original, signer.as_ref(), key, Some(json!(NOW + 600)));
        let rejected = handle_with(
            &state,
            "POST",
            route,
            &headers,
            &json!({"idToken": bad, "validDuration": "3600"}),
        );
        assert_eq!(rejected.status, 400);
        assert!(rejected.body.get("sessionCookie").is_none());
    }
}

/// The control API over the Auth adapter's clock, as the daemon shares one clock between them.
fn control_over(clock: Arc<Mutex<VirtualClock>>) -> ControlState {
    ControlState {
        clock,
        require_demo_prefix: true,
        edition: fireemu_core_types::edition::FirestoreEdition::Standard,
        capabilities: json!({"schemaVersion": 1}).into(),
        rules: Arc::new(fireemu_core_rules::runtime::RulesetSlot::default()),
        storage_rules: Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::default()),
        reset_hooks: Vec::new(),
        functions: None,
        control_token: "test-token".to_owned(),
        app_check: None,
        barrier: None,
        snapshot_hooks: Vec::new(),
        snapshots: Mutex::new(std::collections::BTreeMap::new()),
        faults: None,
        text_indexes: Arc::new(Mutex::new(
            fireemu_core_firestore::text_index::TextIndexCatalog::default(),
        )),
        default_project: "demo-app".to_owned(),
        tenancy: Arc::new(RwLock::new(fireemu_core_session::tenancy::Tenancy::new(
            "demo-app",
        ))),
        sessions: Mutex::new(std::collections::BTreeMap::from([(
            "default".to_owned(),
            "demo-app".to_owned(),
        )])),
        project_hooks: None,
        resource_hooks: Vec::new(),
    }
}

/// `POST clock:set` on the default session; returns the control API's status.
fn set_clock(control: &ControlState, at: LogicalInstant, allow_backwards: bool) -> u16 {
    let instant = at.to_rfc3339().unwrap();
    let body = if allow_backwards {
        json!({"instant": instant, "allowBackwards": true})
    } else {
        json!({"instant": instant})
    };
    control::handle(control, "POST", "/v1/sessions/default/clock:set", &body).status
}

fn lookup_status(state: &AuthState, token: &str) -> u16 {
    handle(state, "POST", LOOKUP, &json!({"idToken": token})).status
}

/// Strict: `clock:set {"allowBackwards": true}` below a held token's `iat`/`auth_time` makes
/// Identity Toolkit refuse the token with `INVALID_ID_TOKEN` (its claims are now in the
/// future) until the clock reaches them again. The refusal is inferred from the Firebase
/// ID-token contract, not recorded (ledger 781). A rewind inside the issuance second, and a
/// forward-only `clock:set`, keep the token usable.
#[test]
fn a_clock_rewind_below_issuance_refuses_a_held_token_in_strict_until_the_clock_catches_up() {
    let (state, _, token, _) = setup();
    let control = control_over(state.clock.clone());
    assert_eq!(set_clock(&control, at_offset(30_000_000_000), false), 200);
    assert_eq!(lookup_status(&state, &token), 200, "positive control");
    // A plain clock:set never moves backwards: it is refused and the token stays usable.
    assert_eq!(set_clock(&control, at_offset(-1), false), 400);
    assert_eq!(lookup_status(&state, &token), 200);
    // Back into the issuance second: the whole-second claims are not in the future.
    assert_eq!(set_clock(&control, AT, true), 200);
    assert_eq!(lookup_status(&state, &token), 200);
    // One nanosecond before the issuance second: refused, and the account cannot change.
    assert_eq!(set_clock(&control, at_offset(-1), true), 200);
    let refused = handle(&state, "POST", LOOKUP, &json!({"idToken": token}));
    assert_eq!(refused.status, 400);
    assert_eq!(refused.body["error"]["message"], "INVALID_ID_TOKEN");
    let update = handle(
        &state,
        "POST",
        UPDATE,
        &json!({"idToken": token, "displayName": "must-not-be-committed"}),
    );
    assert_eq!(update.status, 400);
    // The clock catching up again restores the token: nothing was revoked.
    assert_eq!(set_clock(&control, AT, false), 200);
    let restored = handle(&state, "POST", LOOKUP, &json!({"idToken": token}));
    assert_eq!(restored.status, 200);
    assert!(restored.body["users"][0].get("displayName").is_none());
}

/// Emulator profile (ledger 781): the same rewind leaves the held token usable, as
/// firebase-tools 15.28.2 reads no time claim of an ID token, with unsigned and session-RSA
/// tokens alike. `exp` still applies (ledger 22).
#[test]
fn a_clock_rewind_below_issuance_keeps_a_held_token_usable_in_the_emulator_profile() {
    for signed in [false, true] {
        let (state, _, token, _) = setup_with(Profile::Emulator, signed);
        let control = control_over(state.clock.clone());
        assert_eq!(set_clock(&control, at_offset(30_000_000_000), false), 200);
        assert_eq!(
            set_clock(&control, at_offset(-3_600_000_000_000), true),
            200
        );
        assert_eq!(lookup_status(&state, &token), 200, "signed={signed}");
        let update = handle(
            &state,
            "POST",
            UPDATE,
            &json!({"idToken": token, "displayName": "after-rewind"}),
        );
        assert_eq!(update.status, 200, "signed={signed}: {}", update.body);
        // Past `exp` and the 300 s allowance the token is refused, as before.
        assert_eq!(
            set_clock(&control, at_offset(3_901_000_000_000), false),
            200
        );
        assert_eq!(lookup_status(&state, &token), 400, "signed={signed}");
    }
}

fn at_offset(nanos: i128) -> LogicalInstant {
    LogicalInstant::from_nanos(AT.as_nanos() + nanos)
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 48,
        ..proptest::test_runner::Config::default()
    })]

    /// Model: after any opt-in rewind (or forward set) to `AT + offset`, a token issued at
    /// `AT` with a one-hour lifetime verifies in strict exactly when
    /// `0 <= offset < 3600 s + leeway`: whole-second claims make the issuance second usable,
    /// earlier instants put `iat` and `auth_time` in the future, and `exp` plus Identity
    /// Toolkit's recorded allowance closes the window. The emulator profile has no lower
    /// bound (ledger 781); `exp` still closes it.
    #[test]
    fn a_held_token_verifies_exactly_inside_its_issuance_window_after_any_clock_set(
        offset in proptest::prop_oneof![
            -7_200_000_000_000i128..=7_200_000_000_000i128,
            -2_000_000_000i128..=2_000_000_000i128,
            3_898_000_000_000i128..=3_902_000_000_000i128,
        ],
        detour in 0i128..=7_200_000_000_000i128,
        emulator in proptest::bool::ANY,
    ) {
        let profile = if emulator { Profile::Emulator } else { Profile::Strict };
        let (state, _, token, _) = setup_with(profile, true);
        let control = control_over(state.clock.clone());
        // Reach the target from a later instant, as a rewind in a replayed scenario would.
        proptest::prop_assert_eq!(set_clock(&control, at_offset(detour), false), 200);
        proptest::prop_assert_eq!(set_clock(&control, at_offset(offset), true), 200);
        let lifetime = i128::from(3_600 + IDENTITY_TOOLKIT_EXPIRY_LEEWAY_SECONDS) * 1_000_000_000;
        let expected = if emulator { offset < lifetime } else { (0..lifetime).contains(&offset) };
        proptest::prop_assert_eq!(lookup_status(&state, &token) == 200, expected);
    }
}

/// `original` with its `iat` and `auth_time` moved to `NOW + ahead`, signed by `signer` when
/// the session signs its tokens, otherwise unsigned (a client can make such a token by hand).
fn future_dated(original: &str, signer: Option<&RsaSigner>, ahead: i64) -> String {
    let verifier = signer.map(|s| s as &dyn fireemu_core_auth::jwt::IdTokenSigner);
    let decoded = decode_token(original, verifier).unwrap();
    let mut payload: Value = serde_json::from_str(&decoded.payload_json).unwrap();
    payload["iat"] = json!(NOW + ahead);
    payload["auth_time"] = json!(NOW + ahead);
    let token = encode_payload_with(&payload.to_string(), verifier);
    assert!(decode_token(&token, verifier).is_ok());
    token
}

fn owner() -> RequestHeaders {
    RequestHeaders {
        authorization: Some(OWNER_CREDENTIAL.to_owned()),
        ..RequestHeaders::default()
    }
}

/// Every Identity Toolkit route that verifies an ID token, with a body that reaches the
/// verification, and whether a verified token succeeds outright on it. `delete` goes last.
fn id_token_routes(token: &str) -> Vec<(&'static str, Value, bool)> {
    vec![
        (LOOKUP, json!({"idToken": token}), true),
        (
            UPDATE,
            json!({"idToken": token, "displayName": "future"}),
            true,
        ),
        (
            "/identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=k",
            json!({"requestType": "VERIFY_EMAIL", "idToken": token}),
            true,
        ),
        (
            "/identitytoolkit.googleapis.com/v1/projects/demo-app:createSessionCookie",
            json!({"idToken": token, "validDuration": "3600"}),
            true,
        ),
        (
            SIGN_UP,
            json!({"idToken": token, "email": "linked@example.invalid", "password": "password1"}),
            false,
        ),
        (
            "/identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:start?key=k",
            json!({"idToken": token, "phoneEnrollmentInfo": {"phoneNumber": "+15555550100"}}),
            false,
        ),
        (
            "/identitytoolkit.googleapis.com/v2/accounts/mfaEnrollment:withdraw?key=k",
            json!({"idToken": token, "mfaEnrollmentId": "absent"}),
            false,
        ),
        (
            "/identitytoolkit.googleapis.com/v1/accounts:delete?key=k",
            json!({"idToken": token}),
            true,
        ),
    ]
}

/// Ledger 781: the emulator profile accepts an ID token whose `iat` and `auth_time` are in
/// the future, as firebase-tools 15.28.2 does (its `parseIdToken` reads no time claim), with
/// unsigned and with session-RSA tokens. Strict refuses it with `INVALID_ID_TOKEN` on every
/// route, before anything else.
#[test]
fn a_future_dated_id_token_is_accepted_in_the_emulator_profile_and_refused_in_strict_on_every_route(
) {
    for profile in [Profile::Emulator, Profile::Strict] {
        for signed in [false, true] {
            let (state, signer, original, _) = setup_with(profile, signed);
            let future = future_dated(&original, signed.then_some(signer.as_ref()), 600);
            for (route, body, succeeds) in id_token_routes(&future) {
                // Only session cookie creation is an Admin route (owner credential).
                let response = if route.contains("createSessionCookie") {
                    handle_with(&state, "POST", route, &owner(), &body)
                } else {
                    handle(&state, "POST", route, &body)
                };
                let label = format!("{profile:?} signed={signed} {route}: {}", response.body);
                let refused = response.body["error"]["message"]
                    .as_str()
                    .is_some_and(|m| m.starts_with("INVALID_ID_TOKEN"));
                match profile {
                    Profile::Strict => {
                        assert_eq!(response.status, 400, "{label}");
                        assert!(refused, "{label}");
                    }
                    Profile::Emulator => {
                        assert!(!refused, "{label}");
                        if succeeds {
                            assert_eq!(response.status, 200, "{label}");
                        }
                    }
                }
            }
        }
    }
}

/// Near shapes. Ledger 787 makes the emulator profile accept a string `iat` and a missing
/// `auth_time` (see the hand-made shape test below); what it leaves undecided stays refused in
/// both profiles: an `iat` that is neither a number nor a string, an `auth_time` that is
/// present but not an integer, and an `exp` past Identity Toolkit's 300 s allowance (ledger
/// 22). Strict refuses the near shapes: `iat` one second ahead, and only `auth_time` ahead.
#[test]
fn near_shapes_of_a_future_dated_token_stay_refused_where_they_should() {
    for profile in [Profile::Emulator, Profile::Strict] {
        let (state, signer, original, _) = setup_with(profile, true);
        let lookup =
            |token: &str| handle(&state, "POST", LOOKUP, &json!({"idToken": token})).status;
        for (key, value) in [
            ("iat", Some(json!(null))),
            ("auth_time", Some(json!(NOW.to_string()))),
            ("exp", Some(json!(NOW - 301))),
        ] {
            let bad = revised_token(&original, signer.as_ref(), key, value.clone());
            assert_eq!(lookup(&bad), 400, "{profile:?} {key}={value:?}");
        }
        let expected = if profile == Profile::Strict { 400 } else { 200 };
        for (key, value) in [
            ("iat", Some(json!((NOW + 600).to_string()))),
            ("auth_time", None),
        ] {
            let decided = revised_token(&original, signer.as_ref(), key, value.clone());
            assert_eq!(lookup(&decided), expected, "{profile:?} {key}={value:?}");
        }
        let one_ahead = revised_token(&original, signer.as_ref(), "iat", Some(json!(NOW + 1)));
        let auth_ahead = revised_token(
            &original,
            signer.as_ref(),
            "auth_time",
            Some(json!(NOW + 600)),
        );
        assert_eq!(
            lookup(&one_ahead),
            expected,
            "{profile:?} iat one second ahead"
        );
        assert_eq!(
            lookup(&auth_ahead),
            expected,
            "{profile:?} only auth_time ahead"
        );
    }
}

/// `original` with each `(claim, value or removal)` applied, signed by `signer` when the
/// session signs its tokens, otherwise unsigned (a client can make such a token by hand).
fn hand_made(
    original: &str,
    signer: Option<&RsaSigner>,
    changes: &[(&str, Option<Value>)],
) -> String {
    let verifier = signer.map(|s| s as &dyn fireemu_core_auth::jwt::IdTokenSigner);
    let decoded = decode_token(original, verifier).unwrap();
    let mut payload: Value = serde_json::from_str(&decoded.payload_json).unwrap();
    let object = payload.as_object_mut().unwrap();
    for (key, value) in changes {
        match value {
            Some(value) => {
                object.insert((*key).to_owned(), value.clone());
            }
            None => {
                object.remove(*key);
            }
        }
    }
    let token = encode_payload_with(&payload.to_string(), verifier);
    assert!(decode_token(&token, verifier).is_ok());
    token
}

/// The hand-made shapes of ledger 787 for an account signed up with a password at `NOW` (its
/// `validSince`): a numeric-string or fractional `iat` not before it, a missing `auth_time`, a
/// missing `exp`, and all three at once.
/// Claim changes: each claim and its new value, or `None` to remove it.
type ClaimChanges = Vec<(&'static str, Option<Value>)>;

fn hand_made_shapes() -> Vec<(&'static str, ClaimChanges)> {
    vec![
        (
            "iat a numeric string",
            vec![("iat", Some(json!(NOW.to_string())))],
        ),
        (
            "iat a fraction",
            vec![("iat", Some(serde_json::from_str("1788004860.5").unwrap()))],
        ),
        ("auth_time missing", vec![("auth_time", None)]),
        ("exp missing", vec![("exp", None)]),
        (
            "all at once",
            vec![
                ("iat", Some(json!(NOW.to_string()))),
                ("auth_time", None),
                ("exp", None),
            ],
        ),
    ]
}

/// Ledger 787: the emulator profile accepts the hand-made ID-token shapes firebase-tools
/// 15.28.2 accepts on every Identity Toolkit route that verifies an ID token, unsigned and
/// session-RSA; strict refuses each with `INVALID_ID_TOKEN` before anything else.
#[test]
fn each_hand_made_shape_is_accepted_in_the_emulator_profile_and_refused_in_strict_on_every_route() {
    for profile in [Profile::Emulator, Profile::Strict] {
        for signed in [false, true] {
            for (shape, changes) in hand_made_shapes() {
                let (state, signer, original, _) = setup_with(profile, signed);
                let token = hand_made(&original, signed.then_some(signer.as_ref()), &changes);
                for (route, body, succeeds) in id_token_routes(&token) {
                    let response = if route.contains("createSessionCookie") {
                        handle_with(&state, "POST", route, &owner(), &body)
                    } else {
                        handle(&state, "POST", route, &body)
                    };
                    let label = format!(
                        "{profile:?} signed={signed} {shape} {route}: {}",
                        response.body
                    );
                    let refused = response.body["error"]["message"]
                        .as_str()
                        .is_some_and(|m| m.starts_with("INVALID_ID_TOKEN"));
                    match profile {
                        Profile::Strict => {
                            assert_eq!(response.status, 400, "{label}");
                            assert!(refused, "{label}");
                        }
                        Profile::Emulator => {
                            assert!(!refused, "{label}");
                            if succeeds {
                                assert_eq!(response.status, 200, "{label}");
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A missing `iat` is what firebase-tools' `iat >= Number(user.validSince)` makes of it: an
/// account with a `validSince` (a password account) answers `TOKEN_EXPIRED`, one without (an
/// anonymous account) is accepted. Strict refuses both with `INVALID_ID_TOKEN`.
#[test]
fn a_token_without_iat_follows_the_accounts_valid_since_in_the_emulator_profile() {
    for profile in [Profile::Emulator, Profile::Strict] {
        for signed in [false, true] {
            let (state, signer, password_token, _) = setup_with(profile, signed);
            let anonymous = handle(&state, "POST", SIGN_UP, &json!({}));
            assert_eq!(anonymous.status, 200, "anonymous sign-up");
            let anonymous_token = anonymous.body["idToken"].as_str().unwrap().to_owned();
            for (account, original, expected) in [
                ("password", &password_token, "TOKEN_EXPIRED"),
                ("anonymous", &anonymous_token, ""),
            ] {
                let token = hand_made(
                    original,
                    signed.then_some(signer.as_ref()),
                    &[("iat", None)],
                );
                for route in [LOOKUP, UPDATE] {
                    let response = handle(
                        &state,
                        "POST",
                        route,
                        &json!({"idToken": token, "displayName": "x"}),
                    );
                    let message = response.body["error"]["message"].as_str().unwrap_or("");
                    let label = format!("{profile:?} signed={signed} {account} {route}");
                    match (profile, expected) {
                        (Profile::Strict, _) => {
                            assert_eq!(response.status, 400, "{label}");
                            assert!(
                                message.starts_with("INVALID_ID_TOKEN"),
                                "{label}: {message}"
                            );
                        }
                        (Profile::Emulator, "") => assert_eq!(response.status, 200, "{label}"),
                        (Profile::Emulator, expected) => {
                            assert_eq!(response.status, 400, "{label}");
                            assert_eq!(message, expected, "{label}");
                        }
                    }
                }
            }
        }
    }
}

/// The boundary at `exp` plus Identity Toolkit's 300 s allowance is the same in both profiles
/// (ledger 22): the last nanosecond before it is accepted and the boundary itself refused.
#[test]
fn the_expiry_allowance_boundary_is_exact_in_both_profiles() {
    let boundary = i128::from(3_600 + IDENTITY_TOOLKIT_EXPIRY_LEEWAY_SECONDS) * 1_000_000_000;
    for profile in [Profile::Emulator, Profile::Strict] {
        let (state, _, token, _) = setup_with(profile, true);
        let control = control_over(state.clock.clone());
        assert_eq!(set_clock(&control, at_offset(boundary - 1), false), 200);
        assert_eq!(lookup_status(&state, &token), 200, "{profile:?}");
        assert_eq!(set_clock(&control, at_offset(boundary), false), 200);
        assert_eq!(lookup_status(&state, &token), 400, "{profile:?}");
    }
}

/// Security review S1, option (a), pinned in both profiles. After a rewind, a revocation does
/// not revoke a token the server issued later on the timeline: revocation compares the
/// token's `auth_time` with the account's bound, which the rewound clock sets lower. The
/// emulator profile then accepts the token at once (its `iat` is in the future, which ledger
/// 781 accepts); strict refuses it only until the clock reaches its issue time. README and
/// the control API header document this.
#[test]
fn a_revocation_on_a_rewound_clock_does_not_revoke_tokens_issued_later() {
    for profile in [Profile::Emulator, Profile::Strict] {
        let (state, _, _, _) = setup_with(profile, true);
        let control = control_over(state.clock.clone());
        // Sign in at T1 = AT + 600 s.
        assert_eq!(set_clock(&control, at_offset(600_000_000_000), false), 200);
        let signed_in = handle(
            &state,
            "POST",
            "/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=k",
            &json!({
                "email": "temporal@example.invalid",
                "password": "password1",
                "returnSecureToken": true
            }),
        );
        assert_eq!(signed_in.status, 200, "{}", signed_in.body);
        let later = signed_in.body["idToken"].as_str().unwrap().to_owned();
        let uid = signed_in.body["localId"].as_str().unwrap().to_owned();
        // Rewind to T0 = AT + 10 s and revoke there (Admin validSince = now).
        assert_eq!(set_clock(&control, at_offset(10_000_000_000), true), 200);
        let revoked = handle_with(
            &state,
            "POST",
            "/identitytoolkit.googleapis.com/v1/projects/demo-app/accounts:update",
            &owner(),
            &json!({"localId": uid, "validSince": (NOW + 10).to_string()}),
        );
        assert_eq!(revoked.status, 200, "{}", revoked.body);
        assert_eq!(set_clock(&control, at_offset(11_000_000_000), false), 200);
        let at_t0 = lookup_status(&state, &later);
        assert_eq!(set_clock(&control, at_offset(601_000_000_000), false), 200);
        let after_t1 = lookup_status(&state, &later);
        match profile {
            Profile::Emulator => assert_eq!((at_t0, after_t1), (200, 200), "{profile:?}"),
            Profile::Strict => assert_eq!((at_t0, after_t1), (400, 200), "{profile:?}"),
        }
    }
}

#[test]
fn signed_next_line_iat_reports_token_expired_for_password_account() {
    for profile in [Profile::Emulator, Profile::Strict] {
        for leading in [false, true] {
            let (state, signer, original, _) = setup_with(profile, true);
            let text = if leading {
                format!("\u{85}{NOW}")
            } else {
                format!("{NOW}\u{85}")
            };
            let token = hand_made(
                &original,
                Some(signer.as_ref()),
                &[("iat", Some(json!(text)))],
            );
            let response = handle(&state, "POST", LOOKUP, &json!({"idToken": token}));
            assert_eq!(response.status, 400);
            assert_eq!(
                response.body["error"]["message"],
                if profile == Profile::Emulator {
                    "TOKEN_EXPIRED"
                } else {
                    "INVALID_ID_TOKEN"
                }
            );
        }
    }
}
