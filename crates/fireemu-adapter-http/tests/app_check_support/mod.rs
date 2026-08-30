//! Shared App Check fixtures for the enforcement tests of milestone AC1.
//!
//! The signer is the real `rsa` / `sha2` implementation the daemon uses, seeded through the
//! constructor seam (`AppCheckKeySource::Seed`) so the tokens are reproducible. RSA key
//! generation is slow in a debug build, so one key per seed is generated per test binary.
//!
//! The credential builders below produce exactly the credential states the enforcement matrix
//! of specification section 19 asks for: valid, malformed, bad signature, expired, wrong
//! project and unknown app.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use fireemu_adapter_http::app_check::AppCheckState;
use fireemu_adapter_http::signing::{
    AppCheckKeySource, AppCheckRsaSigner, OsDebugSecrets, Sha256DebugTokenHasher,
    SubtleConstantTimeEq,
};
use fireemu_core_app_check::admission::ServiceAdmission;
use fireemu_core_app_check::claims::{audiences_for, issuer_for, AppCheckClaims};
use fireemu_core_app_check::crypto::DebugTokenHasher;
use fireemu_core_app_check::registry::{
    AppCheckRegistry, AppRegistration, DebugTokenDigest, ProjectEpoch,
};
use fireemu_core_app_check::verify::BaselineMode;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;

/// The virtual-clock start every fixture shares.
pub const START: i64 = 1_788_004_860;
/// The control token the fixtures' privileged routes require.
pub const CONTROL_TOKEN: &str = "test-control-token";
/// The registered app of the `demo-app` project.
pub const APP_ID: &str = "1:1234567890:web:local-test-app";
/// A second registered app of the same `demo-app` project: two apps of one project are what
/// tells "another app" apart from "another project".
pub const SECOND_APP_ID: &str = "1:1234567890:web:second-test-app";
/// The registered app of the `demo-other` project.
pub const OTHER_APP_ID: &str = "1:9876543210:web:other-test-app";
/// A well-formed but never registered app ID, for the unknown-app credential state.
pub const UNREGISTERED_APP_ID: &str = "1:1234567890:web:not-registered";
/// The debug secret registered for [`APP_ID`].
pub const SECRET: &str = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
/// The debug secret registered for [`SECOND_APP_ID`].
pub const SECOND_SECRET: &str = "22222222-2222-4222-9222-222222222222";
/// The debug secret registered for [`OTHER_APP_ID`].
pub const OTHER_SECRET: &str = "11111111-1111-4111-9111-111111111111";

/// One RSA key per seed, generated once for the whole test binary.
#[must_use]
pub fn signer(seed: u64) -> Arc<AppCheckRsaSigner> {
    static KEYS: OnceLock<Mutex<BTreeMap<u64, Arc<AppCheckRsaSigner>>>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut keys = keys.lock().expect("the key cache is not poisoned");
    keys.entry(seed)
        .or_insert_with(|| {
            AppCheckRsaSigner::generate(AppCheckKeySource::Seed(seed)).expect("key generation")
        })
        .clone()
}

/// The SHA-256 digest of a canonical debug secret, under the shell's real hasher.
#[must_use]
pub fn digest_of(secret: &str) -> DebugTokenDigest {
    let canonical = fireemu_core_app_check::exchange::canonical_debug_token(secret)
        .expect("the fixture secret is a canonical UUIDv4");
    DebugTokenDigest::from_bytes(Sha256DebugTokenHasher.sha256(canonical.as_bytes()))
}

/// Two registered projects — `demo-app` with two apps, `demo-other` with one — and an epoch
/// each.
#[must_use]
pub fn registry() -> AppCheckRegistry {
    let mut registry = AppCheckRegistry::new(3600).expect("3600s is inside the TTL range");
    registry
        .register_app(AppRegistration {
            project_id: "demo-app".to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: vec![digest_of(SECRET)],
        })
        .expect("the demo app registers");
    registry
        .register_app(AppRegistration {
            project_id: "demo-app".to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: SECOND_APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: vec![digest_of(SECOND_SECRET)],
        })
        .expect("the second app of the demo project registers");
    registry
        .register_app(AppRegistration {
            project_id: "demo-other".to_owned(),
            project_number: "9876543210".to_owned(),
            app_id: OTHER_APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: vec![digest_of(OTHER_SECRET)],
        })
        .expect("the second app registers");
    registry.set_project_epoch("demo-app", ProjectEpoch::new(0x0123_4567_89AB_CDEF));
    registry.set_project_epoch("demo-other", ProjectEpoch::new(0xFEDC_BA98_7654_3210));
    registry
}

/// A clock pinned at [`START`].
#[must_use]
pub fn clock() -> Arc<Mutex<VirtualClock>> {
    Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(START),
    )))
}

/// The App Check state the exchange routes and the product policies share.
#[must_use]
pub fn app_check_state(seed: u64, clock: Arc<Mutex<VirtualClock>>) -> Arc<AppCheckState> {
    Arc::new(AppCheckState {
        registry: Arc::new(RwLock::new(registry())),
        signer: signer(seed),
        clock,
        control_token: CONTROL_TOKEN.to_owned(),
        hasher: Arc::new(Sha256DebugTokenHasher),
        constant_time: Arc::new(SubtleConstantTimeEq),
        secrets: Arc::new(OsDebugSecrets),
        barrier: None,
    })
}

/// One product's policy over the state's gate, or `None` for `off`.
#[must_use]
pub fn policy(
    state: &AppCheckState,
    service: &'static str,
    mode: BaselineMode,
) -> Option<Arc<ServiceAdmission>> {
    ServiceAdmission::new(state.gate(), service, mode).map(Arc::new)
}

/// A valid session token for a registered app, issued at `at`.
#[must_use]
pub fn token_at(state: &AppCheckState, project: &str, app_id: &str, at: i64) -> String {
    let registry = state.registry.read().expect("the registry is readable");
    let claims = registry
        .issue_claims(project, app_id, LogicalInstant::from_unix_seconds(at))
        .expect("the fixture app may exchange");
    fireemu_core_app_check::jwt::encode(&claims, state.signer.as_ref())
}

/// A valid session token for a registered app, issued at [`START`].
#[must_use]
pub fn token(state: &AppCheckState, project: &str, app_id: &str) -> String {
    token_at(state, project, app_id, START)
}

/// A token whose signature was altered after issuance.
#[must_use]
pub fn bad_signature(state: &AppCheckState) -> String {
    let valid = token(state, "demo-app", APP_ID);
    let (input, signature) = valid
        .rsplit_once('.')
        .expect("a compact JWT has three parts");
    let mut bytes: Vec<char> = signature.chars().collect();
    let last = bytes.len() - 1;
    bytes[last] = if bytes[last] == 'A' { 'B' } else { 'A' };
    format!("{input}.{}", bytes.into_iter().collect::<String>())
}

/// A token that expired before the fixture clock.
#[must_use]
pub fn expired(state: &AppCheckState) -> String {
    token_at(state, "demo-app", APP_ID, START - 7200)
}

/// A valid token for the *other app of the same project*: the credential a resumable upload
/// session started by [`APP_ID`] must refuse.
#[must_use]
pub fn other_app(state: &AppCheckState) -> String {
    token(state, "demo-app", SECOND_APP_ID)
}

/// A correctly signed token for the other registered project.
#[must_use]
pub fn wrong_project(state: &AppCheckState) -> String {
    token(state, "demo-other", OTHER_APP_ID)
}

/// A correctly signed, correctly addressed token whose subject names no registered app.
#[must_use]
pub fn unknown_app(state: &AppCheckState) -> String {
    let epoch = state
        .registry
        .read()
        .expect("readable")
        .project_epoch("demo-app")
        .expect("the fixture project has an epoch");
    let claims = AppCheckClaims {
        iss: issuer_for("1234567890"),
        sub: UNREGISTERED_APP_ID.to_owned(),
        aud: audiences_for("1234567890", "demo-app"),
        iat: START,
        exp: START + 3600,
        jti: "forged-1".to_owned(),
        fireemu_epoch: epoch.claim_text(),
    };
    fireemu_core_app_check::jwt::encode(&claims, state.signer.as_ref())
}

/// Every credential state the enforcement matrix of section 19 enumerates, as the header
/// values a transport would present. `None` means "send no field at all".
#[must_use]
pub fn credential_states(state: &AppCheckState) -> Vec<(&'static str, Option<String>)> {
    vec![
        ("missing", None),
        ("valid", Some(token(state, "demo-app", APP_ID))),
        ("malformed", Some("not-a-jwt".to_owned())),
        ("bad signature", Some(bad_signature(state))),
        ("expired", Some(expired(state))),
        ("wrong project", Some(wrong_project(state))),
        ("unknown app", Some(unknown_app(state))),
    ]
}
