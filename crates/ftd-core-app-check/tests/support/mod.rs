//! Test doubles for the core's cryptographic seams and a seeded registry builder.
//!
//! The core owns no primitive, so its tests supply their own: a keyed, deterministic tag
//! instead of RS256 and a keyed digest instead of SHA-256. They are reproducible and
//! collision-free for the inputs these tests use, and they are emphatically not cryptography.
//! The real `sha2` / `subtle` / `rsa` implementations are exercised by the adapter tests.

#![allow(dead_code)]

use ftd_core_app_check::crypto::{AppCheckSigner, ConstantTimeEq, DebugTokenHasher};
use ftd_core_app_check::registry::{
    AppCheckRegistry, AppRegistration, DebugTokenDigest, ProjectEpoch,
};
use ftd_core_types::determinism::{DeterministicRng, SplitMix64};

/// A keyed 256-bit tag over the input. Two signers with different keys never agree.
fn keyed_tag(key: u64, domain: u64, input: &[u8]) -> [u8; 32] {
    let mut state = SplitMix64::new(key ^ domain);
    let mut acc = state.next_u64();
    for byte in input {
        acc = SplitMix64::new(acc ^ u64::from(*byte).wrapping_mul(0x9E37_79B9)).next_u64();
    }
    let mut out = [0u8; 32];
    for chunk in 0..4 {
        let word = SplitMix64::new(acc ^ (chunk as u64)).next_u64();
        out[chunk * 8..chunk * 8 + 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// A deterministic stand-in for the RS256 signer.
pub struct TestSigner {
    key: u64,
    kid: String,
}

impl TestSigner {
    /// A signer with its own key. Different keys produce different `kid`s and reject each
    /// other's tokens.
    #[must_use]
    pub fn new(key: u64) -> Self {
        Self {
            key,
            kid: format!("ftd-app-check-{key:016x}"),
        }
    }
}

impl AppCheckSigner for TestSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    fn sign(&self, signing_input: &[u8]) -> Vec<u8> {
        keyed_tag(self.key, 0x5349_474E, signing_input).to_vec()
    }

    fn verify(&self, signing_input: &[u8], signature: &[u8]) -> bool {
        signature == self.sign(signing_input)
    }

    fn public_jwk_json(&self) -> String {
        format!(
            r#"{{"kty":"oct","alg":"RS256","use":"sig","kid":"{}"}}"#,
            self.kid
        )
    }
}

/// A deterministic stand-in for SHA-256.
pub struct TestHasher;

impl DebugTokenHasher for TestHasher {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        keyed_tag(0, 0x4841_5348, input)
    }
}

/// A branch-free byte comparison, like the `subtle` implementation in the shell.
pub struct TestEq;

impl ConstantTimeEq for TestEq {
    fn eq(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

/// The digest of a debug secret under [`TestHasher`].
#[must_use]
pub fn digest_of(secret: &str) -> DebugTokenDigest {
    let canonical = ftd_core_app_check::exchange::canonical_debug_token(secret)
        .expect("the test secret is a canonical UUIDv4");
    DebugTokenDigest::from_bytes(TestHasher.sha256(canonical.as_bytes()))
}

/// An epoch drawn from a seeded generator; the daemon draws it from the OS CSPRNG.
#[must_use]
pub fn seeded_epoch(seed: u64) -> ProjectEpoch {
    let mut rng = SplitMix64::new(seed);
    ProjectEpoch::new((u128::from(rng.next_u64()) << 64) | u128::from(rng.next_u64()))
}

/// The debug secret every fixture registers for `demo-app`.
pub const DEMO_SECRET: &str = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

/// The debug secret registered for the second fixture project.
pub const OTHER_SECRET: &str = "11111111-1111-4111-9111-111111111111";

/// The `demo-app` app ID.
pub const DEMO_APP_ID: &str = "1:1234567890:web:local-test-app";

/// The `demo-other` app ID.
pub const OTHER_APP_ID: &str = "1:9876543210:web:other-test-app";

/// A registry with two projects, one app each, a static digest each, and fresh epochs.
#[must_use]
pub fn fixture_registry() -> AppCheckRegistry {
    let mut registry = AppCheckRegistry::new(3600).expect("3600s is inside the TTL range");
    registry
        .register_app(AppRegistration {
            project_id: "demo-app".to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: DEMO_APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: vec![digest_of(DEMO_SECRET)],
        })
        .expect("the demo app registers");
    registry
        .register_app(AppRegistration {
            project_id: "demo-other".to_owned(),
            project_number: "9876543210".to_owned(),
            app_id: OTHER_APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: vec![digest_of(OTHER_SECRET)],
        })
        .expect("the second app registers");
    registry.set_project_epoch("demo-app", seeded_epoch(1));
    registry.set_project_epoch("demo-other", seeded_epoch(2));
    registry
}
