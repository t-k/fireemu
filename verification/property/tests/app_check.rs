//! Property artifacts for `AC-TOKEN-001`, `AC-EXCHANGE-001` and `AC-HEADER-001`
//! (`docs/specifications/firebase-app-check.md` sections 7.3, 10.1 and 11).
//!
//! The core owns no primitive, so these tests supply keyed, deterministic stand-ins for RS256
//! and SHA-256. They are reproducible and collision-free over the generated inputs, and they
//! are not cryptography; the real `rsa` / `sha2` / `subtle` implementations are exercised by
//! `crates/ftd-adapter-http/tests/app_check.rs`.

use ftd_core_app_check::crypto::{AppCheckSigner, ConstantTimeEq, DebugTokenHasher};
use ftd_core_app_check::exchange::{
    canonical_debug_token, exchange, ExchangeOutcome, ExchangeRequest,
};
use ftd_core_app_check::header::{classify_app_check_header, HeaderClassification};
use ftd_core_app_check::jwt::encode;
use ftd_core_app_check::limits::MAX_TOKEN_BYTES;
use ftd_core_app_check::registry::{
    AppCheckRegistry, AppRegistration, DebugTokenDigest, ProjectEpoch,
};
use ftd_core_app_check::verify::{verify_token, AppCheckFailure};
use ftd_core_types::determinism::{DeterministicRng, SplitMix64};
use ftd_core_types::time::LogicalInstant;
use proptest::prelude::*;

const APP_ID: &str = "1:1234567890:web:local-test-app";
const START: i64 = 1_788_004_860;

fn keyed_tag(key: u64, domain: u64, input: &[u8]) -> [u8; 32] {
    let mut acc = SplitMix64::new(key ^ domain).next_u64();
    for byte in input {
        acc = SplitMix64::new(acc ^ u64::from(*byte).wrapping_mul(0x9E37_79B9)).next_u64();
    }
    let mut out = [0u8; 32];
    for (chunk, slot) in out.chunks_mut(8).enumerate() {
        slot.copy_from_slice(&SplitMix64::new(acc ^ chunk as u64).next_u64().to_be_bytes());
    }
    out
}

struct TestSigner {
    key: u64,
    kid: String,
}

impl TestSigner {
    fn new(key: u64) -> Self {
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
        format!(r#"{{"kty":"oct","kid":"{}"}}"#, self.kid)
    }
}

struct TestHasher;

impl DebugTokenHasher for TestHasher {
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        keyed_tag(0, 0x4841_5348, input)
    }
}

struct TestEq;

impl ConstantTimeEq for TestEq {
    fn eq(&self, a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

fn digest_of(secret: &str) -> DebugTokenDigest {
    let canonical = canonical_debug_token(secret).expect("a canonical UUIDv4");
    DebugTokenDigest::from_bytes(TestHasher.sha256(canonical.as_bytes()))
}

/// A registry holding one enabled app of `demo-app` with `secret` registered.
fn registry(secret: &str, ttl: i64) -> AppCheckRegistry {
    let mut registry = AppCheckRegistry::new(ttl).expect("the TTL is inside the range");
    registry
        .register_app(AppRegistration {
            project_id: "demo-app".to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: vec![digest_of(secret)],
        })
        .expect("the fixture app registers");
    registry.set_project_epoch("demo-app", ProjectEpoch::new(0x0123_4567_89AB_CDEF));
    registry
}

/// Renders 16 bytes as a canonical `UUIDv4`.
fn uuid_v4(bytes: [u8; 16]) -> String {
    let mut b = bytes;
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    let hex = |slice: &[u8]| {
        slice
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(&b[0..4]),
        hex(&b[4..6]),
        hex(&b[6..8]),
        hex(&b[8..10]),
        hex(&b[10..16])
    )
}

proptest! {
    /// AC-TOKEN-001: the virtual-clock window is exactly `iat <= now < exp`. There is no
    /// leeway on either side, at any TTL inside the configured range, and `now == exp` is
    /// always expired.
    #[test]
    fn prop_app_check_token_window_is_half_open(
        ttl in 1800i64..=604_800,
        issued_offset in -100_000i64..100_000,
        probe in -5i64..5,
    ) {
        let secret = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
        let registry = registry(secret, ttl);
        let signer = TestSigner::new(1);
        let issued = START + issued_offset;
        let claims = registry
            .issue_claims("demo-app", APP_ID, LogicalInstant::from_unix_seconds(issued))
            .expect("the fixture app issues");
        let token = encode(&claims, &signer);
        prop_assert_eq!(claims.exp, issued + ttl);

        for anchor in [issued, claims.exp] {
            let now = anchor + probe;
            let result = verify_token(
                &token,
                &registry,
                "demo-app",
                &signer,
                LogicalInstant::from_unix_seconds(now),
            );
            let expected_ok = now >= issued && now < claims.exp;
            prop_assert_eq!(result.is_ok(), expected_ok, "iat {} exp {} now {}", issued, claims.exp, now);
            if !expected_ok {
                prop_assert!(matches!(
                    result,
                    Err(AppCheckFailure::NotYetValid | AppCheckFailure::Expired)
                ));
            }
        }
    }

    /// AC-TOKEN-001: a token minted by another instance's key never verifies, whatever the
    /// key ID it claims. Two normally started daemons share their configuration but not
    /// their key, which is what `INV-APPCHECK-011` requires.
    #[test]
    fn prop_app_check_foreign_keys_never_verify(own in any::<u64>(), foreign in any::<u64>()) {
        prop_assume!(own != foreign);
        let secret = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
        let registry = registry(secret, 3600);
        let mine = TestSigner::new(own);
        let theirs = TestSigner::new(foreign);
        let now = LogicalInstant::from_unix_seconds(START);
        let claims = registry
            .issue_claims("demo-app", APP_ID, now)
            .expect("the fixture app issues");

        // Signed by the other instance and labelled with its own key ID.
        let theirs_token = encode(&claims, &theirs);
        prop_assert_eq!(
            verify_token(&theirs_token, &registry, "demo-app", &mine, now),
            Err(AppCheckFailure::UnknownKeyId)
        );
        // Signed by the other instance but relabelled with this instance's key ID.
        let relabelled = theirs_token.replacen(
            &ftd_core_app_check::jwt::base64url_encode(
                format!(r#"{{"alg":"RS256","kid":"{}","typ":"JWT"}}"#, theirs.kid()).as_bytes(),
            ),
            &ftd_core_app_check::jwt::base64url_encode(
                format!(r#"{{"alg":"RS256","kid":"{}","typ":"JWT"}}"#, mine.kid()).as_bytes(),
            ),
            1,
        );
        prop_assert_eq!(
            verify_token(&relabelled, &registry, "demo-app", &mine, now),
            Err(AppCheckFailure::BadSignature)
        );
        // The instance's own token still verifies.
        prop_assert!(verify_token(&encode(&claims, &mine), &registry, "demo-app", &mine, now).is_ok());
    }

    /// AC-EXCHANGE-001: only a digest that is registered for the target app produces a token,
    /// and the public outcome of every other combination is the same `AttestationFailed`.
    #[test]
    fn prop_app_check_exchange_needs_the_registered_digest(
        registered in any::<[u8; 16]>(),
        presented in any::<[u8; 16]>(),
        project in prop::sample::select(vec!["demo-app", "1234567890", "demo-other", "5555555555"]),
        app in prop::sample::select(vec![APP_ID, "1:1234567890:web:other", ""]),
    ) {
        let registered = uuid_v4(registered);
        let presented_text = uuid_v4(presented);
        let registry = registry(&registered, 3600);
        let now = LogicalInstant::from_unix_seconds(START);
        let outcome = exchange(
            &registry,
            &ExchangeRequest {
                project_selector: &project,
                app_id: &app,
                debug_token: &presented_text,
                limited_use: false,
            },
            &TestHasher,
            &TestEq,
            now,
        );
        let should_issue = presented_text == registered
            && (project == "demo-app" || project == "1234567890")
            && app == APP_ID;
        match outcome {
            ExchangeOutcome::Issued(claims) => {
                prop_assert!(should_issue);
                prop_assert_eq!(&claims.sub, APP_ID);
                prop_assert_eq!(&claims.iss, "https://firebaseappcheck.googleapis.com/1234567890");
            }
            other => {
                prop_assert!(!should_issue, "{:?} for {} {} ", other, project, app);
                prop_assert_eq!(other, ExchangeOutcome::AttestationFailed);
            }
        }
    }

    /// AC-EXCHANGE-001: `limitedUse: true` never yields a reusable token, whatever else the
    /// request says.
    #[test]
    fn prop_app_check_limited_use_always_fails_closed(
        secret in any::<[u8; 16]>(),
        project in prop::sample::select(vec!["demo-app", "demo-nope"]),
    ) {
        let registered = uuid_v4(secret);
        let registry = registry(&registered, 3600);
        let outcome = exchange(
            &registry,
            &ExchangeRequest {
                project_selector: &project,
                app_id: APP_ID,
                debug_token: &registered,
                limited_use: true,
            },
            &TestHasher,
            &TestEq,
            LogicalInstant::from_unix_seconds(START),
        );
        prop_assert_eq!(outcome, ExchangeOutcome::ReplayUnsupported);
    }

    /// AC-HEADER-001: the classification depends on the multiset of values only, never on
    /// their order, and only a single eligible value is ever `Present`.
    #[test]
    fn prop_app_check_header_never_selects_one_of_several(
        values in prop::collection::vec("[\x20-\x7e]{0,8}", 0..4),
    ) {
        let eligible = |v: &String| {
            !v.is_empty()
                && v.len() <= MAX_TOKEN_BYTES
                && v.bytes().all(|b| (0x21..=0x7E).contains(&b) && b != b',')
        };
        let expected = match values.as_slice() {
            [] => HeaderClassification::Missing,
            [only] if eligible(only) => HeaderClassification::Present(only.clone()),
            _ => HeaderClassification::Malformed,
        };
        prop_assert_eq!(classify_app_check_header(&values), expected.clone());

        let mut reversed = values.clone();
        reversed.reverse();
        if values.len() == 1 {
            prop_assert_eq!(classify_app_check_header(&reversed), expected);
        } else {
            prop_assert_eq!(classify_app_check_header(&reversed), expected);
            prop_assert!(!matches!(
                classify_app_check_header(&values),
                HeaderClassification::Present(_)
            ));
        }

        // Duplicating any value is always ambiguous, and a folded value is never eligible.
        if let [only] = values.as_slice() {
            prop_assert_eq!(
                classify_app_check_header(&[only.clone(), only.clone()]),
                HeaderClassification::Malformed
            );
            prop_assert_eq!(
                classify_app_check_header(&[format!("{only},{only}")]),
                HeaderClassification::Malformed
            );
        }
    }
}
