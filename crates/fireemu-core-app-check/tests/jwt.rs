//! Compact-JWT and base64url handling (specification section 20: property-based tests are
//! appropriate for compact-JWT parsing, base64url input and time boundaries).
//!
//! The generators are seeded `SplitMix64` instances, so every case is reproducible from the
//! seed in the assertion message.

mod support;

use fireemu_core_app_check::jwt::{base64url_decode, base64url_encode, encode, split_compact};
use fireemu_core_app_check::registry::AppCheckRegistry;
use fireemu_core_app_check::verify::{verify_token, AppCheckFailure};
use fireemu_core_types::determinism::{DeterministicRng, SplitMix64};
use fireemu_core_types::time::LogicalInstant;
use support::{fixture_registry, TestSigner, DEMO_APP_ID};

const START: i64 = 1_788_004_860;

/// A bounded index from the seeded generator, without a lossy cast.
fn below(rng: &mut SplitMix64, bound: usize) -> usize {
    usize::try_from(rng.next_below(bound as u64)).unwrap_or(0)
}

#[test]
fn prop_app_check_base64url_round_trips() {
    let mut rng = SplitMix64::new(0x00A9_C11E_C4EC_0002);
    for case in 0..2000u64 {
        let len = below(&mut rng, 40);
        let bytes: Vec<u8> = (0..len)
            .map(|_| u8::try_from(rng.next_below(256)).unwrap_or(0))
            .collect();
        let encoded = base64url_encode(&bytes);
        assert!(
            encoded
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "case {case}: unpadded base64url has no '=' and no '+' or '/'"
        );
        assert_eq!(
            base64url_decode(&encoded).as_deref(),
            Ok(bytes.as_slice()),
            "case {case}"
        );
    }
}

#[test]
fn prop_app_check_base64url_rejects_foreign_alphabets() {
    let mut rng = SplitMix64::new(0x00A9_C11E_C4EC_0003);
    let foreign = ['=', '+', '/', ' ', '\n', '!', 'é'];
    for case in 0..1000u64 {
        let len = 1 + below(&mut rng, 12);
        let bytes: Vec<u8> = (0..len)
            .map(|_| u8::try_from(rng.next_below(256)).unwrap_or(0))
            .collect();
        let mut text = base64url_encode(&bytes);
        let injected = foreign[below(&mut rng, foreign.len())];
        let at = below(&mut rng, text.len() + 1);
        // Insert on a character boundary; the encoded text is all ASCII.
        text.insert(at.min(text.len()), injected);
        assert_eq!(
            base64url_decode(&text),
            Err(AppCheckFailure::Malformed),
            "case {case}: {text:?} is not unpadded base64url"
        );
    }
}

#[test]
fn prop_app_check_compact_jwt_needs_exactly_three_non_empty_segments() {
    let mut rng = SplitMix64::new(0x00A9_C11E_C4EC_0004);
    for case in 0..2000u64 {
        let segments = below(&mut rng, 6);
        let parts: Vec<String> = (0..segments)
            .map(|_| {
                let len = below(&mut rng, 4);
                base64url_encode(
                    &(0..len)
                        .map(|_| u8::try_from(rng.next_below(256)).unwrap_or(0))
                        .collect::<Vec<u8>>(),
                )
            })
            .collect();
        let token = parts.join(".");
        let expected_ok = segments == 3 && parts.iter().all(|p| !p.is_empty());
        assert_eq!(
            split_compact(&token).is_ok(),
            expected_ok,
            "case {case}: {token:?} has {segments} segment(s)"
        );
    }
}

#[test]
fn prop_app_check_token_time_boundaries() {
    // Around every boundary the answer is exact: `iat <= now < exp`, with no leeway either
    // side. The token is re-issued for each generated `iat` and checked at nine offsets.
    let registry: AppCheckRegistry = fixture_registry();
    let signer = TestSigner::new(1);
    let mut rng = SplitMix64::new(0x00A9_C11E_C4EC_0005);
    for case in 0..200u64 {
        let issued = START + i64::try_from(rng.next_below(100_000)).unwrap_or(0);
        let claims = registry
            .issue_claims(
                "demo-app",
                DEMO_APP_ID,
                LogicalInstant::from_unix_seconds(issued),
            )
            .expect("the fixture app issues");
        let token = encode(&claims, &signer);
        let exp = claims.exp;
        for (offset, valid) in [
            (issued - 2, false),
            (issued - 1, false),
            (issued, true),
            (issued + 1, true),
            (exp - 2, true),
            (exp - 1, true),
            (exp, false),
            (exp + 1, false),
        ] {
            let result = verify_token(
                &token,
                &registry,
                "demo-app",
                &signer,
                LogicalInstant::from_unix_seconds(offset),
            );
            assert_eq!(
                result.is_ok(),
                valid,
                "case {case}: iat {issued}, exp {exp}, now {offset}: {result:?}"
            );
        }
        // Sub-second instants never round a token into or out of validity.
        let just_before_exp = LogicalInstant::from_nanos(i128::from(exp) * 1_000_000_000 - 1);
        assert!(verify_token(&token, &registry, "demo-app", &signer, just_before_exp).is_ok());
        let at_exp = LogicalInstant::from_nanos(i128::from(exp) * 1_000_000_000);
        assert_eq!(
            verify_token(&token, &registry, "demo-app", &signer, at_exp),
            Err(AppCheckFailure::Expired),
            "case {case}"
        );
    }
}

#[test]
fn prop_app_check_single_byte_edits_never_verify() {
    // Flipping one byte of a valid token anywhere makes it fail, whatever the segment.
    let registry = fixture_registry();
    let signer = TestSigner::new(1);
    let claims = registry
        .issue_claims(
            "demo-app",
            DEMO_APP_ID,
            LogicalInstant::from_unix_seconds(START),
        )
        .unwrap();
    let token = encode(&claims, &signer);
    let now = LogicalInstant::from_unix_seconds(START);
    assert!(verify_token(&token, &registry, "demo-app", &signer, now).is_ok());

    let mut rng = SplitMix64::new(0x00A9_C11E_C4EC_0006);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for case in 0..500u64 {
        let mut bytes = token.clone().into_bytes();
        let at = below(&mut rng, bytes.len());
        if bytes[at] == b'.' {
            continue;
        }
        let mut replacement = alphabet[below(&mut rng, alphabet.len())];
        if replacement == bytes[at] {
            replacement = if replacement == b'A' { b'B' } else { b'A' };
        }
        bytes[at] = replacement;
        let edited = String::from_utf8(bytes).expect("the alphabet is ASCII");
        assert!(
            verify_token(&edited, &registry, "demo-app", &signer, now).is_err(),
            "case {case}: a one-byte edit at {at} must not verify"
        );
    }
}
