//! Owner ledger 787: the emulator profile accepts the hand-made ID-token shapes that
//! firebase-tools 15.28.2 accepts (`parseIdToken`, `lib/emulator/auth/operations.js:1715-1731`,
//! which reads `iat` only as `iat >= Number(user.validSince)` and never reads `auth_time` or
//! `exp`): a missing, numeric-string or fractional `iat`, a missing `auth_time` and a missing
//! `exp`. Strict keeps refusing them. An `exp` that is present still has to be an integer and
//! unexpired past the allowance (ledger 22), and signatures are still verified (ledger 713).
//!
//! Local regression cases, not production observations: such a token cannot be produced
//! against production.

use std::sync::Arc;

use fireemu_core_auth::claims::{ClaimValue, IdTokenClaims};
use fireemu_core_auth::jwt::{
    base64url_encode, encode_payload_with, verify_firestore_rules_token, verify_firestore_token,
    verify_id_token_decoded_with_leeway, verify_rules_token, verify_rules_token_for_project,
    FutureClaims, IdTokenSigner, JwtError, TokenAcceptance, IDENTITY_TOOLKIT_EXPIRY_LEEWAY_SECONDS,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, LocalId, NewUser};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::json::{parse, JsonValue};
use fireemu_core_types::time::LogicalInstant;

const NOW: i64 = 1_788_004_860;
const PROJECT: &str = "demo-hand-made";

fn at(seconds: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(seconds)
}

/// A deterministic stand-in for the session RSA signer, so the verified path (not the
/// emulator profile's unsigned mock fallback) decides.
struct ReversingSigner;

impl IdTokenSigner for ReversingSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }
    fn kid(&self) -> &'static str {
        "test"
    }
    fn sign(&self, signing_input: &[u8]) -> Vec<u8> {
        signing_input.iter().rev().copied().collect()
    }
    fn verify(&self, signing_input: &[u8], signature: &[u8]) -> bool {
        self.sign(signing_input) == signature
    }
    fn public_jwk_json(&self) -> String {
        "{}".to_owned()
    }
}

/// Which account the token names: without a `validSince` (an anonymous account), with one
/// because a password is set, or with one because its tokens were revoked after `REVOKED_AT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Account {
    Anonymous,
    Password,
    Revoked,
}

const CREATED_AT: i64 = NOW - 600;
const REVOKED_AT: i64 = NOW - 100;

fn store_with(account: Account) -> (AuthStore, IdTokenClaims, LocalId) {
    let mut store = AuthStore::new(PROJECT, SplitMix64::new(11), TotpPolicy::default());
    store.set_signer(Arc::new(ReversingSigner));
    let uid = store
        .create_user(NewUser::anonymous(), at(CREATED_AT))
        .unwrap();
    match account {
        Account::Anonymous => {}
        Account::Password => store
            .set_password(&uid, "password1", at(CREATED_AT))
            .unwrap(),
        Account::Revoked => store.revoke_tokens(&uid, at(REVOKED_AT)).unwrap(),
    }
    let mut claims = store.id_token_claims(&uid, None, at(NOW)).unwrap();
    claims.auth_time = NOW - 10;
    claims.iat = NOW - 10;
    claims.exp = NOW + 3590;
    (store, claims, uid)
}

/// `claims` signed by the session signer, with each `(key, raw JSON or removal)` applied.
fn token_with(
    store: &AuthStore,
    claims: &IdTokenClaims,
    changes: &[(&str, Option<&str>)],
) -> String {
    let JsonValue::Object(mut members) = parse(&claims.canonical_json()).unwrap() else {
        panic!("claims must encode an object");
    };
    for (key, replacement) in changes {
        match replacement {
            Some(raw) => {
                members.insert((*key).to_owned(), parse(raw).unwrap());
            }
            None => {
                members.remove(*key);
            }
        }
    }
    let mut payload = String::new();
    ClaimValue::from_json(&JsonValue::Object(members)).write_canonical_json(&mut payload);
    encode_payload_with(&payload, store.signer())
}

/// One verifier's answer under a profile: Identity Toolkit (the store policy), Firestore (the
/// store policy and the Rules entry point) and the ID-token Rules entry points (Storage and the
/// callable verifier use them).
fn answers(
    store: &mut AuthStore,
    token: &str,
    emulator: bool,
) -> Vec<(&'static str, Result<(), JwtError>)> {
    let (policy, acceptance) = if emulator {
        (FutureClaims::Accept, TokenAcceptance::EmulatorMock)
    } else {
        (FutureClaims::Refuse, TokenAcceptance::Verified)
    };
    store.set_future_id_token_claims(policy);
    let now = at(NOW);
    vec![
        (
            "identity-toolkit",
            verify_id_token_decoded_with_leeway(
                token,
                store,
                now,
                IDENTITY_TOOLKIT_EXPIRY_LEEWAY_SECONDS,
            )
            .map(|_| ()),
        ),
        (
            "firestore",
            verify_firestore_token(token, store, now).map(|_| ()),
        ),
        (
            "firestore-rules",
            verify_firestore_rules_token(token, store, now, acceptance, None).map(|_| ()),
        ),
        (
            "id-rules",
            verify_rules_token(token, store, now, acceptance).map(|_| ()),
        ),
        (
            "id-rules-for-project",
            verify_rules_token_for_project(token, store, now, acceptance, PROJECT).map(|_| ()),
        ),
    ]
}

const SHAPES: [(&str, &str, Option<&str>); 6] = [
    ("iat missing", "iat", None),
    ("iat as a numeric string", "iat", Some("\"1788004850\"")),
    ("iat as a fraction", "iat", Some("1788004850.5")),
    (
        "iat as a fraction in exponent form",
        "iat",
        Some("1.78800485e9"),
    ),
    ("auth_time missing", "auth_time", None),
    ("exp missing", "exp", None),
];

#[test]
fn each_hand_made_shape_is_accepted_in_the_emulator_profile_and_refused_in_strict_on_every_verifier(
) {
    for (name, key, replacement) in SHAPES {
        let (mut store, claims, _) = store_with(Account::Anonymous);
        let token = token_with(&store, &claims, &[(key, replacement)]);
        for (verifier, answer) in answers(&mut store, &token, true) {
            assert_eq!(answer, Ok(()), "emulator {verifier}: {name}");
        }
        for (verifier, answer) in answers(&mut store, &token, false) {
            assert_eq!(
                answer,
                Err(JwtError::Malformed),
                "strict {verifier}: {name}"
            );
        }
    }
}

#[test]
fn all_five_shapes_at_once_are_accepted_in_the_emulator_profile_only() {
    let (mut store, claims, _) = store_with(Account::Anonymous);
    let token = token_with(
        &store,
        &claims,
        &[("iat", None), ("auth_time", None), ("exp", None)],
    );
    for (verifier, answer) in answers(&mut store, &token, true) {
        assert_eq!(answer, Ok(()), "emulator {verifier}");
    }
    for (verifier, answer) in answers(&mut store, &token, false) {
        assert_eq!(answer, Err(JwtError::Malformed), "strict {verifier}");
    }
}

/// firebase-tools refuses `TOKEN_EXPIRED` when the account has a `validSince` and
/// `iat >= Number(validSince)` is false, which it is for a missing or unreadable `iat`. Identity
/// Toolkit (and the account check behind the ID-token Rules entry points) does the same in the
/// emulator profile; Firestore never reads the account.
#[test]
fn an_unusable_iat_is_refused_as_expired_only_for_an_account_with_a_valid_since() {
    for (raw, label) in [(None, "missing"), (Some("\"soon\""), "non-numeric string")] {
        for account in [Account::Anonymous, Account::Password, Account::Revoked] {
            let (mut store, claims, _) = store_with(account);
            let token = token_with(&store, &claims, &[("iat", raw)]);
            let expected_account = if account == Account::Anonymous {
                Ok(())
            } else {
                Err(JwtError::Revoked)
            };
            for (verifier, answer) in answers(&mut store, &token, true) {
                let expected = if verifier.starts_with("firestore") {
                    Ok(())
                } else {
                    expected_account.clone()
                };
                assert_eq!(
                    answer, expected,
                    "emulator {verifier}: iat {label}, {account:?}"
                );
            }
        }
    }
}

/// With a numeric `iat`, the comparison is firebase-tools' `iat >= Number(validSince)`: an
/// `iat` from before the account's revocation is refused, one from its second on is accepted,
/// whatever its JSON type.
#[test]
fn a_numeric_iat_without_auth_time_is_compared_with_valid_since() {
    for (raw, accepted) in [
        (format!("{}", REVOKED_AT - 1), false),
        (format!("\"{}\"", REVOKED_AT - 1), false),
        (format!("{}.5", REVOKED_AT - 1), false),
        (format!("{REVOKED_AT}"), true),
        (format!("\"{REVOKED_AT}\""), true),
        (format!("\" {REVOKED_AT} \""), true),
        (format!("{REVOKED_AT}.25"), true),
    ] {
        let (mut store, claims, _) = store_with(Account::Revoked);
        let token = token_with(&store, &claims, &[("auth_time", None), ("iat", Some(&raw))]);
        let toolkit = answers(&mut store, &token, true).remove(0).1;
        let expected = if accepted {
            Ok(())
        } else {
            Err(JwtError::Revoked)
        };
        assert_eq!(toolkit, expected, "iat {raw}");
    }
}

/// A token with an integer `auth_time` keeps the existing revocation comparison in both
/// profiles (`auth_time` against the account's bound), so well-formed tokens are unchanged.
#[test]
fn an_integer_auth_time_keeps_the_existing_revocation_check() {
    let (mut store, mut claims, _) = store_with(Account::Revoked);
    claims.auth_time = REVOKED_AT - 1;
    let token = token_with(&store, &claims, &[]);
    for emulator in [true, false] {
        let toolkit = answers(&mut store, &token, emulator).remove(0).1;
        assert_eq!(toolkit, Err(JwtError::Revoked), "emulator={emulator}");
    }
}

/// The near shapes ledger 787 does not name stay refused in both profiles: a present `exp`
/// that is not an integer, an expired one (ledger 22), an `auth_time` that is present but not
/// an integer, and an `iat` that is neither a number nor a string. A bad signature is refused
/// before any of it (ledger 713).
#[test]
fn near_shapes_stay_refused_in_both_profiles() {
    for (name, changes, expected) in [
        (
            "exp as a string",
            vec![("exp", Some("\"1788008450\""))],
            JwtError::Malformed,
        ),
        (
            "exp as a fraction",
            vec![("exp", Some("1788008450.5"))],
            JwtError::Malformed,
        ),
        ("exp null", vec![("exp", Some("null"))], JwtError::Malformed),
        (
            "exp past the allowance",
            vec![("exp", Some("1788004500"))],
            JwtError::Expired,
        ),
        (
            "exp missing but auth_time a string",
            vec![("exp", None), ("auth_time", Some("\"1788004850\""))],
            JwtError::Malformed,
        ),
        (
            "auth_time a string",
            vec![("auth_time", Some("\"1788004850\""))],
            JwtError::Malformed,
        ),
        (
            "auth_time a fraction",
            vec![("auth_time", Some("1788004850.5"))],
            JwtError::Malformed,
        ),
        (
            "auth_time null",
            vec![("auth_time", Some("null"))],
            JwtError::Malformed,
        ),
        ("iat null", vec![("iat", Some("null"))], JwtError::Malformed),
        ("iat true", vec![("iat", Some("true"))], JwtError::Malformed),
        (
            "iat an array",
            vec![("iat", Some("[]"))],
            JwtError::Malformed,
        ),
        (
            "iat an object",
            vec![("iat", Some("{}"))],
            JwtError::Malformed,
        ),
        ("no sub", vec![("sub", None)], JwtError::Malformed),
    ] {
        let (mut store, claims, _) = store_with(Account::Anonymous);
        let token = token_with(&store, &claims, &changes);
        for emulator in [true, false] {
            for (verifier, answer) in answers(&mut store, &token, emulator) {
                // Firestore honours its own 30 s allowance, so its expiry answer is the same.
                assert_eq!(
                    answer,
                    Err(expected.clone()),
                    "emulator={emulator} {verifier}: {name}"
                );
            }
        }
    }
    let (mut store, claims, _) = store_with(Account::Anonymous);
    let token = token_with(&store, &claims, &[("iat", None), ("exp", None)]);
    let (signed_part, _) = token.rsplit_once('.').unwrap();
    let tampered = format!("{signed_part}.{}", base64url_encode(b"not the signature"));
    for emulator in [true, false] {
        for (verifier, answer) in answers(&mut store, &tampered, emulator) {
            assert_eq!(
                answer,
                Err(JwtError::BadSignature),
                "emulator={emulator} {verifier}"
            );
        }
    }
}

/// A token missing `exp` never expires in the emulator profile (firebase-tools never reads
/// it); strict refuses it at any time.
#[test]
fn a_token_without_exp_is_accepted_at_any_later_time_in_the_emulator_profile() {
    let (mut store, claims, _) = store_with(Account::Anonymous);
    let token = token_with(&store, &claims, &[("exp", None)]);
    store.set_future_id_token_claims(FutureClaims::Accept);
    for later in [0, 3600, 86_400 * 365] {
        assert_eq!(
            verify_id_token_decoded_with_leeway(&token, &store, at(NOW + later), 300).map(|_| ()),
            Ok(()),
            "{later}"
        );
    }
    store.set_future_id_token_claims(FutureClaims::Refuse);
    assert_eq!(
        verify_id_token_decoded_with_leeway(&token, &store, at(NOW), 300).map(|_| ()),
        Err(JwtError::Malformed)
    );
}

/// One generated claim value.
#[derive(Clone, Copy, Debug)]
enum Shape {
    Past,
    Future,
    Missing,
    NumericString,
    Fraction,
    WordString,
    Null,
}

impl Shape {
    fn raw(self, past: i64, future: i64) -> Option<String> {
        match self {
            Self::Past => Some(past.to_string()),
            Self::Future => Some(future.to_string()),
            Self::Missing => None,
            Self::NumericString => Some(format!("\"{past}\"")),
            Self::Fraction => Some(format!("{past}.5")),
            Self::WordString => Some("\"later\"".to_owned()),
            Self::Null => Some("null".to_owned()),
        }
    }
}

fn shape() -> impl proptest::strategy::Strategy<Value = Shape> {
    proptest::prop_oneof![
        proptest::strategy::Just(Shape::Past),
        proptest::strategy::Just(Shape::Future),
        proptest::strategy::Just(Shape::Missing),
        proptest::strategy::Just(Shape::NumericString),
        proptest::strategy::Just(Shape::Fraction),
        proptest::strategy::Just(Shape::WordString),
        proptest::strategy::Just(Shape::Null),
    ]
}

fn account() -> impl proptest::strategy::Strategy<Value = Account> {
    proptest::prop_oneof![
        proptest::strategy::Just(Account::Anonymous),
        proptest::strategy::Just(Account::Password),
        proptest::strategy::Just(Account::Revoked),
    ]
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 512,
        ..proptest::test_runner::Config::default()
    })]

    /// Ledgers 781 and 787 as a differential property over every verifier: the emulator
    /// profile and strict give the same answer to a token whose `iat`, `auth_time` and `exp`
    /// are integers with `iat` and `auth_time` not in the future. Otherwise strict refuses, and
    /// the emulator profile differs from it only where one of the decided shapes is present
    /// (a future integer `iat`/`auth_time`; a missing, numeric-string, fractional or word
    /// `iat`; a missing `auth_time`; a missing `exp`), never where only undecided shapes are.
    #[test]
    fn the_profiles_differ_only_on_the_decided_shapes(
        iat in shape(),
        auth_time in shape(),
        exp in shape(),
        who in account(),
    ) {
        let (mut store, claims, _) = store_with(who);
        let past = NOW - 10;
        let iat_raw = iat.raw(past, NOW + 600);
        let auth_raw = auth_time.raw(past, NOW + 600);
        let exp_raw = match exp {
            // An expired exp is a past integer here: past the allowance.
            Shape::Past => Some((NOW - 1000).to_string()),
            Shape::Future => Some((NOW + 3590).to_string()),
            other => other.raw(NOW + 3590, NOW + 3590),
        };
        let token = token_with(
            &store,
            &claims,
            &[
                ("iat", iat_raw.as_deref()),
                ("auth_time", auth_raw.as_deref()),
                ("exp", exp_raw.as_deref()),
            ],
        );
        let emulator = answers(&mut store, &token, true);
        let strict = answers(&mut store, &token, false);
        let integer = |s: Shape| matches!(s, Shape::Past | Shape::Future);
        let ordinary = integer(iat) && integer(auth_time) && integer(exp)
            && matches!(iat, Shape::Past) && matches!(auth_time, Shape::Past);
        let decided = matches!(iat, Shape::Future | Shape::Missing | Shape::NumericString | Shape::Fraction | Shape::WordString)
            || matches!(auth_time, Shape::Future | Shape::Missing)
            || matches!(exp, Shape::Missing);
        let undecided = matches!(iat, Shape::Null)
            || matches!(auth_time, Shape::NumericString | Shape::Fraction | Shape::WordString | Shape::Null)
            || matches!(exp, Shape::NumericString | Shape::Fraction | Shape::WordString | Shape::Null);
        for ((verifier, lenient), (_, exact)) in emulator.iter().zip(&strict) {
            if ordinary {
                proptest::prop_assert_eq!(lenient, exact, "{}", verifier);
                continue;
            }
            proptest::prop_assert!(exact.is_err(), "strict {} accepted {:?}/{:?}/{:?}", verifier, iat, auth_time, exp);
            if lenient.is_ok() {
                proptest::prop_assert!(decided && !undecided, "emulator {} accepted {:?}/{:?}/{:?}", verifier, iat, auth_time, exp);
            }
            if undecided {
                proptest::prop_assert!(lenient.is_err(), "emulator {} accepted undecided {:?}/{:?}/{:?}", verifier, iat, auth_time, exp);
            }
        }
    }
}
