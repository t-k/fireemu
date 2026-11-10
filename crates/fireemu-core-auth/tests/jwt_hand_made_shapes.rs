//! Hand-made ID token shapes: what the `emulator` profile admits that firebase-tools 15.28.2
//! admits, and that the `strict` profile still refuses (owner decision ledger 787, with the
//! coordinator's ruling of 2026-11-10 on revocation and expiry).
//!
//! These are local regression cases, not production observations. The reference model below
//! is written from two sources only, and shares nothing with `jwt.rs`:
//!
//! - firebase-tools 15.28.2 `parseIdToken` (`lib/emulator/auth/operations.js:1715-1731`): the
//!   token is decoded without verification, and the only time check is
//!   `!user.validSince || decoded.payload.iat >= Number(user.validSince)` (`:1727`). `auth_time`
//!   and `exp` are never read, and `iat` is compared as JavaScript compares it, so a value is
//!   first turned into a number (`Number(value)`; `NaN` makes the comparison false).
//! - the expiry contract of ledger 22: an `exp` that is present ends the token's life, with the
//!   surface's allowance, and is read the same way (`Number(exp)`); only an `exp` that is `NaN`
//!   counts as none.
//!
//! `NUMBERS` was produced by Node, not by this crate: `node tests/fixtures/js_number_table.mjs
//! numbers` prints `Number(JSON.parse(raw))` for each raw JSON text, as exact bits (Node 24).

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::format_push_string,
    clippy::type_complexity
)]

use fireemu_core_auth::claims::{ClaimValue, CustomClaims, IdTokenClaims};
use fireemu_core_auth::jwt::{
    encode_payload_with, verify_firestore_token, verify_id_token, verify_rules_token, FutureClaims,
    JwtError, RulesTokenPolicy, TokenAcceptance,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, ImportedUser, LocalId, NewUser, Provider};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::json::{parse, JsonValue};
use fireemu_core_types::time::LogicalInstant;

const NOW: i64 = 1_788_004_860;
const PROJECT: &str = "demo-hand-made";
const CREATED_AT: i64 = NOW - 300;
const REVOKED_AT: i64 = NOW - 100;
const EXPIRED: i64 = NOW - 1000;

fn at(seconds: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(seconds)
}

/// `Number(JSON.parse(raw))`; `None` is `NaN`. Written out by Node, so its digits are not regrouped.
#[allow(clippy::unreadable_literal, clippy::approx_constant)]
const NUMBERS: &[(&str, Option<f64>)] = &[
    ("null", Some(f64::from_bits(0x0000000000000000))),
    ("true", Some(f64::from_bits(0x3ff0000000000000))),
    ("false", Some(f64::from_bits(0x0000000000000000))),
    ("[]", Some(f64::from_bits(0x0000000000000000))),
    ("[1]", Some(f64::from_bits(0x3ff0000000000000))),
    ("[0]", Some(f64::from_bits(0x0000000000000000))),
    ("[1788004860]", Some(f64::from_bits(0x41daa4b27f000000))),
    ("[[1788004860]]", Some(f64::from_bits(0x41daa4b27f000000))),
    ("[1,2]", None),
    ("[null]", Some(f64::from_bits(0x0000000000000000))),
    ("[true]", None),
    ("[\"7\"]", Some(f64::from_bits(0x401c000000000000))),
    ("[[],[]]", None),
    ("{}", None),
    ("{\"a\":1}", None),
    ("\"\"", Some(f64::from_bits(0x0000000000000000))),
    ("\"   \"", Some(f64::from_bits(0x0000000000000000))),
    ("\"12\"", Some(f64::from_bits(0x4028000000000000))),
    ("\" 12 \"", Some(f64::from_bits(0x4028000000000000))),
    ("\"+5\"", Some(f64::from_bits(0x4014000000000000))),
    ("\"-0\"", Some(f64::from_bits(0x8000000000000000))),
    ("\"1e3\"", Some(f64::from_bits(0x408f400000000000))),
    ("\"1.5\"", Some(f64::from_bits(0x3ff8000000000000))),
    ("\".5\"", Some(f64::from_bits(0x3fe0000000000000))),
    ("\"5.\"", Some(f64::from_bits(0x4014000000000000))),
    ("\"+.5e-3\"", Some(f64::from_bits(0x3f40624dd2f1a9fc))),
    ("\"-1788004860\"", Some(f64::from_bits(0xc1daa4b27f000000))),
    ("\"1788004860\"", Some(f64::from_bits(0x41daa4b27f000000))),
    ("\"1788004860.5\"", Some(f64::from_bits(0x41daa4b27f200000))),
    ("\"Infinity\"", Some(f64::INFINITY)),
    ("\"+Infinity\"", Some(f64::INFINITY)),
    ("\"-Infinity\"", Some(f64::NEG_INFINITY)),
    ("\"infinity\"", None),
    ("\"INFINITY\"", None),
    ("\"inf\"", None),
    ("\"-inf\"", None),
    ("\"NaN\"", None),
    ("\"nan\"", None),
    ("\"1e400\"", Some(f64::INFINITY)),
    ("\"-1e309\"", Some(f64::NEG_INFINITY)),
    ("\"1e309\"", Some(f64::INFINITY)),
    ("\"1e-400\"", Some(f64::from_bits(0x0000000000000000))),
    ("\"0x1\"", Some(f64::from_bits(0x3ff0000000000000))),
    ("\"0X1F\"", Some(f64::from_bits(0x403f000000000000))),
    ("\"0x6A92B4FC\"", Some(f64::from_bits(0x41daa4ad3f000000))),
    ("\"0xffffffffffffffffffffffffffffffff\"", Some(f64::from_bits(0x47f0000000000000))),
    ("\"0o17\"", Some(f64::from_bits(0x402e000000000000))),
    ("\"0b101\"", Some(f64::from_bits(0x4014000000000000))),
    ("\"-0x1\"", None),
    ("\"+0x1\"", None),
    ("\"0x\"", None),
    ("\"0xg\"", None),
    ("\"0b2\"", None),
    ("\"0o8\"", None),
    ("\"0x0\"", Some(f64::from_bits(0x0000000000000000))),
    ("\"0b0\"", Some(f64::from_bits(0x0000000000000000))),
    ("\"0o0\"", Some(f64::from_bits(0x0000000000000000))),
    ("\"1_0\"", None),
    ("\"1e\"", None),
    ("\"e5\"", None),
    ("\"--1\"", None),
    ("\"1 2\"", None),
    ("\"1,5\"", None),
    ("\"abc\"", None),
    ("\"\\u00a01788004860\\u00a0\"", Some(f64::from_bits(0x41daa4b27f000000))),
    ("\"\\ufeff5\"", Some(f64::from_bits(0x4014000000000000))),
    ("\"\\u00855\"", None),
    ("\"\\u20285\\u2029\"", Some(f64::from_bits(0x4014000000000000))),
    ("\"\\t\\n5\\r\\u000b\\f\"", Some(f64::from_bits(0x4014000000000000))),
    ("\"\\u200b5\"", None),
    ("0", Some(f64::from_bits(0x0000000000000000))),
    ("-1", Some(f64::from_bits(0xbff0000000000000))),
    ("1788004860", Some(f64::from_bits(0x41daa4b27f000000))),
    ("1788004860.5", Some(f64::from_bits(0x41daa4b27f200000))),
    ("-1788004860.5", Some(f64::from_bits(0xc1daa4b27f200000))),
    ("1e308", Some(f64::from_bits(0x7fe1ccf385ebc8a0))),
    ("1.7976931348623157e308", Some(f64::from_bits(0x7fefffffffffffff))),
    ("-1e308", Some(f64::from_bits(0xffe1ccf385ebc8a0))),
    ("9007199254740993", Some(f64::from_bits(0x4340000000000000))),
    ("9223372036854775807", Some(f64::from_bits(0x43e0000000000000))),
    ("9223372036854775808", Some(f64::from_bits(0x43e0000000000000))),
    ("-9223372036854775808", Some(f64::from_bits(0xc3e0000000000000))),
    ("1e400", Some(f64::INFINITY)),
    ("-1e400", Some(f64::NEG_INFINITY)),
    ("5e-324", Some(f64::from_bits(0x0000000000000001))),
    ("0.0", Some(f64::from_bits(0x0000000000000000))),
    ("-0.0", Some(f64::from_bits(0x8000000000000000))),
    ("[1e400]", Some(f64::INFINITY)),
    ("[-1e400]", Some(f64::NEG_INFINITY)),
    ("[[1e400]]", Some(f64::INFINITY)),
    ("[[-1e400]]", Some(f64::NEG_INFINITY)),
    ("[-0]", Some(f64::from_bits(0x0000000000000000))),
    ("[-0.0]", Some(f64::from_bits(0x0000000000000000))),
    ("[1e21]", Some(f64::from_bits(0x444b1ae4d6e2ef50))),
    ("[1e-7]", Some(f64::from_bits(0x3e7ad7f29abcaf48))),
    ("[5e-324]", Some(f64::from_bits(0x0000000000000001))),
    ("[1.7976931348623157e308]", Some(f64::from_bits(0x7fefffffffffffff))),
    ("[1e300,1e300]", None),
    ("[0.1]", Some(f64::from_bits(0x3fb999999999999a))),
    ("[123456789012345680000]", Some(f64::from_bits(0x441ac53a7e04bcda))),
    ("[9007199254740993]", Some(f64::from_bits(0x4340000000000000))),
    ("[\"1e400\"]", Some(f64::INFINITY)),
    ("[[],[1]]", None),
    ("[1.5e-7]", Some(f64::from_bits(0x3e8421f5f40d8376))),
    ("[1e22]", Some(f64::from_bits(0x4480f0cf064dd592))),
    ("[-1e21]", Some(f64::from_bits(0xc44b1ae4d6e2ef50))),
    ("\"0x201a86d280cba5a\"", Some(f64::from_bits(0x43800d43694065d3))),
    ("\"0x20000000000001\"", Some(f64::from_bits(0x4340000000000000))),
    ("\"0x20000000000002\"", Some(f64::from_bits(0x4340000000000001))),
    ("\"0x20000000000003\"", Some(f64::from_bits(0x4340000000000002))),
    ("\"0x20000000000005\"", Some(f64::from_bits(0x4340000000000002))),
    ("\"0x20000000000006\"", Some(f64::from_bits(0x4340000000000003))),
    ("\"0x20000000000007\"", Some(f64::from_bits(0x4340000000000004))),
    ("\"0x1fffffffffffff\"", Some(f64::from_bits(0x433fffffffffffff))),
    ("\"0x3fffffffffffff\"", Some(f64::from_bits(0x4350000000000000))),
    ("\"0X7fffffffffffffff\"", Some(f64::from_bits(0x43e0000000000000))),
    ("\"0xffffffffffffffff\"", Some(f64::from_bits(0x43f0000000000000))),
    ("\"0x10000000000000001\"", Some(f64::from_bits(0x43f0000000000000))),
    ("\"0x1000000000000000100000000000000000001\"", Some(f64::from_bits(0x48f0000000000000))),
    ("\"0x20000000000000000000000000000000000000000000000000000000000000000000\"", Some(f64::from_bits(0x50c0000000000000))),
    ("\"0o400000000000000001\"", Some(f64::from_bits(0x4340000000000000))),
    ("\"0o400000000000000003\"", Some(f64::from_bits(0x4340000000000002))),
    ("\"0o1777777777777777777777\"", Some(f64::from_bits(0x43f0000000000000))),
    ("\"0o2000000000000000000000\"", Some(f64::from_bits(0x43f0000000000000))),
    ("\"0b100000000000000000000000000000000000000000000000000001\"", Some(f64::from_bits(0x4340000000000000))),
    ("\"0b100000000000000000000000000000000000000000000000000011\"", Some(f64::from_bits(0x4340000000000002))),
    ("\"0b100000000000000000000000000000000000000000000000000010\"", Some(f64::from_bits(0x4340000000000001))),
    ("\"0b111111111111111111111111111111111111111111111111111111\"", Some(f64::from_bits(0x4350000000000000))),
    ("\"0b11111111111111111111111111111111111111111111111111111\"", Some(f64::from_bits(0x433fffffffffffff))),
    ("\"0B1000000000000000000000000000000000000000000000000000011\"", Some(f64::from_bits(0x4350000000000001))),
    ("\"0b1000000000000000000000000000000000000000000000000000000000000\"", Some(f64::from_bits(0x43b0000000000000))),
    ("\"0x1000000000000000000000000000000000000000000000000000000000000\"", Some(f64::from_bits(0x4ef0000000000000))),
    ("\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"", Some(f64::INFINITY)),
    ("\"0x1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"", Some(f64::from_bits(0x7fb0000000000000))),
];

// ---------------------------------------------------------------------------------------
// The reference model
// ---------------------------------------------------------------------------------------

/// `operations.js:1727`: `!user.validSince || iat >= Number(user.validSince)`.
fn official_accepts(valid_since: Option<i64>, iat: Option<f64>) -> bool {
    valid_since.is_none_or(|since| iat.is_some_and(|number| number >= since as f64))
}

/// The expiry contract: a present `exp` ends the token's life `leeway` seconds after it.
fn expired(exp: Option<f64>, leeway: i64) -> bool {
    exp.is_some_and(|number| NOW as f64 >= number + leeway as f64)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Strict,
    Emulator,
}

/// Every way an account comes to exist or lose its `validSince` in firebase-tools. `None` for
/// the `validSince` below means firebase-tools holds none for that account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Account {
    /// Anonymous sign-in: no `validSince` (`signUp` without a password).
    Anonymous,
    /// An email address and no password: `signUp` sets `validSince` only for a password.
    EmailOnly,
    /// Created through the Admin API without a password (`operations.js:164-169`).
    AdminCreatedPasswordless,
    /// A password set at sign-up (`:169`).
    Password,
    /// A password that was removed afterwards: `validSince` stays.
    PasswordRemoved,
    /// An import sets it always (`:341`).
    Imported,
    /// Tokens revoked (`reqBody.validSince`, `:861-862`).
    Revoked,
}

const ACCOUNTS: [Account; 7] = [
    Account::Anonymous,
    Account::EmailOnly,
    Account::AdminCreatedPasswordless,
    Account::Password,
    Account::PasswordRemoved,
    Account::Imported,
    Account::Revoked,
];

impl Account {
    /// The `validSince` firebase-tools holds for the account, as the store sees the instants.
    fn valid_since(self) -> Option<i64> {
        match self {
            Self::Anonymous | Self::EmailOnly | Self::AdminCreatedPasswordless => None,
            Self::Password | Self::PasswordRemoved | Self::Imported => Some(CREATED_AT),
            Self::Revoked => Some(REVOKED_AT),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------

fn store_for(profile: Profile, account: Account) -> (AuthStore, LocalId) {
    let mut store = AuthStore::new(PROJECT, SplitMix64::new(11), TotpPolicy::default());
    let email = "hand-made@example.invalid";
    let uid = match account {
        Account::Anonymous => store
            .create_user(NewUser::anonymous(), at(CREATED_AT))
            .unwrap(),
        Account::EmailOnly | Account::AdminCreatedPasswordless | Account::Revoked => store
            .create_user(NewUser::email(email), at(CREATED_AT))
            .unwrap(),
        Account::Password | Account::PasswordRemoved => store
            .create_user_with_password(NewUser::email(email), "password1", at(CREATED_AT))
            .unwrap(),
        Account::Imported => store
            .import_user(ImportedUser {
                local_id: "imported-1".to_owned(),
                email: Some(email.to_owned()),
                email_verified: false,
                display_name: None,
                photo_url: None,
                phone_number: None,
                disabled: false,
                provider: Provider::Password,
                custom_claims: CustomClaims::default(),
                created_at: at(CREATED_AT),
                last_sign_in_at: None,
                last_refresh_at: None,
                tokens_valid_after: at(CREATED_AT),
                federated: Vec::new(),
                password: None,
                imported_password: None,
                allow_shared_email: false,
                totp_factors: Vec::new(),
                phone_factors: Vec::new(),
            })
            .unwrap(),
    };
    match account {
        Account::AdminCreatedPasswordless => store.user_mut(&uid).unwrap().admin_created = true,
        Account::PasswordRemoved => assert!(store.clear_password(&uid).unwrap()),
        Account::Revoked => store.revoke_tokens(&uid, at(REVOKED_AT)).unwrap(),
        _ => {}
    }
    if profile == Profile::Emulator {
        store.set_future_id_token_claims(FutureClaims::Accept);
    }
    (store, uid)
}

fn claims_of(store: &AuthStore, uid: &LocalId) -> IdTokenClaims {
    store.id_token_claims(uid, None, at(NOW)).unwrap()
}

/// The claims of a well-formed token with `members` replaced by the raw JSON given, or removed
/// for `None`. The text is spliced in, so a number no JSON library keeps (`1e400`) is written
/// as given.
fn token(claims: &IdTokenClaims, members: &[(&str, Option<&str>)]) -> String {
    let JsonValue::Object(mut object) = parse(&claims.canonical_json()).unwrap() else {
        panic!("claims must encode an object");
    };
    for (key, _) in members {
        object.remove(*key);
    }
    let mut payload = String::new();
    ClaimValue::from_json(&JsonValue::Object(object)).write_canonical_json(&mut payload);
    payload.pop();
    for (key, raw) in members {
        if let Some(raw) = raw {
            payload.push_str(&format!(",\"{key}\":{raw}"));
        }
    }
    payload.push('}');
    encode_payload_with(&payload, None)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Surface {
    Toolkit,
    Firestore,
    Rules,
}

fn verify(
    surface: Surface,
    profile: Profile,
    store: &AuthStore,
    token: &str,
) -> Result<(), JwtError> {
    match surface {
        Surface::Toolkit => {
            fireemu_core_auth::jwt::verify_id_token(token, store, at(NOW)).map(|_| ())
        }
        Surface::Firestore => verify_firestore_token(token, store, at(NOW)).map(|_| ()),
        Surface::Rules => {
            let acceptance = match profile {
                Profile::Strict => TokenAcceptance::Verified,
                Profile::Emulator => TokenAcceptance::EmulatorMock,
            };
            // The mock fallback is off, so only the verified path decides.
            verify_rules_token(
                token,
                store,
                at(NOW),
                RulesTokenPolicy::new(acceptance, false),
            )
            .map(|_| ())
        }
    }
}

fn leeway(surface: Surface) -> i64 {
    match surface {
        Surface::Firestore => fireemu_core_auth::jwt::FIRESTORE_EXPIRY_LEEWAY_SECONDS,
        _ => 0,
    }
}

/// What the emulator profile answers, from the model alone.
fn model_emulator(
    surface: Surface,
    account: Account,
    iat: Option<f64>,
    exp: Option<f64>,
) -> Result<(), JwtError> {
    if expired(exp, leeway(surface)) {
        return Err(JwtError::Expired);
    }
    // Firestore does not read the account.
    if surface != Surface::Firestore && !official_accepts(account.valid_since(), iat) {
        return Err(JwtError::Revoked);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------

/// `iat` through every value of the table, on every kind of account, with and without a perfectly
/// good `auth_time`: a usable `auth_time` never rescues an `iat` that does not compare (Sol M1).
#[test]
fn iat_decides_revocation_alone_for_every_account_and_every_value() {
    for account in ACCOUNTS {
        let (store, uid) = store_for(Profile::Emulator, account);
        let claims = claims_of(&store, &uid);
        for auth_time in [None, Some("1788004860"), Some("\"1788004860\"")] {
            for (raw, number) in NUMBERS {
                for surface in [Surface::Toolkit, Surface::Rules, Surface::Firestore] {
                    let token = token(
                        &claims,
                        &[
                            ("iat", Some(raw)),
                            ("auth_time", auth_time),
                            ("exp", Some("1788008460")),
                        ],
                    );
                    assert_eq!(
                        verify(surface, Profile::Emulator, &store, &token),
                        model_emulator(surface, account, *number, Some(1_788_008_460.0)),
                        "{account:?} {surface:?} iat={raw} auth_time={auth_time:?}"
                    );
                }
            }
        }
    }
}

/// A radix `iat` compares at the value Node gives it, right at the `validSince` boundary: the
/// rounding is done once, so `0x201a86d280cba5a` is 144581849829390944 and not the 144581849829390912
/// that rounding after every digit gives.
#[test]
fn a_radix_iat_compares_at_its_rounded_value_on_both_sides_of_the_boundary() {
    let mut checked = 0;
    for (raw, number) in NUMBERS.iter().filter(|(raw, _)| raw.starts_with("\"0")) {
        let Some(value) = number.filter(|v| (9.0e15..4.0e18).contains(v)) else {
            continue;
        };
        let rounded = value as i64;
        for valid_since in [rounded, value.next_up() as i64, value.next_down() as i64] {
            let (mut store, uid) = store_for(Profile::Emulator, Account::Anonymous);
            store.set_valid_since(&uid, at(valid_since)).unwrap();
            let token = token(
                &claims_of(&store, &uid),
                &[
                    ("iat", Some(raw)),
                    ("auth_time", None),
                    ("exp", Some("1788008460")),
                ],
            );
            let expected = if official_accepts(Some(valid_since), *number) {
                Ok(())
            } else {
                Err(JwtError::Revoked)
            };
            assert_eq!(
                verify(Surface::Toolkit, Profile::Emulator, &store, &token),
                expected,
                "iat={raw} validSince={valid_since}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 30, "only {checked} boundary cases ran");
}

/// A token with no `iat` at all, `auth_time` or not.
#[test]
fn a_missing_iat_is_refused_exactly_for_accounts_with_a_valid_since() {
    for account in ACCOUNTS {
        let (store, uid) = store_for(Profile::Emulator, account);
        for auth_time in [None, Some("1788004860")] {
            let token = token(
                &claims_of(&store, &uid),
                &[
                    ("iat", None),
                    ("auth_time", auth_time),
                    ("exp", Some("1788008460")),
                ],
            );
            let expected = if account.valid_since().is_some() {
                Err(JwtError::Revoked)
            } else {
                Ok(())
            };
            assert_eq!(
                verify(Surface::Toolkit, Profile::Emulator, &store, &token),
                expected,
                "{account:?} auth_time={auth_time:?}"
            );
        }
    }
}

/// `exp` through every value of the table: `Number(exp)`, whatever the type, ends the token's
/// life when it is a number, and `NaN` alone counts as no `exp` (Sol M2).
#[test]
fn exp_is_coerced_as_javascript_coerces_it_and_only_nan_is_no_exp() {
    let (store, uid) = store_for(Profile::Emulator, Account::Anonymous);
    let claims = claims_of(&store, &uid);
    for (raw, number) in NUMBERS {
        for surface in [Surface::Toolkit, Surface::Rules, Surface::Firestore] {
            let token = token(&claims, &[("exp", Some(raw))]);
            let got = verify(surface, Profile::Emulator, &store, &token);
            assert_eq!(
                got,
                model_emulator(surface, Account::Anonymous, Some(NOW as f64), *number),
                "{surface:?} exp={raw}"
            );
        }
    }
    // The shapes the review named, spelled out.
    for raw in [
        "false",
        "null",
        "[1]",
        "\"0x1\"",
        "\"-Infinity\"",
        "\"-1e309\"",
        "0",
    ] {
        let token = token(&claims, &[("exp", Some(raw))]);
        assert_eq!(
            verify(Surface::Toolkit, Profile::Emulator, &store, &token),
            Err(JwtError::Expired),
            "exp={raw}"
        );
    }
    for raw in ["\"Infinity\"", "\"1e400\"", "{}", "\"soon\"", "[1,2]"] {
        let token = token(&claims, &[("exp", Some(raw))]);
        assert!(
            verify(Surface::Toolkit, Profile::Emulator, &store, &token).is_ok(),
            "exp={raw}"
        );
    }
    let missing = token(&claims, &[("exp", None)]);
    assert!(verify(Surface::Toolkit, Profile::Emulator, &store, &missing).is_ok());
}

/// A passwordless account created through the Admin API holds no `validSince` in firebase-tools
/// (`operations.js:164-169`), an imported one always does (`:341`) (Opus M1).
#[test]
fn only_an_import_gives_a_passwordless_account_a_valid_since() {
    let bare = |store: &AuthStore, uid: &LocalId| {
        token(
            &claims_of(store, uid),
            &[
                ("iat", None),
                ("auth_time", None),
                ("exp", Some("1788008460")),
            ],
        )
    };
    let (store, uid) = store_for(Profile::Emulator, Account::AdminCreatedPasswordless);
    assert!(store.user_by_id(uid.as_str()).unwrap().admin_created);
    assert!(verify_id_token(&bare(&store, &uid), &store, at(NOW)).is_ok());
    let (store, uid) = store_for(Profile::Emulator, Account::Imported);
    assert_eq!(
        verify_id_token(&bare(&store, &uid), &store, at(NOW)).map(|_| ()),
        Err(JwtError::Revoked)
    );
}

/// The reported shapes, one by one, so a regression names what broke. The emulator profile
/// answers like firebase-tools 15.28.2; the strict profile refuses the same token.
#[test]
fn the_reported_shapes_are_accepted_by_the_emulator_profile_and_refused_by_strict() {
    let shapes: [(&str, [(&str, Option<&str>); 3]); 6] = [
        (
            "iat missing",
            [
                ("iat", None),
                ("auth_time", Some("1788004560")),
                ("exp", Some("1788008460")),
            ],
        ),
        (
            "iat numeric string",
            [
                ("iat", Some("\"1788004860\"")),
                ("auth_time", Some("1788004560")),
                ("exp", Some("1788008460")),
            ],
        ),
        (
            "iat float",
            [
                ("iat", Some("1788004860.5")),
                ("auth_time", Some("1788004560")),
                ("exp", Some("1788008460")),
            ],
        ),
        (
            "auth_time missing",
            [
                ("iat", Some("1788004860")),
                ("auth_time", None),
                ("exp", Some("1788008460")),
            ],
        ),
        (
            "exp missing",
            [
                ("iat", Some("1788004860")),
                ("auth_time", Some("1788004560")),
                ("exp", None),
            ],
        ),
        (
            "all three missing",
            [("iat", None), ("auth_time", None), ("exp", None)],
        ),
    ];
    for (label, members) in shapes {
        for surface in [Surface::Toolkit, Surface::Firestore, Surface::Rules] {
            let (store, uid) = store_for(Profile::Emulator, Account::Anonymous);
            let emulator = token(&claims_of(&store, &uid), &members);
            assert!(
                verify(surface, Profile::Emulator, &store, &emulator).is_ok(),
                "{label} {surface:?}"
            );
            let (strict, uid) = store_for(Profile::Strict, Account::Anonymous);
            let token = token(&claims_of(&strict, &uid), &members);
            let strict_answer = verify(surface, Profile::Strict, &strict, &token);
            assert_eq!(
                strict_answer,
                Err(JwtError::Malformed),
                "{label} {surface:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// The pairwise table
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Int,
    Missing,
    NumString,
    Float,
    TextString,
    Null,
    Bool,
    Expired,
}

const IAT: i64 = NOW;
const AUTH_TIME: i64 = NOW - 300;
const EXP: i64 = NOW + 3600;

/// The JSON of a claim in `shape` around `base`, and `Number()` of it.
fn written(shape: Shape, base: i64) -> (Option<String>, Option<f64>) {
    match shape {
        Shape::Int => (Some(base.to_string()), Some(base as f64)),
        Shape::Missing => (None, None),
        Shape::NumString => (Some(format!("\"{base}\"")), Some(base as f64)),
        Shape::Float => (Some(format!("{base}.5")), Some(base as f64 + 0.5)),
        Shape::TextString => (Some("\"soon\"".to_owned()), None),
        Shape::Null => (Some("null".to_owned()), Some(0.0)),
        Shape::Bool => (Some("true".to_owned()), Some(1.0)),
        Shape::Expired => (Some(EXPIRED.to_string()), Some(EXPIRED as f64)),
    }
}

fn shaped_token(claims: &IdTokenClaims, iat: Shape, auth_time: Shape, exp: Shape) -> String {
    let (iat, auth_time, exp) = (
        written(iat, IAT).0,
        written(auth_time, AUTH_TIME).0,
        written(exp, EXP).0,
    );
    token(
        claims,
        &[
            ("iat", iat.as_deref()),
            ("auth_time", auth_time.as_deref()),
            ("exp", exp.as_deref()),
        ],
    )
}

/// The strict contract: all three claims present integers, then expiry, then (with an account)
/// revocation by `auth_time`. This is what the profile did before ledger 787 and still does.
fn model_strict(
    surface: Surface,
    account: Account,
    (iat, auth_time, exp): (Shape, Shape, Shape),
) -> Result<(), JwtError> {
    let integer = |shape| matches!(shape, Shape::Int | Shape::Expired);
    if !integer(exp) {
        return Err(JwtError::Malformed);
    }
    if written(exp, EXP).1.is_some_and(|e| e <= (NOW - 30) as f64) {
        return Err(JwtError::Expired);
    }
    if !integer(iat) || !integer(auth_time) {
        return Err(JwtError::Malformed);
    }
    let valid_after = match account {
        Account::Revoked => REVOKED_AT,
        _ => CREATED_AT,
    };
    if surface != Surface::Firestore && AUTH_TIME < valid_after {
        return Err(JwtError::Revoked);
    }
    Ok(())
}

/// The pairwise table of `work+emulator-overrefusals.pict` (49 rows, with the required
/// combinations of the seed file). The account kinds are one of each `validSince` source.
#[allow(clippy::type_complexity)]
const ROWS: &[(Profile, Shape, Shape, Shape, Account, Surface)] = {
    use Account::{
        Anonymous as An, Imported as Im, Password as P, PasswordRemoved as Pr, Revoked as Rv,
    };
    use Profile::{Emulator as E, Strict as S};
    use Shape::{Bool as B, Expired as X, Float as F, Int as I, Missing as M, NumString as N};
    use Shape::{Null as Nu, TextString as T};
    use Surface::{Firestore as Fs, Rules as R, Toolkit as Tk};
    &[
        (E, I, I, I, An, Tk),
        (S, I, I, I, An, Tk),
        (E, M, M, M, An, Tk),
        (E, M, I, I, P, Tk),
        (E, M, M, I, P, Tk),
        (E, N, M, I, Rv, Tk),
        (E, F, F, N, Im, Tk),
        (E, M, M, M, An, Fs),
        (E, M, M, M, Pr, R),
        (S, M, I, I, An, Tk),
        (S, N, I, I, Im, Fs),
        (S, I, M, I, An, Tk),
        (S, I, I, M, An, Tk),
        (S, T, I, X, Rv, R),
        (S, Nu, F, I, P, R),
        (S, F, B, X, P, Fs),
        (E, Nu, N, T, Rv, Fs),
        (S, T, N, I, P, R),
        (E, T, F, M, Rv, Fs),
        (S, I, T, F, Rv, R),
        (E, Nu, I, F, An, Tk),
        (E, N, N, M, P, Tk),
        (E, F, T, I, Pr, Fs),
        (E, T, F, X, Im, Tk),
        (E, T, B, F, P, Fs),
        (E, F, N, F, Rv, R),
        (S, N, M, F, P, R),
        (S, M, T, N, Rv, Tk),
        (S, I, N, X, P, Fs),
        (S, M, B, F, An, Tk),
        (E, T, M, N, P, Fs),
        (S, Nu, T, M, An, Tk),
        (E, I, B, M, Rv, R),
        (E, N, B, N, Pr, R),
        (S, F, I, T, Im, Tk),
        (S, I, M, T, P, R),
        (E, M, N, N, Im, Fs),
        (S, N, T, X, An, Fs),
        (S, T, T, T, An, R),
        (E, F, M, M, Rv, Fs),
        (E, N, F, T, Pr, Tk),
        (E, Nu, B, T, Im, Fs),
        (S, M, F, X, P, Fs),
        (S, M, F, T, Rv, Tk),
        (S, I, F, F, P, Tk),
        (S, Nu, I, N, P, R),
        (E, I, M, N, Im, R),
        (E, N, B, I, P, Fs),
        (S, Nu, M, X, An, Tk),
    ]
};

#[test]
fn every_row_of_the_table_answers_as_the_reference_model() {
    for (n, &(profile, iat, auth_time, exp, account, surface)) in ROWS.iter().enumerate() {
        let (store, uid) = store_for(profile, account);
        let token = shaped_token(&claims_of(&store, &uid), iat, auth_time, exp);
        let expected = match profile {
            Profile::Strict => model_strict(surface, account, (iat, auth_time, exp)),
            Profile::Emulator => {
                model_emulator(surface, account, written(iat, IAT).1, written(exp, EXP).1)
            }
        };
        assert_eq!(
            verify(surface, profile, &store, &token),
            expected,
            "row {n}: {profile:?} iat={iat:?} auth_time={auth_time:?} exp={exp:?} {account:?} {surface:?}"
        );
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 768,
        max_shrink_iters: 64,
        ..proptest::test_runner::Config::default()
    })]

    /// For any account, any `iat` and `exp` from the table or written around now, any
    /// `auth_time` at all, the emulator profile answers as the model, and the strict profile
    /// refuses whatever is not three plain integers with the existing `Malformed`.
    #[test]
    fn the_emulator_profile_answers_as_firebase_tools_for_any_claims(
        account in 0usize..7,
        iat_pick in 0usize..(NUMBERS.len() + 3),
        iat_offset in -700i64..=700,
        auth_time_pick in 0usize..(NUMBERS.len() + 1),
        exp_pick in 0usize..(NUMBERS.len() + 2),
        surface in 0usize..3,
    ) {
        let account = ACCOUNTS[account];
        let surface = [Surface::Toolkit, Surface::Rules, Surface::Firestore][surface];
        let around = |offset: i64| (format!("{}", NOW + offset), Some((NOW + offset) as f64));
        let (iat_raw, iat_number) = match NUMBERS.get(iat_pick) {
            Some((raw, number)) => ((*raw).to_owned(), *number),
            None => around(iat_offset),
        };
        let auth_raw = NUMBERS.get(auth_time_pick).map(|(raw, _)| *raw);
        let (exp_raw, exp_number) = match NUMBERS.get(exp_pick) {
            Some((raw, number)) => ((*raw).to_owned(), *number),
            None => ("1788008460".to_owned(), Some(1_788_008_460.0)),
        };
        let (store, uid) = store_for(Profile::Emulator, account);
        let token = token(&claims_of(&store, &uid), &[
            ("iat", Some(&iat_raw)),
            ("auth_time", auth_raw),
            ("exp", Some(&exp_raw)),
        ]);
        proptest::prop_assert_eq!(
            verify(surface, Profile::Emulator, &store, &token),
            model_emulator(surface, account, iat_number, exp_number)
        );
        // Strict: refused unless all three are plain integers (and then by the old rules).
        let (strict, strict_uid) = store_for(Profile::Strict, account);
        let strict_token = token_for_strict(&claims_of(&strict, &strict_uid), &iat_raw, auth_raw, &exp_raw);
        let plain = |raw: &str| raw.parse::<i64>().is_ok();
        if !(plain(&iat_raw) && auth_raw.is_some_and(plain) && plain(&exp_raw)) {
            proptest::prop_assert!(
                verify(surface, Profile::Strict, &strict, &strict_token).is_err()
            );
        }
    }
}

fn token_for_strict(
    claims: &IdTokenClaims,
    iat: &str,
    auth_time: Option<&str>,
    exp: &str,
) -> String {
    token(
        claims,
        &[
            ("iat", Some(iat)),
            ("auth_time", auth_time),
            ("exp", Some(exp)),
        ],
    )
}
