//! Hand-made ID token shapes: what the `emulator` profile admits that firebase-tools 15.28.2
//! admits, and that the `strict` profile still refuses (owner decision ledger 787).
//!
//! These are local regression cases, not production observations. firebase-tools'
//! `parseIdToken` (`lib/emulator/auth/operations.js:1715-1731`) decodes a token without
//! verifying it and reads only the tenant, the user, `iat` (against the user's `validSince`,
//! when the user has one) and `disabled`; the emulator profile follows it, keeping the expiry
//! check of an `exp` that is present (ledger 22). The tables below are the reference model,
//! written from that source and not from the implementation.

use fireemu_core_auth::claims::{ClaimValue, IdTokenClaims};
use fireemu_core_auth::jwt::{
    encode_payload_with, verify_firestore_token, verify_id_token, verify_rules_token, FutureClaims,
    JwtError, RulesTokenPolicy, TokenAcceptance,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Strict,
    Emulator,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// An integer in the expected place.
    Int,
    Missing,
    /// The integer written as a JSON string.
    NumString,
    /// The integer minus a fraction, as a JSON float.
    Float,
    /// A string that is no number.
    TextString,
    Null,
    Bool,
    /// An integer exp far in the past (only for `exp`).
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UserKind {
    /// No password and no revocation: the official emulator gives it no `validSince`.
    Plain,
    /// A password: the official emulator sets `validSince` when the password is set.
    Password,
    /// Refresh tokens revoked at `NOW - 100`.
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Surface {
    Toolkit,
    Firestore,
    Rules,
}

const IAT: i64 = NOW;
const AUTH_TIME: i64 = NOW - 300;
const EXP: i64 = NOW + 3600;
const EXPIRED: i64 = NOW - 1000;
const REVOKED_AT: i64 = NOW - 100;
const CREATED_AT: i64 = NOW - 300;

/// The JSON of `claim` in `shape` around `base`, and the whole second the official emulator's
/// numeric coercion gives it (`None` when it coerces to nothing usable).
fn written(shape: Shape, base: i64) -> (Option<String>, Option<i64>) {
    match shape {
        Shape::Int => (Some(base.to_string()), Some(base)),
        Shape::Missing => (None, None),
        Shape::NumString => (Some(format!("\"{base}\"")), Some(base)),
        Shape::Float => (Some(format!("{base}.5")), Some(base)),
        Shape::TextString => (Some("\"soon\"".to_owned()), None),
        Shape::Null => (Some("null".to_owned()), None),
        Shape::Bool => (Some("true".to_owned()), None),
        Shape::Expired => (Some(EXPIRED.to_string()), Some(EXPIRED)),
    }
}

fn token(claims: &IdTokenClaims, iat: Shape, auth_time: Shape, exp: Shape) -> String {
    let JsonValue::Object(mut members) = parse(&claims.canonical_json()).unwrap() else {
        panic!("claims must encode an object");
    };
    for (key, shape, base) in [
        ("iat", iat, IAT),
        ("auth_time", auth_time, AUTH_TIME),
        ("exp", exp, EXP),
    ] {
        match written(shape, base).0 {
            Some(raw) => {
                members.insert(key.to_owned(), parse(&raw).unwrap());
            }
            None => {
                members.remove(key);
            }
        }
    }
    let mut payload = String::new();
    ClaimValue::from_json(&JsonValue::Object(members)).write_canonical_json(&mut payload);
    encode_payload_with(&payload, None)
}

fn store_for(profile: Profile, user: UserKind) -> (AuthStore, LocalId) {
    let mut store = AuthStore::new(PROJECT, SplitMix64::new(11), TotpPolicy::default());
    let uid = match user {
        UserKind::Password => store
            .create_user_with_password(
                NewUser::email("hand-made@example.invalid"),
                "password1",
                at(CREATED_AT),
            )
            .unwrap(),
        UserKind::Plain | UserKind::Revoked => store
            .create_user(NewUser::email("hand-made@example.invalid"), at(CREATED_AT))
            .unwrap(),
    };
    if user == UserKind::Revoked {
        store.revoke_tokens(&uid, at(REVOKED_AT)).unwrap();
    }
    if profile == Profile::Emulator {
        store.set_future_id_token_claims(FutureClaims::Accept);
    }
    (store, uid)
}

fn claims_of(store: &AuthStore, uid: &LocalId) -> IdTokenClaims {
    store.id_token_claims(uid, None, at(NOW)).unwrap()
}

fn verify(
    surface: Surface,
    profile: Profile,
    store: &AuthStore,
    token: &str,
) -> Result<(), JwtError> {
    match surface {
        Surface::Toolkit => verify_id_token(token, store, at(NOW)).map(|_| ()),
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

/// The reference model. `valid_after` and `has_valid_since` describe the user.
fn expected(
    profile: Profile,
    surface: Surface,
    (iat, auth_time, exp): (Shape, Shape, Shape),
    user: UserKind,
) -> Result<(), JwtError> {
    let account = matches!(surface, Surface::Toolkit | Surface::Rules);
    let integer = |shape| matches!(shape, Shape::Int | Shape::Expired);
    let exp_second = written(exp, EXP).1;
    match profile {
        Profile::Strict => {
            // exp, then iat, then (with an account) auth_time, then revocation.
            if !integer(exp) {
                return Err(JwtError::Malformed);
            }
            // The Firestore allowance is 30 s and the Toolkit's is none; EXPIRED is far past both.
            if exp_second.is_some_and(|e| e <= NOW - 30) {
                return Err(JwtError::Expired);
            }
            if !integer(iat) {
                return Err(JwtError::Malformed);
            }
            if !integer(auth_time) {
                return Err(JwtError::Malformed);
            }
            if account && AUTH_TIME < valid_after(user) {
                return Err(JwtError::Revoked);
            }
            Ok(())
        }
        Profile::Emulator => {
            if exp_second.is_some_and(|e| e <= NOW - 30) {
                return Err(JwtError::Expired);
            }
            if !account {
                return Ok(());
            }
            // The official emulator reads `iat` only; this store's revocation instant is
            // compared with `auth_time`, and `iat` stands in when `auth_time` is no number.
            let basis = written(auth_time, AUTH_TIME)
                .1
                .or_else(|| written(iat, IAT).1);
            let revoked = match basis {
                Some(second) => second < valid_after(user),
                None => has_valid_since(user),
            };
            if revoked {
                Err(JwtError::Revoked)
            } else {
                Ok(())
            }
        }
    }
}

fn valid_after(user: UserKind) -> i64 {
    match user {
        UserKind::Plain | UserKind::Password => CREATED_AT,
        UserKind::Revoked => REVOKED_AT,
    }
}

fn has_valid_since(user: UserKind) -> bool {
    matches!(user, UserKind::Password | UserKind::Revoked)
}

/// The pairwise table of `work+emulator-overrefusals.pict` (49 rows, with the required
/// combinations of the seed file).
#[allow(clippy::type_complexity)]
const ROWS: &[(Profile, Shape, Shape, Shape, UserKind, Surface)] = {
    use Profile::{Emulator as E, Strict as S};
    use Shape::{Bool as B, Expired as X, Float as F, Int as I, Missing as M, NumString as N};
    use Shape::{Null as Nu, TextString as T};
    use Surface::{Firestore as Fs, Rules as R, Toolkit as Tk};
    use UserKind::{Password as P, Plain as Pl, Revoked as Rv};
    &[
        (E, I, I, I, Pl, Tk),
        (S, I, I, I, Pl, Tk),
        (E, M, M, M, Pl, Tk),
        (E, M, I, I, P, Tk),
        (E, M, M, I, P, Tk),
        (E, N, M, I, Rv, Tk),
        (E, F, F, N, Pl, Tk),
        (E, M, M, M, Pl, Fs),
        (E, M, M, M, Pl, R),
        (S, M, I, I, Pl, Tk),
        (S, N, I, I, Pl, Fs),
        (S, I, M, I, Pl, Tk),
        (S, I, I, M, Pl, Tk),
        (S, T, I, X, Rv, R),
        (S, Nu, F, I, P, R),
        (S, F, B, X, P, Fs),
        (E, Nu, N, T, Rv, Fs),
        (S, T, N, I, P, R),
        (E, T, F, M, Rv, Fs),
        (S, I, T, F, Rv, R),
        (E, Nu, I, F, Pl, Tk),
        (E, N, N, M, P, Tk),
        (E, F, T, I, P, Fs),
        (E, T, F, X, Pl, Tk),
        (E, T, B, F, P, Fs),
        (E, F, N, F, Rv, R),
        (S, N, M, F, P, R),
        (S, M, T, N, Rv, Tk),
        (S, I, N, X, P, Fs),
        (S, M, B, F, Pl, Tk),
        (E, T, M, N, P, Fs),
        (S, Nu, T, M, Pl, Tk),
        (E, I, B, M, Rv, R),
        (E, N, B, N, Pl, R),
        (S, F, I, T, Pl, Tk),
        (S, I, M, T, P, R),
        (E, M, N, N, Pl, Fs),
        (S, N, T, X, Pl, Fs),
        (S, T, T, T, Pl, R),
        (E, F, M, M, Rv, Fs),
        (E, N, F, T, Pl, Tk),
        (E, Nu, B, T, Pl, Fs),
        (S, M, F, X, P, Fs),
        (S, M, F, T, Rv, Tk),
        (S, I, F, F, P, Tk),
        (S, Nu, I, N, P, R),
        (E, I, M, N, Pl, R),
        (E, N, B, I, P, Fs),
        (S, Nu, M, X, Pl, Tk),
    ]
};

#[test]
fn every_row_of_the_table_answers_as_the_reference_model() {
    for (n, &(profile, iat, auth_time, exp, user, surface)) in ROWS.iter().enumerate() {
        let (store, uid) = store_for(profile, user);
        let token = token(&claims_of(&store, &uid), iat, auth_time, exp);
        assert_eq!(
            verify(surface, profile, &store, &token),
            expected(profile, surface, (iat, auth_time, exp), user),
            "row {n}: {profile:?} iat={iat:?} auth_time={auth_time:?} exp={exp:?} {user:?} {surface:?}"
        );
    }
}

/// The reported shapes, one by one, so a regression names what broke. The emulator profile
/// answers like firebase-tools 15.28.2; the strict profile refuses the same token.
#[test]
fn the_reported_shapes_are_accepted_by_the_emulator_profile_and_refused_by_strict() {
    let shapes = [
        (
            "iat missing, no validSince",
            Shape::Missing,
            Shape::Int,
            Shape::Int,
        ),
        (
            "iat as a numeric string",
            Shape::NumString,
            Shape::Int,
            Shape::Int,
        ),
        ("iat as a float", Shape::Float, Shape::Int, Shape::Int),
        ("auth_time missing", Shape::Int, Shape::Missing, Shape::Int),
        ("exp missing", Shape::Int, Shape::Int, Shape::Missing),
        (
            "all three missing",
            Shape::Missing,
            Shape::Missing,
            Shape::Missing,
        ),
    ];
    for (label, iat, auth_time, exp) in shapes {
        for surface in [Surface::Toolkit, Surface::Firestore, Surface::Rules] {
            for (profile, accepted) in [(Profile::Emulator, true), (Profile::Strict, false)] {
                let (store, uid) = store_for(profile, UserKind::Plain);
                let token = token(&claims_of(&store, &uid), iat, auth_time, exp);
                let got = verify(surface, profile, &store, &token);
                assert_eq!(
                    got.is_ok(),
                    accepted,
                    "{label} {profile:?} {surface:?}: {got:?}"
                );
                if !accepted {
                    assert_eq!(got, Err(JwtError::Malformed), "{label} {surface:?}");
                }
            }
        }
    }
}

/// firebase-tools answers `TOKEN_EXPIRED` for a token with no usable `iat` when the user has a
/// `validSince` (a password user always has one), and accepts it for a user without one.
#[test]
fn a_missing_issued_at_follows_the_users_valid_since() {
    for (user, auth_time, expect) in [
        (UserKind::Plain, Shape::Missing, Ok(())),
        (UserKind::Password, Shape::Missing, Err(JwtError::Revoked)),
        (UserKind::Revoked, Shape::Missing, Err(JwtError::Revoked)),
        // A usable auth_time carries the comparison instead.
        (UserKind::Password, Shape::Int, Ok(())),
        (UserKind::Revoked, Shape::Int, Err(JwtError::Revoked)),
    ] {
        let (store, uid) = store_for(Profile::Emulator, user);
        let token = token(
            &claims_of(&store, &uid),
            Shape::Missing,
            auth_time,
            Shape::Int,
        );
        assert_eq!(
            verify(Surface::Toolkit, Profile::Emulator, &store, &token),
            expect,
            "{user:?} auth_time={auth_time:?}"
        );
    }
}

/// Each way the official emulator comes to hold a `validSince` makes a token without any usable
/// time claim `TOKEN_EXPIRED`: a password set (above), a password since removed, an Admin
/// creation and a revocation (above). An account with none of them accepts it.
#[test]
fn every_source_of_a_valid_since_counts_and_an_account_without_one_accepts() {
    let bare = |store: &AuthStore, uid: &LocalId| {
        token(
            &claims_of(store, uid),
            Shape::Missing,
            Shape::Missing,
            Shape::Int,
        )
    };
    let (mut store, uid) = store_for(Profile::Emulator, UserKind::Plain);
    assert!(verify_id_token(&bare(&store, &uid), &store, at(NOW)).is_ok());

    store.user_mut(&uid).unwrap().admin_created = true;
    assert_eq!(
        verify_id_token(&bare(&store, &uid), &store, at(NOW)).map(|_| ()),
        Err(JwtError::Revoked),
        "admin created"
    );

    let (mut store, uid) = store_for(Profile::Emulator, UserKind::Password);
    assert!(store.has_password(&uid));
    assert!(store.clear_password(&uid).unwrap());
    assert!(!store.has_password(&uid));
    assert_eq!(
        verify_id_token(&bare(&store, &uid), &store, at(NOW)).map(|_| ()),
        Err(JwtError::Revoked),
        "password removed"
    );
}

/// An `iat` that is no number is the same as a missing one (JavaScript compares `NaN`), and a
/// string or float that is one compares as its value: a fractional second floors.
#[test]
fn issued_at_is_compared_as_the_number_it_coerces_to() {
    // validSince = NOW - 100 (revoked); the token has no auth_time, so iat decides.
    for (iat, expect) in [
        (r#""1788004860""#, Ok(())),
        ("1788004860.5", Ok(())),
        (r#"" 1788004860 ""#, Ok(())),
        ("1788004759.9", Err(JwtError::Revoked)),
        // A string is read like a number is, with its fraction and its exponent.
        (r#""1788004860.5""#, Ok(())),
        (r#""+1788004860""#, Ok(())),
        (r#""1.78800486e9""#, Ok(())),
        (r#""1788004759.9""#, Err(JwtError::Revoked)),
        // Not read as numbers here and so no `iat` (JavaScript reads `Infinity` and hex, which no
        // hand-made token is expected to carry; `NaN` and `inf` are not numbers there either).
        (r#""inf""#, Err(JwtError::Revoked)),
        (r#""NaN""#, Err(JwtError::Revoked)),
        (r#""Infinity""#, Err(JwtError::Revoked)),
        (r#""1788004759""#, Err(JwtError::Revoked)),
        (r#""not a number""#, Err(JwtError::Revoked)),
        ("null", Err(JwtError::Revoked)),
        ("true", Err(JwtError::Revoked)),
        ("[]", Err(JwtError::Revoked)),
        ("{}", Err(JwtError::Revoked)),
    ] {
        let (store, uid) = store_for(Profile::Emulator, UserKind::Revoked);
        let base = token(
            &claims_of(&store, &uid),
            Shape::Int,
            Shape::Missing,
            Shape::Int,
        );
        let revised = revise(&base, "iat", iat);
        assert_eq!(
            verify_id_token(&revised, &store, at(NOW)).map(|_| ()),
            expect,
            "iat={iat}"
        );
        let (strict, _) = store_for(Profile::Strict, UserKind::Revoked);
        assert_eq!(
            verify_id_token(&revised, &strict, at(NOW)).map(|_| ()),
            Err(JwtError::Malformed),
            "strict iat={iat}"
        );
    }
}

/// An empty or blank string is the number 0 in JavaScript, which is before every `validSince`:
/// unlike a text that is no number, it makes the comparison false for a user with none too.
#[test]
fn a_blank_issued_at_is_the_second_zero() {
    let (store, uid) = store_for(Profile::Emulator, UserKind::Plain);
    let base = token(
        &claims_of(&store, &uid),
        Shape::Int,
        Shape::Missing,
        Shape::Int,
    );
    for blank in [r#""""#, r#""   ""#] {
        let revised = revise(&base, "iat", blank);
        assert_eq!(
            verify_id_token(&revised, &store, at(NOW)).map(|_| ()),
            Err(JwtError::Revoked),
            "iat={blank}"
        );
    }
    let text = revise(&base, "iat", r#""soon""#);
    assert!(verify_id_token(&text, &store, at(NOW)).is_ok());
}

/// `exp` present is still checked, whatever form it takes (ledger 22); one that is no number
/// is never read, as in the official emulator.
#[test]
fn a_present_expiry_is_still_checked_and_one_that_is_no_number_is_ignored() {
    for (exp, expect) in [
        (r#""1788008460""#, Ok(())),
        ("1788008460.5", Ok(())),
        (r#""1788003860""#, Err(JwtError::Expired)),
        ("1788003860.5", Err(JwtError::Expired)),
        ("1788003860", Err(JwtError::Expired)),
        (r#""never""#, Ok(())),
        ("null", Ok(())),
        ("false", Ok(())),
        ("[1]", Ok(())),
    ] {
        let (store, uid) = store_for(Profile::Emulator, UserKind::Plain);
        let base = token(&claims_of(&store, &uid), Shape::Int, Shape::Int, Shape::Int);
        let revised = revise(&base, "exp", exp);
        for surface in [Surface::Toolkit, Surface::Firestore, Surface::Rules] {
            assert_eq!(
                verify(surface, Profile::Emulator, &store, &revised),
                expect,
                "{surface:?} exp={exp}"
            );
        }
    }
}

/// The relaxations do not reach what the shape of a token never decided: the subject, the
/// audience and the account.
#[test]
fn the_relaxed_shapes_still_need_a_subject_an_audience_and_an_enabled_account() {
    let (mut store, uid) = store_for(Profile::Emulator, UserKind::Plain);
    let bare = token(
        &claims_of(&store, &uid),
        Shape::Missing,
        Shape::Missing,
        Shape::Missing,
    );
    assert!(verify_id_token(&bare, &store, at(NOW)).is_ok());
    for (key, value) in [
        ("sub", None),
        ("aud", Some("\"another-project\"")),
        ("iss", None),
    ] {
        let revised = match value {
            Some(raw) => revise(&bare, key, raw),
            None => remove(&bare, key),
        };
        for surface in [Surface::Toolkit, Surface::Firestore] {
            assert!(
                verify(surface, Profile::Emulator, &store, &revised).is_err(),
                "{key} {surface:?}"
            );
        }
    }
    store.user_mut(&uid).unwrap().disabled = true;
    assert_eq!(
        verify_id_token(&bare, &store, at(NOW)).map(|_| ()),
        Err(JwtError::UserDisabled)
    );
}

fn revise(token: &str, key: &str, raw: &str) -> String {
    rewrite(token, |members| {
        members.insert(key.to_owned(), parse(raw).unwrap());
    })
}

fn remove(token: &str, key: &str) -> String {
    rewrite(token, |members| {
        members.remove(key);
    })
}

fn rewrite(
    token: &str,
    change: impl FnOnce(&mut std::collections::BTreeMap<String, JsonValue>),
) -> String {
    let decoded = fireemu_core_auth::jwt::decode_unsigned(token).unwrap();
    let JsonValue::Object(mut members) = parse(&decoded.payload_json).unwrap() else {
        panic!("payload must be an object");
    };
    change(&mut members);
    let mut payload = String::new();
    ClaimValue::from_json(&JsonValue::Object(members)).write_canonical_json(&mut payload);
    encode_payload_with(&payload, None)
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config {
        cases: 512,
        ..proptest::test_runner::Config::default()
    })]

    /// For any mix of present, string, float and missing time claims around the user's
    /// `validSince`, the emulator profile's Identity Toolkit answer is the reference model's:
    /// a number (or a numeric string) compares by its whole second, `auth_time` first and
    /// `iat` when it is no number, and with neither the user's `validSince` decides.
    #[test]
    fn the_emulator_profile_compares_whatever_time_claim_it_can_read(
        iat_kind in 0u8..4,
        iat_offset in -600i64..=600,
        auth_kind in 0u8..4,
        auth_offset in -600i64..=600,
        exp_kind in 0u8..4,
        revoked_ago in 1i64..=500,
        revoked in proptest::bool::ANY,
    ) {
        let (mut store, uid) = store_for(Profile::Emulator, UserKind::Plain);
        if revoked {
            store.revoke_tokens(&uid, at(NOW - revoked_ago)).unwrap();
        }
        // A revocation never moves the bound before the account's creation.
        let valid_after = if revoked { (NOW - revoked_ago).max(CREATED_AT) } else { CREATED_AT };
        let claim = |kind: u8, second: i64| -> (Option<String>, Option<i64>) {
            match kind {
                0 => (None, None),
                1 => (Some(second.to_string()), Some(second)),
                2 => (Some(format!("\"{second}\"")), Some(second)),
                _ => (Some(format!("{second}.75")), Some(second)),
            }
        };
        let (iat_raw, iat_second) = claim(iat_kind, NOW + iat_offset);
        let (auth_raw, auth_second) = claim(auth_kind, NOW + auth_offset);
        let (exp_raw, _) = claim(exp_kind, NOW + 3600);
        let mut token = token(&claims_of(&store, &uid), Shape::Missing, Shape::Missing, Shape::Missing);
        for (key, raw) in [("iat", iat_raw), ("auth_time", auth_raw), ("exp", exp_raw)] {
            if let Some(raw) = raw {
                token = revise(&token, key, &raw);
            }
        }
        let expect = match auth_second.or(iat_second) {
            Some(second) if second < valid_after => Err(JwtError::Revoked),
            None if revoked => Err(JwtError::Revoked),
            Some(_) | None => Ok(()),
        };
        proptest::prop_assert_eq!(verify_id_token(&token, &store, at(NOW)).map(|_| ()), expect);
        // The same token on a strict store is refused unless every claim is a plain integer.
        let (mut strict, strict_uid) = store_for(Profile::Strict, UserKind::Plain);
        if revoked {
            strict.revoke_tokens(&strict_uid, at(NOW - revoked_ago)).unwrap();
        }
        let plain = iat_kind == 1 && auth_kind == 1 && exp_kind == 1;
        let strict_answer = verify_id_token(&token, &strict, at(NOW)).map(|_| ());
        if !plain {
            proptest::prop_assert_eq!(strict_answer, Err(JwtError::Malformed));
        }
    }
}
