//! The credential shapes production was observed to issue and honour (AUTH-CREDENTIAL sandbox
//! recording 2026-09-24): the legacy Identity Toolkit token, the expiry allowance, an
//! administrator's `validSince` and the anonymous `provider_id` claim.

use std::collections::BTreeMap;

use fireemu_core_auth::claims::ClaimValue;
use fireemu_core_auth::jwt::{
    encode_payload_shaped, encode_unsigned, legacy_token_payload,
    verify_id_token_decoded_with_leeway, verify_legacy_token, HeaderShape, JwtError, LegacyToken,
    IDENTITY_TOOLKIT_EXPIRY_LEEWAY_SECONDS, LEGACY_TOKEN_ISSUER, LEGACY_TOKEN_TTL_SECONDS,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

const T0: i64 = 1_788_004_860;

fn at(seconds: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(seconds)
}

fn store() -> AuthStore {
    AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default())
}

#[test]
fn observed_lifetimes_are_two_weeks_and_five_minutes() {
    assert_eq!(LEGACY_TOKEN_TTL_SECONDS, 1_209_600);
    assert_eq!(IDENTITY_TOOLKIT_EXPIRY_LEEWAY_SECONDS, 300);
    assert_eq!(LEGACY_TOKEN_ISSUER, "https://identitytoolkit.google.com/");
}

#[test]
fn legacy_payloads_carry_the_provider_at_the_top_level_and_no_session_claims() {
    let password = legacy_token_payload(
        "demo-app",
        T0,
        &LegacyToken {
            uid: "u1",
            sign_in_provider: "password",
            email: Some(("a@example.com", false)),
            extra_claims: None,
            session_epoch: None,
        },
    );
    assert_eq!(
        password,
        r#"{"aud":"demo-app","email":"a@example.com","exp":1789214460,"iat":1788004860,"iss":"https://identitytoolkit.google.com/","sign_in_provider":"password","user_id":"u1","verified":false}"#
    );
    let mut claims = BTreeMap::new();
    claims.insert("role".to_owned(), ClaimValue::String("r".to_owned()));
    let custom = legacy_token_payload(
        "demo-app",
        T0,
        &LegacyToken {
            uid: "u2",
            sign_in_provider: "custom",
            email: None,
            extra_claims: Some(&claims),
            session_epoch: None,
        },
    );
    assert_eq!(
        custom,
        r#"{"aud":"demo-app","exp":1789214460,"extra_claims":{"role":"r"},"iat":1788004860,"iss":"https://identitytoolkit.google.com/","sign_in_provider":"custom","user_id":"u2"}"#
    );
    let empty = BTreeMap::new();
    let without = legacy_token_payload(
        "demo-app",
        T0,
        &LegacyToken {
            uid: "u3",
            sign_in_provider: "custom",
            email: None,
            extra_claims: Some(&empty),
            session_epoch: None,
        },
    );
    assert!(!without.contains("extra_claims"), "{without}");
}

fn legacy(project: &str, issuer: &str, uid: &str, iat: i64) -> String {
    let payload = legacy_token_payload(
        project,
        iat,
        &LegacyToken {
            uid,
            sign_in_provider: "password",
            email: None,
            extra_claims: None,
            session_epoch: None,
        },
    )
    .replace(LEGACY_TOKEN_ISSUER, issuer);
    encode_payload_shaped(&payload, None, HeaderShape::Untyped)
}

/// Only a store that issued a legacy token honours one, so the emulator profile, which never
/// issues them, keeps refusing a forged one (closure review S3).
#[test]
fn a_store_honours_legacy_tokens_only_once_it_issued_one() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("e@example.com"), at(T0))
        .unwrap();
    let token = legacy("demo-app", LEGACY_TOKEN_ISSUER, uid.as_str(), T0);
    assert!(matches!(
        verify_legacy_token(&token, &s, at(T0), 0),
        Err(JwtError::WrongIssuer { .. })
    ));
    let payload = s.legacy_token_payload(&uid, T0, "password", None).unwrap();
    assert!(
        payload.contains(r#""iss":"https://identitytoolkit.google.com/""#),
        "{payload}"
    );
    assert!(payload.contains(r#""email":"e@example.com""#), "{payload}");
    assert!(verify_legacy_token(&token, &s, at(T0), 0).is_ok());
}

#[test]
fn legacy_tokens_verify_their_issuer_audience_lifetime_account_and_revocation() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), at(T0))
        .unwrap();
    s.legacy_token_payload(&uid, T0, "password", None).unwrap();
    let token = legacy("demo-app", LEGACY_TOKEN_ISSUER, uid.as_str(), T0);
    let verified = verify_legacy_token(&token, &s, at(T0), 0).unwrap().0;
    assert_eq!(verified.uid, uid.as_str());
    let exp = T0 + LEGACY_TOKEN_TTL_SECONDS;
    assert!(verify_legacy_token(&token, &s, at(exp + 299), 300).is_ok());
    assert_eq!(
        verify_legacy_token(&token, &s, at(exp + 300), 300).map(|_| ()),
        Err(JwtError::Expired)
    );
    assert_eq!(
        verify_legacy_token(&token, &s, at(exp), 0).map(|_| ()),
        Err(JwtError::Expired)
    );
    assert!(matches!(
        verify_legacy_token(
            &legacy(
                "demo-app",
                "https://securetoken.google.com/demo-app",
                uid.as_str(),
                T0
            ),
            &s,
            at(T0),
            0
        ),
        Err(JwtError::WrongIssuer { .. })
    ));
    assert!(matches!(
        verify_legacy_token(
            &legacy("other-app", LEGACY_TOKEN_ISSUER, uid.as_str(), T0),
            &s,
            at(T0),
            0
        ),
        Err(JwtError::WrongAudience { .. })
    ));
    assert_eq!(
        verify_legacy_token(
            &legacy("demo-app", LEGACY_TOKEN_ISSUER, uid.as_str(), T0 + 1),
            &s,
            at(T0),
            0
        )
        .map(|_| ()),
        Err(JwtError::Malformed),
        "issued in the future"
    );
    assert_eq!(
        verify_legacy_token(
            &legacy("demo-app", LEGACY_TOKEN_ISSUER, "nobody", T0),
            &s,
            at(T0),
            0
        )
        .map(|_| ()),
        Err(JwtError::UnknownUser)
    );
    s.set_valid_since(&uid, at(T0 + 1)).unwrap();
    assert_eq!(
        verify_legacy_token(&token, &s, at(T0 + 2), 0).map(|_| ()),
        Err(JwtError::Revoked)
    );
    s.set_valid_since(&uid, at(T0)).unwrap();
    assert!(verify_legacy_token(&token, &s, at(T0 + 2), 0).is_ok());
    s.user_mut(&uid).unwrap().disabled = true;
    assert_eq!(
        verify_legacy_token(&token, &s, at(T0), 0).map(|_| ()),
        Err(JwtError::UserDisabled)
    );
}

#[test]
fn id_tokens_are_honoured_up_to_the_allowance_past_exp() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("b@example.com"), at(T0))
        .unwrap();
    let token = encode_unsigned(&s.id_token_claims(&uid, None, at(T0)).unwrap());
    let exp = T0 + 3600;
    assert!(verify_id_token_decoded_with_leeway(&token, &s, at(exp + 299), 300).is_ok());
    assert_eq!(
        verify_id_token_decoded_with_leeway(&token, &s, at(exp + 300), 300).map(|_| ()),
        Err(JwtError::Expired)
    );
    assert_eq!(
        verify_id_token_decoded_with_leeway(&token, &s, at(exp), 0).map(|_| ()),
        Err(JwtError::Expired)
    );
}

#[test]
fn an_administrators_valid_since_is_stored_as_given_even_when_earlier() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("c@example.com"), at(T0))
        .unwrap();
    s.set_valid_since(&uid, at(T0 + 100)).unwrap();
    assert!(!s.token_is_valid(&uid, at(T0 + 50), at(T0 + 3600), at(T0 + 60)));
    s.set_valid_since(&uid, at(T0 + 10)).unwrap();
    assert!(s.token_is_valid(&uid, at(T0 + 50), at(T0 + 3600), at(T0 + 60)));
    assert_eq!(s.user(&uid).unwrap().tokens_valid_after, at(T0 + 10));
    assert!(s.user(&uid).unwrap().tokens_revoked);
    let unknown = s
        .create_user(NewUser::email("gone@example.com"), at(T0))
        .unwrap();
    let _ = s.delete_user_by_id(unknown.as_str());
    assert!(s.set_valid_since(&unknown, at(T0)).is_err());
}

#[test]
fn only_anonymous_sessions_carry_a_top_level_provider_id() {
    let mut s = store();
    let anonymous = s.create_user(NewUser::anonymous(), at(T0)).unwrap();
    let email = s
        .create_user(NewUser::email("d@example.com"), at(T0))
        .unwrap();
    let claims = s.id_token_claims(&anonymous, None, at(T0)).unwrap();
    assert_eq!(claims.provider_id.as_deref(), Some("anonymous"));
    assert!(claims
        .canonical_json()
        .contains(r#""provider_id":"anonymous""#));
    let claims = s.id_token_claims(&email, None, at(T0)).unwrap();
    assert_eq!(claims.provider_id, None);
    assert!(!claims.canonical_json().contains("provider_id"));
}
