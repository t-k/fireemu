//! Emulator-compatible unsigned ID tokens (`alg: none`) and their verification.

use ftd_core_auth::claims::{ClaimValue, CustomClaims};
use ftd_core_auth::jwt::{
    decode_unsigned, encode_unsigned, verify_id_token, JwtError, SigningMode, TokenVerification,
};
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::{AuthStore, NewUser};
use ftd_core_types::determinism::SplitMix64;
use ftd_core_types::time::{LogicalDuration, LogicalInstant};

fn t0() -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_004_860)
}

#[test]
fn unsigned_token_has_three_parts_and_round_trips() {
    let mut s = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
    let uid = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    let mut custom = CustomClaims::default();
    custom
        .insert("role", ClaimValue::String("admin".into()))
        .unwrap();
    s.set_custom_claims(&uid, custom).unwrap();
    let claims = s.id_token_claims(&uid, None, t0()).unwrap();
    let token = encode_unsigned(&claims);
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[2], "", "alg none carries an empty signature");
    assert!(
        !token.contains('=') && !token.contains('+') && !token.contains('/'),
        "base64url without padding"
    );
    let decoded = decode_unsigned(&token).unwrap();
    assert_eq!(decoded.header_alg, "none");
    assert_eq!(decoded.header_typ, "JWT");
    assert_eq!(decoded.payload_json, claims.canonical_json());
    assert_eq!(decoded.sub(), Some(uid.as_str()));
    assert_eq!(decoded.exp(), Some(claims.exp));
}

#[test]
fn verification_checks_issuer_audience_expiry_and_revocation() {
    let mut s = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
    let uid = s
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    let claims = s.id_token_claims(&uid, None, t0()).unwrap();
    let token = encode_unsigned(&claims);
    let ok = verify_id_token(
        &token,
        &s,
        t0().checked_add(LogicalDuration::from_seconds(10)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        ok,
        TokenVerification {
            uid: uid.as_str().to_owned(),
            second_factor: None
        }
    );
    let late = t0()
        .checked_add(LogicalDuration::from_seconds(3_600))
        .unwrap();
    assert_eq!(verify_id_token(&token, &s, late), Err(JwtError::Expired));
    let mut other = AuthStore::new("other-app", SplitMix64::new(1), TotpPolicy::default());
    let _ = other
        .create_user(NewUser::email("a@example.com"), t0())
        .unwrap();
    // Issuer and audience both embed the project; the issuer is checked first.
    assert!(matches!(
        verify_id_token(&token, &other, t0()),
        Err(JwtError::WrongIssuer { .. })
    ));
    s.revoke_tokens(
        &uid,
        t0().checked_add(LogicalDuration::from_seconds(5)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        verify_id_token(
            &token,
            &s,
            t0().checked_add(LogicalDuration::from_seconds(10)).unwrap()
        ),
        Err(JwtError::Revoked)
    );
}

#[test]
fn malformed_tokens_and_unsupported_algorithms_are_rejected() {
    assert_eq!(decode_unsigned("abc"), Err(JwtError::Malformed));
    assert_eq!(decode_unsigned("a.b.c.d"), Err(JwtError::Malformed));
    // A token claiming RS256 must not be accepted as unsigned.
    let header = ftd_core_auth::jwt::base64url_encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = ftd_core_auth::jwt::base64url_encode(br#"{"sub":"x"}"#);
    assert_eq!(
        decode_unsigned(&format!("{header}.{payload}.sig")),
        Err(JwtError::UnsupportedAlgorithm("RS256".into()))
    );
    let header = ftd_core_auth::jwt::base64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = ftd_core_auth::jwt::base64url_encode(b"not json");
    assert_eq!(
        decode_unsigned(&format!("{header}.{payload}.")),
        Err(JwtError::Malformed)
    );
}

#[test]
fn rsa_signing_is_declared_unsupported_not_faked() {
    assert!(!SigningMode::SessionRsa.supported());
    assert!(SigningMode::UnsignedEmulator.supported());
    assert_eq!(
        SigningMode::parse_config("session-rsa"),
        Some(SigningMode::SessionRsa)
    );
    assert_eq!(
        SigningMode::parse_config("unsigned-emulator"),
        Some(SigningMode::UnsignedEmulator)
    );
    assert_eq!(SigningMode::parse_config("hs256"), None);
}

#[test]
fn base64url_round_trip_and_rfc4648_vectors() {
    use ftd_core_auth::jwt::{base64url_decode, base64url_encode};
    assert_eq!(base64url_encode(b""), "");
    assert_eq!(base64url_encode(b"f"), "Zg");
    assert_eq!(base64url_encode(b"fo"), "Zm8");
    assert_eq!(base64url_encode(b"foo"), "Zm9v");
    assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
    assert_eq!(base64url_decode("-_8").unwrap(), vec![0xfb, 0xff]);
    assert!(
        base64url_decode("Zm9v=").is_err(),
        "padding is not accepted in JWT segments"
    );
    assert!(base64url_decode("Zm+v").is_err());
    for n in 0..64usize {
        let data: Vec<u8> = (0..n)
            .map(|i| u8::try_from(i * 37 % 256).unwrap())
            .collect();
        assert_eq!(base64url_decode(&base64url_encode(&data)).unwrap(), data);
    }
}
