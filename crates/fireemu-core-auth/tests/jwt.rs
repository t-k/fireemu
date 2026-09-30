//! Emulator-compatible unsigned ID tokens (`alg: none`) and their verification.

use fireemu_core_auth::claims::{ClaimValue, CustomClaims};
use fireemu_core_auth::jwt::{
    base64url_encode, decode_unsigned, encode_unsigned,
    verify_firestore_rules_token_of_removed_tenant, verify_id_token, verify_rules_token,
    verify_rules_token_for_project, JwtError, SigningMode, TokenAcceptance, TokenVerification,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore, NewUser};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use std::sync::{Arc, Mutex};

fn t0() -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_004_860)
}

fn mock_user_token(sub: &str, project: &str) -> String {
    let header = base64url_encode(br#"{"alg":"none","type":"JWT"}"#);
    let payload = base64url_encode(
        format!(r#"{{"aud":"{project}","exp":3600,"iat":0,"sub":"{sub}","user_id":"{sub}"}}"#)
            .as_bytes(),
    );
    format!("{header}.{payload}.")
}

#[test]
fn firebase_rules_mock_tokens_bind_to_the_routed_project() {
    let store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
    let token = mock_user_token("alice", "demo-app-w0");

    assert!(matches!(
        verify_rules_token(&token, &store, t0(), TokenAcceptance::EmulatorMock),
        Err(JwtError::WrongAudience { .. })
    ));
    assert!(verify_rules_token_for_project(
        &token,
        &store,
        t0(),
        TokenAcceptance::EmulatorMock,
        "demo-app-w0",
    )
    .is_ok());
    assert!(matches!(
        verify_rules_token_for_project(
            &token,
            &store,
            t0(),
            TokenAcceptance::EmulatorMock,
            "demo-app-w1",
        ),
        Err(JwtError::WrongAudience { .. })
    ));
    assert!(verify_rules_token_for_project(
        &token,
        &store,
        t0(),
        TokenAcceptance::Verified,
        "demo-app-w0",
    )
    .is_err());
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
    assert!(
        !decoded.payload_json.contains("fireemu_session_epoch"),
        "ordinary production-shaped Auth stores omit the private control-session claim"
    );
    assert_eq!(decoded.sub(), Some(uid.as_str()));
    assert_eq!(decoded.exp(), Some(claims.exp));
}

#[test]
fn disabled_user_is_distinct_from_revocation_and_does_not_bypass_token_validation() {
    let mut s = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
    let uid = s
        .create_user(NewUser::email("disabled@example.com"), t0())
        .unwrap();
    let token = encode_unsigned(&s.id_token_claims(&uid, None, t0()).unwrap());
    s.user_mut(&uid).unwrap().disabled = true;
    assert_eq!(
        verify_id_token(&token, &s, t0()),
        Err(JwtError::UserDisabled)
    );
    assert_eq!(
        verify_id_token("invalid", &s, t0()),
        Err(JwtError::Malformed)
    );
    let expired = t0()
        .checked_add(LogicalDuration::from_seconds(3600))
        .unwrap();
    assert_eq!(verify_id_token(&token, &s, expired), Err(JwtError::Expired));
    s.user_mut(&uid).unwrap().disabled = false;
    assert!(verify_id_token(&token, &s, t0()).is_ok());
    s.revoke_tokens(
        &uid,
        t0().checked_add(LogicalDuration::from_seconds(2)).unwrap(),
    )
    .unwrap();
    assert_eq!(verify_id_token(&token, &s, t0()), Err(JwtError::Revoked));
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
    let header = fireemu_core_auth::jwt::base64url_encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = fireemu_core_auth::jwt::base64url_encode(br#"{"sub":"x"}"#);
    assert_eq!(
        decode_unsigned(&format!("{header}.{payload}.sig")),
        Err(JwtError::UnsupportedAlgorithm("RS256".into()))
    );
    let header = fireemu_core_auth::jwt::base64url_encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = fireemu_core_auth::jwt::base64url_encode(b"not json");
    assert_eq!(
        decode_unsigned(&format!("{header}.{payload}.")),
        Err(JwtError::Malformed)
    );
}

#[test]
fn both_signing_modes_are_supported_and_parse_from_config() {
    assert!(SigningMode::SessionRsa.supported());
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
    use fireemu_core_auth::jwt::{base64url_decode, base64url_encode};
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

/// A removed tenant's token is checked against its project's store: it must name a tenant (a
/// project token is no removed tenant's), and a tenant store is never its project's.
#[test]
fn a_removed_tenants_token_names_a_tenant_and_is_checked_against_its_project() {
    let project = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(5),
        TotpPolicy::default(),
    )));
    let registry = AuthRegistry::new("demo-app", project.clone());
    let tenant = registry.ensure_tenant("demo-app", "tenant-a").unwrap();
    let tenant_token = {
        let mut store = tenant.lock().unwrap();
        let uid = store
            .create_user(NewUser::email("t@example.com"), t0())
            .unwrap();
        encode_unsigned(&store.id_token_claims(&uid, None, t0()).unwrap())
    };
    let project_token = {
        let mut store = project.lock().unwrap();
        let uid = store
            .create_user(NewUser::email("p@example.com"), t0())
            .unwrap();
        encode_unsigned(&store.id_token_claims(&uid, None, t0()).unwrap())
    };
    let check = |token: &str, store: &Arc<Mutex<AuthStore>>| {
        verify_firestore_rules_token_of_removed_tenant(
            token,
            &store.lock().unwrap(),
            t0(),
            TokenAcceptance::Verified,
            None,
            None,
        )
    };
    let decoded = check(&tenant_token, &project).unwrap();
    assert_eq!(
        decoded
            .payload
            .get("firebase")
            .and_then(|f| f.get("tenant"))
            .and_then(|t| t.as_str()),
        Some("tenant-a")
    );
    assert!(matches!(
        check(&project_token, &project),
        Err(JwtError::WrongTenant { .. })
    ));
    assert!(matches!(
        check(&tenant_token, &tenant),
        Err(JwtError::WrongTenant { .. })
    ));
}

#[test]
fn the_tenant_claim_is_read_without_checking_the_algorithm_or_the_signature() {
    use fireemu_core_auth::jwt::{base64url_encode, unverified_tenant_claim};
    let token = |header: &str, payload: &str, signature: &str| {
        format!(
            "{}.{}.{signature}",
            base64url_encode(header.as_bytes()),
            base64url_encode(payload.as_bytes())
        )
    };
    let claims = |firebase: &str| format!(r#"{{"aud":"demo-app","firebase":{firebase}}}"#);
    assert_eq!(
        unverified_tenant_claim(&token(
            r#"{"alg":"RS256","kid":"other"}"#,
            &claims(r#"{"tenant":"t-x"}"#),
            "c2ln"
        )),
        Some("t-x".to_owned())
    );
    // An empty signature segment is allowed by the pattern.
    assert_eq!(
        unverified_tenant_claim(&token("{}", &claims(r#"{"tenant":"t-e"}"#), "")),
        Some("t-e".to_owned())
    );
    for (name, bad) in [
        ("no firebase claim", token("{}", r#"{"aud":"a"}"#, "s")),
        ("no tenant", token("{}", &claims("{}"), "s")),
        (
            "an empty tenant",
            token("{}", &claims(r#"{"tenant":""}"#), "s"),
        ),
        ("a number", token("{}", &claims(r#"{"tenant":5}"#), "s")),
        ("an object", token("{}", &claims(r#"{"tenant":{}}"#), "s")),
        ("two parts", "a.b".to_owned()),
        (
            "four parts",
            format!("{}.x", token("{}", &claims(r#"{"tenant":"t"}"#), "s")),
        ),
        ("one part", "abc".to_owned()),
        (
            "a signature with a bang",
            token("{}", &claims(r#"{"tenant":"t"}"#), "c2ln!"),
        ),
        (
            "a signature with a plus",
            token("{}", &claims(r#"{"tenant":"t"}"#), "c2ln+/=="),
        ),
        (
            "a signature with a space",
            token("{}", &claims(r#"{"tenant":"t"}"#), "a b"),
        ),
        ("empty", String::new()),
        (
            "header not json",
            token("nope", &claims(r#"{"tenant":"t"}"#), "s"),
        ),
        (
            "header not an object",
            token("[]", &claims(r#"{"tenant":"t"}"#), "s"),
        ),
        ("payload not json", token("{}", "nope", "s")),
        ("payload not an object", token("{}", "[1]", "s")),
        ("not base64", "!!.!!.!!".to_owned()),
    ] {
        assert_eq!(unverified_tenant_claim(&bad), None, "{name}");
    }
}
