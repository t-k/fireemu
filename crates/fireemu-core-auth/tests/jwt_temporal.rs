//! ID-token time-claim validation on the store's logical clock.
//!
//! These are local regression cases, not production observations. No wall clock,
//! Firebase account, credential, network connection or fabricated production receipt.

use fireemu_core_auth::claims::{ClaimValue, IdTokenClaims};
use fireemu_core_auth::jwt::{
    decode_unsigned, encode_payload_with, encode_unsigned, verify_id_token,
    verify_id_token_decoded, verify_rules_token, verify_rules_token_for_project, JwtError,
    TokenAcceptance,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, LocalId, NewUser};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::json::{parse, JsonValue};
use fireemu_core_types::time::LogicalInstant;

const NOW: i64 = 1_788_004_860;
const PROJECT: &str = "demo-jwt-time";

fn at(seconds: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(seconds)
}

fn fixture() -> (AuthStore, IdTokenClaims, LocalId) {
    let mut store = AuthStore::new(PROJECT, SplitMix64::new(11), TotpPolicy::default());
    let uid = store
        .create_user(NewUser::email("time@example.invalid"), at(NOW - 300))
        .unwrap();
    let mut claims = store.id_token_claims(&uid, None, at(NOW)).unwrap();
    claims.auth_time = NOW - 300;
    claims.iat = NOW;
    claims.exp = NOW + 3600;
    (store, claims, uid)
}

/// Change one claim while keeping a syntactically valid JSON object and JWT.
fn with_json_claim(claims: &IdTokenClaims, key: &str, replacement: Option<&str>) -> String {
    let JsonValue::Object(mut members) = parse(&claims.canonical_json()).unwrap() else {
        panic!("claims must encode an object");
    };
    match replacement {
        Some(raw) => {
            members.insert(key.to_owned(), parse(raw).unwrap());
        }
        None => {
            members.remove(key);
        }
    }
    let mut payload = String::new();
    ClaimValue::from_json(&JsonValue::Object(members)).write_canonical_json(&mut payload);
    encode_payload_with(&payload, None)
}

#[test]
fn freshly_issued_token_is_usable_in_the_same_second() {
    let (store, mut claims, _) = fixture();
    claims.auth_time = NOW;
    let token = encode_unsigned(&claims);
    let (verified, decoded) = verify_id_token_decoded(&token, &store, at(NOW)).unwrap();
    assert_eq!(verified.uid, claims.sub);
    assert_eq!(decoded.payload_json, claims.canonical_json());
}

#[test]
fn a_future_issued_at_is_rejected_even_with_a_valid_expiry_and_authentication_time() {
    let (store, mut claims, _) = fixture();
    for ahead in [1, 600, 7200] {
        claims.iat = NOW + ahead;
        let token = encode_unsigned(&claims);
        assert!(
            decode_unsigned(&token).is_ok(),
            "this is not a JSON/signature test"
        );
        assert_eq!(
            verify_id_token(&token, &store, at(NOW)),
            Err(JwtError::Malformed)
        );
    }
}

#[test]
fn a_future_authentication_time_is_rejected_independently_of_issued_at() {
    let (store, mut claims, _) = fixture();
    for ahead in [1, 600, 7200] {
        claims.auth_time = NOW + ahead;
        let token = encode_unsigned(&claims);
        assert_eq!(
            verify_id_token(&token, &store, at(NOW)),
            Err(JwtError::Malformed)
        );
    }
}

#[test]
fn a_missing_issued_at_is_not_accepted_as_an_ordinary_id_token() {
    let (store, claims, _) = fixture();
    let token = with_json_claim(&claims, "iat", None);
    assert!(decode_unsigned(&token).is_ok());
    assert_eq!(
        verify_id_token(&token, &store, at(NOW)),
        Err(JwtError::Malformed)
    );
}

#[test]
fn non_numeric_issued_at_claims_are_refused_not_coerced() {
    let (store, claims, _) = fixture();
    for raw in ["null", "true", "false", "\"1788004860\"", "[]", "{}"] {
        let token = with_json_claim(&claims, "iat", Some(raw));
        assert!(decode_unsigned(&token).is_ok());
        assert_eq!(
            verify_id_token(&token, &store, at(NOW)),
            Err(JwtError::Malformed)
        );
    }
}

#[test]
fn authentication_time_remains_required_and_typed() {
    let (store, claims, _) = fixture();
    for raw in [
        None,
        Some("null"),
        Some("true"),
        Some("\"1788004860\""),
        Some("[]"),
    ] {
        let token = with_json_claim(&claims, "auth_time", raw);
        assert_eq!(
            verify_id_token(&token, &store, at(NOW)),
            Err(JwtError::Malformed)
        );
    }
}

#[test]
fn a_refreshed_token_preserves_the_older_authentication_time() {
    let (store, claims, _) = fixture();
    let token = encode_unsigned(&claims);
    let (_, decoded) = verify_id_token_decoded(&token, &store, at(NOW + 10)).unwrap();
    assert_eq!(
        decoded.payload.get("auth_time").and_then(JsonValue::as_i64),
        Some(NOW - 300)
    );
    assert_eq!(
        decoded.payload.get("iat").and_then(JsonValue::as_i64),
        Some(NOW)
    );
}

#[test]
fn the_subsecond_before_issuance_is_refused_but_the_issuance_instant_is_valid() {
    let (store, claims, _) = fixture();
    let token = encode_unsigned(&claims);
    let before = LogicalInstant::from_nanos(at(NOW).as_nanos() - 1);
    assert_eq!(
        verify_id_token(&token, &store, before),
        Err(JwtError::Malformed)
    );
    assert!(verify_id_token(&token, &store, at(NOW)).is_ok());
    assert!(verify_id_token(
        &token,
        &store,
        LogicalInstant::from_nanos(at(NOW).as_nanos() + 1)
    )
    .is_ok());
}

#[test]
fn expiry_is_still_exclusive_and_has_its_existing_error() {
    let (store, claims, _) = fixture();
    let token = encode_unsigned(&claims);
    let before = LogicalInstant::from_nanos(at(claims.exp).as_nanos() - 1);
    assert!(verify_id_token(&token, &store, before).is_ok());
    assert_eq!(
        verify_id_token(&token, &store, at(claims.exp)),
        Err(JwtError::Expired)
    );
    let missing_iat = with_json_claim(&claims, "iat", None);
    assert_eq!(
        verify_id_token(&missing_iat, &store, at(claims.exp)),
        Err(JwtError::Expired)
    );
}

#[test]
fn disabled_and_revoked_accounts_still_refuse_well_timed_tokens() {
    let (mut store, claims, uid) = fixture();
    let token = encode_unsigned(&claims);
    store.user_mut(&uid).unwrap().disabled = true;
    assert_eq!(
        verify_id_token(&token, &store, at(NOW)),
        Err(JwtError::UserDisabled)
    );
    store.user_mut(&uid).unwrap().disabled = false;
    store.revoke_tokens(&uid, at(NOW - 200)).unwrap();
    assert_eq!(
        verify_id_token(&token, &store, at(NOW)),
        Err(JwtError::Revoked)
    );
}

#[test]
fn changing_future_authentication_time_does_not_rehabilitate_a_revoked_token() {
    let (mut store, mut claims, uid) = fixture();
    store.revoke_tokens(&uid, at(NOW - 100)).unwrap();
    claims.auth_time = NOW + 3600;
    let token = encode_unsigned(&claims);
    assert_eq!(
        verify_id_token(&token, &store, at(NOW)),
        Err(JwtError::Malformed)
    );
}

#[test]
fn verified_rules_entry_points_apply_both_time_checks() {
    let (store, claims, _) = fixture();
    for key in ["iat", "auth_time"] {
        let token = with_json_claim(&claims, key, Some(&(NOW + 60).to_string()));
        assert_eq!(
            verify_rules_token(&token, &store, at(NOW), TokenAcceptance::Verified),
            Err(JwtError::Malformed)
        );
        assert_eq!(
            verify_rules_token_for_project(
                &token,
                &store,
                at(NOW),
                TokenAcceptance::Verified,
                PROJECT
            ),
            Err(JwtError::Malformed)
        );
    }
}

#[test]
fn existing_unsigned_mock_opt_in_is_not_silently_removed() {
    let (store, claims, _) = fixture();
    let token = with_json_claim(&claims, "iat", None);
    assert_eq!(
        verify_rules_token(&token, &store, at(NOW), TokenAcceptance::Verified),
        Err(JwtError::Malformed)
    );
    assert!(verify_rules_token(&token, &store, at(NOW), TokenAcceptance::EmulatorMock).is_ok());
}

#[test]
fn namespace_checks_are_not_replaced_by_the_time_check() {
    let (store, mut claims, _) = fixture();
    claims.iat = NOW + 60;
    claims.aud = "demo-other".to_owned();
    assert!(matches!(
        verify_id_token(&encode_unsigned(&claims), &store, at(NOW)),
        Err(JwtError::WrongAudience { .. })
    ));
    claims.aud = PROJECT.to_owned();
    claims.firebase.tenant = Some("other-tenant".to_owned());
    assert!(matches!(
        verify_id_token(&encode_unsigned(&claims), &store, at(NOW)),
        Err(JwtError::WrongTenant { .. })
    ));
    claims.iss = "https://securetoken.google.com/demo-other".to_owned();
    assert!(matches!(
        verify_id_token(&encode_unsigned(&claims), &store, at(NOW)),
        Err(JwtError::WrongIssuer { .. })
    ));
}

#[test]
fn verification_does_not_consume_or_modify_the_account_on_a_time_refusal() {
    let (store, claims, uid) = fixture();
    let before = store
        .id_token_claims(&uid, None, at(NOW))
        .unwrap()
        .canonical_json();
    let mut invalid = claims.clone();
    invalid.iat = NOW + 60;
    let token = encode_unsigned(&invalid);
    for _ in 0..3 {
        assert_eq!(
            verify_id_token(&token, &store, at(NOW)),
            Err(JwtError::Malformed)
        );
    }
    let after = store
        .id_token_claims(&uid, None, at(NOW))
        .unwrap()
        .canonical_json();
    assert_eq!(before, after);
    assert!(verify_id_token(&encode_unsigned(&claims), &store, at(NOW)).is_ok());
}

#[test]
fn very_large_time_claims_do_not_require_duration_arithmetic() {
    let (store, mut claims, _) = fixture();
    claims.exp = i64::MAX;
    claims.iat = i64::MAX;
    assert_eq!(
        verify_id_token(&encode_unsigned(&claims), &store, at(NOW)),
        Err(JwtError::Malformed)
    );
    claims.iat = NOW;
    claims.auth_time = i64::MAX;
    assert_eq!(
        verify_id_token(&encode_unsigned(&claims), &store, at(NOW)),
        Err(JwtError::Malformed)
    );
}
