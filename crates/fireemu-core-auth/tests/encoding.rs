//! Canonical JSON, redaction and error wording pinned by the mutation run.

use fireemu_core_auth::base32;
use fireemu_core_auth::claims::{write_json_string, ClaimValue, CustomClaimsError};
use fireemu_core_auth::jwt::{decode_unsigned, encode, encode_unsigned, JwtError, SigningMode};
use fireemu_core_auth::mfa::{TotpPolicy, TotpSecret};
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;

#[test]
fn json_strings_escape_control_characters_and_lists_use_commas() {
    let mut out = String::new();
    write_json_string(&mut out, "a\u{1}b\u{1f}c d\"\\\n");
    assert_eq!(out, "\"a\\u0001b\\u001fc d\\\"\\\\\\n\"");
    let mut list = String::new();
    ClaimValue::List(vec![
        ClaimValue::Int(1),
        ClaimValue::Bool(true),
        ClaimValue::Null,
    ])
    .write_canonical_json(&mut list);
    assert_eq!(list, "[1,true,null]");
    assert!(!CustomClaimsError::ReservedName("sub".into())
        .to_string()
        .is_empty());
}

#[test]
fn signing_modes_encode_or_refuse_and_secrets_stay_redacted() {
    let mut store = AuthStore::new("demo-app", SplitMix64::new(3), TotpPolicy::default());
    let now = LogicalInstant::from_unix_seconds(1_788_004_860);
    let uid = store
        .create_user(NewUser::email("e@example.com"), now)
        .unwrap();
    let claims = store.id_token_claims(&uid, None, now).unwrap();
    let token = encode(&claims, SigningMode::UnsignedEmulator).unwrap();
    assert_eq!(token, encode_unsigned(&claims));
    assert_eq!(token.split('.').count(), 3);
    assert_eq!(decode_unsigned(&token).unwrap().sub(), Some(uid.as_str()));
    assert!(matches!(
        encode(&claims, SigningMode::SessionRsa),
        Err(JwtError::SigningUnsupported(_))
    ));
    assert!(!JwtError::Malformed.to_string().is_empty());
    let secret = TotpSecret::new(vec![1, 2, 3]);
    assert_eq!(secret.expose_for_enrollment(), &[1, 2, 3]);
    assert_eq!(format!("{secret:?}"), "TotpSecret([redacted])");
    assert!(!base32::decode("1").unwrap_err().to_string().is_empty());
}
