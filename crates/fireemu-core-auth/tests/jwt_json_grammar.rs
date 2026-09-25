//! JWT decoding must use JSON grammar, not Rust's signed radix-number grammar.
//! These tests exercise the real decoder without network, credentials or a signer.

use fireemu_core_auth::jwt::{base64url_encode, decode_unsigned, JwtError};

fn token(header: &str, payload: &str) -> String {
    format!(
        "{}.{}.",
        base64url_encode(header.as_bytes()),
        base64url_encode(payload.as_bytes())
    )
}

#[test]
fn malformed_header_member_names_do_not_become_alg() {
    let input = token(r#"{"\u+061lg":"none","typ":"JWT"}"#, r#"{"sub":"alice"}"#);
    assert_eq!(decode_unsigned(&input), Err(JwtError::Malformed));
}

#[test]
fn malformed_algorithm_escape_does_not_become_none() {
    let input = token(r#"{"alg":"\u+06eone"}"#, r#"{"sub":"alice"}"#);
    assert_eq!(decode_unsigned(&input), Err(JwtError::Malformed));
}

#[test]
fn malformed_payload_names_and_subject_values_are_refused() {
    for payload in [
        r#"{"su\u+062":"alice"}"#,
        r#"{"sub":"\u+061lice"}"#,
        r#"{"sub":"alice","claims":{"\u+061dmin":true}}"#,
    ] {
        let input = token(r#"{"alg":"none"}"#, payload);
        assert_eq!(
            decode_unsigned(&input),
            Err(JwtError::Malformed),
            "{payload}"
        );
    }
}

#[test]
fn valid_json_escapes_and_literal_escape_looking_text_stay_valid() {
    let input = token(
        r#"{"\u0061lg":"none","typ":"JWT"}"#,
        r#"{"su\u0062":"\u0061lice"}"#,
    );
    assert_eq!(decode_unsigned(&input).unwrap().sub(), Some("alice"));
    let input = token(r#"{"alg":"none"}"#, r#"{"sub":"\\u+041"}"#);
    assert_eq!(decode_unsigned(&input).unwrap().sub(), Some(r"\u+041"));
}

#[test]
fn normal_unicode_subjects_and_signed_token_refusal_are_unchanged() {
    let input = token(r#"{"alg":"none"}"#, r#"{"sub":"利用者😀"}"#);
    assert_eq!(decode_unsigned(&input).unwrap().sub(), Some("利用者😀"));
    let input = token(r#"{"alg":"RS256"}"#, r#"{"sub":"alice"}"#);
    assert_eq!(
        decode_unsigned(&input),
        Err(JwtError::UnsupportedAlgorithm("RS256".to_owned()))
    );
}
