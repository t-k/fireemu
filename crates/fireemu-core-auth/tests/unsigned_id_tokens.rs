//! `auth.allowUnsignedIdTokens` (owner ledger 1393): which tokens count as unsigned emulator
//! ID tokens, and how the Security Rules verifiers treat them under each policy.
//!
//! The Firebase JS SDK's `mockUserToken` (`createMockUserToken`, `@firebase/util`), which
//! `@firebase/rules-unit-testing`'s `authenticatedContext()` uses, sends the header
//! `{"alg":"none","type":"JWT"}`, a payload with `iat: 0`, `exp: 3600` and a `sub` that need
//! not name a user, and an empty signature segment.

use fireemu_core_auth::jwt::{
    base64url_encode, encode_unsigned, encode_with, is_sdk_mock_token, is_unsigned_token,
    verify_firestore_rules_token, verify_firestore_rules_token_of_removed_tenant,
    verify_rules_token, verify_rules_token_for_project, IdTokenSigner, JwtError, RulesTokenPolicy,
    TokenAcceptance,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;
use std::sync::Arc;

const PROJECT: &str = "demo-app";

fn now() -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_004_860)
}

fn store() -> AuthStore {
    AuthStore::new(PROJECT, SplitMix64::new(1), TotpPolicy::default())
}

fn token(header: &str, payload: &str, signature: &str) -> String {
    format!(
        "{}.{}.{signature}",
        base64url_encode(header.as_bytes()),
        base64url_encode(payload.as_bytes())
    )
}

/// The payload `createMockUserToken` builds for `authenticatedContext("alice")`, member for
/// member.
fn mock_payload(sub: &str, project: &str) -> String {
    format!(
        r#"{{"iss":"https://securetoken.google.com/{project}","aud":"{project}","iat":0,"exp":3600,"auth_time":0,"sub":"{sub}","user_id":"{sub}","firebase":{{"sign_in_provider":"custom","identities":{{}}}}}}"#
    )
}

/// The token `@firebase/rules-unit-testing` sends for `authenticatedContext(sub)`.
fn mock_user_token(sub: &str, project: &str) -> String {
    token(
        r#"{"alg":"none","type":"JWT"}"#,
        &mock_payload(sub, project),
        "",
    )
}

/// A token that claims an RS256 signature that verifies against nothing.
fn tampered_rs256(sub: &str, project: &str) -> String {
    token(
        r#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#,
        &mock_payload(sub, project),
        &base64url_encode(b"not a signature"),
    )
}

fn strict(allow_unsigned: bool) -> RulesTokenPolicy {
    RulesTokenPolicy::new(TokenAcceptance::Verified, allow_unsigned)
}

fn emulator(allow_unsigned: bool) -> RulesTokenPolicy {
    RulesTokenPolicy::new(TokenAcceptance::EmulatorMock, allow_unsigned)
}

#[test]
fn the_profile_defaults_keep_todays_behaviour() {
    assert_eq!(
        RulesTokenPolicy::from(TokenAcceptance::Verified),
        strict(false)
    );
    assert_eq!(
        RulesTokenPolicy::from(TokenAcceptance::EmulatorMock),
        emulator(true)
    );
    assert_eq!(RulesTokenPolicy::default(), strict(false));
    assert!(strict(true).allows_unsigned());
    assert!(!strict(false).allows_unsigned());
    assert_eq!(strict(true).acceptance(), TokenAcceptance::Verified);
    assert_eq!(emulator(false).acceptance(), TokenAcceptance::EmulatorMock);
}

#[test]
fn the_sdk_mock_token_and_fireemus_own_unsigned_tokens_are_unsigned() {
    assert!(is_unsigned_token(&mock_user_token("alice", PROJECT)));
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), now())
        .unwrap();
    assert!(is_unsigned_token(&encode_unsigned(
        &s.id_token_claims(&uid, None, now()).unwrap()
    )));
    assert!(is_unsigned_token(&token(r#"{"alg":"none"}"#, "{}", "")));
    // The classifier reads the header and the signature only: a payload that does not parse
    // is still an unsigned token, refused later as malformed.
    assert!(is_unsigned_token(&token(
        r#"{"alg":"none"}"#,
        "not json",
        ""
    )));
}

#[test]
fn everything_else_counts_as_signed() {
    let payload = mock_payload("alice", PROJECT);
    for (header, signature) in [
        // A signature, whatever the header says.
        (r#"{"alg":"none","type":"JWT"}"#, "c2ln"),
        (r#"{"alg":"RS256","kid":"k1"}"#, "c2ln"),
        // A signed algorithm with an empty signature.
        (r#"{"alg":"RS256","kid":"k1"}"#, ""),
        (r#"{"alg":"HS256"}"#, ""),
        // `alg` is case-sensitive (RFC 7515 section 4.1.1) and must be the string `none`.
        (r#"{"alg":"None"}"#, ""),
        (r#"{"alg":"NONE"}"#, ""),
        (r#"{"alg":"none "}"#, ""),
        (r#"{"alg":""}"#, ""),
        (r#"{"alg":null}"#, ""),
        (r#"{"alg":["none"]}"#, ""),
        (r#"{"typ":"JWT"}"#, ""),
        // A header that is not a JSON object.
        (r#""none""#, ""),
        (r#"["none"]"#, ""),
        ("alg none", ""),
    ] {
        let candidate = token(header, &payload, signature);
        assert!(
            !is_unsigned_token(&candidate),
            "{header} with signature {signature:?} must count as signed"
        );
    }
    let mock = mock_user_token("alice", PROJECT);
    // Not three segments.
    assert!(!is_unsigned_token(mock.trim_end_matches('.')));
    assert!(!is_unsigned_token(&format!("{mock}.")));
    assert!(!is_unsigned_token(""));
    // A header segment that is not base64url without padding.
    assert!(!is_unsigned_token(&format!("={mock}")));
    let padded_header = format!("{}=", base64url_encode(br#"{"alg":"none"}"#));
    assert!(!is_unsigned_token(&format!(
        "{padded_header}.{}.",
        base64url_encode(b"{}")
    )));
}

#[test]
fn strict_with_the_setting_admits_the_mock_token_on_both_rules_verifiers() {
    let s = store();
    let mock = mock_user_token("alice", PROJECT);
    let decoded = verify_rules_token(&mock, &s, now(), strict(true)).unwrap();
    assert_eq!(decoded.sub(), Some("alice"));
    assert_eq!(decoded.payload_json, mock_payload("alice", PROJECT));
    let decoded = verify_firestore_rules_token(&mock, &s, now(), strict(true), None).unwrap();
    assert_eq!(decoded.sub(), Some("alice"));
    assert!(verify_rules_token_for_project(&mock, &s, now(), strict(true), PROJECT).is_ok());
}

#[test]
fn strict_without_the_setting_refuses_exactly_as_before() {
    let s = store();
    let mock = mock_user_token("alice", PROJECT);
    let before = verify_rules_token(&mock, &s, now(), TokenAcceptance::Verified);
    assert_eq!(before, Err(JwtError::Expired));
    assert_eq!(verify_rules_token(&mock, &s, now(), strict(false)), before);
    let before = verify_firestore_rules_token(&mock, &s, now(), TokenAcceptance::Verified, None);
    assert_eq!(before, Err(JwtError::Expired));
    assert_eq!(
        verify_firestore_rules_token(&mock, &s, now(), strict(false), None),
        before
    );
    assert_eq!(
        verify_rules_token_for_project(&mock, &s, now(), strict(false), PROJECT),
        Err(JwtError::Expired)
    );
}

#[test]
fn a_tampered_signed_token_is_refused_whatever_the_setting() {
    let s = store();
    let forged = tampered_rs256("alice", PROJECT);
    for policy in [strict(true), strict(false), emulator(true), emulator(false)] {
        assert_eq!(
            verify_rules_token(&forged, &s, now(), policy),
            Err(JwtError::UnsupportedAlgorithm("RS256".to_owned())),
            "{policy:?}"
        );
        assert_eq!(
            verify_firestore_rules_token(&forged, &s, now(), policy, None),
            Err(JwtError::UnsupportedAlgorithm("RS256".to_owned())),
            "{policy:?}"
        );
    }
    // `alg: none` with a signature is not a mock token either.
    let signed_none = token(
        r#"{"alg":"none","type":"JWT"}"#,
        &mock_payload("alice", PROJECT),
        "c2ln",
    );
    for policy in [strict(true), emulator(true)] {
        assert_eq!(
            verify_rules_token(&signed_none, &s, now(), policy),
            Err(JwtError::Malformed),
            "{policy:?}"
        );
    }
}

/// A store that signs its ID tokens (`auth.idTokenSigning: session-rsa`) refuses every
/// unsigned token on the Rules surfaces, as the emulator profile already does.
#[test]
fn a_signing_session_refuses_unsigned_tokens_whatever_the_setting() {
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
    let signer: Arc<dyn IdTokenSigner> = Arc::new(ReversingSigner);
    let mut s = store();
    s.set_signer(signer.clone());
    let mock = mock_user_token("alice", PROJECT);
    for policy in [strict(true), emulator(true)] {
        assert_eq!(
            verify_rules_token(&mock, &s, now(), policy),
            Err(JwtError::UnsupportedAlgorithm("none".to_owned())),
            "{policy:?}"
        );
        assert_eq!(
            verify_firestore_rules_token(&mock, &s, now(), policy, None),
            Err(JwtError::UnsupportedAlgorithm("none".to_owned())),
            "{policy:?}"
        );
    }
    // The session's own signed tokens keep verifying.
    let uid = s
        .create_user(NewUser::email("a@example.com"), now())
        .unwrap();
    let real = encode_with(
        &s.id_token_claims(&uid, None, now()).unwrap(),
        Some(signer.as_ref()),
    );
    assert!(verify_rules_token(&real, &s, now(), strict(true)).is_ok());
}

/// The mock token must still be minted for the project the request routes to, and must name
/// a subject; under strict a refusal keeps the verified path's error, so the response is
/// today's.
#[test]
fn strict_refusals_of_unsigned_tokens_keep_the_verified_error() {
    let s = store();
    let foreign = mock_user_token("alice", "demo-other");
    let before = verify_rules_token(&foreign, &s, now(), TokenAcceptance::Verified);
    assert!(matches!(before, Err(JwtError::WrongIssuer { .. })));
    assert_eq!(
        verify_rules_token(&foreign, &s, now(), strict(true)),
        before
    );
    assert_eq!(
        verify_rules_token_for_project(&foreign, &s, now(), strict(true), PROJECT),
        before
    );
    // The emulator profile answers with the mock path's audience error, as before.
    assert!(matches!(
        verify_rules_token(&foreign, &s, now(), emulator(true)),
        Err(JwtError::WrongAudience { .. })
    ));
    // No subject: the verified path stops at the expiry first, and strict answers that.
    let subjectless = token(
        r#"{"alg":"none","type":"JWT"}"#,
        &format!(
            r#"{{"iss":"https://securetoken.google.com/{PROJECT}","aud":"{PROJECT}","iat":0,"exp":3600,"auth_time":0}}"#
        ),
        "",
    );
    assert_eq!(
        verify_rules_token(&subjectless, &s, now(), strict(true)),
        Err(JwtError::Expired)
    );
    assert_eq!(
        verify_firestore_rules_token(&subjectless, &s, now(), strict(true), None),
        Err(JwtError::Expired)
    );
    // The emulator profile keeps answering with the mock path's error, as before.
    assert_eq!(
        verify_rules_token(&subjectless, &s, now(), emulator(true)),
        Err(JwtError::Malformed)
    );
    // A payload that is no JSON object.
    let not_object = token(r#"{"alg":"none"}"#, "[1]", "");
    assert_eq!(
        verify_rules_token(&not_object, &s, now(), strict(true)),
        Err(JwtError::Malformed)
    );
}

#[test]
fn the_emulator_profile_is_unchanged_by_default_and_the_setting_can_refuse() {
    let s = store();
    let mock = mock_user_token("alice", PROJECT);
    assert_eq!(
        verify_rules_token(&mock, &s, now(), TokenAcceptance::EmulatorMock),
        verify_rules_token(&mock, &s, now(), emulator(true))
    );
    assert!(verify_rules_token(&mock, &s, now(), emulator(true)).is_ok());
    assert_eq!(
        verify_rules_token(&mock, &s, now(), emulator(false)),
        Err(JwtError::Expired)
    );
    assert_eq!(
        verify_firestore_rules_token(&mock, &s, now(), emulator(false), None),
        Err(JwtError::Expired)
    );
}

#[test]
fn the_removed_tenant_path_follows_the_setting() {
    let s = store();
    let tenant_mock = token(
        r#"{"alg":"none","type":"JWT"}"#,
        &format!(
            r#"{{"iss":"https://securetoken.google.com/{PROJECT}","aud":"{PROJECT}","iat":0,"exp":3600,"auth_time":0,"sub":"alice","firebase":{{"tenant":"gone"}}}}"#
        ),
        "",
    );
    assert!(verify_firestore_rules_token_of_removed_tenant(
        &tenant_mock,
        &s,
        now(),
        strict(true),
        None,
        None
    )
    .is_ok());
    assert_eq!(
        verify_firestore_rules_token_of_removed_tenant(
            &tenant_mock,
            &s,
            now(),
            strict(false),
            None,
            None
        ),
        Err(JwtError::Expired)
    );
}

/// The verified path is unchanged by the setting: a real token of the store verifies the same
/// way, and its future-claim policy is still the profile's.
#[test]
fn a_verifiable_token_takes_the_verified_path_under_every_policy() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), now())
        .unwrap();
    let real = encode_unsigned(&s.id_token_claims(&uid, None, now()).unwrap());
    let expected = verify_rules_token(&real, &s, now(), TokenAcceptance::Verified).unwrap();
    for policy in [strict(true), strict(false), emulator(true), emulator(false)] {
        assert_eq!(
            verify_rules_token(&real, &s, now(), policy).as_ref(),
            Ok(&expected),
            "{policy:?}"
        );
    }
}

fn header_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Headers whose `alg` takes arbitrary string values, with optional extra members.
        (
            prop_oneof![
                Just("none".to_owned()),
                Just("None".to_owned()),
                Just("RS256".to_owned()),
                "[ -~]{0,8}",
            ],
            proptest::option::of("[a-z]{1,5}"),
        )
            .prop_map(|(alg, extra)| match extra {
                Some(key) if key != "alg" => {
                    serde_like_object(&[(key.as_str(), "\"JWT\""), ("alg", &json_string(&alg))])
                }
                _ => serde_like_object(&[("alg", &json_string(&alg))]),
            }),
        // Headers without a string `alg`.
        prop_oneof![
            Just(r#"{"alg":1}"#.to_owned()),
            Just(r#"{"alg":true}"#.to_owned()),
            Just("{}".to_owned()),
            Just("[]".to_owned()),
            Just(r#""none""#.to_owned()),
        ],
        // Arbitrary bytes.
        "[ -~]{0,24}",
    ]
}

fn json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn serde_like_object(members: &[(&str, &str)]) -> String {
    let body: Vec<String> = members
        .iter()
        .map(|(key, value)| format!("{}:{value}", json_string(key)))
        .collect();
    format!("{{{}}}", body.join(","))
}

/// The reference classifier: exactly three segments, a base64url header that is a JSON object
/// whose `alg` is the string `none`, and an empty signature.
fn reference_is_unsigned(header: &str, signature: &str) -> bool {
    let Ok(value) = serde_json_lite(header) else {
        return false;
    };
    value && signature.is_empty()
}

/// Whether `header` is a JSON object whose `alg` member is exactly the string `none`, for the
/// headers [`header_strategy`] generates.
fn serde_json_lite(header: &str) -> Result<bool, ()> {
    let parsed = fireemu_core_types::json::parse(header).map_err(|_| ())?;
    if !matches!(parsed, fireemu_core_types::json::JsonValue::Object(_)) {
        return Err(());
    }
    Ok(parsed
        .get("alg")
        .and_then(fireemu_core_types::json::JsonValue::as_str)
        == Some("none"))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn the_classifier_matches_the_reference(
        header in header_strategy(),
        payload in "[ -~]{0,24}",
        signature in prop_oneof![Just(String::new()), "[A-Za-z0-9_-]{1,12}"],
    ) {
        let candidate = token(&header, &payload, &signature);
        prop_assert_eq!(
            is_unsigned_token(&candidate),
            reference_is_unsigned(&header, &signature)
        );
    }

    /// Whatever the header, a non-empty signature segment is never unsigned, and no policy
    /// admits a token that is not unsigned unless the store verifies it.
    #[test]
    fn a_signature_or_a_signed_algorithm_never_takes_the_unsigned_path(
        header in header_strategy(),
        signature in "[A-Za-z0-9_-]{1,12}",
        sub in "[a-z]{1,8}",
    ) {
        let candidate = token(&header, &mock_payload(&sub, PROJECT), &signature);
        prop_assert!(!is_unsigned_token(&candidate));
        let s = store();
        for policy in [strict(true), emulator(true)] {
            prop_assert!(verify_rules_token(&candidate, &s, now(), policy).is_err());
        }
    }

    /// For every mock token `authenticatedContext` can mint, strict with the setting admits it
    /// with its claims as given, and strict without the setting answers as `Verified` does.
    #[test]
    fn every_sdk_mock_token_follows_the_setting(
        sub in "[A-Za-z0-9]{1,16}",
        iat in 0_i64..2_000_000_000,
    ) {
        let payload = format!(
            r#"{{"iss":"https://securetoken.google.com/{PROJECT}","aud":"{PROJECT}","iat":{iat},"exp":{},"auth_time":{iat},"sub":"{sub}","user_id":"{sub}","firebase":{{"sign_in_provider":"custom","identities":{{}}}}}}"#,
            iat + 3600
        );
        let mock = token(r#"{"alg":"none","type":"JWT"}"#, &payload, "");
        let s = store();
        let admitted = verify_firestore_rules_token(&mock, &s, now(), strict(true), None).unwrap();
        prop_assert_eq!(&admitted.payload_json, &payload);
        prop_assert_eq!(
            verify_firestore_rules_token(&mock, &s, now(), strict(false), None),
            verify_firestore_rules_token(&mock, &s, now(), TokenAcceptance::Verified, None)
        );
        prop_assert!(verify_firestore_rules_token(&mock, &s, now(), strict(false), None).is_err());
    }
}

/// The exact header `createMockUserToken` (`@firebase/util` 1.15.3) writes:
/// `JSON.stringify({alg: 'none', type: 'JWT'})`.
const SDK_HEADER: &str = r#"{"alg":"none","type":"JWT"}"#;

#[test]
fn only_the_sdk_mock_token_shape_is_a_mock_token() {
    let payload = mock_payload("alice", PROJECT);
    assert!(is_sdk_mock_token(&token(SDK_HEADER, &payload, "")));
    // The classifier reads the header and the signature only.
    assert!(is_sdk_mock_token(&token(SDK_HEADER, "not json", "")));
    for header in [
        // fireemu's own unsigned ID tokens.
        r#"{"alg":"none","typ":"JWT"}"#,
        r#"{"alg":"none"}"#,
        // The same members written differently: another order, spacing, an extra member.
        r#"{"type":"JWT","alg":"none"}"#,
        r#"{"alg": "none", "type": "JWT"}"#,
        r#"{"alg":"none","type":"JWT","kid":"k"}"#,
        r#"{"alg":"none","type":"jwt"}"#,
        r#"{"alg":"None","type":"JWT"}"#,
        r#"{"alg":"RS256","type":"JWT"}"#,
    ] {
        assert!(!is_sdk_mock_token(&token(header, &payload, "")), "{header}");
    }
    assert!(!is_sdk_mock_token(&token(SDK_HEADER, &payload, "c2ln")));
    let mock = token(SDK_HEADER, &payload, "");
    assert!(!is_sdk_mock_token(mock.trim_end_matches('.')));
    assert!(!is_sdk_mock_token(&format!("{mock}.")));
    assert!(!is_sdk_mock_token(&format!(
        "{}=.{}.",
        base64url_encode(SDK_HEADER.as_bytes()),
        base64url_encode(payload.as_bytes())
    )));
}

/// Under strict, fireemu's own unsigned ID tokens keep every claim check, expiry included: an
/// expired one is refused with the setting on, as with it off.
#[test]
fn strict_keeps_every_check_on_fireemus_own_unsigned_tokens() {
    let mut s = store();
    let uid = s
        .create_user(NewUser::email("a@example.com"), now())
        .unwrap();
    let claims = s.id_token_claims(&uid, None, now()).unwrap();
    let issued = encode_unsigned(&claims);
    let later = LogicalInstant::from_unix_seconds(claims.exp + 3600);
    assert_eq!(
        verify_rules_token(&issued, &s, later, strict(true)),
        Err(JwtError::Expired)
    );
    assert_eq!(
        verify_firestore_rules_token(&issued, &s, later, strict(true), None),
        Err(JwtError::Expired)
    );
    // A mock-shaped payload under fireemu's headers is not a mock token under strict either.
    for header in [r#"{"alg":"none","typ":"JWT"}"#, r#"{"alg":"none"}"#] {
        let candidate = token(header, &mock_payload("alice", PROJECT), "");
        assert_eq!(
            verify_rules_token(&candidate, &s, now(), strict(true)),
            verify_rules_token(&candidate, &s, now(), strict(false)),
            "{header}"
        );
        assert!(verify_rules_token(&candidate, &s, now(), strict(true)).is_err());
    }
    // The emulator profile keeps admitting any unsigned token, as the official emulator does.
    let any_unsigned = token(r#"{"alg":"none"}"#, &mock_payload("alice", PROJECT), "");
    assert!(verify_rules_token(&any_unsigned, &s, now(), emulator(true)).is_ok());
    assert!(verify_rules_token(&issued, &s, later, emulator(true)).is_ok());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// The SDK classifier is the exact header bytes and an empty signature, whatever else the
    /// header says.
    #[test]
    fn the_sdk_classifier_is_the_exact_header_and_an_empty_signature(
        header in prop_oneof![Just(SDK_HEADER.to_owned()), header_strategy()],
        payload in "[ -~]{0,24}",
        signature in prop_oneof![Just(String::new()), "[A-Za-z0-9_-]{1,12}"],
    ) {
        let candidate = token(&header, &payload, &signature);
        prop_assert_eq!(
            is_sdk_mock_token(&candidate),
            header == SDK_HEADER && signature.is_empty()
        );
        // Every SDK mock token is an unsigned token.
        if is_sdk_mock_token(&candidate) {
            prop_assert!(is_unsigned_token(&candidate));
        }
    }

    /// Under strict, an unsigned token that is not the SDK shape gets the same answer with the
    /// setting on as off.
    #[test]
    fn strict_answers_other_unsigned_tokens_as_without_the_setting(
        header in header_strategy(),
        sub in "[a-z]{1,8}",
    ) {
        prop_assume!(header != SDK_HEADER);
        let candidate = token(&header, &mock_payload(&sub, PROJECT), "");
        let s = store();
        prop_assert_eq!(
            verify_rules_token(&candidate, &s, now(), strict(true)),
            verify_rules_token(&candidate, &s, now(), strict(false))
        );
    }
}
