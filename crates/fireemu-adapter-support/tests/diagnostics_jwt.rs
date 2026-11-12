//! Tests for JWT and refresh token redaction.

use fireemu_adapter_support::diagnostics::redact::scrub;
use proptest::prelude::*;

#[test]
fn unsigned_tokens_and_refresh_tokens_are_masked() {
    let header = ["eyJhbGci", "OiJub25lIn0"].concat();
    let unsigned = format!("{}.{}.", header, "a".repeat(40));
    // The emulator base64url-encodes this header and the canonical claims JSON.
    let emulator_header = ["eyJhbGciOiJub25l", "IiwidHlwIjoiSldUIn0"].concat();
    let payload = ["eyJzdWIiOi", "J1c2VyIn0"].concat();
    let emulator = format!("{emulator_header}.{payload}.");
    let refresh = format!("refreshToken\":\"{}", "r".repeat(60));
    for text in [unsigned, emulator, refresh] {
        assert_eq!(scrub(&text).0, "[redacted]");
    }
}

#[test]
fn ordinary_words_are_preserved() {
    for text in [
        "authority",
        "authority.Bearer",
        "config.json",
        "x.y.z",
        "eyJabcdef",
    ] {
        assert_eq!(scrub(text).0, text);
    }
}

proptest! {
    #[test]
    fn scrub_is_idempotent_and_does_not_expand(text in ".*") {
        let once = scrub(&text).0;
        prop_assert_eq!(scrub(&once).0, once.clone());
        prop_assert!(once.len() <= text.len().max("[redacted]".len()));
    }
    #[test]
    fn matched_unsigned_token_does_not_survive(payload in "[a-zA-Z0-9_-]{4,80}") {
        let token = format!("{}.{}.", ["eyJ", "abcd"].concat(), payload);
        prop_assert!(!scrub(&token).0.contains(&token));
    }
}
