//! Defence-in-depth removal of secret-shaped text.

/// Returns the scrubbed text and the number of replacements.
pub fn scrub(text: &str) -> (String, u64) {
    let lower = text.to_ascii_lowercase();
    let token_char = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let bearer = lower
        .match_indices("bearer ")
        .any(|(i, _)| text.as_bytes().get(i + 7).is_some_and(|b| token_char(*b)));
    let api_key = text.match_indices("AIza").any(|(i, _)| {
        text.as_bytes()
            .get(i + 4..i + 39)
            .is_some_and(|s| s.iter().all(|b| token_char(*b)))
    });
    // Only long base64url runs next to a refresh label are detected; opaque tokens elsewhere may survive.
    let refresh = ["refreshtoken", "refresh_token", "refresh"]
        .iter()
        .any(|label| {
            lower.match_indices(label).any(|(i, _)| {
                let rest = &text[i + label.len()..];
                let rest = rest.trim_start_matches(|c: char| {
                    c.is_whitespace() || [':', '=', '"', '\''].contains(&c)
                });
                rest.bytes().take_while(|b| token_char(*b)).count() >= 40
            })
        });
    if lower.contains("authorization")
        || bearer
        || text.contains("ya29.")
        || text.contains("rt1.")
        || api_key
        || text.contains("-----BEGIN ")
        || text.contains("\"private_key\"")
        || refresh
    {
        return ("[redacted]".into(), 1);
    }
    let mut redacted = String::new();
    let mut end = 0;
    let mut count = 0;
    for (start, _) in text.match_indices("eyJ") {
        if start < end {
            continue;
        }
        let bytes = text.as_bytes();
        let mut pos = start;
        while bytes.get(pos).is_some_and(|b| token_char(*b)) {
            pos += 1;
        }
        if pos - start < 7 || bytes.get(pos) != Some(&b'.') {
            continue;
        }
        pos += 1;
        let payload_start = pos;
        while bytes.get(pos).is_some_and(|b| token_char(*b)) {
            pos += 1;
        }
        if pos - payload_start < 4 {
            continue;
        }
        // A dot after the payload is taken as the start of a (possibly empty) signature: an unsigned
        // emulator token ends with one, and a sentence period after it is lost rather than a token kept.
        if bytes.get(pos) == Some(&b'.') {
            pos += 1;
            while bytes.get(pos).is_some_and(|b| token_char(*b)) {
                pos += 1;
            }
        }
        redacted.push_str(&text[end..start]);
        redacted.push_str("[redacted]");
        end = pos;
        count += 1;
    }
    if count > 0 {
        redacted.push_str(&text[end..]);
        return (redacted, count);
    }
    for prefix in ["/Users/", "/home/", "C:\\Users\\", "C:/Users/"] {
        if let Some(rest) = text.strip_prefix(prefix) {
            if let Some((_, path)) = rest.split_once(['/', '\\']) {
                return (format!("~/{}", path.replace('\\', "/")), 1);
            }
            return ("~/".into(), 1);
        }
    }
    (text.into(), 0)
}

#[cfg(test)]
mod tests {
    use super::scrub;

    #[test]
    fn two_segment_jwt_is_redacted() {
        let token = format!("{}.{}", "eyJhbGciOiJub25lIn0", "eyJzdWIiOiJ1c2VyIn0");
        assert_eq!(scrub(&token).0, "[redacted]");
    }

        /// What follows a redacted token: a dot right after a two-segment token is read as the start of
    /// its (empty) signature, as an unsigned emulator token ends with one, so it goes with the token.
    fn kept_after<'a>(token: &str, after: &'a str) -> &'a str {
        if token.matches('.').count() == 1 {
            after.strip_prefix('.').unwrap_or(after)
        } else {
            after
        }
    }

    #[test]
    fn jwt_preserves_surrounding_punctuation() {
        for token in [
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0",
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.signature",
        ] {
            for suffix in [".", ",", ")", "\"", "..", ". Next sentence"] {
                assert_eq!(
                    scrub(&format!("{token}{suffix}")),
                    (format!("[redacted]{}", kept_after(token, suffix)), 1)
                );
            }
            assert_eq!(scrub(&format!("({token})")), ("([redacted])".into(), 1));
        }
        for word in ["file.name.ext", "1.2.3"] {
            assert_eq!(scrub(word), (word.into(), 0));
        }
    }

    proptest::proptest! {
        #[test]
        fn jwt_with_surrounding_punctuation_is_redacted(
            header in "[A-Za-z0-9_-]{4,12}",
            payload in "[A-Za-z0-9_-]{4,12}",
            signature in proptest::option::of("[A-Za-z0-9_-]{1,12}"),
            before in proptest::collection::vec(proptest::sample::select("!\"#$%&'()*+,./:;<=>?@[\\]^`{|}~ ".chars().collect::<Vec<_>>()), 0..9),
            after in proptest::collection::vec(proptest::sample::select("!\"#$%&'()*+,./:;<=>?@[\\]^`{|}~ ".chars().collect::<Vec<_>>()), 0..9),
        ) {
            let before: String = before.into_iter().collect();
            let after: String = after.into_iter().collect();
            let token = match signature {
                Some(signature) => format!("eyJ{header}.{payload}.{signature}"),
                None => format!("eyJ{header}.{payload}"),
            };
            proptest::prop_assert_eq!(
                scrub(&format!("{before}{token}{after}")),
                (format!("{before}[redacted]{}", kept_after(&token, &after)), 1),
            );
        }
    }

    #[test]
    fn labeled_and_emulator_refresh_tokens_are_redacted() {
        let opaque = "r".repeat(60);
        for text in [
            format!("\"refreshToken\": \"{opaque}\""),
            "rt1.8.0.demo-app.0123456789abcdef0001".to_owned(),
        ] {
            assert_eq!(scrub(&text).0, "[redacted]");
        }
    }
}
