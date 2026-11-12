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
    let jwt = text
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.'))
        .any(|word| {
            let parts: Vec<_> = word.split('.').collect();
            parts.len() == 3
                && parts[0].starts_with("eyJ")
                && parts[0].len() >= 7
                && parts[1].len() >= 4
                && parts.iter().all(|p| p.bytes().all(token_char))
        });
    // Only long base64url runs next to a refresh label are detected; opaque tokens elsewhere may survive.
    let refresh = ["refreshtoken", "refresh_token", "refresh"]
        .iter()
        .any(|label| {
            lower.match_indices(label).any(|(i, _)| {
                let rest = &text[i + label.len()..];
                let rest = rest.trim_start_matches([':', '=', '"']);
                rest.bytes().take_while(|b| token_char(*b)).count() >= 40
            })
        });
    if lower.contains("authorization")
        || bearer
        || text.contains("ya29.")
        || api_key
        || text.contains("-----BEGIN ")
        || text.contains("\"private_key\"")
        || jwt
        || refresh
    {
        return ("[redacted]".into(), 1);
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
