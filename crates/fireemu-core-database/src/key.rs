//! Keys: validation and the key order.
//!
//! A key is a non-empty string without `.`, `$`, `#`, `[`, `]`, `/` and the ASCII control
//! characters U+0000 to U+001F and U+007F, at most [`Limits::max_key_bytes`] bytes long.
//!
//! Keys are ordered as the SDKs and the server order them (`nameCompare` in
//! `@firebase/database`): keys that parse as 32-bit integers come first, in numeric order
//! (equal numbers, such as `1` and `01`, by length); every other key follows in UTF-16 code
//! unit order. Distinct integer keys of one value and length (`-0`, `00`) are ordered by
//! their strings, which keeps the order total.

use std::cmp::Ordering;

use crate::error::{DatabaseError, ErrorKind, Result};
use crate::limits::Limits;

/// Checks that `key` may name a child.
pub fn validate_key(key: &str, limits: &Limits) -> Result<()> {
    if key.is_empty() {
        return Err(DatabaseError::new(
            ErrorKind::InvalidKey,
            "a key may not be empty",
        ));
    }
    if let Some(bad) = key.chars().find(|c| is_forbidden(*c)) {
        return Err(DatabaseError::new(
            ErrorKind::InvalidKey,
            format!(
                "key {key:?} contains {bad:?}; keys may not contain \".\", \"#\", \"$\", \"/\", \"[\", \"]\" or ASCII control characters"
            ),
        ));
    }
    if key.len() > limits.max_key_bytes {
        return Err(DatabaseError::new(
            ErrorKind::KeyTooLong,
            format!(
                "a key is {} bytes long; the limit is {} bytes",
                key.len(),
                limits.max_key_bytes
            ),
        ));
    }
    Ok(())
}

/// Whether `c` may not appear in a key.
fn is_forbidden(c: char) -> bool {
    matches!(
        c,
        '.' | '$' | '#' | '[' | ']' | '/' | '\u{0}'..='\u{1f}' | '\u{7f}'
    )
}

/// The 32-bit integer `key` spells, if any (`-?0*\d{1,10}` within the i32 range).
pub fn key_as_int(key: &str) -> Option<i32> {
    let digits = key.strip_prefix('-').unwrap_or(key);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // Leading zeros are free; at most ten significant digits follow them.
    let significant = digits.trim_start_matches('0');
    if significant.len() > 10 {
        return None;
    }
    // Ten digits fit in an i64, so the parse cannot fail; the range decides.
    let value: i64 = key.parse().ok()?;
    i32::try_from(value).ok()
}

/// The key order.
pub fn name_compare(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    match (key_as_int(a), key_as_int(b)) {
        // The SDK stops at the length, so `-0` and `00` tie there; the final string order
        // makes the order total without changing any pair the SDK distinguishes.
        (Some(x), Some(y)) => x
            .cmp(&y)
            .then_with(|| a.len().cmp(&b.len()))
            .then_with(|| utf16_cmp(a, b)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => utf16_cmp(a, b),
    }
}

/// UTF-16 code unit order, the order of JavaScript and Java string comparison.
pub fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}
