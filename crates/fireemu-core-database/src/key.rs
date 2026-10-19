//! Keys: validation and the key order.
//!
//! A key is a non-empty string without `.`, `$`, `#`, `[`, `]`, `/` and the ASCII control
//! characters U+0000 to U+001F and U+007F, at most [`Limits::max_key_bytes`] bytes long.
//!
//! Keys are ordered as the SDKs and the server order them (`nameCompare` in
//! `@firebase/database`): keys that parse as 32-bit integers come first, in numeric order
//! (equal numbers, such as `1` and `01`, by length); every other key follows in UTF-16 code
//! unit order.

use std::cmp::Ordering;

use crate::error::Result;
use crate::limits::Limits;

/// Checks that `key` may name a child.
pub fn validate_key(key: &str, limits: &Limits) -> Result<()> {
    let _ = (key, limits);
    todo!()
}

/// The 32-bit integer `key` spells, if any (`-?0*\d{1,10}` within the i32 range).
pub fn key_as_int(key: &str) -> Option<i32> {
    let _ = key;
    todo!()
}

/// The key order.
pub fn name_compare(a: &str, b: &str) -> Ordering {
    let _ = (a, b);
    todo!()
}

/// UTF-16 code unit order, the order of JavaScript and Java string comparison.
pub fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}
