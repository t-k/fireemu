//! Secret comparisons whose result and diagnostics never retain either operand.

use subtle::ConstantTimeEq as _;

/// Compares two byte strings in constant time once their public lengths match.
#[must_use]
pub fn constant_time_eq(presented: &[u8], expected: &[u8]) -> bool {
    presented.len() == expected.len() && bool::from(presented.ct_eq(expected))
}

/// Compares an optional presented string with an expected secret.
#[must_use]
pub fn optional_str_matches(presented: Option<&str>, expected: &str) -> bool {
    presented.is_some_and(|value| constant_time_eq(value.as_bytes(), expected.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{constant_time_eq, optional_str_matches};

    #[test]
    fn secret_comparison_exposes_only_a_boolean_result() {
        let sentinel = "private-control-token-sentinel";
        let result = optional_str_matches(Some("wrong"), sentinel);
        assert!(!result);
        assert!(!format!("{result:?}").contains(sentinel));
        assert!(constant_time_eq(sentinel.as_bytes(), sentinel.as_bytes()));
        assert!(!constant_time_eq(b"private", b"privatf"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
