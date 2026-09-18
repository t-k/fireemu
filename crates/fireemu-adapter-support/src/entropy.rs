//! The operating system's cryptographically secure random number generator.
//!
//! Every secret the daemon mints at start-up -- the control token, the runner secret, the
//! storage admin capability, the App Check signing key, the project epochs and `WebChannel`
//! session ids -- is drawn here, through one call that each supported target implements:
//! `getrandom` on Linux, `arc4random_buf` on the BSDs and macOS, `ProcessPrng` on Windows.
//! Opening a device file by path would work on Unix alone and would abort start-up on the
//! Windows package the project distributes.
//!
//! A draw that fails stays failed. Nothing here falls back to a predictable source; callers
//! that can degrade (a `WebChannel` session id can be keyed instead) decide that for themselves.

use std::fmt;

/// The operating system refused to produce entropy.
///
/// The cause is carried for diagnostics only; it never names a value that was drawn.
#[derive(Debug, Clone, Copy)]
pub struct EntropyUnavailable(getrandom::Error);

impl fmt::Display for EntropyUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the operating system random number generator is unavailable: {}",
            self.0
        )
    }
}

impl std::error::Error for EntropyUnavailable {}

/// Fills `dest` with bytes from the operating system CSPRNG.
///
/// # Errors
///
/// Returns [`EntropyUnavailable`] when the operating system produced no entropy. The contents
/// of `dest` are then unspecified and must not be used.
pub fn fill(dest: &mut [u8]) -> Result<(), EntropyUnavailable> {
    getrandom::fill(dest).map_err(EntropyUnavailable)
}

/// 128 bits from the operating system CSPRNG, lower-case hexadecimal, always 32 characters.
///
/// # Errors
///
/// Returns [`EntropyUnavailable`] when the operating system produced no entropy.
pub fn hex_128() -> Result<String, EntropyUnavailable> {
    use fmt::Write as _;
    let mut bytes = [0u8; 16];
    fill(&mut bytes)?;
    Ok(bytes.iter().fold(String::with_capacity(32), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    }))
}

/// 128 bits from the operating system CSPRNG as an integer.
///
/// # Errors
///
/// Returns [`EntropyUnavailable`] when the operating system produced no entropy.
pub fn u128_value() -> Result<u128, EntropyUnavailable> {
    let mut bytes = [0u8; 16];
    fill(&mut bytes)?;
    Ok(u128::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::{fill, hex_128, u128_value};

    #[test]
    fn hex_draws_thirty_two_lower_case_characters_that_differ_between_calls() {
        let first = hex_128().expect("the operating system CSPRNG is available under test");
        let second = hex_128().expect("the operating system CSPRNG is available under test");
        assert_eq!(first.len(), 32);
        assert_eq!(second.len(), 32);
        assert!(first.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!first.bytes().any(|b| b.is_ascii_uppercase()));
        assert_ne!(first, second);
    }

    #[test]
    fn fill_writes_every_byte_of_the_slice() {
        // A 64-byte draw leaving the tail untouched is what a short read would look like.
        let mut buffer = [0u8; 64];
        fill(&mut buffer).expect("the operating system CSPRNG is available under test");
        let mut again = [0u8; 64];
        fill(&mut again).expect("the operating system CSPRNG is available under test");
        assert_ne!(buffer, again);
        assert_ne!(buffer[48..], [0u8; 16]);
    }

    #[test]
    fn empty_draw_succeeds_without_touching_anything() {
        let mut nothing: [u8; 0] = [];
        fill(&mut nothing).expect("an empty draw is trivially satisfiable");
    }

    #[test]
    fn integer_draws_differ_between_calls() {
        let first = u128_value().expect("the operating system CSPRNG is available under test");
        let second = u128_value().expect("the operating system CSPRNG is available under test");
        assert_ne!(first, second);
        assert_ne!(first, 0);
    }
}
