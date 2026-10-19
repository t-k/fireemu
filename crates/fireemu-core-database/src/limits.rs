//! Size and depth limits of written data.

/// The limits a write is checked against.
///
/// [`Limits::default`] holds the values production documents in "Realtime Database
/// limits": a key is at most 768 bytes, data nests at most 32 levels, and a string value is
/// at most 10 MiB. The adapters pick the limits per profile so the emulator profile never
/// refuses what the official emulator accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The maximum number of keys from the root to the deepest written value.
    pub max_depth: usize,
    /// The maximum UTF-8 length of one key.
    pub max_key_bytes: usize,
    /// The maximum UTF-8 length of one string value.
    pub max_string_bytes: usize,
}

impl Limits {
    /// The limits production documents.
    pub const PRODUCTION: Self = Self {
        max_depth: 32,
        max_key_bytes: 768,
        max_string_bytes: 10 * 1024 * 1024,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::PRODUCTION
    }
}
