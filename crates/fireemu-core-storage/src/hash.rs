//! Digests and encodings surfaced by Cloud Storage object metadata.

use fireemu_core_types::hash::{base64_standard, hex_lower};
pub use fireemu_core_types::hash::{crc32c, md5, Crc32c, Md5};

/// Standard base64 with padding.
#[must_use]
pub fn base64(data: &[u8]) -> String {
    base64_standard(data)
}

/// Lowercase hexadecimal.
#[must_use]
pub fn hex(data: &[u8]) -> String {
    hex_lower(data)
}
