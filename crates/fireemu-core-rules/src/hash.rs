//! Digests and encodings exposed by the Rules `hashing` namespace.

use fireemu_core_types::hash::{base64_url_safe, hex_upper};
pub use fireemu_core_types::hash::{crc32c, md5, sha256};

/// CRC-32 (IEEE 802.3, reflected, polynomial `0xEDB88320`).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    const POLYNOMIAL: u32 = 0xedb8_8320;
    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (POLYNOMIAL & mask);
        }
    }
    !crc
}

/// URL-safe base64 with padding (`bytes.toBase64()`).
#[must_use]
pub fn base64(data: &[u8]) -> String {
    base64_url_safe(data)
}

/// Uppercase hex (`bytes.toHexString()`).
#[must_use]
pub fn hex(data: &[u8]) -> String {
    hex_upper(data)
}
