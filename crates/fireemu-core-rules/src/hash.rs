//! Digests and encodings exposed by the Rules `hashing` namespace.

use fireemu_core_types::hash::{base64_url_safe, hex_upper};
pub use fireemu_core_types::hash::{crc32c, md5, sha256};

// Each entry advances one byte through the reflected IEEE polynomial.
const CRC32_TABLE: [u32; 256] = {
    let mut table = [0; 256];
    let mut index = 0u32;
    while index < 256 {
        let mut crc = index;
        let mut bit = 0;
        while bit < 8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (crc & 1).wrapping_neg());
            bit += 1;
        }
        table[index as usize] = crc;
        index += 1;
    }
    table
};

/// CRC-32 (IEEE 802.3, reflected, polynomial `0xEDB88320`).
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        crc = (crc >> 8) ^ CRC32_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize];
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
