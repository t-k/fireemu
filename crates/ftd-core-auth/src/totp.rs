//! HOTP (RFC 4226) and TOTP (RFC 6238) over HMAC-SHA1.

use ftd_core_types::time::LogicalInstant;

use crate::sha1::hmac_sha1;

/// TOTP parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpParams {
    /// Time step in seconds (30 for Firebase).
    pub period_seconds: u32,
    /// Code digits (6 for Firebase; 8 in the RFC test vectors).
    pub digits: u8,
}

/// HOTP value for `counter` with RFC 4226 dynamic truncation.
#[must_use]
pub fn hotp(secret: &[u8], counter: u64, digits: u8) -> u32 {
    let mac = hmac_sha1(secret, &counter.to_be_bytes());
    let offset = usize::from(mac[19] & 0x0F);
    let binary = (u32::from(mac[offset] & 0x7F) << 24)
        | (u32::from(mac[offset + 1]) << 16)
        | (u32::from(mac[offset + 2]) << 8)
        | u32::from(mac[offset + 3]);
    let modulus = 10u32.saturating_pow(u32::from(digits.min(9)));
    binary % modulus
}

/// Time step counter for `at`. Instants before the Unix epoch clamp to step 0.
#[must_use]
pub fn time_step(params: &TotpParams, at: LogicalInstant) -> u64 {
    let seconds = at.as_nanos().div_euclid(1_000_000_000);
    if seconds <= 0 || params.period_seconds == 0 {
        return 0;
    }
    u64::try_from(seconds / i128::from(params.period_seconds)).unwrap_or(u64::MAX)
}

/// TOTP code at `at`.
#[must_use]
pub fn totp_at(secret: &[u8], params: &TotpParams, at: LogicalInstant) -> u32 {
    hotp(secret, time_step(params, at), params.digits)
}
