//! Retry policy with logical-time backoff.

use ftd_core_types::time::LogicalDuration;

/// Bounded retry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts including the first delivery. `1` means no retries.
    pub max_attempts: u32,
    /// Backoff after the first failed attempt.
    pub base_backoff: LogicalDuration,
    /// Upper bound for the backoff.
    pub max_backoff: LogicalDuration,
}

impl RetryPolicy {
    /// Exponential backoff for the failure of `attempt` (1-based): `base * 2^(attempt-1)`,
    /// capped at `max_backoff`. Never overflows.
    #[must_use]
    pub fn backoff_for_attempt(&self, attempt: u32) -> LogicalDuration {
        let base = self.base_backoff.as_nanos().max(0);
        let cap = self.max_backoff.as_nanos().max(0);
        let shift = attempt.saturating_sub(1);
        // 2^shift * base overflows i128 for shift >= 127 regardless of base > 0.
        let scaled = if shift >= 120 {
            None
        } else {
            base.checked_mul(1i128 << shift)
        };
        LogicalDuration::from_nanos(scaled.map_or(cap, |v| v.min(cap)))
    }

    /// Whether another attempt is allowed after `attempt` (1-based) failed.
    #[must_use]
    pub const fn allows_retry_after(&self, attempt: u32) -> bool {
        attempt < self.max_attempts
    }
}
