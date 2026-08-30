//! Retry policy with logical-time backoff.

use fireemu_core_types::time::LogicalDuration;

/// Bounded retry policy. Built through [`RetryPolicy::try_new`] so that `max_attempts >= 1`
/// and the backoffs are non-negative with `base_backoff <= max_backoff` always hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_attempts: u32,
    base_backoff: LogicalDuration,
    max_backoff: LogicalDuration,
}

/// Invalid retry policy parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryPolicyError {
    /// `max_attempts` was 0; at least the first delivery attempt must be allowed.
    ZeroAttempts,
    /// A backoff was negative.
    NegativeBackoff,
    /// `base_backoff` exceeds `max_backoff`.
    BaseExceedsMax,
}

impl core::fmt::Display for RetryPolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ZeroAttempts => f.write_str("max_attempts must be at least 1"),
            Self::NegativeBackoff => f.write_str("backoff durations must not be negative"),
            Self::BaseExceedsMax => f.write_str("base_backoff must not exceed max_backoff"),
        }
    }
}

impl std::error::Error for RetryPolicyError {}

impl RetryPolicy {
    /// Validates and builds a policy. `max_attempts` counts the first delivery, so `1` means
    /// no retries.
    pub fn try_new(
        max_attempts: u32,
        base_backoff: LogicalDuration,
        max_backoff: LogicalDuration,
    ) -> Result<Self, RetryPolicyError> {
        if max_attempts == 0 {
            return Err(RetryPolicyError::ZeroAttempts);
        }
        if base_backoff.as_nanos() < 0 || max_backoff.as_nanos() < 0 {
            return Err(RetryPolicyError::NegativeBackoff);
        }
        if base_backoff > max_backoff {
            return Err(RetryPolicyError::BaseExceedsMax);
        }
        Ok(Self {
            max_attempts,
            base_backoff,
            max_backoff,
        })
    }

    /// Total attempts including the first delivery.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// Backoff after the first failed attempt.
    #[must_use]
    pub const fn base_backoff(&self) -> LogicalDuration {
        self.base_backoff
    }

    /// Upper bound for the backoff.
    #[must_use]
    pub const fn max_backoff(&self) -> LogicalDuration {
        self.max_backoff
    }

    /// Exponential backoff for the failure of `attempt` (1-based): `base * 2^(attempt-1)`,
    /// capped at `max_backoff`. Never overflows.
    #[must_use]
    pub fn backoff_for_attempt(&self, attempt: u32) -> LogicalDuration {
        let base = self.base_backoff.as_nanos();
        let cap = self.max_backoff.as_nanos();
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
