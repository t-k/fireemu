//! Retry policy with logical-time backoff.

use fireemu_core_types::time::LogicalDuration;

/// Bounded retry policy. Built through [`RetryPolicy::try_new`] so that `max_attempts >= 1`
/// and the backoffs are non-negative with `base_backoff <= max_backoff` always hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    max_attempts: u32,
    base_backoff: LogicalDuration,
    max_backoff: LogicalDuration,
    max_doublings: Option<u32>,
    max_retry_duration: Option<LogicalDuration>,
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
            max_doublings: None,
            max_retry_duration: None,
        })
    }

    /// Builds a policy with Cloud Scheduler's bounded exponential phase and retry window.
    pub fn try_with_limits(
        max_attempts: u32,
        base_backoff: LogicalDuration,
        max_backoff: LogicalDuration,
        max_doublings: u32,
        max_retry_duration: Option<LogicalDuration>,
    ) -> Result<Self, RetryPolicyError> {
        if max_retry_duration.is_some_and(|duration| duration.as_nanos() < 0) {
            return Err(RetryPolicyError::NegativeBackoff);
        }
        let mut policy = Self::try_new(max_attempts, base_backoff, max_backoff)?;
        policy.max_doublings = Some(max_doublings);
        policy.max_retry_duration = max_retry_duration;
        Ok(policy)
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
        let doublings = self.max_doublings.map_or(shift, |limit| shift.min(limit));
        // 2^shift * base overflows i128 for large shifts regardless of base > 0.
        let exponential = (doublings < 120)
            .then(|| base.checked_mul(1i128 << doublings))
            .flatten();
        let linear_steps = shift.saturating_sub(doublings);
        let scaled = exponential
            .and_then(|unit| unit.checked_mul(i128::from(linear_steps).saturating_add(1)));
        LogicalDuration::from_nanos(scaled.map_or(cap, |v| v.min(cap)))
    }

    /// Whether another attempt is allowed after `attempt` (1-based) failed.
    #[must_use]
    pub const fn allows_retry_after(&self, attempt: u32) -> bool {
        attempt < self.max_attempts
    }

    /// Whether the retry after `attempt` fits both the attempt and elapsed-time limits.
    #[must_use]
    pub fn allows_retry_after_elapsed(&self, attempt: u32, elapsed: LogicalDuration) -> bool {
        if !self.allows_retry_after(attempt) {
            return false;
        }
        self.max_retry_duration.is_none_or(|limit| {
            elapsed
                .checked_add(self.backoff_for_attempt(attempt))
                .is_some_and(|next| next <= limit)
        })
    }
}
