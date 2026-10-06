//! Retry policy with logical-time backoff.

use fireemu_core_types::time::LogicalDuration;

/// The growth of the gap per step after the doublings: 2 s (see [`RetryPolicy::backoff_for_attempt`]).
const LINEAR_STEP_NANOS: i128 = 2_000_000_000;

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

    /// Backoff for the failure of `attempt` (1-based): `base * 2^(attempt-1)` for the first `max_doublings` steps (every
    /// step when there is no limit), then 2 s more per step, capped at `max_backoff`. The linear step is the one
    /// Cloud Scheduler showed: 2 s in every parameter set of run `ecef353d18975246` (minimum 4 s with one doubling: 4, 8,
    /// 10, 12, 14; minimum 2 s with three: 2, 4, 8, 16, 18; minimum 4 s with two: 4, 8, 16, 18), not `base * 2^doublings`
    /// as its documentation says. Never overflows.
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
        let scaled = exponential.and_then(|unit| {
            unit.checked_add(LINEAR_STEP_NANOS.saturating_mul(i128::from(linear_steps)))
        });
        LogicalDuration::from_nanos(scaled.map_or(cap, |v| v.min(cap)))
    }

    /// Whether another attempt is allowed after `attempt` (1-based) failed.
    #[must_use]
    pub const fn allows_retry_after(&self, attempt: u32) -> bool {
        attempt < self.max_attempts
    }

    /// Whether a retry follows the failure of `attempt` (1-based) at `elapsed` after the first attempt. With only an
    /// attempt limit it is [`Self::allows_retry_after`]; with only a window, the next attempt must fit it. With both
    /// the chain goes on until **both** are used up: it continues while the attempt limit has retries left, and after
    /// that while the next attempt still fits the window. Cloud Scheduler retried a job with a count of 3 and a window of
    /// 20 s four times, the fourth past the window (run `f123d4fa2d61c5f5`), as its documentation says: "the job will be
    /// retried until both limits are reached".
    #[must_use]
    pub fn allows_retry_after_elapsed(&self, attempt: u32, elapsed: LogicalDuration) -> bool {
        if self.allows_retry_after(attempt) {
            return true;
        }
        self.max_retry_duration.is_some_and(|limit| {
            elapsed
                .checked_add(self.backoff_for_attempt(attempt))
                .is_some_and(|next| next <= limit)
        })
    }
}
