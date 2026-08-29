//! Virtual clock (spec 11.1, 11.2, ADR-004).
//!
//! The runtime never calls `SystemTime::now()`. Every session owns a `VirtualClock`; wall-clock
//! adapters for the `compat` profile live outside the core.

use ftd_core_types::determinism::Clock;
use ftd_core_types::time::{LogicalDuration, LogicalInstant};

/// Errors from clock manipulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockError {
    /// `advance` was called with a negative duration.
    NegativeDuration,
    /// The resulting instant is not representable.
    Overflow,
    /// The operation would move the clock backwards (INV-TIME-001).
    WouldMoveBackwards {
        /// Current instant.
        current: LogicalInstant,
        /// Requested instant.
        requested: LogicalInstant,
    },
}

impl core::fmt::Display for ClockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NegativeDuration => f.write_str("clock cannot advance by a negative duration"),
            Self::Overflow => f.write_str("clock instant overflow"),
            Self::WouldMoveBackwards { current, requested } => {
                write!(
                    f,
                    "clock would move backwards from {current} to {requested}"
                )
            }
        }
    }
}

impl std::error::Error for ClockError {}

/// A deterministic clock that only moves when told to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualClock {
    now: LogicalInstant,
    backwards_sets: u32,
}

impl VirtualClock {
    /// Creates a clock at `start`.
    #[must_use]
    pub const fn new(start: LogicalInstant) -> Self {
        Self {
            now: start,
            backwards_sets: 0,
        }
    }

    /// Advances by `duration` and returns the new instant.
    pub fn advance(&mut self, duration: LogicalDuration) -> Result<LogicalInstant, ClockError> {
        if duration.as_nanos() < 0 {
            return Err(ClockError::NegativeDuration);
        }
        let next = self.now.checked_add(duration).ok_or(ClockError::Overflow)?;
        self.now = next;
        Ok(next)
    }

    /// Advances to `instant`; rejects going backwards.
    pub fn advance_to(&mut self, instant: LogicalInstant) -> Result<LogicalInstant, ClockError> {
        if instant < self.now {
            return Err(ClockError::WouldMoveBackwards {
                current: self.now,
                requested: instant,
            });
        }
        self.now = instant;
        Ok(instant)
    }

    /// Sets the clock. Equivalent to `advance_to`: the default policy forbids going backwards.
    pub fn set(&mut self, instant: LogicalInstant) -> Result<LogicalInstant, ClockError> {
        self.advance_to(instant)
    }

    /// Sets the clock even if it moves backwards. Only allowed right after session creation
    /// or while idle; the caller is responsible for that check. The event is counted so that
    /// traces can flag it.
    pub fn set_allow_backwards(&mut self, instant: LogicalInstant) {
        if instant < self.now {
            self.backwards_sets = self.backwards_sets.saturating_add(1);
        }
        self.now = instant;
    }

    /// Current instant (same as [`Clock::now`]; convenient where the trait is not imported).
    #[must_use]
    pub const fn now_for_test(&self) -> LogicalInstant {
        self.now
    }

    /// Number of times the clock was explicitly moved backwards.
    #[must_use]
    pub const fn backwards_sets(&self) -> u32 {
        self.backwards_sets
    }

    /// Advances by one nanosecond. Fixture loaders use this so that documents created in
    /// sequence never share a create time unless a test asks for a tie (spec 8.9.10).
    pub fn tick(&mut self) -> Result<LogicalInstant, ClockError> {
        self.advance(LogicalDuration::from_nanos(1))
    }
}

impl Clock for VirtualClock {
    fn now(&self) -> LogicalInstant {
        self.now
    }
}
