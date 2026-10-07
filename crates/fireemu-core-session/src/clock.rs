//! Virtual clock (spec 11.1, 11.2, ADR-004).
//!
//! The runtime never calls `SystemTime::now()`. Every session owns a `VirtualClock`; wall-clock
//! adapters for the `compat` profile live outside the core.

use fireemu_core_types::determinism::Clock;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use std::sync::{Arc, Weak};

/// One published clock state; elapsed time counts forward movement only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockSnapshot {
    /// Current wall instant.
    pub instant: LogicalInstant,
    /// Positive nanoseconds consumed since creation within the checked u128 lifetime budget.
    pub elapsed_nanos: u128,
    /// Monotonic publication revision.
    pub revision: u64,
}

/// A nonblocking observer. Callbacks run under the owner's clock lock and must only publish
/// to a mailbox; they must never acquire service locks or invoke application work.
pub type ClockObserver = dyn Fn(ClockSnapshot) + Send + Sync;

/// Errors from clock manipulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockError {
    /// `advance` was called with a negative duration.
    NegativeDuration,
    /// The resulting instant or publication counters are not representable.
    Overflow,
    /// A configured runtime cannot represent the requested instant.
    OutOfRange,
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
            Self::OutOfRange => {
                f.write_str("clock instant is outside the configured runtime range")
            }
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
pub struct VirtualClock {
    now: LogicalInstant,
    backwards_sets: u32,
    elapsed_nanos: u128,
    revision: u64,
    observers: Vec<Weak<ClockObserver>>,
    range: Option<(LogicalInstant, LogicalInstant)>,
}

impl Clone for VirtualClock {
    fn clone(&self) -> Self {
        Self {
            now: self.now,
            backwards_sets: self.backwards_sets,
            elapsed_nanos: self.elapsed_nanos,
            revision: self.revision,
            observers: Vec::new(),
            range: self.range,
        }
    }
}

impl PartialEq for VirtualClock {
    fn eq(&self, other: &Self) -> bool {
        self.now == other.now && self.backwards_sets == other.backwards_sets
    }
}
impl Eq for VirtualClock {}

impl core::fmt::Debug for VirtualClock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VirtualClock")
            .field("now", &self.now)
            .field("backwards_sets", &self.backwards_sets)
            .field("elapsed_nanos", &self.elapsed_nanos)
            .field("revision", &self.revision)
            .field("range", &self.range)
            .finish_non_exhaustive()
    }
}

impl VirtualClock {
    /// Creates a clock at `start`.
    #[must_use]
    pub const fn new(start: LogicalInstant) -> Self {
        Self {
            now: start,
            backwards_sets: 0,
            elapsed_nanos: 0,
            revision: 0,
            observers: Vec::new(),
            range: None,
        }
    }

    /// Advances by `duration` and returns the new instant.
    pub fn advance(&mut self, duration: LogicalDuration) -> Result<LogicalInstant, ClockError> {
        if duration.as_nanos() < 0 {
            return Err(ClockError::NegativeDuration);
        }
        let next = self.now.checked_add(duration).ok_or(ClockError::Overflow)?;
        self.validate_target(next)?;
        self.publish(next);
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
        self.validate_target(instant)?;
        self.publish(instant);
        Ok(instant)
    }

    /// Sets the clock. Equivalent to `advance_to`: the default policy forbids going backwards.
    pub fn set(&mut self, instant: LogicalInstant) -> Result<LogicalInstant, ClockError> {
        self.advance_to(instant)
    }

    /// Sets the clock even if it moves backwards. Only allowed right after session creation
    /// or while idle; the caller is responsible for that check. The event is counted so that
    /// traces can flag it. A configured runtime range is still enforced; use
    /// `try_set_allow_backwards` to observe rejection.
    pub fn set_allow_backwards(&mut self, instant: LogicalInstant) {
        let _ = self.try_set_allow_backwards(instant);
    }

    /// Checked rewind for clocks with configured runtime representation bounds.
    pub fn try_set_allow_backwards(&mut self, instant: LogicalInstant) -> Result<(), ClockError> {
        self.validate_target(instant)?;
        if instant < self.now {
            self.backwards_sets = self.backwards_sets.saturating_add(1);
        }
        self.publish(instant);
        Ok(())
    }

    /// Restrict every writer, including fault delays and fixture ticks, to a runtime range.
    pub fn restrict_range(
        &mut self,
        minimum: LogicalInstant,
        maximum: LogicalInstant,
    ) -> Result<(), ClockError> {
        let (minimum, maximum) = self.range.map_or((minimum, maximum), |(low, high)| {
            (low.max(minimum), high.min(maximum))
        });
        if minimum > maximum || self.now < minimum || self.now > maximum {
            return Err(ClockError::OutOfRange);
        }
        self.range = Some((minimum, maximum));
        Ok(())
    }

    /// Validate without changing the wall, elapsed, revision or observer state.
    pub fn validate_target(&self, instant: LogicalInstant) -> Result<(), ClockError> {
        if self.revision == u64::MAX
            || (instant > self.now
                && self
                    .elapsed_nanos
                    .checked_add(instant.as_nanos().abs_diff(self.now.as_nanos()))
                    .is_none())
        {
            return Err(ClockError::Overflow);
        }
        if self
            .range
            .is_some_and(|(minimum, maximum)| instant < minimum || instant > maximum)
        {
            return Err(ClockError::OutOfRange);
        }
        Ok(())
    }

    /// Adds a weak observer and immediately publishes the initial state to it.
    pub fn observe(&mut self, observer: &Arc<ClockObserver>) {
        self.observers.push(Arc::downgrade(observer));
        observer(self.snapshot());
    }

    /// Current instant and monotonic timer/revision axes.
    #[must_use]
    pub const fn snapshot(&self) -> ClockSnapshot {
        ClockSnapshot {
            instant: self.now,
            elapsed_nanos: self.elapsed_nanos,
            revision: self.revision,
        }
    }

    fn publish(&mut self, instant: LogicalInstant) {
        if instant > self.now {
            self.elapsed_nanos = self
                .elapsed_nanos
                .saturating_add(instant.as_nanos().abs_diff(self.now.as_nanos()));
        }
        self.now = instant;
        self.revision = self.revision.saturating_add(1);
        let snapshot = self.snapshot();
        self.observers.retain(|weak| {
            let Some(observer) = weak.upgrade() else {
                return false;
            };
            observer(snapshot);
            true
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_budget_exhaustion_rejects_without_mutating_any_clock_axis() {
        let mut clock = VirtualClock::new(LogicalInstant::UNIX_EPOCH);
        clock.revision = u64::MAX;
        let before = clock.snapshot();
        assert_eq!(clock.tick(), Err(ClockError::Overflow));
        assert_eq!(clock.snapshot(), before);
        assert_eq!(
            clock.try_set_allow_backwards(LogicalInstant::from_nanos(-1)),
            Err(ClockError::Overflow)
        );
        assert_eq!(clock.backwards_sets(), 0);
        assert_eq!(clock.snapshot(), before);

        clock.revision = 0;
        clock.elapsed_nanos = u128::MAX - 1;
        let before = clock.snapshot();
        assert_eq!(
            clock.advance(LogicalDuration::from_nanos(2)),
            Err(ClockError::Overflow)
        );
        assert_eq!(clock.snapshot(), before);
        clock.tick().unwrap();
        assert_eq!(clock.snapshot().elapsed_nanos, u128::MAX);
        assert_eq!(clock.tick(), Err(ClockError::Overflow));
        // Rewinds and equal instants consume no elapsed budget.
        clock
            .try_set_allow_backwards(LogicalInstant::UNIX_EPOCH)
            .unwrap();
        clock.advance(LogicalDuration::ZERO).unwrap();
    }
}
