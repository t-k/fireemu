//! Virtual clock (spec 11.1, 11.2, ADR-004).
//!
//! The runtime never calls `SystemTime::now()`. Every session owns a `VirtualClock`; wall-clock
//! adapters for the `compat` profile live outside the core. A clock made with
//! [`VirtualClock::following_with`] counts the time a source reports since its last move, so it
//! runs at the pace of real time without the core ever reading the wall clock: the daemon passes
//! a wall-clock source, and [`VirtualClock::following`] a monotonic one.

use fireemu_core_types::determinism::Clock;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use std::sync::{Arc, Weak};
use std::time::Instant;

/// A reading of real time in nanoseconds, from any origin. Only differences are used.
pub type TimeSource = Arc<dyn Fn() -> i128 + Send + Sync>;

/// What a clock that follows real time counts: a source and its reading at the last move.
#[derive(Clone)]
struct Follow {
    source: TimeSource,
    at: i128,
    /// The most drift any read has reported since the last move, so that a source that steps
    /// back holds the clock where it was instead of taking it back.
    peak: std::cell::Cell<i128>,
}

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

/// A deterministic clock that only moves when told to, or that runs on from its last move at
/// the pace of real time ([`VirtualClock::following`]).
pub struct VirtualClock {
    now: LogicalInstant,
    /// The real-time source and its reading when `now` was published, for a clock that follows
    /// real time.
    follow: Option<Follow>,
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
            follow: self.follow.clone(),
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
            follow: None,
            backwards_sets: 0,
            elapsed_nanos: 0,
            revision: 0,
            observers: Vec::new(),
            range: None,
        }
    }

    /// Creates a clock at `start` that keeps running at the pace of real time, measured by the
    /// monotonic clock. A move by hand (`advance`, `advance_to`, a set) is an offset on top:
    /// the clock runs on from where it lands.
    #[must_use]
    pub fn following(start: LogicalInstant) -> Self {
        Self::following_since(start, Instant::now())
    }

    /// [`Self::following`] for a clock that was at `start` when the monotonic clock read
    /// `since` (a clock that has already run for a while).
    #[must_use]
    pub fn following_since(start: LogicalInstant, since: Instant) -> Self {
        let source: TimeSource =
            Arc::new(move || i128::try_from(since.elapsed().as_nanos()).unwrap_or(i128::MAX));
        Self::following_with(start, source, 0)
    }

    /// A clock at `start` that runs with `source`, which read `reading` when the clock was at
    /// `start`. A source that steps back holds the clock until it catches up.
    #[must_use]
    pub fn following_with(start: LogicalInstant, source: TimeSource, reading: i128) -> Self {
        let mut clock = Self::new(start);
        clock.follow = Some(Follow {
            source,
            at: reading,
            peak: std::cell::Cell::new(0),
        });
        clock
    }

    /// Whether the clock runs with real time.
    #[must_use]
    pub const fn is_following(&self) -> bool {
        self.follow.is_some()
    }

    /// Nanoseconds the clock has run since its last move (zero for a frozen clock).
    fn drift_nanos(&self) -> i128 {
        self.follow.as_ref().map_or(0, |follow| {
            let drift = ((follow.source)() - follow.at).max(follow.peak.get());
            follow.peak.set(drift);
            drift
        })
    }

    /// The instant now: the last move plus the real time that has passed since.
    fn live(&self) -> LogicalInstant {
        self.instant_after(self.drift_nanos())
    }

    /// The last move plus `drift` nanoseconds.
    fn instant_after(&self, drift: i128) -> LogicalInstant {
        if drift == 0 {
            return self.now;
        }
        self.now
            .checked_add(LogicalDuration::from_nanos(drift))
            .unwrap_or(self.now)
    }

    /// Publishes the running time to the observers when a following clock has moved since its
    /// last publication, so a schedule or a waiting task notices that time has passed.
    /// Returns whether anything was published; a frozen clock has nothing to publish.
    pub fn sync(&mut self) -> bool {
        if self.follow.is_none() {
            return false;
        }
        let live = self.live();
        if live <= self.now || self.validate_target(live).is_err() {
            return false;
        }
        self.publish(live);
        true
    }

    /// Advances by `duration` and returns the new instant.
    pub fn advance(&mut self, duration: LogicalDuration) -> Result<LogicalInstant, ClockError> {
        if duration.as_nanos() < 0 {
            return Err(ClockError::NegativeDuration);
        }
        let next = self
            .live()
            .checked_add(duration)
            .ok_or(ClockError::Overflow)?;
        self.validate_target(next)?;
        self.publish(next);
        Ok(next)
    }

    /// Advances to `instant`; rejects going backwards.
    pub fn advance_to(&mut self, instant: LogicalInstant) -> Result<LogicalInstant, ClockError> {
        let current = self.live();
        if instant < current {
            return Err(ClockError::WouldMoveBackwards {
                current,
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
        if instant < self.live() {
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
        let now = self.live();
        if minimum > maximum || now < minimum || now > maximum {
            return Err(ClockError::OutOfRange);
        }
        self.range = Some((minimum, maximum));
        Ok(())
    }

    /// Validate without changing the wall, elapsed, revision or observer state.
    pub fn validate_target(&self, instant: LogicalInstant) -> Result<(), ClockError> {
        let drift = self.drift_nanos();
        let now = self.instant_after(drift);
        if self.revision == u64::MAX
            || (instant > now
                && self
                    .elapsed_nanos
                    .saturating_add(drift.unsigned_abs())
                    .checked_add(instant.as_nanos().abs_diff(now.as_nanos()))
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
    pub fn snapshot(&self) -> ClockSnapshot {
        let drift = self.drift_nanos();
        ClockSnapshot {
            instant: self.instant_after(drift),
            elapsed_nanos: self.elapsed_nanos.saturating_add(drift.unsigned_abs()),
            revision: self.revision,
        }
    }

    fn publish(&mut self, instant: LogicalInstant) {
        // Fold in the time that has passed since the last move, then the move itself.
        let drift = self.drift_nanos();
        let live = self.instant_after(drift);
        self.elapsed_nanos = self.elapsed_nanos.saturating_add(drift.unsigned_abs());
        if instant > live {
            self.elapsed_nanos = self
                .elapsed_nanos
                .saturating_add(instant.as_nanos().abs_diff(live.as_nanos()));
        }
        self.now = instant;
        if let Some(follow) = &mut self.follow {
            // The drift just folded in is not counted again.
            follow.at += drift;
            follow.peak.set(0);
        }
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
    pub fn now_for_test(&self) -> LogicalInstant {
        self.live()
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
        self.live()
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
