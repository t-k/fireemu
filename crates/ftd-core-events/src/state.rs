//! Event state machine (spec 10.2).
//!
//! ```text
//! Pending -> Leased -> Running -> Succeeded
//!    |          |         |-> RetryWaiting -> Pending
//!    |          |         |-> DeadLettered
//!    |          |         `-> Cancelled
//!    `----------+-----------> DiscardedStaleEpoch
//! ```
//!
//! Terminal states (`Succeeded`, `DeadLettered`, `Cancelled`, `DiscardedStaleEpoch`) never
//! regress (`INV-EVENT-001`).

use core::fmt;

use ftd_core_types::ids::Epoch;
use ftd_core_types::time::LogicalInstant;

use crate::event::LogicalEvent;
use crate::retry::RetryPolicy;

/// Delivery state of an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventState {
    /// Dispatchable.
    Pending,
    /// Claimed by a worker, not yet running.
    Leased,
    /// Handler running.
    Running,
    /// Delivered successfully. Terminal.
    Succeeded,
    /// Failed; waiting for the retry timer.
    RetryWaiting {
        /// Instant at which the event becomes pending again.
        retry_at: LogicalInstant,
    },
    /// Retries exhausted. Terminal.
    DeadLettered {
        /// Attempts made.
        attempts: u32,
    },
    /// Cancelled by policy or session close. Terminal.
    Cancelled,
    /// Belonged to an older epoch. Terminal.
    DiscardedStaleEpoch,
}

impl EventState {
    /// Whether the state is terminal.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::DeadLettered { .. }
                | Self::Cancelled
                | Self::DiscardedStaleEpoch
        )
    }

    /// Stable name for traces.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Leased => "Leased",
            Self::Running => "Running",
            Self::Succeeded => "Succeeded",
            Self::RetryWaiting { .. } => "RetryWaiting",
            Self::DeadLettered { .. } => "DeadLettered",
            Self::Cancelled => "Cancelled",
            Self::DiscardedStaleEpoch => "DiscardedStaleEpoch",
        }
    }
}

/// Transition errors. The record is unchanged when an error is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventTransitionError {
    /// The event is in a terminal state.
    Terminal {
        /// Current state name.
        state: &'static str,
    },
    /// The transition is not allowed from the current state.
    InvalidTransition {
        /// Current state name.
        from: &'static str,
        /// Attempted action.
        action: &'static str,
    },
    /// `retry_due` was called before the retry instant.
    RetryNotDue,
    /// `discard_stale` was called with the event's own (or an older) epoch.
    EpochIsCurrent,
    /// Attempt counter overflow.
    AttemptOverflow,
    /// The retry instant is not representable in logical time.
    RetryInstantOverflow,
}

impl fmt::Display for EventTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminal { state } => write!(f, "event is terminal ({state})"),
            Self::InvalidTransition { from, action } => {
                write!(f, "cannot {action} an event in state {from}")
            }
            Self::RetryNotDue => f.write_str("retry is not due yet"),
            Self::EpochIsCurrent => f.write_str("event epoch is not older than the given epoch"),
            Self::AttemptOverflow => f.write_str("attempt counter overflow"),
            Self::RetryInstantOverflow => f.write_str("retry instant overflows logical time"),
        }
    }
}

impl std::error::Error for EventTransitionError {}

/// Outcome of a failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureOutcome {
    /// A retry was scheduled.
    RetryScheduled {
        /// When the retry becomes pending.
        retry_at: LogicalInstant,
    },
    /// Retries exhausted.
    DeadLettered,
}

/// An event together with its delivery state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    event: LogicalEvent,
    state: EventState,
    attempt: u32,
}

impl EventRecord {
    /// Wraps a freshly created event in the `Pending` state.
    #[must_use]
    pub const fn new(event: LogicalEvent) -> Self {
        Self {
            event,
            state: EventState::Pending,
            attempt: 0,
        }
    }

    /// The event.
    #[must_use]
    pub const fn event(&self) -> &LogicalEvent {
        &self.event
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> &EventState {
        &self.state
    }

    /// Number of attempts started so far.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    /// Whether the event is terminal.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    fn guard(&self, action: &'static str, allowed: bool) -> Result<(), EventTransitionError> {
        if self.state.is_terminal() {
            return Err(EventTransitionError::Terminal {
                state: self.state.name(),
            });
        }
        if !allowed {
            return Err(EventTransitionError::InvalidTransition {
                from: self.state.name(),
                action,
            });
        }
        Ok(())
    }

    /// `Pending -> Leased`.
    pub fn lease(&mut self) -> Result<(), EventTransitionError> {
        self.guard("lease", matches!(self.state, EventState::Pending))?;
        self.state = EventState::Leased;
        Ok(())
    }

    /// `Leased -> Running`, starting a new attempt.
    pub fn start(&mut self) -> Result<(), EventTransitionError> {
        self.guard("start", matches!(self.state, EventState::Leased))?;
        self.attempt = self
            .attempt
            .checked_add(1)
            .ok_or(EventTransitionError::AttemptOverflow)?;
        self.state = EventState::Running;
        Ok(())
    }

    /// `Running -> Succeeded`.
    pub fn succeed(&mut self) -> Result<(), EventTransitionError> {
        self.guard("succeed", matches!(self.state, EventState::Running))?;
        self.state = EventState::Succeeded;
        Ok(())
    }

    /// `Running -> RetryWaiting | DeadLettered` according to `policy`.
    pub fn fail(
        &mut self,
        policy: &RetryPolicy,
        now: LogicalInstant,
    ) -> Result<FailureOutcome, EventTransitionError> {
        self.guard("fail", matches!(self.state, EventState::Running))?;
        if policy.allows_retry_after(self.attempt) {
            let retry_at = now
                .checked_add(policy.backoff_for_attempt(self.attempt))
                .ok_or(EventTransitionError::RetryInstantOverflow)?;
            self.state = EventState::RetryWaiting { retry_at };
            Ok(FailureOutcome::RetryScheduled { retry_at })
        } else {
            self.state = EventState::DeadLettered {
                attempts: self.attempt,
            };
            Ok(FailureOutcome::DeadLettered)
        }
    }

    /// `Running -> Pending` when the delivery infrastructure failed before the handler
    /// could run to completion (runner death): the attempt is given back, so it is not
    /// charged against the retry policy.
    pub fn interrupt(&mut self) -> Result<(), EventTransitionError> {
        self.guard("interrupt", matches!(self.state, EventState::Running))?;
        self.attempt = self.attempt.saturating_sub(1);
        self.state = EventState::Pending;
        Ok(())
    }

    /// `RetryWaiting -> Pending` once `now >= retry_at`.
    pub fn retry_due(&mut self, now: LogicalInstant) -> Result<(), EventTransitionError> {
        self.guard(
            "retry",
            matches!(self.state, EventState::RetryWaiting { .. }),
        )?;
        if let EventState::RetryWaiting { retry_at } = self.state {
            if now < retry_at {
                return Err(EventTransitionError::RetryNotDue);
            }
        }
        self.state = EventState::Pending;
        Ok(())
    }

    /// Any non-terminal state `-> Cancelled`.
    pub fn cancel(&mut self) -> Result<(), EventTransitionError> {
        self.guard("cancel", true)?;
        self.state = EventState::Cancelled;
        Ok(())
    }

    /// Any non-terminal state `-> DiscardedStaleEpoch` when `current_epoch` is newer than the
    /// event's epoch.
    pub fn discard_stale(&mut self, current_epoch: Epoch) -> Result<(), EventTransitionError> {
        self.guard("discard", true)?;
        if self.event.epoch >= current_epoch {
            return Err(EventTransitionError::EpochIsCurrent);
        }
        self.state = EventState::DiscardedStaleEpoch;
        Ok(())
    }
}
