//! Session lifecycle and epoch isolation (spec 7.3, 7.4, ADR-011).
//!
//! ```text
//! Creating -> Active -> Resetting -> Active -> Closing -> Closed
//! ```
//!
//! A reset is an atomic epoch switch, not a synchronous deletion of all data. Work items carry
//! the epoch they were created in; [`Session::check_work_epoch`] is the guard every work item
//! must pass before mutating state (`INV-EPOCH-001`).

use core::fmt;

use ftd_core_types::determinism::DeterministicIdSource;
use ftd_core_types::ids::{Epoch, SessionId};
use ftd_core_types::time::LogicalInstant;

use crate::clock::VirtualClock;

/// Session lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionState {
    /// Being created; not yet accepting work.
    Creating,
    /// Accepting work.
    Active,
    /// Epoch switch in progress; no work is accepted.
    Resetting,
    /// Shutting down; no new work.
    Closing,
    /// Terminal.
    Closed,
}

/// Lifecycle actions, used in error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionAction {
    /// `Creating -> Active`.
    Activate,
    /// `Active -> Resetting` (epoch + 1).
    BeginReset,
    /// `Resetting -> Active`.
    CompleteReset,
    /// `Creating | Active | Resetting -> Closing`.
    BeginClose,
    /// `Closing -> Closed`.
    CompleteClose,
}

/// An invalid lifecycle transition. The session state is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTransitionError {
    /// State the session was in.
    pub from: SessionState,
    /// Action that was attempted.
    pub action: SessionAction,
}

impl fmt::Display for SessionTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cannot {:?} a session in state {:?}",
            self.action, self.from
        )
    }
}

impl std::error::Error for SessionTransitionError {}

/// Result of the epoch guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkResult {
    /// The work item belongs to the current epoch and the session is active.
    Proceed,
    /// The work item belongs to a different epoch and must be dropped without side effects.
    DiscardedStaleEpoch,
    /// The epoch matches but the session is not accepting mutations right now.
    SessionNotActive(SessionState),
}

/// A test session: the unit of isolation.
#[derive(Debug, Clone)]
pub struct Session {
    id: SessionId,
    seed: u64,
    state: SessionState,
    epoch: Epoch,
    clock: VirtualClock,
    ids: DeterministicIdSource,
}

impl Session {
    /// Creates a session in the `Creating` state.
    #[must_use]
    pub fn create(id: SessionId, seed: u64, clock_start: LogicalInstant) -> Self {
        let epoch = Epoch::initial();
        Self {
            id,
            seed,
            state: SessionState::Creating,
            epoch,
            clock: VirtualClock::new(clock_start),
            ids: Self::id_source_for(id, seed, epoch),
        }
    }

    /// Each epoch gets its own ID stream so that a reset never replays IDs from the previous
    /// epoch, while two sessions with the same seed still produce identical streams.
    fn id_source_for(id: SessionId, seed: u64, epoch: Epoch) -> DeterministicIdSource {
        DeterministicIdSource::new(id, seed ^ epoch.value().rotate_left(32))
    }

    /// Session ID.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// Session seed.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Current epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The session clock.
    #[must_use]
    pub const fn clock(&self) -> &VirtualClock {
        &self.clock
    }

    /// Mutable access to the session clock.
    pub fn clock_mut(&mut self) -> &mut VirtualClock {
        &mut self.clock
    }

    /// The session ID source.
    pub fn ids(&mut self) -> &mut DeterministicIdSource {
        &mut self.ids
    }

    fn transition(
        &mut self,
        action: SessionAction,
        allowed_from: &[SessionState],
        to: SessionState,
    ) -> Result<(), SessionTransitionError> {
        if allowed_from.contains(&self.state) {
            self.state = to;
            Ok(())
        } else {
            Err(SessionTransitionError {
                from: self.state,
                action,
            })
        }
    }

    /// `Creating -> Active`.
    pub fn activate(&mut self) -> Result<(), SessionTransitionError> {
        self.transition(
            SessionAction::Activate,
            &[SessionState::Creating],
            SessionState::Active,
        )
    }

    /// `Active -> Resetting`, bumping the epoch. Returns the new epoch. Work from the old epoch
    /// is stale from this point on.
    pub fn begin_reset(&mut self) -> Result<Epoch, SessionTransitionError> {
        if self.state != SessionState::Active {
            return Err(SessionTransitionError {
                from: self.state,
                action: SessionAction::BeginReset,
            });
        }
        // Epoch exhaustion is unreachable in practice (2^64 resets); treat as a transition
        // failure rather than panicking.
        let next = self.epoch.next().ok_or(SessionTransitionError {
            from: self.state,
            action: SessionAction::BeginReset,
        })?;
        self.state = SessionState::Resetting;
        self.epoch = next;
        self.ids = Self::id_source_for(self.id, self.seed, next);
        Ok(next)
    }

    /// `Resetting -> Active`: publishes the new epoch.
    pub fn complete_reset(&mut self) -> Result<(), SessionTransitionError> {
        self.transition(
            SessionAction::CompleteReset,
            &[SessionState::Resetting],
            SessionState::Active,
        )
    }

    /// `Creating | Active | Resetting -> Closing`. A session must always be closable, even
    /// when a reset was started and never completed.
    pub fn begin_close(&mut self) -> Result<(), SessionTransitionError> {
        self.transition(
            SessionAction::BeginClose,
            &[
                SessionState::Creating,
                SessionState::Active,
                SessionState::Resetting,
            ],
            SessionState::Closing,
        )
    }

    /// `Closing -> Closed`.
    pub fn complete_close(&mut self) -> Result<(), SessionTransitionError> {
        self.transition(
            SessionAction::CompleteClose,
            &[SessionState::Closing],
            SessionState::Closed,
        )
    }

    /// Epoch guard for work items (spec 7.4). Must be called immediately before a work item
    /// mutates state.
    #[must_use]
    pub const fn check_work_epoch(&self, work_epoch: Epoch) -> WorkResult {
        if work_epoch.value() != self.epoch.value() {
            return WorkResult::DiscardedStaleEpoch;
        }
        match self.state {
            SessionState::Active => WorkResult::Proceed,
            other => WorkResult::SessionNotActive(other),
        }
    }
}
