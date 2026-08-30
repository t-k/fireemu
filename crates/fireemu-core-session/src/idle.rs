//! Idle fence for `await-idle` (spec 10.5, `INV-IDLE-001`).
//!
//! The ledger tracks every piece of causal work by kind and epoch. Work is registered with
//! [`WorkLedger::begin`] before it becomes observable and released with [`WorkLedger::end`]
//! only after its effects, including child enqueue reservations, are complete. A verdict of
//! `Idle` therefore means no fenced work can still mutate state.

use core::fmt;
use std::collections::BTreeMap;

use fireemu_core_types::ids::Epoch;
use fireemu_core_types::time::LogicalDuration;

/// Kinds of causal work that keep a session busy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WorkKind {
    /// A pending or running Firestore commit.
    FirestoreCommit,
    /// A dispatchable, leased or running event.
    EventDispatch,
    /// An event waiting for its retry timer.
    EventRetryWait,
    /// A running Function invocation.
    FunctionInvocation,
    /// A schedule that is due but not yet enqueued.
    DueSchedule,
    /// A resumable upload being finalized.
    UploadFinalize,
    /// Text Index backfill, delta apply or READY publish.
    TextIndexBuild,
    /// Snapshot, restore or ruleset activation in progress.
    SnapshotRestoreOrRulesetActivation,
    /// A reservation held by a parent between its completion and its child's enqueue.
    ChildEnqueueReservation,
    /// A schedule that is not yet due. Counted only when explicitly requested.
    ScheduledFutureWork,
}

impl WorkKind {
    /// Whether this kind is counted under the given options.
    #[must_use]
    pub const fn is_fenced(self, options: &AwaitIdleOptions) -> bool {
        match self {
            Self::TextIndexBuild => matches!(options.text_index_builds, IdleWaitPolicy::Wait),
            Self::ScheduledFutureWork => options.include_scheduled_future_work,
            _ => true,
        }
    }
}

/// How `await-idle` treats Text Index builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleWaitPolicy {
    /// Wait for builds to reach `READY` or `NEEDS_REPAIR` (default).
    Wait,
    /// Ignore builds; only for tests that inspect build state itself.
    Ignore,
}

/// Options for one `await-idle` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AwaitIdleOptions {
    /// Count schedules that are not yet due.
    pub include_scheduled_future_work: bool,
    /// Text Index build policy.
    pub text_index_builds: IdleWaitPolicy,
    /// Logical timeout.
    pub timeout: LogicalDuration,
}

impl Default for AwaitIdleOptions {
    fn default() -> Self {
        Self {
            include_scheduled_future_work: false,
            text_index_builds: IdleWaitPolicy::Wait,
            timeout: LogicalDuration::from_seconds(30),
        }
    }
}

/// Opaque handle for a registered piece of work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkToken(u64);

/// Ledger errors. None of them change the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleLedgerError {
    /// The token was never issued or was already ended.
    UnknownToken(WorkToken),
    /// Work from another epoch cannot be registered.
    StaleEpoch {
        /// Ledger epoch.
        current: Epoch,
        /// Epoch the work claimed.
        requested: Epoch,
    },
    /// Token space exhausted (practically unreachable).
    TokenExhausted,
    /// `handoff` was given a token that is not a child-enqueue reservation.
    NotAReservation(WorkToken),
    /// `reset` was given an epoch that is not newer than the ledger epoch.
    EpochNotNewer {
        /// Ledger epoch.
        current: Epoch,
        /// Requested epoch.
        requested: Epoch,
    },
}

impl fmt::Display for IdleLedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownToken(t) => write!(f, "unknown or already ended work token {}", t.0),
            Self::StaleEpoch { current, requested } => {
                write!(
                    f,
                    "work for epoch {requested} rejected; ledger epoch is {current}"
                )
            }
            Self::TokenExhausted => f.write_str("work token space exhausted"),
            Self::NotAReservation(t) => {
                write!(f, "work token {} is not a child-enqueue reservation", t.0)
            }
            Self::EpochNotNewer { current, requested } => {
                write!(f, "ledger epoch {requested} is not newer than {current}")
            }
        }
    }
}

impl std::error::Error for IdleLedgerError {}

/// Verdict of an idle check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdleVerdict {
    /// No fenced work is active.
    Idle,
    /// Fenced work is active; counts per kind in canonical order.
    Busy {
        /// Blocking work kinds and their active counts.
        blocking: Vec<(WorkKind, u32)>,
    },
}

/// Active work ledger for one session epoch.
#[derive(Debug, Clone)]
pub struct WorkLedger {
    epoch: Epoch,
    next_token: u64,
    active: BTreeMap<WorkToken, WorkKind>,
}

impl WorkLedger {
    /// Creates an empty ledger for `epoch`.
    #[must_use]
    pub fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            next_token: 1,
            active: BTreeMap::new(),
        }
    }

    /// Ledger epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Registers a piece of work. Must be called before the work becomes observable.
    pub fn begin(&mut self, kind: WorkKind, epoch: Epoch) -> Result<WorkToken, IdleLedgerError> {
        if epoch != self.epoch {
            return Err(IdleLedgerError::StaleEpoch {
                current: self.epoch,
                requested: epoch,
            });
        }
        let token = WorkToken(self.next_token);
        self.next_token = self
            .next_token
            .checked_add(1)
            .ok_or(IdleLedgerError::TokenExhausted)?;
        self.active.insert(token, kind);
        Ok(token)
    }

    /// Releases a piece of work. Ending twice is an error, never an underflow.
    pub fn end(&mut self, token: WorkToken) -> Result<WorkKind, IdleLedgerError> {
        self.active
            .remove(&token)
            .ok_or(IdleLedgerError::UnknownToken(token))
    }

    /// Atomically releases a child-enqueue reservation and registers the child it promised.
    /// This is the only correct way to hand work from a parent to its child: between the two
    /// halves no observer can see the ledger idle (M-IDLE-002).
    pub fn handoff(
        &mut self,
        reservation: WorkToken,
        child: WorkKind,
    ) -> Result<WorkToken, IdleLedgerError> {
        match self.active.get(&reservation) {
            Some(WorkKind::ChildEnqueueReservation) => {}
            Some(_) => return Err(IdleLedgerError::NotAReservation(reservation)),
            None => return Err(IdleLedgerError::UnknownToken(reservation)),
        }
        // Register the child first so that the ledger is never momentarily empty.
        let token = self.begin(child, self.epoch)?;
        self.active.remove(&reservation);
        Ok(token)
    }

    /// Switches to a strictly newer epoch, dropping every registration from the old one.
    /// Old-epoch work is discarded by the epoch guard before it can mutate state, so it no
    /// longer fences; tokens issued before the reset become unknown.
    pub fn reset(&mut self, new_epoch: Epoch) -> Result<(), IdleLedgerError> {
        if new_epoch <= self.epoch {
            return Err(IdleLedgerError::EpochNotNewer {
                current: self.epoch,
                requested: new_epoch,
            });
        }
        self.epoch = new_epoch;
        self.active.clear();
        Ok(())
    }

    /// Total registered work regardless of options.
    #[must_use]
    pub fn active_total(&self) -> usize {
        self.active.len()
    }

    /// Idle verdict under `options`.
    #[must_use]
    pub fn verdict(&self, options: &AwaitIdleOptions) -> IdleVerdict {
        let mut counts: BTreeMap<WorkKind, u32> = BTreeMap::new();
        for kind in self
            .active
            .values()
            .copied()
            .filter(|k| k.is_fenced(options))
        {
            *counts.entry(kind).or_insert(0) += 1;
        }
        if counts.is_empty() {
            IdleVerdict::Idle
        } else {
            IdleVerdict::Busy {
                blocking: counts.into_iter().collect(),
            }
        }
    }
}
