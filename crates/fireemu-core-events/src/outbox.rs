//! Outbox: the set of event records for a session (spec 8.3, 10.3).
//!
//! The atomic "documents + outbox" publication belongs to the Firestore / Storage commit path;
//! this type provides the deterministic container those paths append to and workers drain.
//!
//! Records are indexed by delivery state, so dispatch and the retry sweep visit the active
//! work rather than every event the session has ever produced, and terminal records are kept
//! only up to a bounded retention window: a long-running session's cost depends on what is
//! outstanding, not on what has already finished.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fireemu_core_types::ids::{Epoch, EventId};
use fireemu_core_types::time::LogicalInstant;

use crate::event::LogicalEvent;
use crate::state::{EventRecord, EventState};

/// How many terminal records an outbox keeps before the oldest ones are dropped. Terminal
/// records are diagnostic only: dispatch, retries and the idle fence read the active ones.
pub const DEFAULT_TERMINAL_RETENTION: usize = 1000;

/// Outbox errors. The outbox is unchanged when an error is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxError {
    /// An event with this ID is already present.
    DuplicateEventId(EventId),
    /// No event with this ID.
    UnknownEventId(EventId),
}

impl fmt::Display for OutboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateEventId(id) => write!(f, "duplicate event id {id}"),
            Self::UnknownEventId(id) => write!(f, "unknown event id {id}"),
        }
    }
}

impl std::error::Error for OutboxError {}

/// Deterministic event container.
#[derive(Debug, Clone)]
pub struct Outbox {
    records: BTreeMap<EventId, EventRecord>,
    /// Pending records in canonical dispatch order: logical time, then event ID.
    pending: BTreeSet<(LogicalInstant, EventId)>,
    /// Retry-waiting records ordered by the instant their timer elapses.
    retrying: BTreeSet<(LogicalInstant, EventId)>,
    /// Reverse lookup used to remove a record from `retrying` after its state changes.
    retry_at_by_id: BTreeMap<EventId, LogicalInstant>,
    /// Records that are not terminal, whatever their state.
    active: BTreeSet<EventId>,
    /// Terminal records in the order they became terminal: the eviction order.
    terminal: VecDeque<EventId>,
    terminal_retention: usize,
    evicted: u64,
}

impl Default for Outbox {
    fn default() -> Self {
        Self::with_terminal_retention(DEFAULT_TERMINAL_RETENTION)
    }
}

impl Outbox {
    /// Empty outbox with the default terminal retention.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty outbox keeping `retention` terminal records (at least one).
    #[must_use]
    pub fn with_terminal_retention(retention: usize) -> Self {
        Self {
            records: BTreeMap::new(),
            pending: BTreeSet::new(),
            retrying: BTreeSet::new(),
            retry_at_by_id: BTreeMap::new(),
            active: BTreeSet::new(),
            terminal: VecDeque::new(),
            terminal_retention: retention.max(1),
            evicted: 0,
        }
    }

    /// How many terminal records this outbox keeps.
    #[must_use]
    pub fn terminal_retention(&self) -> usize {
        self.terminal_retention
    }

    /// How many terminal records have been dropped to stay inside the retention window.
    #[must_use]
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Number of retained records, terminal ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the outbox holds no retained record.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// How many records one dispatch pass visits. It follows the pending work, not the number
    /// of events the session has completed; tests hold that bound.
    #[must_use]
    pub fn dispatch_visits(&self) -> usize {
        self.pending.len()
    }

    /// Appends a pending event.
    pub fn enqueue(&mut self, event: LogicalEvent) -> Result<(), OutboxError> {
        let id = event.event_id;
        if self.records.contains_key(&id) {
            return Err(OutboxError::DuplicateEventId(id));
        }
        self.records.insert(id, EventRecord::new(event));
        self.reindex(id);
        Ok(())
    }

    /// Record by ID, while it is inside the retention window.
    #[must_use]
    pub fn record(&self, id: EventId) -> Option<&EventRecord> {
        self.records.get(&id)
    }

    /// Applies `f` to the record and re-indexes it by the state `f` left it in. The closure
    /// keeps the mutation and the indexing in one step, so no caller can move a record between
    /// states behind the outbox's back.
    pub fn update<R>(
        &mut self,
        id: EventId,
        f: impl FnOnce(&mut EventRecord) -> R,
    ) -> Result<R, OutboxError> {
        let record = self
            .records
            .get_mut(&id)
            .ok_or(OutboxError::UnknownEventId(id))?;
        let out = f(record);
        self.reindex(id);
        Ok(out)
    }

    /// Puts the record back in the index its current state belongs to, evicting the oldest
    /// terminal records when it just became terminal.
    fn reindex(&mut self, id: EventId) {
        let Some(record) = self.records.get(&id) else {
            return;
        };
        // The logical time never changes, so the pending key is always removable.
        let key = (record.event().logical_time, id);
        let state = record.state().clone();
        self.pending.remove(&key);
        if let Some(retry_at) = self.retry_at_by_id.remove(&id) {
            self.retrying.remove(&(retry_at, id));
        }
        match state {
            EventState::Pending => {
                self.pending.insert(key);
                self.active.insert(id);
            }
            EventState::Leased | EventState::Running => {
                self.active.insert(id);
            }
            EventState::RetryWaiting { retry_at } => {
                self.retrying.insert((retry_at, id));
                self.retry_at_by_id.insert(id, retry_at);
                self.active.insert(id);
            }
            EventState::Succeeded
            | EventState::DeadLettered { .. }
            | EventState::Cancelled
            | EventState::DiscardedStaleEpoch => {
                // Every record starts pending, so `active` holds it exactly until the one
                // transition that retires it: the eviction queue never sees a duplicate.
                if self.active.remove(&id) {
                    self.terminal.push_back(id);
                    self.evict();
                }
            }
        }
    }

    /// Drops the oldest terminal records beyond the retention window.
    fn evict(&mut self) {
        while self.terminal.len() > self.terminal_retention {
            if let Some(oldest) = self.terminal.pop_front() {
                self.records.remove(&oldest);
                self.evicted += 1;
            }
        }
    }

    /// Pending events in canonical dispatch order: logical time, then event ID.
    pub fn dispatchable(&self) -> impl Iterator<Item = &LogicalEvent> {
        self.pending
            .iter()
            .filter_map(|(_, id)| self.records.get(id).map(EventRecord::event))
    }

    /// Retry-waiting events whose timer has elapsed at `now`, in canonical order.
    #[must_use]
    pub fn retries_due(&self, now: LogicalInstant) -> Vec<EventId> {
        self.retrying
            .range(..=(now, EventId::new(u128::MAX)))
            .map(|(_, id)| *id)
            .collect()
    }

    /// Number of retry-index entries visited by a due sweep at `now`.
    #[must_use]
    pub fn retry_sweep_visits(&self, now: LogicalInstant) -> usize {
        self.retrying
            .range(..=(now, EventId::new(u128::MAX)))
            .count()
    }

    /// Marks every non-terminal record from an epoch older than `current_epoch` as
    /// `DiscardedStaleEpoch`. Returns the number of records discarded.
    pub fn discard_stale(&mut self, current_epoch: Epoch) -> usize {
        let mut discarded = 0;
        for id in self.active.iter().copied().collect::<Vec<_>>() {
            let done = self
                .update(id, |r| r.discard_stale(current_epoch).is_ok())
                .unwrap_or(false);
            if done {
                discarded += 1;
            }
        }
        discarded
    }

    /// Whether any record is non-terminal. Used by the idle fence cross-check.
    #[must_use]
    pub fn has_active(&self) -> bool {
        !self.active.is_empty()
    }
}
