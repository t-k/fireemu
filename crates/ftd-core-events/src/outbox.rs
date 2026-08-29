//! Outbox: the set of event records for a session (spec 8.3, 10.3).
//!
//! The atomic "documents + outbox" publication belongs to the Firestore / Storage commit path;
//! this type provides the deterministic container those paths append to and workers drain.

use core::fmt;
use std::collections::BTreeMap;

use ftd_core_types::ids::{Epoch, EventId};
use ftd_core_types::time::LogicalInstant;

use crate::event::LogicalEvent;
use crate::state::{EventRecord, EventState};

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
#[derive(Debug, Clone, Default)]
pub struct Outbox {
    records: BTreeMap<EventId, EventRecord>,
}

impl Outbox {
    /// Empty outbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of records, terminal ones included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the outbox holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Appends a pending event.
    pub fn enqueue(&mut self, event: LogicalEvent) -> Result<(), OutboxError> {
        let id = event.event_id;
        if self.records.contains_key(&id) {
            return Err(OutboxError::DuplicateEventId(id));
        }
        self.records.insert(id, EventRecord::new(event));
        Ok(())
    }

    /// Record by ID.
    #[must_use]
    pub fn record(&self, id: EventId) -> Option<&EventRecord> {
        self.records.get(&id)
    }

    /// Mutable record by ID.
    pub fn record_mut(&mut self, id: EventId) -> Result<&mut EventRecord, OutboxError> {
        self.records
            .get_mut(&id)
            .ok_or(OutboxError::UnknownEventId(id))
    }

    /// Pending events in canonical dispatch order: logical time, then event ID.
    pub fn dispatchable(&self) -> impl Iterator<Item = &LogicalEvent> {
        let mut pending: Vec<&LogicalEvent> = self
            .records
            .values()
            .filter(|r| matches!(r.state(), EventState::Pending))
            .map(EventRecord::event)
            .collect();
        pending.sort_by_key(|e| (e.logical_time, e.event_id));
        pending.into_iter()
    }

    /// Retry-waiting events whose timer has elapsed at `now`, in canonical order.
    #[must_use]
    pub fn retries_due(&self, now: LogicalInstant) -> Vec<EventId> {
        let mut due: Vec<(LogicalInstant, EventId)> = self
            .records
            .values()
            .filter_map(|r| match r.state() {
                EventState::RetryWaiting { retry_at } if *retry_at <= now => {
                    Some((*retry_at, r.event().event_id))
                }
                _ => None,
            })
            .collect();
        due.sort();
        due.into_iter().map(|(_, id)| id).collect()
    }

    /// Marks every non-terminal record from an epoch older than `current_epoch` as
    /// `DiscardedStaleEpoch`. Returns the number of records discarded.
    pub fn discard_stale(&mut self, current_epoch: Epoch) -> usize {
        let mut discarded = 0;
        for record in self.records.values_mut() {
            if !record.is_terminal() && record.discard_stale(current_epoch).is_ok() {
                discarded += 1;
            }
        }
        discarded
    }

    /// Whether any record is non-terminal. Used by the idle fence cross-check.
    #[must_use]
    pub fn has_active(&self) -> bool {
        self.records.values().any(|r| !r.is_terminal())
    }
}
