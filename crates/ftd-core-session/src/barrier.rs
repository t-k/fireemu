//! Session-wide admission barrier: every state-mutating request is admitted under a shared
//! guard, a reset holds the exclusive guard across all of its steps (Firestore, Auth,
//! Storage, functions), so no request can observe or straddle a half-reset session.

use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// The barrier.
#[derive(Debug, Default)]
pub struct AdmissionBarrier(RwLock<()>);

/// Held by an admitted request.
pub struct Admitted<'a>(#[allow(dead_code)] RwLockReadGuard<'a, ()>);

/// Held by a reset.
pub struct Exclusive<'a>(#[allow(dead_code)] RwLockWriteGuard<'a, ()>);

impl AdmissionBarrier {
    /// A new, open barrier.
    #[must_use]
    pub const fn new() -> Self {
        Self(RwLock::new(()))
    }

    /// Admits a request; waits while a reset is in progress. Never nest: a request holds
    /// at most one admission at a time (a writer waiting between two nested admissions
    /// would deadlock).
    pub fn admit(&self) -> Admitted<'_> {
        Admitted(self.0.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Takes the barrier exclusively; waits for admitted requests to finish and keeps new
    /// ones out until the guard is dropped.
    pub fn exclusive(&self) -> Exclusive<'_> {
        Exclusive(self.0.write().unwrap_or_else(PoisonError::into_inner))
    }
}
