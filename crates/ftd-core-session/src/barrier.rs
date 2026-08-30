//! Session-wide admission barrier: every state-mutating request is admitted under a shared
//! guard, a reset holds the exclusive guard across all of its steps (Firestore, Auth,
//! Storage, functions), so no request can observe or straddle a half-reset session.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// The barrier.
#[derive(Debug, Default)]
pub struct AdmissionBarrier {
    lock: RwLock<()>,
    /// Bumped by every reset, under the exclusive guard.
    epoch: AtomicU64,
}

/// Held by an admitted request.
pub struct Admitted<'a> {
    #[allow(dead_code)]
    guard: RwLockReadGuard<'a, ()>,
    epoch: u64,
}

impl Admitted<'_> {
    /// The reset epoch the request was admitted into.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Held by a reset.
pub struct Exclusive<'a>(#[allow(dead_code)] RwLockWriteGuard<'a, ()>);

impl AdmissionBarrier {
    /// A new, open barrier.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lock: RwLock::new(()),
            epoch: AtomicU64::new(0),
        }
    }

    /// The current reset epoch: capture it before any work that a reset would invalidate
    /// (verifying a token against the Auth store) and compare it after admission.
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Admits a request that started in `seen`; refuses it when a reset happened in
    /// between (its credentials and intent belong to the previous session).
    pub fn admit_since(&self, seen: u64) -> Result<Admitted<'_>, ResetSince> {
        let admitted = self.admit();
        if admitted.epoch == seen {
            Ok(admitted)
        } else {
            Err(ResetSince)
        }
    }

    /// Admits a request; waits while a reset is in progress. Never nest: a request holds
    /// at most one admission at a time (a writer waiting between two nested admissions
    /// would deadlock).
    pub fn admit(&self) -> Admitted<'_> {
        let guard = self.lock.read().unwrap_or_else(PoisonError::into_inner);
        Admitted {
            guard,
            epoch: self.epoch(),
        }
    }

    /// Takes the barrier exclusively; waits for admitted requests to finish and keeps new
    /// ones out until the guard is dropped.
    pub fn exclusive(&self) -> Exclusive<'_> {
        let guard = self.lock.write().unwrap_or_else(PoisonError::into_inner);
        self.epoch.fetch_add(1, Ordering::SeqCst);
        Exclusive(guard)
    }
}

/// The session was reset between the request's start and its admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetSince;

impl std::fmt::Display for ResetSince {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the session was reset while the request was in flight")
    }
}
