//! Local execution backend: one `FirestoreState` per (project, database), each behind its
//! own read-write lock, a shared virtual clock, strict gateway validation before every query.
//!
//! Locking layers, outermost first:
//!
//! 1. the session [`AdmissionBarrier`]: every operation runs admitted, a reset / capture /
//!    restore takes it exclusively, so nothing observes or straddles a half-reset session;
//! 2. the database catalog (`databases`): held only long enough to locate or create one
//!    entry and clone its [`DatabaseHandle`], never while an operation runs;
//! 3. one database's own lock: it serializes that database's operations and nothing else,
//!    so unrelated projects and databases make progress concurrently.
//!
//! The order is always 1 -> 2 -> 3 and no layer is re-entered, so the layering cannot
//! deadlock. Commit actor attribution is operation-local (see [`Actor`]).

// `tonic::Status` is the error type dictated by the generated service trait.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, RwLock};

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::Query;
use fireemu_core_firestore::store::{
    Aggregation, CommitResult, CommitVersion, Document, DocumentChange, FirestoreError,
    FirestoreState, HistoryCapacityError, HistoryProjection, HistoryUsage, ListedDocument,
    Precondition, QueryExecutionId, QueryStats, TransactionId, Write, WriteOp,
};
use fireemu_core_session::barrier::AdmissionBarrier;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::{Clock, DeterministicRng, SplitMix64};
use fireemu_core_types::ids::{CollectionId, DatabaseId, DocumentId};
use fireemu_core_types::resources::{
    Gauge, Refusal, RetentionRoot, RootBudget, ServiceResources, Unit,
};
use fireemu_proto_firestore::google::firestore::v1 as pb;
use tonic::Status;

use crate::decode::{decode_structured_query, parse_parent, DecodeError, Parent};
use crate::encode::{
    decode_document_name, decode_fields, decode_mask, decode_precondition, decode_transaction,
    decode_write, encode_document, encode_instant, encode_transaction, encode_value,
    status_from_error,
};
use crate::gateway::{AcceptedQuery, Gateway, Rejection};
use crate::rules::{allow_all, ReadCheck, ReadGuard, WriteGuard};

/// `ListDocuments` page size when the request leaves it unset (the service default).
pub const DEFAULT_LIST_PAGE_SIZE: usize = 100;
/// How far back a `read_time` selector may reach (Firestore: one hour without PITR).
pub const READ_TIME_RETENTION_SECONDS: i64 = 3600;

// Transactions use optimistic read-set validation in the core store.

/// One database: its state and its own lock. The catalog hands out `Arc` references to
/// it, so an operation holds this lock alone and never the catalog's.
#[derive(Debug, Default)]
struct DatabaseEntry {
    cell: RwLock<DatabaseCell>,
    /// Wakes writers refused for lock contention when a transaction finishes.
    releases: TransactionReleases,
    /// When each transaction first blocked a writer (wall clock). A transaction that keeps
    /// writers blocked for the lock lease is rolled back the way production expires an idle
    /// transaction, so a virtual clock that does not move cannot hold a lock forever.
    blocking_since: Mutex<BTreeMap<TransactionId, (std::time::Instant, u64)>>,
}

impl DatabaseEntry {
    /// A fresh, attached entry holding a restored state.
    fn restored(state: FirestoreState) -> Self {
        Self {
            cell: RwLock::new(DatabaseCell {
                detached: false,
                state,
            }),
            releases: TransactionReleases::default(),
            blocking_since: Mutex::new(BTreeMap::new()),
        }
    }
}

/// The last observed value of the store's transaction release counter, with a condition a
/// contended writer can sleep on until a transaction finishes and its locks are gone.
#[derive(Debug, Default)]
struct TransactionReleases {
    seen: Mutex<u64>,
    changed: std::sync::Condvar,
}

impl TransactionReleases {
    fn publish(&self, releases: u64) {
        if let Ok(mut seen) = self.seen.lock() {
            if *seen != releases {
                *seen = releases;
                self.changed.notify_all();
            }
        }
    }

    fn current(&self) -> u64 {
        self.seen.lock().map_or(0, |seen| *seen)
    }

    /// Blocks until the counter moves past `seen` or `deadline` passes; `true` when it moved.
    fn wait_past(&self, seen: u64, deadline: std::time::Instant) -> bool {
        let Ok(mut current) = self.seen.lock() else {
            return false;
        };
        loop {
            if *current != seen {
                return true;
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            match self.changed.wait_timeout(current, deadline - now) {
                Ok((guard, _)) => current = guard,
                Err(_) => return false,
            }
        }
    }
}

/// A database's state behind its lock, with the flag that retires it.
#[derive(Debug, Default)]
struct DatabaseCell {
    /// Set by the reset / restore that removed this database from the catalog. A handle
    /// retained across that removal must not read or mutate state nobody can reach any
    /// more, so every operation through it answers `UNAVAILABLE` instead.
    detached: bool,
    state: FirestoreState,
}

/// A retained reference to one database, from [`LocalBackend::database_handle`].
///
/// The handle keeps the database alive but not current: a reset or a snapshot restore
/// detaches it, and every later operation through it fails with `UNAVAILABLE` rather than
/// mutating state that has been dropped from the catalog. Operations through a handle take
/// no session admission - callers that need one (every request surface) go through
/// [`LocalBackend`]'s own methods instead.
#[derive(Clone)]
pub struct DatabaseHandle(Arc<DatabaseEntry>);

impl std::fmt::Debug for DatabaseHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseHandle")
            .field("detached", &self.is_detached())
            .finish()
    }
}

impl DatabaseHandle {
    /// Runs `f` under this database's own lock. `UNAVAILABLE` once the database has been
    /// detached by a reset or a restore, or when its lock is poisoned.
    pub fn with<T>(
        &self,
        f: impl FnOnce(&mut FirestoreState) -> Result<T, Status>,
    ) -> Result<T, Status> {
        let mut cell = self.0.cell.write().map_err(|_| lock_poisoned())?;
        if cell.detached {
            return Err(detached());
        }
        let outcome = f(&mut cell.state);
        // Published under the database lock, so a waiter that read the marker before this
        // operation cannot miss the release it caused.
        self.0.releases.publish(cell.state.transaction_releases());
        outcome
    }

    /// The transaction release marker a contended writer records before trying again.
    fn release_marker(&self) -> u64 {
        self.0.releases.current()
    }

    /// Blocks until a transaction finishes after `marker` was read, or until `deadline`.
    fn wait_for_release(&self, marker: u64, deadline: std::time::Instant) -> bool {
        self.0.releases.wait_past(marker, deadline)
    }

    /// Reads under this database's own lock; `None` once detached or poisoned.
    fn read<T>(&self, f: impl FnOnce(&FirestoreState) -> T) -> Option<T> {
        self.read_status(|state| Ok(f(state))).ok()
    }

    fn read_status<T>(
        &self,
        f: impl FnOnce(&FirestoreState) -> Result<T, Status>,
    ) -> Result<T, Status> {
        let cell = self.0.cell.read().map_err(|_| lock_poisoned())?;
        if cell.detached {
            return Err(detached());
        }
        f(&cell.state)
    }

    /// Whether a reset or restore has retired this database.
    #[must_use]
    pub fn is_detached(&self) -> bool {
        self.0.cell.read().is_ok_and(|c| c.detached)
    }

    /// Retires the database under its own lock: the caller has already removed it from the
    /// catalog, and this waits for whatever operation is still running inside it.
    fn detach(&self) {
        if let Ok(mut cell) = self.0.cell.write() {
            cell.detached = true;
            cell.state = FirestoreState::new();
        }
    }
}

/// Local backend state.
pub struct LocalBackend {
    gateway: Gateway,
    /// Reloadable index catalog used for every new query plan.
    indexes: RwLock<BTreeMap<(Option<String>, String), fireemu_core_firestore::index::IndexSet>>,
    clock: Arc<Mutex<VirtualClock>>,
    /// When this backend's databases came into being: a `read_time` before it is refused as
    /// production refuses one before the database's creation time.
    created_at: fireemu_core_types::time::LogicalInstant,
    /// How long a commit outside a transaction waits for the locks an active read-write
    /// transaction holds on what it read before it is refused with `ABORTED` (production:
    /// "Too much contention on these documents"). Zero refuses at once.
    contention_wait: std::time::Duration,
    /// How long (wall clock) a transaction may keep writers blocked before it is rolled back
    /// the way production expires an idle transaction (see [`DEFAULT_LOCK_LEASE`]).
    lock_lease: std::time::Duration,
    /// Unpinned compatibility runs sample wall time for each Firestore write while every
    /// other product and explicitly pinned run continues to use the virtual clock.
    wall_clock_write_time: bool,
    /// Capacity retention root for databases created by this backend. Pinned-clock runs use
    /// the bounded default; wall-clock parity runs rely on the one-hour time root alone.
    history_version_limit: usize,
    /// Aggregate retained-history admission shared by every database.
    history_budget: Arc<Mutex<HistoryBudgetLedger>>,
    /// Resolves registered projects to their session budget owner.
    tenancy: Mutex<Option<fireemu_core_session::tenancy::SharedTenancy>>,
    /// The database catalog. Locked only to locate, create or retire an entry: an
    /// operation clones the entry's handle and releases this lock before it runs.
    databases: Mutex<BTreeMap<(String, String), Arc<DatabaseEntry>>>,
    /// The sessions' fault plans (looked up by project), when shared.
    faults: Mutex<Option<fireemu_core_session::fault::SharedFaultRegistry>>,
    /// Told after a fault plan moved the virtual clock (the functions runtime re-reads
    /// its schedules and retries).
    clock_observer: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    /// Per-database generation, bumped by every wipe of that database (resume tokens are
    /// bound to it, so a project reset invalidates that project's tokens only).
    generations: Mutex<BTreeMap<(String, String), u64>>,
    ids: Mutex<SplitMix64>,
    /// Draws the starting transaction id of each database; separate from `ids` so that the
    /// generated document ids stay what they were for a given seed.
    transaction_ids: Mutex<SplitMix64>,
    /// Identity source for logical query streams whose response is split into bounded pages.
    query_execution_ids: std::sync::atomic::AtomicU64,
    /// Keys the authenticator appended to every transaction token, so a client cannot name a
    /// transaction it was never handed (production tokens are opaque).
    token_key: [u8; 32],
    /// How many transactions have finished across every database, and the signal a REST
    /// writer refused for lock contention waits on without holding a blocking-pool slot.
    release_count: std::sync::atomic::AtomicU64,
    release_notify: tokio::sync::Notify,
    commits: tokio::sync::broadcast::Sender<CommitNotification>,
    /// Bumped by every reset; long-lived streams compare it to refuse stale sessions.
    epoch: std::sync::atomic::AtomicU64,
    /// Session-wide admission barrier shared with the other surfaces (reset holds it
    /// exclusively).
    barrier: Arc<AdmissionBarrier>,
    /// Called for every commit inside the database critical section, in commit order and
    /// before the commit's response is returned (event triggers): nothing is lost or
    /// reordered, and `await-idle` sees the event as soon as the write returns.
    change_sink: Mutex<Option<ChangeSink>>,
    change_admission: Mutex<Option<Arc<dyn AtomicChangeSink>>>,
}

/// Aggregate logical MVCC limits. Per-session limits combine every project/database owned by
/// one session; global limits combine the complete backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryBudgetLimits {
    /// Logical bytes owned by one session.
    pub session_bytes: u64,
    /// Versions owned by one session.
    pub session_versions: u64,
    /// Logical bytes owned by the backend.
    pub global_bytes: u64,
    /// Versions owned by the backend.
    pub global_versions: u64,
}

impl Default for HistoryBudgetLimits {
    fn default() -> Self {
        Self {
            session_bytes: 1 << 30,
            session_versions: 1_000_000,
            global_bytes: 4 << 30,
            global_versions: 4_000_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum HistoryBudgetOwner {
    Default,
    Project(String),
}

#[derive(Debug, Clone)]
struct HistoryCharge {
    owner: HistoryBudgetOwner,
    usage: HistoryUsage,
}

#[derive(Debug)]
struct PendingHistoryCharge {
    key: (String, String),
    charge: HistoryCharge,
}

#[derive(Debug)]
struct HistoryBudgetLedger {
    limits: HistoryBudgetLimits,
    committed: BTreeMap<(String, String), HistoryCharge>,
    pending: BTreeMap<u64, PendingHistoryCharge>,
    pending_by_key: BTreeMap<(String, String), u64>,
    charged_global: HistoryUsage,
    charged_by_owner: BTreeMap<HistoryBudgetOwner, HistoryUsage>,
    accounting_steps: u64,
    next_reservation: u64,
    /// Refused reservations by the limit that refused them, for the resource report.
    refusals: BTreeMap<&'static str, u64>,
}

impl HistoryBudgetLedger {
    fn new(limits: HistoryBudgetLimits) -> Self {
        Self {
            limits,
            committed: BTreeMap::new(),
            pending: BTreeMap::new(),
            pending_by_key: BTreeMap::new(),
            charged_global: HistoryUsage::default(),
            charged_by_owner: BTreeMap::new(),
            accounting_steps: 0,
            next_reservation: 0,
            refusals: BTreeMap::new(),
        }
    }

    fn note_refusal(&mut self, error: &FirestoreError) {
        let dimension = match error {
            FirestoreError::HistoryCapacity(capacity) => capacity.dimension,
            _ => "other",
        };
        *self.refusals.entry(dimension).or_default() += 1;
    }

    fn adjust_totals(&mut self, old: Option<&HistoryCharge>, new: Option<&HistoryCharge>) {
        if let Some(old) = old {
            self.accounting_steps = self.accounting_steps.saturating_add(1);
            self.charged_global = subtract_aggregate_usage(self.charged_global, old.usage);
            let remove_owner = {
                let total = self.charged_by_owner.entry(old.owner.clone()).or_default();
                *total = subtract_aggregate_usage(*total, old.usage);
                total.versions == 0 && total.total_bytes == 0
            };
            if remove_owner {
                self.charged_by_owner.remove(&old.owner);
            }
        }
        if let Some(new) = new {
            self.accounting_steps = self.accounting_steps.saturating_add(1);
            self.charged_global = add_aggregate_usage(self.charged_global, new.usage);
            let owner = self.charged_by_owner.entry(new.owner.clone()).or_default();
            *owner = add_aggregate_usage(*owner, new.usage);
        }
    }

    fn reserve(
        &mut self,
        key: (String, String),
        owner: HistoryBudgetOwner,
        mut usage: HistoryUsage,
    ) -> Result<u64, FirestoreError> {
        // A speculative reduction is not capacity another database may consume. It becomes
        // visible only when this reservation commits; cancellation must leave the old charge.
        if self.pending_by_key.contains_key(&key) {
            let error = FirestoreError::HistoryCapacity(HistoryCapacityError {
                dimension: "database reservation",
                current: 1,
                maximum: 0,
            });
            self.note_refusal(&error);
            return Err(error);
        }
        let previous = self.committed.get(&key).cloned();
        if let Some(committed) = &previous {
            usage.total_bytes = usage.total_bytes.max(committed.usage.total_bytes);
            usage.versions = usage.versions.max(committed.usage.versions);
        }
        let charge = HistoryCharge { owner, usage };
        let candidate_global = add_aggregate_usage(
            previous.as_ref().map_or(self.charged_global, |old| {
                subtract_aggregate_usage(self.charged_global, old.usage)
            }),
            charge.usage,
        );
        if let Err(error) = self.validate_global(candidate_global) {
            self.note_refusal(&error);
            return Err(error);
        }
        let current_owner_total = self
            .charged_by_owner
            .get(&charge.owner)
            .copied()
            .unwrap_or_default();
        let without_previous = previous.as_ref().map_or(current_owner_total, |old| {
            if old.owner == charge.owner {
                subtract_aggregate_usage(current_owner_total, old.usage)
            } else {
                current_owner_total
            }
        });
        if let Err(error) = self.validate_owner(add_aggregate_usage(without_previous, charge.usage))
        {
            self.note_refusal(&error);
            return Err(error);
        }
        let id = self.next_reservation;
        self.next_reservation = self.next_reservation.wrapping_add(1);
        self.adjust_totals(previous.as_ref(), Some(&charge));
        self.pending.insert(
            id,
            PendingHistoryCharge {
                key: key.clone(),
                charge,
            },
        );
        self.pending_by_key.insert(key, id);
        Ok(id)
    }

    fn validate_global(&self, global: HistoryUsage) -> Result<(), FirestoreError> {
        check_aggregate_history_limit(
            "global versions",
            global.versions,
            self.limits.global_versions,
        )?;
        check_aggregate_history_limit(
            "global bytes",
            global.total_bytes,
            self.limits.global_bytes,
        )?;
        Ok(())
    }

    fn validate_owner(&self, session: HistoryUsage) -> Result<(), FirestoreError> {
        check_aggregate_history_limit(
            "session versions",
            session.versions,
            self.limits.session_versions,
        )?;
        check_aggregate_history_limit(
            "session bytes",
            session.total_bytes,
            self.limits.session_bytes,
        )
    }

    fn validate_replacement(
        &self,
        removed: impl Iterator<Item = HistoryCharge>,
        added: impl Iterator<Item = HistoryCharge>,
    ) -> Result<(), FirestoreError> {
        let mut global = self.charged_global;
        let mut owners = self.charged_by_owner.clone();
        for charge in removed {
            global = subtract_aggregate_usage(global, charge.usage);
            let total = owners.entry(charge.owner).or_default();
            *total = subtract_aggregate_usage(*total, charge.usage);
        }
        for charge in added {
            global = add_aggregate_usage(global, charge.usage);
            let total = owners.entry(charge.owner).or_default();
            *total = add_aggregate_usage(*total, charge.usage);
        }
        self.validate_global(global)?;
        for usage in owners.into_values() {
            self.validate_owner(usage)?;
        }
        Ok(())
    }

    fn remove_committed(&mut self, key: &(String, String)) {
        if let Some(charge) = self.committed.remove(key) {
            self.adjust_totals(Some(&charge), None);
        }
    }

    fn replace_committed(&mut self, key: (String, String), charge: &HistoryCharge) {
        let old = self.committed.insert(key, charge.clone());
        self.adjust_totals(old.as_ref(), Some(charge));
    }
}

fn add_aggregate_usage(mut total: HistoryUsage, usage: HistoryUsage) -> HistoryUsage {
    total.total_bytes = total.total_bytes.saturating_add(usage.total_bytes);
    total.versions = total.versions.saturating_add(usage.versions);
    total
}

fn subtract_aggregate_usage(mut total: HistoryUsage, usage: HistoryUsage) -> HistoryUsage {
    total.total_bytes = total.total_bytes.saturating_sub(usage.total_bytes);
    total.versions = total.versions.saturating_sub(usage.versions);
    total
}

fn check_aggregate_history_limit(
    dimension: &'static str,
    current: u64,
    maximum: u64,
) -> Result<(), FirestoreError> {
    if current > maximum {
        Err(FirestoreError::HistoryCapacity(HistoryCapacityError {
            dimension,
            current,
            maximum,
        }))
    } else {
        Ok(())
    }
}

struct HistoryReservation {
    ledger: Arc<Mutex<HistoryBudgetLedger>>,
    id: u64,
    committed: bool,
}

impl HistoryReservation {
    fn commit(mut self, actual: HistoryUsage) {
        let mut ledger = self
            .ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(mut pending) = ledger.pending.remove(&self.id) {
            ledger.pending_by_key.remove(&pending.key);
            let reserved = pending.charge.clone();
            pending.charge.usage = actual;
            ledger.adjust_totals(Some(&reserved), Some(&pending.charge));
            ledger.committed.insert(pending.key, pending.charge);
        }
        self.committed = true;
    }
}

impl Drop for HistoryReservation {
    fn drop(&mut self) {
        if !self.committed {
            let mut ledger = self
                .ledger
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(pending) = ledger.pending.remove(&self.id) {
                ledger.pending_by_key.remove(&pending.key);
                let committed = ledger.committed.get(&pending.key).cloned();
                ledger.adjust_totals(Some(&pending.charge), committed.as_ref());
            }
        }
    }
}

/// Synchronous observer of committed changes (see [`LocalBackend::set_change_sink`]).
pub type ChangeSink = Arc<dyn Fn(&CommitEvent) + Send + Sync>;

/// A complete logical-event reservation for one Firestore commit.
pub trait CommitPublication: Send {
    /// Publishes the already admitted event batch after the source state is visible.
    fn publish(self: Box<Self>);
}

/// Reserves every logical event a prospective Firestore commit requires.
pub trait AtomicChangeSink: Send + Sync {
    /// Returns a complete reservation or refuses before the source state changes.
    fn reserve(
        &self,
        event: &CommitEvent,
    ) -> Result<Box<dyn CommitPublication>, fireemu_core_types::admission::EventAdmissionError>;
}

struct NoopCommitPublication;

impl CommitPublication for NoopCommitPublication {
    fn publish(self: Box<Self>) {}
}

/// The lock contention wait the daemon runs with. Production makes a colliding writer wait
/// for the transaction's locks and refuses it with `ABORTED` after a bound of its own
/// (measured under a minute in conformance/firestore-production-matrix.json,
/// transactions/lifecycle#out-of-band-write); the official emulator answers "Transaction lock
/// timeout." on the same shape. fireemu waits this long.
pub const DEFAULT_CONTENTION_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

/// How long (wall clock) a transaction may keep other writers blocked on its locks before it
/// is rolled back: production expires a transaction idle for 60 seconds, which is what
/// releases a lock a client stopped driving. The lease is wall time even under a pinned
/// virtual clock, so a client awaiting a write that its own transaction blocks (a pattern
/// the SDKs' commit retries turn into a long wait in production too) eventually proceeds.
pub const DEFAULT_LOCK_LEASE: std::time::Duration = std::time::Duration::from_secs(60);

/// Commit notifications retained for slow Listen and UI subscribers. Lag is recoverable by
/// reading one current database snapshot, so a small ring bounds retained path metadata.
pub const COMMIT_NOTIFICATION_CAPACITY: usize = 32;

/// Metadata key a `dropConnection` fault sets on its status: the server closes the
/// connection (or resets the stream) instead of delivering the response.
pub const DROP_CONNECTION_KEY: &str = "fireemu-drop-connection";

/// A session's Firestore snapshot: its databases, and the auto-ID generator when the
/// session owns it (the default one).
#[derive(Debug, Clone)]
pub struct FirestoreSnapshot {
    /// Databases by `(project, database)`.
    pub databases: BTreeMap<(String, String), FirestoreState>,
    /// The auto-ID generator state.
    pub ids: Option<SplitMix64>,
}

impl FirestoreSnapshot {
    /// A cheap, saturating estimate of the bytes this snapshot retains: the visible documents
    /// of every database it holds (`SNAP-MEM-01`). Additive; no capture or restore semantics
    /// depend on it.
    #[must_use]
    pub fn retained_bytes(&self) -> u64 {
        self.databases
            .values()
            .map(FirestoreState::visible_bytes)
            .fold(0u64, u64::saturating_add)
    }
}

/// Published after every successful commit (drives `Listen` streams).
#[derive(Debug, Clone, PartialEq)]
pub struct CommitEvent {
    /// Who made the commit (`withAuthContext` triggers).
    pub actor: Actor,
    /// Project.
    pub project: String,
    /// Database.
    pub database: String,
    /// Version after the commit.
    pub version: u64,
    /// Commit time (`None` for a reset).
    pub commit_time: Option<fireemu_core_types::time::LogicalInstant>,
    /// Documents the commit changed (before / after), shared with every subscriber.
    pub changes: Arc<[DocumentChange]>,
}

/// Observable kind of one changed path in a compact broadcast notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitChangeKind {
    /// A previously missing document now exists.
    Created,
    /// A live document changed while remaining live.
    Updated,
    /// A previously live document is now missing.
    Deleted,
}

/// One compact changed path. Document images stay in [`CommitEvent`] for synchronous sinks
/// and are never retained by the broadcast ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPathChange {
    /// Changed document path.
    pub path: DocumentPath,
    /// Final transition kind.
    pub kind: CommitChangeKind,
}

/// Compact notification used by Listen and UI subscribers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitNotification {
    /// Project.
    pub project: String,
    /// Database.
    pub database: String,
    /// Version after the commit.
    pub version: u64,
    /// A reset or restore invalidated all retained stream state.
    pub reset: bool,
    /// Changed paths without before/after document images.
    pub changes: Arc<[CommitPathChange]>,
}

fn status(e: DecodeError) -> Status {
    Rejection::Decode(e).to_status()
}

/// The principal behind a commit, in Eventarc's `authtype` / `authid` terms.
///
/// Attribution is operation-local: a write guard stages the actor with
/// [`LocalBackend::set_actor`] and `publish` takes it back, both inside the one database
/// critical section that the operation's own thread holds without yielding (see
/// `PENDING_ACTOR`). Concurrent operations in different databases therefore never consume
/// each other's principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    /// `app_user`, `service_account`, `unauthenticated`, `system`.
    pub auth_type: String,
    /// The user ID (`app_user`) or the service account (`service_account`).
    pub auth_id: Option<String>,
}

impl Actor {
    /// The runtime itself (resets, internal writes).
    #[must_use]
    pub fn system() -> Self {
        Self {
            auth_type: "system".to_owned(),
            auth_id: None,
        }
    }

    /// The actor behind a request principal.
    #[must_use]
    pub fn from_principal(principal: &crate::rules::Principal) -> Self {
        match principal {
            crate::rules::Principal::Owner => Self {
                auth_type: "service_account".to_owned(),
                auth_id: Some("owner".to_owned()),
            },
            crate::rules::Principal::User(a) => Self {
                auth_type: "app_user".to_owned(),
                auth_id: Some(a.uid.clone()),
            },
            crate::rules::Principal::Anonymous => Self {
                auth_type: "unauthenticated".to_owned(),
                auth_id: None,
            },
        }
    }
}

fn lock_poisoned() -> Status {
    Status::internal("backend state lock poisoned")
}

fn detached() -> Status {
    Status::unavailable(
        "the database was reset or restored while this operation held a handle to it",
    )
}

thread_local! {
    /// The actor staged by the write guard of the operation running on this thread.
    ///
    /// Guard, commit and publish run on one thread inside a single database critical
    /// section with no await point in between, so this slot belongs to exactly one
    /// operation at a time - unlike a slot on the backend, which every database would
    /// share. [`ActorScope`] clears it at both ends of the critical section, so an actor
    /// staged by a guard whose commit then failed is never attributed to a later commit.
    static PENDING_ACTOR: std::cell::RefCell<Option<Actor>> =
        const { std::cell::RefCell::new(None) };
}

thread_local! {
    /// Set while a REST request runs on a blocking-pool thread: a write refused for lock
    /// contention is not waited on there (that would hold the pool slot), it is reported
    /// through this slot and the connection task waits without the slot instead.
    static NO_WAIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static CONTENDED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Clears the operation-local actor slot on entry and on the way out.
struct ActorScope;

impl ActorScope {
    fn enter() -> Self {
        Self::clear();
        Self
    }

    fn clear() {
        PENDING_ACTOR.with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut() {
                *slot = None;
            }
        });
    }
}

impl Drop for ActorScope {
    fn drop(&mut self) {
        Self::clear();
    }
}

/// One item of a batch get (core snapshot; encoded after authorization).
#[derive(Debug, Clone)]
pub enum BatchGetItem {
    /// Found document.
    Found(Document),
    /// Missing document name.
    Missing(String),
}

impl BatchGetItem {
    /// Path of the item.
    pub fn path(&self) -> Result<DocumentPath, Status> {
        match self {
            Self::Found(d) => Ok(d.path.clone()),
            Self::Missing(name) => decode_document_name(name).map_err(status),
        }
    }

    /// Snapshot document, if found.
    #[must_use]
    pub const fn document(&self) -> Option<&Document> {
        match self {
            Self::Found(d) => Some(d),
            Self::Missing(_) => None,
        }
    }

    /// Wire form with the response mask applied.
    #[must_use]
    pub fn encode(&self, mask: Option<&[FieldPath]>) -> pb::batch_get_documents_response::Result {
        match self {
            Self::Found(d) => {
                pb::batch_get_documents_response::Result::Found(encode_masked(d, mask))
            }
            Self::Missing(n) => pb::batch_get_documents_response::Result::Missing(n.clone()),
        }
    }
}

/// Result of a batch get: snapshots, the transaction to report and the read time.
#[derive(Debug, Clone)]
pub struct BatchGetOutcome {
    /// Items in request order.
    pub items: Vec<BatchGetItem>,
    /// New transaction token (empty unless `new_transaction` was requested).
    pub transaction: Vec<u8>,
    /// Snapshot time.
    pub read_time: fireemu_core_types::time::LogicalInstant,
    /// Response mask.
    pub mask: Option<Vec<FieldPath>>,
}

/// A single-document read: the exact snapshot the response is built from.
#[derive(Debug, Clone)]
pub struct DocumentSnapshot {
    /// Path.
    pub path: DocumentPath,
    /// Snapshot (`None` = missing).
    pub document: Option<Document>,
    /// Response mask.
    pub mask: Option<Vec<FieldPath>>,
}

/// Consistency selector normalized from the three generated Firestore request enums.
#[derive(Clone, Copy)]
enum SnapshotSelector<'a> {
    Transaction(&'a [u8]),
    NewTransaction(&'a pb::TransactionOptions),
    ReadTime(fireemu_core_types::time::LogicalInstant),
    Latest,
}

/// Snapshot chosen for one read operation. A non-empty report is the token for a transaction
/// created by this operation and therefore must be abandoned if the operation is refused.
struct SelectedSnapshot {
    transaction: Option<TransactionId>,
    report: Vec<u8>,
    read_at: Option<fireemu_core_types::time::LogicalInstant>,
}

#[derive(Clone, Copy)]
struct QueryExecutionContext {
    id: QueryExecutionId,
    complete: bool,
}

enum SnapshotState<'a> {
    Shared(&'a FirestoreState),
    Exclusive(&'a mut FirestoreState),
}

struct SnapshotAccess<'a> {
    state: SnapshotState<'a>,
    selected: SelectedSnapshot,
    query_execution_id: Option<QueryExecutionId>,
    complete_query_execution: bool,
}

impl SnapshotAccess<'_> {
    fn db(&self) -> &FirestoreState {
        match &self.state {
            SnapshotState::Shared(db) => db,
            SnapshotState::Exclusive(db) => db,
        }
    }

    fn version(&self) -> Result<Option<CommitVersion>, Status> {
        self.selected.version(self.db())
    }

    fn read_time(
        &self,
        now: fireemu_core_types::time::LogicalInstant,
    ) -> Result<fireemu_core_types::time::LogicalInstant, Status> {
        self.selected.read_time(self.db(), now)
    }

    fn report(&self) -> &[u8] {
        &self.selected.report
    }

    fn set_query_execution(&mut self, execution_id: QueryExecutionId, complete: bool) {
        self.query_execution_id = Some(execution_id);
        self.complete_query_execution = complete;
    }

    fn record_document_reads(
        &mut self,
        reads: &[(DocumentPath, Option<Document>)],
    ) -> Result<(), Status> {
        match (&mut self.state, &self.selected.transaction) {
            (SnapshotState::Shared(_), None) => Ok(()),
            (SnapshotState::Exclusive(db), Some(transaction)) => {
                for (path, document) in reads {
                    db.record_transaction_read(transaction, path, document.as_ref())
                        .map_err(|error| status_from_error(&error))?;
                }
                Ok(())
            }
            _ => Err(Status::internal("invalid Firestore snapshot access mode")),
        }
    }

    fn run_query_with_stats(
        &mut self,
        query: &Query,
        observed_query: &Query,
        continuation: bool,
    ) -> Result<(Vec<Document>, QueryStats), Status> {
        let version = self.version()?;
        let execution_id = self.query_execution_id;
        let complete = self.complete_query_execution;
        match (&mut self.state, &self.selected.transaction) {
            (SnapshotState::Exclusive(db), Some(transaction)) => {
                let result = if continuation {
                    if let Some(execution_id) = execution_id {
                        db.run_query_in_transaction_continuation_with_stats_as_with_execution(
                            transaction,
                            query,
                            observed_query,
                            execution_id,
                            complete,
                        )
                    } else {
                        db.run_query_in_transaction_continuation_with_stats_as(
                            transaction,
                            query,
                            observed_query,
                        )
                    }
                } else {
                    if let Some(execution_id) = execution_id {
                        db.run_query_in_transaction_with_stats_as_with_execution(
                            transaction,
                            query,
                            observed_query,
                            execution_id,
                            complete,
                        )
                    } else {
                        db.run_query_in_transaction_with_stats_as(
                            transaction,
                            query,
                            observed_query,
                        )
                    }
                };
                result.map_err(|error| status_from_error(&error))
            }
            (SnapshotState::Shared(db), None) => db
                .run_query_with_stats(query, version)
                .map_err(|error| status_from_error(&error)),
            _ => Err(Status::internal("invalid Firestore snapshot access mode")),
        }
    }

    fn run_query_with_stats_after_document(
        &mut self,
        query: &Query,
        observed_query: &Query,
        after: &DocumentPath,
    ) -> Result<(Vec<Document>, QueryStats), Status> {
        let version = self.version()?;
        let execution_id = self.query_execution_id;
        let complete = self.complete_query_execution;
        match (&mut self.state, &self.selected.transaction) {
            (SnapshotState::Exclusive(db), Some(transaction)) => {
                let result = if let Some(execution_id) = execution_id {
                    db.run_query_in_transaction_after_document_with_stats_as_with_execution(
                        transaction,
                        query,
                        observed_query,
                        after,
                        execution_id,
                        complete,
                    )
                } else {
                    db.run_query_in_transaction_after_document_with_stats_as(
                        transaction,
                        query,
                        observed_query,
                        after,
                    )
                };
                result.map_err(|error| status_from_error(&error))
            }
            (SnapshotState::Shared(db), None) => db
                .run_query_after_document_with_stats(query, version, after)
                .map_err(|error| status_from_error(&error)),
            _ => Err(Status::internal("invalid Firestore snapshot access mode")),
        }
    }

    fn record_query(&mut self, query: &Query) -> Result<(), Status> {
        match (&mut self.state, &self.selected.transaction) {
            (SnapshotState::Shared(_), None) => Ok(()),
            (SnapshotState::Exclusive(db), Some(transaction)) => db
                .run_query_in_transaction(transaction, query)
                .map(|_| ())
                .map_err(|error| status_from_error(&error)),
            _ => Err(Status::internal("invalid Firestore snapshot access mode")),
        }
    }
}

impl SelectedSnapshot {
    fn version(&self, db: &FirestoreState) -> Result<Option<CommitVersion>, Status> {
        match (&self.transaction, self.read_at) {
            (Some(transaction), _) => db
                .transaction_read_version(transaction)
                .map(Some)
                .map_err(|error| status_from_error(&error)),
            (None, Some(read_at)) => LocalBackend::retained_read_version(db, read_at).map(Some),
            (None, None) => Ok(None),
        }
    }

    fn read_time(
        &self,
        db: &FirestoreState,
        now: fireemu_core_types::time::LogicalInstant,
    ) -> Result<fireemu_core_types::time::LogicalInstant, Status> {
        match (&self.transaction, self.read_at) {
            (Some(transaction), _) => db
                .transaction_read_time(transaction)
                .map_err(|error| status_from_error(&error)),
            (None, Some(read_at)) => Ok(read_at),
            (None, None) => Ok(db.read_time(now)),
        }
    }
}

impl DocumentSnapshot {
    /// Wire form (`NOT_FOUND` when missing).
    pub fn into_response(self) -> Result<pb::Document, Status> {
        match self.document {
            Some(d) => Ok(encode_masked(&d, self.mask.as_deref())),
            None => Err(Status::not_found(format!(
                "Document not found: {}",
                self.path.resource_name()
            ))),
        }
    }
}

impl LocalBackend {
    /// Creates a backend with the strict gateway and a shared clock.
    #[must_use]
    pub fn new(gateway: Gateway, clock: Arc<Mutex<VirtualClock>>, seed: u64) -> Self {
        let indexes = RwLock::new(BTreeMap::from([(
            (None, DatabaseId::DEFAULT.to_owned()),
            gateway.indexes.clone(),
        )]));
        let created_at = clock
            .lock()
            .map(|clock| clock.now())
            .unwrap_or(fireemu_core_types::time::LogicalInstant::UNIX_EPOCH);
        Self {
            created_at,
            contention_wait: std::time::Duration::ZERO,
            lock_lease: DEFAULT_LOCK_LEASE,
            gateway,
            indexes,
            clock,
            wall_clock_write_time: false,
            history_version_limit:
                fireemu_core_firestore::store::DEFAULT_MAX_RETAINED_VERSIONS_PER_PATH,
            history_budget: Arc::new(Mutex::new(HistoryBudgetLedger::new(
                HistoryBudgetLimits::default(),
            ))),
            tenancy: Mutex::new(None),
            databases: Mutex::new(BTreeMap::new()),
            faults: Mutex::new(None),
            clock_observer: Mutex::new(None),
            generations: Mutex::new(BTreeMap::new()),
            ids: Mutex::new(SplitMix64::new(seed)),
            transaction_ids: Mutex::new(SplitMix64::new(seed ^ 0x0054_584e)),
            query_execution_ids: std::sync::atomic::AtomicU64::new(0),
            token_key: {
                let mut key_source = SplitMix64::new(seed ^ 0x544f_4b45_4e4b_4559);
                let mut key = [0_u8; 32];
                for chunk in key.chunks_mut(8) {
                    chunk.copy_from_slice(&key_source.next_u64().to_be_bytes());
                }
                key
            },
            release_count: std::sync::atomic::AtomicU64::new(0),
            release_notify: tokio::sync::Notify::new(),
            commits: tokio::sync::broadcast::channel(COMMIT_NOTIFICATION_CAPACITY).0,
            epoch: std::sync::atomic::AtomicU64::new(0),
            change_sink: Mutex::new(None),
            change_admission: Mutex::new(None),
            barrier: Arc::new(AdmissionBarrier::new()),
        }
    }

    /// How long a commit outside a transaction waits for the locks an active read-write
    /// transaction holds before it is refused (see [`DEFAULT_CONTENTION_WAIT`]). The
    /// constructor's default is zero: the refusal is immediate and deterministic.
    #[must_use]
    pub const fn with_contention_wait(mut self, wait: std::time::Duration) -> Self {
        self.contention_wait = wait;
        self
    }

    /// The configured lock contention wait.
    #[must_use]
    pub const fn contention_wait(&self) -> std::time::Duration {
        self.contention_wait
    }

    /// How long a transaction may keep writers blocked before it is rolled back.
    #[must_use]
    pub const fn with_lock_lease(mut self, lease: std::time::Duration) -> Self {
        self.lock_lease = lease;
        self
    }

    /// Uses host wall time for Firestore commit timestamps. This is selected only when the
    /// daemon clock was not explicitly pinned.
    #[must_use]
    pub const fn with_wall_clock_write_time(mut self) -> Self {
        self.wall_clock_write_time = true;
        self.history_version_limit = usize::MAX;
        self
    }

    /// Overrides the per-path history capacity for deterministic tests and embedders.
    #[must_use]
    pub const fn with_history_version_limit(mut self, max_versions_per_path: usize) -> Self {
        self.history_version_limit = if max_versions_per_path == 0 {
            1
        } else {
            max_versions_per_path
        };
        self
    }

    /// Overrides aggregate history limits for deterministic tests and embedders.
    #[must_use]
    pub fn with_history_budget_limits(mut self, limits: HistoryBudgetLimits) -> Self {
        self.history_budget = Arc::new(Mutex::new(HistoryBudgetLedger::new(limits)));
        self
    }

    /// Shares the session ownership registry used by control-plane registration.
    pub fn set_tenancy(&self, tenancy: fireemu_core_session::tenancy::SharedTenancy) {
        *self
            .tenancy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(tenancy);
    }

    fn history_owner(&self, project: &str) -> HistoryBudgetOwner {
        let tenancy = self
            .tenancy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        tenancy.map_or(HistoryBudgetOwner::Default, |tenancy| {
            let tenancy = tenancy
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if tenancy.is_registered(project) {
                HistoryBudgetOwner::Project(project.to_owned())
            } else {
                HistoryBudgetOwner::Default
            }
        })
    }

    fn reserve_history(
        &self,
        parent: &Parent,
        projection: HistoryProjection,
    ) -> Result<HistoryReservation, FirestoreError> {
        let owner = self.history_owner(parent.project.as_str());
        let mut ceiling = projection.after;
        ceiling.total_bytes = ceiling.total_bytes.max(projection.before.total_bytes);
        ceiling.versions = ceiling.versions.max(projection.before.versions);
        let mut ledger = self
            .history_budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let id = ledger.reserve(database_key(parent), owner, ceiling)?;
        drop(ledger);
        Ok(HistoryReservation {
            ledger: self.history_budget.clone(),
            id,
            committed: false,
        })
    }

    fn reconcile_history(&self, parent: &Parent, usage: HistoryUsage) {
        let key = database_key(parent);
        let owner = self.history_owner(parent.project.as_str());
        let mut ledger = self
            .history_budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if usage.versions == 0 && usage.total_bytes == 0 {
            ledger.remove_committed(&key);
        } else {
            ledger.replace_committed(key, &HistoryCharge { owner, usage });
        }
    }

    /// The session's admission barrier (share it with every other mutable surface).
    #[must_use]
    pub fn barrier(&self) -> Arc<AdmissionBarrier> {
        self.barrier.clone()
    }

    /// Installs the synchronous commit observer (at most one). Contract: the sink runs
    /// inside the database critical section, so it must not call back into this backend
    /// (self-deadlock) and must not panic (poisoned lock); it should only hand the event to
    /// its own queue.
    pub fn set_change_sink(&self, sink: ChangeSink) {
        if let Ok(mut slot) = self.change_sink.lock() {
            *slot = Some(sink);
        }
    }

    /// Installs the source-publication admission boundary used by a Functions runtime.
    pub fn set_atomic_change_sink(&self, sink: Arc<dyn AtomicChangeSink>) {
        if let Ok(mut slot) = self.change_admission.lock() {
            *slot = Some(sink);
        }
    }

    /// Current reset epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The wipe generation of a database (see `generations`).
    #[must_use]
    pub fn database_generation(&self, parent: &Parent) -> u64 {
        self.generations
            .lock()
            .ok()
            .and_then(|g| g.get(&database_key(parent)).copied())
            .unwrap_or(0)
    }

    fn bump_generations(&self, keys: &[(String, String)]) {
        if let Ok(mut g) = self.generations.lock() {
            for k in keys {
                *g.entry(k.clone()).or_insert(0) += 1;
            }
        }
    }

    /// Drops every database of one project (a session reset of that project): other
    /// projects' streams and epoch are untouched; the project's streams observe the wipe.
    pub fn reset_project(&self, project: &str) {
        self.reset_scope(&fireemu_core_session::tenancy::Scope::Project(
            project.to_owned(),
        ));
    }

    /// Drops every database `scope` owns. The default session's scope also starts a new
    /// epoch (streams opened before it end like on a full reset); a project scope only
    /// bumps the generations of the databases it wiped.
    pub fn reset_scope(&self, scope: &fireemu_core_session::tenancy::Scope) {
        if scope.is_default() {
            // Streams opened before the reset see the epoch change before any data is
            // dropped.
            self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        let cleared = self.take_scope(scope);
        self.bump_generations(&cleared);
        self.announce_wipe(cleared);
    }

    /// Removes every database `scope` owns from the catalog and detaches it, returning the
    /// keys in catalog order.
    ///
    /// The catalog lock is released before the entries are detached, so a reset never
    /// holds it while it waits; detaching takes each removed database's own lock, so the
    /// reset waits for the operations still running inside exactly those databases and
    /// leaves the rest of the catalog alone.
    fn take_scope(&self, scope: &fireemu_core_session::tenancy::Scope) -> Vec<(String, String)> {
        let removed: Vec<((String, String), DatabaseHandle)> = match self.databases.lock() {
            Ok(mut dbs) => {
                let keys: Vec<(String, String)> = dbs
                    .keys()
                    .filter(|(p, _)| scope.owns_project(p))
                    .cloned()
                    .collect();
                keys.into_iter()
                    .filter_map(|k| dbs.remove(&k).map(|e| (k, DatabaseHandle(e))))
                    .collect()
            }
            Err(_) => Vec::new(),
        };
        let keys: Vec<(String, String)> = removed
            .into_iter()
            .map(|(key, handle)| {
                handle.detach();
                key
            })
            .collect();
        let mut ledger = self
            .history_budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for key in &keys {
            ledger.remove_committed(key);
        }
        keys
    }

    fn announce_wipe(&self, databases: Vec<(String, String)>) {
        for (project, database) in databases {
            let _ = self.commits.send(CommitNotification {
                project,
                database,
                version: 0,
                reset: true,
                changes: Arc::from([]),
            });
        }
    }

    /// A copy of every database (the default session's snapshot).
    #[must_use]
    pub fn snapshot_databases(&self) -> BTreeMap<(String, String), FirestoreState> {
        self.copy_databases(&fireemu_core_session::tenancy::Scope::AllExcept(
            std::collections::BTreeSet::new(),
        ))
    }

    /// The handles of the databases `scope` owns, in catalog order.
    fn handles_of(
        &self,
        scope: &fireemu_core_session::tenancy::Scope,
    ) -> Vec<((String, String), DatabaseHandle)> {
        self.databases
            .lock()
            .map(|dbs| {
                dbs.iter()
                    .filter(|((p, _), _)| scope.owns_project(p))
                    .map(|(k, v)| (k.clone(), DatabaseHandle(v.clone())))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Compacts every attached database after the shared virtual clock advances.
    ///
    /// Handles are collected under the catalog lock and compacted one at a time after that
    /// lock is released, so an unrelated database never waits behind a catalog-wide critical
    /// section. A concurrently detached or poisoned database is skipped; requests through it
    /// already fail independently.
    pub fn compact_all(&self, now: fireemu_core_types::time::LogicalInstant) {
        let scope =
            fireemu_core_session::tenancy::Scope::AllExcept(std::collections::BTreeSet::new());
        for (key, handle) in self.handles_of(&scope) {
            let usage = handle.with(|state| {
                state.compact(now);
                Ok(state.history_usage())
            });
            if let Ok(usage) = usage {
                let mut ledger = self
                    .history_budget
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(mut charge) = ledger.committed.get(&key).cloned() {
                    charge.usage = usage;
                    ledger.replace_committed(key, &charge);
                }
            }
        }
    }

    /// One session's Firestore retention report for the resource diagnostics: the session's
    /// logical history charge against its limits (the backend-wide charge for the default
    /// session only, so a session never reads another session's byte or version totals), the
    /// ledger's refusal counts by limit (backend-wide counts by category, carrying no
    /// identifier), and one root per database plus one per database with active transactions.
    /// Each database is read under its own lock, one after another; the report never holds
    /// two databases' locks or the catalog lock while reading a database.
    ///
    /// # Errors
    ///
    /// A database whose lock is poisoned or that was detached while the report was collected
    /// is an error, never a silently missing root: its transactions would otherwise vanish
    /// from a report that claims to be complete.
    pub fn resources(
        &self,
        scope: &fireemu_core_session::tenancy::Scope,
        budget: RootBudget,
    ) -> Result<ServiceResources, String> {
        let owner = match scope {
            fireemu_core_session::tenancy::Scope::Project(project) => {
                HistoryBudgetOwner::Project(project.clone())
            }
            fireemu_core_session::tenancy::Scope::AllExcept(_) => HistoryBudgetOwner::Default,
        };
        let (mut gauges, refusals) = self.history_budget_gauges(&owner, scope.is_default())?;
        let (database_gauges, roots, unreadable) = self.database_roots(scope);
        if unreadable > 0 {
            return Err(format!(
                "{unreadable} database(s) could not be read (poisoned or detached during the report)"
            ));
        }
        gauges.extend(database_gauges);
        Ok(ServiceResources {
            service: "firestore".to_owned(),
            gauges,
            refusals,
            roots: budget.bound(roots),
        })
    }

    /// The ledger's view: the owner's charge against the session limits, the backend-wide
    /// charge against the global limits for the default session only, and the refusals by
    /// limit.
    fn history_budget_gauges(
        &self,
        owner: &HistoryBudgetOwner,
        report_global: bool,
    ) -> Result<(Vec<Gauge>, Vec<Refusal>), String> {
        // A poisoned ledger is a half-applied update, not a value to report as complete.
        let ledger = self
            .history_budget
            .lock()
            .map_err(|_| "the history budget ledger is poisoned".to_owned())?;
        let session = ledger
            .charged_by_owner
            .get(owner)
            .copied()
            .unwrap_or_default();
        let limits = ledger.limits;
        let mut gauges = vec![
            Gauge::logical(
                "history.session_bytes",
                Unit::Bytes,
                session.total_bytes,
                Some(limits.session_bytes),
            ),
            Gauge::logical(
                "history.session_versions",
                Unit::Count,
                session.versions,
                Some(limits.session_versions),
            ),
        ];
        if report_global {
            gauges.push(Gauge::logical(
                "history.global_bytes",
                Unit::Bytes,
                ledger.charged_global.total_bytes,
                Some(limits.global_bytes),
            ));
            gauges.push(Gauge::logical(
                "history.global_versions",
                Unit::Count,
                ledger.charged_global.versions,
                Some(limits.global_versions),
            ));
        }
        let refusals = ledger
            .refusals
            .iter()
            .map(|(reason, count)| Refusal {
                reason: format!("history.{}", reason.replace(' ', "_")),
                count: *count,
            })
            .collect();
        Ok((gauges, refusals))
    }

    /// One root per database the scope owns (its retained versions and bytes) and one per
    /// database with active transactions, each read under that database's own lock.
    fn database_roots(
        &self,
        scope: &fireemu_core_session::tenancy::Scope,
    ) -> (Vec<Gauge>, Vec<RetentionRoot>, usize) {
        let mut roots = Vec::new();
        let mut live_bytes = 0u64;
        let mut historical_bytes = 0u64;
        let mut transactions = 0u64;
        let mut unreadable = 0usize;
        let mut reclaimable_bytes = 0u64;
        let now = self.now();
        for ((project, database), handle) in self.handles_of(scope) {
            let Ok((usage, stats, reclaimable)) = handle.with(|state| {
                Ok((
                    state.history_usage(),
                    state.transaction_bookkeeping_stats(),
                    state.reclaimable_history_usage(now),
                ))
            }) else {
                unreadable += 1;
                continue;
            };
            reclaimable_bytes = reclaimable_bytes.saturating_add(reclaimable.total_bytes);
            live_bytes = live_bytes.saturating_add(usage.live_document_bytes);
            historical_bytes = historical_bytes.saturating_add(usage.historical_document_bytes);
            let active = u64::try_from(stats.active).unwrap_or(u64::MAX);
            transactions = transactions.saturating_add(active);
            let id = format!("{project}/{database}");
            roots.push(RetentionRoot {
                kind: "database".to_owned(),
                id: id.clone(),
                count: usage.versions,
                bytes: usage.total_bytes,
                outstanding: false,
            });
            if active > 0 {
                roots.push(RetentionRoot {
                    kind: "transactions".to_owned(),
                    id,
                    count: active,
                    bytes: stats.conflict_ledger_bytes,
                    outstanding: true,
                });
            }
        }
        let gauges = vec![
            Gauge::logical("history.live_document_bytes", Unit::Bytes, live_bytes, None),
            Gauge::logical(
                "history.historical_document_bytes",
                Unit::Bytes,
                historical_bytes,
                None,
            ),
            Gauge::logical("transactions.active", Unit::Count, transactions, None),
            // What the next compaction would release from these databases' retained history.
            Gauge::logical(
                "history.reclaimable_bytes",
                Unit::Bytes,
                reclaimable_bytes,
                None,
            )
            .with_reclaimable(reclaimable_bytes),
        ];
        (gauges, roots, unreadable)
    }

    /// Aggregate logical Firestore history retained by the backend.
    #[must_use]
    pub fn history_usage(&self) -> HistoryUsage {
        self.history_budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .charged_global
    }

    /// Copies the databases `scope` owns, each under its own lock.
    ///
    /// Cross-database atomicity is the [`AdmissionBarrier`]'s: capture runs under the
    /// exclusive guard, so no operation is in flight and the copies all belong to the same
    /// session state.
    fn copy_databases(
        &self,
        scope: &fireemu_core_session::tenancy::Scope,
    ) -> BTreeMap<(String, String), FirestoreState> {
        self.handles_of(scope)
            .into_iter()
            .filter_map(|(key, handle)| {
                // A snapshot retains the visible state, not the MVCC history: a restore is
                // a new epoch in which nothing can ask for the history any more, so copying
                // it would only multiply the retained bytes.
                handle
                    .read(FirestoreState::visible_snapshot)
                    .map(|state| (key, state))
            })
            .collect()
    }

    /// The databases `scope` owns, plus the auto-ID generator for the default scope (it
    /// is shared by every project, so only the default session snapshots it).
    #[must_use]
    pub fn snapshot_scope(
        &self,
        scope: &fireemu_core_session::tenancy::Scope,
    ) -> FirestoreSnapshot {
        let databases = self.copy_databases(scope);
        let ids = scope
            .is_default()
            .then(|| self.ids.lock().map(|r| r.clone()).ok())
            .flatten();
        FirestoreSnapshot { databases, ids }
    }

    /// Replaces every database with `databases` (the default session's restore): a new
    /// epoch, and the streams opened before it end like on a reset.
    pub fn restore_databases(
        &self,
        databases: BTreeMap<(String, String), FirestoreState>,
    ) -> Result<(), Status> {
        self.restore_scope(
            &fireemu_core_session::tenancy::Scope::AllExcept(std::collections::BTreeSet::new()),
            &FirestoreSnapshot {
                databases,
                ids: None,
            },
        )
    }

    /// Replaces the databases `scope` owns with the snapshot's (the others stay). The
    /// default scope starts a new epoch and puts the auto-ID generator back; a project
    /// scope bumps the generations of the databases it replaced.
    pub fn restore_scope(
        &self,
        scope: &fireemu_core_session::tenancy::Scope,
        snapshot: &FirestoreSnapshot,
    ) -> Result<(), Status> {
        let restored_charges: BTreeMap<(String, String), HistoryCharge> = snapshot
            .databases
            .iter()
            .filter(|(key, _)| scope.owns_project(&key.0))
            .map(|(key, state)| {
                (
                    key.clone(),
                    HistoryCharge {
                        owner: self.history_owner(&key.0),
                        usage: state.history_usage(),
                    },
                )
            })
            .collect();
        {
            let ledger = self
                .history_budget
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !ledger.pending.is_empty() {
                return Err(Status::unavailable(
                    "Firestore history reservations are still in flight",
                ));
            }
            let removed = ledger
                .committed
                .iter()
                .filter(|((project, _), _)| scope.owns_project(project))
                .map(|(_, charge)| charge.clone());
            ledger
                .validate_replacement(removed, restored_charges.values().cloned())
                .map_err(|error| status_from_error(&error))?;
        }
        if scope.is_default() {
            self.epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        // The replaced databases are detached first: a handle retained across the restore
        // belongs to the state that was thrown away, and answers UNAVAILABLE.
        let mut touched = self.take_scope(scope);
        if let Ok(mut dbs) = self.databases.lock() {
            for (k, v) in &snapshot.databases {
                if scope.owns_project(&k.0) {
                    if !touched.contains(k) {
                        touched.push(k.clone());
                    }
                    dbs.insert(
                        k.clone(),
                        Arc::new(DatabaseEntry::restored(
                            v.clone()
                                .with_retained_version_limit(self.history_version_limit),
                        )),
                    );
                }
            }
        }
        if let Some(ids) = &snapshot.ids {
            if let Ok(mut rng) = self.ids.lock() {
                *rng = ids.clone();
            }
        }
        let mut ledger = self
            .history_budget
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let removed_keys: Vec<_> = ledger
            .committed
            .keys()
            .filter(|(project, _)| scope.owns_project(project))
            .cloned()
            .collect();
        for key in removed_keys {
            ledger.remove_committed(&key);
        }
        for (key, charge) in restored_charges {
            ledger.replace_committed(key, &charge);
        }
        self.bump_generations(&touched);
        self.announce_wipe(touched);
        Ok(())
    }

    /// Drops every database (session reset). Listen streams observe the wipe as deletes.
    pub fn reset(&self) {
        self.reset_scope(&fireemu_core_session::tenancy::Scope::AllExcept(
            std::collections::BTreeSet::new(),
        ));
    }

    /// Subscribes to commit events.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<CommitNotification> {
        self.commits.subscribe()
    }

    /// Publishes a commit: the change sink first (synchronously, inside the database
    /// critical section the caller holds), then the `Listen` broadcast.
    /// Shares the session's fault plan with this backend.
    pub fn set_faults(&self, faults: fireemu_core_session::fault::SharedFaultRegistry) {
        if let Ok(mut slot) = self.faults.lock() {
            *slot = Some(faults);
        }
    }

    /// Installs the observer told after a fault plan moved the virtual clock.
    pub fn set_clock_observer(&self, observer: Arc<dyn Fn() + Send + Sync>) {
        if let Ok(mut slot) = self.clock_observer.lock() {
            *slot = Some(observer);
        }
    }

    fn clock_moved(&self) {
        let observer = self.clock_observer.lock().ok().and_then(|o| o.clone());
        if let Some(observer) = observer {
            observer();
        }
    }

    /// The fault plan check (`fault`) for the surfaces outside this module (Listen refreshes).
    pub fn consult_faults(&self, project: &str, operation: &str) -> Result<(), Status> {
        self.fault(project, operation)
    }

    /// Applies `project`'s fault plan to `operation` (spec 18): an error action fails the
    /// request here, a delay moves the virtual clock before it runs.
    fn fault(&self, project: &str, operation: &str) -> Result<(), Status> {
        use fireemu_core_session::fault::FaultAction;
        let faults = self.faults.lock().ok().and_then(|f| f.clone());
        for action in
            fireemu_core_session::fault::decide_for(faults.as_ref(), project, operation, None, None)
        {
            match action {
                FaultAction::ReturnError { code } => {
                    return Err(Status::new(
                        grpc_code(&code),
                        format!("fault plan: {operation} returns {code}"),
                    ))
                }
                FaultAction::TransactionConflict => {
                    return Err(Status::aborted(format!(
                        "fault plan: {operation} conflicts (ABORTED)"
                    )))
                }
                FaultAction::Timeout => {
                    return Err(Status::deadline_exceeded(format!(
                        "fault plan: {operation} timed out"
                    )))
                }
                FaultAction::DropConnection => {
                    // The transport layer closes the connection instead of answering
                    // (see `DROP_CONNECTION_KEY`); the status is what a client that
                    // still gets an answer (WebChannel) sees.
                    let mut status = Status::unavailable(format!(
                        "fault plan: connection dropped during {operation}"
                    ));
                    if let Ok(v) = "1".parse() {
                        status.metadata_mut().insert(DROP_CONNECTION_KEY, v);
                    }
                    return Err(status);
                }
                FaultAction::Delay { seconds } => {
                    if let Ok(mut clock) = self.clock.lock() {
                        let _ = clock.advance(
                            fireemu_core_types::time::LogicalDuration::from_seconds(seconds.max(0)),
                        );
                    }
                    self.clock_moved();
                }
                FaultAction::Duplicate { .. }
                | FaultAction::CrashRunner
                | FaultAction::DeadLetter => {}
            }
        }
        Ok(())
    }

    /// Stages the actor of the commit about to be published (called by write guards inside
    /// the database critical section).
    ///
    /// The actor is kept in this thread's operation-local slot, not on the backend, so a
    /// commit running concurrently in another database cannot consume it (see [`Actor`]).
    #[allow(clippy::unused_self)]
    pub fn set_actor(&self, actor: Actor) {
        PENDING_ACTOR.with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut() {
                *slot = Some(actor);
            }
        });
    }

    fn take_commit_actor() -> Actor {
        PENDING_ACTOR
            .with(|slot| slot.try_borrow_mut().ok().and_then(|mut slot| slot.take()))
            .unwrap_or_else(Actor::system)
    }

    fn commit_with_events(
        &self,
        parent: &Parent,
        db: &mut FirestoreState,
        writes: &[Write],
        transaction: Option<&TransactionId>,
        now: fireemu_core_types::time::LogicalInstant,
    ) -> Result<CommitResult, Status> {
        let actor = Self::take_commit_actor();
        let sink = self
            .change_admission
            .lock()
            .map_err(|_| Status::unavailable("Functions event admission is unavailable"))?
            .clone();
        let (result, (event, publication, history)) = db
            .commit_with_history_admission(writes, transaction, now, |result, projection| {
                let history = self.reserve_history(parent, projection)?;
                let event = CommitEvent {
                    actor,
                    project: parent.project.as_str().to_owned(),
                    database: parent.database.as_str().to_owned(),
                    version: result.version.value(),
                    commit_time: Some(result.commit_time),
                    changes: result.changes.clone(),
                };
                let publication = sink.as_ref().map_or_else(
                    || Ok(Box::new(NoopCommitPublication) as Box<dyn CommitPublication>),
                    |sink| sink.reserve(&event).map_err(FirestoreError::EventAdmission),
                )?;
                Ok((event, publication, history))
            })
            .map_err(|error| status_from_error(&error))?;
        history.commit(db.history_usage());
        publication.publish();
        self.publish_committed(&event, &result);
        Ok(result)
    }

    fn publish_committed(&self, event: &CommitEvent, result: &CommitResult) {
        if let Some(sink) = self.change_sink.lock().ok().and_then(|s| s.clone()) {
            sink(event);
        }
        let changes = result
            .changes
            .iter()
            .map(|change| CommitPathChange {
                path: change.path.clone(),
                kind: match (&change.before, &change.after) {
                    (None, Some(_)) => CommitChangeKind::Created,
                    (Some(_), None) => CommitChangeKind::Deleted,
                    _ => CommitChangeKind::Updated,
                },
            })
            .collect::<Arc<[_]>>();
        let _ = self.commits.send(CommitNotification {
            project: event.project.clone(),
            database: event.database.clone(),
            version: event.version,
            reset: false,
            changes,
        });
    }

    /// Commits `writes` outside a transaction (used by the `Write` stream).
    pub fn commit_writes(
        &self,
        parent: &Parent,
        writes: &[Write],
        guard: WriteGuard<'_>,
    ) -> Result<crate::streams::WireCommit, Status> {
        self.retry_on_contention(parent, None, writes, || {
            self.fault(parent.project.as_str(), "firestore.commit")?;
            let now = self.write_time();
            let result = self.with_db(parent, |db| {
                guard(db, writes, now)?;
                let result = self.commit_with_events(parent, db, writes, None, now)?;
                Ok(result)
            })?;
            Ok(crate::streams::WireCommit::from_result(&result))
        })
    }

    /// Current version and read time of a database (Listen boundaries, resume tokens).
    pub fn snapshot(
        &self,
        parent: &Parent,
    ) -> Result<(CommitVersion, fireemu_core_types::time::LogicalInstant), Status> {
        let now = self.write_time();
        self.read_db(parent, |db| Ok((db.current_version(), db.read_time(now))))
    }

    /// Runs `f` against one consistent database snapshot and wipe generation (version,
    /// generation, read time, lookups and queries all see the same state). `Listen`
    /// refreshes use it.
    pub fn with_snapshot<T>(
        &self,
        parent: &Parent,
        f: impl FnOnce(
            &FirestoreState,
            CommitVersion,
            fireemu_core_types::time::LogicalInstant,
            u64,
        ) -> T,
    ) -> Result<T, Status> {
        let now = self.write_time();
        self.read_db(parent, |db| {
            Ok(f(
                db,
                db.current_version(),
                db.read_time(now),
                self.database_generation(parent),
            ))
        })
    }

    /// Decodes and validates a structured query through the strict gateway.
    pub fn accepted_query(
        &self,
        parent: &Parent,
        sq: &pb::StructuredQuery,
    ) -> Result<AcceptedQuery, Status> {
        let query = decode_structured_query(parent, sq).map_err(status)?;
        let indexes = self.indexes.read().map_err(|_| lock_poisoned())?;
        let empty = fireemu_core_firestore::index::IndexSet::default();
        let project_key = (
            Some(parent.project.as_str().to_owned()),
            parent.database.as_str().to_owned(),
        );
        let shared_key = (None, parent.database.as_str().to_owned());
        let database_indexes = indexes
            .get(&project_key)
            .or_else(|| indexes.get(&shared_key))
            .unwrap_or(&empty);
        self.gateway
            .validate_query_with_indexes(&query, database_indexes)
            .map_err(|rejection| rejection.to_status())
    }

    /// Atomically replaces the index catalog used by subsequent query plans.
    pub fn replace_indexes(&self, indexes: fireemu_core_firestore::index::IndexSet) {
        self.replace_database_indexes(DatabaseId::DEFAULT, indexes);
    }

    /// Atomically replaces one database's index catalog.
    pub fn replace_database_indexes(
        &self,
        database: &str,
        indexes: fireemu_core_firestore::index::IndexSet,
    ) {
        if let Ok(mut current) = self.indexes.write() {
            current.insert((None, database.to_owned()), indexes);
        }
    }

    /// Atomically replaces one routed project's database-specific index catalog.
    pub fn replace_project_database_indexes(
        &self,
        project: &str,
        database: &str,
        indexes: fireemu_core_firestore::index::IndexSet,
    ) {
        if let Ok(mut current) = self.indexes.write() {
            current.insert((Some(project.to_owned()), database.to_owned()), indexes);
        }
    }

    /// Returns a snapshot of the index catalog currently used for query planning.
    #[must_use]
    pub fn indexes(&self) -> fireemu_core_firestore::index::IndexSet {
        self.indexes_for_database(DatabaseId::DEFAULT)
    }

    /// Returns one database's current query-planning index catalog.
    #[must_use]
    pub fn indexes_for_database(&self, database: &str) -> fireemu_core_firestore::index::IndexSet {
        self.indexes.read().map_or_else(
            |error| {
                error
                    .into_inner()
                    .get(&(None, database.to_owned()))
                    .cloned()
                    .unwrap_or_default()
            },
            |indexes| {
                indexes
                    .get(&(None, database.to_owned()))
                    .cloned()
                    .unwrap_or_default()
            },
        )
    }

    /// Runs an accepted query at the latest version and returns core documents.
    pub fn run_query_latest(
        &self,
        parent: &Parent,
        query: &Query,
    ) -> Result<Vec<Document>, Status> {
        self.read_db(parent, |db| {
            db.run_query(query, None).map_err(|e| status_from_error(&e))
        })
    }

    /// `PartitionQuery`: cursor points that split a collection-group query (ordered by
    /// `__name__`, without filters, other orderings, limits or cursors) into up to
    /// `partition_count + 1` ranges of similar size, paged by `page_size` / `page_token`.
    /// The cuts are computed at one version (the `read_time` selector's, else the version
    /// current at the first page) that the page token carries, so later pages see the same
    /// partitioning whatever was written in between; the token is bound to the query.
    #[allow(clippy::too_many_lines)]
    pub fn partition_query(
        &self,
        req: &pb::PartitionQueryRequest,
    ) -> Result<pb::PartitionQueryResponse, Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        if parent.document.is_some() {
            return Err(Status::invalid_argument(
                "PartitionQuery parent must be the database (projects/{p}/databases/{d}/documents)",
            ));
        }
        let Some(pb::partition_query_request::QueryType::StructuredQuery(sq)) = &req.query_type
        else {
            return Err(Status::invalid_argument(
                "PartitionQuery requires a structured_query",
            ));
        };
        self.fault(parent.project.as_str(), "firestore.read")?;
        let query = self.accepted_query(&parent, sq)?.query;
        let name_ascending_only = query.order_by.iter().all(|o| {
            o.field.is_document_name()
                && o.direction == fireemu_core_firestore::query::Direction::Ascending
        });
        if !matches!(
            query.scope,
            fireemu_core_firestore::query::QueryScope::CollectionGroup { .. }
        ) || query.filter.is_some()
            || !name_ascending_only
            || query.limit.is_some()
            || query.offset != 0
            || query.start_at.is_some()
            || query.end_at.is_some()
        {
            return Err(Status::invalid_argument(
                "PartitionQuery requires a collection group query ordered by __name__ only (no filters, order bys, limits, offsets or cursors)",
            ));
        }
        let partition_count = usize::try_from(req.partition_count)
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| Status::invalid_argument("partition_count must be positive"))?;
        let collection_id = query
            .scope
            .collection_id()
            .expect("collection-group checked above")
            .as_str()
            .to_owned();
        if req.page_size < 0 {
            return Err(Status::invalid_argument("page_size must not be negative"));
        }
        let read_time = req.consistency_selector.as_ref().map(
            |pb::partition_query_request::ConsistencySelector::ReadTime(t)| {
                crate::encode::decode_instant(t)
            },
        );
        // Fingerprint of everything a page token must agree with, including the reset
        // epoch and the database generation: a token from before a reset or restore is
        // refused instead of resuming against unrelated history at the same version.
        let fingerprint = {
            let text = format!(
                "{}|{}|{}|{:?}|{}|{}",
                req.parent,
                collection_id,
                partition_count,
                read_time.map(fireemu_core_types::time::LogicalInstant::as_nanos),
                self.epoch(),
                self.database_generation(&parent)
            );
            text.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
                (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
            })
        };
        // The page token: `<version>:<fingerprint>:<index>`.
        let (token_version, start) = if req.page_token.is_empty() {
            (None, 0usize)
        } else {
            let parts: Vec<&str> = req.page_token.split(':').collect();
            let parsed = match parts.as_slice() {
                [v, f, i] => v
                    .parse::<u64>()
                    .ok()
                    .zip(f.parse::<u64>().ok())
                    .zip(i.parse::<usize>().ok())
                    .filter(|((_, f), _)| *f == fingerprint)
                    .map(|((v, _), i)| (v, i)),
                _ => None,
            };
            let (v, i) = parsed.ok_or_else(|| {
                Status::invalid_argument(
                    "invalid page_token (not issued for this query, count and read time, or the session was reset)",
                )
            })?;
            (Some(CommitVersion::from_value(v)), i)
        };
        let (paths, version): (Vec<DocumentPath>, CommitVersion) = self.read_db(&parent, |db| {
            let version = match (token_version, read_time) {
                (Some(v), _) => v,
                (None, Some(t)) => db.version_at(t),
                (None, None) => db.current_version(),
            };
            if version > db.current_version() {
                return Err(Status::invalid_argument("invalid page_token"));
            }
            Ok((
                db.collection_group_partition_paths_at(
                    query.scope.parent(),
                    &collection_id,
                    version,
                    partition_count,
                ),
                version,
            ))
        })?;
        let cursors: Vec<pb::Cursor> = paths
            .into_iter()
            .map(|path| pb::Cursor {
                values: vec![pb::Value {
                    value_type: Some(pb::value::ValueType::ReferenceValue(path.resource_name())),
                }],
                before: true,
            })
            .collect();
        if start > cursors.len() {
            return Err(Status::invalid_argument("invalid page_token"));
        }
        let page = usize::try_from(req.page_size)
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or(cursors.len().max(1));
        let end = (start + page).min(cursors.len());
        Ok(pb::PartitionQueryResponse {
            partitions: cursors[start..end].to_vec(),
            next_page_token: if end < cursors.len() {
                format!("{}:{fingerprint}:{end}", version.value())
            } else {
                String::new()
            },
        })
    }

    /// Current logical time of the backend clock.
    pub fn now(&self) -> fireemu_core_types::time::LogicalInstant {
        self.clock
            .lock()
            .map(|c| c.now())
            .unwrap_or(fireemu_core_types::time::LogicalInstant::UNIX_EPOCH)
    }

    /// Timestamp supplied to one Firestore write attempt.
    fn write_time(&self) -> fireemu_core_types::time::LogicalInstant {
        if !self.wall_clock_write_time {
            return self.now();
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|duration| i128::try_from(duration.as_nanos()).ok())
            .map_or(
                fireemu_core_types::time::LogicalInstant::UNIX_EPOCH,
                fireemu_core_types::time::LogicalInstant::from_nanos,
            )
    }

    /// Reads a database without taking a session admission: for callers that already
    /// hold one (a Storage request evaluating `firestore.get()` in its rules). `None` when
    /// the database does not exist yet or the lock is poisoned.
    pub fn read_unadmitted<T>(
        &self,
        parent: &Parent,
        f: impl FnOnce(&FirestoreState) -> T,
    ) -> Option<T> {
        // The catalog lock is dropped before the database's own lock is taken.
        let handle = {
            let dbs = self.databases.lock().ok()?;
            DatabaseHandle(dbs.get(&database_key(parent))?.clone())
        };
        handle.read(f)
    }

    /// The handle of one database, creating its entry when the database does not exist
    /// yet. The catalog lock is held only for this lookup.
    ///
    /// Operations through the returned handle take no session admission and are not
    /// coordinated with a reset beyond the handle's own detachment; request surfaces
    /// should use [`LocalBackend`]'s operations, which admit first.
    pub fn database_handle(&self, parent: &Parent) -> Result<DatabaseHandle, Status> {
        let mut dbs = self.databases.lock().map_err(|_| lock_poisoned())?;
        // A new database refuses production's limits only when the gateway enforces limits
        // (the `strict` profile); under `firebase` it admits what the official emulator
        // admits.
        let scope = if self.gateway.enforce_limits {
            fireemu_core_firestore::store::LimitScope::Production
        } else {
            fireemu_core_firestore::store::LimitScope::OfficialEmulator
        };
        Ok(DatabaseHandle(
            dbs.entry(database_key(parent))
                .or_insert_with(|| {
                    // Transaction ids start at a seeded offset: a token names one transaction
                    // and cannot be guessed from how many the database has begun.
                    let offset = self
                        .transaction_ids
                        .lock()
                        .map(|mut ids| ids.next_u64() >> 2)
                        .unwrap_or(0);
                    Arc::new(DatabaseEntry::restored(
                        FirestoreState::with_limit_scope(scope)
                            .with_retained_version_limit(self.history_version_limit)
                            .with_transaction_id_offset(offset),
                    ))
                })
                .clone(),
        ))
    }

    fn with_db<T>(
        &self,
        parent: &Parent,
        f: impl FnOnce(&mut FirestoreState) -> Result<T, Status>,
    ) -> Result<T, Status> {
        // Admitted for the whole critical section: a reset waits for it and nothing runs
        // against a half-reset session.
        let _admitted = self.barrier.admit();
        // The catalog is locked only for the lookup; the operation then runs under this
        // database's own lock, so other databases are free to make progress.
        let handle = self.database_handle(parent)?;
        // Attribution is confined to this operation: whatever a previous one left on this
        // thread is dropped here, and whatever this one stages is dropped on the way out.
        let _actor = ActorScope::enter();
        let releases_before = handle.release_marker();
        let outcome = handle.with(|state| {
            let outcome = f(state);
            // Core operations may legally release an expired retention root even when the
            // requested operation returns an error. Reconcile before releasing this database
            // lock so a later same-database commit cannot be overwritten by stale accounting.
            self.reconcile_history(parent, state.history_usage());
            outcome
        });
        if handle.release_marker() != releases_before {
            self.release_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.release_notify.notify_waiters();
        }
        outcome
    }

    fn read_db<T>(
        &self,
        parent: &Parent,
        f: impl FnOnce(&FirestoreState) -> Result<T, Status>,
    ) -> Result<T, Status> {
        let _admitted = self.barrier.admit();
        let handle = self.database_handle(parent)?;
        handle.read_status(f)
    }

    fn auto_id(&self) -> String {
        let mut rng = match self.ids.lock() {
            Ok(r) => r,
            Err(p) => p.into_inner(),
        };
        auto_id_from(&mut rng)
    }

    /// Wire token for a transaction: the handle plus a tag binding it to its database, so a
    /// token issued by one database is rejected by another.
    fn token(&self, parent: &Parent, id: &TransactionId) -> Vec<u8> {
        let mut bytes = encode_transaction(id);
        bytes.extend_from_slice(&database_tag(parent).to_be_bytes());
        let mac = self.token_mac(&bytes);
        bytes.extend_from_slice(&mac);
        bytes
    }

    /// The authenticator of a token's handle and database tag: the first 8 bytes of
    /// SHA-256 over the backend's token key and those bytes.
    fn token_mac(&self, handle_and_tag: &[u8]) -> [u8; 8] {
        let mut digest = fireemu_core_types::hash::Sha256::new();
        digest.update(&self.token_key);
        digest.update(handle_and_tag);
        let full = digest.finalize();
        let mut mac = [0_u8; 8];
        mac.copy_from_slice(&full[..8]);
        mac
    }

    /// The transaction a wire token names, if any (public form of the token check).
    pub fn txn_of(&self, parent: &Parent, bytes: &[u8]) -> Result<Option<TransactionId>, Status> {
        self.txn(parent, bytes)
    }

    fn txn(&self, parent: &Parent, bytes: &[u8]) -> Result<Option<TransactionId>, Status> {
        if bytes.is_empty() {
            return Ok(None);
        }
        // [handle][database tag: 8][authenticator: 8]; a token this backend did not issue,
        // for this database, is invalid whatever else it decodes to.
        let (authenticated, mac) = bytes.split_at(bytes.len().saturating_sub(8));
        let expected = self.token_mac(authenticated);
        let authentic = mac.len() == 8
            && mac
                .iter()
                .zip(expected.iter())
                .fold(0_u8, |difference, (left, right)| {
                    difference | (left ^ right)
                })
                == 0;
        if !authentic {
            return Err(Status::invalid_argument("Invalid transaction."));
        }
        let (handle, tag) = authenticated.split_at(authenticated.len().saturating_sub(8));
        let tag: Option<[u8; 8]> = tag.try_into().ok();
        if tag.map(u64::from_be_bytes) != Some(database_tag(parent)) {
            return Err(Status::invalid_argument(
                "transaction token does not belong to this database",
            ));
        }
        decode_transaction(handle).map(Some).map_err(status)
    }

    fn required_txn(&self, parent: &Parent, bytes: &[u8]) -> Result<TransactionId, Status> {
        self.txn(parent, bytes)?
            .ok_or_else(|| Status::invalid_argument("missing transaction"))
    }

    /// Rejects document names outside the request's database.
    pub fn check_database(parent: &Parent, name: &str) -> Result<DocumentPath, Status> {
        let path = decode_document_name(name).map_err(status)?;
        Self::check_database_path(parent, &path)?;
        Ok(path)
    }

    fn check_database_path(parent: &Parent, path: &DocumentPath) -> Result<(), Status> {
        if path.project() != &parent.project || path.database() != &parent.database {
            let name = path.resource_name();
            return Err(Status::invalid_argument(format!(
                "document {name} does not belong to database projects/{}/databases/{}",
                parent.project.as_str(),
                parent.database.as_str()
            )));
        }
        Ok(())
    }

    /// Validates a `read_time` selector: a well-formed, microsecond-precision timestamp that
    /// is not in the future and lies within the retention window
    /// ([`READ_TIME_RETENTION_SECONDS`]).
    /// The latest instant a `read_time` may name for `parent`'s database: the clock, or the
    /// last commit time when commits were aligned past a clock that did not move (a read at
    /// the commit time a commit just reported is valid in production).
    fn read_time_horizon(
        &self,
        parent: &Parent,
        now: fireemu_core_types::time::LogicalInstant,
    ) -> fireemu_core_types::time::LogicalInstant {
        self.database_handle(parent)
            .ok()
            .and_then(|handle| handle.read(|db| db.read_time(now)))
            .unwrap_or(now)
    }

    fn read_time_selector(
        &self,
        ts: &prost_types::Timestamp,
        now: fireemu_core_types::time::LogicalInstant,
        horizon: fireemu_core_types::time::LogicalInstant,
    ) -> Result<fireemu_core_types::time::LogicalInstant, Status> {
        if !(0..1_000_000_000).contains(&ts.nanos) {
            return Err(Status::invalid_argument("read_time: nanos out of range"));
        }
        if ts.nanos % 1000 != 0 {
            return Err(Status::invalid_argument(
                "read_time must be a microsecond precision timestamp",
            ));
        }
        let at = crate::encode::decode_instant(ts);
        if at.as_nanos() > horizon.max(now).as_nanos() {
            return Err(Status::invalid_argument(
                "read_time must not be in the future",
            ));
        }
        // Production answers a read_time before the database existed with INVALID_ARGUMENT and
        // one inside the database's life but outside the retention window with
        // FAILED_PRECONDITION, in these words (conformance/firestore-production-matrix.json).
        if at < self.created_at {
            return Err(Status::invalid_argument(
                "The requested 'read_time' cannot be before database creation time.",
            ));
        }
        let oldest = now.as_nanos() - i128::from(READ_TIME_RETENTION_SECONDS) * 1_000_000_000;
        if at.as_nanos() < oldest {
            return Err(Status::failed_precondition(
                "The requested 'read_time' is too old.",
            ));
        }
        Ok(at)
    }

    fn retained_read_version(
        db: &FirestoreState,
        at: fireemu_core_types::time::LogicalInstant,
    ) -> Result<CommitVersion, Status> {
        db.version_at_retained(at).ok_or_else(|| {
            Status::failed_precondition(
                "The requested 'read_time' is no longer retained by this database.",
            )
        })
    }

    /// Starts the transaction described by `new_transaction` options: read-only unless a
    /// read-write mode is given (Firestore's default for `new_transaction`), at the
    /// `read_time` snapshot when one is requested.
    fn new_transaction(
        &self,
        parent: &Parent,
        db: &mut FirestoreState,
        opts: &pb::TransactionOptions,
        now: fireemu_core_types::time::LogicalInstant,
    ) -> Result<TransactionId, Status> {
        match &opts.mode {
            Some(pb::transaction_options::Mode::ReadWrite(read_write)) => {
                if read_write.retry_transaction.is_empty() {
                    db.begin_transaction(false, now)
                } else {
                    let previous = self.required_txn(parent, &read_write.retry_transaction)?;
                    db.retry_transaction(&previous, now)
                }
            }
            Some(pb::transaction_options::Mode::ReadOnly(ro)) => match &ro.consistency_selector {
                Some(pb::transaction_options::read_only::ConsistencySelector::ReadTime(ts)) => {
                    let at = self.read_time_selector(ts, now, db.read_time(now))?;
                    db.begin_transaction_at(at, now)
                }
                None => db.begin_transaction(true, now),
            },
            None => db.begin_transaction(true, now),
        }
        .map_err(|e| status_from_error(&e))
    }

    fn select_snapshot(
        &self,
        parent: &Parent,
        db: &mut FirestoreState,
        selector: SnapshotSelector<'_>,
        now: fireemu_core_types::time::LogicalInstant,
    ) -> Result<SelectedSnapshot, Status> {
        match selector {
            SnapshotSelector::Transaction(bytes) => {
                let transaction = self.required_txn(parent, bytes)?;
                db.touch_transaction(&transaction, now)
                    .map_err(|error| status_from_error(&error))?;
                Ok(SelectedSnapshot {
                    transaction: Some(transaction),
                    report: Vec::new(),
                    read_at: None,
                })
            }
            SnapshotSelector::NewTransaction(options) => {
                let transaction = self.new_transaction(parent, db, options, now)?;
                let report = self.token(parent, &transaction);
                Ok(SelectedSnapshot {
                    transaction: Some(transaction),
                    report,
                    read_at: None,
                })
            }
            SnapshotSelector::ReadTime(read_at) => Ok(SelectedSnapshot {
                transaction: None,
                report: Vec::new(),
                read_at: Some(read_at),
            }),
            SnapshotSelector::Latest => Ok(SelectedSnapshot {
                transaction: None,
                report: Vec::new(),
                read_at: None,
            }),
        }
    }

    /// Runs one consistency-selected read and forgets a transaction minted for a response the
    /// client never receives. Existing transaction selectors are never abandoned here.
    fn with_selected_snapshot<T>(
        &self,
        parent: &Parent,
        selector: SnapshotSelector<'_>,
        now: fireemu_core_types::time::LogicalInstant,
        run: impl FnOnce(&mut SnapshotAccess<'_>) -> Result<T, Status>,
    ) -> Result<T, Status> {
        match selector {
            SnapshotSelector::ReadTime(read_at) => self.read_db(parent, |db| {
                run(&mut SnapshotAccess {
                    state: SnapshotState::Shared(db),
                    selected: SelectedSnapshot {
                        transaction: None,
                        report: Vec::new(),
                        read_at: Some(read_at),
                    },
                    query_execution_id: None,
                    complete_query_execution: false,
                })
            }),
            SnapshotSelector::Latest => self.read_db(parent, |db| {
                run(&mut SnapshotAccess {
                    state: SnapshotState::Shared(db),
                    selected: SelectedSnapshot {
                        transaction: None,
                        report: Vec::new(),
                        read_at: None,
                    },
                    query_execution_id: None,
                    complete_query_execution: false,
                })
            }),
            SnapshotSelector::Transaction(_) | SnapshotSelector::NewTransaction(_) => {
                self.with_db(parent, |db| {
                    let selected = self.select_snapshot(parent, db, selector, now)?;
                    let mut access = SnapshotAccess {
                        state: SnapshotState::Exclusive(db),
                        selected,
                        query_execution_id: None,
                        complete_query_execution: false,
                    };
                    let outcome = run(&mut access);
                    if outcome.is_err() && !access.selected.report.is_empty() {
                        if let (SnapshotState::Exclusive(db), Some(transaction)) =
                            (&mut access.state, &access.selected.transaction)
                        {
                            db.abandon_transaction(transaction);
                        }
                    }
                    outcome
                })
            }
        }
    }

    /// `GetDocument` as a snapshot, authorized by `guard` inside the critical section that
    /// reads it (then [`DocumentSnapshot::into_response`]).
    pub fn get_document_snapshot(
        &self,
        req: &pb::GetDocumentRequest,
        guard: ReadGuard<'_>,
    ) -> Result<DocumentSnapshot, Status> {
        let path = decode_document_name(&req.name).map_err(status)?;
        let parent = parse_parent(&req.name).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.read")?;
        let now = self.write_time();
        let (txn, read_at) = match &req.consistency_selector {
            Some(pb::get_document_request::ConsistencySelector::Transaction(t)) => {
                (Some(self.required_txn(&parent, t)?), None)
            }
            Some(pb::get_document_request::ConsistencySelector::ReadTime(ts)) => (
                None,
                Some(self.read_time_selector(ts, now, self.read_time_horizon(&parent, now))?),
            ),
            None => (None, None),
        };
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        let document = if let Some(txn) = txn {
            self.with_db(&parent, |db| {
                db.touch_transaction(&txn, now)
                    .map_err(|e| status_from_error(&e))?;
                let version = db
                    .transaction_read_version(&txn)
                    .map_err(|e| status_from_error(&e))?;
                let document = db.get_at(&path, version).cloned();
                guard(
                    db,
                    Some(version),
                    ReadCheck::Document {
                        path: &path,
                        snapshot: document.as_ref(),
                    },
                )?;
                // The read joins the transaction's read set only once it is authorized.
                db.record_transaction_read(&txn, &path, document.as_ref())
                    .map_err(|e| status_from_error(&e))?;
                Ok(document)
            })?
        } else {
            self.read_db(&parent, |db| {
                let (document, version) = if let Some(at) = read_at {
                    let version = Self::retained_read_version(db, at)?;
                    (db.get_at(&path, version).cloned(), Some(version))
                } else {
                    (db.get(&path).cloned(), None)
                };
                guard(
                    db,
                    version,
                    ReadCheck::Document {
                        path: &path,
                        snapshot: document.as_ref(),
                    },
                )?;
                Ok(document)
            })?
        };
        Ok(DocumentSnapshot {
            path,
            document,
            mask,
        })
    }

    /// `GetDocument`.
    pub fn get_document(
        &self,
        req: &pb::GetDocumentRequest,
        guard: ReadGuard<'_>,
    ) -> Result<pb::Document, Status> {
        self.get_document_snapshot(req, guard)?.into_response()
    }

    /// `BatchGetDocuments`: returns the items and the transaction to report (new or given);
    /// every item is authorized by `guard` against the snapshot it is read from.
    pub fn batch_get_documents(
        &self,
        req: &pb::BatchGetDocumentsRequest,
        guard: ReadGuard<'_>,
    ) -> Result<BatchGetOutcome, Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.read")?;
        let now = self.write_time();
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        let paths = req
            .documents
            .iter()
            .map(|name| Self::check_database(&parent, name))
            .collect::<Result<Vec<_>, _>>()?;
        let selector = match &req.consistency_selector {
            Some(pb::batch_get_documents_request::ConsistencySelector::Transaction(bytes)) => {
                SnapshotSelector::Transaction(bytes)
            }
            Some(pb::batch_get_documents_request::ConsistencySelector::NewTransaction(options)) => {
                SnapshotSelector::NewTransaction(options)
            }
            Some(pb::batch_get_documents_request::ConsistencySelector::ReadTime(ts)) => {
                SnapshotSelector::ReadTime(self.read_time_selector(
                    ts,
                    now,
                    self.read_time_horizon(&parent, now),
                )?)
            }
            None => SnapshotSelector::Latest,
        };
        self.with_selected_snapshot(&parent, selector, now, |access| {
            let read_time = access.read_time(now)?;
            let version = access.version()?;
            // Every document is read from the snapshot first, then the whole batch is
            // authorized, and only then do the reads join the transaction's read set.
            let reads: Vec<(DocumentPath, Option<Document>)> = paths
                .iter()
                .map(|path| {
                    let doc = match version {
                        Some(v) => access.db().get_at(path, v).cloned(),
                        None => access.db().get(path).cloned(),
                    };
                    (path.clone(), doc)
                })
                .collect();
            guard(access.db(), version, ReadCheck::Documents(&reads))?;
            access.record_document_reads(&reads)?;
            // Production answers the found documents in name order and the missing names
            // after them, whatever order the request listed them in.
            let mut items: Vec<BatchGetItem> = req
                .documents
                .iter()
                .zip(reads)
                .map(|(name, (_, doc))| match doc {
                    Some(d) => BatchGetItem::Found(d),
                    None => BatchGetItem::Missing(name.clone()),
                })
                .collect();
            items.sort_by_cached_key(|item| match item {
                BatchGetItem::Found(d) => (0u8, d.path.resource_name()),
                BatchGetItem::Missing(name) => (1u8, name.clone()),
            });
            Ok(BatchGetOutcome {
                items,
                transaction: access.report().to_vec(),
                read_time,
                mask: mask.clone(),
            })
        })
    }

    /// Current document (latest version) without any transaction bookkeeping.
    pub fn current_document(
        &self,
        parent: &Parent,
        path: &DocumentPath,
    ) -> Result<Option<Document>, Status> {
        self.read_db(parent, |db| Ok(db.get(path).cloned()))
    }

    /// Result of `write` against the current state without publishing it.
    pub fn preview_write(
        &self,
        parent: &Parent,
        write: &Write,
    ) -> Result<Option<Document>, Status> {
        let now = self.write_time();
        self.with_db(parent, |db| {
            db.preview_write(write, now)
                .map_err(|e| status_from_error(&e))
        })
    }

    /// Decodes a `CreateDocument` request into its write (the document ID is fixed here, so
    /// that authorization and execution see the same path).
    pub fn plan_create(&self, req: &pb::CreateDocumentRequest) -> Result<(Parent, Write), Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        let collection = CollectionId::try_new(req.collection_id.as_str())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let document_id = if req.document_id.is_empty() {
            self.auto_id()
        } else {
            req.document_id.clone()
        };
        DocumentId::try_new(document_id.as_str())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let relative = match &parent.document {
            Some(p) => format!("{}/{}/{}", p.relative(), collection.as_str(), document_id),
            None => format!("{}/{}", collection.as_str(), document_id),
        };
        let path = DocumentPath::parse(&parent.project, &parent.database, &relative)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let fields = decode_fields(
            &req.document
                .as_ref()
                .map(|d| d.fields.clone())
                .unwrap_or_default(),
        )
        .map_err(status)?;
        let write = Write {
            op: WriteOp::Set {
                path,
                fields,
                update_mask: None,
            },
            precondition: Some(Precondition::Exists(false)),
            transforms: vec![],
        };
        Ok((parent, write))
    }

    /// `CreateDocument`.
    pub fn create_document(&self, req: &pb::CreateDocumentRequest) -> Result<pb::Document, Status> {
        self.create_document_with(req, &allow_all)
    }

    /// Executes a single planned write and returns the resulting document.
    pub fn execute_planned(
        &self,
        parent: &Parent,
        write: &Write,
        mask: Option<&pb::DocumentMask>,
    ) -> Result<pb::Document, Status> {
        self.execute_planned_with(parent, write, mask, &allow_all)
    }

    /// Executes a single planned write; `guard` runs inside the database critical section
    /// (Security Rules) right before the commit.
    pub fn execute_planned_with(
        &self,
        parent: &Parent,
        write: &Write,
        mask: Option<&pb::DocumentMask>,
        guard: WriteGuard<'_>,
    ) -> Result<pb::Document, Status> {
        self.retry_on_contention(parent, None, std::slice::from_ref(write), || {
            self.execute_planned_once(parent, write, mask, guard)
        })
    }

    /// One attempt at a planned write: no waiting for lock contention.
    pub fn execute_planned_once(
        &self,
        parent: &Parent,
        write: &Write,
        mask: Option<&pb::DocumentMask>,
        guard: WriteGuard<'_>,
    ) -> Result<pb::Document, Status> {
        self.fault(parent.project.as_str(), "firestore.commit")?;
        let mask = decode_mask(mask).map_err(status)?;
        let path = write.op.path().clone();
        let now = self.write_time();
        let doc = self.with_db(parent, |db| {
            guard(db, std::slice::from_ref(write), now)?;
            self.commit_with_events(parent, db, std::slice::from_ref(write), None, now)?;
            let doc = db
                .get(&path)
                .map(|document| encode_masked(document, mask.as_deref()))
                .ok_or_else(|| Status::internal("document vanished after commit"))?;
            Ok(doc)
        })?;
        Ok(doc)
    }

    /// Plans, authorizes and publishes a create under one database critical section. An auto-ID
    /// is serialized with the source commit and restored when any later gate refuses it.
    pub fn create_document_with(
        &self,
        req: &pb::CreateDocumentRequest,
        guard: WriteGuard<'_>,
    ) -> Result<pb::Document, Status> {
        let (parent, lease) = Self::plan_create_lease(req)?;
        self.retry_on_contention(&parent, None, std::slice::from_ref(&lease), || {
            self.create_document_once(req, guard)
        })
    }

    /// The database a create addresses and a stand-in write at the target collection (the
    /// document id may not exist yet), which names the same locked ranges the real write
    /// would, for lease bookkeeping.
    pub fn plan_create_lease(req: &pb::CreateDocumentRequest) -> Result<(Parent, Write), Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        let collection = CollectionId::try_new(req.collection_id.as_str())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let document_id = if req.document_id.is_empty() {
            "_"
        } else {
            req.document_id.as_str()
        };
        let relative = match &parent.document {
            Some(path) => format!("{}/{}/{document_id}", path.relative(), collection.as_str()),
            None => format!("{}/{document_id}", collection.as_str()),
        };
        let path = DocumentPath::parse(&parent.project, &parent.database, &relative)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        Ok((
            parent,
            Write {
                op: WriteOp::Delete { path },
                precondition: None,
                transforms: Vec::new(),
            },
        ))
    }

    /// One attempt at a create: no waiting for lock contention.
    pub fn create_document_once(
        &self,
        req: &pb::CreateDocumentRequest,
        guard: WriteGuard<'_>,
    ) -> Result<pb::Document, Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        let collection = CollectionId::try_new(req.collection_id.as_str())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let fields = decode_fields(
            &req.document
                .as_ref()
                .map(|document| document.fields.clone())
                .unwrap_or_default(),
        )
        .map_err(status)?;
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.commit")?;
        let now = self.write_time();
        self.with_db(&parent, |db| {
            let generated_id = req.document_id.is_empty();
            let mut rng = generated_id.then(|| {
                self.ids
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
            });
            let checkpoint = rng.as_deref().cloned();
            let document_id = if generated_id {
                auto_id_from(rng.as_deref_mut().expect("generated IDs hold the RNG lock"))
            } else {
                req.document_id.clone()
            };
            DocumentId::try_new(document_id.as_str())
                .map_err(|error| Status::invalid_argument(error.to_string()))?;
            let relative = match &parent.document {
                Some(path) => format!(
                    "{}/{}/{}",
                    path.relative(),
                    collection.as_str(),
                    document_id
                ),
                None => format!("{}/{}", collection.as_str(), document_id),
            };
            let path = DocumentPath::parse(&parent.project, &parent.database, &relative)
                .map_err(|error| Status::invalid_argument(error.to_string()))?;
            let write = Write {
                op: WriteOp::Set {
                    path: path.clone(),
                    fields: fields.clone(),
                    update_mask: None,
                },
                precondition: Some(Precondition::Exists(false)),
                transforms: Vec::new(),
            };
            let result = (|| {
                guard(db, std::slice::from_ref(&write), now)?;
                self.commit_with_events(&parent, db, std::slice::from_ref(&write), None, now)?;
                db.get(&path)
                    .map(|document| encode_masked(document, mask.as_deref()))
                    .ok_or_else(|| Status::internal("document vanished after commit"))
            })();
            if result.is_err() {
                if let (Some(rng), Some(checkpoint)) = (rng.as_deref_mut(), checkpoint) {
                    *rng = checkpoint;
                }
            }
            result
        })
    }

    /// Decodes an `UpdateDocument` request into its write.
    pub fn plan_update(req: &pb::UpdateDocumentRequest) -> Result<(Parent, Write), Status> {
        let doc = req
            .document
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing document"))?;
        let path = decode_document_name(&doc.name).map_err(status)?;
        let parent = parse_parent(&doc.name).map_err(status)?;
        let write = Write {
            op: WriteOp::Set {
                path,
                fields: decode_fields(&doc.fields).map_err(status)?,
                update_mask: decode_mask(req.update_mask.as_ref()).map_err(status)?,
            },
            precondition: decode_precondition(req.current_document.as_ref()).map_err(status)?,
            transforms: vec![],
        };
        Ok((parent, write))
    }

    /// `UpdateDocument`.
    pub fn update_document(&self, req: &pb::UpdateDocumentRequest) -> Result<pb::Document, Status> {
        let (parent, write) = Self::plan_update(req)?;
        self.execute_planned(&parent, &write, req.mask.as_ref())
    }

    /// Decodes a `DeleteDocument` request into its write.
    pub fn plan_delete(req: &pb::DeleteDocumentRequest) -> Result<(Parent, Write), Status> {
        let path = decode_document_name(&req.name).map_err(status)?;
        let parent = parse_parent(&req.name).map_err(status)?;
        let write = Write {
            op: WriteOp::Delete { path },
            precondition: decode_precondition(req.current_document.as_ref()).map_err(status)?,
            transforms: vec![],
        };
        Ok((parent, write))
    }

    /// `DeleteDocument`.
    pub fn delete_document(&self, req: &pb::DeleteDocumentRequest) -> Result<(), Status> {
        self.delete_document_with(req, &allow_all)
    }

    /// `DeleteDocument` with a write guard.
    pub fn delete_document_with(
        &self,
        req: &pb::DeleteDocumentRequest,
        guard: WriteGuard<'_>,
    ) -> Result<(), Status> {
        let (parent, write) = Self::plan_delete(req)?;
        self.retry_on_contention(&parent, None, std::slice::from_ref(&write), || {
            self.delete_document_once(req, guard)
        })
    }

    /// One attempt at a delete: no waiting for lock contention.
    pub fn delete_document_once(
        &self,
        req: &pb::DeleteDocumentRequest,
        guard: WriteGuard<'_>,
    ) -> Result<(), Status> {
        let (parent, write) = Self::plan_delete(req)?;
        self.fault(parent.project.as_str(), "firestore.commit")?;
        let now = self.write_time();
        self.with_db(&parent, |db| {
            guard(db, std::slice::from_ref(&write), now)?;
            self.commit_with_events(&parent, db, std::slice::from_ref(&write), None, now)?;
            Ok(())
        })
    }

    /// Decodes the writes of a `Commit` request (also used for authorization).
    pub fn plan_commit(req: &pb::CommitRequest) -> Result<(Parent, Vec<Write>), Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        let writes = req
            .writes
            .iter()
            .map(decode_write)
            .collect::<Result<Vec<_>, _>>()
            .map_err(status)?;
        for w in &writes {
            Self::check_database_path(&parent, w.op.path())?;
        }
        Ok((parent, writes))
    }

    /// Decodes the writes of a `BatchWrite` request that are well-formed (malformed writes
    /// are reported per write by [`Self::batch_write`]).
    pub fn plan_batch_write(req: &pb::BatchWriteRequest) -> Result<(Parent, Vec<Write>), Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        let writes = req
            .writes
            .iter()
            .filter_map(|w| decode_write(w).ok())
            .filter(|w| Self::check_database_path(&parent, w.op.path()).is_ok())
            .collect();
        Ok((parent, writes))
    }

    /// `BeginTransaction`.
    pub fn begin_transaction(&self, req: &pb::BeginTransactionRequest) -> Result<Vec<u8>, Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.beginTransaction")?;
        // BeginTransaction without options is read-write (unlike `new_transaction`).
        let now = self.write_time();
        self.with_db(&parent, |db| {
            let id = match req.options.as_ref().and_then(|o| o.mode.as_ref()) {
                Some(pb::transaction_options::Mode::ReadOnly(ro)) => {
                    match &ro.consistency_selector {
                        Some(
                            pb::transaction_options::read_only::ConsistencySelector::ReadTime(ts),
                        ) => {
                            let at = self.read_time_selector(ts, now, db.read_time(now))?;
                            db.begin_transaction_at(at, now)
                        }
                        None => db.begin_transaction(true, now),
                    }
                }
                Some(pb::transaction_options::Mode::ReadWrite(read_write))
                    if !read_write.retry_transaction.is_empty() =>
                {
                    let previous = self.required_txn(&parent, &read_write.retry_transaction)?;
                    db.retry_transaction(&previous, now)
                }
                _ => db.begin_transaction(false, now),
            }
            .map_err(|e| status_from_error(&e))?;
            Ok(self.token(&parent, &id))
        })
    }

    /// `Commit`.
    pub fn commit(&self, req: &pb::CommitRequest) -> Result<pb::CommitResponse, Status> {
        self.commit_with(req, &allow_all)
    }

    /// `Commit` with a write guard. A commit that collides with the locks of an active
    /// read-write transaction waits for a release up to the configured contention wait
    /// (blocking the calling thread; the REST surface runs on a blocking thread) and is then
    /// refused the way production refuses it.
    pub fn commit_with(
        &self,
        req: &pb::CommitRequest,
        guard: WriteGuard<'_>,
    ) -> Result<pb::CommitResponse, Status> {
        let (parent, writes) = Self::plan_commit(req)?;
        let own = self.txn(&parent, &req.transaction)?;
        self.retry_on_contention(&parent, own.as_ref(), &writes, || {
            self.commit_once(req, guard)
        })
    }

    /// One attempt at `Commit`: no waiting for lock contention.
    pub fn commit_once(
        &self,
        req: &pb::CommitRequest,
        guard: WriteGuard<'_>,
    ) -> Result<pb::CommitResponse, Status> {
        let (parent, writes) = Self::plan_commit(req)?;
        self.fault(parent.project.as_str(), "firestore.commit")?;
        let txn = self.txn(&parent, &req.transaction)?;
        let now = self.write_time();
        let result = self.with_db(&parent, |db| {
            guard(db, &writes, now)?;
            let result = self.commit_with_events(&parent, db, &writes, txn.as_ref(), now)?;
            Ok(result)
        })?;
        Ok(encode_commit(&result))
    }

    /// Runs `attempt` until it is not refused for lock contention. A refusal runs the lease
    /// bookkeeping (a holder that kept writers blocked while idle for the lock lease is rolled
    /// back), then waits for a transaction of `parent`'s database to finish, up to the
    /// contention wait, and tries again; past the deadline, or once the refused transaction
    /// itself is gone (the deadlock victim), the refusal is returned. `lease_writes` names
    /// the documents the attempt writes, for the bookkeeping.
    pub fn retry_on_contention<T>(
        &self,
        parent: &Parent,
        own: Option<&TransactionId>,
        lease_writes: &[Write],
        mut attempt: impl FnMut() -> Result<T, Status>,
    ) -> Result<T, Status> {
        let deadline = std::time::Instant::now() + self.contention_wait;
        loop {
            let handle = self.database_handle(parent)?;
            let marker = handle.release_marker();
            match attempt() {
                Err(status) if Self::is_contention(&status) => {
                    let released = self.expire_lock_leases(&handle, lease_writes, own);
                    if NO_WAIT.with(std::cell::Cell::get) {
                        // A blocking-pool thread never waits here; the caller does.
                        CONTENDED.with(|slot| slot.set(true));
                        if released {
                            continue;
                        }
                        return Err(status);
                    }
                    if !Self::should_wait_for_release(&handle, own, deadline) {
                        return Err(status);
                    }
                    if !released {
                        handle.wait_for_release(marker, deadline);
                    }
                }
                outcome => return outcome,
            }
        }
    }

    /// Runs `f` with lock-contention waits disabled on this thread and reports whether a
    /// write was refused for contention: for a blocking-pool thread that must not hold its
    /// slot while waiting. The caller then waits with [`Self::await_any_release`] and repeats.
    pub fn without_waiting<T>(f: impl FnOnce() -> T) -> (T, bool) {
        let previous = NO_WAIT.with(|slot| slot.replace(true));
        CONTENDED.with(|slot| slot.set(false));
        let value = f();
        let contended = CONTENDED.with(|slot| slot.replace(false));
        NO_WAIT.with(|slot| slot.set(previous));
        (value, contended)
    }

    /// How many transactions have finished across every database so far.
    #[must_use]
    pub fn release_count(&self) -> u64 {
        self.release_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Waits, without blocking a thread, until a transaction of any database finishes after
    /// `seen` was read or until `deadline`; `true` when one finished.
    pub async fn await_any_release(&self, seen: u64, deadline: std::time::Instant) -> bool {
        self.await_any_release_after_registration(seen, deadline, || {})
            .await
    }

    /// Waits for a release while registering the notification before checking the generation.
    /// The probe is a deterministic test seam for the notification/check race.
    async fn await_any_release_after_registration(
        &self,
        seen: u64,
        deadline: std::time::Instant,
        mut after_registration: impl FnMut(),
    ) -> bool {
        loop {
            let now = std::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let notified = self.release_notify.notified();
            after_registration();
            if self.release_count() != seen {
                return true;
            }
            if tokio::time::timeout(deadline - now, notified)
                .await
                .is_err()
            {
                return self.release_count() != seen;
            }
        }
    }

    /// [`Self::retry_on_contention`] for an async caller: the wait runs off the runtime.
    pub async fn retry_on_contention_async<T>(
        &self,
        parent: &Parent,
        own: Option<&TransactionId>,
        lease_writes: &[Write],
        mut attempt: impl FnMut() -> Result<T, Status>,
    ) -> Result<T, Status> {
        let deadline = std::time::Instant::now() + self.contention_wait;
        loop {
            let handle = self.database_handle(parent)?;
            let marker = handle.release_marker();
            match attempt() {
                Err(status) if Self::is_contention(&status) => {
                    let released = self.expire_lock_leases(&handle, lease_writes, own);
                    if !Self::should_wait_for_release(&handle, own, deadline) {
                        return Err(status);
                    }
                    if !released {
                        let waiter = handle.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            waiter.wait_for_release(marker, deadline)
                        })
                        .await;
                    }
                }
                outcome => return outcome,
            }
        }
    }

    /// Whether a refused attempt should wait for a transaction to finish and try again:
    /// before the deadline, and, for a transaction's own commit, only while that transaction
    /// is still active (the store aborts the deadlock victim).
    fn should_wait_for_release(
        handle: &DatabaseHandle,
        own: Option<&TransactionId>,
        deadline: std::time::Instant,
    ) -> bool {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        own.is_none_or(|txn| {
            handle
                .read(|db| db.transaction_is_active(txn))
                .unwrap_or(false)
        })
    }

    /// Whether `status` is the lock contention refusal.
    #[must_use]
    pub fn is_contention(status: &Status) -> bool {
        status.code() == tonic::Code::Aborted
            && status.message() == fireemu_core_firestore::store::TOO_MUCH_CONTENTION
    }

    /// Lease bookkeeping for a refused attempt: notes when each holder of a colliding lock
    /// first blocked a writer and how active it was then, and rolls back a holder that has
    /// blocked writers for the lock lease without driving its transaction in the meantime
    /// (production expires an idle transaction; a busy one keeps its locks). `true` when a
    /// holder was rolled back, so the attempt is worth repeating at once.
    pub fn expire_lock_leases(
        &self,
        handle: &DatabaseHandle,
        lease_writes: &[Write],
        own: Option<&TransactionId>,
    ) -> bool {
        let holders: Vec<(TransactionId, u64)> = handle
            .read(|db| {
                db.lock_holders(lease_writes, own)
                    .into_iter()
                    .filter_map(|id| db.transaction_activity(&id).map(|activity| (id, activity)))
                    .collect()
            })
            .unwrap_or_default();
        let now = std::time::Instant::now();
        let expired: Vec<TransactionId> = {
            let Ok(mut since) = handle.0.blocking_since.lock() else {
                return false;
            };
            // Forget holders that finished; keep the clock of every still-active holder, so
            // writers with different write sets do not reset each other's lease.
            let stale: Vec<TransactionId> = since
                .keys()
                .filter(|id| {
                    !handle
                        .read(|db| db.transaction_is_active(id))
                        .unwrap_or(false)
                })
                .cloned()
                .collect();
            for id in stale {
                since.remove(&id);
            }
            holders
                .iter()
                .filter(|(id, activity)| {
                    let entry = since.entry(id.clone()).or_insert((now, *activity));
                    if entry.1 != *activity {
                        // The holder drove its transaction since: not idle, the lease restarts.
                        *entry = (now, *activity);
                    }
                    now.duration_since(entry.0) >= self.lock_lease
                })
                .map(|(id, _)| id.clone())
                .collect()
        };
        if expired.is_empty() {
            return false;
        }
        let _ = handle.with(|db| {
            for id in &expired {
                let _ = db.rollback(id);
            }
            Ok(())
        });
        if let Ok(mut since) = handle.0.blocking_since.lock() {
            for id in &expired {
                since.remove(id);
            }
        }
        true
    }

    /// `Rollback`.
    pub fn rollback(&self, req: &pb::RollbackRequest) -> Result<(), Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        let txn = self.required_txn(&parent, &req.transaction)?;
        let now = self.write_time();
        self.with_db(&parent, |db| {
            db.rollback(&txn).map_err(|e| status_from_error(&e))?;
            db.compact(now);
            self.reconcile_history(&parent, db.history_usage());
            Ok(())
        })
    }

    pub(crate) fn next_query_execution_id(&self) -> QueryExecutionId {
        const ADAPTER_QUERY_EXECUTION_PREFIX: u64 = 1 << 63;
        let sequence = self
            .query_execution_ids
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .wrapping_add(1);
        QueryExecutionId::from_value(sequence | ADAPTER_QUERY_EXECUTION_PREFIX)
    }

    /// Marks one streamed transaction query complete after its final response was accepted by
    /// the gRPC response channel.
    pub(crate) fn finish_query_execution(
        &self,
        database: &str,
        transaction: &[u8],
        execution_id: QueryExecutionId,
    ) -> Result<(), Status> {
        let parent = parse_parent(&format!("{database}/documents")).map_err(status)?;
        let transaction = self.required_txn(&parent, transaction)?;
        let now = self.write_time();
        self.with_db(&parent, |db| {
            db.finish_transaction_query_execution(&transaction, execution_id)
                .map_err(|error| status_from_error(&error))?;
            db.compact(now);
            self.reconcile_history(&parent, db.history_usage());
            Ok(())
        })
    }

    /// `RunQuery`: validates through the strict gateway, then executes locally.
    pub fn run_query(
        &self,
        req: &pb::RunQueryRequest,
        guard: ReadGuard<'_>,
    ) -> Result<(Vec<pb::RunQueryResponse>, Vec<String>), Status> {
        self.run_query_authorized_as(req, req, guard)
    }

    /// Executes a bounded page while authorizing the caller's original query shape.
    /// Synthetic pagination limits and offsets are an adapter implementation detail and must
    /// not change `request.query` as observed by Security Rules.
    /// This public page helper uses the legacy query-shaped transaction observation so callers
    /// can pair it with [`Self::run_query_authorized_as_after`].
    pub fn run_query_authorized_as(
        &self,
        req: &pb::RunQueryRequest,
        authorization_req: &pb::RunQueryRequest,
        guard: ReadGuard<'_>,
    ) -> Result<(Vec<pb::RunQueryResponse>, Vec<String>), Status> {
        self.run_query_authorized_as_after_internal(
            req,
            authorization_req,
            guard,
            None,
            false,
            None,
        )
    }

    /// Executes the first bounded page of one streamed query execution.
    pub(crate) fn run_query_authorized_as_for_execution(
        &self,
        req: &pb::RunQueryRequest,
        authorization_req: &pb::RunQueryRequest,
        guard: ReadGuard<'_>,
        execution_id: QueryExecutionId,
    ) -> Result<(Vec<pb::RunQueryResponse>, Vec<String>), Status> {
        self.run_query_authorized_as_after_internal(
            req,
            authorization_req,
            guard,
            None,
            false,
            Some(QueryExecutionContext {
                id: execution_id,
                complete: false,
            }),
        )
    }

    /// Executes a bounded page after an exclusive document path while authorizing the caller's
    /// original query shape. The continuation is valid only for the canonical ascending
    /// `__name__` order selected by the caller. This public compatibility helper pairs with
    /// [`Self::run_query_authorized_as`] and resolves its transaction observation by query shape.
    /// The gRPC streaming path uses the execution-scoped helper below when identical queries can
    /// be active concurrently.
    pub fn run_query_authorized_as_after(
        &self,
        req: &pb::RunQueryRequest,
        authorization_req: &pb::RunQueryRequest,
        guard: ReadGuard<'_>,
        after_document: Option<&DocumentPath>,
    ) -> Result<(Vec<pb::RunQueryResponse>, Vec<String>), Status> {
        self.run_query_authorized_as_after_internal(
            req,
            authorization_req,
            guard,
            after_document,
            true,
            None,
        )
    }

    /// Executes a continuation page of one streamed query execution.
    pub(crate) fn run_query_authorized_as_after_for_execution(
        &self,
        req: &pb::RunQueryRequest,
        authorization_req: &pb::RunQueryRequest,
        guard: ReadGuard<'_>,
        after_document: Option<&DocumentPath>,
        execution_id: QueryExecutionId,
    ) -> Result<(Vec<pb::RunQueryResponse>, Vec<String>), Status> {
        self.run_query_authorized_as_after_internal(
            req,
            authorization_req,
            guard,
            after_document,
            true,
            Some(QueryExecutionContext {
                id: execution_id,
                complete: false,
            }),
        )
    }

    fn run_query_authorized_as_after_internal(
        &self,
        req: &pb::RunQueryRequest,
        authorization_req: &pb::RunQueryRequest,
        guard: ReadGuard<'_>,
        after_document: Option<&DocumentPath>,
        continuation: bool,
        execution: Option<QueryExecutionContext>,
    ) -> Result<(Vec<pb::RunQueryResponse>, Vec<String>), Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.read")?;
        let Some(pb::run_query_request::QueryType::StructuredQuery(sq)) = &req.query_type else {
            return Err(Status::invalid_argument(
                "RunQuery requires a structured_query",
            ));
        };
        let accepted = self.accepted_query(&parent, sq)?;
        let authorization_parent = parse_parent(&authorization_req.parent).map_err(status)?;
        if authorization_parent.project != parent.project
            || authorization_parent.database != parent.database
            || authorization_parent.document != parent.document
        {
            return Err(Status::invalid_argument(
                "RunQuery authorization parent does not match the execution page",
            ));
        }
        let Some(pb::run_query_request::QueryType::StructuredQuery(authorization_query)) =
            &authorization_req.query_type
        else {
            return Err(Status::invalid_argument(
                "RunQuery requires a structured_query",
            ));
        };
        let authorization = self.accepted_query(&authorization_parent, authorization_query)?;
        let now = self.write_time();
        let selector = match &req.consistency_selector {
            Some(pb::run_query_request::ConsistencySelector::Transaction(bytes)) => {
                SnapshotSelector::Transaction(bytes)
            }
            Some(pb::run_query_request::ConsistencySelector::NewTransaction(options)) => {
                SnapshotSelector::NewTransaction(options)
            }
            Some(pb::run_query_request::ConsistencySelector::ReadTime(ts)) => {
                SnapshotSelector::ReadTime(self.read_time_selector(
                    ts,
                    now,
                    self.read_time_horizon(&parent, now),
                )?)
            }
            None => SnapshotSelector::Latest,
        };
        self.with_selected_snapshot(&parent, selector, now, |access| {
            if let Some(execution) = execution {
                access.set_query_execution(execution.id, execution.complete);
            }
            let version = access.version()?;
            // Authorized from the query constraints before any data is touched.
            guard(
                access.db(),
                version,
                ReadCheck::Query {
                    parent: &authorization_parent,
                    query: &authorization.query,
                },
            )?;
            let (docs, stats) = match (continuation, after_document) {
                (true, Some(after)) => access.run_query_with_stats_after_document(
                    &accepted.query,
                    &authorization.query,
                    after,
                )?,
                (true, None) => {
                    access.run_query_with_stats(&accepted.query, &authorization.query, true)?
                }
                (false, None) => {
                    access.run_query_with_stats(&accepted.query, &authorization.query, false)?
                }
                (false, Some(_)) => {
                    return Err(Status::internal("invalid first RunQuery continuation"));
                }
            };
            let read_time = Some(encode_instant(access.read_time(now)?));
            // The rows the offset skipped, reported on the first result as the backend does.
            let skipped = if after_document.is_some() {
                0
            } else {
                i32::try_from(u64::from(accepted.query.offset).min(stats.matched))
                    .unwrap_or(i32::MAX)
            };
            Ok((
                query_responses(&docs, read_time, access.report(), skipped),
                authorization.warnings.clone(),
            ))
        })
    }

    /// `RunAggregationQuery`.
    pub fn run_aggregation_query(
        &self,
        req: &pb::RunAggregationQueryRequest,
        guard: ReadGuard<'_>,
    ) -> Result<pb::RunAggregationQueryResponse, Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.read")?;
        let Some(pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(saq)) =
            &req.query_type
        else {
            return Err(Status::invalid_argument(
                "RunAggregationQuery requires a structured_aggregation_query",
            ));
        };
        let Some(pb::structured_aggregation_query::QueryType::StructuredQuery(sq)) =
            &saq.query_type
        else {
            return Err(Status::invalid_argument(
                "aggregation query requires a structured_query",
            ));
        };
        let accepted = self.accepted_query(&parent, sq)?;
        let (aliases, aggregations) = decode_aggregations(saq)?;
        let now = self.write_time();
        let selector = match &req.consistency_selector {
            Some(pb::run_aggregation_query_request::ConsistencySelector::Transaction(bytes)) => {
                SnapshotSelector::Transaction(bytes)
            }
            Some(pb::run_aggregation_query_request::ConsistencySelector::NewTransaction(
                options,
            )) => SnapshotSelector::NewTransaction(options),
            Some(pb::run_aggregation_query_request::ConsistencySelector::ReadTime(ts)) => {
                SnapshotSelector::ReadTime(self.read_time_selector(
                    ts,
                    now,
                    self.read_time_horizon(&parent, now),
                )?)
            }
            None => SnapshotSelector::Latest,
        };
        self.with_selected_snapshot(&parent, selector, now, |access| {
            let version = access.version()?;
            // The underlying query is authorized from its constraints, like a list.
            guard(
                access.db(),
                version,
                ReadCheck::Query {
                    parent: &parent,
                    query: &accepted.query,
                },
            )?;
            // Inside a transaction the aggregation is computed at the snapshot and the query
            // is recorded so that later changes abort the commit.
            access.record_query(&accepted.query)?;
            let read_time = access.read_time(now)?;
            let values = access
                .db()
                .run_aggregation(&accepted.query, &aggregations, version)
                .map_err(|e| status_from_error(&e))?;
            let aggregate_fields: HashMap<String, pb::Value> = aliases
                .into_iter()
                .zip(values.iter().map(encode_value))
                .collect();
            Ok(pb::RunAggregationQueryResponse {
                result: Some(pb::AggregationResult { aggregate_fields }),
                transaction: access.report().to_vec(),
                read_time: Some(encode_instant(read_time)),
                explain_metrics: None,
            })
        })
    }

    /// `ListDocuments`: paged by name (or by the request's `order_by`); transaction and
    /// `read_time` snapshots and `show_missing` supported.
    #[allow(clippy::too_many_lines)]
    pub fn list_documents(
        &self,
        req: &pb::ListDocumentsRequest,
        guard: ReadGuard<'_>,
    ) -> Result<pb::ListDocumentsResponse, Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.read")?;
        let now = self.write_time();
        let (txn, read_at) = match &req.consistency_selector {
            Some(pb::list_documents_request::ConsistencySelector::ReadTime(ts)) => (
                None,
                Some(self.read_time_selector(ts, now, self.read_time_horizon(&parent, now))?),
            ),
            Some(pb::list_documents_request::ConsistencySelector::Transaction(t)) => {
                (Some(self.required_txn(&parent, t)?), None)
            }
            None => (None, None),
        };
        let selector = match &req.consistency_selector {
            Some(pb::list_documents_request::ConsistencySelector::ReadTime(_)) => {
                SnapshotSelector::ReadTime(read_at.expect("read time was decoded"))
            }
            Some(pb::list_documents_request::ConsistencySelector::Transaction(bytes)) => {
                SnapshotSelector::Transaction(bytes)
            }
            None => SnapshotSelector::Latest,
        };
        // Page tokens carry the resource name of the last document of the previous page
        // (documents are listed by name) and the identity of the listing they continue:
        // parent, collection, result-shaping options, session generation, and the snapshot
        // (live, read_time or transaction).
        let identity = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            req.parent,
            req.collection_id,
            req.mask
                .as_ref()
                .map(|m| m.field_paths.join(","))
                .unwrap_or_default(),
            req.order_by,
            req.show_missing,
            self.epoch(),
            self.database_generation(&parent),
            match (&txn, read_at) {
                (Some(t), _) => format!(
                    "txn:{}",
                    crate::rest::json::base64_encode(&encode_transaction(t))
                ),
                (None, Some(at)) => format!("rt:{}", at.as_nanos()),
                (None, None) => "live".to_owned(),
            }
        );
        let after = list_page_cursor(&req.page_token, &identity)?;
        let after_path = after
            .as_deref()
            .map(decode_document_name)
            .transpose()
            .map_err(status)?;
        if after_path.as_ref().is_some_and(|path| {
            path.project() != &parent.project
                || path.database() != &parent.database
                || path.parent_document().as_ref() != parent.document.as_ref()
                || path.collection_id().as_str() != req.collection_id
        }) {
            return Err(Status::invalid_argument(
                "page_token cursor is outside the requested collection",
            ));
        }
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        if req.page_size < 0 {
            return Err(Status::invalid_argument("page_size must not be negative"));
        }
        let accepted = self.accepted_query(&parent, &list_query(req)?)?;
        let ordered = !accepted.query.order_by.is_empty();
        // The rules see the page size as `request.query.limit` (the number of documents the
        // request can return); the scan itself stays unlimited so the page cursor applies
        // before truncation.
        let page_size = if req.page_size > 0 {
            usize::try_from(req.page_size).unwrap_or(usize::MAX)
        } else {
            DEFAULT_LIST_PAGE_SIZE
        };
        // One document beyond the page decides whether a `nextPageToken` is issued.
        let scan_size = page_size.saturating_add(1);
        let mut proof_query = accepted.query.clone();
        proof_query.limit = Some(u32::try_from(page_size).unwrap_or(u32::MAX));
        let bounded_name_page = txn.is_none() && !ordered;
        let bounded_ordered_page = txn.is_none() && ordered;
        self.with_selected_snapshot(&parent, selector, now, |access| {
            let version = access.version()?;
            guard(
                access.db(),
                version,
                ReadCheck::Query {
                    parent: &parent,
                    query: &proof_query,
                },
            )?;
            // Inside a transaction the scan is recorded like a query, so a concurrent
            // change to the collection aborts the commit.
            let mut documents = if bounded_name_page && req.show_missing {
                access
                    .db()
                    .list_documents_with_missing_page_at(
                        parent.document.as_ref(),
                        &req.collection_id,
                        version,
                        after_path.as_ref(),
                        scan_size,
                    )
                    .0
                    .into_iter()
                    .map(|entry| match entry {
                        ListedDocument::Present(mut document) => {
                            if let Some(mask) = &mask {
                                document.fields = project_fields(&document.fields, mask);
                            }
                            encode_document(&document)
                        }
                        ListedDocument::Missing(path) => pb::Document {
                            name: path.resource_name(),
                            ..Default::default()
                        },
                    })
                    .collect()
            } else if bounded_ordered_page {
                let mut page_query = accepted.query.clone();
                page_query.limit = Some(u32::try_from(scan_size).unwrap_or(u32::MAX));
                let cursor = after_path
                    .as_ref()
                    .map(|path| {
                        access
                            .db()
                            .cursor_after_document(&accepted.query, version, path)
                    })
                    .transpose()
                    .map_err(|e| status_from_error(&e))?
                    .flatten();
                let cursor_matches_document = cursor.is_some();
                page_query.start_at = cursor;
                let mut docs = access
                    .db()
                    .run_query(&page_query, version)
                    .map_err(|e| status_from_error(&e))?;
                let mut documents = docs
                    .iter_mut()
                    .map(|document| {
                        if let Some(mask) = &mask {
                            document.fields = project_fields(&document.fields, mask);
                        }
                        encode_document(document)
                    })
                    .collect::<Vec<_>>();
                if req.show_missing {
                    let mut missing = Vec::new();
                    let mut continued_missing_suffix = false;
                    if !cursor_matches_document {
                        if let Some(after_path) = after_path.as_ref() {
                            let (cursor_is_missing, page) =
                                access.db().list_missing_parents_page_at(
                                    parent.document.as_ref(),
                                    &req.collection_id,
                                    version,
                                    Some(after_path),
                                    scan_size,
                                );
                            if cursor_is_missing {
                                continued_missing_suffix = true;
                                documents.clear();
                                missing = page;
                            }
                        }
                    }
                    if !continued_missing_suffix && documents.len() < scan_size {
                        missing = access
                            .db()
                            .list_missing_parents_page_at(
                                parent.document.as_ref(),
                                &req.collection_id,
                                version,
                                None,
                                scan_size - documents.len(),
                            )
                            .1;
                    }
                    documents.extend(missing.iter().map(|path| pb::Document {
                        name: path.resource_name(),
                        ..Default::default()
                    }));
                }
                documents
            } else {
                let mut docs = match (&txn, ordered) {
                    (Some(_), _) => {
                        access
                            .run_query_with_stats(&accepted.query, &accepted.query, false)?
                            .0
                    }
                    (None, true) => access
                        .db()
                        .run_query(&accepted.query, version)
                        .map_err(|e| status_from_error(&e))?,
                    (None, false) if bounded_name_page => access.db().list_documents_page_at(
                        parent.document.as_ref(),
                        &req.collection_id,
                        version,
                        after_path.as_ref(),
                        scan_size,
                    ),
                    (None, false) => access.db().list_documents_at(
                        parent.document.as_ref(),
                        &req.collection_id,
                        version,
                    ),
                };
                let mut documents: Vec<pb::Document> = docs
                    .iter_mut()
                    .map(|d| {
                        if let Some(mask) = &mask {
                            d.fields = project_fields(&d.fields, mask);
                        }
                        encode_document(d)
                    })
                    .collect();
                if req.show_missing {
                    // A path that holds no document but has descendants is listed by name
                    // alone, as the backend lists it. Under an explicit order the missing
                    // parents (which have no fields to order on) follow the ordered documents.
                    let missing = access.db().list_missing_parents_at(
                        parent.document.as_ref(),
                        &req.collection_id,
                        version,
                    );
                    documents.extend(missing.iter().map(|path| pb::Document {
                        name: path.resource_name(),
                        ..Default::default()
                    }));
                    if !ordered {
                        documents.sort_by(|a, b| a.name.cmp(&b.name));
                    }
                }
                documents
            };
            if !bounded_name_page && !bounded_ordered_page {
                if let Some(after) = &after {
                    if ordered {
                        // The page continues after the named document at its position in the
                        // ordered result; a document that left the result restarts the page.
                        if let Some(position) = documents.iter().position(|d| d.name == *after) {
                            documents.drain(..=position);
                        }
                    } else {
                        documents.retain(|d| d.name > *after);
                    }
                }
            }
            // A token is issued only when a document follows the page: production answers
            // the last page, full or not, without one (the official emulator issues a token
            // for every full page and then an empty page).
            let full = documents.len() > page_size;
            documents.truncate(page_size);
            let next_page_token = if full {
                documents.last().map_or(String::new(), |d| {
                    crate::rest::json::base64_encode(format!("{}\n{identity}", d.name).as_bytes())
                })
            } else {
                String::new()
            };
            Ok(pb::ListDocumentsResponse {
                documents,
                next_page_token,
            })
        })
    }

    /// `ListCollectionIds`.
    pub fn list_collection_ids(
        &self,
        req: &pb::ListCollectionIdsRequest,
    ) -> Result<pb::ListCollectionIdsResponse, Status> {
        let parent = parse_parent(&req.parent).map_err(status)?;
        let after: Option<String> = if req.page_token.is_empty() {
            None
        } else {
            Some(
                String::from_utf8(
                    crate::rest::json::base64_decode(&req.page_token)
                        .map_err(|_| Status::invalid_argument("malformed page_token"))?,
                )
                .map_err(|_| Status::invalid_argument("malformed page_token"))?,
            )
        };
        let page_size = if req.page_size > 0 {
            usize::try_from(req.page_size).unwrap_or(usize::MAX)
        } else {
            DEFAULT_LIST_PAGE_SIZE
        };
        self.read_db(&parent, |db| {
            let mut ids = db.list_collection_ids(parent.document.as_ref());
            if let Some(after) = &after {
                ids.retain(|id| id > after);
            }
            // As for documents: a token only when a collection id follows the page.
            let full = ids.len() > page_size;
            ids.truncate(page_size);
            let next_page_token = if full {
                ids.last().map_or(String::new(), |id| {
                    crate::rest::json::base64_encode(id.as_bytes())
                })
            } else {
                String::new()
            };
            Ok(pb::ListCollectionIdsResponse {
                collection_ids: ids,
                next_page_token,
            })
        })
    }

    /// `BatchWrite`: each write is applied independently and reported with its own status.
    pub fn batch_write(
        &self,
        req: &pb::BatchWriteRequest,
    ) -> Result<pb::BatchWriteResponse, Status> {
        self.batch_write_with(req, &allow_all)
    }

    /// `BatchWrite` with a write guard (run per write, inside the critical section).
    pub fn batch_write_with(
        &self,
        req: &pb::BatchWriteRequest,
        guard: WriteGuard<'_>,
    ) -> Result<pb::BatchWriteResponse, Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.commit")?;
        let decoded: Vec<Result<Write, Status>> = req
            .writes
            .iter()
            .map(|w| {
                let write = decode_write(w).map_err(status)?;
                Self::check_database_path(&parent, write.op.path())?;
                Ok(write)
            })
            .collect();
        let mut targets = std::collections::BTreeSet::new();
        for path in decoded
            .iter()
            .filter_map(|w| w.as_ref().ok().map(|w| w.op.path()))
        {
            if !targets.insert(path.clone()) {
                return Err(Status::invalid_argument(format!(
                    "BatchWrite contains multiple writes to {}",
                    path.resource_name()
                )));
            }
        }
        self.with_db(&parent, |db| {
            let mut write_results = Vec::with_capacity(req.writes.len());
            let mut statuses = Vec::with_capacity(req.writes.len());
            for decoded in decoded {
                let now = self.write_time();
                let outcome = decoded.and_then(|write| {
                    guard(db, std::slice::from_ref(&write), now)?;
                    self.commit_with_events(&parent, db, std::slice::from_ref(&write), None, now)
                });
                match outcome {
                    Ok(result) => {
                        let encoded = encode_commit(&result);
                        // Every successful write is its own commit and is published as such,
                        // in write order, with its own commit time.
                        write_results
                            .push(encoded.write_results.into_iter().next().unwrap_or_default());
                        statuses.push(fireemu_proto_firestore::google::rpc::Status {
                            code: 0,
                            message: String::new(),
                            details: Vec::new(),
                        });
                    }
                    Err(s) => {
                        write_results.push(pb::WriteResult::default());
                        statuses.push(fireemu_proto_firestore::google::rpc::Status {
                            code: i32::from(s.code()),
                            message: s.message().to_owned(),
                            details: Vec::new(),
                        });
                    }
                }
            }
            Ok(pb::BatchWriteResponse {
                write_results,
                status: statuses,
            })
        })
        .inspect(|response| {
            // A batch is not atomic and does not wait, but a write refused for lock contention
            // still counts towards the holder's lease.
            let contended: Vec<Write> = response
                .status
                .iter()
                .zip(req.writes.iter())
                .filter(|(status, _)| {
                    status.code == i32::from(tonic::Code::Aborted)
                        && status.message == fireemu_core_firestore::store::TOO_MUCH_CONTENTION
                })
                .filter_map(|(_, write)| decode_write(write).ok())
                .collect();
            if !contended.is_empty() {
                if let Ok(handle) = self.database_handle(&parent) {
                    let _ = self.expire_lock_leases(&handle, &contended, None);
                }
            }
        })
    }
}

/// Core commit result → wire.
#[must_use]
pub fn encode_commit(result: &CommitResult) -> pb::CommitResponse {
    pb::CommitResponse {
        write_results: result
            .write_results
            .iter()
            .map(|w| pb::WriteResult {
                update_time: w.update_time.map(encode_instant),
                transform_results: w.transform_results.iter().map(encode_value).collect(),
            })
            .collect(),
        commit_time: Some(encode_instant(result.commit_time)),
    }
}

/// Firestore accepts at most this many aggregations in one query.
const MAX_AGGREGATIONS_PER_QUERY: usize = 5;

/// Decodes and validates the aggregation list: 1..=5 entries, positive `count.up_to`,
/// unique aliases.
fn decode_aggregations(
    saq: &pb::StructuredAggregationQuery,
) -> Result<(Vec<String>, Vec<Aggregation>), Status> {
    if saq.aggregations.is_empty() || saq.aggregations.len() > MAX_AGGREGATIONS_PER_QUERY {
        return Err(Status::invalid_argument(format!(
            "an aggregation query needs 1..={MAX_AGGREGATIONS_PER_QUERY} aggregations"
        )));
    }
    let mut aliases: Vec<String> = Vec::with_capacity(saq.aggregations.len());
    let mut aggregations = Vec::with_capacity(saq.aggregations.len());
    for (i, a) in saq.aggregations.iter().enumerate() {
        use pb::structured_aggregation_query::aggregation::Operator as O;
        let field =
            |f: &Option<pb::structured_query::FieldReference>| -> Result<FieldPath, Status> {
                let r = f
                    .as_ref()
                    .ok_or_else(|| Status::invalid_argument("aggregation without field"))?;
                FieldPath::parse(&r.field_path).map_err(|e| Status::invalid_argument(e.to_string()))
            };
        let agg = match &a.operator {
            Some(O::Count(c)) => Aggregation::Count {
                up_to: match c.up_to {
                    None => None,
                    Some(n) if n > 0 => Some(u64::try_from(n).unwrap_or(u64::MAX)),
                    Some(_) => {
                        return Err(Status::invalid_argument("count.up_to must be positive"))
                    }
                },
            },
            Some(O::Sum(s)) => Aggregation::Sum(field(&s.field)?),
            Some(O::Avg(v)) => Aggregation::Avg(field(&v.field)?),
            None => return Err(Status::invalid_argument("aggregation without operator")),
        };
        let alias = if a.alias.is_empty() {
            format!("field_{}", i + 1)
        } else {
            a.alias.clone()
        };
        if aliases.contains(&alias) {
            return Err(Status::invalid_argument(format!(
                "duplicate aggregation alias {alias:?}"
            )));
        }
        aliases.push(alias);
        aggregations.push(agg);
    }
    Ok((aliases, aggregations))
}

/// Catalog key of a database.
fn database_key(parent: &Parent) -> (String, String) {
    (
        parent.project.as_str().to_owned(),
        parent.database.as_str().to_owned(),
    )
}

fn auto_id_from(rng: &mut SplitMix64) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..20)
        .map(|_| {
            let index = usize::try_from(rng.next_below(ALPHABET.len() as u64)).unwrap_or(0);
            ALPHABET[index] as char
        })
        .collect()
}

fn database_tag(parent: &Parent) -> u64 {
    // FNV-1a over "project\0database": stable, dependency-free.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in parent
        .project
        .as_str()
        .bytes()
        .chain(core::iter::once(0))
        .chain(parent.database.as_str().bytes())
    {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn encode_masked(doc: &Document, mask: Option<&[FieldPath]>) -> pb::Document {
    match mask {
        Some(mask) => {
            let mut d = doc.clone();
            d.fields = project_fields(&d.fields, mask);
            encode_document(&d)
        }
        None => encode_document(doc),
    }
}

fn project_fields(
    fields: &BTreeMap<String, fireemu_core_firestore::value::Value>,
    mask: &[FieldPath],
) -> BTreeMap<String, fireemu_core_firestore::value::Value> {
    fireemu_core_firestore::store::project(fields, mask)
}

/// Convenience for tests: documents as (relative path, fields).
#[must_use]
pub fn document_summary(
    doc: &Document,
) -> (
    String,
    BTreeMap<String, fireemu_core_firestore::value::Value>,
) {
    (doc.path.relative(), doc.fields.clone())
}

/// Structured query of a `ListDocuments` request (unfiltered collection scan).
pub fn list_query(req: &pb::ListDocumentsRequest) -> Result<pb::StructuredQuery, Status> {
    Ok(pb::StructuredQuery {
        from: vec![pb::structured_query::CollectionSelector {
            collection_id: req.collection_id.clone(),
            all_descendants: false,
        }],
        order_by: list_order_by(&req.order_by)?,
        ..Default::default()
    })
}

/// `ListDocuments.order_by`: a comma-separated list of `field [asc|desc]` clauses.
fn list_order_by(order_by: &str) -> Result<Vec<pb::structured_query::Order>, Status> {
    let invalid = || Status::invalid_argument(format!("Invalid order by clause \"{order_by}\"."));
    if order_by.trim().is_empty() {
        return Ok(Vec::new());
    }
    order_by
        .split(',')
        .map(|clause| {
            let mut words = clause.split_whitespace();
            let field = words.next().ok_or_else(invalid)?;
            let direction = match words.next().map(str::to_ascii_lowercase).as_deref() {
                None | Some("asc") => pb::structured_query::Direction::Ascending,
                Some("desc") => pb::structured_query::Direction::Descending,
                Some(_) => return Err(invalid()),
            };
            if words.next().is_some() {
                return Err(invalid());
            }
            Ok(pb::structured_query::Order {
                field: Some(pb::structured_query::FieldReference {
                    field_path: field.to_owned(),
                }),
                direction: direction as i32,
            })
        })
        .collect()
}

/// The document name a `ListDocuments` page token continues after; the token must have been
/// issued for the same listing (`identity`).
fn list_page_cursor(page_token: &str, identity: &str) -> Result<Option<String>, Status> {
    if page_token.is_empty() {
        return Ok(None);
    }
    let malformed = || Status::invalid_argument("malformed page_token");
    let token =
        String::from_utf8(crate::rest::json::base64_decode(page_token).map_err(|_| malformed())?)
            .map_err(|_| malformed())?;
    let (name, token_identity) = token.split_once('\n').ok_or_else(malformed)?;
    if token_identity != identity {
        return Err(Status::invalid_argument(
            "page_token was issued for a different listing",
        ));
    }
    decode_document_name(name).map_err(|_| malformed())?;
    Ok(Some(name.to_owned()))
}

/// `RunQuery` responses for `docs`: one per document (or one empty response carrying the
/// read time), preceded by a dedicated response announcing a new transaction.
fn query_responses(
    docs: &[Document],
    read_time: Option<prost_types::Timestamp>,
    new_transaction: &[u8],
    skipped_results: i32,
) -> Vec<pb::RunQueryResponse> {
    let mut responses: Vec<pb::RunQueryResponse> = docs
        .iter()
        .map(|d| pb::RunQueryResponse {
            transaction: Vec::new(),
            document: Some(encode_document(d)),
            read_time,
            skipped_results: 0,
            ..Default::default()
        })
        .collect();
    if responses.is_empty() {
        // A result-less query still answers with one response carrying read_time.
        responses.push(pb::RunQueryResponse {
            transaction: Vec::new(),
            document: None,
            read_time,
            skipped_results: 0,
            ..Default::default()
        });
    }
    // Production reports an offset in a leading result-less response (`readTime` and
    // `skippedResults`, no document) ahead of the documents; an offset past the end is that
    // single response with every skipped document counted. The official emulator attaches
    // the count to the first document instead and omits it past the end.
    if skipped_results != 0 {
        if responses.first().is_some_and(|r| r.document.is_none()) {
            responses[0].skipped_results = skipped_results;
        } else {
            responses.insert(
                0,
                pb::RunQueryResponse {
                    transaction: Vec::new(),
                    document: None,
                    read_time,
                    skipped_results,
                    ..Default::default()
                },
            );
        }
    }
    if let Some(last) = responses.last_mut() {
        // The last response says so, so a client can tell the end of the results from a
        // stream that stalled.
        last.continuation_selector = Some(pb::run_query_response::ContinuationSelector::Done(true));
    }
    if !new_transaction.is_empty() {
        // A new transaction is announced in a dedicated first response that carries nothing
        // else (RunQueryResponse contract).
        responses.insert(
            0,
            pb::RunQueryResponse {
                transaction: new_transaction.to_vec(),
                ..Default::default()
            },
        );
    }
    responses
}

/// A gRPC status code from its name (or `UNKNOWN`).
fn grpc_code(name: &str) -> tonic::Code {
    match name.to_ascii_uppercase().as_str() {
        "CANCELLED" => tonic::Code::Cancelled,
        "INVALID_ARGUMENT" => tonic::Code::InvalidArgument,
        "DEADLINE_EXCEEDED" => tonic::Code::DeadlineExceeded,
        "NOT_FOUND" => tonic::Code::NotFound,
        "ALREADY_EXISTS" => tonic::Code::AlreadyExists,
        "PERMISSION_DENIED" => tonic::Code::PermissionDenied,
        "RESOURCE_EXHAUSTED" => tonic::Code::ResourceExhausted,
        "FAILED_PRECONDITION" => tonic::Code::FailedPrecondition,
        "ABORTED" => tonic::Code::Aborted,
        "OUT_OF_RANGE" => tonic::Code::OutOfRange,
        "UNIMPLEMENTED" => tonic::Code::Unimplemented,
        "INTERNAL" => tonic::Code::Internal,
        "UNAVAILABLE" => tonic::Code::Unavailable,
        "DATA_LOSS" => tonic::Code::DataLoss,
        "UNAUTHENTICATED" => tonic::Code::Unauthenticated,
        _ => tonic::Code::Unknown,
    }
}

#[cfg(test)]
mod lock_tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
    use fireemu_core_session::tenancy::Tenancy;
    use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
    use fireemu_core_types::time::LogicalInstant;

    use super::*;

    fn backend() -> Arc<LocalBackend> {
        Arc::new(LocalBackend::new(
            Gateway {
                enforce_limits: true,
                ctx: PlanningContext {
                    edition: FirestoreEdition::Standard,
                    api_mode: FirestoreApiMode::Native,
                    policy: IndexValidationPolicy::Conservative,
                },
                indexes: IndexSet::default(),
            },
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ))),
            7,
        ))
    }

    fn history_usage(versions: u64) -> HistoryUsage {
        HistoryUsage {
            versions,
            total_bytes: versions,
            ..HistoryUsage::default()
        }
    }

    #[test]
    fn pending_reduction_does_not_release_committed_capacity() {
        let limits = HistoryBudgetLimits {
            session_bytes: u64::MAX,
            session_versions: u64::MAX,
            global_bytes: u64::MAX,
            global_versions: 14,
        };
        let ledger = Arc::new(Mutex::new(HistoryBudgetLedger::new(limits)));
        let first_key = ("first".to_owned(), "(default)".to_owned());
        let reduction = {
            let mut locked = ledger.lock().unwrap();
            locked.replace_committed(
                first_key.clone(),
                &HistoryCharge {
                    owner: HistoryBudgetOwner::Default,
                    usage: history_usage(10),
                },
            );
            let id = locked
                .reserve(first_key, HistoryBudgetOwner::Default, history_usage(5))
                .unwrap();
            HistoryReservation {
                ledger: Arc::clone(&ledger),
                id,
                committed: false,
            }
        };
        let error = ledger
            .lock()
            .unwrap()
            .reserve(
                ("second".to_owned(), "(default)".to_owned()),
                HistoryBudgetOwner::Default,
                history_usage(5),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            FirestoreError::HistoryCapacity(HistoryCapacityError {
                dimension: "global versions",
                current: 15,
                maximum: 14,
            })
        ));
        drop(reduction);
        let ledger = ledger.lock().unwrap();
        assert!(ledger.pending.is_empty());
        assert!(ledger.pending_by_key.is_empty());
        assert_eq!(ledger.charged_global.versions, 10);
        assert_eq!(
            ledger.charged_by_owner[&HistoryBudgetOwner::Default].versions,
            10
        );
        assert_eq!(
            ledger.committed[&("first".to_owned(), "(default)".to_owned())]
                .usage
                .versions,
            10
        );
    }

    #[test]
    fn one_reservation_has_constant_accounting_work_across_many_owners() {
        let mut ledger = HistoryBudgetLedger::new(HistoryBudgetLimits {
            session_bytes: u64::MAX,
            session_versions: u64::MAX,
            global_bytes: u64::MAX,
            global_versions: u64::MAX,
        });
        for index in 0..8_192 {
            ledger.replace_committed(
                (format!("project-{index}"), "(default)".to_owned()),
                &HistoryCharge {
                    owner: HistoryBudgetOwner::Project(format!("project-{index}")),
                    usage: history_usage(1),
                },
            );
        }
        let before = ledger.accounting_steps;

        ledger
            .reserve(
                ("new-project".to_owned(), "(default)".to_owned()),
                HistoryBudgetOwner::Project("new-project".to_owned()),
                history_usage(1),
            )
            .unwrap();

        assert_eq!(ledger.accounting_steps - before, 1);
        assert_eq!(ledger.charged_global.versions, 8_193);
    }

    #[test]
    fn poisoned_history_and_tenancy_locks_fail_closed_with_recovered_accounting() {
        let backend = backend();
        let tenancy = Arc::new(RwLock::new(Tenancy::new("primary-app")));
        tenancy
            .write()
            .unwrap()
            .register("demo-app", &[], &[])
            .unwrap();
        backend.set_tenancy(tenancy.clone());
        let ledger = backend.history_budget.clone();

        assert!(std::panic::catch_unwind(|| {
            let _guard = ledger.lock().unwrap();
            panic!("poison history ledger");
        })
        .is_err());
        assert!(std::panic::catch_unwind(|| {
            let _guard = tenancy.write().unwrap();
            panic!("poison tenancy registry");
        })
        .is_err());

        let parent = parse_parent("projects/demo-app/databases/(default)/documents").unwrap();
        assert_eq!(
            backend.history_owner("demo-app"),
            HistoryBudgetOwner::Project("demo-app".to_owned())
        );
        let cancelled = backend
            .reserve_history(
                &parent,
                HistoryProjection {
                    before: HistoryUsage::default(),
                    after: history_usage(1),
                },
            )
            .unwrap();
        drop(cancelled);
        assert_eq!(backend.history_usage().versions, 0);

        let request = pb::CommitRequest {
            database: "projects/demo-app/databases/(default)".to_owned(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: "projects/demo-app/databases/(default)/documents/items/one".to_owned(),
                    fields: [(
                        "v".to_owned(),
                        pb::Value {
                            value_type: Some(pb::value::ValueType::IntegerValue(1)),
                        },
                    )]
                    .into_iter()
                    .collect(),
                    ..pb::Document::default()
                })),
                ..pb::Write::default()
            }],
            ..pb::CommitRequest::default()
        };
        backend.commit(&request).unwrap();
        let snapshot = backend.snapshot_databases();
        assert_eq!(backend.history_usage().versions, 1);
        backend.reset();
        assert_eq!(backend.history_usage().versions, 0);
        backend.restore_databases(snapshot).unwrap();
        assert_eq!(backend.history_usage().versions, 1);
    }

    #[test]
    fn two_readers_enter_the_same_database_concurrently() {
        let handle = DatabaseHandle(Arc::new(DatabaseEntry::restored(FirestoreState::new())));
        let first = handle.clone();
        let second = handle;
        let (first_entered_tx, first_entered_rx) = mpsc::channel();
        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let first_thread = std::thread::spawn(move || {
            first.read(|_| {
                first_entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
        });
        first_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        let second_thread = std::thread::spawn(move || {
            second.read(|_| {
                second_entered_tx.send(()).unwrap();
            })
        });

        let concurrent = second_entered_rx.recv_timeout(Duration::from_secs(1));
        release_tx.send(()).unwrap();
        assert!(first_thread.join().unwrap().is_some());
        assert!(second_thread.join().unwrap().is_some());
        assert!(concurrent.is_ok(), "the second reader waited for the first");
    }

    #[test]
    fn two_latest_gets_authorize_under_shared_database_locks() {
        let backend = backend();
        let request = pb::GetDocumentRequest {
            name: "projects/demo-app/databases/(default)/documents/items/missing".to_owned(),
            ..Default::default()
        };
        let (first_entered_tx, first_entered_rx) = mpsc::channel();
        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let first_backend = backend.clone();
        let first_request = request.clone();
        let first = std::thread::spawn(move || {
            let guard = |_: &FirestoreState, _: Option<CommitVersion>, _: ReadCheck<'_>| {
                first_entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            };
            first_backend.get_document_snapshot(&first_request, &guard)
        });
        first_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let second = std::thread::spawn(move || {
            let guard = |_: &FirestoreState, _: Option<CommitVersion>, _: ReadCheck<'_>| {
                second_entered_tx.send(()).unwrap();
                Ok(())
            };
            backend.get_document_snapshot(&request, &guard)
        });
        let concurrent = second_entered_rx.recv_timeout(Duration::from_secs(1));
        release_tx.send(()).unwrap();

        assert!(first.join().unwrap().is_ok());
        assert!(second.join().unwrap().is_ok());
        assert!(
            concurrent.is_ok(),
            "the second GetDocument waited for the first"
        );
    }

    #[tokio::test]
    async fn release_wait_checks_generation_after_registering_notification() {
        let backend = backend();
        let seen = backend.release_count();
        let signal = Arc::clone(&backend);
        let released = backend
            .await_any_release_after_registration(
                seen,
                std::time::Instant::now() + Duration::from_secs(1),
                move || {
                    signal
                        .release_count
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    signal.release_notify.notify_waiters();
                },
            )
            .await;
        assert!(released);
    }
}
