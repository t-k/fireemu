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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex, RwLock};

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::Query;
use fireemu_core_firestore::store::{
    Aggregation, CommitResult, CommitVersion, Document, DocumentChange, FirestoreError,
    FirestoreState, HistoryCapacityError, HistoryProjection, HistoryUsage, ListedDocument,
    Precondition, QueryExecutionId, QueryStats, TransactionId, Write, WriteOp,
};
use fireemu_core_firestore::ttl::{SweepSchedule, TtlCatalog, TtlError, TtlState};
use fireemu_core_firestore::value::Value;
use fireemu_core_session::barrier::AdmissionBarrier;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::{Clock, DeterministicRng, SplitMix64};
use fireemu_core_types::ids::{CollectionId, DatabaseId, DocumentId};
use fireemu_core_types::resources::{
    Gauge, Refusal, RetentionRoot, RootBudget, ServiceResources, Unit,
};
use fireemu_proto_firestore::google::firestore::v1 as pb;
use tonic::Status;

use crate::decode::{decode_structured_query_in, parse_parent, DecodeError, Parent};
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
    /// Never reused within a backend, including across resets and restores.
    incarnation: u64,
    cell: RwLock<DatabaseCell>,
    /// Wakes writers refused for lock contention when a transaction finishes.
    releases: TransactionReleases,
}

impl DatabaseEntry {
    /// A fresh, attached entry holding a restored state.
    fn restored(state: FirestoreState, incarnation: u64) -> Self {
        Self {
            incarnation,
            cell: RwLock::new(DatabaseCell {
                detached: false,
                state,
            }),
            releases: TransactionReleases::default(),
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

/// One attached catalog entry and its non-reused local incarnation.
pub type DatabaseCatalogEntry = ((String, String), u64);

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

/// Whether the caller of `LocalBackend::open_database` may bring a database into being.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// A data-plane request: it reaches a database that already exists, and materializes one
    /// only where the profile lets it.
    RequestOnly,
    /// A path that creates databases of its own (import, restore, the emulator's clear
    /// route): the database exists because this caller says so.
    Creates,
}

/// How many completed field-configuration operations are kept per project.
///
/// A campaign polls the operation its own patch returned, so only a short tail is useful;
/// the bound is what stops a caller that patches in a loop from growing this record. It is
/// per project so that one project's patches cannot evict another project's operations.
pub const FIELD_OPERATIONS_RETAINED_PER_PROJECT: usize = 64;

/// How many documents one expiry sweep deletes before it stops and leaves the rest to the
/// next one.
///
/// A sweep runs inside the control request that moved the clock, so an unbounded one would
/// hold that response open for as long as the store is large. The schedule is not marked
/// when a sweep stops at this bound, so the next clock move continues from where it left
/// off and every eligible document is still deleted, one bounded batch at a time.
pub const MAX_SWEEP_DELETES_PER_RUN: usize = 1024;

/// The expiry-sweep bookkeeping of every attached database.
///
/// The schedules and the in-progress set live under one lock so that deciding a sweep is
/// due and claiming it are a single step. Two callers that arrive together -- a clock move
/// and the control route, or two control requests -- therefore never scan the same database
/// twice for the same expiry.
#[derive(Debug, Default)]
struct TtlSweepState {
    schedules: BTreeMap<(String, String), SweepSchedule>,
    in_progress: BTreeSet<(String, String)>,
}

/// One completed `collectionGroups.fields.patch` long-running operation.
///
/// The local runtime applies a field configuration synchronously, so every recorded
/// operation is already done: the record exists so that the operation name the patch
/// returned can still be polled, which is how the Admin API is used. The rendered response
/// is kept with it, so polling the operation answers exactly what the patch answered even
/// after a later patch changed the field.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldOperation {
    /// `projects/{project}/databases/{database}/operations/{operation}`.
    pub name: String,
    /// The `Field` resource the operation configured.
    pub field: String,
    /// The virtual-clock instant at which the configuration was applied.
    pub at: fireemu_core_types::time::LogicalInstant,
    /// The `Field` resource as it stood when the operation completed.
    pub response: serde_json::Value,
}

/// Local backend state.
pub struct LocalBackend {
    gateway: Gateway,
    /// Reloadable index catalog used for every new query plan.
    indexes: RwLock<BTreeMap<(Option<String>, String), fireemu_core_firestore::index::IndexSet>>,
    /// Time-to-live field configuration per database, keyed like [`LocalBackend::indexes`]:
    /// a project-specific entry wins over the entry shared by every project.
    ttl: RwLock<BTreeMap<(Option<String>, String), TtlCatalog>>,
    /// When each attached database was last swept for expired documents, and which
    /// databases a sweep is running against right now.
    ttl_sweeps: Mutex<TtlSweepState>,
    /// How long an expired document stays readable before a sweep deletes it.
    ttl_sweep_interval: fireemu_core_types::time::LogicalDuration,
    /// The most recent completed field-configuration operations of each project, oldest
    /// first, bounded per project by [`FIELD_OPERATIONS_RETAINED_PER_PROJECT`] so that
    /// neither a caller nor another project can grow or evict this record.
    field_operations: Mutex<BTreeMap<String, std::collections::VecDeque<FieldOperation>>>,
    /// Monotonic ordinal of every recorded field-configuration operation. It never resets
    /// and never depends on how many records are retained, so two operations on the same
    /// field at the same virtual instant still get distinct names once the bound evicts.
    field_operation_ordinals: std::sync::atomic::AtomicU64,
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
    /// The databases that exist in every project without a request having created them: the
    /// ones the configuration declares. `(default)` is always one of them and is not listed.
    declared_databases: RwLock<BTreeSet<String>>,
    /// Whether a data-plane request against a database nothing created materializes it (what
    /// the official Firestore emulator does, the `emulator` profile) or is refused with the
    /// `NOT_FOUND` production answers for a database `databases.create` was never called for
    /// (the `strict` profile's default). There is no local counterpart of that method: a
    /// database comes into being here through the configuration, an import or a restore.
    implicit_database_creation: bool,
    /// Allocates identities for database instances independently of delayed wipe notifications.
    database_incarnations: std::sync::atomic::AtomicU64,
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
    /// Estimated bytes retained by execution-scoped value-order selections.
    query_selection_bytes: Arc<std::sync::atomic::AtomicU64>,
    /// Statistics of the most recent streamed query executions, oldest first, bounded by
    /// [`QUERY_EXECUTION_STATS_RETAINED`].
    query_execution_stats:
        Mutex<std::collections::VecDeque<(QueryExecutionId, QueryExecutionStats)>>,
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

/// Executions whose statistics [`LocalBackend`] keeps for inspection.
const QUERY_EXECUTION_STATS_RETAINED: usize = 64;

/// Work done by one streamed query execution, split into the stage that selects and orders
/// the candidates once and the stage that materializes each page. A general order builds a
/// path selection up front, so its scan counters land in `selection` and every page only
/// clones documents; a name order has no selection and each page scans from its cursor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueryExecutionStats {
    /// The selection stage: paths visited, filters evaluated and candidates held while the
    /// ordered path selection was built. `None` when the execution pages without one.
    pub selection: Option<QueryStats>,
    /// Paths retained by the selection.
    pub selection_paths: u64,
    /// Estimated bytes retained by the selection.
    pub selection_bytes: u64,
    /// The page stage accumulated over every page: counters add, the peak keeps its maximum.
    pub pages: QueryStats,
    /// Pages materialized so far.
    pub page_count: u64,
}

/// Ordered document paths retained for one streamed query execution. Keeping only paths makes
/// the continuation cursor independent of document body size while avoiding a candidate rescan
/// on every page.
#[derive(Debug, Clone)]
pub(crate) struct QuerySelection {
    inner: Arc<QuerySelectionInner>,
}

type AuthorizedQueryPage = (
    Vec<pb::RunQueryResponse>,
    Vec<String>,
    Option<Arc<QuerySelection>>,
);

#[derive(Debug)]
struct QuerySelectionInner {
    paths: Arc<[DocumentPath]>,
    retained_bytes: u64,
    retained_total: Arc<std::sync::atomic::AtomicU64>,
}

impl QuerySelection {
    fn from_paths(
        paths: Vec<DocumentPath>,
        retained_total: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        let retained_bytes = paths
            .iter()
            .map(|path| {
                u64::try_from(std::mem::size_of::<DocumentPath>())
                    .unwrap_or(u64::MAX)
                    .saturating_add(u64::try_from(path.resource_name().len()).unwrap_or(u64::MAX))
            })
            .fold(0u64, u64::saturating_add);
        let _ = retained_total.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |current| Some(current.saturating_add(retained_bytes)),
        );
        Self {
            inner: Arc::new(QuerySelectionInner {
                paths: Arc::from(paths),
                retained_bytes,
                retained_total,
            }),
        }
    }
}

impl Drop for QuerySelectionInner {
    fn drop(&mut self) {
        let _ = self.retained_total.fetch_update(
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
            |current| Some(current.saturating_sub(self.retained_bytes)),
        );
    }
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

    fn run_query_from_paths(
        &mut self,
        query: &Query,
        observed_query: &Query,
        selection: &QuerySelection,
        continuation: bool,
    ) -> Result<(Vec<Document>, QueryStats), Status> {
        let version = self.version()?;
        let execution_id = self
            .query_execution_id
            .ok_or_else(|| Status::internal("ordered query selection has no execution id"))?;
        let complete = self.complete_query_execution;
        match (&mut self.state, &self.selected.transaction) {
            (SnapshotState::Exclusive(db), Some(transaction)) => db
                .run_query_in_transaction_from_paths_with_stats_as_with_execution(
                    transaction,
                    query,
                    observed_query,
                    &selection.inner.paths,
                    execution_id,
                    continuation,
                    complete,
                )
                .map_err(|error| status_from_error(&error)),
            (SnapshotState::Shared(db), None) => {
                Ok(db.documents_at_query_paths_with_stats(query, &selection.inner.paths, version))
            }
            _ => Err(Status::internal("invalid Firestore snapshot access mode")),
        }
    }

    fn run_aggregation(
        &mut self,
        query: &Query,
        aggregations: &[Aggregation],
    ) -> Result<(Vec<Value>, QueryStats), Status> {
        let version = self.version()?;
        match (&mut self.state, &self.selected.transaction) {
            (SnapshotState::Exclusive(db), Some(transaction)) => db
                .run_aggregation_in_transaction_with_stats(transaction, query, aggregations)
                .map_err(|error| status_from_error(&error)),
            (SnapshotState::Shared(db), None) => db
                .run_aggregation_with_stats(query, aggregations, version)
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
                "Document \"{}\" not found.",
                self.path.resource_name()
            ))),
        }
    }
}

/// Rewrites limit diagnostics for the REST transport while retaining the internal status text
/// used by gRPC and core diagnostics.
pub fn rest_limit_diagnostic(status: &Status, resource: &str) -> Status {
    if status.code() == tonic::Code::NotFound
        && (status.message() == format!("No document to update: {resource}")
            || status.message() == format!("Document not found: {resource}"))
    {
        return Status::not_found(format!("Document \"{resource}\" not found."));
    }
    if status.code() == tonic::Code::InvalidArgument
        && is_document_resource(resource)
        && status
            .message()
            .starts_with("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH ")
    {
        let Some(property) = status
            .message()
            .split_once("; property=")
            .map(|(_, name)| name)
        else {
            return status.clone();
        };
        return Status::invalid_argument(format!(
            "Property {property} contains an invalid nested entity."
        ));
    }
    if status.code() != tonic::Code::InvalidArgument
        || !is_document_resource(resource)
        || status
            .metadata()
            .get("fireemu-limit-id")
            .and_then(|value| value.to_str().ok())
            != Some(fireemu_core_firestore::limits::DOCUMENT_BYTES)
    {
        return status.clone();
    }
    let Some((current, maximum)) = status.message().split_once(':').and_then(|(_, message)| {
        let mut words = message.split_whitespace();
        let current = words.next()?.parse::<u64>().ok()?;
        if words.next()? != "exceeds" {
            return None;
        }
        let maximum = words.next()?.parse::<u64>().ok()?;
        Some((current, maximum))
    }) else {
        return status.clone();
    };
    Status::invalid_argument(format!(
        "Document '{resource}' cannot be written because its size ({} bytes) exceeds the maximum allowed size of {} bytes.",
        format_decimal(current),
        format_decimal(maximum),
    ))
}

fn is_document_resource(resource: &str) -> bool {
    let Some(relative) = resource.split_once("/documents/").map(|(_, rest)| rest) else {
        return false;
    };
    !relative.is_empty() && relative.split('/').count() % 2 == 0
}

fn format_decimal(value: u64) -> String {
    let digits = value.to_string();
    let first = digits.len() % 3;
    let mut formatted = String::with_capacity(digits.len() + digits.len() / 3);
    if first != 0 {
        formatted.push_str(&digits[..first]);
    }
    for (index, chunk) in digits.as_bytes()[first..].chunks(3).enumerate() {
        if first != 0 || index != 0 {
            formatted.push(',');
        }
        formatted.push_str(std::str::from_utf8(chunk).expect("digits are ASCII"));
    }
    formatted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admission_backend() -> LocalBackend {
        LocalBackend::new(
            Gateway {
                enforce_limits: true,
                ctx: fireemu_core_firestore::index::PlanningContext {
                    edition: fireemu_core_types::edition::FirestoreEdition::Standard,
                    api_mode: fireemu_core_types::edition::FirestoreApiMode::Native,
                    policy: fireemu_core_firestore::index::IndexValidationPolicy::Production,
                },
                indexes: fireemu_core_firestore::index::IndexSet::default(),
            },
            Arc::new(Mutex::new(VirtualClock::new(
                fireemu_core_types::time::LogicalInstant::from_unix_seconds(1_788_004_860),
            ))),
            7,
        )
    }

    fn parent(database: &str) -> Parent {
        parse_parent(&format!("projects/demo-app/databases/{database}/documents")).unwrap()
    }

    #[test]
    fn a_configured_creation_time_bounds_read_times_instead_of_the_start() {
        use fireemu_core_types::time::LogicalInstant;
        let now = LogicalInstant::from_unix_seconds(1_788_004_860);
        let at = |seconds_before: i64| prost_types::Timestamp {
            seconds: 1_788_004_860 - seconds_before,
            nanos: 0,
        };
        let started = admission_backend();
        assert_eq!(started.created_at(), now);
        assert_eq!(
            started
                .read_time_selector(&at(60), now, now)
                .unwrap_err()
                .message(),
            "The requested 'read_time' cannot be before database creation time."
        );
        let created = LogicalInstant::from_unix_seconds(1_788_004_860 - 7200);
        let backend = admission_backend().with_created_at(created);
        assert_eq!(backend.created_at(), created);
        assert_eq!(
            backend.read_time_selector(&at(3540), now, now).unwrap(),
            LogicalInstant::from_unix_seconds(1_788_004_860 - 3540)
        );
        let too_old = backend.read_time_selector(&at(3660), now, now).unwrap_err();
        assert_eq!(
            (too_old.code(), too_old.message()),
            (
                tonic::Code::FailedPrecondition,
                "The requested 'read_time' is too old."
            )
        );
        assert_eq!(
            backend
                .read_time_selector(&at(7201), now, now)
                .unwrap_err()
                .message(),
            "The requested 'read_time' cannot be before database creation time."
        );
    }

    #[test]
    fn a_database_nothing_created_is_refused_and_is_not_materialized_by_the_refusal() {
        let backend = admission_backend();
        let error = backend
            .database_handle(&parent("never-created"))
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::NotFound);
        assert_eq!(
            error.message(),
            "The database never-created does not exist for project demo-app Please visit \
             https://console.cloud.google.com/datastore/setup?project=demo-app to add a Cloud \
             Datastore or Cloud Firestore database. "
        );
        // A refused request leaves no entry behind, so a second request is refused for the
        // same reason rather than admitted by the first one's side effect.
        assert!(backend.database_catalog().unwrap().is_empty());
        assert_eq!(
            backend
                .database_handle(&parent("never-created"))
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
    }

    #[test]
    fn the_default_and_declared_databases_exist_before_anything_creates_them() {
        let backend = admission_backend().with_declared_databases(["analytics".to_owned()]);
        assert!(backend.database_handle(&parent("(default)")).is_ok());
        assert!(backend.database_handle(&parent("analytics")).is_ok());
        assert_eq!(
            backend
                .database_handle(&parent("reporting"))
                .unwrap_err()
                .code(),
            tonic::Code::NotFound
        );
        // A reload that adds a database makes it reachable; one that drops a database does
        // not unmake the state it already holds.
        backend.replace_declared_databases(["reporting".to_owned()]);
        assert!(backend.database_handle(&parent("reporting")).is_ok());
        assert!(backend.database_handle(&parent("analytics")).is_ok());
    }

    #[test]
    fn a_create_path_makes_a_database_reachable_by_later_requests() {
        let backend = admission_backend();
        assert!(backend.ensure_database(&parent("imported")).is_ok());
        assert!(backend.database_handle(&parent("imported")).is_ok());
    }

    #[test]
    fn the_emulator_profile_materializes_any_database_on_first_touch() {
        // The official Firestore emulator serves any syntactically valid database id without
        // a create, and the `emulator` profile may not refuse more than it does.
        let backend = admission_backend().with_implicit_database_creation(true);
        assert!(backend.database_handle(&parent("never-created")).is_ok());
        assert_eq!(backend.database_catalog().unwrap().len(), 1);
    }

    #[test]
    fn replace_database_indexes_reports_a_poisoned_catalog_lock() {
        let clock = Arc::new(Mutex::new(VirtualClock::new(
            fireemu_core_types::time::LogicalInstant::UNIX_EPOCH,
        )));
        let backend = LocalBackend::new(
            Gateway {
                enforce_limits: true,
                ctx: fireemu_core_firestore::index::PlanningContext {
                    edition: fireemu_core_types::edition::FirestoreEdition::Standard,
                    api_mode: fireemu_core_types::edition::FirestoreApiMode::Native,
                    policy: fireemu_core_firestore::index::IndexValidationPolicy::Production,
                },
                indexes: fireemu_core_firestore::index::IndexSet::default(),
            },
            clock,
            7,
        );
        assert!(backend.replace_database_indexes(
            "staging",
            fireemu_core_firestore::index::IndexSet::default(),
        ));
        let lock = &backend.indexes;
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = lock.write().unwrap();
            panic!("poison the index catalog lock");
        }));
        assert!(poisoned.is_err());

        assert!(!backend.replace_database_indexes(
            "staging",
            fireemu_core_firestore::index::IndexSet::default(),
        ));
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
            ttl: RwLock::new(BTreeMap::new()),
            ttl_sweeps: Mutex::new(TtlSweepState::default()),
            ttl_sweep_interval: fireemu_core_firestore::ttl::DEFAULT_SWEEP_INTERVAL,
            field_operations: Mutex::new(BTreeMap::new()),
            field_operation_ordinals: std::sync::atomic::AtomicU64::new(0),
            clock,
            wall_clock_write_time: false,
            history_version_limit:
                fireemu_core_firestore::store::DEFAULT_MAX_RETAINED_VERSIONS_PER_PATH,
            history_budget: Arc::new(Mutex::new(HistoryBudgetLedger::new(
                HistoryBudgetLimits::default(),
            ))),
            tenancy: Mutex::new(None),
            databases: Mutex::new(BTreeMap::new()),
            declared_databases: RwLock::new(BTreeSet::new()),
            implicit_database_creation: false,
            database_incarnations: std::sync::atomic::AtomicU64::new(0),
            faults: Mutex::new(None),
            clock_observer: Mutex::new(None),
            generations: Mutex::new(BTreeMap::new()),
            ids: Mutex::new(SplitMix64::new(seed)),
            transaction_ids: Mutex::new(SplitMix64::new(seed ^ 0x0054_584e)),
            query_execution_ids: std::sync::atomic::AtomicU64::new(0),
            query_selection_bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            query_execution_stats: Mutex::new(std::collections::VecDeque::new()),
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

    /// When the databases came into being, instead of the clock at construction: the
    /// `createTime` they report and the instant before which a `read_time` is refused.
    #[must_use]
    pub const fn with_created_at(
        mut self,
        created_at: fireemu_core_types::time::LogicalInstant,
    ) -> Self {
        self.created_at = created_at;
        self
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

    /// The databases the configuration declares, which therefore exist in every project
    /// before any request touches them. `(default)` need not be listed.
    #[must_use]
    pub fn with_declared_databases(self, ids: impl IntoIterator<Item = String>) -> Self {
        self.replace_declared_databases(ids);
        self
    }

    /// Replaces the declared databases on a running backend (a configuration reload). A
    /// database already materialized stays reachable: this decides which databases a request
    /// may reach before anything created them, never which ones exist.
    pub fn replace_declared_databases(&self, ids: impl IntoIterator<Item = String>) {
        let mut declared = self
            .declared_databases
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *declared = ids
            .into_iter()
            .filter(|id| id != DatabaseId::DEFAULT)
            .collect();
    }

    /// Materializes an undeclared database on first touch the way the official Firestore
    /// emulator does, instead of refusing it with the `NOT_FOUND` production answers for a
    /// database that was never created. The `emulator` compatibility profile selects this;
    /// the constructor's default is production's refusal.
    #[must_use]
    pub const fn with_implicit_database_creation(mut self, implicit: bool) -> Self {
        self.implicit_database_creation = implicit;
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

    /// Clears every database of one project while preserving its catalog entries.
    ///
    /// This is the semantics of the emulator's `clearFirestore` route: document data is
    /// dropped, but an existing database remains discoverable through the Admin inventory.
    /// The exclusive admission guard makes catalog removal and recreation one operation, and
    /// the range lookup avoids inspecting databases owned by other projects.
    pub fn clear_project_documents(&self, project: &str) -> Result<(), Status> {
        let _exclusive = self.barrier.exclusive();
        let keys = self.take_project(project);
        self.bump_generations(&keys);
        self.announce_wipe(keys.clone());
        for database in keys.into_iter().map(|(_, database)| database) {
            let parent = parse_parent(&format!(
                "projects/{project}/databases/{database}/documents"
            ))
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
            // The route's contract is that a database it cleared survives its own clearing,
            // whatever the profile says about a database nothing created.
            self.ensure_database(&parent)?;
        }
        Ok(())
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

    fn take_project(&self, project: &str) -> Vec<(String, String)> {
        let removed: Vec<((String, String), DatabaseHandle)> = match self.databases.lock() {
            Ok(mut dbs) => {
                let start = (project.to_owned(), String::new());
                let keys: Vec<(String, String)> = dbs
                    .range(start..)
                    .take_while(|((p, _), _)| p == project)
                    .map(|(key, _)| key.clone())
                    .collect();
                keys.into_iter()
                    .filter_map(|key| dbs.remove(&key).map(|entry| (key, DatabaseHandle(entry))))
                    .collect()
            }
            Err(_) => Vec::new(),
        };
        let keys: Vec<_> = removed
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
        if scope.is_default() {
            gauges.push(Gauge::logical(
                "queries.ordered_selection_bytes",
                Unit::Bytes,
                self.query_selection_bytes
                    .load(std::sync::atomic::Ordering::Acquire),
                None,
            ));
        }
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
                            self.database_incarnations
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
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
        let indexes = self.indexes.read().map_err(|_| lock_poisoned())?;
        let key = (
            Some(parent.project.as_str().to_owned()),
            parent.database.as_str().to_owned(),
        );
        let shared = (None, parent.database.as_str().to_owned());
        db.set_index_catalog(
            indexes
                .get(&key)
                .or_else(|| indexes.get(&shared))
                .cloned()
                .unwrap_or_default(),
        );
        drop(indexes);
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
        let query = decode_structured_query_in(parent, sq, self.gateway.production_refusals())
            .map_err(status)?;
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
            .map_err(|rejection| rejection.to_status_in(&crate::gateway::database_name(parent)))
    }

    /// Decodes and validates a structured aggregation query through the strict gateway.
    pub fn accepted_aggregation_query(
        &self,
        parent: &Parent,
        sq: &pb::StructuredQuery,
        aggregations: &[Aggregation],
    ) -> Result<AcceptedQuery, Status> {
        let query = decode_structured_query_in(parent, sq, self.gateway.production_refusals())
            .map_err(status)?;
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
            .validate_aggregation_query_with_indexes(&query, aggregations, database_indexes)
            .map_err(|rejection| rejection.to_status_in(&crate::gateway::database_name(parent)))
    }

    /// Atomically replaces the index catalog used by subsequent query plans.
    pub fn replace_indexes(&self, indexes: fireemu_core_firestore::index::IndexSet) {
        self.replace_database_indexes(DatabaseId::DEFAULT, indexes);
    }

    /// Atomically replaces one database's index catalog.
    ///
    /// Returns `false` when the shared catalog lock is poisoned and the replacement is not
    /// applied.
    pub fn replace_database_indexes(
        &self,
        database: &str,
        indexes: fireemu_core_firestore::index::IndexSet,
    ) -> bool {
        if let Ok(mut current) = self.indexes.write() {
            current.insert((None, database.to_owned()), indexes);
            true
        } else {
            false
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

    /// Returns the project-specific catalog, falling back to the shared database catalog.
    #[must_use]
    pub fn indexes_for_project_database(
        &self,
        project: &str,
        database: &str,
    ) -> fireemu_core_firestore::index::IndexSet {
        let indexes = self
            .indexes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        indexes
            .get(&(Some(project.to_owned()), database.to_owned()))
            .or_else(|| indexes.get(&(None, database.to_owned())))
            .cloned()
            .unwrap_or_default()
    }

    /// Sets how long an expired document stays readable before a sweep deletes it.
    ///
    /// Production deletes typically within 24 hours of expiry and within 72 hours at worst,
    /// so the interval is what a local run varies to reproduce either end of that window.
    #[must_use]
    pub const fn with_ttl_sweep_interval(
        mut self,
        interval: fireemu_core_types::time::LogicalDuration,
    ) -> Self {
        self.ttl_sweep_interval = interval;
        self
    }

    /// The interval between expiry sweeps.
    #[must_use]
    pub const fn ttl_sweep_interval(&self) -> fireemu_core_types::time::LogicalDuration {
        self.ttl_sweep_interval
    }

    /// Returns one database's time-to-live field configuration, falling back to the catalog
    /// shared by every project.
    #[must_use]
    pub fn ttl_catalog(&self, project: &str, database: &str) -> TtlCatalog {
        let catalogs = self
            .ttl
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        catalogs
            .get(&(Some(project.to_owned()), database.to_owned()))
            .or_else(|| catalogs.get(&(None, database.to_owned())))
            .cloned()
            .unwrap_or_default()
    }

    /// Returns the time-to-live policy in force for one collection group.
    ///
    /// The caller that reads a single policy copies that policy alone rather than the whole
    /// catalog, which matters where the read happens under another lock: the expiry sweep
    /// reads it inside the database critical section that commits the deletion.
    #[must_use]
    pub fn ttl_policy(
        &self,
        project: &str,
        database: &str,
        collection_group: &CollectionId,
    ) -> Option<fireemu_core_firestore::ttl::TtlPolicy> {
        let catalogs = self
            .ttl
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        catalogs
            .get(&(Some(project.to_owned()), database.to_owned()))
            .or_else(|| catalogs.get(&(None, database.to_owned())))
            .and_then(|catalog| catalog.policy(collection_group))
            .cloned()
    }

    /// Replaces one database's time-to-live field configuration.
    ///
    /// Used by an import and by a snapshot restore, which install a whole catalog rather
    /// than replaying the patches that built it.
    pub fn replace_ttl_catalog(&self, project: &str, database: &str, catalog: TtlCatalog) {
        let mut catalogs = self
            .ttl
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if catalog.is_empty() {
            catalogs.remove(&(Some(project.to_owned()), database.to_owned()));
        } else {
            catalogs.insert((Some(project.to_owned()), database.to_owned()), catalog);
        }
    }

    /// Every configured time-to-live catalog, keyed by project and database.
    ///
    /// Only the project-specific entries are reported: the shared fallback belongs to the
    /// configuration that installed it, not to any one database's state.
    #[must_use]
    pub fn ttl_catalogs(&self) -> BTreeMap<(String, String), TtlCatalog> {
        let catalogs = self
            .ttl
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        catalogs
            .iter()
            .filter_map(|((project, database), catalog)| {
                project
                    .as_ref()
                    .map(|project| ((project.clone(), database.clone()), catalog.clone()))
            })
            .collect()
    }

    /// Replaces every time-to-live catalog `owned` selects, leaving the rest untouched.
    ///
    /// A snapshot restore and an import both install a whole configuration rather than
    /// replaying the patches that built it, and both are scoped: a project the transition
    /// does not own keeps its policies.
    pub fn restore_ttl_catalogs(
        &self,
        owned: impl Fn(&str) -> bool,
        catalogs: &BTreeMap<(String, String), TtlCatalog>,
    ) {
        let mut current = self
            .ttl
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        current.retain(|(project, _), _| project.as_ref().is_none_or(|p| !owned(p)));
        for ((project, database), catalog) in catalogs {
            if catalog.is_empty() || !owned(project) {
                continue;
            }
            current.insert((Some(project.clone()), database.clone()), catalog.clone());
        }
        drop(current);
        // A restored policy is in force from the restore, so its sweep interval restarts
        // here rather than carrying the schedule of the run that captured it.
        let now = self.now();
        let mut state = self
            .ttl_sweeps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.schedules.retain(|(project, _), _| !owned(project));
        for (key, catalog) in catalogs {
            if catalog.is_empty() || !owned(&key.0) {
                continue;
            }
            let mut schedule = SweepSchedule::new(self.ttl_sweep_interval);
            schedule.start(now);
            state.schedules.insert(key.clone(), schedule);
        }
    }

    /// Enables a time-to-live policy on one collection group field.
    pub fn enable_ttl(
        &self,
        project: &str,
        database: &str,
        collection_group: CollectionId,
        field: FieldPath,
    ) -> Result<TtlState, TtlError> {
        self.enable_ttl_with_offset(project, database, collection_group, field, None)
    }

    /// Enables a time-to-live policy carrying the `expirationOffset` the patch named.
    ///
    /// The expiration time of a document is the stored timestamp plus this offset, so the
    /// sweep that follows honours it without any further bookkeeping.
    pub fn enable_ttl_with_offset(
        &self,
        project: &str,
        database: &str,
        collection_group: CollectionId,
        field: FieldPath,
        expiration_offset: Option<fireemu_core_types::time::LogicalDuration>,
    ) -> Result<TtlState, TtlError> {
        let key = (Some(project.to_owned()), database.to_owned());
        let mut catalogs = self
            .ttl
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let catalog = catalogs.entry(key).or_default();
        let state = catalog.enable_with_offset(collection_group, field, expiration_offset)?;
        drop(catalogs);
        // The policy takes effect now, so the sweep interval is measured from now: a
        // document that was already expired when the policy was created still survives one
        // interval, which is what production's own deletion delay means.
        let now = self.now();
        self.ttl_sweeps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .schedules
            .entry((project.to_owned(), database.to_owned()))
            .or_insert_with(|| SweepSchedule::new(self.ttl_sweep_interval))
            .start(now);
        Ok(state)
    }

    /// Removes the time-to-live policy on one collection group field, reporting whether one
    /// was in force.
    pub fn disable_ttl(
        &self,
        project: &str,
        database: &str,
        collection_group: &CollectionId,
        field: &FieldPath,
    ) -> bool {
        let key = (Some(project.to_owned()), database.to_owned());
        let mut catalogs = self
            .ttl
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(catalog) = catalogs.get_mut(&key) else {
            return false;
        };
        let removed = catalog.disable(collection_group, field);
        if catalog.is_empty() {
            catalogs.remove(&key);
        }
        removed
    }

    /// Records one completed field-configuration operation and returns its resource name.
    pub fn record_field_operation(
        &self,
        project: &str,
        database: &str,
        field: &str,
        at: fireemu_core_types::time::LogicalInstant,
        response: serde_json::Value,
    ) -> String {
        // The ordinal is monotonic and independent of how many records are retained, so a
        // patch that arrives after the bound has started evicting still gets a name of its
        // own even when the clock has not moved and the field is the same.
        let ordinal = self
            .field_operation_ordinals
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut digest = fireemu_core_types::hash::Sha256::new();
        digest.update(b"fireemu:field-operation:");
        digest.update(field.as_bytes());
        digest.update(b":");
        digest.update(at.as_nanos().to_string().as_bytes());
        digest.update(b":");
        digest.update(ordinal.to_string().as_bytes());
        let id = fireemu_core_types::hash::hex_lower(&digest.finalize()[..12]);
        let name = format!("projects/{project}/databases/{database}/operations/{id}");
        let mut operations = self
            .field_operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let project_operations = operations.entry(project.to_owned()).or_default();
        project_operations.push_back(FieldOperation {
            name: name.clone(),
            field: field.to_owned(),
            at,
            response,
        });
        while project_operations.len() > FIELD_OPERATIONS_RETAINED_PER_PROJECT {
            project_operations.pop_front();
        }
        name
    }

    /// One project's recorded field-configuration operation, if it is still retained.
    #[must_use]
    pub fn field_operation(&self, project: &str, name: &str) -> Option<FieldOperation> {
        self.field_operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(project)?
            .iter()
            .find(|operation| operation.name == name)
            .cloned()
    }

    /// One project's retained field-configuration operations, oldest first.
    #[must_use]
    pub fn field_operations(&self, project: &str) -> Vec<FieldOperation> {
        self.field_operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(project)
            .map(|operations| operations.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Every project's retained field-configuration operations, for a snapshot capture.
    #[must_use]
    pub fn field_operations_by_project(&self) -> BTreeMap<String, Vec<FieldOperation>> {
        self.field_operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(project, operations)| (project.clone(), operations.iter().cloned().collect()))
            .collect()
    }

    /// Replaces the field-configuration operations of every project `owned` selects.
    ///
    /// A restore that left them in place would keep answering an operation name minted
    /// against state the restore has just replaced.
    pub fn restore_field_operations(
        &self,
        owned: impl Fn(&str) -> bool,
        captured: &BTreeMap<String, Vec<FieldOperation>>,
    ) {
        let mut operations = self
            .field_operations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        operations.retain(|project, _| !owned(project));
        for (project, records) in captured {
            if records.is_empty() || !owned(project) {
                continue;
            }
            operations.insert(project.clone(), records.iter().cloned().collect());
        }
    }

    /// Establishes the sweep baseline of every database `scope` owns that has a policy, so
    /// that a document expiring before the first clock advance is still observable for one
    /// interval rather than being deleted by the first sweep that runs.
    pub fn start_ttl_sweeps(
        &self,
        scope: &fireemu_core_session::tenancy::Scope,
        now: fireemu_core_types::time::LogicalInstant,
    ) {
        let Ok(catalog) = self.database_catalog() else {
            return;
        };
        let mut state = self
            .ttl_sweeps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for ((project, database), _incarnation) in catalog {
            if !scope.owns_project(&project) {
                continue;
            }
            state
                .schedules
                .entry((project, database))
                .or_insert_with(|| SweepSchedule::new(self.ttl_sweep_interval))
                .start(now);
        }
    }

    /// Deletes every document whose time-to-live field expired before `now`, in every
    /// database `scope` owns whose sweep is due, and returns how many were deleted.
    ///
    /// A deletion is an ordinary delete: it takes the database's own lock, publishes a
    /// change to every listener, delivers the Firestore triggers and evaluates no Security
    /// Rules, which is what production's own expiry does. At most
    /// [`MAX_SWEEP_DELETES_PER_RUN`] documents are deleted per call; a sweep that stops at
    /// that bound does not record itself as having run, so the next one continues.
    pub fn sweep_expired_documents(
        &self,
        scope: &fireemu_core_session::tenancy::Scope,
        now: fireemu_core_types::time::LogicalInstant,
    ) -> usize {
        self.sweep_ttl(scope, now, false)
    }

    /// Runs one expiry sweep whether or not the interval has elapsed, for the control
    /// endpoint that lets a test observe the post-expiry state without advancing a day.
    pub fn sweep_expired_documents_now(
        &self,
        scope: &fireemu_core_session::tenancy::Scope,
        now: fireemu_core_types::time::LogicalInstant,
    ) -> usize {
        self.sweep_ttl(scope, now, true)
    }

    /// One forced sweep with a seam between the candidate scan and the first deletion.
    ///
    /// The sweep selects candidates with a query and then deletes each one under the
    /// database's own lock, re-reading it there. `after_scan` runs between the two, which is
    /// the only way a test can drive a write into that window deterministically; the
    /// production entry points pass a hook that does nothing.
    pub fn sweep_expired_documents_now_with_hook(
        &self,
        scope: &fireemu_core_session::tenancy::Scope,
        now: fireemu_core_types::time::LogicalInstant,
        after_scan: &(dyn Fn() + Sync),
    ) -> usize {
        self.sweep_ttl_with_hook(scope, now, true, after_scan)
    }

    fn sweep_ttl(
        &self,
        scope: &fireemu_core_session::tenancy::Scope,
        now: fireemu_core_types::time::LogicalInstant,
        force: bool,
    ) -> usize {
        self.sweep_ttl_with_hook(scope, now, force, &|| {})
    }

    fn sweep_ttl_with_hook(
        &self,
        scope: &fireemu_core_session::tenancy::Scope,
        now: fireemu_core_types::time::LogicalInstant,
        force: bool,
        after_scan: &(dyn Fn() + Sync),
    ) -> usize {
        let Ok(catalog) = self.database_catalog() else {
            return 0;
        };
        let mut deleted = 0;
        for ((project, database), _incarnation) in catalog {
            // A sweep belongs to the session that asked for it: another session's project
            // keeps the grace period between expiry and deletion that its own clock defines.
            if !scope.owns_project(&project) {
                continue;
            }
            let policies = self.ttl_catalog(&project, &database);
            if policies.is_empty() {
                continue;
            }
            let budget = MAX_SWEEP_DELETES_PER_RUN.saturating_sub(deleted);
            if budget == 0 {
                break;
            }
            let key = (project.clone(), database.clone());
            // Deciding the sweep is due and claiming it are one step under one lock, so a
            // second caller that arrives while this one scans is turned away instead of
            // scanning the same database for the same expiry.
            let Some(previous) = self.claim_sweep(&key, now, force) else {
                continue;
            };
            let (swept, complete) =
                self.sweep_one_database(&project, &database, &policies, now, budget, after_scan);
            deleted += swept;
            // Only a sweep that reached the end of its work counts as having run. One that
            // stopped at the budget gives the schedule back, so the next clock move
            // continues instead of waiting another interval.
            self.release_sweep(&key, previous, complete);
        }
        deleted
    }

    /// Claims one database's sweep, returning the schedule as it stood so that a truncated
    /// sweep can give it back. `None` means this call must not sweep: either the interval
    /// has not elapsed, or another caller is already sweeping this database.
    fn claim_sweep(
        &self,
        key: &(String, String),
        now: fireemu_core_types::time::LogicalInstant,
        force: bool,
    ) -> Option<SweepSchedule> {
        let mut state = self
            .ttl_sweeps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.in_progress.contains(key) {
            return None;
        }
        let schedule = state
            .schedules
            .entry(key.clone())
            .or_insert_with(|| SweepSchedule::new(self.ttl_sweep_interval));
        if !force && !schedule.due(now) {
            schedule.start(now);
            return None;
        }
        let previous = schedule.clone();
        schedule.mark(now);
        state.in_progress.insert(key.clone());
        Some(previous)
    }

    /// Releases the claim [`Self::claim_sweep`] took. A sweep that did not finish its work
    /// restores the schedule it found, so the database stays due.
    fn release_sweep(&self, key: &(String, String), previous: SweepSchedule, complete: bool) {
        let mut state = self
            .ttl_sweeps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.in_progress.remove(key);
        if !complete {
            state.schedules.insert(key.clone(), previous);
        }
    }

    /// Sweeps one database, deleting at most `budget` documents. Returns how many were
    /// deleted and whether every eligible document was reached.
    fn sweep_one_database(
        &self,
        project: &str,
        database: &str,
        policies: &TtlCatalog,
        now: fireemu_core_types::time::LogicalInstant,
        budget: usize,
        after_scan: &(dyn Fn() + Sync),
    ) -> (usize, bool) {
        let (Ok(project_id), Ok(database_id)) = (
            fireemu_core_types::ids::ProjectId::try_new(project),
            DatabaseId::try_new(database),
        ) else {
            // A catalog entry whose identifiers do not parse can never be addressed by a
            // data-plane request either, so there is nothing to sweep and nothing to carry
            // over. The field-configuration surface refuses such identifiers before they
            // reach the catalog.
            return (0, true);
        };
        let parent = Parent {
            project: project_id,
            database: database_id,
            document: None,
        };
        let expires_at = fireemu_core_firestore::ttl::timestamp_at(now);
        let mut deleted = 0;
        let mut complete = true;
        for (collection_group, policy) in policies {
            // Only the time-to-live field is projected, so a sweep never clones a document's
            // payload to decide that the document stays.
            let query = Query {
                projection: Some(vec![policy.field.clone()]),
                ..Query::new(fireemu_core_firestore::query::QueryScope::collection_group(
                    collection_group.clone(),
                ))
            };
            let Ok(documents) = self.run_query_latest(&parent, &query) else {
                continue;
            };
            let mut expired = documents
                .into_iter()
                .filter(|document| policy.is_expired(&document.fields, expires_at))
                .map(|document| document.path)
                .peekable();
            // The scan is over; anything a client writes from here on is seen by the
            // re-evaluation each deletion performs, not by the selection above.
            after_scan();
            for path in expired.by_ref() {
                if deleted >= budget {
                    complete = false;
                    break;
                }
                if self.delete_if_still_expired(&parent, &path, collection_group, expires_at) {
                    deleted += 1;
                }
            }
            if expired.peek().is_some() {
                complete = false;
            }
            if !complete {
                break;
            }
        }
        (deleted, complete)
    }

    /// Deletes one expiry candidate, reporting whether it was deleted.
    ///
    /// The candidate was chosen by a query that ran earlier, so the version it named may no
    /// longer be the current one: a client may have extended the time-to-live field, cleared
    /// it, written a value of another type, or deleted the document and written a new one at
    /// the same path. The policy itself may also have moved: a caller may have cleared it,
    /// changed its `expirationOffset`, or put it on another field of the same collection
    /// group.
    ///
    /// Both halves of the decision are therefore taken again here, inside the database's own
    /// critical section that then commits the deletion: the policy in force for the
    /// collection group, and the version of the document current in that section. A document
    /// whose collection group no longer carries a policy, or whose current version that
    /// policy does not mark expired, is kept. That is what production's own expiry does: the
    /// configuration and the field value in force at the moment of deletion decide.
    fn delete_if_still_expired(
        &self,
        parent: &Parent,
        path: &DocumentPath,
        collection_group: &CollectionId,
        expires_at: fireemu_core_firestore::value::Timestamp,
    ) -> bool {
        let write = Write {
            op: WriteOp::Delete { path: path.clone() },
            precondition: None,
            transforms: vec![],
        };
        self.retry_on_contention(parent, None, std::slice::from_ref(&write), || {
            // The fault belongs to the attempt, not to the candidate, which is where
            // `delete_document_once` evaluates it: a configured commit fault that is spent
            // by one attempt is spent, and the retry after contention draws the next one.
            self.fault(parent.project.as_str(), "firestore.commit")?;
            let now = self.write_time();
            self.with_db(parent, |db| {
                // The catalog lock is taken under this database's lock and released before
                // the commit. Nothing holds the catalog while acquiring a database lock, so
                // the two never contend in the other order. One policy is copied out, not
                // the catalog, so the work under the database lock does not grow with how
                // many collection groups the database configured.
                let policy = self.ttl_policy(
                    parent.project.as_str(),
                    parent.database.as_str(),
                    collection_group,
                );
                let still_expired = policy.is_some_and(|policy| {
                    db.get(path)
                        .is_some_and(|document| policy.is_expired(&document.fields, expires_at))
                });
                if !still_expired {
                    return Ok(false);
                }
                self.commit_with_events(parent, db, std::slice::from_ref(&write), None, now)?;
                Ok(true)
            })
        })
        .unwrap_or(false)
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

    /// Latest query with captured Rules/epoch admission.
    pub fn run_query_latest_guarded(
        &self,
        parent: &Parent,
        query: &Query,
        guard: ReadGuard<'_>,
    ) -> Result<Vec<Document>, Status> {
        self.read_db(parent, |db| {
            guard(db, None, ReadCheck::Query { parent, query })?;
            db.run_query(query, None).map_err(|e| status_from_error(&e))
        })
    }

    /// `PartitionQuery`: up to `partition_count` cursor points that split a collection-group
    /// query (ordered by `__name__`, without filters, other orderings, limits or cursors) at
    /// sampled keys as production does (see [`crate::partition`]), paged by `page_size` /
    /// `page_token`.
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
            return Err(Status::invalid_argument(crate::partition::ANCESTOR_QUERY));
        }
        let Some(pb::partition_query_request::QueryType::StructuredQuery(sq)) = &req.query_type
        else {
            return Err(Status::invalid_argument(
                crate::query_messages::PARTITION_WITHOUT_QUERY,
            ));
        };
        self.fault(parent.project.as_str(), "firestore.read")?;
        if req.partition_count <= 0 {
            return Err(Status::invalid_argument(
                crate::partition::COUNT_NOT_POSITIVE,
            ));
        }
        if req.page_size < 0 {
            return Err(Status::invalid_argument(
                crate::partition::PAGE_SIZE_NEGATIVE,
            ));
        }
        let query = self.accepted_query(&parent, sq)?.query;
        if query.find_nearest.is_some() {
            return Err(Status::unimplemented(
                "PartitionQuery does not support findNearest",
            ));
        }
        // Production answers a kindless query, or one without an explicit order, with no
        // partition at all.
        let split = crate::partition::check_query(&query).map_err(Status::invalid_argument)?;
        let name_ascending_only = query.order_by.iter().all(|o| {
            o.field.is_document_name()
                && o.direction == fireemu_core_firestore::query::Direction::Ascending
        });
        if split && (query.filter.is_some() || !name_ascending_only) {
            return Err(Status::invalid_argument(
                "PartitionQuery requires a collection group query ordered by __name__ only (no filters, order bys, limits, offsets or cursors)",
            ));
        }
        let partition_count = usize::try_from(req.partition_count)
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| Status::invalid_argument(crate::partition::COUNT_NOT_POSITIVE))?;
        let collection_id = query
            .scope
            .collection_id()
            .map_or_else(String::new, |id| id.as_str().to_owned());
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
        // The fingerprint covers the version too, so a token cannot be edited to read an
        // older snapshot than the one it was issued for.
        let bound = |version: u64| {
            version.to_be_bytes().iter().fold(fingerprint, |h, b| {
                (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
            })
        };
        // The page token: `<version>:<fingerprint of the request and version>:<index>`.
        let (token_version, start) = if req.page_token.is_empty() {
            (None, 0usize)
        } else {
            let parts: Vec<&str> = req.page_token.split(':').collect();
            let parsed = match parts.as_slice() {
                [v, f, i] => v
                    .parse::<u64>()
                    .ok()
                    .zip(f.parse::<u64>().ok())
                    .zip(i.parse::<usize>().ok()),
                _ => None,
            };
            // Production: a token it cannot read, and one issued for another request (another
            // query, count or read time, or before a reset), in its own words.
            let ((v, f), i) = parsed
                .ok_or_else(|| Status::invalid_argument(crate::partition::TOKEN_UNREADABLE))?;
            if f != bound(v) {
                return Err(Status::invalid_argument(crate::partition::TOKEN_FOREIGN));
            }
            (Some(CommitVersion::from_value(v)), i)
        };
        let (paths, version): (Vec<DocumentPath>, CommitVersion) = self.read_db(&parent, |db| {
            let version = match (token_version, read_time) {
                (Some(v), _) => v,
                (None, Some(t)) => db.version_at(t),
                (None, None) => db.current_version(),
            };
            if version > db.current_version() {
                return Err(Status::invalid_argument(crate::partition::TOKEN_FOREIGN));
            }
            if !split {
                return Ok((Vec::new(), version));
            }
            let (group, _) = db
                .run_query_paths_with_stats(&query, Some(version))
                .map_err(|error| status_from_error(&error))?;
            Ok((
                crate::partition::partition_cursors(&group, partition_count),
                version,
            ))
        })?;
        let cursors: Vec<pb::Cursor> = paths
            .into_iter()
            .map(|path| pb::Cursor {
                values: vec![pb::Value {
                    value_type: Some(pb::value::ValueType::ReferenceValue(path.resource_name())),
                }],
                before: false,
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
                format!("{}:{}:{end}", version.value(), bound(version.value()))
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

    /// The handle of one database for a request that did not create it. Its entry is created
    /// on first touch only for a database that exists without one (`(default)`, or one the
    /// configuration declares), or when the profile materializes any database on first touch;
    /// otherwise this is the `NOT_FOUND` production answers for a database that was never
    /// created. [`Self::ensure_database`] is the way a database comes into being locally. The
    /// catalog lock is held only for this lookup.
    ///
    /// Operations through the returned handle take no session admission and are not
    /// coordinated with a reset beyond the handle's own detachment; request surfaces
    /// should use [`LocalBackend`]'s operations, which admit first.
    pub fn database_handle(&self, parent: &Parent) -> Result<DatabaseHandle, Status> {
        self.open_database(parent, Admission::RequestOnly)
    }

    /// The handle of one database, creating its entry whatever the profile says: the caller
    /// is itself a path that brings a database into being (an import, a snapshot restore, the
    /// emulator's clear route, a test fixture), not a data-plane request.
    pub fn ensure_database(&self, parent: &Parent) -> Result<DatabaseHandle, Status> {
        self.open_database(parent, Admission::Creates)
    }

    /// Whether a database exists in every project without anything having created it: the
    /// default database, which a project cannot be without, and the ones the configuration
    /// declares.
    fn database_exists_unprompted(&self, database: &str) -> bool {
        database == DatabaseId::DEFAULT
            || self
                .declared_databases
                .read()
                .is_ok_and(|declared| declared.contains(database))
    }

    fn open_database(
        &self,
        parent: &Parent,
        admission: Admission,
    ) -> Result<DatabaseHandle, Status> {
        let mut dbs = self.databases.lock().map_err(|_| lock_poisoned())?;
        // Decided under the catalog lock that would create the entry, so no request is
        // admitted by a database a concurrent request is being refused for.
        if admission == Admission::RequestOnly
            && !self.implicit_database_creation
            && !dbs.contains_key(&database_key(parent))
            && !self.database_exists_unprompted(parent.database.as_str())
        {
            return Err(status(DecodeError::UnknownDatabase {
                project: parent.project.as_str().to_owned(),
                database: parent.database.as_str().to_owned(),
            }));
        }
        // A new database refuses production's limits only when the gateway enforces limits
        // (the `strict` profile); under `emulator` it admits what the official emulator
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
                        self.database_incarnations
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                    ))
                })
                .clone(),
        ))
    }

    /// When this backend's databases came into being: the `createTime` and `updateTime` the
    /// Admin inventory reports, and the floor of its `earliestVersionTime`.
    #[must_use]
    pub const fn created_at(&self) -> fireemu_core_types::time::LogicalInstant {
        self.created_at
    }

    /// The databases the configuration declared, which exist in every project whether or not
    /// a request has touched them. `(default)` is not among them and always exists.
    #[must_use]
    pub fn declared_databases(&self) -> BTreeSet<String> {
        self.declared_databases
            .read()
            .map(|declared| declared.clone())
            .unwrap_or_default()
    }

    /// Returns the attached database catalog without creating entries or touching database
    /// state. The adapter uses this for the read-only Admin inventory surface.
    pub fn database_catalog(&self) -> Result<Vec<DatabaseCatalogEntry>, Status> {
        self.database_catalog_with_hook(|| {})
    }

    fn database_catalog_with_hook(
        &self,
        after_catalog_lock: impl FnOnce(),
    ) -> Result<Vec<DatabaseCatalogEntry>, Status> {
        let dbs = self.databases.lock().map_err(|_| lock_poisoned())?;
        after_catalog_lock();
        let entries: Vec<_> = dbs
            .iter()
            .map(|(key, entry)| (key.clone(), Arc::clone(entry)))
            .collect();
        drop(dbs);
        entries
            .into_iter()
            .map(|(key, entry)| {
                if entry.cell.read().map_err(|_| lock_poisoned())?.detached {
                    return Err(Status::unavailable("database catalog entry is detached"));
                }
                Ok((key, entry.incarnation))
            })
            .collect()
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

    /// The index entries an Explain plan reads in `parent`'s database at the snapshot of
    /// `read_time` (the latest state without one); the gRPC stream counts them once its pages
    /// are done.
    pub(crate) fn explain_index_entries(
        &self,
        parent: &Parent,
        query: &Query,
        aggregations: Option<&[Aggregation]>,
        scans: &[fireemu_core_firestore::index::PlannedScan],
        read_time: Option<&prost_types::Timestamp>,
    ) -> Result<u64, Status> {
        self.read_db(parent, |db| {
            let version = read_time.map(|time| db.version_at(crate::encode::decode_instant(time)));
            crate::service::index_entries(db, version, query, aggregations, scans)
                .map_err(|error| status_from_error(&error))
        })
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

    fn read_time_horizon_without_creation(
        &self,
        parent: &Parent,
        now: fireemu_core_types::time::LogicalInstant,
    ) -> fireemu_core_types::time::LogicalInstant {
        self.read_unadmitted(parent, |db| db.read_time(now))
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
        // Production's texts (FS-QUERY-INDEX read-time, recorded 2026-09-24).
        if ts.nanos % 1000 != 0 {
            return Err(Status::invalid_argument(
                "timestamp cannot have more than microseconds precision",
            ));
        }
        let at = crate::encode::decode_instant(ts);
        if at.as_nanos() > horizon.max(now).as_nanos() {
            return Err(Status::invalid_argument(
                "The requested 'read_time' cannot be in the future.",
            ));
        }
        // Production answers a read_time before the database existed with INVALID_ARGUMENT and
        // one inside the database's life but outside the retention window with
        // FAILED_PRECONDITION, in these words (conformance/firestore-production-matrix.json).
        // Both profiles refuse it: fireemu did before the strict profile existed.
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

    /// Decodes the writes of a `BatchWrite` request for authorization.
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

    /// Lease bookkeeping for a refused attempt: rolls back colliding holders that have been
    /// idle for the lock lease (production expires an idle transaction; a busy one keeps its
    /// locks). The idle check and rollback share the database write lock, so a transaction that
    /// resumes cannot be rolled back from a stale observation. `true` when a holder was rolled
    /// back, so the attempt is worth repeating at once.
    pub fn expire_lock_leases(
        &self,
        handle: &DatabaseHandle,
        lease_writes: &[Write],
        own: Option<&TransactionId>,
    ) -> bool {
        handle
            .with(|db| {
                // Recheck idleness and roll back under the same database write lock. A read
                // followed by a later write lock could otherwise sample an idle holder, let a
                // concurrent transaction operation refresh it, then incorrectly roll it back.
                let expired: Vec<TransactionId> = db
                    .lock_holders(lease_writes, own)
                    .into_iter()
                    .filter(|id| db.transaction_idle_for(id, self.lock_lease))
                    .collect();
                if expired.is_empty() {
                    return Ok(false);
                }
                let mut rolled_back = false;
                for id in &expired {
                    if db.rollback(id).is_ok() {
                        rolled_back = true;
                    }
                }
                Ok(rolled_back)
            })
            .unwrap_or(false)
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

    /// Folds one page (and, on the first page of a general order, the selection stage) into
    /// the execution's statistics.
    fn record_query_execution_page(
        &self,
        execution_id: QueryExecutionId,
        selection: Option<(QueryStats, u64, u64)>,
        page: &QueryStats,
    ) {
        let mut retained = self
            .query_execution_stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let position = retained
            .iter()
            .position(|(id, _)| *id == execution_id)
            .unwrap_or_else(|| {
                while retained.len() >= QUERY_EXECUTION_STATS_RETAINED {
                    retained.pop_front();
                }
                retained.push_back((execution_id, QueryExecutionStats::default()));
                retained.len() - 1
            });
        let stats = &mut retained[position].1;
        if let Some((selection_stats, paths, bytes)) = selection {
            stats.selection = Some(selection_stats);
            stats.selection_paths = paths;
            stats.selection_bytes = bytes;
        }
        stats.pages.absorb(page);
        stats.page_count = stats.page_count.saturating_add(1);
    }

    /// Statistics of one recent streamed query execution.
    #[must_use]
    pub fn query_execution_stats(
        &self,
        execution_id: QueryExecutionId,
    ) -> Option<QueryExecutionStats> {
        self.query_execution_stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|(id, _)| *id == execution_id)
            .map(|(_, stats)| *stats)
    }

    /// The most recently started streamed query execution and its statistics.
    #[must_use]
    pub fn latest_query_execution_stats(&self) -> Option<(QueryExecutionId, QueryExecutionStats)> {
        self.query_execution_stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .back()
            .copied()
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
        let (responses, warnings, _) = self.run_query_authorized_as_after_internal(
            req,
            authorization_req,
            guard,
            None,
            false,
            None,
            None,
        )?;
        Ok((responses, warnings))
    }

    /// Executes the first bounded page of one streamed query execution.
    pub(crate) fn run_query_authorized_as_for_execution(
        &self,
        req: &pb::RunQueryRequest,
        authorization_req: &pb::RunQueryRequest,
        guard: ReadGuard<'_>,
        execution_id: QueryExecutionId,
    ) -> Result<AuthorizedQueryPage, Status> {
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
            None,
        )
    }

    /// Executes a bounded page after an exclusive document path while authorizing the caller's
    /// original query shape. The document-path continuation supports either `__name__` direction
    /// and pairs with [`Self::run_query_authorized_as`] by resolving its transaction observation
    /// from the query shape. The gRPC streaming path uses the execution-scoped helper below when
    /// identical queries can be active concurrently.
    pub fn run_query_authorized_as_after(
        &self,
        req: &pb::RunQueryRequest,
        authorization_req: &pb::RunQueryRequest,
        guard: ReadGuard<'_>,
        after_document: Option<&DocumentPath>,
    ) -> Result<(Vec<pb::RunQueryResponse>, Vec<String>), Status> {
        let (responses, warnings, _) = self.run_query_authorized_as_after_internal(
            req,
            authorization_req,
            guard,
            after_document,
            true,
            None,
            None,
        )?;
        Ok((responses, warnings))
    }

    /// Executes a continuation page of one streamed query execution.
    pub(crate) fn run_query_authorized_as_after_for_execution(
        &self,
        req: &pb::RunQueryRequest,
        authorization_req: &pb::RunQueryRequest,
        guard: ReadGuard<'_>,
        after_document: Option<&DocumentPath>,
        execution_id: QueryExecutionId,
        selection: Option<Arc<QuerySelection>>,
    ) -> Result<(Vec<pb::RunQueryResponse>, Vec<String>), Status> {
        let (responses, warnings, _) = self.run_query_authorized_as_after_internal(
            req,
            authorization_req,
            guard,
            after_document,
            true,
            Some(QueryExecutionContext {
                id: execution_id,
                complete: false,
            }),
            selection,
        )?;
        Ok((responses, warnings))
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn run_query_authorized_as_after_internal(
        &self,
        req: &pb::RunQueryRequest,
        authorization_req: &pb::RunQueryRequest,
        guard: ReadGuard<'_>,
        after_document: Option<&DocumentPath>,
        continuation: bool,
        execution: Option<QueryExecutionContext>,
        selection: Option<Arc<QuerySelection>>,
    ) -> Result<AuthorizedQueryPage, Status> {
        let parent = crate::query_messages::parse_query_parent(&req.parent).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.read")?;
        let Some(pb::run_query_request::QueryType::StructuredQuery(sq)) = &req.query_type else {
            return Err(Status::invalid_argument(
                crate::query_messages::RUN_QUERY_WITHOUT_QUERY,
            ));
        };
        let accepted = self
            .accepted_query(&parent, sq)
            .map_err(|s| crate::index_messages::for_explain(req.explain_options.as_ref(), s))?;
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
                crate::query_messages::RUN_QUERY_WITHOUT_QUERY,
            ));
        };
        let authorization = self
            .accepted_query(&authorization_parent, authorization_query)
            .map_err(|s| crate::index_messages::for_explain(req.explain_options.as_ref(), s))?;
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
            let execution_present = execution.is_some();
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
            let explain_started = std::time::Instant::now();
            if req
                .explain_options
                .as_ref()
                .is_some_and(|options| !options.analyze)
            {
                let mut responses = query_responses(&[], None, access.report(), 0);
                if let Some(response) = responses.last_mut() {
                    response.explain_metrics = Some(crate::service::explain_metrics(
                        &authorization.query,
                        None,
                        accepted.scans.as_deref(),
                        None,
                    ));
                }
                return Ok((responses, authorization.warnings.clone(), selection));
            }
            let mut selection_stage = None;
            let mut selection_matched = None;
            let selection = match selection {
                Some(selection) => Some(selection),
                None if execution_present
                    && (accepted.query.find_nearest.is_some()
                        || accepted.query.effective_order_by().len() != 1) =>
                {
                    let mut selection_query = authorization.query.clone();
                    if selection_query.find_nearest.is_none() {
                        let original_offset = selection_query.offset;
                        selection_query.offset = 0;
                        selection_query.limit = selection_query
                            .limit
                            .map(|limit| limit.saturating_add(original_offset));
                    }
                    let (paths, stats) = access
                        .db()
                        .run_query_paths_with_stats(&selection_query, version)
                        .map_err(|error| status_from_error(&error))?;
                    if accepted.query.find_nearest.is_some() {
                        selection_matched = Some(stats.matched);
                    }
                    let selection =
                        QuerySelection::from_paths(paths, Arc::clone(&self.query_selection_bytes));
                    selection_stage = Some((
                        stats,
                        u64::try_from(selection.inner.paths.len()).unwrap_or(u64::MAX),
                        selection.inner.retained_bytes,
                    ));
                    Some(Arc::new(selection))
                }
                None => None,
            };
            let (docs, stats) = if let Some(selection) = selection.as_deref() {
                access.run_query_from_paths(
                    &accepted.query,
                    &authorization.query,
                    selection,
                    continuation,
                )?
            } else {
                match (continuation, after_document) {
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
                }
            };
            if let Some(execution) = execution {
                self.record_query_execution_page(execution.id, selection_stage, &stats);
            }
            let read_time = Some(encode_instant(access.read_time(now)?));
            // The rows the offset skipped, reported on the first result as the backend does.
            let skipped = if after_document.is_some() {
                0
            } else {
                let available = if accepted.query.find_nearest.is_some() {
                    selection_matched.unwrap_or(stats.matched)
                } else {
                    selection.as_ref().map_or(stats.matched, |selection| {
                        u64::try_from(selection.inner.paths.len()).unwrap_or(u64::MAX)
                    })
                };
                i32::try_from(u64::from(authorization.query.offset).min(available))
                    .unwrap_or(i32::MAX)
            };
            let mut responses = query_responses(&docs, read_time, access.report(), skipped);
            if req
                .explain_options
                .as_ref()
                .is_some_and(|options| options.analyze)
            {
                let index_entries = accepted
                    .scans
                    .as_deref()
                    .map(|scans| {
                        crate::service::index_entries(
                            access.db(),
                            version,
                            &accepted.query,
                            None,
                            scans,
                        )
                    })
                    .transpose()
                    .map_err(|error| status_from_error(&error))?;
                let metrics = crate::service::explain_metrics(
                    &authorization.query,
                    None,
                    accepted.scans.as_deref(),
                    Some(crate::service::ExplainExecution {
                        results_returned: i64::try_from(docs.len()).unwrap_or(i64::MAX),
                        entries: u64::try_from(docs.len())
                            .unwrap_or(u64::MAX)
                            .saturating_add(u64::try_from(skipped).unwrap_or(0)),
                        index_entries,
                        duration: explain_started.elapsed(),
                    }),
                );
                if let Some(response) = responses.last_mut() {
                    response.explain_metrics = Some(metrics);
                }
            }
            Ok((responses, authorization.warnings.clone(), selection))
        })
    }

    /// `RunAggregationQuery`.
    pub fn run_aggregation_query(
        &self,
        req: &pb::RunAggregationQueryRequest,
        guard: ReadGuard<'_>,
    ) -> Result<pb::RunAggregationQueryResponse, Status> {
        self.run_aggregation_query_with_stats(req, guard)
            .map(|(response, _)| response)
    }

    #[allow(clippy::too_many_lines)]
    fn run_aggregation_query_with_stats(
        &self,
        req: &pb::RunAggregationQueryRequest,
        guard: ReadGuard<'_>,
    ) -> Result<(pb::RunAggregationQueryResponse, QueryStats), Status> {
        let parent = crate::query_messages::parse_query_parent(&req.parent).map_err(status)?;
        self.fault(parent.project.as_str(), "firestore.read")?;
        let Some(pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(saq)) =
            &req.query_type
        else {
            return Err(Status::invalid_argument(
                crate::query_messages::AGGREGATION_WITHOUT_QUERY,
            ));
        };
        let sq = crate::query_messages::aggregation_structured_query(saq);
        let sq = sq.as_ref();
        let (aliases, aggregations) = decode_aggregations(saq, self.gateway.production_refusals())?;
        let accepted = self
            .accepted_aggregation_query(&parent, sq, &aggregations)
            .map_err(|s| crate::index_messages::for_explain(req.explain_options.as_ref(), s))?;
        let plan_only = req
            .explain_options
            .as_ref()
            .is_some_and(|options| !options.analyze);
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
            // Only once the database exists and the caller may read the query: a count
            // capped at zero reads nothing and answers at the instant before the epoch.
            if let Some(response) = crate::query_messages::zero_capped_count(
                &aliases,
                &aggregations,
                req.explain_options.is_some() || req.consistency_selector.is_some(),
            ) {
                return Ok((response, QueryStats::default()));
            }
            let explain_started = std::time::Instant::now();
            if plan_only {
                return Ok((
                    pb::RunAggregationQueryResponse {
                        transaction: access.report().to_vec(),
                        explain_metrics: Some(crate::service::explain_metrics(
                            &accepted.query,
                            Some(&aggregations),
                            accepted.scans.as_deref(),
                            None,
                        )),
                        ..Default::default()
                    },
                    QueryStats::default(),
                ));
            }
            // Inside a transaction the aggregation and its conflict observation share one
            // borrowed selection pass, so matching document bodies are never materialized just
            // to record the query.
            let (values, stats) = access.run_aggregation(&accepted.query, &aggregations)?;
            let read_time = access.read_time(now)?;
            let analyze = req
                .explain_options
                .as_ref()
                .is_some_and(|options| options.analyze);
            let index_entries = accepted
                .scans
                .as_deref()
                .filter(|_| analyze)
                .map(|scans| {
                    crate::service::index_entries(
                        access.db(),
                        version,
                        &accepted.query,
                        Some(&aggregations),
                        scans,
                    )
                })
                .transpose()
                .map_err(|error| status_from_error(&error))?;
            let aggregate_fields: HashMap<String, pb::Value> = aliases
                .into_iter()
                .zip(values.iter().map(encode_value))
                .collect();
            Ok((
                pb::RunAggregationQueryResponse {
                    result: Some(pb::AggregationResult { aggregate_fields }),
                    transaction: access.report().to_vec(),
                    read_time: Some(encode_instant(read_time)),
                    explain_metrics: req.explain_options.as_ref().and_then(|options| {
                        options.analyze.then(|| {
                            crate::service::explain_metrics(
                                &accepted.query,
                                Some(&aggregations),
                                accepted.scans.as_deref(),
                                Some(crate::service::ExplainExecution {
                                    results_returned: 1,
                                    entries: accepted.query.limit.map_or(stats.matched, |limit| {
                                        stats.matched.min(
                                            u64::from(limit)
                                                .saturating_add(u64::from(accepted.query.offset)),
                                        )
                                    }),
                                    index_entries,
                                    duration: explain_started.elapsed(),
                                }),
                            )
                        })
                    }),
                },
                stats,
            ))
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
        // Production's texts (FS-DATA-WRITE-LIST, recorded 2026-09-24).
        let parent = crate::query_messages::parse_query_parent(&req.parent).map_err(status)?;
        if req.page_size < 0 {
            return Err(Status::invalid_argument("Page size must be nonnegative."));
        }
        if req.show_missing && !req.order_by.is_empty() {
            return Err(Status::invalid_argument(
                "cannot specify an order when show_missing is true",
            ));
        }
        // Without a collection id production refuses `show_missing`; the emulator profile, which
        // may add no rejection, lists without the missing documents instead.
        if req.show_missing && req.collection_id.is_empty() && self.gateway.production_refusals() {
            return Err(Status::invalid_argument(
                "collection id must be set when show_missing is true",
            ));
        }
        let show_missing = req.show_missing && !req.collection_id.is_empty();
        check_list_mask(req.mask.as_ref())?;
        // Page tokens carry the resource name of the last document of the previous page, the
        // order values it had when the page was issued (an ordered listing continues after
        // those, as production's does), and the identity of the listing they continue:
        // parent, collection, result-shaping options and session generation. The snapshot is
        // not part of it: production continues a token issued at a read time without one,
        // and the other way round (read-time#paged-at-write-1-next-without-read-time).
        let identity = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            req.parent,
            req.collection_id,
            req.mask
                .as_ref()
                .map(|m| m.field_paths.join(","))
                .unwrap_or_default(),
            req.order_by,
            show_missing,
            self.epoch(),
            self.database_generation(&parent),
        );
        let after_cursor = list_page_cursor(&req.page_token, &identity)?;
        let after = after_cursor.as_ref().map(|cursor| cursor.name.clone());
        // The order values the previous page ended on, when the token carries them.
        let token_values = after_cursor
            .as_ref()
            .and_then(|cursor| cursor.values.clone());
        let after_path = after
            .as_deref()
            .map(decode_document_name)
            .transpose()
            .map_err(status)?;
        if after_path.as_ref().is_some_and(|path| {
            path.project() != &parent.project
                || path.database() != &parent.database
                || path.parent_document().as_ref() != parent.document.as_ref()
                || (!req.collection_id.is_empty()
                    && path.collection_id().as_str() != req.collection_id)
        }) {
            return Err(Status::invalid_argument(LIST_TOKEN_FOREIGN));
        }
        let mask = decode_mask(req.mask.as_ref()).map_err(status)?;
        // Faults apply to requests that validated, before anything (a read time) can create
        // the database.
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
        let accepted = self.accepted_query(&parent, &list_query(req)?)?;
        let ordered = !accepted.query.order_by.is_empty();
        // Without a collection id the listing is every document directly below the parent,
        // in name order (gRPC only; grpc/list-documents#every-collection-of-document): read
        // through the query engine like an ordered listing.
        let name_scan = !ordered && !req.collection_id.is_empty();
        // The rules see the page size as `request.query.limit` (the number of documents the
        // request can return); the scan itself stays unlimited so the page cursor applies
        // before truncation. Production serves at most 300 documents a page
        // (large#page-size-1000).
        let page_size = if req.page_size > 0 {
            usize::try_from(req.page_size)
                .unwrap_or(usize::MAX)
                .min(MAX_LIST_PAGE_SIZE)
        } else {
            DEFAULT_LIST_PAGE_SIZE
        };
        // One document beyond the page decides whether a `nextPageToken` is issued.
        let scan_size = page_size.saturating_add(1);
        let mut proof_query = accepted.query.clone();
        proof_query.limit = Some(u32::try_from(page_size).unwrap_or(u32::MAX));
        let bounded_name_page = txn.is_none() && name_scan;
        let bounded_ordered_page = txn.is_none() && !name_scan;
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
            let mut documents = if bounded_name_page && show_missing {
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
                // After the values the page ended on, as the token recorded them.
                let cursor = match token_values.clone() {
                    Some(values) => Some(fireemu_core_firestore::query::Cursor {
                        values,
                        before: false,
                    }),
                    None => after_path
                        .as_ref()
                        .map(|path| {
                            access
                                .db()
                                .cursor_after_document(&accepted.query, version, path)
                        })
                        .transpose()
                        .map_err(|e| status_from_error(&e))?
                        .flatten(),
                };
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
                if show_missing {
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
                        // The whole query is read and recorded as the transaction's read set
                        // (a commit re-runs it to detect a conflict); a page then continues
                        // after the values the token recorded.
                        let all = access
                            .run_query_with_stats(&accepted.query, &accepted.query, false)?
                            .0;
                        match token_values.clone() {
                            Some(values) => {
                                let mut continued = accepted.query.clone();
                                continued.start_at = Some(fireemu_core_firestore::query::Cursor {
                                    values,
                                    before: false,
                                });
                                let after: std::collections::BTreeSet<String> = access
                                    .db()
                                    .run_query(&continued, version)
                                    .map_err(|e| status_from_error(&e))?
                                    .iter()
                                    .map(|d| d.path.resource_name())
                                    .collect();
                                all.into_iter()
                                    .filter(|d| after.contains(&d.path.resource_name()))
                                    .collect()
                            }
                            None => all,
                        }
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
                if show_missing {
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
            if !bounded_name_page && !bounded_ordered_page && token_values.is_none() {
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
            let next_page_token = match documents.last() {
                Some(last) if full => {
                    // An ordered listing also records the order values of its last document
                    // in this snapshot.
                    let values = if name_scan {
                        None
                    } else {
                        decode_document_name(&last.name)
                            .ok()
                            .map(|path| {
                                access
                                    .db()
                                    .cursor_after_document(&accepted.query, version, &path)
                            })
                            .transpose()
                            .map_err(|e| status_from_error(&e))?
                            .flatten()
                            .map(|cursor| cursor.values)
                    };
                    list_page_token(&last.name, &identity, values.as_deref())
                }
                _ => String::new(),
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
        let parent = crate::query_messages::parse_query_parent(&req.parent).map_err(status)?;
        if req.page_size < 0 {
            return Err(Status::invalid_argument(
                "page_size must be greater than or equal to zero.",
            ));
        }
        let now = self.write_time();
        let read_at = match &req.consistency_selector {
            Some(pb::list_collection_ids_request::ConsistencySelector::ReadTime(ts)) => {
                Some(self.read_time_selector(
                    ts,
                    now,
                    self.read_time_horizon_without_creation(&parent, now),
                )?)
            }
            None => None,
        };
        // Capture the database instance before validating the token. A raw project reset
        // may remove its catalog entry before publishing a new generation; incarnation
        // identity distinguishes a replacement even during that interval.
        let handle = {
            let _admitted = self.barrier.admit();
            let existing = self
                .databases
                .lock()
                .map_err(|_| lock_poisoned())?
                .get(&database_key(&parent))
                .cloned()
                .map(DatabaseHandle);
            match existing {
                Some(handle) => Some(handle),
                None if !req.page_token.is_empty() => {
                    return Err(Status::invalid_argument(LIST_TOKEN_FOREIGN));
                }
                None => None,
            }
        };
        // A token is a cursor of collection ids within one database session: production
        // continues it under another parent or read time (list-collection-ids/rest
        // #page-token-from-other-parent, read-time#collection-ids-paged-at-write-1-next-without-
        // read-time).
        let identity = |handle: &DatabaseHandle| {
            format!(
                "{}|{}|{}",
                self.epoch(),
                self.database_generation(&parent),
                handle.0.incarnation,
            )
        };
        if let Some(handle) = &handle {
            list_collection_ids_page_cursor(&req.page_token, &identity(handle))?;
        }
        self.fault(parent.project.as_str(), "firestore.read")?;
        let page_size = if req.page_size > 0 {
            usize::try_from(req.page_size).unwrap_or(usize::MAX)
        } else {
            DEFAULT_LIST_PAGE_SIZE
        };
        let _admitted = self.barrier.admit();
        // A tokenless request for an absent database creates state only after faults
        // succeed, leaving the catalog and deterministic generators untouched on error.
        let handle = match handle {
            Some(handle) => handle,
            None => self.database_handle(&parent)?,
        };
        // Validation and snapshot selection use this same instance under its read lock.
        // Retaining the handle across faults prevents a reset from redirecting an accepted
        // cursor to a replacement database, even when reset bypasses session admission.
        handle
            .read_status(|db| {
                let identity = identity(&handle);
                let after = list_collection_ids_page_cursor(&req.page_token, &identity)?;
                let version = match read_at {
                    Some(at) => Some(Self::retained_read_version(db, at)?),
                    None => None,
                };
                let mut ids = db.list_collection_ids_at(parent.document.as_ref(), version);
                if let Some(after) = &after {
                    ids.retain(|id| id > after);
                }
                // As for documents: a token only when a collection id follows the page.
                let full = ids.len() > page_size;
                ids.truncate(page_size);
                let next_page_token = if full {
                    ids.last().map_or(String::new(), |id| {
                        crate::rest::json::base64_encode(format!("{id}\n{identity}").as_bytes())
                    })
                } else {
                    String::new()
                };
                Ok(pb::ListCollectionIdsResponse {
                    collection_ids: ids,
                    next_page_token,
                })
            })
            .map_err(|error| {
                if !req.page_token.is_empty() && handle.is_detached() {
                    Status::invalid_argument("page_token belongs to a reset database")
                } else {
                    error
                }
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
        let decoded: Vec<Write> = req
            .writes
            .iter()
            .map(|w| {
                let write = decode_write(w).map_err(status)?;
                Self::check_database_path(&parent, write.op.path())?;
                Ok(write)
            })
            .collect::<Result<Vec<_>, Status>>()?;
        // A document named twice refuses the whole request, in production's words (matrix
        // `writes/batch-write#non-atomic-batch`: no status array, nothing landed).
        let mut targets = std::collections::BTreeSet::new();
        for path in decoded.iter().map(|write| write.op.path()) {
            if !targets.insert(path.clone()) {
                return Err(Status::invalid_argument(
                    "the same document cannot be written more than once in a single request",
                ));
            }
        }
        self.with_db(&parent, |db| {
            let mut write_results = Vec::with_capacity(req.writes.len());
            let mut statuses = Vec::with_capacity(req.writes.len());
            for write in decoded {
                let now = self.write_time();
                let outcome = (|| {
                    guard(db, std::slice::from_ref(&write), now)?;
                    self.commit_with_events(&parent, db, std::slice::from_ref(&write), None, now)
                })();
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

/// Decodes and validates the aggregation list in production's terms
/// (`crate::query_messages::decode_aggregations`).
pub(crate) fn decode_aggregations(
    saq: &pb::StructuredAggregationQuery,
    production_refusals: bool,
) -> Result<(Vec<String>, Vec<Aggregation>), Status> {
    crate::query_messages::decode_aggregations(saq, production_refusals)
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
    // Any clause production cannot read, its field path included, is refused as the whole
    // clause (order-and-mask#order-by-invalid-path).
    let invalid = || {
        Status::invalid_argument(format!(
            "Invalid order by clause \"{}\".",
            fireemu_core_types::codec::echo(order_by)
        ))
    };
    if order_by.trim().is_empty() {
        return Ok(Vec::new());
    }
    order_by
        .split(',')
        .map(|clause| {
            let mut words = clause.split_whitespace();
            let field = words.next().ok_or_else(invalid)?;
            FieldPath::parse(field).map_err(|_| invalid())?;
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

/// Production's refusal of a page token that is not one it issued.
const LIST_TOKEN_MALFORMED: &str = "invalid page token";
/// Production's refusal of a page token issued for another listing (another collection,
/// order, mask or `show_missing`).
const LIST_TOKEN_FOREIGN: &str = "Invalid page token.";
/// The most bytes of order values a `ListDocuments` page token carries.
const MAX_TOKEN_CURSOR_BYTES: usize = 1536;
/// The most documents a `ListDocuments` page holds (large#page-size-1000).
pub const MAX_LIST_PAGE_SIZE: usize = 300;

/// Where a `ListDocuments` page token continues: after the named document, and in an ordered
/// listing after the order values that document had when the token was issued.
struct ListCursor {
    name: String,
    values: Option<Vec<fireemu_core_firestore::value::Value>>,
}

fn list_page_token(
    name: &str,
    identity: &str,
    values: Option<&[fireemu_core_firestore::value::Value]>,
) -> String {
    use crate::rest::json::base64_encode;
    use prost::Message as _;
    // Values past the bound are left out, so a token stays small whatever the listing is
    // ordered on (production cuts its index entries at 1500 bytes); such a page continues
    // after its last document's current values, as fireemu's tokens did before.
    let values = values
        .map(|values| {
            pb::Cursor {
                values: values.iter().map(encode_value).collect(),
                before: false,
            }
            .encode_to_vec()
        })
        .filter(|bytes| bytes.len() <= MAX_TOKEN_CURSOR_BYTES)
        .map_or_else(String::new, |bytes| base64_encode(&bytes));
    base64_encode(
        format!(
            "{}\n{}\n{values}",
            base64_encode(name.as_bytes()),
            base64_encode(identity.as_bytes())
        )
        .as_bytes(),
    )
}

/// The cursor a `ListDocuments` page token continues after; the token must have been issued
/// for the same listing (`identity`).
fn list_page_cursor(page_token: &str, identity: &str) -> Result<Option<ListCursor>, Status> {
    use crate::rest::json::base64_decode;
    use prost::Message as _;
    if page_token.is_empty() {
        return Ok(None);
    }
    let malformed = || Status::invalid_argument(LIST_TOKEN_MALFORMED);
    let text = |part: &str| {
        base64_decode(part)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(malformed)
    };
    let token = text(page_token)?;
    let mut parts = token.split('\n');
    let (Some(name), Some(token_identity), Some(values), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed());
    };
    let name = text(name)?;
    decode_document_name(&name).map_err(|_| malformed())?;
    if text(token_identity)? != identity {
        return Err(Status::invalid_argument(LIST_TOKEN_FOREIGN));
    }
    let values = if values.is_empty() {
        None
    } else {
        let cursor = base64_decode(values)
            .ok()
            .and_then(|bytes| pb::Cursor::decode(bytes.as_slice()).ok())
            .ok_or_else(malformed)?;
        Some(
            cursor
                .values
                .iter()
                .map(crate::decode::decode_value)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| malformed())?,
        )
    };
    Ok(Some(ListCursor { name, values }))
}

/// A `ListDocuments` mask in production's words: an empty path and a path that does not parse
/// are refused as a query's property paths are (order-and-mask#mask-empty,
/// #mask-comma-separated); the length limits stay with the shared mask decoder.
fn check_list_mask(mask: Option<&pb::DocumentMask>) -> Result<(), Status> {
    use fireemu_core_firestore::field_path::FieldPathError;
    for path in mask.map_or(&[][..], |mask| mask.field_paths.as_slice()) {
        match FieldPath::parse(path) {
            Ok(_)
            | Err(FieldPathError::PathTooLong { .. } | FieldPathError::SegmentTooLong { .. }) => {}
            Err(FieldPathError::Empty) => {
                return Err(Status::invalid_argument(
                    crate::query_messages::EMPTY_PROPERTY_PATH,
                ));
            }
            Err(_) => {
                return Err(Status::invalid_argument(format!(
                    r#"Invalid property path "{}". Unquoted property paths must match regex ([a-zA-Z_][a-zA-Z_0-9]*), and quoted property paths must match regex (`(?:[^`\\]|(?:\\.))+`)"#,
                    fireemu_core_types::codec::echo(path)
                )));
            }
        }
    }
    Ok(())
}

fn list_collection_ids_page_cursor(
    page_token: &str,
    identity: &str,
) -> Result<Option<String>, Status> {
    if page_token.is_empty() {
        return Ok(None);
    }
    let malformed = || Status::invalid_argument(LIST_TOKEN_MALFORMED);
    let token =
        String::from_utf8(crate::rest::json::base64_decode(page_token).map_err(|_| malformed())?)
            .map_err(|_| malformed())?;
    let (id, token_identity) = token.split_once('\n').ok_or_else(malformed)?;
    if id.is_empty() {
        return Err(malformed());
    }
    if token_identity != identity {
        return Err(Status::invalid_argument(LIST_TOKEN_FOREIGN));
    }
    CollectionId::try_new(id).map_err(|_| malformed())?;
    Ok(Some(id.to_owned()))
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
    // Production marks no response `done` (FS-QUERY-INDEX gRPC recordings, 2026-09-24): the
    // end of the stream is the end of the results.
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
                    policy: IndexValidationPolicy::Production,
                },
                indexes: IndexSet::default(),
            },
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ))),
            7,
        ))
    }

    #[test]
    fn an_already_idle_transaction_releases_its_lock_before_contention_wait() {
        let backend = Arc::new(
            LocalBackend::new(
                backend().gateway.clone(),
                Arc::new(Mutex::new(VirtualClock::new(
                    LogicalInstant::from_unix_seconds(1_788_004_860),
                ))),
                7,
            )
            .with_lock_lease(Duration::from_millis(40))
            .with_contention_wait(Duration::from_millis(120)),
        );
        let database = "projects/demo-app/databases/(default)";
        let document = format!("{database}/documents/idle/doc");
        let transaction = backend
            .begin_transaction(&pb::BeginTransactionRequest {
                database: database.to_owned(),
                ..Default::default()
            })
            .unwrap();
        backend
            .get_document(
                &pb::GetDocumentRequest {
                    name: document.clone(),
                    consistency_selector: Some(
                        pb::get_document_request::ConsistencySelector::Transaction(
                            transaction.clone(),
                        ),
                    ),
                    ..Default::default()
                },
                &crate::rules::allow_all_reads,
            )
            .unwrap_err();

        std::thread::sleep(Duration::from_millis(80));
        let result = backend.commit(&pb::CommitRequest {
            database: database.to_owned(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: document,
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        });
        assert!(
            result.is_ok(),
            "an already-idle holder must be expired: {result:?}"
        );
    }

    fn collection_ids_request_with_token(backend: &LocalBackend) -> pb::ListCollectionIdsRequest {
        let parent = "projects/demo-app/databases/(default)/documents";
        backend
            .commit(&pb::CommitRequest {
                database: "projects/demo-app/databases/(default)".to_owned(),
                writes: ["a", "b"]
                    .into_iter()
                    .map(|id| pb::Write {
                        operation: Some(pb::write::Operation::Update(pb::Document {
                            name: format!("{parent}/{id}/doc"),
                            ..Default::default()
                        })),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            })
            .unwrap();
        let mut request = pb::ListCollectionIdsRequest {
            parent: parent.to_owned(),
            page_size: 1,
            ..Default::default()
        };
        request.page_token = backend
            .list_collection_ids(&request)
            .unwrap()
            .next_page_token;
        assert!(!request.page_token.is_empty());
        request
    }

    /// A listDocuments that a fault fails leaves an absent database absent, with or without a
    /// read time: the fault comes before the read time is resolved (FS-DATA-WRITE-LIST review).
    #[test]
    fn list_documents_faults_do_not_create_the_database() {
        use fireemu_core_session::fault::{
            FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule,
        };

        for (action, code) in [
            (
                FaultAction::ReturnError {
                    code: "UNAVAILABLE".into(),
                },
                tonic::Code::Unavailable,
            ),
            (FaultAction::Timeout, tonic::Code::DeadlineExceeded),
            (FaultAction::TransactionConflict, tonic::Code::Aborted),
            (FaultAction::DropConnection, tonic::Code::Unavailable),
        ] {
            for read_time in [
                None,
                Some(pb::list_documents_request::ConsistencySelector::ReadTime(
                    prost_types::Timestamp {
                        seconds: 1_788_004_860,
                        nanos: 0,
                    },
                )),
            ] {
                let backend = backend();
                let transaction_ids_before = backend.transaction_ids.lock().unwrap().clone();
                let incarnations_before = backend
                    .database_incarnations
                    .load(std::sync::atomic::Ordering::SeqCst);
                let registry = Arc::new(FaultRegistry::new());
                registry.default_state().lock().unwrap().install(FaultPlan {
                    seed: 1,
                    rules: vec![FaultRule {
                        matches: FaultMatch {
                            operation: "firestore.read".into(),
                            nth: None,
                            function: None,
                            event_type: None,
                        },
                        action: action.clone(),
                    }],
                });
                backend.set_faults(registry);
                let error = backend
                    .list_documents(
                        &pb::ListDocumentsRequest {
                            parent: "projects/demo-app/databases/rtdb/documents".to_owned(),
                            collection_id: "c".to_owned(),
                            consistency_selector: read_time.clone(),
                            ..Default::default()
                        },
                        &crate::rules::allow_all_reads,
                    )
                    .unwrap_err();
                assert_eq!(error.code(), code, "{action:?} {read_time:?}");
                assert!(
                    backend.snapshot_databases().is_empty(),
                    "{action:?} {read_time:?}"
                );
                assert_eq!(
                    *backend.transaction_ids.lock().unwrap(),
                    transaction_ids_before
                );
                assert_eq!(
                    backend
                        .database_incarnations
                        .load(std::sync::atomic::Ordering::SeqCst),
                    incarnations_before,
                    "{action:?} {read_time:?}"
                );
            }
        }
    }

    #[test]
    fn list_collection_ids_return_error_does_not_create_database() {
        check_list_collection_ids_fault_leaves_absent_database_unchanged(
            fireemu_core_session::fault::FaultAction::ReturnError {
                code: "UNAVAILABLE".into(),
            },
            tonic::Code::Unavailable,
        );
    }

    #[test]
    fn list_collection_ids_timeout_does_not_create_database() {
        check_list_collection_ids_fault_leaves_absent_database_unchanged(
            fireemu_core_session::fault::FaultAction::Timeout,
            tonic::Code::DeadlineExceeded,
        );
    }

    #[test]
    fn list_collection_ids_transaction_conflict_does_not_create_database() {
        check_list_collection_ids_fault_leaves_absent_database_unchanged(
            fireemu_core_session::fault::FaultAction::TransactionConflict,
            tonic::Code::Aborted,
        );
    }

    #[test]
    fn list_collection_ids_drop_connection_does_not_create_database() {
        check_list_collection_ids_fault_leaves_absent_database_unchanged(
            fireemu_core_session::fault::FaultAction::DropConnection,
            tonic::Code::Unavailable,
        );
    }

    fn check_list_collection_ids_fault_leaves_absent_database_unchanged(
        action: fireemu_core_session::fault::FaultAction,
        code: tonic::Code,
    ) {
        use fireemu_core_session::fault::{FaultMatch, FaultPlan, FaultRegistry, FaultRule};

        let backend = backend();
        let before = backend.snapshot_databases();
        assert!(before.is_empty());
        let transaction_ids_before = backend.transaction_ids.lock().unwrap().clone();
        let document_ids_before = backend.ids.lock().unwrap().clone();
        let incarnations_before = backend
            .database_incarnations
            .load(std::sync::atomic::Ordering::SeqCst);
        let registry = Arc::new(FaultRegistry::new());
        registry.default_state().lock().unwrap().install(FaultPlan {
            seed: 1,
            rules: vec![FaultRule {
                matches: FaultMatch {
                    operation: "firestore.read".into(),
                    nth: None,
                    function: None,
                    event_type: None,
                },
                action,
            }],
        });
        backend.set_faults(registry);
        let error = backend
            .list_collection_ids(&pb::ListCollectionIdsRequest {
                parent: "projects/demo-app/databases/(default)/documents".to_owned(),
                ..Default::default()
            })
            .unwrap_err();
        assert_eq!(error.code(), code);
        assert!(backend.snapshot_databases().is_empty());
        assert_eq!(
            *backend.transaction_ids.lock().unwrap(),
            transaction_ids_before
        );
        assert_eq!(*backend.ids.lock().unwrap(), document_ids_before);
        assert_eq!(
            backend
                .database_incarnations
                .load(std::sync::atomic::Ordering::SeqCst),
            incarnations_before
        );
    }

    #[test]
    fn list_collection_ids_rejects_reset_between_token_validation_and_read() {
        check_list_collection_ids_reset_during_fault(true);
    }

    #[test]
    fn list_collection_ids_rejects_raw_reset_between_token_validation_and_read() {
        check_list_collection_ids_reset_during_fault(false);
    }

    fn check_list_collection_ids_reset_during_fault(admitted_reset: bool) {
        use fireemu_core_session::fault::{
            FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule,
        };

        let backend = backend();
        let request = collection_ids_request_with_token(&backend);
        let registry = Arc::new(FaultRegistry::new());
        registry.default_state().lock().unwrap().install(FaultPlan {
            seed: 1,
            rules: vec![FaultRule {
                matches: FaultMatch {
                    operation: "firestore.read".into(),
                    nth: None,
                    function: None,
                    event_type: None,
                },
                action: FaultAction::Delay { seconds: 1 },
            }],
        });
        backend.set_faults(registry);
        let weak = Arc::downgrade(&backend);
        backend.set_clock_observer(Arc::new(move || {
            let backend = weak.upgrade().unwrap();
            // The delay callback runs after request/token validation and before the read.
            let _exclusive = admitted_reset.then(|| backend.barrier.exclusive());
            backend.reset_project("demo-app");
        }));
        let error = backend.list_collection_ids(&request).unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn list_collection_ids_rejects_replacement_before_raw_reset_publishes_generation() {
        let backend = backend();
        let request = collection_ids_request_with_token(&backend);
        let parent = parse_parent(&request.parent).unwrap();
        let original = backend.database_handle(&parent).unwrap();
        // Pin the old database's read lock: reset can remove it from the catalog, but
        // cannot detach it or publish the generation until this guard is released.
        let held = original.0.cell.read().unwrap();
        let resetting = Arc::clone(&backend);
        let reset = std::thread::spawn(move || resetting.reset_project("demo-app"));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while backend
            .databases
            .lock()
            .unwrap()
            .contains_key(&database_key(&parent))
        {
            assert!(
                std::time::Instant::now() < deadline,
                "reset did not remove the old database"
            );
            std::thread::yield_now();
        }
        let replacement = backend.database_handle(&parent).unwrap();
        assert!(!Arc::ptr_eq(&original.0, &replacement.0));
        assert_eq!(backend.database_generation(&parent), 0);
        let result = backend.list_collection_ids(&request);
        drop(held);
        reset.join().unwrap();
        assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn list_collection_ids_rejects_invalid_cursors_with_matching_identity_before_faults() {
        use fireemu_core_session::fault::{
            FaultAction, FaultMatch, FaultPlan, FaultRegistry, FaultRule,
        };

        let backend = backend();
        let mut request = collection_ids_request_with_token(&backend);
        let token =
            String::from_utf8(crate::rest::json::base64_decode(&request.page_token).unwrap())
                .unwrap();
        let (_, identity) = token.split_once('\n').unwrap();
        let registry = Arc::new(FaultRegistry::new());
        registry.default_state().lock().unwrap().install(FaultPlan {
            seed: 1,
            rules: vec![FaultRule {
                matches: FaultMatch {
                    operation: "firestore.read".into(),
                    nth: None,
                    function: None,
                    event_type: None,
                },
                action: FaultAction::ReturnError {
                    code: "UNAVAILABLE".into(),
                },
            }],
        });
        backend.set_faults(Arc::clone(&registry));
        for cursor in [
            "a/b".to_owned(),
            "a\u{0001}b".to_owned(),
            "__reserved__".to_owned(),
            "a".repeat(1501),
        ] {
            request.page_token =
                crate::rest::json::base64_encode(format!("{cursor}\n{identity}").as_bytes());
            let error = backend.list_collection_ids(&request).unwrap_err();
            assert_eq!(
                error.code(),
                tonic::Code::InvalidArgument,
                "cursor: {cursor:?}"
            );
        }
        let state = registry.default_state();
        let state = state.lock().unwrap();
        assert!(state.counters().is_empty());
        assert!(state.fired().is_empty());
    }

    #[test]
    fn ordered_selection_resource_charge_follows_last_reference() {
        let backend = backend();
        let path = DocumentPath::parse(
            &fireemu_core_types::ids::ProjectId::try_new("demo-app").unwrap(),
            &fireemu_core_types::ids::DatabaseId::default_database(),
            "items/a",
        )
        .unwrap();
        let selection =
            QuerySelection::from_paths(vec![path], Arc::clone(&backend.query_selection_bytes));
        let retained = backend
            .query_selection_bytes
            .load(std::sync::atomic::Ordering::Acquire);
        assert!(retained > 0);
        let clone = selection.clone();
        drop(selection);
        assert_eq!(
            backend
                .query_selection_bytes
                .load(std::sync::atomic::Ordering::Acquire),
            retained
        );
        drop(clone);
        assert_eq!(
            backend
                .query_selection_bytes
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn transactional_aggregation_at_the_adapter_keeps_clone_stats_zero() {
        use crate::rules::allow_all_reads;

        let backend = backend();
        let database = "projects/demo-app/databases/(default)";
        let documents = format!("{database}/documents");
        let payload = "x".repeat(4 * 1024);
        let writes = (0..500)
            .map(|index| pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: format!("{documents}/items/{index:04}"),
                    fields: [
                        (
                            "n".to_owned(),
                            pb::Value {
                                value_type: Some(pb::value::ValueType::IntegerValue(index)),
                            },
                        ),
                        (
                            "payload".to_owned(),
                            pb::Value {
                                value_type: Some(pb::value::ValueType::StringValue(
                                    payload.clone(),
                                )),
                            },
                        ),
                    ]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                })),
                ..Default::default()
            })
            .collect();
        backend
            .commit_with(
                &pb::CommitRequest {
                    database: database.to_owned(),
                    writes,
                    ..Default::default()
                },
                &allow_all,
            )
            .unwrap();

        let aggregation =
            |alias: &str, operator: pb::structured_aggregation_query::aggregation::Operator| {
                pb::structured_aggregation_query::Aggregation {
                    alias: alias.to_owned(),
                    operator: Some(operator),
                }
            };
        let field = || {
            Some(pb::structured_query::FieldReference {
                field_path: "n".to_owned(),
            })
        };
        let request = pb::RunAggregationQueryRequest {
            parent: documents,
            query_type: Some(
                pb::run_aggregation_query_request::QueryType::StructuredAggregationQuery(
                    pb::StructuredAggregationQuery {
                        query_type: Some(
                            pb::structured_aggregation_query::QueryType::StructuredQuery(
                                pb::StructuredQuery {
                                    from: vec![pb::structured_query::CollectionSelector {
                                        collection_id: "items".to_owned(),
                                        all_descendants: false,
                                    }],
                                    ..Default::default()
                                },
                            ),
                        ),
                        aggregations: vec![
                            aggregation(
                                "count",
                                pb::structured_aggregation_query::aggregation::Operator::Count(
                                    pb::structured_aggregation_query::aggregation::Count {
                                        up_to: None,
                                    },
                                ),
                            ),
                            aggregation(
                                "sum",
                                pb::structured_aggregation_query::aggregation::Operator::Sum(
                                    pb::structured_aggregation_query::aggregation::Sum {
                                        field: field(),
                                    },
                                ),
                            ),
                            aggregation(
                                "avg",
                                pb::structured_aggregation_query::aggregation::Operator::Avg(
                                    pb::structured_aggregation_query::aggregation::Avg {
                                        field: field(),
                                    },
                                ),
                            ),
                        ],
                    },
                ),
            ),
            consistency_selector: Some(
                pb::run_aggregation_query_request::ConsistencySelector::NewTransaction(
                    pb::TransactionOptions {
                        mode: Some(pb::transaction_options::Mode::ReadWrite(
                            pb::transaction_options::ReadWrite::default(),
                        )),
                    },
                ),
            ),
            ..Default::default()
        };
        let (response, stats) = backend
            .run_aggregation_query_with_stats(&request, &allow_all_reads)
            .unwrap();
        assert_eq!(stats.matched, 500);
        assert_eq!(stats.cloned_documents, 0);
        assert_eq!(stats.cloned_field_bytes, 0);
        assert_eq!(stats.peak_candidates, 0);
        let result = response.result.unwrap().aggregate_fields;
        assert_eq!(
            result.get("count"),
            Some(&pb::Value {
                value_type: Some(pb::value::ValueType::IntegerValue(500)),
            })
        );
        assert_eq!(
            result.get("sum"),
            Some(&pb::Value {
                value_type: Some(pb::value::ValueType::IntegerValue(124_750)),
            })
        );
        assert_eq!(
            result.get("avg"),
            Some(&pb::Value {
                value_type: Some(pb::value::ValueType::DoubleValue(249.5)),
            })
        );

        backend
            .rollback(&pb::RollbackRequest {
                database: database.to_owned(),
                transaction: response.transaction,
                ..Default::default()
            })
            .unwrap();
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
        let handle = DatabaseHandle(Arc::new(DatabaseEntry::restored(FirestoreState::new(), 0)));
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
    fn catalog_does_not_hold_catalog_lock_while_reading_database() {
        let backend = backend();
        let parent = parse_parent("projects/demo-app/databases/(default)/documents").unwrap();
        let handle = backend.database_handle(&parent).unwrap();
        let (writer_ready_tx, writer_ready_rx) = mpsc::channel();
        let (start_lookup_tx, start_lookup_rx) = mpsc::channel();
        let writer_backend = Arc::clone(&backend);
        let writer = std::thread::spawn(move || {
            handle.with(|_| {
                writer_ready_tx.send(()).unwrap();
                start_lookup_rx.recv().unwrap();
                let lookup_backend = Arc::clone(&writer_backend);
                let lookup_parent = parent;
                let lookup =
                    std::thread::spawn(move || lookup_backend.database_handle(&lookup_parent));
                assert!(lookup.join().unwrap().is_ok());
                Ok(())
            })
        });
        writer_ready_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();

        let (catalog_locked_tx, catalog_locked_rx) = mpsc::channel();
        let (continue_catalog_tx, continue_catalog_rx) = mpsc::channel();
        let catalog_backend = Arc::clone(&backend);
        let catalog = std::thread::spawn(move || {
            catalog_backend.database_catalog_with_hook(|| {
                catalog_locked_tx.send(()).unwrap();
                continue_catalog_rx.recv().unwrap();
            })
        });
        catalog_locked_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        start_lookup_tx.send(()).unwrap();
        continue_catalog_tx.send(()).unwrap();

        assert!(writer.join().unwrap().is_ok());
        assert_eq!(catalog.join().unwrap().unwrap().len(), 1);
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
