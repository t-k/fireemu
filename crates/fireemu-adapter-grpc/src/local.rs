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
    Precondition, QueryStats, TransactionId, Write, WriteOp,
};
use fireemu_core_session::barrier::AdmissionBarrier;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::{Clock, DeterministicRng, SplitMix64};
use fireemu_core_types::ids::{CollectionId, DatabaseId, DocumentId};
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
}

impl DatabaseEntry {
    /// A fresh, attached entry holding a restored state.
    fn restored(state: FirestoreState) -> Self {
        Self {
            cell: RwLock::new(DatabaseCell {
                detached: false,
                state,
            }),
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
        f(&mut cell.state)
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
    next_reservation: u64,
}

impl HistoryBudgetLedger {
    fn new(limits: HistoryBudgetLimits) -> Self {
        Self {
            limits,
            committed: BTreeMap::new(),
            pending: BTreeMap::new(),
            next_reservation: 0,
        }
    }

    fn effective(&self) -> BTreeMap<(String, String), HistoryCharge> {
        let mut effective = self.committed.clone();
        for pending in self.pending.values() {
            effective.insert(pending.key.clone(), pending.charge.clone());
        }
        effective
    }

    fn reserve(
        &mut self,
        key: (String, String),
        owner: HistoryBudgetOwner,
        usage: HistoryUsage,
    ) -> Result<u64, FirestoreError> {
        let mut effective = self.effective();
        effective.insert(
            key.clone(),
            HistoryCharge {
                owner: owner.clone(),
                usage,
            },
        );
        self.validate_effective(&effective)?;
        let id = self.next_reservation;
        self.next_reservation = self.next_reservation.wrapping_add(1);
        self.pending.insert(
            id,
            PendingHistoryCharge {
                key,
                charge: HistoryCharge { owner, usage },
            },
        );
        Ok(id)
    }

    fn validate_effective(
        &self,
        effective: &BTreeMap<(String, String), HistoryCharge>,
    ) -> Result<(), FirestoreError> {
        let global = sum_history_usage(effective.values().map(|charge| charge.usage));
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
        let owners: std::collections::BTreeSet<HistoryBudgetOwner> = effective
            .values()
            .map(|charge| charge.owner.clone())
            .collect();
        for owner in owners {
            let session = sum_history_usage(
                effective
                    .values()
                    .filter(|charge| charge.owner == owner)
                    .map(|charge| charge.usage),
            );
            check_aggregate_history_limit(
                "session versions",
                session.versions,
                self.limits.session_versions,
            )?;
            check_aggregate_history_limit(
                "session bytes",
                session.total_bytes,
                self.limits.session_bytes,
            )?;
        }
        Ok(())
    }
}

fn sum_history_usage(usages: impl Iterator<Item = HistoryUsage>) -> HistoryUsage {
    usages.fold(HistoryUsage::default(), |mut total, usage| {
        total.total_bytes = total.total_bytes.saturating_add(usage.total_bytes);
        total.versions = total.versions.saturating_add(usage.versions);
        total
    })
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
    fn commit(mut self) {
        if let Ok(mut ledger) = self.ledger.lock() {
            if let Some(pending) = ledger.pending.remove(&self.id) {
                ledger.committed.insert(pending.key, pending.charge);
            }
        }
        self.committed = true;
    }
}

impl Drop for HistoryReservation {
    fn drop(&mut self) {
        if !self.committed {
            if let Ok(mut ledger) = self.ledger.lock() {
                ledger.pending.remove(&self.id);
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

enum SnapshotState<'a> {
    Shared(&'a FirestoreState),
    Exclusive(&'a mut FirestoreState),
}

struct SnapshotAccess<'a> {
    state: SnapshotState<'a>,
    selected: SelectedSnapshot,
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
    ) -> Result<(Vec<Document>, QueryStats), Status> {
        let version = self.version()?;
        match (&mut self.state, &self.selected.transaction) {
            (SnapshotState::Exclusive(db), Some(transaction)) => db
                .run_query_in_transaction_with_stats(transaction, query)
                .map_err(|error| status_from_error(&error)),
            (SnapshotState::Shared(db), None) => db
                .run_query_with_stats(query, version)
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
        Self {
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
            commits: tokio::sync::broadcast::channel(COMMIT_NOTIFICATION_CAPACITY).0,
            epoch: std::sync::atomic::AtomicU64::new(0),
            change_sink: Mutex::new(None),
            change_admission: Mutex::new(None),
            barrier: Arc::new(AdmissionBarrier::new()),
        }
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
        if let Ok(mut slot) = self.tenancy.lock() {
            *slot = Some(tenancy);
        }
    }

    fn history_owner(&self, project: &str) -> HistoryBudgetOwner {
        let tenancy = self.tenancy.lock().ok().and_then(|slot| slot.clone());
        tenancy
            .and_then(|tenancy| {
                tenancy.read().ok().map(|tenancy| {
                    if tenancy.is_registered(project) {
                        HistoryBudgetOwner::Project(project.to_owned())
                    } else {
                        HistoryBudgetOwner::Default
                    }
                })
            })
            .unwrap_or(HistoryBudgetOwner::Default)
    }

    fn reserve_history(
        &self,
        parent: &Parent,
        projection: HistoryProjection,
    ) -> Result<HistoryReservation, FirestoreError> {
        let owner = self.history_owner(parent.project.as_str());
        let mut ledger = self.history_budget.lock().map_err(|_| {
            FirestoreError::HistoryCapacity(HistoryCapacityError {
                dimension: "ledger unavailable",
                current: 1,
                maximum: 0,
            })
        })?;
        let id = ledger.reserve(database_key(parent), owner, projection.after)?;
        drop(ledger);
        Ok(HistoryReservation {
            ledger: self.history_budget.clone(),
            id,
            committed: false,
        })
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
        if let Ok(mut ledger) = self.history_budget.lock() {
            for key in &keys {
                ledger.committed.remove(key);
            }
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
            if let (Ok(usage), Ok(mut ledger)) = (usage, self.history_budget.lock()) {
                if let Some(charge) = ledger.committed.get_mut(&key) {
                    charge.usage = usage;
                }
            }
        }
    }

    /// Aggregate logical Firestore history retained by the backend.
    #[must_use]
    pub fn history_usage(&self) -> HistoryUsage {
        self.history_budget
            .lock()
            .map(|ledger| sum_history_usage(ledger.committed.values().map(|charge| charge.usage)))
            .unwrap_or_default()
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
                .map_err(|_| Status::unavailable("Firestore history budget is unavailable"))?;
            if !ledger.pending.is_empty() {
                return Err(Status::unavailable(
                    "Firestore history reservations are still in flight",
                ));
            }
            let mut effective = ledger.committed.clone();
            effective.retain(|(project, _), _| !scope.owns_project(project));
            effective.extend(restored_charges.clone());
            ledger
                .validate_effective(&effective)
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
        if let Ok(mut ledger) = self.history_budget.lock() {
            ledger
                .committed
                .retain(|(project, _), _| !scope.owns_project(project));
            ledger.committed.extend(restored_charges);
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
        history.commit();
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
        self.fault(parent.project.as_str(), "firestore.commit")?;
        let now = self.write_time();
        let result = self.with_db(parent, |db| {
            guard(db, writes, now)?;
            let result = self.commit_with_events(parent, db, writes, None, now)?;
            Ok(result)
        })?;
        Ok(crate::streams::WireCommit::from_result(&result))
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
                    Arc::new(DatabaseEntry::restored(
                        FirestoreState::with_limit_scope(scope)
                            .with_retained_version_limit(self.history_version_limit),
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
        handle.with(f)
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
    fn token(parent: &Parent, id: &TransactionId) -> Vec<u8> {
        let mut bytes = encode_transaction(id);
        bytes.extend_from_slice(&database_tag(parent).to_be_bytes());
        bytes
    }

    fn txn(parent: &Parent, bytes: &[u8]) -> Result<Option<TransactionId>, Status> {
        if bytes.is_empty() {
            return Ok(None);
        }
        let (handle, tag) = bytes.split_at(bytes.len().saturating_sub(8));
        let tag: Option<[u8; 8]> = tag.try_into().ok();
        if tag.map(u64::from_be_bytes) != Some(database_tag(parent)) {
            return Err(Status::invalid_argument(
                "transaction token does not belong to this database",
            ));
        }
        decode_transaction(handle).map(Some).map_err(status)
    }

    fn required_txn(parent: &Parent, bytes: &[u8]) -> Result<TransactionId, Status> {
        Self::txn(parent, bytes)?.ok_or_else(|| Status::invalid_argument("missing transaction"))
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
    fn read_time_selector(
        ts: &prost_types::Timestamp,
        now: fireemu_core_types::time::LogicalInstant,
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
        if at.as_nanos() > now.as_nanos() {
            return Err(Status::invalid_argument(
                "read_time must not be in the future",
            ));
        }
        let oldest = now.as_nanos() - i128::from(READ_TIME_RETENTION_SECONDS) * 1_000_000_000;
        if at.as_nanos() < oldest {
            // FAILED_PRECONDITION, as the backend and the official emulator answer it.
            return Err(Status::failed_precondition(format!(
                "The requested 'read_time' is too old (it must be within the past {READ_TIME_RETENTION_SECONDS} seconds)."
            )));
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
                    let previous = Self::required_txn(parent, &read_write.retry_transaction)?;
                    db.retry_transaction(&previous, now)
                }
            }
            Some(pb::transaction_options::Mode::ReadOnly(ro)) => match &ro.consistency_selector {
                Some(pb::transaction_options::read_only::ConsistencySelector::ReadTime(ts)) => {
                    let at = Self::read_time_selector(ts, now)?;
                    db.begin_transaction_at(at, now)
                }
                None => db.begin_transaction(true, now),
            },
            None => db.begin_transaction(true, now),
        }
        .map_err(|e| status_from_error(&e))
    }

    fn select_snapshot(
        parent: &Parent,
        db: &mut FirestoreState,
        selector: SnapshotSelector<'_>,
        now: fireemu_core_types::time::LogicalInstant,
    ) -> Result<SelectedSnapshot, Status> {
        match selector {
            SnapshotSelector::Transaction(bytes) => {
                let transaction = Self::required_txn(parent, bytes)?;
                db.touch_transaction(&transaction, now)
                    .map_err(|error| status_from_error(&error))?;
                Ok(SelectedSnapshot {
                    transaction: Some(transaction),
                    report: Vec::new(),
                    read_at: None,
                })
            }
            SnapshotSelector::NewTransaction(options) => {
                let transaction = Self::new_transaction(parent, db, options, now)?;
                let report = Self::token(parent, &transaction);
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
                })
            }),
            SnapshotSelector::Transaction(_) | SnapshotSelector::NewTransaction(_) => {
                self.with_db(parent, |db| {
                    let selected = Self::select_snapshot(parent, db, selector, now)?;
                    let mut access = SnapshotAccess {
                        state: SnapshotState::Exclusive(db),
                        selected,
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
                (Some(Self::required_txn(&parent, t)?), None)
            }
            Some(pb::get_document_request::ConsistencySelector::ReadTime(ts)) => {
                (None, Some(Self::read_time_selector(ts, now)?))
            }
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
                SnapshotSelector::ReadTime(Self::read_time_selector(ts, now)?)
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
            let items = req
                .documents
                .iter()
                .zip(reads)
                .map(|(name, (_, doc))| match doc {
                    Some(d) => BatchGetItem::Found(d),
                    None => BatchGetItem::Missing(name.clone()),
                })
                .collect();
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
                            let at = Self::read_time_selector(ts, now)?;
                            db.begin_transaction_at(at, now)
                        }
                        None => db.begin_transaction(true, now),
                    }
                }
                Some(pb::transaction_options::Mode::ReadWrite(read_write))
                    if !read_write.retry_transaction.is_empty() =>
                {
                    let previous = Self::required_txn(&parent, &read_write.retry_transaction)?;
                    db.retry_transaction(&previous, now)
                }
                _ => db.begin_transaction(false, now),
            }
            .map_err(|e| status_from_error(&e))?;
            Ok(Self::token(&parent, &id))
        })
    }

    /// `Commit`.
    pub fn commit(&self, req: &pb::CommitRequest) -> Result<pb::CommitResponse, Status> {
        self.commit_with(req, &allow_all)
    }

    /// `Commit` with a write guard.
    pub fn commit_with(
        &self,
        req: &pb::CommitRequest,
        guard: WriteGuard<'_>,
    ) -> Result<pb::CommitResponse, Status> {
        let (parent, writes) = Self::plan_commit(req)?;
        self.fault(parent.project.as_str(), "firestore.commit")?;
        let txn = Self::txn(&parent, &req.transaction)?;
        let now = self.write_time();
        let result = self.with_db(&parent, |db| {
            guard(db, &writes, now)?;
            let result = self.commit_with_events(&parent, db, &writes, txn.as_ref(), now)?;
            Ok(result)
        })?;
        Ok(encode_commit(&result))
    }

    /// `Rollback`.
    pub fn rollback(&self, req: &pb::RollbackRequest) -> Result<(), Status> {
        let parent = parse_parent(&format!("{}/documents", req.database)).map_err(status)?;
        let txn = Self::required_txn(&parent, &req.transaction)?;
        self.with_db(&parent, |db| {
            db.rollback(&txn).map_err(|e| status_from_error(&e))
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
    pub fn run_query_authorized_as(
        &self,
        req: &pb::RunQueryRequest,
        authorization_req: &pb::RunQueryRequest,
        guard: ReadGuard<'_>,
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
                SnapshotSelector::ReadTime(Self::read_time_selector(ts, now)?)
            }
            None => SnapshotSelector::Latest,
        };
        self.with_selected_snapshot(&parent, selector, now, |access| {
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
            let (docs, stats) = access.run_query_with_stats(&accepted.query)?;
            let read_time = Some(encode_instant(access.read_time(now)?));
            // The rows the offset skipped, reported on the first result as the backend does.
            let skipped = i32::try_from(u64::from(accepted.query.offset).min(stats.matched))
                .unwrap_or(i32::MAX);
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
                SnapshotSelector::ReadTime(Self::read_time_selector(ts, now)?)
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
            Some(pb::list_documents_request::ConsistencySelector::ReadTime(ts)) => {
                (None, Some(Self::read_time_selector(ts, now)?))
            }
            Some(pb::list_documents_request::ConsistencySelector::Transaction(t)) => {
                (Some(Self::required_txn(&parent, t)?), None)
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
                        page_size,
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
                page_query.limit = Some(u32::try_from(page_size).unwrap_or(u32::MAX));
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
                                    page_size,
                                );
                            if cursor_is_missing {
                                continued_missing_suffix = true;
                                documents.clear();
                                missing = page;
                            }
                        }
                    }
                    if !continued_missing_suffix && documents.len() < page_size {
                        missing = access
                            .db()
                            .list_missing_parents_page_at(
                                parent.document.as_ref(),
                                &req.collection_id,
                                version,
                                None,
                                page_size - documents.len(),
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
                    (Some(_), _) => access.run_query_with_stats(&accepted.query)?.0,
                    (None, true) => access
                        .db()
                        .run_query(&accepted.query, version)
                        .map_err(|e| status_from_error(&e))?,
                    (None, false) if bounded_name_page => access.db().list_documents_page_at(
                        parent.document.as_ref(),
                        &req.collection_id,
                        version,
                        after_path.as_ref(),
                        page_size,
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
            // A full page carries a token whether or not anything follows, as the backend
            // and the official emulator issue it; the next page is then simply empty.
            let full = documents.len() >= page_size;
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
            let full = ids.len() >= page_size;
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
    // Reported on the first result; an offset past the end reports nothing, as the
    // official emulator answers it.
    if let Some(first) = responses.first_mut().filter(|r| r.document.is_some()) {
        first.skipped_results = skipped_results;
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
}
