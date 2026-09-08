//! Local Firestore execution (Milestone E): versioned document store, atomic commits with
//! preconditions, update masks and field transforms, MVCC transactions, query execution and
//! aggregations.
//!
//! Invariants owned here: `INV-COMMIT-001` (a commit applies entirely or not at all),
//! `INV-TXN-001` (transaction writes are never partially visible) and `INV-LIMIT-001` (a
//! request that violates a limit changes nothing). Every write is validated against a staged
//! copy first; state is only touched after the whole request has been accepted.

use core::cmp::Ordering;
use core::fmt;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::sync::Arc;

use fireemu_core_limits::catalogs::FIRESTORE_STANDARD_2026_08_25;
use fireemu_core_limits::evaluate::{
    evaluate, LimitDisposition, LimitViolation, DEFAULT_THRESHOLDS,
};
use fireemu_core_limits::model::LimitMaximum;
use fireemu_core_limits::plan::FirestorePlanProfile;
use fireemu_core_types::admission::EventAdmissionError;
use fireemu_core_types::hash::Sha256;
use fireemu_core_types::ids::{CollectionId, DocumentId};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use crate::field_path::FieldPath;
use crate::limits;
use crate::path::DocumentPath;
use crate::query::{
    Cursor, Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope, UnaryOp,
};
use crate::size::{document_size, document_size_bytes};
use crate::value::{normalize_fields_for_storage, stored_fields_eq, Timestamp, Value, ValueKind};

/// How far back a snapshot selector may reach: the documented Firestore `read_time` window
/// of one hour (no PITR). The store owns this value because it decides which versions stay
/// reachable; the gRPC adapter re-declares the same number on the wire
/// (`fireemu_adapter_grpc::local::READ_TIME_RETENTION_SECONDS`) and the two must stay equal.
pub const READ_TIME_RETENTION_SECONDS: i64 = 3600;
/// Default maximum retained versions of one document path. This is an explicit retention
/// root for pinned clocks: older selectors fail instead of growing history without bound.
pub const DEFAULT_MAX_RETAINED_VERSIONS_PER_PATH: usize = 1_024;
/// Maximum distinct query snapshots retained by one transaction for phantom detection.
pub const MAX_TRANSACTION_QUERY_RECORDS: usize = 256;
/// Maximum conflict-ledger bytes retained by one transaction. The 10 MiB budget matches the
/// public API request ceiling while also bounding state accumulated across several reads.
pub const MAX_TRANSACTION_CONFLICT_LEDGER_BYTES: u64 = 10 * 1024 * 1024;
/// Aggregate memory-admission budget for conflict ledgers retained by active transactions.
pub const MAX_ACTIVE_TRANSACTION_CONFLICT_LEDGER_BYTES: u64 = 64 * 1024 * 1024;

/// Monotonic commit version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CommitVersion(u64);

impl CommitVersion {
    /// Raw value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// A version from its raw value (`Listen` resume tokens).
    #[must_use]
    pub const fn from_value(value: u64) -> Self {
        Self(value)
    }
}

/// A stored document version.
#[derive(Debug, Clone, PartialEq)]
pub struct Document {
    /// Path.
    pub path: DocumentPath,
    /// Fields.
    pub fields: BTreeMap<String, Value>,
    /// Creation time (survives updates).
    pub create_time: LogicalInstant,
    /// Last update time.
    pub update_time: LogicalInstant,
    /// Commit version that produced this document version.
    pub version: CommitVersion,
}

/// Immutable document allocation shared by MVCC history and commit-event consumers.
pub type SharedDocument = Arc<Document>;

type DocumentHistory = BTreeMap<DocumentPath, Vec<(CommitVersion, Option<SharedDocument>)>>;
type StagedChange = (DocumentPath, Option<SharedDocument>, Option<SharedDocument>);

/// One name-ordered `ListDocuments` entry when `show_missing` is enabled.
#[derive(Debug, Clone, PartialEq)]
pub enum ListedDocument {
    /// A stored document.
    Present(Document),
    /// A path with descendants but no stored document of its own.
    Missing(DocumentPath),
}

/// A document an import installs, with the times the artifact recorded for it.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedDocument {
    /// Where the document goes.
    pub path: DocumentPath,
    /// Its fields.
    pub fields: BTreeMap<String, Value>,
    /// The creation time to keep; `None` uses the import's commit time.
    pub create_time: Option<LogicalInstant>,
    /// The update time to keep; `None` uses the import's commit time.
    pub update_time: Option<LogicalInstant>,
}

/// Transaction handle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransactionId(u64);

impl TransactionId {
    /// Raw value (used for the wire token).
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Rebuilds a handle from a wire token.
    #[must_use]
    pub const fn from_value(v: u64) -> Self {
        Self(v)
    }
}

/// Identity of one logical query execution inside a transaction.
///
/// A repeated query shape has a different execution identity so a continuation page can only
/// append to the stream that requested it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryExecutionId(u64);

impl QueryExecutionId {
    /// Raw value used by an adapter to carry the identity across pages.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Rebuilds an identity from its raw value.
    #[must_use]
    pub const fn from_value(value: u64) -> Self {
        Self(value)
    }
}

/// Write precondition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    /// The document must (not) exist.
    Exists(bool),
    /// The document's update time must equal this instant.
    UpdateTime(LogicalInstant),
}

/// Field transform kinds.
#[derive(Debug, Clone, PartialEq)]
pub enum TransformKind {
    /// Set to the commit time.
    ServerTimestamp,
    /// Numeric increment (saturating for integers, as documented).
    Increment(Value),
    /// Numeric maximum.
    Maximum(Value),
    /// Numeric minimum.
    Minimum(Value),
    /// Append elements that are not already present.
    AppendMissingElements(Vec<Value>),
    /// Remove all equal elements.
    RemoveAllFromArray(Vec<Value>),
}

/// A field transform.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldTransform {
    /// Field.
    pub field: FieldPath,
    /// Kind.
    pub kind: TransformKind,
}

/// Write operation.
#[derive(Debug, Clone, PartialEq)]
pub enum WriteOp {
    /// Set / update a document. With `update_mask = None` the document is replaced; with a
    /// mask only the listed paths are set (or deleted when absent from `fields`).
    Set {
        /// Path.
        path: DocumentPath,
        /// Fields.
        fields: BTreeMap<String, Value>,
        /// Update mask.
        update_mask: Option<Vec<FieldPath>>,
    },
    /// Delete a document (no-op when absent).
    Delete {
        /// Path.
        path: DocumentPath,
    },
    /// Check the precondition on a document without changing it (transaction reads).
    Verify {
        /// Path.
        path: DocumentPath,
    },
}

impl WriteOp {
    /// Target path.
    #[must_use]
    pub const fn path(&self) -> &DocumentPath {
        match self {
            Self::Set { path, .. } | Self::Delete { path } | Self::Verify { path } => path,
        }
    }
}

/// One write in a commit.
#[derive(Debug, Clone, PartialEq)]
pub struct Write {
    /// Operation.
    pub op: WriteOp,
    /// Precondition.
    pub precondition: Option<Precondition>,
    /// Transforms applied after the operation.
    pub transforms: Vec<FieldTransform>,
}

/// Per-write result.
#[derive(Debug, Clone, PartialEq)]
pub struct WriteResult {
    /// Update time of the written document (commit time), `None` for no-op deletes.
    pub update_time: Option<LogicalInstant>,
    /// Values produced by the transforms, in order.
    pub transform_results: Vec<Value>,
}

/// One document changed by a commit (event source).
#[derive(Debug, Clone, PartialEq)]
pub struct DocumentChange {
    /// Path.
    pub path: DocumentPath,
    /// The document before the commit (`None` = absent).
    pub before: Option<SharedDocument>,
    /// The document after the commit (`None` = deleted).
    pub after: Option<SharedDocument>,
}

/// Commit result.
#[derive(Debug, Clone, PartialEq)]
pub struct CommitResult {
    /// Commit time.
    pub commit_time: LogicalInstant,
    /// Per-write results.
    pub write_results: Vec<WriteResult>,
    /// Version assigned to the commit.
    pub version: CommitVersion,
    /// Documents that actually changed, in path order (no-op writes are not listed).
    pub changes: Arc<[DocumentChange]>,
}

struct StagedDocument {
    before: Option<SharedDocument>,
    current: Option<SharedDocument>,
    changed: bool,
}

/// Aggregation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Aggregation {
    /// Count, optionally capped.
    Count {
        /// Cap.
        up_to: Option<u64>,
    },
    /// Sum of numeric values.
    Sum(FieldPath),
    /// Average of numeric values (`Null` when none).
    Avg(FieldPath),
}

/// Firestore errors (spec 8.12); the wire adapter maps them to gRPC / REST codes.
#[derive(Debug, Clone, PartialEq)]
pub enum FirestoreError {
    /// Invalid request.
    InvalidArgument(String),
    /// Precondition failed.
    FailedPrecondition(String),
    /// Document already exists.
    AlreadyExists(DocumentPath),
    /// Document not found.
    NotFound(DocumentPath),
    /// Transaction conflict.
    Aborted(String),
    /// Limit violated.
    ResourceExhausted(LimitViolation),
    /// The retained MVCC history cannot grow without violating its explicit budget.
    HistoryCapacity(HistoryCapacityError),
    /// A coupled logical event batch could not be reserved before publication.
    EventAdmission(EventAdmissionError),
    /// Not implemented.
    Unimplemented(String),
}

impl fmt::Display for FirestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Self::FailedPrecondition(m) => write!(f, "failed precondition: {m}"),
            Self::AlreadyExists(p) => write!(f, "document already exists: {p}"),
            Self::NotFound(p) => write!(f, "document not found: {p}"),
            Self::Aborted(m) => write!(f, "aborted: {m}"),
            Self::ResourceExhausted(v) => write!(f, "resource exhausted: {v}"),
            Self::HistoryCapacity(error) => write!(f, "history capacity exhausted: {error}"),
            Self::EventAdmission(error) => write!(f, "event admission failed: {error}"),
            Self::Unimplemented(m) => write!(f, "unimplemented: {m}"),
        }
    }
}

/// Configurable hard limits for one database's retained MVCC history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryLimits {
    /// Logical bytes retained by history and its lookup roots.
    pub max_bytes: u64,
    /// Document versions, including tombstones.
    pub max_versions: u64,
}

impl Default for HistoryLimits {
    fn default() -> Self {
        Self {
            max_bytes: 1 << 30,
            max_versions: 1_000_000,
        }
    }
}

/// Deterministic logical accounting for the retained MVCC ownership graph.
///
/// This is not allocator or RSS accounting. Document payload sizes use Firestore's storage
/// size model; fixed metadata charges make every retained lookup root explicit and portable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HistoryUsage {
    /// Newest live document payloads.
    pub live_document_bytes: u64,
    /// Older retained document payloads.
    pub historical_document_bytes: u64,
    /// Path keys plus retained/live lookup-index references.
    pub path_and_index_bytes: u64,
    /// Version tuple metadata.
    pub version_metadata_bytes: u64,
    /// Tombstone markers.
    pub tombstone_bytes: u64,
    /// Commit-time lookup entries.
    pub commit_time_bytes: u64,
    /// Total logical bytes.
    pub total_bytes: u64,
    /// Retained versions, including tombstones.
    pub versions: u64,
    /// Retained tombstones.
    pub tombstones: u64,
    /// Distinct retained paths.
    pub paths: u64,
    /// Retained commit-time entries.
    pub commit_times: u64,
}

const HISTORY_PATH_KEY_OVERHEAD: u64 = 32;
const HISTORY_INDEX_REFERENCE_OVERHEAD: u64 = 16;
const HISTORY_VERSION_METADATA_BYTES: u64 = 16;
const HISTORY_TOMBSTONE_BYTES: u64 = 1;
const HISTORY_COMMIT_TIME_BYTES: u64 = 24;

fn history_path_and_index_bytes(path: &DocumentPath, live: bool) -> u64 {
    let path_bytes = u64::try_from(path.resource_name().len()).unwrap_or(u64::MAX);
    let retained_roots = 4u64;
    let live_roots = u64::from(live) * 3;
    path_bytes
        .saturating_add(HISTORY_PATH_KEY_OVERHEAD)
        .saturating_add(
            (retained_roots + live_roots).saturating_mul(HISTORY_INDEX_REFERENCE_OVERHEAD),
        )
}

fn finish_history_usage(mut usage: HistoryUsage) -> HistoryUsage {
    usage.total_bytes = usage
        .live_document_bytes
        .saturating_add(usage.historical_document_bytes)
        .saturating_add(usage.path_and_index_bytes)
        .saturating_add(usage.version_metadata_bytes)
        .saturating_add(usage.tombstone_bytes)
        .saturating_add(usage.commit_time_bytes);
    usage
}

fn add_history_usage(left: HistoryUsage, right: HistoryUsage) -> HistoryUsage {
    finish_history_usage(HistoryUsage {
        live_document_bytes: left
            .live_document_bytes
            .saturating_add(right.live_document_bytes),
        historical_document_bytes: left
            .historical_document_bytes
            .saturating_add(right.historical_document_bytes),
        path_and_index_bytes: left
            .path_and_index_bytes
            .saturating_add(right.path_and_index_bytes),
        version_metadata_bytes: left
            .version_metadata_bytes
            .saturating_add(right.version_metadata_bytes),
        tombstone_bytes: left.tombstone_bytes.saturating_add(right.tombstone_bytes),
        commit_time_bytes: left
            .commit_time_bytes
            .saturating_add(right.commit_time_bytes),
        total_bytes: 0,
        versions: left.versions.saturating_add(right.versions),
        tombstones: left.tombstones.saturating_add(right.tombstones),
        paths: left.paths.saturating_add(right.paths),
        commit_times: left.commit_times.saturating_add(right.commit_times),
    })
}

fn subtract_history_usage(left: HistoryUsage, right: HistoryUsage) -> HistoryUsage {
    finish_history_usage(HistoryUsage {
        live_document_bytes: left
            .live_document_bytes
            .saturating_sub(right.live_document_bytes),
        historical_document_bytes: left
            .historical_document_bytes
            .saturating_sub(right.historical_document_bytes),
        path_and_index_bytes: left
            .path_and_index_bytes
            .saturating_sub(right.path_and_index_bytes),
        version_metadata_bytes: left
            .version_metadata_bytes
            .saturating_sub(right.version_metadata_bytes),
        tombstone_bytes: left.tombstone_bytes.saturating_sub(right.tombstone_bytes),
        commit_time_bytes: left
            .commit_time_bytes
            .saturating_sub(right.commit_time_bytes),
        total_bytes: 0,
        versions: left.versions.saturating_sub(right.versions),
        tombstones: left.tombstones.saturating_sub(right.tombstones),
        paths: left.paths.saturating_sub(right.paths),
        commit_times: left.commit_times.saturating_sub(right.commit_times),
    })
}

fn history_path_usage(
    path: &DocumentPath,
    versions: &[(CommitVersion, Option<Arc<Document>>)],
) -> HistoryUsage {
    if versions.is_empty() {
        return HistoryUsage::default();
    }
    let live = matches!(versions.last(), Some((_, Some(_))));
    let mut usage = HistoryUsage {
        paths: 1,
        path_and_index_bytes: history_path_and_index_bytes(path, live),
        ..HistoryUsage::default()
    };
    for (index, (_, document)) in versions.iter().enumerate() {
        usage.versions = usage.versions.saturating_add(1);
        usage.version_metadata_bytes = usage
            .version_metadata_bytes
            .saturating_add(HISTORY_VERSION_METADATA_BYTES);
        if let Some(document) = document {
            let bytes = document_size_bytes(path, &document.fields).unwrap_or(u64::MAX);
            if index + 1 == versions.len() {
                usage.live_document_bytes = usage.live_document_bytes.saturating_add(bytes);
            } else {
                usage.historical_document_bytes =
                    usage.historical_document_bytes.saturating_add(bytes);
            }
        } else {
            usage.tombstones = usage.tombstones.saturating_add(1);
            usage.tombstone_bytes = usage
                .tombstone_bytes
                .saturating_add(HISTORY_TOMBSTONE_BYTES);
        }
    }
    finish_history_usage(usage)
}

fn history_path_usage_after_floor(
    path: &DocumentPath,
    versions: &[(CommitVersion, Option<Arc<Document>>)],
    floor: CommitVersion,
) -> HistoryUsage {
    let cut = versions
        .partition_point(|(version, _)| *version <= floor)
        .saturating_sub(1);
    let remaining = &versions[cut..];
    if matches!(remaining, [(version, None)] if *version <= floor) {
        HistoryUsage::default()
    } else {
        history_path_usage(path, remaining)
    }
}

/// A rejected history-budget dimension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryCapacityError {
    /// `bytes` or `versions`.
    pub dimension: &'static str,
    /// Projected value.
    pub current: u64,
    /// Configured maximum.
    pub maximum: u64,
}

impl fmt::Display for HistoryCapacityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} exceeds {}",
            self.dimension, self.current, self.maximum
        )
    }
}

/// Usage before and after a staged commit, passed to aggregate admission owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryProjection {
    /// Usage of the currently published state.
    pub before: HistoryUsage,
    /// A conservative reservation ceiling after the commit. Legal compaction may make the
    /// actually published usage smaller, but never larger.
    pub after: HistoryUsage,
}

impl std::error::Error for FirestoreError {}

#[derive(Debug, Clone)]
struct Transaction {
    read_only: bool,
    read_version: CommitVersion,
    /// Snapshot time reported for every read inside the transaction.
    read_time: LogicalInstant,
    started_at: LogicalInstant,
    /// Observed version per read path (`None` = absent at read time).
    read_set: BTreeMap<DocumentPath, Option<CommitVersion>>,
    /// Query executions inside the transaction and a collision-resistant digest of each
    /// completed snapshot result. A changed result at commit time is a phantom conflict.
    queries: Vec<TransactionQueryObservation>,
    /// Estimated bytes retained by the read-set documents and query execution descriptors.
    conflict_ledger_bytes: u64,
    last_activity: LogicalInstant,
    state: TransactionState,
    /// Bumped on every operation the client drives through this transaction, so a waiter
    /// under a clock that does not move can still tell an idle holder from a busy one.
    activity: u64,
    /// Set while a commit of this transaction is held back by another transaction's locks
    /// (the adapter is waiting for that release). Another transaction that then runs into
    /// this one's locks is the deadlock production resolves by aborting one side: that other
    /// side is aborted, so this one can proceed.
    waiting_to_commit: bool,
}

#[derive(Debug, Clone)]
struct TransactionQueryObservation {
    execution_id: QueryExecutionId,
    query: Query,
    required_fields: Vec<FieldPath>,
    observation: QueryObservation,
    consumption: Consumption,
    /// Only a completed stream has enough rows to compare with a fresh execution at commit.
    complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueryObservation {
    rows: u64,
    digest: Sha256,
}

/// The retained transaction metadata for one query result row. It contains no document fields,
/// so a borrowed aggregation can register the same read set without materializing the result.
struct ObservedQueryDocument {
    path: DocumentPath,
    version: CommitVersion,
    bytes: u64,
}

impl Default for QueryObservation {
    fn default() -> Self {
        Self {
            rows: 0,
            digest: Sha256::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionState {
    Active,
    RetryableAborted,
    RolledBack,
    Retried,
    Finished,
}

/// Execution counters for one query. Test and verification surface (`FS-QUERY-PERF-*`); the
/// wire API never exposes them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueryStats {
    /// Documents visited by the scan.
    pub scanned: u64,
    /// Documents that passed scope, filter, ordering and cursors, or documents materialized
    /// from a cached selection during this page. The selection total is recorded separately.
    pub matched: u64,
    /// Largest number of candidate rows held at once. With a finite `offset + limit` this
    /// never exceeds that sum, whatever the size of the matched set.
    pub peak_candidates: u64,
    /// Documents cloned into the result. Execution borrows every value it filters and orders
    /// on, so this is the only place where a document's heap-backed fields are copied.
    pub cloned_documents: u64,
    /// Heap-backed field bytes copied into projected results. This excludes stored fields
    /// inspected only for filters, ordering and cursors.
    pub cloned_field_bytes: u64,
    /// Retained history paths inspected to establish historical listing visibility.
    pub visibility_checks: u64,
    /// Scope-index paths visited before visibility resolution. A parent-scoped scan that walks
    /// unrelated paths shows up here even when `scanned` stays small.
    pub index_paths_visited: u64,
    /// Documents whose filter expression was evaluated (in-scope rows with a filter).
    pub filter_evaluations: u64,
}

impl QueryStats {
    /// Folds one more stage or page into an accumulated total: counters add, the peak keeps
    /// the maximum.
    pub fn absorb(&mut self, other: &Self) {
        self.scanned = self.scanned.saturating_add(other.scanned);
        self.matched = self.matched.saturating_add(other.matched);
        self.peak_candidates = self.peak_candidates.max(other.peak_candidates);
        self.cloned_documents = self.cloned_documents.saturating_add(other.cloned_documents);
        self.cloned_field_bytes = self
            .cloned_field_bytes
            .saturating_add(other.cloned_field_bytes);
        self.visibility_checks = self
            .visibility_checks
            .saturating_add(other.visibility_checks);
        self.index_paths_visited = self
            .index_paths_visited
            .saturating_add(other.index_paths_visited);
        self.filter_evaluations = self
            .filter_evaluations
            .saturating_add(other.filter_evaluations);
    }
}

/// Bounded transaction-ledger counters exposed for performance regression tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransactionBookkeepingStats {
    /// Active transactions retained by the database.
    pub active: usize,
    /// Finished transaction attempts retained as retry lineage.
    pub finished: usize,
    /// Active expiry deadlines in the ordered deadline index.
    pub deadlines: usize,
    /// Finished-lineage expiry deadlines retained by the ordered index.
    pub finished_deadlines: usize,
    /// Deadline index entries examined while pruning expired transactions.
    pub pruned_deadlines: u64,
    /// Estimated bytes retained by all active transaction conflict ledgers.
    pub conflict_ledger_bytes: u64,
}

/// Which catalog limits a database refuses.
///
/// Every limit the pinned official Firestore emulator refuses is refused under either
/// scope. The difference is the limits only production enforces: the `strict` profile
/// refuses them too, the `firebase` profile admits the request the way the official
/// emulator does, so a suite written against the official emulator sees the same answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LimitScope {
    /// Every enforced limit, production's set (the `strict` profile).
    #[default]
    Production,
    /// Only the limits the official emulator refuses too (the `firebase` profile).
    OfficialEmulator,
}

type DirectCollectionPaths =
    BTreeMap<(Option<DocumentPath>, CollectionId), BTreeSet<Arc<DocumentPath>>>;
type CollectionGroupPaths = BTreeMap<CollectionId, BTreeSet<Arc<DocumentPath>>>;
type ListingTrieIter<'a> = Box<dyn Iterator<Item = (&'a DocumentId, &'a ListingTrieDocument)> + 'a>;
type ListingTrieNodeIter<'a> = Box<dyn Iterator<Item = &'a ListingTrieDocument> + 'a>;

#[derive(Debug, Clone, Default)]
struct ListingTrie {
    collections: BTreeMap<CollectionId, ListingTrieCollection>,
}

#[derive(Debug, Clone, Default)]
struct ListingTrieCollection {
    documents: BTreeMap<DocumentId, ListingTrieDocument>,
    live_candidates: BTreeSet<DocumentId>,
}

#[derive(Debug, Clone, Default)]
struct ListingTrieDocument {
    retained_subtree_paths: usize,
    live_subtree_paths: usize,
    retained_here: Option<Arc<DocumentPath>>,
    representative: Option<Arc<DocumentPath>>,
    children: ListingTrie,
}

impl ListingTrie {
    fn insert_retained(&mut self, path: &DocumentPath) {
        Self::insert_retained_pairs(self, path.pairs(), Arc::new(path.clone()));
    }

    fn insert_retained_pairs(
        trie: &mut Self,
        pairs: &[(CollectionId, DocumentId)],
        path: Arc<DocumentPath>,
    ) {
        let Some(((collection, document), rest)) = pairs.split_first() else {
            return;
        };
        let node = trie
            .collections
            .entry(collection.clone())
            .or_default()
            .documents
            .entry(document.clone())
            .or_default();
        node.retained_subtree_paths += 1;
        node.representative.get_or_insert_with(|| Arc::clone(&path));
        if rest.is_empty() {
            node.retained_here = Some(path);
        } else {
            Self::insert_retained_pairs(&mut node.children, rest, path);
        }
    }

    fn remove_retained(&mut self, path: &DocumentPath) {
        Self::remove_retained_pairs(self, path.pairs());
    }

    fn remove_retained_pairs(trie: &mut Self, pairs: &[(CollectionId, DocumentId)]) {
        let Some(((collection, document), rest)) = pairs.split_first() else {
            return;
        };
        let mut remove_collection = false;
        if let Some(collection_node) = trie.collections.get_mut(collection) {
            let mut remove_document = false;
            if let Some(node) = collection_node.documents.get_mut(document) {
                node.retained_subtree_paths = node.retained_subtree_paths.saturating_sub(1);
                if rest.is_empty() {
                    node.retained_here = None;
                } else {
                    Self::remove_retained_pairs(&mut node.children, rest);
                }
                remove_document = node.retained_subtree_paths == 0;
            }
            if remove_document {
                collection_node.documents.remove(document);
                collection_node.live_candidates.remove(document);
            }
            remove_collection = collection_node.documents.is_empty();
        }
        if remove_collection {
            trie.collections.remove(collection);
        }
    }

    fn adjust_live(&mut self, path: &DocumentPath, increase: bool) {
        Self::adjust_live_pairs(self, path.pairs(), increase);
    }

    fn adjust_live_pairs(trie: &mut Self, pairs: &[(CollectionId, DocumentId)], increase: bool) {
        let Some(((collection, document), rest)) = pairs.split_first() else {
            return;
        };
        let Some(collection_node) = trie.collections.get_mut(collection) else {
            debug_assert!(!increase, "live paths must first enter the retained trie");
            return;
        };
        let Some(node) = collection_node.documents.get_mut(document) else {
            debug_assert!(!increase, "live paths must first enter the retained trie");
            return;
        };
        let was_live = node.live_subtree_paths > 0;
        {
            if increase {
                node.live_subtree_paths += 1;
            } else {
                node.live_subtree_paths = node.live_subtree_paths.saturating_sub(1);
            }
            if !rest.is_empty() {
                Self::adjust_live_pairs(&mut node.children, rest, increase);
            }
        }
        let is_live = node.live_subtree_paths > 0;
        if was_live != is_live {
            if is_live {
                collection_node.live_candidates.insert(document.clone());
            } else {
                collection_node.live_candidates.remove(document);
            }
        }
    }

    fn collection(
        &self,
        parent: Option<&DocumentPath>,
        collection_id: &CollectionId,
    ) -> Option<&ListingTrieCollection> {
        self.collections_under(parent)?.get(collection_id)
    }

    fn collections_under(
        &self,
        parent: Option<&DocumentPath>,
    ) -> Option<&BTreeMap<CollectionId, ListingTrieCollection>> {
        let mut trie = self;
        if let Some(parent) = parent {
            for (collection, document) in parent.pairs() {
                trie = &trie
                    .collections
                    .get(collection)?
                    .documents
                    .get(document)?
                    .children;
            }
        }
        Some(&trie.collections)
    }
}

/// Reclaimable usage at one immutable database version and retention floor.
#[derive(Debug, Clone, Copy)]
struct CompactionForecast {
    version: CommitVersion,
    floor: CommitVersion,
    reclaimed: HistoryUsage,
}

/// One Firestore database.
#[derive(Debug, Clone)]
pub struct FirestoreState {
    index_catalog: Arc<crate::index::IndexSet>,
    /// Version history per path; `None` entries are tombstones.
    history: DocumentHistory,
    /// Retained paths grouped by their exact parent and innermost collection.
    direct_collection_paths: DirectCollectionPaths,
    /// Live paths grouped by their exact parent and innermost collection.
    live_direct_collection_paths: DirectCollectionPaths,
    /// Retained document hierarchy for name-ordered listing candidates.
    listing_trie: ListingTrie,
    /// Retained paths grouped by their innermost collection for collection-group queries.
    collection_group_paths: CollectionGroupPaths,
    /// Live paths grouped by their innermost collection for latest collection-group queries.
    live_collection_group_paths: CollectionGroupPaths,
    /// Every live path in resource-name order for latest kindless descendant queries.
    live_paths: BTreeSet<Arc<DocumentPath>>,
    /// Which limits commits refuse.
    limit_scope: LimitScope,
    version: CommitVersion,
    next_transaction: u64,
    next_query_execution: u64,
    transactions: BTreeMap<TransactionId, Transaction>,
    active_transaction_count: usize,
    /// How many transactions have left the active state (commit, abort, rollback, expiry):
    /// every one releases the locks its reads held, so a writer refused for contention can
    /// tell when trying again may succeed.
    transaction_releases: u64,
    active_transaction_deadlines: BTreeSet<(LogicalInstant, TransactionId)>,
    active_transaction_versions: BTreeMap<CommitVersion, usize>,
    active_transaction_conflict_ledger_bytes: u64,
    finished_transactions: BTreeSet<TransactionId>,
    finished_transaction_deadlines: BTreeSet<(LogicalInstant, TransactionId)>,
    transaction_prune_visits: u64,
    /// Last published commit time; commit times are strictly monotonic per database.
    last_commit_time: Option<LogicalInstant>,
    /// Commit time of every retained version (`read_time` snapshots).
    commit_times: VecDeque<(CommitVersion, LogicalInstant)>,
    /// Versions strictly below this one have been compacted away: no supported read, no
    /// active transaction and no acceptable resume token can still name them.
    compaction_floor: CommitVersion,
    /// Oldest version required by the per-path capacity root.
    capacity_floor: CommitVersion,
    /// Maximum versions retained for one path unless an active transaction pins an older
    /// snapshot.
    max_versions_per_path: usize,
    /// Whole-database logical history limits.
    history_limits: HistoryLimits,
    /// Exact logical usage, maintained with each published history mutation. Keeping this
    /// cached makes a no-op admission independent of retained-history cardinality.
    history_usage: HistoryUsage,
    /// Last immutable compaction forecast. A refused external admission can retry without
    /// rescanning the retained corpus; every published mutation invalidates it.
    compaction_forecast: Option<CompactionForecast>,
    /// Paths whose history still holds something a later compaction could drop (more than
    /// one version, or a single tombstone). Compaction only visits these.
    compactable: BTreeSet<DocumentPath>,
}

impl Default for FirestoreState {
    fn default() -> Self {
        Self {
            index_catalog: Arc::new(crate::index::IndexSet::default()),
            history: BTreeMap::new(),
            direct_collection_paths: BTreeMap::new(),
            live_direct_collection_paths: BTreeMap::new(),
            listing_trie: ListingTrie::default(),
            collection_group_paths: BTreeMap::new(),
            live_collection_group_paths: BTreeMap::new(),
            live_paths: BTreeSet::new(),
            limit_scope: LimitScope::default(),
            version: CommitVersion::default(),
            next_transaction: 0,
            next_query_execution: 0,
            transactions: BTreeMap::new(),
            active_transaction_count: 0,
            transaction_releases: 0,
            active_transaction_deadlines: BTreeSet::new(),
            active_transaction_versions: BTreeMap::new(),
            active_transaction_conflict_ledger_bytes: 0,
            finished_transactions: BTreeSet::new(),
            finished_transaction_deadlines: BTreeSet::new(),
            transaction_prune_visits: 0,
            last_commit_time: None,
            commit_times: VecDeque::new(),
            compaction_floor: CommitVersion::default(),
            capacity_floor: CommitVersion::default(),
            max_versions_per_path: DEFAULT_MAX_RETAINED_VERSIONS_PER_PATH,
            history_limits: HistoryLimits::default(),
            history_usage: HistoryUsage::default(),
            compaction_forecast: None,
            compactable: BTreeSet::new(),
        }
    }
}

fn limit(id: &str) -> &'static fireemu_core_limits::model::LimitDefinition {
    FIRESTORE_STANDARD_2026_08_25
        .find(id)
        .unwrap_or_else(|| unreachable!("catalog entry {id} is checked by catalog tests"))
}

fn check_limit(id: &str, current: u64) -> Result<(), FirestoreError> {
    match evaluate(
        limit(id),
        current,
        &FirestorePlanProfile::default(),
        DEFAULT_THRESHOLDS,
    ) {
        LimitDisposition::Reject(v) => Err(FirestoreError::ResourceExhausted(v)),
        _ => Ok(()),
    }
}

fn seconds_limit(id: &str, fallback: i64) -> LogicalDuration {
    match limit(id).maximum {
        LimitMaximum::Fixed(secs) => {
            LogicalDuration::from_seconds(i64::try_from(secs).unwrap_or(i64::MAX))
        }
        _ => LogicalDuration::from_seconds(fallback),
    }
}

/// The message the official emulator returns (with `ABORTED`) for a transaction that has been
/// finished -- committed, rolled back, or run past its budget. `ABORTED` is the code the SDKs
/// retry a transaction on.
const TRANSACTION_NO_LONGER_VALID: &str =
    "The referenced transaction has expired or is no longer valid.";
const TRANSACTION_CONCURRENT_MODIFICATION: &str =
    "Transaction was aborted due to a concurrent modification.";
/// Production's answer to a write that collides with the locks an active read-write
/// transaction holds on what it read (`concurrencyMode: PESSIMISTIC`).
pub const TOO_MUCH_CONTENTION: &str = "Too much contention on these documents. Please try again.";
const MAX_FINISHED_TRANSACTION_LINEAGE: usize = 8_192;

fn transaction_ttl() -> LogicalDuration {
    seconds_limit(limits::TRANSACTION_TOTAL_TIME, 270)
}

fn transaction_idle_ttl() -> LogicalDuration {
    seconds_limit(limits::TRANSACTION_IDLE_TIME, 60)
}

fn transaction_deadline(transaction: &Transaction) -> LogicalInstant {
    let total = transaction_lineage_deadline(transaction);
    let idle = transaction
        .last_activity
        .checked_add(transaction_idle_ttl())
        .unwrap_or(LogicalInstant::MAX);
    total.min(idle)
}

fn transaction_lineage_deadline(transaction: &Transaction) -> LogicalInstant {
    transaction
        .started_at
        .checked_add(transaction_ttl())
        .unwrap_or(LogicalInstant::MAX)
}

fn decrement_version_count(versions: &mut BTreeMap<CommitVersion, usize>, version: CommitVersion) {
    let Some(count) = versions.get_mut(&version) else {
        return;
    };
    *count -= 1;
    if *count == 0 {
        versions.remove(&version);
    }
}

fn observed_document_bytes(path: &DocumentPath, document: Option<&Document>) -> u64 {
    document.map_or_else(
        || {
            u64::try_from(path.resource_name().len())
                .unwrap_or(u64::MAX)
                .saturating_add(32)
        },
        |document| document_size(path, &document.fields).map_or(u64::MAX, |size| size.total),
    )
}

fn query_observation(documents: &[Document]) -> QueryObservation {
    let mut observation = QueryObservation::default();
    for document in documents {
        observation.push(document);
    }
    observation
}

impl QueryObservation {
    fn push(&mut self, document: &Document) {
        self.push_parts(&document.path, document.version);
    }

    fn push_parts(&mut self, path: &DocumentPath, version: CommitVersion) {
        self.rows = self.rows.saturating_add(1);
        for segment in path.resource_name_segments() {
            self.digest.update(
                &u64::try_from(segment.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            self.digest.update(segment.as_bytes());
        }
        self.digest.update(&version.value().to_be_bytes());
    }
}

fn document_in_scope(document: &Document, scope: &QueryScope) -> bool {
    path_in_scope(&document.path, scope)
}

/// Whether a document at `path` belongs to the range `scope` selects.
fn path_in_scope(path: &DocumentPath, scope: &QueryScope) -> bool {
    let parent_len = scope.parent().map_or(0, |parent| parent.pairs().len());
    match scope {
        QueryScope::Collection {
            parent,
            collection_id,
        } => {
            path.pairs().len() == parent_len + 1
                && path.collection_id() == collection_id
                && parent
                    .as_ref()
                    .is_none_or(|prefix| path.pairs()[..parent_len] == *prefix.pairs())
        }
        QueryScope::CollectionGroup {
            parent,
            collection_id,
        } => {
            path.collection_id() == collection_id
                && parent.as_ref().is_none_or(|prefix| {
                    path.pairs().len() > parent_len && path.pairs()[..parent_len] == *prefix.pairs()
                })
        }
        QueryScope::KindlessAllDescendants { parent } => parent.as_ref().is_none_or(|prefix| {
            path.pairs().len() > parent_len && path.pairs()[..parent_len] == *prefix.pairs()
        }),
    }
}

/// Exclusive bounds `(parent, successor)` enclosing exactly the strict descendants of
/// `parent` in path order.
fn descendant_bounds(parent: &DocumentPath) -> (DocumentPath, DocumentPath) {
    (parent.clone(), parent.descendants_upper_bound())
}

fn is_strict_descendant(path: &DocumentPath, parent: &DocumentPath) -> bool {
    path.pairs().len() > parent.pairs().len()
        && path.pairs()[..parent.pairs().len()] == *parent.pairs()
}

fn field_path_retained_bytes(path: &FieldPath) -> u64 {
    path.segments().iter().fold(
        u64::try_from(core::mem::size_of::<FieldPath>()).unwrap_or(u64::MAX),
        |total, segment| {
            total
                .saturating_add(u64::try_from(core::mem::size_of::<String>()).unwrap_or(u64::MAX))
                .saturating_add(
                    u64::try_from(segment.len())
                        .unwrap_or(u64::MAX)
                        .saturating_mul(2),
                )
        },
    )
}

fn allocation_bytes<T>(capacity: usize) -> u64 {
    u64::try_from(capacity)
        .unwrap_or(u64::MAX)
        .saturating_mul(u64::try_from(core::mem::size_of::<T>()).unwrap_or(u64::MAX))
}

fn document_path_retained_bytes(path: &DocumentPath) -> u64 {
    let mut total = u64::try_from(core::mem::size_of::<DocumentPath>()).unwrap_or(u64::MAX);
    total = total
        .saturating_add(
            u64::try_from(path.project().as_str().len())
                .unwrap_or(u64::MAX)
                .saturating_mul(2),
        )
        .saturating_add(
            u64::try_from(path.database().as_str().len())
                .unwrap_or(u64::MAX)
                .saturating_mul(2),
        )
        .saturating_add(allocation_bytes::<(
            fireemu_core_types::ids::CollectionId,
            fireemu_core_types::ids::DocumentId,
        )>(path.pairs().len()));
    for (collection, document) in path.pairs() {
        total = total
            .saturating_add(
                u64::try_from(collection.as_str().len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(2),
            )
            .saturating_add(
                u64::try_from(document.as_str().len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(2),
            );
    }
    total
}

fn value_retained_bytes(value: &Value) -> u64 {
    const BTREE_ENTRY_OVERHEAD: u64 = 128;

    let mut total = u64::try_from(core::mem::size_of::<Value>()).unwrap_or(u64::MAX);
    let mut pending = vec![value];
    while let Some(value) = pending.pop() {
        match value {
            Value::String(text) | Value::Reference(text) => {
                total = total.saturating_add(u64::try_from(text.capacity()).unwrap_or(u64::MAX));
            }
            Value::Bytes(bytes) => {
                total = total.saturating_add(u64::try_from(bytes.capacity()).unwrap_or(u64::MAX));
            }
            Value::Array(values) => {
                total = total.saturating_add(allocation_bytes::<Value>(values.capacity()));
                pending.extend(values);
            }
            Value::Vector(values) => {
                total = total.saturating_add(allocation_bytes::<f64>(values.capacity()));
            }
            Value::Map(entries) => {
                for (key, value) in entries {
                    total = total
                        .saturating_add(
                            u64::try_from(core::mem::size_of::<(String, Value)>())
                                .unwrap_or(u64::MAX),
                        )
                        .saturating_add(BTREE_ENTRY_OVERHEAD)
                        .saturating_add(u64::try_from(key.capacity()).unwrap_or(u64::MAX));
                    pending.push(value);
                }
            }
            Value::Null
            | Value::Boolean(_)
            | Value::Integer(_)
            | Value::Double(_)
            | Value::Timestamp(_)
            | Value::GeoPoint(_) => {}
        }
    }
    total
}

fn query_retained_bytes(query: &Query) -> u64 {
    let mut total = 256u64;
    let (parent, collection) = match &query.scope {
        QueryScope::Collection {
            parent,
            collection_id,
        }
        | QueryScope::CollectionGroup {
            parent,
            collection_id,
        } => (parent.as_ref(), Some(collection_id.as_str())),
        QueryScope::KindlessAllDescendants { parent } => (parent.as_ref(), None),
    };
    if let Some(parent) = parent {
        total = total.saturating_add(document_path_retained_bytes(parent));
    }
    if let Some(collection) = collection {
        total = total.saturating_add(u64::try_from(collection.len()).unwrap_or(u64::MAX));
    }
    if let Some(filter) = &query.filter {
        let mut pending = vec![filter];
        while let Some(filter) = pending.pop() {
            total = total.saturating_add(64);
            match filter {
                FilterExpr::Field { field, value, .. } => {
                    total = total.saturating_add(field_path_retained_bytes(field));
                    total = total.saturating_add(value_retained_bytes(value));
                }
                FilterExpr::Unary { field, .. } => {
                    total = total.saturating_add(field_path_retained_bytes(field));
                }
                FilterExpr::And(children) | FilterExpr::Or(children) => {
                    pending.extend(children);
                }
            }
        }
    }
    for order in &query.order_by {
        total = total
            .saturating_add(32)
            .saturating_add(field_path_retained_bytes(&order.field));
    }
    for cursor in [query.start_at.as_ref(), query.end_at.as_ref()]
        .into_iter()
        .flatten()
    {
        total = total.saturating_add(32);
        for value in &cursor.values {
            total = total.saturating_add(value_retained_bytes(value));
        }
    }
    if let Some(projection) = &query.projection {
        for field in projection {
            total = total.saturating_add(field_path_retained_bytes(field));
        }
    }
    total
}

impl FirestoreState {
    /// Empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the index generation used to validate subsequent writes and imports.
    pub fn set_index_catalog(&mut self, indexes: crate::index::IndexSet) {
        if *self.index_catalog != indexes {
            self.index_catalog = Arc::new(indexes);
        }
    }

    /// Empty database refusing the limits of `scope`.
    #[must_use]
    pub fn with_limit_scope(scope: LimitScope) -> Self {
        Self {
            limit_scope: scope,
            ..Self::default()
        }
    }

    /// Empty database with an explicit maximum retained-version count per document path.
    /// Zero is normalized to one because the live version itself can never be discarded.
    #[must_use]
    pub fn with_history_version_limit(max_versions_per_path: usize) -> Self {
        Self::default().with_retained_version_limit(max_versions_per_path)
    }

    /// Creates a store with explicit whole-database history limits.
    #[must_use]
    pub fn with_history_limits(limits: HistoryLimits) -> Self {
        Self {
            history_limits: limits,
            ..Self::default()
        }
    }

    /// Overrides whole-database history limits without changing retained state.
    #[must_use]
    pub const fn with_retained_history_limits(mut self, limits: HistoryLimits) -> Self {
        self.history_limits = limits;
        self
    }

    /// Sets the maximum retained-version count per document path on this database.
    #[must_use]
    pub fn with_retained_version_limit(mut self, max_versions_per_path: usize) -> Self {
        self.max_versions_per_path = max_versions_per_path.max(1);
        self
    }

    /// Starts transaction ids at `offset` instead of zero, so a token is not guessable from
    /// the count of transactions a database has begun (the adapter draws the offset from the
    /// session seed). Ids stay monotonic; only the first one moves.
    #[must_use]
    pub const fn with_transaction_id_offset(mut self, offset: u64) -> Self {
        self.next_transaction = offset;
        self
    }

    /// Which limits commits refuse.
    #[must_use]
    pub const fn limit_scope(&self) -> LimitScope {
        self.limit_scope
    }

    /// Latest commit version.
    #[must_use]
    pub const fn current_version(&self) -> CommitVersion {
        self.version
    }

    /// Latest version of a document.
    #[must_use]
    pub fn get(&self, path: &DocumentPath) -> Option<&Document> {
        self.history
            .get(path)
            .and_then(|h| h.last())
            .and_then(|(_, d)| d.as_deref())
    }

    /// Document as of `version`.
    #[must_use]
    pub fn get_at(&self, path: &DocumentPath, version: CommitVersion) -> Option<&Document> {
        self.history
            .get(path)?
            .iter()
            .rev()
            .find(|(v, _)| *v <= version)
            .and_then(|(_, d)| d.as_deref())
    }

    fn insert_scope_path(&mut self, path: &DocumentPath) {
        let shared = Arc::new(path.clone());
        self.direct_collection_paths
            .entry((path.parent_document(), path.collection_id().clone()))
            .or_default()
            .insert(Arc::clone(&shared));
        self.listing_trie.insert_retained(path);
        self.collection_group_paths
            .entry(path.collection_id().clone())
            .or_default()
            .insert(shared);
    }

    fn insert_live_scope_path(&mut self, path: &DocumentPath) {
        let shared = Arc::new(path.clone());
        self.live_direct_collection_paths
            .entry((path.parent_document(), path.collection_id().clone()))
            .or_default()
            .insert(Arc::clone(&shared));
        self.live_collection_group_paths
            .entry(path.collection_id().clone())
            .or_default()
            .insert(Arc::clone(&shared));
        self.live_paths.insert(shared);
        self.listing_trie.adjust_live(path, true);
    }

    fn remove_scope_path(&mut self, path: &DocumentPath) {
        let direct_key = (path.parent_document(), path.collection_id().clone());
        if let std::collections::btree_map::Entry::Occupied(mut entry) =
            self.direct_collection_paths.entry(direct_key)
        {
            entry.get_mut().remove(path);
            if entry.get().is_empty() {
                entry.remove();
            }
        }
        self.listing_trie.remove_retained(path);
        if let std::collections::btree_map::Entry::Occupied(mut entry) = self
            .collection_group_paths
            .entry(path.collection_id().clone())
        {
            entry.get_mut().remove(path);
            if entry.get().is_empty() {
                entry.remove();
            }
        }
    }

    fn remove_live_scope_path(&mut self, path: &DocumentPath) {
        let direct_key = (path.parent_document(), path.collection_id().clone());
        if let std::collections::btree_map::Entry::Occupied(mut entry) =
            self.live_direct_collection_paths.entry(direct_key)
        {
            entry.get_mut().remove(path);
            if entry.get().is_empty() {
                entry.remove();
            }
        }
        if let std::collections::btree_map::Entry::Occupied(mut entry) = self
            .live_collection_group_paths
            .entry(path.collection_id().clone())
        {
            entry.get_mut().remove(path);
            if entry.get().is_empty() {
                entry.remove();
            }
        }
        self.live_paths.remove(path);
        self.listing_trie.adjust_live(path, false);
    }

    fn rebuild_scope_paths(
        history: &DocumentHistory,
    ) -> (
        DirectCollectionPaths,
        CollectionGroupPaths,
        DirectCollectionPaths,
        CollectionGroupPaths,
        BTreeSet<Arc<DocumentPath>>,
        ListingTrie,
    ) {
        let mut direct = BTreeMap::new();
        let mut groups = BTreeMap::new();
        let mut live_direct = BTreeMap::new();
        let mut live_groups = BTreeMap::new();
        let mut live_paths = BTreeSet::new();
        let mut listing_trie = ListingTrie::default();
        for (path, versions) in history {
            let shared = Arc::new(path.clone());
            direct
                .entry((path.parent_document(), path.collection_id().clone()))
                .or_insert_with(BTreeSet::new)
                .insert(Arc::clone(&shared));
            listing_trie.insert_retained(path);
            groups
                .entry(path.collection_id().clone())
                .or_insert_with(BTreeSet::new)
                .insert(Arc::clone(&shared));
            if matches!(versions.last(), Some((_, Some(_)))) {
                live_direct
                    .entry((path.parent_document(), path.collection_id().clone()))
                    .or_insert_with(BTreeSet::new)
                    .insert(Arc::clone(&shared));
                live_groups
                    .entry(path.collection_id().clone())
                    .or_insert_with(BTreeSet::new)
                    .insert(Arc::clone(&shared));
                live_paths.insert(shared);
                listing_trie.adjust_live(path, true);
            }
        }
        (
            direct,
            groups,
            live_direct,
            live_groups,
            live_paths,
            listing_trie,
        )
    }

    fn scope_paths<'a>(
        &'a self,
        scope: &'a QueryScope,
        version: Option<CommitVersion>,
    ) -> Box<dyn Iterator<Item = &'a DocumentPath> + 'a> {
        match scope {
            QueryScope::Collection {
                parent,
                collection_id,
            } => Box::new(
                if version.is_some() {
                    &self.direct_collection_paths
                } else {
                    &self.live_direct_collection_paths
                }
                .get(&(parent.clone(), collection_id.clone()))
                .into_iter()
                .flat_map(|paths| paths.iter().map(AsRef::as_ref)),
            ),
            QueryScope::CollectionGroup {
                parent,
                collection_id,
            } => {
                let paths = if version.is_some() {
                    &self.collection_group_paths
                } else {
                    &self.live_collection_group_paths
                };
                let Some(paths) = paths.get(collection_id) else {
                    return Box::new(core::iter::empty());
                };
                if let Some(parent) = parent {
                    let lower = Arc::new(parent.clone());
                    Box::new(
                        paths
                            .range((
                                core::ops::Bound::Excluded(lower),
                                core::ops::Bound::Unbounded,
                            ))
                            .map(AsRef::as_ref)
                            .take_while(move |path| is_strict_descendant(path, parent)),
                    )
                } else {
                    Box::new(paths.iter().map(AsRef::as_ref))
                }
            }
            QueryScope::KindlessAllDescendants { parent } => {
                if version.is_some() {
                    if let Some(parent) = parent {
                        Box::new(
                            self.history
                                .range((
                                    core::ops::Bound::Excluded(parent.clone()),
                                    core::ops::Bound::Unbounded,
                                ))
                                .map(|(path, _)| path)
                                .take_while(move |path| is_strict_descendant(path, parent)),
                        )
                    } else {
                        Box::new(self.history.keys())
                    }
                } else if let Some(parent) = parent {
                    let lower = Arc::new(parent.clone());
                    Box::new(
                        self.live_paths
                            .range((
                                core::ops::Bound::Excluded(lower),
                                core::ops::Bound::Unbounded,
                            ))
                            .map(AsRef::as_ref)
                            .take_while(move |path| is_strict_descendant(path, parent)),
                    )
                } else {
                    Box::new(self.live_paths.iter().map(AsRef::as_ref))
                }
            }
        }
    }

    /// All paths in descending resource-name order. Unlike a continuation range this starts at
    /// the end of each scope, allowing the first page of a `__name__ DESC` query to seek too.
    fn scope_paths_descending<'a>(
        &'a self,
        scope: &'a QueryScope,
        version: Option<CommitVersion>,
    ) -> Box<dyn Iterator<Item = &'a DocumentPath> + 'a> {
        use core::ops::Bound::Excluded;

        match scope {
            QueryScope::Collection {
                parent,
                collection_id,
            } => {
                let paths = if version.is_some() {
                    &self.direct_collection_paths
                } else {
                    &self.live_direct_collection_paths
                };
                Box::new(
                    paths
                        .get(&(parent.clone(), collection_id.clone()))
                        .into_iter()
                        .flat_map(|paths| paths.iter().rev().map(AsRef::as_ref)),
                )
            }
            QueryScope::CollectionGroup {
                parent,
                collection_id,
            } => {
                let paths = if version.is_some() {
                    &self.collection_group_paths
                } else {
                    &self.live_collection_group_paths
                };
                let Some(paths) = paths.get(collection_id) else {
                    return Box::new(core::iter::empty());
                };
                if let Some(parent) = parent {
                    let (lower, upper) = descendant_bounds(parent);
                    Box::new(
                        paths
                            .range::<DocumentPath, _>((Excluded(&lower), Excluded(&upper)))
                            .rev()
                            .map(AsRef::as_ref),
                    )
                } else {
                    Box::new(paths.iter().rev().map(AsRef::as_ref))
                }
            }
            QueryScope::KindlessAllDescendants { parent } => {
                if version.is_some() {
                    if let Some(parent) = parent {
                        let (lower, upper) = descendant_bounds(parent);
                        Box::new(
                            self.history
                                .range::<DocumentPath, _>((Excluded(&lower), Excluded(&upper)))
                                .rev()
                                .map(|(path, _)| path),
                        )
                    } else {
                        Box::new(self.history.keys().rev())
                    }
                } else if let Some(parent) = parent {
                    let (lower, upper) = descendant_bounds(parent);
                    Box::new(
                        self.live_paths
                            .range::<DocumentPath, _>((Excluded(&lower), Excluded(&upper)))
                            .rev()
                            .map(AsRef::as_ref),
                    )
                } else {
                    Box::new(self.live_paths.iter().rev().map(AsRef::as_ref))
                }
            }
        }
    }

    /// Returns document paths strictly after `after` for a name-ascending scope.
    ///
    /// The scope indexes are ordered by resource name, so this range starts the iterator at the
    /// continuation boundary instead of scanning and rejecting the prefix before it.
    fn scope_paths_after<'a>(
        &'a self,
        scope: &'a QueryScope,
        version: Option<CommitVersion>,
        after: &'a DocumentPath,
    ) -> Box<dyn Iterator<Item = &'a DocumentPath> + 'a> {
        use core::ops::Bound::{Excluded, Unbounded};

        match scope {
            QueryScope::Collection {
                parent,
                collection_id,
            } => {
                let paths = if version.is_some() {
                    &self.direct_collection_paths
                } else {
                    &self.live_direct_collection_paths
                };
                Box::new(
                    paths
                        .get(&(parent.clone(), collection_id.clone()))
                        .into_iter()
                        .flat_map(move |paths| {
                            paths
                                .range::<DocumentPath, _>((Excluded(after), Unbounded))
                                .map(AsRef::as_ref)
                        }),
                )
            }
            QueryScope::CollectionGroup {
                parent,
                collection_id,
            } => {
                let paths = if version.is_some() {
                    &self.collection_group_paths
                } else {
                    &self.live_collection_group_paths
                };
                let Some(paths) = paths.get(collection_id) else {
                    return Box::new(core::iter::empty());
                };
                let paths = paths
                    .range::<DocumentPath, _>((Excluded(after), Unbounded))
                    .map(AsRef::as_ref);
                if let Some(parent) = parent {
                    Box::new(paths.take_while(move |path| is_strict_descendant(path, parent)))
                } else {
                    Box::new(paths)
                }
            }
            QueryScope::KindlessAllDescendants { parent } => {
                if version.is_some() {
                    if let Some(parent) = parent {
                        Box::new(
                            self.history
                                .range::<DocumentPath, _>((Excluded(after), Unbounded))
                                .map(|(path, _)| path)
                                .take_while(move |path| is_strict_descendant(path, parent)),
                        )
                    } else {
                        Box::new(
                            self.history
                                .range::<DocumentPath, _>((Excluded(after), Unbounded))
                                .map(|(path, _)| path),
                        )
                    }
                } else {
                    let paths = self
                        .live_paths
                        .range::<DocumentPath, _>((Excluded(after), Unbounded))
                        .map(AsRef::as_ref);
                    if let Some(parent) = parent {
                        Box::new(paths.take_while(move |path| is_strict_descendant(path, parent)))
                    } else {
                        Box::new(paths)
                    }
                }
            }
        }
    }

    /// Returns document paths strictly before `before` for a name-descending scope.
    ///
    /// The scope indexes are ordered by resource name, so reversing the prefix range starts the
    /// iterator at the continuation boundary instead of rescanning the names already returned.
    fn scope_paths_before<'a>(
        &'a self,
        scope: &'a QueryScope,
        version: Option<CommitVersion>,
        before: &'a DocumentPath,
    ) -> Box<dyn Iterator<Item = &'a DocumentPath> + 'a> {
        use core::ops::Bound::{Excluded, Unbounded};

        match scope {
            QueryScope::Collection {
                parent,
                collection_id,
            } => {
                let paths = if version.is_some() {
                    &self.direct_collection_paths
                } else {
                    &self.live_direct_collection_paths
                };
                Box::new(
                    paths
                        .get(&(parent.clone(), collection_id.clone()))
                        .into_iter()
                        .flat_map(move |paths| {
                            paths
                                .range::<DocumentPath, _>((Unbounded, Excluded(before)))
                                .rev()
                                .map(AsRef::as_ref)
                        }),
                )
            }
            QueryScope::CollectionGroup {
                parent,
                collection_id,
            } => {
                let paths = if version.is_some() {
                    &self.collection_group_paths
                } else {
                    &self.live_collection_group_paths
                };
                let Some(paths) = paths.get(collection_id) else {
                    return Box::new(core::iter::empty());
                };
                // Every path strictly between a parent and one of its descendants is itself a
                // descendant, so the parent is the lower bound and no per-path filter is needed.
                // A continuation outside the parent yields nothing.
                if let Some(parent) = parent {
                    if !is_strict_descendant(before, parent) {
                        return Box::new(core::iter::empty());
                    }
                }
                let lower = parent.as_ref().map_or(Unbounded, Excluded);
                Box::new(
                    paths
                        .range::<DocumentPath, _>((lower, Excluded(before)))
                        .rev()
                        .map(AsRef::as_ref),
                )
            }
            QueryScope::KindlessAllDescendants { parent } => {
                if let Some(parent) = parent {
                    if !is_strict_descendant(before, parent) {
                        return Box::new(core::iter::empty());
                    }
                }
                let lower = parent.as_ref().map_or(Unbounded, Excluded);
                if version.is_some() {
                    Box::new(
                        self.history
                            .range::<DocumentPath, _>((lower, Excluded(before)))
                            .rev()
                            .map(|(path, _)| path),
                    )
                } else {
                    Box::new(
                        self.live_paths
                            .range::<DocumentPath, _>((lower, Excluded(before)))
                            .rev()
                            .map(AsRef::as_ref),
                    )
                }
            }
        }
    }

    /// All live documents (latest versions), in path order.
    fn live_documents(&self, at: Option<CommitVersion>) -> impl Iterator<Item = &Document> {
        self.history.iter().filter_map(move |(path, _)| match at {
            Some(v) => self.get_at(path, v),
            None => self.get(path),
        })
    }

    /// Every live document (latest versions), in path order.
    ///
    /// This is what an export walks: the current state of the database, without the version
    /// history, transactions or tombstones that belong to the running session.
    #[must_use]
    pub fn documents(&self) -> Vec<Document> {
        self.live_documents(None).cloned().collect()
    }

    /// Consumes a detached state and returns its live documents without cloning them.
    ///
    /// Export owns the visible-only state returned by `snapshot_scope`, so moving documents
    /// out avoids keeping a second full copy beside the snapshot while preserving path order.
    #[must_use]
    pub fn into_documents(self) -> Vec<Document> {
        self.history
            .into_values()
            .filter_map(|versions| versions.into_iter().next_back()?.1)
            .map(|document| {
                Arc::try_unwrap(document).unwrap_or_else(|shared| shared.as_ref().clone())
            })
            .collect()
    }

    /// A cheap, saturating estimate of the bytes the visible documents hold (`SNAP-MEM-01`):
    /// the newest version of every live document, sized by the same `document_size` model the
    /// limits use. A document whose size overflows the model contributes zero rather than
    /// aborting the estimate; saturating throughout, so no database can overflow the estimate
    /// into a small number and slip past a byte budget. This is what a named snapshot retains.
    #[must_use]
    pub fn visible_bytes(&self) -> u64 {
        self.live_documents(None)
            .map(|d| document_size(&d.path, &d.fields).map_or(0, |b| b.total))
            .fold(0u64, u64::saturating_add)
    }

    /// The visible state of this database as an independent copy: the newest version of
    /// every live document, and nothing of the running session.
    ///
    /// This is what a named snapshot retains. The version history, the tombstones, the open
    /// transactions and the commit-time index that serve `read_time` selectors and `Listen`
    /// resume tokens are not copied: a restore is a new epoch in which every stream has
    /// ended and every transaction is gone, so nothing could ask for them, and copying them
    /// would make a snapshot cost the whole retained history rather than the live data. The
    /// copy keeps the commit version and the last commit time, so commits after a restore
    /// stay monotonic, and its compaction floor is that version: a `read_time` before it or
    /// a resume token from before it is refused exactly as after a compaction.
    #[must_use]
    pub fn visible_snapshot(&self) -> Self {
        let history = self
            .history
            .iter()
            .filter_map(|(path, versions)| {
                let (version, document) = versions.last()?;
                let document = document.as_ref()?;
                Some((path.clone(), vec![(*version, Some(document.clone()))]))
            })
            .collect();
        let (
            direct_collection_paths,
            collection_group_paths,
            live_direct_collection_paths,
            live_collection_group_paths,
            live_paths,
            listing_trie,
        ) = Self::rebuild_scope_paths(&history);
        let mut snapshot = Self {
            index_catalog: Arc::clone(&self.index_catalog),
            history,
            direct_collection_paths,
            live_direct_collection_paths,
            listing_trie,
            collection_group_paths,
            live_collection_group_paths,
            live_paths,
            limit_scope: self.limit_scope,
            version: self.version,
            next_transaction: self.next_transaction,
            next_query_execution: self.next_query_execution,
            transactions: BTreeMap::new(),
            active_transaction_count: 0,
            transaction_releases: 0,
            active_transaction_deadlines: BTreeSet::new(),
            active_transaction_versions: BTreeMap::new(),
            active_transaction_conflict_ledger_bytes: 0,
            finished_transactions: BTreeSet::new(),
            finished_transaction_deadlines: BTreeSet::new(),
            transaction_prune_visits: 0,
            last_commit_time: self.last_commit_time,
            commit_times: self.commit_times.back().copied().into_iter().collect(),
            compaction_floor: self.version,
            capacity_floor: self.version,
            max_versions_per_path: self.max_versions_per_path,
            history_limits: self.history_limits,
            history_usage: HistoryUsage::default(),
            compaction_forecast: None,
            compactable: BTreeSet::new(),
        };
        snapshot.history_usage = snapshot.recount_history_usage();
        snapshot
    }

    /// Installs `documents` as one commit, keeping the creation and update times they
    /// carry.
    ///
    /// An import is not a sequence of writes: the documents come from an artifact that
    /// already recorded what the database held, so they are published together, at one
    /// commit version and one commit time, and a document that named its own creation time
    /// keeps it. `None` times fall back to the commit time -- which is what the official
    /// Firestore managed export always leads to, because that format records no document
    /// timestamps at all.
    ///
    /// The result is the same [`CommitResult`] a commit produces, so the caller can publish
    /// the change set the way a normal commit does. Every document is validated first, so a
    /// rejected one leaves the database untouched.
    pub fn import_documents(
        &mut self,
        documents: Vec<ImportedDocument>,
        now: LogicalInstant,
    ) -> Result<CommitResult, FirestoreError> {
        let commit_time = self.next_commit_time(now);
        let next_version = CommitVersion(self.version.0 + 1);
        // Stage and validate everything before anything is published.
        let mut staged: BTreeMap<DocumentPath, Document> = BTreeMap::new();
        for imported in documents {
            let mut fields = imported.fields;
            normalize_fields_for_storage(&mut fields);
            let document = Document {
                path: imported.path.clone(),
                fields,
                create_time: imported.create_time.unwrap_or(commit_time),
                update_time: imported.update_time.unwrap_or(commit_time),
                version: next_version,
            };
            validate_document(&document)?;
            self.index_catalog
                .document_index_usage(&document.path, &document.fields)?;
            staged.insert(imported.path, document);
        }
        self.last_commit_time = Some(commit_time);
        self.compaction_forecast = None;
        if staged.is_empty() {
            return Ok(CommitResult {
                commit_time,
                write_results: Vec::new(),
                version: self.version,
                changes: Arc::from([]),
            });
        }
        self.version = next_version;
        self.commit_times.push_back((next_version, commit_time));
        let mut changes = Vec::with_capacity(staged.len());
        for (path, document) in staged {
            let before = self
                .history
                .get(&path)
                .and_then(|versions| versions.last())
                .and_then(|(_, document)| document.clone());
            let became_live = before.is_none();
            // A second version is something a later compaction can drop, exactly as after a
            // normal commit.
            let compactable = self.history.contains_key(&path);
            if !compactable {
                self.insert_scope_path(&path);
            }
            if became_live {
                self.insert_live_scope_path(&path);
            }
            let document = Arc::new(document);
            changes.push(DocumentChange {
                path: path.clone(),
                before,
                after: Some(Arc::clone(&document)),
            });
            self.history
                .entry(path.clone())
                .or_default()
                .push((next_version, Some(document)));
            self.record_capacity_pressure(&path);
            if compactable {
                self.compactable.insert(path);
            }
        }
        self.history_usage = self.recount_history_usage();
        self.compact(now);
        Ok(CommitResult {
            commit_time,
            write_results: Vec::new(),
            version: next_version,
            changes: Arc::from(changes),
        })
    }

    /// Begins a transaction at the current version.
    pub fn begin_transaction(
        &mut self,
        read_only: bool,
        now: LogicalInstant,
    ) -> Result<TransactionId, FirestoreError> {
        let read_time = self.read_time(now);
        self.insert_transaction(read_only, self.version, read_time, now)
    }

    /// Begins a retry attempt linked to a transaction previously issued by this database.
    /// The previous attempt may already be finished after an `ABORTED` commit, but an unknown
    /// handle is never accepted as retry lineage.
    pub fn retry_transaction(
        &mut self,
        previous: &TransactionId,
        now: LogicalInstant,
    ) -> Result<TransactionId, FirestoreError> {
        self.prune_transactions(now);
        let Some(previous_attempt) = self.transactions.get(previous) else {
            return Err(FirestoreError::InvalidArgument(
                "Invalid retry transaction.".into(),
            ));
        };
        if previous_attempt.read_only {
            return Err(FirestoreError::InvalidArgument(
                "read-only transaction cannot be retried as read-write".into(),
            ));
        }
        // A client retrying an attempt that is still active (its commit was held back by
        // another transaction's locks and the client gave up waiting) abandons that attempt:
        // it is rolled back, and its locks released, before the retry begins.
        if previous_attempt.state == TransactionState::Active {
            self.finish_transaction(previous, TransactionState::RolledBack);
        }
        // Finishing the attempt may have evicted it from the bounded finished lineage.
        let Some(previous_attempt) = self.transactions.get(previous) else {
            return Err(FirestoreError::InvalidArgument(
                "Invalid retry transaction.".into(),
            ));
        };
        if !matches!(
            previous_attempt.state,
            TransactionState::RetryableAborted | TransactionState::RolledBack
        ) {
            return Err(FirestoreError::InvalidArgument(
                "Invalid retry transaction.".into(),
            ));
        }
        self.ensure_transaction_capacity()?;
        if let Some(previous_attempt) = self.transactions.get_mut(previous) {
            previous_attempt.state = TransactionState::Retried;
        }
        let read_time = self.read_time(now);
        self.insert_transaction(false, self.version, read_time, now)
    }

    /// Starts a read-only transaction over the snapshot at `read_time` (the latest version
    /// committed at or before it); its budgets still run from `now`. A `read_time` older than
    /// the retained history is refused instead of being served from unrelated versions.
    pub fn begin_transaction_at(
        &mut self,
        read_time: LogicalInstant,
        now: LogicalInstant,
    ) -> Result<TransactionId, FirestoreError> {
        let Some(version) = self.version_at_retained(read_time) else {
            return Err(FirestoreError::FailedPrecondition(
                "read_time is no longer retained by this database".into(),
            ));
        };
        self.insert_transaction(true, version, read_time, now)
    }

    fn insert_transaction(
        &mut self,
        read_only: bool,
        read_version: CommitVersion,
        read_time: LogicalInstant,
        now: LogicalInstant,
    ) -> Result<TransactionId, FirestoreError> {
        // Keep recent finished attempts so `retry_transaction` can name the attempt that was
        // just aborted. Old lineage is bounded and never participates in reads or conflicts.
        self.prune_transactions(now);
        self.ensure_transaction_capacity()?;
        self.next_transaction += 1;
        let id = TransactionId(self.next_transaction);
        let transaction = Transaction {
            read_only,
            read_version,
            read_time,
            started_at: now,
            read_set: BTreeMap::new(),
            queries: Vec::new(),
            conflict_ledger_bytes: 0,
            last_activity: now,
            state: TransactionState::Active,
            activity: 0,
            waiting_to_commit: false,
        };
        self.active_transaction_deadlines
            .insert((transaction_deadline(&transaction), id.clone()));
        *self
            .active_transaction_versions
            .entry(read_version)
            .or_default() += 1;
        self.active_transaction_count += 1;
        self.transactions.insert(id.clone(), transaction);
        Ok(id)
    }

    fn prune_transactions(&mut self, now: LogicalInstant) {
        while let Some((deadline, id)) = self.active_transaction_deadlines.first().cloned() {
            if deadline > now {
                break;
            }
            self.active_transaction_deadlines
                .remove(&(deadline, id.clone()));
            self.transaction_prune_visits = self.transaction_prune_visits.saturating_add(1);
            let Some(transaction) = self.transactions.get_mut(&id) else {
                continue;
            };
            if transaction.state != TransactionState::Active
                || transaction_deadline(transaction) != deadline
            {
                continue;
            }
            transaction.state = TransactionState::Finished;
            self.active_transaction_conflict_ledger_bytes = self
                .active_transaction_conflict_ledger_bytes
                .saturating_sub(transaction.conflict_ledger_bytes);
            transaction.conflict_ledger_bytes = 0;
            transaction.read_set.clear();
            transaction.queries.clear();
            self.active_transaction_count = self.active_transaction_count.saturating_sub(1);
            decrement_version_count(
                &mut self.active_transaction_versions,
                transaction.read_version,
            );
            self.finished_transaction_deadlines
                .insert((transaction_lineage_deadline(transaction), id.clone()));
            self.finished_transactions.insert(id);
        }
        while let Some((deadline, id)) = self.finished_transaction_deadlines.first().cloned() {
            if deadline > now {
                break;
            }
            self.finished_transaction_deadlines
                .remove(&(deadline, id.clone()));
            self.finished_transactions.remove(&id);
            if self
                .transactions
                .get(&id)
                .is_some_and(|transaction| transaction.state != TransactionState::Active)
            {
                self.transactions.remove(&id);
            }
        }
        self.evict_finished_transactions();
    }

    fn ensure_transaction_capacity(&self) -> Result<(), FirestoreError> {
        const MAX_ACTIVE_TRANSACTIONS: usize = 4_096;
        if self.active_transaction_count >= MAX_ACTIVE_TRANSACTIONS {
            return Err(FirestoreError::FailedPrecondition(
                "too many active transactions".into(),
            ));
        }
        Ok(())
    }

    fn finish_transaction(&mut self, id: &TransactionId, state: TransactionState) {
        let deadline = self
            .transactions
            .get(id)
            .filter(|transaction| transaction.state == TransactionState::Active)
            .map(transaction_deadline);
        let Some(deadline) = deadline else {
            if let Some(transaction) = self.transactions.get_mut(id) {
                transaction.state = state;
            }
            return;
        };
        self.active_transaction_deadlines
            .remove(&(deadline, id.clone()));
        self.active_transaction_count = self.active_transaction_count.saturating_sub(1);
        self.transaction_releases = self.transaction_releases.wrapping_add(1);
        if let Some(transaction) = self.transactions.get(id) {
            decrement_version_count(
                &mut self.active_transaction_versions,
                transaction.read_version,
            );
        }
        if let Some(transaction) = self.transactions.get_mut(id) {
            transaction.state = state;
            self.active_transaction_conflict_ledger_bytes = self
                .active_transaction_conflict_ledger_bytes
                .saturating_sub(transaction.conflict_ledger_bytes);
            transaction.conflict_ledger_bytes = 0;
            transaction.read_set.clear();
            transaction.queries.clear();
            self.finished_transaction_deadlines
                .insert((transaction_lineage_deadline(transaction), id.clone()));
        }
        self.finished_transactions.insert(id.clone());
        self.evict_finished_transactions();
    }

    fn evict_finished_transactions(&mut self) {
        while self.finished_transactions.len() > MAX_FINISHED_TRANSACTION_LINEAGE {
            let Some(id) = self.finished_transactions.pop_first() else {
                break;
            };
            if let Some(transaction) = self.transactions.get(&id) {
                self.finished_transaction_deadlines
                    .remove(&(transaction_lineage_deadline(transaction), id.clone()));
            }
            if self
                .transactions
                .get(&id)
                .is_some_and(|transaction| transaction.state != TransactionState::Active)
            {
                self.transactions.remove(&id);
            }
        }
    }

    /// Returns bounded transaction-ledger counters for performance regression tests.
    #[must_use]
    pub fn transaction_bookkeeping_stats(&self) -> TransactionBookkeepingStats {
        TransactionBookkeepingStats {
            active: self.active_transaction_count,
            finished: self.finished_transactions.len(),
            deadlines: self.active_transaction_deadlines.len(),
            finished_deadlines: self.finished_transaction_deadlines.len(),
            pruned_deadlines: self.transaction_prune_visits,
            conflict_ledger_bytes: self.active_transaction_conflict_ledger_bytes,
        }
    }

    /// Forgets a transaction that was never handed to the client (its read was refused).
    pub fn abandon_transaction(&mut self, id: &TransactionId) {
        if let Some(transaction) = self.transactions.remove(id) {
            if transaction.state == TransactionState::Active {
                self.active_transaction_deadlines
                    .remove(&(transaction_deadline(&transaction), id.clone()));
                self.active_transaction_count = self.active_transaction_count.saturating_sub(1);
                decrement_version_count(
                    &mut self.active_transaction_versions,
                    transaction.read_version,
                );
                self.active_transaction_conflict_ledger_bytes = self
                    .active_transaction_conflict_ledger_bytes
                    .saturating_sub(transaction.conflict_ledger_bytes);
            } else {
                self.finished_transactions.remove(id);
                self.finished_transaction_deadlines
                    .remove(&(transaction_lineage_deadline(&transaction), id.clone()));
            }
        }
    }

    /// Records a document read that was served from the transaction's snapshot (after the
    /// read was authorized), so that a later change aborts the commit.
    pub fn record_transaction_read(
        &mut self,
        id: &TransactionId,
        path: &DocumentPath,
        observed: Option<&Document>,
    ) -> Result<(), FirestoreError> {
        let transaction = self.transaction(id)?;
        if transaction.read_only {
            return Ok(());
        }
        let additional = if transaction.read_set.contains_key(path) {
            0
        } else {
            observed_document_bytes(path, observed)
        };
        let transaction_overflow = transaction.conflict_ledger_bytes.saturating_add(additional)
            > MAX_TRANSACTION_CONFLICT_LEDGER_BYTES;
        let global_overflow = self
            .active_transaction_conflict_ledger_bytes
            .saturating_add(additional)
            > MAX_ACTIVE_TRANSACTION_CONFLICT_LEDGER_BYTES;
        if transaction_overflow || global_overflow {
            self.finish_transaction(id, TransactionState::RetryableAborted);
            return Err(FirestoreError::Aborted(
                "transaction observed data exceeds the retained conflict-detection budget".into(),
            ));
        }
        if let Some(transaction) = self.transactions.get_mut(id) {
            transaction
                .read_set
                .insert(path.clone(), observed.map(|document| document.version));
            transaction.conflict_ledger_bytes =
                transaction.conflict_ledger_bytes.saturating_add(additional);
            self.active_transaction_conflict_ledger_bytes = self
                .active_transaction_conflict_ledger_bytes
                .saturating_add(additional);
        }
        Ok(())
    }

    /// Checks that a transaction is still usable at `now` (total and idle budgets,
    /// `FS-LIMIT-TRANSACTION-TOTAL-TIME` / `FS-LIMIT-TRANSACTION-IDLE-TIME`) and records the
    /// activity. A transaction that has run out its budget is finished and reported as
    /// `ABORTED` with the message the official emulator gives a transaction that is no longer
    /// valid -- the code the SDKs retry on. After the expired attempt is rejected, the client
    /// can begin a fresh transaction snapshot that observes an out-of-band write.
    pub fn touch_transaction(
        &mut self,
        id: &TransactionId,
        now: LogicalInstant,
    ) -> Result<(), FirestoreError> {
        let t = self.transaction(id)?;
        // Expiry is inclusive at the deadline (`now >= deadline`). Commit validation uses
        // this same boundary, so the transaction is gone at the exact deadline.
        let previous_deadline = transaction_deadline(t);
        let expired = now >= previous_deadline;
        if expired {
            self.finish_transaction(id, TransactionState::Finished);
            self.compact(now);
            return Err(FirestoreError::Aborted(TRANSACTION_NO_LONGER_VALID.into()));
        }
        self.active_transaction_deadlines
            .remove(&(previous_deadline, id.clone()));
        if let Some(transaction) = self.transactions.get_mut(id) {
            transaction.last_activity = now;
            transaction.activity = transaction.activity.wrapping_add(1);
            self.active_transaction_deadlines
                .insert((transaction_deadline(transaction), id.clone()));
        }
        Ok(())
    }

    /// How many operations `id` has driven so far; `None` unless the transaction is active.
    /// A waiter compares two readings to tell whether the holder went idle.
    #[must_use]
    pub fn transaction_activity(&self, id: &TransactionId) -> Option<u64> {
        self.transactions
            .get(id)
            .filter(|t| t.state == TransactionState::Active)
            .map(|t| t.activity)
    }

    /// The version visible at `at` (the latest version committed at or before it; the empty
    /// database before the first commit). Times older than the retained history clamp to the
    /// compaction floor, which is the oldest state the store can still describe; use
    /// [`Self::version_at_retained`] to tell that case apart.
    #[must_use]
    pub fn version_at(&self, at: LogicalInstant) -> CommitVersion {
        let idx = self
            .commit_times
            .partition_point(|(_, t)| t.as_nanos() <= at.as_nanos());
        idx.checked_sub(1)
            .and_then(|i| self.commit_times.get(i))
            .map_or(self.compaction_floor, |(v, _)| *v)
    }

    /// The version visible at `at`, or `None` when `at` is older than the retained history
    /// and the answer would be a different snapshot than the caller asked for.
    #[must_use]
    pub fn version_at_retained(&self, at: LogicalInstant) -> Option<CommitVersion> {
        if self.compaction_floor.value() > 0
            && self
                .commit_times
                .front()
                .is_none_or(|(_, t)| at.as_nanos() < t.as_nanos())
        {
            return None;
        }
        Some(self.version_at(at))
    }

    /// Oldest version whose history is still exact. Everything below it was compacted away.
    #[must_use]
    pub const fn compaction_floor(&self) -> CommitVersion {
        self.compaction_floor
    }

    /// Whether a snapshot at `version` can still be reproduced exactly: not compacted away
    /// and not ahead of this database. `Listen` checks it before honouring a resume token.
    #[must_use]
    pub fn is_retained(&self, version: CommitVersion) -> bool {
        version >= self.compaction_floor && version <= self.version
    }

    /// Number of document versions currently retained, tombstones included. Bounded by the
    /// live document count plus what the retention roots still pin.
    #[must_use]
    pub fn retained_versions(&self) -> usize {
        self.history.values().map(Vec::len).sum()
    }

    /// Returns exact deterministic logical usage for every retained MVCC ownership root.
    #[must_use]
    pub fn history_usage(&self) -> HistoryUsage {
        self.history_usage
    }

    fn recount_history_usage(&self) -> HistoryUsage {
        let mut usage = HistoryUsage::default();
        for (path, versions) in &self.history {
            usage = add_history_usage(usage, history_path_usage(path, versions));
        }
        usage.commit_times = u64::try_from(self.commit_times.len()).unwrap_or(u64::MAX);
        usage.commit_time_bytes = usage.commit_times.saturating_mul(HISTORY_COMMIT_TIME_BYTES);
        finish_history_usage(usage)
    }

    fn base_compaction_reclaim(&mut self, floor: CommitVersion) -> HistoryUsage {
        if floor <= self.compaction_floor {
            return HistoryUsage::default();
        }
        if let Some(forecast) = self
            .compaction_forecast
            .filter(|forecast| forecast.version == self.version && forecast.floor == floor)
        {
            return forecast.reclaimed;
        }

        let mut reclaimed = HistoryUsage::default();
        for path in &self.compactable {
            let versions = self
                .history
                .get(path)
                .map(Vec::as_slice)
                .unwrap_or_default();
            reclaimed = add_history_usage(
                reclaimed,
                subtract_history_usage(
                    history_path_usage(path, versions),
                    history_path_usage_after_floor(path, versions, floor),
                ),
            );
        }
        let removed_commit_times = u64::try_from(
            self.commit_times
                .iter()
                .take_while(|(version, _)| *version < floor)
                .count(),
        )
        .unwrap_or(u64::MAX);
        reclaimed.commit_times = removed_commit_times;
        reclaimed.commit_time_bytes =
            removed_commit_times.saturating_mul(HISTORY_COMMIT_TIME_BYTES);
        self.compaction_forecast = Some(CompactionForecast {
            version: self.version,
            floor,
            reclaimed,
        });
        reclaimed
    }

    fn projected_retention_floor(
        &self,
        projected_capacity_floor: CommitVersion,
        projected_version: CommitVersion,
        now: LogicalInstant,
    ) -> CommitVersion {
        let window = i128::from(READ_TIME_RETENTION_SECONDS) * 1_000_000_000;
        let oldest_read = LogicalInstant::from_nanos(now.as_nanos().saturating_sub(window));
        let mut floor = self.version_at(oldest_read).max(projected_capacity_floor);
        if let Some(oldest_transaction) = self
            .transactions
            .values()
            .filter(|transaction| {
                transaction.state == TransactionState::Active
                    && transaction_deadline(transaction) > now
            })
            .map(|transaction| transaction.read_version)
            .min()
        {
            floor = floor.min(oldest_transaction);
        }
        floor.max(projected_capacity_floor).min(projected_version)
    }

    fn projected_history_usage(
        &mut self,
        staged: &[StagedChange],
        now: LogicalInstant,
    ) -> (HistoryUsage, HistoryUsage) {
        let mut usage = self.history_usage();
        let mut projected_capacity_floor = self.capacity_floor;
        let next_version = CommitVersion(self.version.0.saturating_add(1));
        if !staged.is_empty() {
            usage.commit_times = usage.commit_times.saturating_add(1);
            usage.commit_time_bytes = usage
                .commit_time_bytes
                .saturating_add(HISTORY_COMMIT_TIME_BYTES);
        }
        for (path, before, after) in staged {
            usage.versions = usage.versions.saturating_add(1);
            usage.version_metadata_bytes = usage
                .version_metadata_bytes
                .saturating_add(HISTORY_VERSION_METADATA_BYTES);
            if let Some(before) = before {
                let bytes = document_size(path, &before.fields).map_or(u64::MAX, |size| size.total);
                usage.live_document_bytes = usage.live_document_bytes.saturating_sub(bytes);
                usage.historical_document_bytes =
                    usage.historical_document_bytes.saturating_add(bytes);
            }
            if let Some(after) = after {
                let bytes = document_size(path, &after.fields).map_or(u64::MAX, |size| size.total);
                usage.live_document_bytes = usage.live_document_bytes.saturating_add(bytes);
            } else {
                usage.tombstones = usage.tombstones.saturating_add(1);
                usage.tombstone_bytes = usage
                    .tombstone_bytes
                    .saturating_add(HISTORY_TOMBSTONE_BYTES);
            }
            if self.history.contains_key(path) {
                if before.is_some() && after.is_none() {
                    usage.path_and_index_bytes = usage
                        .path_and_index_bytes
                        .saturating_sub(3 * HISTORY_INDEX_REFERENCE_OVERHEAD);
                } else if before.is_none() && after.is_some() {
                    usage.path_and_index_bytes = usage
                        .path_and_index_bytes
                        .saturating_add(3 * HISTORY_INDEX_REFERENCE_OVERHEAD);
                }
            } else {
                usage.paths = usage.paths.saturating_add(1);
                usage.path_and_index_bytes = usage
                    .path_and_index_bytes
                    .saturating_add(history_path_and_index_bytes(path, after.is_some()));
            }
            let existing = self
                .history
                .get(path)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let evicted_count = existing
                .len()
                .saturating_add(1)
                .saturating_sub(self.max_versions_per_path);
            if evicted_count > 0 {
                let oldest_kept = existing
                    .get(evicted_count)
                    .map_or(next_version, |(version, _)| *version);
                projected_capacity_floor = projected_capacity_floor.max(oldest_kept);
            }
        }
        let uncompacted = finish_history_usage(usage);

        let projected_version = if staged.is_empty() {
            self.version
        } else {
            next_version
        };
        let floor =
            self.projected_retention_floor(projected_capacity_floor, projected_version, now);

        // The cached forecast describes the immutable retained state. Replace the reclaim
        // contribution only for paths this prospective commit changes, keeping retries
        // proportional to the write set instead of to all retained history.
        let mut reclaimed = self.base_compaction_reclaim(floor);
        for (path, _, after) in staged {
            let existing = self
                .history
                .get(path)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let existing_reclaim = subtract_history_usage(
                history_path_usage(path, existing),
                history_path_usage_after_floor(path, existing, floor),
            );
            reclaimed = subtract_history_usage(reclaimed, existing_reclaim);

            let mut projected = existing.to_vec();
            projected.push((next_version, after.clone()));
            let projected_reclaim = subtract_history_usage(
                history_path_usage(path, &projected),
                history_path_usage_after_floor(path, &projected, floor),
            );
            reclaimed = add_history_usage(reclaimed, projected_reclaim);
        }
        (uncompacted, subtract_history_usage(uncompacted, reclaimed))
    }

    fn check_history_limits(&self, usage: HistoryUsage) -> Result<(), FirestoreError> {
        if usage.versions > self.history_limits.max_versions {
            return Err(FirestoreError::HistoryCapacity(HistoryCapacityError {
                dimension: "versions",
                current: usage.versions,
                maximum: self.history_limits.max_versions,
            }));
        }
        if usage.total_bytes > self.history_limits.max_bytes {
            return Err(FirestoreError::HistoryCapacity(HistoryCapacityError {
                dimension: "bytes",
                current: usage.total_bytes,
                maximum: self.history_limits.max_bytes,
            }));
        }
        Ok(())
    }

    /// Oldest version still stored for any path (`None` when the database is empty).
    #[must_use]
    pub fn oldest_retained_version(&self) -> Option<CommitVersion> {
        self.history
            .values()
            .filter_map(|h| h.first().map(|(v, _)| *v))
            .min()
    }

    /// Commit time of the oldest snapshot that can still be resolved (`None` before the
    /// first commit).
    #[must_use]
    pub fn oldest_retained_commit_time(&self) -> Option<LogicalInstant> {
        self.commit_times.front().map(|(_, t)| *t)
    }

    /// The retention floor at `now`: the oldest version any retention root can still reach.
    /// The roots are the one-hour `read_time` window ([`READ_TIME_RETENTION_SECONDS`]) and
    /// the read version of every transaction that is still usable. The per-path capacity is
    /// a hard floor: crossing it invalidates an older transaction instead of retaining
    /// unbounded history while a suite clock is pinned.
    fn retention_floor(&self, now: LogicalInstant) -> CommitVersion {
        let window = i128::from(READ_TIME_RETENTION_SECONDS) * 1_000_000_000;
        let oldest_read = LogicalInstant::from_nanos(now.as_nanos().saturating_sub(window));
        let mut floor = self.version_at(oldest_read).max(self.capacity_floor);
        if let Some(oldest_transaction) = self.active_transaction_versions.keys().next() {
            floor = floor.min(*oldest_transaction);
        }
        floor.max(self.capacity_floor).min(self.version)
    }

    /// What the next compaction at `now` would release: the logical usage of every retained
    /// version below the retention floor that no snapshot, transaction or read-time root can
    /// still reach. Nothing is dropped; the forecast is cached until the store changes.
    pub fn reclaimable_history_usage(&mut self, now: LogicalInstant) -> HistoryUsage {
        let floor = self.retention_floor(now);
        self.base_compaction_reclaim(floor)
    }

    /// Drops every version that no retention root can reach any more and returns the new
    /// compaction floor. Deterministic: the store runs it itself at the end of every commit,
    /// so the floor only depends on the commit sequence and the logical times it was given.
    ///
    /// Retained: the newest version or tombstone of every path (so live reads never change),
    /// the newest version at or before the floor of every path (so snapshots at the floor
    /// stay exact) and everything after the floor. A path whose only remaining version is a
    /// tombstone at or below the floor is dropped entirely: at every version the store can
    /// still be asked about, it is indistinguishable from a path that never existed.
    pub fn compact(&mut self, now: LogicalInstant) -> CommitVersion {
        self.prune_transactions(now);
        let floor = self.retention_floor(now);
        if floor <= self.compaction_floor {
            return self.compaction_floor;
        }
        self.compaction_forecast = None;
        self.compaction_floor = floor;
        let mut removed_commit_times = 0u64;
        while self
            .commit_times
            .front()
            .is_some_and(|(version, _)| *version < floor)
        {
            self.commit_times.pop_front();
            removed_commit_times = removed_commit_times.saturating_add(1);
        }
        self.history_usage.commit_times = self
            .history_usage
            .commit_times
            .saturating_sub(removed_commit_times);
        self.history_usage.commit_time_bytes = self
            .history_usage
            .commit_time_bytes
            .saturating_sub(removed_commit_times.saturating_mul(HISTORY_COMMIT_TIME_BYTES));
        self.history_usage = finish_history_usage(self.history_usage);
        let mut compactable = core::mem::take(&mut self.compactable);
        let mut removed_paths = Vec::new();
        let mut usage_changes = Vec::new();
        compactable.retain(|path| {
            let Some(h) = self.history.get_mut(path) else {
                return false;
            };
            let before_usage = history_path_usage(path, h);
            // Keep the newest version at or before the floor plus everything after it; drop
            // the prefix nothing can observe.
            let cut = h.partition_point(|(v, _)| *v <= floor).saturating_sub(1);
            if cut > 0 {
                h.drain(..cut);
            }
            let emptied = match h.as_slice() {
                [] => true,
                [(v, None)] => *v <= floor,
                _ => false,
            };
            if emptied {
                self.history.remove(path);
                removed_paths.push(path.clone());
                usage_changes.push((before_usage, HistoryUsage::default()));
                return false;
            }
            let after_usage = self
                .history
                .get(path)
                .map_or_else(HistoryUsage::default, |history| {
                    history_path_usage(path, history)
                });
            usage_changes.push((before_usage, after_usage));
            self.history
                .get(path)
                .is_some_and(|h| h.len() > 1 || matches!(h.first(), Some((_, None))))
        });
        self.compactable = compactable;
        for (before, after) in usage_changes {
            self.history_usage =
                add_history_usage(subtract_history_usage(self.history_usage, before), after);
        }
        for path in removed_paths {
            self.remove_scope_path(&path);
        }
        floor
    }

    /// Time reported for a live read at `now`: never earlier than the last commit, so a
    /// document's `update_time` is always comparable with the `read_time` it was read at.
    #[must_use]
    pub fn read_time(&self, now: LogicalInstant) -> LogicalInstant {
        match self.last_commit_time {
            Some(last) if last.as_nanos() > now.as_nanos() => last,
            _ => now,
        }
    }

    /// Snapshot time of a transaction (the time its reads report).
    pub fn transaction_read_time(
        &self,
        id: &TransactionId,
    ) -> Result<LogicalInstant, FirestoreError> {
        Ok(self.transaction(id)?.read_time)
    }

    /// Snapshot version a transaction reads at.
    pub fn transaction_read_version(
        &self,
        id: &TransactionId,
    ) -> Result<CommitVersion, FirestoreError> {
        Ok(self.transaction(id)?.read_version)
    }

    fn transaction(&self, id: &TransactionId) -> Result<&Transaction, FirestoreError> {
        match self.transactions.get(id) {
            Some(t)
                if t.state == TransactionState::Active
                    && t.read_version >= self.compaction_floor =>
            {
                Ok(t)
            }
            // A finished transaction is reported the way the official emulator reports it:
            // `ABORTED`, which is the code the SDKs retry a transaction on.
            Some(_) => Err(FirestoreError::Aborted(TRANSACTION_NO_LONGER_VALID.into())),
            None => Err(FirestoreError::InvalidArgument(
                "Invalid transaction.".into(),
            )),
        }
    }

    /// Reads a document inside a transaction (snapshot at the transaction's read version) and
    /// records it in the read set.
    pub fn get_in_transaction(
        &mut self,
        id: &TransactionId,
        path: &DocumentPath,
    ) -> Result<Option<Document>, FirestoreError> {
        let read_version = self.transaction(id)?.read_version;
        let doc = self.get_at(path, read_version).cloned();
        self.record_transaction_read(id, path, doc.as_ref())?;
        Ok(doc)
    }

    fn allocate_query_execution_id(&mut self) -> QueryExecutionId {
        self.next_query_execution = self.next_query_execution.wrapping_add(1);
        QueryExecutionId::from_value(self.next_query_execution)
    }

    /// Runs a query inside a transaction, recording every returned document in the read set.
    pub fn run_query_in_transaction(
        &mut self,
        id: &TransactionId,
        query: &Query,
    ) -> Result<Vec<Document>, FirestoreError> {
        Ok(self.run_query_in_transaction_with_stats(id, query)?.0)
    }

    /// [`Self::run_query_in_transaction`] with the execution counters.
    pub fn run_query_in_transaction_with_stats(
        &mut self,
        id: &TransactionId,
        query: &Query,
    ) -> Result<(Vec<Document>, QueryStats), FirestoreError> {
        let execution_id = self.allocate_query_execution_id();
        self.run_query_in_transaction_with_stats_as_with_execution(
            id,
            query,
            query,
            execution_id,
            true,
        )
    }

    /// Runs a transaction query while recording the logical query shape supplied by the adapter.
    pub fn run_query_in_transaction_with_stats_as(
        &mut self,
        id: &TransactionId,
        query: &Query,
        observed_query: &Query,
    ) -> Result<(Vec<Document>, QueryStats), FirestoreError> {
        let execution_id = self.allocate_query_execution_id();
        self.run_query_in_transaction_with_stats_as_with_execution(
            id,
            query,
            observed_query,
            execution_id,
            true,
        )
    }

    /// Runs the first page of a transaction query for one logical execution. The adapter keeps
    /// the observation incomplete until every page of the stream has been sent to the client.
    pub fn run_query_in_transaction_with_stats_as_with_execution(
        &mut self,
        id: &TransactionId,
        query: &Query,
        observed_query: &Query,
        execution_id: QueryExecutionId,
        complete: bool,
    ) -> Result<(Vec<Document>, QueryStats), FirestoreError> {
        let read_version = self.transaction(id)?.read_version;
        let (docs, stats) = self.run_query_with_stats(query, Some(read_version))?;
        self.record_transaction_query_observation(
            id,
            execution_id,
            observed_query,
            &docs,
            false,
            complete,
        )?;
        Ok((docs, stats))
    }

    /// Runs a continuation page while appending its rows to the logical query observation.
    pub fn run_query_in_transaction_continuation_with_stats_as(
        &mut self,
        id: &TransactionId,
        query: &Query,
        observed_query: &Query,
    ) -> Result<(Vec<Document>, QueryStats), FirestoreError> {
        let execution_id = self.legacy_query_execution_id(id, observed_query)?;
        self.run_query_in_transaction_continuation_with_stats_as_with_execution(
            id,
            query,
            observed_query,
            execution_id,
            true,
        )
    }

    /// Runs a continuation page for the specified logical query execution.
    pub fn run_query_in_transaction_continuation_with_stats_as_with_execution(
        &mut self,
        id: &TransactionId,
        query: &Query,
        observed_query: &Query,
        execution_id: QueryExecutionId,
        complete: bool,
    ) -> Result<(Vec<Document>, QueryStats), FirestoreError> {
        let read_version = self.transaction(id)?.read_version;
        let (docs, stats) = self.run_query_with_stats(query, Some(read_version))?;
        self.record_transaction_query_observation(
            id,
            execution_id,
            observed_query,
            &docs,
            true,
            complete,
        )?;
        Ok((docs, stats))
    }

    /// Runs one page from an execution-scoped ordered path list inside a transaction. The list
    /// was built at this transaction's snapshot, so this path avoids rescanning and cloning the
    /// complete ordered result for every page while retaining the usual query observation.
    #[allow(clippy::too_many_arguments)]
    pub fn run_query_in_transaction_from_paths_with_stats_as_with_execution(
        &mut self,
        id: &TransactionId,
        query: &Query,
        observed_query: &Query,
        paths: &[DocumentPath],
        execution_id: QueryExecutionId,
        continuation: bool,
        complete: bool,
    ) -> Result<(Vec<Document>, QueryStats), FirestoreError> {
        let read_version = self.transaction(id)?.read_version;
        let (docs, stats) =
            self.documents_at_query_paths_with_stats(query, paths, Some(read_version));
        self.record_transaction_query_observation(
            id,
            execution_id,
            observed_query,
            &docs,
            continuation,
            complete,
        )?;
        Ok((docs, stats))
    }

    /// Runs a name-ascending query inside a transaction after an exclusive document path.
    /// The continuation uses the retained scope index while recording the same query
    /// observation and returned documents in the transaction read set.
    pub fn run_query_in_transaction_after_document_with_stats(
        &mut self,
        id: &TransactionId,
        query: &Query,
        after: &DocumentPath,
    ) -> Result<(Vec<Document>, QueryStats), FirestoreError> {
        let read_version = self.transaction(id)?.read_version;
        let (docs, stats) =
            self.run_query_after_document_with_stats(query, Some(read_version), after)?;
        let mut observed_query = query.clone();
        observed_query.start_at = Some(Cursor {
            values: vec![Value::Reference(after.resource_name())],
            before: false,
        });
        self.record_transaction_query(id, &observed_query, &docs)?;
        Ok((docs, stats))
    }

    /// Runs a name-ascending continuation while appending it to a logical query observation.
    pub fn run_query_in_transaction_after_document_with_stats_as(
        &mut self,
        id: &TransactionId,
        query: &Query,
        observed_query: &Query,
        after: &DocumentPath,
    ) -> Result<(Vec<Document>, QueryStats), FirestoreError> {
        let execution_id = self.legacy_query_execution_id(id, observed_query)?;
        self.run_query_in_transaction_after_document_with_stats_as_with_execution(
            id,
            query,
            observed_query,
            after,
            execution_id,
            true,
        )
    }

    /// Runs a name-ascending continuation for the specified logical query execution.
    pub fn run_query_in_transaction_after_document_with_stats_as_with_execution(
        &mut self,
        id: &TransactionId,
        query: &Query,
        observed_query: &Query,
        after: &DocumentPath,
        execution_id: QueryExecutionId,
        complete: bool,
    ) -> Result<(Vec<Document>, QueryStats), FirestoreError> {
        let read_version = self.transaction(id)?.read_version;
        let (docs, stats) =
            self.run_query_after_document_with_stats(query, Some(read_version), after)?;
        self.record_transaction_query_observation(
            id,
            execution_id,
            observed_query,
            &docs,
            true,
            complete,
        )?;
        Ok((docs, stats))
    }

    fn record_transaction_query(
        &mut self,
        id: &TransactionId,
        query: &Query,
        docs: &[Document],
    ) -> Result<(), FirestoreError> {
        let execution_id = self.allocate_query_execution_id();
        self.record_transaction_query_observation(id, execution_id, query, docs, false, true)
    }

    fn legacy_query_execution_id(
        &self,
        id: &TransactionId,
        query: &Query,
    ) -> Result<QueryExecutionId, FirestoreError> {
        let transaction = self.transaction(id)?;
        let mut matches = transaction
            .queries
            .iter()
            .filter(|entry| entry.query == *query)
            .map(|entry| entry.execution_id);
        let Some(execution_id) = matches.next() else {
            return Err(FirestoreError::InvalidArgument(
                "No matching transaction query execution.".into(),
            ));
        };
        if matches.next().is_some() {
            return Err(FirestoreError::InvalidArgument(
                "Transaction query continuation is ambiguous.".into(),
            ));
        }
        Ok(execution_id)
    }

    fn record_transaction_query_observation(
        &mut self,
        id: &TransactionId,
        execution_id: QueryExecutionId,
        query: &Query,
        docs: &[Document],
        append_observation: bool,
        complete: bool,
    ) -> Result<(), FirestoreError> {
        // Read-only snapshots never validate a commit or acquire document/range locks.
        // Retain bounded execution descriptors for continuation and completion validation,
        // but do not charge or retain result documents for conflict detection.
        let read_only = self.transaction(id)?.read_only;
        let rows = if read_only {
            Vec::new()
        } else {
            docs.iter()
                .map(|document| ObservedQueryDocument {
                    path: document.path.clone(),
                    version: document.version,
                    bytes: observed_document_bytes(&document.path, Some(document)),
                })
                .collect()
        };
        let observation = if read_only {
            QueryObservation::default()
        } else {
            query_observation(docs)
        };
        self.record_transaction_query_observation_parts(
            id,
            execution_id,
            query,
            observation,
            &rows,
            Vec::new(),
            Consumption::Ordered,
            append_observation,
            complete,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn record_transaction_query_observation_parts(
        &mut self,
        id: &TransactionId,
        execution_id: QueryExecutionId,
        query: &Query,
        observation: QueryObservation,
        rows: &[ObservedQueryDocument],
        required_fields: Vec<FieldPath>,
        consumption: Consumption,
        append_observation: bool,
        complete: bool,
    ) -> Result<(), FirestoreError> {
        let execution_index = self.transactions.get(id).and_then(|transaction| {
            transaction
                .queries
                .iter()
                .position(|entry| entry.execution_id == execution_id)
        });
        if append_observation && execution_index.is_none() {
            return Err(FirestoreError::InvalidArgument(
                "No matching transaction query execution.".into(),
            ));
        }
        if !append_observation && execution_index.is_some() {
            return Err(FirestoreError::InvalidArgument(
                "Transaction query execution already started.".into(),
            ));
        }
        let is_new_execution = execution_index.is_none();
        if is_new_execution
            && self.transactions.get(id).is_some_and(|transaction| {
                transaction.queries.len() >= MAX_TRANSACTION_QUERY_RECORDS
            })
        {
            self.finish_transaction(id, TransactionState::RetryableAborted);
            return Err(FirestoreError::Aborted(
                "transaction recorded too many distinct queries".into(),
            ));
        }
        let document_bytes = self.transactions.get(id).map_or(0, |transaction| {
            rows.iter()
                .filter(|row| !transaction.read_set.contains_key(&row.path))
                .map(|row| row.bytes)
                .fold(0u64, u64::saturating_add)
        });
        let query_bytes = if is_new_execution {
            query_retained_bytes(query)
        } else {
            0
        };
        let additional = document_bytes.saturating_add(query_bytes);
        let observation_overflow = self.transactions.get(id).is_some_and(|transaction| {
            transaction.conflict_ledger_bytes.saturating_add(additional)
                > MAX_TRANSACTION_CONFLICT_LEDGER_BYTES
                || self
                    .active_transaction_conflict_ledger_bytes
                    .saturating_add(additional)
                    > MAX_ACTIVE_TRANSACTION_CONFLICT_LEDGER_BYTES
        });
        if observation_overflow {
            self.finish_transaction(id, TransactionState::RetryableAborted);
            return Err(FirestoreError::Aborted(
                "transaction observed data exceeds the retained conflict-detection budget".into(),
            ));
        }
        if let Some(t) = self.transactions.get_mut(id) {
            for row in rows {
                t.read_set.insert(row.path.clone(), Some(row.version));
            }
            t.conflict_ledger_bytes = t.conflict_ledger_bytes.saturating_add(additional);
            self.active_transaction_conflict_ledger_bytes = self
                .active_transaction_conflict_ledger_bytes
                .saturating_add(additional);
            if let Some(index) = execution_index {
                for row in rows {
                    t.queries[index]
                        .observation
                        .push_parts(&row.path, row.version);
                }
                if complete {
                    t.queries[index].complete = true;
                }
            } else if is_new_execution {
                t.queries.push(TransactionQueryObservation {
                    execution_id,
                    query: query.clone(),
                    required_fields,
                    observation,
                    consumption,
                    complete,
                });
            }
        }
        Ok(())
    }

    /// Marks all pages of one transaction query execution as delivered.
    pub fn finish_transaction_query_execution(
        &mut self,
        id: &TransactionId,
        execution_id: QueryExecutionId,
    ) -> Result<(), FirestoreError> {
        let transaction = self.transaction(id)?;
        let Some(index) = transaction
            .queries
            .iter()
            .position(|entry| entry.execution_id == execution_id)
        else {
            return Err(FirestoreError::InvalidArgument(
                "No matching transaction query execution.".into(),
            ));
        };
        if let Some(transaction) = self.transactions.get_mut(id) {
            transaction.queries[index].complete = true;
        }
        Ok(())
    }

    /// Number of query executions retained by an active transaction.
    pub fn transaction_recorded_query_count(
        &self,
        id: &TransactionId,
    ) -> Result<usize, FirestoreError> {
        Ok(self.transaction(id)?.queries.len())
    }

    /// Rolls back (finishes) a transaction.
    pub fn rollback(&mut self, id: &TransactionId) -> Result<(), FirestoreError> {
        self.transaction(id)?;
        self.finish_transaction(id, TransactionState::RolledBack);
        Ok(())
    }

    /// Applies `writes` atomically. Nothing is modified when an error is returned. Commit
    /// times are strictly monotonic per database even when the clock did not advance, so
    /// `update_time` preconditions cannot be satisfied by a stale timestamp.
    ///
    /// Transaction concurrency is pessimistic, as in production: what an active read-write
    /// transaction read is locked (see `check_contention`), and a transaction whose read set
    /// nevertheless changed is aborted before any staged write is published. SDKs retry that
    /// attempt against a new snapshot.
    pub fn commit(
        &mut self,
        writes: &[Write],
        transaction: Option<&TransactionId>,
        now: LogicalInstant,
    ) -> Result<CommitResult, FirestoreError> {
        self.commit_with_admission(writes, transaction, now, |_| Ok(()))
            .map(|(result, ())| result)
    }

    /// Applies `writes` only after `admit` reserves every coupled logical event.
    ///
    /// The callback sees the exact result while all source changes are still private. Once it
    /// returns a reservation, publishing the staged source change has no recoverable failure
    /// branch; the caller can therefore publish that reservation before releasing its database
    /// lock.
    #[allow(clippy::too_many_lines)]
    pub fn commit_with_admission<R>(
        &mut self,
        writes: &[Write],
        transaction: Option<&TransactionId>,
        now: LogicalInstant,
        admit: impl FnOnce(&CommitResult) -> Result<R, FirestoreError>,
    ) -> Result<(CommitResult, R), FirestoreError> {
        self.commit_with_history_admission(writes, transaction, now, |result, _| admit(result))
    }

    /// Applies a commit after both database and aggregate history admission.
    ///
    /// The reservation ceiling is computed after legal maintenance and before publication.
    /// Capacity and coupled-event refusal leave every visible version, transaction and
    /// commit-time root unchanged; maintenance may only discard already unreachable history.
    #[allow(clippy::too_many_lines)]
    pub fn commit_with_history_admission<R>(
        &mut self,
        writes: &[Write],
        transaction: Option<&TransactionId>,
        now: LogicalInstant,
        admit: impl FnOnce(&CommitResult, HistoryProjection) -> Result<R, FirestoreError>,
    ) -> Result<(CommitResult, R), FirestoreError> {
        if let Some(id) = transaction {
            self.validate_transaction_commit(id, writes, now)?;
        }
        self.check_contention(writes, transaction, now)?;
        Self::check_transform_budget(writes)?;

        // Commit times are microsecond-aligned (Firestore update-time precision) and advance
        // by one microsecond when the clock did not move between commits.
        let commit_time = self.next_commit_time(now);

        // Stage every write against a working copy; fail before touching state. A write
        // whose result equals the current document is a no-op: it keeps the existing version
        // and update time (Firestore semantics) and never creates a spurious conflict.
        let mut staged: BTreeMap<DocumentPath, StagedDocument> = BTreeMap::new();
        let mut results = Vec::with_capacity(writes.len());
        let next_version = CommitVersion(self.version.0 + 1);
        for write in writes {
            let path = write.op.path().clone();
            if !staged.contains_key(&path) {
                let before = self
                    .history
                    .get(&path)
                    .and_then(|versions| versions.last())
                    .and_then(|(_, document)| document.clone());
                staged.insert(
                    path.clone(),
                    StagedDocument {
                        current: before.clone(),
                        before,
                        changed: false,
                    },
                );
            }
            let stage = staged.get_mut(&path).unwrap_or_else(|| unreachable!());
            let current = stage.current.as_deref();
            check_precondition(write.precondition.as_ref(), current, &path)?;
            let (next, mut result) = apply_write(write, current, commit_time, next_version)?;
            if let Some(Cow::Owned(doc)) = &next {
                validate_document(doc)?;
                self.index_catalog
                    .document_index_usage(&doc.path, &doc.fields)?;
            }
            if matches!(write.op, WriteOp::Verify { .. }) {
                // A verify changes nothing and reports the document's current update time,
                // the time of the state it verified.
                result.update_time = current.map(|c| c.update_time);
            }
            // A verify never changes state, whatever the document holds; every other write
            // is a no-op when its result is the stored content of the current document
            // (NaN equals NaN here, but an integer never equals a double).
            let unchanged = matches!(write.op, WriteOp::Verify { .. })
                || match (current, &next) {
                    (Some(c), Some(n)) => stored_fields_eq(&c.fields, &n.fields),
                    (None, None) => true,
                    _ => false,
                };
            if unchanged {
                // A no-op Set keeps the existing update time.
                if let (Some(c), false) = (current, matches!(write.op, WriteOp::Verify { .. })) {
                    result.update_time = Some(c.update_time);
                }
            } else {
                stage.current = next.map(|doc| Arc::new(doc.into_owned()));
                stage.changed = true;
            }
            results.push(result);
        }

        // Build the exact externally visible result before publishing either side.
        let staged_changes: Vec<StagedChange> = staged
            .into_iter()
            .filter(|(_, staged)| staged.changed)
            .map(|(path, staged)| (path, staged.before, staged.current))
            .collect();
        let changed = !staged_changes.is_empty();
        let version = if changed { next_version } else { self.version };
        let published_changes: Arc<[DocumentChange]> = staged_changes
            .iter()
            .map(|(path, before, after)| DocumentChange {
                path: path.clone(),
                before: before.clone(),
                after: after.clone(),
            })
            .collect();
        let result = CommitResult {
            commit_time,
            write_results: results,
            version,
            changes: published_changes,
        };
        let before = self.history_usage();
        let (uncompacted, after) = self.projected_history_usage(&staged_changes, now);
        self.check_history_limits(after)?;
        let reservation = admit(&result, HistoryProjection { before, after })?;

        // Publish. All fallible validation and external admission completed above. Every
        // accepted commit consumes a commit time, changed documents or not.
        self.last_commit_time = Some(commit_time);
        self.compaction_forecast = None;
        self.history_usage = uncompacted;
        if changed {
            self.version = next_version;
            self.commit_times.push_back((next_version, commit_time));
            for (path, before, doc) in staged_changes {
                let became_live = before.is_none() && doc.is_some();
                let became_missing = before.is_some() && doc.is_none();
                // A second version, or a tombstone, is something a later compaction can drop.
                let compactable = self.history.contains_key(&path) || doc.is_none();
                if !self.history.contains_key(&path) {
                    self.insert_scope_path(&path);
                }
                if became_live {
                    self.insert_live_scope_path(&path);
                } else if became_missing {
                    self.remove_live_scope_path(&path);
                }
                self.history
                    .entry(path.clone())
                    .or_default()
                    .push((next_version, doc));
                self.record_capacity_pressure(&path);
                if compactable {
                    self.compactable.insert(path);
                }
            }
        }
        if let Some(id) = transaction {
            self.finish_transaction(id, TransactionState::Finished);
        }
        // Retention is owned by the store: every commit drops the history that has fallen
        // out of the read window and is not pinned by an active transaction.
        self.compact(now);
        debug_assert!(self.history_usage.total_bytes <= after.total_bytes);
        debug_assert!(self.history_usage.versions <= after.versions);
        Ok((result, reservation))
    }

    /// Production refuses more than the catalogued number of field transforms on one document
    /// in a commit with `INVALID_ARGUMENT`, in every profile: the official emulator's leniency
    /// here accepts a write production would reject.
    fn check_transform_budget(writes: &[Write]) -> Result<(), FirestoreError> {
        let mut transforms_per_document: BTreeMap<&DocumentPath, u64> = BTreeMap::new();
        for write in writes {
            let count = transforms_per_document.entry(write.op.path()).or_default();
            *count += write.transforms.len() as u64;
            check_limit(limits::FIELD_TRANSFORMS_PER_DOCUMENT, *count)?;
        }
        Ok(())
    }

    fn record_capacity_pressure(&mut self, path: &DocumentPath) {
        let Some(versions) = self.history.get(path) else {
            return;
        };
        if versions.len() <= self.max_versions_per_path {
            return;
        }
        let oldest_kept = versions[versions.len() - self.max_versions_per_path].0;
        self.capacity_floor = self.capacity_floor.max(oldest_kept);
    }

    fn validate_transaction_commit(
        &mut self,
        id: &TransactionId,
        writes: &[Write],
        now: LogicalInstant,
    ) -> Result<(), FirestoreError> {
        let transaction = self.transaction(id)?;
        if now >= transaction_deadline(transaction) {
            self.finish_transaction(id, TransactionState::Finished);
            self.compact(now);
            return Err(FirestoreError::Aborted(TRANSACTION_NO_LONGER_VALID.into()));
        }
        let transaction = self.transaction(id)?;
        if transaction.read_only && !writes.is_empty() {
            return Err(FirestoreError::InvalidArgument(
                "Cannot modify entities in a read-only transaction.".into(),
            ));
        }
        if transaction.read_only {
            // Production refuses committing a read-only transaction at all, even with no
            // writes, and calls the transaction no longer valid.
            return Err(FirestoreError::InvalidArgument(
                TRANSACTION_NO_LONGER_VALID.into(),
            ));
        }
        if self.transaction_conflicted(id)? {
            self.finish_transaction(id, TransactionState::RetryableAborted);
            return Err(FirestoreError::Aborted(
                TRANSACTION_CONCURRENT_MODIFICATION.into(),
            ));
        }
        Ok(())
    }

    /// Pessimistic locking, as production runs it (`concurrencyMode: PESSIMISTIC`, measured
    /// in conformance/firestore-production-matrix.json, transactions/lifecycle): every
    /// document an active read-write transaction read, and every query range it executed,
    /// is locked until that transaction finishes.
    ///
    /// A commit that touches a locked document is refused with `ABORTED` and production's
    /// wording, and the adapter waits for a release before trying again or giving that answer.
    /// A commit outside a transaction, or by a transaction none of the lock holders is
    /// waiting on, leaves everything as it was. A transaction that runs into the locks of a
    /// holder which is itself waiting to commit is the deadlock production resolves by
    /// aborting one side: it is aborted (retryable) so the waiting holder can proceed.
    fn check_contention(
        &mut self,
        writes: &[Write],
        own: Option<&TransactionId>,
        now: LogicalInstant,
    ) -> Result<(), FirestoreError> {
        if writes.is_empty() {
            return Ok(());
        }
        self.prune_transactions(now);
        if let Some(transaction) = own.and_then(|id| self.transactions.get_mut(id)) {
            transaction.waiting_to_commit = false;
        }
        let floor = self.compaction_floor;
        let holders: Vec<bool> = self
            .transactions
            .iter()
            .filter(|(id, holder)| {
                holder.state == TransactionState::Active
                    && !holder.read_only
                    && holder.read_version >= floor
                    && own != Some(*id)
                    && writes.iter().any(|write| {
                        let path = write.op.path();
                        holder.read_set.contains_key(path)
                            || holder
                                .queries
                                .iter()
                                .any(|entry| path_in_scope(path, &entry.query.scope))
                    })
            })
            .map(|(_, holder)| holder.waiting_to_commit)
            .collect();
        if holders.is_empty() {
            return Ok(());
        }
        if let Some(id) = own {
            if holders.iter().any(|waiting| *waiting) {
                self.finish_transaction(id, TransactionState::RetryableAborted);
            } else if let Some(transaction) = self.transactions.get_mut(id) {
                transaction.waiting_to_commit = true;
            }
        }
        Err(FirestoreError::Aborted(TOO_MUCH_CONTENTION.into()))
    }

    /// The active read-write transactions whose locks `writes` would collide with, other than
    /// `own`: what a refused writer is waiting on.
    #[must_use]
    pub fn lock_holders(
        &self,
        writes: &[Write],
        own: Option<&TransactionId>,
    ) -> Vec<TransactionId> {
        self.transactions
            .iter()
            .filter(|(id, holder)| {
                holder.state == TransactionState::Active
                    && !holder.read_only
                    && holder.read_version >= self.compaction_floor
                    && own != Some(*id)
                    && writes.iter().any(|write| {
                        let path = write.op.path();
                        holder.read_set.contains_key(path)
                            || holder
                                .queries
                                .iter()
                                .any(|entry| path_in_scope(path, &entry.query.scope))
                    })
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Whether `id` names a transaction that is still active (a commit refused for lock
    /// contention may be tried again once the holder finishes).
    #[must_use]
    pub fn transaction_is_active(&self, id: &TransactionId) -> bool {
        self.transactions
            .get(id)
            .is_some_and(|t| t.state == TransactionState::Active)
    }

    /// How many transactions have finished so far; a change means locks were released.
    #[must_use]
    pub const fn transaction_releases(&self) -> u64 {
        self.transaction_releases
    }

    fn transaction_conflicted(&self, id: &TransactionId) -> Result<bool, FirestoreError> {
        let transaction = self.transaction(id)?;
        for (path, observed) in &transaction.read_set {
            if self.get(path).map(|document| document.version) != *observed {
                return Ok(true);
            }
        }
        for entry in transaction.queries.iter().filter(|entry| entry.complete) {
            let mut current = QueryObservation::default();
            let required_fields: Vec<&FieldPath> = entry.required_fields.iter().collect();
            self.select(
                &entry.query,
                None,
                &required_fields,
                entry.consumption,
                |document| {
                    current.push(document);
                },
            )?;
            if current != entry.observation {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The commit time a commit at `now` would receive: microsecond-aligned and strictly
    /// after the last commit. Rules previews use it so that server timestamps match.
    #[must_use]
    pub fn next_commit_time(&self, now: LogicalInstant) -> LogicalInstant {
        let aligned_now =
            LogicalInstant::from_nanos(now.as_nanos() - now.as_nanos().rem_euclid(1_000));
        match self.last_commit_time {
            Some(last) if last.as_nanos() >= aligned_now.as_nanos() => {
                LogicalInstant::from_nanos(last.as_nanos() + 1_000)
            }
            _ => aligned_now,
        }
    }

    /// Result of applying `write` to `current` (the `request.resource` seen by Security
    /// Rules when several writes of one commit target the same document). Preconditions are
    /// not checked here.
    pub fn preview_from(
        current: Option<&Document>,
        write: &Write,
        now: LogicalInstant,
    ) -> Result<Option<Document>, FirestoreError> {
        let (next, _) = apply_write(write, current, now, CommitVersion::default())?;
        Ok(next.map(Cow::into_owned))
    }

    /// Result of applying `write` to the current document without publishing anything (the
    /// `request.resource` seen by Security Rules). Preconditions are not checked here.
    pub fn preview_write(
        &self,
        write: &Write,
        now: LogicalInstant,
    ) -> Result<Option<Document>, FirestoreError> {
        let current = self.get(write.op.path()).cloned();
        let (next, _) = apply_write(
            write,
            current.as_ref(),
            now,
            CommitVersion(self.version.0 + 1),
        )?;
        Ok(next.map(Cow::into_owned))
    }

    /// Documents directly under `parent` (root when `None`) in `collection_id`, by name.
    #[must_use]
    pub fn list_documents(
        &self,
        parent: Option<&DocumentPath>,
        collection_id: &str,
    ) -> Vec<Document> {
        self.list_documents_at(parent, collection_id, None)
    }

    /// Documents directly under `parent` in `collection_id` as of `version` (latest when
    /// `None`).
    #[must_use]
    pub fn list_documents_at(
        &self,
        parent: Option<&DocumentPath>,
        collection_id: &str,
        version: Option<CommitVersion>,
    ) -> Vec<Document> {
        let Ok(collection_id) = CollectionId::try_new(collection_id) else {
            return Vec::new();
        };
        let paths = if version.is_some() {
            &self.direct_collection_paths
        } else {
            &self.live_direct_collection_paths
        };
        paths
            .get(&(parent.cloned(), collection_id))
            .into_iter()
            .flat_map(|paths| paths.iter())
            .filter_map(|path| match version {
                Some(version) => self.get_at(path, version),
                None => self.get(path),
            })
            .cloned()
            .collect()
    }

    /// A name-ordered page directly under `parent`, after an optional exclusive cursor.
    ///
    /// At most `limit` documents are cloned; retained tombstones and paths outside the exact
    /// collection scope are never visited.
    #[must_use]
    pub fn list_documents_page_at(
        &self,
        parent: Option<&DocumentPath>,
        collection_id: &str,
        version: Option<CommitVersion>,
        after: Option<&DocumentPath>,
        limit: usize,
    ) -> Vec<Document> {
        self.list_documents_page_at_with_stats(parent, collection_id, version, after, limit)
            .0
    }

    /// [`Self::list_documents_page_at`] with deterministic scan and clone counters.
    #[must_use]
    pub fn list_documents_page_at_with_stats(
        &self,
        parent: Option<&DocumentPath>,
        collection_id: &str,
        version: Option<CommitVersion>,
        after: Option<&DocumentPath>,
        limit: usize,
    ) -> (Vec<Document>, QueryStats) {
        use std::ops::Bound::{Excluded, Unbounded};

        if limit == 0 {
            return (Vec::new(), QueryStats::default());
        }
        let Ok(collection_id) = CollectionId::try_new(collection_id) else {
            return (Vec::new(), QueryStats::default());
        };
        let paths_by_scope = if version.is_some() {
            &self.direct_collection_paths
        } else {
            &self.live_direct_collection_paths
        };
        let Some(paths) = paths_by_scope.get(&(parent.cloned(), collection_id)) else {
            return (Vec::new(), QueryStats::default());
        };
        let path_count = paths.len();
        let paths: Box<dyn Iterator<Item = &Arc<DocumentPath>>> = match after {
            Some(after) => Box::new(paths.range::<DocumentPath, _>((Excluded(after), Unbounded))),
            None => Box::new(paths.iter()),
        };
        let mut documents = Vec::with_capacity(limit.min(path_count));
        let mut stats = QueryStats::default();
        for path in paths {
            stats.scanned += 1;
            let document = match version {
                Some(version) => self.get_at(path, version),
                None => self.get(path),
            };
            let Some(document) = document else {
                continue;
            };
            stats.matched += 1;
            documents.push(document.clone());
            stats.cloned_documents += 1;
            stats.peak_candidates = stats.peak_candidates.max(documents.len() as u64);
            if documents.len() == limit {
                break;
            }
        }
        (documents, stats)
    }

    fn listing_node_visible_at(
        &self,
        node: &ListingTrieDocument,
        version: CommitVersion,
        checks: &mut u64,
    ) -> bool {
        if let Some(path) = &node.retained_here {
            *checks += 1;
            if self.get_at(path, version).is_some() {
                return true;
            }
        }
        node.children.collections.values().any(|collection| {
            collection
                .documents
                .values()
                .any(|child| self.listing_node_visible_at(child, version, checks))
        })
    }

    fn listing_candidate_path(node: &ListingTrieDocument, depth: usize) -> Option<DocumentPath> {
        node.representative
            .as_ref()
            .and_then(|path| path.ancestor(depth))
    }

    fn listing_missing_candidate(
        &self,
        node: &ListingTrieDocument,
        depth: usize,
        version: Option<CommitVersion>,
    ) -> Option<DocumentPath> {
        let mut checks = 0;
        let visible = match version {
            Some(version) => self.listing_node_visible_at(node, version, &mut checks),
            None => node.live_subtree_paths > 0,
        };
        if !visible {
            return None;
        }
        let candidate = Self::listing_candidate_path(node, depth)?;
        let present = match version {
            Some(version) => self.get_at(&candidate, version).is_some(),
            None => self.get(&candidate).is_some(),
        };
        (!present).then_some(candidate)
    }

    /// Paths directly under `parent` in `collection_id` that hold no document but have
    /// descendants (`ListDocuments` with `show_missing`), by name, as of `version`.
    #[must_use]
    pub fn list_missing_parents_at(
        &self,
        parent: Option<&DocumentPath>,
        collection_id: &str,
        version: Option<CommitVersion>,
    ) -> Vec<DocumentPath> {
        self.list_missing_parents_page_at(parent, collection_id, version, None, usize::MAX)
            .1
    }

    /// A bounded missing-parent suffix. The boolean reports whether `after` is still a
    /// missing result at this snapshot; callers restart the ordered listing when it is not.
    #[must_use]
    pub fn list_missing_parents_page_at(
        &self,
        parent: Option<&DocumentPath>,
        collection_id: &str,
        version: Option<CommitVersion>,
        after: Option<&DocumentPath>,
        limit: usize,
    ) -> (bool, Vec<DocumentPath>) {
        use std::ops::Bound::{Excluded, Unbounded};

        if limit == 0 {
            return (false, Vec::new());
        }
        let Ok(collection_id) = CollectionId::try_new(collection_id) else {
            return (false, Vec::new());
        };
        let Some(candidates) = self.listing_trie.collection(parent, &collection_id) else {
            return (false, Vec::new());
        };
        let depth = parent.map_or(1, |path| path.pairs().len() + 1);
        let cursor_is_missing = after.is_some_and(|after| {
            candidates
                .documents
                .get(after.document_id())
                .and_then(|node| self.listing_missing_candidate(node, depth, version))
                .is_some()
        });
        let nodes: ListingTrieNodeIter<'_> = match (version, after) {
            (Some(_), Some(after)) => Box::new(
                candidates
                    .documents
                    .range::<DocumentId, _>((Excluded(after.document_id()), Unbounded))
                    .map(|(_, node)| node),
            ),
            (Some(_), None) => Box::new(candidates.documents.values()),
            (None, Some(after)) => Box::new(
                candidates
                    .live_candidates
                    .range::<DocumentId, _>((Excluded(after.document_id()), Unbounded))
                    .filter_map(|document| candidates.documents.get(document)),
            ),
            (None, None) => Box::new(
                candidates
                    .live_candidates
                    .iter()
                    .filter_map(|document| candidates.documents.get(document)),
            ),
        };
        let page = nodes
            .filter_map(|node| self.listing_missing_candidate(node, depth, version))
            .take(limit)
            .collect();
        (cursor_is_missing, page)
    }

    /// A bounded name-ordered page that includes missing parents with descendants.
    ///
    /// Descendants in other collection scopes are never visited. Only present documents in
    /// the returned page are cloned; missing entries clone their path alone.
    #[must_use]
    pub fn list_documents_with_missing_page_at(
        &self,
        parent: Option<&DocumentPath>,
        collection_id: &str,
        version: Option<CommitVersion>,
        after: Option<&DocumentPath>,
        limit: usize,
    ) -> (Vec<ListedDocument>, QueryStats) {
        use std::ops::Bound::{Excluded, Unbounded};

        if limit == 0 {
            return (Vec::new(), QueryStats::default());
        }
        let Ok(collection_id) = CollectionId::try_new(collection_id) else {
            return (Vec::new(), QueryStats::default());
        };
        let Some(candidates) = self.listing_trie.collection(parent, &collection_id) else {
            return (Vec::new(), QueryStats::default());
        };
        let candidate_count = if version.is_some() {
            candidates.documents.len()
        } else {
            candidates.live_candidates.len()
        };
        let depth = parent.map_or(1, |path| path.pairs().len() + 1);
        let mut stats = QueryStats::default();
        let candidates: ListingTrieIter<'_> = match (version, after) {
            (Some(_), Some(after)) => Box::new(
                candidates
                    .documents
                    .range::<DocumentId, _>((Excluded(after.document_id()), Unbounded)),
            ),
            (Some(_), None) => Box::new(candidates.documents.iter()),
            (None, Some(after)) => Box::new(
                candidates
                    .live_candidates
                    .range::<DocumentId, _>((Excluded(after.document_id()), Unbounded))
                    .filter_map(|document| candidates.documents.get_key_value(document)),
            ),
            (None, None) => Box::new(
                candidates
                    .live_candidates
                    .iter()
                    .filter_map(|document| candidates.documents.get_key_value(document)),
            ),
        };
        let mut entries = Vec::with_capacity(limit.min(candidate_count));
        for (_, node) in candidates {
            stats.scanned += 1;
            let visible = match version {
                Some(version) => {
                    self.listing_node_visible_at(node, version, &mut stats.visibility_checks)
                }
                // The latest iterator is sourced from `live_candidates`, so every yielded
                // node has at least one live document in its subtree.
                None => true,
            };
            if !visible {
                continue;
            }
            let Some(candidate) = Self::listing_candidate_path(node, depth) else {
                continue;
            };
            let document = match version {
                Some(version) => self.get_at(&candidate, version),
                None => self.get(&candidate),
            };
            let entry = if let Some(document) = document {
                stats.cloned_documents += 1;
                ListedDocument::Present(document.clone())
            } else {
                ListedDocument::Missing(candidate)
            };
            entries.push(entry);
            stats.matched += 1;
            stats.peak_candidates = stats.peak_candidates.max(entries.len() as u64);
            if entries.len() == limit {
                break;
            }
        }
        (entries, stats)
    }

    /// Name-ordered cut paths for a collection-group partition query.
    ///
    /// The retained collection-group index narrows the scan before visible rows are counted.
    /// Only the selected cut paths are cloned.
    #[must_use]
    pub fn collection_group_partition_paths_at(
        &self,
        parent: Option<&DocumentPath>,
        collection_id: &str,
        version: CommitVersion,
        partition_count: usize,
    ) -> Vec<DocumentPath> {
        let Ok(collection_id) = CollectionId::try_new(collection_id) else {
            return Vec::new();
        };
        let group_paths = if version == self.version {
            &self.live_collection_group_paths
        } else {
            &self.collection_group_paths
        };
        let Some(paths) = group_paths.get(&collection_id) else {
            return Vec::new();
        };
        let scope = QueryScope::collection_group_under(parent.cloned(), collection_id);
        let visible = || {
            paths.iter().map(AsRef::as_ref).filter(|path| {
                self.get_at(path, version)
                    .is_some_and(|document| document_in_scope(document, &scope))
            })
        };
        let count = visible().count();
        let cuts = partition_count.min(count.saturating_sub(1));
        if cuts == 0 {
            return Vec::new();
        }
        // Two passes retain only the requested cut paths, not every matching document.
        // u128 avoids an overflow for a large collection/count product.
        let mut next = 1usize;
        visible()
            .enumerate()
            .filter_map(|(rank, path)| {
                let target = (count as u128 * next as u128 / (cuts as u128 + 1)) as usize;
                if next <= cuts && rank == target {
                    next += 1;
                    Some(path.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Collection IDs directly under `parent` (root when `None`), sorted.
    #[must_use]
    pub fn list_collection_ids(&self, parent: Option<&DocumentPath>) -> Vec<String> {
        self.listing_trie
            .collections_under(parent)
            .into_iter()
            .flat_map(|collections| collections.iter())
            .filter(|(_, collection)| !collection.live_candidates.is_empty())
            .map(|(collection_id, _)| collection_id.as_str().to_owned())
            .collect()
    }

    /// Executes a canonical query at `version` (latest when `None`).
    pub fn run_query(
        &self,
        query: &Query,
        version: Option<CommitVersion>,
    ) -> Result<Vec<Document>, FirestoreError> {
        Ok(self.run_query_with_stats(query, version)?.0)
    }

    /// Builds an exclusive query cursor from the named document when that document is still
    /// part of the query result at `version`. A missing or no-longer-matching document returns
    /// `None`, which lets `ListDocuments` preserve its restart-from-the-beginning contract.
    pub fn cursor_after_document(
        &self,
        query: &Query,
        version: Option<CommitVersion>,
        path: &DocumentPath,
    ) -> Result<Option<Cursor>, FirestoreError> {
        let document = match version {
            Some(version) => self.get_at(path, version),
            None => self.get(path),
        };
        let Some(document) = document else {
            return Ok(None);
        };
        if !document_in_scope(document, &query.scope) {
            return Ok(None);
        }
        if let Some(filter) = &query.filter {
            if !eval_filter(filter, document)? {
                return Ok(None);
            }
        }
        let order = query.effective_order_by();
        let Some(key) = order_key(document, &order) else {
            return Ok(None);
        };
        if !cursor_admits(&key, query.start_at.as_ref(), query.end_at.as_ref(), &order) {
            return Ok(None);
        }
        Ok(Some(Cursor {
            values: key.into_iter().map(FieldRef::into_value).collect(),
            before: false,
        }))
    }

    /// [`Self::run_query`] with the execution counters (`FS-QUERY-PERF-*`).
    ///
    /// Scope, filters, ordering and cursors are evaluated on values borrowed from the stored
    /// documents, so a row that is scanned and rejected copies nothing. When the query has a
    /// finite limit, only `offset + limit` candidates are ever held at once (a bounded heap
    /// keyed by the query order), whatever the size of the matched set; documents are cloned
    /// once the selection is final.
    pub fn run_query_with_stats(
        &self,
        query: &Query,
        version: Option<CommitVersion>,
    ) -> Result<(Vec<Document>, QueryStats), FirestoreError> {
        let mut out: Vec<Document> = Vec::new();
        let mut stats = self.select(query, version, &[], Consumption::Ordered, |doc| {
            out.push(project_document(doc, query.projection.as_deref()));
        })?;
        stats.cloned_documents = out.len() as u64;
        stats.cloned_field_bytes = out
            .iter()
            .map(|document| fields_retained_bytes(&document.fields))
            .fold(0u64, u64::saturating_add);
        Ok((out, stats))
    }

    /// Executes a query without cloning its documents and returns the ordered document paths.
    ///
    /// The caller may retain these paths as an execution-scoped continuation cursor. The
    /// selection still applies filters, cursors, offsets and limits, but only the path of each
    /// selected document is copied, so a later page does not rescan or retain full documents.
    pub fn run_query_paths_with_stats(
        &self,
        query: &Query,
        version: Option<CommitVersion>,
    ) -> Result<(Vec<DocumentPath>, QueryStats), FirestoreError> {
        let mut paths = Vec::new();
        let stats = self.select(query, version, &[], Consumption::Ordered, |document| {
            paths.push(document.path.clone());
        })?;
        Ok((paths, stats))
    }

    /// [`Self::documents_at_query_paths`] with the page-stage statistics: `matched` is the
    /// materialized page size, `cloned_documents` and `cloned_field_bytes` cover the page's output, and
    /// the scan counters stay zero because no candidate is visited again.
    pub fn documents_at_query_paths_with_stats(
        &self,
        query: &Query,
        paths: &[DocumentPath],
        version: Option<CommitVersion>,
    ) -> (Vec<Document>, QueryStats) {
        let docs = self.documents_at_query_paths(query, paths, version);
        let stats = QueryStats {
            matched: u64::try_from(docs.len()).unwrap_or(u64::MAX),
            cloned_documents: u64::try_from(docs.len()).unwrap_or(u64::MAX),
            cloned_field_bytes: docs
                .iter()
                .map(|document| fields_retained_bytes(&document.fields))
                .fold(0u64, u64::saturating_add),
            ..QueryStats::default()
        };
        (docs, stats)
    }

    /// Materializes only the selected paths for a page, applying the query projection without
    /// evaluating the full candidate set again. Paths must have been produced from the same
    /// snapshot and query predicate.
    pub fn documents_at_query_paths(
        &self,
        query: &Query,
        paths: &[DocumentPath],
        version: Option<CommitVersion>,
    ) -> Vec<Document> {
        let offset = usize::try_from(query.offset).unwrap_or(usize::MAX);
        let limit = query
            .limit
            .and_then(|limit| usize::try_from(limit).ok())
            .unwrap_or(usize::MAX);
        paths
            .iter()
            .skip(offset)
            .take(limit)
            .filter_map(|path| match version {
                Some(version) => self.get_at(path, version),
                None => self.get(path),
            })
            .map(|document| project_document(document, query.projection.as_deref()))
            .collect()
    }

    /// Executes a name-ordered query strictly after `after` using the ordered scope index.
    /// Both ascending and descending resource-name continuations seek from the scope boundary.
    pub fn run_query_after_document_with_stats(
        &self,
        query: &Query,
        version: Option<CommitVersion>,
        after: &DocumentPath,
    ) -> Result<(Vec<Document>, QueryStats), FirestoreError> {
        let order = query.effective_order_by();
        if order.len() != 1
            || !order[0].field.is_document_name()
            || !matches!(
                order[0].direction,
                Direction::Ascending | Direction::Descending
            )
        {
            return Err(FirestoreError::InvalidArgument(
                "document continuation requires a single __name__ order".into(),
            ));
        }
        let descending = order[0].direction == Direction::Descending;
        let paths = if descending {
            self.scope_paths_before(&query.scope, version, after)
        } else {
            self.scope_paths_after(&query.scope, version, after)
        };
        let visited = core::cell::Cell::new(0u64);
        let mut out = Vec::new();
        let mut stats = select_from(
            query,
            paths
                .inspect(|_| visited.set(visited.get() + 1))
                .filter_map(|path| match version {
                    Some(version) => self.get_at(path, version),
                    None => self.get(path),
                }),
            Some(order[0].direction),
            &[],
            Consumption::Ordered,
            |doc| out.push(project_document(doc, query.projection.as_deref())),
        )?;
        stats.index_paths_visited = visited.get();
        stats.cloned_documents = out.len() as u64;
        stats.cloned_field_bytes = out
            .iter()
            .map(|document| fields_retained_bytes(&document.fields))
            .fold(0u64, u64::saturating_add);
        Ok((out, stats))
    }

    /// Applies a query to only the supplied current documents when membership is local to
    /// each row. Limits, offsets, and cursors depend on rows outside the changed subset and
    /// therefore return `None` so callers can fall back to a full query.
    pub fn run_incremental_query<'a, I>(
        &self,
        query: &Query,
        changed_documents: I,
    ) -> Result<Option<Vec<Document>>, FirestoreError>
    where
        I: IntoIterator<Item = &'a Document>,
    {
        if query.limit.is_some()
            || query.offset != 0
            || query.start_at.is_some()
            || query.end_at.is_some()
        {
            return Ok(None);
        }
        let mut documents = Vec::new();
        select_from(
            query,
            changed_documents,
            None,
            &[],
            Consumption::Ordered,
            |document| documents.push(project_document(document, query.projection.as_deref())),
        )?;
        Ok(Some(documents))
    }

    /// Feeds every document the query selects to `sink`, borrowed from the store, in query
    /// order when `consumption` asks for it.
    ///
    /// This is the one selection routine: [`Self::run_query_with_stats`] clones what it
    /// receives, [`Self::run_aggregation_with_stats`] folds it into accumulators. An
    /// unordered consumer of a query without offset or limit is served straight from the
    /// scan -- no candidate is retained at all -- because nothing it computes depends on the
    /// order of the rows. The counters describe the selection; `cloned_documents` is left
    /// at zero for the caller to set.
    fn select<'a, F: FnMut(&'a Document)>(
        &'a self,
        query: &Query,
        version: Option<CommitVersion>,
        required_fields: &[&FieldPath],
        consumption: Consumption,
        sink: F,
    ) -> Result<QueryStats, FirestoreError> {
        let scope = &query.scope;
        let order = query.effective_order_by();
        let descending_name = matches!(
            order.as_slice(),
            [order] if order.field.is_document_name() && order.direction == Direction::Descending
        );
        let visited = core::cell::Cell::new(0u64);
        // A filter that pins `__name__` names its candidates: look them up instead of
        // scanning the scope. `select_from` still applies the scope, the whole filter, the
        // order, cursors and limits, so the candidates only need the right source order.
        let named = query.filter.as_ref().and_then(pinned_document_names);
        let paths: Box<dyn Iterator<Item = &DocumentPath> + '_> = match &named {
            Some(candidates) if descending_name => Box::new(candidates.iter().rev()),
            Some(candidates) => Box::new(candidates.iter()),
            None if descending_name => self.scope_paths_descending(scope, version),
            None => self.scope_paths(scope, version),
        };
        let documents = paths
            .inspect(|_| visited.set(visited.get() + 1))
            .filter_map(|path| match version {
                Some(version) => self.get_at(path, version),
                None => self.get(path),
            });
        let mut stats = select_from(
            query,
            documents,
            Some(if descending_name {
                Direction::Descending
            } else {
                Direction::Ascending
            }),
            required_fields,
            consumption,
            sink,
        )?;
        stats.index_paths_visited = visited.get();
        Ok(stats)
    }

    /// Runs aggregations over the query results.
    pub fn run_aggregation(
        &self,
        query: &Query,
        aggregations: &[Aggregation],
        version: Option<CommitVersion>,
    ) -> Result<Vec<Value>, FirestoreError> {
        Ok(self
            .run_aggregation_with_stats(query, aggregations, version)?
            .0)
    }

    /// [`Self::run_aggregation`] with the execution counters (`FS-AGG-PERF-*`).
    ///
    /// The aggregations fold over the selected documents as the selection produces them:
    /// a count keeps a counter, a sum its numeric accumulator, an average the sum and the
    /// number of contributors. No document is cloned (`cloned_documents` is always zero),
    /// and a query without offset or limit retains no candidate either, so the memory an
    /// aggregation costs is independent of the number and size of the matching documents.
    pub fn run_aggregation_with_stats(
        &self,
        query: &Query,
        aggregations: &[Aggregation],
        version: Option<CommitVersion>,
    ) -> Result<(Vec<Value>, QueryStats), FirestoreError> {
        let mut required_fields = Vec::new();
        for aggregation in aggregations {
            if let Aggregation::Sum(field) | Aggregation::Avg(field) = aggregation {
                if field.is_document_name() {
                    return Err(FirestoreError::InvalidArgument(
                        "Aggregations are not supported for the property: __key__".into(),
                    ));
                }
                if !required_fields.contains(&field) {
                    required_fields.push(field);
                }
            }
        }
        let mut accumulators: Vec<Accumulator> = aggregations
            .iter()
            .map(|_| Accumulator::default())
            .collect();
        let stats = self.select(
            query,
            version,
            &required_fields,
            Consumption::Unordered,
            |doc| {
                for (aggregation, accumulator) in aggregations.iter().zip(&mut accumulators) {
                    accumulator.fold(aggregation, doc);
                }
            },
        )?;
        let values = aggregations
            .iter()
            .zip(accumulators)
            .map(|(aggregation, accumulator)| accumulator.finish(aggregation))
            .collect();
        Ok((values, stats))
    }

    /// Runs an aggregation in a transaction while recording its observation in the same
    /// borrowed selection pass. Only document paths, versions and the query digest are retained
    /// for a read-write transaction; document bodies are never materialized just for conflict
    /// detection.
    pub fn run_aggregation_in_transaction_with_stats(
        &mut self,
        id: &TransactionId,
        query: &Query,
        aggregations: &[Aggregation],
    ) -> Result<(Vec<Value>, QueryStats), FirestoreError> {
        let read_only = self.transaction(id)?.read_only;
        let execution_id = self.allocate_query_execution_id();
        let mut required_fields = Vec::new();
        for aggregation in aggregations {
            if let Aggregation::Sum(field) | Aggregation::Avg(field) = aggregation {
                if field.is_document_name() {
                    return Err(FirestoreError::InvalidArgument(
                        "Aggregations are not supported for the property: __key__".into(),
                    ));
                }
                if !required_fields.contains(&field) {
                    required_fields.push(field);
                }
            }
        }
        let mut accumulators: Vec<Accumulator> = aggregations
            .iter()
            .map(|_| Accumulator::default())
            .collect();
        let mut observation = QueryObservation::default();
        let mut rows = Vec::new();
        let stats = self.select(
            query,
            Some(self.transaction(id)?.read_version),
            &required_fields,
            Consumption::Unordered,
            |document| {
                for (aggregation, accumulator) in aggregations.iter().zip(&mut accumulators) {
                    accumulator.fold(aggregation, document);
                }
                if !read_only {
                    observation.push(document);
                    rows.push(ObservedQueryDocument {
                        path: document.path.clone(),
                        version: document.version,
                        bytes: observed_document_bytes(&document.path, Some(document)),
                    });
                }
            },
        )?;
        let observed_required_fields: Vec<FieldPath> =
            required_fields.iter().copied().cloned().collect();
        self.record_transaction_query_observation_parts(
            id,
            execution_id,
            query,
            observation,
            &rows,
            observed_required_fields,
            Consumption::Unordered,
            false,
            true,
        )?;
        let values = aggregations
            .iter()
            .zip(accumulators)
            .map(|(aggregation, accumulator)| accumulator.finish(aggregation))
            .collect();
        Ok((values, stats))
    }
}

/// Whether a consumer of a selection needs the rows in query order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Consumption {
    /// The rows are returned, so they arrive in query order.
    Ordered,
    /// The rows are folded into something order-independent (an aggregation).
    Unordered,
}

/// The scalar state of one aggregation while the selection streams past it.
#[derive(Debug, Default)]
struct Accumulator {
    /// Selected documents (`count`).
    count: u64,
    /// Running numeric sum (`sum`, `avg`); integers saturate, as documented.
    sum: Option<Value>,
    /// Documents that contributed a numeric value to `sum`.
    contributors: u64,
}

impl Accumulator {
    fn fold(&mut self, aggregation: &Aggregation, doc: &Document) {
        match aggregation {
            Aggregation::Count { .. } => self.count += 1,
            Aggregation::Sum(field) | Aggregation::Avg(field) => {
                if let Some(v) = get_field(&doc.fields, field) {
                    if is_number(v) {
                        let sum = self.sum.take().unwrap_or(Value::Integer(0));
                        self.sum = Some(add_aggregated(&sum, v));
                        self.contributors += 1;
                    }
                }
            }
        }
    }

    fn finish(self, aggregation: &Aggregation) -> Value {
        match aggregation {
            Aggregation::Count { up_to } => {
                let n = self.count;
                Value::Integer(i64::try_from(up_to.map_or(n, |cap| n.min(cap))).unwrap_or(i64::MAX))
            }
            Aggregation::Sum(_) => self.sum.unwrap_or(Value::Integer(0)),
            Aggregation::Avg(_) => {
                if self.contributors == 0 {
                    return Value::Null;
                }
                #[allow(clippy::cast_precision_loss)]
                let total = match self.sum {
                    Some(Value::Integer(i)) => i as f64,
                    Some(Value::Double(d)) => d,
                    _ => 0.0,
                };
                #[allow(clippy::cast_precision_loss)]
                let divisor = self.contributors as f64;
                Value::Double(total / divisor)
            }
        }
    }
}

fn check_precondition(
    precondition: Option<&Precondition>,
    current: Option<&Document>,
    path: &DocumentPath,
) -> Result<(), FirestoreError> {
    match (precondition, current) {
        (Some(Precondition::Exists(true)), None) => Err(FirestoreError::NotFound(path.clone())),
        (Some(Precondition::Exists(false)), Some(_)) => {
            Err(FirestoreError::AlreadyExists(path.clone()))
        }
        (None | Some(Precondition::Exists(_)), _) => Ok(()),
        (Some(Precondition::UpdateTime(t)), Some(doc)) if doc.update_time == *t => Ok(()),
        (Some(Precondition::UpdateTime(_)), _) => Err(FirestoreError::FailedPrecondition(format!(
            "update time precondition failed for {path}"
        ))),
    }
}

fn apply_write<'a>(
    write: &Write,
    current: Option<&'a Document>,
    now: LogicalInstant,
    version: CommitVersion,
) -> Result<(Option<Cow<'a, Document>>, WriteResult), FirestoreError> {
    match &write.op {
        WriteOp::Verify { .. } => {
            if !write.transforms.is_empty() {
                return Err(FirestoreError::InvalidArgument(
                    "transforms on a verify".into(),
                ));
            }
            // Precondition already checked by the caller; nothing changes.
            Ok((
                current.map(Cow::Borrowed),
                WriteResult {
                    update_time: None,
                    transform_results: vec![],
                },
            ))
        }
        WriteOp::Delete { .. } => {
            if !write.transforms.is_empty() {
                return Err(FirestoreError::InvalidArgument(
                    "transforms on a delete".into(),
                ));
            }
            // Firestore never reports an update time for a delete.
            Ok((
                None,
                WriteResult {
                    update_time: None,
                    transform_results: vec![],
                },
            ))
        }
        WriteOp::Set {
            path,
            fields,
            update_mask,
        } => {
            let create_time = current.as_ref().map_or(now, |d| d.create_time);
            let mut next_fields = match (update_mask, current) {
                (None, _) => clone_field_tree(fields),
                (Some(mask), current) => {
                    let mut base = current
                        .map(|d| clone_field_tree(&d.fields))
                        .unwrap_or_default();
                    for p in mask {
                        match get_field(fields, p) {
                            Some(v) => set_field(&mut base, p, v.clone()),
                            None => delete_field(&mut base, p),
                        }
                    }
                    base
                }
            };
            // Production compares array transforms at storage precision, including values
            // supplied by this same write. Ordinary arrays retain their duplicates.
            normalize_fields_for_storage(&mut next_fields);
            let mut transform_results = Vec::with_capacity(write.transforms.len());
            for t in &write.transforms {
                let produced = apply_transform(&mut next_fields, t, now)?;
                transform_results.push(produced);
            }
            // Store what production stores (timestamps at microsecond precision) so that
            // reads, ordering and the no-op check below see the same content as production.
            normalize_fields_for_storage(&mut next_fields);
            let doc = Document {
                path: path.clone(),
                fields: next_fields,
                create_time,
                update_time: now,
                version,
            };
            Ok((
                Some(Cow::Owned(doc)),
                WriteResult {
                    update_time: Some(now),
                    transform_results,
                },
            ))
        }
    }
}

/// The document paths a filter restricts `__name__` to, in ascending resource-name order
/// without duplicates, when it does: a top-level `__name__ ==` or `__name__ in`, possibly
/// as one conjunct of a top-level `and`. Any other shape (a name condition under `or`, a
/// range, `not-in`) returns `None`, meaning the scope must be scanned. With several
/// conjuncts the smallest set wins; the others are enforced by the filter evaluation. A
/// reference that is not a document name can never equal a stored path and yields no
/// candidate.
fn pinned_document_names(filter: &FilterExpr) -> Option<Vec<DocumentPath>> {
    fn conjunct(filter: &FilterExpr) -> Option<Vec<DocumentPath>> {
        let FilterExpr::Field { field, op, value } = filter else {
            return None;
        };
        if !field.is_document_name() {
            return None;
        }
        let mut paths: Vec<DocumentPath> = match (op, value) {
            (FieldOp::Equal, Value::Reference(name)) => {
                DocumentPath::from_resource_name(name).into_iter().collect()
            }
            (FieldOp::In, Value::Array(names)) => names
                .iter()
                .filter_map(|name| match name {
                    Value::Reference(name) => DocumentPath::from_resource_name(name),
                    _ => None,
                })
                .collect(),
            _ => return None,
        };
        paths.sort_unstable();
        paths.dedup();
        Some(paths)
    }
    match filter {
        FilterExpr::And(children) => children.iter().filter_map(conjunct).min_by_key(Vec::len),
        other => conjunct(other),
    }
}

fn clone_field_tree(fields: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    #[cfg(test)]
    FIELD_TREE_CLONES.with(|count| count.set(count.get().saturating_add(1)));
    fields.clone()
}

#[cfg(test)]
thread_local! {
    static FIELD_TREE_CLONES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn take_field_tree_clone_count() -> usize {
    FIELD_TREE_CLONES.with(std::cell::Cell::take)
}

fn select_from<'a, I, F>(
    query: &Query,
    documents: I,
    source_order: Option<Direction>,
    required_fields: &[&FieldPath],
    consumption: Consumption,
    mut sink: F,
) -> Result<QueryStats, FirestoreError>
where
    I: IntoIterator<Item = &'a Document>,
    F: FnMut(&'a Document),
{
    let scope = &query.scope;
    let order = query.effective_order_by();
    let offset = usize::try_from(query.offset).unwrap_or(usize::MAX);
    let bound = query.limit.map(|limit| {
        usize::try_from(u64::from(query.offset) + u64::from(limit)).unwrap_or(usize::MAX)
    });
    let streaming = consumption == Consumption::Unordered && bound.is_none() && offset == 0;
    let path_ordered = source_order.is_some_and(|source_direction| {
        order.len() == 1
            && order[0].field.is_document_name()
            && order[0].direction == source_direction
    });
    let mut stats = QueryStats::default();
    if bound == Some(0) {
        return Ok(stats);
    }
    let mut heap: BinaryHeap<Candidate<'a, '_>> = BinaryHeap::new();
    let mut rows: Vec<Candidate<'a, '_>> = Vec::new();
    for document in documents {
        stats.scanned += 1;
        if !document_in_scope(document, scope) {
            continue;
        }
        if required_fields
            .iter()
            .any(|field| get_field(&document.fields, field).is_none())
        {
            continue;
        }
        if let Some(filter) = &query.filter {
            stats.filter_evaluations += 1;
            if !eval_filter(filter, document)? {
                continue;
            }
        }
        let Some(key) = order_key(document, &order) else {
            continue;
        };
        if !cursor_admits(&key, query.start_at.as_ref(), query.end_at.as_ref(), &order) {
            continue;
        }
        stats.matched += 1;
        if streaming {
            sink(document);
            continue;
        }
        let candidate = Candidate {
            key,
            doc: document,
            order: &order,
        };
        if path_ordered {
            if let Some(bound) = bound {
                rows.push(candidate);
                stats.peak_candidates = stats.peak_candidates.max(rows.len() as u64);
                if rows.len() >= bound {
                    break;
                }
                continue;
            }
        }
        match bound {
            Some(0) => {}
            Some(maximum) if heap.len() >= maximum => {
                if heap.peek().is_some_and(|worst| candidate < *worst) {
                    heap.pop();
                    heap.push(candidate);
                }
            }
            Some(_) => heap.push(candidate),
            None => rows.push(candidate),
        }
        stats.peak_candidates = stats.peak_candidates.max((heap.len() + rows.len()) as u64);
    }
    if streaming {
        return Ok(stats);
    }
    let mut selected = if path_ordered && bound.is_some() {
        rows
    } else if bound.is_some() {
        heap.into_sorted_vec()
    } else {
        rows.sort_by(|left, right| compare_keys(&left.key, &right.key, &order));
        rows
    };
    if offset > 0 {
        selected.drain(..offset.min(selected.len()));
    }
    if let Some(limit) = query.limit {
        selected.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    }
    for candidate in selected {
        sink(candidate.doc);
    }
    Ok(stats)
}

fn validate_stored_field_name(name: &str) -> Result<(), FirestoreError> {
    // __name__ is a query pseudo-field, never a stored field name.
    if name == "__name__" {
        return Err(FirestoreError::InvalidArgument(format!(
            "field name '{name}' is reserved."
        )));
    }
    FieldPath::from_segments([name])
        .map(|_| ())
        .map_err(|e| FirestoreError::InvalidArgument(format!("field name {name:?}: {e}")))
}

fn validate_document(doc: &Document) -> Result<(), FirestoreError> {
    for (name, value) in &doc.fields {
        validate_stored_field_name(name)?;
        check_limit(
            limits::NESTED_MAP_ARRAY_DEPTH,
            u64::from(value.nesting_depth()),
        )?;
    }
    let size = document_size(&doc.path, &doc.fields)
        .map_err(|e| FirestoreError::InvalidArgument(e.to_string()))?;
    check_limit(limits::DOCUMENT_BYTES, size.total)?;
    for value in doc.fields.values() {
        validate_value(value, false)?;
    }
    Ok(())
}

/// The value rules every stored value obeys: an array never holds an array directly, and a
/// reference names a document (`projects/{p}/databases/{d}/documents/` plus an even number
/// of non-empty segments).
fn validate_value(value: &Value, inside_array: bool) -> Result<(), FirestoreError> {
    // Production counts the payload, not storage accounting's trailing string byte.
    let payload_bytes = match value {
        Value::String(value) => value.len(),
        Value::Bytes(value) => value.len(),
        _ => 0,
    };
    if payload_bytes > limits::MAX_FIELD_PAYLOAD_BYTES {
        return Err(FirestoreError::InvalidArgument(
            "The value of a property is longer than 1048487 bytes.".into(),
        ));
    }
    match value {
        Value::Array(items) => {
            if inside_array {
                return Err(FirestoreError::InvalidArgument(
                    "Nested arrays are not allowed".into(),
                ));
            }
            items.iter().try_for_each(|v| validate_value(v, true))
        }
        Value::Map(fields) => fields.iter().try_for_each(|(name, value)| {
            validate_stored_field_name(name)?;
            validate_value(value, false)
        }),
        Value::Reference(name) => validate_reference(name),
        _ => Ok(()),
    }
}

fn validate_reference(name: &str) -> Result<(), FirestoreError> {
    let malformed = || {
        FirestoreError::InvalidArgument(format!(
            "Document name {name:?} is not a document path: projects/{{project}}/databases/{{database}}/documents/{{collection}}/{{document}}..."
        ))
    };
    let segments: Vec<&str> = name.split('/').collect();
    if segments.len() < 7
        || segments[0] != "projects"
        || segments[2] != "databases"
        || segments[4] != "documents"
        || segments[1].is_empty()
        || segments[3].is_empty()
    {
        return Err(malformed());
    }
    let relative = &segments[5..];
    if relative.len() % 2 != 0 || relative.iter().any(|s| s.is_empty()) {
        return Err(FirestoreError::InvalidArgument(format!(
            "Document parent name {name:?} lacks \"/\" at index {}.",
            name.len()
        )));
    }
    Ok(())
}

/// Navigates a field path.
#[must_use]
pub fn get_field<'a>(fields: &'a BTreeMap<String, Value>, path: &FieldPath) -> Option<&'a Value> {
    let mut segments = path.segments().iter();
    let mut current = fields.get(segments.next()?)?;
    for s in segments {
        match current {
            Value::Map(m) => current = m.get(s)?,
            _ => return None,
        }
    }
    Some(current)
}

fn set_field(fields: &mut BTreeMap<String, Value>, path: &FieldPath, value: Value) {
    let segments = path.segments();
    let mut map = fields;
    for s in &segments[..segments.len() - 1] {
        let entry = map
            .entry(s.clone())
            .or_insert_with(|| Value::Map(BTreeMap::new()));
        if !matches!(entry, Value::Map(_)) {
            *entry = Value::Map(BTreeMap::new());
        }
        map = match entry {
            Value::Map(m) => m,
            _ => unreachable!("just replaced with a map"),
        };
    }
    map.insert(segments[segments.len() - 1].clone(), value);
}

fn delete_field(fields: &mut BTreeMap<String, Value>, path: &FieldPath) {
    let segments = path.segments();
    let mut map = fields;
    for s in &segments[..segments.len() - 1] {
        match map.get_mut(s) {
            Some(Value::Map(m)) => map = m,
            _ => return,
        }
    }
    map.remove(&segments[segments.len() - 1]);
}

fn is_number(v: &Value) -> bool {
    matches!(v, Value::Integer(_) | Value::Double(_))
}

#[allow(clippy::cast_precision_loss)]
fn add_numbers(a: &Value, b: &Value) -> Value {
    match (a, b) {
        (Value::Integer(x), Value::Integer(y)) => Value::Integer(x.saturating_add(*y)),
        (Value::Integer(x), Value::Double(y)) | (Value::Double(y), Value::Integer(x)) => {
            Value::Double(*x as f64 + y)
        }
        (Value::Double(x), Value::Double(y)) => Value::Double(x + y),
        (_, other) => other.clone(),
    }
}

/// Addition for `sum` / `avg`: an integer sum that overflows becomes a double, as the
/// backend and the official emulator report it (a transform increment saturates instead).
#[allow(clippy::cast_precision_loss)]
fn add_aggregated(a: &Value, b: &Value) -> Value {
    match (a, b) {
        (Value::Integer(x), Value::Integer(y)) => x
            .checked_add(*y)
            .map_or_else(|| Value::Double(*x as f64 + *y as f64), Value::Integer),
        _ => add_numbers(a, b),
    }
}

fn apply_transform(
    fields: &mut BTreeMap<String, Value>,
    t: &FieldTransform,
    now: LogicalInstant,
) -> Result<Value, FirestoreError> {
    let current = get_field(fields, &t.field).cloned();
    let produced = match &t.kind {
        TransformKind::ServerTimestamp => {
            // The commit time at microsecond precision (production stores server timestamps
            // with microseconds): strictly increasing across commits even when the clock did
            // not move, so `orderBy` on a server timestamp follows commit order, and identical
            // for every transform of one commit.
            let micros = now.as_nanos().div_euclid(1_000);
            let secs = i64::try_from(micros.div_euclid(1_000_000))
                .map_err(|_| FirestoreError::InvalidArgument("commit time out of range".into()))?;
            let nanos = u32::try_from(micros.rem_euclid(1_000_000) * 1_000).unwrap_or(0);
            Value::Timestamp(
                Timestamp::new(secs, nanos).map_err(|_| {
                    FirestoreError::InvalidArgument("commit time out of range".into())
                })?,
            )
        }
        TransformKind::Increment(delta) => {
            if !is_number(delta) {
                return Err(FirestoreError::InvalidArgument(
                    "increment operand must be numeric".into(),
                ));
            }
            match current {
                Some(c) if is_number(&c) => add_numbers(&c, delta),
                _ => delta.clone(),
            }
        }
        TransformKind::Maximum(operand) | TransformKind::Minimum(operand) => {
            if !is_number(operand) {
                return Err(FirestoreError::InvalidArgument(
                    "maximum / minimum operand must be numeric".into(),
                ));
            }
            let want_max = matches!(t.kind, TransformKind::Maximum(_));
            match current {
                Some(Value::Double(n)) if n.is_nan() => Value::Double(n),
                Some(c) if is_number(&c) && matches!(operand, Value::Double(n) if n.is_nan()) => {
                    operand.clone()
                }
                Some(c) if is_number(&c) => {
                    let ord = c.canonical_cmp(operand);
                    if (want_max && ord == Ordering::Less)
                        || (!want_max && ord == Ordering::Greater)
                    {
                        operand.clone()
                    } else {
                        c
                    }
                }
                _ => operand.clone(),
            }
        }
        TransformKind::AppendMissingElements(items) => {
            let mut arr = match current {
                Some(Value::Array(a)) => a,
                _ => Vec::new(),
            };
            for item in items {
                let mut item = item.clone();
                item.normalize_for_storage();
                if !arr
                    .iter()
                    .any(|x| x.canonical_cmp(&item) == Ordering::Equal)
                {
                    arr.push(item);
                }
            }
            Value::Array(arr)
        }
        TransformKind::RemoveAllFromArray(items) => {
            let mut items = items.clone();
            items.iter_mut().for_each(Value::normalize_for_storage);
            let arr = match current {
                Some(Value::Array(a)) => a,
                _ => Vec::new(),
            };
            Value::Array(
                arr.into_iter()
                    .filter(|x| !items.iter().any(|i| i.canonical_cmp(x) == Ordering::Equal))
                    .collect(),
            )
        }
    };
    let reported = match t.kind {
        // Array transforms report a null transform result (the stored array is not echoed).
        TransformKind::AppendMissingElements(_) | TransformKind::RemoveAllFromArray(_) => {
            Value::Null
        }
        _ => produced.clone(),
    };
    set_field(fields, &t.field, produced);
    Ok(reported)
}

/// A queried field as execution sees it: borrowed from the stored document, or the
/// document's own name. `__name__` is compared segment-wise against the path so that a
/// scanned row never renders its resource name.
#[derive(Debug, Clone, Copy)]
enum FieldRef<'a> {
    /// A stored field value.
    Stored(&'a Value),
    /// The document name (`__name__`), ordered as a reference.
    Name(&'a DocumentPath),
}

impl<'a> FieldRef<'a> {
    fn into_value(self) -> Value {
        match self {
            Self::Stored(value) => value.clone(),
            Self::Name(path) => Value::Reference(path.resource_name()),
        }
    }

    fn kind(self) -> ValueKind {
        match self {
            Self::Stored(v) => v.kind(),
            Self::Name(_) => ValueKind::Reference,
        }
    }

    /// The stored value, or `None` for `__name__` (which is never an array or a map).
    fn stored(self) -> Option<&'a Value> {
        match self {
            Self::Stored(v) => Some(v),
            Self::Name(_) => None,
        }
    }

    fn is_null(self) -> bool {
        matches!(self, Self::Stored(Value::Null))
    }

    fn is_nan(self) -> bool {
        matches!(self, Self::Stored(Value::Double(d)) if d.is_nan())
    }

    fn cmp_value(self, other: &Value) -> Ordering {
        match self {
            Self::Stored(v) => v.canonical_cmp(other),
            Self::Name(p) => match other {
                Value::Reference(name) => p.cmp_reference(name),
                _ => ValueKind::Reference.cmp(&other.kind()),
            },
        }
    }

    fn cmp_ref(self, other: Self) -> Ordering {
        match (self, other) {
            (Self::Stored(a), Self::Stored(b)) => a.canonical_cmp(b),
            (Self::Name(a), Self::Name(b)) => a.cmp_resource_name(b),
            (Self::Name(_), Self::Stored(v)) => ValueKind::Reference.cmp(&v.kind()),
            (Self::Stored(v), Self::Name(_)) => v.kind().cmp(&ValueKind::Reference),
        }
    }
}

/// One row kept for selection: the order key borrows from `doc`, so a candidate that is
/// later dropped costs no copy of the document.
struct Candidate<'d, 'o> {
    key: Vec<FieldRef<'d>>,
    doc: &'d Document,
    order: &'o [OrderClause],
}

impl PartialEq for Candidate<'_, '_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Candidate<'_, '_> {}

impl PartialOrd for Candidate<'_, '_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Candidate<'_, '_> {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_keys(&self.key, &other.key, self.order)
    }
}

fn field_value<'a>(doc: &'a Document, path: &FieldPath) -> Option<FieldRef<'a>> {
    if path.is_document_name() {
        return Some(FieldRef::Name(&doc.path));
    }
    get_field(&doc.fields, path).map(FieldRef::Stored)
}

fn same_type_as(a: FieldRef<'_>, b: &Value) -> bool {
    let ka = a.kind();
    let kb = b.kind();
    ka == kb
        || (matches!(ka, ValueKind::Number | ValueKind::Nan)
            && matches!(kb, ValueKind::Number | ValueKind::Nan))
}

fn equal(a: &Value, b: &Value) -> bool {
    if matches!(a, Value::Double(d) if d.is_nan()) || matches!(b, Value::Double(d) if d.is_nan()) {
        return false;
    }
    a.canonical_cmp(b) == Ordering::Equal
}

/// Equality between a queried field and a query operand (`NaN` equals nothing).
fn equal_ref(a: FieldRef<'_>, b: &Value) -> bool {
    if a.is_nan() || matches!(b, Value::Double(d) if d.is_nan()) {
        return false;
    }
    a.cmp_value(b) == Ordering::Equal
}

fn eval_filter(filter: &FilterExpr, doc: &Document) -> Result<bool, FirestoreError> {
    Ok(match filter {
        FilterExpr::And(children) => {
            for c in children {
                if !eval_filter(c, doc)? {
                    return Ok(false);
                }
            }
            true
        }
        FilterExpr::Or(children) => {
            for c in children {
                if eval_filter(c, doc)? {
                    return Ok(true);
                }
            }
            false
        }
        FilterExpr::Unary { field, op } => {
            let v = field_value(doc, field);
            match op {
                UnaryOp::IsNull => matches!(v, Some(x) if x.is_null()),
                UnaryOp::IsNotNull => matches!(v, Some(x) if !x.is_null()),
                UnaryOp::IsNan => matches!(v, Some(x) if x.is_nan()),
                UnaryOp::IsNotNan => matches!(v, Some(x) if !x.is_nan()),
            }
        }
        FilterExpr::Field { field, op, value } => {
            let Some(v) = field_value(doc, field) else {
                return Ok(false);
            };
            // A null operand matches nothing under any field operator: null is compared
            // through the unary `IS_NULL` / `IS_NOT_NULL` filters, which is what the SDKs
            // send for `== null` / `!= null`, and the official emulator answers the raw
            // field filter the same way. A null candidate inside an `in` /
            // `array-contains-any` list is ignored for the same reason.
            if matches!(value, Value::Null) {
                return Ok(false);
            }
            match op {
                FieldOp::Equal => equal_ref(v, value),
                FieldOp::NotEqual => !equal_ref(v, value) && !v.is_null(),
                FieldOp::LessThan
                | FieldOp::LessThanOrEqual
                | FieldOp::GreaterThan
                | FieldOp::GreaterThanOrEqual => {
                    if !same_type_as(v, value) || v.is_nan() {
                        return Ok(false);
                    }
                    let ord = v.cmp_value(value);
                    match op {
                        FieldOp::LessThan => ord == Ordering::Less,
                        FieldOp::LessThanOrEqual => ord != Ordering::Greater,
                        FieldOp::GreaterThan => ord == Ordering::Greater,
                        _ => ord != Ordering::Less,
                    }
                }
                FieldOp::ArrayContains => {
                    matches!(v.stored(), Some(Value::Array(items)) if items.iter().any(|i| equal(i, value)))
                }
                FieldOp::In => {
                    matches!(value, Value::Array(candidates)
                        if candidates.iter().any(|c| !matches!(c, Value::Null) && equal_ref(v, c)))
                }
                FieldOp::NotIn => {
                    // `not-in` never matches null fields, and a null candidate matches nothing.
                    matches!(value, Value::Array(candidates)
                        if !candidates.iter().any(|c| equal_ref(v, c) || matches!(c, Value::Null)))
                        && !v.is_null()
                }
                FieldOp::ArrayContainsAny => match (v.stored(), value) {
                    (Some(Value::Array(items)), Value::Array(candidates)) => {
                        items.iter().any(|i| {
                            candidates
                                .iter()
                                .any(|c| !matches!(c, Value::Null) && equal(i, c))
                        })
                    }
                    _ => false,
                },
            }
        }
    })
}

fn order_key<'a>(doc: &'a Document, order: &[OrderClause]) -> Option<Vec<FieldRef<'a>>> {
    order.iter().map(|o| field_value(doc, &o.field)).collect()
}

fn compare_keys(a: &[FieldRef<'_>], b: &[FieldRef<'_>], order: &[OrderClause]) -> Ordering {
    for ((x, y), clause) in a.iter().zip(b).zip(order) {
        let ord = x.cmp_ref(*y);
        let ord = match clause.direction {
            Direction::Ascending => ord,
            Direction::Descending => ord.reverse(),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

/// Compares an order key with a cursor's values, clause by clause.
fn compare_cursor(key: &[FieldRef<'_>], values: &[Value], order: &[OrderClause]) -> Ordering {
    for ((x, y), clause) in key.iter().zip(values).zip(order) {
        let ord = x.cmp_value(y);
        let ord = match clause.direction {
            Direction::Ascending => ord,
            Direction::Descending => ord.reverse(),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

fn cursor_admits(
    key: &[FieldRef<'_>],
    start: Option<&Cursor>,
    end: Option<&Cursor>,
    order: &[OrderClause],
) -> bool {
    if let Some(c) = start {
        let ord = compare_cursor(key, &c.values, order);
        let ok = match ord {
            Ordering::Greater => true,
            Ordering::Equal => c.before,
            Ordering::Less => false,
        };
        if !ok {
            return false;
        }
    }
    if let Some(c) = end {
        let ord = compare_cursor(key, &c.values, order);
        let ok = match ord {
            Ordering::Less => true,
            Ordering::Equal => !c.before,
            Ordering::Greater => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Exact projection of `fields` onto `projection` (nested paths keep only the named leaf).
#[must_use]
pub fn project(
    fields: &BTreeMap<String, Value>,
    projection: &[FieldPath],
) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    for p in projection {
        if p.is_document_name() {
            continue;
        }
        if let Some(v) = get_field(fields, p) {
            set_field(&mut out, p, v.clone());
        }
    }
    out
}

fn project_document(document: &Document, projection: Option<&[FieldPath]>) -> Document {
    Document {
        path: document.path.clone(),
        fields: projection.map_or_else(
            || document.fields.clone(),
            |fields| project(&document.fields, fields),
        ),
        create_time: document.create_time,
        update_time: document.update_time,
        version: document.version,
    }
}

fn fields_retained_bytes(fields: &BTreeMap<String, Value>) -> u64 {
    fields.iter().fold(0u64, |total, (key, value)| {
        total
            .saturating_add(u64::try_from(key.len()).unwrap_or(u64::MAX))
            .saturating_add(value_retained_bytes(value))
    })
}

#[cfg(test)]
mod scope_index_tests {
    use super::*;
    use fireemu_core_types::ids::{DatabaseId, ProjectId};

    fn path(value: &str) -> DocumentPath {
        DocumentPath::parse(
            &ProjectId::try_new("demo-app").expect("valid project"),
            &DatabaseId::default_database(),
            value,
        )
        .expect("valid document path")
    }

    fn set(value: &str) -> Write {
        Write {
            op: WriteOp::Set {
                path: path(value),
                fields: BTreeMap::new(),
                update_mask: None,
            },
            precondition: None,
            transforms: Vec::new(),
        }
    }

    fn delete(value: &str) -> Write {
        Write {
            op: WriteOp::Delete { path: path(value) },
            precondition: None,
            transforms: Vec::new(),
        }
    }

    fn assert_trie_projection(
        state: &FirestoreState,
        trie: &ListingTrie,
        prefix: &mut Vec<(CollectionId, DocumentId)>,
    ) {
        for (collection, collection_node) in &trie.collections {
            let expected_documents = state
                .history
                .keys()
                .filter_map(|path| {
                    path.pairs()
                        .starts_with(prefix)
                        .then(|| path.pairs().get(prefix.len()))
                        .flatten()
                        .and_then(|(candidate_collection, document)| {
                            (candidate_collection == collection).then(|| document.clone())
                        })
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(
                collection_node
                    .documents
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>(),
                expected_documents
            );
            let expected_live_candidates = collection_node
                .documents
                .iter()
                .filter_map(|(document, node)| {
                    (node.live_subtree_paths > 0).then_some(document.clone())
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(collection_node.live_candidates, expected_live_candidates);
            for (document, node) in &collection_node.documents {
                prefix.push((collection.clone(), document.clone()));
                let retained = state
                    .history
                    .keys()
                    .filter(|path| path.pairs().starts_with(prefix))
                    .count();
                let live = state
                    .history
                    .iter()
                    .filter(|(path, versions)| {
                        path.pairs().starts_with(prefix)
                            && matches!(versions.last(), Some((_, Some(_))))
                    })
                    .count();
                assert_eq!(node.retained_subtree_paths, retained);
                assert_eq!(node.live_subtree_paths, live);
                assert_eq!(
                    node.retained_here.is_some(),
                    state.history.keys().any(|path| path.pairs() == prefix)
                );
                assert_trie_projection(state, &node.children, prefix);
                prefix.pop();
            }
        }
    }

    fn collect_trie_representatives(
        trie: &ListingTrie,
        nodes: &mut usize,
        representatives: &mut BTreeSet<usize>,
    ) {
        for collection in trie.collections.values() {
            for node in collection.documents.values() {
                *nodes += 1;
                representatives.insert(
                    node.representative
                        .as_ref()
                        .map_or(0, |path| Arc::as_ptr(path) as usize),
                );
                collect_trie_representatives(&node.children, nodes, representatives);
            }
        }
    }

    fn assert_scope_projection(state: &FirestoreState) {
        assert_eq!(state.history_usage, state.recount_history_usage());
        let mut direct: BTreeMap<_, BTreeSet<DocumentPath>> = BTreeMap::new();
        let mut groups: BTreeMap<_, BTreeSet<DocumentPath>> = BTreeMap::new();
        let mut live_direct: BTreeMap<_, BTreeSet<DocumentPath>> = BTreeMap::new();
        let mut live_groups: BTreeMap<_, BTreeSet<DocumentPath>> = BTreeMap::new();
        let mut live_paths = BTreeSet::new();
        for (path, versions) in &state.history {
            direct
                .entry((path.parent_document(), path.collection_id().clone()))
                .or_default()
                .insert(path.clone());
            groups
                .entry(path.collection_id().clone())
                .or_default()
                .insert(path.clone());
            if matches!(versions.last(), Some((_, Some(_)))) {
                live_paths.insert(path.clone());
                live_direct
                    .entry((path.parent_document(), path.collection_id().clone()))
                    .or_default()
                    .insert(path.clone());
                live_groups
                    .entry(path.collection_id().clone())
                    .or_default()
                    .insert(path.clone());
            }
        }
        let actual_direct = state
            .direct_collection_paths
            .iter()
            .map(|(scope, paths)| {
                (
                    scope.clone(),
                    paths.iter().map(|path| path.as_ref().clone()).collect(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let actual_groups = state
            .collection_group_paths
            .iter()
            .map(|(scope, paths)| {
                (
                    scope.clone(),
                    paths.iter().map(|path| path.as_ref().clone()).collect(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let actual_live_direct = state
            .live_direct_collection_paths
            .iter()
            .map(|(scope, paths)| {
                (
                    scope.clone(),
                    paths.iter().map(|path| path.as_ref().clone()).collect(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let actual_live_groups = state
            .live_collection_group_paths
            .iter()
            .map(|(scope, paths)| {
                (
                    scope.clone(),
                    paths.iter().map(|path| path.as_ref().clone()).collect(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let actual_live_paths = state
            .live_paths
            .iter()
            .map(|path| path.as_ref().clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_direct, direct);
        assert_eq!(actual_groups, groups);
        assert_eq!(actual_live_direct, live_direct);
        assert_eq!(actual_live_groups, live_groups);
        assert_eq!(actual_live_paths, live_paths);

        assert_trie_projection(state, &state.listing_trie, &mut Vec::new());
    }

    #[test]
    fn scope_indexes_exactly_project_retained_history() {
        let mut state = FirestoreState::new();
        state
            .commit(
                &[set("root/a/children/x"), set("root/b")],
                None,
                LogicalInstant::UNIX_EPOCH,
            )
            .expect("create indexed paths");
        assert_scope_projection(&state);
        assert_scope_projection(&state.visible_snapshot());

        state
            .commit(
                &[delete("root/a/children/x")],
                None,
                LogicalInstant::from_unix_seconds(1),
            )
            .expect("retain a historical tombstone");
        assert_scope_projection(&state);
        state
            .commit(
                &[set("clock/tick")],
                None,
                LogicalInstant::from_unix_seconds(READ_TIME_RETENTION_SECONDS + 2),
            )
            .expect("advance beyond retention");
        assert!(!state.history.contains_key(&path("root/a/children/x")));
        assert_scope_projection(&state);
    }

    #[test]
    fn cached_history_usage_survives_mixed_state_transitions() {
        let mut state = FirestoreState::new();
        state
            .commit(
                &[set("mixed/a"), set("mixed/b")],
                None,
                LogicalInstant::UNIX_EPOCH,
            )
            .expect("create two documents");
        assert_scope_projection(&state);

        state
            .commit(
                &[set("mixed/a"), delete("mixed/b"), set("mixed/c")],
                None,
                LogicalInstant::from_unix_seconds(1),
            )
            .expect("publish an update, delete, and create together");
        assert_scope_projection(&state);

        let transaction = state
            .begin_transaction(false, LogicalInstant::from_unix_seconds(2))
            .expect("begin transaction");
        state.rollback(&transaction).expect("roll transaction back");
        assert_scope_projection(&state);

        let forecast_time = LogicalInstant::from_unix_seconds(READ_TIME_RETENTION_SECONDS + 3);
        let _ = state.projected_history_usage(&[], forecast_time);
        assert!(state.compaction_forecast.is_some());
        state
            .import_documents(
                vec![ImportedDocument {
                    path: path("imported/a"),
                    fields: BTreeMap::new(),
                    create_time: None,
                    update_time: None,
                }],
                forecast_time,
            )
            .expect("import one document");
        assert!(state.compaction_forecast.is_none());
        assert_scope_projection(&state);
        assert_scope_projection(&state.visible_snapshot());

        state.compact(LogicalInstant::from_unix_seconds(
            READ_TIME_RETENTION_SECONDS * 2 + 4,
        ));
        assert_scope_projection(&state);
    }

    #[test]
    fn listing_trie_shares_one_path_across_maximum_depth_prefixes() {
        let relative = (0..crate::path::MAX_SUBCOLLECTION_DEPTH)
            .flat_map(|depth| [format!("c{depth}"), format!("d{depth}")])
            .collect::<Vec<_>>()
            .join("/");
        let mut state = FirestoreState::new();
        state
            .commit(&[set(&relative)], None, LogicalInstant::UNIX_EPOCH)
            .expect("maximum-depth path is indexable");

        let mut nodes = 0;
        let mut representatives = BTreeSet::new();
        collect_trie_representatives(&state.listing_trie, &mut nodes, &mut representatives);
        assert_eq!(nodes, crate::path::MAX_SUBCOLLECTION_DEPTH);
        assert_eq!(representatives.len(), 1);
    }

    #[test]
    fn limit_scope_constructor_preserves_the_requested_profile() {
        assert_eq!(
            FirestoreState::with_limit_scope(LimitScope::OfficialEmulator).limit_scope(),
            LimitScope::OfficialEmulator
        );
    }

    #[test]
    fn owned_visible_state_moves_documents_without_cloning_fields() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "payload".to_owned(),
            Value::String("large-payload".repeat(128)),
        );
        let mut state = FirestoreState::new();
        state
            .commit(
                &[Write {
                    op: WriteOp::Set {
                        path: path("items/a"),
                        fields,
                        update_mask: None,
                    },
                    precondition: None,
                    transforms: Vec::new(),
                }],
                None,
                LogicalInstant::UNIX_EPOCH,
            )
            .expect("create document");
        let before = match state
            .get(&path("items/a"))
            .and_then(|document| document.fields.get("payload"))
        {
            Some(Value::String(value)) => value.as_ptr(),
            other => panic!("expected string field, got {other:?}"),
        };

        let documents = state.into_documents();
        let after = match documents[0].fields.get("payload") {
            Some(Value::String(value)) => value.as_ptr(),
            other => panic!("expected string field, got {other:?}"),
        };

        assert_eq!(documents.len(), 1);
        assert_eq!(before, after, "the owned field allocation is moved");
    }

    #[test]
    fn commit_change_and_history_share_the_updated_document_allocation() {
        let path = path("items/large");
        let mut state = FirestoreState::new();
        state
            .commit(&[set("items/large")], None, LogicalInstant::UNIX_EPOCH)
            .expect("create document");
        take_field_tree_clone_count();
        let mut fields = BTreeMap::new();
        fields.insert(
            "payload".to_owned(),
            Value::String("x".repeat(1024 * 1024 - 1024)),
        );
        let result = state
            .commit(
                &[Write {
                    op: WriteOp::Set {
                        path: path.clone(),
                        fields,
                        update_mask: None,
                    },
                    precondition: None,
                    transforms: Vec::new(),
                }],
                None,
                LogicalInstant::from_unix_seconds(1),
            )
            .expect("update document");

        let changed = result.changes[0].after.as_ref().expect("after image");
        let stored = state
            .history
            .get(&path)
            .and_then(|versions| versions.last())
            .and_then(|(_, document)| document.as_ref())
            .expect("stored document");
        assert!(take_field_tree_clone_count() <= 2);
        assert!(Arc::ptr_eq(changed, stored));
    }

    #[test]
    fn verify_borrows_the_current_document_field_tree() {
        let mut state = FirestoreState::new();
        state
            .commit(&[set("items/verify")], None, LogicalInstant::UNIX_EPOCH)
            .unwrap();
        let current = state.get(&path("items/verify")).unwrap();
        let write = Write {
            op: WriteOp::Verify {
                path: current.path.clone(),
            },
            precondition: None,
            transforms: vec![],
        };
        let (next, _) = apply_write(
            &write,
            Some(current),
            LogicalInstant::UNIX_EPOCH,
            CommitVersion::default(),
        )
        .unwrap();
        assert!(std::ptr::eq(
            &raw const next.as_ref().unwrap().fields,
            &raw const current.fields
        ));
    }
}
