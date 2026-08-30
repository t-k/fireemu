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
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

use ftd_core_limits::catalogs::FIRESTORE_STANDARD_2026_08_25;
use ftd_core_limits::evaluate::{evaluate, LimitDisposition, LimitViolation, DEFAULT_THRESHOLDS};
use ftd_core_limits::model::LimitMaximum;
use ftd_core_limits::plan::FirestorePlanProfile;
use ftd_core_types::time::{LogicalDuration, LogicalInstant};

use crate::field_path::FieldPath;
use crate::path::DocumentPath;
use crate::query::{Cursor, Direction, FieldOp, FilterExpr, OrderClause, Query, UnaryOp};
use crate::size::document_size;
use crate::value::{Timestamp, Value, ValueKind};

/// How far back a snapshot selector may reach: the documented Firestore `read_time` window
/// of one hour (no PITR). The store owns this value because it decides which versions stay
/// reachable; the gRPC adapter re-declares the same number on the wire
/// (`ftd_adapter_grpc::local::READ_TIME_RETENTION_SECONDS`) and the two must stay equal.
pub const READ_TIME_RETENTION_SECONDS: i64 = 3600;

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
    pub before: Option<Document>,
    /// The document after the commit (`None` = deleted).
    pub after: Option<Document>,
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
    pub changes: Vec<DocumentChange>,
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
            Self::Unimplemented(m) => write!(f, "unimplemented: {m}"),
        }
    }
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
    /// Queries executed inside the transaction with their result fingerprints; re-evaluated
    /// at commit so that phantom rows abort the transaction.
    queries: Vec<(Query, Vec<(DocumentPath, CommitVersion)>)>,
    last_activity: LogicalInstant,
    finished: bool,
}

/// Execution counters for one query. Test and verification surface (`FS-QUERY-PERF-*`); the
/// wire API never exposes them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueryStats {
    /// Documents visited by the scan.
    pub scanned: u64,
    /// Documents that passed scope, filter, ordering and cursors.
    pub matched: u64,
    /// Largest number of candidate rows held at once. With a finite `offset + limit` this
    /// never exceeds that sum, whatever the size of the matched set.
    pub peak_candidates: u64,
    /// Documents cloned into the result. Execution borrows every value it filters and orders
    /// on, so this is the only place where a document's heap-backed fields are copied.
    pub cloned_documents: u64,
}

/// One Firestore database.
#[derive(Debug, Clone, Default)]
pub struct FirestoreState {
    /// Version history per path; `None` entries are tombstones.
    history: BTreeMap<DocumentPath, Vec<(CommitVersion, Option<Document>)>>,
    version: CommitVersion,
    next_transaction: u64,
    transactions: BTreeMap<TransactionId, Transaction>,
    /// Last published commit time; commit times are strictly monotonic per database.
    last_commit_time: Option<LogicalInstant>,
    /// Commit time of every retained version (`read_time` snapshots).
    commit_times: Vec<(CommitVersion, LogicalInstant)>,
    /// Versions strictly below this one have been compacted away: no supported read, no
    /// active transaction and no acceptable resume token can still name them.
    compaction_floor: CommitVersion,
    /// Paths whose history still holds something a later compaction could drop (more than
    /// one version, or a single tombstone). Compaction only visits these.
    compactable: BTreeSet<DocumentPath>,
}

fn limit(id: &str) -> &'static ftd_core_limits::model::LimitDefinition {
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

fn transaction_ttl() -> LogicalDuration {
    seconds_limit("FS-LIMIT-TRANSACTION-TOTAL-TIME", 270)
}

fn transaction_idle_ttl() -> LogicalDuration {
    seconds_limit("FS-LIMIT-TRANSACTION-IDLE-TIME", 60)
}

fn elapsed(now: LogicalInstant, earlier: LogicalInstant) -> LogicalDuration {
    now.checked_duration_since(earlier)
        .unwrap_or(LogicalDuration::from_nanos(i128::MAX))
}

impl FirestoreState {
    /// Empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
            .and_then(|(_, d)| d.as_ref())
    }

    /// Document as of `version`.
    #[must_use]
    pub fn get_at(&self, path: &DocumentPath, version: CommitVersion) -> Option<&Document> {
        self.history
            .get(path)?
            .iter()
            .rev()
            .find(|(v, _)| *v <= version)
            .and_then(|(_, d)| d.as_ref())
    }

    fn latest_version_of(&self, path: &DocumentPath) -> Option<CommitVersion> {
        self.history
            .get(path)
            .and_then(|h| h.last())
            .and_then(|(v, d)| d.as_ref().map(|_| *v))
    }

    /// All live documents (latest versions), in path order.
    fn live_documents(&self, at: Option<CommitVersion>) -> impl Iterator<Item = &Document> {
        self.history.iter().filter_map(move |(path, _)| match at {
            Some(v) => self.get_at(path, v),
            None => self.get(path),
        })
    }

    /// Begins a transaction at the current version.
    pub fn begin_transaction(
        &mut self,
        read_only: bool,
        now: LogicalInstant,
    ) -> Result<TransactionId, FirestoreError> {
        let read_time = self.read_time(now);
        Ok(self.insert_transaction(read_only, self.version, read_time, now))
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
            return Err(FirestoreError::FailedPrecondition(format!(
                "read_time is older than the retained history ({READ_TIME_RETENTION_SECONDS} s)"
            )));
        };
        Ok(self.insert_transaction(true, version, read_time, now))
    }

    fn insert_transaction(
        &mut self,
        read_only: bool,
        read_version: CommitVersion,
        read_time: LogicalInstant,
        now: LogicalInstant,
    ) -> TransactionId {
        // Expired transactions are dropped here so abandoned ones never accumulate.
        let ttl = transaction_ttl();
        self.transactions
            .retain(|_, t| !t.finished && elapsed(now, t.started_at) <= ttl);
        self.next_transaction += 1;
        let id = TransactionId(self.next_transaction);
        self.transactions.insert(
            id.clone(),
            Transaction {
                read_only,
                read_version,
                read_time,
                started_at: now,
                read_set: BTreeMap::new(),
                queries: Vec::new(),
                last_activity: now,
                finished: false,
            },
        );
        id
    }

    /// Forgets a transaction that was never handed to the client (its read was refused).
    pub fn abandon_transaction(&mut self, id: &TransactionId) {
        self.transactions.remove(id);
    }

    /// Records a document read that was served from the transaction's snapshot (after the
    /// read was authorized), so that a later change aborts the commit.
    pub fn record_transaction_read(
        &mut self,
        id: &TransactionId,
        path: &DocumentPath,
        observed: Option<&Document>,
    ) -> Result<(), FirestoreError> {
        self.transaction(id)?;
        if let Some(t) = self.transactions.get_mut(id) {
            t.read_set.insert(path.clone(), observed.map(|d| d.version));
        }
        Ok(())
    }

    /// Checks that a transaction is still usable at `now` (total and idle budgets,
    /// `FS-LIMIT-TRANSACTION-TOTAL-TIME` / `FS-LIMIT-TRANSACTION-IDLE-TIME`) and records the
    /// activity. An expired transaction is finished and reported as `InvalidArgument`.
    pub fn touch_transaction(
        &mut self,
        id: &TransactionId,
        now: LogicalInstant,
    ) -> Result<(), FirestoreError> {
        let t = self.transaction(id)?;
        let expired = if elapsed(now, t.started_at) > transaction_ttl() {
            Some("transaction expired (FS-LIMIT-TRANSACTION-TOTAL-TIME)")
        } else if elapsed(now, t.last_activity) > transaction_idle_ttl() {
            Some("transaction expired (FS-LIMIT-TRANSACTION-IDLE-TIME)")
        } else {
            None
        };
        if let Some(t) = self.transactions.get_mut(id) {
            match expired {
                Some(_) => t.finished = true,
                None => t.last_activity = now,
            }
        }
        expired.map_or(Ok(()), |m| Err(FirestoreError::InvalidArgument(m.into())))
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
                .first()
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
        self.commit_times.first().map(|(_, t)| *t)
    }

    /// The retention floor at `now`: the oldest version any retention root can still reach.
    /// The roots are the one-hour `read_time` window ([`READ_TIME_RETENTION_SECONDS`]) and
    /// the read version of every transaction that is still usable.
    fn retention_floor(&self, now: LogicalInstant) -> CommitVersion {
        let window = i128::from(READ_TIME_RETENTION_SECONDS) * 1_000_000_000;
        let oldest_read = LogicalInstant::from_nanos(now.as_nanos().saturating_sub(window));
        let mut floor = self.version_at(oldest_read);
        let ttl = transaction_ttl();
        for t in self.transactions.values() {
            if t.finished || elapsed(now, t.started_at) > ttl {
                continue;
            }
            floor = floor.min(t.read_version);
        }
        floor.min(self.version)
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
        let floor = self.retention_floor(now);
        if floor <= self.compaction_floor {
            return self.compaction_floor;
        }
        self.compaction_floor = floor;
        let dropped = self.commit_times.partition_point(|(v, _)| *v < floor);
        self.commit_times.drain(..dropped);
        let mut compactable = core::mem::take(&mut self.compactable);
        compactable.retain(|path| {
            let Some(h) = self.history.get_mut(path) else {
                return false;
            };
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
                return false;
            }
            self.history
                .get(path)
                .is_some_and(|h| h.len() > 1 || matches!(h.first(), Some((_, None))))
        });
        self.compactable = compactable;
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
            Some(t) if !t.finished => Ok(t),
            Some(_) => Err(FirestoreError::InvalidArgument(
                "transaction already finished".into(),
            )),
            None => Err(FirestoreError::InvalidArgument(
                "unknown transaction".into(),
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
        let observed = doc.as_ref().map(|d| d.version);
        if let Some(t) = self.transactions.get_mut(id) {
            t.read_set.insert(path.clone(), observed);
        }
        Ok(doc)
    }

    /// Runs a query inside a transaction, recording every returned document in the read set.
    pub fn run_query_in_transaction(
        &mut self,
        id: &TransactionId,
        query: &Query,
    ) -> Result<Vec<Document>, FirestoreError> {
        let read_version = self.transaction(id)?.read_version;
        let docs = self.run_query(query, Some(read_version))?;
        if let Some(t) = self.transactions.get_mut(id) {
            for d in &docs {
                t.read_set.insert(d.path.clone(), Some(d.version));
            }
            t.queries.push((query.clone(), fingerprint(&docs)));
        }
        Ok(docs)
    }

    /// Rolls back (finishes) a transaction.
    pub fn rollback(&mut self, id: &TransactionId) -> Result<(), FirestoreError> {
        self.transaction(id)?;
        if let Some(t) = self.transactions.get_mut(id) {
            t.finished = true;
        }
        Ok(())
    }

    /// Applies `writes` atomically. With a transaction, the read set and every recorded query
    /// are validated first (`ABORTED` on conflict). Nothing is modified when an error is
    /// returned. Commit times are strictly monotonic per database even when the clock did not
    /// advance, so `update_time` preconditions cannot be satisfied by a stale timestamp.
    pub fn commit(
        &mut self,
        writes: &[Write],
        transaction: Option<&TransactionId>,
        now: LogicalInstant,
    ) -> Result<CommitResult, FirestoreError> {
        if let Some(id) = transaction {
            self.touch_transaction(id, now)?;
            let t = self.transaction(id)?;
            if t.read_only && !writes.is_empty() {
                return Err(FirestoreError::InvalidArgument(
                    "read-only transaction cannot write".into(),
                ));
            }
            if let Some(conflict) = self.transaction_conflict(t) {
                if let Some(t) = self.transactions.get_mut(id) {
                    t.finished = true;
                }
                return Err(FirestoreError::Aborted(conflict));
            }
        }

        let mut transforms_per_document: BTreeMap<&DocumentPath, u64> = BTreeMap::new();
        for write in writes {
            let n = transforms_per_document.entry(write.op.path()).or_default();
            *n += write.transforms.len() as u64;
            check_limit("FS-LIMIT-FIELD-TRANSFORMS-PER-DOCUMENT", *n)?;
        }

        // Commit times are microsecond-aligned (Firestore update-time precision) and advance
        // by one microsecond when the clock did not move between commits.
        let commit_time = self.next_commit_time(now);

        // Stage every write against a working copy; fail before touching state. A write
        // whose result equals the current document is a no-op: it keeps the existing version
        // and update time (Firestore semantics) and never creates a spurious conflict.
        let mut staged: BTreeMap<DocumentPath, (Option<Document>, bool)> = BTreeMap::new();
        let mut results = Vec::with_capacity(writes.len());
        let next_version = CommitVersion(self.version.0 + 1);
        for write in writes {
            let path = write.op.path().clone();
            let current: Option<Document> = match staged.get(&path) {
                Some((s, _)) => s.clone(),
                None => self.get(&path).cloned(),
            };
            check_precondition(write.precondition.as_ref(), current.as_ref(), &path)?;
            let (next, mut result) =
                apply_write(write, current.clone(), commit_time, next_version)?;
            if let Some(doc) = &next {
                validate_document(doc)?;
            }
            let unchanged = match (&current, &next) {
                (Some(c), Some(n)) => c.fields == n.fields,
                (None, None) => true,
                _ => false,
            };
            if unchanged {
                // A no-op Set keeps the existing update time; a verify reports none.
                if let (Some(c), false) = (&current, matches!(write.op, WriteOp::Verify { .. })) {
                    result.update_time = Some(c.update_time);
                }
                let previously_changed = staged.get(&path).is_some_and(|(_, c)| *c);
                staged.insert(path, (current, previously_changed));
            } else {
                staged.insert(path, (next, true));
            }
            results.push(result);
        }

        // Publish.
        let changed: Vec<(DocumentPath, Option<Document>)> = staged
            .into_iter()
            .filter(|(_, (_, changed))| *changed)
            .map(|(p, (d, _))| (p, d))
            .collect();
        // Every accepted commit consumes a commit time, changed documents or not.
        self.last_commit_time = Some(commit_time);
        let mut document_changes = Vec::with_capacity(changed.len());
        let version = if changed.is_empty() {
            self.version
        } else {
            self.version = next_version;
            self.commit_times.push((next_version, commit_time));
            for (path, doc) in changed {
                let before = self.get(&path).cloned();
                // A second version, or a tombstone, is something a later compaction can drop.
                let compactable = self.history.contains_key(&path) || doc.is_none();
                document_changes.push(DocumentChange {
                    path: path.clone(),
                    before,
                    after: doc.clone(),
                });
                self.history
                    .entry(path.clone())
                    .or_default()
                    .push((next_version, doc));
                if compactable {
                    self.compactable.insert(path);
                }
            }
            next_version
        };
        if let Some(id) = transaction {
            if let Some(t) = self.transactions.get_mut(id) {
                t.finished = true;
            }
        }
        // Retention is owned by the store: every commit drops the history that has fallen
        // out of the read window and is not pinned by an active transaction.
        self.compact(now);
        Ok(CommitResult {
            commit_time,
            write_results: results,
            version,
            changes: document_changes,
        })
    }

    /// First conflict between a transaction's reads and the current state, if any.
    fn transaction_conflict(&self, t: &Transaction) -> Option<String> {
        for (path, observed) in &t.read_set {
            if self.latest_version_of(path) != *observed {
                return Some(format!(
                    "document {path} changed since the transaction read it"
                ));
            }
        }
        for (query, seen) in &t.queries {
            let current = self.run_query(query, None).map(|d| fingerprint(&d));
            if current.as_ref().ok() != Some(seen) {
                return Some("query results changed since the transaction ran it".into());
            }
        }
        None
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
        current: Option<Document>,
        write: &Write,
        now: LogicalInstant,
    ) -> Result<Option<Document>, FirestoreError> {
        let (next, _) = apply_write(write, current, now, CommitVersion::default())?;
        Ok(next)
    }

    /// Result of applying `write` to the current document without publishing anything (the
    /// `request.resource` seen by Security Rules). Preconditions are not checked here.
    pub fn preview_write(
        &self,
        write: &Write,
        now: LogicalInstant,
    ) -> Result<Option<Document>, FirestoreError> {
        let current = self.get(write.op.path()).cloned();
        let (next, _) = apply_write(write, current, now, CommitVersion(self.version.0 + 1))?;
        Ok(next)
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
        let parent_len = parent.map_or(0, |p| p.pairs().len());
        self.live_documents(version)
            .filter(|d| {
                d.path.pairs().len() == parent_len + 1
                    && d.path.collection_id().as_str() == collection_id
                    && parent.is_none_or(|p| d.path.pairs()[..parent_len] == *p.pairs())
            })
            .cloned()
            .collect()
    }

    /// Collection IDs directly under `parent` (root when `None`), sorted.
    #[must_use]
    pub fn list_collection_ids(&self, parent: Option<&DocumentPath>) -> Vec<String> {
        let parent_len = parent.map_or(0, |p| p.pairs().len());
        let ids: BTreeSet<String> = self
            .live_documents(None)
            .filter(|d| {
                d.path.pairs().len() > parent_len
                    && parent.is_none_or(|p| d.path.pairs()[..parent_len] == *p.pairs())
            })
            .map(|d| d.path.pairs()[parent_len].0.as_str().to_owned())
            .collect();
        ids.into_iter().collect()
    }

    /// Executes a canonical query at `version` (latest when `None`).
    pub fn run_query(
        &self,
        query: &Query,
        version: Option<CommitVersion>,
    ) -> Result<Vec<Document>, FirestoreError> {
        Ok(self.run_query_with_stats(query, version)?.0)
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
        let scope = &query.scope;
        let parent_len = scope.parent.as_ref().map_or(0, |p| p.pairs().len());
        let order = query.effective_order_by();
        let offset = usize::try_from(query.offset).unwrap_or(usize::MAX);
        // `offset + limit` rows are enough to answer a query with a finite limit: everything
        // beyond them is dropped by the truncation anyway.
        let bound = query
            .limit
            .map(|l| usize::try_from(u64::from(query.offset) + u64::from(l)).unwrap_or(usize::MAX));
        let mut stats = QueryStats::default();
        let mut heap: BinaryHeap<Candidate<'_>> = BinaryHeap::new();
        let mut rows: Vec<Candidate<'_>> = Vec::new();
        for doc in self.live_documents(version) {
            stats.scanned += 1;
            let in_scope = if scope.all_descendants {
                doc.path.collection_id() == &scope.collection_id
            } else {
                doc.path.pairs().len() == parent_len + 1
                    && doc.path.collection_id() == &scope.collection_id
                    && scope
                        .parent
                        .as_ref()
                        .is_none_or(|p| doc.path.pairs()[..parent_len] == *p.pairs())
            };
            if !in_scope {
                continue;
            }
            if let Some(f) = &query.filter {
                if !eval_filter(f, doc)? {
                    continue;
                }
            }
            let Some(key) = order_key(doc, &order) else {
                continue;
            };
            // Cursors are a predicate on the order key alone, so they are applied before the
            // selection instead of after a full sort.
            if !cursor_admits(&key, query.start_at.as_ref(), query.end_at.as_ref(), &order) {
                continue;
            }
            stats.matched += 1;
            let candidate = Candidate {
                key,
                doc,
                order: &order,
            };
            match bound {
                Some(0) => {}
                Some(k) if heap.len() >= k => {
                    // The heap holds the `k` smallest rows seen so far; its root is the
                    // largest of them.
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
        let mut selected: Vec<Candidate<'_>> = if bound.is_some() {
            heap.into_sorted_vec()
        } else {
            rows.sort_by(|a, b| compare_keys(&a.key, &b.key, &order));
            rows
        };
        if offset > 0 {
            selected.drain(..offset.min(selected.len()));
        }
        if let Some(limit) = query.limit {
            selected.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        stats.cloned_documents = selected.len() as u64;
        let mut out: Vec<Document> = selected.into_iter().map(|c| c.doc.clone()).collect();
        if let Some(projection) = &query.projection {
            for d in &mut out {
                d.fields = project(&d.fields, projection);
            }
        }
        Ok((out, stats))
    }

    /// Runs aggregations over the query results.
    pub fn run_aggregation(
        &self,
        query: &Query,
        aggregations: &[Aggregation],
        version: Option<CommitVersion>,
    ) -> Result<Vec<Value>, FirestoreError> {
        let docs = self.run_query(query, version)?;
        aggregations
            .iter()
            .map(|a| {
                Ok(match a {
                    Aggregation::Count { up_to } => {
                        let n = docs.len() as u64;
                        Value::Integer(
                            i64::try_from(up_to.map_or(n, |cap| n.min(cap))).unwrap_or(i64::MAX),
                        )
                    }
                    Aggregation::Sum(field) => sum_values(&docs, field).0,
                    Aggregation::Avg(field) => {
                        let (sum, count) = sum_values(&docs, field);
                        if count == 0 {
                            Value::Null
                        } else {
                            #[allow(clippy::cast_precision_loss)]
                            let total = match sum {
                                Value::Integer(i) => i as f64,
                                Value::Double(d) => d,
                                _ => 0.0,
                            };
                            #[allow(clippy::cast_precision_loss)]
                            let divisor = count as f64;
                            Value::Double(total / divisor)
                        }
                    }
                })
            })
            .collect()
    }
}

fn fingerprint(docs: &[Document]) -> Vec<(DocumentPath, CommitVersion)> {
    docs.iter().map(|d| (d.path.clone(), d.version)).collect()
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

fn apply_write(
    write: &Write,
    current: Option<Document>,
    now: LogicalInstant,
    version: CommitVersion,
) -> Result<(Option<Document>, WriteResult), FirestoreError> {
    match &write.op {
        WriteOp::Verify { .. } => {
            if !write.transforms.is_empty() {
                return Err(FirestoreError::InvalidArgument(
                    "transforms on a verify".into(),
                ));
            }
            // Precondition already checked by the caller; nothing changes.
            Ok((
                current,
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
                (None, _) => fields.clone(),
                (Some(mask), current) => {
                    let mut base = current.map(|d| d.fields).unwrap_or_default();
                    for p in mask {
                        match get_field(fields, p) {
                            Some(v) => set_field(&mut base, p, v.clone()),
                            None => delete_field(&mut base, p),
                        }
                    }
                    base
                }
            };
            check_limit(
                "FS-LIMIT-FIELD-TRANSFORMS-PER-DOCUMENT",
                write.transforms.len() as u64,
            )?;
            let mut transform_results = Vec::with_capacity(write.transforms.len());
            for t in &write.transforms {
                let produced = apply_transform(&mut next_fields, t, now)?;
                transform_results.push(produced);
            }
            let doc = Document {
                path: path.clone(),
                fields: next_fields,
                create_time,
                update_time: now,
                version,
            };
            Ok((
                Some(doc),
                WriteResult {
                    update_time: Some(now),
                    transform_results,
                },
            ))
        }
    }
}

fn validate_document(doc: &Document) -> Result<(), FirestoreError> {
    for (name, value) in &doc.fields {
        FieldPath::from_segments([name.as_str()])
            .map_err(|e| FirestoreError::InvalidArgument(format!("field name {name:?}: {e}")))?;
        check_limit(
            "FS-LIMIT-NESTED-MAP-ARRAY-DEPTH",
            u64::from(value.nesting_depth()),
        )?;
    }
    let size = document_size(&doc.path, &doc.fields)
        .map_err(|e| FirestoreError::InvalidArgument(e.to_string()))?;
    check_limit("FS-LIMIT-DOCUMENT-BYTES", size.total)
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
                if !arr.iter().any(|x| x.canonical_cmp(item) == Ordering::Equal) {
                    arr.push(item.clone());
                }
            }
            Value::Array(arr)
        }
        TransformKind::RemoveAllFromArray(items) => {
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
struct Candidate<'a> {
    key: Vec<FieldRef<'a>>,
    doc: &'a Document,
    order: &'a [OrderClause],
}

impl PartialEq for Candidate<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Candidate<'_> {}

impl PartialOrd for Candidate<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Candidate<'_> {
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
                    matches!(value, Value::Array(candidates) if candidates.iter().any(|c| equal_ref(v, c)))
                }
                FieldOp::NotIn => {
                    // `not-in` never matches null fields, and a null candidate matches nothing.
                    matches!(value, Value::Array(candidates)
                        if !candidates.iter().any(|c| equal_ref(v, c) || matches!(c, Value::Null)))
                        && !v.is_null()
                }
                FieldOp::ArrayContainsAny => match (v.stored(), value) {
                    (Some(Value::Array(items)), Value::Array(candidates)) => {
                        items.iter().any(|i| candidates.iter().any(|c| equal(i, c)))
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

/// Sum of numeric values of `field` and the number of numeric contributors.
fn sum_values(docs: &[Document], field: &FieldPath) -> (Value, u64) {
    let mut sum = Value::Integer(0);
    let mut count = 0u64;
    for d in docs {
        if let Some(v) = get_field(&d.fields, field) {
            if is_number(v) {
                sum = add_numbers(&sum, v);
                count += 1;
            }
        }
    }
    (sum, count)
}
