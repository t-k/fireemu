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
use std::collections::{BTreeMap, BTreeSet};

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

/// Monotonic commit version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CommitVersion(u64);

impl CommitVersion {
    /// Raw value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
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
    /// Commit time of every published version (`read_time` snapshots).
    commit_times: Vec<(CommitVersion, LogicalInstant)>,
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
    /// committed at or before it); its budgets still run from `now`.
    pub fn begin_transaction_at(
        &mut self,
        read_time: LogicalInstant,
        now: LogicalInstant,
    ) -> Result<TransactionId, FirestoreError> {
        let version = self.version_at(read_time);
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
    /// database before the first commit).
    #[must_use]
    pub fn version_at(&self, at: LogicalInstant) -> CommitVersion {
        let idx = self
            .commit_times
            .partition_point(|(_, t)| t.as_nanos() <= at.as_nanos());
        idx.checked_sub(1)
            .and_then(|i| self.commit_times.get(i))
            .map_or(CommitVersion::default(), |(v, _)| *v)
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
                document_changes.push(DocumentChange {
                    path: path.clone(),
                    before,
                    after: doc.clone(),
                });
                self.history
                    .entry(path)
                    .or_default()
                    .push((next_version, doc));
            }
            next_version
        };
        if let Some(id) = transaction {
            if let Some(t) = self.transactions.get_mut(id) {
                t.finished = true;
            }
        }
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
        let scope = &query.scope;
        let parent_len = scope.parent.as_ref().map_or(0, |p| p.pairs().len());
        let order = query.effective_order_by();
        let mut rows: Vec<(Vec<Value>, Document)> = Vec::new();
        for doc in self.live_documents(version) {
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
            rows.push((key, doc.clone()));
        }
        rows.sort_by(|a, b| compare_keys(&a.0, &b.0, &order));
        let mut selected: Vec<Document> = rows
            .into_iter()
            .filter(|(key, _)| {
                cursor_admits(key, query.start_at.as_ref(), query.end_at.as_ref(), &order)
            })
            .map(|(_, d)| d)
            .collect();
        let offset = usize::try_from(query.offset).unwrap_or(usize::MAX);
        if offset > 0 {
            selected.drain(..offset.min(selected.len()));
        }
        if let Some(limit) = query.limit {
            selected.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        if let Some(projection) = &query.projection {
            for d in &mut selected {
                d.fields = project(&d.fields, projection);
            }
        }
        Ok(selected)
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
            // REQUEST_TIME is documented with millisecond precision.
            let millis = now.as_nanos().div_euclid(1_000_000);
            let secs = i64::try_from(millis.div_euclid(1_000))
                .map_err(|_| FirestoreError::InvalidArgument("commit time out of range".into()))?;
            let nanos = u32::try_from(millis.rem_euclid(1_000) * 1_000_000).unwrap_or(0);
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

fn field_value(doc: &Document, path: &FieldPath) -> Option<Value> {
    if path.is_document_name() {
        return Some(Value::Reference(doc.path.resource_name()));
    }
    get_field(&doc.fields, path).cloned()
}

fn same_type(a: &Value, b: &Value) -> bool {
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
                UnaryOp::IsNull => matches!(v, Some(Value::Null)),
                UnaryOp::IsNotNull => matches!(v, Some(x) if x != Value::Null),
                UnaryOp::IsNan => matches!(v, Some(Value::Double(d)) if d.is_nan()),
                UnaryOp::IsNotNan => {
                    matches!(v, Some(x) if !matches!(x, Value::Double(d) if d.is_nan()))
                }
            }
        }
        FilterExpr::Field { field, op, value } => {
            let Some(v) = field_value(doc, field) else {
                return Ok(false);
            };
            match op {
                FieldOp::Equal => equal(&v, value),
                FieldOp::NotEqual => !equal(&v, value) && !matches!(v, Value::Null),
                FieldOp::LessThan
                | FieldOp::LessThanOrEqual
                | FieldOp::GreaterThan
                | FieldOp::GreaterThanOrEqual => {
                    if !same_type(&v, value) || matches!(v, Value::Double(d) if d.is_nan()) {
                        return Ok(false);
                    }
                    let ord = v.canonical_cmp(value);
                    match op {
                        FieldOp::LessThan => ord == Ordering::Less,
                        FieldOp::LessThanOrEqual => ord != Ordering::Greater,
                        FieldOp::GreaterThan => ord == Ordering::Greater,
                        _ => ord != Ordering::Less,
                    }
                }
                FieldOp::ArrayContains => {
                    matches!(&v, Value::Array(items) if items.iter().any(|i| equal(i, value)))
                }
                FieldOp::In => {
                    matches!(value, Value::Array(candidates) if candidates.iter().any(|c| equal(&v, c)))
                }
                FieldOp::NotIn => {
                    // `not-in` never matches null fields, and a null candidate matches nothing.
                    matches!(value, Value::Array(candidates)
                        if !candidates.iter().any(|c| equal(&v, c) || matches!(c, Value::Null)))
                        && !matches!(v, Value::Null)
                }
                FieldOp::ArrayContainsAny => match (&v, value) {
                    (Value::Array(items), Value::Array(candidates)) => {
                        items.iter().any(|i| candidates.iter().any(|c| equal(i, c)))
                    }
                    _ => false,
                },
            }
        }
    })
}

fn order_key(doc: &Document, order: &[OrderClause]) -> Option<Vec<Value>> {
    order.iter().map(|o| field_value(doc, &o.field)).collect()
}

fn compare_keys(a: &[Value], b: &[Value], order: &[OrderClause]) -> Ordering {
    for ((x, y), clause) in a.iter().zip(b).zip(order) {
        let ord = x.canonical_cmp(y);
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
    key: &[Value],
    start: Option<&Cursor>,
    end: Option<&Cursor>,
    order: &[OrderClause],
) -> bool {
    if let Some(c) = start {
        let n = c.values.len().min(key.len());
        let ord = compare_keys(&key[..n], &c.values[..n], &order[..n]);
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
        let n = c.values.len().min(key.len());
        let ord = compare_keys(&key[..n], &c.values[..n], &order[..n]);
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
