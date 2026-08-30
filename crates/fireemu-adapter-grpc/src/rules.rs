//! Firestore Security Rules enforcement shared by the gRPC service, the streams and the
//! REST surface.
//!
//! `Authorization: Bearer owner` (Admin SDK against an emulator) bypasses rules. Any other
//! bearer token is verified as an ID token against the shared [`AuthStore`] (issuer,
//! audience, expiry, revocation) and becomes `request.auth`. A request without a token is
//! evaluated as unauthenticated. When no ruleset is loaded every request is allowed (the
//! runtime prints a warning at start).
//!
//! Reads are authorized against the exact snapshot that is returned; writes are authorized
//! inside the database critical section that commits them, against the sequentially staged
//! state of the commit (a second write to a document created earlier in the same commit is
//! an `update`).
//!
//! Queries (`list`, `ListDocuments`, aggregations, `Listen` query targets) are authorized
//! from their constraints, not from their results: for every disjunction of the query's
//! disjunctive normal form a synthetic `resource` is built from the equality /
//! `array-contains` constraints and the rule must accept it (`RULES-QUERY-CONSTRAINTS`).
//! A rule that reads a field the query does not constrain fails closed, as it does in
//! production; inequality constraints become ranges, `in` a set of candidates, `!=` /
//! `not-in` an exclusion set, and `request.query` carries `limit`, `offset` and `orderBy`
//! (`"field ASC, other DESC"`, the Emulator's rendering). The decision never depends on
//! stored data, so it leaks nothing about it.
//!
//! Writes serve `getAfter()` from the state every write of the commit will leave behind.

// `tonic::Status` is the error type dictated by the generated trait.
#![allow(clippy::result_large_err)]

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, RwLock};

use fireemu_core_auth::jwt::verify_id_token_decoded;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{Direction, FieldOp, FilterExpr, Query, UnaryOp};
use fireemu_core_firestore::store::{CommitVersion, Document, FirestoreState, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_rules::ast::Ruleset;
use fireemu_core_rules::eval::{
    evaluate_request_with, try_compare, Decision, DenyReason, DocumentAccess, Method,
    RequestContext, RulesService, ABSTRACT_PREFIX, ABSTRACT_SEGMENT,
};
use fireemu_core_rules::runtime::LoadedRules;
use fireemu_core_rules::value::{AuthContext, RangeBound, RulesValue, ValueRange};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::Clock;
use fireemu_core_types::time::LogicalInstant;
use tonic::metadata::MetadataMap;
use tonic::Status;

use crate::decode::Parent;

/// `get()` / `exists()` over a database snapshot (inside a read's or commit's critical
/// section, or a `Listen` refresh); `version` selects the snapshot served (`None` = latest).
pub struct StateReader<'a> {
    /// Database.
    pub db: &'a FirestoreState,
    /// Project / database of the request.
    pub parent: &'a Parent,
    /// Snapshot version the request is served from.
    pub version: Option<CommitVersion>,
}

/// Rules path segments (`databases/{db}/documents/...`) → document path in the request's
/// project. Other databases are unreachable (`None`).
fn rules_segments_to_path(parent: &Parent, segments: &[String]) -> Option<DocumentPath> {
    let [db_literal, db, docs_literal, rest @ ..] = segments else {
        return None;
    };
    if db_literal != "databases"
        || docs_literal != "documents"
        || rest.is_empty()
        || rest.len() % 2 != 0
    {
        return None;
    }
    if db != parent.database.as_str() {
        return None;
    }
    DocumentPath::parse(&parent.project, &parent.database, &rest.join("/")).ok()
}

impl DocumentAccess for StateReader<'_> {
    fn get(&self, segments: &[String]) -> Option<RulesValue> {
        let path = rules_segments_to_path(self.parent, segments)?;
        match self.version {
            Some(v) => self.db.get_at(&path, v).map(resource_value),
            None => self.db.get(&path).map(resource_value),
        }
    }
}

/// Document accesses of one multi-document request, shared by every operation's evaluation
/// (`RULES-DOC-ACCESS-MULTI-TOTAL`); each operation keeps its own per-operation cache and
/// budget.
struct AggregateReader<'a> {
    inner: &'a dyn DocumentAccess,
    seen: RefCell<BTreeSet<Vec<String>>>,
}

impl DocumentAccess for AggregateReader<'_> {
    fn get(&self, segments: &[String]) -> Option<RulesValue> {
        if let Ok(mut seen) = self.seen.try_borrow_mut() {
            seen.insert(segments.to_vec());
        }
        self.inner.get(segments)
    }

    fn get_after(&self, segments: &[String]) -> Option<Option<RulesValue>> {
        if let Ok(mut seen) = self.seen.try_borrow_mut() {
            // A distinct access from `get()` of the same path.
            let mut key = vec![AFTER_MARKER.to_owned()];
            key.extend_from_slice(segments);
            seen.insert(key);
        }
        self.inner.get_after(segments)
    }
}

/// Segment prefix distinguishing `getAfter()` accesses in the aggregate budget.
const AFTER_MARKER: &str = "\u{0}after";

/// `get()` over the current state and `getAfter()` over the state the commit being
/// authorized will leave behind (every write of the batch applied).
struct WriteReader<'a> {
    db: &'a FirestoreState,
    parent: &'a Parent,
    after: &'a BTreeMap<DocumentPath, Option<Document>>,
}

impl DocumentAccess for WriteReader<'_> {
    fn get(&self, segments: &[String]) -> Option<RulesValue> {
        let path = rules_segments_to_path(self.parent, segments)?;
        self.db.get(&path).map(resource_value)
    }

    fn get_after(&self, segments: &[String]) -> Option<Option<RulesValue>> {
        let Some(path) = rules_segments_to_path(self.parent, segments) else {
            return Some(None);
        };
        Some(match self.after.get(&path) {
            Some(staged) => staged.as_ref().map(resource_value),
            None => self.db.get(&path).map(resource_value),
        })
    }
}

/// `get()` / `exists()` over the latest state of one database for callers outside the
/// Firestore surfaces (Storage rules' `firestore.get()`). The caller already holds a
/// session admission; the read takes only the database lock.
pub struct LatestReader {
    /// Backend.
    pub backend: Arc<crate::local::LocalBackend>,
    /// Project / database the rules paths resolve in.
    pub parent: Parent,
}

impl DocumentAccess for LatestReader {
    fn get(&self, segments: &[String]) -> Option<RulesValue> {
        let path = rules_segments_to_path(&self.parent, segments)?;
        self.backend
            .read_unadmitted(&self.parent, |db| db.get(&path).map(resource_value))
            .flatten()
    }
}

/// Maximum distinct `get()` / `exists()` documents of one single-document or query request.
fn single_max() -> u64 {
    limit_value("RULES-DOC-ACCESS-SINGLE", 10)
}

/// Maximum distinct `get()` / `exists()` documents across one multi-document request.
fn multi_total_max() -> u64 {
    limit_value("RULES-DOC-ACCESS-MULTI-TOTAL", 20)
}

fn limit_value(id: &str, fallback: u64) -> u64 {
    fireemu_core_limits::catalogs::ALL_CATALOGS
        .iter()
        .find_map(|c| c.find(id))
        .and_then(|l| match l.maximum {
            fireemu_core_limits::model::LimitMaximum::Fixed(v) => Some(v),
            _ => None,
        })
        .unwrap_or(fallback)
}

/// The emulator's owner credential: `Authorization: Bearer owner`.
pub const OWNER_TOKEN: &str = "owner";

/// Whether the caller presented the emulator's exact owner credential.
///
/// [`RulesEnforcer::principal_from_authorization`] maps exactly this value to
/// [`Principal::Owner`], but it is only consulted while Security Rules are enforced: with
/// rules disabled every caller becomes the owner without presenting anything. That is not an
/// App Check bypass (specification section 12.2), so the App Check path verifies the
/// credential itself, through this function, whatever the rules configuration is.
#[must_use]
pub fn is_owner_credential(authorization: Option<&str>) -> bool {
    authorization
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|token| token == OWNER_TOKEN)
}

/// Who is making the request.
#[derive(Debug, Clone, PartialEq)]
pub enum Principal {
    /// Admin credentials: rules are bypassed.
    Owner,
    /// A verified end user.
    User(AuthContext),
    /// No credentials.
    Anonymous,
}

/// Authorization hook run inside the database critical section before a commit.
pub type WriteGuard<'a> =
    &'a dyn Fn(&FirestoreState, &[Write], LogicalInstant) -> Result<(), Status>;

/// Owned write guard (see [`write_guard`]).
pub type BoxedWriteGuard<'a> =
    Box<dyn Fn(&FirestoreState, &[Write], LogicalInstant) -> Result<(), Status> + 'a>;

/// What a read guard authorizes, against the snapshot being served.
pub enum ReadCheck<'a> {
    /// One document read (`get`).
    Document {
        /// Document.
        path: &'a DocumentPath,
        /// The document as it will be returned.
        snapshot: Option<&'a Document>,
    },
    /// A multi-document read (`BatchGetDocuments`): every item is a `get`, and the items
    /// share the `RULES-DOC-ACCESS-MULTI-TOTAL` budget.
    Documents(&'a [(DocumentPath, Option<Document>)]),
    /// A query (`list`), proven from its constraints.
    Query {
        /// Project / database of the request.
        parent: &'a Parent,
        /// Accepted query.
        query: &'a Query,
    },
}

/// Authorization hook run inside the database critical section of a read: `version` is
/// the snapshot version served (`None` = latest), so `get()` / `exists()` in the rules see
/// exactly the state the response is built from.
pub type ReadGuard<'a> =
    &'a dyn Fn(&FirestoreState, Option<CommitVersion>, ReadCheck<'_>) -> Result<(), Status>;

/// Owned read guard (see [`read_guard`]).
pub type BoxedReadGuard<'a> =
    Box<dyn Fn(&FirestoreState, Option<CommitVersion>, ReadCheck<'_>) -> Result<(), Status> + 'a>;

/// A read guard that allows everything (no rules configured / owner).
pub fn allow_all_reads(
    _: &FirestoreState,
    _: Option<CommitVersion>,
    _: ReadCheck<'_>,
) -> Result<(), Status> {
    Ok(())
}

/// Builds the read guard for `principal`.
pub fn read_guard<'a>(
    rules: Option<&'a Arc<RulesEnforcer>>,
    principal: &'a Principal,
) -> BoxedReadGuard<'a> {
    match rules {
        Some(r) => Box::new(move |db, version, check| match check {
            ReadCheck::Document { path, snapshot } => {
                let parent = Parent {
                    project: path.project().clone(),
                    database: path.database().clone(),
                    document: None,
                };
                let reader = StateReader {
                    db,
                    parent: &parent,
                    version,
                };
                r.authorize_get(principal, path, snapshot, &reader)
            }
            ReadCheck::Documents(items) => {
                let Some((first, _)) = items.first() else {
                    return Ok(());
                };
                let parent = Parent {
                    project: first.project().clone(),
                    database: first.database().clone(),
                    document: None,
                };
                let reader = StateReader {
                    db,
                    parent: &parent,
                    version,
                };
                r.authorize_gets(principal, items, &reader)
            }
            ReadCheck::Query { parent, query } => {
                let reader = StateReader {
                    db,
                    parent,
                    version,
                };
                r.authorize_query(principal, parent, query, &reader)
            }
        }),
        None => Box::new(allow_all_reads),
    }
}

/// A guard that allows everything (no rules configured / owner).
pub fn allow_all(_: &FirestoreState, _: &[Write], _: LogicalInstant) -> Result<(), Status> {
    Ok(())
}

/// Production Firestore accepts only ID tokens minted for the requested project: a token
/// whose `aud` names another project (another session's) is refused before any rule
/// runs, so `request.auth != null` never holds across sessions.
pub fn check_audience(principal: &Principal, project: &str) -> Result<(), Status> {
    let Principal::User(ctx) = principal else {
        return Ok(());
    };
    match ctx.token.get("aud") {
        Some(fireemu_core_rules::value::RulesValue::String(aud)) if aud == project => Ok(()),
        Some(fireemu_core_rules::value::RulesValue::String(aud)) => Err(Status::unauthenticated(
            format!("ID token audience {aud:?} does not match project {project:?}"),
        )),
        _ => Err(Status::unauthenticated("ID token has no audience claim")),
    }
}

/// Rules enforcement state shared by every surface.
pub struct RulesEnforcer {
    rules: Arc<RwLock<LoadedRules>>,
    auth: Arc<Mutex<AuthStore>>,
    clock: Arc<Mutex<VirtualClock>>,
    /// Stores of the other session projects (tokens are verified against the store of
    /// their `aud`).
    registry: Option<Arc<fireemu_core_auth::store::AuthRegistry>>,
}

impl RulesEnforcer {
    /// Creates the enforcer over the shared rules, user store and clock.
    #[must_use]
    pub fn new(
        rules: Arc<RwLock<LoadedRules>>,
        auth: Arc<Mutex<AuthStore>>,
        clock: Arc<Mutex<VirtualClock>>,
    ) -> Self {
        Self {
            rules,
            auth,
            clock,
            registry: None,
        }
    }

    /// Verifies tokens of every registered session project, not only the default one.
    #[must_use]
    pub fn with_registry(mut self, registry: Arc<fireemu_core_auth::store::AuthRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    fn now(&self) -> Result<LogicalInstant, Status> {
        self.clock
            .lock()
            .map(|c| c.now())
            .map_err(|_| Status::internal("clock lock poisoned"))
    }

    /// Whether a ruleset is loaded (poisoned state is an error, never "no rules").
    pub fn loaded(&self) -> Result<bool, Status> {
        self.rules
            .read()
            .map(|r| r.is_loaded())
            .map_err(|_| Status::internal("rules lock poisoned"))
    }

    /// Resolves the caller from the request metadata.
    pub fn principal(&self, metadata: &MetadataMap) -> Result<Principal, Status> {
        let Some(value) = metadata.get("authorization") else {
            return Ok(Principal::Anonymous);
        };
        let value = value
            .to_str()
            .map_err(|_| Status::unauthenticated("malformed authorization metadata"))?;
        self.principal_from_authorization(Some(value))
    }

    /// Resolves the caller from an `Authorization` header value.
    pub fn principal_from_authorization(&self, value: Option<&str>) -> Result<Principal, Status> {
        let Some(value) = value else {
            return Ok(Principal::Anonymous);
        };
        let token = value
            .strip_prefix("Bearer ")
            .ok_or_else(|| Status::unauthenticated("authorization must be a Bearer token"))?;
        if token == OWNER_TOKEN {
            return Ok(Principal::Owner);
        }
        let now = self.now()?;
        // The token's audience names its project: verify against that project's store.
        let store_arc = match &self.registry {
            Some(registry) => {
                let default = self
                    .auth
                    .lock()
                    .map_err(|_| Status::internal("auth store lock poisoned"))?;
                let aud = fireemu_core_auth::jwt::decode_token(token, default.signer())
                    .ok()
                    .and_then(|d| {
                        d.payload
                            .get("aud")
                            .and_then(fireemu_core_types::json::JsonValue::as_str)
                            .map(str::to_owned)
                    });
                drop(default);
                aud.and_then(|a| registry.store_for(&a))
                    .unwrap_or_else(|| self.auth.clone())
            }
            None => self.auth.clone(),
        };
        let store = store_arc
            .lock()
            .map_err(|_| Status::internal("auth store lock poisoned"))?;
        let (_, decoded) = verify_id_token_decoded(token, &store, now)
            .map_err(|e| Status::unauthenticated(format!("invalid ID token: {e}")))?;
        drop(store);
        let ctx = AuthContext::from_id_token_json(&decoded.payload_json)
            .map_err(|e| Status::unauthenticated(format!("invalid ID token claims: {e}")))?;
        Ok(Principal::User(ctx))
    }

    /// Owner-only surfaces (collection enumeration) while rules are loaded.
    pub fn require_owner(&self, principal: &Principal, what: &str) -> Result<(), Status> {
        if matches!(principal, Principal::Owner) || !self.loaded()? {
            return Ok(());
        }
        Err(Status::permission_denied(format!(
            "{what} requires admin credentials while Security Rules are enforced"
        )))
    }

    /// Runs the loaded ruleset for one request; `Ok(())` = allowed.
    fn evaluate(
        &self,
        principal: &Principal,
        method: Method,
        path: &DocumentPath,
        resource: Option<&Document>,
        request_resource: Option<&Document>,
        access: &dyn DocumentAccess,
    ) -> Result<(), Status> {
        if matches!(principal, Principal::Owner) {
            return Ok(());
        }
        let rules = self
            .rules
            .read()
            .map_err(|_| Status::internal("rules lock poisoned"))?;
        let Some(ruleset) = &rules.ruleset else {
            return Ok(());
        };
        let now = self.now()?;
        evaluate_with(
            ruleset,
            principal,
            method,
            path,
            resource,
            request_resource,
            now,
            access,
        )
    }

    /// Authorizes a single-document read against the snapshot that will be returned;
    /// `access` serves `get()` / `exists()` in the rules.
    pub fn authorize_get(
        &self,
        principal: &Principal,
        path: &DocumentPath,
        snapshot: Option<&Document>,
        access: &dyn DocumentAccess,
    ) -> Result<(), Status> {
        check_audience(principal, path.project().as_str())?;
        self.evaluate(principal, Method::Get, path, snapshot, None, access)
    }

    /// Authorizes a multi-document read: each item is a `get` with its own per-operation
    /// budget, and the distinct documents accessed across the items are limited by
    /// `RULES-DOC-ACCESS-MULTI-TOTAL`.
    pub fn authorize_gets(
        &self,
        principal: &Principal,
        items: &[(DocumentPath, Option<Document>)],
        access: &dyn DocumentAccess,
    ) -> Result<(), Status> {
        if let Some((first, _)) = items.first() {
            check_audience(principal, first.project().as_str())?;
        }
        if matches!(principal, Principal::Owner) {
            return Ok(());
        }
        let rules = self
            .rules
            .read()
            .map_err(|_| Status::internal("rules lock poisoned"))?;
        let Some(ruleset) = &rules.ruleset else {
            return Ok(());
        };
        let now = self.now()?;
        let reader = AggregateReader {
            inner: access,
            seen: RefCell::new(BTreeSet::new()),
        };
        let multi_total = multi_total_max();
        for (path, snapshot) in items {
            evaluate_with(
                ruleset,
                principal,
                Method::Get,
                path,
                snapshot.as_ref(),
                None,
                now,
                &reader,
            )?;
            let accessed = reader.seen.borrow().len() as u64;
            if items.len() > 1 && accessed > multi_total {
                return Err(Status::permission_denied(format!(
                    "get on {} denied by Security Rules: RULES-DOC-ACCESS-MULTI-TOTAL: {accessed} exceeds {multi_total}",
                    path.relative()
                )));
            }
        }
        Ok(())
    }

    /// Authorizes a query from its constraints (see the module documentation). One ruleset
    /// snapshot, one request time and one `get()` / `exists()` budget serve every proof
    /// (placeholder depth and disjunction); collection-group queries are proven at more than
    /// one depth, so a rule has to cover the group with a recursive wildcard as in
    /// production.
    pub fn authorize_query(
        &self,
        principal: &Principal,
        parent: &Parent,
        query: &Query,
        access: &dyn DocumentAccess,
    ) -> Result<(), Status> {
        check_audience(principal, parent.project.as_str())?;
        if matches!(principal, Principal::Owner) {
            return Ok(());
        }
        let rules = self
            .rules
            .read()
            .map_err(|_| Status::internal("rules lock poisoned"))?;
        let Some(ruleset) = &rules.ruleset else {
            return Ok(());
        };
        let now = self.now()?;
        let reader = AggregateReader {
            inner: access,
            seen: RefCell::new(BTreeSet::new()),
        };
        let single_max = single_max();
        for placeholder in placeholder_paths(parent, query)? {
            for disjunction in query.dnf() {
                let ctx = RequestContext {
                    service: RulesService::Firestore,
                    method: Method::List,
                    path: rules_path(&placeholder),
                    auth: match principal {
                        Principal::User(a) => Some(a.clone()),
                        _ => None,
                    },
                    resource: Some(abstract_resource(&disjunction)),
                    request_resource: None,
                    time_unix_nanos: now.as_nanos(),
                    abstract_path: true,
                    request_query: Some(query_value(query)),
                };
                decide(ruleset, &ctx, Method::List, &placeholder, &reader)?;
                let accessed = reader.seen.borrow().len() as u64;
                if accessed > single_max {
                    return Err(Status::permission_denied(format!(
                        "list on {} denied by Security Rules: RULES-DOC-ACCESS-SINGLE: {accessed} exceeds {single_max}",
                        placeholder.relative()
                    )));
                }
            }
        }
        Ok(())
    }

    /// Authorizes the writes of one commit against the sequentially staged state `db` will
    /// see, at the commit time the commit will receive. Meant to run inside the database
    /// critical section (see [`WriteGuard`]); one ruleset snapshot serves every write.
    pub fn authorize_writes_in(
        &self,
        principal: &Principal,
        parent: &Parent,
        db: &FirestoreState,
        writes: &[Write],
        now: LogicalInstant,
    ) -> Result<(), Status> {
        check_audience(principal, parent.project.as_str())?;
        if matches!(principal, Principal::Owner) {
            return Ok(());
        }
        let rules = self
            .rules
            .read()
            .map_err(|_| Status::internal("rules lock poisoned"))?;
        let Some(ruleset) = &rules.ruleset else {
            return Ok(());
        };
        let at = db.next_commit_time(now);
        // The state after the whole commit, for `getAfter()`.
        let mut after: BTreeMap<DocumentPath, Option<Document>> = BTreeMap::new();
        for write in writes {
            if matches!(write.op, WriteOp::Verify { .. }) {
                continue;
            }
            let path = write.op.path();
            let current = match after.get(path) {
                Some(s) => s.clone(),
                None => db.get(path).cloned(),
            };
            let next = match &write.op {
                WriteOp::Delete { .. } => None,
                _ => FirestoreState::preview_from(current, write, at)
                    .map_err(|e| crate::encode::status_from_error(&e))?,
            };
            after.insert(path.clone(), next);
        }
        let state_reader = WriteReader {
            db,
            parent,
            after: &after,
        };
        let reader = AggregateReader {
            inner: &state_reader,
            seen: RefCell::new(BTreeSet::new()),
        };
        let multi_total = multi_total_max();
        let mut staged: BTreeMap<DocumentPath, Option<Document>> = BTreeMap::new();
        for write in writes {
            let path = write.op.path();
            let current = match staged.get(path) {
                Some(s) => s.clone(),
                None => db.get(path).cloned(),
            };
            let (method, preview) = match &write.op {
                WriteOp::Delete { .. } => (Method::Delete, None),
                // A verify is a transactional read of the document.
                WriteOp::Verify { .. } => (Method::Get, None),
                WriteOp::Set { .. } => (
                    if current.is_some() {
                        Method::Update
                    } else {
                        Method::Create
                    },
                    FirestoreState::preview_from(current.clone(), write, at)
                        .map_err(|e| crate::encode::status_from_error(&e))?,
                ),
            };
            evaluate_with(
                ruleset,
                principal,
                method,
                path,
                current.as_ref(),
                preview.as_ref(),
                at,
                &reader,
            )?;
            let accessed = reader.seen.borrow().len() as u64;
            if writes.len() > 1 && accessed > multi_total {
                return Err(Status::permission_denied(format!(
                    "{} on {} denied by Security Rules: RULES-DOC-ACCESS-MULTI-TOTAL: {accessed} exceeds {multi_total}",
                    method_name(method),
                    path.relative()
                )));
            }
            if !matches!(write.op, WriteOp::Verify { .. }) {
                staged.insert(path.clone(), preview);
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_with(
    ruleset: &Ruleset,
    principal: &Principal,
    method: Method,
    path: &DocumentPath,
    resource: Option<&Document>,
    request_resource: Option<&Document>,
    now: LogicalInstant,
    access: &dyn DocumentAccess,
) -> Result<(), Status> {
    let ctx = RequestContext {
        service: RulesService::Firestore,
        method,
        path: rules_path(path),
        auth: match principal {
            Principal::User(a) => Some(a.clone()),
            _ => None,
        },
        resource: resource.map(resource_value),
        request_resource: request_resource.map(resource_value),
        time_unix_nanos: now.as_nanos(),
        abstract_path: false,
        request_query: None,
    };
    decide(ruleset, &ctx, method, path, access)
}

fn decide(
    ruleset: &Ruleset,
    ctx: &RequestContext,
    method: Method,
    path: &DocumentPath,
    access: &dyn DocumentAccess,
) -> Result<(), Status> {
    match evaluate_request_with(ruleset, ctx, Some(access)).decision {
        Decision::Allow => Ok(()),
        Decision::Deny(reason) => Err(Status::permission_denied(format!(
            "{} on {} denied by Security Rules: {}",
            method_name(method),
            path.relative(),
            deny_text(&reason)
        ))),
    }
}

/// A write guard over an optional enforcer.
pub fn write_guard<'a>(
    rules: Option<&'a Arc<RulesEnforcer>>,
    principal: &'a Principal,
) -> BoxedWriteGuard<'a> {
    match rules {
        Some(r) => Box::new(move |db, writes, now| {
            let Some(first) = writes.first() else {
                return Ok(());
            };
            let parent = Parent {
                project: first.op.path().project().clone(),
                database: first.op.path().database().clone(),
                document: None,
            };
            r.authorize_writes_in(principal, &parent, db, writes, now)
        }),
        None => Box::new(allow_all),
    }
}

/// The `resource` every document matching `disjunction` is known to look like: a partial
/// map of the constrained fields (equality, `array-contains` as a partial list, `is null`),
/// an undetermined id and name. Everything else is undetermined, so a rule that depends on
/// it cannot be proven.
fn abstract_resource(disjunction: &[FilterExpr]) -> RulesValue {
    let mut data: BTreeMap<String, RulesValue> = BTreeMap::new();
    // Inequality filters on one field combine into one range (Firestore requires every
    // range filter of a field to share the value's class); an equality wins over them.
    let mut ranges: BTreeMap<&FieldPath, Option<ValueRange>> = BTreeMap::new();
    for atom in disjunction {
        if let FilterExpr::Field { field, op, value } = atom {
            if !field.is_document_name() {
                if let Some(bound) = range_bound(*op, value) {
                    let entry = ranges.entry(field).or_insert_with(|| {
                        Some(ValueRange {
                            lower: None,
                            upper: None,
                        })
                    });
                    *entry = entry.take().and_then(|r| tighten(r, bound));
                }
            }
        }
    }
    for (field, range) in ranges {
        set_nested(
            &mut data,
            field,
            range.map_or(RulesValue::Unknown, RulesValue::Range),
        );
    }
    for atom in disjunction {
        match atom {
            FilterExpr::Field { field, op, value } if !field.is_document_name() => match op {
                FieldOp::Equal => set_nested(&mut data, field, rules_value(value)),
                FieldOp::ArrayContains => {
                    set_nested(
                        &mut data,
                        field,
                        RulesValue::PartialList(vec![rules_value(value)]),
                    );
                }
                // The array holds at least one of the values, not all of them.
                FieldOp::ArrayContainsAny => {
                    if let Value::Array(items) = value {
                        if !items.is_empty() {
                            set_nested(
                                &mut data,
                                field,
                                RulesValue::PartialListAny(items.iter().map(rules_value).collect()),
                            );
                        }
                    }
                }
                // One of the candidates (an empty `in` matches nothing; left undetermined).
                FieldOp::In => {
                    if let Value::Array(items) = value {
                        if !items.is_empty() {
                            set_nested(
                                &mut data,
                                field,
                                RulesValue::OneOf(items.iter().map(rules_value).collect()),
                            );
                        }
                    }
                }
                // Exists, is not null and differs from the listed values.
                FieldOp::NotEqual => {
                    set_nested(
                        &mut data,
                        field,
                        RulesValue::NotOneOf(vec![rules_value(value)]),
                    );
                }
                FieldOp::NotIn => {
                    if let Value::Array(items) = value {
                        set_nested(
                            &mut data,
                            field,
                            RulesValue::NotOneOf(items.iter().map(rules_value).collect()),
                        );
                    }
                }
                _ => {}
            },
            FilterExpr::Unary {
                field,
                op: UnaryOp::IsNull,
            } => set_nested(&mut data, field, RulesValue::Null),
            _ => {}
        }
    }
    let mut m = BTreeMap::new();
    m.insert("data".to_owned(), RulesValue::PartialMap(data));
    m.insert("id".to_owned(), RulesValue::Unknown);
    m.insert("__name__".to_owned(), RulesValue::Unknown);
    RulesValue::Map(m)
}

/// The bound an inequality filter puts on its field: `(bound, is_lower)`. Only values of a
/// comparable class qualify.
fn range_bound(op: FieldOp, value: &Value) -> Option<(RangeBound, bool)> {
    let v = rules_value(value);
    if !matches!(
        v,
        RulesValue::Int(_)
            | RulesValue::Float(_)
            | RulesValue::String(_)
            | RulesValue::Timestamp(_)
            | RulesValue::Bytes(_)
    ) {
        return None;
    }
    if let RulesValue::Float(f) = v {
        if f.is_nan() {
            return None;
        }
    }
    let (inclusive, is_lower) = match op {
        FieldOp::GreaterThan => (false, true),
        FieldOp::GreaterThanOrEqual => (true, true),
        FieldOp::LessThan => (false, false),
        FieldOp::LessThanOrEqual => (true, false),
        _ => return None,
    };
    Some((
        RangeBound {
            value: Box::new(v),
            inclusive,
        },
        is_lower,
    ))
}

/// Narrows `range` by `bound`; `None` when the bounds do not belong to one class (such a
/// filter would not run in Firestore, and an undetermined field is the safe result).
fn tighten(mut range: ValueRange, (bound, is_lower): (RangeBound, bool)) -> Option<ValueRange> {
    if let Some(class) = range.class() {
        if bound.value.compare_class() != class {
            return None;
        }
    }
    let slot = if is_lower {
        &mut range.lower
    } else {
        &mut range.upper
    };
    *slot = match slot.take() {
        None => Some(bound),
        Some(current) => {
            let ord = try_compare(&bound.value, &current.value)?;
            let stricter = match (ord, is_lower) {
                (core::cmp::Ordering::Greater, true) | (core::cmp::Ordering::Less, false) => true,
                (core::cmp::Ordering::Equal, _) => !bound.inclusive,
                _ => false,
            };
            Some(if stricter { bound } else { current })
        }
    };
    Some(range)
}

/// `request.query` of a list request: `limit`, `offset` and `orderBy`. `orderBy` is the
/// explicit ordering rendered as `"field ASC, other DESC"` (the Emulator's form; the
/// production rendering is not documented) and `null` without one.
fn query_value(query: &Query) -> RulesValue {
    let mut m = BTreeMap::new();
    m.insert(
        "limit".to_owned(),
        query
            .limit
            .map_or(RulesValue::Null, |l| RulesValue::Int(i64::from(l))),
    );
    m.insert(
        "offset".to_owned(),
        RulesValue::Int(i64::from(query.offset)),
    );
    m.insert(
        "orderBy".to_owned(),
        if query.order_by.is_empty() {
            RulesValue::Null
        } else {
            RulesValue::String(
                query
                    .order_by
                    .iter()
                    .map(|o| {
                        format!(
                            "{} {}",
                            o.field.canonical(),
                            match o.direction {
                                Direction::Ascending => "ASC",
                                Direction::Descending => "DESC",
                            }
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            )
        },
    );
    RulesValue::Map(m)
}

/// Sets a nested constrained field; intermediate levels are partial maps (other keys may
/// exist), an exact map value replaces the level entirely.
fn set_nested(fields: &mut BTreeMap<String, RulesValue>, path: &FieldPath, value: RulesValue) {
    let segments = path.segments();
    let mut map = fields;
    for s in &segments[..segments.len() - 1] {
        let entry = map
            .entry(s.clone())
            .or_insert_with(|| RulesValue::PartialMap(BTreeMap::new()));
        if !matches!(entry, RulesValue::PartialMap(_) | RulesValue::Map(_)) {
            *entry = RulesValue::PartialMap(BTreeMap::new());
        }
        map = match entry {
            RulesValue::PartialMap(m) | RulesValue::Map(m) => m,
            _ => return,
        };
    }
    if let Some(last) = segments.last() {
        map.insert(last.clone(), value);
    }
}

const fn method_name(m: Method) -> &'static str {
    match m {
        Method::Get => "get",
        Method::List => "list",
        Method::Create => "create",
        Method::Update => "update",
        Method::Delete => "delete",
    }
}

fn deny_text(reason: &DenyReason) -> String {
    match reason {
        DenyReason::NoMatchingRule => "no match block covers this path".to_owned(),
        DenyReason::NoMatchingAllow => "no allow statement evaluated to true".to_owned(),
        DenyReason::Unsupported(m) => format!("unsupported rules feature: {m}"),
        DenyReason::BudgetExceeded {
            limit_id,
            current,
            maximum,
        } => format!("{limit_id}: {current} exceeds {maximum}"),
    }
}

/// Rules path for a document: `/databases/{db}/documents/{relative}`.
#[must_use]
pub fn rules_path(path: &DocumentPath) -> String {
    format!(
        "/databases/{}/documents/{}",
        path.database().as_str(),
        path.relative()
    )
}

/// Document paths standing in for "any document of this query". A collection query has one
/// (its collection, id undetermined); a collection-group query prepends the "any prefix"
/// marker that only a recursive wildcard rule can cover, as production requires.
pub fn placeholder_paths(parent: &Parent, query: &Query) -> Result<Vec<DocumentPath>, Status> {
    let collection_id = query.scope.collection_id.as_str();
    let relative = match (&query.scope.parent, query.scope.all_descendants) {
        (Some(p), false) => format!("{}/{collection_id}/{ABSTRACT_SEGMENT}", p.relative()),
        (_, false) => format!("{collection_id}/{ABSTRACT_SEGMENT}"),
        (_, true) => {
            format!("{ABSTRACT_PREFIX}/{ABSTRACT_PREFIX}/{collection_id}/{ABSTRACT_SEGMENT}")
        }
    };
    let path = DocumentPath::parse(&parent.project, &parent.database, &relative)
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    Ok(vec![path])
}

fn reference_path(resource_name: &str) -> RulesValue {
    // "projects/{p}/databases/{d}/documents/..." -> ["databases", d, "documents", ...]
    let segments: Vec<String> = resource_name
        .split('/')
        .skip(2)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    RulesValue::Path(segments)
}

/// Firestore value → Rules value (distinct types, full timestamp precision).
#[must_use]
pub fn rules_value(v: &Value) -> RulesValue {
    match v {
        Value::Null => RulesValue::Null,
        Value::Boolean(b) => RulesValue::Bool(*b),
        Value::Integer(i) => RulesValue::Int(*i),
        Value::Double(d) => RulesValue::Float(*d),
        Value::Timestamp(t) => {
            RulesValue::Timestamp(i128::from(t.seconds()) * 1_000_000_000 + i128::from(t.nanos()))
        }
        Value::String(s) => RulesValue::String(s.clone()),
        Value::Bytes(b) => RulesValue::Bytes(b.clone()),
        Value::Reference(r) => reference_path(r),
        Value::GeoPoint(g) => RulesValue::LatLng {
            latitude: g.latitude(),
            longitude: g.longitude(),
        },
        Value::Array(items) => RulesValue::List(items.iter().map(rules_value).collect()),
        Value::Vector(dims) => {
            RulesValue::List(dims.iter().map(|d| RulesValue::Float(*d)).collect())
        }
        Value::Map(m) => {
            RulesValue::Map(m.iter().map(|(k, v)| (k.clone(), rules_value(v))).collect())
        }
    }
}

/// `resource` / `request.resource` value: `{ data, id, __name__ }`.
#[must_use]
pub fn resource_value(doc: &Document) -> RulesValue {
    let mut m = BTreeMap::new();
    m.insert(
        "data".to_owned(),
        RulesValue::Map(
            doc.fields
                .iter()
                .map(|(k, v)| (k.clone(), rules_value(v)))
                .collect(),
        ),
    );
    m.insert(
        "id".to_owned(),
        RulesValue::String(doc.path.document_id().as_str().to_owned()),
    );
    m.insert(
        "__name__".to_owned(),
        reference_path(&doc.path.resource_name()),
    );
    RulesValue::Map(m)
}

/// Refuses work admitted into a later reset epoch than the one the caller started in: the
/// caller's token was verified against the previous session's Auth store.
pub fn same_epoch(
    barrier: &fireemu_core_session::barrier::AdmissionBarrier,
    epoch: u64,
) -> Result<(), Status> {
    if barrier.epoch() == epoch {
        Ok(())
    } else {
        Err(Status::unavailable(
            "the session was reset while the request was in flight; retry against the new session",
        ))
    }
}
