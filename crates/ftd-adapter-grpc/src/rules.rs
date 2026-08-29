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
//! production; inequality constraints are not used to prove rules yet (conservative). The
//! decision never depends on stored data, so it leaks nothing about it.

// `tonic::Status` is the error type dictated by the generated trait.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use ftd_core_auth::jwt::{decode_unsigned, verify_id_token};
use ftd_core_auth::store::AuthStore;
use ftd_core_firestore::field_path::FieldPath;
use ftd_core_firestore::path::DocumentPath;
use ftd_core_firestore::query::{FieldOp, FilterExpr, Query, UnaryOp};
use ftd_core_firestore::store::{Document, FirestoreState, Write, WriteOp};
use ftd_core_firestore::value::Value;
use ftd_core_rules::ast::Ruleset;
use ftd_core_rules::eval::{evaluate_request, Decision, DenyReason, Method, RequestContext};
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_rules::value::{AuthContext, RulesValue};
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::Clock;
use ftd_core_types::time::LogicalInstant;
use tonic::metadata::MetadataMap;
use tonic::Status;

use crate::decode::Parent;

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

/// A guard that allows everything (no rules configured / owner).
pub fn allow_all(_: &FirestoreState, _: &[Write], _: LogicalInstant) -> Result<(), Status> {
    Ok(())
}

/// Rules enforcement state shared by every surface.
pub struct RulesEnforcer {
    rules: Arc<RwLock<LoadedRules>>,
    auth: Arc<Mutex<AuthStore>>,
    clock: Arc<Mutex<VirtualClock>>,
}

impl RulesEnforcer {
    /// Creates the enforcer over the shared rules, user store and clock.
    #[must_use]
    pub fn new(
        rules: Arc<RwLock<LoadedRules>>,
        auth: Arc<Mutex<AuthStore>>,
        clock: Arc<Mutex<VirtualClock>>,
    ) -> Self {
        Self { rules, auth, clock }
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
        if token == "owner" {
            return Ok(Principal::Owner);
        }
        let now = self.now()?;
        let store = self
            .auth
            .lock()
            .map_err(|_| Status::internal("auth store lock poisoned"))?;
        verify_id_token(token, &store, now)
            .map_err(|e| Status::unauthenticated(format!("invalid ID token: {e}")))?;
        drop(store);
        let decoded = decode_unsigned(token)
            .map_err(|e| Status::unauthenticated(format!("invalid ID token: {e}")))?;
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
        )
    }

    /// Authorizes a single-document read against the snapshot that will be returned.
    pub fn authorize_get(
        &self,
        principal: &Principal,
        path: &DocumentPath,
        snapshot: Option<&Document>,
    ) -> Result<(), Status> {
        self.evaluate(principal, Method::Get, path, snapshot, None)
    }

    /// Authorizes a query from its constraints (see the module documentation). One ruleset
    /// snapshot and one request time serve every disjunction.
    pub fn authorize_query(
        &self,
        principal: &Principal,
        parent: &Parent,
        query: &Query,
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
        let placeholder = placeholder_path(parent, query)?;
        for disjunction in query.dnf() {
            let synthetic = Document {
                path: placeholder.clone(),
                fields: constrained_fields(&disjunction),
                create_time: now,
                update_time: now,
                version: ftd_core_firestore::store::CommitVersion::default(),
            };
            evaluate_with(
                ruleset,
                principal,
                Method::List,
                &placeholder,
                Some(&synthetic),
                None,
                now,
            )?;
        }
        Ok(())
    }

    /// Authorizes the writes of one commit against the sequentially staged state `db` will
    /// see, at the commit time the commit will receive. Meant to run inside the database
    /// critical section (see [`WriteGuard`]); one ruleset snapshot serves every write.
    pub fn authorize_writes_in(
        &self,
        principal: &Principal,
        db: &FirestoreState,
        writes: &[Write],
        now: LogicalInstant,
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
        let at = db.next_commit_time(now);
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
            )?;
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
) -> Result<(), Status> {
    let ctx = RequestContext {
        method,
        path: rules_path(path),
        auth: match principal {
            Principal::User(a) => Some(a.clone()),
            _ => None,
        },
        resource: resource.map(resource_value),
        request_resource: request_resource.map(resource_value),
        time_unix_nanos: now.as_nanos(),
    };
    match evaluate_request(ruleset, &ctx).decision {
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
        Some(r) => {
            Box::new(move |db, writes, now| r.authorize_writes_in(principal, db, writes, now))
        }
        None => Box::new(allow_all),
    }
}

/// Fields every document matching `disjunction` must carry (equality and array-membership
/// constraints only).
fn constrained_fields(disjunction: &[FilterExpr]) -> BTreeMap<String, Value> {
    let mut fields = BTreeMap::new();
    for atom in disjunction {
        match atom {
            FilterExpr::Field { field, op, value } if !field.is_document_name() => match op {
                FieldOp::Equal => set_nested(&mut fields, field, value.clone()),
                FieldOp::ArrayContains => {
                    set_nested(&mut fields, field, Value::Array(vec![value.clone()]));
                }
                FieldOp::ArrayContainsAny => {
                    if let Value::Array(items) = value {
                        set_nested(&mut fields, field, Value::Array(items.clone()));
                    }
                }
                _ => {}
            },
            FilterExpr::Unary {
                field,
                op: UnaryOp::IsNull,
            } => set_nested(&mut fields, field, Value::Null),
            _ => {}
        }
    }
    fields
}

fn set_nested(fields: &mut BTreeMap<String, Value>, path: &FieldPath, value: Value) {
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

/// Document path standing in for "any document of this query" (the wildcard binds to
/// `ftd-placeholder`; collection-group queries bind at the root, where `{path=**}` matches
/// zero segments).
pub fn placeholder_path(parent: &Parent, query: &Query) -> Result<DocumentPath, Status> {
    let collection_id = query.scope.collection_id.as_str();
    let relative = match (&query.scope.parent, query.scope.all_descendants) {
        (Some(p), false) => format!("{}/{collection_id}/ftd-placeholder", p.relative()),
        _ => format!("{collection_id}/ftd-placeholder"),
    };
    DocumentPath::parse(&parent.project, &parent.database, &relative)
        .map_err(|e| Status::invalid_argument(e.to_string()))
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
