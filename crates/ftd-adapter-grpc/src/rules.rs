//! Firestore Security Rules enforcement on the gRPC request path.
//!
//! `Authorization: Bearer owner` (Admin SDK against an emulator) bypasses rules. Any other
//! bearer token is verified as an ID token against the shared [`AuthStore`] (issuer,
//! audience, expiry, revocation) and becomes `request.auth`. A request without a token is
//! evaluated as unauthenticated. When no ruleset is loaded every request is allowed (the
//! runtime prints a warning at start).
//!
//! `list` requests are evaluated per returned document; when nothing is returned the rule
//! is evaluated without `resource`, and a denial that only stems from reading the absent
//! `resource` is treated as allowed (an empty result leaks nothing). Production Firestore
//! proves list rules against the query constraints instead, so a query the production
//! service would reject can pass here (`RULES-LIST-APPROX`); the reverse never happens for
//! non-empty results.

// `tonic::Status` is the error type dictated by the generated trait.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use ftd_core_auth::jwt::{base64url_encode, decode_unsigned, verify_id_token};
use ftd_core_auth::store::AuthStore;
use ftd_core_firestore::path::DocumentPath;
use ftd_core_firestore::store::{Document, Write, WriteOp};
use ftd_core_firestore::value::Value;
use ftd_core_rules::eval::{evaluate_request, Decision, DenyReason, Method, RequestContext};
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_rules::value::{AuthContext, RulesValue};
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::Clock;
use ftd_core_types::time::LogicalInstant;
use tonic::metadata::MetadataMap;
use tonic::Status;

use crate::decode::Parent;
use crate::local::LocalBackend;

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

/// Rules enforcement state shared by the gRPC service.
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

    fn now(&self) -> LogicalInstant {
        self.clock
            .lock()
            .map(|c| c.now())
            .unwrap_or(LogicalInstant::UNIX_EPOCH)
    }

    /// Resolves the caller from the request metadata.
    pub fn principal(&self, metadata: &MetadataMap) -> Result<Principal, Status> {
        let Some(value) = metadata.get("authorization") else {
            return Ok(Principal::Anonymous);
        };
        let value = value
            .to_str()
            .map_err(|_| Status::unauthenticated("malformed authorization metadata"))?;
        let token = value
            .strip_prefix("Bearer ")
            .ok_or_else(|| Status::unauthenticated("authorization must be a Bearer token"))?;
        if token == "owner" {
            return Ok(Principal::Owner);
        }
        let now = self.now();
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

    /// Evaluates one request. `Ok(true)` = allowed; `Ok(false)` = denied only because the
    /// rule needed the absent `resource`.
    fn evaluate(
        &self,
        principal: &Principal,
        method: Method,
        path: &DocumentPath,
        resource: Option<&Document>,
        request_resource: Option<&Document>,
    ) -> Result<bool, Status> {
        if matches!(principal, Principal::Owner) {
            return Ok(true);
        }
        let rules = self
            .rules
            .read()
            .map_err(|_| Status::internal("rules lock poisoned"))?;
        let Some(ruleset) = &rules.ruleset else {
            return Ok(true);
        };
        let ctx = RequestContext {
            method,
            path: rules_path(path),
            auth: match principal {
                Principal::User(a) => Some(a.clone()),
                _ => None,
            },
            resource: resource.map(resource_value),
            request_resource: request_resource.map(resource_value),
            time_unix_seconds: i64::try_from(self.now().as_nanos().div_euclid(1_000_000_000))
                .unwrap_or(i64::MAX),
        };
        let report = evaluate_request(ruleset, &ctx);
        match report.decision {
            Decision::Allow => Ok(true),
            Decision::Deny(_) if resource.is_none() && report.absent_resource_used => Ok(false),
            Decision::Deny(reason) => Err(Status::permission_denied(format!(
                "{} on {} denied by Security Rules: {}",
                method_name(method),
                path.relative(),
                deny_text(&reason)
            ))),
        }
    }

    /// Authorizes a single-document read.
    pub fn authorize_get(
        &self,
        principal: &Principal,
        backend: &LocalBackend,
        parent: &Parent,
        path: &DocumentPath,
    ) -> Result<(), Status> {
        if matches!(principal, Principal::Owner) || !self.is_loaded() {
            return Ok(());
        }
        let current = backend.current_document(parent, path)?;
        self.evaluate(principal, Method::Get, path, current.as_ref(), None)
            .map(|_| ())
    }

    /// Authorizes a `list` over the documents about to be returned. `placeholder` is the
    /// path evaluated when the result set is empty.
    pub fn authorize_list(
        &self,
        principal: &Principal,
        backend: &LocalBackend,
        parent: &Parent,
        documents: &[DocumentPath],
        placeholder: &DocumentPath,
    ) -> Result<(), Status> {
        if matches!(principal, Principal::Owner) || !self.is_loaded() {
            return Ok(());
        }
        if documents.is_empty() {
            self.evaluate(principal, Method::List, placeholder, None, None)?;
            return Ok(());
        }
        for path in documents {
            let current = backend.current_document(parent, path)?;
            self.evaluate(principal, Method::List, path, current.as_ref(), None)?;
        }
        Ok(())
    }

    /// Authorizes one write (create / update / delete is derived from the current state).
    pub fn authorize_write(
        &self,
        principal: &Principal,
        backend: &LocalBackend,
        parent: &Parent,
        write: &Write,
    ) -> Result<(), Status> {
        if matches!(principal, Principal::Owner) || !self.is_loaded() {
            return Ok(());
        }
        let path = write.op.path();
        let current = backend.current_document(parent, path)?;
        let (method, preview) = match &write.op {
            WriteOp::Delete { .. } => (Method::Delete, None),
            WriteOp::Set { .. } => (
                if current.is_some() {
                    Method::Update
                } else {
                    Method::Create
                },
                backend.preview_write(parent, write)?,
            ),
        };
        self.evaluate(principal, method, path, current.as_ref(), preview.as_ref())
            .map(|_| ())
    }

    fn is_loaded(&self) -> bool {
        self.rules.read().is_ok_and(|r| r.is_loaded())
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

/// Firestore value → Rules value.
#[must_use]
pub fn rules_value(v: &Value) -> RulesValue {
    match v {
        Value::Null => RulesValue::Null,
        Value::Boolean(b) => RulesValue::Bool(*b),
        Value::Integer(i) => RulesValue::Int(*i),
        Value::Double(d) => RulesValue::Float(*d),
        Value::Timestamp(t) => RulesValue::Timestamp(t.seconds()),
        Value::String(s) => RulesValue::String(s.clone()),
        Value::Bytes(b) => RulesValue::String(base64url_encode(b)),
        Value::Reference(r) => reference_path(r),
        Value::GeoPoint(g) => {
            let mut m = BTreeMap::new();
            m.insert("latitude".to_owned(), RulesValue::Float(g.latitude()));
            m.insert("longitude".to_owned(), RulesValue::Float(g.longitude()));
            RulesValue::Map(m)
        }
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
