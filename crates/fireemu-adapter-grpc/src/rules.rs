//! Firestore Security Rules enforcement shared by the gRPC service, the streams and the
//! REST surface.
//!
//! `Authorization: Bearer owner` (Admin SDK against an emulator) bypasses rules. Any other
//! bearer token is verified as an ID token against the shared [`AuthStore`] (issuer,
//! audience, expiry, revocation) and becomes `request.auth`. A request without a token is
//! evaluated as unauthenticated. When no ruleset is loaded every request is allowed (the
//! runtime prints a warning at start).
//!
//! How much of that verification a caller's token has to survive is the compatibility
//! profile's decision, carried here as [`TokenAcceptance`]: the `emulator` profile also
//! admits the unsigned mock tokens the official emulators admit (an unknown `sub`, an `exp`
//! nobody reads), while `strict` keeps the full verification.
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
use std::sync::{Arc, Mutex};

use fireemu_core_auth::jwt::{
    verify_firestore_rules_token, verify_rules_token, verify_rules_token_for_project, JwtError,
    TokenAcceptance,
};
use fireemu_core_auth::store::AuthStore;
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{Direction, FieldOp, FilterExpr, Query, QueryScope, UnaryOp};
use fireemu_core_firestore::store::{
    CommitVersion, Document, FirestoreState, Precondition, Write, WriteOp,
};
use fireemu_core_firestore::value::Value;
use fireemu_core_rules::ast::Ruleset;
use fireemu_core_rules::coverage::{Coverage, CoverageEntry, RequestTrace, RulesDiagnostics};
use fireemu_core_rules::eval::{
    evaluate_request_traced_owned, try_compare, Decision, DenyReason, DocumentAccess, Method,
    RequestContext, RulesService, ABSTRACT_PREFIX, ABSTRACT_SEGMENT,
};
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
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
pub type ReadGuard<'a> = &'a dyn for<'check> Fn(
    &FirestoreState,
    Option<CommitVersion>,
    ReadCheck<'check>,
) -> Result<(), Status>;

/// Owned read guard (see [`read_guard`]).
pub type BoxedReadGuard<'a> = Box<
    dyn for<'check> Fn(
            &FirestoreState,
            Option<CommitVersion>,
            ReadCheck<'check>,
        ) -> Result<(), Status>
        + 'a,
>;

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

/// Why replacing a ruleset failed.
#[derive(Debug)]
pub enum RulesLoadError {
    /// The source does not compile; the position is the compiler's.
    Compile(fireemu_core_rules::parse::ParseError),
    /// Atomic publication failed after the source compiled.
    Publish(String),
}

/// Which ID-token checks a caller's credential goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenSemantics {
    /// ID-token verification as Identity Toolkit and the Admin SDK do it: a revoked, disabled
    /// or deleted account's token is refused, and so is one past `exp`. The default, for every
    /// surface nothing observed to be more lenient (callable Functions).
    #[default]
    IdToken,
    /// What Firestore was observed to check (FS-RULES, 2026-09-24/25): the token alone, with a
    /// 30-second allowance past `exp`, not the account.
    Firestore,
}

/// Rules enforcement state shared by every surface.
pub struct RulesEnforcer {
    rules: Arc<RulesetSlot>,
    database_rules: BTreeMap<String, Arc<RulesetSlot>>,
    auth: Arc<Mutex<AuthStore>>,
    clock: Arc<Mutex<VirtualClock>>,
    /// Stores of the other session projects (tokens are verified against the store of
    /// their `aud`).
    registry: Option<Arc<fireemu_core_auth::store::AuthRegistry>>,
    /// How a caller's ID token is verified: the compatibility profile decides
    /// (`firebase` admits the official emulators' mock tokens, `strict` does not).
    acceptance: TokenAcceptance,
    /// Whether a client request is refused while its database has no ruleset: production
    /// refuses every client request without a `cloud.firestore` release (the `strict`
    /// profile); the official emulator allows everything (the `emulator` profile).
    refuse_without_ruleset: bool,
    /// Whether an end user may open a read-write transaction: production refuses it with the
    /// ordinary denial (the `strict` profile); the official emulator opens it.
    end_user_transactions: bool,
    /// Which ID-token checks apply (see [`TokenSemantics`]).
    token_semantics: TokenSemantics,
}

impl RulesEnforcer {
    /// Creates the enforcer over the shared rules, user store and clock.
    #[must_use]
    pub fn new(
        rules: Arc<RulesetSlot>,
        auth: Arc<Mutex<AuthStore>>,
        clock: Arc<Mutex<VirtualClock>>,
    ) -> Self {
        Self {
            rules,
            database_rules: BTreeMap::new(),
            auth,
            clock,
            registry: None,
            acceptance: TokenAcceptance::default(),
            refuse_without_ruleset: false,
            end_user_transactions: true,
            token_semantics: TokenSemantics::default(),
        }
    }

    /// Sets which ID-token checks apply: the Firestore surfaces use
    /// [`TokenSemantics::Firestore`].
    #[must_use]
    pub const fn with_token_semantics(mut self, semantics: TokenSemantics) -> Self {
        self.token_semantics = semantics;
        self
    }

    /// Sets whether a client request is refused while its database has no ruleset.
    #[must_use]
    pub const fn with_refusal_without_ruleset(mut self, refuse: bool) -> Self {
        self.refuse_without_ruleset = refuse;
        self
    }

    /// Sets whether an end user may open a read-write transaction.
    #[must_use]
    pub const fn with_end_user_transactions(mut self, allowed: bool) -> Self {
        self.end_user_transactions = allowed;
        self
    }

    /// Whether `principal` may open a transaction with `options` (`None` is the default, a
    /// read-write transaction), by `BeginTransaction` or a read's `newTransaction`.
    /// Production refuses an end user, signed in or not, a read-write transaction with its
    /// usual denial whatever the rules say, and opens a read-only one (FS-RULES, 2026-09-25).
    pub fn check_new_transaction(
        &self,
        principal: &Principal,
        options: Option<&fireemu_proto_firestore::google::firestore::v1::TransactionOptions>,
    ) -> Result<(), Status> {
        use fireemu_proto_firestore::google::firestore::v1::transaction_options::Mode;
        let read_only = options.is_some_and(|o| matches!(o.mode, Some(Mode::ReadOnly(_))));
        if read_only || self.end_user_transactions || matches!(principal, Principal::Owner) {
            return Ok(());
        }
        let rules = self.rules.snapshot().map_err(Status::internal)?;
        Err(denied(
            &rules.diagnostics,
            principal,
            Method::Get,
            "BeginTransaction".to_owned(),
            "an end user may not open a read-write transaction in production".to_owned(),
        ))
    }

    /// The answer to a client request against a database without a ruleset.
    fn without_ruleset(
        &self,
        diagnostics: &Mutex<RulesDiagnostics>,
        principal: &Principal,
        method: Method,
        path: String,
    ) -> Result<(), Status> {
        if self.refuse_without_ruleset {
            Err(denied(
                diagnostics,
                principal,
                method,
                path,
                "no ruleset is loaded for this database".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    /// The loaded rules, whose `diagnostics` a coverage report and a request trace read.
    #[must_use]
    pub fn rules(&self) -> &Arc<RulesetSlot> {
        &self.rules
    }

    /// Verifies tokens of every registered session project, not only the default one.
    #[must_use]
    pub fn with_registry(mut self, registry: Arc<fireemu_core_auth::store::AuthRegistry>) -> Self {
        self.registry = Some(registry);
        self
    }

    /// Installs rulesets declared for named Firestore databases.
    #[must_use]
    pub fn with_database_rules(mut self, rules: BTreeMap<String, Arc<RulesetSlot>>) -> Self {
        self.database_rules = rules;
        self
    }

    fn rules_for_database(&self, database: &str) -> &Arc<RulesetSlot> {
        self.database_rules.get(database).unwrap_or(&self.rules)
    }

    /// Sets how a caller's ID token is verified. The default is
    /// [`TokenAcceptance::Verified`], so a caller that forgets to pass the compatibility
    /// profile gets the stricter behaviour rather than the looser one.
    #[must_use]
    pub const fn with_token_acceptance(mut self, acceptance: TokenAcceptance) -> Self {
        self.acceptance = acceptance;
        self
    }

    fn now(&self) -> Result<LogicalInstant, Status> {
        self.clock
            .lock()
            .map(|c| c.now())
            .map_err(|_| Status::internal("clock lock poisoned"))
    }

    /// Replaces the loaded ruleset, as `PUT /emulator/v1/projects/{p}:securityRules` and the
    /// control API's `PUT /v1/rules` both do. The swap is atomic: a source that does not
    /// compile leaves the previous ruleset in force, so a failed load never opens a session
    /// up.
    pub fn replace_source(&self, source: &str) -> Result<(), RulesLoadError> {
        let loaded = LoadedRules::from_source(source).map_err(RulesLoadError::Compile)?;
        self.rules
            .replace_loaded(loaded)
            .map_err(RulesLoadError::Publish)?;
        Ok(())
    }

    /// Whether a ruleset is loaded (poisoned state is an error, never "no rules").
    pub fn loaded(&self) -> Result<bool, Status> {
        self.rules
            .snapshot()
            .map(|rules| rules.is_loaded())
            .map_err(Status::internal)
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

    /// Resolves the caller and binds an unsigned Firebase-profile mock token to the project
    /// named by the routed Firestore resource.
    pub fn principal_for_project(
        &self,
        metadata: &MetadataMap,
        expected_project: &str,
    ) -> Result<Principal, Status> {
        let Some(value) = metadata.get("authorization") else {
            return Ok(Principal::Anonymous);
        };
        let value = value
            .to_str()
            .map_err(|_| Status::unauthenticated("malformed authorization metadata"))?;
        self.principal_from_authorization_for_project(Some(value), expected_project)
    }

    /// Resolves the caller from an `Authorization` header value.
    pub fn principal_from_authorization(&self, value: Option<&str>) -> Result<Principal, Status> {
        self.principal_from_authorization_with_project(value, None)
    }

    /// Resolves an `Authorization` header for a routed Firestore project.
    pub fn principal_from_authorization_for_project(
        &self,
        value: Option<&str>,
        expected_project: &str,
    ) -> Result<Principal, Status> {
        self.principal_from_authorization_with_project(value, Some(expected_project))
    }

    fn principal_from_authorization_with_project(
        &self,
        value: Option<&str>,
        expected_project: Option<&str>,
    ) -> Result<Principal, Status> {
        let Some(value) = value else {
            return Ok(Principal::Anonymous);
        };
        // The strict profile refuses a credential in production's shapes (see
        // `refusal`); the emulator profile keeps the texts it has always answered with.
        let production = self.acceptance == TokenAcceptance::Verified;
        let token = value
            .strip_prefix("Bearer ")
            .filter(|token| !production || !token.is_empty())
            .ok_or_else(|| {
                if production {
                    Status::permission_denied(PERMISSION_DENIED_MESSAGE)
                } else {
                    Status::unauthenticated("authorization must be a Bearer token")
                }
            })?;
        if token == OWNER_TOKEN {
            return Ok(Principal::Owner);
        }
        // A bearer value that is not a JWT is taken for an OAuth access token by the front end.
        if production && token.split('.').count() != 3 {
            return Err(Status::unauthenticated(INVALID_CREDENTIALS_MESSAGE));
        }
        let now = self.now()?;
        // The token's audience names its project: verify against that project's store.
        let store_arc = match &self.registry {
            Some(registry) => {
                let default = self
                    .auth
                    .lock()
                    .map_err(|_| Status::internal("auth store lock poisoned"))?;
                let target = fireemu_core_auth::jwt::decode_token(token, default.signer())
                    .ok()
                    .and_then(|d| {
                        let audience = d
                            .payload
                            .get("aud")
                            .and_then(fireemu_core_types::json::JsonValue::as_str)
                            .map(str::to_owned)?;
                        let tenant = d
                            .payload
                            .get("firebase")
                            .and_then(|firebase| firebase.get("tenant"))
                            .and_then(fireemu_core_types::json::JsonValue::as_str)
                            .map(str::to_owned);
                        Some((audience, tenant))
                    });
                drop(default);
                target
                    .and_then(|(project, tenant)| match tenant {
                        Some(tenant) => registry.tenant_store(&project, &tenant),
                        None => registry.store_for(&project),
                    })
                    .unwrap_or_else(|| self.auth.clone())
            }
            None => self.auth.clone(),
        };
        let store = store_arc
            .lock()
            .map_err(|_| Status::internal("auth store lock poisoned"))?;
        let verified = match (self.token_semantics, expected_project) {
            (TokenSemantics::Firestore, _) => {
                verify_firestore_rules_token(token, &store, now, self.acceptance, expected_project)
            }
            (TokenSemantics::IdToken, Some(project)) => {
                verify_rules_token_for_project(token, &store, now, self.acceptance, project)
            }
            (TokenSemantics::IdToken, None) => {
                verify_rules_token(token, &store, now, self.acceptance)
            }
        };
        let decoded = verified.map_err(|error| match error {
            JwtError::Expired if production => Status::unauthenticated(EXPIRED_CREDENTIALS_MESSAGE),
            _ if production => Status::permission_denied(PERMISSION_DENIED_MESSAGE),
            error => Status::unauthenticated(format!("invalid ID token: {error}")),
        })?;
        drop(store);
        let ctx = AuthContext::from_id_token_json(&decoded.payload_json).map_err(|e| {
            if production {
                Status::permission_denied(PERMISSION_DENIED_MESSAGE)
            } else {
                Status::unauthenticated(format!("invalid ID token claims: {e}"))
            }
        })?;
        Ok(Principal::User(ctx))
    }

    /// Owner-only surfaces (collection enumeration) while rules are loaded.
    pub fn require_owner(&self, principal: &Principal, what: &str) -> Result<(), Status> {
        if matches!(principal, Principal::Owner) {
            return Ok(());
        }
        let rules = self.rules.snapshot().map_err(Status::internal)?;
        if !rules.is_loaded() {
            return self.without_ruleset(
                &rules.diagnostics,
                principal,
                Method::List,
                what.to_owned(),
            );
        }
        // Production refuses an end user here with its usual Security Rules denial.
        Err(denied(
            &rules.diagnostics,
            principal,
            Method::List,
            what.to_owned(),
            format!("{what} is for administrators only while Security Rules are enforced"),
        ))
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
            .rules_for_database(path.database().as_str())
            .snapshot()
            .map_err(Status::internal)?;
        let Some(ruleset) = &rules.ruleset else {
            return self.without_ruleset(&rules.diagnostics, principal, method, path.relative());
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
            Some(&rules.diagnostics),
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
            .rules_for_database(
                items
                    .first()
                    .map_or(fireemu_core_types::ids::DatabaseId::DEFAULT, |(path, _)| {
                        path.database().as_str()
                    }),
            )
            .snapshot()
            .map_err(Status::internal)?;
        let Some(ruleset) = &rules.ruleset else {
            let path = items
                .first()
                .map(|(path, _)| path.relative())
                .unwrap_or_default();
            return self.without_ruleset(&rules.diagnostics, principal, Method::Get, path);
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
                Some(&rules.diagnostics),
            )?;
            let accessed = reader.seen.borrow().len() as u64;
            if items.len() > 1 && accessed > multi_total {
                return Err(denied(
                    &rules.diagnostics,
                    principal,
                    Method::Get,
                    path.relative(),
                    format!("RULES-DOC-ACCESS-MULTI-TOTAL: {accessed} exceeds {multi_total}"),
                ));
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
            .rules_for_database(parent.database.as_str())
            .snapshot()
            .map_err(Status::internal)?;
        let Some(ruleset) = &rules.ruleset else {
            return self.without_ruleset(
                &rules.diagnostics,
                principal,
                Method::List,
                "a query".to_owned(),
            );
        };
        let now = self.now()?;
        let reader = AggregateReader {
            inner: access,
            seen: RefCell::new(BTreeSet::new()),
        };
        let list_max = multi_total_max();
        if let Some(candidates) = exact_name_candidates(parent, query) {
            return authorize_exact_names(
                ruleset,
                &rules.diagnostics,
                principal,
                query,
                &candidates,
                &reader,
                now,
            );
        }
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
                decide(
                    ruleset,
                    ctx,
                    Method::List,
                    &placeholder,
                    &reader,
                    Some(&rules.diagnostics),
                )?;
                let accessed = reader.seen.borrow().len() as u64;
                if accessed > list_max {
                    return Err(denied(
                        &rules.diagnostics,
                        principal,
                        Method::List,
                        placeholder.relative(),
                        format!("RULES-DOC-ACCESS-MULTI-TOTAL: {accessed} exceeds {list_max}"),
                    ));
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
            .rules_for_database(parent.database.as_str())
            .snapshot()
            .map_err(Status::internal)?;
        let Some(ruleset) = &rules.ruleset else {
            let path = writes
                .first()
                .map(|write| write.op.path().relative())
                .unwrap_or_default();
            return self.without_ruleset(&rules.diagnostics, principal, Method::Update, path);
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
                _ => FirestoreState::preview_from(current.as_ref(), write, at)
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
                // The precondition names the method when there is one: production judges an
                // `exists: false` write as a create and an `exists: true` or `updateTime` one as
                // an update whatever the document is now, and the precondition then refuses it
                // if it does not hold (FS-RULES, 2026-09-24).
                WriteOp::Set { .. } => (
                    match write.precondition {
                        Some(Precondition::Exists(true) | Precondition::UpdateTime(_)) => {
                            Method::Update
                        }
                        None if current.is_some() => Method::Update,
                        Some(Precondition::Exists(false)) | None => Method::Create,
                    },
                    FirestoreState::preview_from(current.as_ref(), write, at)
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
                Some(&rules.diagnostics),
            )?;
            let accessed = reader.seen.borrow().len() as u64;
            if writes.len() > 1 && accessed > multi_total {
                return Err(denied(
                    &rules.diagnostics,
                    principal,
                    method,
                    path.relative(),
                    format!("RULES-DOC-ACCESS-MULTI-TOTAL: {accessed} exceeds {multi_total}"),
                ));
            }
            if !matches!(write.op, WriteOp::Verify { .. }) {
                staged.insert(path.clone(), preview);
            }
        }
        Ok(())
    }
}

/// A query whose every disjunct is `__name__ ==` a document: each named document is decided
/// as a `list` against what is stored, with one `get()` / `exists()` budget.
#[allow(clippy::too_many_arguments)]
fn authorize_exact_names(
    ruleset: &Ruleset,
    diagnostics: &Mutex<RulesDiagnostics>,
    principal: &Principal,
    query: &Query,
    candidates: &[DocumentPath],
    reader: &AggregateReader<'_>,
    now: LogicalInstant,
) -> Result<(), Status> {
    let list_max = multi_total_max();
    for candidate in candidates {
        let segments = rules_document_segments(candidate);
        let resource = reader.inner.get(&segments);
        let ctx = RequestContext {
            service: RulesService::Firestore,
            method: Method::List,
            path: rules_path(candidate),
            auth: match principal {
                Principal::User(auth) => Some(auth.clone()),
                _ => None,
            },
            resource,
            request_resource: None,
            time_unix_nanos: now.as_nanos(),
            abstract_path: false,
            request_query: Some(query_value(query)),
        };
        let resource_absent = ctx.resource.is_none();
        let (report, _) = evaluate_request_traced_owned(ruleset, ctx, Some(reader));
        if !matches!(report.decision, Decision::Allow)
            || (resource_absent && report.absent_resource_used)
        {
            let reason = match &report.decision {
                Decision::Deny(reason) => deny_text(reason),
                Decision::Allow => "the rule read the resource of a missing document".into(),
            };
            return Err(denied(
                diagnostics,
                principal,
                Method::List,
                candidate.relative(),
                reason,
            ));
        }
        let accessed = reader.seen.borrow().len() as u64;
        if accessed > list_max {
            return Err(denied(
                diagnostics,
                principal,
                Method::List,
                candidate.relative(),
                format!("RULES-DOC-ACCESS-MULTI-TOTAL: {accessed} exceeds {list_max}"),
            ));
        }
    }
    Ok(())
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
    diagnostics: Option<&Mutex<RulesDiagnostics>>,
) -> Result<(), Status> {
    let dependencies = ruleset.value_dependencies();
    let ctx = RequestContext {
        service: RulesService::Firestore,
        method,
        path: rules_path(path),
        auth: match principal {
            Principal::User(a) => Some(a.clone()),
            _ => None,
        },
        resource: resource
            .filter(|_| dependencies.existing_resource())
            .map(resource_value),
        request_resource: request_resource
            .filter(|_| dependencies.request_resource())
            .map(resource_value),
        time_unix_nanos: now.as_nanos(),
        abstract_path: false,
        request_query: None,
    };
    decide(ruleset, ctx, method, path, access, diagnostics)
}

fn decide(
    ruleset: &Ruleset,
    ctx: RequestContext,
    method: Method,
    path: &DocumentPath,
    access: &dyn DocumentAccess,
    diagnostics: Option<&Mutex<RulesDiagnostics>>,
) -> Result<(), Status> {
    let uid = ctx.auth.as_ref().map(|auth| auth.uid.clone());
    let (report, coverage) = evaluate_request_traced_owned(ruleset, ctx, Some(access));
    let denial = match &report.decision {
        Decision::Allow => None,
        Decision::Deny(reason) => Some(format!(
            "{} on {} denied by Security Rules: {}",
            method_name(method),
            path.relative(),
            deny_text(reason)
        )),
    };
    if let Some(sink) = diagnostics {
        let trace_enabled = sink.lock().is_ok_and(|sink| sink.request_traces_enabled());
        let trace = trace_enabled.then(|| {
            let expressions: Vec<CoverageEntry> = coverage.entries().into_iter().cloned().collect();
            let path = path.relative();
            let reason = denial.clone().unwrap_or_default();
            (expressions, path, uid, reason)
        });
        if let Ok(mut sink) = sink.lock() {
            if let Some((expressions, path, uid, reason)) = trace {
                sink.push(&coverage, move |sequence| RequestTrace {
                    sequence,
                    method: method_name(method),
                    path,
                    allowed: reason.is_empty(),
                    reason,
                    uid,
                    expressions,
                });
            } else {
                sink.merge_coverage(&coverage);
            }
        }
    }
    match denial {
        None => Ok(()),
        Some(_) => Err(Status::permission_denied(PERMISSION_DENIED_MESSAGE)),
    }
}

/// What production answers for every Security Rules denial, in both profiles (FS-RULES scope
/// decision R6). The reason fireemu found stays in the ruleset's request traces. Production
/// answers the same for a credential it cannot verify, another scheme and an empty bearer.
pub const PERMISSION_DENIED_MESSAGE: &str = "Missing or insufficient permissions.";

/// Production's answer to an ID token past its allowance (FS-RULES, 2026-09-24).
pub const EXPIRED_CREDENTIALS_MESSAGE: &str = "Missing or invalid authentication.";

/// The front end's answer to a bearer value that is not a JWT, which it takes for an OAuth
/// access token (FS-RULES, 2026-09-24).
pub const INVALID_CREDENTIALS_MESSAGE: &str = "Request had invalid authentication credentials. Expected OAuth 2 access token, login cookie or other valid authentication credential. See https://developers.google.com/identity/sign-in/web/devconsole-project.";

/// A denial decided outside the evaluator (a budget across items, an exact-name query): traced
/// with its reason like an evaluated one, answered with production's text.
fn denied(
    diagnostics: &Mutex<RulesDiagnostics>,
    principal: &Principal,
    method: Method,
    path: String,
    reason: String,
) -> Status {
    if let Ok(mut sink) = diagnostics.lock() {
        if sink.request_traces_enabled() {
            let uid = match principal {
                Principal::User(auth) => Some(auth.uid.clone()),
                _ => None,
            };
            sink.push(&Coverage::default(), move |sequence| RequestTrace {
                sequence,
                method: method_name(method),
                path,
                allowed: false,
                reason,
                uid,
                expressions: Vec::new(),
            });
        }
    }
    Status::permission_denied(PERMISSION_DENIED_MESSAGE)
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
    let mut exclusions: BTreeMap<&FieldPath, Vec<RulesValue>> = BTreeMap::new();
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
                match op {
                    FieldOp::NotEqual => exclusions
                        .entry(field)
                        .or_default()
                        .push(rules_value(value)),
                    FieldOp::NotIn => {
                        if let Value::Array(items) = value {
                            exclusions
                                .entry(field)
                                .or_default()
                                .extend(items.iter().map(rules_value));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    for (field, range) in &ranges {
        let value = match (range.clone(), exclusions.get(field)) {
            (Some(range), Some(excluded)) => RulesValue::RangeExcluding {
                range,
                excluded: excluded.clone(),
            },
            (Some(range), None) => RulesValue::Range(range),
            (None, _) => RulesValue::Unknown,
        };
        set_nested(&mut data, field, value);
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
                _ => {}
            },
            FilterExpr::Unary {
                field,
                op: UnaryOp::IsNull,
            } => set_nested(&mut data, field, RulesValue::Null),
            _ => {}
        }
    }
    for (field, excluded) in exclusions {
        if !ranges.contains_key(field) {
            set_nested_exclusion(&mut data, field, excluded);
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

/// `request.query` of a list request: `limit`, `offset` and `orderBy`.
///
/// `orderBy` is a **map** from field path to `"ASC"` / `"DESC"`, which is what the pinned
/// official emulator carries: `request.query.orderBy.keys() == ['n']` and
/// `request.query.orderBy['n'] == 'ASC'` both hold for a query ordered by `n` ascending,
/// while `orderBy is list` does not (`conformance/rules-programs.json`,
/// `query-order-by-shape`). Without an explicit ordering it is `null`, as `limit` is
/// without a limit.
/// The name of the ninth `request.query` key. The FS-RULES exploration (2026-09-25, not
/// evidence) read its first 12 characters, `selectOnlyKe`, a length over 12 and a bool; the
/// rest of the name is inferred until it is read.
pub const REQUEST_QUERY_KEYS_ONLY_KEY: &str = "selectOnlyKeys";

/// `request.query` as production builds it: the three documented keys and six more (FS-RULES
/// exploration 2026-09-25, not evidence). Observed for a plain root query: `kind` is the
/// collection id, `parent` null, `allDescendants` and `distinct` false, `groupBy` a map and the
/// keys-only flag a bool. Unobserved: `kind` of a query without a collection id (empty here),
/// `parent` below a document (its path here), `groupBy`'s members (none here) and the keys-only
/// flag's value (true here only for a projection of exactly `__name__`).
fn query_value(query: &Query) -> RulesValue {
    let (parent, kind, all_descendants) = match &query.scope {
        QueryScope::Collection {
            parent,
            collection_id,
        } => (parent, collection_id.as_str(), false),
        QueryScope::CollectionGroup {
            parent,
            collection_id,
        } => (parent, collection_id.as_str(), true),
        QueryScope::KindlessAllDescendants { parent } => (parent, "", true),
        QueryScope::KindlessChildren { parent } => (parent, "", false),
    };
    let mut m = BTreeMap::new();
    m.insert(
        "allDescendants".to_owned(),
        RulesValue::Bool(all_descendants),
    );
    m.insert("distinct".to_owned(), RulesValue::Bool(false));
    m.insert("groupBy".to_owned(), RulesValue::Map(BTreeMap::new()));
    m.insert("kind".to_owned(), RulesValue::String(kind.to_owned()));
    m.insert(
        "parent".to_owned(),
        parent.as_ref().map_or(RulesValue::Null, |document| {
            RulesValue::Path(rules_document_segments(document))
        }),
    );
    m.insert(
        REQUEST_QUERY_KEYS_ONLY_KEY.to_owned(),
        RulesValue::Bool(
            query
                .projection
                .as_ref()
                .is_some_and(|fields| fields.len() == 1 && fields[0].is_document_name()),
        ),
    );
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
    m.insert("orderBy".to_owned(), {
        // A map in every query, empty when it has no order (FS-RULES, 2026-09-24).
        RulesValue::Map(
            query
                .order_by
                .iter()
                .map(|o| {
                    (
                        o.field.canonical(),
                        RulesValue::String(
                            match o.direction {
                                Direction::Ascending => "ASC",
                                Direction::Descending => "DESC",
                            }
                            .to_owned(),
                        ),
                    )
                })
                .collect(),
        )
    });
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
        if !matches!(
            entry,
            RulesValue::PartialMap(_) | RulesValue::PartialMapExcluding { .. } | RulesValue::Map(_)
        ) {
            *entry = RulesValue::PartialMap(BTreeMap::new());
        }
        map = match entry {
            RulesValue::PartialMap(m) | RulesValue::Map(m) => m,
            RulesValue::PartialMapExcluding { fields, .. } => fields,
            _ => return,
        };
    }
    if let Some(last) = segments.last() {
        map.insert(last.clone(), value);
    }
}

/// Merges a parent-level exclusion with any partial child constraints already present at that
/// path. Query proofs need both facts: a child range remains available to the evaluator while
/// the complete map is known not to equal each excluded value.
fn set_nested_exclusion(
    fields: &mut BTreeMap<String, RulesValue>,
    path: &FieldPath,
    excluded_values: Vec<RulesValue>,
) {
    let segments = path.segments();
    let Some(last) = segments.last() else {
        return;
    };
    let mut map = fields;
    for segment in &segments[..segments.len() - 1] {
        let entry = map
            .entry(segment.clone())
            .or_insert_with(|| RulesValue::PartialMap(BTreeMap::new()));
        if let RulesValue::NotOneOf(excluded) = entry {
            // A parent exclusion may be encountered before a nested exclusion (the
            // BTreeMap ordering is parent-first). Preserve it while introducing the
            // partial child map instead of replacing the parent's constraint.
            let parent_excluded = std::mem::take(excluded);
            *entry = RulesValue::PartialMapExcluding {
                fields: BTreeMap::new(),
                excluded: parent_excluded,
            };
        } else if !matches!(
            entry,
            RulesValue::PartialMap(_) | RulesValue::PartialMapExcluding { .. } | RulesValue::Map(_)
        ) {
            *entry = RulesValue::PartialMap(BTreeMap::new());
        }
        map = match entry {
            RulesValue::PartialMap(m) | RulesValue::Map(m) => m,
            RulesValue::PartialMapExcluding { fields, .. } => fields,
            _ => return,
        };
    }
    let merged = match map.remove(last) {
        Some(RulesValue::PartialMap(fields)) => RulesValue::PartialMapExcluding {
            fields,
            excluded: excluded_values,
        },
        Some(RulesValue::PartialMapExcluding {
            fields,
            mut excluded,
        }) => {
            excluded.extend(excluded_values);
            RulesValue::PartialMapExcluding { fields, excluded }
        }
        Some(RulesValue::NotOneOf(mut previous)) => {
            previous.extend(excluded_values);
            RulesValue::NotOneOf(previous)
        }
        Some(existing) => existing,
        None => RulesValue::NotOneOf(excluded_values),
    };
    map.insert(last.clone(), merged);
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
    use fireemu_core_firestore::query::QueryScope;
    let relative = match &query.scope {
        QueryScope::Collection {
            parent: Some(parent),
            collection_id,
        } => format!(
            "{}/{}/{ABSTRACT_SEGMENT}",
            parent.relative(),
            collection_id.as_str()
        ),
        QueryScope::Collection {
            parent: None,
            collection_id,
        } => format!("{}/{ABSTRACT_SEGMENT}", collection_id.as_str()),
        QueryScope::CollectionGroup { collection_id, .. } => {
            format!("{ABSTRACT_PREFIX}/{ABSTRACT_PREFIX}/{collection_id}/{ABSTRACT_SEGMENT}")
        }
        QueryScope::KindlessAllDescendants {
            parent: Some(parent),
        } => format!(
            "{}/{ABSTRACT_PREFIX}/{ABSTRACT_SEGMENT}/{ABSTRACT_PREFIX}/{ABSTRACT_SEGMENT}",
            parent.relative()
        ),
        QueryScope::KindlessAllDescendants { parent: None } => {
            format!("{ABSTRACT_PREFIX}/{ABSTRACT_SEGMENT}/{ABSTRACT_PREFIX}/{ABSTRACT_SEGMENT}")
        }
        // Any collection directly under the parent: the collection id is undetermined too.
        QueryScope::KindlessChildren {
            parent: Some(parent),
        } => format!(
            "{}/{ABSTRACT_SEGMENT}/{ABSTRACT_SEGMENT}",
            parent.relative()
        ),
        QueryScope::KindlessChildren { parent: None } => {
            format!("{ABSTRACT_SEGMENT}/{ABSTRACT_SEGMENT}")
        }
    };
    let path = DocumentPath::parse(&parent.project, &parent.database, &relative)
        .map_err(|e| Status::invalid_argument(e.to_string()))?;
    Ok(vec![path])
}

/// Finite same-database candidates of a pure `__name__ ==`/`in` query. Any additional
/// predicate, cursor, offset or limit falls back to the content-independent constraint proof.
fn exact_name_candidates(parent: &Parent, query: &Query) -> Option<Vec<DocumentPath>> {
    if query.limit.is_some()
        || query.offset != 0
        || query.start_at.is_some()
        || query.end_at.is_some()
    {
        return None;
    }
    let prefix = format!(
        "projects/{}/databases/{}/documents/",
        parent.project.as_str(),
        parent.database.as_str()
    );
    let mut candidates = BTreeSet::new();
    for disjunction in query.dnf() {
        let [FilterExpr::Field {
            field,
            op: FieldOp::Equal,
            value: Value::Reference(reference),
        }] = disjunction.as_slice()
        else {
            return None;
        };
        if !field.is_document_name() {
            return None;
        }
        let relative = reference.strip_prefix(&prefix)?;
        let path = DocumentPath::parse(&parent.project, &parent.database, relative).ok()?;
        if !query_scope_contains(&query.scope, &path) {
            return None;
        }
        candidates.insert(path);
    }
    (!candidates.is_empty()).then(|| candidates.into_iter().collect())
}

fn query_scope_contains(
    scope: &fireemu_core_firestore::query::QueryScope,
    path: &DocumentPath,
) -> bool {
    use fireemu_core_firestore::query::QueryScope;
    match scope {
        QueryScope::Collection {
            parent,
            collection_id,
        } => {
            path.parent_document().as_ref() == parent.as_ref()
                && path.collection_id() == collection_id
        }
        QueryScope::CollectionGroup {
            parent,
            collection_id,
        } => {
            path.collection_id() == collection_id
                && parent
                    .as_ref()
                    .is_none_or(|ancestor| path_is_below(path, ancestor))
        }
        QueryScope::KindlessAllDescendants { parent } => parent
            .as_ref()
            .is_none_or(|ancestor| path_is_below(path, ancestor)),
        QueryScope::KindlessChildren { parent } => {
            path.parent_document().as_ref() == parent.as_ref()
        }
    }
}

fn path_is_below(path: &DocumentPath, ancestor: &DocumentPath) -> bool {
    path.pairs().len() > ancestor.pairs().len()
        && path.pairs()[..ancestor.pairs().len()] == *ancestor.pairs()
}

fn rules_document_segments(path: &DocumentPath) -> Vec<String> {
    [
        "databases".to_owned(),
        path.database().as_str().to_owned(),
        "documents".to_owned(),
    ]
    .into_iter()
    .chain(path.relative().split('/').map(str::to_owned))
    .collect()
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

#[cfg(test)]
mod tests {
    use super::abstract_resource;
    use fireemu_core_firestore::field_path::FieldPath;
    use fireemu_core_firestore::query::{FieldOp, FilterExpr};
    use fireemu_core_firestore::value::Value;
    use fireemu_core_rules::value::RulesValue;
    use std::collections::BTreeMap;

    #[test]
    fn abstract_resource_retains_parent_exclusion_when_nested_exclusion_is_added() {
        let parent = FieldPath::parse("meta").unwrap();
        let nested = FieldPath::parse("meta.score").unwrap();
        let mut excluded_map = BTreeMap::new();
        excluded_map.insert("score".to_owned(), Value::Integer(6));
        let resource = abstract_resource(&[
            FilterExpr::Field {
                field: parent,
                op: FieldOp::NotEqual,
                value: Value::Map(excluded_map),
            },
            FilterExpr::Field {
                field: nested,
                op: FieldOp::NotEqual,
                value: Value::Integer(5),
            },
        ]);

        let RulesValue::Map(resource) = resource else {
            panic!("resource should be a map");
        };
        let RulesValue::PartialMap(data) = resource.get("data").expect("resource data") else {
            panic!("resource data should be a partial map");
        };
        let RulesValue::PartialMapExcluding { fields, excluded } =
            data.get("meta").expect("meta constraint")
        else {
            panic!("parent exclusion must be retained alongside nested constraints");
        };
        assert_eq!(
            fields.get("score"),
            Some(&RulesValue::NotOneOf(vec![RulesValue::Int(5)]))
        );
        assert_eq!(excluded.len(), 1);
        assert!(matches!(
            &excluded[0],
            RulesValue::Map(values)
                if values.get("score") == Some(&RulesValue::Int(6))
        ));
    }

    #[test]
    fn a_kindless_children_query_stands_for_any_direct_child_of_its_parent() {
        use super::{placeholder_paths, query_scope_contains};
        use crate::decode::Parent;
        use fireemu_core_firestore::path::DocumentPath;
        use fireemu_core_firestore::query::{Query, QueryScope};
        use fireemu_core_rules::eval::ABSTRACT_SEGMENT;
        use fireemu_core_types::ids::{DatabaseId, ProjectId};
        let project = ProjectId::try_new("p").unwrap();
        let database = DatabaseId::try_new("(default)").unwrap();
        let doc = |relative: &str| DocumentPath::parse(&project, &database, relative).unwrap();
        let parent = Parent {
            project: project.clone(),
            database: database.clone(),
            document: None,
        };
        let root = Query::new(QueryScope::kindless_children(None));
        assert_eq!(
            placeholder_paths(&parent, &root).unwrap(),
            vec![doc(&format!("{ABSTRACT_SEGMENT}/{ABSTRACT_SEGMENT}"))]
        );
        let nested = Query::new(QueryScope::kindless_children(Some(doc("a/b"))));
        assert_eq!(
            placeholder_paths(&parent, &nested).unwrap(),
            vec![doc(&format!("a/b/{ABSTRACT_SEGMENT}/{ABSTRACT_SEGMENT}"))]
        );
        assert!(query_scope_contains(&root.scope, &doc("x/1")));
        assert!(!query_scope_contains(&root.scope, &doc("x/1/y/2")));
        assert!(query_scope_contains(&nested.scope, &doc("a/b/c/d")));
        assert!(!query_scope_contains(&nested.scope, &doc("a/b/c/d/e/f")));
        assert!(!query_scope_contains(&nested.scope, &doc("a/c/c/d")));
    }
}
