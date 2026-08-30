//! Control API (`CTL-1` subset, spec 15): virtual clock manipulation, health, capabilities.
//!
//! ```text
//! GET  /health/live
//! GET  /health/ready
//! GET  /v1/capabilities
//! GET  /v1/sessions/{session}                 -> { "clock": "<rfc3339>" }
//! POST /v1/sessions/{session}/clock:set       { "instant": "<rfc3339>" }
//! POST /v1/sessions/{session}/clock:advance   { "seconds": n } | { "millis": n }
//! POST /v1/sessions/{session}/clock:advanceTo { "instant": "<rfc3339>" }
//! POST /v1/sessions/{session}:awaitIdle       { "timeoutSeconds": n }
//! GET  /v1/sessions/{session}/functions
//! POST /v1/sessions/{session}/functions/{name}:run
//! ```
//!
//! The daemon currently runs one implicit session; every session name maps to it. Sessions,
//! snapshots and `await-idle` arrive with the session runtime.

use std::sync::{Arc, Mutex, RwLock};

use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_session::tenancy::Scope;
use ftd_core_types::determinism::Clock;
use ftd_core_types::edition::FirestoreEdition;
use ftd_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::{json, Value};

use crate::identity_toolkit::{JsonResponse, RequestHeaders};

/// The functions runtime as the control API sees it (spec 10.5 `await-idle`, 11.2 clock
/// operations, manual schedule runs).
pub trait FunctionsHook: Send + Sync {
    /// The virtual clock moved: enqueue due schedules and release due retries.
    fn on_clock_changed(&self);
    /// Runs a scheduled function now.
    fn run_schedule(&self, function: &str) -> Result<(), String>;
    /// Whether no event is pending, leased, running or retry-waiting.
    fn is_idle(&self) -> bool;
    /// Notified whenever work completes.
    fn idle_notify(&self) -> Arc<tokio::sync::Notify>;
    /// Status JSON (queue depths, functions).
    fn status(&self) -> Value;
    /// Publishes Pub/Sub messages (`{data, attributes, orderingKey}` each) on `topic`;
    /// returns the message IDs.
    fn publish(&self, topic: &str, messages: &[Value]) -> Result<Vec<String>, String>;
    /// The project the functions belong to (the Pub/Sub REST path must name it).
    fn project(&self) -> String;
}

/// One adapter's failure during a session-state transition (a reset, a deletion, a
/// snapshot capture or a restore). The part names the store that could not take part, so
/// the response can say whether Storage or Auth was the one that refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionFailure {
    /// The store that failed (`firestore`, `storage`, `auth`, ...).
    pub part: &'static str,
    /// What went wrong.
    pub message: String,
}

impl TransitionFailure {
    /// A failure of `part`.
    pub fn new(part: &'static str, message: impl Into<String>) -> Self {
        Self {
            part,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for TransitionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.part, self.message)
    }
}

impl std::error::Error for TransitionFailure {}

/// Per-project state management for sessions other than the default one.
///
/// `reset_scope` and `remove` own several stores at once (Firestore databases, Storage
/// buckets, an Auth store). Both must check every store they will touch before they
/// mutate any of them, so that a failure leaves the project exactly as it was: the
/// control routes report the failure instead of publishing a half-wiped session.
pub trait ProjectHooks: Send + Sync {
    /// A session for `project` was created: allocate its state (an Auth store, ...).
    fn create(&self, project: &str) -> Result<(), String>;
    /// Wipe everything `scope` owns (Firestore databases, buckets, Auth users).
    fn reset_scope(&self, scope: &Scope) -> Result<(), TransitionFailure>;
    /// Drop the project's state and forget it.
    fn remove(&self, project: &str) -> Result<(), TransitionFailure>;
}

/// One adapter's part of a session snapshot: an opaque copy of its state.
pub type SnapshotPart = Arc<dyn std::any::Any + Send + Sync>;

/// Captures and restores one adapter's state (Firestore databases, Storage objects, Auth
/// users, the clock, ...). `restore` runs under the exclusive session barrier, in the
/// order the hooks were registered.
///
/// A restore is a validate / prepare / apply protocol driven by the snapshot route: every
/// hook's [`SnapshotHook::validate`] runs first, then every hook's
/// [`SnapshotHook::capture`] takes a pre-image, and only then does the first
/// [`SnapshotHook::restore`] mutate anything. A hook that rejects the apply is rolled back
/// by re-applying the pre-image to the hooks before it, so no request ever observes a
/// half-restored session.
pub trait SnapshotHook: Send + Sync {
    /// Part name (`firestore`, `auth`, ...).
    fn name(&self) -> &'static str;
    /// Whether the part is shared by every session (the clock, rules, functions): only the
    /// default session's snapshots carry it.
    fn shared(&self) -> bool {
        false
    }
    /// Captures what `scope` owns. Never mutates: the restore protocol also uses it to
    /// take the pre-image it rolls back to.
    fn capture(&self, scope: &Scope) -> Result<SnapshotPart, TransitionFailure>;
    /// Whether `part` belongs to this hook and `scope` can be restored right now, without
    /// mutating anything. Every hook is validated before any hook applies.
    fn validate(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure>;
    /// Puts a captured part back for `scope`.
    fn restore(&self, scope: &Scope, part: &SnapshotPart) -> Result<(), TransitionFailure>;
}

/// How many named snapshots one session may retain (`SNAP-MEM-01`). Each one holds a full
/// copy of the session's Firestore databases, Storage objects, Auth store, fault state and
/// text indexes, so an unbounded set of unique names would keep a test's whole history
/// resident for the daemon's lifetime. Capturing a new name beyond this budget is refused
/// with `RESOURCE_EXHAUSTED` (429) and changes nothing; replacing a name that is already
/// retained is always allowed and releases what that name held.
pub const MAX_SNAPSHOTS_PER_SESSION: usize = 16;

/// A named snapshot.
pub struct Snapshot {
    /// The clock at capture.
    pub clock: String,
    /// One part per hook, in hook order (`None` for a shared part a project session skips).
    pub parts: Vec<Option<SnapshotPart>>,
}

/// Shared control-plane state.
pub struct ControlState {
    /// The virtual clock shared by every adapter.
    pub clock: Arc<Mutex<VirtualClock>>,
    /// Only `demo-` project IDs are accepted by the Firestore surface.
    pub require_demo_prefix: bool,
    /// Configured edition.
    pub edition: FirestoreEdition,
    /// Capability manifest served at `/v1/capabilities`.
    pub capabilities: Value,
    /// Loaded Firestore Security Rules (shared with the gRPC adapter).
    pub rules: Arc<RwLock<LoadedRules>>,
    /// Loaded Storage Security Rules (shared with the Storage adapter).
    pub storage_rules: Arc<RwLock<LoadedRules>>,
    /// Hooks run by a reset of the default session after its scope is wiped (the shared
    /// parts: the functions runtime).
    pub reset_hooks: Vec<Arc<dyn Fn() + Send + Sync>>,
    /// Snapshot capture / restore, one hook per adapter.
    pub snapshot_hooks: Vec<Arc<dyn SnapshotHook>>,
    /// Snapshots kept in memory, by session then name (at most
    /// [`MAX_SNAPSHOTS_PER_SESSION`] per session).
    pub snapshots: Mutex<SnapshotStore>,
    /// The sessions' fault plans (spec 18), one state per session, shared with every
    /// adapter.
    pub faults: Option<ftd_core_session::fault::SharedFaultRegistry>,
    /// Text Index definitions (`FS-TEXT-VAL-1`, strict validation only), by database.
    pub text_indexes: Arc<Mutex<ftd_core_firestore::text_index::TextIndexCatalog>>,
    /// The default session's project.
    pub default_project: String,
    /// Which session owns which project, bucket and API key.
    pub tenancy: ftd_core_session::tenancy::SharedTenancy,
    /// Sessions by name → project (`default` is always present). Sessions are isolated
    /// by project: each has its own Firestore databases, Storage buckets, Auth store,
    /// fault plan, snapshots and text indexes; the virtual clock, rules and functions
    /// are shared (they belong to the default session).
    pub sessions: Mutex<SessionMap>,
    /// Per-project state hooks for the sessions other than the default one.
    pub project_hooks: Option<Arc<dyn ProjectHooks>>,
    /// Functions runtime, when configured.
    pub functions: Option<Arc<dyn FunctionsHook>>,
    /// Session admission barrier: a reset holds it exclusively across every hook, so no
    /// request straddles a half-reset session; other control mutations are admitted.
    pub barrier: Option<Arc<ftd_core_session::barrier::AdmissionBarrier>>,
    /// Control token (spec 15.2): browser requests (those carrying an `Origin`) must present
    /// it as `Authorization: Bearer <token>` on privileged routes, so a page on localhost
    /// cannot reset state, move the clock or change rules; command-line clients on loopback
    /// need not.
    pub control_token: String,
    /// The App Check registry, when App Check is enabled: the observation route reads it, and
    /// the lifecycle hooks rotate epochs through it.
    pub app_check: Option<ftd_core_app_check::AppCheckGate>,
}

/// Where the App Check observations of one session are served.
///
/// The route is privileged for every method whatever the `Origin` (specification section 15),
/// unlike the rest of the control API, whose guard only challenges browser requests: the
/// detailed failure reasons here are exactly what an unprivileged view must never see.
pub const APP_CHECK_OBSERVATIONS_SUFFIX: &str = "/appCheck/observations";

/// Whether a response to `path` must carry `Cache-Control: no-store`.
#[must_use]
pub fn is_no_store_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    path.starts_with("/v1/sessions/") && path.ends_with(APP_CHECK_OBSERVATIONS_SUFFIX)
}

fn error(status: u16, message: &str) -> JsonResponse {
    JsonResponse {
        status,
        body: json!({"error": {"code": status, "message": message}}),
    }
}

fn ok(body: Value) -> JsonResponse {
    JsonResponse { status: 200, body }
}

/// Whether a presented bearer value is the control token, compared in constant time like the
/// other credentials the daemon holds (debug tokens, download tokens, the runner secret).
#[must_use]
pub fn token_matches(presented: Option<&str>, expected: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    let Some(presented) = presented else {
        return false;
    };
    // A length mismatch is a mismatch; lengths are not secret.
    presented.len() == expected.len() && bool::from(presented.as_bytes().ct_eq(expected.as_bytes()))
}

/// What the session owning `project` owns.
fn scope_of(state: &ControlState, project: &str) -> Scope {
    state.tenancy.read().map_or_else(
        |_| Scope::Project(project.to_owned()),
        |t| t.scope_of(project),
    )
}

/// Retained snapshots by session then name.
pub type SnapshotStore =
    std::collections::BTreeMap<String, std::collections::BTreeMap<String, Snapshot>>;

/// Sessions by name to project.
pub type SessionMap = std::collections::BTreeMap<String, String>;

/// Whether every book a session is registered in can be written. The only failure these
/// locks have is poisoning, which is permanent, so a probe that passes means the apply
/// that follows cannot fail on a lock. Each is taken and released on its own: a caller
/// runs project hooks between the probe and the apply, and those reach the same registries.
fn probe_session_books(state: &ControlState) -> Option<JsonResponse> {
    let poisoned = if state.sessions.lock().is_err() {
        "the session map"
    } else if state.tenancy.write().is_err() {
        "the tenancy registry"
    } else if state.text_indexes.lock().is_err() {
        "the text index catalog"
    } else if state.snapshots.lock().is_err() {
        "the snapshot store"
    } else {
        return None;
    };
    Some(error(
        500,
        &format!("INTERNAL : {poisoned} is poisoned; the session is unchanged"),
    ))
}

/// Applies `apply` to every book a session is registered in at once, so that a
/// deregistration cannot be observed half done. The locks are taken in the order a
/// creation takes them (the session map, then the tenancy registry, then the text index
/// catalog, then the snapshot store), and both callers hold the exclusive barrier.
fn with_session_books(
    state: &ControlState,
    apply: impl FnOnce(
        &mut SnapshotStore,
        &mut ftd_core_firestore::text_index::TextIndexCatalog,
        &mut ftd_core_session::tenancy::Tenancy,
        &mut SessionMap,
    ),
) -> Result<(), String> {
    let mut sessions = state
        .sessions
        .lock()
        .map_err(|_| "the session map is poisoned".to_owned())?;
    let mut tenancy = state
        .tenancy
        .write()
        .map_err(|_| "the tenancy registry is poisoned".to_owned())?;
    let mut catalog = state
        .text_indexes
        .lock()
        .map_err(|_| "the text index catalog is poisoned".to_owned())?;
    let mut snapshots = state
        .snapshots
        .lock()
        .map_err(|_| "the snapshot store is poisoned".to_owned())?;
    apply(&mut snapshots, &mut catalog, &mut tenancy, &mut sessions);
    Ok(())
}

fn clock_json(clock: &VirtualClock) -> Value {
    json!({"clock": clock.now().to_rfc3339().unwrap_or_else(|_| clock.now().to_string()), "backwardsSets": clock.backwards_sets()})
}

/// Whether `path` belongs to the control API.
#[must_use]
pub fn is_control_path(path: &str) -> bool {
    path.starts_with("/v1/") || path.starts_with("/health/")
}

/// Routes one control request.
#[must_use]
pub fn handle(state: &ControlState, method: &str, path: &str, body: &Value) -> JsonResponse {
    handle_with(state, method, path, &RequestHeaders::default(), body)
}

/// Routes one control request with its headers: browser requests from non-loopback origins
/// are refused (the control API mutates runtime state).
#[must_use]
pub fn handle_with(
    state: &ControlState,
    method: &str,
    path: &str,
    headers: &RequestHeaders,
    body: &Value,
) -> JsonResponse {
    if let Some(refusal) = browser_guard(state, method, path, headers) {
        return refusal;
    }
    let path = path.split('?').next().unwrap_or(path);
    match (method, path) {
        ("GET", "/health/live" | "/health/ready") => ok(json!({"status": "ok"})),
        ("GET", "/v1/capabilities") => ok(state.capabilities.clone()),
        ("GET", "/v1/limits") => ok(json!({
            "catalogs": ftd_core_limits::catalogs::ALL_CATALOGS.iter().map(|c| json!({
                "id": c.meta.id,
                "product": c.meta.product,
                "edition": c.meta.edition,
                "officialLastUpdatedUtc": c.meta.official_last_updated_utc,
                "limits": c.limits.iter().map(|l| json!({
                    "id": l.id,
                    "boundary": format!("{:?}", l.boundary),
                    "unit": format!("{:?}", l.unit),
                    "maximum": match l.maximum {
                        ftd_core_limits::model::LimitMaximum::Fixed(v) => json!(v),
                        ftd_core_limits::model::LimitMaximum::PlanDependent { billing_disabled, billing_enabled } => json!({"billingDisabled": billing_disabled, "billingEnabled": billing_enabled}),
                        ftd_core_limits::model::LimitMaximum::NotApplicable => Value::Null,
                    },
                    "precision": format!("{:?}", l.precision),
                    "implemented": format!("{:?}", l.implemented),
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>()
        })),
        ("GET", "/v1/sessions") => {
            let Ok(sessions) = state.sessions.lock() else {
                return error(500, "INTERNAL");
            };
            let tenancy = state.tenancy.read().ok();
            ok(json!({"sessions": sessions.iter().map(|(name, project)| {
                let buckets = tenancy.as_ref().map(|t| t.declared_buckets(project)).unwrap_or_default();
                json!({"name": name, "project": project, "buckets": buckets})
            }).collect::<Vec<_>>()}))
        }
        ("POST", "/v1/sessions") => create_session(state, body),
        (m, p) if p.starts_with("/v1/sessions/") && p.ends_with(APP_CHECK_OBSERVATIONS_SUFFIX) => {
            app_check_observations(state, m, p, headers)
        }
        (m, p) if p.starts_with("/v1/sessions/") => session_route(state, m, p, body),
        // The Pub/Sub REST shape (`projects/{p}/topics/{t}:publish`), for clients that speak it.
        ("POST", p) if p.starts_with("/v1/projects/") && p.ends_with(":publish") => {
            let _admitted = state.barrier.as_ref().map(|b| b.admit());
            match p["/v1/projects/".len()..]
                .strip_suffix(":publish")
                .and_then(|r| r.split_once("/topics/"))
            {
                Some((project, topic)) if !topic.is_empty() && !topic.contains('/') => {
                    match &state.functions {
                        Some(f) if f.project() != project => error(
                            404,
                            &format!("NOT_FOUND : this runtime serves project {}", f.project()),
                        ),
                        _ => publish_route(state, topic, body),
                    }
                }
                _ => error(404, "NOT_FOUND"),
            }
        }
        ("GET" | "PUT" | "DELETE", "/v1/storage/rules") => {
            let _admitted = state.barrier.as_ref().map(|b| b.admit());
            rules_route(&state.storage_rules, method, body)
        }
        ("GET", "/v1/rules") => match state.rules.read() {
            Ok(r) => ok(json!({"loaded": r.is_loaded(), "source": r.source})),
            Err(_) => error(500, "INTERNAL"),
        },
        ("PUT", "/v1/rules") => {
            // Admitted like a data request: a snapshot or reset never straddles it.
            let _admitted = state.barrier.as_ref().map(|b| b.admit());
            let Some(source) = body.get("source").and_then(Value::as_str) else {
                return error(
                    400,
                    "INVALID_ARGUMENT : body.source (rules text) is required",
                );
            };
            match LoadedRules::from_source(source) {
                Ok(loaded) => match state.rules.write() {
                    Ok(mut slot) => {
                        *slot = loaded;
                        ok(json!({"loaded": true}))
                    }
                    Err(_) => error(500, "INTERNAL"),
                },
                Err(e) => error(400, &format!("INVALID_ARGUMENT : rules do not parse: {e}")),
            }
        }
        ("DELETE", "/v1/rules") => {
            let _admitted = state.barrier.as_ref().map(|b| b.admit());
            let slot = state.rules.write();
            match slot {
                Ok(mut slot) => {
                    *slot = LoadedRules::default();
                    ok(json!({"loaded": false}))
                }
                Err(_) => error(500, "INTERNAL"),
            }
        }
        _ => error(404, "NOT_FOUND"),
    }
}

/// GET / PUT / DELETE on a rules slot.
fn rules_route(slot: &RwLock<LoadedRules>, method: &str, body: &Value) -> JsonResponse {
    match method {
        "GET" => match slot.read() {
            Ok(r) => ok(json!({"loaded": r.is_loaded(), "source": r.source})),
            Err(_) => error(500, "INTERNAL"),
        },
        "PUT" => {
            let Some(source) = body.get("source").and_then(Value::as_str) else {
                return error(
                    400,
                    "INVALID_ARGUMENT : body.source (rules text) is required",
                );
            };
            match LoadedRules::from_source(source) {
                Ok(loaded) => match slot.write() {
                    Ok(mut s) => {
                        *s = loaded;
                        ok(json!({"loaded": true}))
                    }
                    Err(_) => error(500, "INTERNAL"),
                },
                Err(e) => error(400, &format!("INVALID_ARGUMENT : rules do not parse: {e}")),
            }
        }
        _ => match slot.write() {
            Ok(mut s) => {
                *s = LoadedRules::default();
                ok(json!({"loaded": false}))
            }
            Err(_) => error(500, "INTERNAL"),
        },
    }
}

/// `POST /v1/sessions {"name"?, "project"}`: a session isolated by project. The name
/// defaults to the project; `demo-` projects only when `requireDemoPrefix` is set.
#[allow(clippy::too_many_lines)]
fn create_session(state: &ControlState, body: &Value) -> JsonResponse {
    let Some(project) = body.get("project").and_then(Value::as_str) else {
        return error(400, "INVALID_ARGUMENT : project is required");
    };
    let valid_id = |s: &str| {
        (1..=63).contains(&s.len())
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !s.starts_with('-')
    };
    if !valid_id(project) {
        return error(
            400,
            "INVALID_ARGUMENT : project must be lowercase letters, digits and dashes (1..=63)",
        );
    }
    if state.require_demo_prefix && !project.starts_with("demo-") {
        return error(
            400,
            "INVALID_ARGUMENT : projects must start with demo- (projects.requireDemoPrefix)",
        );
    }
    let name = body.get("name").and_then(Value::as_str).unwrap_or(project);
    if !valid_id(name) {
        return error(
            400,
            "INVALID_ARGUMENT : name must be lowercase letters, digits and dashes (1..=63)",
        );
    }
    // A first look without the barrier: a name or project that is already taken is
    // refused without disturbing the requests in flight (taking the barrier exclusively
    // publishes a new epoch, ADR-011). The authoritative check runs under it below.
    match state.sessions.lock() {
        Ok(sessions) => {
            if let Some(taken) = conflicting_session(&sessions, name, project) {
                return taken;
            }
        }
        Err(_) => return error(500, "INTERNAL : the session map is poisoned"),
    }
    let mut buckets = Vec::new();
    for (i, b) in body
        .get("buckets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(bucket) = b.as_str() else {
            return error(
                400,
                &format!("INVALID_ARGUMENT : buckets[{i}] must be a string"),
            );
        };
        if let Err(e) = ftd_core_storage::name::BucketName::try_new(bucket) {
            return error(400, &format!("INVALID_ARGUMENT : buckets[{i}]: {e}"));
        }
        buckets.push(bucket.to_owned());
    }
    let mut api_keys = Vec::new();
    for (i, k) in body
        .get("apiKeys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(key) = k.as_str().filter(|k| {
            (1..=128).contains(&k.len())
                && k.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        }) else {
            return error(
                400,
                &format!("INVALID_ARGUMENT : apiKeys[{i}] must be 1..=128 of [A-Za-z0-9._-]"),
            );
        };
        api_keys.push(key.to_owned());
    }
    // Exclusive while the session comes into being: no request observes the tenancy, the
    // Auth store, the fault state and the session map in a half-registered state, and
    // whatever the default session had stored under this project is wiped so the new
    // session starts empty rather than inheriting it. The barrier is taken before the
    // session map, in the same order a reset and a deletion take them.
    let _exclusive = state.barrier.as_ref().map(|b| b.exclusive());
    let Ok(mut sessions) = state.sessions.lock() else {
        return error(500, "INTERNAL : the session map is poisoned");
    };
    if let Some(taken) = conflicting_session(&sessions, name, project) {
        return taken;
    }
    {
        let Ok(mut tenancy) = state.tenancy.write() else {
            return error(500, "INTERNAL : the tenancy registry is poisoned");
        };
        if let Err(e) = tenancy.register(project, &buckets, &api_keys) {
            return error(409, &format!("ALREADY_EXISTS : {e}"));
        }
    }
    if let Some(hooks) = &state.project_hooks {
        if let Err(e) = hooks.create(project) {
            if let Ok(mut tenancy) = state.tenancy.write() {
                tenancy.unregister(project);
            }
            return error(500, &format!("INTERNAL : {e}"));
        }
        // Wiping what the default session held under the project is part of the creation:
        // a store that refuses it takes the whole creation back.
        if let Err(e) = hooks.reset_scope(&Scope::Project(project.to_owned())) {
            let undone = hooks.remove(project).is_ok();
            if let Ok(mut tenancy) = state.tenancy.write() {
                tenancy.unregister(project);
            }
            let tail = if undone {
                "; nothing was registered"
            } else {
                "; the project's Auth store could not be dropped either"
            };
            return error(
                500,
                &format!("INTERNAL : creating session {name:?}: {e}{tail}"),
            );
        }
    }
    if let Ok(mut catalog) = state.text_indexes.lock() {
        catalog.retain_others(|p| p == project);
    }
    if let Some(faults) = &state.faults {
        faults.register(project);
    }
    sessions.insert(name.to_owned(), project.to_owned());
    ok(json!({"name": name, "project": project, "buckets": buckets, "created": true}))
}

/// The refusal for a session name or project that is already taken, if either is.
fn conflicting_session(
    sessions: &std::collections::BTreeMap<String, String>,
    name: &str,
    project: &str,
) -> Option<JsonResponse> {
    if sessions.contains_key(name) {
        return Some(error(409, &format!("ALREADY_EXISTS : session {name:?}")));
    }
    if sessions.values().any(|p| p == project) {
        return Some(error(
            409,
            &format!("ALREADY_EXISTS : project {project:?} already has a session"),
        ));
    }
    None
}

/// `GET /v1/sessions/{session}/appCheck/observations` (specification section 15).
///
/// Every method needs the control token, whether or not an `Origin` is present, because the
/// body carries the stable failure reasons that public responses deliberately collapse. App
/// IDs come from the observations, which already aggregate an unverified identity into the
/// bounded `unknown` bucket, so no caller-supplied text becomes a counter label.
///
/// The registry keeps one ring and one set of counters per project, and this route reads the
/// session's project alone: another project's traffic can neither be read here nor push this
/// project's recent observations out of the window. The counters count every observation
/// recorded since the project was last reset, including the ones the ring has since dropped.
fn app_check_observations(
    state: &ControlState,
    method: &str,
    path: &str,
    headers: &RequestHeaders,
) -> JsonResponse {
    let presented = headers
        .authorization
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(str::trim);
    if !token_matches(presented, &state.control_token) {
        return error(
            403,
            "CONTROL_TOKEN_REQUIRED : App Check observations carry privileged failure reasons and need Authorization: Bearer <control token> on every method",
        );
    }
    let session = path["/v1/sessions/".len()..]
        .strip_suffix(APP_CHECK_OBSERVATIONS_SUFFIX)
        .unwrap_or_default();
    if session.is_empty() || session.contains('/') {
        return error(404, "NOT_FOUND");
    }
    let project = match state.sessions.lock() {
        Ok(sessions) => sessions.get(session).cloned(),
        Err(_) => return error(500, "INTERNAL"),
    };
    let Some(project) = project else {
        return error(
            404,
            &format!("NOT_FOUND : no session {session:?} (POST /v1/sessions creates one)"),
        );
    };
    if method != "GET" {
        return error(405, "METHOD_NOT_ALLOWED : this route is read-only");
    }
    let Some(gate) = &state.app_check else {
        return error(
            404,
            "NOT_FOUND : App Check is not enabled in this runtime (appCheck.enabled)",
        );
    };
    let Ok(registry) = gate.registry().read() else {
        return error(500, "INTERNAL");
    };
    // The session's own project ring and its own counters: a project is never served another
    // project's observations, and no filter here is what makes that true.
    let observations = registry.observations(&project);
    let counters = registry.observation_counters(&project);
    ok(json!({
        "session": session,
        "project": project,
        "policyGeneration": registry.policy_generation(&project),
        "counters": counters.into_iter().map(|(key, count)| json!({
            "service": key.service,
            "appId": key.app_id,
            "function": key.function,
            "category": key.category.as_str(),
            "outcome": key.outcome(),
            "count": count,
        })).collect::<Vec<_>>(),
        "observations": observations.iter().map(|o| json!({
            "service": o.service,
            "transport": o.transport,
            "operation": o.operation,
            "mode": o.mode.as_config_str(),
            "category": o.category.as_str(),
            "reason": o.privileged_reason(),
            "appId": o.app_id,
            "at": o.at.to_rfc3339().unwrap_or_default(),
            "policyGeneration": o.policy_generation,
            "admitted": o.admitted,
        })).collect::<Vec<_>>(),
    }))
}

fn session_route(state: &ControlState, method: &str, path: &str, body: &Value) -> JsonResponse {
    let rest = &path["/v1/sessions/".len()..];
    let (session, action) = rest.split_once('/').map_or((rest, ""), |(s, a)| (s, a));
    if session.is_empty() {
        return error(404, "NOT_FOUND");
    }
    let project = match state.sessions.lock() {
        Ok(sessions) => sessions.get(session).cloned(),
        Err(_) => return error(500, "INTERNAL"),
    };
    let Some(project) = project else {
        return error(
            404,
            &format!("NOT_FOUND : no session {session:?} (POST /v1/sessions creates one)"),
        );
    };
    let is_default = project == state.default_project;
    if (method, action) == ("DELETE", "") {
        if is_default {
            return error(
                400,
                "INVALID_ARGUMENT : the default session cannot be deleted; reset it",
            );
        }
        return delete_session(state, session, &project);
    }
    if (method, action) == ("POST", "reset") {
        return reset_session(state, session, &project, is_default);
    }
    if let Some(rest) = action.strip_prefix("snapshots") {
        return snapshot_route(state, session, &project, method, rest, body);
    }
    if action == "faultPlan" {
        return fault_plan_route(state, session, &project, method, body);
    }
    if let Some(rest) = action.strip_prefix("firestore/text-indexes") {
        return text_index_route(state, session, &project, method, rest, body);
    }
    let _admitted = state.barrier.as_ref().map(|b| b.admit());
    if !is_default && (action.starts_with("functions") || action.starts_with("pubsub/topics/")) {
        // The functions runtime (and its fault plan) belongs to the default session.
        return error(
            400,
            "FAILED_PRECONDITION : functions and Pub/Sub topics belong to the default session; use /v1/sessions/default/...",
        );
    }
    if let Some(rest) = action.strip_prefix("functions") {
        return functions_route(state, method, rest);
    }
    if let Some(rest) = action.strip_prefix("pubsub/topics/") {
        return match (method, rest.strip_suffix(":publish")) {
            ("POST", Some(topic)) if !topic.is_empty() && !topic.contains('/') => {
                publish_route(state, topic, body)
            }
            _ => error(404, "NOT_FOUND"),
        };
    }
    let response = clock_route(state, session, method, action, body);
    if response.status == 200 && action.starts_with("clock:") {
        if let Some(f) = &state.functions {
            f.on_clock_changed();
        }
    }
    response
}

/// `DELETE /v1/sessions/{s}`: wipes the project's state and deregisters the session, or
/// reports which store refused and leaves the session exactly as it was
/// (`SESSION-ATOMIC-03`, `SESSION-ATOMIC-05`).
fn delete_session(state: &ControlState, session: &str, project: &str) -> JsonResponse {
    let _exclusive = state.barrier.as_ref().map(|b| b.exclusive());
    // Validate before anything mutates: every book the deletion writes is probed first.
    // The probes are taken and released one at a time because the project hooks reach the
    // same registries, and holding one across them would deadlock.
    if let Some(refusal) = probe_session_books(state) {
        return refusal;
    }
    // The adapter state goes first: it is the fallible half of the deletion, and it
    // validates its own stores before wiping any of them. Nothing the session is
    // registered in has changed yet, so a refusal leaves the session usable.
    if let Some(hooks) = &state.project_hooks {
        if let Err(e) = hooks.remove(project) {
            return error(
                500,
                &format!("INTERNAL : deleting session {session:?}: {e}; the session is unchanged"),
            );
        }
    }
    if let Some(faults) = &state.faults {
        faults.remove(project);
    }
    let books = with_session_books(state, |snapshots, catalog, tenancy, sessions| {
        snapshots.remove(session);
        catalog.retain_others(|p| p == project);
        tenancy.unregister(project);
        sessions.remove(session);
    });
    if let Err(e) = books {
        return error(
            500,
            &format!("INTERNAL : session {session:?} was wiped but not deregistered: {e}"),
        );
    }
    ok(json!({"session": session, "project": project, "deleted": true}))
}

/// `POST /v1/sessions/{s}/reset`: wipes what the session owns, or reports which store
/// refused and leaves every store as it was (`SESSION-ATOMIC-03`).
fn reset_session(
    state: &ControlState,
    session: &str,
    project: &str,
    is_default: bool,
) -> JsonResponse {
    // Exclusive across every hook: requests in flight finish first, new ones wait. Taking
    // it publishes the new epoch (ADR-011), so work that started in the previous one is
    // discarded whether or not the wipe below succeeds, which is the conservative side of
    // the invariant.
    let _exclusive = state.barrier.as_ref().map(|b| b.exclusive());
    let scope = scope_of(state, project);
    if let Some(hooks) = &state.project_hooks {
        if let Err(e) = hooks.reset_scope(&scope) {
            return error(
                500,
                &format!("INTERNAL : resetting session {session:?}: {e}; no store was wiped"),
            );
        }
    }
    if is_default {
        // The shared parts (functions) belong to the default session.
        for hook in &state.reset_hooks {
            hook();
        }
        return ok(
            json!({"session": session, "project": project, "reset": true, "scope": "default", "hooks": state.reset_hooks.len()}),
        );
    }
    ok(json!({"session": session, "project": project, "reset": true, "scope": "project"}))
}

/// Refuses keys outside `allowed` (strict validation: nothing is silently ignored).
fn only_keys(value: &Value, what: &str, allowed: &[&str]) -> Result<(), String> {
    let Some(obj) = value.as_object() else {
        return Err(format!("{what} must be an object"));
    };
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("{what}.{key} is outside the supported subset"));
        }
    }
    Ok(())
}

/// Parses one entry of the canonical `firestore.text-indexes.json` (`{"index": {...},
/// "xFirebaseTestd": {...}}`, or the bare `index` object) into its project, database and
/// definition. Every level is checked strictly: an unknown or output-only field is refused.
#[allow(clippy::too_many_lines)]
pub fn parse_text_index(
    entry: &Value,
) -> Result<
    (
        String,
        String,
        ftd_core_firestore::text_index::TextIndexDefinition,
    ),
    String,
> {
    use ftd_core_firestore::text_index::{
        DefaultTextLanguage, LanguageOverridePolicy, TextIndexDefinition, TextIndexState,
        TextIndexType, TextIndexedField, TextMatchType,
    };
    let (index, local) = match entry.get("index") {
        Some(index) => {
            only_keys(entry, "entry", &["index", "xFirebaseTestd"])?;
            (index, entry.get("xFirebaseTestd"))
        }
        None => (entry, None),
    };
    only_keys(
        index,
        "index",
        &[
            "name",
            "queryScope",
            "apiScope",
            "fields",
            "searchIndexOptions",
            "state",
            "density",
            "multikey",
            "unique",
            "shardCount",
        ],
    )?;
    for key in ["density", "multikey", "unique", "shardCount"] {
        if index.get(key).is_some() {
            return Err(format!(
                "index.{key} is not supported for text indexes (refused rather than ignored)"
            ));
        }
    }
    if index.get("state").is_some() {
        return Err(
            "index.state is output only (xFirebaseTestd.state models a lifecycle state)".to_owned(),
        );
    }
    let name = index
        .get("name")
        .and_then(Value::as_str)
        .ok_or("index.name is required")?;
    // projects/{p}/databases/{d}/collectionGroups/{c}/indexes/{id}
    let parts: Vec<&str> = name.split('/').collect();
    let (project, database, collection, id) = match parts.as_slice() {
        ["projects", p, "databases", d, "collectionGroups", c, "indexes", id] => (*p, *d, *c, *id),
        _ => {
            return Err(
                "index.name must be projects/{p}/databases/{d}/collectionGroups/{c}/indexes/{id}"
                    .to_owned(),
            )
        }
    };
    ftd_core_types::ids::ProjectId::try_new(project.to_owned())
        .map_err(|e| format!("index.name project: {e}"))?;
    ftd_core_types::ids::DatabaseId::try_new(database.to_owned())
        .map_err(|e| format!("index.name database: {e}"))?;
    let collection_id = ftd_core_types::ids::CollectionId::try_new(collection)
        .map_err(|e| format!("collection group: {e}"))?;
    let query_scope = match index.get("queryScope") {
        None => ftd_core_firestore::index::IndexQueryScope::Collection,
        Some(Value::String(s)) if s == "COLLECTION" => {
            ftd_core_firestore::index::IndexQueryScope::Collection
        }
        Some(Value::String(s)) if s == "COLLECTION_GROUP" => {
            ftd_core_firestore::index::IndexQueryScope::CollectionGroup
        }
        Some(other) => return Err(format!("unsupported queryScope {other}")),
    };
    let api_scope = match index.get("apiScope") {
        None => "ANY_API".to_owned(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => return Err(format!("apiScope must be a string, got {other}")),
    };
    let mut fields = Vec::new();
    for f in index
        .get("fields")
        .and_then(Value::as_array)
        .ok_or("index.fields is required")?
    {
        only_keys(f, "fields[]", &["fieldPath", "searchConfig"])?;
        let path = f
            .get("fieldPath")
            .and_then(Value::as_str)
            .ok_or("fields[].fieldPath is required")?;
        let path = ftd_core_firestore::field_path::FieldPath::parse(path)
            .map_err(|e| format!("fieldPath {path:?}: {e}"))?;
        let Some(config) = f.get("searchConfig") else {
            return Err(format!(
                "field {}: searchConfig.textSpec is required (only text indexes are defined here)",
                path.canonical()
            ));
        };
        only_keys(config, "fields[].searchConfig", &["textSpec"])?;
        let text = config.get("textSpec").ok_or_else(|| {
            format!(
                "field {}: searchConfig.textSpec is required",
                path.canonical()
            )
        })?;
        only_keys(text, "fields[].searchConfig.textSpec", &["indexSpecs"])?;
        let specs = text
            .get("indexSpecs")
            .and_then(Value::as_array)
            .ok_or("textSpec.indexSpecs is required")?;
        let [spec] = specs.as_slice() else {
            return Err(format!(
                "field {}: exactly one indexSpec is supported",
                path.canonical()
            ));
        };
        only_keys(spec, "indexSpecs[]", &["indexType", "matchType"])?;
        let index_type = match spec.get("indexType") {
            None => TextIndexType::Tokenized,
            Some(Value::String(s)) if s == "TOKENIZED" => TextIndexType::Tokenized,
            Some(other) => return Err(format!("unsupported indexType {other} (TOKENIZED only)")),
        };
        let match_type = match spec.get("matchType") {
            None => TextMatchType::MatchGlobally,
            Some(Value::String(s)) if s == "MATCH_GLOBALLY" => TextMatchType::MatchGlobally,
            Some(other) => {
                return Err(format!(
                    "unsupported matchType {other} (MATCH_GLOBALLY only)"
                ))
            }
        };
        fields.push(TextIndexedField {
            path,
            index_type,
            match_type,
        });
    }
    let options = index.get("searchIndexOptions");
    if let Some(o) = options {
        only_keys(
            o,
            "index.searchIndexOptions",
            &["textLanguage", "textLanguageOverrideFieldPath"],
        )?;
    }
    let language = match options.and_then(|o| o.get("textLanguage")) {
        None => DefaultTextLanguage::Autodetect,
        Some(Value::String(s)) if s.is_empty() || s == "auto" => DefaultTextLanguage::Autodetect,
        Some(Value::String(tag)) => DefaultTextLanguage::Tag(tag.clone()),
        Some(other) => return Err(format!("textLanguage must be a string, got {other}")),
    };
    let language_override = match options.and_then(|o| o.get("textLanguageOverrideFieldPath")) {
        Some(Value::String(p)) if !p.is_empty() => LanguageOverridePolicy::ExplicitField(
            ftd_core_firestore::field_path::FieldPath::parse(p)
                .map_err(|e| format!("textLanguageOverrideFieldPath: {e}"))?,
        ),
        Some(Value::String(_)) => LanguageOverridePolicy::Disabled,
        Some(_) => return Err("textLanguageOverrideFieldPath must be a string".to_owned()),
        None => match local.and_then(|l| l.get("languageOverride")) {
            None => LanguageOverridePolicy::BackendDefaultUnresolved,
            Some(Value::String(s)) if s == "implicit" => {
                LanguageOverridePolicy::ImplicitLanguageField
            }
            Some(Value::String(s)) if s == "disabled" => LanguageOverridePolicy::Disabled,
            Some(other) => {
                return Err(format!(
                    "xFirebaseTestd.languageOverride {other} must be implicit or disabled"
                ))
            }
        },
    };
    let mut state = TextIndexState::Ready;
    if let Some(local) = local {
        only_keys(
            local,
            "xFirebaseTestd",
            &["state", "buildPolicy", "languageOverride"],
        )?;
        match local.get("state") {
            None => {}
            Some(Value::String(s)) => {
                state = TextIndexState::parse(s).ok_or_else(|| format!("unknown state {s:?}"))?;
            }
            Some(other) => {
                return Err(format!(
                    "xFirebaseTestd.state must be a string, got {other}"
                ))
            }
        }
        match local.get("buildPolicy") {
            None => {}
            Some(Value::String(p)) if p == "synchronous" || p == "validation-only" => {}
            Some(other) => {
                return Err(format!(
                    "buildPolicy {other} must be synchronous or validation-only"
                ))
            }
        }
    }
    Ok((
        project.to_owned(),
        database.to_owned(),
        TextIndexDefinition {
            id: id.to_owned(),
            collection_id,
            query_scope,
            api_scope,
            fields,
            language,
            language_override,
            state,
        },
    ))
}

/// A definition as JSON (list / describe output).
fn text_index_json(
    project: &str,
    database: &str,
    d: &ftd_core_firestore::text_index::TextIndexDefinition,
) -> Value {
    use ftd_core_firestore::text_index::{DefaultTextLanguage, LanguageOverridePolicy};
    json!({
        "id": d.id,
        "project": project,
        "database": database,
        "name": format!("projects/{project}/databases/{database}/collectionGroups/{}/indexes/{}", d.collection_id.as_str(), d.id),
        "collectionGroup": d.collection_id.as_str(),
        "queryScope": match d.query_scope {
            ftd_core_firestore::index::IndexQueryScope::Collection => "COLLECTION",
            ftd_core_firestore::index::IndexQueryScope::CollectionGroup => "COLLECTION_GROUP",
        },
        "apiScope": d.api_scope,
        "fields": d.fields.iter().map(|f| json!({"fieldPath": f.path.canonical(), "indexType": "TOKENIZED", "matchType": "MATCH_GLOBALLY"})).collect::<Vec<_>>(),
        "textLanguage": match &d.language { DefaultTextLanguage::Tag(t) => json!(t), DefaultTextLanguage::Autodetect => json!("auto") },
        "languageOverride": match &d.language_override {
            LanguageOverridePolicy::ExplicitField(p) => json!({"field": p.canonical()}),
            LanguageOverridePolicy::ImplicitLanguageField => json!("implicit"),
            LanguageOverridePolicy::Disabled => json!("disabled"),
            LanguageOverridePolicy::BackendDefaultUnresolved => json!("unresolved"),
        },
        "state": d.state.as_str(),
        "fidelity": "strict-validation-only",
    })
}

/// `firestore/text-indexes` (`:load` a canonical file body, POST one definition, GET
/// lists), `firestore/text-indexes/{id}` (GET, DELETE; `body.project` / `body.database`
/// pick one when the ID exists in several databases) and the 1.x lifecycle actions
/// (`UNIMPLEMENTED`, no state change). A session sees only the databases of the projects
/// it owns. Text indexes are an Enterprise feature.
#[allow(clippy::too_many_lines)]
fn text_index_route(
    state: &ControlState,
    session: &str,
    project: &str,
    method: &str,
    rest: &str,
    body: &Value,
) -> JsonResponse {
    use ftd_core_firestore::text_index::TextIndexCatalog;
    if state.edition != FirestoreEdition::Enterprise {
        return error(
            400,
            "FAILED_PRECONDITION : text indexes need firestore.edition = enterprise",
        );
    }
    let scope = scope_of(state, project);
    let Ok(mut catalog) = state.text_indexes.lock() else {
        return error(500, "INTERNAL");
    };
    let add = |catalog: &mut TextIndexCatalog, entry: &Value| -> Result<Value, String> {
        let (p, d, def) = parse_text_index(entry)?;
        if !scope.owns_project(&p) {
            return Err(format!(
                "index.name names project {p:?}, which this session does not own"
            ));
        }
        let id = def.id.clone();
        let warnings = catalog.add(&p, &d, def).map_err(|e| e.to_string())?;
        Ok(json!({"id": id, "project": p, "database": d, "warnings": warnings}))
    };
    let owned_total = |catalog: &TextIndexCatalog| {
        catalog
            .entries()
            .filter(|(p, _, _)| scope.owns_project(p))
            .count()
    };
    match (method, rest) {
        ("POST", ":load") => {
            let Some(entries) = body.get("indexes").and_then(Value::as_array) else {
                return error(
                    400,
                    "INVALID_ARGUMENT : body.indexes (the canonical file's array) is required",
                );
            };
            // Validated as a whole before any is kept: a bad entry rejects the file.
            let mut trial = catalog.clone();
            let mut loaded = Vec::with_capacity(entries.len());
            for (i, e) in entries.iter().enumerate() {
                match add(&mut trial, e) {
                    Ok(v) => loaded.push(v),
                    Err(m) => return error(400, &format!("INVALID_ARGUMENT : indexes[{i}]: {m}")),
                }
            }
            *catalog = trial;
            ok(json!({"session": session, "loaded": loaded, "total": owned_total(&catalog)}))
        }
        ("POST", "") => match add(&mut catalog, body) {
            Ok(v) => ok(v),
            Err(m) => error(400, &format!("INVALID_ARGUMENT : {m}")),
        },
        ("GET", "") => ok(json!({
            "session": session,
            "indexes": catalog
                .entries()
                .filter(|(p, _, _)| scope.owns_project(p))
                .map(|(p, d, def)| text_index_json(p, d, def))
                .collect::<Vec<_>>(),
        })),
        (verb, rest) => {
            let Some(rest) = rest.strip_prefix('/') else {
                return error(404, "NOT_FOUND");
            };
            let (id, action) = rest
                .split_once(':')
                .map_or((rest, None), |(i, a)| (i, Some(a)));
            let candidates: Vec<(String, String)> = catalog
                .entries()
                .filter(|(p, _, def)| scope.owns_project(p) && def.id == id)
                .map(|(p, d, _)| (p.to_owned(), d.to_owned()))
                .collect();
            let wanted = (
                body.get("project").and_then(Value::as_str),
                body.get("database").and_then(Value::as_str),
            );
            let target = match candidates.as_slice() {
                [] => return error(404, &format!("NOT_FOUND : no text index {id:?}")),
                [one] => one.clone(),
                many => match many.iter().find(|(p, d)| {
                    wanted.0.is_none_or(|w| w == p) && wanted.1.is_none_or(|w| w == d)
                }) {
                    Some(one) if wanted.0.is_some() || wanted.1.is_some() => one.clone(),
                    _ => {
                        return error(
                            409,
                            &format!("ALREADY_EXISTS : text index {id:?} exists in several databases; pass body.project and body.database"),
                        )
                    }
                },
            };
            let (project, database) = (target.0.as_str(), target.1.as_str());
            match (verb, action) {
                ("GET", None) => match catalog.get(project, database, id) {
                    Some(def) => ok(text_index_json(project, database, def)),
                    None => error(404, &format!("NOT_FOUND : no text index {id:?}")),
                },
                ("DELETE", None) => {
                    if catalog.remove(project, database, id) {
                        ok(json!({"id": id, "project": project, "database": database, "deleted": true}))
                    } else {
                        error(404, &format!("NOT_FOUND : no text index {id:?}"))
                    }
                }
                (
                    "POST",
                    Some(lifecycle @ ("advanceBackfill" | "completeBackfill" | "failBuild" | "repair")),
                ) => error(501, &format!("UNIMPLEMENTED : {lifecycle} needs the backfill engine (FS-TEXT-IDX-1, 1.x); the index state is unchanged")),
                _ => error(404, "NOT_FOUND"),
            }
        }
    }
}

/// Whether `action` means anything for `operation` (a plan naming a combination the
/// adapters would ignore is refused instead of reporting faults that never happen).
fn action_allowed(operation: &str, action: &ftd_core_session::fault::FaultAction) -> bool {
    use ftd_core_session::fault::FaultAction as A;
    match operation {
        "firestore.commit" | "storage.upload" => matches!(
            action,
            A::ReturnError { .. }
                | A::Delay { .. }
                | A::Timeout
                | A::TransactionConflict
                | A::DropConnection
        ),
        "firestore.read"
        | "firestore.beginTransaction"
        | "storage.read"
        | "storage.delete"
        | "storage.list"
        | "storage.request" => matches!(
            action,
            A::ReturnError { .. } | A::Delay { .. } | A::Timeout | A::DropConnection
        ),
        "functions.invoke" => matches!(
            action,
            A::ReturnError { .. }
                | A::Delay { .. }
                | A::Timeout
                | A::DeadLetter
                | A::CrashRunner
                | A::DropConnection
        ),
        "functions.deliver" => matches!(action, A::Duplicate { .. }),
        _ => false,
    }
}

/// `PUT /v1/sessions/{s}/faultPlan` installs the session's plan (spec 18.2 shape), `GET`
/// returns it with the faults that fired, `DELETE` removes it. Each session has its own
/// plan and counters.
#[allow(clippy::too_many_lines)]
fn fault_plan_route(
    state: &ControlState,
    session: &str,
    project: &str,
    method: &str,
    body: &Value,
) -> JsonResponse {
    use ftd_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule};
    let Some(registry) = &state.faults else {
        return error(404, "NOT_FOUND : fault plans are not available");
    };
    let faults = registry.for_project(project);
    match method {
        "GET" => {
            let Ok(f) = faults.lock() else {
                return error(500, "INTERNAL");
            };
            let plan = f.plan().map(|p| json!({"seed": p.seed, "rules": p.rules.iter().map(rule_json).collect::<Vec<_>>()}));
            let fired: Vec<Value> = f
                .fired()
                .iter()
                .map(|r| json!({"operation": r.operation, "occurrence": r.occurrence, "functionOccurrence": r.function_occurrence, "function": r.function, "action": r.action.to_string()}))
                .collect();
            ok(json!({"session": session, "plan": plan, "fired": fired, "counters": f.counters()}))
        }
        "PUT" => {
            let seed = body.get("seed").and_then(Value::as_u64).unwrap_or(0);
            let Some(rules) = body.get("rules").and_then(Value::as_array) else {
                return error(400, "INVALID_ARGUMENT : rules must be an array");
            };
            let mut parsed = Vec::with_capacity(rules.len());
            for (i, r) in rules.iter().enumerate() {
                let Some(m) = r.get("match") else {
                    return error(
                        400,
                        &format!("INVALID_ARGUMENT : rules[{i}].match is required"),
                    );
                };
                let event_type = m
                    .get("eventType")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                // A rule naming only an event type is a delivery rule (spec 18.2).
                let operation = match m.get("operation") {
                    None if event_type.is_some() => "functions.deliver",
                    Some(Value::String(o)) if KNOWN_OPERATIONS.contains(&o.as_str()) => o.as_str(),
                    _ => {
                        return error(
                            400,
                            &format!(
                                "INVALID_ARGUMENT : rules[{i}].match.operation must be one of {}",
                                KNOWN_OPERATIONS.join(", ")
                            ),
                        )
                    }
                };
                let nth = match m.get("nth") {
                    None | Some(Value::Null) => None,
                    Some(v) => match v.as_u64().filter(|n| *n >= 1) {
                        Some(n) => Some(n),
                        None => return error(400, &format!("INVALID_ARGUMENT : rules[{i}].match.nth must be a positive integer")),
                    },
                };
                let a = r.get("action").cloned().unwrap_or(Value::Null);
                let action = match a.get("type").and_then(Value::as_str) {
                    Some("returnError") => match a.get("code").and_then(Value::as_str) {
                        Some(code) if !code.is_empty() => FaultAction::ReturnError { code: code.to_owned() },
                        _ => return error(400, &format!("INVALID_ARGUMENT : rules[{i}].action.code is required")),
                    },
                    Some("delay") => match a.get("seconds").and_then(Value::as_i64) {
                        Some(seconds) if (0..=86_400 * 366).contains(&seconds) => FaultAction::Delay { seconds },
                        _ => return error(400, &format!("INVALID_ARGUMENT : rules[{i}].action.seconds must be 0..=31622400")),
                    },
                    Some("duplicate") => match a.get("count").and_then(Value::as_u64) {
                        Some(count) if (1..=100).contains(&count) => FaultAction::Duplicate { count: u32::try_from(count).unwrap_or(1) },
                        _ => return error(400, &format!("INVALID_ARGUMENT : rules[{i}].action.count must be 1..=100")),
                    },
                    Some("crashRunner") => FaultAction::CrashRunner,
                    Some("timeout") => FaultAction::Timeout,
                    Some("deadLetter") => FaultAction::DeadLetter,
                    Some("transactionConflict") => FaultAction::TransactionConflict,
                    Some("dropConnection") => FaultAction::DropConnection,
                    _ => return error(400, &format!("INVALID_ARGUMENT : rules[{i}].action.type must be one of returnError, delay, duplicate, crashRunner, timeout, deadLetter, transactionConflict, dropConnection")),
                };
                if !action_allowed(operation, &action) {
                    return error(
                        400,
                        &format!("INVALID_ARGUMENT : rules[{i}]: action {action} does not apply to {operation}"),
                    );
                }
                parsed.push(FaultRule {
                    matches: FaultMatch {
                        operation: operation.to_owned(),
                        nth,
                        function: m.get("function").and_then(Value::as_str).map(str::to_owned),
                        event_type,
                    },
                    action,
                });
            }
            let Ok(mut f) = faults.lock() else {
                return error(500, "INTERNAL");
            };
            let count = parsed.len();
            f.install(FaultPlan {
                seed,
                rules: parsed,
            });
            ok(json!({"session": session, "installed": true, "rules": count}))
        }
        "DELETE" => {
            let Ok(mut f) = faults.lock() else {
                return error(500, "INTERNAL");
            };
            f.clear();
            ok(json!({"session": session, "installed": false}))
        }
        _ => error(405, "METHOD_NOT_ALLOWED"),
    }
}

/// Operations a fault rule can name.
const KNOWN_OPERATIONS: &[&str] = &[
    "firestore.commit",
    "firestore.read",
    "firestore.beginTransaction",
    "storage.upload",
    "storage.read",
    "storage.delete",
    "storage.list",
    "storage.request",
    "functions.invoke",
    "functions.deliver",
];

fn rule_json(r: &ftd_core_session::fault::FaultRule) -> Value {
    use ftd_core_session::fault::FaultAction;
    let action = match &r.action {
        FaultAction::ReturnError { code } => json!({"type": "returnError", "code": code}),
        FaultAction::Delay { seconds } => json!({"type": "delay", "seconds": seconds}),
        FaultAction::Duplicate { count } => json!({"type": "duplicate", "count": count}),
        FaultAction::CrashRunner => json!({"type": "crashRunner"}),
        FaultAction::Timeout => json!({"type": "timeout"}),
        FaultAction::DeadLetter => json!({"type": "deadLetter"}),
        FaultAction::TransactionConflict => json!({"type": "transactionConflict"}),
        FaultAction::DropConnection => json!({"type": "dropConnection"}),
    };
    json!({"match": {"operation": r.matches.operation, "nth": r.matches.nth, "function": r.matches.function, "eventType": r.matches.event_type}, "action": action})
}

/// `snapshots` (POST `{"name"}` captures, GET lists), `snapshots/{name}:restore`,
/// `snapshots/{name}` (DELETE). Snapshots belong to the session that took them and hold
/// what it owns: its Firestore databases, buckets, users, fault plan and text indexes;
/// the default session's also carry the shared parts (clock, rules, the auto-ID generator)
/// and reset the functions runtime on restore. Capture and restore hold the exclusive
/// session barrier, so a snapshot never straddles a request and a restore is atomic
/// across every adapter. A default-session capture refuses outstanding functions work
/// unless `allowNonQuiescent` is set (spec 14.3): that work is not captured, and a restore
/// drops it.
///
/// A capture is all or nothing: every hook is copied before any of them is retained, so a
/// store that cannot be read refuses the snapshot instead of leaving an empty part behind.
/// A session retains at most [`MAX_SNAPSHOTS_PER_SESSION`] names; a new name beyond that
/// is `RESOURCE_EXHAUSTED` (429) and changes nothing, while capturing over a retained name
/// is always admitted and releases what that name held. `GET` reports `retained`, `limit`
/// and `remaining`.
#[allow(clippy::too_many_lines)]
fn snapshot_route(
    state: &ControlState,
    session: &str,
    project: &str,
    method: &str,
    rest: &str,
    body: &Value,
) -> JsonResponse {
    let valid_name = |n: &str| {
        !n.is_empty()
            && n.len() <= 64
            && n.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    let scope = scope_of(state, project);
    match (method, rest) {
        ("GET", "") => {
            let Ok(snapshots) = state.snapshots.lock() else {
                return error(500, "INTERNAL : the snapshot store is poisoned");
            };
            let list: Vec<Value> = snapshots
                .get(session)
                .into_iter()
                .flatten()
                .map(|(name, s)| json!({"name": name, "clock": s.clock, "parts": s.parts.iter().flatten().count()}))
                .collect();
            let retained = list.len();
            ok(json!({
                "session": session,
                "snapshots": list,
                "retained": retained,
                "limit": MAX_SNAPSHOTS_PER_SESSION,
                "remaining": MAX_SNAPSHOTS_PER_SESSION.saturating_sub(retained),
            }))
        }
        ("POST", "") => {
            let Some(name) = body
                .get("name")
                .and_then(Value::as_str)
                .filter(|n| valid_name(n))
            else {
                return error(
                    400,
                    "INVALID_ARGUMENT : name ([A-Za-z0-9._-], at most 64 characters) is required",
                );
            };
            let _exclusive = state.barrier.as_ref().map(|b| b.exclusive());
            let quiescent =
                !scope.is_default() || state.functions.as_ref().is_none_or(|f| f.is_idle());
            if !quiescent && body.get("allowNonQuiescent").and_then(Value::as_bool) != Some(true) {
                return error(
                    409,
                    "FAILED_PRECONDITION : functions work is outstanding; await idle first or set allowNonQuiescent",
                );
            }
            // Admission before any state is copied: a new name beyond the budget is
            // refused and nothing is captured, so the retained set is unchanged. A name
            // that is already retained is a replacement and is always admitted.
            match state.snapshots.lock() {
                Ok(snapshots) => {
                    if let Some(refusal) = over_budget(&snapshots, session, name) {
                        return refusal;
                    }
                }
                Err(_) => return error(500, "INTERNAL : the snapshot store is poisoned"),
            }
            // Every part is captured before any of them is kept: a store that cannot be
            // copied refuses the whole snapshot rather than leaving an empty part behind
            // that a later restore would put back as the truth (SESSION-ATOMIC-01).
            let mut parts: Vec<Option<SnapshotPart>> =
                Vec::with_capacity(state.snapshot_hooks.len());
            for hook in &state.snapshot_hooks {
                if scope.is_default() || !hook.shared() {
                    match hook.capture(&scope) {
                        Ok(part) => parts.push(Some(part)),
                        Err(e) => {
                            return error(
                                500,
                                &format!(
                                    "INTERNAL : capturing {e}; snapshot {name:?} was not taken"
                                ),
                            )
                        }
                    }
                } else {
                    parts.push(None);
                }
            }
            let names: Vec<&str> = state
                .snapshot_hooks
                .iter()
                .zip(&parts)
                .filter(|(_, p)| p.is_some())
                .map(|(h, _)| h.name())
                .collect();
            let clock = state
                .clock
                .lock()
                .map(|c| c.now().to_rfc3339().unwrap_or_default())
                .unwrap_or_default();
            let Ok(mut snapshots) = state.snapshots.lock() else {
                return error(500, "INTERNAL : the snapshot store is poisoned");
            };
            if let Some(refusal) = over_budget(&snapshots, session, name) {
                return refusal;
            }
            // The replaced entry is dropped here: what only it held is released.
            let replaced = snapshots
                .entry(session.to_owned())
                .or_default()
                .insert(
                    name.to_owned(),
                    Snapshot {
                        clock: clock.clone(),
                        parts,
                    },
                )
                .is_some();
            let retained = snapshots
                .get(session)
                .map_or(0, std::collections::BTreeMap::len);
            ok(
                json!({"session": session, "name": name, "clock": clock, "replaced": replaced, "parts": names, "retained": retained, "limit": MAX_SNAPSHOTS_PER_SESSION}),
            )
        }
        ("POST", r) => {
            let Some(name) = r.strip_prefix('/').and_then(|r| r.strip_suffix(":restore")) else {
                return error(404, "NOT_FOUND");
            };
            let _exclusive = state.barrier.as_ref().map(|b| b.exclusive());
            // The parts are lifted out of the store (they are reference-counted copies)
            // and the lock released: the hooks below take locks of their own.
            let (parts, clock) = match state.snapshots.lock() {
                Ok(snapshots) => match snapshots.get(session).and_then(|s| s.get(name)) {
                    Some(snapshot) => (snapshot.parts.clone(), snapshot.clock.clone()),
                    None => return error(404, &format!("NOT_FOUND : no snapshot {name:?}")),
                },
                Err(_) => return error(500, "INTERNAL : the snapshot store is poisoned"),
            };
            if parts.len() != state.snapshot_hooks.len() {
                return error(500, "INTERNAL : snapshot shape mismatch");
            }
            let applicable: Vec<(&Arc<dyn SnapshotHook>, &SnapshotPart)> = state
                .snapshot_hooks
                .iter()
                .zip(&parts)
                .filter_map(|(hook, part)| part.as_ref().map(|part| (hook, part)))
                .collect();
            if let Err(e) = restore_parts(&scope, &applicable) {
                return error(500, &e);
            }
            ok(json!({"session": session, "name": name, "restored": true, "clock": clock}))
        }
        ("DELETE", r) => {
            let Some(name) = r.strip_prefix('/') else {
                return error(404, "NOT_FOUND");
            };
            let Ok(mut snapshots) = state.snapshots.lock() else {
                return error(500, "INTERNAL : the snapshot store is poisoned");
            };
            // Dropping the entry releases every part only it held.
            match snapshots.get_mut(session).and_then(|s| s.remove(name)) {
                Some(_) => {
                    let retained = snapshots
                        .get(session)
                        .map_or(0, std::collections::BTreeMap::len);
                    ok(
                        json!({"session": session, "name": name, "deleted": true, "retained": retained, "limit": MAX_SNAPSHOTS_PER_SESSION}),
                    )
                }
                None => error(404, &format!("NOT_FOUND : no snapshot {name:?}")),
            }
        }
        _ => error(404, "NOT_FOUND"),
    }
}

/// The refusal for a capture that would take `session` past
/// [`MAX_SNAPSHOTS_PER_SESSION`], if it would. Replacing a retained name never does.
fn over_budget(snapshots: &SnapshotStore, session: &str, name: &str) -> Option<JsonResponse> {
    let held = snapshots.get(session)?;
    if held.contains_key(name) || held.len() < MAX_SNAPSHOTS_PER_SESSION {
        return None;
    }
    Some(error(
        429,
        &format!(
            "RESOURCE_EXHAUSTED : session {session:?} already retains {} snapshots (the per-session budget); delete one or capture over a name it already holds",
            held.len()
        ),
    ))
}

/// Restores every part of a snapshot as one transition: validate, then take a pre-image of
/// every hook, then apply in hook order. A hook that refuses the apply is reported and the
/// hooks before it are put back to their pre-image, so the session is the one that entered
/// the route rather than a mixture of two (`SESSION-ATOMIC-02`, `SESSION-ATOMIC-05`).
fn restore_parts(
    scope: &Scope,
    applicable: &[(&Arc<dyn SnapshotHook>, &SnapshotPart)],
) -> Result<(), String> {
    for (hook, part) in applicable {
        hook.validate(scope, part)
            .map_err(|e| format!("INTERNAL : restoring {e}; nothing was restored"))?;
    }
    let mut pre_image = Vec::with_capacity(applicable.len());
    for (hook, _) in applicable {
        pre_image.push(hook.capture(scope).map_err(|e| {
            format!("INTERNAL : preparing the rollback of {e}; nothing was restored")
        })?);
    }
    for (i, (hook, part)) in applicable.iter().enumerate() {
        let Err(failure) = hook.restore(scope, part) else {
            continue;
        };
        let mut rollback: Vec<String> = Vec::new();
        for ((earlier, _), pre) in applicable[..i].iter().zip(&pre_image).rev() {
            if let Err(e) = earlier.restore(scope, pre) {
                rollback.push(e.to_string());
            }
        }
        return Err(if rollback.is_empty() {
            format!("INTERNAL : restoring {failure}; the session was rolled back to the state it had before the restore")
        } else {
            format!(
                "INTERNAL : restoring {failure}; the rollback failed too ({}) and the session is partially restored",
                rollback.join(", ")
            )
        });
    }
    Ok(())
}

fn functions_route(state: &ControlState, method: &str, rest: &str) -> JsonResponse {
    let Some(functions) = &state.functions else {
        return error(404, "NOT_FOUND : no functions runtime is configured");
    };
    match (method, rest) {
        ("GET", "") => ok(functions.status()),
        ("POST", r) => match r.strip_prefix('/').and_then(|r| r.strip_suffix(":run")) {
            Some(name) if !name.is_empty() => match functions.run_schedule(name) {
                Ok(()) => ok(json!({"function": name, "enqueued": true})),
                Err(e) => error(400, &format!("INVALID_ARGUMENT : {e}")),
            },
            _ => error(404, "NOT_FOUND"),
        },
        _ => error(404, "NOT_FOUND"),
    }
}

/// `POST .../topics/{topic}:publish` with `{"messages": [{"data": <base64>, "attributes":
/// {...}, "orderingKey": "..."}]}` (a `json` value is accepted in place of `data` and
/// encoded for the function). Returns `{"messageIds": [...]}`.
fn publish_route(state: &ControlState, topic: &str, body: &Value) -> JsonResponse {
    let Some(functions) = &state.functions else {
        return error(404, "NOT_FOUND : no functions runtime is configured");
    };
    let Some(messages) = body.get("messages").and_then(Value::as_array) else {
        return error(400, "INVALID_ARGUMENT : messages must be an array");
    };
    let mut normalised = Vec::with_capacity(messages.len());
    for m in messages {
        let Some(obj) = m.as_object() else {
            return error(400, "INVALID_ARGUMENT : each message must be an object");
        };
        let mut msg = m.clone();
        match (obj.get("data"), obj.get("json")) {
            (Some(Value::String(data)), _) => {
                if !is_base64(data) {
                    return error(400, "INVALID_ARGUMENT : data must be base64");
                }
            }
            (None | Some(Value::Null), Some(json)) => {
                msg["data"] = Value::String(base64_encode(json.to_string().as_bytes()));
            }
            (None | Some(Value::Null), None) => msg["data"] = Value::String(String::new()),
            _ => return error(400, "INVALID_ARGUMENT : data must be a base64 string"),
        }
        if let Some(key) = obj.get("orderingKey") {
            if !key.is_null() && key.as_str().is_none_or(|k| k.len() > 1024) {
                return error(
                    400,
                    "INVALID_ARGUMENT : orderingKey must be a string of at most 1024 bytes",
                );
            }
        }
        if let Some(attrs) = obj.get("attributes") {
            if !attrs.is_null()
                && !attrs
                    .as_object()
                    .is_some_and(|a| a.values().all(Value::is_string))
            {
                return error(
                    400,
                    "INVALID_ARGUMENT : attributes must be an object of strings",
                );
            }
        }
        normalised.push(msg);
    }
    match functions.publish(topic, &normalised) {
        Ok(ids) => ok(json!({"messageIds": ids})),
        Err(e) => error(400, &format!("INVALID_ARGUMENT : {e}")),
    }
}

/// Whether `s` is standard base64 (padding optional, correct length).
fn is_base64(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    let padding = s.len() - body.len();
    padding <= 2
        && (body.len() + padding) % 4 == 0
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// Standard base64 with padding.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);
        let bits = (u32::from(buf[0]) << 16) | (u32::from(buf[1]) << 8) | u32::from(buf[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((bits >> (18 - i * 6)) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The browser policy of every control route (also applied by the asynchronous
/// `awaitIdle` path): foreign origins are refused, and a page on a loopback origin needs
/// the control token for anything but reads.
#[must_use]
pub fn browser_guard(
    state: &ControlState,
    method: &str,
    path: &str,
    headers: &RequestHeaders,
) -> Option<JsonResponse> {
    let origin = headers.origin.as_deref()?;
    if !crate::identity_toolkit::origin_is_local(origin) {
        return Some(error(403, "FORBIDDEN_ORIGIN"));
    }
    let privileged = method != "GET" && !path.starts_with("/health/");
    let presented = headers
        .authorization
        .as_deref()
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(str::trim);
    if privileged && !token_matches(presented, &state.control_token) {
        return Some(error(
            403,
            "CONTROL_TOKEN_REQUIRED : browser requests need Authorization: Bearer <control token> (printed at start, FTD_CONTROL_TOKEN)",
        ));
    }
    None
}

/// `POST /v1/sessions/{s}:awaitIdle`: waits until the functions runtime has no outstanding
/// work (or `timeoutSeconds`, default 30, elapses).
pub async fn await_idle(state: &ControlState, body: &Value) -> JsonResponse {
    let timeout = body
        .get("timeoutSeconds")
        .and_then(Value::as_f64)
        .unwrap_or(30.0)
        .clamp(0.0, 600.0);
    let Some(functions) = &state.functions else {
        return ok(json!({"idle": true, "note": "no functions runtime is configured"}));
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs_f64(timeout);
    loop {
        if functions.is_idle() {
            return ok(json!({"idle": true, "status": functions.status()}));
        }
        let notify = functions.idle_notify();
        let notified = notify.notified();
        if functions.is_idle() {
            return ok(json!({"idle": true, "status": functions.status()}));
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() || tokio::time::timeout(remaining, notified).await.is_err() {
            return JsonResponse {
                status: 504,
                body: json!({"error": {"code": 504, "message": "DEADLINE_EXCEEDED : work is still outstanding", "status": functions.status()}}),
            };
        }
    }
}

/// Whether `path` is the `awaitIdle` endpoint (served asynchronously by the server).
#[must_use]
pub fn is_await_idle_path(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    path.starts_with("/v1/sessions/") && path.ends_with(":awaitIdle")
}

fn clock_route(
    state: &ControlState,
    session: &str,
    method: &str,
    action: &str,
    body: &Value,
) -> JsonResponse {
    let Ok(mut clock) = state.clock.lock() else {
        return error(500, "INTERNAL");
    };
    match (method, action) {
        ("GET", "") => ok(
            json!({"session": session, "edition": state.edition.as_config_str(), "requireDemoPrefix": state.require_demo_prefix, "clock": clock_json(&clock)}),
        ),
        ("POST", "clock:advance") => {
            let duration = if let Some(s) = body.get("seconds").and_then(Value::as_i64) {
                LogicalDuration::from_seconds(s)
            } else if let Some(ms) = body.get("millis").and_then(Value::as_i64) {
                LogicalDuration::from_millis(ms)
            } else {
                return error(400, "INVALID_ARGUMENT : seconds or millis required");
            };
            match clock.advance(duration) {
                Ok(_) => ok(clock_json(&clock)),
                Err(e) => error(400, &format!("INVALID_ARGUMENT : {e}")),
            }
        }
        ("POST", "clock:set" | "clock:advanceTo") => {
            let Some(instant) = body.get("instant").and_then(Value::as_str) else {
                return error(400, "INVALID_ARGUMENT : instant required");
            };
            let Ok(target) = LogicalInstant::parse_rfc3339(instant) else {
                return error(400, "INVALID_ARGUMENT : instant must be RFC 3339");
            };
            let allow_backwards = body
                .get("allowBackwards")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if action == "clock:set" && allow_backwards {
                clock.set_allow_backwards(target);
                return ok(clock_json(&clock));
            }
            match clock.advance_to(target) {
                Ok(_) => ok(clock_json(&clock)),
                Err(e) => error(400, &format!("INVALID_ARGUMENT : {e}")),
            }
        }
        _ => error(404, "NOT_FOUND"),
    }
}
