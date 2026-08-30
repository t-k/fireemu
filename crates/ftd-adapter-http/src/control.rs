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

/// Per-project state management for sessions other than the default one.
pub trait ProjectHooks: Send + Sync {
    /// A session for `project` was created: allocate its state (an Auth store, ...).
    fn create(&self, project: &str) -> Result<(), String>;
    /// Wipe the project's state (Firestore databases, default buckets, Auth users).
    fn reset(&self, project: &str);
    /// Drop the project's state and forget it.
    fn remove(&self, project: &str);
}

/// One adapter's part of a session snapshot: an opaque copy of its state.
pub type SnapshotPart = Arc<dyn std::any::Any + Send + Sync>;

/// Captures and restores one adapter's state (Firestore databases, Storage objects, Auth
/// users, the clock, ...). `restore` runs under the exclusive session barrier, in the
/// order the hooks were registered.
pub trait SnapshotHook: Send + Sync {
    /// What the part is (status output).
    fn name(&self) -> &'static str;
    /// A copy of the current state.
    fn capture(&self) -> SnapshotPart;
    /// Replaces the current state with a copy taken by `capture`.
    fn restore(&self, part: &SnapshotPart) -> Result<(), String>;
}

/// A named session snapshot.
pub struct Snapshot {
    /// The clock at capture.
    pub clock: String,
    /// One part per hook, in hook order.
    pub parts: Vec<SnapshotPart>,
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
    /// Hooks run by `POST /v1/sessions/{s}/reset` (Firestore wipe, Auth wipe, ...).
    pub reset_hooks: Vec<Arc<dyn Fn() + Send + Sync>>,
    /// Snapshot capture / restore, one hook per adapter.
    pub snapshot_hooks: Vec<Arc<dyn SnapshotHook>>,
    /// Snapshots kept in memory by name.
    pub snapshots: Mutex<std::collections::BTreeMap<String, Snapshot>>,
    /// The session's fault plan (spec 18), shared with every adapter.
    pub faults: Option<ftd_core_session::fault::SharedFaults>,
    /// Text Index definitions (`FS-TEXT-VAL-1`, strict validation only).
    pub text_indexes: Arc<Mutex<ftd_core_firestore::text_index::TextIndexSet>>,
    /// The default session's project.
    pub default_project: String,
    /// Sessions by name → project (`default` is always present). Sessions are isolated
    /// by project: each has its own Firestore databases, Storage buckets and Auth store;
    /// the virtual clock, rules, functions and fault plan are shared.
    pub sessions: Mutex<std::collections::BTreeMap<String, String>>,
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
            ok(
                json!({"sessions": sessions.iter().map(|(name, project)| json!({"name": name, "project": project})).collect::<Vec<_>>()}),
            )
        }
        ("POST", "/v1/sessions") => create_session(state, body),
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
            rules_route(&state.storage_rules, method, body)
        }
        ("GET", "/v1/rules") => match state.rules.read() {
            Ok(r) => ok(json!({"loaded": r.is_loaded(), "source": r.source})),
            Err(_) => error(500, "INTERNAL"),
        },
        ("PUT", "/v1/rules") => {
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
        ("DELETE", "/v1/rules") => match state.rules.write() {
            Ok(mut slot) => {
                *slot = LoadedRules::default();
                ok(json!({"loaded": false}))
            }
            Err(_) => error(500, "INTERNAL"),
        },
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
    let Ok(mut sessions) = state.sessions.lock() else {
        return error(500, "INTERNAL");
    };
    if sessions.contains_key(name) {
        return error(409, &format!("ALREADY_EXISTS : session {name:?}"));
    }
    if sessions.values().any(|p| p == project) {
        return error(
            409,
            &format!("ALREADY_EXISTS : project {project:?} already has a session"),
        );
    }
    if let Some(hooks) = &state.project_hooks {
        if let Err(e) = hooks.create(project) {
            return error(500, &format!("INTERNAL : {e}"));
        }
    }
    sessions.insert(name.to_owned(), project.to_owned());
    ok(json!({"name": name, "project": project, "created": true}))
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
        let _exclusive = state.barrier.as_ref().map(|b| b.exclusive());
        if let Some(hooks) = &state.project_hooks {
            hooks.remove(&project);
        }
        if let Ok(mut sessions) = state.sessions.lock() {
            sessions.remove(session);
        }
        return ok(json!({"session": session, "project": project, "deleted": true}));
    }
    if (method, action) == ("POST", "reset") {
        // Exclusive across every hook: requests in flight finish first, new ones wait.
        let _exclusive = state.barrier.as_ref().map(|b| b.exclusive());
        if is_default {
            for hook in &state.reset_hooks {
                hook();
            }
            return ok(
                json!({"session": session, "project": project, "reset": true, "hooks": state.reset_hooks.len()}),
            );
        }
        if let Some(hooks) = &state.project_hooks {
            hooks.reset(&project);
        }
        return ok(
            json!({"session": session, "project": project, "reset": true, "scope": "project"}),
        );
    }
    if let Some(rest) = action.strip_prefix("snapshots") {
        return snapshot_route(state, session, method, rest, body);
    }
    if action == "faultPlan" {
        return fault_plan_route(state, session, method, body);
    }
    if let Some(rest) = action.strip_prefix("firestore/text-indexes") {
        return text_index_route(state, session, method, rest, body);
    }
    let _admitted = state.barrier.as_ref().map(|b| b.admit());
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

/// Parses one entry of the canonical `firestore.text-indexes.json` (`{"index": {...},
/// "xFirebaseTestd": {...}}`, or the bare `index` object) into a definition.
#[allow(clippy::too_many_lines)]
pub fn parse_text_index(
    entry: &Value,
) -> Result<ftd_core_firestore::text_index::TextIndexDefinition, String> {
    use ftd_core_firestore::text_index::{
        DefaultTextLanguage, LanguageOverridePolicy, TextIndexDefinition, TextIndexState,
        TextIndexType, TextIndexedField, TextMatchType,
    };
    let (index, local) = match entry.get("index") {
        Some(index) => (index, entry.get("xFirebaseTestd")),
        None => (entry, None),
    };
    let Some(obj) = index.as_object() else {
        return Err("index must be an object".to_owned());
    };
    for key in obj.keys() {
        if ![
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
        ]
        .contains(&key.as_str())
        {
            return Err(format!(
                "index.{key} is outside the supported Admin API subset"
            ));
        }
        if ["density", "multikey", "unique", "shardCount"].contains(&key.as_str()) {
            return Err(format!(
                "index.{key} is not supported for text indexes (refused rather than ignored)"
            ));
        }
    }
    let name = index
        .get("name")
        .and_then(Value::as_str)
        .ok_or("index.name is required")?;
    // projects/{p}/databases/{d}/collectionGroups/{c}/indexes/{id}
    let parts: Vec<&str> = name.split('/').collect();
    let (collection, id) =
        match parts.as_slice() {
            ["projects", _, "databases", _, "collectionGroups", c, "indexes", id] => (*c, *id),
            _ => return Err(
                "index.name must be projects/{p}/databases/{d}/collectionGroups/{c}/indexes/{id}"
                    .to_owned(),
            ),
        };
    let collection_id = ftd_core_types::ids::CollectionId::try_new(collection)
        .map_err(|e| format!("collection group: {e}"))?;
    let query_scope = match index
        .get("queryScope")
        .and_then(Value::as_str)
        .unwrap_or("COLLECTION")
    {
        "COLLECTION" => ftd_core_firestore::index::IndexQueryScope::Collection,
        "COLLECTION_GROUP" => ftd_core_firestore::index::IndexQueryScope::CollectionGroup,
        other => return Err(format!("unsupported queryScope {other:?}")),
    };
    let api_scope = index
        .get("apiScope")
        .and_then(Value::as_str)
        .unwrap_or("ANY_API")
        .to_owned();
    let mut fields = Vec::new();
    for f in index
        .get("fields")
        .and_then(Value::as_array)
        .ok_or("index.fields is required")?
    {
        let path = f
            .get("fieldPath")
            .and_then(Value::as_str)
            .ok_or("fields[].fieldPath is required")?;
        let path = ftd_core_firestore::field_path::FieldPath::parse(path)
            .map_err(|e| format!("fieldPath {path:?}: {e}"))?;
        let Some(text) = f.get("searchConfig").and_then(|c| c.get("textSpec")) else {
            return Err(format!(
                "field {}: searchConfig.textSpec is required (only text indexes are defined here)",
                path.canonical()
            ));
        };
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
        let index_type = match spec
            .get("indexType")
            .and_then(Value::as_str)
            .unwrap_or("TOKENIZED")
        {
            "TOKENIZED" => TextIndexType::Tokenized,
            other => return Err(format!("unsupported indexType {other:?} (TOKENIZED only)")),
        };
        let match_type = match spec
            .get("matchType")
            .and_then(Value::as_str)
            .unwrap_or("MATCH_GLOBALLY")
        {
            "MATCH_GLOBALLY" => TextMatchType::MatchGlobally,
            other => {
                return Err(format!(
                    "unsupported matchType {other:?} (MATCH_GLOBALLY only)"
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
    let language = match options
        .and_then(|o| o.get("textLanguage"))
        .and_then(Value::as_str)
    {
        None | Some("" | "auto") => DefaultTextLanguage::Autodetect,
        Some(tag) => DefaultTextLanguage::Tag(tag.to_owned()),
    };
    let language_override = match options.and_then(|o| o.get("textLanguageOverrideFieldPath")) {
        Some(Value::String(p)) if !p.is_empty() => LanguageOverridePolicy::ExplicitField(
            ftd_core_firestore::field_path::FieldPath::parse(p)
                .map_err(|e| format!("textLanguageOverrideFieldPath: {e}"))?,
        ),
        Some(Value::String(_)) => LanguageOverridePolicy::Disabled,
        Some(_) => return Err("textLanguageOverrideFieldPath must be a string".to_owned()),
        None => match local
            .and_then(|l| l.get("languageOverride"))
            .and_then(Value::as_str)
        {
            Some("implicit") => LanguageOverridePolicy::ImplicitLanguageField,
            Some("disabled") => LanguageOverridePolicy::Disabled,
            Some(other) => {
                return Err(format!(
                    "xFirebaseTestd.languageOverride {other:?} must be implicit or disabled"
                ))
            }
            None => LanguageOverridePolicy::BackendDefaultUnresolved,
        },
    };
    let mut state = TextIndexState::Ready;
    if let Some(local) = local {
        let Some(obj) = local.as_object() else {
            return Err("xFirebaseTestd must be an object".to_owned());
        };
        for key in obj.keys() {
            if !["state", "buildPolicy", "languageOverride"].contains(&key.as_str()) {
                return Err(format!("unknown xFirebaseTestd key {key:?}"));
            }
        }
        if let Some(s) = obj.get("state").and_then(Value::as_str) {
            state = TextIndexState::parse(s).ok_or_else(|| format!("unknown state {s:?}"))?;
        }
        if let Some(p) = obj.get("buildPolicy").and_then(Value::as_str) {
            if !["synchronous", "validation-only"].contains(&p) {
                return Err(format!(
                    "buildPolicy {p:?} must be synchronous or validation-only"
                ));
            }
        }
    }
    Ok(TextIndexDefinition {
        id: id.to_owned(),
        collection_id,
        query_scope,
        api_scope,
        fields,
        language,
        language_override,
        state,
    })
}

/// A definition as JSON (list / describe output).
fn text_index_json(d: &ftd_core_firestore::text_index::TextIndexDefinition) -> Value {
    use ftd_core_firestore::text_index::{DefaultTextLanguage, LanguageOverridePolicy};
    json!({
        "id": d.id,
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
/// lists), `firestore/text-indexes/{id}` (GET, DELETE) and the 1.x lifecycle actions
/// (`UNIMPLEMENTED`, no state change). Text indexes are an Enterprise feature.
fn text_index_route(
    state: &ControlState,
    session: &str,
    method: &str,
    rest: &str,
    body: &Value,
) -> JsonResponse {
    if state.edition != FirestoreEdition::Enterprise {
        return error(
            400,
            "FAILED_PRECONDITION : text indexes need firestore.edition = enterprise",
        );
    }
    let Ok(mut set) = state.text_indexes.lock() else {
        return error(500, "INTERNAL");
    };
    let add = |set: &mut ftd_core_firestore::text_index::TextIndexSet,
               entry: &Value|
     -> Result<Value, String> {
        let def = parse_text_index(entry)?;
        let id = def.id.clone();
        let warnings = set.add(def).map_err(|e| e.to_string())?;
        Ok(json!({"id": id, "warnings": warnings}))
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
            let mut trial = set.clone();
            let mut loaded = Vec::with_capacity(entries.len());
            for (i, e) in entries.iter().enumerate() {
                match add(&mut trial, e) {
                    Ok(v) => loaded.push(v),
                    Err(m) => return error(400, &format!("INVALID_ARGUMENT : indexes[{i}]: {m}")),
                }
            }
            *set = trial;
            ok(json!({"session": session, "loaded": loaded, "total": set.definitions().len()}))
        }
        ("POST", "") => match add(&mut set, body) {
            Ok(v) => ok(v),
            Err(m) => error(400, &format!("INVALID_ARGUMENT : {m}")),
        },
        ("GET", "") => ok(
            json!({"session": session, "indexes": set.definitions().iter().map(text_index_json).collect::<Vec<_>>()}),
        ),
        (m, r) => {
            let Some(r) = r.strip_prefix('/') else {
                return error(404, "NOT_FOUND");
            };
            let (id, action) = r.split_once(':').map_or((r, None), |(i, a)| (i, Some(a)));
            match (m, action) {
                ("GET", None) => match set.get(id) {
                    Some(d) => ok(text_index_json(d)),
                    None => error(404, &format!("NOT_FOUND : no text index {id:?}")),
                },
                ("DELETE", None) => {
                    if set.remove(id) {
                        ok(json!({"id": id, "deleted": true}))
                    } else {
                        error(404, &format!("NOT_FOUND : no text index {id:?}"))
                    }
                }
                (
                    "POST",
                    Some(a @ ("advanceBackfill" | "completeBackfill" | "failBuild" | "repair")),
                ) => {
                    if set.get(id).is_none() {
                        return error(404, &format!("NOT_FOUND : no text index {id:?}"));
                    }
                    error(501, &format!("UNIMPLEMENTED : {a} needs the backfill engine (FS-TEXT-IDX-1, 1.x); the index state is unchanged"))
                }
                _ => error(404, "NOT_FOUND"),
            }
        }
    }
}

/// `PUT /v1/sessions/{s}/faultPlan` installs a plan (spec 18.2 shape), `GET` returns it with
/// the faults that fired, `DELETE` removes it.
#[allow(clippy::too_many_lines)]
fn fault_plan_route(
    state: &ControlState,
    session: &str,
    method: &str,
    body: &Value,
) -> JsonResponse {
    use ftd_core_session::fault::{FaultAction, FaultMatch, FaultPlan, FaultRule};
    let Some(faults) = &state.faults else {
        return error(404, "NOT_FOUND : fault plans are not available");
    };
    match method {
        "GET" => {
            let Ok(f) = faults.lock() else {
                return error(500, "INTERNAL");
            };
            let plan = f.plan().map(|p| json!({"seed": p.seed, "rules": p.rules.iter().map(rule_json).collect::<Vec<_>>()}));
            let fired: Vec<Value> = f
                .fired()
                .iter()
                .map(|r| json!({"operation": r.operation, "occurrence": r.occurrence, "function": r.function, "action": r.action.to_string()}))
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
                let Some(operation) = m
                    .get("operation")
                    .and_then(Value::as_str)
                    .filter(|o| KNOWN_OPERATIONS.contains(o))
                else {
                    return error(
                        400,
                        &format!(
                            "INVALID_ARGUMENT : rules[{i}].match.operation must be one of {}",
                            KNOWN_OPERATIONS.join(", ")
                        ),
                    );
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
                parsed.push(FaultRule {
                    matches: FaultMatch {
                        operation: operation.to_owned(),
                        nth,
                        function: m.get("function").and_then(Value::as_str).map(str::to_owned),
                        event_type: m
                            .get("eventType")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
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
/// `snapshots/{name}` (DELETE). Capture and restore hold the exclusive session barrier, so
/// a snapshot never straddles a request and a restore is atomic across every adapter. A
/// capture refuses a session with functions work outstanding unless `allowNonQuiescent`
/// is set (spec 14.3); a restore resets the functions runtime (its queue belongs to the
/// state it was replaced with).
fn snapshot_route(
    state: &ControlState,
    session: &str,
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
    match (method, rest) {
        ("GET", "") => {
            let Ok(snapshots) = state.snapshots.lock() else {
                return error(500, "INTERNAL");
            };
            let list: Vec<Value> = snapshots
                .iter()
                .map(|(name, s)| json!({"name": name, "clock": s.clock, "parts": s.parts.len()}))
                .collect();
            ok(json!({"session": session, "snapshots": list}))
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
            let quiescent = state.functions.as_ref().is_none_or(|f| f.is_idle());
            if !quiescent && body.get("allowNonQuiescent").and_then(Value::as_bool) != Some(true) {
                return error(
                    409,
                    "FAILED_PRECONDITION : functions work is outstanding; await idle first or set allowNonQuiescent",
                );
            }
            let parts: Vec<SnapshotPart> =
                state.snapshot_hooks.iter().map(|h| h.capture()).collect();
            let clock = state
                .clock
                .lock()
                .map(|c| c.now().to_rfc3339().unwrap_or_default())
                .unwrap_or_default();
            let Ok(mut snapshots) = state.snapshots.lock() else {
                return error(500, "INTERNAL");
            };
            let replaced = snapshots
                .insert(
                    name.to_owned(),
                    Snapshot {
                        clock: clock.clone(),
                        parts,
                    },
                )
                .is_some();
            ok(
                json!({"session": session, "name": name, "clock": clock, "replaced": replaced, "parts": state.snapshot_hooks.iter().map(|h| h.name()).collect::<Vec<_>>()}),
            )
        }
        ("POST", r) => {
            let Some(name) = r.strip_prefix('/').and_then(|r| r.strip_suffix(":restore")) else {
                return error(404, "NOT_FOUND");
            };
            let _exclusive = state.barrier.as_ref().map(|b| b.exclusive());
            let Ok(snapshots) = state.snapshots.lock() else {
                return error(500, "INTERNAL");
            };
            let Some(snapshot) = snapshots.get(name) else {
                return error(404, &format!("NOT_FOUND : no snapshot {name:?}"));
            };
            if snapshot.parts.len() != state.snapshot_hooks.len() {
                return error(500, "INTERNAL : snapshot shape mismatch");
            }
            for (hook, part) in state.snapshot_hooks.iter().zip(&snapshot.parts) {
                if let Err(e) = hook.restore(part) {
                    return error(500, &format!("INTERNAL : restoring {}: {e}", hook.name()));
                }
            }
            let clock = snapshot.clock.clone();
            drop(snapshots);
            ok(json!({"session": session, "name": name, "restored": true, "clock": clock}))
        }
        ("DELETE", r) => {
            let Some(name) = r.strip_prefix('/') else {
                return error(404, "NOT_FOUND");
            };
            let Ok(mut snapshots) = state.snapshots.lock() else {
                return error(500, "INTERNAL");
            };
            match snapshots.remove(name) {
                Some(_) => ok(json!({"session": session, "name": name, "deleted": true})),
                None => error(404, &format!("NOT_FOUND : no snapshot {name:?}")),
            }
        }
        _ => error(404, "NOT_FOUND"),
    }
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
    if privileged && presented != Some(state.control_token.as_str()) {
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
