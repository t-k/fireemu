//! The UI surface at the handler level: browser policy, the embedded app, the privileged
//! fronts to Firestore / Auth / Storage / control, and the commit stream.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::RestState;
use fireemu_adapter_http::app_check::AppCheckState;
use fireemu_adapter_http::control::ControlState;
use fireemu_adapter_http::identity_toolkit::AuthState;
use fireemu_adapter_http::storage::StorageState;
use fireemu_adapter_ui::{handle, AppCheckInfo, RuntimeInfo, UiBody, UiRequest, UiState};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_rules::runtime::RulesetSlot;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const TOKEN: &str = "ui-test-token";

fn state() -> Arc<UiState> {
    state_with(None)
}

/// The UI state, optionally with App Check wired into both the control API (the observation
/// route reads its registry) and the UI front (the debug-token routes need the full state).
#[allow(clippy::too_many_lines)]
fn state_with(app_check: Option<Arc<AppCheckState>>) -> Arc<UiState> {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let backend = Arc::new(LocalBackend::new(gateway.clone(), clock.clone(), 7));
    let auth_store = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(5),
        TotpPolicy::default(),
    )));
    let rules = Arc::new(RulesetSlot::default());
    let storage_rules = Arc::new(fireemu_adapter_http::storage::StorageRulesRegistry::default());
    let storage = Arc::new(StorageState {
        store: Mutex::new(fireemu_core_storage::store::StorageState::new(9)),
        clock: clock.clone(),
        auth: Arc::new(fireemu_core_auth::store::AuthRegistry::new(
            "demo-app",
            auth_store.clone(),
        )),
        tenancy: None,
        rules: storage_rules.clone(),
        project: "demo-app".to_owned(),
        events: None,
        barrier: None,
        firestore: None,
        faults: None,
        clock_observer: None,
        app_check_policy: None,
        admin_capability: None,
        token_acceptance: fireemu_core_auth::jwt::TokenAcceptance::default(),
    });
    let control = Arc::new(ControlState {
        clock: clock.clone(),
        require_demo_prefix: true,
        edition: FirestoreEdition::Standard,
        capabilities: json!({"schemaVersion": 1}).into(),
        rules,
        storage_rules,
        reset_hooks: Vec::new(),
        functions: None,
        control_token: TOKEN.to_owned(),
        app_check: app_check.as_ref().map(|s| s.gate()),
        barrier: None,
        snapshot_hooks: Vec::new(),
        snapshots: Mutex::new(BTreeMap::new()),
        faults: Some(Arc::new(fireemu_core_session::fault::FaultRegistry::new())),
        text_indexes: Arc::new(Mutex::new(
            fireemu_core_firestore::text_index::TextIndexCatalog::default(),
        )),
        default_project: "demo-app".to_owned(),
        tenancy: Arc::new(RwLock::new(fireemu_core_session::tenancy::Tenancy::new(
            "demo-app",
        ))),
        sessions: Mutex::new(BTreeMap::from([(
            "default".to_owned(),
            "demo-app".to_owned(),
        )])),
        project_hooks: None,
        resource_hooks: Vec::new(),
    });
    Arc::new(UiState {
        stream_limiter: Arc::new(fireemu_adapter_ui::sse::StreamLimiter::default()),
        control_token: TOKEN.to_owned(),
        info: RuntimeInfo {
            version: "test".to_owned(),
            project: "demo-app".to_owned(),
            edition: "standard".to_owned(),
            firestore_addr: "127.0.0.1:8080".to_owned(),
            http_addr: "127.0.0.1:9099".to_owned(),
            storage_addr: "127.0.0.1:9199".to_owned(),
            functions_addr: None,
            functions_source: None,
            ui_addr: "127.0.0.1:4000".to_owned(),
            rules_enforced: true,
            clock_pinned: true,
            app_check: app_check.as_ref().map(|s| AppCheckInfo {
                kid: s.signer.kid().to_owned(),
                modes: vec![
                    ("auth".to_owned(), "unenforced".to_owned()),
                    ("firestore".to_owned(), "enforced".to_owned()),
                    ("storage".to_owned(), "off".to_owned()),
                ],
            }),
        },
        rest: Arc::new(RestState {
            local: backend.clone(),
            gateway: Arc::new(gateway),
            rules: None,
            app_check: None,
        }),
        backend,
        auth: Arc::new(AuthState {
            store: auth_store,
            clock,
            wall_clock: None,
            totp_extension_enabled: false,
            barrier: None,
            events: None,
            notices: None,
            blocking: None,
            operation_gate: Arc::new(Mutex::new(())),
            control_token: Some(TOKEN.to_owned()),
            registry: None,
            allow_routed_projects: false,
            stateless_refresh_tokens: true,
            query_limits:
                fireemu_adapter_http::identity_toolkit::AuthQueryLimits::EmulatorUnbounded,
            fake_custom_token_expiry:
                fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
            app_check: None,
            app_check_policy: None,
            tenancy: None,
        }),
        storage,
        control,
        functions: None,
        app_check,
    })
}

fn request(method: &str, target: &str, body: &Value) -> UiRequest {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    UiRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        // Every API request presents the token; `browser(.., None)` drops it.
        headers: BTreeMap::from([
            ("host".to_owned(), "127.0.0.1:4000".to_owned()),
            ("authorization".to_owned(), format!("Bearer {TOKEN}")),
        ]),
        body: if body.is_null() {
            Vec::new()
        } else {
            serde_json::to_vec(body).unwrap()
        },
    }
}

fn browser(mut req: UiRequest, token: Option<&str>) -> UiRequest {
    req.headers
        .insert("origin".to_owned(), "http://127.0.0.1:4000".to_owned());
    req.headers.remove("authorization");
    if let Some(t) = token {
        req.headers
            .insert("authorization".to_owned(), format!("Bearer {t}"));
    }
    req
}

async fn call(s: &Arc<UiState>, req: UiRequest) -> (u16, Value) {
    let r = handle(s, &req).await;
    let body = r.body_json().unwrap_or(Value::Null);
    (r.status, body)
}

fn text(body: &UiBody) -> String {
    match body {
        UiBody::Full(b) => String::from_utf8_lossy(b).into_owned(),
        UiBody::Stream(_) => "<stream>".to_owned(),
    }
}

#[tokio::test]
async fn config_describes_the_runtime_and_the_page_carries_it() {
    let s = state();
    let (status, body) = call(&s, request("GET", "/ui/api/config", &Value::Null)).await;
    assert_eq!(status, 200);
    assert_eq!(body["project"], "demo-app");
    assert_eq!(body["edition"], "standard");
    assert_eq!(body["sessions"][0]["project"], "demo-app");
    assert_eq!(body["controlToken"], TOKEN);
    let page = handle(&s, &request("GET", "/ui/", &Value::Null)).await;
    assert_eq!(page.status, 200);
    let html = text(&page.body);
    assert!(html.contains("window.__FIREEMU__ = {"), "{html}");
    assert!(html.contains(TOKEN));
    assert!(page
        .headers
        .iter()
        .any(|(k, v)| k == "content-type" && v.starts_with("text/html")));
    // Deep links load the app; unknown files do not.
    assert_eq!(
        handle(
            &s,
            &request("GET", "/ui/firestore/data/users", &Value::Null)
        )
        .await
        .status,
        200
    );
    assert_eq!(
        handle(&s, &request("GET", "/ui/missing.js", &Value::Null))
            .await
            .status,
        404
    );
    assert_eq!(
        handle(&s, &request("GET", "/ui/fireemu-ui.json", &Value::Null))
            .await
            .status,
        404
    );
}

#[tokio::test]
async fn browser_requests_need_a_loopback_origin_host_and_the_control_token() {
    let s = state();
    // A page on localhost without the token: refused for the API, fine for the app.
    let (status, body) = call(
        &s,
        browser(request("GET", "/ui/api/config", &Value::Null), None),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("CONTROL_TOKEN_REQUIRED"));
    assert_eq!(
        handle(&s, &browser(request("GET", "/ui/", &Value::Null), None))
            .await
            .status,
        200
    );
    // With the token in the header it is admitted; in the query it is not (histories and
    // logs would keep it).
    let (status, _) = call(
        &s,
        browser(request("GET", "/ui/api/config", &Value::Null), Some(TOKEN)),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = call(
        &s,
        browser(
            request(
                "GET",
                &format!("/ui/api/config?token={TOKEN}"),
                &Value::Null,
            ),
            None,
        ),
    )
    .await;
    assert_eq!(status, 403);
    // Without an Origin (a navigation, an <iframe> or <script src> from another site, a
    // script on the loopback machine) the token is required all the same.
    let mut bare = request("GET", "/ui/api/config", &Value::Null);
    bare.headers.remove("authorization");
    let (status, body) = call(&s, bare).await;
    assert_eq!(status, 403, "{body}");
    // The served page carries the policy that keeps it out of other sites' frames and
    // lets only its bundle and the nonced configuration script run.
    let page = handle(&s, &browser(request("GET", "/ui/", &Value::Null), None)).await;
    let header = |name: &str| {
        page.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    assert_eq!(header("x-frame-options"), "DENY");
    let csp = header("content-security-policy");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    let nonce = csp
        .split("'nonce-")
        .nth(1)
        .and_then(|rest| rest.split('\'').next())
        .unwrap_or_default()
        .to_owned();
    assert!(!nonce.is_empty(), "{csp}");
    assert!(text(&page.body).contains(&format!("<script nonce=\"{nonce}\">")));
    // A wrong token, a foreign origin, a foreign host: refused.
    let (status, _) = call(
        &s,
        browser(request("GET", "/ui/api/config", &Value::Null), Some("nope")),
    )
    .await;
    assert_eq!(status, 403);
    let mut foreign = request("GET", "/ui/api/config", &Value::Null);
    foreign
        .headers
        .insert("origin".to_owned(), "https://evil.example".to_owned());
    foreign
        .headers
        .insert("authorization".to_owned(), format!("Bearer {TOKEN}"));
    assert_eq!(call(&s, foreign).await.0, 403);
    let mut rebound = request("GET", "/ui/", &Value::Null);
    rebound
        .headers
        .insert("host".to_owned(), "attacker.example:4000".to_owned());
    let (status, body) = call(&s, rebound).await;
    assert_eq!(status, 403);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("FORBIDDEN_HOST"));
    // Control characters in the target are refused at the boundary.
    let mut nul = request("GET", "/ui/api/config", &Value::Null);
    nul.query = "token=a\u{0}b".to_owned();
    assert_eq!(call(&s, nul).await.0, 400);
}

#[tokio::test]
async fn firestore_front_runs_as_owner_and_streams_commits() {
    let s = state();
    let docs = "/ui/api/firestore/v1/projects/demo-app/databases/(default)/documents";
    // Open the stream before the commit so the event is observed.
    let stream = handle(
        &s,
        &request(
            "GET",
            "/ui/api/firestore/watch?project=demo-app&database=(default)",
            &Value::Null,
        ),
    )
    .await;
    assert_eq!(stream.status, 200);
    let UiBody::Stream(mut rx) = stream.body else {
        panic!("not a stream");
    };
    let ready = rx.recv().await.unwrap();
    assert!(std::str::from_utf8(&ready)
        .unwrap()
        .starts_with("event: ready"));
    let (status, body) = call(
        &s,
        request(
            "PATCH",
            &format!("{docs}/users/alice"),
            &json!({"fields": {"name": {"stringValue": "Alice"}}}),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = call(
        &s,
        request("GET", &format!("{docs}/users/alice"), &Value::Null),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["fields"]["name"]["stringValue"], "Alice");
    let (status, body) = call(
        &s,
        request("POST", &format!("{docs}:listCollectionIds"), &json!({})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["collectionIds"], json!(["users"]));
    let commit = rx.recv().await.unwrap();
    let commit = std::str::from_utf8(&commit).unwrap();
    assert!(commit.starts_with("event: commit\n"), "{commit}");
    let data: Value =
        serde_json::from_str(commit.trim().strip_prefix("event: commit\ndata: ").unwrap()).unwrap();
    assert_eq!(
        data["changes"][0]["path"],
        "projects/demo-app/databases/(default)/documents/users/alice"
    );
    assert_eq!(data["changes"][0]["kind"], "created");
    // Another database is filtered out; a foreign project too.
    let (status, _) = call(
        &s,
        request(
            "PATCH",
            "/ui/api/firestore/v1/projects/demo-app/databases/other/documents/x/y",
            &json!({"fields": {}}),
        ),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = call(
        &s,
        request("DELETE", &format!("{docs}/users/alice"), &Value::Null),
    )
    .await;
    assert_eq!(status, 200);
    let deleted = rx.recv().await.unwrap();
    let deleted = std::str::from_utf8(&deleted).unwrap();
    assert!(deleted.contains("\"kind\":\"deleted\""), "{deleted}");
}

#[tokio::test]
async fn auth_front_reaches_admin_and_emulator_routes() {
    let s = state();
    let admin = "/ui/api/auth/identitytoolkit.googleapis.com/v1/projects/demo-app";
    let (status, body) = call(
        &s,
        request(
            "POST",
            &format!("{admin}/accounts"),
            &json!({"email": "a@example.com", "password": "hunter22", "displayName": "A"}),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let uid = body["localId"].as_str().unwrap().to_owned();
    let (status, body) = call(
        &s,
        request(
            "GET",
            &format!("{admin}/accounts:batchGet?maxResults=10"),
            &Value::Null,
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["users"][0]["email"], "a@example.com");
    let (status, body) = call(
        &s,
        request("POST", &format!("{admin}/accounts:update"), &json!({"localId": uid, "customAttributes": "{\"role\":\"admin\"}", "disableUser": true}),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = call(
        &s,
        request(
            "POST",
            &format!("{admin}/accounts:sendOobCode"),
            &json!({"requestType": "PASSWORD_RESET", "email": "a@example.com"}),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = call(
        &s,
        request(
            "GET",
            "/ui/api/auth/emulator/v1/projects/demo-app/oobCodes",
            &Value::Null,
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["oobCodes"][0]["email"], "a@example.com");
    // Client routes are not exposed through the UI.
    let (status, _) = call(
        &s,
        request(
            "POST",
            "/ui/api/auth/identitytoolkit.googleapis.com/v1/accounts:signUp",
            &json!({}),
        ),
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn storage_front_lists_uploads_downloads_and_deletes() {
    let s = state();
    let (status, body) = call(&s, request("GET", "/ui/api/storage/buckets", &Value::Null)).await;
    assert_eq!(status, 200);
    assert_eq!(body["buckets"][0]["name"], "demo-app.appspot.com");
    let mut upload = request("POST", "/ui/api/storage/upload/storage/v1/b/demo-app.appspot.com/o?uploadType=media&name=dir%2Fhello.txt", &Value::Null,
    );
    upload
        .headers
        .insert("content-type".to_owned(), "text/plain".to_owned());
    upload.body = b"hello".to_vec();
    let (status, body) = call(&s, upload).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["name"], "dir/hello.txt");
    let (status, body) = call(
        &s,
        request(
            "GET",
            "/ui/api/storage/storage/v1/b/demo-app.appspot.com/o?prefix=dir%2F&delimiter=%2F",
            &Value::Null,
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["items"][0]["name"], "dir/hello.txt");
    let download = handle(
        &s,
        &request("GET", "/ui/api/storage/download/storage/v1/b/demo-app.appspot.com/o/dir%2Fhello.txt?alt=media", &Value::Null,
        ),
    )
    .await;
    assert_eq!(download.status, 200);
    assert_eq!(text(&download.body), "hello");
    let (status, _) = call(
        &s,
        request(
            "DELETE",
            "/ui/api/storage/storage/v1/b/demo-app.appspot.com/o/dir%2Fhello.txt",
            &Value::Null,
        ),
    )
    .await;
    assert!(status == 200 || status == 204, "{status}");
    // The Firebase protocol is not exposed through the UI.
    let (status, _) = call(
        &s,
        request(
            "GET",
            "/ui/api/storage/v0/b/demo-app.appspot.com/o",
            &Value::Null,
        ),
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn control_front_moves_the_clock_and_manages_snapshots() {
    let s = state();
    let (status, body) = call(
        &s,
        request(
            "POST",
            "/ui/api/control/v1/sessions/default/clock:advance",
            &json!({"seconds": 60}),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["clock"], "2026-08-29T12:02:00Z");
    let (status, body) = call(
        &s,
        request(
            "POST",
            "/ui/api/control/v1/sessions/default/snapshots",
            &json!({"name": "seeded"}),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = call(
        &s,
        request(
            "GET",
            "/ui/api/control/v1/sessions/default/snapshots",
            &Value::Null,
        ),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["snapshots"][0]["name"], "seeded");
    let (status, body) = call(
        &s,
        request(
            "POST",
            "/ui/api/control/v1/sessions/default:awaitIdle",
            &json!({}),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["idle"], true);
    let (status, _) = call(&s, request("GET", "/ui/api/control/v1/rules", &Value::Null)).await;
    assert_eq!(status, 200);
    let (status, _) = call(&s, request("GET", "/ui/api/control/other", &Value::Null)).await;
    assert_eq!(status, 404);
    let (status, body) = call(&s, request("GET", "/ui/api/functions", &Value::Null)).await;
    assert_eq!(status, 200);
    assert_eq!(body["configured"], false);
    let (status, _) = call(&s, request("GET", "/ui/api/functions/logs", &Value::Null)).await;
    assert_eq!(status, 404);
}

#[test]
fn host_and_control_character_checks() {
    use fireemu_adapter_ui::{has_control_chars, host_is_local};
    assert!(host_is_local("localhost:4000"));
    assert!(host_is_local("127.0.0.1"));
    assert!(host_is_local("127.0.0.2"));
    assert!(host_is_local("LOCALHOST:4000"));
    assert!(host_is_local("[::1]:4000"));
    assert!(!host_is_local("evil.example:4000"));
    assert!(!host_is_local("localhost."));
    assert!(!host_is_local("127.attacker.example"));
    assert!(!host_is_local("127.0.0.1.evil.example"));
    assert!(has_control_chars("a\u{0}b"));
    assert!(has_control_chars("a\nb"));
    assert!(!has_control_chars("/ui/api/config?x=%00"));
}

#[tokio::test]
async fn buckets_are_listed_per_session_project_and_a_missing_host_is_refused() {
    let s = state();
    let (status, body) = call(
        &s,
        request(
            "GET",
            "/ui/api/storage/buckets?project=demo-app",
            &Value::Null,
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["buckets"][0]["name"], "demo-app.appspot.com");
    let (status, _) = call(
        &s,
        request(
            "GET",
            "/ui/api/storage/buckets?project=demo-z",
            &Value::Null,
        ),
    )
    .await;
    assert_eq!(status, 404);
    let mut hostless = request("GET", "/ui/api/config", &Value::Null);
    hostless.headers.remove("host");
    let (status, body) = call(&s, hostless).await;
    assert_eq!(status, 403, "{body}");
}

/// A runner that speaks the fireemu protocol and succeeds at everything: enough for
/// the log stream to have invocation records to deliver.
const INLINE_RUNNER: &str = r#"
import json, sys

def send(m):
    p = json.dumps(m).encode()
    sys.stdout.buffer.write(f"{len(p)}\n".encode())
    sys.stdout.buffer.write(p)
    sys.stdout.buffer.flush()

send({"type": "hello", "runner": "ui-test", "manifest": {"functions": [
    {"name": "tick", "trigger": {"type": "schedule", "schedule": "every 5 minutes"}}
]}})
while True:
    line = sys.stdin.buffer.readline()
    if not line:
        break
    msg = json.loads(sys.stdin.buffer.read(int(line.strip())))
    if msg.get("type") == "shutdown":
        break
    if msg.get("type") != "invoke":
        continue
    send({"type": "result", "invocationId": msg["invocationId"], "ok": True})
"#;

/// The UI state with a real functions runtime behind it.
async fn state_with_functions() -> (
    Arc<UiState>,
    Arc<fireemu_adapter_functions::runtime::FunctionsRuntime>,
) {
    use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
    use fireemu_adapter_functions::runtime::{CatchUpPolicy, FunctionsConfig, OverlapPolicy};
    let spec = SpawnSpec {
        command: vec![
            "python3".to_owned(),
            "-c".to_owned(),
            INLINE_RUNNER.to_owned(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: std::time::Duration::from_secs(20),
    };
    let runner = Runner::spawn_spec(&spec).await.unwrap();
    let manifest = fireemu_adapter_functions::manifest_json::parse_manifest(
        runner.hello().manifest.as_ref().unwrap(),
    )
    .unwrap();
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let runtime = fireemu_adapter_functions::runtime::FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: "demo-app".into(),
            default_bucket: "demo-app.appspot.com".into(),
            location: "nam5".into(),
            session: fireemu_core_types::ids::SessionId::new(7),
            max_running: 4,
            debug_mode: false,
            retry_attempts: 4,
            max_catch_up_runs: 1000,
            runner_secret: "s".into(),
            overlap: OverlapPolicy::Allow,
            catch_up: CatchUpPolicy::All,
            functions_host: None,
        },
        clock,
        Arc::new(runner),
        None,
    );
    tokio::spawn(runtime.clone().dispatch_loop());
    let mut state = Arc::try_unwrap(state())
        .ok()
        .expect("the state is unshared");
    state.functions = Some(runtime.clone());
    (Arc::new(state), runtime)
}

/// A runner that hosts an HTTP echo server (so HTTP / callable functions and task dispatch
/// have somewhere to go) and speaks the fireemu protocol. A POST whose path names the task
/// queue is recorded to `FIREEMU_UI_TASK_PROBE` and acknowledged with `204`; every other
/// request is echoed as JSON so an invocation's forwarding can be asserted from the outside.
const INLINE_HTTP_RUNNER: &str = r#"
import http.server, json, os, sys, threading

def send(m):
    p = json.dumps(m).encode()
    sys.stdout.buffer.write(f"{len(p)}\n".encode())
    sys.stdout.buffer.write(p)
    sys.stdout.buffer.flush()

probe = os.environ.get("FIREEMU_UI_TASK_PROBE", "")

class Handler(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        if probe and self.path.endswith("/countJob"):
            with open(probe, "a", encoding="utf-8") as f:
                f.write(body.decode("utf-8", "replace") + "\n")
            self.send_response(204)
            self.end_headers()
            return
        payload = json.dumps({
            "method": self.command,
            "path": self.path,
            "body": body.decode("utf-8", "replace"),
        }).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    do_GET = _handle
    do_POST = _handle
    def log_message(self, *args):
        pass

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
send({"type": "hello", "runner": "ui-http", "httpPort": srv.server_address[1], "manifest": {"functions": [
    {"name": "echo", "trigger": {"type": "http", "callable": False}},
    {"name": "add", "trigger": {"type": "http", "callable": True, "enforceAppCheck": False, "consumeAppCheckToken": "disabled"}},
    {"name": "mirror", "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.created", "document": "todos/{id}"}}
]}})
while True:
    line = sys.stdin.buffer.readline()
    if not line:
        break
    msg = json.loads(sys.stdin.buffer.read(int(line.strip())))
    if msg.get("type") == "shutdown":
        break
    if msg.get("type") == "invoke":
        send({"type": "result", "invocationId": msg["invocationId"], "ok": True})
"#;

/// The UI state with a real Functions port bound in front of an HTTP-capable runner, so the
/// invoke and enqueue fronts can be driven end to end. Returns the state, the runtime, and
/// the path the task handler records dispatched tasks to.
async fn state_with_http_functions() -> (
    Arc<UiState>,
    Arc<fireemu_adapter_functions::runtime::FunctionsRuntime>,
    std::path::PathBuf,
) {
    use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
    use fireemu_adapter_functions::runtime::{CatchUpPolicy, FunctionsConfig, OverlapPolicy};
    use fireemu_core_functions::manifest::{TaskRateLimits, TaskRetryConfig, Trigger};

    let dir = std::env::temp_dir().join(format!("fireemu-ui-invoke-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let probe = dir.join("tasks");
    let _ = std::fs::remove_file(&probe);

    let spec = SpawnSpec {
        command: vec![
            "python3".to_owned(),
            "-c".to_owned(),
            INLINE_HTTP_RUNNER.to_owned(),
        ],
        cwd: None,
        env: vec![(
            "FIREEMU_UI_TASK_PROBE".to_owned(),
            probe.display().to_string(),
        )],
        hello_timeout: std::time::Duration::from_secs(20),
    };
    let runner = Runner::spawn_spec(&spec).await.unwrap();
    let mut manifest = fireemu_adapter_functions::manifest_json::parse_manifest(
        runner.hello().manifest.as_ref().unwrap(),
    )
    .unwrap();
    // A task-queue function, cloning the HTTP template so it shares the region and runner.
    let mut count_job = manifest.get("echo").unwrap().clone();
    "countJob".clone_into(&mut count_job.name);
    "countJob".clone_into(&mut count_job.entry_point);
    count_job.trigger = Trigger::TaskQueue {
        retry: TaskRetryConfig::default(),
        rate_limits: TaskRateLimits::default(),
    };
    manifest.functions.push(count_job);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let runtime = fireemu_adapter_functions::runtime::FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: "demo-app".into(),
            default_bucket: "demo-app.appspot.com".into(),
            location: "nam5".into(),
            session: fireemu_core_types::ids::SessionId::new(7),
            max_running: 4,
            debug_mode: false,
            retry_attempts: 4,
            max_catch_up_runs: 1000,
            runner_secret: "s".into(),
            overlap: OverlapPolicy::Allow,
            catch_up: CatchUpPolicy::All,
            functions_host: Some(addr.clone()),
        },
        clock,
        Arc::new(runner),
        None,
    );
    tokio::spawn(runtime.clone().dispatch_loop());
    tokio::spawn(fireemu_adapter_functions::http::serve_functions(
        listener,
        runtime.clone(),
        fireemu_adapter_functions::http::HttpAdmission::new(),
    ));

    let mut state = Arc::try_unwrap(state())
        .ok()
        .expect("the state is unshared");
    state.info.functions_addr = Some(addr);
    state.functions = Some(runtime.clone());
    (Arc::new(state), runtime, probe)
}

/// Waits for the task probe to hold at least `expected` recorded dispatches.
async fn wait_for_probe(probe: &std::path::Path, expected: usize) -> Vec<String> {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let lines = std::fs::read_to_string(probe)
                .unwrap_or_default()
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if lines.len() >= expected {
                return lines;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the probe reached the expected number of dispatches")
}

#[tokio::test]
async fn invoking_an_on_request_function_forwards_through_the_port_and_returns_its_response() {
    let (s, runtime, _probe) = state_with_http_functions().await;
    let (status, body) = call(
        &s,
        browser(
            request(
                "POST",
                "/ui/api/functions/echo:invoke",
                &json!({"method": "post", "path": "/greet", "query": "x=1", "body": "{\"hi\":true}"}),
            ),
            Some(TOKEN),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], 200);
    assert_eq!(body["bodyEncoding"], "utf8");
    // The runner echoed exactly the method, route and body the console asked it to forward.
    let echoed: Value = serde_json::from_str(body["body"].as_str().unwrap()).unwrap();
    assert_eq!(echoed["method"], "POST");
    assert_eq!(echoed["path"], "/demo-app/us-central1/echo/greet?x=1");
    assert_eq!(echoed["body"], "{\"hi\":true}");
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn invoking_refuses_a_non_http_function_an_unknown_name_and_a_bad_method() {
    let (s, runtime, _probe) = state_with_http_functions().await;
    // A Firestore trigger is not HTTP-invokable.
    let (status, _) = call(
        &s,
        browser(
            request("POST", "/ui/api/functions/mirror:invoke", &json!({})),
            Some(TOKEN),
        ),
    )
    .await;
    assert_eq!(status, 400);
    // An unknown function.
    let (status, _) = call(
        &s,
        browser(
            request("POST", "/ui/api/functions/nope:invoke", &json!({})),
            Some(TOKEN),
        ),
    )
    .await;
    assert_eq!(status, 404);
    // A method that could not be framed safely is refused before anything is sent.
    let (status, _) = call(
        &s,
        browser(
            request(
                "POST",
                "/ui/api/functions/echo:invoke",
                &json!({"method": "GET DELETE"}),
            ),
            Some(TOKEN),
        ),
    )
    .await;
    assert_eq!(status, 400);
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn enqueuing_a_task_dispatches_it_to_the_queue_handler() {
    let (s, runtime, probe) = state_with_http_functions().await;
    let (status, body) = call(
        &s,
        browser(
            request(
                "POST",
                "/ui/api/functions/countJob:enqueue",
                &json!({"data": {"n": 7}, "id": "job-1"}),
            ),
            Some(TOKEN),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body["task"]["name"],
        "projects/demo-app/locations/us-central1/queues/countJob/tasks/job-1"
    );
    // The accepted response echoes the decoded body, as the Admin SDK's does.
    assert_eq!(body["task"]["httpRequest"]["body"], json!({"data": {"n": 7}}));
    // The task actually reached the handler over the port with the wrapped payload.
    let entries = wait_for_probe(&probe, 1).await;
    let dispatched: Value = serde_json::from_str(&entries[0]).unwrap();
    assert_eq!(dispatched, json!({"data": {"n": 7}}));
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn enqueuing_refuses_a_non_task_function_and_a_bad_id() {
    let (s, runtime, _probe) = state_with_http_functions().await;
    let (status, _) = call(
        &s,
        browser(
            request(
                "POST",
                "/ui/api/functions/echo:enqueue",
                &json!({"data": {}}),
            ),
            Some(TOKEN),
        ),
    )
    .await;
    assert_eq!(status, 400, "echo is not a task-queue function");
    let (status, body) = call(
        &s,
        browser(
            request(
                "POST",
                "/ui/api/functions/countJob:enqueue",
                &json!({"data": {}, "id": "bad id"}),
            ),
            Some(TOKEN),
        ),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    runtime.runner().shutdown().await;
}

#[tokio::test]
async fn the_functions_overview_reports_the_clock_and_a_schedule_next_run() {
    let (s, runtime) = state_with_functions().await;
    let (status, body) = call(&s, request("GET", "/ui/api/functions", &Value::Null)).await;
    assert_eq!(status, 200);
    // The runtime clock starts at 12:01:00Z; "every 5 minutes" next runs at 12:05:00Z.
    assert_eq!(body["clock"], "2026-08-29T12:01:00Z");
    let tick = body["functions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == "tick")
        .expect("the tick schedule is listed");
    assert_eq!(tick["nextRun"], "2026-08-29T12:05:00Z");
    runtime.runner().shutdown().await;
}

/// The next server-sent event of a stream, keep-alive comments skipped.
async fn next_sse(rx: &mut tokio::sync::mpsc::Receiver<bytes::Bytes>) -> (String, Value) {
    loop {
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
            .await
            .expect("the stream produced an event in time")
            .expect("the stream is open");
        let frame = String::from_utf8_lossy(&chunk).into_owned();
        let Some((name, rest)) = frame.split_once('\n') else {
            continue;
        };
        let Some(name) = name.strip_prefix("event: ") else {
            continue; // a keep-alive comment
        };
        let data = rest.trim().strip_prefix("data: ").unwrap_or("null");
        return (name.to_owned(), serde_json::from_str(data).unwrap());
    }
}

async fn open_log_stream(s: &Arc<UiState>) -> tokio::sync::mpsc::Receiver<bytes::Bytes> {
    let r = handle(s, &request("GET", "/ui/api/functions/logs", &Value::Null)).await;
    assert_eq!(r.status, 200);
    match r.body {
        UiBody::Stream(rx) => rx,
        UiBody::Full(_) => panic!("the log route answers with a stream"),
    }
}

#[tokio::test]
async fn the_functions_log_stream_sends_deltas_and_resyncs_an_expired_cursor() {
    // FN-RET-05: each connection follows its own cursor and receives only what it is missing;
    // a cursor the runtime can no longer answer produces an explicit resync carrying the
    // retained window, not a silent gap and not a copy of everything on every poll.
    let (s, runtime) = state_with_functions().await;
    runtime.run_schedule("tick").unwrap();
    assert!(runtime
        .await_idle(std::time::Duration::from_secs(10))
        .await
        .is_ok());

    // The first client's snapshot carries the one record made so far.
    let mut first = open_log_stream(&s).await;
    let (name, data) = next_sse(&mut first).await;
    assert_eq!(name, "snapshot");
    assert_eq!(data["invocations"].as_array().unwrap().len(), 1);
    let generation = data["generation"].as_u64().unwrap();

    // A second record reaches the first client as a delta of exactly one invocation.
    runtime.run_schedule("tick").unwrap();
    assert!(runtime
        .await_idle(std::time::Duration::from_secs(10))
        .await
        .is_ok());
    let (name, data) = next_sse(&mut first).await;
    assert_eq!(name, "invocation");
    assert_eq!(data["function"], "tick");
    assert_eq!(data["outcome"], "ok");
    let sequence = data["sequence"].as_u64().unwrap();

    // A client connecting now starts from the whole retained window instead.
    let mut second = open_log_stream(&s).await;
    let (name, data) = next_sse(&mut second).await;
    assert_eq!(name, "snapshot");
    assert_eq!(data["invocations"].as_array().unwrap().len(), 2);
    assert_eq!(data["generation"].as_u64().unwrap(), generation);

    // The retention window shrinks below what the first client is missing: it is told to
    // resync rather than handed a delta with a hole in it.
    runtime.set_retention(1, 1);
    for _ in 0..3 {
        runtime.run_schedule("tick").unwrap();
        assert!(runtime
            .await_idle(std::time::Duration::from_secs(10))
            .await
            .is_ok());
    }
    let mut saw_resync = false;
    for _ in 0..6 {
        let (name, data) = next_sse(&mut first).await;
        if name == "resync" {
            assert_eq!(data["generation"].as_u64().unwrap(), generation);
            let window = data["invocations"].as_array().unwrap();
            assert_eq!(window.len(), 1, "the resync carries the retained window");
            assert!(window[0]["sequence"].as_u64().unwrap() > sequence);
            saw_resync = true;
            break;
        }
        assert_eq!(name, "invocation", "only deltas until the cursor expires");
    }
    assert!(saw_resync, "the expired cursor produced a resync");
    runtime.runner().shutdown().await;
}

// --- App Check (specification sections 9 and 15) -----------------------------------------

/// The registered app of the App Check fixture, and its static debug secret.
const AC_APP_ID: &str = "1:1234567890:web:local-test-app";
const AC_SECRET: &str = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

/// One RSA key for the whole test binary: generation is slow in a debug build.
fn ac_signer() -> Arc<fireemu_adapter_http::signing::AppCheckRsaSigner> {
    static KEY: std::sync::OnceLock<Arc<fireemu_adapter_http::signing::AppCheckRsaSigner>> =
        std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        fireemu_adapter_http::signing::AppCheckRsaSigner::generate(
            fireemu_adapter_http::signing::AppCheckKeySource::Seed(11),
        )
        .expect("the seeded key generates")
    })
    .clone()
}

/// The App Check state the UI front and the control API share: one enabled app of the default
/// project with one static debug-token digest, and one disabled app of another project.
fn ac_state() -> Arc<AppCheckState> {
    use fireemu_core_app_check::crypto::DebugTokenHasher;
    let canonical = fireemu_core_app_check::exchange::canonical_debug_token(AC_SECRET)
        .expect("the fixture secret is a canonical UUIDv4");
    let digest = fireemu_core_app_check::registry::DebugTokenDigest::from_bytes(
        fireemu_adapter_http::signing::Sha256DebugTokenHasher.sha256(canonical.as_bytes()),
    );
    let mut registry =
        fireemu_core_app_check::registry::AppCheckRegistry::new(3600).expect("3600s is in range");
    registry
        .register_app(fireemu_core_app_check::registry::AppRegistration {
            project_id: "demo-app".to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: AC_APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: vec![digest],
        })
        .expect("the fixture app registers");
    registry
        .register_app(fireemu_core_app_check::registry::AppRegistration {
            project_id: "demo-other".to_owned(),
            project_number: "9876543210".to_owned(),
            app_id: "1:9876543210:web:other-test-app".to_owned(),
            enabled: false,
            debug_token_digests: Vec::new(),
        })
        .expect("the second project registers");
    registry.set_project_epoch(
        "demo-app",
        fireemu_core_app_check::registry::ProjectEpoch::new(0x0123_4567_89AB_CDEF),
    );
    Arc::new(AppCheckState {
        registry: Arc::new(RwLock::new(registry)),
        signer: ac_signer(),
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        control_token: TOKEN.to_owned(),
        hasher: Arc::new(fireemu_adapter_http::signing::Sha256DebugTokenHasher),
        constant_time: Arc::new(fireemu_adapter_http::signing::SubtleConstantTimeEq),
        secrets: Arc::new(fireemu_adapter_http::signing::OsDebugSecrets),
        barrier: None,
    })
}

/// The hexadecimal digest of the fixture secret: no response of the surface may contain it.
fn ac_digest_hex() -> String {
    use fireemu_core_app_check::crypto::DebugTokenHasher;
    use std::fmt::Write as _;
    let canonical = fireemu_core_app_check::exchange::canonical_debug_token(AC_SECRET).unwrap();
    fireemu_adapter_http::signing::Sha256DebugTokenHasher
        .sha256(canonical.as_bytes())
        .iter()
        .fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn header<'a>(r: &'a fireemu_adapter_ui::UiResponse, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn the_app_check_summary_lists_apps_and_modes_and_carries_no_digest() {
    let s = state_with(Some(ac_state()));
    let r = handle(&s, &request("GET", "/ui/api/appcheck/config", &Value::Null)).await;
    assert_eq!(header(&r, "cache-control"), Some("no-store"));
    let body = r.body_json().unwrap();
    assert_eq!(body["enabled"], json!(true));
    assert!(body["kid"]
        .as_str()
        .unwrap()
        .starts_with("fireemu-app-check-"));
    assert_eq!(
        body["modes"],
        json!([
            {"service": "auth", "mode": "unenforced"},
            {"service": "firestore", "mode": "enforced"},
            {"service": "storage", "mode": "off"},
        ])
    );
    assert_eq!(body["tokenTtlSeconds"], json!(3600));
    let apps = body["apps"].as_array().unwrap();
    assert_eq!(apps.len(), 2, "both registered projects are listed");
    assert_eq!(apps[0]["appId"], json!(AC_APP_ID));
    assert_eq!(apps[0]["projectId"], json!("demo-app"));
    assert_eq!(apps[0]["projectNumber"], json!("1234567890"));
    assert_eq!(apps[0]["enabled"], json!(true));
    assert_eq!(apps[0]["staticDigestCount"], json!(1));
    assert_eq!(apps[0]["dynamicTokenCount"], json!(0));
    assert_eq!(apps[1]["enabled"], json!(false));

    // The summary describes the registration, never the credentials behind it.
    let text = serde_json::to_string(&body).unwrap();
    assert!(
        !text.contains(&ac_digest_hex()),
        "no digest reaches the page"
    );
    assert!(
        !text.contains(AC_SECRET),
        "no debug secret reaches the page"
    );
    assert!(
        !text.contains("0123456789abcdef"),
        "no project epoch reaches the page"
    );
}

#[tokio::test]
async fn the_app_check_summary_filters_by_project() {
    let s = state_with(Some(ac_state()));
    let (status, body) = call(
        &s,
        request(
            "GET",
            "/ui/api/appcheck/config?project=demo-app",
            &Value::Null,
        ),
    )
    .await;
    assert_eq!(status, 200);
    let apps = body["apps"].as_array().unwrap();
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0]["projectId"], json!("demo-app"));
}

#[tokio::test]
async fn a_runtime_without_app_check_says_so_and_refuses_the_management_routes() {
    let s = state();
    let (status, body) = call(&s, request("GET", "/ui/api/appcheck/config", &Value::Null)).await;
    assert_eq!(status, 200);
    assert_eq!(body["enabled"], json!(false));
    assert_eq!(body["apps"], json!([]));
    assert_eq!(body["kid"], Value::Null);

    let path = format!("/ui/api/appcheck/projects/demo-app/apps/{AC_APP_ID}/debugTokens");
    let (status, body) = call(&s, request("GET", &path, &Value::Null)).await;
    assert_eq!(status, 404);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("appCheck.enabled"));

    // `window.__FIREEMU__` tells the page the surface does not exist here.
    let (_, config) = call(&s, request("GET", "/ui/api/config", &Value::Null)).await;
    assert_eq!(config["appCheckEnabled"], json!(false));
}

#[tokio::test]
async fn the_debug_token_front_creates_lists_and_deletes_one_dynamic_token() {
    let s = state_with(Some(ac_state()));
    let (_, config) = call(&s, request("GET", "/ui/api/config", &Value::Null)).await;
    assert_eq!(config["appCheckEnabled"], json!(true));

    let path = format!("/ui/api/appcheck/projects/demo-app/apps/{AC_APP_ID}/debugTokens");
    let created = handle(
        &s,
        &request(
            "POST",
            &path,
            &json!({"displayName": "ci runner", "generate": true}),
        ),
    )
    .await;
    assert_eq!(header(&created, "cache-control"), Some("no-store"));
    let created = created.body_json().unwrap();
    let secret = created["debugToken"].as_str().unwrap().to_owned();
    assert_eq!(
        secret.len(),
        36,
        "a canonical UUIDv4 comes back exactly once"
    );
    let token_id = created["tokenId"].as_str().unwrap().to_owned();
    assert_eq!(created["displayName"], json!("ci runner"));

    // The list shows the record without the credential behind it.
    let (status, listed) = call(&s, request("GET", &path, &Value::Null)).await;
    assert_eq!(status, 200);
    let text = serde_json::to_string(&listed).unwrap();
    assert!(!text.contains(&secret), "the raw secret is never listed");
    let tokens = listed["debugTokens"].as_array().unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0]["tokenId"], json!(token_id));
    assert_eq!(tokens[0]["displayName"], json!("ci runner"));
    let prefix = tokens[0]["digestPrefix"].as_str().unwrap();
    assert!(prefix.len() < 64, "a prefix, never the full digest");

    // The summary counts it as dynamic, not as a configured digest.
    let (_, summary) = call(&s, request("GET", "/ui/api/appcheck/config", &Value::Null)).await;
    assert_eq!(summary["apps"][0]["staticDigestCount"], json!(1));
    assert_eq!(summary["apps"][0]["dynamicTokenCount"], json!(1));

    // A malformed supplied secret is refused before anything is registered.
    let (status, _) = call(
        &s,
        request("POST", &path, &json!({"debugToken": "not-a-uuid"})),
    )
    .await;
    assert_eq!(status, 400);

    let (status, _) = call(
        &s,
        request("DELETE", &format!("{path}/{token_id}"), &Value::Null),
    )
    .await;
    assert_eq!(status, 200);
    let (_, listed) = call(&s, request("GET", &path, &Value::Null)).await;
    assert_eq!(listed["debugTokens"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn the_debug_token_front_refuses_an_unconfigured_app_and_a_browser_without_the_token() {
    let s = state_with(Some(ac_state()));
    let unknown = "/ui/api/appcheck/projects/demo-app/apps/1:1234567890:web:nope/debugTokens";
    let (status, body) = call(&s, request("GET", unknown, &Value::Null)).await;
    assert_eq!(status, 404);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("static configuration"));

    // The UI guard runs first: a page that cannot present the control token never reaches the
    // privileged front at all.
    let path = format!("/ui/api/appcheck/projects/demo-app/apps/{AC_APP_ID}/debugTokens");
    let (status, body) = call(&s, browser(request("GET", &path, &Value::Null), None)).await;
    assert_eq!(status, 403);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("CONTROL_TOKEN_REQUIRED"));
}

/// One observation of `project`, as an adapter would have recorded it.
fn ac_observation(
    project: &str,
    service: &'static str,
    operation: &str,
) -> fireemu_core_app_check::observe::Observation {
    fireemu_core_app_check::observe::Observation {
        project_id: project.to_owned(),
        service,
        transport: "grpc",
        operation: operation.to_owned(),
        mode: fireemu_core_app_check::verify::BaselineMode::Enforced,
        category: fireemu_core_app_check::observe::CredentialCategory::Invalid,
        failure: Some(fireemu_core_app_check::verify::AppCheckFailure::Malformed),
        app_id: fireemu_core_app_check::observe::UNKNOWN_APP_LABEL.to_owned(),
        at: LogicalInstant::from_unix_seconds(1_788_004_860),
        policy_generation: 1,
        admitted: false,
    }
}

#[tokio::test]
async fn the_observation_route_answers_through_the_control_front() {
    let app_check = ac_state();
    let s = state_with(Some(app_check.clone()));
    {
        let registry = app_check.registry.read().unwrap();
        registry.record_observation(ac_observation("demo-app", "firestore", "Commit"));
    }
    let r = handle(
        &s,
        &request(
            "GET",
            "/ui/api/control/v1/sessions/default/appCheck/observations",
            &Value::Null,
        ),
    )
    .await;
    assert_eq!(
        header(&r, "cache-control"),
        Some("no-store"),
        "privileged failure reasons are never cached"
    );
    let body = r.body_json().unwrap();
    assert_eq!(body["project"], json!("demo-app"));
    let counters = body["counters"].as_array().unwrap();
    assert_eq!(counters.len(), 1);
    assert_eq!(counters[0]["service"], json!("firestore"));
    assert_eq!(counters[0]["appId"], json!("unknown"));
    assert_eq!(counters[0]["category"], json!("invalid"));
    assert_eq!(counters[0]["outcome"], json!("denied"));
    assert_eq!(counters[0]["count"], json!(1));
    let observations = body["observations"].as_array().unwrap();
    assert_eq!(observations[0]["operation"], json!("Commit"));
    assert_eq!(observations[0]["mode"], json!("enforced"));
    assert!(observations[0]["reason"].is_string());
    let text = serde_json::to_string(&body).unwrap();
    assert!(!text.contains(AC_SECRET));
    assert!(!text.contains(&ac_digest_hex()));
}

/// The page is served the selected session's project and nothing else: the front carries the
/// session name through to the control API, which reads that project's own ring.
#[tokio::test]
async fn the_observation_front_serves_only_the_selected_sessions_project() {
    let app_check = ac_state();
    let s = state_with(Some(app_check.clone()));
    s.control
        .sessions
        .lock()
        .unwrap()
        .insert("second".to_owned(), "demo-other".to_owned());
    {
        let registry = app_check.registry.read().unwrap();
        registry.record_observation(ac_observation("demo-app", "firestore", "Commit"));
        for _ in 0..3 {
            registry.record_observation(ac_observation("demo-other", "storage", "storage.upload"));
        }
    }

    let default = handle(
        &s,
        &request(
            "GET",
            "/ui/api/control/v1/sessions/default/appCheck/observations",
            &Value::Null,
        ),
    )
    .await
    .body_json()
    .unwrap();
    assert_eq!(default["project"], json!("demo-app"));
    let observations = default["observations"].as_array().unwrap();
    assert_eq!(observations.len(), 1, "{observations:?}");
    assert_eq!(observations[0]["operation"], json!("Commit"));
    assert!(
        !serde_json::to_string(&default)
            .unwrap()
            .contains("storage.upload"),
        "the other session's traffic is not this session's: {default}"
    );

    let second = handle(
        &s,
        &request(
            "GET",
            "/ui/api/control/v1/sessions/second/appCheck/observations",
            &Value::Null,
        ),
    )
    .await
    .body_json()
    .unwrap();
    assert_eq!(second["project"], json!("demo-other"));
    assert_eq!(second["observations"].as_array().unwrap().len(), 3);
    let counters = second["counters"].as_array().unwrap();
    assert_eq!(counters.len(), 1, "{counters:?}");
    assert_eq!(counters[0]["service"], json!("storage"));
    assert_eq!(counters[0]["count"], json!(3));
    assert!(
        counters[0]["function"].is_null(),
        "only a callable name is a counter label: {counters:?}"
    );
}

#[tokio::test]
async fn concurrent_event_streams_are_bounded_and_the_surplus_is_refused() {
    // The UI caps concurrent event streams (`sse::MAX_STREAMS`) so a runaway client cannot pile
    // up tasks that poll the runtime. Every slot is served; the next stream is refused with 429
    // rather than admitted. The commit stream fills the slots without a functions runtime.
    let s = state();
    let watch = "/ui/api/firestore/watch?project=demo-app";
    let mut held = Vec::new();
    for _ in 0..fireemu_adapter_ui::sse::MAX_STREAMS {
        let r = handle(&s, &request("GET", watch, &Value::Null)).await;
        assert_eq!(r.status, 200);
        match r.body {
            UiBody::Stream(rx) => held.push(rx),
            UiBody::Full(_) => panic!("the watch route answers with a stream"),
        }
    }
    let refused = handle(&s, &request("GET", watch, &Value::Null)).await;
    assert_eq!(refused.status, 429);
    let body = refused.body_json().unwrap();
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .starts_with("RESOURCE_EXHAUSTED"));
    // Holding the receivers keeps the slots taken; dropping them lets the tasks end.
    drop(held);
}

#[tokio::test]
async fn the_alerts_front_needs_a_runtime_and_refuses_a_get() {
    let s = state();
    // No functions runtime is wired into the default test state, so an alert has nowhere to go.
    let (status, body) = call(
        &s,
        browser(
            request(
                "POST",
                "/ui/api/functions/alerts",
                &json!({"alertType": "crashlytics.newFatalIssue"}),
            ),
            Some(TOKEN),
        ),
    )
    .await;
    assert_eq!(status, 404, "{body}");
    // GET is not how an alert is published.
    let (status, _) = call(
        &s,
        browser(
            request("GET", "/ui/api/functions/alerts", &Value::Null),
            Some(TOKEN),
        ),
    )
    .await;
    assert_eq!(status, 405);
}
