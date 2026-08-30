//! The UI surface at the handler level: browser policy, the embedded app, the privileged
//! fronts to Firestore / Auth / Storage / control, and the commit stream.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};

use ftd_adapter_grpc::gateway::Gateway;
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_grpc::rest::RestState;
use ftd_adapter_http::control::ControlState;
use ftd_adapter_http::identity_toolkit::AuthState;
use ftd_adapter_http::storage::StorageState;
use ftd_adapter_ui::{handle, RuntimeInfo, UiBody, UiRequest, UiState};
use ftd_core_auth::mfa::TotpPolicy;
use ftd_core_auth::store::AuthStore;
use ftd_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use ftd_core_rules::runtime::LoadedRules;
use ftd_core_session::clock::VirtualClock;
use ftd_core_types::determinism::SplitMix64;
use ftd_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use ftd_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const TOKEN: &str = "ui-test-token";

fn state() -> Arc<UiState> {
    let gateway = Gateway {
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Conservative,
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
    let rules = Arc::new(RwLock::new(LoadedRules::default()));
    let storage_rules = Arc::new(RwLock::new(LoadedRules::default()));
    let storage = Arc::new(StorageState {
        store: Mutex::new(ftd_core_storage::store::StorageState::new(9)),
        clock: clock.clone(),
        auth: Arc::new(ftd_core_auth::store::AuthRegistry::new(
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
    });
    let control = Arc::new(ControlState {
        clock: clock.clone(),
        require_demo_prefix: true,
        edition: FirestoreEdition::Standard,
        capabilities: json!({"schemaVersion": 1}),
        rules,
        storage_rules,
        reset_hooks: Vec::new(),
        functions: None,
        control_token: TOKEN.to_owned(),
        barrier: None,
        snapshot_hooks: Vec::new(),
        snapshots: Mutex::new(BTreeMap::new()),
        faults: Some(Arc::new(ftd_core_session::fault::FaultRegistry::new())),
        text_indexes: Arc::new(Mutex::new(
            ftd_core_firestore::text_index::TextIndexCatalog::default(),
        )),
        default_project: "demo-app".to_owned(),
        tenancy: Arc::new(RwLock::new(ftd_core_session::tenancy::Tenancy::new(
            "demo-app",
        ))),
        sessions: Mutex::new(BTreeMap::from([(
            "default".to_owned(),
            "demo-app".to_owned(),
        )])),
        project_hooks: None,
    });
    Arc::new(UiState {
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
            barrier: None,
            events: None,
            control_token: Some(TOKEN.to_owned()),
            registry: None,
            app_check: None,
            app_check_policy: None,
            tenancy: None,
        }),
        storage,
        control,
        functions: None,
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
    assert!(html.contains("window.__FTD__ = {"), "{html}");
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
        handle(&s, &request("GET", "/ui/ftd-ui.json", &Value::Null))
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
fn new_log_lines_survive_trimming_and_runner_replacement() {
    use ftd_adapter_ui::sse::new_lines;
    let lines = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let a = lines(&["1", "2", "3"]);
    assert_eq!(new_lines(&[], &a), &a[..]);
    assert_eq!(
        new_lines(&a, &lines(&["1", "2", "3", "4"])),
        &lines(&["4"])[..]
    );
    // The buffer was trimmed at the front.
    assert_eq!(
        new_lines(&a, &lines(&["2", "3", "4", "5"])),
        &lines(&["4", "5"])[..]
    );
    // A new runner: nothing in common, everything is new.
    assert_eq!(new_lines(&a, &lines(&["x", "y"])), &lines(&["x", "y"])[..]);
    assert!(new_lines(&a, &a).is_empty());
}

#[test]
fn host_and_control_character_checks() {
    use ftd_adapter_ui::{has_control_chars, host_is_local};
    assert!(host_is_local("localhost:4000"));
    assert!(host_is_local("127.0.0.1"));
    assert!(host_is_local("[::1]:4000"));
    assert!(!host_is_local("evil.example:4000"));
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

/// A runner that speaks the firebase-testd protocol and succeeds at everything: enough for
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
    Arc<ftd_adapter_functions::runtime::FunctionsRuntime>,
) {
    use ftd_adapter_functions::runner::{Runner, SpawnSpec};
    use ftd_adapter_functions::runtime::{CatchUpPolicy, FunctionsConfig, OverlapPolicy};
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
    let manifest = ftd_adapter_functions::manifest_json::parse_manifest(
        runner.hello().manifest.as_ref().unwrap(),
    )
    .unwrap();
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let runtime = ftd_adapter_functions::runtime::FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: "demo-app".into(),
            default_bucket: "demo-app.appspot.com".into(),
            location: "nam5".into(),
            session: ftd_core_types::ids::SessionId::new(7),
            max_running: 4,
            retry_attempts: 4,
            max_catch_up_runs: 1000,
            runner_secret: "s".into(),
            overlap: OverlapPolicy::Allow,
            catch_up: CatchUpPolicy::All,
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
