//! The callable trust boundary of the Functions proxy (specification section 13.4; scenarios
//! 1, 2, 4, 5, 7, 8 and 9 of the Functions list in section 19; obligations `AC-FN-001`,
//! `AC-HEADER-001` and `AC-BOUNDARY-001`).
//!
//! Every assertion here is about the bytes that actually reach the runner: the fake runner
//! hosts an HTTP server that echoes the method, path and every header instance it received, so
//! "the invalid token is removed before runner-side unsafe decoding" is checked by looking at
//! what the runner got, not at what the daemon meant to send.
//!
//! The App Check signer is the same deterministic stand-in the Firestore adapter tests use:
//! RSA key generation is far too slow for a test binary this size, and the shell's real
//! `rsa` / `sha2` implementations are covered by the `fireemu-adapter-http` App Check tests.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use fireemu_adapter_functions::callable::CallableTrust;
use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use fireemu_adapter_grpc::rules::RulesEnforcer;
use fireemu_core_app_check::admission::{AppCheckGate, ServiceAdmission};
use fireemu_core_app_check::crypto::AppCheckSigner;
use fireemu_core_app_check::registry::{AppCheckRegistry, AppRegistration, ProjectEpoch};
use fireemu_core_app_check::verify::BaselineMode;
use fireemu_core_auth::jwt::encode_unsigned;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_rules::runtime::RulesetSlot;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::{DeterministicRng, SplitMix64};
use fireemu_core_types::ids::SessionId;
use fireemu_core_types::time::LogicalInstant;
use serde_json::Value;

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const PROJECT: &str = "demo-app";
const APP_ID: &str = "1:1234567890:web:local-test-app";
const OTHER_APP_ID: &str = "1:9876543210:web:other-test-app";

// ------------------------------------------------------------------------------------------
// A deterministic stand-in for the RS256 signer.
// ------------------------------------------------------------------------------------------

fn keyed_tag(key: u64, input: &[u8]) -> [u8; 32] {
    let mut acc = SplitMix64::new(key).next_u64();
    for byte in input {
        acc = SplitMix64::new(acc ^ u64::from(*byte).wrapping_mul(0x9E37_79B9)).next_u64();
    }
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(
            &SplitMix64::new(acc ^ (i as u64).wrapping_mul(0x1234_5678))
                .next_u64()
                .to_be_bytes(),
        );
    }
    out
}

struct TestSigner {
    key: u64,
    kid: String,
}

impl TestSigner {
    fn new(key: u64) -> Self {
        Self {
            key,
            kid: format!("fireemu-app-check-{key:016x}"),
        }
    }
}

impl AppCheckSigner for TestSigner {
    fn alg(&self) -> &'static str {
        "RS256"
    }
    fn kid(&self) -> &str {
        &self.kid
    }
    fn sign(&self, input: &[u8]) -> Vec<u8> {
        keyed_tag(self.key, input).to_vec()
    }
    fn verify(&self, input: &[u8], signature: &[u8]) -> bool {
        signature == self.sign(input)
    }
    fn public_jwk_json(&self) -> String {
        format!(r#"{{"kty":"oct","kid":"{}"}}"#, self.kid)
    }
}

fn gate() -> AppCheckGate {
    let mut registry = AppCheckRegistry::new(3600).expect("3600s is inside the TTL range");
    registry
        .register_app(AppRegistration {
            project_id: PROJECT.to_owned(),
            project_number: "1234567890".to_owned(),
            app_id: APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: Vec::new(),
        })
        .expect("the demo app registers");
    registry
        .register_app(AppRegistration {
            project_id: "demo-other".to_owned(),
            project_number: "9876543210".to_owned(),
            app_id: OTHER_APP_ID.to_owned(),
            enabled: true,
            debug_token_digests: Vec::new(),
        })
        .expect("the other app registers");
    registry.set_project_epoch(PROJECT, ProjectEpoch::new(0x0123_4567_89AB_CDEF));
    registry.set_project_epoch("demo-other", ProjectEpoch::new(0xFEDC_BA98_7654_3210));
    AppCheckGate::new(
        Arc::new(RwLock::new(registry)),
        Arc::new(TestSigner::new(11)),
    )
}

fn token_for(gate: &AppCheckGate, project: &str, app_id: &str) -> String {
    let registry = gate.registry().read().expect("readable");
    let claims = registry
        .issue_claims(project, app_id, START)
        .expect("the fixture app may exchange");
    fireemu_core_app_check::jwt::encode(&claims, gate.signer().as_ref())
}

// ------------------------------------------------------------------------------------------
// Harness: the real proxy in front of the fake runner's echo server.
// ------------------------------------------------------------------------------------------

struct Harness {
    addr: std::net::SocketAddr,
    gate: AppCheckGate,
    auth: Arc<Mutex<AuthStore>>,
    runtime: Arc<FunctionsRuntime>,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Harness {
    fn token(&self) -> String {
        token_for(&self.gate, PROJECT, APP_ID)
    }

    fn other_app_token(&self) -> String {
        token_for(&self.gate, "demo-other", OTHER_APP_ID)
    }

    /// A signed-in user of this project and the `Authorization` value that names them.
    fn user(&self, email: &str) -> (String, String) {
        let mut store = self.auth.lock().expect("the store is not poisoned");
        let uid = store
            .create_user(NewUser::email(email), START)
            .expect("the user is created");
        let claims = store
            .id_token_claims(&uid, None, START)
            .expect("claims for the new user");
        (
            uid.as_str().to_owned(),
            format!("Bearer {}", encode_unsigned(&claims)),
        )
    }

    async fn call(&self, function: &str, headers: &[(&str, &str)]) -> (u16, Value) {
        let response = self.request("POST", function, headers).await;
        (
            response.status,
            serde_json::from_slice(&response.body).unwrap_or(Value::Null),
        )
    }

    async fn request(
        &self,
        method: &str,
        function: &str,
        headers: &[(&str, &str)],
    ) -> fireemu_adapter_functions::http::ProxiedResponse {
        use std::fmt::Write as _;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut request = format!("{method} /{PROJECT}/us-central1/{function} HTTP/1.1\r\n");
        for (k, v) in headers {
            let _ = write!(request, "{k}: {v}\r\n");
        }
        let body = if method == "POST" {
            br#"{"data":{"a":2,"b":3}}"#.as_slice()
        } else {
            &[]
        };
        let _ = write!(
            request,
            "host: {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            self.addr,
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(self.addr)
            .await
            .expect("the functions port accepts");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("the request is written");
        stream.write_all(body).await.expect("the body is written");
        stream.flush().await.expect("flush");
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .expect("the response is read");
        fireemu_adapter_functions::http::parse_response(&raw, method)
            .expect("a well-formed response")
    }

    async fn guarded_request_with_a_delayed_body(&self) -> std::io::Result<u16> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let body = vec![b'x'; 4 * 1024 * 1024];
        let head = format!(
            "POST /{PROJECT}/us-central1/guarded HTTP/1.1\r\nhost: {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            self.addr,
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(self.addr).await?;
        stream.write_all(head.as_bytes()).await?;
        stream.flush().await?;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        stream.write_all(&body).await?;
        stream.flush().await?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        fireemu_adapter_functions::http::parse_response(&raw, "POST")
            .map(|response| response.status)
            .map_err(std::io::Error::other)
    }

    async fn request_with_an_unrenderable_connection_value(
        &self,
    ) -> fireemu_adapter_functions::http::ProxiedResponse {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut request = format!(
            "POST /{PROJECT}/us-central1/guardedV2 HTTP/1.1\r\nhost: {}\r\ncontent-type: application/json\r\ncontent-length: 7\r\nConnection: x-private,",
            self.addr
        )
        .into_bytes();
        request.extend_from_slice(b"\xff\r\nx-private: secret\r\n\r\n{\"x\":1}");
        let mut stream = tokio::net::TcpStream::connect(self.addr)
            .await
            .expect("the functions port accepts");
        stream
            .write_all(&request)
            .await
            .expect("the raw request is written");
        stream.flush().await.expect("flush");
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .expect("the refusal is read");
        fireemu_adapter_functions::http::parse_response(&raw, "POST")
            .expect("a well-formed refusal")
    }

    async fn post_raw_to(&self, addr: std::net::SocketAddr, path: &str, body: &[u8]) -> u16 {
        self.raw_to_from(addr, path, body, None).await.status
    }

    async fn raw_to_from(
        &self,
        addr: std::net::SocketAddr,
        path: &str,
        body: &[u8],
        origin: Option<&str>,
    ) -> fireemu_adapter_functions::http::ProxiedResponse {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let origin = origin.map_or_else(String::new, |value| format!("origin: {value}\r\n"));
        let head = format!("POST {path} HTTP/1.1\r\nhost: {addr}\r\n{origin}content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the functions port accepts");
        stream
            .write_all(head.as_bytes())
            .await
            .expect("the request head is written");
        stream
            .write_all(body)
            .await
            .expect("the request body is written");
        stream.flush().await.expect("flush");
        let mut raw = Vec::new();
        stream
            .read_to_end(&mut raw)
            .await
            .expect("the response is read");
        fireemu_adapter_functions::http::parse_response(&raw, "POST")
            .expect("a well-formed response")
    }
}

fn response_header<'a>(
    response: &'a fireemu_adapter_functions::http::ProxiedResponse,
    name: &str,
) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Every value of one header the runner received, in wire order.
fn echoed(body: &Value, name: &str) -> Vec<String> {
    body["headers"]
        .as_array()
        .map(|fields| {
            fields
                .iter()
                .filter(|f| f[0].as_str() == Some(name))
                .filter_map(|f| f[1].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

async fn start(trusted: bool) -> Harness {
    start_with_consume(trusted, "disabled").await
}

async fn start_with_consume(trusted: bool, consume: &str) -> Harness {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: vec![("FIREEMU_FAKE_CONSUME".to_owned(), consume.to_owned())],
        hello_timeout: Duration::from_secs(20),
    };
    let runner = Runner::spawn_spec(&spec)
        .await
        .expect("the fake runner starts");
    let manifest =
        parse_manifest(runner.hello().manifest.as_ref().expect("a manifest")).expect("it parses");
    let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: PROJECT.into(),
            default_bucket: "demo-app.appspot.com".into(),
            location: "nam5".into(),
            session: SessionId::new(7),
            max_running: 4,
            debug_mode: false,
            retry_attempts: 4,
            max_catch_up_runs: 1000,
            runner_secret: "runner-secret".into(),
            overlap: fireemu_adapter_functions::runtime::OverlapPolicy::Allow,
            catch_up: fireemu_adapter_functions::runtime::CatchUpPolicy::All,
            functions_host: None,
        },
        clock.clone(),
        Arc::new(runner),
        Some(spec),
    );
    let gate = gate();
    let auth = Arc::new(Mutex::new(AuthStore::new(
        PROJECT,
        SplitMix64::new(3),
        TotpPolicy::default(),
    )));
    if trusted {
        let policy = ServiceAdmission::new(gate.clone(), "functions", BaselineMode::Unenforced)
            .map(Arc::new)
            .expect("unenforced is a policy");
        let verifier = Arc::new(RulesEnforcer::new(
            Arc::new(RulesetSlot::default()),
            auth.clone(),
            clock,
        ));
        runtime.set_callable_trust(Arc::new(CallableTrust::new(policy, verifier, PROJECT)));
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("a local address");
    let server = tokio::spawn(fireemu_adapter_functions::http::serve_functions(
        listener,
        runtime.clone(),
        fireemu_adapter_functions::http::HttpAdmission::new(),
    ));
    Harness {
        addr,
        gate,
        auth,
        runtime,
        server,
    }
}

impl Harness {
    async fn stop(self) {
        self.server.abort();
        self.runtime.runner().shutdown().await;
    }
}

// ------------------------------------------------------------------------------------------
// Scenario 1: an enforced callable rejects a missing App Check token before the handler runs
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_enforced_callable_rejects_a_missing_app_check_token_before_invoking_the_handler() {
    let h = start(true).await;
    let (status, body) = h.call("guarded", &[]).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"]["status"], "UNAUTHENTICATED");
    assert_eq!(body["error"]["message"], "Unauthenticated");
    assert!(
        body.get("headers").is_none(),
        "the runner was never reached: {body}"
    );
    let browser_denial = h
        .request("POST", "guarded", &[("origin", "http://127.0.0.1:5173")])
        .await;
    assert_eq!(browser_denial.status, 401);
    assert_eq!(
        response_header(&browser_denial, "access-control-allow-origin"),
        Some("http://127.0.0.1:5173")
    );
    assert_eq!(response_header(&browser_denial, "vary"), Some("Origin"));
    let token = h.token();
    let (status, body) = h.call("guarded", &[("x-firebase-appcheck", &token)]).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(echoed(&body, "x-firebase-appcheck"), vec![token]);
    h.stop().await;
}

#[tokio::test]
async fn an_enforced_streaming_callable_returns_the_sdk_sse_error_without_invoking_the_handler() {
    let h = start(true).await;
    let denial = h
        .request(
            "POST",
            "guardedV2",
            &[
                ("accept", "text/event-stream"),
                ("origin", "http://127.0.0.1:5173"),
            ],
        )
        .await;

    assert_eq!(denial.status, 200);
    assert_eq!(
        response_header(&denial, "access-control-allow-origin"),
        Some("http://127.0.0.1:5173")
    );
    assert_eq!(response_header(&denial, "vary"), Some("Origin"));
    let frame = denial
        .body
        .strip_prefix(b"data: ")
        .and_then(|body| body.strip_suffix(b"\n\n"))
        .expect("the streaming SDK receives one complete SSE frame");
    let body: Value = serde_json::from_slice(frame).expect("the SSE payload is JSON");
    assert_eq!(body["error"]["status"], "UNAUTHENTICATED");
    assert_eq!(body["error"]["message"], "Unauthenticated");
    assert!(
        body.get("headers").is_none(),
        "the runner was never reached: {body}"
    );
    h.stop().await;
}

#[tokio::test]
async fn a_first_generation_callable_with_a_stream_accept_header_keeps_the_json_denial() {
    let h = start(true).await;
    let denial = h
        .request("POST", "guarded", &[("accept", "text/event-stream")])
        .await;

    assert_eq!(denial.status, 401);
    assert_eq!(
        response_header(&denial, "content-type"),
        Some("application/json; charset=utf-8")
    );
    let body: Value = serde_json::from_slice(&denial.body).expect("the v1 denial remains JSON");
    assert_eq!(body["error"]["status"], "UNAUTHENTICATED");
    assert_eq!(body["error"]["message"], "Unauthenticated");
    h.stop().await;
}

#[tokio::test]
async fn an_unrenderable_connection_value_is_refused_before_a_named_header_reaches_the_runner() {
    let h = start(true).await;
    let response = h.request_with_an_unrenderable_connection_value().await;
    assert_eq!(response.status, 400);
    assert_eq!(response.body, b"invalid Connection header");
    h.stop().await;
}

#[tokio::test]
async fn a_callable_denial_drains_a_body_that_arrives_after_its_headers() {
    let h = start(true).await;
    let status = h
        .guarded_request_with_a_delayed_body()
        .await
        .expect("the client receives a complete denial without a connection reset");
    assert_eq!(status, 401);
    h.stop().await;
}

#[tokio::test]
async fn a_cloud_tasks_request_uses_the_official_express_json_limit() {
    let h = start(true).await;
    let tasks_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Tasks");
    let tasks_addr = tasks_listener.local_addr().expect("a local Tasks address");
    let tasks_server = tokio::spawn(fireemu_adapter_functions::http::serve_tasks(
        tasks_listener,
        h.runtime.clone(),
        fireemu_adapter_functions::http::HttpAdmission::new(),
    ));
    let mut boundary = br#"{"padding":""#.to_vec();
    boundary.extend(std::iter::repeat_n(
        b'x',
        fireemu_adapter_functions::http::MAX_TASK_BODY_BYTES - boundary.len() - 2,
    ));
    boundary.extend_from_slice(br#""}"#);
    assert_eq!(
        boundary.len(),
        fireemu_adapter_functions::http::MAX_TASK_BODY_BYTES
    );
    let tasks_path = "/projects/demo-app/locations/us-central1/queues/work/tasks";
    assert_eq!(h.post_raw_to(tasks_addr, tasks_path, &boundary).await, 404);

    let mut over = boundary.clone();
    over.push(b' ');
    let status = h.post_raw_to(tasks_addr, tasks_path, &over).await;
    assert_eq!(status, 413);
    assert_eq!(
        h.post_raw_to(h.addr, "/demo-app/us-central1/echo", &over)
            .await,
        200,
        "the Tasks JSON limit must not replace the Functions body limit"
    );
    tasks_server.abort();
    h.stop().await;
}

#[tokio::test]
async fn support_service_routes_are_isolated_from_the_functions_listener() {
    let h = start(true).await;
    let eventarc_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Eventarc");
    let eventarc_addr = eventarc_listener
        .local_addr()
        .expect("a local Eventarc address");
    let eventarc_server = tokio::spawn(fireemu_adapter_functions::http::serve_eventarc(
        eventarc_listener,
        h.runtime.clone(),
        fireemu_adapter_functions::http::HttpAdmission::new(),
    ));
    let tasks_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Tasks");
    let tasks_addr = tasks_listener.local_addr().expect("a local Tasks address");
    let tasks_server = tokio::spawn(fireemu_adapter_functions::http::serve_tasks(
        tasks_listener,
        h.runtime.clone(),
        fireemu_adapter_functions::http::HttpAdmission::new(),
    ));

    let functions_path = "/demo-app/us-central1/echo";
    let eventarc_path = "/google/publishEvents";
    let tasks_path = "/projects/demo-app/locations/us-central1/queues/taskA";
    assert_eq!(h.post_raw_to(h.addr, functions_path, b"{}").await, 200);
    assert_eq!(
        h.post_raw_to(eventarc_addr, eventarc_path, br#"{"events":[]}"#)
            .await,
        200
    );
    let tasks_response = h.raw_to_from(tasks_addr, tasks_path, b"{}", None).await;
    assert_eq!(tasks_response.status, 404);
    assert!(
        String::from_utf8_lossy(&tasks_response.body).contains("no onTaskDispatched function"),
        "the Tasks listener must produce its own resource error"
    );

    let foreign_body = vec![b'x'; fireemu_adapter_functions::http::MAX_TASK_BODY_BYTES + 1];
    for (surface, addr, paths) in [
        ("functions", h.addr, [eventarc_path, tasks_path]),
        ("eventarc", eventarc_addr, [functions_path, tasks_path]),
        ("tasks", tasks_addr, [functions_path, eventarc_path]),
    ] {
        for path in paths {
            assert_eq!(
                h.post_raw_to(addr, path, &foreign_body).await,
                404,
                "{surface} accepted the foreign route {path}"
            );
        }
    }
    for (surface, addr, path, body) in [
        (
            "eventarc",
            eventarc_addr,
            eventarc_path,
            br#"{"events":[]}"#.as_slice(),
        ),
        ("tasks", tasks_addr, tasks_path, b"{}".as_slice()),
    ] {
        let response = h
            .raw_to_from(addr, path, body, Some("https://attacker.example"))
            .await;
        assert_eq!(
            response.status, 403,
            "{surface} accepted a non-loopback browser origin"
        );
        assert_eq!(response.body, b"forbidden origin");
    }

    eventarc_server.abort();
    tasks_server.abort();
    h.stop().await;
}

#[tokio::test]
async fn an_enforced_callable_answers_a_genuine_local_preflight_without_admission_or_invocation() {
    let h = start(true).await;
    let response = h
        .request(
            "OPTIONS",
            "guarded",
            &[
                ("origin", "http://127.0.0.1:5173"),
                ("access-control-request-method", "POST"),
                (
                    "access-control-request-headers",
                    "authorization,content-type,x-firebase-appcheck",
                ),
                ("sec-fetch-site", "same-site"),
                ("sec-fetch-mode", "cors"),
            ],
        )
        .await;
    assert_eq!(response.status, 204);
    assert_eq!(
        response_header(&response, "access-control-allow-origin"),
        Some("http://127.0.0.1:5173")
    );
    assert_eq!(
        response_header(&response, "access-control-allow-methods"),
        Some("POST")
    );
    assert_eq!(
        response_header(&response, "access-control-allow-headers"),
        Some("authorization,content-type,x-firebase-appcheck")
    );
    assert_eq!(
        response_header(&response, "vary"),
        Some("Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Sec-Fetch-Site, Sec-Fetch-Mode")
    );
    assert!(response.body.is_empty());
    assert!(
        h.gate
            .registry()
            .read()
            .unwrap()
            .observations(PROJECT)
            .is_empty(),
        "a preflight is not an App Check admission"
    );

    let token = h.token();
    let (_, bearer) = h.user("preflight@example.com");
    let (status, body) = h
        .call(
            "guarded",
            &[
                ("origin", "http://127.0.0.1:5173"),
                ("authorization", &bearer),
                ("x-firebase-appcheck", &token),
            ],
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(echoed(&body, "authorization"), vec![bearer]);
    assert_eq!(echoed(&body, "x-firebase-appcheck"), vec![token]);
    h.stop().await;
}

#[tokio::test]
async fn callable_preflight_rejects_nonlocal_or_malformed_browser_requests() {
    let h = start(true).await;
    for headers in [
        vec![("access-control-request-method", "POST")],
        vec![("origin", "http://localhost:5173")],
        vec![
            ("origin", "https://attacker.example"),
            ("access-control-request-method", "POST"),
        ],
        vec![
            ("origin", "null"),
            ("access-control-request-method", "POST"),
        ],
        vec![
            ("origin", "http://localhost:5173"),
            ("access-control-request-method", "PUT"),
        ],
        vec![
            ("origin", "http://localhost:5173"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", "x-fireemu-runner-secret"),
        ],
        vec![
            ("origin", "http://localhost:5173"),
            ("access-control-request-method", "POST"),
            ("sec-fetch-site", "cross-site"),
        ],
        vec![
            ("origin", "http://localhost:5173"),
            ("access-control-request-method", "POST"),
            ("sec-fetch-mode", "navigate"),
        ],
        vec![
            ("origin", "http://localhost:5173"),
            ("access-control-request-method", "POST"),
            ("access-control-request-method", "POST"),
        ],
        vec![
            ("origin", "http://localhost:5173"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", "content-type"),
            ("access-control-request-headers", "authorization"),
        ],
        vec![
            ("origin", "http://localhost:5173"),
            ("origin", "http://127.0.0.1:5173"),
            ("access-control-request-method", "POST"),
        ],
    ] {
        let response = h.request("OPTIONS", "guarded", &headers).await;
        assert_ne!(response.status, 204, "{headers:?}");
        assert!(
            response_header(&response, "access-control-allow-origin").is_none(),
            "a refused preflight has no CORS grant: {headers:?}"
        );
    }
    assert!(h
        .gate
        .registry()
        .read()
        .unwrap()
        .observations(PROJECT)
        .is_empty());
    h.stop().await;
}

// ------------------------------------------------------------------------------------------
// Scenario 2: an invalid callable token is removed before runner-side unsafe decoding
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_invalid_callable_token_is_removed_before_runner_side_unsafe_decoding() {
    let h = start(true).await;
    for invalid in [
        "not-a-jwt".to_owned(),
        h.other_app_token(),
        format!("{}x", h.token()),
    ] {
        let (status, body) = h.call("add", &[("x-firebase-appcheck", &invalid)]).await;
        assert_eq!(status, 200, "an unenforced callable still runs: {body}");
        assert!(
            echoed(&body, "x-firebase-appcheck").is_empty(),
            "the runner must never see {invalid}: {body}"
        );
    }
    h.stop().await;
}

// ------------------------------------------------------------------------------------------
// Scenario 3 / 4: a valid callable forwards the token; an unenforced one runs without it
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_valid_callable_token_is_forwarded_byte_for_byte_exactly_once() {
    let h = start(true).await;
    let token = h.token();
    let (status, body) = h.call("add", &[("x-firebase-appcheck", &token)]).await;
    assert_eq!(status, 200);
    assert_eq!(
        echoed(&body, "x-firebase-appcheck"),
        vec![token],
        "byte for byte, exactly one field"
    );
    h.stop().await;
}

#[tokio::test]
async fn an_unenforced_callable_runs_with_no_app_check_field_at_all() {
    let h = start(true).await;
    let (status, body) = h.call("add", &[]).await;
    assert_eq!(status, 200);
    assert!(echoed(&body, "x-firebase-appcheck").is_empty());
    h.stop().await;
}

// ------------------------------------------------------------------------------------------
// Scenario 5: onRequest receives the original field without automatic enforcement
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn on_request_receives_the_original_app_check_field_without_classification() {
    let h = start(true).await;
    // Two instances and an unverifiable value: an `onRequest` function owns its own
    // verification, so the proxy classifies nothing and selects nothing.
    let (status, body) = h
        .call(
            "echo",
            &[
                ("x-firebase-appcheck", "first"),
                ("x-firebase-appcheck", "second"),
            ],
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        echoed(&body, "x-firebase-appcheck"),
        vec!["first".to_owned(), "second".to_owned()],
        "the raw field list is forwarded unchanged: {body}"
    );
    h.stop().await;
}

// ------------------------------------------------------------------------------------------
// Scenarios 7 and 9: callable Auth integrity (`INV-APPCHECK-010`)
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_forged_auth_token_never_reaches_a_callable() {
    let h = start(true).await;
    let token = h.token();
    for forged in [
        "Bearer not-a-jwt",
        "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInVzZXJfaWQiOiJhZG1pbiJ9.",
        "Basic dXNlcjpwYXNz",
    ] {
        let (status, body) = h
            .call(
                "add",
                &[("x-firebase-appcheck", &token), ("authorization", forged)],
            )
            .await;
        assert_eq!(status, 200);
        assert!(
            echoed(&body, "authorization").is_empty(),
            "{forged} must not reach the runner: {body}"
        );
    }
    h.stop().await;
}

#[tokio::test]
async fn bearer_owner_never_reaches_a_callable() {
    let h = start(true).await;
    let (status, body) = h.call("add", &[("authorization", "Bearer owner")]).await;
    assert_eq!(status, 200);
    assert!(
        echoed(&body, "authorization").is_empty(),
        "the emulator's admin credential is not a callable user identity: {body}"
    );
    h.stop().await;
}

#[tokio::test]
async fn a_verified_id_token_is_reinserted_exactly_once() {
    let h = start(true).await;
    let (_, bearer) = h.user("ada@example.com");
    let (status, body) = h.call("add", &[("authorization", &bearer)]).await;
    assert_eq!(status, 200);
    assert_eq!(echoed(&body, "authorization"), vec![bearer]);
    h.stop().await;
}

#[tokio::test]
async fn duplicate_authorization_fields_are_invalid_and_none_survives() {
    let h = start(true).await;
    let (_, bearer) = h.user("ada@example.com");
    let (status, body) = h
        .call(
            "add",
            &[("authorization", &bearer), ("authorization", &bearer)],
        )
        .await;
    assert_eq!(status, 200);
    assert!(
        echoed(&body, "authorization").is_empty(),
        "an ambiguous credential is no credential: {body}"
    );
    h.stop().await;
}

// ------------------------------------------------------------------------------------------
// Scenario 8: mixed-case duplicate App Check fields never reach runner-side decoding
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn mixed_case_duplicate_app_check_fields_never_reach_runner_side_decoding() {
    let h = start(true).await;
    let token = h.token();
    let (status, body) = h
        .call(
            "add",
            &[
                ("X-Firebase-AppCheck", &token),
                ("x-firebase-appcheck", &token),
            ],
        )
        .await;
    assert_eq!(status, 200);
    assert!(
        echoed(&body, "x-firebase-appcheck").is_empty(),
        "two instances are ambiguous, not a value to choose: {body}"
    );

    // The same request against the enforcing callable is refused outright.
    let (status, _) = h
        .call(
            "guarded",
            &[
                ("X-Firebase-AppCheck", &token),
                ("x-firebase-appcheck", &token),
            ],
        )
        .await;
    assert_eq!(status, 401);
    h.stop().await;
}

#[tokio::test]
async fn a_comma_folded_app_check_field_is_never_split() {
    let h = start(true).await;
    let token = h.token();
    let folded = format!("{token},{token}");
    let (status, body) = h.call("add", &[("x-firebase-appcheck", &folded)]).await;
    assert_eq!(status, 200);
    assert!(echoed(&body, "x-firebase-appcheck").is_empty(), "{body}");
    h.stop().await;
}

// ------------------------------------------------------------------------------------------
// The runner secret and the emulator-internal auth override channels
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn caller_supplied_trusted_fields_never_pass_through() {
    let h = start(true).await;
    let (status, body) = h
        .call(
            "add",
            &[
                ("x-fireemu-runner-secret", "guessed"),
                ("x-callable-context-auth", "%7B%22uid%22%3A%22admin%22%7D"),
                ("x-original-auth", "Bearer forged"),
            ],
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(
        echoed(&body, "x-fireemu-runner-secret"),
        vec!["runner-secret".to_owned()],
        "exactly the daemon's own secret, and only it"
    );
    assert!(
        echoed(&body, "x-callable-context-auth").is_empty(),
        "{body}"
    );
    assert!(echoed(&body, "x-original-auth").is_empty(), "{body}");

    // The same fields are stripped from an `onRequest` function too: they are emulator
    // channels, not application input.
    let (_, body) = h
        .call("echo", &[("x-callable-context-auth", "%7B%7D")])
        .await;
    assert!(
        echoed(&body, "x-callable-context-auth").is_empty(),
        "{body}"
    );
    h.stop().await;
}

// ------------------------------------------------------------------------------------------
// Inactive protocol: nothing changes for a daemon without App Check
// ------------------------------------------------------------------------------------------

#[tokio::test]
async fn without_the_trusted_protocol_a_callable_receives_what_it_always_did() {
    let h = start(false).await;
    let (status, body) = h
        .call(
            "guarded",
            &[
                ("x-firebase-appcheck", "whatever"),
                ("authorization", "Bearer owner"),
            ],
        )
        .await;
    assert_eq!(status, 200, "no daemon-side enforcement without App Check");
    assert_eq!(
        echoed(&body, "x-firebase-appcheck"),
        vec!["whatever".to_owned()]
    );
    assert_eq!(
        echoed(&body, "authorization"),
        vec!["Bearer owner".to_owned()]
    );
    h.stop().await;
}
