//! `storage.cors`: a bucket's CORS configuration decides which cross-origin requests the
//! strict profile lets a browser read, on the JSON API, the XML API and the Firebase API's media
//! reads, as Cloud Storage does. A bucket with no configuration keeps the permissive answer.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fireemu_adapter_http::storage::{StorageRulesRegistry, StorageState};
use fireemu_adapter_http::storage_cors::BucketCors;
use fireemu_adapter_http::storage_server::{serve_storage_with_budget, BodyBudget};
use fireemu_core_auth::jwt::TokenAcceptance;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::StorageState as ObjectStore;
use fireemu_core_storage::store::{NewMetadata, Precondition};
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};
use std::fmt::Write as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
const CONFIGURED: &str = "demo-app.appspot.com";
const OPEN: &str = "demo-app.firebasestorage.app";
const ORIGIN: &str = "http://localhost:3000";
const ALLOW_ALL_RULES: &str = "rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read, write: if true; } } }";

fn state(acceptance: TokenAcceptance) -> StorageState {
    StorageState {
        store: Mutex::new(ObjectStore::new(9)),
        clock: Arc::new(Mutex::new(VirtualClock::new(START))),
        auth: Arc::new(fireemu_core_auth::store::AuthRegistry::new(
            "demo-app",
            Arc::new(Mutex::new(AuthStore::new(
                "demo-app",
                SplitMix64::new(3),
                TotpPolicy::default(),
            ))),
        )),
        tenancy: None,
        rules: Arc::new(StorageRulesRegistry::global(Arc::new(RulesetSlot::new(
            LoadedRules::from_source(ALLOW_ALL_RULES).unwrap(),
        )))),
        project: "demo-app".to_owned(),
        events: None,
        barrier: None,
        firestore: None,
        faults: None,
        clock_observer: None,
        app_check_policy: None,
        admin_capability: None,
        server_requests: fireemu_adapter_http::storage::StorageServerRequests::default(),
        token_acceptance: acceptance,
        allow_unsigned_id_tokens: acceptance == TokenAcceptance::EmulatorMock,
        control_token: Some("storage-test-control-token".to_owned()),
    }
}

fn seed(s: &StorageState, bucket: &str) {
    s.store
        .lock()
        .unwrap()
        .put(
            &BucketName::try_new(bucket).unwrap(),
            &ObjectName::try_new("a.txt").unwrap(),
            b"hello".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            START,
        )
        .unwrap();
}

fn configured(acceptance: TokenAcceptance, cors: &Value) -> StorageState {
    let s = state(acceptance);
    seed(&s, CONFIGURED);
    seed(&s, OPEN);
    s.rules.set_bucket_cors(BTreeMap::from([(
        CONFIGURED.to_owned(),
        BucketCors::from_json(cors).unwrap(),
    )]));
    s
}

struct Answer {
    status: u16,
    headers: Vec<(String, String)>,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn cors_names(&self) -> Vec<&str> {
        self.headers
            .iter()
            .map(|(n, _)| n.as_str())
            .filter(|n| n.to_ascii_lowercase().starts_with("access-control-"))
            .collect()
    }
}

static BUDGET: BodyBudget = BodyBudget::new(8 * 1024 * 1024);

/// Serves `state` on a loopback port for one test.
async fn serve(state: StorageState) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let _ = serve_storage_with_budget(listener, Arc::new(state), &BUDGET).await;
    });
    (addr, task)
}

async fn send(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
) -> Answer {
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n",
        addr.port()
    );
    // The emulator's owner credential, so the object reads are not the anonymous XML refusal.
    head.push_str("Authorization: Bearer owner\r\n");
    for (name, value) in extra {
        write!(head, "{name}: {value}\r\n").unwrap();
    }
    head.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        stream.read_to_end(&mut raw),
    )
    .await
    .expect("no answer within 20 s")
    .unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, _) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
        .collect();
    Answer { status, headers }
}

fn rule() -> Value {
    json!([{
        "origin": [ORIGIN],
        "method": ["GET", "PUT"],
        "responseHeader": ["Content-Type", "x-goog-content-length-range"],
        "maxAgeSeconds": 600,
    }])
}

/// The three object routes a browser reads or writes: the JSON API media read, the XML API's
/// object read and the Firebase API's media read.
fn reads(bucket: &str) -> [String; 3] {
    [
        format!("/storage/v1/b/{bucket}/o/a.txt?alt=media"),
        format!("/{bucket}/a.txt"),
        format!("/v0/b/{bucket}/o/a.txt?alt=media"),
    ]
}

#[tokio::test]
async fn a_configured_bucket_answers_a_matching_preflight_with_its_rule() {
    let (addr, task) = serve(configured(TokenAcceptance::Verified, &rule())).await;
    let mut paths = reads(CONFIGURED).to_vec();
    paths.push(format!(
        "/upload/storage/v1/b/{CONFIGURED}/o?uploadType=media&name=u.txt"
    ));
    paths.push(format!("/{CONFIGURED}"));
    for path in paths {
        let answer = send(
            addr,
            "OPTIONS",
            &path,
            &[
                ("Origin", ORIGIN),
                ("Access-Control-Request-Method", "PUT"),
                (
                    "Access-Control-Request-Headers",
                    "content-type, x-goog-content-length-range",
                ),
            ],
        )
        .await;
        assert_eq!(answer.status, 200, "{path}");
        assert_eq!(
            answer.header("access-control-allow-origin"),
            Some(ORIGIN),
            "{path}"
        );
        assert_eq!(
            answer.header("access-control-allow-methods"),
            Some("PUT"),
            "{path}"
        );
        assert_eq!(
            answer.header("access-control-allow-headers"),
            Some("content-type, x-goog-content-length-range"),
            "{path}"
        );
        assert_eq!(
            answer.header("access-control-max-age"),
            Some("600"),
            "{path}"
        );
    }
    task.abort();
}

#[tokio::test]
async fn a_preflight_no_rule_matches_is_answered_200_without_any_cors_header() {
    // RECORDED on a bucket with no CORS configuration (storage-signed-put): 200, no
    // access-control header. UNRECORDED for a configured bucket the rule does not match.
    let (addr, task) = serve(configured(TokenAcceptance::Verified, &rule())).await;
    let cases: [(&str, &str, &str); 3] = [
        ("http://localhost:3001", "PUT", "content-type"),
        (ORIGIN, "DELETE", "content-type"),
        (ORIGIN, "PUT", "authorization"),
    ];
    for (origin, method, headers) in cases {
        let answer = send(
            addr,
            "OPTIONS",
            &format!("/{CONFIGURED}/a.txt"),
            &[
                ("Origin", origin),
                ("Access-Control-Request-Method", method),
                ("Access-Control-Request-Headers", headers),
            ],
        )
        .await;
        assert_eq!(answer.status, 200, "{origin} {method} {headers}");
        assert_eq!(
            answer.cors_names(),
            Vec::<&str>::new(),
            "{origin} {method} {headers}"
        );
    }
    task.abort();
}

#[tokio::test]
async fn actual_reads_carry_the_rule_headers_only_for_a_matching_origin_and_method() {
    let (addr, task) = serve(configured(TokenAcceptance::Verified, &rule())).await;
    for path in reads(CONFIGURED) {
        let hit = send(addr, "GET", &path, &[("Origin", ORIGIN)]).await;
        assert_eq!(hit.status, 200, "{path}");
        assert_eq!(
            hit.header("access-control-allow-origin"),
            Some(ORIGIN),
            "{path}"
        );
        assert_eq!(
            hit.header("access-control-expose-headers"),
            Some("Content-Type,x-goog-content-length-range"),
            "{path}"
        );
        let other = send(addr, "GET", &path, &[("Origin", "http://localhost:3001")]).await;
        assert_eq!(other.status, 200, "{path}: the request still succeeds");
        assert_eq!(other.cors_names(), Vec::<&str>::new(), "{path}");
        let none = send(addr, "GET", &path, &[]).await;
        assert_eq!(none.status, 200, "{path}");
        assert_eq!(
            none.cors_names(),
            Vec::<&str>::new(),
            "{path}: no Origin, no CORS headers"
        );
    }
    task.abort();
}

#[tokio::test]
async fn an_empty_configuration_is_a_bucket_with_no_cors_at_all() {
    let (addr, task) = serve(configured(TokenAcceptance::Verified, &json!([]))).await;
    for path in reads(CONFIGURED) {
        let answer = send(addr, "GET", &path, &[("Origin", ORIGIN)]).await;
        assert_eq!(answer.status, 200, "{path}");
        assert_eq!(answer.cors_names(), Vec::<&str>::new(), "{path}");
        let preflight = send(
            addr,
            "OPTIONS",
            &path,
            &[("Origin", ORIGIN), ("Access-Control-Request-Method", "GET")],
        )
        .await;
        assert_eq!(preflight.status, 200, "{path}");
        assert_eq!(preflight.cors_names(), Vec::<&str>::new(), "{path}");
    }
    task.abort();
}

#[tokio::test]
async fn a_bucket_without_a_configuration_keeps_the_permissive_answer() {
    let (addr, task) = serve(configured(TokenAcceptance::Verified, &rule())).await;
    for path in reads(OPEN) {
        let answer = send(addr, "GET", &path, &[("Origin", ORIGIN)]).await;
        assert_eq!(answer.status, 200, "{path}");
        assert_eq!(
            answer.header("access-control-allow-origin"),
            Some(ORIGIN),
            "{path}"
        );
    }
    let preflight = send(
        addr,
        "OPTIONS",
        &format!("/{OPEN}/a.txt"),
        &[("Origin", ORIGIN), ("Access-Control-Request-Method", "PUT")],
    )
    .await;
    assert_eq!(preflight.status, 204);
    assert_eq!(
        preflight.header("access-control-allow-origin"),
        Some(ORIGIN)
    );
    task.abort();
}

#[tokio::test]
async fn the_emulator_profile_ignores_the_configuration() {
    let (addr, task) = serve(configured(TokenAcceptance::EmulatorMock, &json!([]))).await;
    let answer = send(
        addr,
        "GET",
        &format!("/{CONFIGURED}/a.txt"),
        &[("Origin", ORIGIN)],
    )
    .await;
    assert_eq!(answer.header("access-control-allow-origin"), Some(ORIGIN));
    task.abort();
}

#[tokio::test]
async fn the_firebase_api_metadata_answers_keep_the_firebase_api_own_cors() {
    // The Firebase API (`/v0`) answers JSON metadata with its own CORS (recorded `*` without an
    // Origin); only its media reads follow the bucket's configuration.
    let (addr, task) = serve(configured(TokenAcceptance::Verified, &json!([]))).await;
    let answer = send(
        addr,
        "GET",
        &format!("/v0/b/{CONFIGURED}/o/a.txt"),
        &[("Origin", ORIGIN)],
    )
    .await;
    assert_eq!(answer.status, 200);
    assert!(
        answer.header("access-control-allow-origin").is_some(),
        "{:?}",
        answer.headers
    );
    task.abort();
}

#[tokio::test]
async fn a_non_local_origin_is_still_refused_whatever_the_rule_lists() {
    let wide = json!([{"origin": ["*"], "method": ["*"]}]);
    let (addr, task) = serve(configured(TokenAcceptance::Verified, &wide)).await;
    let answer = send(
        addr,
        "GET",
        &format!("/{CONFIGURED}/a.txt"),
        &[("Origin", "https://evil.example")],
    )
    .await;
    assert_eq!(answer.status, 403);
    task.abort();
}
