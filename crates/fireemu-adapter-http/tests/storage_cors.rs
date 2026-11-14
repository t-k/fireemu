//! `storage.cors`: a bucket's CORS configuration decides which cross-origin requests the
//! strict profile lets a browser read on the XML API and Firebase media reads. The JSON API has its own CORS policy. Unlisted XML buckets are permissive unless configured otherwise.

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
const OTHER_ORIGIN: &str = "http://localhost:4000";
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
    body: Vec<u8>,
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
    if !extra
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
    {
        head.push_str("Authorization: Bearer owner\r\n");
    }
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
    let boundary = raw
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap();
    let head = std::str::from_utf8(&raw[..boundary]).unwrap();
    let body = raw[boundary + 4..].to_vec();
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
    Answer {
        status,
        headers,
        body,
    }
}

fn rule() -> Value {
    json!([{
        "origin": [ORIGIN],
        "method": ["GET", "PUT"],
        "responseHeader": ["Content-Type", "x-goog-content-length-range"],
        "maxAgeSeconds": 600,
    }])
}

/// The object routes governed by the bucket configuration: XML and Firebase media reads.
fn reads(bucket: &str) -> [String; 2] {
    [
        format!("/{bucket}/a.txt"),
        format!("/v0/b/{bucket}/o/a.txt?alt=media"),
    ]
}

#[tokio::test]
async fn a_configured_bucket_answers_a_matching_preflight_with_its_rule() {
    // UNRECORDED assumption for two named XML headers: configured spelling and order, joined with commas without spaces; C2 recorded only Content-Type.
    let (addr, task) = serve(configured(TokenAcceptance::Verified, &rule())).await;
    let mut paths = reads(CONFIGURED).to_vec();
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
            Some(if path.starts_with("/v0/") {
                "PUT"
            } else {
                "GET,PUT"
            }),
            "{path}"
        );
        assert_eq!(
            answer.header("access-control-allow-headers"),
            Some(if path.starts_with("/v0/") {
                "content-type, x-goog-content-length-range"
            } else {
                "Content-Type,x-goog-content-length-range"
            }),
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
    // access-control header. RECORDED (STORAGE-STRICTNESS-OBS run ss-48adbd8e, case C3): a configured bucket with no matching method also answers 200.
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
async fn encoded_firebase_media_queries_use_bucket_cors() {
    let state = configured(TokenAcceptance::Verified, &json!([]));
    state.rules.set_unlisted_buckets_cors_none(true);
    let (addr, task) = serve(state).await;
    for bucket in [CONFIGURED, OPEN] {
        for query in ["alt=%6Dedia", "%61lt=media", "alt=other&alt=media"] {
            let path = format!("/v0/b/{bucket}/o/a.txt?{query}");
            let answer = send(addr, "GET", &path, &[("Origin", ORIGIN)]).await;
            assert_eq!(answer.status, 200, "{path}");
            assert!(answer.cors_names().is_empty(), "{path}");
        }
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
async fn unlisted_bucket_cors_can_default_to_none() {
    let state = configured(TokenAcceptance::Verified, &rule());
    state.rules.set_unlisted_buckets_cors_none(true);
    state.rules.set_bucket_cors(BTreeMap::from([
        (
            CONFIGURED.to_owned(),
            BucketCors::from_json(&rule()).unwrap(),
        ),
        ("empty-bucket".to_owned(), BucketCors::default()),
    ]));
    seed(&state, "empty-bucket");
    let (addr, task) = serve(state).await;
    for bucket in [OPEN, "empty-bucket", CONFIGURED] {
        for path in reads(bucket) {
            let answer = send(addr, "GET", &path, &[("Origin", ORIGIN)]).await;
            assert_eq!(answer.status, 200, "{path}");
            let preflight = send(
                addr,
                "OPTIONS",
                &path,
                &[("Origin", ORIGIN), ("Access-Control-Request-Method", "GET")],
            )
            .await;
            assert_eq!(preflight.status, 200, "{path}");
            if bucket == CONFIGURED {
                assert_eq!(
                    answer.header("access-control-allow-origin"),
                    Some(ORIGIN),
                    "{path}"
                );
                assert_eq!(
                    preflight.header("access-control-allow-origin"),
                    Some(ORIGIN),
                    "{path}"
                );
            } else {
                assert!(answer.cors_names().is_empty(), "{path}");
                assert!(preflight.cors_names().is_empty(), "{path}");
            }
        }
    }
    task.abort();
}

#[tokio::test]
async fn emulator_ignores_unlisted_bucket_cors_default() {
    let state = configured(TokenAcceptance::EmulatorMock, &rule());
    state.rules.set_unlisted_buckets_cors_none(true);
    let (addr, task) = serve(state).await;
    for path in reads(OPEN) {
        let answer = send(addr, "GET", &path, &[("Origin", ORIGIN)]).await;
        assert_eq!(
            answer.header("access-control-allow-origin"),
            Some(ORIGIN),
            "{path}"
        );
        let preflight = send(
            addr,
            "OPTIONS",
            &path,
            &[("Origin", ORIGIN), ("Access-Control-Request-Method", "GET")],
        )
        .await;
        assert_eq!(preflight.status, 204, "{path}");
        assert_eq!(
            preflight.header("access-control-allow-origin"),
            Some(ORIGIN),
            "{path}"
        );
    }
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
    for path in [
        format!("/{CONFIGURED}/a.txt"),
        format!("/storage/v1/b/{CONFIGURED}/o/a.txt"),
    ] {
        for method in ["GET", "OPTIONS"] {
            let answer = send(addr, method, &path, &[("Origin", "https://evil.example")]).await;
            assert_eq!(answer.status, 403, "{method} {path}");
            assert!(answer.cors_names().is_empty());
        }
    }
    task.abort();
}

// Firebase and XML routes keep their existing behavior; JSON API CORS is covered independently below.
#[tokio::test]
async fn absent_and_empty_cors_keep_base_behavior_for_xml_and_firebase() {
    for production_exact in [false, true] {
        for empty_entry in [false, true] {
            let s = state(TokenAcceptance::Verified);
            seed(&s, CONFIGURED);
            s.rules.set_unlisted_buckets_cors_none(production_exact);
            if empty_entry {
                s.rules.set_bucket_cors(BTreeMap::from([(
                    CONFIGURED.to_owned(),
                    BucketCors::default(),
                )]));
            }
            let (addr, task) = serve(s).await;
            for path in [
                format!("/{CONFIGURED}/a.txt"),
                format!("/v0/b/{CONFIGURED}/o/a.txt?alt=media"),
                format!("/v0/b/{CONFIGURED}/o/a.txt"),
            ] {
                let firebase_metadata = path.starts_with("/v0/") && !path.contains("alt=media");
                let no_cors = !firebase_metadata && (empty_entry || production_exact);
                for method in ["GET", "OPTIONS"] {
                    let answer = send(
                        addr,
                        method,
                        &path,
                        &[("Origin", ORIGIN), ("Access-Control-Request-Method", "GET")],
                    )
                    .await;
                    assert_eq!(
                        answer.status,
                        if method == "OPTIONS" && !no_cors {
                            204
                        } else {
                            200
                        },
                        "{path}: {method}, empty {empty_entry}, productionExact {production_exact}"
                    );
                    if no_cors {
                        assert!(answer.cors_names().is_empty(), "{path}: {method}, empty {empty_entry}, productionExact {production_exact}");
                    } else {
                        assert_eq!(
                            answer.header("access-control-allow-origin"),
                            Some(ORIGIN),
                            "{path}: {method}"
                        );
                        assert_eq!(
                            answer.header("access-control-allow-credentials"),
                            None,
                            "{path}: {method}"
                        );
                        assert_eq!(answer.header("access-control-expose-headers"), Some("content-type,x-firebase-storage-version,X-Goog-Upload-Size-Received,x-goog-upload-url,x-goog-upload-command,x-gupload-uploadid,x-goog-upload-header-content-length,x-goog-upload-header-content-type,x-goog-upload-protocol,x-goog-upload-status,x-goog-upload-chunk-granularity,x-goog-upload-control-url"), "{path}: {method}");
                        if method == "OPTIONS" {
                            assert_eq!(
                                answer.header("access-control-allow-methods"),
                                Some("GET,HEAD,PUT,PATCH,POST,DELETE")
                            );
                            assert_eq!(answer.header("access-control-max-age"), None);
                            assert_eq!(
                                answer.header("vary"),
                                Some("Origin, Access-Control-Request-Headers")
                            );
                        }
                    }
                }
            }
            task.abort();
            let _ = task.await;
        }
    }
}

#[tokio::test]
async fn json_api_routes_use_api_cors_and_keep_non_cors_framing() {
    for production_exact in [false, true] {
        let s = configured(TokenAcceptance::Verified, &rule());
        s.rules.set_unlisted_buckets_cors_none(production_exact);
        let (addr, task) = serve(s).await;
        for (method, path) in [
            ("GET", format!("/storage/v1/b/{CONFIGURED}")),
            ("GET", format!("/b/{CONFIGURED}")),
            ("GET", "/b".to_owned()),
            ("POST", format!("/storage/v1/b/{CONFIGURED}/o/a.txt/acl")),
            (
                "DELETE",
                format!("/storage/v1/b/{CONFIGURED}/o/a.txt/acl/allUsers"),
            ),
        ] {
            let bare = send(addr, method, &path, &[]).await;
            let browser = send(addr, method, &path, &[("Origin", ORIGIN)]).await;
            assert_eq!(browser.status, bare.status, "{method} {path}");
            assert_eq!(browser.body, bare.body, "{method} {path}: JSON bytes");
            let mut bare_headers = bare.headers.clone();
            let mut browser_headers = browser.headers.clone();
            for headers in [&mut bare_headers, &mut browser_headers] {
                headers.retain(|(name, _)| {
                    !name.starts_with("access-control-") && name != "vary" && name != "date"
                });
                headers.sort();
            }
            assert_eq!(
                browser_headers, bare_headers,
                "{method} {path}: non-CORS framing"
            );
            // Bucket, list and ACL routes use the JSON API policy even when their exact CORS
            // response shape was not part of the object-read recording.
            assert_eq!(
                browser.header("access-control-allow-credentials"),
                Some("true"),
                "{method} {path}: JSON API default"
            );
        }
        task.abort();
        let _ = task.await;
    }
}

#[tokio::test]
async fn json_api_cors_is_independent_of_bucket_configuration() {
    // Generated by PICT with cors.tsv's five axes. XML rows are included so the same input
    // combinations prove that the bucket policy remains scoped to the XML API.
    const CASES: &str = "\
apiFamily bucketConfig requestMode requestOrigin productionExact
json omitted normal matching false
json empty normal matching false
json empty preflight matching false
json omitted normal matching true
json omitted preflight matching true
json rule normal nonMatching true
json rule preflight nonMatching true
json rule normal matching true
json rule preflight matching true
xml empty normal matching false
xml empty preflight matching false
xml omitted normal matching true
xml omitted preflight matching true
xml rule normal nonMatching true
xml rule preflight nonMatching true
xml rule normal matching true
xml rule preflight matching true
xml empty normal nonMatching false
xml rule preflight nonMatching false
xml empty normal nonMatching true
json omitted normal nonMatching false
";
    for line in CASES.lines().skip(1).filter(|line| !line.is_empty()) {
        let [family, config, mode, relation, production_exact] =
            line.split_whitespace().collect::<Vec<_>>()[..]
        else {
            panic!("invalid generated PICT row: {line}");
        };
        let s = state(TokenAcceptance::Verified);
        seed(&s, CONFIGURED);
        s.rules
            .set_unlisted_buckets_cors_none(production_exact == "true");
        match config {
            "empty" => s.rules.set_bucket_cors(BTreeMap::from([(
                CONFIGURED.to_owned(),
                BucketCors::default(),
            )])),
            "rule" => s.rules.set_bucket_cors(BTreeMap::from([(
                CONFIGURED.to_owned(),
                BucketCors::from_json(&rule()).unwrap(),
            )])),
            "omitted" => {}
            _ => panic!("invalid bucket config in PICT row: {line}"),
        }
        let origin = if relation == "matching" {
            ORIGIN
        } else {
            OTHER_ORIGIN
        };
        let path = if family == "json" {
            format!("/storage/v1/b/{CONFIGURED}/o/a.txt?alt=media")
        } else {
            format!("/{CONFIGURED}/a.txt")
        };
        let (addr, task) = serve(s).await;
        let method = if mode == "normal" { "GET" } else { "OPTIONS" };
        let answer = send(
            addr,
            method,
            &path,
            &[
                ("Origin", origin),
                ("Access-Control-Request-Method", "GET"),
                (
                    "Access-Control-Request-Headers",
                    "x-goog-content-length-range",
                ),
            ],
        )
        .await;
        assert_eq!(answer.status, 200, "{line}");
        if family == "json" {
            assert_eq!(
                answer.header("access-control-allow-origin"),
                Some(origin),
                "{line}"
            );
            assert_eq!(
                answer.header("access-control-allow-credentials"),
                Some("true"),
                "{line}"
            );
            assert_eq!(answer.header("vary"), Some("Origin, X-Origin"), "{line}");
            if mode == "preflight" {
                assert_eq!(
                    answer.header("access-control-allow-methods"),
                    Some("DELETE,GET,HEAD,PATCH,POST,PUT"),
                    "{line}"
                );
                assert_eq!(
                    answer.header("access-control-allow-headers"),
                    Some("x-goog-content-length-range"),
                    "{line}"
                );
                assert_eq!(
                    answer.header("access-control-max-age"),
                    Some("3600"),
                    "{line}"
                );
            }
        } else {
            let should_match = match config {
                "rule" => relation == "matching",
                "empty" => false,
                "omitted" => production_exact != "true",
                _ => unreachable!(),
            };
            assert_eq!(
                answer.header("access-control-allow-origin"),
                should_match.then_some(origin),
                "{line}"
            );
            assert_eq!(
                answer.header("access-control-allow-credentials"),
                None,
                "{line}"
            );
        }
        task.abort();
        let _ = task.await;
    }

    let s = state(TokenAcceptance::Verified);
    seed(&s, CONFIGURED);
    s.rules.set_bucket_cors(BTreeMap::from([(
        CONFIGURED.to_owned(),
        BucketCors::from_json(&rule()).unwrap(),
    )]));
    let (addr, task) = serve(s).await;
    let upload_preflight = send(
        addr,
        "OPTIONS",
        &format!("/upload/storage/v1/b/{CONFIGURED}/o?uploadType=media&name=upload.txt"),
        &[
            ("Origin", OTHER_ORIGIN),
            ("Access-Control-Request-Method", "POST"),
            ("Access-Control-Request-Headers", "content-type"),
        ],
    )
    .await;
    assert_eq!(upload_preflight.status, 200);
    assert_eq!(
        upload_preflight.header("access-control-allow-origin"),
        Some(OTHER_ORIGIN)
    );
    assert_eq!(
        upload_preflight.header("access-control-allow-methods"),
        Some("DELETE,GET,HEAD,PATCH,POST,PUT")
    );
    let upload = send(
        addr,
        "POST",
        &format!("/upload/storage/v1/b/{CONFIGURED}/o?uploadType=media&name=upload.txt"),
        &[("Origin", OTHER_ORIGIN), ("Content-Type", "text/plain")],
    )
    .await;
    assert_eq!(
        upload.header("access-control-allow-origin"),
        Some(OTHER_ORIGIN)
    );
    assert!(upload
        .header("access-control-expose-headers")
        .is_some_and(|headers| headers.contains("x-goog-upload-url")));
    task.abort();
    let _ = task.await;
}

/// The fixture omits successful metadata bodies; only recorded bodies and stable headers are compared byte for byte.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn strict_storage_answers_match_the_production_recording() {
    let recording: Value = serde_json::from_str(include_str!(
        "../../../conformance/storage-strictness-obs/recordings/run-1.json"
    ))
    .unwrap();
    for row in recording["rows"].as_array().unwrap() {
        let case = row["case"].as_str().unwrap();
        if case == "K1" {
            continue;
        }
        // The recorded bucket has nonempty rules except R3. productionExact must not alter these XML, Firebase or JSON API answers.
        for production_exact in [false, true] {
            let mut s = state(TokenAcceptance::Verified);
            s.rules
                .set_undeclared_buckets(fireemu_adapter_http::storage::UndeclaredBuckets::Refuse);
            let bucket = "fireemu-obs-ss-48adbd8e";
            for (bucket, name) in [
                (bucket, "cors/o.txt"),
                (OPEN, "storage-strictness/ss-48adbd8e/d.txt"),
            ] {
                s.store
                    .lock()
                    .unwrap()
                    .put(
                        &BucketName::try_new(bucket).unwrap(),
                        &ObjectName::try_new(name).unwrap(),
                        b"cors".to_vec(),
                        NewMetadata {
                            content_type: Some("text/plain".to_owned()),
                            ..NewMetadata::default()
                        },
                        Precondition::default(),
                        START,
                    )
                    .unwrap();
            }
            {
                let rules = if case == "R3" {
                    json!([])
                } else {
                    json!([
                        {"origin":["*"],"method":["GET"],"responseHeader":["*"]},
                        {"origin":["http://localhost:3000"],"method":["PUT","GET"],"responseHeader":["Content-Type"],"maxAgeSeconds":600}
                    ])
                };
                s.rules.set_bucket_cors(BTreeMap::from([(
                    bucket.to_owned(),
                    BucketCors::from_json(&rules).unwrap(),
                )]));
            }
            if case == "F1" {
                s.rules = Arc::new(StorageRulesRegistry::global(Arc::new(RulesetSlot::new(
                    LoadedRules::from_source("rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read: if request.auth != null; } } }").unwrap(),
                ))));
            }
            s.rules.set_unlisted_buckets_cors_none(production_exact);
            let url = row["url"]
                .as_str()
                .unwrap()
                .replace("RUN", "ss-48adbd8e")
                .replace("p.firebasestorage.app", OPEN);
            let path = &url[url.find("://").unwrap() + 3..];
            let path = &path[path.find('/').unwrap()..];
            let mut extra: Vec<(String, String)> = row["requestHeaders"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(name, value)| (name.clone(), value.as_str().unwrap().to_owned()))
                .collect();
            // C1/C4/C5 (also C6/C8/R3) used http://a.example. The local guard requires localhost:4000; the same wildcard rule still matches.
            for (_, value) in &mut extra {
                if value == "http://a.example" {
                    *value = "http://localhost:4000".to_owned();
                }
            }
            if case == "F1" {
                extra.push(("authorization".to_owned(), "Firebase not-a-jwt".to_owned()));
            }
            let extra: Vec<(&str, &str)> = extra
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_str()))
                .collect();
            let (addr, task) = serve(s).await;
            let answer = send(addr, row["method"].as_str().unwrap(), path, &extra).await;
            task.abort();
            let _ = task.await;
            assert_eq!(
                u64::from(answer.status),
                row["status"].as_u64().unwrap(),
                "{case}, productionExact {production_exact}"
            );
            for (name, value) in row["headers"].as_object().unwrap() {
                // A13/A14/C7 metadata contains generated identifiers and the recording deliberately omits its bytes.
                if name == "content-length" && matches!(case, "A13" | "A14" | "C7") {
                    continue;
                }
                let expected = value
                    .as_str()
                    .unwrap()
                    .replace("http://a.example", "http://localhost:4000");
                let actual = answer
                    .headers
                    .iter()
                    .filter(|(n, _)| n.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                assert!(answer.header(name).is_some(), "{case}: missing {name}");
                assert_eq!(
                    actual, expected,
                    "{case}: {name}, productionExact {production_exact}"
                );
            }
            for name in [
                "access-control-allow-origin",
                "access-control-allow-credentials",
                "access-control-allow-methods",
                "access-control-allow-headers",
                "access-control-expose-headers",
                "access-control-max-age",
                "vary",
            ] {
                if row["headers"].get(name).is_none() {
                    assert_eq!(answer.header(name), None, "{case}: unexpected {name}");
                }
            }
            if let Some(body) = row["body"].as_str() {
                assert_eq!(
                    answer.body,
                    body.as_bytes(),
                    "{case}: exact production body"
                );
                assert_eq!(
                    answer.body.len() as u64,
                    row["bodyBytes"].as_u64().unwrap(),
                    "{case}: bodyBytes"
                );
            } else if matches!(case, "A13" | "A14" | "C7") {
                let body: Value = serde_json::from_slice(&answer.body).unwrap();
                if case == "A14" {
                    assert_eq!(body["items"][0]["name"], "cors/o.txt");
                } else {
                    assert_eq!(body["name"], "cors/o.txt");
                }
            } else {
                assert_eq!(
                    answer.body.len() as u64,
                    row["bodyBytes"].as_u64().unwrap(),
                    "{case}: bodyBytes"
                );
                // Media body bytes were omitted too; verify the seeded content without claiming it was recorded.
                if matches!(case, "C5" | "C6") {
                    assert_eq!(answer.body, b"cors");
                } else {
                    assert!(answer.body.is_empty(), "{case}");
                }
            }
        }
    }
}

#[tokio::test]
async fn malformed_firebase_credentials_remain_anonymous_and_bad_signatures_remain_refused() {
    use fireemu_core_auth::jwt::base64url_encode;
    let bad_signature = format!("Firebase {}.{}.{}",
        base64url_encode(br#"{"alg":"RS256","kid":"k1","typ":"JWT"}"#),
        base64url_encode(br#"{"aud":"demo-app","sub":"alice","iss":"https://securetoken.google.com/demo-app","exp":2000000000,"iat":1700000000}"#),
        base64url_encode(b"not a signature"));
    for acceptance in [TokenAcceptance::Verified, TokenAcceptance::EmulatorMock] {
        let s = configured(acceptance, &json!([]));
        let (addr, task) = serve(s).await;
        let path = format!("/v0/b/{CONFIGURED}/o/a.txt");
        let anonymous = send(
            addr,
            "GET",
            &path,
            &[("Authorization", "Firebase not-a-jwt")],
        )
        .await;
        let signed = send(addr, "GET", &path, &[("Authorization", &bad_signature)]).await;
        task.abort();
        let _ = task.await;
        assert_eq!(
            anonymous.status, 200,
            "allow-all Rules decide for the malformed token"
        );
        assert_eq!(
            signed.status,
            if acceptance == TokenAcceptance::Verified {
                401
            } else {
                200
            }
        );
        if acceptance == TokenAcceptance::Verified {
            let body: Value = serde_json::from_slice(&signed.body).unwrap();
            assert_eq!(body["error"]["status"], "UNAUTHENTICATED");
        }
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn emulator_keeps_its_answers_for_the_recorded_routes() {
    let recording: Value = serde_json::from_str(include_str!(
        "../../../conformance/storage-strictness-obs/recordings/run-1.json"
    ))
    .unwrap();
    for row in recording["rows"].as_array().unwrap() {
        let case = row["case"].as_str().unwrap();
        if case == "K1" {
            continue;
        }
        let mut s = configured(TokenAcceptance::EmulatorMock, &rule());
        // Neither strict-only setting may affect the emulator, even when populated directly by a test.
        s.rules
            .set_undeclared_buckets(fireemu_adapter_http::storage::UndeclaredBuckets::Refuse);
        s.rules.set_unlisted_buckets_cors_none(true);
        if case == "F1" {
            s.rules = Arc::new(StorageRulesRegistry::global(Arc::new(RulesetSlot::new(
                LoadedRules::from_source("rules_version = '2'; service firebase.storage { match /b/{bucket}/o { match /{path=**} { allow read: if request.auth != null; } } }").unwrap(),
            ))));
        }
        let url = row["url"]
            .as_str()
            .unwrap()
            .replace("fireemu-obs-RUN-absent", "typo-bucket")
            .replace("fireemu-obs-RUN", CONFIGURED)
            .replace("p.firebasestorage.app", OPEN)
            .replace("storage-strictness%2FRUN%2Fd.txt", "a.txt")
            .replace("cors%2Fo.txt", "a.txt")
            .replace("cors/o.txt", "a.txt");
        let path = &url[url.find("://").unwrap() + 3..];
        let path = &path[path.find('/').unwrap()..];
        let mut extra: Vec<(String, String)> = row["requestHeaders"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, value)| {
                (
                    name.clone(),
                    value
                        .as_str()
                        .unwrap()
                        .replace("http://a.example", "http://localhost:4000"),
                )
            })
            .collect();
        if case == "F1" {
            extra.push(("authorization".to_owned(), "Firebase not-a-jwt".to_owned()));
        }
        let extra: Vec<(&str, &str)> = extra
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let (addr, task) = serve(s).await;
        let answer = send(addr, row["method"].as_str().unwrap(), path, &extra).await;
        task.abort();
        let _ = task.await;
        let expected_status = match case {
            "A1" | "A2" | "A5" | "A6" | "A8" | "A9" | "A11" => 404,
            "C1" | "C2" | "C3" | "C4" | "C8" | "R3" | "F2" => 204,
            "F1" => 403,
            _ => 200,
        };
        assert_eq!(
            answer.status,
            expected_status,
            "{case}: {}",
            String::from_utf8_lossy(&answer.body)
        );
        if row["method"] == "OPTIONS" {
            assert_eq!(
                answer.header("access-control-allow-methods"),
                Some("GET,HEAD,PUT,PATCH,POST,DELETE"),
                "{case}"
            );
            assert_eq!(answer.header("access-control-max-age"), None, "{case}");
            assert_eq!(
                answer.header("vary"),
                Some("Origin, Access-Control-Request-Headers"),
                "{case}"
            );
            assert_eq!(
                answer.header("access-control-allow-headers"),
                row["requestHeaders"]["access-control-request-headers"].as_str(),
                "{case}"
            );
            assert!(answer.body.is_empty(), "{case}");
        } else {
            assert_eq!(answer.header("vary"), Some("Origin"), "{case}");
        }
        assert_eq!(
            answer.header("access-control-allow-credentials"),
            None,
            "{case}"
        );
        assert_eq!(answer.header("access-control-expose-headers"), Some("content-type,x-firebase-storage-version,X-Goog-Upload-Size-Received,x-goog-upload-url,x-goog-upload-command,x-gupload-uploadid,x-goog-upload-header-content-length,x-goog-upload-header-content-type,x-goog-upload-protocol,x-goog-upload-status,x-goog-upload-chunk-granularity,x-goog-upload-control-url"), "{case}");
        let origin = row["requestHeaders"]["origin"]
            .as_str()
            .map(|o| o.replace("http://a.example", "http://localhost:4000"));
        assert_eq!(
            answer.header("access-control-allow-origin"),
            origin.as_deref(),
            "{case}"
        );
        if matches!(case, "A1" | "A2" | "A5" | "A6" | "A8" | "A9") {
            assert!(
                String::from_utf8_lossy(&answer.body).contains("No such object"),
                "{case}"
            );
        }
        if case == "F1" {
            assert_eq!(
                serde_json::from_slice::<Value>(&answer.body).unwrap()["error"]["message"],
                "Permission denied. No READ permission."
            );
        }
        if case == "F2" {
            assert_eq!(answer.header("content-length"), None);
            assert!(answer.body.is_empty());
        }
    }
}
