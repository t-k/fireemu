//! The runtime against a fake runner: dispatch, outcomes, retries in virtual time,
//! schedules, await-idle, and the protocol helpers.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ftd_adapter_functions::events::{firestore_event, storage_event};
use ftd_adapter_functions::http::parse_response;
use ftd_adapter_functions::manifest_json::{manifest_to_json, parse_manifest};
use ftd_adapter_functions::runner::{Runner, SpawnSpec};
use ftd_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use ftd_adapter_grpc::local::CommitEvent;
use ftd_core_firestore::path::DocumentPath;
use ftd_core_firestore::store::{CommitVersion, Document, DocumentChange};
use ftd_core_firestore::value::Value as FsValue;
use ftd_core_functions::manifest::{DocumentEvent, ObjectEvent};
use ftd_core_session::clock::VirtualClock;
use ftd_core_storage::name::{BucketName, ObjectName};
use ftd_core_storage::store::{NewMetadata, Precondition, StorageEvent, StorageState};
use ftd_core_types::ids::SessionId;
use ftd_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::json;

const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);

fn doc(path: &str, v: i64) -> Document {
    Document {
        path: DocumentPath::parse(
            &ftd_core_types::ids::ProjectId::try_new("demo-app").unwrap(),
            &ftd_core_types::ids::DatabaseId::default_database(),
            path,
        )
        .unwrap(),
        fields: [("v".to_owned(), FsValue::Integer(v))]
            .into_iter()
            .collect(),
        create_time: START,
        update_time: START,
        version: CommitVersion::default(),
    }
}

fn commit(changes: Vec<DocumentChange>) -> CommitEvent {
    CommitEvent {
        project: "demo-app".into(),
        database: "(default)".into(),
        version: 1,
        commit_time: Some(START),
        changes: Arc::new(changes),
    }
}

async fn start() -> (Arc<FunctionsRuntime>, Arc<Mutex<VirtualClock>>) {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py");
    let spec = SpawnSpec {
        command: vec!["python3".to_owned(), script.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(20),
    };
    let runner = Runner::spawn_spec(&spec).await.unwrap();
    let manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
    let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: "demo-app".into(),
            default_bucket: "demo-app.appspot.com".into(),
            location: "nam5".into(),
            session: SessionId::new(7),
            max_running: 4,
            retry_attempts: 4,
            max_catch_up_runs: 1000,
            runner_secret: "s".into(),
        },
        clock.clone(),
        Arc::new(runner),
        Some(spec),
    );
    tokio::spawn(runtime.clone().dispatch_loop());
    (runtime, clock)
}

#[tokio::test]
async fn events_are_dispatched_and_retried_in_virtual_time() {
    let (runtime, clock) = start().await;
    assert!(runtime.is_idle());
    // items/a is created: `ok` (created) and `fail` (written) both match.
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("items/a", 1).path,
        before: None,
        after: Some(doc("items/a", 1)),
    }]));
    assert!(!runtime.is_idle());
    // `fail` retries: the session stays busy until virtual time releases the retry.
    let waited = runtime.await_idle(Duration::from_millis(800)).await;
    assert!(waited.is_err(), "retry-waiting keeps the session busy");
    let history = runtime.history();
    assert!(history
        .iter()
        .any(|r| r.function == "ok" && r.outcome == "ok"));
    assert!(history
        .iter()
        .any(|r| r.function == "fail" && r.attempt == 1 && r.outcome.starts_with("failed")));
    // Retries: attempts 2..4 happen as the clock advances (backoff 10s, 20s, 40s).
    for _ in 0..3 {
        clock
            .lock()
            .unwrap()
            .advance(LogicalDuration::from_seconds(60))
            .unwrap();
        runtime.on_clock_changed();
        let _ = runtime.await_idle(Duration::from_millis(500)).await;
    }
    assert!(runtime.await_idle(Duration::from_secs(2)).await.is_ok());
    let dead = runtime.dead_letters();
    assert_eq!(dead.len(), 1, "{dead:?}");
    assert_eq!((dead[0].function.as_str(), dead[0].attempt), ("fail", 4));
    // A non-matching path fires nothing.
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("other/x", 1).path,
        before: None,
        after: Some(doc("other/x", 1)),
    }]));
    assert!(runtime.is_idle());
    // Schedules: the retries advanced 3 minutes; 12 more make 15, i.e. three "every 5
    // minutes" runs (catch-up enqueues every missed run).
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(12 * 60))
        .unwrap();
    runtime.on_clock_changed();
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    let ticks = runtime
        .history()
        .iter()
        .filter(|r| r.function == "tick")
        .count();
    assert_eq!(ticks, 3);
    runtime.run_schedule("tick").unwrap();
    assert!(runtime.run_schedule("ok").is_err(), "not a schedule");
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    // Storage: the slow function times out (1s) and is dead-lettered (no retry).
    let mut store = StorageState::new(1);
    let meta = store
        .put(
            &BucketName::try_new("demo-app.appspot.com").unwrap(),
            &ObjectName::try_new("a.txt").unwrap(),
            b"x".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            START,
        )
        .unwrap();
    runtime.on_storage_event(&StorageEvent::Finalized(meta));
    // The event is dead-lettered at the deadline, but the handler is still running in the
    // runner, so the session is not idle until it finishes.
    let busy = runtime.await_idle(Duration::from_secs(3)).await;
    assert!(busy.is_err(), "{busy:?}");
    assert!(runtime
        .dead_letters()
        .iter()
        .any(|r| r.function == "slow" && r.outcome == "timeout"));
    assert_eq!(runtime.status()["running"], 1);
    let status = runtime.status();
    assert_eq!(
        status["running"], 1,
        "the hung handler still holds its slot"
    );
    assert_eq!(status["deadLettered"], 2);
    // Killing the runner releases the slot and stops dispatch.
    runtime.runner().shutdown().await;
    assert!(runtime.await_idle(Duration::from_secs(5)).await.is_ok());
    assert!(!runtime.runner_alive());
}

#[tokio::test]
async fn reset_discards_in_flight_work() {
    let (runtime, _clock) = start().await;
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("items/b", 1).path,
        before: Some(doc("items/b", 0)),
        after: Some(doc("items/b", 1)),
    }]));
    // `fail` (written) will be retry-waiting; a reset drops it, kills the runner and
    // restarts it, after which dispatch resumes.
    let _ = runtime.await_idle(Duration::from_millis(500)).await;
    assert!(!runtime.is_idle());
    runtime.reset();
    assert!(runtime.is_idle());
    assert_eq!(runtime.status()["epoch"], 1);
    for _ in 0..100 {
        if runtime.runner_alive() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(runtime.runner_alive(), "the runner was restarted");
    runtime.on_commit(&commit(vec![DocumentChange {
        path: doc("items/c", 1).path,
        before: None,
        after: Some(doc("items/c", 1)),
    }]));
    let _ = runtime.await_idle(Duration::from_secs(5)).await;
    assert!(runtime
        .history()
        .iter()
        .any(|r| r.function == "ok" && r.outcome == "ok" && r.event_id > 1));
    runtime.runner().shutdown().await;
}

#[test]
fn manifest_json_round_trips_and_rejects_bad_input() {
    let v = json!({"functions": [
        {"name": "a", "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.updated", "document": "x/{id}"}, "timeoutSeconds": 5, "retry": true},
        {"name": "b", "trigger": {"type": "callable"}},
        {"name": "c", "trigger": {"type": "schedule", "schedule": "0 3 * * *", "timeZone": "Asia/Tokyo"}, "region": "asia-northeast1"},
        {"name": "d", "trigger": {"type": "storage", "eventType": "google.cloud.storage.object.v1.deleted", "bucket": "b"}}
    ]});
    let m = parse_manifest(&v).unwrap();
    assert_eq!(m.functions.len(), 4);
    assert_eq!(m.functions[2].region, "asia-northeast1");
    let back = manifest_to_json(&m);
    assert_eq!(back["functions"][0]["retry"], true);
    assert_eq!(back["functions"][1]["trigger"]["callable"], true);
    for bad in [
        json!({"functions": [{"name": "x", "trigger": {"type": "firestore", "eventType": "nope", "document": "a/{b}"}}]}),
        json!({"functions": [{"name": "x", "trigger": {"type": "firestore", "eventType": "google.cloud.firestore.document.v1.created", "document": "a"}}]}),
        json!({"functions": [{"name": "x", "trigger": {"type": "schedule", "schedule": "* * * * *", "timeZone": "America/New_York"}}]}),
        json!({"functions": [{"name": "x", "trigger": {"type": "pubsub"}}]}),
        json!({"functions": [{"name": "x", "trigger": {"type": "http"}}, {"name": "x", "trigger": {"type": "http"}}]}),
        json!({"nope": 1}),
    ] {
        assert!(parse_manifest(&bad).is_err(), "{bad}");
    }
}

#[test]
fn cloudevents_carry_the_shapes_the_sdk_decodes() {
    let before = doc("todos/t1", 1);
    let after = doc("todos/t1", 2);
    let e = firestore_event(
        "e1",
        "demo-app",
        "(default)",
        "nam5",
        "todos/t1",
        DocumentEvent::Updated,
        Some(&before),
        Some(&after),
        START,
    );
    assert_eq!(e["type"], "google.cloud.firestore.document.v1.updated");
    assert_eq!(
        e["source"],
        "projects/demo-app/databases/(default)/documents/todos/t1"
    );
    assert_eq!(e["subject"], "documents/todos/t1");
    assert_eq!(e["document"], "todos/t1");
    assert_eq!(e["database"], "(default)");
    assert_eq!(e["datacontenttype"], "application/json");
    assert_eq!(e["data"]["value"]["fields"]["v"]["integerValue"], "2");
    assert_eq!(e["data"]["oldValue"]["fields"]["v"]["integerValue"], "1");
    assert_eq!(e["data"]["updateMask"]["fieldPaths"], json!(["v"]));
    let created = firestore_event(
        "e2",
        "demo-app",
        "(default)",
        "nam5",
        "todos/t1",
        DocumentEvent::Created,
        None,
        Some(&after),
        START,
    );
    assert!(created["data"].get("oldValue").is_none());
    assert!(created["data"].get("updateMask").is_none());
    let mut store = StorageState::new(1);
    let meta = store
        .put(
            &BucketName::try_new("demo-app.appspot.com").unwrap(),
            &ObjectName::try_new("dir/a.txt").unwrap(),
            b"abc".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            START,
        )
        .unwrap();
    let s = storage_event("e3", ObjectEvent::Finalized, &meta, START);
    assert_eq!(s["type"], "google.cloud.storage.object.v1.finalized");
    assert_eq!(s["bucket"], "demo-app.appspot.com");
    assert_eq!(s["subject"], "objects/dir/a.txt");
    assert_eq!(s["data"]["size"], "3");
    assert_eq!(s["data"]["name"], "dir/a.txt");
    assert!(s["data"]["selfLink"]
        .as_str()
        .unwrap()
        .ends_with("/o/dir%2Fa.txt"));
}

#[test]
fn http_responses_are_parsed_with_every_body_framing() {
    let chunked = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n";
    let r = parse_response(chunked, "GET").unwrap();
    assert_eq!((r.status, r.body.as_slice()), (200, &b"hello!"[..]));
    assert_eq!(
        r.headers,
        vec![("Content-Type".to_owned(), "text/plain".to_owned())]
    );
    let sized = b"HTTP/1.1 404 Not Found\r\ncontent-length: 3\r\n\r\nnopIGNORED";
    assert_eq!(parse_response(sized, "GET").unwrap().body, b"nop");
    // HEAD and body-less statuses omit the declared body; a truncated GET is an error.
    let head = b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\n";
    assert!(parse_response(head, "HEAD").unwrap().body.is_empty());
    assert!(parse_response(head, "GET").is_err());
    assert!(parse_response(b"HTTP/1.1 204 No Content\r\n\r\n", "GET")
        .unwrap()
        .body
        .is_empty());
    let closed = b"HTTP/1.1 500 X\r\n\r\nwhole body";
    assert_eq!(parse_response(closed, "GET").unwrap().body, b"whole body");
    assert!(parse_response(b"garbage", "GET").is_err());
    assert!(parse_response(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nshort", "GET").is_err());
}
