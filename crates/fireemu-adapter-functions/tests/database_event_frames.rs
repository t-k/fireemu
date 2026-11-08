//! The bytes a runner receives for a write that fires several RTDB triggers on one large
//! snapshot. The digests were taken from the frames of the tree before event building shared
//! one serialization per snapshot; any change to a delivered byte fails here.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fireemu_adapter_functions::events::{
    DatabaseChangeData, DatabaseCommit, DatabaseEventShape, DatabaseReferenceChange,
};
use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{FunctionsConfig, FunctionsRuntime};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

/// Logs the length and SHA-256 of each whole `invoke` frame exactly as it arrived.
const RUNNER: &str = r"
import hashlib, json, sys
def send(value):
    value=json.dumps(value).encode()
    sys.stdout.buffer.write(str(len(value)).encode()+b'\n'+value)
    sys.stdout.buffer.flush()
send({'type':'hello','runner':'database-frame-digest'})
while True:
    line=sys.stdin.buffer.readline()
    if not line: break
    raw=sys.stdin.buffer.read(int(line))
    msg=json.loads(raw)
    if msg.get('type')=='shutdown': break
    if msg.get('type')!='invoke': continue
    send({'type':'log','level':'info','message':'%s %d %s'%(msg['function'],len(raw),hashlib.sha256(raw).hexdigest()),'invocationId':msg['invocationId'],'functionName':msg['function'],'user':True})
    send({'type':'result','invocationId':msg['invocationId'],'ok':True})
";

fn manifest() -> fireemu_core_functions::manifest::FunctionManifest {
    let function = |name: &str, kind: &str| {
        json!({"name": name, "generation": 2, "trigger": {
            "type": "database", "eventType": format!("google.firebase.database.ref.v1.{kind}"),
            "instance": "app-*", "ref": "/{top}"
        }})
    };
    parse_manifest(&json!({"functions": [
        function("a_written", "written"),
        function("b_updated", "updated"),
        function("c_written", "written"),
        function("d_created", "created"),
    ]}))
    .unwrap()
}

/// `/items` with `count` small objects, then one value changed.
fn snapshots(count: usize) -> (Value, Value) {
    let item = |index: usize, score: usize| {
        json!({"name": format!("user-{index:06}"), "score": score, "active": index % 2 == 0,
               "note": "caf\u{e9} \u{1F600} \"quoted\" \\ /"})
    };
    let mut before = serde_json::Map::new();
    for index in 0..count {
        before.insert(format!("k{index:06}"), item(index, index % 1000));
    }
    let mut after = before.clone();
    after.insert(format!("k{:06}", count / 2), item(count / 2, 99_999));
    (Value::Object(before), Value::Object(after))
}

fn commit(count: usize) -> DatabaseCommit {
    let (before, after) = snapshots(count);
    DatabaseCommit {
        project: "demo-db".to_owned(),
        instance: "app-first".to_owned(),
        location: "us-central1".to_owned(),
        host: "firebaseio.com".to_owned(),
        sequence: 5,
        time: LogicalInstant::from_unix_seconds(100),
        data: DatabaseChangeData::References(vec![DatabaseReferenceChange {
            reference: "/items".to_owned(),
            before,
            after,
        }]),
        auth_type: "USER".to_owned(),
        auth_id: Some("verified-user".to_owned()),
        auth: Some(json!({"uid":"verified-user"})),
    }
}

async fn runtime(shape: DatabaseEventShape) -> Arc<FunctionsRuntime> {
    let runner = Runner::spawn_spec(&SpawnSpec {
        command: vec!["python3".to_owned(), "-c".to_owned(), RUNNER.to_owned()],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(10),
    })
    .await
    .unwrap();
    FunctionsRuntime::new(
        manifest(),
        FunctionsConfig {
            project: "demo-db".to_owned(),
            location: "us-central1".to_owned(),
            database_event_shape: shape,
            ..FunctionsConfig::for_tests(1000, "test".to_owned())
        },
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(100),
        ))),
        Arc::new(runner),
        None,
    )
}

/// `function length sha256` lines of the frames delivered for `commit`, sorted by function.
async fn delivered(shape: DatabaseEventShape, commit: &DatabaseCommit) -> (Vec<String>, Duration) {
    let runtime = runtime(shape).await;
    let started = Instant::now();
    runtime.reserve_database_events(commit).unwrap().publish();
    let reserved = started.elapsed();
    let dispatch = tokio::spawn(runtime.clone().dispatch_loop());
    runtime.await_idle(Duration::from_secs(120)).await.unwrap();
    let mut lines: Vec<String> = runtime
        .runner()
        .logs_since(None)
        .lines
        .iter()
        .map(|line| line.message().to_owned())
        .collect();
    lines.sort();
    runtime.shutdown().await;
    dispatch.await.unwrap();
    (lines, reserved)
}

#[tokio::test]
async fn the_frames_of_a_multi_trigger_write_keep_their_bytes() {
    for (shape, expected) in [
        (DatabaseEventShape::Official, EXPECTED_OFFICIAL),
        (DatabaseEventShape::Production, EXPECTED_PRODUCTION),
    ] {
        let (lines, _) = delivered(shape, &commit(3000)).await;
        assert_eq!(lines, expected, "{shape:?}\n{lines:#?}");
    }
}

/// Measurement, not a gate: `cargo test --release -p fireemu-adapter-functions --test
/// database_event_frames -- --ignored --nocapture` with `FRAME_ITEMS` objects (130000 is 7 MB).
#[tokio::test]
#[ignore = "measurement"]
async fn measure_a_large_multi_trigger_write() {
    let items: usize = std::env::var("FRAME_ITEMS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(130_000);
    let change = commit(items);
    for run in 0..3 {
        let started = Instant::now();
        let (lines, reserved) = delivered(DatabaseEventShape::Official, &change).await;
        println!(
            "run {run}: reserve {reserved:?}, total {:?}",
            started.elapsed()
        );
        if run == 0 {
            for line in &lines {
                println!("{line}");
            }
        }
    }
}

const EXPECTED_OFFICIAL: &[&str] = &[
    "a_written 286987 a26dae6c816628ad5aceeccb63efd5563c263890819a2330730a8804fd6f77dd",
    "b_updated 286987 0517e243a4fbe87ab81b33bda50e925256991726d5a6f4af542e722b1abe8e89",
    "c_written 286987 385202a05e3ca13f1bd9dd9820cf1102136826110684bb64dfc8829af900b2a8",
];
const EXPECTED_PRODUCTION: &[&str] = &[
    "a_written 286940 103a371be402f3a41334b995d9cff65a403067ce0c368075ac2fc8f1bb9727f7",
    "b_updated 286940 520dc8b13935e7f8b875a3b063e3e14b90a7220519b15846c4d80af1187e4707",
    "c_written 286940 0f29a5debcf10e092b7dd33ed79ae51c9d5f47da329a878136ba3c474b16a76d",
];

/// The `data` member as the event was built before it was assembled member by member: a
/// `json!` of both snapshots and an independently written delta.
fn legacy_data(before: &Value, after: &Value) -> Value {
    fn delta(before: &Value, after: &Value) -> Value {
        match (before, after) {
            (Value::Object(old), Value::Object(new)) => {
                let mut out = serde_json::Map::new();
                for key in old.keys().chain(new.keys()) {
                    let (a, b) = (
                        old.get(key).unwrap_or(&Value::Null),
                        new.get(key).unwrap_or(&Value::Null),
                    );
                    if a != b {
                        out.insert(key.clone(), delta(a, b));
                    }
                }
                Value::Object(out)
            }
            _ => after.clone(),
        }
    }
    json!({"@type":"type.googleapis.com/google.events.firebase.database.v1.ReferenceEventData",
           "data": before, "delta": delta(before, after)})
}

mod properties {
    use super::*;
    use fireemu_adapter_functions::events::database_event_payloads_for;
    use proptest::prelude::*;

    fn snapshot() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::Bool),
            any::<i32>().prop_map(|n| json!(n)),
            "[a-c\u{e9}]{0,3}".prop_map(Value::String),
        ];
        leaf.prop_recursive(3, 16, 3, |inner| {
            prop::collection::btree_map("[a-c]{1,2}", inner, 0..4)
                .prop_map(|map| Value::Object(map.into_iter().collect()))
        })
    }

    proptest! {
        #[test]
        fn the_data_member_is_the_snapshot_and_its_delta(
            before in snapshot(), after in snapshot(),
        ) {
            prop_assume!(before != after);
            let mut commit = commit(0);
            commit.data = DatabaseChangeData::References(vec![DatabaseReferenceChange {
                reference: "/items".to_owned(), before: before.clone(), after: after.clone(),
            }]);
            let manifest = manifest();
            for shape in [DatabaseEventShape::Official, DatabaseEventShape::Production] {
                for function in &manifest.functions {
                    for (_, payload) in database_event_payloads_for(&commit, function, shape) {
                        prop_assert_eq!(&payload["data"], &legacy_data(&before, &after));
                    }
                }
            }
        }
    }
}
