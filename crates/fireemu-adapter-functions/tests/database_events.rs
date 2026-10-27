//! RTDB trigger contracts through the existing Functions event pipeline.

use fireemu_adapter_functions::manifest_json::{manifest_to_json, parse_manifest};
use serde_json::json;

#[test]
fn database_manifest_roundtrips_instance_and_reference_patterns() {
    let value = json!({"functions": [{
        "name": "changed", "generation": 2,
        "trigger": {"type": "database", "eventType": "google.firebase.database.ref.v1.written",
                    "instance": "app-*", "ref": "/users/{uid=*-test}/value"}
    }]});
    let manifest = parse_manifest(&value).expect("a supported RTDB trigger");
    let output = manifest_to_json(&manifest);
    assert_eq!(output["functions"][0]["trigger"]["type"], "database");
    assert_eq!(output["functions"][0]["trigger"]["instance"], "app-*");
    assert_eq!(
        output["functions"][0]["trigger"]["ref"],
        "/users/{uid=*-test}/value"
    );
}

#[test]
fn database_manifest_refuses_multiple_segment_patterns() {
    for reference in ["/users/**", "/users/{uid=**}", "/a/{uid}/{uid}"] {
        let value = json!({"functions": [{"name": "invalid", "trigger": {
            "type": "database", "eventType": "google.firebase.database.ref.v1.written",
            "ref": reference
        }}]});
        assert!(parse_manifest(&value).is_err(), "{reference}");
    }
}

use fireemu_adapter_functions::events::{
    database_event_payloads, DatabaseChangeData, DatabaseCommit,
};
use fireemu_core_types::time::LogicalInstant;

fn commit() -> DatabaseCommit {
    DatabaseCommit {
        project: "demo-db".to_owned(),
        instance: "app-first".to_owned(),
        location: "us-central1".to_owned(),
        host: "firebaseio.com".to_owned(),
        sequence: 5,
        time: LogicalInstant::from_unix_seconds(100),
        data: DatabaseChangeData::Whole {
            before: json!({"users": {"a": {"old": 1}, "b": {"keep": true}}}),
            after: json!({"users": {"a": {"new": 2}, "b": {"keep": true}, "c": 3}}),
        },
        auth_type: "USER".to_owned(),
        auth_id: Some("verified-user".to_owned()),
        auth: Some(json!({"uid":"verified-user","token":{"role":"member"}})),
    }
}
fn trigger(kind: &str) -> fireemu_core_functions::manifest::FunctionManifest {
    parse_manifest(
        &json!({"functions": [{"name":"db", "generation":2,"trigger": {
            "type":"database", "eventType":format!("google.firebase.database.ref.v1.{kind}"),
            "instance":"app-*", "ref":"/users/{uid}"
        }}]}),
    )
    .unwrap()
}
#[test]
fn an_ancestor_update_emits_only_changed_bound_references_with_complete_delta() {
    let manifest = trigger("written");
    let result = database_event_payloads(&commit(), &manifest.functions[0]);
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, "/users/a");
    assert_eq!(result[0].1["data"]["data"], json!({"old":1}));
    assert_eq!(result[0].1["data"]["delta"], json!({"old":null,"new":2}));
    assert_eq!(result[0].1["instance"], "app-first");
    assert_eq!(result[0].1["authtype"], "app_user");
    assert_eq!(result[0].1["authid"], "verified-user");
    assert_eq!(result[1].0, "/users/c");
}
#[test]
fn unchanged_wrong_instance_wrong_region_and_wrong_mutation_family_emit_nothing() {
    let manifest = trigger("deleted");
    assert!(database_event_payloads(&commit(), &manifest.functions[0]).is_empty());
    let manifest = trigger("written");
    let mut change = commit();
    change.data = DatabaseChangeData::Whole {
        before: json!({"same":true}),
        after: json!({"same":true}),
    };
    assert!(database_event_payloads(&change, &manifest.functions[0]).is_empty());
    change = commit();
    change.instance = "other".to_owned();
    assert!(database_event_payloads(&change, &manifest.functions[0]).is_empty());
    change = commit();
    change.location = "europe-west1".to_owned();
    assert!(database_event_payloads(&change, &manifest.functions[0]).is_empty());
}

use fireemu_adapter_functions::runner::{Runner, SpawnSpec};
use fireemu_adapter_functions::runtime::{
    FunctionsConfig, FunctionsRuntime, SourceEventAdmissionError, DATABASE_FANOUT_DROPPED,
    MAX_ACTIVE_EVENT_RECORDS,
};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalDuration;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// This framing-only runner opens no sockets. Snapshot semantics are tested with the real
// installed Node SDK in tools/runner-node/database.test.mjs, not emulated here.
const RUNNER: &str = r"
import json, sys
def send(value):
    value=json.dumps(value).encode()
    sys.stdout.buffer.write(str(len(value)).encode()+b'\n'+value)
    sys.stdout.buffer.flush()
send({'type':'hello','runner':'database-framing-test'})
attempt=0
while True:
    line=sys.stdin.buffer.readline()
    if not line: break
    msg=json.loads(sys.stdin.buffer.read(int(line)))
    if msg.get('type')=='shutdown': break
    if msg.get('type')!='invoke': continue
    attempt+=1
    send({'type':'log','level':'info','message':json.dumps(msg['event']),'invocationId':msg['invocationId'],'functionName':msg['function'],'user':True})
    send({'type':'result','invocationId':msg['invocationId'],'ok':not(sys.argv[1]=='fail-once' and attempt==1),'error':'first attempt failed'})
";

async fn runtime(fail_once: bool) -> (Arc<FunctionsRuntime>, Arc<Mutex<VirtualClock>>) {
    runtime_shaped(
        fail_once,
        fireemu_adapter_functions::events::DatabaseEventShape::default(),
    )
    .await
}

async fn runtime_shaped(
    fail_once: bool,
    shape: fireemu_adapter_functions::events::DatabaseEventShape,
) -> (Arc<FunctionsRuntime>, Arc<Mutex<VirtualClock>>) {
    let runner = Runner::spawn_spec(&SpawnSpec {
        command: vec![
            "python3".to_owned(),
            "-c".to_owned(),
            RUNNER.to_owned(),
            if fail_once { "fail-once" } else { "ok" }.to_owned(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(10),
    })
    .await
    .unwrap();
    let mut manifest = trigger("written");
    manifest.functions[0].retry = true;
    let clock = Arc::new(Mutex::new(VirtualClock::new(commit().time)));
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            project: "demo-db".to_owned(),
            location: "us-central1".to_owned(),
            database_event_shape: shape,
            ..FunctionsConfig::for_tests(1000, "test".to_owned())
        },
        clock.clone(),
        Arc::new(runner),
        None,
    );
    (runtime, clock)
}

#[tokio::test]
async fn database_capture_scopes_project_instance_and_generation_region() {
    let (runtime, _) = runtime(false).await;
    assert_eq!(
        runtime
            .database_capture_patterns("demo-db", "app-first", "us-central1")
            .len(),
        1
    );
    assert!(runtime
        .database_capture_patterns("another-project", "app-first", "us-central1")
        .is_empty());
    assert!(runtime
        .database_capture_patterns("demo-db", "unmatched", "us-central1")
        .is_empty());
    assert!(runtime
        .database_capture_patterns("demo-db", "app-first", "europe-west1")
        .is_empty());
    let mut other = commit();
    other.project = "another-project".to_owned();
    runtime.reserve_database_events(&other).unwrap().publish();
    assert_eq!(
        runtime.source_event_accounting().unwrap().published_records,
        0
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn database_reservations_are_invisible_refundable_and_invalidated_by_reset() {
    let (runtime, _) = runtime(false).await;
    let reservation = runtime.reserve_database_events(&commit()).unwrap();
    assert_eq!(
        runtime.source_event_accounting().unwrap().reserved_records,
        2
    );
    assert_eq!(
        runtime.source_event_accounting().unwrap().published_records,
        0
    );
    assert!(runtime.history().is_empty());
    drop(reservation);
    assert_eq!(
        runtime.source_event_accounting().unwrap().reserved_records,
        0
    );
    let stale = runtime.reserve_database_events(&commit()).unwrap();
    runtime.reset();
    stale.publish();
    assert_eq!(
        runtime.source_event_accounting().unwrap().reserved_records,
        0
    );
    assert_eq!(
        runtime.source_event_accounting().unwrap().published_records,
        0
    );
    assert!(runtime.history().is_empty());
    runtime.begin_shutdown();
    assert!(matches!(
        runtime.reserve_database_events(&commit()),
        Err(SourceEventAdmissionError::Unavailable)
    ));
    runtime.shutdown().await;
}

fn dropped_fanouts(runtime: &FunctionsRuntime) -> u64 {
    runtime
        .resources(fireemu_core_types::resources::RootBudget::DEFAULT)
        .unwrap()
        .refusals
        .into_iter()
        .find(|refusal| refusal.reason == format!("admission.{DATABASE_FANOUT_DROPPED}"))
        .map_or(0, |refusal| refusal.count)
}

fn user_changes(count: usize) -> DatabaseChangeData {
    use fireemu_adapter_functions::events::DatabaseReferenceChange;
    DatabaseChangeData::References(
        (0..count)
            .map(|n| DatabaseReferenceChange {
                reference: format!("/users/id{n}"),
                before: serde_json::Value::Null,
                after: json!(n),
            })
            .collect(),
    )
}

/// Review S4 (2026-10-25): a fanout larger than the whole event budget can never be admitted,
/// so it is dropped (counted, nothing charged) and the source write proceeds, as production
/// accepts it.
#[tokio::test]
async fn database_fanout_beyond_the_whole_budget_is_dropped_without_charging_records() {
    let (runtime, _) = runtime(false).await;
    let mut change = commit();
    change.data = user_changes(MAX_ACTIVE_EVENT_RECORDS + 1);
    let reservation = runtime
        .reserve_database_events(&change)
        .expect("a fanout that can never fit is dropped, not refused");
    assert_eq!(
        runtime.source_event_accounting().unwrap().reserved_records,
        0
    );
    reservation.publish();
    assert_eq!(
        runtime.source_event_accounting().unwrap().published_records,
        0
    );
    assert_eq!(dropped_fanouts(&runtime), 1);
    // A dropped larger source operation cannot consume the following operation's capacity.
    let reservation = runtime.reserve_database_events(&commit()).unwrap();
    assert_eq!(
        runtime.source_event_accounting().unwrap().reserved_records,
        2
    );
    drop(reservation);
    runtime.shutdown().await;
}

fn outbox_bytes(runtime: &FunctionsRuntime) -> u64 {
    runtime
        .resources(fireemu_core_types::resources::RootBudget::DEFAULT)
        .unwrap()
        .gauges
        .into_iter()
        .find(|gauge| gauge.id == "outbox.bytes")
        .unwrap()
        .current
}

/// The budget is inclusive: exactly 4096 events, or exactly 64 MiB, fit an empty queue and are
/// reserved, never dropped.
#[tokio::test]
async fn database_fanout_of_exactly_the_whole_budget_is_reserved() {
    use fireemu_adapter_functions::events::DatabaseReferenceChange;
    use fireemu_adapter_functions::runtime::MAX_ACTIVE_EVENT_BYTES;
    let (runtime, _) = runtime(false).await;
    let mut change = commit();
    change.data = user_changes(MAX_ACTIVE_EVENT_RECORDS);
    let reservation = runtime.reserve_database_events(&change).unwrap();
    assert_eq!(
        runtime.source_event_accounting().unwrap().reserved_records,
        MAX_ACTIVE_EVENT_RECORDS
    );
    drop(reservation);
    // Eight events of exactly an eighth of the byte budget each: measure one event's overhead
    // with an empty string, then pad.
    let events = |padding: usize| {
        let mut change = commit();
        change.data = DatabaseChangeData::References(
            (0..8)
                .map(|n| DatabaseReferenceChange {
                    reference: format!("/users/id{n}"),
                    before: serde_json::Value::Null,
                    after: json!("x".repeat(padding)),
                })
                .collect(),
        );
        change
    };
    let probe = runtime.reserve_database_events(&events(0)).unwrap();
    let overhead = usize::try_from(outbox_bytes(&runtime)).unwrap() / 8;
    drop(probe);
    let exact = events(MAX_ACTIVE_EVENT_BYTES / 8 - overhead);
    let reservation = runtime.reserve_database_events(&exact).unwrap();
    assert_eq!(
        usize::try_from(outbox_bytes(&runtime)).unwrap(),
        MAX_ACTIVE_EVENT_BYTES
    );
    drop(reservation);
    assert_eq!(dropped_fanouts(&runtime), 0);
    // One byte more can never fit.
    let over = events(MAX_ACTIVE_EVENT_BYTES / 8 - overhead + 1);
    drop(runtime.reserve_database_events(&over).unwrap());
    assert_eq!(dropped_fanouts(&runtime), 1);
    assert_eq!(outbox_bytes(&runtime), 0);
    runtime.shutdown().await;
}

/// Merge review S1 (2026-10-26): whether a fanout can ever fit is decided before the current
/// queue is consulted, so an oversized fanout is dropped at once even while the queue is busy,
/// never refused with a 503 that only a later retry turns into a drop.
#[tokio::test]
async fn an_oversized_fanout_is_dropped_even_while_the_queue_is_busy() {
    let (runtime, _) = runtime(false).await;
    let holding = runtime.reserve_database_events(&commit()).unwrap();
    let mut change = commit();
    change.data = user_changes(MAX_ACTIVE_EVENT_RECORDS + 1);
    drop(
        runtime
            .reserve_database_events(&change)
            .expect("a fanout that can never fit is dropped whatever the queue holds"),
    );
    assert_eq!(dropped_fanouts(&runtime), 1);
    assert_eq!(
        runtime.source_event_accounting().unwrap().reserved_records,
        2,
        "only the held reservation remains"
    );
    drop(holding);
    runtime.shutdown().await;
}

/// Merge review S2: an event larger than an invocation frame is dropped alone; the write's other
/// events are still delivered, as production delivers them.
#[tokio::test]
async fn only_the_event_larger_than_a_frame_is_dropped() {
    use fireemu_adapter_functions::events::DatabaseReferenceChange;
    let (runtime, _) = runtime(false).await;
    let mut change = commit();
    change.data = DatabaseChangeData::References(vec![
        DatabaseReferenceChange {
            reference: "/users/big".to_owned(),
            before: json!("a".repeat(8 * 1024 * 1024)),
            after: json!("b".repeat(8 * 1024 * 1024)),
        },
        DatabaseReferenceChange {
            reference: "/users/small".to_owned(),
            before: serde_json::Value::Null,
            after: json!(1),
        },
    ]);
    let reservation = runtime.reserve_database_events(&change).unwrap();
    assert_eq!(
        runtime.source_event_accounting().unwrap().reserved_records,
        1
    );
    assert_eq!(dropped_fanouts(&runtime), 1);
    reservation.publish();
    assert_eq!(
        runtime.source_event_accounting().unwrap().published_records,
        1
    );
    runtime.shutdown().await;
}

/// Merge review R2-S1: a write refused while the queue is full is not applied, so its
/// over-frame event is neither counted nor warned about; the retry counts it once.
#[tokio::test]
async fn a_refused_write_counts_no_dropped_event() {
    use fireemu_adapter_functions::events::DatabaseReferenceChange;
    let (runtime, _) = runtime(false).await;
    let mut held = commit();
    held.data = user_changes(MAX_ACTIVE_EVENT_RECORDS);
    let holding = runtime.reserve_database_events(&held).unwrap();
    let mut change = commit();
    change.data = DatabaseChangeData::References(vec![
        DatabaseReferenceChange {
            reference: "/users/big".to_owned(),
            before: json!("a".repeat(8 * 1024 * 1024)),
            after: json!("b".repeat(8 * 1024 * 1024)),
        },
        DatabaseReferenceChange {
            reference: "/users/small".to_owned(),
            before: serde_json::Value::Null,
            after: json!(1),
        },
    ]);
    assert!(matches!(
        runtime.reserve_database_events(&change),
        Err(SourceEventAdmissionError::Capacity)
    ));
    assert_eq!(dropped_fanouts(&runtime), 0);
    drop(holding);
    let reservation = runtime.reserve_database_events(&change).unwrap();
    assert_eq!(dropped_fanouts(&runtime), 1);
    assert!(
        !runtime.drop_database_fanout("app-first", "probe"),
        "the warning was spent once"
    );
    drop(reservation);
    runtime.shutdown().await;
}

#[tokio::test]
async fn only_the_first_dropped_fanout_of_a_session_is_printed() {
    let (runtime, _) = runtime(false).await;
    assert!(runtime.drop_database_fanout("app-first", "test"));
    assert!(!runtime.drop_database_fanout("app-first", "test"));
    assert_eq!(dropped_fanouts(&runtime), 2);
    runtime.shutdown().await;
}

/// A fanout that fits an empty queue but not the current one stays a refusal: the caller
/// answers 503 and a retry succeeds once deliveries drain.
#[tokio::test]
async fn database_fanout_that_fits_an_empty_queue_is_refused_only_while_the_queue_is_full() {
    let (runtime, _) = runtime(false).await;
    let mut held = commit();
    held.data = user_changes(MAX_ACTIVE_EVENT_RECORDS - 1);
    let holding = runtime.reserve_database_events(&held).unwrap();
    assert!(matches!(
        runtime.reserve_database_events(&commit()),
        Err(SourceEventAdmissionError::Capacity)
    ));
    assert_eq!(dropped_fanouts(&runtime), 0);
    drop(holding);
    let reservation = runtime.reserve_database_events(&commit()).unwrap();
    assert_eq!(
        runtime.source_event_accounting().unwrap().reserved_records,
        2
    );
    drop(reservation);
    runtime.shutdown().await;
}

#[tokio::test]
async fn database_ipc_capacity_counts_json_escaping_and_the_invoke_envelope() {
    use fireemu_adapter_functions::events::DatabaseReferenceChange;
    let (runtime, _) = runtime(false).await;
    for (character, bytes, accepted) in [
        ('a', 7 * 1024 * 1024, true),
        ('a', 8 * 1024 * 1024, false),
        ('\0', 3 * 1024 * 1024, false),
    ] {
        let mut change = commit();
        change.data = DatabaseChangeData::References(vec![DatabaseReferenceChange {
            reference: "/users/a".to_owned(),
            before: json!(character.to_string().repeat(bytes)),
            after: json!("b".repeat(bytes)),
        }]);
        let dropped = dropped_fanouts(&runtime);
        let result = runtime.reserve_database_events(&change);
        // An event larger than an invocation frame can never be delivered; production does
        // not deliver an oversized event either, and still accepts the write (review S4).
        drop(result.expect("a fitting event is reserved and an oversized one dropped"));
        assert_eq!(dropped_fanouts(&runtime), dropped + u64::from(!accepted));
        assert_eq!(
            runtime.source_event_accounting().unwrap().reserved_records,
            0
        );
        assert_eq!(
            runtime.source_event_accounting().unwrap().published_records,
            0
        );
    }
    // The event alone fits exactly; its enclosing invocation must still be refused.
    let mut change = commit();
    change.data = DatabaseChangeData::References(vec![DatabaseReferenceChange {
        reference: "/users/a".to_owned(),
        before: serde_json::Value::Null,
        after: json!(""),
    }]);
    let manifest = trigger("written");
    let mut event = database_event_payloads(&change, &manifest.functions[0])
        .remove(0)
        .1;
    event["id"] = json!("00000000-0000-4000-8000-000000000000");
    let overhead = serde_json::to_vec(&event).unwrap().len();
    let padding = fireemu_adapter_functions::protocol::MAX_FRAME_BYTES - overhead;
    let DatabaseChangeData::References(ref mut references) = change.data else {
        unreachable!()
    };
    references[0].after = json!("x".repeat(padding));
    event = database_event_payloads(&change, &manifest.functions[0])
        .remove(0)
        .1;
    event["id"] = json!("00000000-0000-4000-8000-000000000000");
    assert_eq!(
        serde_json::to_vec(&event).unwrap().len(),
        fireemu_adapter_functions::protocol::MAX_FRAME_BYTES
    );
    let dropped = dropped_fanouts(&runtime);
    drop(runtime.reserve_database_events(&change).unwrap());
    assert_eq!(dropped_fanouts(&runtime), dropped + 1);
    assert_eq!(
        runtime.source_event_accounting().unwrap().reserved_records,
        0
    );
    runtime.shutdown().await;
}

#[tokio::test]
async fn retry_reuses_immutable_source_snapshot_and_its_causal_parent() {
    use fireemu_adapter_functions::events::DatabaseReferenceChange;
    let (runtime, clock) = runtime(true).await;
    let mut change = commit();
    change.data = DatabaseChangeData::References(vec![DatabaseReferenceChange {
        reference: "/users/a".to_owned(),
        before: json!({"old":1}),
        after: json!({"new":2}),
    }]);
    runtime.reserve_database_events(&change).unwrap().publish();
    change.data = DatabaseChangeData::References(Vec::new());
    let dispatch = tokio::spawn(runtime.clone().dispatch_loop());
    tokio::time::timeout(Duration::from_secs(5), async {
        while runtime.history().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(30))
        .unwrap();
    runtime.on_clock_changed();
    runtime.await_idle(Duration::from_secs(5)).await.unwrap();
    assert_eq!(runtime.history().len(), 2);
    let logs = runtime.runner().logs_since(None);
    let events: Vec<_> = logs
        .lines
        .iter()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line.message()).ok())
        .collect();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], events[1]);
    assert_eq!(events[0]["data"]["data"], json!({"old":1}));
    assert_eq!(events[0]["data"]["delta"], json!({"old":null,"new":2}));
    let status = runtime.status();
    let entries = status["causality"]["events"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["parent"], "database-commit:app-first@5");
    runtime.shutdown().await;
    dispatch.await.unwrap();
}

#[tokio::test]
async fn the_event_id_the_function_receives_follows_the_profile_shape() {
    use fireemu_adapter_functions::events::DatabaseEventShape;
    for (shape, production) in [
        (DatabaseEventShape::Production, true),
        (DatabaseEventShape::Official, false),
    ] {
        let (runtime, _) = runtime_shaped(false, shape).await;
        runtime
            .reserve_database_events(&commit())
            .unwrap()
            .publish();
        let dispatch = tokio::spawn(runtime.clone().dispatch_loop());
        runtime.await_idle(Duration::from_secs(5)).await.unwrap();
        let logs = runtime.runner().logs_since(None);
        let events: Vec<_> = logs
            .lines
            .iter()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line.message()).ok())
            .collect();
        assert_eq!(events.len(), 2, "{shape:?}");
        for event in &events {
            let id = event["id"].as_str().unwrap();
            if production {
                assert_eq!(id.len(), 28, "{id}");
                assert!(id.ends_with('='), "{id}");
                assert_eq!(
                    event["source"].as_str().unwrap().split('/').nth(4),
                    Some("_")
                );
                assert!(event.get("datacontenttype").is_none());
            } else {
                assert_eq!(id.len(), 36, "{id}");
                assert_eq!(id.matches('-').count(), 4, "{id}");
                assert_eq!(event["datacontenttype"], "application/json");
            }
        }
        assert_ne!(events[0]["id"], events[1]["id"]);
        runtime.shutdown().await;
        dispatch.await.unwrap();
    }
}
