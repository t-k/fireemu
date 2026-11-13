use super::{FunctionsConfig, FunctionsRuntime};
use crate::manifest_json::parse_manifest;
use crate::runner::{Runner, SpawnSpec};
use fireemu_core_functions::manifest::{ObjectEvent, Trigger};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{NewMetadata, Precondition, StorageEvent, StorageState};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const START: i64 = 1_788_004_860;

/// A runtime whose manifest has one Storage function per event kind on the default bucket.
async fn runtime() -> (Arc<FunctionsRuntime>, Arc<Mutex<VirtualClock>>) {
    let spec = SpawnSpec {
        command: vec![
            "python3".to_owned(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fake_runner.py").to_owned(),
        ],
        cwd: None,
        env: Vec::new(),
        hello_timeout: Duration::from_secs(60),
    };
    let runner = Runner::spawn_spec(&spec).await.unwrap();
    let mut manifest = parse_manifest(runner.hello().manifest.as_ref().unwrap()).unwrap();
    let template = manifest.get("echo").unwrap().clone();
    manifest
        .functions
        .retain(|f| !matches!(f.trigger, Trigger::Storage { .. }));
    for (name, event) in [
        ("onFinalized", ObjectEvent::Finalized),
        ("onDeleted", ObjectEvent::Deleted),
        ("onArchived", ObjectEvent::Archived),
    ] {
        let mut function = template.clone();
        function.name = name.to_owned();
        function.entry_point = name.to_owned();
        function.trigger = Trigger::Storage {
            event,
            bucket: None,
        };
        manifest.functions.push(function);
    }
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(START),
    )));
    let runtime = FunctionsRuntime::new(
        manifest,
        FunctionsConfig {
            retry_attempts: 1,
            functions_host: Some("127.0.0.1:5001".to_owned()),
            ..FunctionsConfig::for_tests(1, "test-secret".to_owned())
        },
        clock.clone(),
        Arc::new(runner),
        Some(spec),
    );
    (runtime, clock)
}

fn put(store: &mut StorageState, at: i64) -> fireemu_core_storage::store::ObjectMetadata {
    store
        .put(
            &BucketName::try_new("demo-app.appspot.com").unwrap(),
            &ObjectName::try_new("o.txt").unwrap(),
            b"x".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            LogicalInstant::from_unix_seconds(START + at),
        )
        .unwrap()
}

/// The payloads the runtime built for `event`, by event type, without publishing them (a
/// published delivery may already have been taken by the runner).
fn payloads(runtime: &Arc<FunctionsRuntime>, event: &StorageEvent) -> Vec<(String, Value)> {
    // Dropping the reservation unpublished gives its capacity back.
    let reservation = runtime.reserve_storage_event(event).unwrap();
    reservation
        .deliveries
        .as_ref()
        .unwrap()
        .iter()
        .map(|d| {
            (
                d.event.event_type.as_str().to_owned(),
                (*d.payload.payload).clone(),
            )
        })
        .collect()
}

/// An unversioned overwrite announces the replaced generation as deleted, stamped with the
/// creation instant of the new generation (RECORDED, FE v5: the same microsecond as the
/// Finalized event of the new generation). The runtime admits the events much later, so a
/// payload stamped with the admission instant would differ.
#[tokio::test]
async fn the_deleted_event_of_an_overwrite_takes_the_replacement_instant_not_the_admission_instant()
{
    let (runtime, clock) = runtime().await;
    let mut store = StorageState::new(1);
    put(&mut store, 1);
    let _ = store.drain_events();
    put(&mut store, 5);
    let events = store.drain_events();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(600))
        .unwrap();
    assert!(matches!(
        events.as_slice(),
        [StorageEvent::Deleted { .. }, StorageEvent::Finalized(_)]
    ));
    let deleted = payloads(&runtime, &events[0]);
    let finalized = payloads(&runtime, &events[1]);
    assert_eq!(deleted.len(), 1, "{deleted:?}");
    assert_eq!(finalized.len(), 1, "{finalized:?}");
    assert_eq!(deleted[0].0, "google.cloud.storage.object.v1.deleted");
    assert_eq!(deleted[0].1["time"], finalized[0].1["time"]);
    // The admission instant is 600 s later than the replacement: it is not what was stamped.
    assert!(
        !deleted[0].1["time"]
            .as_str()
            .unwrap()
            .starts_with("2026-08-29T12:11"),
        "{}",
        deleted[0].1["time"]
    );
    // The Deleted event of an overwrite carries no `timeDeleted`.
    assert!(deleted[0].1["data"].get("timeDeleted").is_none());
    runtime.shutdown().await;
}

/// The Archived event and the Deleted event of a noncurrent generation carry the instant the
/// generation stopped being live as `timeDeleted`; the Archived `time` is that instant too,
/// and the noncurrent Deleted `time` is the admission instant, as recorded.
#[tokio::test]
async fn archived_and_noncurrent_deleted_events_carry_time_deleted_from_the_core_event() {
    let (runtime, clock) = runtime().await;
    let mut store = StorageState::new(1);
    let bucket = BucketName::try_new("demo-app.appspot.com").unwrap();
    store.set_versioning(&bucket, true);
    let first = put(&mut store, 1);
    let second = put(&mut store, 5);
    let events = store.drain_events();
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(600))
        .unwrap();
    let archived_event = events
        .iter()
        .find(|e| matches!(e, StorageEvent::Archived { .. }))
        .unwrap();
    let archived = payloads(&runtime, archived_event);
    assert_eq!(archived.len(), 1, "{archived:?}");
    assert_eq!(
        archived[0].1["data"]["generation"],
        first.generation.to_string()
    );
    let time_deleted = archived[0].1["data"]["timeDeleted"].as_str().unwrap();
    assert!(
        time_deleted.starts_with("2026-08-29T12:01:05"),
        "{time_deleted}"
    );
    assert_eq!(
        archived[0].1["time"]
            .as_str()
            .unwrap()
            .trim_end_matches('Z')[..19],
        time_deleted.trim_end_matches('Z')[..19]
    );
    // Deleting the noncurrent generation by number.
    let name = ObjectName::try_new("o.txt").unwrap();
    store
        .delete_generation(&bucket, &name, first.generation, Precondition::default())
        .unwrap();
    let deleted_event = store.drain_events().remove(0);
    let deleted = payloads(&runtime, &deleted_event);
    assert_eq!(deleted.len(), 1, "{deleted:?}");
    assert_eq!(
        deleted[0].1["data"]["timeDeleted"],
        archived[0].1["data"]["timeDeleted"]
    );
    assert!(
        deleted[0].1["time"]
            .as_str()
            .unwrap()
            .starts_with("2026-08-29T12:11"),
        "the deletion instant is the admission instant: {}",
        deleted[0].1["time"]
    );
    let _ = second;
    runtime.shutdown().await;
}
