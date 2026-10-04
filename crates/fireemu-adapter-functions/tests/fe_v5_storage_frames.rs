//! The Storage events of one overwrite and of the deletes of a versioned bucket, against the
//! shapes the FE v5 production recording delivered (run `functions-events-formal-20261004T182904Z`,
//! frames of `storageFinalized`, `storageDeleted` and `storageArchived`, v1 and v2, two passes).
//! Only structure is compared: key sets, the form of the time fields and which instants coincide.
//! No identifier of the recording is copied.

use fireemu_adapter_functions::events::{storage_event, storage_event_parts};
use fireemu_core_functions::manifest::ObjectEvent;
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{
    NewMetadata, ObjectMetadata, Precondition, StorageEvent, StorageState,
};
use fireemu_core_types::time::LogicalInstant;
use serde_json::Value;

/// The keys of the `data` of a recorded Finalized, Deleted (live generation) and MetadataUpdated
/// payload (the last adds `metadata`).
const FINALIZED_KEYS: [&str; 17] = [
    "bucket",
    "contentType",
    "crc32c",
    "etag",
    "generation",
    "id",
    "kind",
    "md5Hash",
    "mediaLink",
    "metageneration",
    "name",
    "selfLink",
    "size",
    "storageClass",
    "timeCreated",
    "timeStorageClassUpdated",
    "updated",
];

fn t(n: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_000_000 + n)
}

fn put(store: &mut StorageState, at: i64) -> ObjectMetadata {
    store
        .put(
            &BucketName::try_new("demo-app.appspot.com").unwrap(),
            &ObjectName::try_new("fe-events/o.txt").unwrap(),
            b"x".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            t(at),
        )
        .unwrap()
}

/// The payload the runtime builds for a core event admitted at `admitted`.
fn payload(event: &StorageEvent, admitted: LogicalInstant) -> Value {
    let parts = storage_event_parts(event);
    storage_event(
        "7-1",
        parts.kind,
        parts.object,
        parts.at.unwrap_or(admitted),
        parts.time_deleted,
    )
}

fn keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value["data"].as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

fn expected(extra: &[&str]) -> Vec<String> {
    let mut all: Vec<String> = FINALIZED_KEYS
        .iter()
        .chain(extra)
        .map(|k| (*k).to_owned())
        .collect();
    all.sort();
    all
}

fn millis_form(value: &Value) -> bool {
    let s = value.as_str().unwrap();
    // 2026-10-04T18:36:46.701Z
    s.len() == 24 && s.ends_with('Z') && s.as_bytes()[19] == b'.'
}

#[test]
fn an_overwrite_in_a_versioned_bucket_delivers_the_recorded_archived_and_finalized_shapes() {
    let mut store = StorageState::new(1);
    let bucket = BucketName::try_new("demo-app.appspot.com").unwrap();
    store.set_versioning(&bucket, true);
    put(&mut store, 1);
    let _ = store.drain_events();
    put(&mut store, 5);
    let events = store.drain_events();
    // Observed order: Finalized, then Archived (4 of 4 deliveries).
    assert!(
        matches!(
            events.as_slice(),
            [StorageEvent::Finalized(_), StorageEvent::Archived { .. }]
        ),
        "{events:?}"
    );
    let finalized = payload(&events[0], t(6));
    let archived = payload(&events[1], t(6));
    assert_eq!(keys(&finalized), expected(&[]));
    assert_eq!(keys(&archived), expected(&["timeDeleted"]));
    // The Archived data is the noncurrent generation as it was (metageneration 1, `updated`
    // unchanged) and its `timeDeleted` is the instant of the overwrite, to the millisecond.
    assert!(millis_form(&archived["data"]["timeDeleted"]));
    assert_eq!(
        archived["data"]["timeDeleted"],
        finalized["data"]["timeCreated"]
    );
    // The Archived `time` is that same instant to the microsecond, as the Finalized one.
    assert_eq!(archived["time"], finalized["time"]);
}

#[test]
fn deleting_a_noncurrent_generation_delivers_time_deleted_and_the_deletion_instant() {
    let mut store = StorageState::new(1);
    let bucket = BucketName::try_new("demo-app.appspot.com").unwrap();
    store.set_versioning(&bucket, true);
    let first = put(&mut store, 1);
    let second = put(&mut store, 5);
    let _ = store.drain_events();
    let name = ObjectName::try_new("fe-events/o.txt").unwrap();
    store
        .delete_generation(&bucket, &name, first.generation, Precondition::default())
        .unwrap();
    let noncurrent = payload(&store.drain_events()[0], t(30));
    // RECORDED: the Deleted payload of a noncurrent generation carries `timeDeleted`, the archive
    // instant; its CloudEvent `time` is the deletion instant, not that one.
    assert_eq!(keys(&noncurrent), expected(&["timeDeleted"]));
    let overwrite = storage_event("7-1", ObjectEvent::Finalized, &second, t(30), None);
    assert_eq!(
        noncurrent["data"]["timeDeleted"],
        overwrite["data"]["timeCreated"]
    );
    assert!(millis_form(&noncurrent["data"]["timeDeleted"]));
    assert_ne!(noncurrent["time"], noncurrent["data"]["timeDeleted"]);
    // The live generation deleted by number has no `timeDeleted`.
    store
        .delete_generation(&bucket, &name, second.generation, Precondition::default())
        .unwrap();
    let live = payload(&store.drain_events()[0], t(31));
    assert_eq!(keys(&live), expected(&[]));
}

#[test]
fn an_overwrite_in_an_unversioned_bucket_delivers_deleted_at_the_replacement_instant() {
    let mut store = StorageState::new(1);
    put(&mut store, 1);
    let _ = store.drain_events();
    put(&mut store, 5);
    let events = store.drain_events();
    // Observed order in 3 of 4 deliveries: Deleted, then Finalized.
    assert!(
        matches!(
            events.as_slice(),
            [StorageEvent::Deleted { .. }, StorageEvent::Finalized(_)]
        ),
        "{events:?}"
    );
    // Admitted much later than the overwrite: the Deleted `time` still is the replacement's
    // creation instant, the same microsecond as the Finalized one (recorded); no `timeDeleted`.
    let deleted = payload(&events[0], t(60));
    let finalized = payload(&events[1], t(60));
    assert_eq!(keys(&deleted), expected(&[]));
    assert_eq!(deleted["time"], finalized["time"]);
}
