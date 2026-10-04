//! Object versioning: a versioned bucket keeps the generation an overwrite or a plain delete
//! replaces, as a noncurrent version, and announces it with an Archived event. The order of the
//! Archived and Finalized events of one overwrite, and whether a plain delete of a live object
//! also announces a Deleted event, are unrecorded (the FE recording decides); the tests state
//! the shapes the store implements, which are the most likely ones.

use std::collections::BTreeMap;

use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{
    NewMetadata, ObjectMetadata, Precondition, StorageError, StorageEvent, StorageState,
};
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;

fn t(n: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_000_000 + n)
}
fn bucket() -> BucketName {
    BucketName::try_new("demo-app.appspot.com").unwrap()
}
fn name(s: &str) -> ObjectName {
    ObjectName::try_new(s).unwrap()
}
fn put(store: &mut StorageState, b: &BucketName, n: &str, data: &str, at: i64) -> ObjectMetadata {
    store
        .put(
            b,
            &name(n),
            data.as_bytes().to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            t(at),
        )
        .unwrap()
}
fn kinds(events: &[StorageEvent]) -> Vec<(&'static str, u64)> {
    events
        .iter()
        .map(|event| match event {
            StorageEvent::Finalized(m) => ("finalized", m.generation),
            StorageEvent::Deleted(m) => ("deleted", m.generation),
            StorageEvent::MetadataUpdated(m) => ("metadata", m.generation),
            StorageEvent::Archived { object, .. } => ("archived", object.generation),
        })
        .collect()
}

#[test]
fn a_bucket_is_unversioned_until_it_is_configured() {
    let mut store = StorageState::new(1);
    let b = bucket();
    assert!(!store.versioning(&b));
    store.set_versioning(&b, true);
    assert!(store.versioning(&b));
    assert!(!store.versioning(&BucketName::try_new("other-bucket").unwrap()));
    store.set_versioning(&b, false);
    assert!(!store.versioning(&b));
}

#[test]
fn an_overwrite_in_a_versioned_bucket_keeps_the_old_generation_and_announces_it() {
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    let first = put(&mut store, &b, "o.txt", "before", 1);
    let _ = store.drain_events();
    let second = put(&mut store, &b, "o.txt", "updated", 2);
    assert_ne!(first.generation, second.generation);
    assert_eq!(
        store.get(&b, &name("o.txt")).unwrap().generation,
        second.generation
    );
    let noncurrent = store.noncurrent_versions(&b, &name("o.txt"));
    assert_eq!(noncurrent.len(), 1);
    assert_eq!(noncurrent[0].object.generation, first.generation);
    assert_eq!(noncurrent[0].time_deleted, t(2));
    assert_eq!(store.bytes(&noncurrent[0].object), b"before");
    // Archived (the old generation, at the overwrite time) before Finalized (the new one).
    let events = store.drain_events();
    assert_eq!(
        kinds(&events),
        vec![
            ("archived", first.generation),
            ("finalized", second.generation)
        ]
    );
    match &events[0] {
        StorageEvent::Archived { time_deleted, .. } => assert_eq!(*time_deleted, t(2)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_overwrite_in_an_unversioned_bucket_keeps_nothing() {
    let mut store = StorageState::new(1);
    let b = bucket();
    put(&mut store, &b, "o.txt", "before", 1);
    let _ = store.drain_events();
    let second = put(&mut store, &b, "o.txt", "updated", 2);
    assert!(store.noncurrent_versions(&b, &name("o.txt")).is_empty());
    assert_eq!(
        kinds(&store.drain_events()),
        vec![("finalized", second.generation)]
    );
    assert_eq!(store.retained_blob_bytes(), "updated".len() as u64);
}

#[test]
fn deleting_the_live_object_of_a_versioned_bucket_archives_it_and_announces_no_delete() {
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    let live = put(&mut store, &b, "o.txt", "data", 1);
    let _ = store.drain_events();
    store
        .delete(&b, &name("o.txt"), Precondition::default(), t(2))
        .unwrap();
    assert!(store.get(&b, &name("o.txt")).is_none());
    let noncurrent = store.noncurrent_versions(&b, &name("o.txt"));
    assert_eq!(noncurrent.len(), 1);
    assert_eq!(noncurrent[0].object.generation, live.generation);
    assert_eq!(
        kinds(&store.drain_events()),
        vec![("archived", live.generation)]
    );
    assert_eq!(store.retained_blob_bytes(), 4);
}

#[test]
fn deleting_a_generation_removes_it_for_good_and_announces_a_delete() {
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    let first = put(&mut store, &b, "o.txt", "one", 1);
    let second = put(&mut store, &b, "o.txt", "two", 2);
    let _ = store.drain_events();
    // A noncurrent generation.
    let deleted = store
        .delete_generation(
            &b,
            &name("o.txt"),
            first.generation,
            Precondition::default(),
        )
        .unwrap();
    assert_eq!(deleted.generation, first.generation);
    assert!(store.noncurrent_versions(&b, &name("o.txt")).is_empty());
    assert_eq!(
        kinds(&store.drain_events()),
        vec![("deleted", first.generation)]
    );
    assert_eq!(store.retained_blob_bytes(), 3, "only the live blob is left");
    // The live generation, by number: permanent, no archive.
    store
        .delete_generation(
            &b,
            &name("o.txt"),
            second.generation,
            Precondition::default(),
        )
        .unwrap();
    assert!(store.get(&b, &name("o.txt")).is_none());
    assert!(store.noncurrent_versions(&b, &name("o.txt")).is_empty());
    assert_eq!(
        kinds(&store.drain_events()),
        vec![("deleted", second.generation)]
    );
    assert_eq!(store.retained_blob_bytes(), 0);
    // An unknown generation is not found, and nothing changes.
    assert_eq!(
        store.delete_generation(&b, &name("o.txt"), 999, Precondition::default()),
        Err(StorageError::NotFound)
    );
    assert!(store.drain_events().is_empty());
}

#[test]
fn a_generation_lookup_finds_live_and_noncurrent_versions() {
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    let first = put(&mut store, &b, "o.txt", "one", 1);
    let second = put(&mut store, &b, "o.txt", "two", 2);
    let (live, time_deleted) = store
        .generation(&b, &name("o.txt"), second.generation)
        .unwrap();
    assert_eq!((live.generation, time_deleted), (second.generation, None));
    let (old, time_deleted) = store
        .generation(&b, &name("o.txt"), first.generation)
        .unwrap();
    assert_eq!(
        (old.generation, time_deleted),
        (first.generation, Some(t(2)))
    );
    assert!(store.generation(&b, &name("o.txt"), 12345).is_none());
    assert!(store
        .generation(&b, &name("other.txt"), first.generation)
        .is_none());
}

#[test]
fn versions_are_listed_by_name_then_generation_with_the_live_one_marked() {
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    let a1 = put(&mut store, &b, "a.txt", "1", 1);
    let a2 = put(&mut store, &b, "a.txt", "22", 2);
    let c1 = put(&mut store, &b, "c.txt", "3", 3);
    put(
        &mut store,
        &BucketName::try_new("other-bucket").unwrap(),
        "a.txt",
        "x",
        4,
    );
    let listed: Vec<(String, u64, bool)> = store
        .list_versions(&b, "")
        .into_iter()
        .map(|v| {
            (
                v.object.name.as_str().to_owned(),
                v.object.generation,
                v.time_deleted.is_none(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        vec![
            ("a.txt".to_owned(), a1.generation, false),
            ("a.txt".to_owned(), a2.generation, true),
            ("c.txt".to_owned(), c1.generation, true),
        ]
    );
    assert_eq!(
        store.list_versions(&b, "c").len(),
        1,
        "a prefix filters by name"
    );
}

#[test]
fn turning_versioning_off_keeps_the_existing_versions_and_stops_archiving() {
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    let first = put(&mut store, &b, "o.txt", "one", 1);
    put(&mut store, &b, "o.txt", "two", 2);
    store.set_versioning(&b, false);
    let third = put(&mut store, &b, "o.txt", "three", 3);
    let versions = store.noncurrent_versions(&b, &name("o.txt"));
    assert_eq!(
        versions.len(),
        1,
        "the version kept before is still there, no new one"
    );
    assert_eq!(versions[0].object.generation, first.generation);
    assert_eq!(
        store.get(&b, &name("o.txt")).unwrap().generation,
        third.generation
    );
    assert_eq!(
        store.retained_blob_bytes(),
        ("one".len() + "three".len()) as u64
    );
}

#[test]
fn noncurrent_bytes_count_toward_the_stored_bytes_limit() {
    for versioned in [true, false] {
        let mut store = StorageState::new(1);
        store.set_stored_bytes_limit(Some(10));
        let b = bucket();
        store.set_versioning(&b, versioned);
        put(&mut store, &b, "o.txt", "123456", 1);
        let overwrite = store.put(
            &b,
            &name("o.txt"),
            b"abcdef".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            t(2),
        );
        if versioned {
            assert_eq!(overwrite.err(), Some(StorageError::StoredBytesLimit));
            assert_eq!(
                store.retained_blob_bytes(),
                6,
                "a refused write changes nothing"
            );
            assert!(store.noncurrent_versions(&b, &name("o.txt")).is_empty());
        } else {
            overwrite.unwrap();
            assert_eq!(
                store.retained_blob_bytes(),
                6,
                "a replacement is charged its difference"
            );
        }
    }
}

#[test]
fn copy_and_resumable_finalize_archive_the_destination_like_a_put() {
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    let src = put(&mut store, &b, "src.txt", "source", 1);
    let dst1 = put(&mut store, &b, "dst.txt", "old", 2);
    let _ = store.drain_events();
    let dst2 = store
        .copy(
            (&b, &name("src.txt")),
            (&b, &name("dst.txt")),
            None,
            Precondition::default(),
            t(3),
        )
        .unwrap();
    assert_eq!(
        kinds(&store.drain_events()),
        vec![
            ("archived", dst1.generation),
            ("finalized", dst2.generation)
        ]
    );
    assert_eq!(store.noncurrent_versions(&b, &name("dst.txt")).len(), 1);
    assert!(
        store.noncurrent_versions(&b, &name("src.txt")).is_empty(),
        "the source is untouched"
    );
    assert_eq!(
        store.get(&b, &name("src.txt")).unwrap().generation,
        src.generation
    );

    let id = store
        .begin_upload(
            &b,
            &name("dst.txt"),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(4),
        )
        .unwrap();
    store.append_upload(&id, 0, b"resumed", t(4)).unwrap();
    let dst3 = store.finalize_upload(&id, t(5)).unwrap();
    assert_eq!(
        kinds(&store.drain_events()),
        vec![
            ("archived", dst2.generation),
            ("finalized", dst3.generation)
        ]
    );
    assert_eq!(store.noncurrent_versions(&b, &name("dst.txt")).len(), 2);
}

#[test]
fn a_refused_admission_leaves_the_store_and_its_versions_untouched() {
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    let first = put(&mut store, &b, "o.txt", "one", 1);
    let _ = store.drain_events();
    let mut seen = Vec::new();
    let refused = store.put_with_admission(
        &b,
        &name("o.txt"),
        b"two".to_vec(),
        NewMetadata::default(),
        Precondition::default(),
        t(2),
        |events: &[StorageEvent]| -> Result<(), StorageError> {
            seen = kinds(events);
            Err(StorageError::StoredBytesLimit)
        },
    );
    assert!(refused.is_err());
    // The admission saw the whole batch, Archived first.
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], ("archived", first.generation));
    assert_eq!(seen[1].0, "finalized");
    assert_eq!(
        store.get(&b, &name("o.txt")).unwrap().generation,
        first.generation
    );
    assert!(store.noncurrent_versions(&b, &name("o.txt")).is_empty());
    assert!(store.drain_events().is_empty());
    assert_eq!(store.retained_blob_bytes(), 3);
}

#[test]
fn a_bucket_reset_drops_versions_and_configuration_and_a_snapshot_restores_them() {
    let mut store = StorageState::new(1);
    let b = bucket();
    let other = BucketName::try_new("other-bucket").unwrap();
    store.set_versioning(&b, true);
    store.set_versioning(&other, true);
    let first = put(&mut store, &b, "o.txt", "one", 1);
    put(&mut store, &b, "o.txt", "two", 2);
    put(&mut store, &other, "x.txt", "keep", 3);
    let snapshot = store.capture_buckets(|name| name == b.as_str());
    assert_eq!(snapshot.noncurrent_versions(&b, &name("o.txt")).len(), 1);
    assert!(snapshot.versioning(&b));
    assert_eq!(store.remove_bucket(&b), 1);
    assert!(store.noncurrent_versions(&b, &name("o.txt")).is_empty());
    assert!(
        !store.versioning(&b),
        "a reset forgets the configuration too"
    );
    assert!(store.versioning(&other), "another bucket is untouched");
    assert_eq!(store.retained_blob_bytes(), "keep".len() as u64);
    store.restore_buckets(|name| name == b.as_str(), &snapshot);
    assert!(store.versioning(&b));
    let restored = store.noncurrent_versions(&b, &name("o.txt"));
    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].object.generation, first.generation);
    assert_eq!(store.bytes(&restored[0].object), b"one");
    assert_eq!(
        store.retained_blob_bytes(),
        ("keep".len() + "one".len() + "two".len()) as u64
    );
    store.clear();
    assert!(store.noncurrent_versions(&b, &name("o.txt")).is_empty());
    assert!(!store.versioning(&b) && !store.versioning(&other));
    assert_eq!(store.retained_blob_bytes(), 0);
}

// ---- a reference model of one versioned and one unversioned bucket ----

#[derive(Debug, Clone)]
enum Op {
    Put { name: u8, size: u8 },
    Delete { name: u8 },
    DeleteGeneration { name: u8, nth: u8 },
    Versioning(bool),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0u8..3, 1u8..6).prop_map(|(name, size)| Op::Put { name, size }),
        2 => (0u8..3).prop_map(|name| Op::Delete { name }),
        2 => (0u8..3, 0u8..4).prop_map(|(name, nth)| Op::DeleteGeneration { name, nth }),
        1 => any::<bool>().prop_map(Op::Versioning),
    ]
}

#[derive(Default)]
struct Model {
    versioned: bool,
    live: BTreeMap<String, (u64, usize)>,
    noncurrent: BTreeMap<String, Vec<(u64, usize)>>,
}

proptest! {
    /// Any sequence of writes, deletes, deletes by generation and configuration changes leaves the
    /// store equal to a plain model: the live generation and size of every name, its noncurrent
    /// versions in generation order, the retained bytes (live plus noncurrent), unique increasing
    /// generations, and the events of each step.
    #[test]
    fn the_store_follows_a_reference_model_of_versioning(ops in proptest::collection::vec(op(), 1..40)) {
        let mut store = StorageState::new(7);
        let b = bucket();
        let mut model = Model::default();
        let mut last_generation = 0u64;
        for (step, operation) in ops.into_iter().enumerate() {
            let now = t(i64::try_from(step).unwrap() + 1);
            let _ = store.drain_events();
            let mut expected: Vec<(&'static str, u64)> = Vec::new();
            match operation {
                Op::Put { name: n, size } => {
                    let key = format!("o{n}");
                    let data = "x".repeat(usize::from(size));
                    let meta = store.put(&b, &name(&key), data.into_bytes(), NewMetadata::default(), Precondition::default(), now).unwrap();
                    prop_assert!(meta.generation > last_generation, "generations strictly increase");
                    last_generation = meta.generation;
                    if let Some(old) = model.live.insert(key.clone(), (meta.generation, usize::from(size))) {
                        if model.versioned {
                            model.noncurrent.entry(key).or_default().push(old);
                            expected.push(("archived", old.0));
                        }
                    }
                    expected.push(("finalized", meta.generation));
                }
                Op::Delete { name: n } => {
                    let key = format!("o{n}");
                    let result = store.delete(&b, &name(&key), Precondition::default(), now);
                    match model.live.remove(&key) {
                        None => prop_assert_eq!(result.err(), Some(StorageError::NotFound)),
                        Some(old) => {
                            prop_assert!(result.is_ok());
                            if model.versioned {
                                model.noncurrent.entry(key).or_default().push(old);
                                expected.push(("archived", old.0));
                            } else {
                                expected.push(("deleted", old.0));
                            }
                        }
                    }
                }
                Op::DeleteGeneration { name: n, nth } => {
                    let key = format!("o{n}");
                    // Choose the nth known generation of the name (noncurrent first, then live).
                    let mut known: Vec<(u64, bool)> = model.noncurrent.get(&key).into_iter().flatten().map(|v| (v.0, false)).collect();
                    if let Some(live) = model.live.get(&key) {
                        known.push((live.0, true));
                    }
                    if known.is_empty() {
                        prop_assert_eq!(
                            store.delete_generation(&b, &name(&key), 424_242, Precondition::default()).err(),
                            Some(StorageError::NotFound)
                        );
                    } else {
                        let (generation, is_live) = known[usize::from(nth) % known.len()];
                        prop_assert!(store.delete_generation(&b, &name(&key), generation, Precondition::default()).is_ok());
                        if is_live {
                            model.live.remove(&key);
                        } else if let Some(list) = model.noncurrent.get_mut(&key) {
                            list.retain(|v| v.0 != generation);
                        }
                        expected.push(("deleted", generation));
                    }
                }
                Op::Versioning(enabled) => {
                    store.set_versioning(&b, enabled);
                    model.versioned = enabled;
                }
            }
            prop_assert_eq!(kinds(&store.drain_events()), expected);
            // Observable state equals the model.
            let mut bytes = 0usize;
            for n in 0u8..3 {
                let key = format!("o{n}");
                let live = store.get(&b, &name(&key)).map(|m| (m.generation, usize::try_from(m.size).unwrap()));
                prop_assert_eq!(live, model.live.get(&key).copied());
                let kept: Vec<(u64, usize)> = store
                    .noncurrent_versions(&b, &name(&key))
                    .iter()
                    .map(|v| (v.object.generation, usize::try_from(v.object.size).unwrap()))
                    .collect();
                let mut want = model.noncurrent.get(&key).cloned().unwrap_or_default();
                want.sort_unstable();
                prop_assert_eq!(&kept, &want);
                bytes += want.iter().map(|v| v.1).sum::<usize>() + model.live.get(&key).map_or(0, |v| v.1);
            }
            prop_assert_eq!(store.retained_blob_bytes(), bytes as u64, "retained bytes are live plus noncurrent");
            prop_assert_eq!(store.versioning(&b), model.versioned);
        }
    }
}

#[test]
fn the_resource_gauges_count_noncurrent_bytes_and_a_bucket_that_holds_only_versions() {
    use fireemu_core_types::resources::RootBudget;
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    put(&mut store, &b, "o.txt", "1234", 1);
    put(&mut store, &b, "o.txt", "12345678", 2);
    let gauge = |store: &StorageState, name: &str| {
        store
            .resources(|_| true, RootBudget::DEFAULT)
            .gauges
            .iter()
            .find(|g| g.id == name)
            .map(|g| g.current)
            .unwrap()
    };
    assert_eq!(gauge(&store, "objects.count"), 1);
    assert_eq!(gauge(&store, "objects.noncurrent"), 1);
    assert_eq!(
        gauge(&store, "objects.bytes"),
        12,
        "live and noncurrent data"
    );
    store
        .delete(&b, &name("o.txt"), Precondition::default(), t(3))
        .unwrap();
    assert_eq!(gauge(&store, "objects.count"), 0);
    assert_eq!(gauge(&store, "objects.noncurrent"), 2);
    assert_eq!(gauge(&store, "objects.bytes"), 12);
    let roots = store.resources(|_| true, RootBudget::DEFAULT).roots;
    assert_eq!(roots.total, 1, "the bucket is still reported: {roots:?}");
}
