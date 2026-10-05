//! Object versioning: a versioned bucket keeps the generation an overwrite or a plain delete
//! replaces, as a noncurrent version, and announces it with an Archived event. The order of the
//! Archived and Finalized events of one overwrite, and whether a plain delete of a live object
//! also announces a Deleted event, are unrecorded (the FE recording decides); the tests state
//! the shapes the store implements, which are the most likely ones.

use std::collections::BTreeMap;

use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{
    MetadataPatch, NewMetadata, ObjectMetadata, Precondition, StorageError, StorageEvent,
    StorageState, VersionsCursor,
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
            StorageEvent::Deleted { object, .. } => ("deleted", object.generation),
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
    // OBSERVED ORDER (FE v5, 4 of 4 deliveries): Finalized (the new generation) before Archived
    // (the old one, at the overwrite time).
    let events = store.drain_events();
    assert_eq!(
        kinds(&events),
        vec![
            ("finalized", second.generation),
            ("archived", first.generation)
        ]
    );
    match &events[1] {
        StorageEvent::Archived { time_deleted, .. } => assert_eq!(*time_deleted, t(2)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_overwrite_in_an_unversioned_bucket_keeps_nothing() {
    let mut store = StorageState::new(1);
    let b = bucket();
    let first = put(&mut store, &b, "o.txt", "before", 1);
    let _ = store.drain_events();
    let second = put(&mut store, &b, "o.txt", "updated", 2);
    assert!(store.noncurrent_versions(&b, &name("o.txt")).is_empty());
    // RECORDED (FE v5, both passes): production announces the replaced generation as deleted
    // ("This includes objects that are overwritten",
    // https://firebase.google.com/docs/functions/gcp-storage-events), and delivered Deleted before
    // Finalized in 3 of 4 observations (the order is not guaranteed).
    assert_eq!(
        kinds(&store.drain_events()),
        vec![
            ("deleted", first.generation),
            ("finalized", second.generation)
        ]
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
    // Another bucket's versions, live and noncurrent, never leak into this bucket's listing.
    let other = BucketName::try_new("other-bucket").unwrap();
    store.set_versioning(&other, true);
    put(&mut store, &other, "a.txt", "x", 4);
    put(&mut store, &other, "a.txt", "y", 5);
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
            ("finalized", dst2.generation),
            ("archived", dst1.generation)
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
            ("finalized", dst3.generation),
            ("archived", dst2.generation)
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
    // The admission saw the whole batch, Finalized first (the observed order).
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].0, "finalized");
    assert_eq!(seen[1], ("archived", first.generation));
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
                    match model.live.insert(key.clone(), (meta.generation, usize::from(size))) {
                        // Observed order: Finalized, then Archived.
                        Some(old) if model.versioned => {
                            model.noncurrent.entry(key).or_default().push(old);
                            expected.push(("finalized", meta.generation));
                            expected.push(("archived", old.0));
                        }
                        // Observed order (3 of 4): Deleted, then Finalized.
                        Some(old) => {
                            expected.push(("deleted", old.0));
                            expected.push(("finalized", meta.generation));
                        }
                        None => expected.push(("finalized", meta.generation)),
                    }
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

#[test]
fn a_noncurrent_generation_can_be_the_source_of_a_copy() {
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    let one = put(&mut store, &b, "o.txt", "one", 1);
    let two = put(&mut store, &b, "o.txt", "two", 2);
    let _ = store.drain_events();
    let (restored, ()) = store
        .copy_generation_with_admission(
            (&b, &name("o.txt"), Some(one.generation)),
            (&b, &name("o.txt")),
            None,
            Precondition::default(),
            t(3),
            |_| Ok(()),
        )
        .unwrap();
    assert_eq!(store.bytes(&restored), b"one");
    assert!(restored.generation > two.generation);
    assert_eq!(
        kinds(&store.drain_events()),
        vec![
            ("finalized", restored.generation),
            ("archived", two.generation)
        ]
    );
    // The live generation by number is the plain copy; an unknown one is not found and the
    // admission closure never runs.
    let live = store
        .copy_generation_with_admission(
            (&b, &name("o.txt"), Some(restored.generation)),
            (&b, &name("live.txt")),
            None,
            Precondition::default(),
            t(4),
            |_| Ok(()),
        )
        .unwrap()
        .0;
    assert_eq!(store.bytes(&live), b"one");
    let mut asked = false;
    let missing = store.copy_generation_with_admission(
        (&b, &name("o.txt"), Some(424_242)),
        (&b, &name("x.txt")),
        None,
        Precondition::default(),
        t(5),
        |_| {
            asked = true;
            Ok(())
        },
    );
    assert_eq!(missing.err(), Some(StorageError::NotFound));
    assert!(!asked);
}

#[test]
fn patching_a_noncurrent_generation_leaves_the_live_object_and_announces_nothing() {
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    let one = put(&mut store, &b, "o.txt", "one", 1);
    let two = put(&mut store, &b, "o.txt", "two", 2);
    let _ = store.drain_events();
    let patch = MetadataPatch {
        content_type: Some(Some("text/x-old".to_owned())),
        ..MetadataPatch::default()
    };
    let mut batch_len = None;
    let (patched, ()) = store
        .update_generation_metadata_with_admission(
            &b,
            &name("o.txt"),
            one.generation,
            &patch,
            Precondition::default(),
            t(3),
            |events| {
                batch_len = Some(events.len());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(batch_len, Some(0), "nothing is announced");
    assert_eq!(patched.generation, one.generation);
    assert_eq!(patched.metageneration, one.metageneration + 1);
    assert_eq!(patched.content_type, "text/x-old");
    assert_eq!(patched.updated, t(3));
    let live = store.get(&b, &name("o.txt")).unwrap();
    assert_eq!(live.generation, two.generation);
    assert_eq!(live.metageneration, two.metageneration);
    assert_eq!(live.content_type, two.content_type);
    let (kept, deleted_at) = store
        .generation(&b, &name("o.txt"), one.generation)
        .unwrap();
    assert_eq!(kept.content_type, "text/x-old");
    assert_eq!(
        deleted_at,
        Some(t(2)),
        "it stopped being live at the overwrite"
    );
    assert!(store.drain_events().is_empty());
    // A precondition on the noncurrent generation is checked against it.
    let stale = store.update_generation_metadata_with_admission(
        &b,
        &name("o.txt"),
        one.generation,
        &patch,
        Precondition {
            if_metageneration_match: Some(1),
            ..Precondition::default()
        },
        t(4),
        |_| Ok(()),
    );
    assert!(stale.is_err(), "the metageneration moved to 2");
    // The live generation by number is a plain metadata update; an unknown one is not found.
    let (live_patched, ()) = store
        .update_generation_metadata_with_admission(
            &b,
            &name("o.txt"),
            two.generation,
            &patch,
            Precondition::default(),
            t(5),
            |_| Ok(()),
        )
        .unwrap();
    assert_eq!(live_patched.metageneration, two.metageneration + 1);
    assert_eq!(
        kinds(&store.drain_events()),
        vec![("metadata", two.generation)]
    );
    assert_eq!(
        store
            .update_generation_metadata_with_admission(
                &b,
                &name("o.txt"),
                424_242,
                &patch,
                Precondition::default(),
                t(6),
                |_| Ok(()),
            )
            .err(),
        Some(StorageError::NotFound)
    );
}

#[test]
fn a_bucket_is_known_when_it_holds_an_object_or_was_configured() {
    let mut store = StorageState::new(1);
    let b = bucket();
    let other = BucketName::try_new("other-bucket").unwrap();
    assert!(!store.bucket_known(&b));
    put(&mut store, &b, "o.txt", "x", 1);
    assert!(store.bucket_known(&b));
    assert!(!store.bucket_known(&other), "another bucket is not known");
    // A bucket whose only content is noncurrent versions is still known.
    store.set_versioning(&other, true);
    assert!(store.bucket_known(&other), "configured");
    put(&mut store, &other, "o.txt", "x", 2);
    store
        .delete(&other, &name("o.txt"), Precondition::default(), t(3))
        .unwrap();
    store.set_versioning(&other, false);
    assert!(store.get(&other, &name("o.txt")).is_none());
    assert!(
        store.bucket_known(&other),
        "holds a noncurrent version only"
    );
    store
        .delete_generation(
            &other,
            &name("o.txt"),
            store.noncurrent_versions(&other, &name("o.txt"))[0]
                .object
                .generation,
            Precondition::default(),
        )
        .unwrap();
    assert!(
        store.bucket_known(&other),
        "a bucket that was configured stays known, disabled or not"
    );
    store.remove_bucket(&other);
    assert!(!store.bucket_known(&other), "nothing left");
}

/// Pages through a versions listing and returns the pages' entries as strings:
/// `name#generation` for an item, the prefix itself for a folded prefix.
fn page_through(
    store: &StorageState,
    b: &BucketName,
    prefix: &str,
    delimiter: &str,
    size: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut cursor: Option<VersionsCursor> = None;
    for _ in 0..1000 {
        let page = store.list_versions_page(b, prefix, delimiter, cursor.as_ref(), size);
        assert!(page.items.len() + page.prefixes.len() <= size);
        // Items and prefixes are separate lists; rebuild the order the page was cut in (by name,
        // then by generation).
        let mut entries: Vec<(String, u64, String)> = page
            .items
            .iter()
            .map(|v| {
                (
                    v.object.name.as_str().to_owned(),
                    v.object.generation,
                    format!("{}#{}", v.object.name.as_str(), v.object.generation),
                )
            })
            .chain(page.prefixes.iter().map(|p| (p.clone(), 0, p.clone())))
            .collect();
        entries.sort();
        out.extend(entries.into_iter().map(|(_, _, entry)| entry));
        match page.next {
            Some(next) => cursor = Some(next),
            None => return out,
        }
    }
    panic!("a listing that never ends");
}

#[test]
fn a_versions_page_resumes_at_its_cursor_through_prefixes_and_generations() {
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    let a1 = put(&mut store, &b, "dir/a.txt", "1", 1);
    let a2 = put(&mut store, &b, "dir/a.txt", "22", 2);
    let b1 = put(&mut store, &b, "dir/b.txt", "3", 3);
    let top1 = put(&mut store, &b, "top.txt", "4", 4);
    let top2 = put(&mut store, &b, "top.txt", "5", 5);
    // Unfolded: every generation, in order.
    let all = vec![
        format!("dir/a.txt#{}", a1.generation),
        format!("dir/a.txt#{}", a2.generation),
        format!("dir/b.txt#{}", b1.generation),
        format!("top.txt#{}", top1.generation),
        format!("top.txt#{}", top2.generation),
    ];
    for size in 1..=6 {
        assert_eq!(page_through(&store, &b, "", "", size), all, "size {size}");
    }
    // Folded at `/`: the prefix once, however many generations it hides, and never again on a
    // later page.
    let folded = vec![
        "dir/".to_owned(),
        format!("top.txt#{}", top1.generation),
        format!("top.txt#{}", top2.generation),
    ];
    for size in 1..=4 {
        assert_eq!(
            page_through(&store, &b, "", "/", size),
            folded,
            "size {size}"
        );
    }
    // A prefix filter, with a cursor in the middle of an object's generations.
    assert_eq!(
        page_through(&store, &b, "top", "", 1),
        vec![
            format!("top.txt#{}", top1.generation),
            format!("top.txt#{}", top2.generation)
        ]
    );
    let first = store.list_versions_page(&b, "", "", None, 2);
    assert_eq!(
        first.next,
        Some(VersionsCursor::Item {
            name: "dir/b.txt".to_owned(),
            generation: b1.generation
        })
    );
    // A page of size zero names the first entry and holds nothing.
    let empty = store.list_versions_page(&b, "", "", None, 0);
    assert!(empty.items.is_empty() && empty.prefixes.is_empty());
    assert!(empty.next.is_some());
    // The listing of an empty bucket, and one past the end.
    let nobody = BucketName::try_new("nobody").unwrap();
    assert_eq!(
        store.list_versions_page(&nobody, "", "", None, 5),
        fireemu_core_storage::store::VersionsPage {
            items: Vec::new(),
            prefixes: Vec::new(),
            next: None
        }
    );
    let past = VersionsCursor::Item {
        name: "zzz".to_owned(),
        generation: 1,
    };
    assert!(store
        .list_versions_page(&b, "", "", Some(&past), 5)
        .items
        .is_empty());
}

proptest! {
    /// Paging a versions listing with any page size yields exactly what one big page yields, and
    /// that equals the folded `list_versions` sequence, for any prefix and delimiter.
    #[test]
    fn paging_a_versions_listing_equals_one_listing(
        writes in proptest::collection::vec((0u8..6, 0u8..3), 1..30),
        prefix_len in 0usize..3,
        delimit in any::<bool>(),
        size in 1usize..7,
    ) {
        let mut store = StorageState::new(5);
        let b = bucket();
        store.set_versioning(&b, true);
        let names = ["a", "a/x", "a/y", "b", "b/z/w", "c"];
        for (step, (n, kind)) in writes.into_iter().enumerate() {
            let key = names[usize::from(n)];
            let now = t(i64::try_from(step).unwrap() + 1);
            if kind == 0 {
                let _ = store.delete(&b, &name(key), Precondition::default(), now);
            } else {
                store
                    .put(&b, &name(key), vec![b'x'; usize::from(kind)], NewMetadata::default(), Precondition::default(), now)
                    .unwrap();
            }
        }
        let prefix = &"abc"[..prefix_len.min(1)];
        let delimiter = if delimit { "/" } else { "" };
        // The reference: fold `list_versions` the way the listing defines.
        let mut expected: Vec<String> = Vec::new();
        for entry in store.list_versions(&b, prefix) {
            let n = entry.object.name.as_str();
            let rest = &n[prefix.len()..];
            match (!delimiter.is_empty()).then(|| rest.find(delimiter)).flatten() {
                Some(at) => {
                    let folded = format!("{prefix}{}{delimiter}", &rest[..at]);
                    if expected.last() != Some(&folded) {
                        expected.push(folded);
                    }
                }
                None => expected.push(format!("{n}#{}", entry.object.generation)),
            }
        }
        prop_assert_eq!(page_through(&store, &b, prefix, delimiter, size), expected.clone());
        prop_assert_eq!(page_through(&store, &b, prefix, delimiter, 1000), expected);
    }
}

#[test]
fn deleting_a_noncurrent_generation_carries_the_time_it_stopped_being_live() {
    let mut store = StorageState::new(1);
    let b = bucket();
    store.set_versioning(&b, true);
    let first = put(&mut store, &b, "o.txt", "one", 1);
    let second = put(&mut store, &b, "o.txt", "two", 2);
    let _ = store.drain_events();
    // RECORDED (FE v5, v1 and v2, both passes): the Deleted event of a noncurrent generation
    // carries `timeDeleted`, the archive instant; the live generation deleted by number does not.
    store
        .delete_generation(
            &b,
            &name("o.txt"),
            first.generation,
            Precondition::default(),
        )
        .unwrap();
    match store.drain_events().as_slice() {
        [StorageEvent::Deleted {
            object,
            time_deleted,
            at,
        }] => {
            assert_eq!(object.generation, first.generation);
            assert_eq!(*time_deleted, Some(t(2)), "the archive instant");
            assert_eq!(*at, None, "the event is stamped when it is admitted");
        }
        other => panic!("{other:?}"),
    }
    store
        .delete_generation(
            &b,
            &name("o.txt"),
            second.generation,
            Precondition::default(),
        )
        .unwrap();
    match store.drain_events().as_slice() {
        [StorageEvent::Deleted {
            time_deleted, at, ..
        }] => assert_eq!((*time_deleted, *at), (None, None)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_deleted_event_of_an_unversioned_overwrite_is_stamped_with_the_replacement_instant() {
    let mut store = StorageState::new(1);
    let b = bucket();
    put(&mut store, &b, "o.txt", "before", 1);
    let _ = store.drain_events();
    let second = put(&mut store, &b, "o.txt", "updated", 5);
    // RECORDED (FE v5): the Deleted event of the replaced generation has the creation instant of
    // the new generation as its time, the same instant as the Finalized event; it carries no
    // `timeDeleted`.
    match store.drain_events().as_slice() {
        [StorageEvent::Deleted {
            time_deleted, at, ..
        }, StorageEvent::Finalized(_)] => {
            assert_eq!(*at, Some(second.time_created));
            assert_eq!(*time_deleted, None);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn versioning_is_a_tri_state_per_bucket() {
    let mut store = StorageState::new(1);
    let b = bucket();
    let other = BucketName::try_new("other-bucket").unwrap();
    // RECORDED (FE v5): never configured, enabled, and disabled are three different answers.
    assert_eq!(store.versioning_state(&b), None);
    store.set_versioning(&b, true);
    assert_eq!(store.versioning_state(&b), Some(true));
    store.set_versioning(&b, false);
    assert_eq!(store.versioning_state(&b), Some(false));
    assert!(!store.versioning(&b));
    assert!(store.bucket_known(&b), "a configured bucket is known");
    assert_eq!(store.versioning_state(&other), None);
    // A snapshot carries every state of the buckets it owns; a clear drops them all.
    store.set_versioning(&other, true);
    let captured = store.capture_buckets(|bucket| bucket == b.as_str());
    let mut restored = StorageState::new(1);
    restored.restore_buckets(|bucket| bucket == b.as_str(), &captured);
    assert_eq!(restored.versioning_state(&b), Some(false));
    assert_eq!(restored.versioning_state(&other), None, "not owned");
    // Removing a bucket drops its configuration, enabled or disabled.
    store.remove_bucket(&b);
    assert_eq!(store.versioning_state(&b), None);
    assert_eq!(store.versioning_state(&other), Some(true));
    store.clear();
    assert_eq!(store.versioning_state(&other), None);
}

proptest! {
    /// `version_keys_from` (the batch a filtered listing reads outside the store lock) is the
    /// `list_versions` sequence from `from` on, cut to `max`, for any prefix; walking the keys in
    /// batches of any size, each resuming just after the last key, yields every key once.
    #[test]
    fn version_keys_in_batches_equal_the_versions_listing(
        writes in proptest::collection::vec((0u8..6, 0u8..3), 1..30),
        prefix_len in 0usize..2,
        from in proptest::option::of((0u8..6, 0u64..4)),
        size in 1usize..7,
    ) {
        let mut store = StorageState::new(5);
        let b = bucket();
        store.set_versioning(&b, true);
        let names = ["a", "a/x", "a/y", "b", "b/z/w", "c"];
        for (step, (n, kind)) in writes.into_iter().enumerate() {
            let key = names[usize::from(n)];
            let now = t(i64::try_from(step).unwrap() + 1);
            if kind == 0 {
                let _ = store.delete(&b, &name(key), Precondition::default(), now);
            } else {
                store
                    .put(&b, &name(key), vec![b'x'; usize::from(kind)], NewMetadata::default(), Precondition::default(), now)
                    .unwrap();
            }
        }
        let prefix = &"abc"[..prefix_len];
        let all: Vec<(String, u64)> = store
            .list_versions(&b, prefix)
            .iter()
            .map(|e| (e.object.name.as_str().to_owned(), e.object.generation))
            .collect();
        // From the start in one batch: everything.
        prop_assert_eq!(store.version_keys_from(&b, prefix, None, usize::MAX), all.clone());
        // From a key (which need not exist), inclusive: the keys at or after it.
        if let Some((n, generation)) = from {
            let start = (names[usize::from(n)], generation);
            let expected: Vec<(String, u64)> = all
                .iter()
                .filter(|(name, g)| (name.as_str(), *g) >= start)
                .take(size)
                .cloned()
                .collect();
            prop_assert_eq!(store.version_keys_from(&b, prefix, Some(start), size), expected);
        }
        // Batches of `size`, each resuming after the last key: the whole sequence, once.
        let mut walked = Vec::new();
        let mut resume: Option<(String, u64)> = None;
        loop {
            let batch = store.version_keys_from(
                &b,
                prefix,
                resume.as_ref().map(|(name, g)| (name.as_str(), *g)),
                size,
            );
            let Some((last, generation)) = batch.last().cloned() else { break };
            walked.extend(batch);
            resume = Some((last, generation + 1));
        }
        prop_assert_eq!(walked, all);
    }
}

proptest! {
    /// Under the strict profile's identities (generations are microsecond timestamps) every write
    /// path that archives draws from the one allocator: puts, copies, copies from a noncurrent
    /// generation and resumable finalizes, however many land on the same instant, issue strictly
    /// increasing generations, so live and noncurrent generations never collide and their order
    /// is the order of the writes.
    #[test]
    fn every_archiving_write_path_draws_strictly_increasing_generations(
        steps in proptest::collection::vec((0u8..4, 0u8..2, 0i64..2), 1..24),
    ) {
        let mut store = StorageState::new(7);
        store.set_production_order(true);
        let b = bucket();
        store.set_versioning(&b, true);
        let targets = [name("x.txt"), name("y.txt")];
        let mut issued: Vec<u64> = Vec::new();
        let mut now = 1i64;
        for (path, target, advance) in steps {
            now += advance;
            let at = t(now);
            let dst = &targets[usize::from(target)];
            let written = match path {
                0 => Some(store.put(&b, dst, b"p".to_vec(), NewMetadata::default(), Precondition::default(), at).unwrap()),
                1 => store
                    .copy((&b, &targets[usize::from(1 - target)]), (&b, dst), None, Precondition::default(), at)
                    .ok(),
                2 => {
                    // Restore the oldest noncurrent generation of the other object, when there is one.
                    let other = &targets[usize::from(1 - target)];
                    let oldest = store.noncurrent_versions(&b, other).first().map(|v| v.object.generation);
                    oldest.and_then(|g| {
                        store
                            .copy_generation_with_admission((&b, other, Some(g)), (&b, dst), None, Precondition::default(), at, |_| Ok(()))
                            .ok()
                            .map(|(m, ())| m)
                    })
                }
                _ => {
                    let id = store
                        .begin_upload(&b, dst, NewMetadata::default(), Precondition::default(), None, at)
                        .unwrap();
                    store.append_upload(&id, 0, b"r", at).unwrap();
                    Some(store.finalize_upload(&id, at).unwrap())
                }
            };
            if let Some(object) = written {
                issued.push(object.generation);
            }
        }
        prop_assert!(issued.windows(2).all(|w| w[0] < w[1]), "{:?}", issued);
        // Every generation the store holds, live or noncurrent, was issued once.
        let mut held: Vec<u64> = targets
            .iter()
            .flat_map(|n| {
                store
                    .list_versions(&b, n.as_str())
                    .iter()
                    .map(|e| e.object.generation)
                    .collect::<Vec<_>>()
            })
            .collect();
        held.sort_unstable();
        let mut unique = held.clone();
        unique.dedup();
        prop_assert_eq!(held, unique, "a generation is held twice");
    }
}
