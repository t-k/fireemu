//! Committed object spill storage.

use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::spill::{ProcessSpill, SpillDir};
use fireemu_core_storage::store::{NewMetadata, Precondition, StorageError, StorageState};
use fireemu_core_types::time::LogicalInstant;
use std::fs;

#[test]
#[allow(clippy::too_many_lines)]
fn spill_lifecycle_and_failure() {
    let root = std::env::temp_dir().join(format!("spill-store-{}", std::process::id()));
    let process = ProcessSpill::create(&root).unwrap();
    let mut store = StorageState::new(1);
    let mut memory = StorageState::new(1);
    let bucket = BucketName::try_new("example.appspot.com").unwrap();
    let name = ObjectName::try_new("object").unwrap();
    let now = LogicalInstant::UNIX_EPOCH;
    let body = b"0123456789".to_vec();
    store.set_spill(Some((process.spill_dir(), 4)));
    let meta = store
        .put(
            &bucket,
            &name,
            body.clone(),
            NewMetadata::default(),
            Precondition::default(),
            now,
        )
        .unwrap();
    let expected = memory
        .put(
            &bucket,
            &name,
            body.clone(),
            NewMetadata::default(),
            Precondition::default(),
            now,
        )
        .unwrap();
    assert_eq!(meta, expected);
    assert_eq!(store.get(&bucket, &name), Some(&meta));
    assert_eq!(spill_files(process.path()).len(), 1);
    assert_eq!(store.body_bytes(&meta).unwrap().as_ref(), body);
    assert_eq!(*store.body_shared(&meta).unwrap(), body);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.bytes(&meta))).is_err());
    let snapshot = store.clone();
    store
        .delete(&bucket, &name, Precondition::default(), now)
        .unwrap();
    assert_eq!(spill_files(process.path()).len(), 1);
    drop(snapshot);
    assert_eq!(spill_files(process.path()).len(), 0);
    store
        .put(
            &bucket,
            &name,
            body.clone(),
            NewMetadata::default(),
            Precondition::default(),
            now,
        )
        .unwrap();
    let old = spill_files(process.path()).remove(0);
    store
        .put(
            &bucket,
            &name,
            body.clone(),
            NewMetadata::default(),
            Precondition::default(),
            now,
        )
        .unwrap();
    assert!(!old.exists());
    assert_eq!(spill_files(process.path()).len(), 1);
    store.clear();
    assert_eq!(spill_files(process.path()).len(), 0);
    store.set_spill(Some((process.spill_dir(), 11)));
    store
        .put(
            &bucket,
            &name,
            body.clone(),
            NewMetadata::default(),
            Precondition::default(),
            now,
        )
        .unwrap();
    assert_eq!(spill_files(process.path()).len(), 0);
    store.set_spill(None);
    store
        .put(
            &bucket,
            &name,
            body.clone(),
            NewMetadata::default(),
            Precondition::default(),
            now,
        )
        .unwrap();
    assert_eq!(spill_files(process.path()).len(), 0);
    let bad = root.join("not-a-directory");
    fs::write(&bad, b"x").unwrap();
    store.set_spill(Some((SpillDir::new(&bad), 4)));
    let before = store.retained_blob_bytes();
    store.drain_events();
    let missing = ObjectName::try_new("missing").unwrap();
    assert!(matches!(
        store.put(
            &bucket,
            &missing,
            body,
            NewMetadata::default(),
            Precondition::default(),
            now
        ),
        Err(StorageError::SpillFailed(_))
    ));
    assert!(store.get(&bucket, &missing).is_none());
    assert_eq!(store.retained_blob_bytes(), before);
    assert!(store.drain_events().is_empty());
    store
        .put(
            &bucket,
            &missing,
            vec![1],
            NewMetadata::default(),
            Precondition::default(),
            now,
        )
        .unwrap();
    store.set_spill(Some((process.spill_dir(), 0)));
    store
        .put(
            &bucket,
            &name,
            vec![1],
            NewMetadata::default(),
            Precondition::default(),
            now,
        )
        .unwrap();
    drop(store);
    assert_eq!(spill_files(process.path()).len(), 0);
    drop(process);
    fs::remove_dir_all(root).unwrap();
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config { cases: 64, failure_persistence: None, ..proptest::test_runner::Config::default() })]
    #[test]
    fn spilled_and_memory_stores_agree(
        ops in proptest::collection::vec((0u8..4, 0usize..2, 0usize..4, 0usize..2, 0usize..4, proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=3000)), 0..=30)
    ) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!("spill-store-property-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let process = ProcessSpill::create(&root).unwrap();
        let mut memory = StorageState::new(1);
        let mut spilled = StorageState::new(1);
        spilled.set_spill(Some((process.spill_dir(), 0)));
        let buckets = [BucketName::try_new("first.appspot.com").unwrap(), BucketName::try_new("second.appspot.com").unwrap()];
        let names = ["one", "two", "three", "four"].map(|name| ObjectName::try_new(name).unwrap());
        let now = LogicalInstant::UNIX_EPOCH;
        for (op, b, n, db, dn, bytes) in ops {
            let bucket = &buckets[b];
            let name = &names[n];
            match op {
                0 => {
                    let a = memory.put(bucket, name, bytes.clone(), NewMetadata::default(), Precondition::default(), now);
                    let b = spilled.put(bucket, name, bytes, NewMetadata::default(), Precondition::default(), now);
                    assert_eq!(a, b);
                }
                1 => assert_eq!(memory.delete(bucket, name, Precondition::default(), now), spilled.delete(bucket, name, Precondition::default(), now)),
                2 => assert_eq!(memory.copy((bucket, name), (&buckets[db], &names[dn]), None, Precondition::default(), now), spilled.copy((bucket, name), (&buckets[db], &names[dn]), None, Precondition::default(), now)),
                _ => {
                    let a = memory.get(bucket, name);
                    let b = spilled.get(bucket, name);
                    assert_eq!(a, b);
                    if let (Some(a), Some(b)) = (a, b) {
                        assert_eq!(memory.body_bytes(a).unwrap(), spilled.body_bytes(b).unwrap());
                    }
                }
            }
        }
        drop(spilled);
        drop(process);
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn spilled_read_failure_and_generation_delete() {
    let root = std::env::temp_dir().join(format!("spill-store-read-{}", std::process::id()));
    let process = ProcessSpill::create(&root).unwrap();
    let mut store = StorageState::new(1);
    store.set_spill(Some((process.spill_dir(), 0)));
    let bucket = BucketName::try_new("example.appspot.com").unwrap();
    let name = ObjectName::try_new("object").unwrap();
    let meta = store
        .put(
            &bucket,
            &name,
            vec![1, 2],
            NewMetadata::default(),
            Precondition::default(),
            LogicalInstant::UNIX_EPOCH,
        )
        .unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.shared_bytes(&meta)))
            .is_err()
    );
    let path = spill_files(process.path()).remove(0);
    fs::remove_file(path).unwrap();
    // The store reads through the handle it opened, so an unlinked spill file still serves its bytes.
    assert_eq!(store.body_bytes(&meta).unwrap().as_ref(), [1, 2]);
    assert_eq!(*store.body_shared(&meta).unwrap(), vec![1, 2]);
    store
        .delete_generation(&bucket, &name, meta.generation, Precondition::default())
        .unwrap();
    assert_eq!(spill_files(process.path()).len(), 0);
    drop(store);
    drop(process);
    fs::remove_dir_all(root).unwrap();
}

/// The spill files in a process directory; the owner marker is not one of them.
fn spill_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("spill-"))
        })
        .collect()
}

#[test]
fn a_spilled_body_is_shared_with_a_snapshot_and_not_with_a_copy() {
    let root = std::env::temp_dir().join(format!("spill-shared-{}", std::process::id()));
    let process = ProcessSpill::create(&root).unwrap();
    let bucket = BucketName::try_new("example.appspot.com").unwrap();
    let name = ObjectName::try_new("shared").unwrap();
    let now = LogicalInstant::UNIX_EPOCH;
    let mut store = StorageState::new(1);
    store.set_spill(Some((process.spill_dir(), 1)));
    store
        .put(
            &bucket,
            &name,
            b"0123456789".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            now,
        )
        .unwrap();
    let snapshot = store.clone();
    assert_eq!(snapshot.blob_bytes_shared_with(&store), 10);
    let mut copy = StorageState::new(1);
    copy.set_spill(Some((process.spill_dir(), 1)));
    copy.put(
        &bucket,
        &name,
        b"0123456789".to_vec(),
        NewMetadata::default(),
        Precondition::default(),
        now,
    )
    .unwrap();
    assert_eq!(copy.blob_bytes_shared_with(&store), 0);
    drop(snapshot);
    drop(copy);
    drop(store);
    drop(process);
    let _ = fs::remove_dir(&root);
}

#[test]
fn an_upload_spills_at_exactly_the_threshold_and_not_below() {
    let root = std::env::temp_dir().join(format!("spill-threshold-{}", std::process::id()));
    let process = ProcessSpill::create(&root).unwrap();
    let bucket = BucketName::try_new("example.appspot.com").unwrap();
    let now = LogicalInstant::UNIX_EPOCH;
    let mut store = StorageState::new(1);
    store.set_spill(Some((process.spill_dir(), 8)));
    for (name, size, expected_files) in [("below", 7_usize, 0), ("at", 8_usize, 1)] {
        let object = ObjectName::try_new(name).unwrap();
        let id = store
            .begin_upload(
                &bucket,
                &object,
                NewMetadata::default(),
                Precondition::default(),
                None,
                now,
            )
            .unwrap();
        store.append_upload(&id, 0, &vec![7_u8; size], now).unwrap();
        store.finalize_upload(&id, now).unwrap();
        assert_eq!(
            spill_files(process.path()).len(),
            expected_files,
            "size {size}"
        );
    }
    drop(store);
    drop(process);
    let _ = fs::remove_dir(&root);
}

#[test]
fn a_spill_directory_debug_output_names_the_type_and_not_the_path() {
    let text = format!("{:?}", SpillDir::new("/private/var/does-not-appear"));
    assert!(text.contains("SpillDir"), "{text}");
    assert!(!text.contains("does-not-appear"), "{text}");
}
