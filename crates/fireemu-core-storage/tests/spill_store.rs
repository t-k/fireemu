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
    assert_eq!(fs::read_dir(process.path()).unwrap().count(), 1);
    assert_eq!(store.body_bytes(&meta).unwrap().as_ref(), body);
    assert_eq!(*store.body_shared(&meta).unwrap(), body);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| store.bytes(&meta))).is_err());
    let snapshot = store.clone();
    store
        .delete(&bucket, &name, Precondition::default(), now)
        .unwrap();
    assert_eq!(fs::read_dir(process.path()).unwrap().count(), 1);
    drop(snapshot);
    assert_eq!(fs::read_dir(process.path()).unwrap().count(), 0);
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
    let old = fs::read_dir(process.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
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
    assert_eq!(fs::read_dir(process.path()).unwrap().count(), 1);
    store.clear();
    assert_eq!(fs::read_dir(process.path()).unwrap().count(), 0);
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
    assert_eq!(fs::read_dir(process.path()).unwrap().count(), 0);
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
    assert_eq!(fs::read_dir(process.path()).unwrap().count(), 0);
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
    assert_eq!(fs::read_dir(process.path()).unwrap().count(), 0);
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
    let path = fs::read_dir(process.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::remove_file(path).unwrap();
    assert!(store.body_bytes(&meta).is_err());
    assert!(store.body_shared(&meta).is_err());
    store
        .delete_generation(&bucket, &name, meta.generation, Precondition::default())
        .unwrap();
    assert_eq!(fs::read_dir(process.path()).unwrap().count(), 0);
    drop(store);
    drop(process);
    fs::remove_dir_all(root).unwrap();
}
