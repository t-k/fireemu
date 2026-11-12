//! Committed object spill storage.

#[cfg(unix)]
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::spill::{ProcessSpill, SpillDir};
#[cfg(unix)]
use fireemu_core_storage::store::{NewMetadata, Precondition, StorageError, StorageState};
#[cfg(unix)]
use fireemu_core_types::time::LogicalInstant;
#[cfg(unix)]
use std::fs;

#[cfg(not(unix))]
#[test]
fn process_spill_is_unsupported() {
    let root = std::env::temp_dir().join("spill-store-unsupported");
    let Err(error) = ProcessSpill::create(&root) else {
        panic!("process spill must be refused");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    assert_eq!(error.to_string(), "process spill is unsupported");
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
fn compare_results<T: std::fmt::Debug + PartialEq>(
    a: &Result<T, StorageError>,
    b: &Result<T, StorageError>,
) {
    assert_eq!(a, b);
    if let (Err(a), Err(b)) = (a, b) {
        assert_eq!(a.to_string(), b.to_string());
    }
}

#[cfg(unix)]
fn version_bodies(
    store: &StorageState,
    buckets: &[BucketName; 2],
) -> Vec<(
    fireemu_core_storage::store::ObjectMetadata,
    Option<LogicalInstant>,
    Vec<u8>,
)> {
    buckets
        .iter()
        .flat_map(|bucket| store.list_versions(bucket, ""))
        .map(|entry| {
            (
                entry.object.clone(),
                entry.time_deleted,
                store.body_bytes(entry.object).unwrap().to_vec(),
            )
        })
        .collect()
}

#[cfg(unix)]
fn compare_spill_state(
    memory: &StorageState,
    spilled: &StorageState,
    buckets: &[BucketName; 2],
    windows: (usize, usize),
) {
    assert_eq!(memory.all_objects(), spilled.all_objects());
    assert_eq!(memory.retained_blob_bytes(), spilled.retained_blob_bytes());
    assert_eq!(
        memory.retained_upload_bytes(),
        spilled.retained_upload_bytes()
    );
    for (a, b) in memory.all_objects().iter().zip(spilled.all_objects()) {
        let left = memory.body_bytes(a).unwrap();
        let right = spilled.body_bytes(b).unwrap();
        assert_eq!(left, right);
        let start = windows.0.min(left.len());
        let end = windows.1.min(left.len());
        let (start, end) = (start.min(end), start.max(end));
        for (start, end) in [(start, end), (0, 0), (0, left.len())] {
            assert_eq!(&left[start..end], &right[start..end]);
        }
    }
    for bucket in buckets {
        let left = memory.list_versions(bucket, "");
        let right = spilled.list_versions(bucket, "");
        assert_eq!(left, right);
        for entry in left {
            let object = entry.object;
            assert_eq!(
                memory.generation(bucket, &object.name, object.generation),
                spilled.generation(bucket, &object.name, object.generation)
            );
            assert_eq!(
                memory.body_bytes(object).unwrap(),
                spilled.body_bytes(object).unwrap()
            );
        }
    }
}

#[cfg(unix)]
proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config { cases: 64, failure_persistence: None, ..proptest::test_runner::Config::default() })]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn spill_surface_matches_memory(
        threshold in 0u64..=3000,
        versioned in 0usize..2,
        windows in (0usize..=3000, 0usize..=3000),
        ops in proptest::collection::vec((0u8..10, 0usize..2, 0usize..4, 0u8..5, proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=3000)), 0..=30)
    ) {
        use fireemu_core_storage::store::{ImportedObject, ObjectDigests, UploadOptions};
        use std::collections::BTreeSet;
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!("spill-surface-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let process = ProcessSpill::create(&root).unwrap();
        let mut memory = StorageState::new(1);
        let mut spilled = StorageState::new(1);
        spilled.set_spill(Some((process.spill_dir(), threshold)));
        let buckets = [BucketName::try_new("first.appspot.com").unwrap(), BucketName::try_new("second.appspot.com").unwrap()];
        let names = ["one", "two", "three", "four"].map(|name| ObjectName::try_new(name).unwrap());
        let now = LogicalInstant::UNIX_EPOCH;
        memory.set_versioning(&buckets[versioned], true);
        spilled.set_versioning(&buckets[versioned], true);
        let mut snapshots = Vec::new();
        let mut upload = None;
        let seeded = [
            (0, versioned, 0, 0, vec![0; usize::try_from(threshold.saturating_sub(1)).unwrap()]),
            (0, versioned, 1, 0, vec![1; usize::try_from(threshold).unwrap()]),
        ];
        for (op, b, n, choice, bytes) in seeded.into_iter().chain(ops) {
            let bucket = &buckets[b];
            let name = &names[n];
            let current = memory.get(bucket, name);
            let generation = current.map_or(1, |m| m.generation);
            let metageneration = current.map_or(1, |m| m.metageneration);
            let pre = match choice {
                1 => Precondition { if_generation_match: Some(generation), ..Precondition::default() },
                2 => Precondition { if_generation_match: Some(generation + 1), ..Precondition::default() },
                3 => Precondition { if_metageneration_match: Some(metageneration), ..Precondition::default() },
                4 => Precondition { if_metageneration_match: Some(metageneration + 1), ..Precondition::default() },
                _ => Precondition::default(),
            };
            match op {
                0 | 1 => {
                    let a = memory.put(bucket, name, bytes.clone(), NewMetadata::default(), pre, now);
                    let b = spilled.put(bucket, name, bytes, NewMetadata::default(), pre, now);
                    compare_results(&a, &b);
                }
                2 => {
                    let a = memory.delete(bucket, name, pre, now);
                    let b = spilled.delete(bucket, name, pre, now);
                    compare_results(&a, &b);
                }
                3 => {
                    let frozen = version_bodies(&memory, &buckets);
                    snapshots.push((memory.clone(), spilled.clone(), frozen));
                }
                4 => { if !snapshots.is_empty() { snapshots.remove(n % snapshots.len()); } }
                5 => {
                    let mut imported_memory = StorageState::new(1);
                    let mut imported_spilled = StorageState::new(1);
                    imported_spilled.set_spill(Some((process.spill_dir(), threshold)));
                    for object in memory.all_objects() {
                        let imported = ImportedObject {
                            bucket: object.bucket.clone(), name: object.name.clone(), generation: object.generation,
                            metageneration: object.metageneration, content_type: object.content_type.clone(),
                            content_disposition: object.content_disposition.clone(), content_encoding: object.content_encoding.clone(),
                            content_language: object.content_language.clone(), cache_control: object.cache_control.clone(),
                            custom: object.custom.clone(), custom_defined: object.custom_defined, time_created: object.time_created,
                            updated: object.updated, download_tokens: object.download_tokens.clone(), md5: Some(object.md5),
                            crc32c: Some(object.crc32c), size: Some(object.size),
                        };
                        let body = memory.body_bytes(object).unwrap().to_vec();
                        let a = imported_memory.insert_imported(imported.clone(), body.clone()).unwrap();
                        let b = imported_spilled.insert_imported(imported, body).unwrap();
                        assert_eq!(a, b);
                        let mut restored = a;
                        restored.blob = object.blob;
                        assert_eq!(&restored, object);
                    }
                    compare_spill_state(&imported_memory, &imported_spilled, &buckets, windows);
                    for (original, restored) in memory.all_objects().iter().zip(imported_memory.all_objects()) {
                        assert_eq!(memory.body_bytes(original).unwrap(), imported_memory.body_bytes(restored).unwrap());
                    }
                }
                6 => {
                    snapshots.clear();
                    upload = None;
                    memory.clear();
                    spilled.clear();
                    assert!(memory.all_objects().is_empty());
                    assert_eq!(spill_files(process.path()).len(), 0);
                    memory.set_versioning(&buckets[versioned], true);
                    spilled.set_versioning(&buckets[versioned], true);
                    compare_spill_state(&memory, &spilled, &buckets, windows);
                    let a = memory.put(bucket, name, bytes.clone(), NewMetadata::default(), Precondition::default(), now);
                    let b = spilled.put(bucket, name, bytes, NewMetadata::default(), Precondition::default(), now);
                    compare_results(&a, &b);
                    assert!(a.is_ok());
                }
                7 => {
                    let total = match choice { 0 => None, 1 | 3 => Some(bytes.len() as u64 + 1), _ => Some(bytes.len() as u64) };
                    let mut digest = ObjectDigests::new(&bytes).md5();
                    digest[0] ^= 1;
                    let options = UploadOptions { total, expected_md5: (choice >= 3).then_some(digest), ..UploadOptions::default() };
                    let a = memory.begin_upload_with(bucket, name, NewMetadata::default(), Precondition::default(), options.clone(), now);
                    let b = spilled.begin_upload_with(bucket, name, NewMetadata::default(), Precondition::default(), options, now);
                    compare_results(&a, &b);
                    upload = a.ok().map(|id| (id, bytes, 0usize));
                }
                8 => {
                    if let Some((id, body, offset)) = &mut upload {
                        let (start, end) = if choice % 2 == 0 && *offset > 0 { (0, *offset) } else { (*offset, if *offset == 0 { body.len().div_ceil(2) } else { body.len() }) };
                        let a = memory.append_upload(id, start as u64, &body[start..end], now);
                        let b = spilled.append_upload(id, start as u64, &body[start..end], now);
                        compare_results(&a, &b);
                        if a.is_ok() { *offset = (*offset).max(end); }
                    }
                }
                _ => {
                    if let Some((id, _, _)) = upload.take() {
                        let a = memory.finalize_upload(&id, now);
                        let b = spilled.finalize_upload(&id, now);
                        compare_results(&a, &b);
                    }
                }
            }
            compare_spill_state(&memory, &spilled, &buckets, windows);
            let mut blobs = BTreeSet::new();
            for (object, _, _) in version_bodies(&spilled, &buckets) {
                if object.size >= threshold { blobs.insert(object.blob); }
            }
            for (a, b, frozen) in &snapshots {
                assert_eq!(&version_bodies(a, &buckets), frozen);
                assert_eq!(&version_bodies(b, &buckets), frozen);
                compare_spill_state(a, b, &buckets, windows);
                for (object, _, _) in version_bodies(b, &buckets) {
                    if object.size >= threshold { blobs.insert(object.blob); }
                }
            }
            assert_eq!(spill_files(process.path()).len(), blobs.len());
        }
        drop(snapshots);
        drop(spilled);
        drop(process);
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(unix)]
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
#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
#[test]
fn imported_objects_spill_and_preserve_metadata_and_bytes() {
    use fireemu_core_storage::store::ImportedObject;
    use std::collections::BTreeMap;

    let root = std::env::temp_dir().join(format!("spill-import-{}", std::process::id()));
    let process = ProcessSpill::create(&root).unwrap();
    let bucket = BucketName::try_new("example.appspot.com").unwrap();
    let now = LogicalInstant::UNIX_EPOCH;
    let imported = |name: &str, size: usize| ImportedObject {
        bucket: bucket.clone(),
        name: ObjectName::try_new(name).unwrap(),
        generation: 42,
        metageneration: 3,
        content_type: "text/plain".to_owned(),
        content_disposition: None,
        content_encoding: None,
        content_language: None,
        cache_control: Some("public, max-age=60".to_owned()),
        custom: BTreeMap::from([("custom".to_owned(), "value".to_owned())]),
        custom_defined: true,
        time_created: now,
        updated: now,
        download_tokens: vec![],
        md5: None,
        crc32c: None,
        size: Some(size as u64),
    };
    let mut store = StorageState::new(1);
    let mut memory = StorageState::new(1);
    store.set_spill(Some((process.spill_dir(), 4)));
    for (name, body) in [("large", &b"0123456789"[..]), ("small", &b"ab"[..])] {
        let object = imported(name, body.len());
        let meta = store
            .insert_imported(object.clone(), body.to_vec())
            .unwrap();
        let expected = memory.insert_imported(object, body.to_vec()).unwrap();
        assert_eq!(meta, expected);
        assert_eq!(store.body_bytes(&meta).unwrap().as_ref(), body);
        assert_eq!(store.body_shared(&meta).unwrap().as_slice(), body);
    }
    assert_eq!(store.retained_blob_bytes(), memory.retained_blob_bytes());
    let files = spill_files(process.path());
    assert_eq!(files.len(), 1);
    assert_eq!(fs::read(&files[0]).unwrap(), b"0123456789");

    let bad = root.join("not-a-directory");
    fs::write(&bad, b"x").unwrap();
    store.set_spill(Some((SpillDir::new(&bad), 4)));
    let before = store.retained_blob_bytes();
    let missing = imported("missing", 10);
    assert!(matches!(
        store.insert_imported(missing.clone(), b"0123456789".to_vec()),
        Err(StorageError::SpillFailed(_))
    ));
    assert!(store.get(&bucket, &missing.name).is_none());
    let existing = imported("large", 10);
    let original = store.get(&bucket, &existing.name).unwrap().clone();
    assert!(matches!(
        store.insert_imported(existing, b"abcdefghij".to_vec()),
        Err(StorageError::SpillFailed(_))
    ));
    assert_eq!(store.get(&bucket, &original.name), Some(&original));
    assert_eq!(store.body_bytes(&original).unwrap().as_ref(), b"0123456789");
    assert_eq!(store.retained_blob_bytes(), before);
    drop(store);
    drop(process);
    fs::remove_dir_all(root).unwrap();
}
