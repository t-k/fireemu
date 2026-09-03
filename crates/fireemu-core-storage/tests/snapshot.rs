//! `SNAP-MEM-01` / `SNAP-MEM-02` / `SNAP-MEM-05`: a session snapshot shares its object data
//! with the live store by allocation instead of copying it, stays exact when the live store
//! moves on, and releases the sharing when either side drops or replaces the blob.

use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{NewMetadata, Precondition, StorageEvent, StorageState};
use fireemu_core_types::time::LogicalInstant;
use std::sync::{Arc, Mutex};

fn t(n: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_000_000 + n)
}
fn bucket() -> BucketName {
    BucketName::try_new("demo-app.appspot.com").unwrap()
}
fn name(s: &str) -> ObjectName {
    ObjectName::try_new(s).unwrap()
}

const MIB: usize = 1024 * 1024;

fn put(store: &mut StorageState, object: &str, bytes: Vec<u8>) {
    store
        .put(
            &bucket(),
            &name(object),
            bytes,
            NewMetadata::default(),
            Precondition::default(),
            t(0),
        )
        .unwrap();
}

#[test]
fn captures_share_blobs_with_the_live_store_and_with_each_other() {
    let mut live = StorageState::new(7);
    let payload = vec![0xA5u8; MIB];
    put(&mut live, "big.bin", payload.clone());
    put(&mut live, "small.txt", b"hello".to_vec());
    let retained = live.retained_blob_bytes();
    assert_eq!(retained, (MIB + 5) as u64);

    // Several captures of the same state retain the same allocations, not copies: the
    // shared bytes equal the whole payload, so N snapshots cost one payload, not N.
    let first = live.capture_buckets(|_| true);
    let second = live.capture_buckets(|_| true);
    assert_eq!(first.blob_bytes_shared_with(&live), retained);
    assert_eq!(second.blob_bytes_shared_with(&first), retained);

    // Overwriting an object in the live store replaces its blob; the captures keep the
    // old bytes exactly and stop sharing that blob with the live store.
    put(&mut live, "big.bin", vec![0x5Au8; 16]);
    assert_eq!(first.blob_bytes_shared_with(&live), 5);
    let meta = first.get(&bucket(), &name("big.bin")).unwrap().clone();
    assert_eq!(first.bytes(&meta), payload.as_slice());

    // Deleting in the live store releases its reference; the capture still serves the data.
    live.delete(&bucket(), &name("small.txt"), Precondition::default())
        .unwrap();
    assert_eq!(first.blob_bytes_shared_with(&live), 0);
    let small = first.get(&bucket(), &name("small.txt")).unwrap().clone();
    assert_eq!(first.bytes(&small), b"hello");
}

#[test]
fn snapshot_export_work_does_not_hold_the_live_store_lock() {
    let live = Arc::new(Mutex::new(StorageState::new(7)));
    put(&mut live.lock().unwrap(), "large.bin", vec![0xA5; 16 * MIB]);
    let snapshot = live.lock().unwrap().capture_buckets(|_| true);
    let (reading_tx, reading_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let exporter = std::thread::spawn(move || {
        let metadata = snapshot.get(&bucket(), &name("large.bin")).unwrap();
        reading_tx.send(snapshot.bytes(metadata).len()).unwrap();
        release_rx.recv().unwrap();
        snapshot.bytes(metadata)[0]
    });
    assert_eq!(reading_rx.recv().unwrap(), 16 * MIB);

    put(
        &mut live.lock().unwrap(),
        "concurrent-upload.bin",
        b"uploaded while export still reads its snapshot".to_vec(),
    );

    release_tx.send(()).unwrap();
    assert_eq!(exporter.join().unwrap(), 0xA5);
    assert!(live
        .lock()
        .unwrap()
        .get(&bucket(), &name("concurrent-upload.bin"))
        .is_some());
}

#[test]
#[ignore = "release qualification; allocates one GiB of object data"]
fn one_gibibyte_snapshot_export_releases_the_store_before_writing() {
    let live = Arc::new(Mutex::new(StorageState::new(7)));
    for index in 0..4 {
        put(
            &mut live.lock().unwrap(),
            &format!("part-{index}.bin"),
            vec![u8::try_from(index).unwrap(); 256 * MIB],
        );
    }
    let capture_started = std::time::Instant::now();
    let snapshot = live.lock().unwrap().capture_buckets(|_| true);
    let capture_elapsed = capture_started.elapsed();
    assert_eq!(snapshot.retained_blob_bytes(), 1024 * MIB as u64);
    assert_eq!(
        snapshot.blob_bytes_shared_with(&live.lock().unwrap()),
        1024 * MIB as u64
    );
    let (writing_tx, writing_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let exporter = std::thread::spawn(move || {
        let bytes: u64 = snapshot
            .all_objects()
            .into_iter()
            .map(|metadata| snapshot.bytes(metadata).len() as u64)
            .sum();
        writing_tx.send(bytes).unwrap();
        release_rx.recv().unwrap();
        bytes
    });
    assert_eq!(writing_rx.recv().unwrap(), 1024 * MIB as u64);

    let mut store = live
        .try_lock()
        .expect("snapshot export writing must not retain the live store lock");
    put(&mut store, "concurrent-upload.bin", b"upload".to_vec());
    drop(store);

    release_tx.send(()).unwrap();
    assert_eq!(exporter.join().unwrap(), 1024 * MIB as u64);
    eprintln!("one GiB snapshot capture completed in {capture_elapsed:?}");
}

#[test]
fn restore_shares_the_captured_blobs_instead_of_copying_them() {
    let mut live = StorageState::new(7);
    put(&mut live, "big.bin", vec![1u8; MIB]);
    let capture = live.capture_buckets(|_| true);

    put(&mut live, "big.bin", vec![2u8; 8]);
    put(&mut live, "extra.bin", vec![3u8; 64]);
    live.restore_buckets(|_| true, &capture);

    let meta = live.get(&bucket(), &name("big.bin")).unwrap().clone();
    assert_eq!(live.bytes(&meta), vec![1u8; MIB].as_slice());
    assert_eq!(live.get(&bucket(), &name("extra.bin")), None);
    assert_eq!(
        live.blob_bytes_shared_with(&capture),
        MIB as u64,
        "the restore points at the captured allocation"
    );
}

#[test]
fn restoring_an_older_snapshot_never_reuses_an_issued_generation() {
    let mut live = StorageState::new(7);
    put(&mut live, "object.txt", b"captured".to_vec());
    let capture = live.capture_buckets(|_| true);

    put(&mut live, "object.txt", b"newer".to_vec());
    put(&mut live, "other.txt", b"highest".to_vec());
    let highest_issued = live
        .get(&bucket(), &name("other.txt"))
        .expect("later object")
        .generation;

    live.restore_buckets(|_| true, &capture);
    put(&mut live, "object.txt", b"after restore".to_vec());
    let generation_after_restore = live
        .get(&bucket(), &name("object.txt"))
        .expect("restored object was replaced")
        .generation;

    assert!(
        generation_after_restore > highest_issued,
        "restore must preserve the allocator high-water above every issued generation"
    );
}

#[test]
fn restoring_one_scope_preserves_global_allocators_and_credentials() {
    let default_bucket = bucket();
    let registered_bucket = BucketName::try_new("registered.appspot.com").unwrap();
    let mut live = StorageState::new(7);
    live.put(
        &default_bucket,
        &name("captured.txt"),
        b"captured".to_vec(),
        NewMetadata::default(),
        Precondition::default(),
        t(0),
    )
    .unwrap();
    let capture = live.capture_buckets(|bucket| bucket == default_bucket.as_str());

    live.put(
        &registered_bucket,
        &name("registered.txt"),
        b"registered bytes".to_vec(),
        NewMetadata::default(),
        Precondition::default(),
        t(1),
    )
    .unwrap();
    let issued_token = live.mint_download_token();
    let registered_upload = live
        .begin_upload(
            &registered_bucket,
            &name("upload.bin"),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(1),
        )
        .unwrap();

    live.restore_buckets(|bucket| bucket == default_bucket.as_str(), &capture);
    let token_after_restore = live.mint_download_token();
    let default_upload = live
        .begin_upload(
            &default_bucket,
            &name("new-upload.bin"),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(2),
        )
        .unwrap();
    live.put(
        &default_bucket,
        &name("new-object.txt"),
        b"default bytes".to_vec(),
        NewMetadata::default(),
        Precondition::default(),
        t(2),
    )
    .unwrap();

    assert_ne!(
        token_after_restore, issued_token,
        "bearer tokens never repeat"
    );
    assert_ne!(default_upload, registered_upload, "upload IDs never repeat");
    assert_eq!(
        live.upload_bucket(&registered_upload, t(2)).unwrap(),
        &registered_bucket
    );
    let registered = live
        .get(&registered_bucket, &name("registered.txt"))
        .expect("registered project object survives default restore");
    assert_eq!(live.bytes(registered), b"registered bytes");
}

#[test]
fn restoring_one_scope_preserves_pending_events_from_other_scopes() {
    let default_bucket = bucket();
    let registered_bucket = BucketName::try_new("registered.appspot.com").unwrap();
    let mut live = StorageState::new(7);
    live.put(
        &default_bucket,
        &name("captured.txt"),
        b"captured".to_vec(),
        NewMetadata::default(),
        Precondition::default(),
        t(0),
    )
    .unwrap();
    let _ = live.drain_events();
    let capture = live.capture_buckets(|bucket| bucket == default_bucket.as_str());
    live.put(
        &default_bucket,
        &name("owned.txt"),
        b"owned".to_vec(),
        NewMetadata::default(),
        Precondition::default(),
        t(1),
    )
    .unwrap();
    live.put(
        &registered_bucket,
        &name("retained.txt"),
        b"retained".to_vec(),
        NewMetadata::default(),
        Precondition::default(),
        t(1),
    )
    .unwrap();

    live.restore_buckets(|bucket| bucket == default_bucket.as_str(), &capture);

    let events = live.drain_events();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        StorageEvent::Finalized(metadata) if metadata.bucket == registered_bucket
    ));
}
