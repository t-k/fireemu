//! `SNAP-MEM-01` / `SNAP-MEM-02` / `SNAP-MEM-05`: a session snapshot shares its object data
//! with the live store by allocation instead of copying it, stays exact when the live store
//! moves on, and releases the sharing when either side drops or replaces the blob.

use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{NewMetadata, Precondition, StorageState};
use fireemu_core_types::time::LogicalInstant;

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
fn restore_shares_the_captured_blobs_instead_of_copying_them() {
    let mut live = StorageState::new(7);
    put(&mut live, "big.bin", vec![1u8; MIB]);
    let capture = live.capture_buckets(|_| true);

    put(&mut live, "big.bin", vec![2u8; 8]);
    put(&mut live, "extra.bin", vec![3u8; 64]);
    live.restore_buckets(|_| true, &capture, true);

    let meta = live.get(&bucket(), &name("big.bin")).unwrap().clone();
    assert_eq!(live.bytes(&meta), vec![1u8; MIB].as_slice());
    assert_eq!(live.get(&bucket(), &name("extra.bin")), None);
    assert_eq!(
        live.blob_bytes_shared_with(&capture),
        MIB as u64,
        "the restore points at the captured allocation"
    );
}
