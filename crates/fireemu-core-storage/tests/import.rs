//! Installing objects from an import artifact: the recorded identity is kept, the digests
//! are checked against the bytes, and nothing is announced as a new write.

use std::collections::BTreeMap;

use fireemu_core_storage::hash::{crc32c, md5};
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{
    ImportedObject, NewMetadata, Precondition, StorageError, StorageState,
};
use fireemu_core_types::time::LogicalInstant;

fn bucket() -> BucketName {
    BucketName::try_new("demo-app.appspot.com").expect("a valid bucket")
}

fn object(name: &str) -> ObjectName {
    ObjectName::try_new(name).expect("a valid object name")
}

fn t(n: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_000_000 + n)
}

fn imported(name: &str, bytes: &[u8]) -> ImportedObject {
    ImportedObject {
        bucket: bucket(),
        name: object(name),
        generation: 1_788_105_513_194,
        metageneration: 3,
        content_type: "text/plain".to_owned(),
        content_disposition: None,
        content_encoding: None,
        content_language: None,
        cache_control: Some("public, max-age=60".to_owned()),
        custom: BTreeMap::from([("custom".to_owned(), "value".to_owned())]),
        custom_defined: true,
        time_created: t(-10_000),
        updated: t(-5_000),
        download_tokens: vec!["kept-token".to_owned()],
        md5: Some(md5(bytes)),
        crc32c: Some(crc32c(bytes)),
        size: Some(bytes.len() as u64),
    }
}

#[test]
fn an_imported_object_keeps_its_recorded_identity_bytes_and_tokens() {
    let mut store = StorageState::new(7);
    let bytes = b"hello storage\n".to_vec();
    let meta = store
        .insert_imported(imported("images/hello.txt", &bytes), bytes.clone())
        .expect("the import succeeds");
    assert_eq!(meta.generation, 1_788_105_513_194);
    assert_eq!(meta.metageneration, 3);
    assert_eq!(meta.time_created, t(-10_000));
    assert_eq!(meta.updated, t(-5_000));
    assert_eq!(meta.download_tokens, vec!["kept-token".to_owned()]);
    assert_eq!(meta.cache_control.as_deref(), Some("public, max-age=60"));
    assert_eq!(meta.custom.get("custom").map(String::as_str), Some("value"));
    assert_eq!(meta.size, bytes.len() as u64);

    let stored = store
        .get(&bucket(), &object("images/hello.txt"))
        .expect("the object is stored");
    assert_eq!(store.bytes(stored), bytes.as_slice());
    assert_eq!(stored.md5_base64(), "DFKqKz9JSntkXcjLkQABSQ==");
}

#[test]
fn an_import_announces_no_storage_event() {
    let mut store = StorageState::new(7);
    store
        .insert_imported(imported("a", b"x"), b"x".to_vec())
        .expect("the import succeeds");
    assert!(
        store.drain_events().is_empty(),
        "an import restores state; it never fires an object-finalized trigger"
    );
}

#[test]
fn a_blob_whose_digest_does_not_match_its_metadata_is_refused() {
    let mut store = StorageState::new(7);
    let recorded = imported("a", b"the recorded bytes");
    let mismatch = store.insert_imported(recorded.clone(), b"different bytes".to_vec());
    assert!(matches!(mismatch, Err(StorageError::ChecksumMismatch(_))));
    assert!(store.get(&bucket(), &object("a")).is_none());

    let mut wrong_size = recorded.clone();
    wrong_size.md5 = None;
    wrong_size.crc32c = None;
    wrong_size.size = Some(999);
    assert!(matches!(
        store.insert_imported(wrong_size, b"the recorded bytes".to_vec()),
        Err(StorageError::ChecksumMismatch(_))
    ));
}

#[test]
fn an_import_without_recorded_digests_computes_them_from_the_bytes() {
    let mut store = StorageState::new(7);
    let mut without = imported("a", b"x");
    without.md5 = None;
    without.crc32c = None;
    without.size = None;
    let meta = store
        .insert_imported(without, b"payload".to_vec())
        .expect("the import succeeds");
    assert_eq!(meta.size, 7);
    assert_eq!(meta.md5, md5(b"payload"));
    assert_eq!(meta.crc32c, crc32c(b"payload"));
}

#[test]
fn a_write_after_an_import_takes_a_generation_past_the_imported_one() {
    let mut store = StorageState::new(7);
    store
        .insert_imported(imported("a", b"x"), b"x".to_vec())
        .expect("the import succeeds");
    let written = store
        .put(
            &bucket(),
            &object("b"),
            b"y".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            t(0),
        )
        .expect("the write succeeds");
    assert!(
        written.generation > 1_788_105_513_194,
        "a later write cannot reuse an imported generation"
    );
}

#[test]
fn buckets_and_all_objects_list_what_an_export_walks() {
    let mut store = StorageState::new(7);
    let other = BucketName::try_new("second.appspot.com").expect("a valid bucket");
    store
        .insert_imported(imported("b/second", b"x"), b"x".to_vec())
        .expect("the import succeeds");
    store
        .insert_imported(imported("a/first", b"y"), b"y".to_vec())
        .expect("the import succeeds");
    let mut in_other = imported("only", b"z");
    in_other.bucket = other.clone();
    store
        .insert_imported(in_other, b"z".to_vec())
        .expect("the import succeeds");

    assert_eq!(store.buckets(), vec![bucket(), other]);
    let names: Vec<&str> = store
        .all_objects()
        .iter()
        .map(|o| o.name.as_str())
        .collect();
    assert_eq!(names, vec!["a/first", "b/second", "only"]);
}

#[test]
fn importing_over_an_existing_object_replaces_its_bytes_and_drops_the_old_blob() {
    let mut store = StorageState::new(7);
    store
        .insert_imported(imported("a", b"first"), b"first".to_vec())
        .expect("the first import succeeds");
    store
        .insert_imported(imported("a", b"second"), b"second".to_vec())
        .expect("the second import succeeds");
    let stored = store.get(&bucket(), &object("a")).expect("the object");
    assert_eq!(store.bytes(stored), b"second");
    assert_eq!(store.all_objects().len(), 1);
}
