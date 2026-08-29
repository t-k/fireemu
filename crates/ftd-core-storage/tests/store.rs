//! Object store: names, generations, preconditions, listing, resumable uploads, hashes.

use std::collections::BTreeMap;

use ftd_core_storage::hash::{base64, crc32c, hex, md5};
use ftd_core_storage::name::{BucketName, NameError, ObjectName};
use ftd_core_storage::store::{
    MetadataPatch, NewMetadata, Precondition, StorageError, StorageEvent, StorageState,
};
use ftd_core_types::time::LogicalInstant;

fn t(n: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_000_000 + n)
}
fn bucket() -> BucketName {
    BucketName::try_new("demo-app.appspot.com").unwrap()
}
fn name(s: &str) -> ObjectName {
    ObjectName::try_new(s).unwrap()
}

#[test]
fn hashes_match_reference_vectors() {
    assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        hex(&md5(b"The quick brown fox jumps over the lazy dog")),
        "9e107d9d372bb6826bd81d3542a419d6"
    );
    assert_eq!(crc32c(b""), 0);
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    assert_eq!(base64(b"hello"), "aGVsbG8=");
}

#[test]
fn object_names_are_opaque_utf8_and_never_normalized() {
    let nfc = name("\u{304C}.pdf");
    let nfd = name("\u{304B}\u{3099}.pdf");
    assert_ne!(nfc, nfd, "NFC and NFD are different objects");
    assert!(name("folder/請求書.pdf").as_str().contains('/'));
    assert_eq!(ObjectName::try_new("").unwrap_err(), NameError::Empty);
    assert_eq!(ObjectName::try_new("..").unwrap_err(), NameError::Dot);
    assert_eq!(
        ObjectName::try_new("a\nb").unwrap_err(),
        NameError::ControlCharacter
    );
    assert_eq!(
        ObjectName::try_new(".well-known/acme-challenge/x").unwrap_err(),
        NameError::ReservedPrefix
    );
    assert_eq!(
        ObjectName::try_new("x".repeat(1025)).unwrap_err(),
        NameError::TooLong
    );
    assert!(
        ObjectName::try_new("%2F.pdf").is_ok(),
        "already-decoded names are data"
    );
    assert_eq!(
        BucketName::try_new("Bad_Bucket").unwrap_err(),
        NameError::InvalidBucketCharacter
    );
}

#[test]
fn generations_metagenerations_and_preconditions() {
    let mut s = StorageState::new(1);
    let b = bucket();
    let n = name("a/b.txt");
    let first = s
        .put(
            &b,
            &n,
            b"one".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            t(0),
        )
        .unwrap();
    assert_eq!(
        (first.generation, first.metageneration, first.size),
        (1, 1, 3)
    );
    assert_eq!(first.content_type, "application/octet-stream");
    assert_eq!(s.bytes(&first), b"one");
    assert_eq!(first.download_tokens.len(), 1);

    // Metadata update bumps the metageneration only.
    let patched = s
        .update_metadata(
            &b,
            &n,
            MetadataPatch {
                content_type: Some(Some("text/plain".into())),
                custom: Some(BTreeMap::from([("k".to_owned(), Some("v".to_owned()))])),
                ..MetadataPatch::default()
            },
            Precondition::default(),
            t(1),
        )
        .unwrap();
    assert_eq!((patched.generation, patched.metageneration), (1, 2));
    assert_eq!(patched.content_type, "text/plain");
    assert_eq!(patched.updated, t(1));

    // Data replacement bumps the generation, resets the metageneration, keeps tokens.
    let second = s
        .put(
            &b,
            &n,
            b"two!".to_vec(),
            NewMetadata::default(),
            Precondition {
                if_generation_match: Some(1),
                ..Precondition::default()
            },
            t(2),
        )
        .unwrap();
    assert_eq!((second.generation, second.metageneration), (2, 1));
    assert_eq!(second.download_tokens, first.download_tokens);
    assert!(matches!(
        s.put(
            &b,
            &n,
            vec![],
            NewMetadata::default(),
            Precondition {
                if_generation_match: Some(1),
                ..Precondition::default()
            },
            t(3)
        ),
        Err(StorageError::PreconditionFailed(_))
    ));
    // ifGenerationMatch 0 = must not exist.
    assert!(matches!(
        s.put(
            &b,
            &n,
            vec![],
            NewMetadata::default(),
            Precondition {
                if_generation_match: Some(0),
                ..Precondition::default()
            },
            t(3)
        ),
        Err(StorageError::PreconditionFailed(_))
    ));
    let deleted = s.delete(&b, &n, Precondition::default()).unwrap();
    assert_eq!(deleted.generation, 2);
    assert_eq!(
        s.delete(&b, &n, Precondition::default()),
        Err(StorageError::NotFound)
    );
    let events: Vec<&str> = s
        .drain_events()
        .iter()
        .map(|e| match e {
            StorageEvent::Finalized(_) => "finalized",
            StorageEvent::MetadataUpdated(_) => "metadata",
            StorageEvent::Deleted(_) => "deleted",
        })
        .collect();
    assert_eq!(
        events,
        vec!["finalized", "metadata", "finalized", "deleted"]
    );
}

#[test]
fn listing_uses_the_namespace_with_prefix_and_delimiter() {
    let mut s = StorageState::new(2);
    let b = bucket();
    for n in [
        "a.txt",
        "dir/x.txt",
        "dir/sub/y.txt",
        "dir/z.txt",
        "dirty.txt",
        "日本/a.txt",
    ] {
        s.put(
            &b,
            &name(n),
            vec![],
            NewMetadata::default(),
            Precondition::default(),
            t(0),
        )
        .unwrap();
    }
    let root = s.list(&b, "", Some("/"), None, 0);
    let items: Vec<&str> = root.items.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(items, vec!["a.txt", "dirty.txt"]);
    assert_eq!(root.prefixes, vec!["dir/", "日本/"]);
    let dir = s.list(&b, "dir/", Some("/"), None, 0);
    let items: Vec<&str> = dir.items.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(items, vec!["dir/x.txt", "dir/z.txt"]);
    assert_eq!(dir.prefixes, vec!["dir/sub/"]);
    // No delimiter: flat listing, paged.
    let page1 = s.list(&b, "dir", None, None, 2);
    assert_eq!(page1.items.len(), 2);
    let token = page1.next_page_token.clone().unwrap();
    let page2 = s.list(&b, "dir", None, Some(&token), 2);
    let names: Vec<&str> = page2.items.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(names, vec!["dir/z.txt", "dirty.txt"]);
    assert!(page2.next_page_token.is_none());
}

#[test]
fn resumable_uploads_are_an_explicit_state_machine() {
    let mut s = StorageState::new(3);
    let b = bucket();
    let n = name("big.bin");
    let id = s
        .begin_upload(
            &b,
            &n,
            NewMetadata {
                content_type: Some("image/png".into()),
                ..NewMetadata::default()
            },
            Precondition::default(),
            Some(6),
            t(0),
        )
        .unwrap();
    let p = s.upload_chunk(&id, 0, b"abc", false, t(1)).unwrap();
    assert_eq!((p.received, p.committed.is_none()), (3, true));
    // A retried chunk is harmless; a gap is an offset error.
    assert_eq!(
        s.upload_chunk(&id, 0, b"abc", false, t(1))
            .unwrap()
            .received,
        3
    );
    assert_eq!(
        s.upload_chunk(&id, 5, b"x", false, t(1)),
        Err(StorageError::UploadOffset { expected: 3 })
    );
    assert_eq!(s.upload_status(&id).unwrap().0, 3);
    let done = s.upload_chunk(&id, 3, b"def", true, t(2)).unwrap();
    let meta = done.committed.unwrap();
    assert_eq!((meta.size, meta.content_type.as_str()), (6, "image/png"));
    assert_eq!(s.bytes(&meta), b"abcdef");
    assert_eq!(
        s.upload_chunk(&id, 6, b"", true, t(3)),
        Err(StorageError::UploadFinalized)
    );
    // Declared total must match.
    let id2 = s
        .begin_upload(
            &b,
            &name("short.bin"),
            NewMetadata::default(),
            Precondition::default(),
            Some(10),
            t(0),
        )
        .unwrap();
    assert_eq!(
        s.upload_chunk(&id2, 0, b"abc", true, t(1)),
        Err(StorageError::UploadSizeMismatch)
    );
    // Sessions expire on the virtual clock.
    let id3 = s
        .begin_upload(
            &b,
            &name("late.bin"),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(0),
        )
        .unwrap();
    assert_eq!(
        s.upload_chunk(&id3, 0, b"x", true, t(8 * 24 * 3600)),
        Err(StorageError::UploadNotFound)
    );
}
