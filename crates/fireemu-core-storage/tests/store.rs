//! Object store: names, generations, preconditions, listing, resumable uploads, hashes.

use std::collections::BTreeMap;

use fireemu_core_storage::hash::{base64, crc32c, hex, md5};
use fireemu_core_storage::name::{BucketName, NameError, ObjectName};
use fireemu_core_storage::store::{
    MetadataPatch, NewMetadata, Precondition, StorageError, StorageEvent, StorageState,
};
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
    // Tokens are not minted by the store: they ride in as `firebaseStorageDownloadTokens`
    // custom metadata (the Firebase upload dialect injects one), as upstream stores them.
    assert_eq!(first.download_tokens.len(), 0);

    // Metadata update bumps the metageneration only.
    let patched = s
        .update_metadata(
            &b,
            &n,
            &MetadataPatch {
                content_type: Some(Some("text/plain".into())),
                custom: Some(fireemu_core_storage::store::CustomMetadataPatch::Merge(
                    BTreeMap::from([("k".to_owned(), Some("v".to_owned()))]),
                )),
                ..MetadataPatch::default()
            },
            Precondition::default(),
            t(1),
        )
        .unwrap();
    assert_eq!((patched.generation, patched.metageneration), (1, 2));
    assert_eq!(patched.content_type, "text/plain");
    assert_eq!(patched.updated, t(1));

    // Data replacement bumps the generation and resets the metageneration; the previous
    // generation's download tokens die with it (a new upload carries its own).
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
    let root = s.list(&b, "", Some("/"), None, None);
    let items: Vec<&str> = root.items.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(items, vec!["a.txt", "dirty.txt"]);
    assert_eq!(root.prefixes, vec!["dir/", "日本/"]);
    let dir = s.list(&b, "dir/", Some("/"), None, None);
    let items: Vec<&str> = dir.items.iter().map(|m| m.name.as_str()).collect();
    assert_eq!(items, vec!["dir/x.txt", "dir/z.txt"]);
    assert_eq!(dir.prefixes, vec!["dir/sub/"]);
    // No delimiter: flat listing, paged.
    let page1 = s.list(&b, "dir", None, None, Some(2));
    assert_eq!(page1.items.len(), 2);
    // The token names the first item of the next page, which that page includes.
    let token = page1.next_page_token.clone().unwrap();
    assert_eq!(token, "dir/z.txt");
    let page2 = s.list(&b, "dir", None, Some(&token), Some(2));
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
    assert_eq!(s.upload_status(&id, t(1)).unwrap().0, 3);
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

#[test]
fn pagination_pages_items_only_and_repeats_every_prefix() {
    let mut s = StorageState::new(1);
    let b = bucket();
    for n in ["dir/a", "dir/b", "other/x", "root", "root2"] {
        s.put(
            &b,
            &name(n),
            b"x".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            t(1),
        )
        .unwrap();
    }
    // Folded prefixes are not paged: every page carries all of them; only items count
    // against max_results, and the token names the first item of the next page.
    let page1 = s.list(&b, "", Some("/"), None, Some(1));
    assert_eq!(page1.prefixes, vec!["dir/", "other/"]);
    assert_eq!(page1.items.len(), 1);
    assert_eq!(page1.items[0].name.as_str(), "root");
    assert_eq!(page1.next_page_token.as_deref(), Some("root2"));
    let page2 = s.list(&b, "", Some("/"), page1.next_page_token.as_deref(), Some(1));
    assert_eq!(page2.prefixes, vec!["dir/", "other/"]);
    assert_eq!(page2.items[0].name.as_str(), "root2");
    assert!(page2.next_page_token.is_none());
    // A token that names no item restarts from the beginning, as the official emulator's
    // `findIndex` fallback does.
    let restarted = s.list(&b, "", Some("/"), Some("no-such-item"), None);
    assert_eq!(restarted.items.len(), 2);
    // An explicit max_results of 0 is an empty page whose token names the first item.
    let empty = s.list(&b, "", Some("/"), None, Some(0));
    assert!(empty.items.is_empty());
    assert_eq!(empty.prefixes, vec!["dir/", "other/"]);
    assert_eq!(empty.next_page_token.as_deref(), Some("root"));
}

#[test]
fn folded_object_names_are_not_valid_page_tokens() {
    let mut s = StorageState::new(1);
    let b = bucket();
    let item = s
        .put(
            &b,
            &name("a-item"),
            b"shared".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            t(1),
        )
        .unwrap();
    s.put(
        &b,
        &name("z/folded"),
        Vec::new(),
        NewMetadata::default(),
        Precondition::default(),
        t(1),
    )
    .unwrap();

    let page = s.list(&b, "", Some("/"), Some("z/folded"), Some(1));
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0], item);
    assert_eq!(page.prefixes, ["z/"]);

    let first = s.shared_bytes(&item);
    let second = s.shared_bytes(&item);
    assert_eq!(first.as_slice(), b"shared");
    assert!(std::sync::Arc::ptr_eq(&first, &second));
}

#[test]
fn not_match_preconditions_and_patch_apply() {
    let mut s = StorageState::new(1);
    let b = bucket();
    let n = name("p");
    let m = s
        .put(
            &b,
            &n,
            b"x".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            t(1),
        )
        .unwrap();
    let not_current = Precondition {
        if_generation_not_match: Some(m.generation),
        ..Precondition::default()
    };
    assert!(matches!(
        s.delete(&b, &n, not_current),
        Err(StorageError::NotModified(_))
    ));
    let other = Precondition {
        if_generation_not_match: Some(m.generation + 1),
        ..Precondition::default()
    };
    let patch = MetadataPatch {
        content_type: Some(None),
        cache_control: Some(Some("no-cache".into())),
        ..MetadataPatch::default()
    };
    let preview = patch.apply(&m);
    assert_eq!(preview.content_type, "application/octet-stream");
    assert_eq!(preview.cache_control.as_deref(), Some("no-cache"));
    assert_eq!(preview.metageneration, m.metageneration);
    let updated = s.update_metadata(&b, &n, &patch, other, t(2)).unwrap();
    assert_eq!(updated.cache_control.as_deref(), Some("no-cache"));
    assert_eq!(updated.metageneration, m.metageneration + 1);
}

#[test]
fn upload_sessions_keep_the_committed_object_and_enforce_the_declared_total() {
    let mut s = StorageState::new(1);
    let b = bucket();
    let n = name("r");
    let id = s
        .begin_upload(
            &b,
            &n,
            NewMetadata::default(),
            Precondition::default(),
            Some(3),
            t(1),
        )
        .unwrap();
    assert_eq!(s.set_upload_total(&id, 3, t(1)), Ok(()));
    assert_eq!(
        s.set_upload_total(&id, 4, t(1)),
        Err(StorageError::UploadSizeMismatch)
    );
    assert_eq!(
        s.append_upload(&id, 0, b"abcd", t(1)),
        Err(StorageError::UploadSizeMismatch)
    );
    let id = s
        .begin_upload(
            &b,
            &n,
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(1),
        )
        .unwrap();
    s.append_upload(&id, 0, b"abc", t(1)).unwrap();
    let pending = s.pending_upload(&id, t(1)).unwrap();
    assert_eq!(pending.bytes, b"abc");
    let committed = s.finalize_upload(&id, t(2)).unwrap();
    // A later overwrite does not change what the session reports.
    s.put(
        &b,
        &n,
        b"zzzz".to_vec(),
        NewMetadata::default(),
        Precondition::default(),
        t(3),
    )
    .unwrap();
    let (received, status) = s.upload_status(&id, t(3)).unwrap();
    assert_eq!(received, 3);
    assert_eq!(status, Some(committed));
}

#[test]
fn limits_names_and_displays_sit_on_their_documented_boundaries() {
    use fireemu_core_storage::store::{
        MAX_CUSTOM_METADATA_BYTES, MAX_OBJECT_BYTES, MAX_UPLOAD_SESSIONS,
        UPLOAD_SESSION_TTL_SECONDS,
    };
    assert_eq!(MAX_OBJECT_BYTES, 268_435_456);
    assert_eq!(MAX_CUSTOM_METADATA_BYTES, 8192);
    assert_eq!(UPLOAD_SESSION_TTL_SECONDS, 604_800);
    assert_eq!(MAX_UPLOAD_SESSIONS, 256);
    assert!(ObjectName::try_new("x".repeat(1024)).is_ok());
    assert!(BucketName::try_new("b".repeat(222)).is_ok());
    assert_eq!(
        BucketName::try_new("b".repeat(223)).unwrap_err(),
        NameError::TooLong
    );
    assert_eq!(BucketName::try_new("").unwrap_err(), NameError::Empty);
    assert_eq!(bucket().as_str(), "demo-app.appspot.com");
    assert_eq!(bucket().to_string(), "demo-app.appspot.com");
    assert_eq!(name("a/b").to_string(), "a/b");
    assert_eq!(NameError::TooLong.to_string(), "name is too long");
    assert_eq!(
        NameError::InvalidBucketCharacter.to_string(),
        "bucket name contains an invalid character"
    );
    assert_eq!(
        StorageError::UploadOffset { expected: 3 }.to_string(),
        "upload offset mismatch, expected 3"
    );
    assert_eq!(
        StorageError::TooManyUploads.to_string(),
        "too many open upload sessions"
    );
}

#[test]
fn custom_metadata_budget_is_exact_on_put_update_and_upload_start() {
    let mut s = StorageState::new(1);
    let b = bucket();
    let n = name("m");
    let custom = |value_len: usize| BTreeMap::from([("k".to_owned(), "v".repeat(value_len))]);
    // 1 byte of key + 8191 bytes of value = exactly the budget.
    let ok = NewMetadata {
        custom: Some(custom(8191)),
        ..NewMetadata::default()
    };
    let over = NewMetadata {
        custom: Some(custom(8192)),
        ..NewMetadata::default()
    };
    assert!(s
        .put(
            &b,
            &n,
            b"x".to_vec(),
            ok.clone(),
            Precondition::default(),
            t(1)
        )
        .is_ok());
    assert_eq!(
        s.put(
            &b,
            &n,
            b"x".to_vec(),
            over.clone(),
            Precondition::default(),
            t(1)
        ),
        Err(StorageError::MetadataTooLarge)
    );
    assert_eq!(
        s.begin_upload(&b, &n, over, Precondition::default(), None, t(1)),
        Err(StorageError::MetadataTooLarge)
    );
    assert!(s
        .begin_upload(&b, &n, ok, Precondition::default(), None, t(1))
        .is_ok());
    let patch = MetadataPatch {
        custom: Some(fireemu_core_storage::store::CustomMetadataPatch::Merge(
            BTreeMap::from([("k2".to_owned(), Some("v".to_owned()))]),
        )),
        ..MetadataPatch::default()
    };
    assert_eq!(
        s.update_metadata(&b, &n, &patch, Precondition::default(), t(2)),
        Err(StorageError::MetadataTooLarge)
    );
    let shrink = MetadataPatch {
        custom: Some(fireemu_core_storage::store::CustomMetadataPatch::Merge(
            BTreeMap::from([("k".to_owned(), None)]),
        )),
        ..MetadataPatch::default()
    };
    let m = s
        .update_metadata(&b, &n, &shrink, Precondition::default(), t(2))
        .unwrap();
    assert!(m.custom.is_empty());
}

#[test]
fn hashes_etag_tokens_and_bucket_scans() {
    let mut s = StorageState::new(5);
    let b = bucket();
    let other = BucketName::try_new("other-bucket").unwrap();
    let m = s
        .put(
            &b,
            &name("h"),
            b"abc".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            t(1),
        )
        .unwrap();
    assert_eq!(m.md5_base64(), "kAFQmDzST7DWlj99KOF/cg==");
    assert_eq!(m.crc32c_base64(), "Nks/tw==");
    assert_eq!(m.etag(), format!("\"{}-1\"", m.generation));
    assert_eq!(m.download_tokens.len(), 0, "the store mints nothing on put");
    let _ = s.drain_events();
    // A token is a metadata change: the metageneration bumps and a MetadataUpdated event
    // is recorded, as the official emulator's addDownloadToken behaves.
    let with_token = s.add_download_token(&b, &name("h"), t(2)).unwrap();
    let token = with_token.download_tokens[0].clone();
    assert_eq!(token.len(), 36, "UUID-shaped token");
    assert_eq!(token.as_bytes()[14], b'4', "UUID version 4");
    assert_eq!(with_token.metageneration, 2);
    assert_eq!(with_token.updated, t(2));
    let second = s.add_download_token(&b, &name("h"), t(3)).unwrap();
    assert_eq!(second.download_tokens.len(), 2);
    assert_ne!(second.download_tokens[1], token, "tokens are distinct");
    // Removing the last token mints a replacement; every change bumps the metageneration.
    let removed = s
        .remove_download_token(&b, &name("h"), &token, t(4))
        .unwrap();
    assert_eq!(
        removed.download_tokens,
        vec![second.download_tokens[1].clone()]
    );
    let replaced = s
        .remove_download_token(&b, &name("h"), &removed.download_tokens[0], t(5))
        .unwrap();
    assert_eq!(
        replaced.download_tokens.len(),
        1,
        "the last removal mints a new one"
    );
    assert_ne!(replaced.download_tokens[0], removed.download_tokens[0]);
    // The replacement mint is upstream's own silent update, so removing the last token
    // moves the metageneration by two (measured against the pinned suite).
    assert_eq!(replaced.metageneration, 6);
    let events = s.drain_events();
    assert_eq!(
        events.len(),
        4,
        "each token change is one MetadataUpdated event"
    );
    assert!(events
        .iter()
        .all(|e| matches!(e, StorageEvent::MetadataUpdated(_))));
    // Tokens ride in and out through the firebaseStorageDownloadTokens custom key.
    let seeded = s
        .put(
            &b,
            &name("seeded"),
            b"s".to_vec(),
            NewMetadata {
                custom: Some(BTreeMap::from([(
                    "firebaseStorageDownloadTokens".to_owned(),
                    "tok-a,tok-b,tok-a".to_owned(),
                )])),
                ..NewMetadata::default()
            },
            Precondition::default(),
            t(6),
        )
        .unwrap();
    assert_eq!(seeded.download_tokens, vec!["tok-a", "tok-b"]);
    assert!(
        seeded.custom.is_empty(),
        "the key never stays custom metadata"
    );
    assert_eq!(
        s.add_download_token(&b, &name("missing"), t(7)),
        Err(StorageError::NotFound)
    );
    assert_eq!(
        s.remove_download_token(&b, &name("missing"), "x", t(7)),
        Err(StorageError::NotFound)
    );
    s.put(
        &other,
        &name("o"),
        b"1".to_vec(),
        NewMetadata::default(),
        Precondition::default(),
        t(1),
    )
    .unwrap();
    assert_eq!(s.objects(&b).len(), 2, "h and the token-seeded object");
    assert_eq!(s.objects(&other)[0].name.as_str(), "o");
    assert!(
        s.get(&other, &name("h")).is_none(),
        "buckets are separate namespaces"
    );
    s.clear();
    assert!(s.objects(&b).is_empty() && s.objects(&other).is_empty());
    assert!(s.drain_events().is_empty());
}

#[test]
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
fn preconditions_check_both_directions_of_each_field() {
    let mut s = StorageState::new(1);
    let b = bucket();
    let n = name("p");
    let m = s
        .put(
            &b,
            &n,
            b"x".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            t(1),
        )
        .unwrap();
    let cases = [
        (
            Precondition {
                if_generation_match: Some(m.generation + 1),
                ..Precondition::default()
            },
            false,
        ),
        (
            Precondition {
                if_generation_match: Some(m.generation),
                ..Precondition::default()
            },
            true,
        ),
        (
            Precondition {
                if_metageneration_match: Some(2),
                ..Precondition::default()
            },
            false,
        ),
        (
            Precondition {
                if_metageneration_match: Some(1),
                ..Precondition::default()
            },
            true,
        ),
        (
            Precondition {
                if_metageneration_not_match: Some(1),
                ..Precondition::default()
            },
            false,
        ),
        (
            Precondition {
                if_metageneration_not_match: Some(2),
                ..Precondition::default()
            },
            true,
        ),
    ];
    for (pre, ok) in cases {
        let patch = MetadataPatch::default();
        let r = s.update_metadata(&b, &n, &patch, pre, t(2));
        assert_eq!(r.is_ok(), ok, "{pre:?}");
        if ok {
            // Restore the metageneration expectation for the next case.
            s.delete(&b, &n, Precondition::default()).unwrap();
            let again = s
                .put(
                    &b,
                    &n,
                    b"x".to_vec(),
                    NewMetadata::default(),
                    Precondition::default(),
                    t(1),
                )
                .unwrap();
            assert!(again.generation > m.generation);
            // Cases after this one compare against metageneration 1 again; the generation
            // cases were first, so nothing else depends on the generation value.
        }
    }
    // A missing object counts as generation 0 for match preconditions.
    let absent = Precondition {
        if_generation_match: Some(0),
        ..Precondition::default()
    };
    assert!(s
        .put(
            &b,
            &name("new"),
            b"y".to_vec(),
            NewMetadata::default(),
            absent,
            t(3)
        )
        .is_ok());
    let current = s.get(&b, &name("new")).unwrap().generation;
    assert_eq!(
        s.put(
            &b,
            &name("new"),
            b"y".to_vec(),
            NewMetadata::default(),
            absent,
            t(3)
        ),
        Err(StorageError::PreconditionFailed(format!(
            "ifGenerationMatch 0 but the current generation is {current}"
        )))
    );
}

#[test]
fn upload_sessions_expire_are_capped_and_reject_oversized_totals() {
    use fireemu_core_storage::store::{
        MAX_OBJECT_BYTES, MAX_UPLOAD_SESSIONS, UPLOAD_SESSION_TTL_SECONDS,
    };
    let mut s = StorageState::new(1);
    let b = bucket();
    assert_eq!(
        s.begin_upload(
            &b,
            &name("x"),
            NewMetadata::default(),
            Precondition::default(),
            Some(MAX_OBJECT_BYTES + 1),
            t(0)
        ),
        Err(StorageError::TooLarge)
    );
    let id = s
        .begin_upload(
            &b,
            &name("x"),
            NewMetadata::default(),
            Precondition::default(),
            Some(MAX_OBJECT_BYTES),
            t(0),
        )
        .unwrap();
    assert_eq!(id.as_str().len(), "upload-00000001-".len() + 36);
    assert_eq!(
        s.set_upload_total(&id, MAX_OBJECT_BYTES + 1, t(0)),
        Err(StorageError::TooLarge)
    );
    // Exactly the TTL is still alive; one second more is gone.
    assert_eq!(
        s.upload_status(&id, t(UPLOAD_SESSION_TTL_SECONDS))
            .unwrap()
            .0,
        0
    );
    assert_eq!(
        s.upload_status(&id, t(UPLOAD_SESSION_TTL_SECONDS + 1)),
        Err(StorageError::UploadNotFound)
    );
    // Cancel frees the buffer and blocks further chunks.
    let id = s
        .begin_upload(
            &b,
            &name("c"),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(0),
        )
        .unwrap();
    s.append_upload(&id, 0, b"abc", t(0)).unwrap();
    s.cancel_upload(&id, t(0)).unwrap();
    assert_eq!(s.upload_status(&id, t(0)).unwrap().0, 0);
    assert_eq!(
        s.append_upload(&id, 3, b"d", t(0)),
        Err(StorageError::UploadFinalized)
    );
    assert_eq!(
        s.cancel_upload(&id, t(UPLOAD_SESSION_TTL_SECONDS + 1)),
        Err(StorageError::UploadNotFound)
    );
    // The cap counts open sessions; expired ones are swept first.
    let mut s = StorageState::new(2);
    for i in 0..MAX_UPLOAD_SESSIONS {
        s.begin_upload(
            &b,
            &name(&format!("n{i}")),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(0),
        )
        .unwrap();
    }
    assert_eq!(
        s.begin_upload(
            &b,
            &name("one-more"),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(0)
        ),
        Err(StorageError::TooManyUploads)
    );
    assert!(s
        .begin_upload(
            &b,
            &name("later"),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(UPLOAD_SESSION_TTL_SECONDS + 1)
        )
        .is_ok());
}

#[test]
fn absent_objects_satisfy_only_if_generation_match_zero() {
    let mut s = StorageState::new(1);
    let b = bucket();
    let n = name("absent");
    let put = |s: &mut StorageState, pre: Precondition| {
        s.put(&b, &n, b"x".to_vec(), NewMetadata::default(), pre, t(1))
    };
    assert!(matches!(
        put(
            &mut s,
            Precondition {
                if_generation_not_match: Some(123),
                ..Precondition::default()
            }
        ),
        Err(StorageError::PreconditionFailed(_))
    ));
    assert!(matches!(
        put(
            &mut s,
            Precondition {
                if_metageneration_match: Some(0),
                ..Precondition::default()
            }
        ),
        Err(StorageError::PreconditionFailed(_))
    ));
    assert!(matches!(
        put(
            &mut s,
            Precondition {
                if_metageneration_not_match: Some(1),
                ..Precondition::default()
            }
        ),
        Err(StorageError::PreconditionFailed(_))
    ));
    assert!(put(
        &mut s,
        Precondition {
            if_generation_match: Some(0),
            ..Precondition::default()
        }
    )
    .is_ok());
}

#[test]
fn finished_upload_sessions_do_not_count_against_the_open_session_cap() {
    use fireemu_core_storage::store::{MAX_FINISHED_UPLOAD_SESSIONS, MAX_UPLOAD_SESSIONS};
    let mut s = StorageState::new(1);
    let b = bucket();
    let mut first: Option<fireemu_core_storage::store::UploadId> = None;
    for i in 0..(MAX_UPLOAD_SESSIONS + MAX_FINISHED_UPLOAD_SESSIONS + 10) {
        let id = s
            .begin_upload(
                &b,
                &name(&format!("f{i}")),
                NewMetadata::default(),
                Precondition::default(),
                None,
                t(0),
            )
            .unwrap();
        s.upload_chunk(&id, 0, b"x", true, t(0)).unwrap();
        first.get_or_insert(id);
    }
    // The oldest finished sessions were evicted; recent ones still answer status queries.
    assert_eq!(
        s.upload_status(&first.unwrap(), t(0)),
        Err(StorageError::UploadNotFound)
    );
}

#[test]
fn declared_checksums_end_the_session_on_mismatch() {
    use fireemu_core_storage::store::UploadOptions;
    let mut s = StorageState::new(1);
    let b = bucket();
    let id = s
        .begin_upload_with(
            &b,
            &name("c"),
            NewMetadata::default(),
            Precondition::default(),
            UploadOptions {
                expected_crc32c: Some(0),
                authorization: Some("Bearer owner".into()),
                ..UploadOptions::default()
            },
            t(0),
        )
        .unwrap();
    s.append_upload(&id, 0, b"abc", t(0)).unwrap();
    assert_eq!(
        s.pending_upload(&id, t(0)).unwrap().authorization,
        Some("Bearer owner")
    );
    assert!(matches!(
        s.finalize_upload(&id, t(0)),
        Err(StorageError::ChecksumMismatch(_))
    ));
    assert_eq!(
        s.finalize_upload(&id, t(0)),
        Err(StorageError::UploadFinalized)
    );
    assert!(s.get(&b, &name("c")).is_none());
    let id = s
        .begin_upload(
            &b,
            &name("c"),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(0),
        )
        .unwrap();
    s.set_upload_hashes(
        &id,
        Some(fireemu_core_storage::hash::md5(b"abc")),
        None,
        t(0),
    )
    .unwrap();
    s.append_upload(&id, 0, b"abc", t(0)).unwrap();
    assert!(s.finalize_upload(&id, t(0)).is_ok());
}

#[test]
fn resumable_checksums_hash_each_accepted_byte_once() {
    use fireemu_core_storage::store::UploadOptions;

    let mut store = StorageState::new(1);
    let bucket = bucket();
    let expected = b"abcdefgh";
    let id = store
        .begin_upload_with(
            &bucket,
            &name("incremental"),
            NewMetadata::default(),
            Precondition::default(),
            UploadOptions {
                expected_md5: Some(md5(expected)),
                expected_crc32c: Some(crc32c(expected)),
                ..UploadOptions::default()
            },
            t(0),
        )
        .unwrap();

    store.append_upload(&id, 0, b"abcde", t(0)).unwrap();
    // Only the unseen suffix is accepted and hashed when a retry overlaps prior bytes.
    store.append_upload(&id, 3, b"defgh", t(0)).unwrap();
    // A fully repeated chunk must not perturb either digest.
    store.append_upload(&id, 0, expected, t(0)).unwrap();

    let metadata = store.finalize_upload(&id, t(0)).unwrap();
    assert_eq!(metadata.md5, md5(expected));
    assert_eq!(metadata.crc32c, crc32c(expected));
    assert_eq!(store.bytes(&metadata), expected);
}

#[test]
fn an_owned_chunk_is_adopted_by_an_empty_session_and_follows_every_append_rule() {
    let mut s = StorageState::new(4);
    let (b, n) = (bucket(), name("owned.bin"));
    let id = s
        .begin_upload(
            &b,
            &n,
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(1),
        )
        .unwrap();
    // The first chunk of an empty session becomes the session buffer as it is.
    let chunk = vec![9u8; 4096];
    let at = chunk.as_ptr();
    assert_eq!(s.append_upload_owned(&id, 0, chunk, t(1)), Ok(4096));
    assert_eq!(s.pending_upload(&id, t(1)).unwrap().bytes.as_ptr(), at);
    // A later chunk appends, a gap is refused, a repeat is ignored.
    assert_eq!(
        s.append_upload_owned(&id, 4096, vec![1u8; 4], t(1)),
        Ok(4100)
    );
    assert_eq!(
        s.append_upload_owned(&id, 4200, vec![1u8; 4], t(1)),
        Err(StorageError::UploadOffset { expected: 4100 })
    );
    assert_eq!(s.append_upload_owned(&id, 0, vec![9u8; 8], t(1)), Ok(4100));
    let meta = s.finalize_upload(&id, t(2)).unwrap();
    assert_eq!(meta.size, 4100);
    // The committed blob is still the buffer the first chunk arrived in.
    assert_eq!(s.bytes(&meta).len(), 4100);

    // A declared total is enforced on the adopted chunk as well.
    let id = s
        .begin_upload(
            &b,
            &name("small.bin"),
            NewMetadata::default(),
            Precondition::default(),
            Some(2),
            t(3),
        )
        .unwrap();
    assert_eq!(
        s.append_upload_owned(&id, 0, vec![1u8; 3], t(3)),
        Err(StorageError::UploadSizeMismatch)
    );
    assert_eq!(
        s.append_upload_owned(&id, 0, vec![1u8; 1], t(3)),
        Err(StorageError::UploadFinalized),
        "a size mismatch ends the session"
    );
}

#[test]
fn download_tokens_are_capped_and_do_not_escape_the_metadata_budget() {
    use fireemu_core_storage::store::{
        CustomMetadataPatch, MAX_DOWNLOAD_TOKENS, MAX_DOWNLOAD_TOKEN_LEN,
    };
    let mut s = StorageState::new(7);
    let b = bucket();
    let n = name("t");

    // The per-token length cap: an over-long single token is dropped, not stored, and never
    // stashes unbounded state under this one key (S-1). Non-token custom metadata is what the
    // 8 KiB budget still guards, so a short list rides through and the budget is unaffected.
    let long_token = "b".repeat(MAX_DOWNLOAD_TOKEN_LEN + 1);
    let with_long = NewMetadata {
        custom: Some(BTreeMap::from([(
            "firebaseStorageDownloadTokens".to_owned(),
            format!("keep,{long_token}"),
        )])),
        ..NewMetadata::default()
    };
    let m = s
        .put(
            &b,
            &n,
            b"x".to_vec(),
            with_long,
            Precondition::default(),
            t(1),
        )
        .unwrap();
    assert_eq!(
        m.download_tokens,
        vec!["keep"],
        "the over-long token is dropped"
    );

    // The count cap: a list far past MAX_DOWNLOAD_TOKENS keeps only the cap, so the joined
    // value can never grow without bound (cap x length stays well under the 8 KiB budget).
    let many: Vec<String> = (0..MAX_DOWNLOAD_TOKENS + 200)
        .map(|i| format!("t{i}"))
        .collect();
    let over = NewMetadata {
        custom: Some(BTreeMap::from([(
            "firebaseStorageDownloadTokens".to_owned(),
            many.join(","),
        )])),
        ..NewMetadata::default()
    };
    let m = s
        .put(&b, &n, b"y".to_vec(), over, Precondition::default(), t(2))
        .unwrap();
    assert_eq!(
        m.download_tokens.len(),
        MAX_DOWNLOAD_TOKENS,
        "the count is capped on put"
    );

    // update_metadata caps the same way when it merges the key.
    let patch = MetadataPatch {
        custom: Some(CustomMetadataPatch::Merge(BTreeMap::from([(
            "firebaseStorageDownloadTokens".to_owned(),
            Some(many.join(",")),
        )]))),
        ..MetadataPatch::default()
    };
    let m = s
        .update_metadata(&b, &n, &patch, Precondition::default(), t(3))
        .unwrap();
    assert_eq!(
        m.download_tokens.len(),
        MAX_DOWNLOAD_TOKENS,
        "the count is capped on update"
    );

    // ?create_token=true (add_download_token) refuses to grow past the cap one at a time.
    for k in 0..1000 {
        if s.add_download_token(&b, &n, t(4 + k)).is_err() {
            break;
        }
    }
    assert_eq!(
        s.get(&b, &n).unwrap().download_tokens.len(),
        MAX_DOWNLOAD_TOKENS,
        "minting one token at a time never exceeds the cap"
    );

    // The plain (non-token) custom budget is unchanged: a 9 KiB ordinary value is refused.
    let fat = NewMetadata {
        custom: Some(BTreeMap::from([("k".to_owned(), "v".repeat(9 * 1024))])),
        ..NewMetadata::default()
    };
    assert_eq!(
        s.put(
            &b,
            &name("fat"),
            b"x".to_vec(),
            fat,
            Precondition::default(),
            t(2000)
        ),
        Err(StorageError::MetadataTooLarge)
    );
}

#[test]
fn copying_an_object_keeps_metadata_within_the_budget() {
    let mut s = StorageState::new(9);
    let b = bucket();
    s.put(
        &b,
        &name("src"),
        b"data".to_vec(),
        NewMetadata {
            custom: Some(BTreeMap::from([("k".to_owned(), "v".to_owned())])),
            ..NewMetadata::default()
        },
        Precondition::default(),
        t(0),
    )
    .unwrap();
    // A copy with no override inherits the source's ordinary custom metadata (the adapter is
    // what carries download tokens across a copy; the storage-probe pins that path).
    let copied = s
        .copy(
            (&b, &name("src")),
            (&b, &name("dst")),
            None,
            Precondition::default(),
            t(1),
        )
        .unwrap();
    assert_eq!(copied.custom.get("k").map(String::as_str), Some("v"));
    // A copy whose override metadata carries an oversized ordinary value is refused on the
    // budget, so the S-1 changes did not open a copy-shaped bypass.
    let over = NewMetadata {
        custom: Some(BTreeMap::from([("k".to_owned(), "v".repeat(9 * 1024))])),
        ..NewMetadata::default()
    };
    assert_eq!(
        s.copy(
            (&b, &name("src")),
            (&b, &name("dst2")),
            Some(over),
            Precondition::default(),
            t(2)
        ),
        Err(StorageError::MetadataTooLarge)
    );
}

#[test]
fn a_denied_upload_releases_its_bytes_but_keeps_its_count() {
    use fireemu_core_storage::store::UploadPhase;
    let mut s = StorageState::new(11);
    let b = bucket();
    let id = s
        .begin_upload(
            &b,
            &name("big.bin"),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(0),
        )
        .unwrap();
    let chunk = vec![7u8; 1024 * 1024];
    s.append_upload_owned(&id, 0, chunk, t(0)).unwrap();
    // Rules refused the finalization: the session is terminal, the byte count stays
    // observable, and the bytes themselves are released (S-2).
    s.mark_upload_denied(&id, t(0)).unwrap();
    assert_eq!(
        s.upload_phase(&id, t(0)).unwrap(),
        UploadPhase::Denied(1024 * 1024)
    );
    let (received, committed) = s.upload_status(&id, t(0)).unwrap();
    assert_eq!((received, committed.is_none()), (1024 * 1024, true));
}

#[test]
fn a_denied_upload_can_never_be_revived() {
    let mut s = StorageState::new(13);
    let b = bucket();
    let id = s
        .begin_upload(
            &b,
            &name("x.bin"),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(0),
        )
        .unwrap();
    s.append_upload_owned(&id, 0, vec![1u8; 8], t(0)).unwrap();
    s.mark_upload_denied(&id, t(0)).unwrap();
    // Every mutating path refuses a denied session, so no object is ever published.
    assert_eq!(
        s.append_upload(&id, 8, b"more", t(0)),
        Err(StorageError::UploadFinalized)
    );
    assert_eq!(
        s.append_upload_owned(&id, 8, b"more".to_vec(), t(0)),
        Err(StorageError::UploadFinalized)
    );
    assert_eq!(
        s.finalize_upload(&id, t(0)),
        Err(StorageError::UploadFinalized)
    );
    assert_eq!(
        s.cancel_upload(&id, t(0)),
        Err(StorageError::UploadFinalized)
    );
    assert!(s.pending_upload(&id, t(0)).is_err());
    assert!(s.get(&b, &name("x.bin")).is_none(), "nothing was published");
}
