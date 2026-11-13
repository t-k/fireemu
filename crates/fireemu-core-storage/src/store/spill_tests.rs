//! Failure handling of resumable sessions that keep their bytes in spill files.

use super::*;
use crate::spill::fault::{fail_next, Op};
use std::sync::atomic::{AtomicU64, Ordering};

const NOW: LogicalInstant = LogicalInstant::UNIX_EPOCH;

struct Fixture {
    dir: std::path::PathBuf,
    store: StorageState,
    bucket: BucketName,
}

impl Fixture {
    fn new(threshold: u64) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "store-spill-faults-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut store = StorageState::new(1);
        store.set_spill(Some((SpillDir::new(&dir), threshold)));
        Self {
            dir,
            store,
            bucket: BucketName::try_new("example.appspot.com").unwrap(),
        }
    }

    fn session(&mut self, name: &str) -> UploadId {
        self.store
            .begin_upload(
                &self.bucket,
                &ObjectName::try_new(name).unwrap(),
                NewMetadata::default(),
                Precondition::default(),
                None,
                NOW,
            )
            .unwrap()
    }

    fn files(&self) -> usize {
        std::fs::read_dir(&self.dir).map_or(0, Iterator::count)
    }

    fn received(&mut self, id: &UploadId) -> Vec<u8> {
        match &self.store.uploads.get(id).unwrap().received {
            SessionBytes::Memory(bytes) => bytes.clone(),
            SessionBytes::Spilled(file) => file.read_all().unwrap(),
        }
    }

    /// The running digests agree with the bytes the session holds.
    fn assert_consistent(&mut self, id: &UploadId) {
        let bytes = self.received(id);
        assert_eq!(
            self.store.pending_upload(id, NOW).unwrap().digests,
            ObjectDigests::new(&bytes)
        );
        assert_eq!(
            self.store.pending_upload(id, NOW).unwrap().len,
            bytes.len() as u64
        );
        assert_eq!(
            self.store.retained_upload_bytes,
            StorageState::upload_bytes(&self.store.uploads)
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn a_failed_truncate_leaves_the_session_as_it_was_and_a_retry_rolls_back() {
    let mut f = Fixture::new(4);
    let id = f.session("object");
    f.store.append_upload(&id, 0, b"abcdef", NOW).unwrap();
    let checkpoint = f.store.upload_checkpoint(&id).unwrap();
    f.store.append_upload(&id, 6, b"ghij", NOW).unwrap();
    fail_next(Op::Truncate);
    assert!(matches!(
        f.store.rollback_upload(&id, checkpoint.clone()),
        Err(StorageError::SpillFailed(_))
    ));
    assert_eq!(f.received(&id), b"abcdefghij");
    assert_eq!(f.store.retained_upload_bytes, 10);
    f.assert_consistent(&id);
    // The session is still receiving at the longer offset, so the client's retry is accepted.
    assert_eq!(f.store.append_upload(&id, 6, b"ghij", NOW), Ok(10));
    f.store.rollback_upload(&id, checkpoint).unwrap();
    assert_eq!(f.received(&id), b"abcdef");
    assert_eq!(f.store.retained_upload_bytes, 6);
    f.assert_consistent(&id);
}

#[test]
fn a_finalizing_chunk_refused_by_the_bound_reports_a_rollback_that_failed() {
    let mut f = Fixture::new(4);
    let id = f.session("object");
    f.store.append_upload(&id, 0, b"abcdef", NOW).unwrap();
    f.store.set_stored_bytes_limit(Some(8));
    fail_next(Op::Truncate);
    assert!(matches!(
        f.store.upload_chunk(&id, 6, b"ghijkl", true, NOW),
        Err(StorageError::SpillFailed(_))
    ));
    assert_eq!(f.received(&id), b"abcdefghijkl");
    f.assert_consistent(&id);
    assert!(f
        .store
        .get(&f.bucket.clone(), &ObjectName::try_new("object").unwrap())
        .is_none());
    // Without the fault the same chunk is taken back and the bound is reported.
    f.store
        .rollback_upload(&id, f.store.upload_checkpoint(&id).unwrap())
        .unwrap();
    let id = f.session("again");
    f.store.append_upload(&id, 0, b"abcdef", NOW).unwrap();
    assert_eq!(
        f.store.upload_chunk(&id, 6, b"ghijkl", true, NOW),
        Err(StorageError::StoredBytesLimit)
    );
    assert_eq!(f.received(&id), b"abcdef");
}

#[test]
fn object_capture_does_not_copy_pending_uploads() {
    let mut f = Fixture::new(4);
    let name = ObjectName::try_new("committed").unwrap();
    f.store
        .put(
            &f.bucket,
            &name,
            b"abc".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            NOW,
        )
        .unwrap();
    let id = f.session("pending");
    f.store.append_upload(&id, 0, b"pending", NOW).unwrap();
    assert_eq!(f.files(), 1);
    fail_next(Op::Copy);
    let captured = f.store.capture_bucket_objects(|_| true);
    assert!(captured.uploads.is_empty());
    assert_eq!(captured.retained_upload_bytes, 0);
    let object = captured.get(&f.bucket, &name).unwrap();
    assert_eq!(object, f.store.get(&f.bucket, &name).unwrap());
    assert_eq!(captured.body_bytes(object).unwrap().as_ref(), b"abc");
    assert_eq!(f.files(), 1);
    assert!(matches!(
        f.store.capture_buckets(|_| true),
        Err(StorageError::SpillFailed(_))
    ));
    assert_eq!(f.received(&id), b"pending");
}

#[test]
fn a_failed_capture_changes_nothing_and_leaves_no_file() {
    let mut f = Fixture::new(4);
    let first = f.session("first");
    let second = f.session("second");
    f.store
        .append_upload(&first, 0, b"0123456789", NOW)
        .unwrap();
    f.store.append_upload(&second, 0, b"abcdefgh", NOW).unwrap();
    assert_eq!(f.files(), 2);
    fail_next(Op::Copy);
    assert!(matches!(
        f.store.capture_buckets(|_| true),
        Err(StorageError::SpillFailed(_))
    ));
    assert_eq!(f.files(), 2);
    assert_eq!(f.received(&first), b"0123456789");
    assert_eq!(f.received(&second), b"abcdefgh");
    f.assert_consistent(&first);
    let captured = f.store.capture_buckets(|_| true).unwrap();
    assert_eq!(f.files(), 4);
    drop(captured);
    assert_eq!(f.files(), 2);
}

#[test]
fn a_failed_restore_changes_nothing() {
    let mut f = Fixture::new(4);
    let id = f.session("object");
    f.store.append_upload(&id, 0, b"01234567", NOW).unwrap();
    let captured = f.store.capture_buckets(|_| true).unwrap();
    f.store.append_upload(&id, 8, b"89", NOW).unwrap();
    let kept = f.session("kept");
    f.store
        .append_upload(&kept, 0, b"keep me please", NOW)
        .unwrap();
    let files = f.files();
    fail_next(Op::Copy);
    assert!(matches!(
        f.store.restore_buckets(|_| true, &captured),
        Err(StorageError::SpillFailed(_))
    ));
    assert_eq!(f.files(), files);
    assert_eq!(f.received(&id), b"0123456789");
    assert_eq!(f.received(&kept), b"keep me please");
    f.assert_consistent(&id);
    f.store.restore_buckets(|_| true, &captured).unwrap();
    assert_eq!(f.received(&id), b"01234567");
    assert!(!f.store.uploads.contains_key(&kept));
    f.assert_consistent(&id);
}

#[test]
fn a_failed_move_into_a_file_leaves_a_memory_session_untouched() {
    let mut f = Fixture::new(8);
    let id = f.session("object");
    f.store.append_upload(&id, 0, b"abcde", NOW).unwrap();
    fail_next(Op::AppendAfterWrite);
    assert!(matches!(
        f.store.append_upload(&id, 5, b"fghij", NOW),
        Err(StorageError::SpillFailed(_))
    ));
    assert_eq!(f.store.spilled_upload_sessions(), 0);
    assert_eq!(f.files(), 0);
    assert_eq!(f.received(&id), b"abcde");
    f.assert_consistent(&id);
    assert_eq!(f.store.append_upload(&id, 5, b"fghij", NOW), Ok(10));
    assert_eq!(f.store.spilled_upload_sessions(), 1);
    assert_eq!(f.received(&id), b"abcdefghij");
    f.assert_consistent(&id);
}

#[test]
fn a_failed_append_to_a_spilled_session_keeps_the_bytes_and_digests_in_step() {
    let mut f = Fixture::new(4);
    let id = f.session("object");
    f.store.append_upload(&id, 0, b"abcdef", NOW).unwrap();
    assert_eq!(f.store.spilled_upload_sessions(), 1);
    fail_next(Op::AppendAfterWrite);
    assert!(matches!(
        f.store.append_upload(&id, 6, b"ghij", NOW),
        Err(StorageError::SpillFailed(_))
    ));
    assert_eq!(f.received(&id), b"abcdef");
    assert_eq!(f.store.retained_upload_bytes, 6);
    f.assert_consistent(&id);
    assert_eq!(f.store.append_upload(&id, 6, b"XY", NOW), Ok(8));
    assert_eq!(f.received(&id), b"abcdefXY");
    f.assert_consistent(&id);
    let object = f.store.finalize_upload(&id, NOW).unwrap();
    assert_eq!(f.store.body_bytes(&object).unwrap().as_ref(), b"abcdefXY");
}

#[test]
fn an_empty_session_adopts_a_small_owned_chunk_but_spills_one_at_the_threshold() {
    let mut f = Fixture::new(8);
    let id = f.session("small");
    let chunk = vec![9u8; 7];
    let at = chunk.as_ptr();
    f.store.append_upload_owned(&id, 0, chunk, NOW).unwrap();
    match &f.store.uploads.get(&id).unwrap().received {
        SessionBytes::Memory(bytes) => assert_eq!(bytes.as_ptr(), at),
        SessionBytes::Spilled(_) => panic!("below the threshold the session stays in memory"),
    }
    let id = f.session("large");
    f.store
        .append_upload_owned(&id, 0, vec![1u8; 8], NOW)
        .unwrap();
    assert!(f.store.uploads.get(&id).unwrap().received.is_spilled());
    assert_eq!(f.received(&id), vec![1u8; 8]);
    f.assert_consistent(&id);
}

#[test]
fn an_object_below_the_threshold_that_was_spilled_as_a_session_is_read_back_into_memory() {
    let mut f = Fixture::new(8);
    let id = f.session("object");
    f.store.append_upload(&id, 0, b"abc", NOW).unwrap();
    let checkpoint = f.store.upload_checkpoint(&id).unwrap();
    f.store.append_upload(&id, 3, b"defghijk", NOW).unwrap();
    assert!(f.store.uploads.get(&id).unwrap().received.is_spilled());
    f.store.rollback_upload(&id, checkpoint).unwrap();
    let object = f.store.finalize_upload(&id, NOW).unwrap();
    assert_eq!(f.store.bytes(&object), b"abc");
    assert_eq!(f.files(), 0);
}

#[test]
fn a_spilled_session_finalizes_to_a_memory_object_when_the_spill_is_switched_off() {
    let mut f = Fixture::new(4);
    let id = f.session("object");
    f.store.append_upload(&id, 0, b"abcdefgh", NOW).unwrap();
    f.store.set_spill(None);
    let object = f.store.finalize_upload(&id, NOW).unwrap();
    assert_eq!(f.store.bytes(&object), b"abcdefgh");
    assert_eq!(f.files(), 0);
}

#[test]
fn a_failed_read_back_leaves_the_session_open() {
    let mut f = Fixture::new(4);
    let id = f.session("object");
    f.store.append_upload(&id, 0, b"abcdefgh", NOW).unwrap();
    f.store.set_spill(None);
    // Break the file: the read-back at finalization must fail without losing the session.
    let SessionBytes::Spilled(file) = &f.store.uploads.get(&id).unwrap().received else {
        panic!("spilled");
    };
    let path = file.path().to_owned();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(2)
        .unwrap();
    assert!(matches!(
        f.store.finalize_upload(&id, NOW),
        Err(StorageError::SpillFailed(_))
    ));
    assert!(matches!(
        f.store.upload_phase(&id, NOW),
        Ok(UploadPhase::Active(8))
    ));
}

#[test]
fn truncating_a_spilled_session_touches_the_file_only_when_it_gets_shorter() {
    let mut f = Fixture::new(4);
    let id = f.session("object");
    f.store.append_upload(&id, 0, b"abcdef", NOW).unwrap();
    let SessionBytes::Spilled(file) = &mut f.store.uploads.get_mut(&id).unwrap().received else {
        panic!("spilled");
    };
    let mut bytes = SessionBytes::Spilled(file.try_clone().unwrap());
    // At the length or past it nothing is truncated, so an armed failure is not triggered.
    fail_next(Op::Truncate);
    bytes.truncate(6).unwrap();
    bytes.truncate(7).unwrap();
    assert_eq!(bytes.len(), 6);
    assert!(matches!(
        bytes.truncate(5),
        Err(StorageError::SpillFailed(_))
    ));
    assert_eq!(bytes.len(), 6);
    bytes.truncate(5).unwrap();
    assert_eq!(bytes.len(), 5);
}

#[test]
fn the_running_hashes_of_a_session_are_those_of_its_bytes_in_memory_and_in_a_file() {
    for threshold in [1_000, 4] {
        let mut f = Fixture::new(threshold);
        let id = f.session("object");
        f.store.append_upload(&id, 0, b"hello ", NOW).unwrap();
        f.store.append_upload(&id, 6, b"world", NOW).unwrap();
        assert_eq!(
            f.store.uploads.get(&id).unwrap().received.is_spilled(),
            threshold == 4
        );
        let expected = ObjectDigests::new(b"hello world");
        assert_eq!(
            f.store.upload_running_hashes(&id, NOW),
            Ok((expected.crc32c, expected.md5))
        );
        f.assert_consistent(&id);
    }
}
