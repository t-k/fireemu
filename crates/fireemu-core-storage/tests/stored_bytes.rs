//! `storage.maxStoredBytes`: a local bound on the object data a store retains (owner ledger
//! 759). Unset, nothing is bounded. A write that would cross the bound is refused with
//! `StoredBytesLimit` and changes no object, generation, event or byte count; a refused final
//! chunk of a resumable upload does not advance its offset, and the session stays usable.

use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{
    NewMetadata, Precondition, StorageError, StorageState, UploadPhase,
};
use fireemu_core_types::resources::RootBudget;
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

fn put(s: &mut StorageState, object: &str, len: usize) -> Result<(), StorageError> {
    s.put(
        &bucket(),
        &name(object),
        vec![7; len],
        NewMetadata::default(),
        Precondition::default(),
        t(0),
    )
    .map(drop)
}

/// The bytes the objects of every bucket hold, counted from their metadata.
fn recount(s: &StorageState) -> u64 {
    s.buckets()
        .iter()
        .flat_map(|b| s.objects(b))
        .map(|meta| meta.size)
        .sum()
}

/// What a refusal must leave unchanged.
fn observable(s: &StorageState) -> (Vec<String>, u64, u64) {
    let objects = s
        .buckets()
        .iter()
        .flat_map(|b| s.objects(b))
        .map(|meta| {
            format!(
                "{}/{}#{}:{}",
                meta.bucket.as_str(),
                meta.name.as_str(),
                meta.generation,
                meta.size
            )
        })
        .collect();
    (
        objects,
        s.retained_blob_bytes(),
        s.next_generation_preview(t(0)).unwrap(),
    )
}

#[test]
fn an_unset_limit_bounds_nothing() {
    let mut s = StorageState::new(1);
    assert_eq!(s.stored_bytes_limit(), None);
    for object in ["a", "b", "c"] {
        put(&mut s, object, 1 << 20).unwrap();
    }
    assert_eq!(s.retained_blob_bytes(), 3 << 20);
}

#[test]
fn a_write_past_the_limit_is_refused_whole() {
    let mut s = StorageState::new(1);
    s.set_stored_bytes_limit(Some(10));
    assert_eq!(s.stored_bytes_limit(), Some(10));
    put(&mut s, "a", 6).unwrap();
    put(&mut s, "b", 4).unwrap();
    assert_eq!(
        s.retained_blob_bytes(),
        10,
        "exactly at the limit is accepted"
    );
    s.drain_events();
    let before = observable(&s);
    assert_eq!(put(&mut s, "c", 1), Err(StorageError::StoredBytesLimit));
    assert_eq!(observable(&s), before);
    assert!(s.drain_events().is_empty(), "a refusal publishes no event");
}

#[test]
fn a_replacement_is_charged_only_its_difference() {
    let mut s = StorageState::new(1);
    s.set_stored_bytes_limit(Some(10));
    put(&mut s, "a", 6).unwrap();
    put(&mut s, "b", 4).unwrap();
    put(&mut s, "a", 6).unwrap();
    put(&mut s, "a", 2).unwrap();
    assert_eq!(s.retained_blob_bytes(), 6);
    assert_eq!(put(&mut s, "a", 7), Err(StorageError::StoredBytesLimit));
    put(&mut s, "a", 6).unwrap();
    s.delete(&bucket(), &name("b"), Precondition::default())
        .unwrap();
    put(&mut s, "a", 10).unwrap();
    assert_eq!(s.retained_blob_bytes(), 10);
}

#[test]
fn a_copy_is_charged_like_a_new_object() {
    let mut s = StorageState::new(1);
    s.set_stored_bytes_limit(Some(10));
    put(&mut s, "a", 6).unwrap();
    let before = observable(&s);
    assert_eq!(
        s.copy(
            (&bucket(), &name("a")),
            (&bucket(), &name("b")),
            None,
            Precondition::default(),
            t(1),
        ),
        Err(StorageError::StoredBytesLimit)
    );
    assert_eq!(observable(&s), before);
}

#[test]
fn a_refused_final_chunk_keeps_the_session_and_its_offset() {
    let mut s = StorageState::new(1);
    s.set_stored_bytes_limit(Some(10));
    put(&mut s, "a", 6).unwrap();
    let id = s
        .begin_upload(
            &bucket(),
            &name("b"),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(1),
        )
        .unwrap();
    assert_eq!(
        s.upload_chunk(&id, 0, b"abc", false, t(2))
            .unwrap()
            .received,
        3
    );
    let before = observable(&s);
    assert_eq!(
        s.upload_chunk(&id, 3, b"de", true, t(3)),
        Err(StorageError::StoredBytesLimit)
    );
    assert_eq!(observable(&s), before);
    assert_eq!(s.upload_phase(&id, t(3)).unwrap(), UploadPhase::Active(3));

    // Once there is room, the same chunk finishes the upload with the right bytes.
    s.delete(&bucket(), &name("a"), Precondition::default())
        .unwrap();
    let done = s.upload_chunk(&id, 3, b"de", true, t(4)).unwrap();
    assert_eq!(done.committed.map(|meta| meta.size), Some(5));
    let meta = s.get(&bucket(), &name("b")).cloned().unwrap();
    assert_eq!(s.bytes(&meta), b"abcde");
}

#[test]
fn a_refused_finalize_keeps_the_session_cancellable() {
    let mut s = StorageState::new(1);
    s.set_stored_bytes_limit(Some(4));
    let id = s
        .begin_upload(
            &bucket(),
            &name("b"),
            NewMetadata::default(),
            Precondition::default(),
            None,
            t(1),
        )
        .unwrap();
    s.upload_chunk(&id, 0, b"abcde", false, t(2)).unwrap();
    assert_eq!(
        s.finalize_upload(&id, t(3)),
        Err(StorageError::StoredBytesLimit)
    );
    assert_eq!(s.upload_phase(&id, t(3)).unwrap(), UploadPhase::Active(5));
    s.cancel_upload(&id, t(4)).unwrap();
    assert_eq!(
        s.upload_phase(&id, t(4)).unwrap(),
        UploadPhase::Cancelled(0)
    );
}

/// A store can be over its bound (an import, a restore, a lowered configuration). A write
/// that does not grow the total still passes then; only one that grows it is refused.
#[test]
fn over_the_limit_only_a_write_that_grows_the_total_is_refused() {
    let mut s = StorageState::new(1);
    put(&mut s, "a", 6).unwrap();
    put(&mut s, "b", 4).unwrap();
    s.set_stored_bytes_limit(Some(8));
    assert_eq!(s.retained_blob_bytes(), 10);

    put(&mut s, "a", 5).unwrap();
    assert_eq!(s.retained_blob_bytes(), 9, "a shrinking replacement passes");
    put(&mut s, "a", 5).unwrap();
    assert_eq!(s.retained_blob_bytes(), 9, "an equal replacement passes");
    put(&mut s, "c", 0).unwrap();
    assert_eq!(put(&mut s, "a", 6), Err(StorageError::StoredBytesLimit));
    assert_eq!(put(&mut s, "d", 1), Err(StorageError::StoredBytesLimit));
    assert_eq!(s.retained_blob_bytes(), 9);
}

#[test]
fn the_objects_bytes_gauge_reports_the_limit() {
    let mut s = StorageState::new(1);
    put(&mut s, "a", 3).unwrap();
    let gauge = |s: &StorageState| {
        s.resources(|_| true, RootBudget::DEFAULT)
            .gauges
            .into_iter()
            .find(|gauge| gauge.id == "objects.bytes")
            .unwrap()
    };
    assert_eq!((gauge(&s).current, gauge(&s).limit), (3, None));
    s.set_stored_bytes_limit(Some(10));
    assert_eq!((gauge(&s).current, gauge(&s).limit), (3, Some(10)));
}

#[derive(Debug, Clone)]
enum Op {
    Put(u8, usize),
    Copy(u8, u8),
    Delete(u8),
    Upload(u8, usize, usize),
    RemoveBucket,
    ClearAndRestore,
    /// The bound changes under a store that may already hold more (as after an import, a
    /// restore or a lowered configuration).
    SetLimit(Option<u64>),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0_u8..4, 0_usize..12).prop_map(|(o, n)| Op::Put(o, n)),
        2 => (0_u8..4, 0_u8..4).prop_map(|(a, b)| Op::Copy(a, b)),
        2 => (0_u8..4).prop_map(Op::Delete),
        2 => (0_u8..4, 0_usize..8, 0_usize..8).prop_map(|(o, a, b)| Op::Upload(o, a, b)),
        1 => Just(Op::RemoveBucket),
        1 => Just(Op::ClearAndRestore),
        1 => proptest::option::of(0_u64..24).prop_map(Op::SetLimit),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Against the object metadata: the running byte count never drifts; an accepted write
    /// never grows the total past the bound; and every refusal was needed, a write that would
    /// have grown the total and taken it past the bound.
    #[test]
    fn the_stored_byte_count_matches_the_objects_and_respects_the_limit(
        limit in proptest::option::of(0_u64..24),
        ops in proptest::collection::vec(op(), 1..40),
    ) {
        let mut s = StorageState::new(1);
        let mut limit = limit;
        s.set_stored_bytes_limit(limit);
        for (step, op) in (0_i64..).zip(ops) {
            let before = observable(&s);
            let before_bytes = s.retained_blob_bytes();
            let size_of = |s: &StorageState, object: u8| {
                s.get(&bucket(), &name(&format!("o{object}"))).map_or(0, |meta| meta.size)
            };
            // What the write would add and what it would replace.
            let (size, replaced) = match &op {
                Op::Put(o, n) => (*n as u64, size_of(&s, *o)),
                Op::Copy(a, b) => (size_of(&s, *a), size_of(&s, *b)),
                Op::Upload(o, first, last) => ((*first + *last) as u64, size_of(&s, *o)),
                _ => (0, 0),
            };
            let refused = match &op {
                Op::Put(o, n) => put(&mut s, &format!("o{o}"), *n).err(),
                Op::Copy(a, b) => s
                    .copy(
                        (&bucket(), &name(&format!("o{a}"))),
                        (&bucket(), &name(&format!("o{b}"))),
                        None,
                        Precondition::default(),
                        t(step),
                    )
                    .err(),
                Op::Delete(o) => s
                    .delete(&bucket(), &name(&format!("o{o}")), Precondition::default())
                    .err(),
                Op::Upload(o, first, last) => {
                    let id = s
                        .begin_upload(
                            &bucket(),
                            &name(&format!("o{o}")),
                            NewMetadata::default(),
                            Precondition::default(),
                            None,
                            t(step),
                        )
                        .unwrap();
                    s.upload_chunk(&id, 0, &vec![1; *first], false, t(step)).unwrap();
                    let refused = s
                        .upload_chunk(&id, *first as u64, &vec![2; *last], true, t(step))
                        .err();
                    if refused.is_some() {
                        prop_assert_eq!(
                            s.upload_phase(&id, t(step)).unwrap(),
                            UploadPhase::Active(*first as u64)
                        );
                    }
                    refused
                }
                Op::RemoveBucket => {
                    let held = s.objects(&bucket()).len();
                    prop_assert_eq!(s.remove_bucket(&bucket()), held);
                    None
                }
                // A session snapshot and its restore keep the count with the objects.
                Op::SetLimit(new) => {
                    limit = *new;
                    s.set_stored_bytes_limit(limit);
                    None
                }
                Op::ClearAndRestore => {
                    let captured = s.capture_buckets(|_| true);
                    prop_assert_eq!(captured.retained_blob_bytes(), recount(&captured));
                    s.clear();
                    prop_assert_eq!(s.retained_blob_bytes(), 0);
                    s.restore_buckets(|_| true, &captured);
                    prop_assert_eq!(observable(&s), before.clone());
                    None
                }
            };
            prop_assert_eq!(s.retained_blob_bytes(), recount(&s), "after {:?}", op);
            if let Some(limit) = limit {
                if s.retained_blob_bytes() > before_bytes {
                    prop_assert!(s.retained_blob_bytes() <= limit, "after {:?}", op);
                }
            }
            match refused {
                None => {}
                Some(StorageError::NotFound) => prop_assert_eq!(observable(&s), before),
                Some(StorageError::StoredBytesLimit) => {
                    let limit = limit.expect("only a bound refuses");
                    prop_assert!(size > replaced, "a refused write would have grown: {:?}", op);
                    prop_assert!(
                        before_bytes - replaced + size > limit,
                        "a refused write would have crossed {}: {:?}", limit, op
                    );
                    prop_assert_eq!(observable(&s), before);
                }
                Some(other) => prop_assert!(false, "unexpected {:?} for {:?}", other, op),
            }
        }
    }
}
