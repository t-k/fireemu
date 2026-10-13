//! The public-read bit an object's `allUsers:READER` ACL entry sets: it belongs to one generation
//! of one object, so an overwrite, a delete and a bucket reset end it, and a session snapshot
//! carries it.

use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{NewMetadata, Precondition, StorageState};
use fireemu_core_types::time::LogicalInstant;

fn t(n: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_000_000 + n)
}
fn bucket(name: &str) -> BucketName {
    BucketName::try_new(name).unwrap()
}
fn name(s: &str) -> ObjectName {
    ObjectName::try_new(s).unwrap()
}

fn put(store: &mut StorageState, b: &str, object: &str) {
    store
        .put(
            &bucket(b),
            &name(object),
            b"data".to_vec(),
            NewMetadata::default(),
            Precondition::default(),
            t(0),
        )
        .unwrap();
}

#[test]
fn an_object_is_private_until_made_public() {
    let mut store = StorageState::new(1);
    put(&mut store, "bucket-one", "a.txt");
    assert!(!store.is_public_read(&bucket("bucket-one"), &name("a.txt")));
    assert!(store.set_public_read(&bucket("bucket-one"), &name("a.txt")));
    assert!(store.is_public_read(&bucket("bucket-one"), &name("a.txt")));
    assert!(!store.is_public_read(&bucket("bucket-one"), &name("b.txt")));
    assert!(!store.is_public_read(&bucket("bucket-two"), &name("a.txt")));
}

#[test]
fn making_an_absent_object_public_changes_nothing() {
    let mut store = StorageState::new(1);
    assert!(!store.set_public_read(&bucket("bucket-one"), &name("missing.txt")));
    put(&mut store, "bucket-one", "missing.txt");
    assert!(!store.is_public_read(&bucket("bucket-one"), &name("missing.txt")));
}

#[test]
fn an_overwrite_a_delete_and_a_recreate_end_the_public_bit() {
    let mut store = StorageState::new(1);
    put(&mut store, "bucket-one", "a.txt");
    store.set_public_read(&bucket("bucket-one"), &name("a.txt"));
    put(&mut store, "bucket-one", "a.txt");
    assert!(
        !store.is_public_read(&bucket("bucket-one"), &name("a.txt")),
        "a new generation starts with the bucket's default ACL"
    );
    store.set_public_read(&bucket("bucket-one"), &name("a.txt"));
    store
        .delete(
            &bucket("bucket-one"),
            &name("a.txt"),
            Precondition::default(),
            t(1),
        )
        .unwrap();
    put(&mut store, "bucket-one", "a.txt");
    assert!(!store.is_public_read(&bucket("bucket-one"), &name("a.txt")));
}

#[test]
fn a_bucket_reset_and_a_clear_end_the_public_bit() {
    let mut store = StorageState::new(1);
    put(&mut store, "bucket-one", "a.txt");
    put(&mut store, "bucket-two", "a.txt");
    store.set_public_read(&bucket("bucket-one"), &name("a.txt"));
    store.set_public_read(&bucket("bucket-two"), &name("a.txt"));
    store.remove_bucket(&bucket("bucket-one"));
    assert!(!store.is_public_read(&bucket("bucket-one"), &name("a.txt")));
    assert!(store.is_public_read(&bucket("bucket-two"), &name("a.txt")));
    store.remove_buckets_where(|b| b == "bucket-two");
    assert!(!store.is_public_read(&bucket("bucket-two"), &name("a.txt")));
    put(&mut store, "bucket-two", "a.txt");
    assert!(!store.is_public_read(&bucket("bucket-two"), &name("a.txt")));
    store.set_public_read(&bucket("bucket-two"), &name("a.txt"));
    store.clear();
    put(&mut store, "bucket-two", "a.txt");
    assert!(!store.is_public_read(&bucket("bucket-two"), &name("a.txt")));
}

#[test]
fn a_snapshot_carries_the_bit_of_the_buckets_it_captured() {
    let mut live = StorageState::new(1);
    put(&mut live, "bucket-one", "a.txt");
    put(&mut live, "bucket-two", "a.txt");
    live.set_public_read(&bucket("bucket-one"), &name("a.txt"));
    let captured = live.capture_buckets(|b| b == "bucket-one");
    assert!(captured.is_public_read(&bucket("bucket-one"), &name("a.txt")));
    assert!(!captured.is_public_read(&bucket("bucket-two"), &name("a.txt")));

    // The live store moves on: the object becomes private again, then the snapshot is restored.
    put(&mut live, "bucket-one", "a.txt");
    assert!(!live.is_public_read(&bucket("bucket-one"), &name("a.txt")));
    live.restore_buckets(|b| b == "bucket-one", &captured);
    assert!(live.is_public_read(&bucket("bucket-one"), &name("a.txt")));
    // The bucket the capture did not select keeps its own state.
    live.set_public_read(&bucket("bucket-two"), &name("a.txt"));
    live.restore_buckets(|b| b == "bucket-one", &captured);
    assert!(live.is_public_read(&bucket("bucket-two"), &name("a.txt")));
}

mod model {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    #[derive(Debug, Clone)]
    enum Step {
        Put(u8),
        Delete(u8),
        MakePublic(u8),
    }

    fn step() -> impl Strategy<Value = Step> {
        prop_oneof![
            (0u8..3).prop_map(Step::Put),
            (0u8..3).prop_map(Step::Delete),
            (0u8..3).prop_map(Step::MakePublic),
        ]
    }

    proptest! {
        /// A reference model: an object is public exactly when it was made public after the last
        /// time it was written, and it still exists.
        #[test]
        fn the_bit_follows_the_reference_model(steps in proptest::collection::vec(step(), 0..40)) {
            let mut store = StorageState::new(1);
            let mut live: BTreeSet<u8> = BTreeSet::new();
            let mut public: BTreeSet<u8> = BTreeSet::new();
            let b = bucket("bucket-one");
            for (i, s) in steps.iter().enumerate() {
                let at = t(i64::try_from(i).unwrap());
                match s {
                    Step::Put(k) => {
                        store.put(&b, &name(&format!("o{k}")), b"x".to_vec(), NewMetadata::default(), Precondition::default(), at).unwrap();
                        live.insert(*k);
                        public.remove(k);
                    }
                    Step::Delete(k) => {
                        let _ = store.delete(&b, &name(&format!("o{k}")), Precondition::default(), at);
                        live.remove(k);
                        public.remove(k);
                    }
                    Step::MakePublic(k) => {
                        let done = store.set_public_read(&b, &name(&format!("o{k}")));
                        prop_assert_eq!(done, live.contains(k));
                        if done {
                            public.insert(*k);
                        }
                    }
                }
                for k in 0u8..3 {
                    prop_assert_eq!(
                        store.is_public_read(&b, &name(&format!("o{k}"))),
                        public.contains(&k),
                        "o{} after {:?}", k, s
                    );
                }
            }
        }
    }
}
