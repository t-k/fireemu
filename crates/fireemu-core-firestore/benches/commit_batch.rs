//! Micro-benchmark for the maximum write-count commit with large document field trees.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{FirestoreState, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

const WRITE_COUNT: usize = 500;
const PAYLOAD_BYTES: usize = 100 * 1024;
const SAMPLES: usize = 5;

fn path(index: usize) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").expect("project id"),
        &DatabaseId::default_database(),
        &format!("benchmarks/document-{index:03}"),
    )
    .expect("document path")
}

fn writes(payload: &str) -> Vec<Write> {
    (0..WRITE_COUNT)
        .map(|index| Write {
            op: WriteOp::Set {
                path: path(index),
                fields: BTreeMap::from([("payload".to_owned(), Value::String(payload.to_owned()))]),
                update_mask: None,
            },
            precondition: None,
            transforms: Vec::new(),
        })
        .collect()
}

fn main() {
    let seed = writes("seed");
    let update = writes(&"x".repeat(PAYLOAD_BYTES));
    let mut samples = Vec::with_capacity(SAMPLES);

    for sample in 0..SAMPLES {
        let mut state = FirestoreState::new();
        state
            .commit(&seed, None, LogicalInstant::UNIX_EPOCH)
            .expect("seed commit");
        let started = Instant::now();
        let result = state
            .commit(
                black_box(&update),
                None,
                LogicalInstant::from_unix_seconds(
                    i64::try_from(sample).expect("sample count fits i64") + 1,
                ),
            )
            .expect("measured commit");
        black_box(result);
        samples.push(started.elapsed());
    }

    samples.sort_unstable();
    let median = samples[SAMPLES / 2];
    let total = samples.iter().copied().sum::<Duration>();
    println!(
        "commit_batch: {WRITE_COUNT} writes x {PAYLOAD_BYTES} bytes; median {median:?}; mean {:?}",
        total / u32::try_from(SAMPLES).expect("sample count fits u32")
    );
}
