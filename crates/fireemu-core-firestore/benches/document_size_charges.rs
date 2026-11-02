//! FSM-3 micro-benchmark for the document size charges taken on the write and read paths.
//!
//! A commit admits every written document against the document size limit, and a read-write
//! transaction's query charges every returned document to its conflict ledger. Both need only
//! the document's total size.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{Query, QueryScope};
use fireemu_core_firestore::store::{FirestoreState, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

const DOCUMENTS: usize = 500;
const FIELDS: usize = 20;
const SAMPLES: usize = 11;

fn path(index: usize) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").expect("project id"),
        &DatabaseId::default_database(),
        &format!("benchmarks/document-{index:05}"),
    )
    .expect("document path")
}

fn writes() -> Vec<Write> {
    (0..DOCUMENTS)
        .map(|index| Write {
            op: WriteOp::Set {
                path: path(index),
                fields: (0..FIELDS)
                    .map(|field| {
                        (
                            format!("field_{field:02}"),
                            Value::String(format!("value-{index}-{field}")),
                        )
                    })
                    .collect::<BTreeMap<_, _>>(),
                update_mask: None,
            },
            precondition: None,
            transforms: Vec::new(),
        })
        .collect()
}

fn main() {
    let writes = writes();
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("benchmarks").expect("collection id"),
    ));
    let mut commits = Vec::with_capacity(SAMPLES);
    let mut reads = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let mut state = FirestoreState::new();
        let started = Instant::now();
        black_box(
            state
                .commit(black_box(&writes), None, LogicalInstant::UNIX_EPOCH)
                .expect("measured commit"),
        );
        commits.push(started.elapsed());

        let now = LogicalInstant::from_unix_seconds(1);
        let transaction = state.begin_transaction(false, now).expect("transaction");
        let started = Instant::now();
        let documents = state
            .run_query_in_transaction(&transaction, black_box(&query))
            .expect("measured transactional query");
        reads.push(started.elapsed());
        assert_eq!(documents.len(), DOCUMENTS);
        black_box(documents);
    }
    commits.sort_unstable();
    reads.sort_unstable();
    println!(
        "commit documents={DOCUMENTS} fields={FIELDS} median={:.3}ms; transactional query median={:.3}ms",
        duration_ms(commits[SAMPLES / 2]),
        duration_ms(reads[SAMPLES / 2]),
    );
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}
