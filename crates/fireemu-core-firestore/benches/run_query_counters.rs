//! FSM-1 micro-benchmark for an unprojected collection query that returns every stored document.
//!
//! It times `run_query_with_stats`, the path a non-transactional `RunQuery` takes, so the
//! bookkeeping done after the selection (the clone counters) shows up next to the selection.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{Query, QueryScope};
use fireemu_core_firestore::store::{FirestoreState, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

const DOCUMENTS: usize = 2_000;
const FIELDS: usize = 20;
const SAMPLES: usize = 21;

fn path(index: usize) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").expect("project id"),
        &DatabaseId::default_database(),
        &format!("benchmarks/document-{index:05}"),
    )
    .expect("document path")
}

fn fields(index: usize) -> BTreeMap<String, Value> {
    (0..FIELDS)
        .map(|field| {
            let value = match field % 4 {
                0 => Value::Integer(i64::try_from(index * field).expect("fits i64")),
                1 => Value::String(format!("value-{index}-{field}")),
                2 => Value::Array(vec![Value::Integer(1), Value::String("tag".to_owned())]),
                _ => Value::Map(BTreeMap::from([
                    (
                        "nested".to_owned(),
                        Value::String("nested value".to_owned()),
                    ),
                    ("count".to_owned(), Value::Integer(7)),
                ])),
            };
            (format!("field_{field:02}"), value)
        })
        .collect()
}

fn main() {
    let writes: Vec<Write> = (0..DOCUMENTS)
        .map(|index| Write {
            op: WriteOp::Set {
                path: path(index),
                fields: fields(index),
                update_mask: None,
            },
            precondition: None,
            transforms: Vec::new(),
        })
        .collect();
    let mut state = FirestoreState::new();
    for chunk in writes.chunks(500) {
        state
            .commit(chunk, None, LogicalInstant::UNIX_EPOCH)
            .expect("seed commit");
    }
    let query = Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("benchmarks").expect("collection id"),
    ));

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        let result = state
            .run_query_with_stats(black_box(&query), None)
            .expect("measured query");
        samples.push(started.elapsed());
        assert_eq!(result.0.len(), DOCUMENTS);
        black_box(result);
    }
    samples.sort_unstable();
    let median = samples[SAMPLES / 2];
    let min = samples[0];
    println!(
        "run_query_with_stats documents={DOCUMENTS} fields={FIELDS} samples={SAMPLES} min={:.3}ms median={:.3}ms",
        duration_ms(min),
        duration_ms(median),
    );
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}
