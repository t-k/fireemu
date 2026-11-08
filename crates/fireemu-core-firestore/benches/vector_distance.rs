//! Micro-benchmark for a `find_nearest` query over stored vectors, for Euclidean and cosine.
//!
//! It times `run_query_with_stats` end to end: candidate selection, the distance of every
//! candidate to the query vector, and the top-k ranking. The distance is evaluated once per
//! candidate, so cosine's per-candidate work shows up directly in the median.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::{Duration, Instant};

use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::query::{DistanceMeasure, FindNearest, Query, QueryScope};
use fireemu_core_firestore::store::{FirestoreState, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{CollectionId, DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

const DOCUMENTS: usize = 4_000;
const DIMENSIONS: [usize; 2] = [16, 768];
const LIMIT: u32 = 10;
const SAMPLES: usize = 11;

fn path(index: usize) -> DocumentPath {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").expect("project id"),
        &DatabaseId::default_database(),
        &format!("vectors/document-{index:05}"),
    )
    .expect("document path")
}

/// Deterministic components with mixed signs and magnitudes, so the norms are not trivial.
fn vector(index: usize, dimensions: usize) -> Vec<f64> {
    (0..dimensions)
        .map(|component| {
            let seed = u32::try_from((index * 31 + component * 17) % 997).expect("below 997");
            let sign = if seed % 2 == 0 { 1.0 } else { -1.0 };
            sign * (f64::from(seed) + 1.0) / 113.0
        })
        .collect()
}

fn seeded_state(dimensions: usize) -> FirestoreState {
    let writes: Vec<Write> = (0..DOCUMENTS)
        .map(|index| Write {
            op: WriteOp::Set {
                path: path(index),
                fields: BTreeMap::from([(
                    "embedding".to_owned(),
                    Value::Vector(vector(index, dimensions)),
                )]),
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
    state
}

fn find_nearest(dimensions: usize, measure: DistanceMeasure) -> Query {
    Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("vectors").expect("collection id"),
    ))
    .with_find_nearest(FindNearest {
        vector_field: FieldPath::parse("embedding").expect("field path"),
        query_vector: vector(usize::MAX - 7, dimensions),
        distance_measure: measure,
        limit: LIMIT,
        distance_result_field: None,
        distance_threshold: None,
    })
}

fn main() {
    for dimensions in DIMENSIONS {
        let state = seeded_state(dimensions);
        for (name, measure) in [
            ("euclidean", DistanceMeasure::Euclidean),
            ("cosine", DistanceMeasure::Cosine),
        ] {
            let query = find_nearest(dimensions, measure);
            let mut samples = Vec::with_capacity(SAMPLES);
            for _ in 0..SAMPLES {
                let started = Instant::now();
                let result = state
                    .run_query_with_stats(black_box(&query), None)
                    .expect("measured query");
                samples.push(started.elapsed());
                assert_eq!(result.0.len(), LIMIT as usize);
                black_box(result);
            }
            samples.sort_unstable();
            println!(
                "find_nearest measure={name} documents={DOCUMENTS} dimensions={dimensions} limit={LIMIT} samples={SAMPLES} min={:.3}ms median={:.3}ms",
                duration_ms(samples[0]),
                duration_ms(samples[SAMPLES / 2]),
            );
        }
    }
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}
