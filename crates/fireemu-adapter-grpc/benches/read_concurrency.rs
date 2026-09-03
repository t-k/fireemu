//! Shared-lock scaling benchmark for latest-version document reads.

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::{Arc, Barrier, Mutex};
use std::time::Instant;

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rules::allow_all_reads;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;

const DATABASE: &str = "projects/demo-bench/databases/(default)";
const DOCUMENTS: usize = 100_000;
const READS: usize = 400_000;

fn backend() -> Arc<LocalBackend> {
    Arc::new(LocalBackend::new(
        Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Conservative,
            },
            indexes: IndexSet::default(),
        },
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        7,
    ))
}

fn seed(backend: &LocalBackend) {
    for batch_start in (0..DOCUMENTS).step_by(500) {
        let writes = (batch_start..batch_start + 500)
            .map(|index| pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: format!("{DATABASE}/documents/items/{index:06}"),
                    fields: HashMap::from([(
                        "value".to_owned(),
                        pb::Value {
                            value_type: Some(pb::value::ValueType::IntegerValue(
                                i64::try_from(index).expect("document count fits i64"),
                            )),
                        },
                    )]),
                    ..Default::default()
                })),
                ..Default::default()
            })
            .collect();
        backend
            .commit(&pb::CommitRequest {
                database: DATABASE.to_owned(),
                writes,
                ..Default::default()
            })
            .expect("seed commit");
    }
}

fn measure(backend: &Arc<LocalBackend>, workers: usize) -> u128 {
    let barrier = Arc::new(Barrier::new(workers + 1));
    let started = Instant::now();
    let threads: Vec<_> = (0..workers)
        .map(|worker| {
            let backend = backend.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                for read in 0..READS / workers {
                    let index = (read * workers + worker) % DOCUMENTS;
                    let snapshot = backend
                        .get_document_snapshot(
                            &pb::GetDocumentRequest {
                                name: format!("{DATABASE}/documents/items/{index:06}"),
                                ..Default::default()
                            },
                            &allow_all_reads,
                        )
                        .expect("latest read");
                    black_box(snapshot);
                }
            })
        })
        .collect();
    barrier.wait();
    for thread in threads {
        thread.join().expect("reader thread");
    }
    u128::try_from(READS).expect("read count fits u128") * 1_000_000_000
        / started.elapsed().as_nanos()
}

fn main() {
    let backend = backend();
    seed(&backend);
    for workers in [1, 2, 4] {
        let throughput = measure(&backend, workers);
        println!("read_concurrency: {workers} worker(s), {throughput} reads/s");
    }
}
