//! Verify-only commits across payload sizes and operation counts.

use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Instant;

use fireemu_core_firestore::path::DocumentPath;
use fireemu_core_firestore::store::{FirestoreState, Write, WriteOp};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::ids::{DatabaseId, ProjectId};
use fireemu_core_types::time::LogicalInstant;

fn main() {
    let path = DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        "benchmarks/verify",
    )
    .unwrap();
    for payload_bytes in [1024, 100 * 1024, 900 * 1024] {
        for count in [1, 100, 500] {
            let mut state = FirestoreState::new();
            state
                .commit(
                    &[Write {
                        op: WriteOp::Set {
                            path: path.clone(),
                            fields: BTreeMap::from([(
                                "payload".to_owned(),
                                Value::String("x".repeat(payload_bytes)),
                            )]),
                            update_mask: None,
                        },
                        precondition: None,
                        transforms: vec![],
                    }],
                    None,
                    LogicalInstant::UNIX_EPOCH,
                )
                .unwrap();
            let writes = vec![
                Write {
                    op: WriteOp::Verify { path: path.clone() },
                    precondition: None,
                    transforms: vec![],
                };
                count
            ];
            let mut samples = Vec::new();
            for sample in 0..21 {
                let start = Instant::now();
                let result = state
                    .commit(
                        black_box(&writes),
                        None,
                        LogicalInstant::from_unix_seconds(sample + 1),
                    )
                    .unwrap();
                let elapsed = start.elapsed();
                assert!(result.changes.is_empty());
                black_box(result);
                if sample > 0 {
                    samples.push(elapsed);
                }
            }
            samples.sort_unstable();
            println!(
                "verify: bytes={payload_bytes} count={count} median={:?}",
                samples[samples.len() / 2]
            );
        }
    }
}
