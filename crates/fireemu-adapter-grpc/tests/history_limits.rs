//! Local bounds on retained Firestore history (`firestore.history` in fireemu.json): the
//! per-path version cap and the database byte limit a configuration may lower, and the
//! one-hour `read_time` window that reclaims superseded versions on the virtual clock.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_firestore::store::HistoryLimits;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use fireemu_proto_firestore::google::firestore::v1 as pb;

const DATABASE: &str = "projects/demo-app/databases/(default)";

fn backend() -> (LocalBackend, Arc<Mutex<VirtualClock>>) {
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
    };
    (LocalBackend::new(gateway, Arc::clone(&clock), 7), clock)
}

fn update(document: &str, payload: &str) -> pb::CommitRequest {
    pb::CommitRequest {
        database: DATABASE.to_owned(),
        writes: vec![pb::Write {
            operation: Some(pb::write::Operation::Update(pb::Document {
                name: format!("{DATABASE}/documents/items/{document}"),
                fields: [(
                    "payload".to_owned(),
                    pb::Value {
                        value_type: Some(pb::value::ValueType::StringValue(payload.to_owned())),
                    },
                )]
                .into_iter()
                .collect(),
                ..Default::default()
            })),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn commit(backend: &LocalBackend, document: &str, payload: &str) -> pb::CommitResponse {
    backend
        .commit_with(
            &update(document, payload),
            &fireemu_adapter_grpc::rules::allow_all,
        )
        .expect("commit")
}

fn read(
    backend: &LocalBackend,
    document: &str,
    read_time: Option<prost_types::Timestamp>,
) -> Result<pb::Document, (tonic::Code, String)> {
    backend
        .get_document(
            &pb::GetDocumentRequest {
                name: format!("{DATABASE}/documents/items/{document}"),
                consistency_selector: read_time
                    .map(pb::get_document_request::ConsistencySelector::ReadTime),
                ..Default::default()
            },
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .map_err(|status| (status.code(), status.message().to_owned()))
}

fn payload_of(document: &pb::Document) -> &str {
    match document.fields["payload"].value_type.as_ref() {
        Some(pb::value::ValueType::StringValue(text)) => text,
        other => panic!("payload is a string, got {other:?}"),
    }
}

fn advance(clock: &Mutex<VirtualClock>, seconds: i64) {
    clock
        .lock()
        .unwrap()
        .advance(LogicalDuration::from_seconds(seconds))
        .unwrap();
}

#[test]
fn repeated_updates_are_reclaimed_once_the_read_time_window_passes() {
    let (backend, clock) = backend();
    for round in 0..50 {
        commit(&backend, "a", &format!("round {round}"));
        advance(&clock, 1);
    }
    let retained = backend.history_usage();
    assert_eq!(retained.versions, 50, "{retained:?}");

    // An hour and a second later every superseded version is outside the read-time window,
    // and the next commit's compaction releases them.
    advance(&clock, 3_601);
    commit(&backend, "b", "after the window");
    let reclaimed = backend.history_usage();
    assert_eq!(reclaimed.versions, 2, "{reclaimed:?}");
    assert!(
        reclaimed.total_bytes < retained.total_bytes,
        "{reclaimed:?} after {retained:?}"
    );
    assert_eq!(payload_of(&read(&backend, "a", None).unwrap()), "round 49");
}

#[test]
fn a_per_path_cap_bounds_wall_clock_history() {
    for cap in [None, Some(4)] {
        let (backend, _clock) = backend();
        let mut backend = backend.with_wall_clock_write_time();
        if let Some(cap) = cap {
            backend = backend.with_history_version_limit(cap);
        }
        let first = commit(&backend, "a", "round 0");
        for round in 1..10 {
            commit(&backend, "a", &format!("round {round}"));
        }
        let retained = backend.history_usage();
        let early = read(&backend, "a", first.commit_time);
        match cap {
            // Production keeps every version of the last hour, and so does the default.
            None => {
                assert_eq!(retained.versions, 10, "{retained:?}");
                assert_eq!(payload_of(&early.unwrap()), "round 0");
            }
            // A configured cap keeps the newest versions only; an older read_time is refused.
            Some(cap) => {
                assert_eq!(
                    retained.versions,
                    u64::try_from(cap).unwrap(),
                    "{retained:?}"
                );
                let (code, message) = early.unwrap_err();
                assert_eq!(code, tonic::Code::FailedPrecondition, "{message}");
                assert_eq!(
                    message,
                    "The requested 'read_time' is no longer retained by this database."
                );
            }
        }
        assert_eq!(payload_of(&read(&backend, "a", None).unwrap()), "round 9");
    }
}

const NO_LONGER_RETAINED: &str =
    "The requested 'read_time' is no longer retained by this database.";
const TRANSACTION_GONE: &str = "The referenced transaction has expired or is no longer valid.";

fn begin(
    backend: &LocalBackend,
    read_only_at: Option<prost_types::Timestamp>,
) -> Result<Vec<u8>, (tonic::Code, String)> {
    backend
        .begin_transaction(&pb::BeginTransactionRequest {
            database: DATABASE.to_owned(),
            options: read_only_at.map(|read_time| pb::TransactionOptions {
                mode: Some(pb::transaction_options::Mode::ReadOnly(
                    pb::transaction_options::ReadOnly {
                        consistency_selector: Some(
                            pb::transaction_options::read_only::ConsistencySelector::ReadTime(
                                read_time,
                            ),
                        ),
                    },
                )),
            }),
            ..Default::default()
        })
        .map_err(|status| (status.code(), status.message().to_owned()))
}

fn read_in(
    backend: &LocalBackend,
    document: &str,
    transaction: &[u8],
) -> Result<pb::Document, (tonic::Code, String)> {
    backend
        .get_document(
            &pb::GetDocumentRequest {
                name: format!("{DATABASE}/documents/items/{document}"),
                consistency_selector: Some(
                    pb::get_document_request::ConsistencySelector::Transaction(
                        transaction.to_vec(),
                    ),
                ),
                ..Default::default()
            },
            &fireemu_adapter_grpc::rules::allow_all_reads,
        )
        .map_err(|status| (status.code(), status.message().to_owned()))
}

/// The cap is not a per-document bound: one document past it moves the oldest retained
/// version of the whole database, so a document written once loses its `read_time` reach too.
#[test]
fn a_busy_document_past_the_cap_moves_the_retention_point_for_every_document() {
    for cap in [None, Some(2)] {
        let (backend, clock) = backend();
        let backend = match cap {
            Some(cap) => backend.with_history_version_limit(cap),
            None => backend.with_history_version_limit(usize::MAX),
        };
        let cold = commit(&backend, "cold", "written once");
        for round in 0..5 {
            advance(&clock, 1);
            commit(&backend, "hot", &format!("round {round}"));
        }
        let at_cold = read(&backend, "cold", cold.commit_time);
        let read_only = begin(&backend, cold.commit_time);
        if cap.is_none() {
            assert_eq!(payload_of(&at_cold.unwrap()), "written once");
            assert!(read_only.is_ok(), "{read_only:?}");
        } else {
            assert_eq!(
                at_cold.unwrap_err(),
                (
                    tonic::Code::FailedPrecondition,
                    NO_LONGER_RETAINED.to_owned()
                )
            );
            assert_eq!(
                read_only.unwrap_err(),
                (
                    tonic::Code::FailedPrecondition,
                    "read_time is no longer retained by this database".to_owned()
                )
            );
        }
        assert_eq!(
            payload_of(&read(&backend, "cold", None).unwrap()),
            "written once"
        );
    }
}

/// A transaction already open on a snapshot below the moved retention point is aborted, even
/// when it only touches a document nobody else writes. SDKs retry ABORTED.
#[test]
fn a_transaction_below_the_capped_retention_point_is_aborted() {
    for cap in [None, Some(2)] {
        let (backend, clock) = backend();
        let backend = match cap {
            Some(cap) => backend.with_history_version_limit(cap),
            None => backend.with_history_version_limit(usize::MAX),
        };
        commit(&backend, "cold", "written once");
        let transaction = begin(&backend, None).unwrap();
        assert_eq!(
            payload_of(&read_in(&backend, "cold", &transaction).unwrap()),
            "written once"
        );
        for round in 0..5 {
            advance(&clock, 1);
            commit(&backend, "hot", &format!("round {round}"));
        }
        let again = read_in(&backend, "cold", &transaction);
        let mut write = update("cold", "from the transaction");
        write.transaction.clone_from(&transaction);
        let committed = backend
            .commit_with(&write, &fireemu_adapter_grpc::rules::allow_all)
            .map_err(|status| (status.code(), status.message().to_owned()));
        if cap.is_none() {
            assert!(again.is_ok(), "{again:?}");
            assert!(committed.is_ok(), "{committed:?}");
        } else {
            let gone = (tonic::Code::Aborted, TRANSACTION_GONE.to_owned());
            assert_eq!(again.unwrap_err(), gone);
            assert_eq!(committed.unwrap_err(), gone);
        }
    }
}

#[test]
fn a_lowered_byte_limit_refuses_history_growth_whole() {
    let payload = "x".repeat(64 * 1024);
    let limits = HistoryLimits {
        max_bytes: 1 << 20,
        ..HistoryLimits::default()
    };
    let (limited, clock) = backend();
    let limited = limited.with_history_limits(limits);
    let mut accepted = 0;
    let refused = loop {
        match limited.commit_with(
            &update("a", &format!("{accepted} {payload}")),
            &fireemu_adapter_grpc::rules::allow_all,
        ) {
            Ok(_) => accepted += 1,
            Err(status) => break status,
        }
        advance(&clock, 1);
        assert!(
            accepted < 64,
            "1 MiB of history holds fewer than 64 versions of 64 KiB"
        );
    };
    assert_eq!(
        refused.code(),
        tonic::Code::ResourceExhausted,
        "{refused:?}"
    );
    assert_eq!(
        refused.message(),
        "Firestore retained history capacity is exhausted"
    );
    let usage = limited.history_usage();
    assert_eq!(usage.versions, accepted, "{usage:?}");
    assert!(usage.total_bytes <= limits.max_bytes, "{usage:?}");
    assert!(
        payload_of(&read(&limited, "a", None).unwrap()).starts_with(&format!("{} ", accepted - 1))
    );

    // The default limit takes the same writes.
    let (default, clock) = backend();
    for round in 0..=accepted {
        commit(&default, "a", &format!("{round} {payload}"));
        advance(&clock, 1);
    }
    assert_eq!(default.history_usage().versions, accepted + 1);
}

#[test]
fn a_restored_snapshot_takes_the_backend_s_history_limits() {
    let payload = "x".repeat(64 * 1024);
    let (source, clock) = backend();
    commit(&source, "a", &payload);
    advance(&clock, 1);
    let snapshot = source.snapshot_databases();

    let (limited, clock) = backend();
    let limited = limited.with_history_limits(HistoryLimits {
        max_bytes: 1 << 20,
        ..HistoryLimits::default()
    });
    limited.restore_databases(snapshot).unwrap();
    let mut accepted = 0_u32;
    let refused = loop {
        advance(&clock, 1);
        match limited.commit_with(
            &update("a", &format!("{accepted} {payload}")),
            &fireemu_adapter_grpc::rules::allow_all,
        ) {
            Ok(_) => accepted += 1,
            Err(status) => break status,
        }
        assert!(
            accepted < 64,
            "the restored database kept the default 1 GiB limit"
        );
    };
    assert_eq!(
        refused.code(),
        tonic::Code::ResourceExhausted,
        "{refused:?}"
    );
}
