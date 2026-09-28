//! FS-TRANSFORM-DIAGNOSTICS-023. Expected messages come from the immutable production
//! matrix, never its official-emulator or historical-fireemu columns. These are native
//! backend/wire-mapping regressions, not a fresh production call or the full 18-step replay.
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::error_response;
use fireemu_adapter_grpc::rules::allow_all_reads;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use pb::document_transform::field_transform::TransformType;
use serde_json::Value as Json;

const DB: &str = "projects/demo-firestore-probe/databases/(default)";
const DOC: &str = "projects/demo-firestore-probe/databases/(default)/documents/tf/doc";
const OTHER: &str = "projects/demo-firestore-probe/databases/(default)/documents/tf/prefix";
const MISSING: &str = "projects/demo-firestore-probe/databases/(default)/documents/tf/none";
const INCREMENT: &str = "increment-with-non-numeric-operand";
const DELETE_TRANSFORM: &str = "server-timestamp-on-a-delete";

fn production_row(id: &str) -> &'static Json {
    static MATRIX: OnceLock<Json> = OnceLock::new();
    let matrix = MATRIX.get_or_init(|| {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../conformance/firestore-production-matrix.json"
        )))
        .expect("valid saved production JSON")
    });
    assert_eq!(matrix["evidence"]["verified"], true);
    assert_eq!(matrix["evidence"]["validation"], serde_json::json!([]));
    let observation = &matrix["evidence"]["observations"]["production"];
    assert_eq!(observation["observation"]["side"], "production");
    assert_eq!(observation["observation"]["mode"], "live");
    assert_eq!(
        observation["source"]["gitSha"],
        "2526c61eda5fc53ac91250307786127ae3c601be"
    );
    let matching: Vec<_> = matrix["programs"]
        .as_array()
        .expect("programs array")
        .iter()
        .filter(|program| program["id"] == "writes/transforms")
        .collect();
    assert_eq!(matching.len(), 1);
    let program: &'static Json = matching[0];
    let row = &program["steps"][id]["production"];
    assert_eq!(row["status"], 400);
    assert_eq!(row["code"], "INVALID_ARGUMENT");
    assert!(row["message"].as_str().is_some_and(|text| !text.is_empty()));
    row
}

fn backend() -> LocalBackend {
    LocalBackend::new(
        Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        },
        Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        7,
    )
}

fn value(value_type: pb::value::ValueType) -> pb::Value {
    pb::Value {
        value_type: Some(value_type),
    }
}

fn set(name: &str, n: i64) -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Update(pb::Document {
            name: name.to_owned(),
            fields: HashMap::from([("n".to_owned(), value(pb::value::ValueType::IntegerValue(n)))]),
            ..Default::default()
        })),
        ..Default::default()
    }
}

fn increment(name: &str, operand: pb::value::ValueType) -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Update(pb::Document {
            name: name.to_owned(),
            ..Default::default()
        })),
        update_mask: Some(pb::DocumentMask {
            field_paths: Vec::new(),
        }),
        update_transforms: vec![pb::document_transform::FieldTransform {
            field_path: "n".to_owned(),
            transform_type: Some(TransformType::Increment(value(operand))),
        }],
        ..Default::default()
    }
}

fn delete_with_transform() -> pb::Write {
    pb::Write {
        operation: Some(pb::write::Operation::Delete(DOC.to_owned())),
        update_transforms: vec![pb::document_transform::FieldTransform {
            field_path: "at".to_owned(),
            transform_type: Some(TransformType::SetToServerValue(
                pb::document_transform::field_transform::ServerValue::RequestTime as i32,
            )),
        }],
        ..Default::default()
    }
}

fn commit(writes: Vec<pb::Write>) -> pb::CommitRequest {
    pb::CommitRequest {
        database: DB.to_owned(),
        writes,
        ..Default::default()
    }
}

fn read(backend: &LocalBackend, name: &str) -> pb::Document {
    backend
        .get_document(
            &pb::GetDocumentRequest {
                name: name.to_owned(),
                ..Default::default()
            },
            &allow_all_reads,
        )
        .expect("existing document")
}

fn assert_refusal(backend: &LocalBackend, writes: Vec<pb::Write>, id: &str) {
    let actual = backend
        .commit(&commit(writes))
        .expect_err("request must be refused");
    let expected = production_row(id);
    assert_eq!(actual.code(), tonic::Code::InvalidArgument);
    assert_eq!(
        actual.message(),
        expected["message"].as_str().expect("message")
    );
    let http = error_response(&actual);
    assert_eq!(serde_json::json!(http.status), expected["status"]);
    assert_eq!(http.body["error"]["code"], expected["status"]);
    assert_eq!(http.body["error"]["status"], expected["code"]);
    assert_eq!(http.body["error"]["message"], expected["message"]);
}

#[test]
fn string_increment_matches_saved_message_and_preserves_document() {
    let backend = backend();
    backend.commit(&commit(vec![set(DOC, 3)])).expect("seed");
    let before = read(&backend, DOC);
    assert_refusal(
        &backend,
        vec![increment(
            DOC,
            pb::value::ValueType::StringValue("1".into()),
        )],
        INCREMENT,
    );
    assert_eq!(read(&backend, DOC), before);
}

#[test]
fn delete_transform_matches_saved_message_and_preserves_document() {
    let backend = backend();
    backend.commit(&commit(vec![set(DOC, 3)])).expect("seed");
    let before = read(&backend, DOC);
    assert_refusal(&backend, vec![delete_with_transform()], DELETE_TRANSFORM);
    assert_eq!(read(&backend, DOC), before);
}

#[test]
fn refused_increment_does_not_publish_a_preceding_write() {
    let backend = backend();
    backend.commit(&commit(vec![set(DOC, 3)])).expect("seed");
    let before = read(&backend, DOC);
    assert_refusal(
        &backend,
        vec![
            set(OTHER, 99),
            increment(DOC, pb::value::ValueType::StringValue("1".into())),
        ],
        INCREMENT,
    );
    let missing = backend
        .get_document(
            &pb::GetDocumentRequest {
                name: OTHER.to_owned(),
                ..Default::default()
            },
            &allow_all_reads,
        )
        .expect_err("prefix write not published");
    assert_eq!(missing.code(), tonic::Code::NotFound);
    assert_eq!(read(&backend, DOC), before);
}

#[test]
fn refused_increment_does_not_create_a_missing_document() {
    let backend = backend();
    assert_refusal(
        &backend,
        vec![increment(
            MISSING,
            pb::value::ValueType::StringValue("1".into()),
        )],
        INCREMENT,
    );
    let missing = backend
        .get_document(
            &pb::GetDocumentRequest {
                name: MISSING.to_owned(),
                ..Default::default()
            },
            &allow_all_reads,
        )
        .expect_err("no partial creation");
    assert_eq!(missing.code(), tonic::Code::NotFound);
}

#[test]
fn valid_integer_and_double_increments_still_succeed_after_refusal() {
    let backend = backend();
    backend.commit(&commit(vec![set(DOC, 3)])).expect("seed");
    assert_refusal(
        &backend,
        vec![increment(
            DOC,
            pb::value::ValueType::StringValue("1".into()),
        )],
        INCREMENT,
    );
    let integer = backend
        .commit(&commit(vec![increment(
            DOC,
            pb::value::ValueType::IntegerValue(2),
        )]))
        .expect("integer increment");
    assert_eq!(
        integer.write_results[0].transform_results,
        vec![value(pb::value::ValueType::IntegerValue(5))]
    );
    let double = backend
        .commit(&commit(vec![increment(
            DOC,
            pb::value::ValueType::DoubleValue(0.5),
        )]))
        .expect("double increment");
    assert_eq!(
        double.write_results[0].transform_results,
        vec![value(pb::value::ValueType::DoubleValue(5.5))]
    );
}

#[test]
fn ordinary_delete_still_succeeds_after_transform_refusal() {
    let backend = backend();
    backend.commit(&commit(vec![set(DOC, 3)])).expect("seed");
    assert_refusal(&backend, vec![delete_with_transform()], DELETE_TRANSFORM);
    backend
        .commit(&commit(vec![pb::Write {
            operation: Some(pb::write::Operation::Delete(DOC.to_owned())),
            ..Default::default()
        }]))
        .expect("ordinary delete");
    let missing = backend
        .get_document(
            &pb::GetDocumentRequest {
                name: DOC.to_owned(),
                ..Default::default()
            },
            &allow_all_reads,
        )
        .expect_err("deleted");
    assert_eq!(missing.code(), tonic::Code::NotFound);
}
