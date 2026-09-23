//! Finite write boundaries on actual REST handlers, not synthetic API responses.
//!
//! The stdlib-only Python compiler creates inputs; the Rust backend decides results.
//! Each point gets an isolated in-memory backend and explicit local indexes. There
//! is no network access or production approval. Wire/gRPC/SDK checks remain separate.

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::{RestRequest, RestState};
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet, IndexValidationPolicy,
    PlanningContext,
};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const NAMES: &str = "projects/demo-fs-data-write/databases/(default)/documents";
const NONCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn fixture(family: &str, position: &str) -> Value {
    let compiler = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/compat-broad/fs-data-write-local/boundaries.py");
    let output = Command::new("python3")
        .args(["-I", "-S", "-B"])
        .arg(compiler)
        .args([
            "--nonce",
            NONCE,
            "--family",
            family,
            "--position",
            position,
            "--stdout",
        ])
        .output()
        .expect("Python 3 is required for local boundary input compilation");
    assert!(
        output.status.success(),
        "boundary compiler failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["productionExecuted"], false);
    assert_eq!(envelope["authorizesProduction"], false);
    assert_eq!(envelope["nativeExecuted"], false);
    let cases = envelope["cases"].as_array_mut().unwrap();
    assert_eq!(cases.len(), 1);
    let case = cases.pop().unwrap();
    assert_eq!(case["family"], family);
    assert_eq!(case["position"], position);
    case
}

fn indexes(config: &Value) -> IndexSet {
    let mut result = IndexSet::default();
    for rule in config["fieldOverrides"].as_array().unwrap() {
        assert_eq!(rule["fieldPath"], "*");
        assert_eq!(rule["indexes"], json!([]));
        result.set_default_single_field_indexes(
            &CollectionId::try_new(rule["collectionGroup"].as_str().unwrap()).unwrap(),
            vec![],
        );
    }
    for definition in config["indexes"].as_array().unwrap() {
        assert_eq!(definition["queryScope"], "COLLECTION");
        let fields = definition["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| IndexField {
                path: FieldPath::parse(field["fieldPath"].as_str().unwrap()).unwrap(),
                mode: if field.get("arrayConfig").is_some() {
                    assert_eq!(field["arrayConfig"], "CONTAINS");
                    IndexFieldMode::Contains
                } else {
                    assert_eq!(field["order"], "ASCENDING");
                    IndexFieldMode::Ascending
                },
            })
            .collect();
        result.add_composite(IndexDefinition {
            collection_group: CollectionId::try_new(
                definition["collectionGroup"].as_str().unwrap(),
            )
            .unwrap(),
            query_scope: IndexQueryScope::Collection,
            fields,
        });
    }
    result
}

fn gateway(indexes: IndexSet) -> Gateway {
    Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes,
    }
}

fn state(case: &Value) -> RestState {
    let configured = indexes(&case["indexConfiguration"]);
    RestState {
        local: Arc::new(LocalBackend::new(
            gateway(configured.clone()),
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(1_788_004_860),
            ))),
            7,
        )),
        gateway: Arc::new(gateway(configured)),
        rules: None,
        app_check: None,
        control_token: None,
    }
}

fn call(state: &RestState, method: &str, path: &str, body: Value) -> (u16, Value) {
    let response = state.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: String::new(),
        authorization: Some("Bearer owner".to_owned()),
        app_check: Vec::new(),
        body,
        origin: None,
        browser_metadata: false,
    });
    (response.status, response.body)
}

fn get(state: &RestState, resource: &str) -> (u16, Value) {
    call(state, "GET", &format!("/v1/{resource}"), Value::Null)
}

fn set(resource: &str, number: i64) -> Value {
    json!({"update": {"name": resource, "fields": {"n": {"integerValue": number.to_string()}}}})
}

fn assert_field(state: &RestState, resource: &str, number: i64) {
    let (status, document) = get(state, resource);
    assert_eq!(status, 200);
    assert_eq!(document["fields"]["n"]["integerValue"], number.to_string());
}

fn invalid_path(case: &Value) -> bool {
    case["position"] == "over"
        && matches!(
            case["family"].as_str().unwrap(),
            "collection-id" | "document-id" | "subcollection-depth" | "document-name"
        )
}

fn assert_target(state: &RestState, case: &Value, accepted: bool) {
    let (status, document) = get(state, case["resource"].as_str().unwrap());
    if accepted {
        assert_eq!(status, 200, "{}", case["id"]);
        assert_eq!(document["name"], case["resource"]);
        assert!(
            document["fields"] == case["document"]["fields"],
            "stored fields changed or were truncated: {}",
            case["id"]
        );
    } else if invalid_path(case) {
        // A 400 for an invalid name is not an absence proof.
        assert_eq!(status, 400, "{}", case["id"]);
        assert_eq!(document["error"]["status"], "INVALID_ARGUMENT");
    } else {
        assert_eq!(status, 404, "{}", case["id"]);
        assert_eq!(document["error"]["status"], "NOT_FOUND");
    }
}

fn status_code(status: &Value) -> i64 {
    assert!(status.is_object());
    match status.get("code") {
        None => 0, // Protobuf JSON may omit the zero-valued success code.
        Some(value) => value.as_i64().expect("numeric canonical status code"),
    }
}

fn exercise(family: &str, surface: &str) {
    for position in ["below", "exact", "over"] {
        let case = fixture(family, position);
        let state = state(&case);
        let accepted = case["expect"]["accepted"].as_bool().unwrap();
        let control = format!("{NAMES}/control/before");
        let suffix = format!("{NAMES}/control/after");
        let (status, _) = call(
            &state,
            "POST",
            &format!("/v1/{NAMES}:commit"),
            json!({"writes": [set(&control, 1)]}),
        );
        assert_eq!(status, 200);
        let before = get(&state, &control).1;
        let body = if surface == "patch" {
            case["document"].clone()
        } else {
            json!({"writes": [set(&control, 2), case["write"], set(&suffix, 3)]})
        };
        let route = if surface == "patch" {
            format!("/v1/{}", case["resource"].as_str().unwrap())
        } else {
            format!("/v1/{NAMES}:{surface}")
        };
        let (status, response) = call(
            &state,
            if surface == "patch" { "PATCH" } else { "POST" },
            &route,
            body,
        );
        if surface == "batchWrite" {
            if invalid_path(&case) || (family == "field-name" && !accepted) {
                assert_eq!(status, 400, "{}", case["id"]);
                assert_eq!(response["error"]["status"], "INVALID_ARGUMENT");
                assert_eq!(get(&state, &control).1, before, "control changed");
                assert_eq!(get(&state, &suffix).0, 404, "suffix published");
            } else {
                assert_eq!(status, 200, "{}", case["id"]);
                let statuses = response["status"].as_array().unwrap();
                assert_eq!(statuses.len(), 3);
                assert_eq!(status_code(&statuses[0]), 0);
                assert_eq!(status_code(&statuses[1]), if accepted { 0 } else { 3 });
                assert_eq!(status_code(&statuses[2]), 0);
                assert_eq!(response["writeResults"].as_array().unwrap().len(), 3);
                assert_field(&state, &control, 2);
                assert_field(&state, &suffix, 3);
            }
        } else {
            assert_eq!(status, if accepted { 200 } else { 400 }, "{}", case["id"]);
            if !accepted {
                assert_eq!(response["error"]["status"], "INVALID_ARGUMENT");
            }
            if surface == "commit" && accepted {
                assert_eq!(response["writeResults"].as_array().unwrap().len(), 3);
                assert_field(&state, &control, 2);
                assert_field(&state, &suffix, 3);
            } else {
                assert_eq!(get(&state, &control).1, before, "control changed");
                assert_eq!(get(&state, &suffix).0, 404, "suffix published");
            }
        }
        assert_target(&state, &case, accepted);
    }
}

macro_rules! boundaries {
    ($patch:ident, $commit:ident, $batch:ident, $family:literal) => {
        #[test]
        fn $patch() {
            exercise($family, "patch");
        }
        #[test]
        fn $commit() {
            exercise($family, "commit");
        }
        #[test]
        fn $batch() {
            exercise($family, "batchWrite");
        }
    };
}

boundaries!(
    collection_id_patch,
    collection_id_commit,
    collection_id_batch,
    "collection-id"
);

boundaries!(
    document_id_patch,
    document_id_commit,
    document_id_batch,
    "document-id"
);

boundaries!(
    subcollection_depth_patch,
    subcollection_depth_commit,
    subcollection_depth_batch,
    "subcollection-depth"
);

boundaries!(
    document_name_patch,
    document_name_commit,
    document_name_batch,
    "document-name"
);

boundaries!(
    field_name_patch,
    field_name_commit,
    field_name_batch,
    "field-name"
);

boundaries!(
    field_path_patch,
    field_path_commit,
    field_path_batch,
    "field-path"
);

boundaries!(
    field_string_patch,
    field_string_commit,
    field_string_batch,
    "field-string"
);

boundaries!(
    field_bytes_patch,
    field_bytes_commit,
    field_bytes_batch,
    "field-bytes"
);

boundaries!(
    field_map_patch,
    field_map_commit,
    field_map_batch,
    "field-map"
);

boundaries!(
    field_array_patch,
    field_array_commit,
    field_array_batch,
    "field-array"
);

boundaries!(
    indexed_value_patch,
    indexed_value_commit,
    indexed_value_batch,
    "indexed-value"
);

boundaries!(
    index_count_patch,
    index_count_commit,
    index_count_batch,
    "index-count"
);

boundaries!(
    index_entry_patch,
    index_entry_commit,
    index_entry_batch,
    "index-entry"
);

boundaries!(
    index_sum_patch,
    index_sum_commit,
    index_sum_batch,
    "index-sum"
);
