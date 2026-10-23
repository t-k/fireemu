//! Finite local text search through the public Firestore transports.
use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::{RestRequest, RestState};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const DB: &str = "projects/demo-app/databases/(default)";
fn fixture() -> RestState {
    let gateway = Gateway {
        enforce_limits: false,
        ctx: PlanningContext {
            edition: FirestoreEdition::Enterprise,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Emulator,
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    RestState {
        local: Arc::new(LocalBackend::new(gateway.clone(), clock, 7)),
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
        control_token: None,
    }
}
fn request(
    state: &RestState,
    method: &str,
    path: &str,
    body: Value,
) -> fireemu_adapter_grpc::rest::RestResponse {
    state.handle(&RestRequest {
        method: method.into(),
        path: format!("/v1/{path}"),
        query: String::new(),
        authorization: Some("Bearer owner".into()),
        origin: None,
        remote_peer: false,
        browser_metadata: false,
        app_check: Vec::new(),
        body,
        batch_field_order: Vec::new(),
        key_order: fireemu_adapter_grpc::rest::json_syntax::KeyOrder::default(),
    })
}
fn search_query(query: &str) -> Value {
    json!({"structuredPipeline":{"pipeline":{"stages":[
        {"name":"collection","args":[{"referenceValue":"/products"}]},
        {"name":"search","options":{"query":{"functionValue":{"name":"document_matches","args":[{"stringValue":query}]}}}}
    ]}}})
}
#[test]
fn search_requires_a_real_ready_index_instead_of_silently_scanning_unindexed_fields() {
    let state = fixture();
    let response = request(
        &state,
        "POST",
        &format!("{DB}/documents:executePipeline"),
        search_query("waffles"),
    );
    assert_eq!(response.status, 400, "{}", response.body);
    assert!(
        response.body.to_string().contains("FS_TEXT_INDEX"),
        "{}",
        response.body
    );
}

fn install(
    state: &RestState,
    exact: bool,
) -> Arc<Mutex<fireemu_core_firestore::text_index::TextIndexCatalog>> {
    use fireemu_core_firestore::text_index::*;
    use fireemu_core_firestore::{field_path::FieldPath, index::IndexQueryScope};
    let mut catalog = TextIndexCatalog::default();
    catalog
        .add(
            "demo-app",
            "(default)",
            TextIndexDefinition {
                id: "products-text".into(),
                collection_id: fireemu_core_types::ids::CollectionId::try_new("products").unwrap(),
                query_scope: IndexQueryScope::Collection,
                api_scope: "ANY_API".into(),
                fields: ["title", "body"]
                    .into_iter()
                    .map(|field| TextIndexedField {
                        path: FieldPath::parse(field).unwrap(),
                        index_type: TextIndexType::Tokenized,
                        match_type: TextMatchType::MatchGlobally,
                    })
                    .collect(),
                language: DefaultTextLanguage::Tag("en".into()),
                language_override: LanguageOverridePolicy::Disabled,
                state: TextIndexState::Ready,
            },
        )
        .unwrap();
    let catalog = Arc::new(Mutex::new(catalog));
    state
        .local
        .set_text_indexes(catalog.clone(), exact)
        .unwrap();
    catalog
}
fn put(state: &RestState, id: &str, title: &str, body: &str) {
    let r = request(
        state,
        "PATCH",
        &format!("{DB}/documents/products/{id}"),
        json!({"fields":{"title":{"stringValue":title},"body":{"stringValue":body}}}),
    );
    assert_eq!(r.status, 200, "{}", r.body);
}
fn results(body: &Value) -> Vec<&Value> {
    body.as_array()
        .unwrap()
        .iter()
        .filter_map(|response| response.get("results"))
        .flat_map(|rows| rows.as_array().unwrap())
        .collect()
}
fn ids(body: &Value) -> Vec<String> {
    results(body)
        .iter()
        .map(|row| {
            row["name"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
                .to_owned()
        })
        .collect()
}
#[test]
fn ready_search_sees_updates_inserts_and_deletes_and_preserves_source_metadata() {
    let state = fixture();
    let _catalog = install(&state, false);
    put(&state, "a", "red fox", "one");
    put(&state, "b", "red", "fox");
    let path = format!("{DB}/documents:executePipeline");
    let first = request(&state, "POST", &path, search_query("\"red fox\""));
    assert_eq!(first.status, 200, "{}", first.body);
    assert_eq!(ids(&first.body), ["a"]);
    let source = request(
        &state,
        "GET",
        &format!("{DB}/documents/products/a"),
        json!({}),
    );
    assert_eq!(
        results(&first.body)[0]["createTime"],
        source.body["createTime"]
    );
    assert_eq!(
        results(&first.body)[0]["updateTime"],
        source.body["updateTime"]
    );
    put(&state, "a", "blue", "one");
    assert!(results(&request(&state, "POST", &path, search_query("\"red fox\"")).body).is_empty());
    put(&state, "c", "red fox", "inserted");
    assert_eq!(
        ids(&request(&state, "POST", &path, search_query("\"red fox\"")).body),
        ["c"]
    );
    assert_eq!(
        request(
            &state,
            "DELETE",
            &format!("{DB}/documents/products/c"),
            json!({})
        )
        .status,
        200
    );
    assert!(results(&request(&state, "POST", &path, search_query("\"red fox\"")).body).is_empty());
}
#[test]
fn score_projection_paging_and_downstream_select_keep_unprojected_search_fields() {
    let state = fixture();
    let _catalog = install(&state, false);
    put(&state, "a", "first", "waffles waffles");
    put(&state, "b", "second", "waffles");
    put(&state, "c", "third", "waffles");
    let mut query = search_query("waffles");
    let options = &mut query["structuredPipeline"]["pipeline"]["stages"][1]["options"];
    options["add_fields"] =
        json!({"mapValue":{"fields":{"rank":{"functionValue":{"name":"score","args":[]}}}}});
    options["sort"] = json!({"arrayValue":{"values":[{"mapValue":{"fields":{"expression":{"functionValue":{"name":"score","args":[]}},"direction":{"stringValue":"descending"}}}}]}});
    options["retrieval_depth"] = json!({"integerValue":"2"});
    options["limit"] = json!({"integerValue":"1"});
    let ranked = request(
        &state,
        "POST",
        &format!("{DB}/documents:executePipeline"),
        query,
    );
    assert_eq!(ranked.status, 200, "{}", ranked.body);
    assert_eq!(results(&ranked.body).len(), 1);
    assert!(
        results(&ranked.body)[0]["fields"]["rank"]["doubleValue"]
            .as_f64()
            .unwrap()
            > 0.0
    );
    let mut query = search_query("body:waffles");
    query["structuredPipeline"]["pipeline"]["stages"].as_array_mut().unwrap().push(json!({"name":"select","args":[{"mapValue":{"fields":{"label":{"fieldReferenceValue":"title"}}}}]}));
    let projected = request(
        &state,
        "POST",
        &format!("{DB}/documents:executePipeline"),
        query,
    );
    assert_eq!(projected.status, 200, "{}", projected.body);
    assert_eq!(results(&projected.body).len(), 3);
    assert!(results(&projected.body)
        .iter()
        .all(|row| row["fields"]["label"]["stringValue"].is_string()));
}
#[test]
fn unavailable_builds_and_production_exact_never_return_approximate_search_results() {
    let state = fixture();
    let catalog = install(&state, false);
    put(&state, "a", "waffles", "body");
    catalog
        .lock()
        .unwrap()
        .lifecycle(
            "demo-app",
            "(default)",
            "products-text",
            "failBuild",
            None,
            100,
            None,
            Vec::new(),
            fireemu_adapter_support::lexical::tokenize,
        )
        .unwrap();
    let failed = request(
        &state,
        "POST",
        &format!("{DB}/documents:executePipeline"),
        search_query("waffles"),
    );
    assert_eq!(failed.status, 400, "{}", failed.body);
    assert!(failed.body.to_string().contains("FS_TEXT_INDEX"));
    catalog
        .lock()
        .unwrap()
        .lifecycle(
            "demo-app",
            "(default)",
            "products-text",
            "repair",
            None,
            100,
            None,
            Vec::new(),
            fireemu_adapter_support::lexical::tokenize,
        )
        .unwrap();
    assert_eq!(
        request(
            &state,
            "POST",
            &format!("{DB}/documents:executePipeline"),
            search_query("waffles")
        )
        .status,
        400
    );
    let exact = fixture();
    let _catalog = install(&exact, true);
    put(&exact, "a", "waffles", "body");
    let refused = request(
        &exact,
        "POST",
        &format!("{DB}/documents:executePipeline"),
        search_query("waffles"),
    );
    assert_eq!(refused.status, 501, "{}", refused.body);
    assert!(refused.body.to_string().contains("FS_TEXT_UNOBSERVED"));
}
#[test]
fn unknown_options_misplaced_search_and_wrong_scope_leave_catalog_unchanged() {
    let state = fixture();
    let catalog = install(&state, false);
    put(&state, "a", "waffles", "body");
    let before = catalog.lock().unwrap().clone();
    for (key, value) in [
        ("unknown", json!({"stringValue":"x"})),
        ("limit", json!({"integerValue":"-1"})),
        ("language_code", json!({"stringValue":"not a tag"})),
        ("query_enhancement", json!({"stringValue":"required"})),
    ] {
        let mut body = search_query("waffles");
        body["structuredPipeline"]["pipeline"]["stages"][1]["options"][key] = value;
        let response = request(
            &state,
            "POST",
            &format!("{DB}/documents:executePipeline"),
            body,
        );
        assert!(matches!(response.status, 400 | 501), "{}", response.body);
    }
    let mut body = search_query("waffles");
    body["structuredPipeline"]["pipeline"]["stages"]
        .as_array_mut()
        .unwrap()
        .insert(1, json!({"name":"limit","args":[{"integerValue":"1"}]}));
    assert_eq!(
        request(
            &state,
            "POST",
            &format!("{DB}/documents:executePipeline"),
            body
        )
        .status,
        501
    );
    let other = request(
        &state,
        "POST",
        "projects/demo-other/databases/(default)/documents:executePipeline",
        search_query("waffles"),
    );
    assert_eq!(other.status, 400, "{}", other.body);
    assert_eq!(*catalog.lock().unwrap(), before);
}
#[tokio::test]
async fn grpc_and_rest_share_the_same_index_snapshot_search_and_result_order() {
    use fireemu_proto_firestore::google::firestore::v1::firestore_server::Firestore;
    use tonic::codegen::tokio_stream::StreamExt;
    let state = fixture();
    let _catalog = install(&state, false);
    put(&state, "a", "waffles", "coffee");
    put(&state, "b", "waffles", "tea");
    let body = search_query("waffles -coffee");
    let expected = request(
        &state,
        "POST",
        &format!("{DB}/documents:executePipeline"),
        body.clone(),
    );
    assert_eq!(expected.status, 200, "{}", expected.body);
    let service = fireemu_adapter_grpc::service::GatewayService::local(
        (*state.gateway).clone(),
        state.local.clone(),
    );
    let request_pb =
        fireemu_adapter_grpc::rest::pipeline_json::request_from_json(DB, &body).unwrap();
    let mut stream = service
        .execute_pipeline(tonic::Request::new(request_pb))
        .await
        .unwrap()
        .into_inner();
    let mut rows = Vec::new();
    while let Some(row) = stream.next().await {
        rows.push(fireemu_adapter_grpc::rest::pipeline_json::response_to_json(
            &row.unwrap(),
        ));
    }
    assert_eq!(Value::Array(rows), expected.body);
}

#[test]
fn noncovering_invalid_indexes_do_not_mask_a_valid_covering_index() {
    use fireemu_core_firestore::{field_path::FieldPath, text_index::LanguageOverridePolicy};
    for policy in [
        LanguageOverridePolicy::BackendDefaultUnresolved,
        LanguageOverridePolicy::ExplicitField(FieldPath::parse("title").unwrap()),
    ] {
        let state = fixture();
        let catalog = install(&state, false);
        {
            let mut catalog = catalog.lock().unwrap();
            let mut valid = catalog
                .get("demo-app", "(default)", "products-text")
                .unwrap()
                .clone();
            catalog.remove("demo-app", "(default)", "products-text");
            let mut invalid = valid.clone();
            invalid.id = "invalid-title".into();
            invalid.fields.retain(|f| f.path.canonical() == "title");
            invalid.language_override = policy;
            valid.fields.retain(|f| f.path.canonical() == "body");
            catalog.add("demo-app", "(default)", invalid).unwrap();
            catalog.add("demo-app", "(default)", valid).unwrap();
        }
        put(&state, "a", "bad tag!", "fox");
        let path = format!("{DB}/documents:executePipeline");
        let found = request(&state, "POST", &path, search_query("body:fox"));
        assert_eq!(found.status, 200, "{}", found.body);
        assert_eq!(ids(&found.body), ["a"]);
        let invalid = request(&state, "POST", &path, search_query("title:bad"));
        assert_eq!(invalid.status, 400, "{}", invalid.body);
    }
}
