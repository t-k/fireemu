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
    fixture_with_policy(IndexValidationPolicy::Emulator)
}
fn fixture_with_policy(policy: IndexValidationPolicy) -> RestState {
    let gateway = Gateway {
        enforce_limits: false,
        ctx: PlanningContext {
            edition: FirestoreEdition::Enterprise,
            api_mode: FirestoreApiMode::Native,
            policy,
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
fn production_boundary_membership_reaches_core_through_a_ready_english_index() {
    let state = fixture();
    let _catalog = install(&state, false);
    let observed: Value = serde_json::from_str(include_str!(
        "../../fireemu-core-firestore/tests/fixtures/production_text_boundary.json"
    ))
    .unwrap();
    for doc in observed["documents"].as_array().unwrap() {
        put(
            &state,
            doc["id"].as_str().unwrap(),
            doc["title"].as_str().unwrap(),
            doc["body"].as_str().unwrap(),
        );
    }
    for round in observed["rounds"].as_array().unwrap() {
        for row in round.as_array().unwrap() {
            let query = row["query"].as_str().unwrap();
            let mut body = search_query(query);
            body["structuredPipeline"]["pipeline"]["stages"][1]["options"]["language_code"] =
                json!({"stringValue":"en"});
            let found = request(
                &state,
                "POST",
                &format!("{DB}/documents:executePipeline"),
                body,
            );
            assert_eq!(found.status, 200, "{}", found.body);
            let mut actual = ids(&found.body);
            actual.sort();
            let expected: Vec<_> = row["members"]
                .as_array()
                .unwrap()
                .iter()
                .map(|member| member.as_str().unwrap())
                .collect();
            assert_eq!(actual, expected, "query={query:?}");
        }
    }
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
    // Preserve the unverified legacy field restriction while checking downstream projection.
    let mut query = search_query("body:\"waffles\"");
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
            fireemu_adapter_support::lexical::tokenize_index,
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
            fireemu_adapter_support::lexical::tokenize_index,
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
    // Qualified phrases exercise the unverified legacy development coverage gate.
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
        let found = request(&state, "POST", &path, search_query("body:\"fox\""));
        assert_eq!(found.status, 200, "{}", found.body);
        assert_eq!(ids(&found.body), ["a"]);
        let invalid = request(&state, "POST", &path, search_query("title:\"bad\""));
        assert_eq!(invalid.status, 400, "{}", invalid.body);
    }
}

#[test]
fn latin_purpose_adapter_queries_use_query_analysis_and_rebuild_with_index_analysis() {
    let state = fixture();
    let _catalog = install(&state, false);
    put(&state, "copper", "İris", "marker");
    put(&state, "silver", "Crème brûlée", "marker");
    put(&state, "jade", "ά", "marker");
    put(&state, "opal", "α", "marker");
    put(&state, "talc", "Straße", "marker");
    let path = format!("{DB}/documents:executePipeline");
    for (query, expected) in [
        ("iris", vec!["copper"]),
        ("İris", vec!["copper"]),
        ("\"creme brulee\"", vec!["silver"]),
        ("ά", vec!["jade"]),
        ("α", vec!["opal"]),
        ("strasse", vec!["talc"]),
    ] {
        let response = request(&state, "POST", &path, search_query(query));
        assert_eq!(response.status, 200, "{query}: {}", response.body);
        assert_eq!(ids(&response.body), expected, "{query}");
    }
}

#[test]
fn strict_enterprise_search_root_or_matches_the_production_error() {
    let state = fixture_with_policy(IndexValidationPolicy::Production);
    let _catalog = install(&state, true);
    let (left, right) = ("cedar", "mango");
    let response = request(
        &state,
        "POST",
        &format!("{DB}/documents:executePipeline"),
        json!({"structuredPipeline":{"pipeline":{"stages":[
            {"args":[{"referenceValue":"/score-boolean-a-20261025"}],"name":"collection"},
            {"args":[],"name":"search","options":{
                "add_fields":{"mapValue":{"fields":{"rank":{"functionValue":{"args":[],"name":"score"}}}}},
                "query":{"functionValue":{"args":[
                    {"functionValue":{"args":[{"stringValue":left}],"name":"document_matches"}},
                    {"functionValue":{"args":[{"stringValue":right}],"name":"document_matches"}}
                ],"name":"or"}},
                "query_enhancement":{"stringValue":"disabled"},
                "sort":{"arrayValue":{"values":[{"mapValue":{"fields":{
                    "direction":{"stringValue":"descending"},
                    "expression":{"functionValue":{"args":[],"name":"score"}}
                }}}]}}
            }}
        ]}}}),
    );
    assert_eq!(response.status, 400, "{}", response.body);
    let errors = response.body.as_array().expect("stream error array");
    assert_eq!(errors.len(), 1);
    let error = &errors[0]["error"];
    assert_eq!(error["code"].as_u64(), Some(400));
    assert_eq!(error["status"].as_str(), Some("INVALID_ARGUMENT"));
    assert_eq!(error["message"].as_str(), Some(format!(
            "search(...) only supports 'document_matches' or distance based searches like lte(geo_distance(field(STRING), GEO_POINT), NUMBER) but got or(document_matches(\"{left}\"), document_matches(\"{right}\"))"
        ).as_str()));
}

#[test]
fn other_search_roots_remain_unimplemented() {
    let state = fixture_with_policy(IndexValidationPolicy::Production);
    let _catalog = install(&state, true);
    let mut body = search_query("cedar");
    body["structuredPipeline"]["pipeline"]["stages"][1]["options"]["query"]["functionValue"]
        ["name"] = json!("unrecorded_root");
    let response = request(
        &state,
        "POST",
        &format!("{DB}/documents:executePipeline"),
        body,
    );
    assert_eq!(response.status, 501, "{}", response.body);
    assert_eq!(response.body[0]["error"]["status"], "UNIMPLEMENTED");
}

#[test]
fn search_root_classification_covers_pairwise_terms_and_policies() {
    let cases = [
        ("or", "observed", IndexValidationPolicy::Production),
        ("other", "observed", IndexValidationPolicy::Production),
        (
            "document_matches",
            "observed",
            IndexValidationPolicy::Emulator,
        ),
        ("or", "alternate", IndexValidationPolicy::Emulator),
        ("other", "alternate", IndexValidationPolicy::Production),
        ("or", "unicode", IndexValidationPolicy::Production),
        (
            "document_matches",
            "unicode",
            IndexValidationPolicy::Production,
        ),
        ("other", "unicode", IndexValidationPolicy::Emulator),
        (
            "document_matches",
            "alternate",
            IndexValidationPolicy::Emulator,
        ),
    ];
    for (root, terms, policy) in cases {
        let state = fixture_with_policy(policy);
        let _catalog = install(&state, false);
        let (left, right) = match terms {
            "observed" => ("cedar", "mango"),
            "alternate" => ("birch", "peach"),
            _ => ("cèdre", "mangue"),
        };
        let mut body = search_query(left);
        if root == "or" {
            let query =
                &mut body["structuredPipeline"]["pipeline"]["stages"][1]["options"]["query"];
            *query = json!({"functionValue":{"name":"or","args":[
                {"functionValue":{"name":"document_matches","args":[{"stringValue":left}]}},
                {"functionValue":{"name":"document_matches","args":[{"stringValue":right}]}}
            ]}});
        } else if root == "other" {
            body["structuredPipeline"]["pipeline"]["stages"][1]["options"]["query"]
                ["functionValue"]["name"] = json!("unrecorded_root");
        }
        let response = request(
            &state,
            "POST",
            &format!("{DB}/documents:executePipeline"),
            body,
        );
        let expected = match root {
            "or" if policy == IndexValidationPolicy::Emulator => 400,
            "or" | "other" => 501,
            _ => 200,
        };
        assert_eq!(
            response.status, expected,
            "root={root}, terms={terms}: {}",
            response.body
        );
        if root == "or" && policy == IndexValidationPolicy::Emulator {
            let message = format!(
                "search(...) only supports 'document_matches' or distance based searches like lte(geo_distance(field(STRING), GEO_POINT), NUMBER) but got or(document_matches({}), document_matches({}))",
                serde_json::to_string(left).unwrap(),
                serde_json::to_string(right).unwrap()
            );
            assert_eq!(response.body[0]["error"]["message"], message);
        }
    }
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(16))]
    #[test]
    fn search_root_or_diagnostic_quotes_input_strings(left in "[[:print:]]{0,32}", right in "[[:print:]]{0,32}") {
        let state = fixture_with_policy(IndexValidationPolicy::Emulator);
        let _catalog = install(&state, true);
        let mut body = search_query("");
        body["structuredPipeline"]["pipeline"]["stages"][1]["options"]["query"] = json!({"functionValue":{"name":"or","args":[
            {"functionValue":{"name":"document_matches","args":[{"stringValue":left}]}},
            {"functionValue":{"name":"document_matches","args":[{"stringValue":right}]}}
        ]}});
        let response = request(&state, "POST", &format!("{DB}/documents:executePipeline"), body);
        proptest::prop_assert_eq!(response.status, 400);
        let message = format!("search(...) only supports 'document_matches' or distance based searches like lte(geo_distance(field(STRING), GEO_POINT), NUMBER) but got or(document_matches({}), document_matches({}))", serde_json::to_string(&left).unwrap(), serde_json::to_string(&right).unwrap());
        proptest::prop_assert_eq!(&response.body[0]["error"]["message"], &json!(message));
    }
}

#[test]
fn strict_search_root_or_neighbors_remain_unobserved() {
    let state = fixture_with_policy(IndexValidationPolicy::Production);
    let _catalog = install(&state, true);
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../conformance/fs-ent-text-refusal-requests.json"
    ))
    .unwrap();
    let observed = fixture["programs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|program| program["id"] == "fs-ent-text/v1/search-root-or-refusal")
        .unwrap()["steps"][0]["body"]
        .clone();
    let mut changed_terms = observed.clone();
    changed_terms["structuredPipeline"]["pipeline"]["stages"][1]["options"]["query"]
        ["functionValue"]["args"][0]["functionValue"]["args"][0]["stringValue"] = json!("birch");
    let mut changed_collection = observed.clone();
    changed_collection["structuredPipeline"]["pipeline"]["stages"][0]["args"][0]
        ["referenceValue"] = json!("/products");
    let mut changed_options = observed;
    changed_options["structuredPipeline"]["pipeline"]["stages"][1]["options"]
        .as_object_mut()
        .unwrap()
        .remove("query_enhancement");
    for body in [changed_terms, changed_collection, changed_options] {
        let response = request(
            &state,
            "POST",
            &format!("{DB}/documents:executePipeline"),
            body,
        );
        assert_eq!(response.status, 501, "{}", response.body);
        assert_eq!(response.body[0]["error"]["status"], "UNIMPLEMENTED");
        assert!(response.body[0]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not observed locally"));
    }
}
