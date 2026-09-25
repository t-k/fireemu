//! Generated index suggestions must retain collection and field identities through JSON.
//! Uses `serde_json` already present in this adapter; the std-only core gains no dependency.

use fireemu_adapter_grpc::gateway::{Gateway, Rejection};
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::index::{
    IndexDecision, IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet,
    IndexValidationPolicy, PlanningContext,
};
use fireemu_core_firestore::query::{
    Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope,
};
use fireemu_core_firestore::value::Value;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::ids::CollectionId;
use serde_json::{json, Value as Json};

fn fp(segments: &[&str]) -> FieldPath {
    FieldPath::from_segments(segments.iter().copied()).unwrap()
}

fn definition(collection: &str, scope: IndexQueryScope, field: FieldPath) -> IndexDefinition {
    IndexDefinition {
        collection_group: CollectionId::try_new(collection).unwrap(),
        query_scope: scope,
        fields: vec![
            IndexField {
                path: field,
                mode: IndexFieldMode::Ascending,
            },
            IndexField {
                path: FieldPath::document_name(),
                mode: IndexFieldMode::Ascending,
            },
        ],
    }
}

/// Test-only typed reconstruction. This is not the production config-file loader.
fn decoded_definition(fragment: &str) -> IndexDefinition {
    let value: Json = serde_json::from_str(fragment).expect("index suggestion must be valid JSON");
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), 3, "no injected top-level members");
    let scope = match object["queryScope"].as_str().unwrap() {
        "COLLECTION" => IndexQueryScope::Collection,
        "COLLECTION_GROUP" => IndexQueryScope::CollectionGroup,
        other => panic!("unexpected scope {other}"),
    };
    let fields = object["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| {
            let item = value.as_object().unwrap();
            assert_eq!(item.len(), 2, "one fieldPath and one mode");
            let mode = if let Some(order) = item.get("order") {
                match order.as_str().unwrap() {
                    "ASCENDING" => IndexFieldMode::Ascending,
                    "DESCENDING" => IndexFieldMode::Descending,
                    other => panic!("unexpected order {other}"),
                }
            } else if let Some(array) = item.get("arrayConfig") {
                assert_eq!(array, "CONTAINS");
                IndexFieldMode::Contains
            } else {
                let vector = item["vectorConfig"].as_object().unwrap();
                assert_eq!(vector.len(), 2);
                assert_eq!(vector["flat"], json!({}));
                IndexFieldMode::Vector {
                    dimension: u32::try_from(vector["dimension"].as_u64().unwrap()).unwrap(),
                }
            };
            IndexField {
                path: FieldPath::parse(item["fieldPath"].as_str().unwrap()).unwrap(),
                mode,
            }
        })
        .collect();
    IndexDefinition {
        collection_group: CollectionId::try_new(object["collectionGroup"].as_str().unwrap())
            .unwrap(),
        query_scope: scope,
        fields,
    }
}

const SCOPES: [IndexQueryScope; 2] = [
    IndexQueryScope::Collection,
    IndexQueryScope::CollectionGroup,
];

#[test]
fn ordinary_ascii_suggestion_keeps_its_existing_bytes() {
    let index = definition("tasks", IndexQueryScope::Collection, fp(&["done"]));
    assert_eq!(
        index.indexes_json_fragment(),
        "{\n  \"collectionGroup\": \"tasks\",\n  \"queryScope\": \"COLLECTION\",\n  \"fields\": [\n      {\"fieldPath\": \"done\", \"order\": \"ASCENDING\"},\n      {\"fieldPath\": \"__name__\", \"order\": \"ASCENDING\"}\n  ]\n}"
    );
    assert_eq!(decoded_definition(&index.indexes_json_fragment()), index);
}

#[test]
fn valid_special_names_roundtrip_without_double_decoding() {
    for scope in SCOPES {
        for name in [
            "普通の名前",
            "quotes\"inside",
            r"back\slash",
            "tick`inside",
            "two.words",
            r"literal\u0041",
            "space name",
            "😀",
        ] {
            let index = definition(name, scope, fp(&["outer", name]));
            assert_eq!(decoded_definition(&index.indexes_json_fragment()), index);
        }
    }
}

#[test]
fn json_looking_collection_escapes_remain_literal_identifiers() {
    for name in [
        r"items\u0041",
        r"items\n",
        r"items\b",
        r"items\t",
        r"items\\tail",
    ] {
        let index = definition(name, IndexQueryScope::Collection, fp(&["field"]));
        let parsed: Json = serde_json::from_str(&index.indexes_json_fragment()).unwrap();
        assert_eq!(parsed["collectionGroup"].as_str(), Some(name));
        assert_eq!(decoded_definition(&index.indexes_json_fragment()), index);
    }
}

#[test]
fn member_looking_identifiers_cannot_change_modes_or_add_json_members() {
    for name in [
        r#"a", "queryScope": "COLLECTION_GROUP", "extra": "x"#,
        r#"x", "order": "DESCENDING"#,
        r#"x"}, {"fieldPath": "injected", "arrayConfig": "CONTAINS"#,
    ] {
        let index = definition(name, IndexQueryScope::Collection, fp(&[name]));
        let fragment = index.indexes_json_fragment();
        assert_eq!(decoded_definition(&fragment), index);
        let parsed: Json = serde_json::from_str(&fragment).unwrap();
        assert_eq!(parsed["fields"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["queryScope"], "COLLECTION");
    }
}

#[test]
fn every_mode_and_scope_survives_json_roundtrip() {
    for scope in SCOPES {
        for mode in [
            IndexFieldMode::Ascending,
            IndexFieldMode::Descending,
            IndexFieldMode::Contains,
            IndexFieldMode::Vector { dimension: 2 },
        ] {
            let mut index = definition(r#"items\""#, scope, fp(&[r#"embed\"`"#]));
            index.fields[0].mode = mode;
            assert_eq!(decoded_definition(&index.indexes_json_fragment()), index);
        }
    }
}

#[test]
fn a_literal_dotted_field_is_not_changed_into_a_nested_field() {
    let literal = definition("tasks", IndexQueryScope::Collection, fp(&["a.b"]));
    let nested = definition("tasks", IndexQueryScope::Collection, fp(&["a", "b"]));
    assert_ne!(literal.fields[0].path, nested.fields[0].path);
    assert_eq!(
        decoded_definition(&literal.indexes_json_fragment()),
        literal
    );
    assert_eq!(decoded_definition(&nested.indexes_json_fragment()), nested);
}

#[test]
fn maximum_length_identifiers_are_not_truncated_when_escaped() {
    for name in ["\"".repeat(1500), "\\".repeat(1500), "名".repeat(500)] {
        let index = definition(&name, IndexQueryScope::Collection, fp(&[&name]));
        assert_eq!(decoded_definition(&index.indexes_json_fragment()), index);
    }
}

fn gateway() -> Gateway {
    Gateway {
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: IndexValidationPolicy::Production,
        },
        indexes: IndexSet::default(),
        enforce_limits: true,
    }
}

fn query_scope(collection: &CollectionId, scope: IndexQueryScope) -> QueryScope {
    match scope {
        IndexQueryScope::Collection => QueryScope::collection(None, collection.clone()),
        IndexQueryScope::CollectionGroup => QueryScope::collection_group(collection.clone()),
    }
}

fn suggestion(rejection: &Rejection) -> &str {
    let Rejection::MissingIndex { fragment, .. } = rejection else {
        panic!("expected missing index, got {rejection:?}");
    };
    let status = rejection.to_status();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        status
            .metadata()
            .get("fireemu-reason")
            .unwrap()
            .to_str()
            .unwrap(),
        "FS_GW_MISSING_INDEX"
    );
    assert!(status.message().ends_with(fragment.as_str()));
    fragment
}

#[test]
fn the_strict_gateway_suggestion_can_be_parsed_and_used_without_renaming_fields() {
    for scope in SCOPES {
        let collection = CollectionId::try_new(r#"items\"日本"#).unwrap();
        let query = Query::new(query_scope(&collection, scope))
            .with_order(OrderClause {
                field: fp(&["a\"quoted"]),
                direction: Direction::Ascending,
            })
            .with_order(OrderClause {
                field: fp(&[r"back\tick`"]),
                direction: Direction::Ascending,
            });
        let mut gateway = gateway();
        let rejection = gateway.validate_query(&query).unwrap_err();
        let index = decoded_definition(suggestion(&rejection));
        assert_eq!(index.collection_group, collection);
        assert_eq!(index.fields[0].path, query.order_by[0].field);
        assert_eq!(index.fields[1].path, query.order_by[1].field);
        gateway.indexes.add_composite(index);
        assert!(gateway.validate_query(&query).is_ok());
    }
}

#[test]
fn the_strict_gateway_does_not_treat_a_vector_index_as_scalar_equality_support() {
    for scope in SCOPES {
        let collection = CollectionId::try_new("vector-gateway").unwrap();
        let field = fp(&["embedding"]);
        let mut gateway = gateway();
        gateway
            .indexes
            .set_default_single_field_indexes(&collection, vec![]);
        gateway.indexes.add_composite(IndexDefinition {
            collection_group: collection.clone(),
            query_scope: scope,
            fields: vec![IndexField {
                path: field.clone(),
                mode: IndexFieldMode::Vector { dimension: 2 },
            }],
        });
        let query = Query::new(query_scope(&collection, scope)).with_filter(FilterExpr::Field {
            field,
            op: FieldOp::Equal,
            value: Value::String("not-a-vector".to_owned()),
        });
        let rejection = gateway.validate_query(&query).unwrap_err();
        let scalar = decoded_definition(suggestion(&rejection));
        assert!(scalar.fields.iter().all(|field| matches!(
            field.mode,
            IndexFieldMode::Ascending | IndexFieldMode::Descending
        )));
        gateway.indexes.add_composite(scalar);
        assert!(matches!(
            gateway.validate_query(&query).unwrap().decision,
            IndexDecision::UseIndex { .. }
        ));
    }
}
