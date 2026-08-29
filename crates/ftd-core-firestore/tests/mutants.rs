//! Boundary and wording checks that pin behaviour the mutation run found unobserved.

use std::collections::BTreeMap;

use ftd_core_firestore::field_path::{FieldPath, FieldPathError};
use ftd_core_firestore::index::{
    decide, IndexDecision, IndexDefinition, IndexField, IndexFieldMode, IndexQueryScope, IndexSet,
    IndexValidationPolicy, PlanningContext,
};
use ftd_core_firestore::path::{
    DocumentPath, PathError, MAX_DOCUMENT_NAME_BYTES, MAX_SUBCOLLECTION_DEPTH,
};
use ftd_core_firestore::query::{
    Cursor, Direction, FieldOp, FilterExpr, OrderClause, Query, QueryScope, UnaryOp,
};
use ftd_core_firestore::size::{document_size, MAX_CONTRIBUTORS};
use ftd_core_firestore::value::Value;
use ftd_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use ftd_core_types::ids::{CollectionId, DatabaseId, IdSyntaxError, ProjectId};

fn parse(relative: &str) -> Result<DocumentPath, PathError> {
    DocumentPath::parse(
        &ProjectId::try_new("demo-app").unwrap(),
        &DatabaseId::default_database(),
        relative,
    )
}

#[test]
fn document_paths_report_exact_segment_indexes_depths_and_lengths() {
    assert_eq!(MAX_DOCUMENT_NAME_BYTES, 6144);
    assert_eq!(
        parse("users/alice/__bad__/x").unwrap_err(),
        PathError::InvalidSegment {
            index: 2,
            error: IdSyntaxError::ReservedDunder
        }
    );
    assert_eq!(
        parse("users/alice/tasks/.").unwrap_err(),
        PathError::InvalidSegment {
            index: 3,
            error: IdSyntaxError::DotSegment
        }
    );
    assert_eq!(
        parse("a/b/c").unwrap_err(),
        PathError::OddSegmentCount { segments: 3 }
    );
    let deepest = vec!["c/d"; MAX_SUBCOLLECTION_DEPTH].join("/");
    assert_eq!(
        parse(&deepest).unwrap().pairs().len(),
        MAX_SUBCOLLECTION_DEPTH
    );
    let too_deep = vec!["c/d"; MAX_SUBCOLLECTION_DEPTH + 1].join("/");
    assert_eq!(
        parse(&too_deep).unwrap_err(),
        PathError::TooDeep {
            depth: MAX_SUBCOLLECTION_DEPTH + 1,
            maximum: MAX_SUBCOLLECTION_DEPTH
        }
    );
    // The resource name limit is inclusive: exactly 6144 bytes is accepted, one more is not.
    let prefix = parse("c/d").unwrap().resource_name().len() - "c/d".len();
    let mut pairs: Vec<String> = Vec::new();
    while prefix + pairs.join("/").len() + "/c/".len() + 1400 < MAX_DOCUMENT_NAME_BYTES {
        pairs.push(format!("c/{}", "d".repeat(1400)));
    }
    let used = prefix + pairs.join("/").len() + "/c/".len();
    let exact = format!(
        "{}/c/{}",
        pairs.join("/"),
        "e".repeat(MAX_DOCUMENT_NAME_BYTES - used)
    );
    let ok = parse(&exact).unwrap();
    assert_eq!(ok.resource_name().len(), MAX_DOCUMENT_NAME_BYTES);
    assert_eq!(ok.to_string(), ok.resource_name());
    let over = format!(
        "{}/c/{}",
        pairs.join("/"),
        "e".repeat(MAX_DOCUMENT_NAME_BYTES - used + 1)
    );
    assert_eq!(
        parse(&over).unwrap_err(),
        PathError::NameTooLong {
            bytes: MAX_DOCUMENT_NAME_BYTES + 1,
            maximum: MAX_DOCUMENT_NAME_BYTES
        }
    );
    // Parents: none at the root, one level up otherwise.
    let root = parse("users/alice").unwrap();
    assert!(root.parent_document().is_none());
    let nested = parse("users/alice/tasks/t1/steps/s1").unwrap();
    let parent = nested.parent_document().unwrap();
    assert_eq!(parent.relative(), "users/alice/tasks/t1");
    assert_eq!(parent.parent_document().unwrap().relative(), "users/alice");
    assert_eq!(
        root.resource_name(),
        "projects/demo-app/databases/(default)/documents/users/alice"
    );
    for e in [
        PathError::Empty,
        PathError::OddSegmentCount { segments: 1 },
        PathError::TooDeep {
            depth: 1,
            maximum: 0,
        },
    ] {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn field_paths_quote_escape_and_reject_at_the_documented_boundaries() {
    // `__` and `___` are too short to be reserved; `__a__` is.
    assert!(FieldPath::parse("__").is_ok());
    assert!(FieldPath::parse("___").is_ok());
    assert!(matches!(
        FieldPath::parse("__a__").unwrap_err(),
        FieldPathError::ReservedSegment { .. }
    ));
    // Backslashes and backticks are escaped when a segment is quoted.
    let p = FieldPath::from_segments(["a\\b", "c`d", "plain"]).unwrap();
    assert_eq!(p.to_string(), "`a\\\\b`.`c\\`d`.plain");
    assert_eq!(p.segments(), ["a\\b", "c`d", "plain"]);
    // After a quoted segment only a dot or the end may follow.
    assert!(matches!(
        FieldPath::parse("`a`b").unwrap_err(),
        FieldPathError::UnquotedSpecialCharacter { offset: 3 }
    ));
    assert_eq!(FieldPath::parse("`a`").unwrap().segments(), ["a"]);
    assert_eq!(FieldPath::parse("x.`a`").unwrap().segments(), ["x", "a"]);
    assert_eq!(
        FieldPath::parse("a.").unwrap_err(),
        FieldPathError::EmptySegment { index: 1 }
    );
    assert_eq!(
        FieldPath::parse("a..b").unwrap_err(),
        FieldPathError::EmptySegment { index: 1 }
    );
    for e in [
        FieldPathError::Empty,
        FieldPathError::EmptySegment { index: 0 },
        FieldPathError::UnterminatedQuote { offset: 0 },
        FieldPathError::UnquotedSpecialCharacter { offset: 0 },
        FieldPathError::ControlCharacter { offset: 0 },
    ] {
        assert!(!e.to_string().is_empty());
    }
}

fn fp(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}

fn field(path: &str, op: FieldOp, v: Value) -> FilterExpr {
    FilterExpr::Field {
        field: fp(path),
        op,
        value: v,
    }
}

fn tasks() -> Query {
    Query::new(QueryScope::collection(
        None,
        CollectionId::try_new("tasks").unwrap(),
    ))
}

fn order(field: &str, direction: Direction) -> OrderClause {
    OrderClause {
        field: fp(field),
        direction,
    }
}

fn standard() -> PlanningContext {
    PlanningContext {
        edition: FirestoreEdition::Standard,
        api_mode: FirestoreApiMode::Native,
        policy: IndexValidationPolicy::Conservative,
    }
}

fn composite(fields: &[(&str, IndexFieldMode)]) -> IndexSet {
    let mut set = IndexSet::default();
    set.add_composite(IndexDefinition {
        collection_group: CollectionId::try_new("tasks").unwrap(),
        query_scope: IndexQueryScope::Collection,
        fields: fields
            .iter()
            .map(|(f, m)| IndexField {
                path: fp(f),
                mode: *m,
            })
            .collect(),
    });
    set
}

fn served(q: &Query, indexes: &IndexSet) -> bool {
    matches!(
        decide(&q.canonicalize().unwrap(), indexes, &standard()),
        IndexDecision::UseIndex { .. }
    )
}

#[test]
fn composite_index_matching_checks_modes_and_name_direction() {
    let by_priority = tasks()
        .with_filter(field("owner", FieldOp::Equal, Value::String("u".into())))
        .with_order(order("priority", Direction::Ascending));
    // An array-config field cannot serve an ordering.
    assert!(!served(
        &by_priority,
        &composite(&[
            ("owner", IndexFieldMode::Ascending),
            ("priority", IndexFieldMode::Contains)
        ])
    ));
    assert!(served(
        &by_priority,
        &composite(&[
            ("owner", IndexFieldMode::Ascending),
            ("priority", IndexFieldMode::Descending)
        ])
    ));
    // An explicit __name__ in the index must agree with the scan direction.
    let name_desc = composite(&[
        ("owner", IndexFieldMode::Ascending),
        ("priority", IndexFieldMode::Ascending),
        ("__name__", IndexFieldMode::Descending),
    ]);
    assert!(
        !served(&by_priority, &name_desc),
        "forward scan wants __name__ ascending"
    );
    let reversed = tasks()
        .with_filter(field("owner", FieldOp::Equal, Value::String("u".into())))
        .with_order(order("priority", Direction::Descending))
        .with_order(order("__name__", Direction::Ascending));
    assert!(
        served(&reversed, &name_desc),
        "reversed scan reads __name__ ascending"
    );
    let reversed_wrong_name = tasks()
        .with_filter(field("owner", FieldOp::Equal, Value::String("u".into())))
        .with_order(order("priority", Direction::Descending))
        .with_order(order("__name__", Direction::Descending));
    assert!(!served(&reversed_wrong_name, &name_desc));
    // array-contains plus an ordering on another field needs a composite index; with only
    // __name__ ordering the automatic index serves it.
    let contains_ordered = tasks()
        .with_filter(field(
            "tags",
            FieldOp::ArrayContains,
            Value::String("x".into()),
        ))
        .with_order(order("priority", Direction::Ascending));
    let decision = decide(
        &contains_ordered.canonicalize().unwrap(),
        &IndexSet::default(),
        &standard(),
    );
    assert!(
        matches!(decision, IndexDecision::MissingRequired { .. }),
        "{decision}"
    );
    let text = decision.to_string();
    assert!(
        text.contains("missing index (tags Contains, priority Ascending"),
        "{text}"
    );
    let contains_only = tasks()
        .with_filter(field(
            "tags",
            FieldOp::ArrayContains,
            Value::String("x".into()),
        ))
        .with_order(order("__name__", Direction::Descending));
    assert!(matches!(
        decide(
            &contains_only.canonicalize().unwrap(),
            &IndexSet::default(),
            &standard()
        ),
        IndexDecision::UseIndex { .. }
    ));
    // Suggested definitions spell the field modes as firestore.indexes.json does.
    let suggestion = match decision {
        IndexDecision::MissingRequired { requirement } => requirement.indexes_json_fragment(),
        other => panic!("{other}"),
    };
    assert!(
        suggestion.contains("\"arrayConfig\": \"CONTAINS\""),
        "{suggestion}"
    );
    assert!(
        suggestion.contains("\"order\": \"ASCENDING\""),
        "{suggestion}"
    );
}

#[test]
fn query_operator_names_cursor_arity_and_limit_boundaries() {
    assert_eq!(FieldOp::Equal.name(), "EQUAL");
    assert_eq!(FieldOp::ArrayContainsAny.name(), "ARRAY_CONTAINS_ANY");
    assert_eq!(FieldOp::NotIn.name(), "NOT_IN");
    // Cursor values may not exceed the effective order-by arity (one field + __name__).
    let ordered = tasks().with_order(order("priority", Direction::Ascending));
    let mut two = ordered.clone();
    two.start_at = Some(Cursor {
        values: vec![Value::Integer(1), Value::String("t1".into())],
        before: true,
    });
    assert!(two.canonicalize().is_ok());
    let mut three = ordered;
    three.start_at = Some(Cursor {
        values: vec![Value::Integer(1), Value::String("t1".into()), Value::Null],
        before: true,
    });
    assert!(three.canonicalize().is_err());
    // One array-contains without array-contains-any is fine.
    let one = tasks()
        .with_filter(field(
            "tags",
            FieldOp::ArrayContains,
            Value::String("x".into()),
        ))
        .canonicalize()
        .unwrap();
    assert!(one.check_standard_limits().is_ok());
    // `!= null` and `is not NaN` count as inequality fields, like `>`.
    let with_unary = tasks()
        .with_filter(FilterExpr::And(vec![
            FilterExpr::Unary {
                field: fp("a"),
                op: UnaryOp::IsNotNull,
            },
            field("b", FieldOp::GreaterThan, Value::Integer(0)),
        ]))
        .canonicalize()
        .unwrap();
    assert_eq!(with_unary.inequality_fields().len(), 2);
    // Nested AND inside AND flattens; OR inside OR flattens.
    let nested = tasks()
        .with_filter(FilterExpr::And(vec![
            FilterExpr::And(vec![
                field("a", FieldOp::Equal, Value::Integer(1)),
                field("b", FieldOp::Equal, Value::Integer(2)),
            ]),
            field("c", FieldOp::Equal, Value::Integer(3)),
        ]))
        .canonicalize()
        .unwrap();
    assert_eq!(nested.dnf_disjunction_count(), 1);
    assert_eq!(nested.component_count().filters, 3);
}

#[test]
fn size_breakdown_keeps_exactly_the_largest_contributors() {
    let path = parse("docs/big").unwrap();
    let mut fields: BTreeMap<String, Value> = BTreeMap::new();
    for i in 0..(MAX_CONTRIBUTORS + 5) {
        fields.insert(format!("f{i:02}"), Value::String("x".repeat(i + 1)));
    }
    let size = document_size(&path, &fields).unwrap();
    assert_eq!(size.largest_contributors.len(), MAX_CONTRIBUTORS);
    assert_eq!(
        size.largest_contributors[0].name,
        format!("f{:02}", MAX_CONTRIBUTORS + 4)
    );
    assert!(size
        .largest_contributors
        .windows(2)
        .all(|w| w[0].bytes >= w[1].bytes));
    assert_eq!(
        ftd_core_firestore::size::SizeError::Overflow.to_string(),
        "size calculation overflow"
    );
}
