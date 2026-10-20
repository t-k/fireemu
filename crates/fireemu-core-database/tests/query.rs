//! Query order, bounds and limits.

mod support;

use fireemu_core_database::{ErrorKind, Json, OrderBy, QueryParams, Tree};
use serde_json::json;
use support::{j, p, tree_with};

fn keys(tree: &Tree, path: &str, query: &QueryParams) -> Vec<String> {
    query.validate().unwrap();
    query
        .run(tree.get(&p(path)))
        .into_iter()
        .map(|(k, _)| k.to_owned())
        .collect()
}

fn child(path: &str) -> OrderBy {
    OrderBy::Child(p(path))
}

/// The documented orderByChild example: missing and null first, then false, true, numbers,
/// strings and objects; ties by key.
fn mixed() -> Tree {
    tree_with(json!({
        "obj2": {"v": {"z": 1}},
        "obj1": {"v": {"a": 1}},
        "str_b": {"v": "b"},
        "str_a": {"v": "a"},
        "num_10": {"v": 10},
        "num_neg": {"v": -1.5},
        "num_2": {"v": 2},
        "true": {"v": true},
        "false": {"v": false},
        "none": {"other": 1},
        "leaf": 5
    }))
}

#[test]
fn order_by_child_follows_the_documented_type_order() {
    assert_eq!(
        keys(&mixed(), "/", &QueryParams::ordered_by(child("v"))),
        [
            "leaf", "none", "false", "true", "num_neg", "num_2", "num_10", "str_a", "str_b",
            "obj1", "obj2"
        ]
    );
}

#[test]
fn order_by_value_orders_leaves_and_puts_objects_last() {
    let tree = tree_with(json!({"a": "x", "b": 3, "c": {"n": 1}, "d": false, "e": 1}));
    assert_eq!(
        keys(&tree, "/", &QueryParams::ordered_by(OrderBy::Value)),
        ["d", "e", "b", "a", "c"]
    );
}

#[test]
fn order_by_key_uses_the_key_order() {
    let tree = tree_with(json!({"b": 1, "10": 1, "a": 1, "2": 1, "-1": 1}));
    assert_eq!(
        keys(&tree, "/", &QueryParams::ordered_by(OrderBy::Key)),
        ["-1", "2", "10", "a", "b"]
    );
}

#[test]
fn order_by_priority_puts_no_priority_first_then_numbers_then_strings() {
    let tree = tree_with(json!({
        "s": {".value": 1, ".priority": "a"},
        "n2": {".value": 1, ".priority": 2},
        "n1": {".value": 1, ".priority": 1},
        "none_b": 1,
        "none_a": 1
    }));
    assert_eq!(
        keys(&tree, "/", &QueryParams::default()),
        ["none_a", "none_b", "n1", "n2", "s"]
    );
}

#[test]
fn start_and_end_bounds_are_inclusive_and_after_before_exclusive() {
    let tree = tree_with(json!({"a": 1, "b": 2, "c": 2, "d": 3}));
    let by_value = || QueryParams::ordered_by(OrderBy::Value);
    assert_eq!(
        keys(&tree, "/", &by_value().start_at(Json::int(2), None)),
        ["b", "c", "d"]
    );
    assert_eq!(
        keys(&tree, "/", &by_value().start_after(Json::int(2), None)),
        ["d"]
    );
    assert_eq!(
        keys(&tree, "/", &by_value().end_at(Json::int(2), None)),
        ["a", "b", "c"]
    );
    assert_eq!(
        keys(&tree, "/", &by_value().end_before(Json::int(2), None)),
        ["a"]
    );
    assert_eq!(
        keys(&tree, "/", &by_value().equal_to(Json::int(2), None)),
        ["b", "c"]
    );
}

#[test]
fn a_bound_key_name_splits_children_with_equal_values() {
    let tree = tree_with(json!({"a": 1, "b": 2, "c": 2, "d": 2, "e": 3}));
    let by_value = || QueryParams::ordered_by(OrderBy::Value);
    assert_eq!(
        keys(&tree, "/", &by_value().start_at(Json::int(2), Some("c"))),
        ["c", "d", "e"]
    );
    assert_eq!(
        keys(&tree, "/", &by_value().start_after(Json::int(2), Some("c"))),
        ["d", "e"]
    );
    assert_eq!(
        keys(&tree, "/", &by_value().end_at(Json::int(2), Some("c"))),
        ["a", "b", "c"]
    );
    assert_eq!(
        keys(&tree, "/", &by_value().end_before(Json::int(2), Some("c"))),
        ["a", "b"]
    );
    assert_eq!(
        keys(&tree, "/", &by_value().equal_to(Json::int(2), Some("c"))),
        ["c"]
    );
}

#[test]
fn null_bounds_select_children_without_the_value() {
    let tree = mixed();
    assert_eq!(
        keys(
            &tree,
            "/",
            &QueryParams::ordered_by(child("v")).equal_to(Json::Null, None)
        ),
        ["leaf", "none"]
    );
}

#[test]
fn key_bounds_compare_with_the_key_order() {
    let tree = tree_with(json!({"1": 1, "2": 1, "10": 1, "a": 1, "b": 1}));
    let by_key = || QueryParams::ordered_by(OrderBy::Key);
    assert_eq!(
        keys(&tree, "/", &by_key().start_at(Json::string("2"), None)),
        ["2", "10", "a", "b"]
    );
    assert_eq!(
        keys(&tree, "/", &by_key().end_before(Json::string("a"), None)),
        ["1", "2", "10"]
    );
    assert_eq!(
        keys(&tree, "/", &by_key().start_after(Json::string("10"), None)),
        ["a", "b"]
    );
}

#[test]
fn limits_keep_the_first_or_last_children_of_the_range() {
    let tree = tree_with(json!({"a": 1, "b": 2, "c": 3, "d": 4}));
    let by_value = || QueryParams::ordered_by(OrderBy::Value);
    assert_eq!(keys(&tree, "/", &by_value().limit_to_first(2)), ["a", "b"]);
    assert_eq!(keys(&tree, "/", &by_value().limit_to_last(2)), ["c", "d"]);
    assert_eq!(
        keys(
            &tree,
            "/",
            &by_value().start_at(Json::int(2), None).limit_to_last(1)
        ),
        ["d"]
    );
    assert_eq!(
        keys(&tree, "/", &by_value().limit_to_first(10)),
        ["a", "b", "c", "d"]
    );
    assert!(keys(&tree, "/", &by_value().limit_to_first(0)).is_empty());
}

#[test]
fn queries_on_leaves_and_absent_locations_select_nothing() {
    let tree = tree_with(json!({"a": 1}));
    assert!(keys(&tree, "/a", &QueryParams::default()).is_empty());
    assert!(keys(&tree, "/missing", &QueryParams::default()).is_empty());
}

#[test]
fn deep_child_paths_order_by_the_nested_value() {
    let tree = tree_with(json!({
        "x": {"m": {"n": 3}},
        "y": {"m": {"n": 1}},
        "z": {"m": 7}
    }));
    assert_eq!(
        keys(&tree, "/", &QueryParams::ordered_by(child("m/n"))),
        ["z", "y", "x"]
    );
}

#[test]
fn bound_values_must_fit_the_order() {
    let bad = [
        QueryParams::ordered_by(OrderBy::Key).start_at(Json::int(1), None),
        QueryParams::ordered_by(OrderBy::Key).start_at(Json::string("a"), Some("k")),
        QueryParams::ordered_by(OrderBy::Key).end_at(Json::Null, None),
        QueryParams::default().start_at(Json::Bool(true), None),
        QueryParams::ordered_by(OrderBy::Value).start_at(j(json!({"a": 1})), None),
        QueryParams::ordered_by(OrderBy::Value).end_at(j(json!([1])), None),
    ];
    for query in bad {
        assert_eq!(
            query.validate().unwrap_err().kind,
            ErrorKind::InvalidQuery,
            "{query:?}"
        );
    }
    QueryParams::ordered_by(OrderBy::Value)
        .start_at(Json::Bool(false), Some("k"))
        .end_at(Json::Null, None)
        .validate()
        .unwrap();
}
