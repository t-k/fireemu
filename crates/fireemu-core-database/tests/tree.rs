//! Writes, reads, priorities, server values and the export format.

mod support;

use fireemu_core_database::{ErrorKind, Format, Json, Limits, Path, Tree};
use serde_json::json;
use support::{j, p, s, tree_with, NOW};

fn plain(tree: &Tree, path: &str) -> serde_json::Value {
    s(&tree.get_json(&p(path), Format::Plain))
}

fn export(tree: &Tree, path: &str) -> serde_json::Value {
    s(&tree.get_json(&p(path), Format::Export))
}

#[test]
fn set_and_get_round_trip_and_absent_reads_null() {
    let tree = tree_with(json!({"a": {"b": 1, "c": "x"}, "d": true}));
    assert_eq!(
        plain(&tree, "/"),
        json!({"a": {"b": 1, "c": "x"}, "d": true})
    );
    assert_eq!(plain(&tree, "/a/b"), json!(1));
    assert_eq!(plain(&tree, "/missing"), json!(null));
    assert_eq!(plain(&tree, "/a/b/deeper"), json!(null));
}

#[test]
fn null_deletes_and_empty_parents_are_pruned() {
    let mut tree = tree_with(json!({"a": {"b": {"c": 1}}, "x": 1}));
    tree.set(&p("/a/b/c"), &Json::Null, NOW).unwrap();
    assert_eq!(plain(&tree, "/"), json!({"x": 1}));
    tree.set(&p("/x"), &Json::Null, NOW).unwrap();
    assert!(tree.root().is_none());
    assert_eq!(plain(&tree, "/"), json!(null));
}

#[test]
fn null_children_and_empty_objects_store_nothing() {
    let tree = tree_with(json!({"a": null, "b": {}, "c": {"d": null}, "e": [], "f": 1}));
    assert_eq!(plain(&tree, "/"), json!({"f": 1}));
}

#[test]
fn plain_reads_render_dense_index_keys_as_arrays() {
    // The SDK's `val()` rule, and the official emulator's GET for the same writes: every
    // key a canonical index and the largest below twice the count.
    let read = |value: serde_json::Value| plain(&tree_with(json!({ "l": value })), "/l");
    assert_eq!(read(json!(["a", null, "c"])), json!(["a", null, "c"]));
    assert_eq!(
        read(json!({"0": "a", "3": "b"})),
        json!(["a", null, null, "b"])
    );
    assert_eq!(read(json!({"1": "x"})), json!([null, "x"]));
    assert_eq!(
        read(json!({"0": "a", "4": "b"})),
        json!({"0": "a", "4": "b"})
    );
    assert_eq!(read(json!({"0": "a", "x": 1})), json!({"0": "a", "x": 1}));
    assert_eq!(read(json!({"00": 1})), json!({"00": 1}));
    assert_eq!(read(json!({"2": "x"})), json!({"2": "x"}));
    assert_eq!(read(json!([[1, 2], {"0": "z"}])), json!([[1, 2], ["z"]]));
    assert_eq!(
        read(json!({"0": {".value": "a", ".priority": 1}, "1": "b", ".priority": 5})),
        json!(["a", "b"])
    );
}

#[test]
fn exports_keep_index_keys_as_objects() {
    // The SDK never converts in export format; the REST layer renders the official
    // emulator's form on its own.
    let tree = tree_with(json!({"l": ["a", null, "c"]}));
    assert_eq!(export(&tree, "/l"), json!({"0": "a", "2": "c"}));
}

#[test]
fn writing_below_a_leaf_replaces_the_leaf() {
    let mut tree = tree_with(json!({"a": 5}));
    tree.set(&p("/a/b"), &j(json!(1)), NOW).unwrap();
    assert_eq!(plain(&tree, "/"), json!({"a": {"b": 1}}));
}

#[test]
fn deleting_below_a_leaf_changes_nothing() {
    let mut tree = tree_with(json!({"a": 5}));
    tree.set(&p("/a/b"), &Json::Null, NOW).unwrap();
    assert_eq!(plain(&tree, "/"), json!({"a": 5}));
}

#[test]
fn priorities_are_written_with_dot_priority_and_dot_value() {
    let tree = tree_with(json!({
        "leaf": {".value": 3, ".priority": 1},
        "obj": {"x": 1, ".priority": "p"}
    }));
    assert_eq!(plain(&tree, "/"), json!({"leaf": 3, "obj": {"x": 1}}));
    assert_eq!(
        export(&tree, "/"),
        json!({"leaf": {".value": 3, ".priority": 1.0}, "obj": {"x": 1, ".priority": "p"}})
    );
    assert_eq!(plain(&tree, "/leaf/.priority"), json!(1.0));
    assert_eq!(plain(&tree, "/obj/.priority"), json!("p"));
    assert_eq!(plain(&tree, "/missing/.priority"), json!(null));
}

#[test]
fn setting_dot_priority_changes_only_an_existing_node() {
    let mut tree = tree_with(json!({"a": 1}));
    tree.set(&p("/a/.priority"), &j(json!(7)), NOW).unwrap();
    assert_eq!(export(&tree, "/a"), json!({".value": 1, ".priority": 7}));
    tree.set(&p("/a/.priority"), &Json::Null, NOW).unwrap();
    assert_eq!(export(&tree, "/a"), json!(1));
    // The official emulator refuses "could not set priority on non-existent node".
    let err = tree
        .set(&p("/missing/.priority"), &j(json!(7)), NOW)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PriorityOnAbsentNode);
    assert_eq!(export(&tree, "/"), json!({"a": 1}));
}

#[test]
fn a_priority_placeholder_resolves_against_the_stored_priority() {
    let mut tree = tree_with(json!({"a": {".value": 1, ".priority": 5}}));
    let inc = j(json!({".sv": {"increment": 1}}));
    tree.set(&p("/a/.priority"), &inc, NOW).unwrap();
    // A `.priority` member is a double (5.0), so the increment gives 6.0.
    assert_eq!(export(&tree, "/a"), json!({".value": 1, ".priority": 6.0}));
    tree.set(
        &p("/a"),
        &j(json!({".value": 2, ".priority": {".sv": {"increment": 1}}})),
        NOW,
    )
    .unwrap();
    assert_eq!(export(&tree, "/a"), json!({".value": 2, ".priority": 7.0}));
    tree.set(
        &p("/b"),
        &j(json!({"x": 1, ".priority": {".sv": {"increment": 2}}})),
        NOW,
    )
    .unwrap();
    assert_eq!(export(&tree, "/b"), json!({"x": 1, ".priority": 2.0}));
}

#[test]
fn update_priorities_need_a_node_that_exists_before_the_update() {
    let mut tree = tree_with(json!({"keep": 1}));
    let entries = |pairs: &[(&str, serde_json::Value)]| {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), j(v.clone())))
            .collect::<Vec<_>>()
    };
    for order in [
        entries(&[("b/.priority", json!(3)), ("b/c", json!(1))]),
        entries(&[("b/c", json!(1)), ("b/.priority", json!(3))]),
    ] {
        let err = tree.update(&Path::root(), &order, NOW).unwrap_err();
        assert_eq!(err.kind, ErrorKind::PriorityOnAbsentNode);
        assert_eq!(export(&tree, "/"), json!({"keep": 1}));
    }
    tree.set(&p("/b"), &j(json!({"x": 1})), NOW).unwrap();
    tree.update(
        &Path::root(),
        &entries(&[("b/.priority", json!(3)), ("b/c", json!(1))]),
        NOW,
    )
    .unwrap();
    assert_eq!(export(&tree, "/b"), json!({"c": 1, "x": 1, ".priority": 3}));
    // The priority is applied after the values, so a node the update empties is gone.
    tree.set(&p("/d"), &j(json!({"x": 1})), NOW).unwrap();
    tree.update(
        &Path::root(),
        &entries(&[("d/.priority", json!(3)), ("d/x", json!(null))]),
        NOW,
    )
    .unwrap();
    assert_eq!(export(&tree, "/d"), json!(null));
}

#[test]
fn a_priority_on_an_empty_value_is_refused() {
    // The official emulator answers "couldn't parse" for each of these.
    let mut tree = Tree::new(Limits::default());
    for value in [
        json!({".priority": 1}),
        json!({"a": null, ".priority": 1}),
        json!({".value": null, ".priority": 1}),
        json!({"a": {".priority": 1}}),
        json!({"a": {}, ".priority": 1}),
    ] {
        let err = tree.set(&p("/n"), &j(value.clone()), NOW).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidData, "{value}");
    }
    tree.set(&p("/n"), &j(json!({})), NOW).unwrap();
    tree.set(&p("/n"), &j(json!({"a": {}})), NOW).unwrap();
    assert!(tree.root().is_none());
}

#[test]
fn deletes_are_held_to_the_depth_and_path_limits() {
    let mut tree = Tree::new(Limits::default());
    let deep = (0..33)
        .map(|i| format!("k{i}"))
        .collect::<Vec<_>>()
        .join("/");
    let err = tree.set(&p(&deep), &Json::Null, NOW).unwrap_err();
    assert_eq!(err.kind, ErrorKind::PathTooDeep);
    let err = tree
        .set(
            &p("/x"),
            &j(json!({ "k".repeat(400): { "k".repeat(400): null } })),
            NOW,
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PathTooLong);
}

#[test]
fn overwriting_a_value_drops_its_priority_but_child_writes_keep_it() {
    let mut tree = tree_with(json!({"a": {"x": 1, ".priority": 2}}));
    tree.set(&p("/a/y"), &j(json!(2)), NOW).unwrap();
    assert_eq!(
        export(&tree, "/a"),
        json!({"x": 1, "y": 2, ".priority": 2.0})
    );
    tree.set(&p("/a"), &j(json!({"z": 1})), NOW).unwrap();
    assert_eq!(export(&tree, "/a"), json!({"z": 1}));
}

#[test]
fn a_priority_disappears_with_the_last_child() {
    let mut tree = tree_with(json!({"a": {"x": 1, ".priority": 2}}));
    tree.set(&p("/a/x"), &Json::Null, NOW).unwrap();
    tree.set(&p("/a/x"), &j(json!(1)), NOW).unwrap();
    assert_eq!(export(&tree, "/a"), json!({"x": 1}));
}

#[test]
fn a_leaf_keeps_its_priority_when_a_child_replaces_it() {
    let mut tree = tree_with(json!({"a": {".value": 1, ".priority": 9}}));
    tree.set(&p("/a/b"), &j(json!(1)), NOW).unwrap();
    assert_eq!(export(&tree, "/a"), json!({"b": 1, ".priority": 9.0}));
}

#[test]
fn invalid_priorities_and_value_shapes_are_refused() {
    let mut tree = Tree::new(Limits::default());
    let cases = [
        (
            json!({"a": 1, ".priority": true}),
            ErrorKind::InvalidPriority,
        ),
        (
            json!({"a": 1, ".priority": {"x": 1}}),
            ErrorKind::InvalidPriority,
        ),
        (json!({".value": 1, "a": 2}), ErrorKind::InvalidData),
        (json!({"a.b": 1}), ErrorKind::InvalidKey),
        (json!({"": 1}), ErrorKind::InvalidKey),
        (json!({".other": 1}), ErrorKind::InvalidKey),
    ];
    for (value, kind) in cases {
        let err = tree.set(&p("/x"), &j(value.clone()), NOW).unwrap_err();
        assert_eq!(err.kind, kind, "{value}");
    }
    assert!(tree.root().is_none());
    tree.set(&p("/x"), &j(json!(1)), NOW).unwrap();
    let err = tree
        .set(&p("/x/.priority"), &j(json!(true)), NOW)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidPriority);
    assert_eq!(export(&tree, "/x"), json!(1));
}

#[test]
fn info_is_read_only() {
    let mut tree = Tree::new(Limits::default());
    let err = tree
        .set(&p("/.info/connected"), &j(json!(true)), NOW)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::ReadOnlyPath);
    let err = tree
        .update(&Path::root(), &[(".info/x".to_owned(), j(json!(1)))], NOW)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::ReadOnlyPath);
}

#[test]
fn depth_counts_keys_from_the_root_to_the_deepest_value() {
    let mut tree = Tree::new(Limits::default());
    let deep = |n: usize| {
        (0..n)
            .map(|i| format!("k{i}"))
            .collect::<Vec<_>>()
            .join("/")
    };
    tree.set(&p(&deep(32)), &j(json!(1)), NOW).unwrap();
    let err = tree.set(&p(&deep(33)), &j(json!(1)), NOW).unwrap_err();
    assert_eq!(err.kind, ErrorKind::PathTooDeep);
    tree.set(&p(&deep(31)), &j(json!({"x": 1})), NOW).unwrap();
    let err = tree
        .set(&p(&deep(31)), &j(json!({"x": {"y": 1}})), NOW)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PathTooDeep);
}

#[test]
fn written_keys_count_towards_the_path_length() {
    let mut tree = Tree::new(Limits::default());
    // "/x" plus a separator plus the key: 1 + 1 + 766 = 768 bytes.
    tree.set(&p("/x"), &j(json!({ "k".repeat(766): 1 })), NOW)
        .unwrap();
    let err = tree
        .set(&p("/x"), &j(json!({ "k".repeat(767): 1 })), NOW)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PathTooLong);
    let err = tree
        .set(&p("/x"), &j(json!({"a": { "k".repeat(765): 1 }})), NOW)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PathTooLong);
}

#[test]
fn strings_are_limited_in_bytes() {
    let limits = Limits {
        max_string_bytes: 4,
        ..Limits::default()
    };
    let mut tree = Tree::new(limits);
    tree.set(&p("/a"), &j(json!("abcd")), NOW).unwrap();
    let err = tree.set(&p("/a"), &j(json!("abcde")), NOW).unwrap_err();
    assert_eq!(err.kind, ErrorKind::StringTooLong);
    let err = tree.set(&p("/a"), &j(json!("ああ")), NOW).unwrap_err();
    assert_eq!(err.kind, ErrorKind::StringTooLong);
}

#[test]
fn server_timestamp_resolves_to_the_context_time() {
    let mut tree = Tree::new(Limits::default());
    tree.set(
        &p("/a"),
        &j(json!({"t": {".sv": "timestamp"}, "x": {".value": 1, ".priority": {".sv": "timestamp"}}})),
        NOW,
    )
    .unwrap();
    assert_eq!(
        export(&tree, "/a"),
        json!({"t": NOW.now_millis, "x": {".value": 1, ".priority": 1_760_000_000_000.0}})
    );
}

#[test]
fn increment_adds_to_the_stored_number_or_starts_from_the_delta() {
    let mut tree = tree_with(json!({"n": 5, "s": "text", "f": 0.5}));
    let inc = |d: serde_json::Value| j(json!({".sv": {"increment": d}}));
    tree.set(&p("/n"), &inc(json!(2)), NOW).unwrap();
    tree.set(&p("/s"), &inc(json!(2)), NOW).unwrap();
    tree.set(&p("/missing"), &inc(json!(-3)), NOW).unwrap();
    tree.set(&p("/f"), &inc(json!(0.25)), NOW).unwrap();
    assert_eq!(
        plain(&tree, "/"),
        json!({"n": 7, "s": 2, "missing": -3, "f": 0.75})
    );
}

#[test]
fn increment_inside_an_object_uses_the_stored_child() {
    let mut tree = tree_with(json!({"a": {"count": 10}}));
    tree.set(
        &p("/a"),
        &j(json!({"count": {".sv": {"increment": 1}}, "y": 1})),
        NOW,
    )
    .unwrap();
    assert_eq!(plain(&tree, "/a"), json!({"count": 11, "y": 1}));
}

#[test]
fn unknown_or_malformed_server_values_are_refused() {
    let mut tree = Tree::new(Limits::default());
    for value in [
        json!({".sv": "nope"}),
        json!({".sv": {"increment": "1"}}),
        json!({".sv": {"increment": 1, "x": 2}}),
        json!({".sv": {"other": 1}}),
        json!({".sv": 5}),
        json!({".sv": "timestamp", "x": 1}),
    ] {
        let err = tree.set(&p("/a"), &j(value.clone()), NOW).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidServerValue, "{value}");
    }
}

#[test]
fn increment_in_a_prioritized_value_uses_the_stored_number() {
    let mut tree = tree_with(json!({"n": 5}));
    tree.set(
        &p("/n"),
        &j(json!({".value": {".sv": {"increment": 1}}, ".priority": 2})),
        NOW,
    )
    .unwrap();
    assert_eq!(export(&tree, "/n"), json!({".value": 6, ".priority": 2.0}));
}

#[test]
fn trees_report_their_limits_and_node_depth() {
    let limits = Limits {
        max_depth: 3,
        ..Limits::default()
    };
    assert_eq!(*Tree::new(limits).limits(), limits);
    let tree = tree_with(json!({"a": {"b": {"c": 1}}, "d": 1}));
    assert_eq!(tree.root().unwrap().depth(), 3);
    assert_eq!(tree.get(&p("/a/b")).unwrap().depth(), 1);
    assert_eq!(tree.get(&p("/d")).unwrap().depth(), 0);
}

#[test]
fn multipath_update_writes_each_path_and_keeps_siblings() {
    let mut tree = tree_with(json!({"a": {"x": 1, "y": 2}, "b": {"z": 3}}));
    tree.update(
        &p("/"),
        &[
            ("a/x".to_owned(), j(json!(10))),
            ("b".to_owned(), j(json!(null))),
            ("c/d/e".to_owned(), j(json!("new"))),
        ],
        NOW,
    )
    .unwrap();
    assert_eq!(
        plain(&tree, "/"),
        json!({"a": {"x": 10, "y": 2}, "c": {"d": {"e": "new"}}})
    );
}

#[test]
fn update_at_a_base_path_is_relative_to_it() {
    let mut tree = tree_with(json!({"a": {"x": 1}}));
    tree.update(&p("/a"), &[("y".to_owned(), j(json!(2)))], NOW)
        .unwrap();
    assert_eq!(plain(&tree, "/a"), json!({"x": 1, "y": 2}));
}

#[test]
fn overlapping_update_paths_are_refused_and_nothing_is_written() {
    let mut tree = tree_with(json!({"keep": 1}));
    let err = tree
        .update(
            &Path::root(),
            &[
                ("a".to_owned(), j(json!(1))),
                ("a/b".to_owned(), j(json!(2))),
            ],
            NOW,
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::OverlappingUpdate);
    let err = tree
        .update(
            &Path::root(),
            &[
                ("a/".to_owned(), j(json!(1))),
                ("/a".to_owned(), j(json!(2))),
            ],
            NOW,
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::OverlappingUpdate);
    assert_eq!(plain(&tree, "/"), json!({"keep": 1}));
}

#[test]
fn an_invalid_entry_aborts_the_whole_update() {
    let mut tree = tree_with(json!({"keep": 1}));
    let err = tree
        .update(
            &Path::root(),
            &[
                ("a".to_owned(), j(json!(1))),
                ("b".to_owned(), j(json!({"c.d": 1}))),
            ],
            NOW,
        )
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidKey);
    assert_eq!(plain(&tree, "/"), json!({"keep": 1}));
}

#[test]
fn update_server_values_resolve_against_the_tree_before_the_update() {
    let mut tree = tree_with(json!({"n": 1}));
    tree.update(
        &Path::root(),
        &[
            ("n".to_owned(), j(json!({".sv": {"increment": 1}}))),
            ("m".to_owned(), j(json!({".sv": {"increment": 1}}))),
        ],
        NOW,
    )
    .unwrap();
    assert_eq!(plain(&tree, "/"), json!({"n": 2, "m": 1}));
}

#[test]
fn update_can_set_a_priority() {
    let mut tree = tree_with(json!({"a": 1}));
    tree.update(&p("/a"), &[(".priority".to_owned(), j(json!(4)))], NOW)
        .unwrap();
    assert_eq!(export(&tree, "/a"), json!({".value": 1, ".priority": 4}));
}

#[test]
fn shallow_truncates_children_to_true() {
    let tree = tree_with(json!({"a": {"b": 1}, "c": "x"}));
    assert_eq!(
        s(&tree.root().unwrap().shallow()),
        json!({"a": true, "c": true})
    );
    assert_eq!(s(&tree.get(&p("/c")).unwrap().shallow()), json!("x"));
}

#[test]
fn export_reads_back_to_the_same_tree() {
    let tree = tree_with(json!({
        "a": {".value": "v", ".priority": 1.5},
        "b": {"c": {".value": false, ".priority": "z"}, ".priority": 3},
        "d": 4
    }));
    let exported = tree.get_json(&Path::root(), Format::Export);
    let mut copy = Tree::new(Limits::default());
    copy.set(&Path::root(), &exported, NOW).unwrap();
    assert_eq!(copy, tree);
}

#[test]
fn a_key_at_the_root_has_no_separator() {
    let mut tree = Tree::new(Limits::default());
    tree.set(&Path::root(), &j(json!({ "k".repeat(768): 1 })), NOW)
        .unwrap();
    let err = tree
        .set(&Path::root(), &j(json!({ "k".repeat(769): 1 })), NOW)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::PathTooLong);
}

#[test]
fn priorities_inside_data_are_doubles_and_written_ones_keep_their_type() {
    // The official emulator answers `{".value":1,".priority":2.0}` for a `.priority` member
    // of 2, and `5` for a write of 5 to `<location>/.priority` (ledger 1475, provisional).
    use fireemu_core_database::{Number, Priority};
    let mut tree =
        tree_with(json!({"a": {".value": 1, ".priority": 2}, "b": {"x": 1, ".priority": 3}}));
    let priority = |tree: &Tree, path: &str| tree.get(&p(path)).unwrap().priority.clone();
    assert!(matches!(priority(&tree, "/a"), Some(Priority::Number(Number::Double(d))) if d == 2.0));
    assert!(matches!(priority(&tree, "/b"), Some(Priority::Number(Number::Double(d))) if d == 3.0));
    tree.set(&p("/a/.priority"), &j(json!(5)), NOW).unwrap();
    assert!(matches!(
        priority(&tree, "/a"),
        Some(Priority::Number(Number::Int(5)))
    ));
    tree.set(&p("/a"), &j(json!({".value": 1, ".priority": "s"})), NOW)
        .unwrap();
    assert_eq!(
        priority(&tree, "/a"),
        Some(Priority::String("s".to_owned()))
    );
}
