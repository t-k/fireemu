//! Exact scoped rollback and borrowed before-state reconstruction.
use fireemu_core_database::{
    Format, Json, NodeView, Number, Path, ScopeView, ServerValueContext, Tree,
};
const NOW: ServerValueContext = ServerValueContext { now_millis: 100 };
fn path(text: &str) -> Path {
    Path::from_keys(text.split('/').filter(|key| !key.is_empty()))
}
fn view_json(node: Option<NodeView<'_>>) -> Json {
    let Some(node) = node else {
        return Json::Null;
    };
    if let Some(leaf) = node.leaf() {
        let value = match leaf {
            fireemu_core_database::Leaf::Bool(v) => Json::Bool(*v),
            fireemu_core_database::Leaf::Number(v) => Json::Number(*v),
            fireemu_core_database::Leaf::String(v) => Json::string(v),
        };
        return node.priority().map_or_else(
            || value.clone(),
            |p| Json::object([(".value", value.clone()), (".priority", p.to_json())]),
        );
    }
    let mut entries: Vec<_> = node
        .children()
        .unwrap()
        .map(|(k, v)| (k.to_owned(), view_json(Some(v))))
        .collect();
    if let Some(p) = node.priority() {
        entries.push((".priority".into(), p.to_json()));
    }
    Json::object(entries)
}
fn prioritized(value: Json, priority: Json) -> Json {
    Json::object([(".value", value), (".priority", priority)])
}

#[test]
fn restoration_and_overlay_preserve_ancestor_leaves_priorities_and_existence() {
    let fixtures = [
        Json::Null,
        prioritized(Json::string("ancestor"), Json::string("root-priority")),
        Json::object([
            ("a", prioritized(Json::string("leaf"), Json::int(2))),
            (".priority", Json::int(1)),
        ]),
        Json::object([
            (
                "a",
                Json::object([
                    (
                        "x",
                        prioritized(Json::Number(Number::Double(-0.0)), Json::int(3)),
                    ),
                    (".priority", Json::int(2)),
                ]),
            ),
            (".priority", Json::int(1)),
        ]),
        Json::object([
            (
                "a",
                Json::object([
                    ("x", Json::int(1)),
                    ("y", Json::string("sibling")),
                    (".priority", Json::int(2)),
                ]),
            ),
            ("b", Json::string("unrelated")),
            (".priority", Json::int(1)),
        ]),
    ];
    for fixture in fixtures {
        for scope in ["/", "/a", "/a/x", "/a/x/deep", "/a/.priority", "/z/deep"] {
            for value in [
                Json::Null,
                Json::int(4),
                Json::object([("nested", Json::Bool(true))]),
            ] {
                let mut tree = Tree::default();
                tree.set(&Path::root(), &fixture, NOW).unwrap();
                let original = tree.clone();
                let at = path(scope);
                let snapshot = tree.save_scope(&at);
                // Invalid priority values are also safe to restore.
                let _ = tree.set(&at, &value, NOW);
                let before = snapshot.view(&tree);
                for reference in ["/", "/a", "/a/x", "/a/x/deep", "/a/y", "/b", "/z"] {
                    let reference = path(reference);
                    assert_eq!(
                        format!("{:?}", view_json(before.get(&reference))),
                        format!("{:?}", original.get_json(&reference, Format::Export)),
                        "scope {scope}, reference {reference}"
                    );
                }
                tree.restore_scope(snapshot);
                assert_eq!(
                    format!("{tree:?}"),
                    format!("{original:?}"),
                    "scope {scope}"
                );
            }
        }
    }
}

#[test]
fn snapshot_does_not_retain_unrelated_siblings_and_overlay_borrows_them() {
    let mut tree = Tree::default();
    tree.set(
        &Path::root(),
        &Json::object([
            ("a", Json::int(1)),
            ("b", Json::string("unrelated-marker".repeat(4096))),
        ]),
        NOW,
    )
    .unwrap();
    let snapshot = tree.save_scope(&path("/a"));
    let debug = format!("{snapshot:?}");
    assert!(!debug.contains("unrelated-marker"));
    assert!(debug.len() < 512);
    tree.set(&path("/a"), &Json::Bool(true), NOW).unwrap();
    let Some(NodeView::Borrowed(before)) = snapshot.view(&tree).get(&path("/b")) else {
        panic!("sibling must be borrowed")
    };
    assert!(std::ptr::eq(before, tree.get(&path("/b")).unwrap()));
    assert_eq!(
        view_json(ScopeView::from(&tree).get(&path("/a"))),
        Json::Bool(true)
    );
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(128))]
    #[test]
    fn scoped_operation_sequences_restore_exact_representation(
        initial in proptest::collection::btree_map("[ab]{1,2}", proptest::num::i64::ANY, 0..8),
        operations in proptest::collection::vec(proptest::option::of(proptest::num::i64::ANY), 1..16),
        depth in 0usize..4,
        leaf_ancestor in proptest::bool::ANY,
    ) {
        let mut tree = Tree::default();
        let branch = if leaf_ancestor { prioritized(Json::Number(Number::Double(-0.0)), Json::int(9)) } else { Json::object(initial.into_iter().map(|(k,v)| (k,Json::int(v)))) };
        tree.set(&Path::root(), &Json::object([("a", branch), ("b", Json::Bool(true)), (".priority", Json::int(7))]), NOW).unwrap();
        let original = format!("{tree:?}");
        let original_json = format!("{:?}", tree.get_json(&Path::root(), Format::Export));
        let scope = Path::from_keys(std::iter::repeat_n("a", depth));
        let snapshot = tree.save_scope(&scope);
        for value in operations {
            tree.set(&scope, &value.map_or(Json::Null, Json::int), NOW).unwrap();
        }
        proptest::prop_assert_eq!(format!("{:?}", view_json(snapshot.view(&tree).root())), original_json);
        tree.restore_scope(snapshot);
        proptest::prop_assert_eq!(format!("{tree:?}"), original);
    }
}
