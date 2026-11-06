//! Layout and byte-level export contracts for the stored tree.

#[test]
#[cfg(target_pointer_width = "64")]
fn unprioritized_nodes_fit_forty_bytes() {
    let bytes = std::mem::size_of::<fireemu_core_database::Node>();
    assert!(bytes <= 40, "an unprioritized node occupies {bytes} bytes");
}

use fireemu_adapter_database::rest::{prepare_import, Database, RestOptions};
use proptest::prelude::*;

fn exported(input: &str) -> String {
    let options = RestOptions::default();
    let prepared = prepare_import("demo-footprint", input.to_owned(), &options.limits).unwrap();
    let mut database = Database::new(options, 0);
    database.install_import(prepared, 0).unwrap();
    database.export_texts().remove(0).1
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn export_bytes_preserve_priorities_numbers_and_key_order(
        integer in -10000i64..10000,
        double in any::<bool>(),
        priority in 0usize..4,
        shape in 0usize..3,
    ) {
        let value = if double { format!("{integer}.0") } else { integer.to_string() };
        let priority = match priority {
            0 => String::new(),
            1 => ",\".priority\":2.0".to_owned(),
            2 => ",\".priority\":-0.0".to_owned(),
            _ => ",\".priority\":\"rank\"".to_owned(),
        };
        let (input, expected) = match shape {
            0 if priority.is_empty() => (value.clone(), value),
            0 => {
                let input = format!("{{\".value\":{value}{priority}}}");
                let expected = format!("{{\".value\":{value}{priority}}}");
                (input, expected)
            }
            1 => {
                let input = format!("{{\"1\":{value},\"0\":true{priority}}}");
                let expected = if priority.is_empty() {
                    format!("[true,{value}]")
                } else {
                    format!("{{\"0\":true,\"1\":{value}{priority}}}")
                };
                (input, expected)
            }
            _ => {
                let input = format!("{{\"z\":{value},\"10\":false,\"2\":true,\"a\":\"😀\"{priority}}}");
                let expected = if priority.is_empty() {
                    format!("{{\"2\":true,\"10\":false,\"a\":\"😀\",\"z\":{value}}}")
                } else {
                    format!("{{\"2\":true,\"10\":false,{},\"a\":\"😀\",\"z\":{value}}}", &priority[1..])
                };
                (input, expected)
            }
        };
        let actual = exported(&input);
        prop_assert_eq!(actual.as_bytes(), expected.as_bytes());
    }
}

#[test]
fn snapshot_admission_keeps_the_inline_node_byte_charge() {
    use fireemu_core_database::{Content, Priority};
    struct InlineNode {
        _content: Content,
        _priority: Option<Priority>,
    }
    let node = size_of::<InlineNode>() as u64;
    #[cfg(target_pointer_width = "64")]
    assert_eq!(
        node, 56,
        "the historical snapshot charge is a policy boundary"
    );
    let options = RestOptions::default();
    let prepared = prepare_import(
        "demo-footprint",
        r#"{"ab":{".value":1,".priority":"pp"}}"#.to_owned(),
        &options.limits,
    )
    .unwrap();
    let old_tree_charge = 2 * node + size_of::<String>() as u64 + 2 + 2;
    assert_eq!(prepared.retained_bytes(), old_tree_charge);
    let mut database = Database::new(options, 0);
    database.install_import(prepared, 0).unwrap();
    let snapshot = database.capture_namespaces_where(|_| true);
    // Imported names appear in both the tree and imported-namespace sets.
    let old_snapshot_charge = old_tree_charge + 2 * "demo-footprint".len() as u64;
    assert_eq!(snapshot.retained_bytes(), old_snapshot_charge);
    // SNAP-MEM-01 admits equality and refuses one byte over the session byte budget.
    // Keep the HTTP policy unchanged; pin its input and both adjacent boundaries here.
    let budget = 1u64 << 30;
    let existing = budget - old_snapshot_charge;
    assert_eq!(existing + snapshot.retained_bytes(), budget);
    assert!(existing + 1 + snapshot.retained_bytes() > budget);
}

const PRIORITY_CASES: [(&str, &str, &str, &str); 21] = [
    ("leaf", "none", "int", "replace"),
    ("leaf", "int", "double", "priority"),
    ("dense", "string", "negzero", "replace"),
    ("sparse", "double", "int", "delete"),
    ("small", "int", "int", "delete"),
    ("leaf", "double", "negzero", "unchanged"),
    ("wide", "none", "int", "replace"),
    ("sparse", "none", "negzero", "priority"),
    ("dense", "none", "double", "delete"),
    ("small", "none", "double", "unchanged"),
    ("small", "string", "negzero", "priority"),
    ("sparse", "string", "int", "unchanged"),
    ("leaf", "string", "double", "delete"),
    ("sparse", "double", "double", "replace"),
    ("wide", "string", "negzero", "delete"),
    ("wide", "double", "double", "priority"),
    ("sparse", "int", "negzero", "replace"),
    ("dense", "int", "int", "unchanged"),
    ("dense", "double", "int", "priority"),
    ("wide", "int", "int", "unchanged"),
    ("small", "double", "double", "replace"),
];

#[test]
fn generated_priority_representation_cases() {
    use fireemu_adapter_database::json_text::{output_json, parse, render, Style};
    use fireemu_core_database::{Content, Format, Json, Limits, Path, ServerValueContext, Tree};

    let context = ServerValueContext { now_millis: 0 };
    for (shape, priority, number, operation) in PRIORITY_CASES {
        let leaf = match number {
            "double" => "1.0",
            "negzero" => "-0.0",
            _ => "1",
        };
        let p = match priority {
            "int" => "2",
            "double" => "2.5",
            "string" => "\"rank\"",
            _ => "null",
        };
        let keys: Vec<String> = match shape {
            "leaf" => vec![],
            "dense" => vec!["0".into(), "1".into()],
            "sparse" => vec!["0".into(), "3".into()],
            "wide" => (0..128).map(|i| format!("k{i:03}")).collect(),
            _ => vec!["a".into(), "b".into()],
        };
        let input = if keys.is_empty() {
            format!("{{\".value\":{leaf},\".priority\":{p}}}")
        } else {
            let fields = keys
                .iter()
                .map(|key| format!("\"{key}\":{leaf}"))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{fields},\".priority\":{p}}}")
        };
        let value = parse(&input).unwrap();
        let mut tree = Tree::default();
        tree.set(&Path::root(), &value, context).unwrap();
        let export =
            |tree: &Tree, format| render(&output_json(tree.root(), format), Style::Compact);
        let before = export(&tree, Format::Export);
        let before_plain = export(&tree, Format::Plain);
        let snapshot = tree.clone();
        match operation {
            "replace" => {
                tree.set(&Path::root(), &Json::Bool(true), context).unwrap();
                assert_eq!(export(&tree, Format::Export), "true");
            }
            "delete" => {
                if keys.is_empty() {
                    tree.set(&Path::root(), &Json::Null, context).unwrap();
                } else {
                    for key in &keys {
                        tree.set(
                            &Path::parse(key, &Limits::default()).unwrap(),
                            &Json::Null,
                            context,
                        )
                        .unwrap();
                    }
                }
                assert!(tree.root().is_none());
                assert_eq!(export(&tree, Format::Export), "null");
            }
            "priority" => {
                let path = Path::parse("/.priority", &Limits::default()).unwrap();
                tree.set(&path, &Json::int(4), context).unwrap();
                assert!(tree.get_json(&path, Format::Plain).same_form(&Json::int(4)));
                assert!(
                    fireemu_adapter_database::json_text::written_priority_at(&tree, &path)
                        .same_form(&Json::int(4))
                );
                assert_eq!(export(&tree, Format::Plain), before_plain);
            }
            _ => {
                tree.set(&Path::root(), &value, context).unwrap();
                assert_eq!(export(&tree, Format::Export), before);
            }
        }
        assert_eq!(export(&snapshot, Format::Export), before);
        if let Some(root) = tree.root() {
            assert!(!matches!(&root.content, Content::Children(children) if children.is_empty()));
        }
    }
}
