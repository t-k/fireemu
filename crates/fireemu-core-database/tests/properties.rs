//! Property tests: the tree against a flat reference model, the export round trip, the key
//! order, and queries against an independent tuple-ordering reference.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::many_single_char_names
)]

mod support;

use std::cmp::Ordering;
use std::collections::BTreeMap;

use fireemu_core_database::key::{key_as_int, name_compare};
use fireemu_core_database::{
    Content, Format, Json, Leaf, Limits, Node, Number, OrderBy, Path, QueryParams, Tree,
};
use proptest::prelude::*;
use support::NOW;

// ---------------------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------------------

fn key() -> impl Strategy<Value = String> {
    // Leading zeros, `-0`, the 32-bit edges and non-BMP keys reach the tree and the
    // queries, so `name_compare` and the array rule are exercised inside them.
    prop::sample::select(vec![
        "a",
        "b",
        "c",
        "0",
        "1",
        "2",
        "10",
        "-1",
        "z9",
        "00",
        "01",
        "-0",
        "2147483647",
        "2147483648",
        "-2147483648",
        "\u{1F600}",
        "\u{FF61}",
    ])
    .prop_map(str::to_owned)
}

fn path() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(key(), 0..4)
}

fn leaf() -> impl Strategy<Value = Json> {
    prop_oneof![
        any::<bool>().prop_map(Json::Bool),
        (-3i64..4).prop_map(Json::int),
        // Halves keep doubles exact in the reference below.
        (-3i64..4).prop_map(|h| Json::Number(Number::from_f64(h as f64 + 0.5).unwrap())),
        prop::sample::select(vec!["", "a", "b", "ab", "\u{1F600}", "\u{FF61}"])
            .prop_map(Json::string),
    ]
}

fn value() -> impl Strategy<Value = Json> {
    let leafy = prop_oneof![1 => Just(Json::Null), 6 => leaf()];
    leafy.prop_recursive(3, 24, 4, |inner| {
        prop::collection::btree_map(key(), inner, 0..4).prop_map(Json::Object)
    })
}

fn priority() -> impl Strategy<Value = Option<Json>> {
    prop_oneof![
        2 => Just(None),
        1 => (-2i64..3).prop_map(|n| Some(Json::int(n))),
        1 => prop::sample::select(vec!["a", "b"]).prop_map(|s| Some(Json::string(s))),
    ]
}

/// A value whose objects and leaves may carry priorities (export format input).
fn prioritized_value() -> impl Strategy<Value = Json> {
    let leafy = (leaf(), priority()).prop_map(|(leaf, priority)| match priority {
        None => leaf,
        Some(p) => Json::object([(".value", leaf), (".priority", p)]),
    });
    leafy.prop_recursive(3, 24, 4, |inner| {
        (prop::collection::btree_map(key(), inner, 1..4), priority()).prop_map(|(map, p)| {
            let mut map = map;
            if let Some(p) = p {
                map.insert(".priority".to_owned(), p);
            }
            Json::Object(map)
        })
    })
}

#[derive(Debug, Clone)]
enum Op {
    Set(Vec<String>, Json),
    Update(Vec<String>, Vec<(Vec<String>, Json)>),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (path(), value()).prop_map(|(p, v)| Op::Set(p, v)),
        1 => (path(), prop::collection::vec((path(), value()), 0..4)).prop_map(|(base, entries)| {
            // Keep only entries that overlap none of the earlier ones.
            let mut kept: Vec<(Vec<String>, Json)> = Vec::new();
            for (rel, v) in entries {
                if kept.iter().all(|(k, _)| !k.starts_with(&rel) && !rel.starts_with(k)) {
                    kept.push((rel, v));
                }
            }
            Op::Update(base, kept)
        }),
    ]
}

// ---------------------------------------------------------------------------------------
// The flat reference model: leaf paths to leaf values, priorities ignored.
// ---------------------------------------------------------------------------------------

type Model = BTreeMap<Vec<String>, Json>;

fn flatten_json(json: &Json, at: &[String], out: &mut Model) {
    match json {
        Json::Null => {}
        Json::Object(map) => {
            for (k, v) in map {
                let mut child = at.to_vec();
                child.push(k.clone());
                flatten_json(v, &child, out);
            }
        }
        Json::Array(_) => unreachable!("the generators build no arrays"),
        leaf => {
            out.insert(at.to_vec(), leaf.clone());
        }
    }
}

fn model_set(model: &mut Model, at: &[String], json: &Json) {
    let mut written = Model::new();
    flatten_json(json, at, &mut written);
    model.retain(|p, _| !p.starts_with(at));
    if !written.is_empty() {
        // A leaf above the written location is replaced by the new children.
        model.retain(|p, _| !(p.len() < at.len() && at.starts_with(p)));
    }
    model.extend(written);
}

fn flatten_tree(tree: &Tree) -> Model {
    let mut out = Model::new();
    if let Some(root) = tree.root() {
        // The model holds no priorities, so the export is the stored tree without arrays.
        flatten_json(&root.to_json(Format::Export), &[], &mut out);
    }
    out
}

fn assert_no_empty_maps(node: &Node) {
    if let Content::Children(children) = &node.content {
        assert!(!children.is_empty(), "an empty map was stored");
        children.values().for_each(assert_no_empty_maps);
    }
}

fn join(keys: &[String]) -> String {
    keys.join("/")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn writes_match_the_flat_reference_model(ops in prop::collection::vec(op(), 1..12)) {
        let mut tree = Tree::new(Limits::default());
        let mut model = Model::new();
        for op in ops {
            match op {
                Op::Set(at, v) => {
                    tree.set(&Path::from_keys(at.clone()), &v, NOW).unwrap();
                    model_set(&mut model, &at, &v);
                }
                Op::Update(base, entries) => {
                    let wire: Vec<(String, Json)> =
                        entries.iter().map(|(rel, v)| (join(rel), v.clone())).collect();
                    tree.update(&Path::from_keys(base.clone()), &wire, NOW).unwrap();
                    for (rel, v) in &entries {
                        let mut at = base.clone();
                        at.extend(rel.iter().cloned());
                        model_set(&mut model, &at, v);
                    }
                }
            }
            prop_assert_eq!(&flatten_tree(&tree), &model);
            if let Some(root) = tree.root() {
                assert_no_empty_maps(root);
            }
        }
    }

    #[test]
    fn export_reads_back_to_the_same_tree(v in prioritized_value()) {
        let mut tree = Tree::new(Limits::default());
        tree.set(&Path::root(), &v, NOW).unwrap();
        let exported = tree.get_json(&Path::root(), Format::Export);
        let mut copy = Tree::new(Limits::default());
        copy.set(&Path::root(), &exported, NOW).unwrap();
        prop_assert_eq!(&copy, &tree);
        // Exporting again is a fixed point.
        prop_assert_eq!(copy.get_json(&Path::root(), Format::Export), exported);
    }

    #[test]
    fn plain_reads_are_the_sdk_val_of_the_export(v in prioritized_value()) {
        let mut tree = Tree::new(Limits::default());
        tree.set(&Path::root(), &v, NOW).unwrap();
        let plain = tree.get_json(&Path::root(), Format::Plain);
        prop_assert_eq!(&plain, &sdk_val(&tree.get_json(&Path::root(), Format::Export)));
        // Writing a plain read back stores the same values without priorities.
        let mut stripped = Tree::new(Limits::default());
        stripped.set(&Path::root(), &plain, NOW).unwrap();
        prop_assert_eq!(stripped.get_json(&Path::root(), Format::Plain), plain);
        let exported = stripped.get_json(&Path::root(), Format::Export);
        let text = format!("{exported:?}");
        prop_assert!(!text.contains(".priority"), "{}", text);
    }
}

/// `val()` of `@firebase/database` applied to an export: priorities and `.value` wrappers
/// dropped, and an object whose keys all match `0|[1-9][0-9]*` with the largest below
/// twice the count read as an array.
fn sdk_val(export: &Json) -> Json {
    match export {
        Json::Object(map) => {
            if let Some(value) = map.get(".value") {
                return sdk_val(value);
            }
            let children: BTreeMap<&String, Json> = map
                .iter()
                .filter(|(k, _)| k.as_str() != ".priority")
                .map(|(k, v)| (k, sdk_val(v)))
                .collect();
            let indexes: Option<Vec<usize>> = children
                .keys()
                .map(|k| {
                    let canonical = k.as_str() == "0"
                        || (!k.starts_with('0') && k.chars().all(|c| c.is_ascii_digit()));
                    if canonical {
                        k.parse().ok()
                    } else {
                        None
                    }
                })
                .collect();
            match indexes {
                Some(indexes)
                    if indexes
                        .iter()
                        .max()
                        .is_some_and(|max| *max < 2 * indexes.len()) =>
                {
                    let mut items = vec![Json::Null; indexes.iter().max().unwrap() + 1];
                    for (index, value) in indexes.into_iter().zip(children.into_values()) {
                        items[index] = value;
                    }
                    Json::Array(items)
                }
                _ => Json::Object(children.into_iter().map(|(k, v)| (k.clone(), v)).collect()),
            }
        }
        other => other.clone(),
    }
}

// ---------------------------------------------------------------------------------------
// Key order
// ---------------------------------------------------------------------------------------

fn any_key() -> impl Strategy<Value = String> {
    prop_oneof![
        (-50i64..50).prop_map(|n| n.to_string()),
        (0usize..3, 0u32..20).prop_map(|(z, n)| format!("{}{n}", "0".repeat(z))),
        Just("-0".to_owned()),
        Just("2147483647".to_owned()),
        Just("2147483648".to_owned()),
        Just("-2147483648".to_owned()),
        Just("-2147483649".to_owned()),
        "[a-c\u{FF61}\u{1F600}-]{1,3}",
    ]
}

/// The 32-bit integer the SDK reads from a key (`tryParseInt`), transliterated.
fn sdk_int(s: &str) -> Option<i64> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    let ok = !digits.is_empty()
        && digits.bytes().all(|c| c.is_ascii_digit())
        && digits.trim_start_matches('0').len() <= 10;
    let v: i128 = if ok { s.parse().ok()? } else { return None };
    (i128::from(i32::MIN)..=i128::from(i32::MAX))
        .contains(&v)
        .then_some(v as i64)
}

/// `nameCompare` of `@firebase/database`, transliterated: `None` where it answers 0 for
/// distinct keys.
fn sdk_name_compare(a: &str, b: &str) -> Option<Ordering> {
    if a == b {
        return Some(Ordering::Equal);
    }
    match (sdk_int(a), sdk_int(b)) {
        (Some(x), Some(y)) => {
            let d = if x == y {
                a.len() as i64 - b.len() as i64
            } else {
                x - y
            };
            (d != 0).then(|| d.cmp(&0))
        }
        (Some(_), None) => Some(Ordering::Less),
        (None, Some(_)) => Some(Ordering::Greater),
        (None, None) => Some(a.encode_utf16().cmp(b.encode_utf16())),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn name_compare_is_a_total_order_that_agrees_with_the_sdk(
        a in any_key(), b in any_key(), c in any_key()
    ) {
        let ab = name_compare(&a, &b);
        prop_assert_eq!(ab, name_compare(&b, &a).reverse());
        prop_assert_eq!(ab == Ordering::Equal, a == b);
        if ab != Ordering::Greater && name_compare(&b, &c) != Ordering::Greater {
            prop_assert_ne!(name_compare(&a, &c), Ordering::Greater);
        }
        if let Some(sdk) = sdk_name_compare(&a, &b) {
            prop_assert_eq!(ab, sdk);
        }
        prop_assert_eq!(key_as_int(&a).map(i64::from), sdk_int(&a));
    }
}

// ---------------------------------------------------------------------------------------
// Queries against a tuple-ordering reference
// ---------------------------------------------------------------------------------------

/// A totally ordered stand-in for an index value: (rank, number in halves, UTF-16 string).
type RefValue = (u8, i64, Vec<u16>);
/// A stand-in for a key: (class, integer, length, UTF-16 string); class 0 is the minimum
/// sentinel, 1 integer keys, 2 other keys, 3 the maximum sentinel.
type RefKey = (u8, i64, usize, Vec<u16>);

fn ref_value_of_leaf(leaf: &Leaf) -> RefValue {
    match leaf {
        Leaf::Bool(false) => (1, 0, vec![]),
        Leaf::Bool(true) => (2, 0, vec![]),
        // Every generated number is a multiple of one half.
        Leaf::Number(n) => (3, (n.as_f64() * 2.0) as i64, vec![]),
        Leaf::String(s) => (4, 0, s.encode_utf16().collect()),
    }
}

fn ref_value(node: Option<&Node>) -> RefValue {
    match node.map(|n| &n.content) {
        None => (0, 0, vec![]),
        Some(Content::Leaf(leaf)) => ref_value_of_leaf(leaf),
        Some(Content::Children(_)) => (5, 0, vec![]),
    }
}

fn ref_value_of_json(json: &Json) -> RefValue {
    match json {
        Json::Null => (0, 0, vec![]),
        Json::Bool(b) => ref_value_of_leaf(&Leaf::Bool(*b)),
        Json::Number(n) => ref_value_of_leaf(&Leaf::Number(*n)),
        Json::String(s) => ref_value_of_leaf(&Leaf::String(s.clone())),
        _ => unreachable!(),
    }
}

fn ref_key(key: &str) -> RefKey {
    match key_as_int(key) {
        Some(n) => (1, i64::from(n), key.len(), key.encode_utf16().collect()),
        None => (2, 0, 0, key.encode_utf16().collect()),
    }
}

fn ref_index(order: &OrderBy, key: &str, node: &Node) -> RefValue {
    match order {
        OrderBy::Priority => match &node.priority {
            None => (0, 0, vec![]),
            Some(p) => ref_value_of_leaf(&p.as_leaf()),
        },
        OrderBy::Value => ref_value(Some(node)),
        OrderBy::Child(path) => ref_value(node.descendant(path)),
        OrderBy::Key => (0, 0, key.encode_utf16().collect()),
    }
}

/// The reference position of a child: index value, key, and a tie tag (children sit at 1,
/// between the minimum (0) and maximum (2) sentinels of a key bound).
type RefPosition = (RefValue, RefKey, u8);

fn ref_position(order: &OrderBy, key: &str, node: &Node) -> RefPosition {
    match order {
        OrderBy::Key => ((0, 0, vec![]), ref_key(key), 1),
        _ => (ref_index(order, key, node), ref_key(key), 1),
    }
}

fn ref_bound(order: &OrderBy, bound: &fireemu_core_database::Bound) -> RefPosition {
    use fireemu_core_database::BoundKey;
    match (order, &bound.key) {
        (OrderBy::Key, key) => {
            let Json::String(name) = &bound.value else {
                unreachable!()
            };
            let tag = if *key == BoundKey::Min { 0 } else { 2 };
            ((0, 0, vec![]), ref_key(name), tag)
        }
        (_, BoundKey::Min) => (ref_value_of_json(&bound.value), (0, 0, 0, vec![]), 1),
        (_, BoundKey::Max) => (ref_value_of_json(&bound.value), (3, 0, 0, vec![]), 1),
        (_, BoundKey::Name(n)) => (ref_value_of_json(&bound.value), ref_key(n), 1),
    }
}

fn reference_query(query: &QueryParams, node: Option<&Node>) -> Vec<String> {
    let Some(Content::Children(children)) = node.map(|n| &n.content) else {
        return vec![];
    };
    let mut rows: Vec<(RefPosition, String)> = children
        .iter()
        .map(|(k, child)| (ref_position(&query.order_by, k, child), k.clone()))
        .collect();
    rows.sort();
    rows.retain(|(pos, _)| {
        let start_ok = query.start.as_ref().is_none_or(|b| {
            let bp = ref_bound(&query.order_by, b);
            *pos > bp || (*pos == bp && b.inclusive)
        });
        let end_ok = query.end.as_ref().is_none_or(|b| {
            let bp = ref_bound(&query.order_by, b);
            *pos < bp || (*pos == bp && b.inclusive)
        });
        start_ok && end_ok
    });
    let mut keys: Vec<String> = rows.into_iter().map(|(_, k)| k).collect();
    match query.limit {
        None => {}
        Some(fireemu_core_database::Limit::First(n)) => keys.truncate(n as usize),
        Some(fireemu_core_database::Limit::Last(n)) => {
            let skip = keys.len().saturating_sub(n as usize);
            keys.drain(..skip);
        }
    }
    keys
}

fn order() -> impl Strategy<Value = OrderBy> {
    prop_oneof![
        Just(OrderBy::Priority),
        Just(OrderBy::Key),
        Just(OrderBy::Value),
        Just(OrderBy::Child(Path::from_keys(["a"]))),
        Just(OrderBy::Child(Path::from_keys(["a", "b"]))),
    ]
}

fn bound_value(order: &OrderBy) -> BoxedStrategy<Json> {
    match order {
        OrderBy::Key => key().prop_map(Json::String).boxed(),
        OrderBy::Priority => prop_oneof![
            Just(Json::Null),
            (-2i64..3).prop_map(Json::int),
            prop::sample::select(vec!["a", "b"]).prop_map(Json::string),
        ]
        .boxed(),
        _ => prop_oneof![1 => Just(Json::Null), 4 => leaf()].boxed(),
    }
}

#[derive(Debug, Clone, Copy)]
enum BoundKind {
    StartAt,
    StartAfter,
    EndAt,
    EndBefore,
    EqualTo,
}

fn query() -> impl Strategy<Value = QueryParams> {
    order().prop_flat_map(|order| {
        let named = !matches!(order, OrderBy::Key);
        let bound = (
            prop::sample::select(vec![
                BoundKind::StartAt,
                BoundKind::StartAfter,
                BoundKind::EndAt,
                BoundKind::EndBefore,
                BoundKind::EqualTo,
            ]),
            bound_value(&order),
            if named {
                prop::option::of(key()).boxed()
            } else {
                Just(None).boxed()
            },
        );
        (
            Just(order),
            prop::collection::vec(bound, 0..3),
            prop::option::of((any::<bool>(), 0u32..5)),
        )
            .prop_map(|(order, bounds, limit)| {
                let mut q = QueryParams::ordered_by(order);
                for (kind, value, key) in bounds {
                    let key = key.as_deref();
                    q = match kind {
                        BoundKind::StartAt => q.start_at(value, key),
                        BoundKind::StartAfter => q.start_after(value, key),
                        BoundKind::EndAt => q.end_at(value, key),
                        BoundKind::EndBefore => q.end_before(value, key),
                        BoundKind::EqualTo => q.equal_to(value, key),
                    };
                }
                match limit {
                    None => q,
                    Some((true, n)) => q.limit_to_first(n),
                    Some((false, n)) => q.limit_to_last(n),
                }
            })
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn queries_match_the_tuple_reference(v in prioritized_value(), q in query()) {
        let mut tree = Tree::new(Limits::default());
        tree.set(&Path::root(), &v, NOW).unwrap();
        q.validate().unwrap();
        let got: Vec<String> = q.run(tree.root()).into_iter().map(|(k, _)| k.to_owned()).collect();
        prop_assert_eq!(got, reference_query(&q, tree.root()));
    }

    #[test]
    fn limits_take_a_prefix_or_suffix_of_the_unlimited_result(
        v in prioritized_value(), q in query(), n in 0u32..6
    ) {
        let mut tree = Tree::new(Limits::default());
        tree.set(&Path::root(), &v, NOW).unwrap();
        let mut unlimited = q.clone();
        unlimited.limit = None;
        let all: Vec<&str> = unlimited.run(tree.root()).into_iter().map(|(k, _)| k).collect();
        let first: Vec<&str> =
            unlimited.clone().limit_to_first(n).run(tree.root()).into_iter().map(|(k, _)| k).collect();
        let last: Vec<&str> =
            unlimited.limit_to_last(n).run(tree.root()).into_iter().map(|(k, _)| k).collect();
        let n = n as usize;
        prop_assert_eq!(&first[..], &all[..n.min(all.len())]);
        prop_assert_eq!(&last[..], &all[all.len().saturating_sub(n)..]);
    }
}

// ---------------------------------------------------------------------------------------
// Priorities and server values
// ---------------------------------------------------------------------------------------

fn small_key() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["a", "b", "0", "1"]).prop_map(str::to_owned)
}

/// One update entry: a value at a relative path, or a priority (possibly a placeholder) on
/// a relative path.
fn entry() -> impl Strategy<Value = (Vec<String>, bool, Json)> {
    let value = prop_oneof![
        3 => leaf(),
        1 => Just(Json::Null),
        1 => (-3i64..4).prop_map(|d| Json::object([(".sv", Json::object([("increment", Json::int(d))]))])),
    ];
    let priority = prop_oneof![
        Just(Json::Null),
        (-3i64..4).prop_map(Json::int),
        (-3i64..4)
            .prop_map(|d| Json::object([(".sv", Json::object([("increment", Json::int(d))]))])),
    ];
    prop_oneof![
        (prop::collection::vec(small_key(), 1..3), value).prop_map(|(p, v)| (p, false, v)),
        (prop::collection::vec(small_key(), 1..3), priority).prop_map(|(p, v)| (p, true, v)),
    ]
}

fn wire_path(keys: &[String], priority: bool) -> String {
    let mut path = keys.join("/");
    if priority {
        path.push_str("/.priority");
    }
    path
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    /// A multipath update equals its value writes one by one followed by its priority
    /// writes, with every placeholder resolved against the tree before the update, and it
    /// is refused as a whole when a priority names a node absent before the update.
    #[test]
    fn update_is_values_then_priorities(
        initial in prioritized_value(),
        entries in prop::collection::vec(entry(), 0..5),
    ) {
        let mut tree = Tree::new(Limits::default());
        tree.set(&Path::root(), &initial, NOW).unwrap();
        // Keep entries that overlap no earlier one, as the API demands.
        let mut kept: Vec<(Vec<String>, bool, Json)> = Vec::new();
        for (keys, priority, value) in entries {
            let mut full = keys.clone();
            if priority {
                full.push(".priority".to_owned());
            }
            let overlaps = kept.iter().any(|(k, p, _)| {
                let mut other = k.clone();
                if *p {
                    other.push(".priority".to_owned());
                }
                other.starts_with(&full) || full.starts_with(&other)
            });
            if !overlaps {
                kept.push((keys, priority, value));
            }
        }
        let before = tree.clone();
        let wire: Vec<(String, Json)> = kept
            .iter()
            .map(|(keys, priority, value)| (wire_path(keys, *priority), value.clone()))
            .collect();
        let result = tree.update(&Path::root(), &wire, NOW);

        let absent_priority_target = kept
            .iter()
            .any(|(keys, priority, _)| *priority && before.get(&Path::from_keys(keys.clone())).is_none());
        if absent_priority_target {
            prop_assert!(result.is_err());
            prop_assert_eq!(&tree, &before);
            return Ok(());
        }
        // Resolve every placeholder against the tree before the update, then apply.
        let mut expected = before.clone();
        let resolved: Vec<(Vec<String>, bool, Json)> = kept
            .iter()
            .map(|(keys, priority, value)| {
                let node = before.get(&Path::from_keys(keys.clone()));
                let base = if *priority {
                    fireemu_core_database::server_value::stored_priority(node)
                } else {
                    node.cloned()
                };
                let json = fireemu_core_database::server_value::resolve(value, base.as_ref(), NOW);
                (keys.clone(), *priority, json.unwrap_or(Json::Null))
            })
            .collect();
        let mut failed = false;
        for (keys, _, value) in resolved.iter().filter(|(_, p, _)| !*p) {
            failed |= expected.set(&Path::from_keys(keys.clone()), value, NOW).is_err();
        }
        for (keys, _, value) in resolved.iter().filter(|(_, p, _)| *p) {
            let path = Path::from_keys(keys.clone());
            if expected.get(&path).is_some() {
                failed |= expected.set(&path.child(".priority"), value, NOW).is_err();
            }
        }
        if failed {
            prop_assert!(result.is_err());
            prop_assert_eq!(&tree, &before);
        } else {
            prop_assert!(result.is_ok(), "{:?}", result);
            prop_assert_eq!(&tree, &expected);
        }
    }

    /// Increments add up: any sequence of increments on a number gives the start plus the
    /// sum, in integer arithmetic while it fits.
    #[test]
    fn increments_add_up(start in -1000i64..1000, deltas in prop::collection::vec(-50i64..50, 0..10)) {
        let mut tree = Tree::new(Limits::default());
        let at = Path::from_keys(["n"]);
        tree.set(&at, &Json::int(start), NOW).unwrap();
        for delta in &deltas {
            let inc = Json::object([(".sv", Json::object([("increment", Json::int(*delta))]))]);
            tree.set(&at, &inc, NOW).unwrap();
        }
        prop_assert_eq!(
            tree.get_json(&at, Format::Plain),
            Json::int(start + deltas.iter().sum::<i64>())
        );
    }
}

// ---------------------------------------------------------------------------------------
// Same form
// ---------------------------------------------------------------------------------------

/// `value` with every integer written as the double of the same value.
fn as_doubles(value: &Json) -> Json {
    match value {
        Json::Number(Number::Int(i)) => Json::Number(Number::from_f64(*i as f64).unwrap()),
        Json::Array(items) => Json::Array(items.iter().map(as_doubles).collect()),
        Json::Object(map) => Json::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), as_doubles(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn has_int(value: &Json) -> bool {
    match value {
        Json::Number(Number::Int(_)) => true,
        Json::Array(items) => items.iter().any(has_int),
        Json::Object(map) => map.values().any(has_int),
        _ => false,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn same_form_tells_apart_what_equality_does_not(v in value()) {
        prop_assert!(v.same_form(&v));
        let doubled = as_doubles(&v);
        // Equal in value either way; the same form only when there was no integer.
        prop_assert_eq!(&v, &doubled);
        prop_assert_eq!(v.same_form(&doubled), !has_int(&v));
        prop_assert_eq!(doubled.same_form(&v), !has_int(&v));
    }

    #[test]
    fn same_form_implies_equality(a in value(), b in value()) {
        if a.same_form(&b) {
            prop_assert_eq!(&a, &b);
        }
    }
}

#[test]
fn same_form_compares_numbers_by_kind_and_bits() {
    let double = |x: f64| Json::Number(Number::from_f64(x).unwrap());
    assert!(Json::int(1).same_form(&Json::int(1)));
    assert!(!Json::int(1).same_form(&double(1.0)));
    assert!(double(1.5).same_form(&double(1.5)));
    assert!(!double(0.0).same_form(&double(-0.0)));
    assert_eq!(double(0.0), double(-0.0));
    assert!(!Json::int(1).same_form(&Json::int(2)));
    assert!(!Json::Null.same_form(&Json::Bool(false)));
    assert!(!Json::Array(vec![Json::int(1)]).same_form(&Json::Array(vec![double(1.0)])));
    assert!(
        !Json::Array(vec![Json::int(1)]).same_form(&Json::Array(vec![Json::int(1), Json::int(2)]))
    );
    assert!(
        !Json::Array(vec![Json::int(1), Json::int(2)]).same_form(&Json::Array(vec![Json::int(1)]))
    );
    assert!(!Json::object([("a", Json::int(1))]).same_form(&Json::object([("b", Json::int(1))])));
    assert!(!Json::object([("a", Json::int(1))])
        .same_form(&Json::object([("a", Json::int(1)), ("b", Json::int(1))])));
    assert!(!Json::string("a").same_form(&Json::string("b")));
}
