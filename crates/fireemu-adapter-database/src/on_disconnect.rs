//! The writes a realtime connection registers for its end (`o`, `om`, `oc`).
//!
//! They are kept the way the SDK keeps them (`SparseSnapshotTree`), which is also what the
//! official emulator (firebase-database-emulator v4.11.2) does with them: a write at a path
//! replaces what was registered at and below it, a write below a registered value changes that
//! value, and cancelling below a registered value splits it into its children first when it holds
//! the first key of the cancelled path (below a leaf, or at a path it does not hold, it changes
//! nothing). When the connection ends, every registered value becomes one
//! entry of a single update at the root, so the update is applied whole or not at all. Values
//! keep their server-value placeholders until then. The entries come out in the order of the
//! official emulator's maps (see [`crate::scala_map`]): a node's children in the order they
//! were registered up to four of them, by key hash from the fifth on.

use std::collections::BTreeMap;

use fireemu_core_database::Json;

/// Registered writes, as a tree of paths.
#[derive(Debug, Default)]
pub(crate) struct Pending {
    /// The value registered at this path, which covers everything below it.
    value: Option<Json>,
    /// The paths below, when no value covers them.
    children: Children,
}

/// The children of a node, in registration order, with what decides how they are listed.
#[derive(Debug, Default)]
struct Children {
    items: Vec<(String, Pending)>,
    /// Whether the map held five children at some time: it then stays a hash map.
    hashed: bool,
}

impl Children {
    fn get_mut(&mut self, key: &str) -> Option<&mut Pending> {
        self.items
            .iter_mut()
            .find(|(name, _)| name == key)
            .map(|(_, child)| child)
    }

    /// The child `key`, added after the others when it is new.
    fn child(&mut self, key: &str) -> &mut Pending {
        let at = if let Some(at) = self.items.iter().position(|(name, _)| name == key) {
            at
        } else {
            self.items.push((key.to_owned(), Pending::default()));
            self.hashed |= self.items.len() >= 5;
            self.items.len() - 1
        };
        &mut self.items[at].1
    }

    fn remove(&mut self, key: &str) {
        self.items.retain(|(name, _)| name != key);
        // A map emptied by cancels is a new map again (probed on the jar).
        if self.items.is_empty() {
            self.hashed = false;
        }
    }

    fn clear(&mut self) {
        self.items.clear();
        self.hashed = false;
    }

    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The children in the order the official emulator lists them.
    fn in_order(&self) -> impl Iterator<Item = &(String, Pending)> {
        let names: Vec<&str> = self.items.iter().map(|(name, _)| name.as_str()).collect();
        crate::scala_map::scala_order(&names, self.hashed)
            .into_iter()
            .map(|at| &self.items[at])
    }
}

impl Pending {
    /// Registers `data` for the path `keys`. Null children of `data` are dropped, as the official
    /// emulator does when it stores the value.
    pub(crate) fn remember(&mut self, keys: &[String], data: Json) {
        self.place(keys, without_nulls(data));
    }

    fn place(&mut self, keys: &[String], data: Json) {
        if keys.is_empty() {
            self.value = Some(data);
            self.children.clear();
        } else if let Some(value) = self.value.take() {
            self.value = Some(update_child(value, keys, data));
        } else {
            self.children.child(&keys[0]).place(&keys[1..], data);
        }
    }

    /// Cancels what is registered at and below `keys`; `true` when nothing is left here.
    pub(crate) fn forget(&mut self, keys: &[String]) -> bool {
        if keys.is_empty() {
            self.value = None;
            self.children.clear();
            return true;
        }
        if let Some(value) = self.value.take() {
            // A leaf, and a value that holds nothing at the first key, stay as registered (probed on the
            // official emulator, which splits only when that key exists).
            if !holds(&value, &keys[0]) {
                self.value = Some(value);
                return false;
            }
            // The children that remain go in, in key order (integers first, by number). The child the
            // cancel runs through goes in only when something of it remains, so a branch the cancel
            // empties never counts towards five.
            let mut children = children_of(value);
            children.sort_by(|a, b| fireemu_core_database::key::name_compare(&a.0, &b.0));
            for (key, child) in children {
                if key == keys[0] && vanishes(&child, &keys[1..]) {
                    continue;
                }
                self.place(&[key], child);
            }
            return self.forget(keys);
        }
        if let Some(child) = self.children.get_mut(&keys[0]) {
            if child.forget(&keys[1..]) {
                self.children.remove(&keys[0]);
            }
        }
        self.children.is_empty()
    }

    /// Every registered value with its path, in the order the entries fire.
    pub(crate) fn entries(&self) -> Vec<(Vec<String>, Json)> {
        let mut entries = Vec::new();
        self.collect(&mut Vec::new(), &mut entries);
        entries
    }

    fn collect(&self, prefix: &mut Vec<String>, entries: &mut Vec<(Vec<String>, Json)>) {
        if let Some(value) = &self.value {
            entries.push((prefix.clone(), value.clone()));
            return;
        }
        for (key, child) in self.children.in_order() {
            prefix.push(key.clone());
            child.collect(prefix, entries);
            prefix.pop();
        }
    }
}

const PRIORITY: &str = ".priority";
const VALUE: &str = ".value";

/// Whether `value` is a leaf: not an object, or an object carrying `.value`.
fn is_leaf(value: &Json) -> bool {
    match value {
        Json::Object(map) => map.contains_key(VALUE),
        Json::Null => false,
        _ => true,
    }
}

/// `value` without its null children, at any depth: an object left without children is null.
fn without_nulls(value: Json) -> Json {
    match value {
        Json::Object(map) => {
            let map: BTreeMap<String, Json> = map
                .into_iter()
                .map(|(key, child)| (key, without_nulls(child)))
                .filter(|(_, child)| *child != Json::Null)
                .collect();
            if map.is_empty() {
                Json::Null
            } else {
                Json::Object(map)
            }
        }
        other => other,
    }
}

/// Whether `value` is split by a cancel whose path starts at `key`: it is not a leaf and holds
/// that child, or holds a priority when `key` names it.
fn holds(value: &Json, key: &str) -> bool {
    match value {
        Json::Object(map) if !is_leaf(value) => map.contains_key(key),
        _ => false,
    }
}

/// Whether cancelling `keys` below `value` leaves nothing of it.
fn vanishes(value: &Json, keys: &[String]) -> bool {
    let Some((key, rest)) = keys.split_first() else {
        return true;
    };
    if !holds(value, key) {
        return false;
    }
    match value {
        Json::Object(map) => {
            let mut children = map.iter().filter(|(name, _)| *name != PRIORITY);
            match (children.next(), children.next()) {
                (Some((name, child)), None) => name == key && vanishes(child, rest),
                _ => false,
            }
        }
        _ => false,
    }
}

/// The children of a value that is not a leaf, without its priority.
fn children_of(value: Json) -> Vec<(String, Json)> {
    match value {
        Json::Object(map) => map.into_iter().filter(|(key, _)| key != PRIORITY).collect(),
        _ => Vec::new(),
    }
}

/// `value` with the location `keys` below it replaced by `data`, as the SDK's
/// `Node.updateChild` does: a leaf becomes a parent and keeps its priority, null removes a
/// child, and a parent left without children is null.
fn update_child(value: Json, keys: &[String], data: Json) -> Json {
    let Some((key, rest)) = keys.split_first() else {
        return data;
    };
    // Removing something below a leaf leaves the leaf.
    if data == Json::Null && key != PRIORITY && is_leaf(&value) {
        return value;
    }
    let mut map = match value {
        // A prioritized leaf: a priority replaces or removes its priority only.
        Json::Object(mut map) if map.contains_key(VALUE) && key == PRIORITY && rest.is_empty() => {
            if data == Json::Null {
                return map.remove(VALUE).unwrap_or(Json::Null);
            }
            map.insert(PRIORITY.to_owned(), data);
            return Json::Object(map);
        }
        Json::Object(map) if map.contains_key(VALUE) => {
            map.into_iter().filter(|(key, _)| key == PRIORITY).collect()
        }
        Json::Object(map) => map,
        Json::Null => BTreeMap::new(),
        leaf => {
            if key == PRIORITY && rest.is_empty() {
                let mut map = BTreeMap::from([(VALUE.to_owned(), leaf)]);
                if data != Json::Null {
                    map.insert(PRIORITY.to_owned(), data);
                }
                return Json::Object(map);
            }
            BTreeMap::new()
        }
    };
    let child = map.remove(key).unwrap_or(Json::Null);
    let child = update_child(child, rest, data);
    if child != Json::Null {
        map.insert(key.clone(), child);
    }
    if map.keys().all(|key| key == PRIORITY) {
        return Json::Null;
    }
    Json::Object(map)
}

#[cfg(test)]
mod tests {
    use super::{update_child, Pending};
    use fireemu_core_database::{Json, Limits, Path, ServerValueContext, Tree};
    use proptest::prelude::*;

    fn keys(path: &str) -> Vec<String> {
        path.split('/')
            .filter(|k| !k.is_empty())
            .map(str::to_owned)
            .collect()
    }

    fn json(text: &str) -> Json {
        crate::json_text::parse(text).unwrap()
    }

    fn entries(pending: &Pending) -> Vec<(String, String)> {
        pending
            .entries()
            .into_iter()
            .map(|(k, v)| {
                (
                    k.join("/"),
                    crate::json_text::render(&v, crate::json_text::Style::Compact),
                )
            })
            .collect()
    }

    #[test]
    fn a_child_update_follows_node_rules() {
        assert_eq!(
            update_child(json("5"), &keys("c"), json("3")),
            json(r#"{"c":3}"#)
        );
        assert_eq!(
            update_child(json(r#"{".value":5,".priority":2}"#), &keys("c"), json("3")),
            json(r#"{".priority":2,"c":3}"#)
        );
        assert_eq!(
            update_child(json("5"), &keys(".priority"), json("2")),
            json(r#"{".value":5,".priority":2}"#)
        );
        assert_eq!(
            update_child(json(r#"{"a":1}"#), &keys("a"), Json::Null),
            Json::Null
        );
        assert_eq!(
            update_child(json(r#"{"a":1,".priority":4}"#), &keys("a"), Json::Null),
            Json::Null
        );
        assert_eq!(
            update_child(json(r#"{"a":{"b":1}}"#), &keys("a/c"), json("2")),
            json(r#"{"a":{"b":1,"c":2}}"#)
        );
        assert_eq!(
            update_child(Json::Null, &keys("a/b"), json("1")),
            json(r#"{"a":{"b":1}}"#)
        );
        assert_eq!(update_child(json("1"), &[], json("2")), json("2"));
        assert_eq!(update_child(json("1"), &keys("a/b"), Json::Null), json("1"));
        // A priority for a prioritized leaf replaces or removes its priority only.
        assert_eq!(
            update_child(
                json(r#"{".value":5,".priority":2}"#),
                &keys(".priority"),
                json("3")
            ),
            json(r#"{".value":5,".priority":3}"#)
        );
        assert_eq!(
            update_child(
                json(r#"{".value":5,".priority":2}"#),
                &keys(".priority"),
                Json::Null
            ),
            json("5")
        );
        assert_eq!(
            update_child(
                json(r#"{".value":1,".priority":2}"#),
                &keys("a"),
                Json::Null
            ),
            json(r#"{".value":1,".priority":2}"#)
        );
    }

    #[test]
    fn forgetting_splits_values_and_prunes_empty_branches() {
        let mut pending = Pending::default();
        pending.remember(&keys("x/y"), json("1"));
        assert!(pending.forget(&keys("x/y")));
        assert!(pending.entries().is_empty());
        pending.remember(&keys("a"), json(r#"{"b":1,"c":2,".priority":3}"#));
        assert!(!pending.forget(&keys("a/b")));
        assert_eq!(entries(&pending), vec![("a/c".to_owned(), "2".to_owned())]);
        // Forgetting what was never registered keeps the rest.
        assert!(!pending.forget(&keys("q/r")));
        assert_eq!(entries(&pending), vec![("a/c".to_owned(), "2".to_owned())]);
        pending.remember(&keys("l"), json("5"));
        pending.forget(&keys("l/x"));
        assert_eq!(entries(&pending).len(), 2);
        assert!(pending.forget(&[]));
        assert!(pending.entries().is_empty());
    }

    /// The value as the official emulator stores it: null children dropped at any depth, an object
    /// left empty is null.
    fn stored(value: &Json) -> Json {
        let Json::Object(map) = value else {
            return value.clone();
        };
        let kept: std::collections::BTreeMap<String, Json> = map
            .iter()
            .map(|(key, child)| (key.clone(), stored(child)))
            .filter(|(_, child)| *child != Json::Null)
            .collect();
        if kept.is_empty() {
            Json::Null
        } else {
            Json::Object(kept)
        }
    }

    /// The value with the location `keys` removed and the parents it leaves empty pruned; unchanged when the
    /// value holds nothing at the path or a leaf is in the way.
    fn without(value: &Json, keys: &[&str]) -> Json {
        let (Some((key, rest)), Json::Object(map)) = (keys.split_first(), value) else {
            return if keys.is_empty() {
                Json::Null
            } else {
                value.clone()
            };
        };
        let Some(child) = map.get(*key) else {
            return value.clone();
        };
        let mut map = map.clone();
        match without(child, rest) {
            Json::Null => {
                map.remove(*key);
            }
            kept => {
                map.insert((*key).to_owned(), kept);
            }
        }
        if map.is_empty() {
            Json::Null
        } else {
            Json::Object(map)
        }
    }

    fn set_at(root: &mut Json, path: &[String], value: Json) {
        let Some((key, rest)) = path.split_first() else {
            *root = value;
            return;
        };
        if !matches!(root, Json::Object(_)) {
            *root = Json::Object(std::collections::BTreeMap::new());
        }
        if let Json::Object(map) = root {
            set_at(map.entry(key.clone()).or_insert(Json::Null), rest, value);
        }
    }

    fn nested_value() -> impl Strategy<Value = Json> {
        let leaf = prop_oneof![3 => (0i64..3).prop_map(Json::int), 1 => Just(Json::Null)];
        leaf.prop_recursive(3, 24, 6, |inner| {
            prop::collection::btree_map(
                prop::sample::select(vec!["a", "b", "c", "9", "10", "-1"]).prop_map(str::to_owned),
                inner,
                1..7,
            )
            .prop_map(Json::Object)
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// A cancel below a registered value (split, leave whole, or empty a branch) leaves the
        /// entries that rebuild exactly the value without the cancelled location.
        #[test]
        fn a_cancel_below_a_value_leaves_the_rest_of_it(
            value in nested_value(),
            cancel in prop::collection::vec(
                prop::sample::select(vec!["a", "b", "c", "9", "10", "-1", "zz"]),
                1..4,
            ),
        ) {
            let mut pending = Pending::default();
            pending.remember(&["s".to_owned()], value.clone());
            let path: Vec<String> = std::iter::once("s")
                .chain(cancel.iter().copied())
                .map(str::to_owned)
                .collect();
            pending.forget(&path);
            let mut rebuilt = Json::Null;
            for (at, entry) in pending.entries() {
                set_at(&mut rebuilt, &at, entry);
            }
            // A value that is null once stored stays a null entry; a cancel that removes the
            // last of a value leaves no entry.
            let stored_value = stored(&value);
            let want = match without(&stored_value, &cancel) {
                Json::Null if stored_value != Json::Null => Json::Null,
                kept => Json::object([("s", kept)]),
            };
            prop_assert_eq!(rebuilt, want);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Registered writes, applied as one update, leave what the same writes applied one
        /// by one would leave.
        #[test]
        fn one_update_equals_the_writes_in_order(
            groups in prop::collection::vec(
                (
                    prop::collection::vec(prop::sample::select(vec!["a", "b", "c"]), 0..4),
                    prop_oneof![
                        (0i64..3).prop_map(Json::int),
                        Just(Json::Null),
                        (0i64..3).prop_map(|n| Json::object([("a", Json::int(n))])),
                        (0i64..3).prop_map(|n| Json::object([("b", Json::object([("c", Json::int(n))]))])),
                        (0i64..3, 0i64..3).prop_map(|(n, p)| {
                            Json::object([(".value", Json::int(n)), (".priority", Json::int(p))])
                        }),
                    ],
                    // A priority written right after the value at the same path, so the node
                    // is there for it in both orders.
                    prop::option::of(prop_oneof![(0i64..3).prop_map(Json::int), Just(Json::Null)]),
                ),
                0..8,
            ),
        ) {
            let mut writes: Vec<(Vec<&str>, Json)> = Vec::new();
            for (keys, value, priority) in groups {
                let priority = priority.filter(|_| !keys.is_empty() && value != Json::Null);
                writes.push((keys.clone(), value));
                if let Some(priority) = priority {
                    let mut at = keys;
                    at.push(".priority");
                    writes.push((at, priority));
                }
            }
            let context = ServerValueContext { now_millis: 0 };
            let mut pending = Pending::default();
            let mut one_by_one = Tree::new(Limits::default());
            for (keys, value) in &writes {
                let keys: Vec<String> = keys.iter().map(|k| (*k).to_owned()).collect();
                pending.remember(&keys, value.clone());
                one_by_one
                    .set(&Path::from_keys(keys.iter().cloned()), value, context)
                    .unwrap();
            }
            let mut at_once = Tree::new(Limits::default());
            let entries = pending.entries();
            match entries.as_slice() {
                [(keys, value)] if keys.is_empty() => {
                    at_once.set(&Path::root(), value, context).unwrap();
                }
                _ => {
                    let wire: Vec<(String, Json)> = entries
                        .into_iter()
                        .map(|(keys, value)| (keys.join("/"), value))
                        .collect();
                    at_once.update(&Path::root(), &wire, context).unwrap();
                }
            }
            prop_assert_eq!(at_once.root(), one_by_one.root());
        }
    }

    #[test]
    fn a_null_value_is_an_entry_and_a_cancel_below_it_changes_nothing() {
        // Probed on the official emulator: `o /s null`, `oc /s/a` still fires `s: null`.
        let mut pending = Pending::default();
        pending.remember(&keys("a"), Json::Null);
        assert_eq!(entries(&pending), vec![("a".to_owned(), "null".to_owned())]);
        assert!(!pending.forget(&keys("a/b")));
        assert_eq!(entries(&pending), vec![("a".to_owned(), "null".to_owned())]);
        assert!(pending.forget(&keys("a")));
        assert!(pending.entries().is_empty());
    }

    #[test]
    fn a_cancel_of_a_path_the_value_does_not_hold_leaves_it_whole() {
        // Probed on the official emulator (order review S4): it splits only when the first key exists.
        for cancel in ["s/zz", "s/zz/x", "s/.priority"] {
            let mut pending = Pending::default();
            pending.remember(&keys("s"), json(r#"{"a":1,"b":2}"#));
            assert!(!pending.forget(&keys(cancel)), "{cancel}");
            assert_eq!(
                entries(&pending),
                vec![("s".to_owned(), r#"{"a":1,"b":2}"#.to_owned())],
                "{cancel}"
            );
        }
        // An existing child is a split, and a cancel below it that holds nothing keeps that child whole.
        let mut pending = Pending::default();
        pending.remember(&keys("s"), json(r#"{"a":{"x":1,"y":2},"b":2}"#));
        assert!(!pending.forget(&keys("s/a/z")));
        assert_eq!(
            entries(&pending),
            vec![
                ("s/a".to_owned(), r#"{"x":1,"y":2}"#.to_owned()),
                ("s/b".to_owned(), "2".to_owned()),
            ]
        );
    }

    #[test]
    fn null_children_are_dropped_when_a_value_is_registered() {
        // Order review S6, probed on the official emulator: `o /s {a: null, b: 1}`, `oc /s/a` fires `s: {b: 1}`.
        let mut pending = Pending::default();
        pending.remember(&keys("s"), json(r#"{"a":null,"b":1}"#));
        assert!(!pending.forget(&keys("s/a")));
        assert_eq!(
            entries(&pending),
            vec![("s".to_owned(), r#"{"b":1}"#.to_owned())]
        );
        // A child that holds only nulls is gone too, and an object of nulls is a null entry.
        pending.remember(&keys("t"), json(r#"{"a":{"x":null},"b":null}"#));
        pending.remember(&keys("u/v"), json(r#"{"x":null,"y":2}"#));
        assert_eq!(
            entries(&pending),
            vec![
                ("s".to_owned(), r#"{"b":1}"#.to_owned()),
                ("t".to_owned(), "null".to_owned()),
                ("u/v".to_owned(), r#"{"y":2}"#.to_owned()),
            ]
        );
    }

    #[test]
    fn nulls_do_not_count_towards_five() {
        let mut pending = Pending::default();
        pending.remember(
            &keys("s"),
            json(r#"{"a":{"x":null},"b":1,"c":1,"d":1,"e":1,"f":1}"#),
        );
        pending.forget(&keys("s/b"));
        assert_eq!(
            pending
                .entries()
                .into_iter()
                .map(|(k, _)| k.join("/"))
                .collect::<Vec<_>>(),
            ["s/c", "s/d", "s/e", "s/f"]
        );
    }

    #[test]
    fn a_leaf_with_a_priority_is_not_split_by_a_cancel_of_its_value() {
        let mut pending = Pending::default();
        pending.remember(&keys("s"), json(r#"{".value":1,".priority":2}"#));
        assert!(!pending.forget(&keys("s/.value")));
        assert_eq!(
            entries(&pending),
            vec![("s".to_owned(), r#"{".value":1,".priority":2}"#.to_owned())]
        );
    }

    #[test]
    fn cancelling_the_priority_of_a_child_keeps_the_child() {
        // Only the priority goes, so the child still counts towards five (recorded on the jar).
        let mut pending = Pending::default();
        pending.remember(
            &keys("s"),
            json(r#"{"e2":{".priority":1,"x":1},"e3":1,"e4":1,"e5":1,"e6":1}"#),
        );
        pending.forget(&keys("s/e2/.priority"));
        assert_eq!(
            pending
                .entries()
                .into_iter()
                .map(|(k, _)| k.join("/"))
                .collect::<Vec<_>>(),
            ["s/e6", "s/e5", "s/e4", "s/e3", "s/e2/x"]
        );
    }

    #[test]
    fn a_cancel_of_the_priority_splits_a_value_that_holds_one() {
        let mut pending = Pending::default();
        pending.remember(&keys("s"), json(r#"{".priority":1,"b":1,"c":2}"#));
        assert!(!pending.forget(&keys("s/.priority")));
        assert_eq!(
            entries(&pending),
            vec![
                ("s/b".to_owned(), "1".to_owned()),
                ("s/c".to_owned(), "2".to_owned()),
            ]
        );
    }

    #[test]
    fn a_branch_the_cancel_empties_is_not_counted_towards_five() {
        // Order review M3: the jar sends the four that remain in registration order.
        let mut pending = Pending::default();
        pending.remember(
            &keys("s"),
            json(r#"{"e2":{"x":1},"e3":1,"e4":1,"e5":1,"e6":1}"#),
        );
        assert!(!pending.forget(&keys("s/e2/x")));
        assert_eq!(
            pending
                .entries()
                .into_iter()
                .map(|(k, _)| k.join("/"))
                .collect::<Vec<_>>(),
            ["s/e3", "s/e4", "s/e5", "s/e6"]
        );
    }

    /// Replays registrations (`o` register, `c` cancel) and returns the paths in fire order.
    fn fired(ops: &[(String, String)]) -> Vec<String> {
        let mut pending = Pending::default();
        for (op, path) in ops {
            if op == "o" {
                pending.remember(&keys(path), json("1"));
            } else {
                pending.forget(&keys(path));
            }
        }
        pending
            .entries()
            .into_iter()
            .map(|(k, _)| k.join("/"))
            .collect()
    }

    #[test]
    fn the_fire_order_is_the_recorded_one_for_nested_registrations() {
        let fixture = crate::scala_map::tests::fixture();
        let cases = fixture["nested"].as_array().unwrap();
        assert!(cases.len() >= 40);
        for case in cases {
            let ops: Vec<(String, String)> = crate::scala_map::tests::strings(&case["registered"])
                .into_iter()
                .map(|path| ("o".to_owned(), path))
                .collect();
            assert_eq!(
                fired(&ops),
                crate::scala_map::tests::strings(&case["order"]),
                "{case}"
            );
        }
    }

    #[test]
    fn production_five_registered_e2_to_marker_fire_e6_e5_marker_e4_e3_e2() {
        let fixture = crate::scala_map::tests::fixture();
        let case = &fixture["production5"];
        let ops: Vec<(String, String)> = crate::scala_map::tests::strings(&case["registered"])
            .into_iter()
            .map(|path| ("o".to_owned(), path))
            .collect();
        assert_eq!(
            fired(&ops),
            crate::scala_map::tests::strings(&case["order"])
        );
    }

    #[test]
    fn registering_cancelling_and_registering_again_follow_the_recorded_probes() {
        let fixture = crate::scala_map::tests::fixture();
        let probes = fixture["probes"].as_array().unwrap();
        assert!(probes.len() >= 6);
        for probe in probes {
            let ops: Vec<(String, String)> = probe["ops"]
                .as_array()
                .unwrap()
                .iter()
                .map(|op| {
                    (
                        op[0].as_str().unwrap().to_owned(),
                        op[1].as_str().unwrap().to_owned(),
                    )
                })
                .collect();
            assert_eq!(
                fired(&ops),
                crate::scala_map::tests::strings(&probe["order"]),
                "{probe}"
            );
        }
    }

    #[test]
    fn a_split_by_a_cancel_inserts_only_the_children_that_remain_in_key_order() {
        // Raw frames on the jar, with the order review's rows (M2): the cancelled child is not inserted, the
        // others go in Firebase key order (integers first by number), and the map turns hashed only at five.
        let cases = crate::scala_map::tests::cases();
        let splits = cases["splits"].as_array().unwrap();
        assert!(splits.len() >= 8);
        // The S4 and S6 cases hear the whole value on a listen above its children; the integration
        // test in tests/multi_path_order.rs replays them.
        for case in splits.iter().filter(|case| {
            let name = case["name"].as_str().unwrap();
            !name.starts_with("S4:") && !name.starts_with("S6:")
        }) {
            let mut pending = Pending::default();
            for op in case["ops"].as_array().unwrap() {
                let (action, path) = (op[0].as_str().unwrap(), op[1].as_str().unwrap());
                if action == "o" {
                    pending.remember(&keys(path), json(&op[2].to_string()));
                } else {
                    pending.forget(&keys(path));
                }
            }
            let fired: Vec<String> = pending
                .entries()
                .into_iter()
                .map(|(k, _)| k.join("/"))
                .collect();
            let want: Vec<String> = crate::scala_map::tests::strings(&case["order"])
                .into_iter()
                .map(|frame| match frame.strip_prefix("m:") {
                    // `m:s/e2{y}`: the entry below the listen's path.
                    Some(merge) => merge.replace('{', "/").replace('}', ""),
                    None => frame.trim_start_matches("d:").to_owned(),
                })
                .collect();
            assert_eq!(fired, want, "{case}");
        }
    }
}
