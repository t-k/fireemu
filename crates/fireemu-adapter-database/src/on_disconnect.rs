//! The writes a realtime connection registers for its end (`o`, `om`, `oc`).
//!
//! They are kept the way the SDK keeps them (`SparseSnapshotTree`), which is also what the
//! official emulator (firebase-database-emulator v4.11.2) does with them: a write at a path
//! replaces what was registered at and below it, a write below a registered value changes that
//! value, and cancelling below a registered value splits it into its children first (below a
//! leaf it changes nothing). When the connection ends, every registered value becomes one
//! entry of a single update at the root, so the update is applied whole or not at all. Values
//! keep their server-value placeholders until then.

use std::collections::BTreeMap;

use fireemu_core_database::Json;

/// Registered writes, as a tree of paths.
#[derive(Debug, Default)]
pub(crate) struct Pending {
    /// The value registered at this path, which covers everything below it.
    value: Option<Json>,
    /// The paths below, when no value covers them.
    children: BTreeMap<String, Pending>,
}

impl Pending {
    /// Registers `data` for the path `keys`.
    pub(crate) fn remember(&mut self, keys: &[String], data: Json) {
        if keys.is_empty() {
            self.value = Some(data);
            self.children.clear();
        } else if let Some(value) = self.value.take() {
            self.value = Some(update_child(value, keys, data));
        } else {
            self.children
                .entry(keys[0].clone())
                .or_default()
                .remember(&keys[1..], data);
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
            if is_leaf(&value) {
                self.value = Some(value);
                return false;
            }
            for (key, child) in children_of(value) {
                self.remember(&[key], child);
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

    /// Every registered value with its path, in key order.
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
        for (key, child) in &self.children {
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
    let mut map = match value {
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
    use fireemu_core_database::Json;

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

    #[test]
    fn a_null_value_is_an_entry_and_splits_into_nothing() {
        let mut pending = Pending::default();
        pending.remember(&keys("a"), Json::Null);
        assert_eq!(entries(&pending), vec![("a".to_owned(), "null".to_owned())]);
        assert!(pending.forget(&keys("a/b")));
        assert!(pending.entries().is_empty());
    }
}
