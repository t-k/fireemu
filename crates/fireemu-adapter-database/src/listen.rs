//! Realtime listens (`q`/`n`) and the data messages pushed for them.
//!
//! The shapes follow what the official emulator (firebase-database-emulator v4.11.2) pushes:
//!
//! - A plain listen receives the value at its location first (unless the client's hash
//!   already matches), then, for every write that changes that value, a `d` message at the
//!   written path when the write lies at or below the location, a `d` message at the location
//!   when the write lies above it, and an `m` message for a multipath write (at the write's
//!   base, or at the location with the entries below it).
//! - A tagged query listen (`t`) receives its window, then the window's changes: one `d`
//!   message for a single changed or entering child, an `m` message for several, a child that
//!   was deleted from the data reported as null. A child pushed out of a limit window only by
//!   another one entering is not reported: the client trims its window itself.
//! - A query whose order needs an index that is not declared is served as a plain listen of
//!   the whole location, with the warning `no_index`.
//!
//! Messages are written `{"t":"d","d":{"b":{"p":<path>,"d":<data>[,"t":<tag>]},"a":<action>}}`
//! with the path relative to the root and no leading slash, in that member order.

use std::collections::BTreeMap;

use fireemu_core_database::hash::node_hash;
use fireemu_core_database::{Content, Json, Node, Path, QueryParams, Tree};

use crate::json_text::{priority_at, render, wire_json, Style};
use crate::rest::Change;

/// One listen of a realtime connection.
#[derive(Debug)]
pub(crate) struct Listen {
    /// The connection.
    pub client: u64,
    /// The namespace.
    pub namespace: String,
    /// The listened location.
    pub path: Path,
    /// The tag the client registered it under (`None` for a plain listen).
    pub tag: Option<u64>,
    /// The query and its tag, for a tagged query served as a window.
    pub window: Option<(QueryParams, u64)>,
    /// What the client was last sent.
    pub last: Json,
}

impl Listen {
    /// The children a window shows, `None` for a listen that is not a window. A window on
    /// a leaf shows nothing, as a query `g` on a leaf answers null.
    fn window_children<'a>(&self, tree: &'a Tree) -> Option<Vec<(&'a str, &'a Node)>> {
        let (query, _) = self.window.as_ref()?;
        Some(match tree.get(&self.path) {
            Some(node) if matches!(node.content, Content::Children(_)) => query.run(Some(node)),
            _ => Vec::new(),
        })
    }

    /// The data the listen currently shows.
    pub fn view(&self, tree: &Tree) -> Json {
        match self.window_children(tree) {
            None => wire_json(tree.get(&self.path)),
            Some(children) if children.is_empty() => Json::Null,
            Some(children) => Json::Object(
                children
                    .into_iter()
                    .map(|(key, child)| (key.to_owned(), wire_json(Some(child))))
                    .collect(),
            ),
        }
    }

    /// The hash the client compares to skip the first value: of the location, or of the
    /// window's children.
    pub fn hash(&self, tree: &Tree) -> String {
        match self.window_children(tree) {
            None => node_hash(tree.get(&self.path)),
            Some(children) if children.is_empty() => node_hash(None),
            Some(children) => node_hash(Some(&Node {
                content: Content::Children(
                    children
                        .into_iter()
                        .map(|(key, child)| (key.to_owned(), child.clone()))
                        .collect(),
                ),
                priority: None,
            })),
        }
    }

    fn tag(&self) -> Option<u64> {
        self.window.as_ref().map(|(_, tag)| *tag)
    }

    /// The whole view as a `d` message.
    pub fn snapshot(&self, view: &Json) -> String {
        frame("d", &self.path, view, self.tag())
    }

    /// The messages for a change that turned the view from `self.last` into `fresh`.
    pub fn changes(&self, tree: &Tree, change: &Change, fresh: &Json) -> Vec<String> {
        if self.window.is_some() {
            return self.window_changes(tree, fresh);
        }
        let location = &self.path;
        match change {
            Change::Put(path) if location.contains(path) => {
                let data = if path.is_priority() {
                    priority_at(tree, path)
                } else {
                    wire_json(tree.get(path))
                };
                vec![frame("d", path, &data, None)]
            }
            Change::Patch(base, entries) if location.contains(base) => {
                let data = entries
                    .iter()
                    .map(|entry| (entry.keys().join("/"), value_at(tree, &base.join(entry))))
                    .collect();
                vec![frame("m", base, &Json::Object(data), None)]
            }
            Change::Patch(base, entries) => {
                let absolute: Vec<Path> = entries.iter().map(|entry| base.join(entry)).collect();
                if absolute.iter().any(|path| path.contains(location)) {
                    return vec![frame("d", location, fresh, None)];
                }
                let data: BTreeMap<String, Json> = absolute
                    .iter()
                    .filter(|path| location.contains(path))
                    .map(|path| {
                        let relative = &path.keys()[location.depth()..];
                        (relative.join("/"), value_at(tree, path))
                    })
                    .collect();
                if data.is_empty() {
                    return Vec::new();
                }
                vec![frame("m", location, &Json::Object(data), None)]
            }
            Change::Put(_) => vec![frame("d", location, fresh, None)],
        }
    }

    fn window_changes(&self, tree: &Tree, fresh: &Json) -> Vec<String> {
        let (Json::Object(before), Json::Object(after)) = (&self.last, fresh) else {
            return vec![self.snapshot(fresh)];
        };
        let mut entries: BTreeMap<String, Json> = after
            .iter()
            .filter(|(key, value)| before.get(*key) != Some(*value))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        for key in before.keys().filter(|key| !after.contains_key(*key)) {
            // A child pushed out by a newcomer is the client's to trim; a deleted one is not.
            if tree.get(&self.path.child(key)).is_none() {
                entries.insert(key.clone(), Json::Null);
            }
        }
        let tag = self.tag();
        match entries.len() {
            0 => Vec::new(),
            1 => entries
                .into_iter()
                .map(|(key, value)| frame("d", &self.path.child(&key), &value, tag))
                .collect(),
            _ => vec![frame("m", &self.path, &Json::Object(entries), tag)],
        }
    }
}

fn value_at(tree: &Tree, path: &Path) -> Json {
    if path.is_priority() {
        priority_at(tree, path)
    } else {
        wire_json(tree.get(path))
    }
}

/// A pushed data message.
pub(crate) fn frame(action: &str, path: &Path, data: &Json, tag: Option<u64>) -> String {
    let tag = tag.map(|t| format!(",\"t\":{t}")).unwrap_or_default();
    format!(
        "{{\"t\":\"d\",\"d\":{{\"b\":{{\"p\":{},\"d\":{}{tag}}},\"a\":{}}}}}",
        render(&Json::String(path.keys().join("/")), Style::Compact),
        render(data, Style::Compact),
        render(&Json::string(action), Style::Compact),
    )
}
