//! Realtime listens (`q`/`n`) and the data messages pushed for them.
//!
//! The shapes follow what the official emulator (firebase-database-emulator v4.11.2) pushes.
//! A write counts only when it is effective: it writes null, or it changes the value it
//! writes (see [`crate::rest::Database::effective`]); a merge counts its effective entries.
//!
//! - A plain listen receives the value at its location first (unless the client's hash
//!   already matches). Then a put at or below the location gives a `d` message at the written
//!   path, and a put above it a `d` message at the location, even when the location's value
//!   did not change. A merge based at or below the location gives an `m` message at its base
//!   with its effective entries in the order they were sent; a merge based above it gives a
//!   `d` message at the location when an entry covers the location, and an `m` message at the
//!   location with the entries below it otherwise.
//! - A tagged query listen (`t`) receives its window. A put at or above the location sends
//!   the window again. A put inside it sends what changed in the window: what entered or
//!   changed first, then what was deleted, as null; a child pushed out of a limit window by
//!   another one entering is not reported (the client trims its window itself). A put whose
//!   child is the only change gives a `d` message at the written path, anything else an `m`
//!   message at the location; null that changes nothing is sent as written where the
//!   window shows a child, or where a window that is not full would show one. Merges follow [`Listen::window_merge`]. An empty window is
//!   null, or `{}` for a window without a limit.
//! - A query whose order needs an index that is not declared is served as a plain listen of
//!   the whole location, with the warning `no_index`.
//!
//! Messages are written `{"t":"d","d":{"b":{"p":<path>,"d":<data>[,"t":<tag>]},"a":<action>}}`
//! with the path relative to the root and no leading slash, in that member order.
//!
//! Not followed: a null written to an absent child where a window ordered by a child or
//! value, with bounds, would show it is not sent, since no order can place an absent child.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use fireemu_core_database::hash::node_hash;
use fireemu_core_database::{Content, Json, Leaf, Limit, Node, OrderBy, Path, QueryParams, Tree};

use crate::json_text::{priority_at, render, value_at, wire_json, Style};
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
    pub tag: Option<i64>,
    /// The query and its tag, for a tagged query served as a window.
    pub window: Option<(QueryParams, i64)>,
    /// What the client was last sent.
    pub last: Json,
}

impl Listen {
    /// The children a window shows, `None` for a listen that is not a window. A window on
    /// a leaf shows nothing, as a query `g` on a leaf answers null.
    fn window_children<'a>(&self, tree: &'a Tree) -> Option<Vec<(&'a str, &'a Node)>> {
        let (query, _) = self.window.as_ref()?;
        Some(query.run(tree.get(&self.path)))
    }

    /// The data the listen currently shows.
    pub fn view(&self, tree: &Tree) -> Json {
        match self.window_children(tree) {
            None if self.path.is_priority() => priority_at(tree, &self.path),
            None => wire_json(tree.get(&self.path)),
            Some(children) if children.is_empty() => match &self.window {
                Some((query, _)) if query.limit.is_none() => Json::Object(BTreeMap::new()),
                _ => Json::Null,
            },
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
            None if self.path.is_priority() => {
                let parent = self.path.parent().unwrap_or_default();
                let priority = tree.get(&parent).and_then(|node| node.priority.as_ref());
                node_hash(priority.map(|p| Node::leaf(p.as_leaf())).as_ref())
            }
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

    fn tag(&self) -> Option<i64> {
        self.window.as_ref().map(|(_, tag)| *tag)
    }

    /// The whole view as a `d` message.
    pub fn snapshot(&self, view: &Json) -> String {
        frame("d", &self.path, view, self.tag())
    }

    /// The messages a write sends this listen; `fresh` is the view after it.
    pub fn changes(&self, tree: &Tree, change: &Change, fresh: &Json) -> Vec<String> {
        if self.window.is_some() {
            self.window_changes(tree, change, fresh)
        } else {
            self.plain_changes(tree, change, fresh)
        }
    }

    fn plain_changes(&self, tree: &Tree, change: &Change, fresh: &Json) -> Vec<String> {
        let location = &self.path;
        match change {
            Change::Put {
                path,
                effective: true,
            } => {
                if location.contains(path) {
                    vec![frame("d", path, &value_at(tree, path), None)]
                } else if path.contains(location) {
                    vec![frame("d", location, fresh, None)]
                } else {
                    Vec::new()
                }
            }
            Change::Put { .. } => Vec::new(),
            Change::Patch { base, entries } => {
                let written = effective_paths(base, entries);
                if location.contains(base) {
                    let data = relative_values(tree, base, &written);
                    return message("m", base, &data, None);
                }
                if written.iter().any(|path| path.contains(location)) {
                    return vec![frame("d", location, fresh, None)];
                }
                let below: Vec<Path> = written
                    .into_iter()
                    .filter(|path| location.contains(path))
                    .collect();
                message(
                    "m",
                    location,
                    &relative_values(tree, location, &below),
                    None,
                )
            }
        }
    }

    fn window_changes(&self, tree: &Tree, change: &Change, fresh: &Json) -> Vec<String> {
        let location = &self.path;
        let tag = self.tag();
        let child_of = |path: &Path| path.keys().get(location.depth()).cloned();
        match change {
            Change::Put {
                effective: false, ..
            } => Vec::new(),
            Change::Put { path, .. } if path.contains(location) => vec![self.snapshot(fresh)],
            Change::Put { path, .. } if location.contains(path) => {
                let written = child_of(path);
                let entries = window_diff(
                    tree,
                    location,
                    &self.last,
                    fresh,
                    &written.iter().collect::<Vec<_>>(),
                );
                if entries.is_empty() && self.would_show_nothing_at(tree, path) {
                    // Null written where the window would show a child: sent as written.
                    return vec![frame("d", path, &Json::Null, tag)];
                }
                let shown =
                    |key: &String| matches!(&self.last, Json::Object(map) if map.contains_key(key));
                match entries.as_slice() {
                    // The client holds the child: the write as written.
                    [(key, _)] if Some(key) == written.as_ref() && shown(key) => {
                        vec![frame("d", path, &value_at(tree, path), tag)]
                    }
                    // A child that entered arrives whole (only the written child can).
                    [(key, value)] => {
                        vec![frame("d", &location.child(key), value, tag)]
                    }
                    _ => message("m", location, &entries, tag),
                }
            }
            Change::Put { .. } => Vec::new(),
            Change::Patch { base, entries } => {
                let written = effective_paths(base, entries);
                if written.iter().any(|path| path.contains(location)) {
                    return vec![self.snapshot(fresh)];
                }
                let inside: Vec<Path> = written
                    .into_iter()
                    .filter(|path| location.contains(path))
                    .collect();
                if inside.is_empty() {
                    return Vec::new();
                }
                self.window_merge(tree, base, &inside, fresh)
            }
        }
    }

    /// Whether null written to `path`, below the location, changed nothing the window
    /// shows but lies where it shows a child: inside a child it shows, or where a window
    /// that is not full would show one whose key fits its range. Only the key order can
    /// place an absent child, so other orders count only without bounds.
    fn would_show_nothing_at(&self, tree: &Tree, path: &Path) -> bool {
        let Some((query, _)) = &self.window else {
            return false;
        };
        if value_at(tree, path) != Json::Null {
            return false;
        }
        let shown = as_map(&self.last);
        let key = &path.keys()[self.path.depth()];
        if shown.contains_key(key) {
            return true;
        }
        let window = OldWindow::new(query, tree, &self.path, &shown);
        if window.bounds.is_some() {
            return false;
        }
        match query.order_by {
            OrderBy::Key => window.holds(query, key, Some(&Node::leaf(Leaf::Bool(false)))),
            _ => query.start.is_none() && query.end.is_none(),
        }
    }

    /// The messages a merge sends a window, the entries below its location given. The
    /// official emulator keeps the entries that touch the window: a child it showed or
    /// shows now, or, for a limit window, a child that sorts inside the window it showed.
    /// A range window receives them as an `m` message. A limit window receives them as an
    /// `m` message, with the children that entered without an entry, all last first, when
    /// every entry touches it; otherwise it receives what changed in the window, as a `d`
    /// message at the child for one change and an `m` message at the location for more.
    /// A merge inside one child is passed on as it was sent.
    fn window_merge(&self, tree: &Tree, base: &Path, inside: &[Path], fresh: &Json) -> Vec<String> {
        let Some((query, tag)) = &self.window else {
            return Vec::new();
        };
        let tag = Some(*tag);
        let location = &self.path;
        let depth = location.depth();
        let before = as_map(&self.last);
        let after = as_map(fresh);
        let old_window = OldWindow::new(query, tree, location, &before);
        let touches = |path: &Path| {
            let key = &path.keys()[depth];
            before.contains_key(key)
                || after.contains_key(key)
                || old_window.holds(query, key, tree.get(&location.child(key)))
        };
        let kept: Vec<&Path> = inside.iter().filter(|path| touches(path)).collect();
        if kept.is_empty() {
            // Nulls that changed nothing still reach the places the window shows.
            return inside
                .iter()
                .filter(|path| self.would_show_nothing_at(tree, path))
                .map(|path| frame("d", path, &Json::Null, tag))
                .collect();
        }
        if base != location && location.contains(base) {
            let kept: Vec<Path> = kept.into_iter().cloned().collect();
            return message("m", base, &relative_values(tree, base, &kept), tag);
        }
        if query.limit.is_some() && kept.len() < inside.len() {
            let written: Vec<&String> = inside.iter().map(|path| &path.keys()[depth]).collect();
            let changed = window_diff(tree, location, &self.last, fresh, &written);
            return match changed.as_slice() {
                [(key, value)] => vec![frame("d", &location.child(key), value, tag)],
                _ => message("m", location, &changed, tag),
            };
        }
        let mut sequence: Vec<(String, Json)> = kept
            .iter()
            .map(|path| (path.keys()[depth..].join("/"), value_at(tree, path)))
            .collect();
        if query.limit.is_some() {
            // Children an entry wrote whole; one written deeper still enters whole.
            let covered: Vec<&String> = kept
                .iter()
                .filter(|path| path.depth() == depth + 1)
                .map(|path| &path.keys()[depth])
                .collect();
            sequence.extend(
                after
                    .iter()
                    .filter(|(key, _)| !before.contains_key(*key) && !covered.contains(key))
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
        }
        sequence.reverse();
        message("m", location, &sequence, tag)
    }
}

/// The children a window showed, as nodes in query order, to tell whether a child sorts
/// inside it.
struct OldWindow {
    /// The first and last child, when the window was full.
    bounds: Option<((String, Node), (String, Node))>,
}

impl OldWindow {
    fn new(
        query: &QueryParams,
        tree: &Tree,
        location: &Path,
        shown: &BTreeMap<String, Json>,
    ) -> Self {
        let full = match query.limit {
            Some(Limit::First(n) | Limit::Last(n)) => shown.len() >= n as usize,
            None => false,
        };
        if !full {
            return Self { bounds: None };
        }
        let mut nodes: Vec<(String, Node)> = shown
            .iter()
            .filter_map(|(key, value)| {
                let node = Node::from_json(value, &location.child(key), tree.limits()).ok()??;
                Some((key.clone(), node))
            })
            .collect();
        nodes.sort_by(|(ka, a), (kb, b)| query.compare_children(ka, a, kb, b));
        let bounds = match (nodes.first(), nodes.last()) {
            (Some(first), Some(last)) => Some((first.clone(), last.clone())),
            _ => None,
        };
        Self { bounds }
    }

    /// Whether `key`, holding `node` now, sorts inside the range of the query and, when the
    /// window was full, between its first and last child.
    fn holds(&self, query: &QueryParams, key: &str, node: Option<&Node>) -> bool {
        let Some(node) = node else {
            return false;
        };
        let alone = Node {
            content: Content::Children(BTreeMap::from([(key.to_owned(), node.clone())])),
            priority: None,
        };
        let in_range = QueryParams {
            limit: None,
            ..query.clone()
        }
        .run(Some(&alone))
        .len()
            == 1;
        match &self.bounds {
            None => in_range,
            Some(((first_key, first), (last_key, last))) => {
                in_range
                    && query.compare_children(first_key, first, key, node) != Ordering::Greater
                    && query.compare_children(key, node, last_key, last) != Ordering::Greater
            }
        }
    }
}

fn as_map(view: &Json) -> BTreeMap<String, Json> {
    match view {
        Json::Object(map) => map.clone(),
        _ => BTreeMap::new(),
    }
}

/// The absolute paths of a merge's effective entries, in the order they were sent.
fn effective_paths(base: &Path, entries: &[crate::rest::Patched]) -> Vec<Path> {
    entries
        .iter()
        .filter(|entry| entry.effective)
        .map(|entry| base.join(&entry.path))
        .collect()
}

/// The values at `paths`, keyed by their path relative to `from`, which contains them.
fn relative_values(tree: &Tree, from: &Path, paths: &[Path]) -> Vec<(String, Json)> {
    paths
        .iter()
        .map(|path| (path.keys()[from.depth()..].join("/"), value_at(tree, path)))
        .collect()
}

/// What changed between two views of a window: the children that entered or changed, in
/// key order, then the children that left it, in key order: deleted ones as null, and ones
/// the write moved out with their new value. A child that left the window untouched was
/// pushed out and is not reported.
fn window_diff(
    tree: &Tree,
    location: &Path,
    last: &Json,
    fresh: &Json,
    written: &[&String],
) -> Vec<(String, Json)> {
    let (before, after) = (as_map(last), as_map(fresh));
    let mut changed: Vec<(String, Json)> = after
        .iter()
        .filter(|(key, value)| before.get(*key) != Some(*value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    changed.extend(
        before
            .keys()
            .filter(|key| !after.contains_key(*key))
            .filter_map(|key| match tree.get(&location.child(key)) {
                None => Some((key.clone(), Json::Null)),
                Some(node) if written.contains(&key) => Some((key.clone(), wire_json(Some(node)))),
                Some(_) => None,
            }),
    );
    changed
}

/// One message with `entries` as its data in their order, or none when there are none.
fn message(action: &str, path: &Path, entries: &[(String, Json)], tag: Option<i64>) -> Vec<String> {
    if entries.is_empty() {
        return Vec::new();
    }
    let members: Vec<String> = entries
        .iter()
        .map(|(key, value)| {
            format!(
                "{}:{}",
                render(&Json::String(key.clone()), Style::Compact),
                render(value, Style::Compact)
            )
        })
        .collect();
    vec![frame_text(
        action,
        path,
        &format!("{{{}}}", members.join(",")),
        tag,
    )]
}

/// A pushed data message.
pub(crate) fn frame(action: &str, path: &Path, data: &Json, tag: Option<i64>) -> String {
    frame_text(action, path, &render(data, Style::Compact), tag)
}

fn frame_text(action: &str, path: &Path, data: &str, tag: Option<i64>) -> String {
    let tag = tag.map(|t| format!(",\"t\":{t}")).unwrap_or_default();
    format!(
        "{{\"t\":\"d\",\"d\":{{\"b\":{{\"p\":{},\"d\":{data}{tag}}},\"a\":{}}}}}",
        render(&Json::String(path.keys().join("/")), Style::Compact),
        render(&Json::string(action), Style::Compact),
    )
}
