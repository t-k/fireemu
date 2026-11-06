//! The tree of one database namespace.

use std::collections::BTreeMap;

use crate::error::{DatabaseError, ErrorKind, Result};
use crate::json::Json;
use crate::limits::Limits;
use crate::node::{Content, Format, Node, Priority};
use crate::path::Path;
use crate::server_value::{resolve, stored_priority, ServerValueContext};

/// One checked write, ready to apply.
enum Write {
    /// Replace the value at a path (`None` deletes).
    Value(Path, Option<Node>),
    /// Set the priority of the node at a path, if it exists.
    Priority(Path, Option<Priority>),
    /// A write of what is already stored: the official emulator keeps the stored form
    /// (1.0 written over 1 leaves 1). Holds the value as written, for its answer.
    Unchanged(Option<Node>),
}

/// The data of one namespace.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Tree {
    root: Option<Node>,
    limits: Limits,
}

impl Tree {
    /// An empty tree checking writes against `limits`.
    pub fn new(limits: Limits) -> Self {
        Self { root: None, limits }
    }

    /// The limits writes are checked against.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The root node, if the tree holds anything.
    pub fn root(&self) -> Option<&Node> {
        self.root.as_ref()
    }

    /// A cheap, saturating estimate of the heap bytes the tree retains (see
    /// [`Node::retained_bytes`]); 0 when it holds nothing.
    pub fn retained_bytes(&self) -> u64 {
        self.root.as_ref().map_or(0, Node::retained_bytes)
    }

    /// The node at `path`.
    pub fn get(&self, path: &Path) -> Option<&Node> {
        self.root.as_ref()?.descendant(path)
    }

    /// The value at `path` as JSON (`null` when absent). A path ending in `.priority` reads
    /// the priority of its parent.
    pub fn get_json(&self, path: &Path, format: Format) -> Json {
        if path.is_priority() {
            let parent = path.parent().unwrap_or_default();
            return self
                .get(&parent)
                .and_then(|node| node.priority.as_ref())
                .map_or(Json::Null, Priority::to_json);
        }
        self.get(path)
            .map_or(Json::Null, |node| node.to_json(format))
    }

    /// Replaces the value at `path` with `value` (`null` deletes). A path ending in
    /// `.priority` sets the priority of an existing parent.
    ///
    /// Returns the node as written, its server values resolved: what a write answers, even
    /// when an equal value stays stored in its own form. `None` for a deletion and for a
    /// `.priority` path.
    pub fn set(
        &mut self,
        path: &Path,
        value: &Json,
        context: ServerValueContext,
    ) -> Result<Option<Node>> {
        let write = self.prepare(path, value, context)?;
        let written = match &write {
            Write::Value(_, node) | Write::Unchanged(node) => node.clone(),
            Write::Priority(..) => None,
        };
        self.apply(write);
        Ok(written)
    }

    /// Replaces the whole tree with `root`, as a write of it at the root would: a value equal
    /// to what is stored leaves the stored form in place (1.0 written over 1 leaves 1).
    pub fn replace_root(&mut self, root: Option<Node>) {
        if root != self.root {
            self.root = root;
        }
    }

    /// Applies a multipath update at `base`: each key of `entries` is a path relative to
    /// `base`, and its value replaces that location. The paths may not overlap. Every entry is
    /// checked, and its server values resolved against the tree before the update, before
    /// any is applied.
    pub fn update(
        &mut self,
        base: &Path,
        entries: &[(String, Json)],
        context: ServerValueContext,
    ) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let paths = entries
            .iter()
            .map(|(relative, _)| {
                let relative = Path::parse(relative, &self.limits)?;
                // Re-parsing the joined path applies the `.info` and `.priority` placement
                // rules to the whole path, not only to the relative part.
                Path::parse(&base.join(&relative).to_string(), &self.limits)
            })
            .collect::<Result<Vec<_>>>()?;
        check_disjoint(&paths)?;
        let writes = paths
            .iter()
            .zip(entries)
            .map(|(path, (_, value))| self.prepare(path, value, context))
            .collect::<Result<Vec<_>>>()?;
        // Priorities go last, after the values at their level, as the SDK's
        // `applySubtreeWrite` orders them; a node the update empties keeps no priority.
        let (priorities, values): (Vec<Write>, Vec<Write>) = writes
            .into_iter()
            .partition(|write| matches!(write, Write::Priority(..)));
        for write in values.into_iter().chain(priorities) {
            self.apply(write);
        }
        Ok(())
    }

    /// Checks one write against the tree as it is now and resolves its server values.
    fn prepare(&self, path: &Path, value: &Json, context: ServerValueContext) -> Result<Write> {
        if path.is_info() {
            return Err(DatabaseError::new(
                ErrorKind::ReadOnlyPath,
                format!("{path} is read-only"),
            ));
        }
        if path.is_priority() {
            let parent = path.parent().unwrap_or_default();
            let Some(node) = self.get(&parent) else {
                return Err(DatabaseError::new(
                    ErrorKind::PriorityOnAbsentNode,
                    "could not set priority on non-existent node",
                ));
            };
            let resolved = resolve(value, stored_priority(Some(node)).as_ref(), context)?;
            let priority = Priority::from_json(&resolved)?;
            if priority == node.priority {
                return Ok(Write::Unchanged(None));
            }
            return Ok(Write::Priority(parent, priority));
        }
        let resolved = resolve(value, self.get(path), context)?;
        let node = Node::from_json_owned(resolved, path, &self.limits)?;
        if node.as_ref() == self.get(path) {
            return Ok(Write::Unchanged(node));
        }
        Ok(Write::Value(path.clone(), node))
    }

    fn apply(&mut self, write: Write) {
        match write {
            Write::Value(path, node) => {
                self.root = replace(self.root.take(), path.keys(), node);
            }
            Write::Priority(path, priority) => {
                if let Some(node) = self.get_mut(&path) {
                    node.priority = priority;
                }
            }
            Write::Unchanged(_) => {}
        }
    }

    fn get_mut(&mut self, path: &Path) -> Option<&mut Node> {
        let mut node = self.root.as_mut()?;
        for key in path.keys() {
            node = match &mut node.content {
                Content::Leaf(_) => return None,
                Content::Children(children) => children.get_mut(key)?,
            };
        }
        Some(node)
    }
}

/// Refuses paths of which one equals or contains another.
fn check_disjoint(paths: &[Path]) -> Result<()> {
    let mut sorted: Vec<&Path> = paths.iter().collect();
    sorted.sort();
    // In key-sequence order every descendant of a path follows it before any other path,
    // so comparing neighbours finds every overlap.
    for pair in sorted.windows(2) {
        if pair[0].contains(pair[1]) {
            return Err(DatabaseError::new(
                ErrorKind::OverlappingUpdate,
                format!(
                    "path {} is an ancestor of, or the same as, {}",
                    pair[0], pair[1]
                ),
            ));
        }
    }
    Ok(())
}

/// `node` with the location `keys` below it replaced by `value`, pruned of empty maps.
fn replace(node: Option<Node>, keys: &[String], value: Option<Node>) -> Option<Node> {
    let Some((key, rest)) = keys.split_first() else {
        return value;
    };
    match node {
        None => replace(None, rest, value).map(|child| Node {
            content: Content::Children(BTreeMap::from([(key.clone(), child)])),
            priority: None,
        }),
        Some(Node {
            content: Content::Leaf(leaf),
            priority,
        }) => {
            let leaf = Node {
                content: Content::Leaf(leaf),
                priority,
            };
            // Nothing lives below a leaf, so a delete there changes nothing; a value
            // replaces the leaf with children but keeps the location's priority.
            match replace(None, rest, value) {
                None => Some(leaf),
                Some(child) => Some(Node {
                    content: Content::Children(BTreeMap::from([(key.clone(), child)])),
                    priority: leaf.priority,
                }),
            }
        }
        Some(Node {
            content: Content::Children(mut children),
            priority,
        }) => {
            match replace(children.remove(key), rest, value) {
                Some(child) => {
                    children.insert(key.clone(), child);
                }
                None if children.is_empty() => return None,
                None => {}
            }
            Some(Node {
                content: Content::Children(children),
                priority,
            })
        }
    }
}

/// Exact contents of a written scope and the metadata of its ancestor spine.
/// Unrelated sibling subtrees are not retained. Restore only after writes confined
/// to the saved scope; this is not a snapshot of arbitrary mutations elsewhere.
#[derive(Debug)]
pub struct ScopeSnapshot {
    path: Path,
    node: Option<Node>,
    priorities: Vec<Option<Priority>>,
}

impl Tree {
    /// Saves a scope, including leaf ancestors displaced by a descendant write and
    /// ancestor priorities lost if deletion prunes the last child. Priority paths
    /// save their parent. Cost is the saved subtree plus spine metadata and lookups.
    pub fn save_scope(&self, path: &Path) -> ScopeSnapshot {
        let scope = if path.is_priority() {
            path.parent().unwrap_or_default()
        } else {
            path.clone()
        };
        let mut node = self.root();
        let mut priorities = Vec::new();
        for key in scope.keys() {
            let Some(Node {
                content: Content::Children(children),
                priority,
            }) = node
            else {
                break;
            };
            priorities.push(priority.clone());
            node = children.get(key);
        }
        ScopeSnapshot {
            path: Path::from_keys(scope.keys()[..priorities.len()].iter().cloned()),
            node: node.cloned(),
            priorities,
        }
    }

    /// Restores exact saved representation without write validation or equality
    /// normalization. The snapshot is consumed and unrelated siblings are moved.
    pub fn restore_scope(&mut self, snapshot: ScopeSnapshot) {
        self.root = restore_spine(
            self.root.take(),
            snapshot.path.keys(),
            &snapshot.priorities,
            snapshot.node,
        );
    }
}

fn restore_spine(
    current: Option<Node>,
    keys: &[String],
    priorities: &[Option<Priority>],
    saved: Option<Node>,
) -> Option<Node> {
    let Some((key, rest)) = keys.split_first() else {
        return saved;
    };
    let mut children = match current {
        Some(Node {
            content: Content::Children(children),
            ..
        }) => children,
        _ => BTreeMap::new(),
    };
    let old_child = restore_spine(children.remove(key), rest, &priorities[1..], saved);
    if let Some(child) = old_child {
        children.insert(key.clone(), child);
    }
    if children.is_empty() {
        return None;
    }
    Some(Node {
        content: Content::Children(children),
        priority: priorities[0].clone(),
    })
}

/// A borrowed tree, optionally overlaid with the exact pre-write scope.
#[derive(Clone, Copy)]
pub struct ScopeView<'a> {
    tree: &'a Tree,
    snapshot: Option<&'a ScopeSnapshot>,
}

impl<'a> From<&'a Tree> for ScopeView<'a> {
    fn from(tree: &'a Tree) -> Self {
        Self {
            tree,
            snapshot: None,
        }
    }
}

impl ScopeSnapshot {
    /// Reads the original tree using this snapshot and unchanged live siblings.
    pub fn view<'a>(&'a self, tree: &'a Tree) -> ScopeView<'a> {
        ScopeView {
            tree,
            snapshot: Some(self),
        }
    }
}

impl<'a> ScopeView<'a> {
    /// The namespace's unchanged validation limits.
    pub fn limits(self) -> &'a Limits {
        self.tree.limits()
    }

    /// The root as it existed before the scoped write.
    pub fn root(self) -> Option<NodeView<'a>> {
        match self.snapshot {
            None => self.tree.root().map(NodeView::Borrowed),
            Some(snapshot) if snapshot.path.is_root() => {
                snapshot.node.as_ref().map(NodeView::Borrowed)
            }
            Some(snapshot) => Some(NodeView::Spine {
                current: self.tree.root(),
                snapshot,
                depth: 0,
            }),
        }
    }

    /// A node without materializing its ancestors or cloning sibling branches.
    pub fn get(self, path: &Path) -> Option<NodeView<'a>> {
        let mut node = self.root()?;
        for key in path.keys() {
            node = node.child(key)?;
        }
        Some(node)
    }
}

/// Borrowed contents of a node in a scope overlay.
#[derive(Clone, Copy)]
pub enum NodeView<'a> {
    /// An unchanged live node or a saved subtree node.
    Borrowed(&'a Node),
    /// An original ancestor, with its written child overlaid lazily.
    #[non_exhaustive]
    Spine {
        /// Its possibly pruned live counterpart.
        current: Option<&'a Node>,
        /// Original scope and ancestor metadata.
        snapshot: &'a ScopeSnapshot,
        /// This ancestor's depth in the saved path.
        depth: usize,
    },
}

impl<'a> NodeView<'a> {
    /// A leaf value, if this location was a leaf.
    pub fn leaf(self) -> Option<&'a crate::node::Leaf> {
        match self {
            Self::Borrowed(Node {
                content: Content::Leaf(leaf),
                ..
            }) => Some(leaf),
            _ => None,
        }
    }

    /// Exact original priority.
    pub fn priority(self) -> Option<&'a Priority> {
        match self {
            Self::Borrowed(node) => node.priority.as_ref(),
            Self::Spine {
                snapshot, depth, ..
            } => snapshot.priorities[depth].as_ref(),
        }
    }

    /// One original child, looking up only the relevant branch.
    pub fn child(self, key: &str) -> Option<Self> {
        if let Self::Spine {
            current,
            snapshot,
            depth,
        } = self
        {
            if key == snapshot.path.keys()[depth] {
                return if depth + 1 == snapshot.path.depth() {
                    snapshot.node.as_ref().map(Self::Borrowed)
                } else {
                    Some(Self::Spine {
                        current: child_node(current, key),
                        snapshot,
                        depth: depth + 1,
                    })
                };
            }
            return child_node(current, key).map(Self::Borrowed);
        }
        let Self::Borrowed(node) = self else {
            unreachable!()
        };
        child_node(Some(node), key).map(Self::Borrowed)
    }

    /// Original children in key order. The iterator overlays one child without
    /// collecting the surrounding map or cloning any nodes.
    pub fn children(self) -> Option<ViewChildren<'a>> {
        let (current, overlay) = match self {
            Self::Borrowed(node) => (Some(node), None),
            Self::Spine {
                current,
                snapshot,
                depth,
            } => {
                let key = snapshot.path.keys()[depth].as_str();
                (current, Some((key, self.child(key))))
            }
        };
        if self.leaf().is_some() {
            return None;
        }
        let children = current.and_then(node_children);
        Some(ViewChildren {
            iter: children
                .map(BTreeMap::iter)
                .into_iter()
                .flatten()
                .peekable(),
            overlay,
        })
    }

    /// Child count without traversing sibling values.
    pub fn child_count(self) -> usize {
        match self {
            Self::Borrowed(node) => node_children(node).map_or(0, BTreeMap::len),
            Self::Spine {
                current,
                snapshot,
                depth,
            } => {
                let key = &snapshot.path.keys()[depth];
                let children = current.and_then(node_children);
                children.map_or(0, BTreeMap::len)
                    - usize::from(children.is_some_and(|children| children.contains_key(key)))
                    + usize::from(self.child(key).is_some())
            }
        }
    }

    /// Compares logical contents, retaining the core's existing node equality.
    pub fn equals(self, other: &Node) -> bool {
        if let Self::Borrowed(node) = self {
            if std::ptr::eq(node, other) {
                return true;
            }
            #[cfg(test)]
            scope_equality_tests::record_structural_comparison();
            return node == other;
        }
        if self.priority() != other.priority.as_ref() {
            return false;
        }
        let Some(children) = node_children(other) else {
            return false;
        };
        self.child_count() == children.len()
            && self
                .children()
                .into_iter()
                .flatten()
                .all(|(key, node)| children.get(key).is_some_and(|other| node.equals(other)))
    }
}

fn node_children(node: &Node) -> Option<&BTreeMap<String, Node>> {
    match &node.content {
        Content::Children(children) => Some(children),
        Content::Leaf(_) => None,
    }
}
fn child_node<'a>(node: Option<&'a Node>, key: &str) -> Option<&'a Node> {
    node.and_then(node_children)?.get(key)
}

/// Ordered child iterator for a borrowed scope view.
pub struct ViewChildren<'a> {
    iter: std::iter::Peekable<
        std::iter::Flatten<
            std::option::IntoIter<std::collections::btree_map::Iter<'a, String, Node>>,
        >,
    >,
    overlay: Option<(&'a str, Option<NodeView<'a>>)>,
}
impl<'a> Iterator for ViewChildren<'a> {
    type Item = (&'a str, NodeView<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        if let Some((key, node)) = self.overlay {
            if self
                .iter
                .peek()
                .is_none_or(|(next, _)| key <= next.as_str())
            {
                if self
                    .iter
                    .peek()
                    .is_some_and(|(next, _)| key == next.as_str())
                {
                    self.iter.next();
                }
                self.overlay = None;
                if let Some(node) = node {
                    return Some((key, node));
                }
            }
        }
        self.iter
            .next()
            .map(|(key, node)| (key.as_str(), NodeView::Borrowed(node)))
    }
}

#[cfg(test)]
mod scope_equality_tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        static STRUCTURAL_COMPARISONS: Cell<usize> = const { Cell::new(0) };
    }
    pub(super) fn record_structural_comparison() {
        STRUCTURAL_COMPARISONS.with(|count| count.set(count.get() + 1));
    }

    #[test]
    fn identical_borrowed_nodes_never_enter_structural_comparison() {
        let mut tree = Tree::default();
        let now = ServerValueContext { now_millis: 0 };
        tree.set(
            &Path::root(),
            &Json::object([
                ("a", Json::int(1)),
                ("b", Json::object([("nested", Json::int(2))])),
            ]),
            now,
        )
        .unwrap();
        let original = tree.clone();
        let snapshot = tree.save_scope(&Path::from_keys(["a"]));
        tree.set(&Path::from_keys(["a"]), &Json::int(3), now)
            .unwrap();
        let sibling = Path::from_keys(["b"]);
        let before = snapshot.view(&tree).get(&sibling).unwrap();
        let after = tree.get(&sibling).unwrap();
        STRUCTURAL_COMPARISONS.with(|count| count.set(0));
        assert!(before.equals(after));
        assert_eq!(
            STRUCTURAL_COMPARISONS.with(Cell::get),
            0,
            "unchanged borrowed siblings must not enter recursive equality"
        );
        assert!(before.equals(original.get(&sibling).unwrap()));
        assert_eq!(
            STRUCTURAL_COMPARISONS.with(Cell::get),
            1,
            "distinct nodes still require structural equality"
        );
        assert!(!before.equals(tree.get(&Path::from_keys(["a"])).unwrap()));
        assert_eq!(STRUCTURAL_COMPARISONS.with(Cell::get), 2);
    }
}
