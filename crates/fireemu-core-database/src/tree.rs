//! The tree of one database namespace.

use std::collections::BTreeMap;

use crate::error::{DatabaseError, ErrorKind, Result};
use crate::json::Json;
use crate::limits::Limits;
use crate::node::{Content, Format, Node, Priority};
use crate::path::Path;
use crate::server_value::{resolve, ServerValueContext};

/// One checked write, ready to apply.
enum Write {
    /// Replace the value at a path (`None` deletes).
    Value(Path, Option<Node>),
    /// Set the priority of the node at a path, if it exists.
    Priority(Path, Option<Priority>),
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
    pub fn set(&mut self, path: &Path, value: &Json, context: ServerValueContext) -> Result<()> {
        let write = self.prepare(path, value, context)?;
        self.apply(write);
        Ok(())
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
        for write in writes {
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
            let resolved = resolve(value, None, context)?;
            let priority = Priority::from_json(&resolved)?;
            return Ok(Write::Priority(path.parent().unwrap_or_default(), priority));
        }
        let resolved = resolve(value, self.get(path), context)?;
        let node = Node::from_json(&resolved, path.depth(), &self.limits)?;
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
