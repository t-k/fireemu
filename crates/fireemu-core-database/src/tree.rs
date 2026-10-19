//! The tree of one database namespace.

use crate::error::Result;
use crate::json::Json;
use crate::limits::Limits;
use crate::node::{Format, Node};
use crate::path::Path;
use crate::server_value::ServerValueContext;

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
        let _ = (path, format);
        todo!()
    }

    /// Replaces the value at `path` with `value` (`null` deletes). A path ending in
    /// `.priority` sets the priority of an existing parent.
    pub fn set(&mut self, path: &Path, value: &Json, context: &ServerValueContext) -> Result<()> {
        let _ = (path, value, context);
        todo!()
    }

    /// Applies a multipath update at `base`: each key of `entries` is a path relative to
    /// `base`, and its value replaces that location. The paths may not overlap. Every entry is
    /// checked, and its server values resolved against the tree before the update, before
    /// any is applied.
    pub fn update(
        &mut self,
        base: &Path,
        entries: &[(String, Json)],
        context: &ServerValueContext,
    ) -> Result<()> {
        let _ = (base, entries, context);
        todo!()
    }
}
