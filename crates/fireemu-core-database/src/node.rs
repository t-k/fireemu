//! Nodes of the tree.
//!
//! A location holds nothing (`None` at the API), a leaf (boolean, number or string) or a
//! non-empty map of children; either may carry a priority. A node never holds an empty map:
//! writing `null` removes a child and every parent left without children, and a priority
//! cannot outlive the value it belongs to.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::error::Result;
use crate::json::Json;
use crate::key::utf16_cmp;
use crate::limits::Limits;
use crate::number::Number;
use crate::path::Path;

/// A leaf value.
#[derive(Debug, Clone, PartialEq)]
pub enum Leaf {
    /// A boolean.
    Bool(bool),
    /// A number.
    Number(Number),
    /// A string.
    String(String),
}

/// A priority: a number or a string.
#[derive(Debug, Clone, PartialEq)]
pub enum Priority {
    /// A numeric priority.
    Number(Number),
    /// A string priority.
    String(String),
}

/// What a node holds.
#[derive(Debug, Clone, PartialEq)]
pub enum Content {
    /// A leaf value.
    Leaf(Leaf),
    /// A non-empty map of children.
    Children(BTreeMap<String, Node>),
}

/// A non-empty location.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    /// The value.
    pub content: Content,
    /// The priority, if one is set.
    pub priority: Option<Priority>,
}

/// How a node is rendered as JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Values only, as a plain REST `GET` returns them.
    Plain,
    /// `format=export`: priorities as `.priority`, prioritized leaves as `.value`.
    Export,
}

impl Leaf {
    /// The rank of the leaf's type in the value order: booleans, numbers, strings.
    fn type_rank(&self) -> u8 {
        match self {
            Self::Bool(_) => 0,
            Self::Number(_) => 1,
            Self::String(_) => 2,
        }
    }

    /// The value order of leaves: `false` < `true` < numbers < strings (UTF-16 order).
    pub fn value_cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Bool(a), Self::Bool(b)) => a.cmp(b),
            (Self::Number(a), Self::Number(b)) => a.total_cmp(*b),
            (Self::String(a), Self::String(b)) => utf16_cmp(a, b),
            _ => self.type_rank().cmp(&other.type_rank()),
        }
    }

    fn to_json(&self) -> Json {
        match self {
            Self::Bool(b) => Json::Bool(*b),
            Self::Number(n) => Json::Number(*n),
            Self::String(s) => Json::String(s.clone()),
        }
    }
}

impl Priority {
    /// The priority as a leaf value.
    pub fn as_leaf(&self) -> Leaf {
        match self {
            Self::Number(n) => Leaf::Number(*n),
            Self::String(s) => Leaf::String(s.clone()),
        }
    }

    /// The priority as JSON.
    pub fn to_json(&self) -> Json {
        match self {
            Self::Number(n) => Json::Number(*n),
            Self::String(s) => Json::String(s.clone()),
        }
    }

    /// Reads a priority: `null` is no priority, numbers and strings are priorities.
    pub fn from_json(json: &Json) -> Result<Option<Self>> {
        let _ = json;
        todo!()
    }
}

/// The order of index values, which may be absent: absent < leaves < children. Two nodes
/// with children compare equal (the key decides).
pub fn compare_values(a: Option<&Node>, b: Option<&Node>) -> Ordering {
    let _ = (a, b);
    todo!()
}

impl Node {
    /// A leaf without priority.
    pub fn leaf(leaf: Leaf) -> Self {
        Self {
            content: Content::Leaf(leaf),
            priority: None,
        }
    }

    /// Builds the node `json` describes, or `None` when it describes nothing. `depth` is the
    /// number of keys above the node; written data may not nest deeper than the limit.
    /// Server values must be resolved first.
    pub fn from_json(json: &Json, depth: usize, limits: &Limits) -> Result<Option<Self>> {
        let _ = (json, depth, limits);
        todo!()
    }

    /// The node as JSON.
    pub fn to_json(&self, format: Format) -> Json {
        let _ = format;
        todo!()
    }

    /// The `shallow=true` rendering: a leaf as itself, every child of a map as `true`.
    pub fn shallow(&self) -> Json {
        match &self.content {
            Content::Leaf(leaf) => leaf.to_json(),
            Content::Children(children) => {
                Json::Object(children.keys().map(|k| (k.clone(), Json::Bool(true))).collect())
            }
        }
    }

    /// The child named `key`, if any.
    pub fn child(&self, key: &str) -> Option<&Node> {
        match &self.content {
            Content::Leaf(_) => None,
            Content::Children(children) => children.get(key),
        }
    }

    /// The node at `path` below this one.
    pub fn descendant(&self, path: &Path) -> Option<&Node> {
        let mut node = self;
        for key in path.keys() {
            node = node.child(key)?;
        }
        Some(node)
    }

    /// The number of key levels below this node (0 for a leaf).
    pub fn depth(&self) -> usize {
        match &self.content {
            Content::Leaf(_) => 0,
            Content::Children(children) => {
                1 + children.values().map(Node::depth).max().unwrap_or(0)
            }
        }
    }
}
