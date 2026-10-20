//! Nodes of the tree.
//!
//! A location holds nothing (`None` at the API), a leaf (boolean, number or string) or a
//! non-empty map of children; either may carry a priority. A node never holds an empty map:
//! writing `null` removes a child and every parent left without children, and a priority
//! cannot outlive the value it belongs to.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::error::{DatabaseError, ErrorKind, Result};
use crate::json::Json;
use crate::key::{utf16_cmp, validate_key};
use crate::limits::Limits;
use crate::number::Number;
use crate::path::{check_path_bytes, Path, PRIORITY_KEY};
use crate::server_value::SERVER_VALUE_KEY;

/// The `.value` key of a prioritized leaf.
pub const VALUE_KEY: &str = ".value";

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

/// Where a node being built sits: keys above it and the byte length of its path.
#[derive(Debug, Clone, Copy)]
struct Position {
    depth: usize,
    bytes: usize,
}

/// How a node is rendered as JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Values only, as the SDK's `val()` and a plain REST `GET` give them: children whose
    /// keys are dense array indexes become an array.
    Plain,
    /// `format=export`: priorities as `.priority`, prioritized leaves as `.value`, and
    /// index-keyed children kept as objects (the SDK's `exportVal()`).
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
        match json {
            Json::Null => Ok(None),
            Json::Number(n) => Ok(Some(Self::Number(*n))),
            Json::String(s) => Ok(Some(Self::String(s.clone()))),
            Json::Bool(_) | Json::Array(_) | Json::Object(_) => Err(DatabaseError::new(
                ErrorKind::InvalidPriority,
                "a priority must be null, a number or a string",
            )),
        }
    }
}

/// The order of index values, which may be absent: absent < leaves < children. Two nodes
/// with children compare equal (the key decides).
pub fn compare_values(a: Option<&Node>, b: Option<&Node>) -> Ordering {
    match (a.map(|n| &n.content), b.map(|n| &n.content)) {
        (None, None) | (Some(Content::Children(_)), Some(Content::Children(_))) => Ordering::Equal,
        (None, Some(_)) | (Some(Content::Leaf(_)), Some(Content::Children(_))) => Ordering::Less,
        (Some(_), None) | (Some(Content::Children(_)), Some(Content::Leaf(_))) => Ordering::Greater,
        (Some(Content::Leaf(x)), Some(Content::Leaf(y))) => x.value_cmp(y),
    }
}

impl Node {
    /// A leaf without priority.
    pub fn leaf(leaf: Leaf) -> Self {
        Self {
            content: Content::Leaf(leaf),
            priority: None,
        }
    }

    /// Builds the node `json` describes for the location `at`, or `None` when it describes
    /// nothing. Written data may not nest deeper, or reach longer paths, than the limits.
    /// Server values must be resolved first.
    pub fn from_json(json: &Json, at: &Path, limits: &Limits) -> Result<Option<Self>> {
        Self::build(
            json,
            Position {
                depth: at.depth(),
                bytes: at.byte_len(),
            },
            limits,
        )
    }

    fn build(json: &Json, at: Position, limits: &Limits) -> Result<Option<Self>> {
        // A null is held to the depth limit too: the official emulator refuses a delete
        // below depth 32 like any other write there.
        if at.depth > limits.max_depth {
            return Err(too_deep(limits));
        }
        if matches!(json, Json::Null) {
            return Ok(None);
        }
        match json {
            Json::Null => Ok(None),
            Json::Bool(b) => Ok(Some(Self::leaf(Leaf::Bool(*b)))),
            Json::Number(n) => Ok(Some(Self::leaf(Leaf::Number(*n)))),
            Json::String(s) => {
                if s.len() > limits.max_string_bytes {
                    return Err(DatabaseError::new(
                        ErrorKind::StringTooLong,
                        format!(
                            "a string value is {} bytes long; the limit is {} bytes",
                            s.len(),
                            limits.max_string_bytes
                        ),
                    ));
                }
                Ok(Some(Self::leaf(Leaf::String(s.clone()))))
            }
            Json::Array(items) => {
                let entries = items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| (index.to_string(), item));
                Self::from_entries(entries, None, at, limits)
            }
            Json::Object(map) => Self::from_object(map, at, limits),
        }
    }

    fn from_object(
        map: &BTreeMap<String, Json>,
        at: Position,
        limits: &Limits,
    ) -> Result<Option<Self>> {
        if map.contains_key(SERVER_VALUE_KEY) {
            return Err(DatabaseError::new(
                ErrorKind::InvalidServerValue,
                "server values must be resolved before the data is stored",
            ));
        }
        // The official emulator stores a `.priority` member's number as a double (it answers
        // `2.0` for 2); a priority written to `<location>/.priority` keeps its type.
        let priority = match map.get(PRIORITY_KEY) {
            Some(json) => Priority::from_json(json)?.map(|priority| match priority {
                Priority::Number(n) => Priority::Number(Number::Double(n.as_f64())),
                other @ Priority::String(_) => other,
            }),
            None => None,
        };
        if let Some(value) = map.get(VALUE_KEY) {
            if map.keys().any(|k| k != VALUE_KEY && k != PRIORITY_KEY) {
                return Err(DatabaseError::new(
                    ErrorKind::InvalidData,
                    "an object with \".value\" may hold only \".priority\" besides it",
                ));
            }
            let node = Self::build(value, at, limits)?;
            if node.is_none() && priority.is_some() {
                return Err(priority_without_value());
            }
            return Ok(node.map(|node| node.with_priority(priority)));
        }
        let entries = map
            .iter()
            .filter(|(k, _)| k.as_str() != PRIORITY_KEY)
            .map(|(k, v)| (k.clone(), v));
        Self::from_entries(entries, priority, at, limits)
    }

    fn from_entries<'a>(
        entries: impl Iterator<Item = (String, &'a Json)>,
        priority: Option<Priority>,
        at: Position,
        limits: &Limits,
    ) -> Result<Option<Self>> {
        let mut children = BTreeMap::new();
        for (key, value) in entries {
            validate_key(&key)?;
            let separator = usize::from(at.depth > 0);
            let child_at = Position {
                depth: at.depth + 1,
                bytes: at.bytes + separator + key.len(),
            };
            check_path_bytes(child_at.bytes, limits)?;
            if let Some(child) = Self::build(value, child_at, limits)? {
                children.insert(key, child);
            }
        }
        if children.is_empty() {
            if priority.is_some() {
                return Err(priority_without_value());
            }
            return Ok(None);
        }
        Ok(Some(Self {
            content: Content::Children(children),
            priority,
        }))
    }

    /// This node with `priority` instead of its own.
    #[must_use]
    pub fn with_priority(mut self, priority: Option<Priority>) -> Self {
        self.priority = priority;
        self
    }

    /// The node as JSON.
    pub fn to_json(&self, format: Format) -> Json {
        let priority = match format {
            Format::Plain => None,
            Format::Export => self.priority.as_ref(),
        };
        match (&self.content, priority) {
            (Content::Leaf(leaf), None) => leaf.to_json(),
            (Content::Leaf(leaf), Some(priority)) => Json::object([
                (VALUE_KEY, leaf.to_json()),
                (PRIORITY_KEY, priority.to_json()),
            ]),
            (Content::Children(children), None) if format == Format::Plain => {
                match array_length(children) {
                    Some(length) => {
                        let mut items = vec![Json::Null; length];
                        for (key, child) in children {
                            // `array_length` checked that every key is an index below `length`.
                            if let Some(slot) =
                                key.parse::<usize>().ok().and_then(|i| items.get_mut(i))
                            {
                                *slot = child.to_json(format);
                            }
                        }
                        Json::Array(items)
                    }
                    None => Json::Object(
                        children
                            .iter()
                            .map(|(k, child)| (k.clone(), child.to_json(format)))
                            .collect(),
                    ),
                }
            }
            (Content::Children(children), priority) => {
                let mut map: BTreeMap<String, Json> = children
                    .iter()
                    .map(|(k, child)| (k.clone(), child.to_json(format)))
                    .collect();
                if let Some(priority) = priority {
                    map.insert(PRIORITY_KEY.to_owned(), priority.to_json());
                }
                Json::Object(map)
            }
        }
    }

    /// The `shallow=true` rendering: a leaf as itself, every child of a map as `true`.
    pub fn shallow(&self) -> Json {
        match &self.content {
            Content::Leaf(leaf) => leaf.to_json(),
            Content::Children(children) => Json::Object(
                children
                    .keys()
                    .map(|k| (k.clone(), Json::Bool(true)))
                    .collect(),
            ),
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

    /// A cheap, saturating estimate of the heap bytes this node retains: the node itself, each
    /// child's key (with its `String`) and node, and the bytes of string values and string
    /// priorities. Numbers and booleans live inside the node.
    pub fn retained_bytes(&self) -> u64 {
        let mut bytes = size_of::<Self>() as u64;
        if let Some(Priority::String(priority)) = &self.priority {
            bytes = bytes.saturating_add(priority.len() as u64);
        }
        match &self.content {
            Content::Leaf(Leaf::String(text)) => bytes = bytes.saturating_add(text.len() as u64),
            Content::Leaf(_) => {}
            Content::Children(children) => {
                for (key, child) in children {
                    bytes = bytes
                        .saturating_add(size_of::<String>() as u64)
                        .saturating_add(key.len() as u64)
                        .saturating_add(child.retained_bytes());
                }
            }
        }
        bytes
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

/// The error for data nested deeper than the limit.
pub(crate) fn too_deep(limits: &Limits) -> DatabaseError {
    DatabaseError::new(
        ErrorKind::PathTooDeep,
        format!(
            "the data is nested deeper than the limit of {} levels",
            limits.max_depth
        ),
    )
}

/// The error for a priority given to an empty value, which the official emulator refuses
/// ("couldn't parse") where the SDK would store nothing.
fn priority_without_value() -> DatabaseError {
    DatabaseError::new(
        ErrorKind::InvalidData,
        "a priority needs a value; the data describes nothing",
    )
}

/// The array length index-keyed children render as in the plain format, if they do: every
/// key matches `0|[1-9][0-9]*` and the largest is below twice the number of children (the
/// SDK's `ChildrenNode.val()` rule).
pub fn array_length(children: &BTreeMap<String, Node>) -> Option<usize> {
    let mut max = 0usize;
    for key in children.keys() {
        let canonical = key == "0"
            || (!key.is_empty()
                && !key.starts_with('0')
                && key.bytes().all(|b| b.is_ascii_digit()));
        if !canonical {
            return None;
        }
        max = max.max(key.parse().ok()?);
    }
    (max < 2 * children.len()).then_some(max + 1)
}
