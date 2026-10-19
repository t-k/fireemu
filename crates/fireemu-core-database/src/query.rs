//! Queries: the order of children, range bounds and limits.
//!
//! A query orders the children of a location by priority (the default), by key, by value or
//! by the value of a descendant path, breaking ties by key. Values order as absent < `false`
//! < `true` < numbers < strings < objects; keys as [`crate::key::name_compare`]. Bounds
//! compare `(value, key)` pairs: a bound without a key name starts before every key of its
//! value (`startAt`, `endBefore`) or ends after all of them (`endAt`, `startAfter`).
//! `limitToFirst` keeps the first children of the range, `limitToLast` the last ones.

use std::cmp::Ordering;

use crate::error::{DatabaseError, ErrorKind, Result};
use crate::json::Json;
use crate::key::name_compare;
use crate::node::{Content, Leaf, Node};
use crate::path::Path;

/// What children are ordered by.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum OrderBy {
    /// Priority (`$priority`), the SDK default.
    #[default]
    Priority,
    /// Key (`$key`).
    Key,
    /// Value (`$value`).
    Value,
    /// The value at a descendant path.
    Child(Path),
}

/// The key half of a bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundKey {
    /// Before every key.
    Min,
    /// After every key.
    Max,
    /// A key name.
    Name(String),
}

/// One end of a range.
#[derive(Debug, Clone, PartialEq)]
pub struct Bound {
    /// The index value (`null`, a boolean, a number or a string).
    pub value: Json,
    /// The key half.
    pub key: BoundKey,
    /// Whether children equal to the bound are inside the range.
    pub inclusive: bool,
}

/// How many children a query keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// The first `n` children of the range.
    First(u32),
    /// The last `n` children of the range.
    Last(u32),
}

/// A query on the children of one location.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct QueryParams {
    /// The order.
    pub order_by: OrderBy,
    /// The start of the range.
    pub start: Option<Bound>,
    /// The end of the range.
    pub end: Option<Bound>,
    /// The limit.
    pub limit: Option<Limit>,
}

impl QueryParams {
    /// A query in `order_by` order without bounds or limit.
    pub fn ordered_by(order_by: OrderBy) -> Self {
        Self {
            order_by,
            ..Self::default()
        }
    }

    /// `startAt(value, key)`.
    #[must_use]
    pub fn start_at(mut self, value: Json, key: Option<&str>) -> Self {
        self.start = Some(Bound {
            value,
            key: key.map_or(BoundKey::Min, |k| BoundKey::Name(k.to_owned())),
            inclusive: true,
        });
        self
    }

    /// `startAfter(value, key)`.
    #[must_use]
    pub fn start_after(mut self, value: Json, key: Option<&str>) -> Self {
        self.start = Some(Bound {
            value,
            key: key.map_or(BoundKey::Max, |k| BoundKey::Name(k.to_owned())),
            inclusive: false,
        });
        self
    }

    /// `endAt(value, key)`.
    #[must_use]
    pub fn end_at(mut self, value: Json, key: Option<&str>) -> Self {
        self.end = Some(Bound {
            value,
            key: key.map_or(BoundKey::Max, |k| BoundKey::Name(k.to_owned())),
            inclusive: true,
        });
        self
    }

    /// `endBefore(value, key)`.
    #[must_use]
    pub fn end_before(mut self, value: Json, key: Option<&str>) -> Self {
        self.end = Some(Bound {
            value,
            key: key.map_or(BoundKey::Min, |k| BoundKey::Name(k.to_owned())),
            inclusive: false,
        });
        self
    }

    /// `equalTo(value, key)`.
    #[must_use]
    pub fn equal_to(self, value: Json, key: Option<&str>) -> Self {
        self.start_at(value.clone(), key).end_at(value, key)
    }

    /// `limitToFirst(n)`.
    #[must_use]
    pub fn limit_to_first(mut self, n: u32) -> Self {
        self.limit = Some(Limit::First(n));
        self
    }

    /// `limitToLast(n)`.
    #[must_use]
    pub fn limit_to_last(mut self, n: u32) -> Self {
        self.limit = Some(Limit::Last(n));
        self
    }

    /// Checks the bounds against the order: a bound value is `null`, a boolean, a number or
    /// a string; `orderByKey` bounds are strings without a key name; `orderByPriority` bounds
    /// are `null`, numbers or strings.
    pub fn validate(&self) -> Result<()> {
        for bound in self.start.iter().chain(self.end.iter()) {
            let fits = match (&self.order_by, &bound.value) {
                (OrderBy::Key, Json::String(_)) => !matches!(bound.key, BoundKey::Name(_)),
                (_, Json::Array(_) | Json::Object(_))
                | (OrderBy::Key, _)
                | (OrderBy::Priority, Json::Bool(_)) => false,
                _ => true,
            };
            if !fits {
                return Err(DatabaseError::new(
                    ErrorKind::InvalidQuery,
                    format!("bound {bound:?} does not fit order {:?}", self.order_by),
                ));
            }
        }
        Ok(())
    }

    /// The children of `node` the query selects, in query order. The query must be valid.
    pub fn run<'a>(&self, node: Option<&'a Node>) -> Vec<(&'a str, &'a Node)> {
        let Some(Content::Children(children)) = node.map(|n| &n.content) else {
            return Vec::new();
        };
        let mut selected: Vec<(&'a str, &'a Node)> = children
            .iter()
            .map(|(key, child)| (key.as_str(), child))
            .filter(|(key, child)| self.in_range(key, child))
            .collect();
        selected.sort_by(|(ka, a), (kb, b)| self.compare_children(ka, a, kb, b));
        match self.limit {
            None => {}
            Some(Limit::First(n)) => selected.truncate(n as usize),
            Some(Limit::Last(n)) => {
                let skip = selected.len().saturating_sub(n as usize);
                selected.drain(..skip);
            }
        }
        selected
    }

    /// The query order of two children.
    pub fn compare_children(&self, key_a: &str, a: &Node, key_b: &str, b: &Node) -> Ordering {
        match &self.order_by {
            OrderBy::Key => name_compare(key_a, key_b),
            order => index_value(order, a)
                .cmp_with(&index_value(order, b))
                .then_with(|| name_compare(key_a, key_b)),
        }
    }

    fn in_range(&self, key: &str, child: &Node) -> bool {
        let after_start = self.start.as_ref().is_none_or(|bound| {
            let ord = self.compare_to_bound(key, child, bound);
            ord == Ordering::Greater || (ord == Ordering::Equal && bound.inclusive)
        });
        let before_end = self.end.as_ref().is_none_or(|bound| {
            let ord = self.compare_to_bound(key, child, bound);
            ord == Ordering::Less || (ord == Ordering::Equal && bound.inclusive)
        });
        after_start && before_end
    }

    /// The order of a child against a bound.
    fn compare_to_bound(&self, key: &str, child: &Node, bound: &Bound) -> Ordering {
        let primary = match (&self.order_by, &bound.value) {
            (OrderBy::Key, Json::String(name)) => name_compare(key, name),
            (order, value) => index_value(order, child).cmp_with(&IndexValue::of_bound(value)),
        };
        primary.then_with(|| match &bound.key {
            BoundKey::Min => Ordering::Greater,
            BoundKey::Max => Ordering::Less,
            BoundKey::Name(name) => name_compare(key, name),
        })
    }
}

/// The value a child is ordered by.
enum IndexValue<'a> {
    Absent,
    Leaf(Leaf),
    LeafRef(&'a Leaf),
    Children,
}

impl<'a> IndexValue<'a> {
    fn of_node(node: Option<&'a Node>) -> Self {
        match node.map(|n| &n.content) {
            None => Self::Absent,
            Some(Content::Leaf(leaf)) => Self::LeafRef(leaf),
            Some(Content::Children(_)) => Self::Children,
        }
    }

    fn of_bound(value: &Json) -> Self {
        match value {
            Json::Bool(b) => Self::Leaf(Leaf::Bool(*b)),
            Json::Number(n) => Self::Leaf(Leaf::Number(*n)),
            Json::String(s) => Self::Leaf(Leaf::String(s.clone())),
            // `validate` refuses arrays and objects; `null` is the absent value.
            Json::Null | Json::Array(_) | Json::Object(_) => Self::Absent,
        }
    }

    fn leaf(&self) -> Option<&Leaf> {
        match self {
            Self::Leaf(leaf) => Some(leaf),
            Self::LeafRef(leaf) => Some(leaf),
            Self::Absent | Self::Children => None,
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Self::Absent => 0,
            Self::Leaf(_) | Self::LeafRef(_) => 1,
            Self::Children => 2,
        }
    }

    /// Absent < leaves (in value order) < children (all equal).
    fn cmp_with(&self, other: &IndexValue<'_>) -> Ordering {
        match (self.leaf(), other.leaf()) {
            (Some(a), Some(b)) => a.value_cmp(b),
            _ => self.rank().cmp(&other.rank()),
        }
    }
}

fn index_value<'a>(order: &OrderBy, child: &'a Node) -> IndexValue<'a> {
    match order {
        OrderBy::Priority => match &child.priority {
            None => IndexValue::Absent,
            Some(priority) => IndexValue::Leaf(priority.as_leaf()),
        },
        OrderBy::Value => IndexValue::of_node(Some(child)),
        OrderBy::Child(path) => IndexValue::of_node(child.descendant(path)),
        // Key order never asks for an index value.
        OrderBy::Key => IndexValue::Absent,
    }
}
