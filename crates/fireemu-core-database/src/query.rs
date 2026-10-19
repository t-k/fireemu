//! Queries: the order of children, range bounds and limits.
//!
//! A query orders the children of a location by priority (the default), by key, by value or
//! by the value of a descendant path, breaking ties by key. Values order as absent < `false`
//! < `true` < numbers < strings < objects; keys as [`crate::key::name_compare`]. Bounds
//! compare `(value, key)` pairs: a bound without a key name starts before every key of its
//! value (`startAt`, `endBefore`) or ends after all of them (`endAt`, `startAfter`).
//! `limitToFirst` keeps the first children of the range, `limitToLast` the last ones.

use crate::error::Result;
use crate::json::Json;
use crate::node::Node;
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
        todo!()
    }

    /// The children of `node` the query selects, in query order.
    pub fn run<'a>(&self, node: Option<&'a Node>) -> Vec<(&'a str, &'a Node)> {
        let _ = node;
        todo!()
    }
}
