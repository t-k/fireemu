//! The JSON value the adapters hand to the core and read back from it.

use std::collections::BTreeMap;

use crate::number::Number;

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A finite number.
    Number(Number),
    /// A string.
    String(String),
    /// An array; written arrays become objects keyed by index.
    Array(Vec<Json>),
    /// An object.
    Object(BTreeMap<String, Json>),
}

impl Json {
    /// An integer value.
    pub fn int(value: i64) -> Self {
        Self::Number(Number::Int(value))
    }

    /// A string value.
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    /// An object built from `(key, value)` pairs.
    pub fn object<K: Into<String>>(entries: impl IntoIterator<Item = (K, Json)>) -> Self {
        Self::Object(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}
