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
    /// Whether `self` and `other` are written the same: the same structure, and numbers of
    /// the same kind and bits. `==` compares numbers by value, so `1 == 1.0` and
    /// `0.0 == -0.0`; here both pairs differ.
    pub fn same_form(&self, other: &Json) -> bool {
        match (self, other) {
            (Json::Null, Json::Null) => true,
            (Json::Bool(a), Json::Bool(b)) => a == b,
            (Json::Number(a), Json::Number(b)) => a.same_form(*b),
            (Json::String(a), Json::String(b)) => a == b,
            (Json::Array(a), Json::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.same_form(y))
            }
            (Json::Object(a), Json::Object(b)) => {
                a.len() == b.len()
                    && a.iter()
                        .zip(b)
                        .all(|((ka, va), (kb, vb))| ka == kb && va.same_form(vb))
            }
            _ => false,
        }
    }

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
