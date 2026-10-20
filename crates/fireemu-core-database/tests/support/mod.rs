//! Test helpers: `serde_json` values to and from the core's [`Json`].

#![allow(dead_code)]

use fireemu_core_database::{Json, Limits, Number, Path, ServerValueContext, Tree};

/// The core JSON for a `serde_json` value.
pub fn j(value: serde_json::Value) -> Json {
    match value {
        serde_json::Value::Null => Json::Null,
        serde_json::Value::Bool(b) => Json::Bool(b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Json::Number(Number::Int(i)),
            None => Json::Number(Number::from_f64(n.as_f64().unwrap()).unwrap()),
        },
        serde_json::Value::String(s) => Json::String(s),
        serde_json::Value::Array(items) => Json::Array(items.into_iter().map(j).collect()),
        serde_json::Value::Object(map) => {
            Json::Object(map.into_iter().map(|(k, v)| (k, j(v))).collect())
        }
    }
}

/// The `serde_json` value for core JSON.
pub fn s(value: &Json) -> serde_json::Value {
    match value {
        Json::Null => serde_json::Value::Null,
        Json::Bool(b) => serde_json::Value::Bool(*b),
        Json::Number(Number::Int(i)) => serde_json::Value::from(*i),
        Json::Number(Number::Double(d)) => serde_json::Value::from(*d),
        Json::String(s) => serde_json::Value::String(s.clone()),
        Json::Array(items) => serde_json::Value::Array(items.iter().map(s).collect()),
        Json::Object(map) => {
            serde_json::Value::Object(map.iter().map(|(k, v)| (k.clone(), s(v))).collect())
        }
    }
}

/// A validated path.
pub fn p(path: &str) -> Path {
    Path::parse(path, &Limits::default()).unwrap()
}

/// The server time the tests use.
pub const NOW: ServerValueContext = ServerValueContext {
    now_millis: 1_760_000_000_000,
};

/// A tree holding `value` at the root.
pub fn tree_with(value: serde_json::Value) -> Tree {
    let mut tree = Tree::new(Limits::default());
    tree.set(&Path::root(), &j(value), NOW).unwrap();
    tree
}
