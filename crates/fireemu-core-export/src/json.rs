//! A minimal JSON writer for the export documents.
//!
//! `fireemu-core-types` parses JSON but does not write it, and a `fireemu-core-*` crate
//! takes no third-party dependency, so the export documents are serialized here. The output
//! is the two-space indented shape the official CLI writes (`JSON.stringify(value,
//! undefined, 2)`), because an export directory is something a person reads and diffs.
//!
//! Object members are written in the order they were inserted, so a document keeps the
//! member order the official emulator uses rather than an alphabetical one.

use std::fmt::Write as _;

use fireemu_core_types::json::JsonValue;

/// A JSON document being built. Members keep insertion order.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`.
    Null,
    /// A boolean.
    Bool(bool),
    /// A number written without a fraction.
    Int(i64),
    /// A number written with `serde_json`-compatible shortest round-trip formatting.
    Float(f64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object, in insertion order.
    Object(Vec<(String, Json)>),
}

impl Json {
    /// An empty object.
    #[must_use]
    pub fn object() -> Self {
        Self::Object(Vec::new())
    }

    /// Adds a member, replacing one of the same name in place.
    pub fn insert(&mut self, key: impl Into<String>, value: Json) {
        if let Self::Object(members) = self {
            let key = key.into();
            if let Some(slot) = members.iter_mut().find(|(k, _)| *k == key) {
                slot.1 = value;
            } else {
                members.push((key, value));
            }
        }
    }

    /// Adds a member when `value` is present.
    pub fn insert_some(&mut self, key: impl Into<String>, value: Option<Json>) {
        if let Some(value) = value {
            self.insert(key, value);
        }
    }

    /// A string member.
    #[must_use]
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    /// The same document as a parsed [`JsonValue`], so that a member this crate does not
    /// model can be carried through an import and written out again unchanged.
    #[must_use]
    pub fn from_value(value: &JsonValue) -> Self {
        match value {
            JsonValue::Null => Self::Null,
            JsonValue::Bool(b) => Self::Bool(*b),
            JsonValue::Int(i) => Self::Int(*i),
            JsonValue::Float(f) => Self::Float(*f),
            JsonValue::String(s) => Self::String(s.clone()),
            JsonValue::Array(items) => Self::Array(items.iter().map(Self::from_value).collect()),
            JsonValue::Object(members) => Self::Object(
                members
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::from_value(v)))
                    .collect(),
            ),
        }
    }

    /// The document as pretty-printed text with a trailing newline.
    #[must_use]
    pub fn to_pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, 0);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String, depth: usize) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(true) => out.push_str("true"),
            Self::Bool(false) => out.push_str("false"),
            Self::Int(i) => {
                let _ = write!(out, "{i}");
            }
            Self::Float(f) => out.push_str(&write_float(*f)),
            Self::String(s) => write_string(out, s),
            Self::Array(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    indent(out, depth + 1);
                    item.write(out, depth + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                indent(out, depth);
                out.push(']');
            }
            Self::Object(members) => {
                if members.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                for (i, (key, value)) in members.iter().enumerate() {
                    indent(out, depth + 1);
                    write_string(out, key);
                    out.push_str(": ");
                    value.write(out, depth + 1);
                    if i + 1 < members.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                indent(out, depth);
                out.push('}');
            }
        }
    }
}

fn indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

/// A finite double in the shortest form that reads back exactly. A non-finite one has no
/// JSON spelling and is written as `null`, exactly as `JSON.stringify` does.
fn write_float(value: f64) -> String {
    if !value.is_finite() {
        return "null".to_owned();
    }
    let mut text = format!("{value}");
    if text.ends_with(".0") {
        text.truncate(text.len() - 2);
    }
    text
}

fn write_string(out: &mut String, value: &str) {
    fireemu_core_types::codec::write_json_string(
        out,
        value,
        fireemu_core_types::codec::JsonControlEscape::Short,
    );
}

#[cfg(test)]
mod tests {
    use super::Json;

    #[test]
    fn an_object_keeps_the_order_its_members_were_inserted_in() {
        let mut doc = Json::object();
        doc.insert("version", Json::string("15.28.2"));
        doc.insert("auth", {
            let mut auth = Json::object();
            auth.insert("path", Json::string("auth_export"));
            auth
        });
        assert_eq!(
            doc.to_pretty(),
            "{\n  \"version\": \"15.28.2\",\n  \"auth\": {\n    \"path\": \"auth_export\"\n  }\n}\n"
        );
    }

    #[test]
    fn control_characters_and_quotes_are_escaped() {
        let doc = Json::string("a\"b\\c\nd\u{1}");
        assert_eq!(doc.to_pretty(), "\"a\\\"b\\\\c\\nd\\u0001\"\n");
    }

    #[test]
    fn an_empty_object_and_array_stay_on_one_line() {
        let mut doc = Json::object();
        doc.insert("empty", Json::object());
        doc.insert("none", Json::Array(Vec::new()));
        assert_eq!(doc.to_pretty(), "{\n  \"empty\": {},\n  \"none\": []\n}\n");
    }

    #[test]
    fn a_non_finite_double_is_written_as_null_like_json_stringify() {
        assert_eq!(Json::Float(f64::NAN).to_pretty(), "null\n");
        assert_eq!(Json::Float(1.5).to_pretty(), "1.5\n");
        assert_eq!(Json::Float(2.0).to_pretty(), "2\n");
    }
}
