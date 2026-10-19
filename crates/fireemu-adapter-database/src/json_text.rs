//! JSON text of request bodies and answers.
//!
//! Answers follow the official emulator's rendering: keys in the server's key order (the
//! SDK `nameCompare`, which also places `.priority`), doubles in Java `Double.toString` form,
//! children whose keys are dense array indexes as arrays, and Jackson's pretty layout for
//! `print=pretty`.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use fireemu_core_database::key::name_compare;
use fireemu_core_database::node::VALUE_KEY;
use fireemu_core_database::path::PRIORITY_KEY;
use fireemu_core_database::{Content, Format, Json, Leaf, Node, Number, Path, Priority, Tree};

/// The layout of rendered JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    /// No whitespace (the default answer).
    Compact,
    /// `print=pretty`.
    Pretty,
}

pub use crate::json_parse::ParseError;

/// Parses one JSON value. Integers that fit an i64 stay integers; other numbers become the
/// correctly rounded double of their text (and integral doubles integers, see
/// [`Number::from_f64`]).
pub fn parse(text: &str) -> Result<Json, ParseError> {
    crate::json_parse::parse(text)
}

/// The answer JSON for a node (`null` when absent), with dense integer-keyed children as
/// arrays. A node that carries its own priority stays an object in the export format.
pub fn output_json(node: Option<&Node>, format: Format) -> Json {
    let Some(node) = node else {
        return Json::Null;
    };
    let priority = match format {
        Format::Plain => None,
        Format::Export => node.priority.as_ref(),
    };
    match &node.content {
        Content::Leaf(leaf) => {
            let value = leaf_json(leaf);
            match priority {
                None => value,
                Some(p) => {
                    Json::object([(VALUE_KEY, value), (PRIORITY_KEY, priority_json(p, true))])
                }
            }
        }
        Content::Children(children) => {
            if priority.is_none() {
                if let Some(length) = array_length(children) {
                    let mut items = vec![Json::Null; length];
                    for (key, child) in children {
                        // `array_length` checked that every key is an index below `length`.
                        let index: usize = key.parse().unwrap_or(0);
                        items[index] = output_json(Some(child), format);
                    }
                    return Json::Array(items);
                }
            }
            let mut map: BTreeMap<String, Json> = children
                .iter()
                .map(|(k, child)| (k.clone(), output_json(Some(child), format)))
                .collect();
            if let Some(p) = priority {
                map.insert(PRIORITY_KEY.to_owned(), priority_json(p, false));
            }
            Json::Object(map)
        }
    }
}

fn leaf_json(leaf: &Leaf) -> Json {
    match leaf {
        Leaf::Bool(b) => Json::Bool(*b),
        Leaf::Number(n) => Json::Number(*n),
        Leaf::String(s) => Json::String(s.clone()),
    }
}

/// The realtime protocol's JSON for a node: the export form without array conversion
/// (the official emulator answers `{"0":"a","1":"b"}` there), `null` when absent.
pub fn wire_json(node: Option<&Node>) -> Json {
    let Some(node) = node else {
        return Json::Null;
    };
    let value = match &node.content {
        Content::Leaf(leaf) => leaf_json(leaf),
        Content::Children(children) => Json::Object(
            children
                .iter()
                .map(|(k, child)| (k.clone(), wire_json(Some(child))))
                .collect(),
        ),
    };
    match (&node.priority, value) {
        (None, value) => value,
        (Some(p), Json::Object(mut map)) => {
            map.insert(PRIORITY_KEY.to_owned(), priority_json(p, false));
            Json::Object(map)
        }
        (Some(p), leaf) => {
            Json::object([(VALUE_KEY, leaf), (PRIORITY_KEY, priority_json(p, true))])
        }
    }
}

/// The array length children render as: every key is a canonical index (`0` or a digit
/// string without a leading zero) and the largest is below twice the number of children,
/// the rule of the SDK's `val()`.
fn array_length(children: &BTreeMap<String, Node>) -> Option<usize> {
    let mut max = 0usize;
    for key in children.keys() {
        let canonical =
            key == "0" || (!key.starts_with('0') && key.bytes().all(|b| b.is_ascii_digit()));
        if !canonical || key.is_empty() {
            return None;
        }
        max = max.max(key.parse().ok()?);
    }
    (max < 2 * children.len()).then_some(max + 1)
}

/// The value a write to `path` reports in its events and data messages: the node's, or
/// for a `<location>/.priority` path the priority as it was written.
pub fn value_at(tree: &Tree, path: &Path) -> Json {
    if path.is_priority() {
        written_priority_at(tree, path)
    } else {
        wire_json(tree.get(path))
    }
}

/// A priority as answer JSON. Numbers keep the type the core stored (ledger 1475): a
/// `.priority` member is a double, a priority written to `<location>/.priority` keeps its
/// parsed type. The official emulator stores a leaf's priority as a double, so an integer
/// priority of a leaf reads as one (`5.0`).
fn priority_json(priority: &Priority, leaf: bool) -> Json {
    match priority {
        #[allow(clippy::cast_precision_loss)]
        Priority::Number(Number::Int(int)) if leaf => Json::Number(Number::Double(*int as f64)),
        other => other.to_json(),
    }
}

/// The answer for reading a `<location>/.priority` path: the priority of the location,
/// `null` when it has none.
pub fn priority_at(tree: &Tree, path: &Path) -> Json {
    let parent = path.parent().unwrap_or_default();
    tree.get(&parent).map_or(Json::Null, |node| {
        let leaf = matches!(node.content, Content::Leaf(_));
        node.priority
            .as_ref()
            .map_or(Json::Null, |priority| priority_json(priority, leaf))
    })
}

/// The priority at a `<location>/.priority` path as it was written: the official emulator
/// answers a write and notifies it with the written value, even on a leaf.
pub fn written_priority_at(tree: &Tree, path: &Path) -> Json {
    let parent = path.parent().unwrap_or_default();
    tree.get(&parent)
        .and_then(|node| node.priority.as_ref())
        .map_or(Json::Null, Priority::to_json)
}

/// Writes a number: integers as digits, doubles in Java's form (ledger 1475).
fn write_number(out: &mut String, number: Number) {
    match number {
        Number::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Number::Double(d) => out.push_str(&java_double(d)),
    }
}

/// Renders JSON text.
pub fn render(json: &Json, style: Style) -> String {
    let mut out = String::new();
    write_json(&mut out, json, style, 0);
    out
}

fn write_json(out: &mut String, json: &Json, style: Style, objects_above: usize) {
    match json {
        Json::Null => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Number(number) => write_number(out, *number),
        Json::String(s) => write_string(out, s),
        Json::Array(items) => write_array(out, items, style, objects_above),
        Json::Object(map) => write_object(out, map, style, objects_above),
    }
}

fn write_string(out: &mut String, s: &str) {
    // serde_json escapes exactly what Jackson escapes: quote, backslash and control
    // characters, as short escapes where they exist and \u00XX otherwise.
    out.push_str(&serde_json::to_string(s).unwrap_or_default());
}

fn write_array(out: &mut String, items: &[Json], style: Style, objects_above: usize) {
    match style {
        Style::Compact => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(out, item, style, objects_above);
            }
            out.push(']');
        }
        // Jackson keeps arrays on one line and does not indent for them.
        Style::Pretty if items.is_empty() => out.push_str("[ ]"),
        Style::Pretty => {
            out.push_str("[ ");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_json(out, item, style, objects_above);
            }
            out.push_str(" ]");
        }
    }
}

fn write_object(
    out: &mut String,
    map: &BTreeMap<String, Json>,
    style: Style,
    objects_above: usize,
) {
    let mut entries: Vec<(&String, &Json)> = map.iter().collect();
    // A prioritized leaf is written `.value` first, as the server writes it.
    entries.sort_by(|(a, _), (b, _)| {
        (a.as_str() != VALUE_KEY)
            .cmp(&(b.as_str() != VALUE_KEY))
            .then_with(|| name_compare(a, b))
    });
    match style {
        Style::Compact => {
            out.push('{');
            for (i, (key, value)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_json(out, value, style, objects_above + 1);
            }
            out.push('}');
        }
        Style::Pretty if entries.is_empty() => out.push_str("{ }"),
        Style::Pretty => {
            out.push('{');
            let inner = "  ".repeat(objects_above + 1);
            for (i, (key, value)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('\n');
                out.push_str(&inner);
                write_string(out, key);
                out.push_str(" : ");
                write_json(out, value, style, objects_above + 1);
            }
            out.push('\n');
            out.push_str(&"  ".repeat(objects_above));
            out.push('}');
        }
    }
}

/// A double as Java's `Double.toString` writes it: the shortest digits that read back to
/// the same double, in plain notation for magnitudes in [10^-3, 10^7) and as `d.dddE±n`
/// otherwise, always with a digit after the point.
pub fn java_double(value: f64) -> String {
    // The core holds only finite numbers; the text for anything else is Java's.
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value < 0.0 { "-Infinity" } else { "Infinity" }.to_owned();
    }
    if value == 0.0 {
        return if value.is_sign_negative() {
            "-0.0"
        } else {
            "0.0"
        }
        .to_owned();
    }
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let sign = if value < 0.0 { "-" } else { "" };
    let magnitude = value.abs();
    if (1e-3..1e7).contains(&magnitude) {
        if exponent >= 0 {
            let point = usize::try_from(exponent).unwrap_or(0) + 1;
            let whole: String = if digits.len() > point {
                digits[..point].to_owned()
            } else {
                format!("{digits}{}", "0".repeat(point - digits.len()))
            };
            let fraction = if digits.len() > point {
                &digits[point..]
            } else {
                "0"
            };
            format!("{sign}{whole}.{fraction}")
        } else {
            let zeros = usize::try_from(-exponent - 1).unwrap_or(0);
            format!("{sign}0.{}{digits}", "0".repeat(zeros))
        }
    } else {
        let fraction = if digits.len() > 1 { &digits[1..] } else { "0" };
        format!("{sign}{}.{fraction}E{exponent}", &digits[..1])
    }
}
