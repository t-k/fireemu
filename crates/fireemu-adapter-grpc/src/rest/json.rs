//! Firestore REST JSON <-> protobuf mapping (the documented proto3 JSON form of the
//! `google.firestore.v1` messages, restricted to what the local backend serves).

use std::collections::HashMap;

use fireemu_core_firestore::value::MAX_NESTING_DEPTH;
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use fireemu_proto_firestore::google::firestore::v1::structured_query as sq;
use serde_json::{json, Map, Value};

use crate::encode::{decode_instant, encode_instant};

/// A malformed JSON request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError(pub String);

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, JsonError> {
    Err(JsonError(msg.into()))
}

// ------------------------------------------------------------------------------------------
// base64 (standard alphabet, padded) — the proto3 JSON encoding of `bytes`
// ------------------------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
#[must_use]
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Standard or URL-safe base64, padding optional.
///
/// Padding, when present, must terminate the last quantum and have its complete
/// length. A single remaining sextet is truncated input, not an empty byte string.
pub fn base64_decode(text: &str) -> Result<Vec<u8>, JsonError> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut padding = 0u32;
    for c in text.bytes() {
        match c {
            b'\n' | b'\r' => continue,
            b'=' => {
                padding += 1;
                if padding > 2 {
                    return err("invalid base64");
                }
                continue;
            }
            _ if padding != 0 => return err("invalid base64"),
            _ => {}
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return err("invalid base64"),
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).unwrap_or(0));
        }
    }
    let expected_padding = match bits {
        0 => 0,
        2 => 1,
        4 => 2,
        _ => return err("invalid base64"),
    };
    if padding != 0 && padding != expected_padding {
        return err("invalid base64");
    }
    Ok(out)
}

/// `base64_decode` for a named request field, in production's wording.
///
/// Production names the request field, its proto type and the offending value rather than
/// reporting a bare decoder failure: `Invalid value at 'transaction' (TYPE_BYTES), Base64
/// decoding failed for "not base64!"` (conformance/firestore-production-matrix.json,
/// transactions/lifecycle, `commit-with-malformed-transaction`, recorded 2026-09-07). The
/// same recording names a field by its proto path in `snake_case`
/// (`writes[0].update.fields[0].value.bytes_value`), so `field` is a proto path, not the
/// JSON spelling. The value is quoted the way JSON quotes a string, which reproduces the
/// recorded text exactly and leaves a value containing a quote unambiguous.
pub fn base64_decode_field(field: &str, text: &str) -> Result<Vec<u8>, JsonError> {
    base64_decode(text).map_err(|_| {
        JsonError(format!(
            "Invalid value at '{field}' (TYPE_BYTES), Base64 decoding failed for {}",
            Value::String(text.to_owned())
        ))
    })
}

/// The proto path of the field a request value came from, built as the parser descends.
///
/// Production names a malformed value by its path in the request *message*, in proto
/// spelling, not by the JSON the client sent: `writes[0].update.fields[0].value.bytes_value`
/// for a bad `bytesValue` in the first write of a commit
/// (conformance/firestore-production-matrix.json, errors/rest-shapes, `write-bad-base64`,
/// recorded 2026-09-07). Repeated fields and map entries are indexed; every other segment is
/// the `snake_case` proto field name.
///
/// The path is a borrowed chain rather than a `String` so that descending costs nothing: it
/// is walked into text only when a value is actually refused.
#[derive(Clone, Copy)]
pub struct FieldPath<'a> {
    parent: Option<&'a FieldPath<'a>>,
    segment: Segment<'a>,
}

#[derive(Clone, Copy)]
enum Segment<'a> {
    /// One or more dot-joined proto field names.
    Field(&'a str),
    /// A repeated-field or map-entry position, rendered `[n]`.
    Index(usize),
}

impl<'a> FieldPath<'a> {
    /// The path of a top-level request field.
    #[must_use]
    pub const fn root(name: &'a str) -> Self {
        Self {
            parent: None,
            segment: Segment::Field(name),
        }
    }

    /// A field below this one. `name` may be dot-joined to add several segments at once.
    #[must_use]
    pub const fn field<'b>(&'b self, name: &'b str) -> FieldPath<'b> {
        FieldPath {
            parent: Some(self),
            segment: Segment::Field(name),
        }
    }

    /// A repeated-field or map-entry position below this one.
    #[must_use]
    pub const fn index(&self, at: usize) -> FieldPath<'_> {
        FieldPath {
            parent: Some(self),
            segment: Segment::Index(at),
        }
    }

    fn write_into(&self, out: &mut String) {
        if let Some(parent) = self.parent {
            parent.write_into(out);
        }
        match self.segment {
            Segment::Field(name) => {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(name);
            }
            Segment::Index(at) => {
                out.push('[');
                out.push_str(&at.to_string());
                out.push(']');
            }
        }
    }

    /// The path as production spells it.
    #[must_use]
    pub fn to_proto_path(&self) -> String {
        let mut out = String::new();
        self.write_into(&mut out);
        out
    }
}

// ------------------------------------------------------------------------------------------
// timestamps
// ------------------------------------------------------------------------------------------

/// RFC 3339 with the protobuf JSON fraction: none, three, six or nine digits, whichever
/// is the shortest exact rendering.
pub(crate) fn timestamp_to_json(t: &prost_types::Timestamp) -> Value {
    let full = decode_instant(t)
        .to_rfc3339()
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    Value::String(shorten_fraction(&full))
}

fn shorten_fraction(rfc3339: &str) -> String {
    let Some((head, fraction)) = rfc3339.strip_suffix('Z').and_then(|s| s.split_once('.')) else {
        return rfc3339.to_owned();
    };
    let trimmed = fraction.trim_end_matches('0');
    let digits = match trimmed.len() {
        0 => 0,
        1..=3 => 3,
        4..=6 => 6,
        _ => 9,
    };
    if digits == 0 {
        format!("{head}Z")
    } else {
        format!("{head}.{}Z", &fraction[..digits])
    }
}

/// Proto3 JSON leaves an unset or empty field out; this is the one place the rule is
/// applied to the request-level objects fireemu builds by hand.
pub fn without_empty(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.retain(|_, v| match v {
            Value::Array(items) => !items.is_empty(),
            Value::Object(fields) => !fields.is_empty(),
            Value::Null => false,
            _ => true,
        });
    }
    value
}

/// The keys a request object may carry; anything else is `Payload isn't valid for
/// request.`, which is what the official emulator answers for an unknown field or a second
/// member of a oneof.
pub fn strict_keys(v: &Value, allowed: &[&str]) -> Result<(), JsonError> {
    let Some(obj) = v.as_object() else {
        return err("Payload isn't valid for request.");
    };
    if obj.keys().any(|k| !allowed.contains(&k.as_str())) {
        return err("Payload isn't valid for request.");
    }
    Ok(())
}

fn struct_to_json(value: &prost_types::Struct) -> Value {
    Value::Object(
        value
            .fields
            .iter()
            .map(|(key, value)| (key.clone(), struct_value_to_json(value)))
            .collect(),
    )
}

fn struct_value_to_json(value: &prost_types::Value) -> Value {
    use prost_types::value::Kind;
    match &value.kind {
        Some(Kind::StringValue(value)) => Value::String(value.clone()),
        Some(Kind::NumberValue(value)) => serde_json::json!(value),
        Some(Kind::BoolValue(value)) => Value::Bool(*value),
        Some(Kind::StructValue(value)) => struct_to_json(value),
        Some(Kind::ListValue(value)) => {
            Value::Array(value.values.iter().map(struct_value_to_json).collect())
        }
        Some(Kind::NullValue(_)) | None => Value::Null,
    }
}

/// Serialize Explain's protobuf messages, including implicit-presence defaults and Struct values.
pub(crate) fn explain_metrics_to_json(metrics: &pb::ExplainMetrics) -> Value {
    let mut out = serde_json::json!({});
    if let Some(plan) = &metrics.plan_summary {
        out["planSummary"] = serde_json::json!({});
        if !plan.indexes_used.is_empty() {
            out["planSummary"]["indexesUsed"] =
                Value::Array(plan.indexes_used.iter().map(struct_to_json).collect());
        }
    }
    if let Some(stats) = &metrics.execution_stats {
        let mut execution = serde_json::json!({});
        if stats.results_returned != 0 {
            execution["resultsReturned"] = Value::String(stats.results_returned.to_string());
        }
        if stats.read_operations != 0 {
            execution["readOperations"] = Value::String(stats.read_operations.to_string());
        }
        if let Some(duration) = &stats.execution_duration {
            execution["executionDuration"] = Value::String(duration.to_string());
        }
        if let Some(debug) = &stats.debug_stats {
            execution["debugStats"] = struct_to_json(debug);
        }
        out["executionStats"] = execution;
    }
    out
}

/// Parses the finite local `ExplainOptions` contract.
pub fn explain_options_from_json(
    v: Option<&Value>,
) -> Result<Option<pb::ExplainOptions>, JsonError> {
    let Some(v) = v else { return Ok(None) };
    strict_keys(v, &["analyze"])?;
    let Some(analyze) = v.get("analyze") else {
        return Ok(Some(pb::ExplainOptions::default()));
    };
    let Some(analyze) = analyze.as_bool() else {
        return err("explainOptions.analyze must be a boolean");
    };
    Ok(Some(pb::ExplainOptions { analyze }))
}

#[cfg(test)]
mod explain_tests {
    use super::*;

    #[test]
    fn explain_options_accepts_only_boolean_analyze() {
        assert!(
            explain_options_from_json(Some(&json!({"analyze": true})))
                .unwrap()
                .unwrap()
                .analyze
        );
        assert!(explain_options_from_json(Some(&json!({"analyze": "true"}))).is_err());
        assert!(explain_options_from_json(Some(&json!({"unknown": false}))).is_err());
    }
}

/// Returns the first request key that is not part of the endpoint's accepted key set.
pub fn first_unknown_key<'a>(v: &'a Value, allowed: &[&str]) -> Option<&'a str> {
    v.as_object()?
        .keys()
        .find(|key| !allowed.contains(&key.as_str()))
        .map(String::as_str)
}

fn timestamp_from_json(v: &Value) -> Result<prost_types::Timestamp, JsonError> {
    let Some(s) = v.as_str() else {
        return err("timestamp must be an RFC 3339 string");
    };
    LogicalInstant::parse_rfc3339(s)
        .map(encode_instant)
        .map_err(|e| JsonError(format!("invalid timestamp {s:?}: {e}")))
}

// ------------------------------------------------------------------------------------------
// values and documents
// ------------------------------------------------------------------------------------------

/// Protobuf value → JSON.
#[must_use]
pub fn value_to_json(v: &pb::Value) -> Value {
    use pb::value::ValueType as V;
    match &v.value_type {
        // Pipeline expression values never come out of the local backend.
        None
        | Some(
            V::NullValue(_)
            | V::FieldReferenceValue(_)
            | V::VariableReferenceValue(_)
            | V::FunctionValue(_)
            | V::PipelineValue(_),
        ) => json!({"nullValue": null}),
        Some(V::BooleanValue(b)) => json!({"booleanValue": b}),
        Some(V::IntegerValue(i)) => json!({"integerValue": i.to_string()}),
        Some(V::DoubleValue(d)) => {
            if d.is_nan() {
                json!({"doubleValue": "NaN"})
            } else if d.is_infinite() {
                json!({"doubleValue": if *d > 0.0 { "Infinity" } else { "-Infinity" }})
            } else {
                json!({"doubleValue": d})
            }
        }
        Some(V::TimestampValue(t)) => json!({"timestampValue": timestamp_to_json(t)}),
        Some(V::StringValue(s)) => json!({"stringValue": s}),
        Some(V::BytesValue(b)) => json!({"bytesValue": base64_encode(b)}),
        Some(V::ReferenceValue(r)) => json!({"referenceValue": r}),
        Some(V::GeoPointValue(g)) => {
            json!({"geoPointValue": {"latitude": g.latitude, "longitude": g.longitude}})
        }
        Some(V::ArrayValue(a)) => {
            if a.values.is_empty() {
                json!({"arrayValue": {}})
            } else {
                json!({"arrayValue": {"values": a.values.iter().map(value_to_json).collect::<Vec<_>>()}})
            }
        }
        Some(V::MapValue(m)) => {
            if m.fields.is_empty() {
                json!({"mapValue": {}})
            } else {
                let fields: Map<String, Value> = m
                    .fields
                    .iter()
                    .map(|(k, v)| (k.clone(), value_to_json(v)))
                    .collect();
                json!({"mapValue": {"fields": fields}})
            }
        }
    }
}

/// JSON → protobuf value, for a position whose request field path is not established.
///
/// Query filters, cursors and `findNearest` reach this entry; production's own path form for
/// them is recorded for other value types (`structured_query.where.field_filter.value.
/// integer_value`) but not for a malformed `bytesValue`, and a nested composite filter has no
/// recording at all, so those refusals keep the bare decoder message rather than a guess.
pub fn value_from_json(v: &Value) -> Result<pb::Value, JsonError> {
    value_from_json_at(v, 0, None)
}

/// JSON → protobuf value, naming `path` if the value is refused.
pub fn value_from_json_in(v: &Value, path: &FieldPath<'_>) -> Result<pb::Value, JsonError> {
    value_from_json_at(v, 0, Some(path))
}

fn nested_depth(parent_depth: u32) -> Result<u32, JsonError> {
    let depth = parent_depth.saturating_add(1);
    if depth > MAX_NESTING_DEPTH {
        return err(format!(
            "FS-LIMIT-NESTED-MAP-ARRAY-DEPTH has maximum {MAX_NESTING_DEPTH}, got {depth}"
        ));
    }
    Ok(depth)
}

fn vector_map_from_json(
    inner: &Value,
    parent_depth: u32,
    path: Option<&FieldPath<'_>>,
) -> Result<Option<pb::MapValue>, JsonError> {
    let Some(fields) = inner.get("fields").and_then(Value::as_object) else {
        return Ok(None);
    };
    let Some(type_value) = fields.get("__type__").and_then(Value::as_object) else {
        return Ok(None);
    };
    let Some(array_value) = fields.get("value").and_then(Value::as_object) else {
        return Ok(None);
    };
    if fields.len() != 2
        || type_value.len() != 1
        || type_value.get("stringValue").and_then(Value::as_str) != Some("__vector__")
        || array_value.len() != 1
    {
        return Ok(None);
    }
    let Some(array) = array_value.get("arrayValue") else {
        return Ok(None);
    };
    if !array.is_object() {
        return err("arrayValue must be an object");
    }
    strict_keys(array, &["values"])?;
    // The two entries are held sorted, so `value` is the second; the vector's elements sit
    // under its `arrayValue`.
    let entry = path.map(|p| p.field("map_value.fields"));
    let entry = entry.as_ref().map(|p| p.index(1));
    let values_path = entry.as_ref().map(|p| p.field("value.array_value.values"));
    let values = match array.get("values") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(at, value)| {
                let element = values_path.as_ref().map(|p| p.index(at));
                value_from_json_at(value, parent_depth, element.as_ref())
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return err("arrayValue.values must be an array"),
    };
    Ok(Some(pb::MapValue {
        fields: HashMap::from([
            (
                "__type__".to_owned(),
                pb::Value {
                    value_type: Some(pb::value::ValueType::StringValue("__vector__".to_owned())),
                },
            ),
            (
                "value".to_owned(),
                pb::Value {
                    value_type: Some(pb::value::ValueType::ArrayValue(pb::ArrayValue { values })),
                },
            ),
        ]),
    }))
}

#[allow(clippy::too_many_lines)]
fn value_from_json_at(
    v: &Value,
    parent_depth: u32,
    path: Option<&FieldPath<'_>>,
) -> Result<pb::Value, JsonError> {
    use pb::value::ValueType as V;
    let Some(obj) = v.as_object() else {
        return err("a value must be an object with exactly one *Value key");
    };
    if obj.len() != 1 {
        return err("a value must have exactly one *Value key");
    }
    let (key, inner) = obj
        .iter()
        .next()
        .map_or(("", &Value::Null), |(k, v)| (k.as_str(), v));
    let value_type = match key {
        "nullValue" => {
            let valid = match inner {
                Value::Null => true,
                Value::String(name) => prost_types::NullValue::from_str_name(name).is_some(),
                Value::Number(number) => number.as_i64() == Some(0),
                _ => false,
            };
            if !valid {
                return err("nullValue must be null, a string, or an integer");
            }
            V::NullValue(0)
        }
        "booleanValue" => V::BooleanValue(
            inner
                .as_bool()
                .ok_or_else(|| JsonError("booleanValue must be a boolean".into()))?,
        ),
        "integerValue" => V::IntegerValue(match inner {
            Value::String(s) => s.parse::<i64>().map_err(|_| match path {
                Some(path) => JsonError(format!(
                    "Invalid value at '{}' (TYPE_INT64), {}",
                    path.field("integer_value").to_proto_path(),
                    Value::String(s.clone())
                )),
                None => JsonError(format!("integerValue {s:?} is not an int64")),
            })?,
            Value::Number(n) => n
                .as_i64()
                .ok_or_else(|| JsonError("integerValue must be an int64".into()))?,
            _ => return err("integerValue must be a string or number"),
        }),
        "doubleValue" => V::DoubleValue(match inner {
            Value::Number(n) => n
                .as_f64()
                .ok_or_else(|| JsonError("doubleValue must be a number".into()))?,
            Value::String(s) => match s.as_str() {
                "NaN" => f64::NAN,
                "Infinity" => f64::INFINITY,
                "-Infinity" => f64::NEG_INFINITY,
                _ => s
                    .parse::<f64>()
                    .map_err(|_| JsonError(format!("doubleValue {s:?} is not a number")))?,
            },
            _ => return err("doubleValue must be a number"),
        }),
        "timestampValue" => V::TimestampValue(timestamp_from_json(inner).map_err(|error| {
            match (path, inner.as_str()) {
                (Some(path), Some(text))
                    if !text.ends_with(['Z', 'z'])
                        && !text
                            .get(10..)
                            .is_some_and(|tail| tail.bytes().any(|byte| byte == b'+' || byte == b'-')) => JsonError(format!(
                    "Invalid value at '{}' (type.googleapis.com/google.protobuf.Timestamp), Field 'timestampValue', Illegal timestamp format; timestamps must end with 'Z' or have a valid timezone offset.",
                    path.field("timestamp_value").to_proto_path()
                )),
                _ => error,
            }
        })?),
        "stringValue" => V::StringValue(
            inner
                .as_str()
                .ok_or_else(|| JsonError("stringValue must be a string".into()))?
                .to_owned(),
        ),
        "bytesValue" => {
            let text = inner
                .as_str()
                .ok_or_else(|| JsonError("bytesValue must be a base64 string".into()))?;
            V::BytesValue(match path {
                Some(path) => {
                    base64_decode_field(&path.field("bytes_value").to_proto_path(), text)?
                }
                None => base64_decode(text)?,
            })
        }
        "referenceValue" => V::ReferenceValue(
            inner
                .as_str()
                .ok_or_else(|| JsonError("referenceValue must be a string".into()))?
                .to_owned(),
        ),
        "geoPointValue" => {
            let coordinate = |key: &str, range: f64| -> Result<f64, JsonError> {
                let v = inner
                    .get(key)
                    .and_then(Value::as_f64)
                    .ok_or_else(|| JsonError(format!("geoPointValue.{key} must be a number")))?;
                if !v.is_finite() || v.abs() > range {
                    return err(format!("geoPointValue.{key} out of range"));
                }
                Ok(v)
            };
            V::GeoPointValue(fireemu_proto_firestore::google::r#type::LatLng {
                latitude: coordinate("latitude", 90.0)?,
                longitude: coordinate("longitude", 180.0)?,
            })
        }
        "arrayValue" => {
            let values = path.map(|p| p.field("array_value.values"));
            V::ArrayValue(array_from_json(inner, parent_depth, values.as_ref())?)
        }
        "mapValue" => {
            if !inner.is_object() {
                return err("mapValue must be an object");
            }
            strict_keys(inner, &["fields"])?;
            if let Some(vector) = vector_map_from_json(inner, parent_depth, path)? {
                V::MapValue(vector)
            } else {
                let depth = nested_depth(parent_depth)?;
                let fields = path.map(|p| p.field("map_value.fields"));
                V::MapValue(pb::MapValue {
                    fields: fields_from_json_at(inner.get("fields"), depth, fields.as_ref())?,
                })
            }
        }
        other => match path {
            Some(path) => {
                return err(format!(
                    "Invalid JSON payload received. Unknown name {} at '{}': Cannot find field.",
                    Value::String(other.to_owned()),
                    path.to_proto_path()
                ));
            }
            None => return err(format!("unknown value key {other:?}")),
        },
    };
    Ok(pb::Value {
        value_type: Some(value_type),
    })
}

fn array_from_json(
    inner: &Value,
    parent_depth: u32,
    path: Option<&FieldPath<'_>>,
) -> Result<pb::ArrayValue, JsonError> {
    if !inner.is_object() {
        return err("arrayValue must be an object");
    }
    strict_keys(inner, &["values"])?;
    let depth = nested_depth(parent_depth)?;
    let values = match inner.get("values") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(at, value)| {
                let element = path.map(|p| p.index(at));
                value_from_json_at(value, depth, element.as_ref())
            })
            .collect::<Result<_, _>>()?,
        Some(Value::String(text)) => match path {
            Some(path) => {
                return err(format!(
                    "Invalid value at '{}' (type.googleapis.com/google.firestore.v1.Value), {}",
                    path.to_proto_path(),
                    Value::String(text.clone())
                ));
            }
            None => return err("arrayValue.values must be an array"),
        },
        Some(_) => return err("arrayValue.values must be an array"),
    };
    Ok(pb::ArrayValue { values })
}

/// `fields` object → protobuf map.
pub fn fields_from_json(v: Option<&Value>) -> Result<HashMap<String, pb::Value>, JsonError> {
    fields_from_json_at(v, 0, None)
}

/// `path` names the `fields` map itself; each entry is `[n].value` below it, the way
/// production spells a map entry.
fn fields_from_json_at(
    v: Option<&Value>,
    parent_depth: u32,
    path: Option<&FieldPath<'_>>,
) -> Result<HashMap<String, pb::Value>, JsonError> {
    let mut out = HashMap::new();
    let Some(v) = v.filter(|value| !value.is_null()) else {
        return Ok(out);
    };
    let Some(obj) = v.as_object() else {
        return err("fields must be an object");
    };
    for (at, (k, v)) in obj.iter().enumerate() {
        let entry = path.map(|p| p.index(at));
        let entry = entry.as_ref().map(|p| p.field("value"));
        let value = value_from_json_at(v, parent_depth, entry.as_ref()).map_err(|error| {
            if parent_depth == 0 && error.0.starts_with("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH ") {
                JsonError(format!("{}; property={k}", error.0))
            } else {
                error
            }
        })?;
        out.insert(k.clone(), value);
    }
    Ok(out)
}

/// Protobuf document → JSON.
#[must_use]
pub fn document_to_json(d: &pb::Document) -> Value {
    let fields: Map<String, Value> = d
        .fields
        .iter()
        .map(|(k, v)| (k.clone(), value_to_json(v)))
        .collect();
    let mut out = json!({"name": d.name});
    if !fields.is_empty() {
        out["fields"] = Value::Object(fields);
    }
    if let Some(t) = &d.create_time {
        out["createTime"] = timestamp_to_json(t);
    }
    if let Some(t) = &d.update_time {
        out["updateTime"] = timestamp_to_json(t);
    }
    out
}

/// JSON → protobuf document (`name` may be absent for create).
///
/// `path` is the document's own field in the request that carries it: `writes[0].update` in
/// a commit, `document` on the document routes.
pub fn document_from_json(v: &Value, path: &FieldPath<'_>) -> Result<pb::Document, JsonError> {
    if !v.is_object() {
        return err("document must be an object");
    }
    let fields = path.field("fields");
    Ok(pb::Document {
        name: v
            .get("name")
            .filter(|value| !value.is_null())
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| JsonError("document.name must be a string".into()))
            })
            .transpose()?
            .unwrap_or_default()
            .to_owned(),
        fields: fields_from_json_at(v.get("fields"), 0, Some(&fields))?,
        create_time: None,
        update_time: None,
    })
}

// ------------------------------------------------------------------------------------------
// masks, preconditions, writes
// ------------------------------------------------------------------------------------------

/// `{"fieldPaths": [...]}` → mask.
pub fn mask_from_json(v: Option<&Value>) -> Result<Option<pb::DocumentMask>, JsonError> {
    let Some(v) = v.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    strict_keys(v, &["fieldPaths"])?;
    let field_paths = match v.get("fieldPaths") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(paths)) => paths
            .iter()
            .map(|p| {
                p.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| JsonError("field paths must be strings".into()))
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return err("mask.fieldPaths must be an array"),
    };
    Ok(Some(pb::DocumentMask { field_paths }))
}

/// Mask from repeated query parameters.
#[must_use]
pub fn mask_from_paths(paths: &[String]) -> Option<pb::DocumentMask> {
    if paths.is_empty() {
        None
    } else {
        Some(pb::DocumentMask {
            field_paths: paths.to_vec(),
        })
    }
}

/// `{"exists": bool}` / `{"updateTime": ts}` → precondition.
pub fn precondition_from_json(v: Option<&Value>) -> Result<Option<pb::Precondition>, JsonError> {
    let Some(v) = v.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    strict_keys(v, &["exists", "updateTime"])?;
    // ProtoJSON null leaves a oneof member unset. Keep false as a present
    // exists condition, and keep an empty enclosing Precondition present so
    // the backend's existing empty-condition validation is not bypassed.
    let exists = v.get("exists").filter(|value| !value.is_null());
    let update_time = v.get("updateTime").filter(|value| !value.is_null());
    if exists.is_some() && update_time.is_some() {
        // A oneof carries one member.
        return err("Payload isn't valid for request.");
    }
    let condition_type = if let Some(e) = exists {
        Some(pb::precondition::ConditionType::Exists(
            e.as_bool()
                .ok_or_else(|| JsonError("currentDocument.exists must be a boolean".into()))?,
        ))
    } else if let Some(t) = update_time {
        Some(pb::precondition::ConditionType::UpdateTime(
            timestamp_from_json(t)?,
        ))
    } else {
        None
    };
    Ok(Some(pb::Precondition { condition_type }))
}

fn transform_from_json(
    v: &Value,
    path: &FieldPath<'_>,
) -> Result<pb::document_transform::FieldTransform, JsonError> {
    use pb::document_transform::field_transform::TransformType as T;
    let field_path = v
        .get("fieldPath")
        .and_then(Value::as_str)
        .ok_or_else(|| JsonError("fieldTransform.fieldPath is required".into()))?
        .to_owned();
    let array = |key: &str, proto: &str| -> Result<pb::ArrayValue, JsonError> {
        let Some(inner) = v.get(key).filter(|value| !value.is_null()) else {
            return Ok(pb::ArrayValue::default());
        };
        if !inner.is_object() {
            return err(format!("{key} must be an object"));
        }
        strict_keys(inner, &["values"])?;
        let proto = path.field(proto);
        let values_path = proto.field("values");
        Ok(pb::ArrayValue {
            values: match inner.get("values") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(items)) => items
                    .iter()
                    .enumerate()
                    .map(|(at, value)| value_from_json_in(value, &values_path.index(at)))
                    .collect::<Result<_, _>>()?,
                Some(_) => return err(format!("{key}.values must be an array")),
            },
        })
    };
    let operation_count = [
        "setToServerValue",
        "increment",
        "maximum",
        "minimum",
        "appendMissingElements",
        "removeAllFromArray",
    ]
    .iter()
    .filter(|key| v.get(**key).is_some_and(|value| !value.is_null()))
    .count();
    if operation_count > 1 {
        return err("Payload isn't valid for request.");
    }
    let transform_type =
        if let Some(sv) = v.get("setToServerValue").filter(|value| !value.is_null()) {
            let server_value = match sv {
                Value::String(name) => {
                    pb::document_transform::field_transform::ServerValue::from_str_name(name)
                }
                Value::Number(number) => number
                    .as_i64()
                    .and_then(|number| i32::try_from(number).ok())
                    .and_then(|number| {
                        pb::document_transform::field_transform::ServerValue::try_from(number).ok()
                    }),
                _ => return err("setToServerValue must be a string or enum number"),
            };
            T::SetToServerValue(
                server_value
                    .map(|value| value as i32)
                    .ok_or_else(|| JsonError("unknown setToServerValue".into()))?,
            )
        } else if let Some(x) = v.get("increment").filter(|value| !value.is_null()) {
            T::Increment(value_from_json_in(x, &path.field("increment"))?)
        } else if let Some(x) = v.get("maximum").filter(|value| !value.is_null()) {
            T::Maximum(value_from_json_in(x, &path.field("maximum"))?)
        } else if let Some(x) = v.get("minimum").filter(|value| !value.is_null()) {
            T::Minimum(value_from_json_in(x, &path.field("minimum"))?)
        } else if v
            .get("appendMissingElements")
            .is_some_and(|value| !value.is_null())
        {
            T::AppendMissingElements(array("appendMissingElements", "append_missing_elements")?)
        } else if v
            .get("removeAllFromArray")
            .is_some_and(|value| !value.is_null())
        {
            T::RemoveAllFromArray(array("removeAllFromArray", "remove_all_from_array")?)
        } else {
            return err("fieldTransform without a transform");
        };
    Ok(pb::document_transform::FieldTransform {
        field_path,
        transform_type: Some(transform_type),
    })
}

/// JSON → write.
///
/// `path` is the write's own position in the request that carries it, `writes[n]`.
pub fn write_from_json(v: &Value, path: &FieldPath<'_>) -> Result<pb::Write, JsonError> {
    strict_keys(
        v,
        &[
            "update",
            "delete",
            "verify",
            "transform",
            "updateMask",
            "updateTransforms",
            "currentDocument",
        ],
    )?;
    let operation_count = ["update", "delete", "verify", "transform"]
        .iter()
        .filter(|k| v.get(**k).is_some_and(|value| !value.is_null()))
        .count();
    if operation_count > 1 {
        // A oneof carries one member.
        return err("Payload isn't valid for request.");
    }
    let operation = if let Some(d) = v.get("update").filter(|value| !value.is_null()) {
        Some(pb::write::Operation::Update(document_from_json(
            d,
            &path.field("update"),
        )?))
    } else if let Some(n) = v.get("delete").filter(|value| !value.is_null()) {
        Some(pb::write::Operation::Delete(
            n.as_str()
                .ok_or_else(|| JsonError("delete must be a document name".into()))?
                .to_owned(),
        ))
    } else if let Some(n) = v.get("verify").filter(|value| !value.is_null()) {
        Some(pb::write::Operation::Verify(
            n.as_str()
                .ok_or_else(|| JsonError("verify must be a document name".into()))?
                .to_owned(),
        ))
    } else if let Some(t) = v.get("transform").filter(|value| !value.is_null()) {
        if !t.is_object() {
            return err("transform must be an object");
        }
        strict_keys(t, &["document", "fieldTransforms"])?;
        Some(pb::write::Operation::Transform(pb::DocumentTransform {
            document: t
                .get("document")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            field_transforms: match t.get("fieldTransforms") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(items)) => {
                    let transforms = path.field("transform.field_transforms");
                    items
                        .iter()
                        .enumerate()
                        .map(|(at, item)| transform_from_json(item, &transforms.index(at)))
                        .collect::<Result<_, _>>()?
                }
                Some(_) => return err("fieldTransforms must be an array"),
            },
        }))
    } else {
        None
    };
    Ok(pb::Write {
        update_mask: mask_from_json(v.get("updateMask"))?,
        update_transforms: match v.get("updateTransforms") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => {
                let transforms = path.field("update_transforms");
                items
                    .iter()
                    .enumerate()
                    .map(|(at, item)| transform_from_json(item, &transforms.index(at)))
                    .collect::<Result<_, _>>()?
            }
            Some(_) => return err("updateTransforms must be an array"),
        },
        current_document: precondition_from_json(v.get("currentDocument"))?,
        operation,
    })
}

/// JSON writes for `BatchWrite`.
///
/// An empty write object is retained as a default protobuf write so the backend can report a
/// row-local invalid-operation status. Other operation-less objects remain malformed payloads.
pub fn batch_writes_from_json(items: &[Value]) -> Result<Vec<pb::Write>, JsonError> {
    let path = FieldPath::root("writes");
    items
        .iter()
        .enumerate()
        .map(|(at, item)| {
            if item.as_object().is_some_and(serde_json::Map::is_empty) {
                Ok(pb::Write::default())
            } else {
                write_from_json(item, &path.index(at))
            }
        })
        .collect()
}

/// Write result → JSON.
#[must_use]
pub fn write_result_to_json(w: &pb::WriteResult) -> Value {
    let mut out = json!({
        "transformResults": w.transform_results.iter().map(value_to_json).collect::<Vec<_>>(),
    });
    if let Some(t) = &w.update_time {
        out["updateTime"] = timestamp_to_json(t);
    }
    without_empty(out)
}

/// Commit response → JSON. A commit without writes answers `{}`: no write results, and no
/// commit time either, which is what the official emulator answers for it.
#[must_use]
pub fn commit_to_json(c: &pb::CommitResponse) -> Value {
    let mut out = json!({
        "writeResults": c.write_results.iter().map(write_result_to_json).collect::<Vec<_>>(),
    });
    if let (Some(t), false) = (&c.commit_time, c.write_results.is_empty()) {
        out["commitTime"] = timestamp_to_json(t);
    }
    without_empty(out)
}

// ------------------------------------------------------------------------------------------
// structured queries
// ------------------------------------------------------------------------------------------

fn field_reference(v: Option<&Value>) -> Result<Option<sq::FieldReference>, JsonError> {
    let Some(v) = v else { return Ok(None) };
    Ok(Some(sq::FieldReference {
        field_path: v
            .get("fieldPath")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonError("field.fieldPath is required".into()))?
            .to_owned(),
    }))
}

fn field_operator(value: Option<&Value>) -> Result<i32, JsonError> {
    use sq::field_filter::Operator as O;
    // An absent operator is the proto default. An unknown enum number passes through as it
    // does on the wire: the query decoder refuses both as production does.
    let Some(value) = value else {
        return Ok(O::Unspecified as i32);
    };
    let operator = match value {
        Value::String(name) => O::from_str_name(name).map(|operator| operator as i32),
        Value::Number(number) => number
            .as_i64()
            .and_then(|number| i32::try_from(number).ok()),
        _ => return err("fieldFilter.op must be a string or enum number"),
    };
    operator.ok_or_else(|| JsonError("unknown field filter operator".into()))
}

/// An enum given by number passes through as it does on the wire; the query decoder refuses an
/// unknown one in production's words, for REST and gRPC alike.
fn enum_number(number: &serde_json::Number, what: &str) -> Result<i32, JsonError> {
    number
        .as_i64()
        .and_then(|number| i32::try_from(number).ok())
        .ok_or_else(|| JsonError(format!("{what} must be a string or enum number")))
}

fn unary_operator(value: Option<&Value>) -> Result<i32, JsonError> {
    use sq::unary_filter::Operator as O;
    // An absent operator is the proto default; the query decoder refuses it as production does.
    let Some(value) = value else {
        return Ok(O::Unspecified as i32);
    };
    match value {
        Value::String(name) => O::from_str_name(name)
            .map(|operator| operator as i32)
            .ok_or_else(|| JsonError("unknown unary filter operator".into())),
        Value::Number(number) => enum_number(number, "unaryFilter.op"),
        _ => err("unaryFilter.op must be a string or enum number"),
    }
}

fn filter_from_json(v: &Value) -> Result<sq::Filter, JsonError> {
    let filter_type = if let Some(c) = v.get("compositeFilter") {
        if !c.is_object() {
            return err("compositeFilter must be an object");
        }
        let op = match c.get("op") {
            Some(Value::String(name)) => sq::composite_filter::Operator::from_str_name(name)
                .ok_or_else(|| JsonError("unknown composite filter operator".into()))?
                as i32,
            Some(Value::Number(number)) => enum_number(number, "compositeFilter.op")?,
            Some(_) => return err("compositeFilter.op must be a string or enum number"),
            None => sq::composite_filter::Operator::Unspecified as i32,
        };
        sq::filter::FilterType::CompositeFilter(sq::CompositeFilter {
            op,
            filters: match c.get("filters") {
                None | Some(Value::Null) => Vec::new(),
                Some(filters) => filters
                    .as_array()
                    .ok_or_else(|| JsonError("compositeFilter.filters must be an array".into()))?
                    .iter()
                    .map(filter_from_json)
                    .collect::<Result<_, _>>()?,
            },
        })
    } else if let Some(f) = v.get("fieldFilter") {
        sq::filter::FilterType::FieldFilter(sq::FieldFilter {
            field: field_reference(f.get("field"))?,
            op: field_operator(f.get("op"))?,
            value: f.get("value").map(value_from_json).transpose()?,
        })
    } else if let Some(u) = v.get("unaryFilter") {
        sq::filter::FilterType::UnaryFilter(sq::UnaryFilter {
            op: unary_operator(u.get("op"))?,
            operand_type: field_reference(u.get("field"))?
                .map(sq::unary_filter::OperandType::Field),
        })
    } else {
        // No filter type set: the query decoder refuses it as production does.
        return Ok(sq::Filter { filter_type: None });
    };
    Ok(sq::Filter {
        filter_type: Some(filter_type),
    })
}

fn cursor_from_json(v: Option<&Value>) -> Result<Option<pb::Cursor>, JsonError> {
    let Some(v) = v else { return Ok(None) };
    if v.is_null() {
        return Ok(None);
    }
    let Some(v) = v.as_object() else {
        return err("cursor must be an object");
    };
    let values = match v.get("values") {
        None | Some(Value::Null) => Vec::new(),
        Some(values) => values
            .as_array()
            .ok_or_else(|| JsonError("cursor.values must be an array".into()))?
            .iter()
            .map(value_from_json)
            .collect::<Result<_, _>>()?,
    };
    let before = match v.get("before") {
        None | Some(Value::Null) => false,
        Some(before) => before
            .as_bool()
            .ok_or_else(|| JsonError("cursor.before must be a boolean".into()))?,
    };
    Ok(Some(pb::Cursor { values, before }))
}

/// Int32 from a JSON number, numeric string or `{"value": n}` wrapper.
pub fn int32(v: Option<&Value>, what: &str) -> Result<Option<i32>, JsonError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_i64()
            .and_then(|i| i32::try_from(i).ok())
            .map(Some)
            .ok_or_else(|| JsonError(format!("{what} must be an int32"))),
        Some(Value::String(s)) => s
            .parse::<i32>()
            .map(Some)
            .map_err(|_| JsonError(format!("{what} must be an int32"))),
        Some(Value::Object(o)) => int32(o.get("value"), what),
        Some(_) => err(format!("{what} must be an int32")),
    }
}

/// Parses the optional server request options object. Tags are currently accepted for wire
/// compatibility and intentionally have no local execution effect.
pub fn request_options_from_json(
    v: Option<&Value>,
) -> Result<Option<pb::RequestOptions>, JsonError> {
    let Some(v) = v else { return Ok(None) };
    if v.is_null() {
        return Ok(None);
    }
    strict_keys(v, &["requestTags"])?;
    let request_tags = match v.get("requestTags") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| JsonError("requestOptions.requestTags must be strings".into()))
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return err("requestOptions.requestTags must be an array"),
    };
    Ok(Some(pb::RequestOptions { request_tags }))
}

fn find_nearest_from_json(raw: &Value) -> Result<pb::structured_query::FindNearest, JsonError> {
    strict_keys(
        raw,
        &[
            "vectorField",
            "queryVector",
            "distanceMeasure",
            "limit",
            "distanceResultField",
            "distanceThreshold",
        ],
    )?;
    // Absent members are proto defaults; the query decoder refuses them as production does.
    let vector_field = field_reference(raw.get("vectorField"))?;
    let query_vector = raw.get("queryVector").map(value_from_json).transpose()?;
    let distance_measure = match raw.get("distanceMeasure") {
        Some(Value::String(name)) => sq::find_nearest::DistanceMeasure::from_str_name(name)
            .ok_or_else(|| JsonError("unknown distance measure".into()))?
            as i32,
        Some(Value::Number(number)) => enum_number(number, "findNearest.distanceMeasure")?,
        None => sq::find_nearest::DistanceMeasure::Unspecified as i32,
        Some(_) => return err("findNearest.distanceMeasure must be a string or enum number"),
    };
    let limit = int32(raw.get("limit"), "findNearest.limit")?;
    let distance_result_field = raw
        .get("distanceResultField")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| JsonError("findNearest.distanceResultField must be a string".into()))
                .map(str::to_owned)
        })
        .transpose()?
        .unwrap_or_default();
    let distance_threshold = raw
        .get("distanceThreshold")
        .map(|value| {
            // proto3 JSON spells non-finite doubles as strings.
            match value {
                Value::String(text) => match text.as_str() {
                    "NaN" => Some(f64::NAN),
                    "Infinity" => Some(f64::INFINITY),
                    "-Infinity" => Some(f64::NEG_INFINITY),
                    other => other.parse::<f64>().ok(),
                },
                other => other.as_f64(),
            }
            .ok_or_else(|| JsonError("findNearest.distanceThreshold must be a number".into()))
        })
        .transpose()?;
    Ok(pb::structured_query::FindNearest {
        vector_field,
        query_vector,
        distance_measure: distance_measure as i32,
        limit,
        distance_result_field,
        distance_threshold,
    })
}

/// JSON → structured query.
#[allow(clippy::too_many_lines)]
pub fn structured_query_from_json(v: &Value) -> Result<pb::StructuredQuery, JsonError> {
    if !v.is_object() {
        return err("structuredQuery must be an object");
    }
    let from = v
        .get("from")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| JsonError("from must be an array".into()))
        })
        .transpose()?
        .map(|items| {
            items
                .iter()
                .map(|f| {
                    if !f.is_object() {
                        return err("from elements must be objects");
                    }
                    Ok(sq::CollectionSelector {
                        collection_id: match f.get("collectionId") {
                            None | Some(Value::Null) => String::new(),
                            Some(value) => value
                                .as_str()
                                .ok_or_else(|| {
                                    JsonError("from.collectionId must be a string".into())
                                })?
                                .to_owned(),
                        },
                        all_descendants: match f.get("allDescendants") {
                            None | Some(Value::Null) => false,
                            Some(value) => value.as_bool().ok_or_else(|| {
                                JsonError("from.allDescendants must be a boolean".into())
                            })?,
                        },
                    })
                })
                .collect::<Result<Vec<_>, JsonError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let order_by = v
        .get("orderBy")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| JsonError("orderBy must be an array".into()))
        })
        .transpose()?
        .map(|items| {
            items
                .iter()
                .map(|o| {
                    if !o.is_object() {
                        return err("orderBy elements must be objects");
                    }
                    let direction = match o.get("direction") {
                        None | Some(Value::Null) => sq::Direction::Ascending,
                        Some(value) => match value.as_str() {
                            Some("ASCENDING" | "DIRECTION_UNSPECIFIED") => sq::Direction::Ascending,
                            Some("DESCENDING") => sq::Direction::Descending,
                            Some(other) => {
                                return err(format!("unknown order direction {other:?}"))
                            }
                            None => match value.as_i64() {
                                Some(0 | 1) => sq::Direction::Ascending,
                                Some(2) => sq::Direction::Descending,
                                Some(other) => {
                                    return err(format!("unknown order direction {other}"))
                                }
                                None => {
                                    return err("orderBy.direction must be a string or enum number")
                                }
                            },
                        },
                    };
                    Ok(sq::Order {
                        field: field_reference(o.get("field"))?,
                        direction: direction as i32,
                    })
                })
                .collect::<Result<Vec<_>, JsonError>>()
        })
        .transpose()?
        .unwrap_or_default();
    let select = match v.get("select") {
        None | Some(Value::Null) => None,
        Some(s) => {
            let Some(s) = s.as_object() else {
                return err("select must be an object");
            };
            let fields = match s.get("fields") {
                None | Some(Value::Null) => Vec::new(),
                Some(fields) => fields
                    .as_array()
                    .ok_or_else(|| JsonError("select.fields must be an array".into()))?
                    .iter()
                    .map(|f| field_reference(Some(f)).map(Option::unwrap_or_default))
                    .collect::<Result<Vec<_>, _>>()?,
            };
            Some(sq::Projection { fields })
        }
    };
    let find_nearest = v
        .get("findNearest")
        .filter(|value| !value.is_null())
        .map(find_nearest_from_json)
        .transpose()?;
    Ok(pb::StructuredQuery {
        select,
        from,
        r#where: v
            .get("where")
            .filter(|value| !value.is_null())
            .map(filter_from_json)
            .transpose()?,
        order_by,
        start_at: cursor_from_json(v.get("startAt"))?,
        end_at: cursor_from_json(v.get("endAt"))?,
        offset: int32(v.get("offset"), "offset")?.unwrap_or(0),
        limit: int32(v.get("limit"), "limit")?,
        find_nearest,
    })
}

/// A wrapper message's value as fireemu read it before (`int32`): `{"value": ...}` unwrapped at
/// any depth, an empty wrapper as null.
fn unwrap_wrapper(mut value: &Value) -> &Value {
    while let Value::Object(wrapper) = value {
        value = wrapper.get("value").unwrap_or(&Value::Null);
    }
    value
}

/// JSON → aggregation query.
pub fn aggregation_query_from_json(v: &Value) -> Result<pb::StructuredAggregationQuery, JsonError> {
    use pb::structured_aggregation_query::aggregation as agg;
    let aggregations = match v.get("aggregations") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|a| {
                let operator = if let Some(c) = a.get("count") {
                    Some(agg::Operator::Count(agg::Count {
                        // `upTo` is an Int64Value (the transcoder spells it as a string). Its
                        // wrapper message form is read as fireemu read it before:
                        // `{"value": ...}` at any depth, and an empty wrapper as no cap. The
                        // strict transcoder admits only the plain `{"value": n}` form.
                        up_to: match c.get("upTo").map(unwrap_wrapper) {
                            None | Some(Value::Null) => None,
                            Some(Value::String(text)) => Some(
                                text.parse::<i64>()
                                    .map_err(|_| JsonError("count.upTo must be an int64".into()))?,
                            ),
                            Some(value) => {
                                Some(value.as_i64().ok_or_else(|| {
                                    JsonError("count.upTo must be an int64".into())
                                })?)
                            }
                        },
                    }))
                } else if let Some(s) = a.get("sum") {
                    Some(agg::Operator::Sum(agg::Sum {
                        field: field_reference(s.get("field"))?,
                    }))
                } else if let Some(s) = a.get("avg") {
                    Some(agg::Operator::Avg(agg::Avg {
                        field: field_reference(s.get("field"))?,
                    }))
                } else {
                    // No operator: the aggregation decoder refuses it as production does.
                    None
                };
                Ok(pb::structured_aggregation_query::Aggregation {
                    alias: a
                        .get("alias")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    operator,
                })
            })
            .collect::<Result<Vec<_>, JsonError>>(),
        Some(_) => return err("aggregations must be an array"),
    }?;
    let query_type = v
        .get("structuredQuery")
        .map(structured_query_from_json)
        .transpose()?
        .map(pb::structured_aggregation_query::QueryType::StructuredQuery);
    Ok(pb::StructuredAggregationQuery {
        aggregations,
        query_type,
    })
}

/// Transaction options JSON (`{"readOnly": {}}` / `{"readWrite": {}}`). A
/// `readOnly.readTime` is carried through so the backend can refuse it explicitly;
/// `readWrite.retryTransaction` is accepted (retries start a fresh transaction here).
///
/// `field` is the proto path of the options message within the request that carries it
/// (`options` on `BeginTransaction`, `new_transaction` on the read requests), so a refusal
/// names the field production would name.
pub fn transaction_options_from_json(
    v: Option<&Value>,
    field: &str,
) -> Result<pb::TransactionOptions, JsonError> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(pb::TransactionOptions::default());
    };
    strict_keys(v, &["readOnly", "readWrite"])?;
    let read_only = v.get("readOnly").filter(|value| !value.is_null());
    let read_write = v.get("readWrite").filter(|value| !value.is_null());
    if read_only.is_some() && read_write.is_some() {
        return err("readOnly and readWrite are mutually exclusive");
    }
    let mode = match (read_only, read_write) {
        (Some(read_only), None) => {
            strict_keys(read_only, &["readTime"])?;
            let read_time = read_only
                .get("readTime")
                .filter(|value| !value.is_null())
                .map(timestamp_from_json)
                .transpose()?;
            Some(pb::transaction_options::Mode::ReadOnly(
                pb::transaction_options::ReadOnly {
                    consistency_selector: read_time
                        .map(pb::transaction_options::read_only::ConsistencySelector::ReadTime),
                },
            ))
        }
        (None, Some(read_write)) => {
            strict_keys(read_write, &["retryTransaction", "concurrencyMode"])?;
            let retry = match read_write
                .get("retryTransaction")
                .filter(|value| !value.is_null())
            {
                Some(value) => value
                    .as_str()
                    .ok_or_else(|| JsonError("readWrite.retryTransaction must be a string".into()))
                    .and_then(|text| {
                        base64_decode_field(&format!("{field}.read_write.retry_transaction"), text)
                    })?,
                None => Vec::new(),
            };
            let concurrency_mode = match read_write
                .get("concurrencyMode")
                .filter(|value| !value.is_null())
            {
                None => 0,
                Some(Value::String(value)) => {
                    pb::transaction_options::ConcurrencyMode::from_str_name(value)
                        .map(|mode| mode as i32)
                        .ok_or_else(|| {
                            JsonError("readWrite.concurrencyMode must be a valid enum".into())
                        })?
                }
                Some(Value::Number(value)) => {
                    let value = value
                        .as_i64()
                        .and_then(|value| i32::try_from(value).ok())
                        .ok_or_else(|| {
                            JsonError("readWrite.concurrencyMode must be a valid enum".into())
                        })?;
                    pb::transaction_options::ConcurrencyMode::try_from(value)
                        .map(|mode| mode as i32)
                        .map_err(|_| {
                            JsonError("readWrite.concurrencyMode must be a valid enum".into())
                        })?
                }
                Some(_) => return err("readWrite.concurrencyMode must be a string or integer"),
            };
            Some(pb::transaction_options::Mode::ReadWrite(
                pb::transaction_options::ReadWrite {
                    retry_transaction: retry,
                    concurrency_mode,
                },
            ))
        }
        _ => None,
    };
    Ok(pb::TransactionOptions { mode })
}

/// `readTime` consistency selector value, if the request carries one.
pub fn read_time_from_json(v: &Value) -> Result<Option<prost_types::Timestamp>, JsonError> {
    v.get("readTime")
        .filter(|value| !value.is_null())
        .map(timestamp_from_json)
        .transpose()
}

/// Optional RFC 3339 timestamp field → JSON (used for `readTime` / `commitTime`).
#[must_use]
pub fn optional_timestamp_to_json(t: Option<&prost_types::Timestamp>) -> Value {
    t.map_or(Value::Null, timestamp_to_json)
}

// ------------------------------------------------------------------------------------------
// Listen / Write stream messages (WebChannel carries their proto3 JSON form)
// ------------------------------------------------------------------------------------------

/// JSON → `ListenRequest`.
#[allow(clippy::too_many_lines)]
pub fn listen_request_from_json(v: &Value) -> Result<pb::ListenRequest, JsonError> {
    if !v.is_object() {
        return err("ListenRequest must be an object");
    }
    strict_keys(
        v,
        &[
            "database",
            "labels",
            "requestOptions",
            "addTarget",
            "removeTarget",
        ],
    )?;
    let add_target = v.get("addTarget").filter(|value| !value.is_null());
    let remove_target = v.get("removeTarget").filter(|value| !value.is_null());
    if add_target.is_some() && remove_target.is_some() {
        return err("Payload isn't valid for request.");
    }
    let target_change = if let Some(t) = add_target {
        if !t.is_object() {
            return err("addTarget must be an object");
        }
        strict_keys(
            t,
            &[
                "targetId",
                "once",
                "expectedCount",
                "query",
                "documents",
                "resumeToken",
                "readTime",
            ],
        )?;
        let query = t.get("query").filter(|value| !value.is_null());
        let documents = t.get("documents").filter(|value| !value.is_null());
        if query.is_some() && documents.is_some() {
            return err("Payload isn't valid for request.");
        }
        let target_type = if let Some(q) = query {
            if !q.is_object() {
                return err("query must be an object");
            }
            strict_keys(q, &["parent", "structuredQuery"])?;
            Some(pb::target::TargetType::Query(pb::target::QueryTarget {
                parent: q
                    .get("parent")
                    .filter(|value| !value.is_null())
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| JsonError("query.parent must be a string".into()))
                            .map(str::to_owned)
                    })
                    .transpose()?
                    .unwrap_or_default(),
                query_type: q
                    .get("structuredQuery")
                    .filter(|value| !value.is_null())
                    .map(structured_query_from_json)
                    .transpose()?
                    .map(pb::target::query_target::QueryType::StructuredQuery),
            }))
        } else if let Some(d) = documents {
            if !d.is_object() {
                return err("documents must be an object");
            }
            strict_keys(d, &["documents"])?;
            let documents = match d.get("documents") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(items)) => items
                    .iter()
                    .enumerate()
                    .map(|(index, value)| {
                        value.as_str().map(str::to_owned).ok_or_else(|| {
                            JsonError(format!("documents[{index}] must be a string"))
                        })
                    })
                    .collect::<Result<_, _>>()?,
                Some(_) => return err("documents must be an array"),
            };
            Some(pb::target::TargetType::Documents(
                pb::target::DocumentsTarget { documents },
            ))
        } else {
            None
        };
        let resume_token = t.get("resumeToken").filter(|value| !value.is_null());
        let read_time = t.get("readTime").filter(|value| !value.is_null());
        if resume_token.is_some() && read_time.is_some() {
            return err("Payload isn't valid for request.");
        }
        let resume_type = if let Some(token) = resume_token {
            Some(pb::target::ResumeType::ResumeToken(base64_decode(
                token
                    .as_str()
                    .ok_or_else(|| JsonError("resumeToken must be a base64 string".into()))?,
            )?))
        } else if let Some(rt) = read_time {
            Some(pb::target::ResumeType::ReadTime(timestamp_from_json(rt)?))
        } else {
            None
        };
        Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
            target_id: int32(t.get("targetId"), "targetId")?.unwrap_or(0),
            once: t
                .get("once")
                .filter(|value| !value.is_null())
                .map(|value| {
                    value
                        .as_bool()
                        .ok_or_else(|| JsonError("once must be a boolean".into()))
                })
                .transpose()?
                .unwrap_or(false),
            expected_count: int32(t.get("expectedCount"), "expectedCount")?,
            target_type,
            resume_type,
        }))
    } else if let Some(id) = remove_target {
        Some(pb::listen_request::TargetChange::RemoveTarget(
            int32(Some(id), "removeTarget")?.unwrap_or(0),
        ))
    } else {
        None
    };
    Ok(pb::ListenRequest {
        database: v
            .get("database")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        labels: HashMap::new(),
        request_options: None,
        target_change,
    })
}

/// JSON → `WriteRequest`.
pub fn write_request_from_json(v: &Value) -> Result<pb::WriteRequest, JsonError> {
    if !v.is_object() {
        return err("WriteRequest must be an object");
    }
    strict_keys(
        v,
        &[
            "database",
            "streamId",
            "writes",
            "streamToken",
            "labels",
            "requestOptions",
        ],
    )?;
    let writes = match v.get("writes") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => {
            let path = FieldPath::root("writes");
            items
                .iter()
                .enumerate()
                .map(|(at, item)| write_from_json(item, &path.index(at)))
                .collect::<Result<_, _>>()?
        }
        Some(_) => return err("writes must be an array"),
    };
    Ok(pb::WriteRequest {
        database: v
            .get("database")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        stream_id: v
            .get("streamId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        writes,
        stream_token: match v.get("streamToken").and_then(Value::as_str) {
            Some(t) => base64_decode(t)?,
            None => Vec::new(),
        },
        labels: HashMap::new(),
        request_options: None,
    })
}

fn target_change_type_name(t: i32) -> &'static str {
    match pb::target_change::TargetChangeType::try_from(t) {
        Ok(pb::target_change::TargetChangeType::Add) => "ADD",
        Ok(pb::target_change::TargetChangeType::Remove) => "REMOVE",
        Ok(pb::target_change::TargetChangeType::Current) => "CURRENT",
        Ok(pb::target_change::TargetChangeType::Reset) => "RESET",
        _ => "NO_CHANGE",
    }
}

/// `ListenResponse` → JSON.
#[must_use]
pub fn listen_response_to_json(r: &pb::ListenResponse) -> Value {
    use pb::listen_response::ResponseType as R;
    match &r.response_type {
        Some(R::TargetChange(t)) => {
            let mut v = json!({
                "targetChange": {
                    "targetChangeType": target_change_type_name(t.target_change_type),
                    "targetIds": t.target_ids,
                }
            });
            if !t.resume_token.is_empty() {
                v["targetChange"]["resumeToken"] = Value::String(base64_encode(&t.resume_token));
            }
            if let Some(rt) = &t.read_time {
                v["targetChange"]["readTime"] = timestamp_to_json(rt);
            }
            if let Some(c) = &t.cause {
                v["targetChange"]["cause"] = json!({"code": c.code, "message": c.message});
            }
            v
        }
        Some(R::DocumentChange(d)) => json!({
            "documentChange": {
                "document": d.document.as_ref().map(document_to_json),
                "targetIds": d.target_ids,
                "removedTargetIds": d.removed_target_ids,
            }
        }),
        Some(R::DocumentDelete(d)) => json!({
            "documentDelete": {
                "document": d.document,
                "removedTargetIds": d.removed_target_ids,
                "readTime": optional_timestamp_to_json(d.read_time.as_ref()),
            }
        }),
        Some(R::DocumentRemove(d)) => json!({
            "documentRemove": {
                "document": d.document,
                "removedTargetIds": d.removed_target_ids,
                "readTime": optional_timestamp_to_json(d.read_time.as_ref()),
            }
        }),
        Some(R::Filter(f)) => json!({"filter": {"targetId": f.target_id, "count": f.count}}),
        None => json!({}),
    }
}

/// `WriteResponse` → JSON.
#[must_use]
pub fn write_response_to_json(r: &pb::WriteResponse) -> Value {
    let mut v = json!({
        "streamToken": base64_encode(&r.stream_token),
        "writeResults": r.write_results.iter().map(write_result_to_json).collect::<Vec<_>>(),
    });
    if !r.stream_id.is_empty() {
        v["streamId"] = Value::String(r.stream_id.clone());
    }
    if let Some(t) = &r.commit_time {
        v["commitTime"] = timestamp_to_json(t);
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These unit tests predate the request field path and do not assert one; they parse a
    /// write as the first write of a commit.
    fn write_from_json_for_test(v: &Value) -> Result<pb::Write, JsonError> {
        let writes = FieldPath::root("writes");
        write_from_json(v, &writes.index(0))
    }

    fn nested_map(levels: u32) -> Value {
        let mut value = json!({"integerValue": "1"});
        for _ in 0..levels {
            value = json!({"mapValue": {"fields": {"nested": value}}});
        }
        value
    }

    fn nested_map_with_vector(levels: u32) -> Value {
        let mut value = json!({
            "mapValue": {
                "fields": {
                    "__type__": {"stringValue": "__vector__"},
                    "value": {"arrayValue": {"values": [{"doubleValue": 1.0}]}}
                }
            }
        });
        for _ in 0..levels {
            value = json!({"mapValue": {"fields": {"nested": value}}});
        }
        value
    }

    #[test]
    fn json_value_decoder_stops_at_the_firestore_depth_limit() {
        assert!(value_from_json(&nested_map(MAX_NESTING_DEPTH)).is_ok());
        let error = value_from_json(&nested_map(MAX_NESTING_DEPTH + 1))
            .expect_err("one level past the limit is rejected");
        assert!(error.0.contains("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH"));
    }

    #[test]
    fn json_vector_sentinel_has_the_same_leaf_depth_as_grpc() {
        assert!(value_from_json(&nested_map_with_vector(MAX_NESTING_DEPTH)).is_ok());
        let error = value_from_json(&nested_map_with_vector(MAX_NESTING_DEPTH + 1))
            .expect_err("one enclosing map past the limit is rejected");
        assert!(error.0.contains("FS-LIMIT-NESTED-MAP-ARRAY-DEPTH"));
    }

    #[test]
    fn structured_query_json_decodes_find_nearest() {
        let query = structured_query_from_json(&json!({
            "from": [{"collectionId": "items"}],
            "findNearest": {
                "vectorField": {"fieldPath": "embedding"},
                "queryVector": {"mapValue": {"fields": {
                    "__type__": {"stringValue": "__vector__"},
                    "value": {"arrayValue": {"values": [{"doubleValue": 1.0}]}}
                }}},
                "distanceMeasure": "COSINE",
                "limit": 2,
                "distanceResultField": "distance",
                "distanceThreshold": 0.5
            }
        }))
        .unwrap();
        let nearest = query.find_nearest.unwrap();
        assert_eq!(
            nearest.distance_measure,
            sq::find_nearest::DistanceMeasure::Cosine as i32
        );
        assert_eq!(nearest.limit, Some(2));
        assert_eq!(nearest.distance_result_field, "distance");
        assert_eq!(nearest.distance_threshold, Some(0.5));
        assert!(query_vector_is_vector(
            nearest.query_vector.as_ref().unwrap()
        ));
    }

    #[test]
    fn structured_query_rejects_non_array_from_and_order_by() {
        for (field, value) in [("from", json!("items")), ("orderBy", json!({}))] {
            let error = structured_query_from_json(&json!({field: value}))
                .expect_err("a present query list must be an array");
            assert!(error.0.contains(&format!("{field} must be an array")));
        }
        for (field, value) in [("from", json!([null])), ("orderBy", json!([1]))] {
            let error = structured_query_from_json(&json!({field: value}))
                .expect_err("a query list element must be an object");
            assert!(error
                .0
                .contains(&format!("{field} elements must be objects")));
        }
    }

    #[test]
    fn protojson_value_messages_reject_scalar_container_payloads() {
        for key in ["arrayValue", "mapValue"] {
            let error = value_from_json(&json!({key: 1}))
                .expect_err("a message field must not coerce a scalar to its default");
            assert!(error.0.contains("must be an object"), "{key}: {error:?}");
        }
        let error = value_from_json(&json!({"nullValue": {"invalid": true}}))
            .expect_err("NullValue is an enum and cannot consume an object");
        assert!(error
            .0
            .contains("nullValue must be null, a string, or an integer"));
    }

    #[test]
    fn malformed_batch_write_integer_reports_the_production_proto_field_path() {
        let writes = FieldPath::root("writes");
        let error = write_from_json(
            &json!({
                "update": {
                    "name": "projects/demo/databases/(default)/documents/items/one",
                    "fields": {"v": {"integerValue": "not-a-number"}}
                }
            }),
            &writes.index(1),
        )
        .expect_err("invalid int64 is refused before a BatchWrite is applied");
        assert_eq!(
            error.0,
            "Invalid value at 'writes[1].update.fields[0].value.integer_value' (TYPE_INT64), \"not-a-number\""
        );
        assert_eq!(
            value_from_json(&json!({"integerValue": "not-a-number"}))
                .expect_err("unscoped parser still reports its local error")
                .0,
            "integerValue \"not-a-number\" is not an int64"
        );
    }

    #[test]
    fn malformed_batch_write_integer_quotes_control_characters_as_json() {
        let writes = FieldPath::root("writes");
        let invalid = format!("no{}", '\u{1f}');
        let error = write_from_json(
            &json!({
                "update": {
                    "name": "projects/demo/databases/(default)/documents/items/one",
                    "fields": {"v": {"integerValue": invalid}}
                }
            }),
            &writes.index(1),
        )
        .expect_err("invalid int64 is refused before a BatchWrite is applied");
        assert_eq!(
            error.0,
            "Invalid value at 'writes[1].update.fields[0].value.integer_value' (TYPE_INT64), \"no\\u001f\""
        );
    }

    #[test]
    fn protojson_query_enums_accept_numeric_wire_values() {
        let query = structured_query_from_json(&json!({
            "where": {
                "compositeFilter": {
                    "op": 1,
                    "filters": [{
                        "fieldFilter": {
                            "field": {"fieldPath": "value"},
                            "op": 5,
                            "value": {"integerValue": "1"}
                        }
                    }]
                }
            },
            "orderBy": [{"field": {"fieldPath": "value"}, "direction": 2}]
        }))
        .expect("numeric enum values use the protobuf wire numbers");
        let Some(sq::filter::FilterType::CompositeFilter(composite)) =
            query.r#where.and_then(|filter| filter.filter_type)
        else {
            panic!("expected composite filter");
        };
        assert_eq!(composite.op, 1);
        let Some(sq::filter::FilterType::FieldFilter(field)) = composite
            .filters
            .into_iter()
            .next()
            .and_then(|filter| filter.filter_type)
        else {
            panic!("expected field filter");
        };
        assert_eq!(field.op, 5);
        assert_eq!(query.order_by[0].direction, 2);

        let nearest = structured_query_from_json(&json!({
            "findNearest": {
                "vectorField": {"fieldPath": "embedding"},
                "queryVector": {"arrayValue": {"values": [{"doubleValue": 1.0}]}},
                "distanceMeasure": 1,
                "limit": 1
            }
        }))
        .expect("numeric distance enum values use the protobuf wire numbers");
        assert_eq!(nearest.find_nearest.unwrap().distance_measure, 1);

        let write = write_from_json_for_test(&json!({
            "transform": {
                "document": "projects/demo/databases/(default)/documents/items/one",
                "fieldTransforms": [{
                    "fieldPath": "updated",
                    "setToServerValue": 1
                }]
            }
        }))
        .expect("numeric server enum values use the protobuf wire numbers");
        assert!(matches!(
            write.operation,
            Some(pb::write::Operation::Transform(transform))
                if matches!(
                    transform.field_transforms[0].transform_type,
                    Some(
                        pb::document_transform::field_transform::TransformType::SetToServerValue(1)
                    )
                )
        ));
    }

    #[test]
    fn protojson_repeated_fields_reject_non_arrays() {
        let request_error = write_request_from_json(&json!("not-an-object"))
            .expect_err("WriteRequest is a message and must be an object");
        assert!(request_error.0.contains("WriteRequest must be an object"));

        let write_error = write_request_from_json(&json!({"writes": "not-an-array"}))
            .expect_err("WriteRequest.writes is repeated and must be an array");
        assert!(write_error.0.contains("writes must be an array"));

        let listen_error = listen_request_from_json(&json!({
            "addTarget": {"documents": {"documents": "not-an-array"}}
        }))
        .expect_err("DocumentsTarget.documents is repeated and must be an array");
        assert!(listen_error.0.contains("documents must be an array"));

        let listen_message_error = listen_request_from_json(&json!({
            "addTarget": {"documents": "not-an-object"}
        }))
        .expect_err("DocumentsTarget is a message and must be an object");
        assert!(listen_message_error
            .0
            .contains("documents must be an object"));

        let listen = listen_request_from_json(&json!({
            "addTarget": null,
            "removeTarget": null
        }))
        .expect("null oneof members are unset");
        assert!(listen.target_change.is_none());

        let transform_error = write_from_json_for_test(&json!({
            "update": {"name": "projects/demo/databases/(default)/documents/items/one"},
            "updateTransforms": "not-an-array"
        }))
        .expect_err("Write.updateTransforms is repeated and must be an array");
        assert!(transform_error
            .0
            .contains("updateTransforms must be an array"));

        let transform_message_error = write_from_json_for_test(&json!({
            "transform": "not-an-object"
        }))
        .expect_err("DocumentTransform is a message and must be an object");
        assert!(transform_message_error
            .0
            .contains("transform must be an object"));

        let field_transform_error = write_from_json_for_test(&json!({
            "transform": {
                "document": "projects/demo/databases/(default)/documents/items/one",
                "fieldTransforms": "not-an-array"
            }
        }))
        .expect_err("DocumentTransform.fieldTransforms is repeated and must be an array");
        assert!(field_transform_error
            .0
            .contains("fieldTransforms must be an array"));

        let mask = mask_from_json(Some(&json!({"fieldPaths": null})))
            .expect("a null repeated field is treated as an empty list");
        assert!(mask
            .expect("the mask message is present")
            .field_paths
            .is_empty());

        let value_error = value_from_json(&json!({
            "arrayValue": {"values": "not-an-array"}
        }))
        .expect_err("ArrayValue.values is repeated and must be an array");
        assert!(value_error.0.contains("arrayValue.values must be an array"));

        let aggregation_error = aggregation_query_from_json(&json!({
            "aggregations": "not-an-array"
        }))
        .expect_err("StructuredAggregationQuery.aggregations is repeated and must be an array");
        assert!(aggregation_error
            .0
            .contains("aggregations must be an array"));

        let write = write_from_json_for_test(&json!({
            "transform": {
                "document": "projects/demo/databases/(default)/documents/items/one",
                "fieldTransforms": [{
                    "fieldPath": "value",
                    "setToServerValue": null,
                    "increment": {"integerValue": "1"}
                }]
            }
        }))
        .expect("a null oneof member is unset when another member is present");
        assert!(matches!(
            write.operation,
            Some(pb::write::Operation::Transform(transform))
                if matches!(
                    transform.field_transforms[0].transform_type,
                    Some(
                        pb::document_transform::field_transform::TransformType::Increment(_)
                    )
                )
        ));
    }

    fn query_vector_is_vector(value: &pb::Value) -> bool {
        matches!(
            &value.value_type,
            Some(pb::value::ValueType::MapValue(map)) if map.fields.contains_key("__type__")
        )
    }
}
