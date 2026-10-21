//! JSON mapping of `ExecutePipelineRequest` and `ExecutePipelineResponse` for the REST
//! `:executePipeline` route. Pipeline expression values (`fieldReferenceValue`,
//! `functionValue`, `pipelineValue`, `variableReferenceValue`) are decoded here only, so the
//! document and query routes keep refusing them through [`super::json::value_from_json`].

/// The deepest expression tree a REST pipeline body may hold: the JSON grammar's own nesting
/// bound. A literal's 20-level limit is the compiler's (the official emulator counts it from the
/// literal, not from the stage that holds it).
const MAX_EXPRESSION_DEPTH: u32 = 100;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use serde_json::{json, Map, Value};

use super::json::{
    base64_decode, base64_encode, read_time_from_json, strict_keys, timestamp_to_json,
    transaction_options_from_json, value_from_json, value_to_json, JsonError,
};

fn err<T>(message: impl Into<String>) -> Result<T, JsonError> {
    Err(JsonError(message.into()))
}

/// The keys an `ExecutePipelineRequest` body may carry.
const REQUEST_KEYS: &[&str] = &[
    "database",
    "structuredPipeline",
    "transaction",
    "newTransaction",
    "readTime",
    "autoCommitTransaction",
    // Accepted and ignored: request tags change nothing local.
    "requestOptions",
];

/// The bytes the official emulator 1.22.0 reads from a `bytesValue`, or `None` when it refuses
/// the body (`Payload isn't valid for request.`; review r10 ruling, table
/// conformance/fs-ent-pipeline-base64.json): every trailing `=` is dropped, then the rest must use
/// one alphabet (standard `+/` or URL-safe `-_`, never both), hold no other character (no line
/// break, space, `=` or anything else) and not leave a lone sextet (length mod 4 is not 1). Bits
/// past the last whole byte are ignored, as the official decoder ignores them.
pub fn official_base64(text: &str) -> Option<Vec<u8>> {
    let body = text.trim_end_matches('=');
    let standard = body.contains(['+', '/']);
    let url_safe = body.contains(['-', '_']);
    if (standard && url_safe) || body.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in body.bytes() {
        let sextet = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(sextet);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).unwrap_or(0));
        }
    }
    Some(out)
}

/// An `:executePipeline` body (its field names already normalized by the transcoder, so
/// `bytes_value` reads as `bytesValue`) with every `bytesValue` decoded as the official emulator
/// decodes it and written back as canonical base64, or `Err` when one is base64 the official
/// emulator refuses. Production is unrecorded for these forms, so only this method reads bytes
/// this way; the other methods keep the shared decoder (see
/// docs.local/issues/open/rest-base64-skips-line-breaks-outside-execute-pipeline.md).
pub fn official_bytes(body: &Value) -> Result<Value, ()> {
    match body {
        Value::Object(object) => object
            .iter()
            .map(|(key, inner)| {
                let value = match (key.as_str(), inner) {
                    ("bytesValue", Value::String(text)) => Value::String(
                        super::json::base64_encode(&official_base64(text).ok_or(())?),
                    ),
                    _ => official_bytes(inner)?,
                };
                Ok((key.clone(), value))
            })
            .collect::<Result<Map<String, Value>, ()>>()
            .map(Value::Object),
        Value::Array(values) => values
            .iter()
            .map(official_bytes)
            .collect::<Result<Vec<_>, ()>>()
            .map(Value::Array),
        other => Ok(other.clone()),
    }
}

/// JSON → `ExecutePipelineRequest`. `database` is the URL-bound database; a body
/// `database` must name the same one.
pub fn request_from_json(
    database: &str,
    body: &Value,
) -> Result<pb::ExecutePipelineRequest, JsonError> {
    strict_keys(body, REQUEST_KEYS)?;
    match body.get("database") {
        None | Some(Value::Null) => {}
        Some(Value::String(named)) if named == database => {}
        Some(_) => {
            return err(format!(
                "database must be {database:?}, the database the URL names"
            ))
        }
    }
    let pipeline_type = match body.get("structuredPipeline").filter(|v| !v.is_null()) {
        None => None,
        Some(structured) => Some(
            pb::execute_pipeline_request::PipelineType::StructuredPipeline(
                structured_pipeline_from_json(structured)?,
            ),
        ),
    };
    let given = ["transaction", "newTransaction", "readTime"]
        .iter()
        .filter(|key| body.get(**key).is_some_and(|v| !v.is_null()))
        .count();
    if given > 1 {
        return err("transaction, newTransaction and readTime are mutually exclusive");
    }
    let consistency_selector = if let Some(transaction) =
        body.get("transaction").filter(|v| !v.is_null())
    {
        let Some(text) = transaction.as_str() else {
            return err("transaction must be a base64 string");
        };
        Some(pb::execute_pipeline_request::ConsistencySelector::Transaction(base64_decode(text)?))
    } else if let Some(options) = body.get("newTransaction").filter(|v| !v.is_null()) {
        Some(
            pb::execute_pipeline_request::ConsistencySelector::NewTransaction(
                transaction_options_from_json(Some(options), "new_transaction")?,
            ),
        )
    } else {
        read_time_from_json(body)?.map(pb::execute_pipeline_request::ConsistencySelector::ReadTime)
    };
    let auto_commit_transaction = match body.get("autoCommitTransaction") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return err("autoCommitTransaction must be a boolean"),
    };
    Ok(pb::ExecutePipelineRequest {
        database: database.to_owned(),
        pipeline_type,
        consistency_selector,
        auto_commit_transaction,
        request_options: None,
    })
}

fn structured_pipeline_from_json(v: &Value) -> Result<pb::StructuredPipeline, JsonError> {
    let Some(object) = v.as_object() else {
        return err("structuredPipeline must be an object");
    };
    let pipeline = match object.get("pipeline").filter(|v| !v.is_null()) {
        None => None,
        Some(pipeline) => Some(pipeline_from_json(pipeline, 0)?),
    };
    Ok(pb::StructuredPipeline {
        pipeline,
        options: value_map_from_json(object.get("options"), 0)?,
    })
}

fn pipeline_from_json(v: &Value, depth: u32) -> Result<pb::Pipeline, JsonError> {
    let Some(object) = v.as_object() else {
        return err("pipeline must be an object");
    };
    let stages = match object.get("stages") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(stages)) => stages
            .iter()
            .map(|stage| stage_from_json(stage, depth))
            .collect::<Result<_, _>>()?,
        Some(_) => return err("stages must be an array"),
    };
    Ok(pb::Pipeline { stages })
}

fn stage_from_json(v: &Value, depth: u32) -> Result<pb::pipeline::Stage, JsonError> {
    let Some(object) = v.as_object() else {
        return err("a stage must be an object");
    };
    Ok(pb::pipeline::Stage {
        name: string_field(object, "name")?,
        args: values_from_json(object.get("args"), depth)?,
        options: value_map_from_json(object.get("options"), depth)?,
    })
}

fn string_field(object: &Map<String, Value>, key: &str) -> Result<String, JsonError> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => err(format!("{key} must be a string")),
    }
}

fn values_from_json(v: Option<&Value>, depth: u32) -> Result<Vec<pb::Value>, JsonError> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| expression_from_json(value, depth))
            .collect(),
        Some(_) => err("args must be an array"),
    }
}

fn value_map_from_json(
    v: Option<&Value>,
    depth: u32,
) -> Result<std::collections::HashMap<String, pb::Value>, JsonError> {
    match v {
        None | Some(Value::Null) => Ok(std::collections::HashMap::new()),
        Some(Value::Object(entries)) => entries
            .iter()
            .map(|(key, value)| {
                expression_from_json(value, depth).map(|value| (key.clone(), value))
            })
            .collect(),
        Some(_) => err("options and fields must be an object"),
    }
}

/// A pipeline value: the expression kinds and the containers that may hold them are decoded
/// here, every other kind by the document value decoder.
pub fn expression_from_json(v: &Value, parent_depth: u32) -> Result<pb::Value, JsonError> {
    use pb::value::ValueType as V;
    let depth = parent_depth.saturating_add(1);
    if depth > MAX_EXPRESSION_DEPTH {
        return err(format!(
            "FS-LIMIT-NESTED-MAP-ARRAY-DEPTH has maximum {MAX_EXPRESSION_DEPTH}, got {depth}"
        ));
    }
    let Some((key, inner)) = v
        .as_object()
        .filter(|o| o.len() == 1)
        .and_then(|o| o.iter().next())
    else {
        return value_from_json(v);
    };
    let value_type = match key.as_str() {
        "fieldReferenceValue" => V::FieldReferenceValue(
            inner
                .as_str()
                .ok_or_else(|| JsonError("fieldReferenceValue must be a string".into()))?
                .to_owned(),
        ),
        "variableReferenceValue" => V::VariableReferenceValue(
            inner
                .as_str()
                .ok_or_else(|| JsonError("variableReferenceValue must be a string".into()))?
                .to_owned(),
        ),
        "functionValue" => {
            let Some(object) = inner.as_object() else {
                return err("functionValue must be an object");
            };
            V::FunctionValue(pb::Function {
                name: string_field(object, "name")?,
                args: values_from_json(object.get("args"), depth)?,
                options: value_map_from_json(object.get("options"), depth)?,
            })
        }
        "pipelineValue" => V::PipelineValue(pipeline_from_json(inner, depth)?),
        "arrayValue" => {
            let Some(object) = inner.as_object() else {
                return err("arrayValue must be an object");
            };
            V::ArrayValue(pb::ArrayValue {
                values: values_from_json(object.get("values"), depth)?,
            })
        }
        "mapValue" => {
            let Some(object) = inner.as_object() else {
                return err("mapValue must be an object");
            };
            V::MapValue(pb::MapValue {
                fields: value_map_from_json(object.get("fields"), depth)?,
            })
        }
        _ => return value_from_json(v),
    };
    Ok(pb::Value {
        value_type: Some(value_type),
    })
}

/// `ExecutePipelineResponse` → JSON, with the same result documents as gRPC.
#[must_use]
pub fn response_to_json(response: &pb::ExecutePipelineResponse) -> Value {
    let mut out = json!({});
    if !response.transaction.is_empty() {
        out["transaction"] = Value::String(base64_encode(&response.transaction));
    }
    if !response.results.is_empty() {
        out["results"] = Value::Array(
            response
                .results
                .iter()
                .map(|document| {
                    let mut result = json!({});
                    if !document.name.is_empty() {
                        result["name"] = Value::String(document.name.clone());
                    }
                    if !document.fields.is_empty() {
                        result["fields"] = Value::Object(
                            document
                                .fields
                                .iter()
                                .map(|(k, v)| (k.clone(), value_to_json(v)))
                                .collect(),
                        );
                    }
                    if let Some(time) = &document.create_time {
                        result["createTime"] = timestamp_to_json(time);
                    }
                    if let Some(time) = &document.update_time {
                        result["updateTime"] = timestamp_to_json(time);
                    }
                    result
                })
                .collect(),
        );
    }
    if let Some(time) = &response.execution_time {
        out["executionTime"] = timestamp_to_json(time);
    }
    out
}

#[cfg(test)]
mod tests;
