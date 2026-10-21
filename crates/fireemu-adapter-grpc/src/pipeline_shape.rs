//! The strict profile's shape-match rule for pipeline refusals (coordinator ruling of
//! 2026-10-21 for `PX1d` round 5): strict answers an `INVALID_ARGUMENT` only when the request's
//! normalized shape equals the shape of a request production refused in a committed O-n
//! fixture, and its text is that row's text. Anything else is `UNIMPLEMENTED`.
//!
//! A shape keeps the stages in order, stage and function names, the value kinds, the count of
//! array elements, and every map's entries in wire order. It replaces only field names and
//! values of the same kind: a field reference whose path is plain names joined by `.`, and a
//! map key (a select alias or a literal's key) that is a plain name (letters, digits and `_`,
//! not starting with a digit, not reserved `__..__`, at most 100 bytes). Any other path or key
//! (`__name__`, empty, dotted, quoted, reserved, long) and option names stay as written, since
//! production's checks and texts depend on them. A map of two or more entries
//! whose wire order the transport did not keep (gRPC, whose decoded maps are unordered) has no
//! shape, so strict answers no refusal of such a request.
//!
//! The table of recorded shapes is derived from conformance/fs-ent-pipeline-requests.json and
//! conformance/fs-ent-pipeline-production.json when first used.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::LazyLock;

use fireemu_proto_firestore::google::firestore::v1 as pb;
use serde_json::Value;
use tonic::Status;

use crate::rest::json_syntax::{self, KeyOrder};

const REQUESTS: &str = include_str!("../../../conformance/fs-ent-pipeline-requests.json");
const PRODUCTION: &str = include_str!("../../../conformance/fs-ent-pipeline-production.json");

/// How a pipeline's refusals are answered: as fireemu computes them (the emulator profile), or
/// only when the request has a recorded shape (strict; `None` when it has no shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefusalGate {
    /// Every refusal is answered.
    Open,
    /// A refusal is answered only for a request of this recorded shape.
    Recorded(Option<String>),
}

impl RefusalGate {
    /// The answer for `error`: unchanged unless it is an `INVALID_ARGUMENT` strict cannot trace
    /// to a production row of the request's shape with the same text, which becomes
    /// `UNIMPLEMENTED`.
    #[must_use]
    pub fn answer(&self, error: Status) -> Status {
        let Self::Recorded(shape) = self else {
            return error;
        };
        if error.code() != tonic::Code::InvalidArgument {
            return error;
        }
        let traced = shape.as_deref().is_some_and(|shape| {
            recorded()
                .get(shape)
                .is_some_and(|texts| texts.contains(&normalized_text(error.message())))
        });
        if traced {
            return error;
        }
        let mut status = Status::unimplemented(format!(
            "{}; production has not refused a request of this shape with this text, so this refusal is not observed locally",
            error.message()
        ));
        if let Ok(code) = "FS_PIPE_UNSUPPORTED_STAGE".parse() {
            status.metadata_mut().insert("fireemu-code", code);
        }
        status
    }
}

/// The shape of a REST `executePipeline` body, read with the wire order of its maps.
#[must_use]
pub fn shape_of_json(body: &Value, order: &KeyOrder) -> Option<String> {
    let body = body.as_object()?;
    let mut out = String::new();
    if let Some(structured) = body.get("structuredPipeline") {
        let structured = structured.as_object()?;
        if let Some(pipeline) = structured.get("pipeline") {
            let pipeline = pipeline.as_object()?;
            if let Some(stages) = pipeline.get("stages") {
                out.push_str("stages[");
                for (at, stage) in stages.as_array()?.iter().enumerate() {
                    let pointer = format!("/structuredPipeline/pipeline/stages/{at}");
                    stage_json(&mut out, stage, order, &pointer)?;
                }
                out.push(']');
            }
            for (key, value) in pipeline {
                if key != "stages" {
                    let _ = write!(out, "+pipeline.{}", raw(key, value));
                }
            }
        }
        if let Some(options) = structured.get("options").filter(|o| !is_empty_object(o)) {
            out.push_str("options");
            map_json(
                &mut out,
                options.as_object()?,
                order,
                "/structuredPipeline/options",
                Keys::Literal,
            )?;
        }
        for (key, value) in structured {
            if !matches!(key.as_str(), "pipeline" | "options") {
                let _ = write!(out, "+structured.{}", raw(key, value));
            }
        }
    }
    for key in body.keys() {
        if !matches!(key.as_str(), "database" | "structuredPipeline") {
            let _ = write!(out, "+{key}");
        }
    }
    Some(out)
}

/// The shape of a gRPC request, whose maps carry no wire order.
#[must_use]
pub fn shape_of_request(request: &pb::ExecutePipelineRequest) -> Option<String> {
    let mut out = String::new();
    if let Some(pb::execute_pipeline_request::PipelineType::StructuredPipeline(structured)) =
        &request.pipeline_type
    {
        if let Some(pipeline) = &structured.pipeline {
            out.push_str("stages[");
            for stage in &pipeline.stages {
                stage_pb(&mut out, stage)?;
            }
            out.push(']');
        }
        if !structured.options.is_empty() {
            out.push_str("options");
            map_pb(&mut out, &structured.options, Keys::Literal)?;
        }
    }
    match &request.consistency_selector {
        None => {}
        Some(pb::execute_pipeline_request::ConsistencySelector::Transaction(_)) => {
            out.push_str("+transaction");
        }
        Some(pb::execute_pipeline_request::ConsistencySelector::NewTransaction(_)) => {
            out.push_str("+newTransaction");
        }
        Some(pb::execute_pipeline_request::ConsistencySelector::ReadTime(_)) => {
            out.push_str("+readTime");
        }
    }
    Some(out)
}

fn stage_json(out: &mut String, stage: &Value, order: &KeyOrder, pointer: &str) -> Option<()> {
    let stage = stage.as_object()?;
    let name = stage
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let _ = write!(out, "{}(", quoted(name));
    if let Some(args) = stage.get("args") {
        for (at, arg) in args.as_array()?.iter().enumerate() {
            value_json(out, arg, order, &format!("{pointer}/args/{at}"))?;
            out.push(',');
        }
    }
    out.push(')');
    if let Some(options) = stage.get("options").filter(|o| !is_empty_object(o)) {
        out.push_str("options");
        map_json(
            out,
            options.as_object()?,
            order,
            &format!("{pointer}/options"),
            Keys::Literal,
        )?;
    }
    for (key, value) in stage {
        if !matches!(key.as_str(), "name" | "args" | "options") {
            let _ = write!(out, "+{}", raw(key, value));
        }
    }
    out.push(';');
    Some(())
}

fn stage_pb(out: &mut String, stage: &pb::pipeline::Stage) -> Option<()> {
    let _ = write!(out, "{}(", quoted(&stage.name));
    for arg in &stage.args {
        value_pb(out, arg)?;
        out.push(',');
    }
    out.push(')');
    if !stage.options.is_empty() {
        out.push_str("options");
        map_pb(out, &stage.options, Keys::Literal)?;
    }
    out.push(';');
    Some(())
}

/// How a map's keys enter its shape.
#[derive(Clone, Copy)]
enum Keys {
    /// Option names, kept as written.
    Literal,
    /// Field names (select aliases, a literal's keys): a plain name is replaced.
    FieldNames,
}

/// The longest key replaced as a plain name.
const PLAIN_NAME_BYTES: usize = 100;

impl Keys {
    fn shape(self, key: &str) -> String {
        if matches!(self, Self::FieldNames) && is_plain_name(key) {
            "name".to_owned()
        } else {
            quoted(key)
        }
    }
}

/// A name every check treats alike: letters, digits and `_`, not starting with a digit, not
/// reserved (`__..__`), at most [`PLAIN_NAME_BYTES`].
fn is_plain_name(name: &str) -> bool {
    name.len() <= PLAIN_NAME_BYTES
        && name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && !(name.len() >= 4 && name.starts_with("__") && name.ends_with("__"))
}

/// A field reference: a path of plain names is replaced; any other path (`__name__`, quoted,
/// reserved or malformed segments) is kept, since production's checks depend on it.
fn field_shape(path: &str) -> String {
    if path.split('.').all(is_plain_name) {
        "field".to_owned()
    } else {
        format!("field{}", quoted(path))
    }
}

/// A map's entries in wire order: `{"key":shape,...}`.
fn map_json(
    out: &mut String,
    map: &serde_json::Map<String, Value>,
    order: &KeyOrder,
    pointer: &str,
    names: Keys,
) -> Option<()> {
    out.push('{');
    let keys: Vec<&String> = if map.len() > 1 {
        let keys = order.keys(pointer)?;
        if keys.len() != map.len() || !keys.iter().all(|k| map.contains_key(k)) {
            return None;
        }
        keys.iter().collect()
    } else {
        map.keys().collect()
    };
    for key in keys {
        out.push_str(&names.shape(key));
        out.push(':');
        value_json(
            out,
            &map[key.as_str()],
            order,
            &format!("{pointer}/{}", json_syntax::pointer_segment(key)),
        )?;
        out.push(',');
    }
    out.push('}');
    Some(())
}

/// A map with no wire order has a shape only with at most one entry.
fn map_pb(out: &mut String, map: &HashMap<String, pb::Value>, names: Keys) -> Option<()> {
    if map.len() > 1 {
        return None;
    }
    out.push('{');
    for (key, value) in map {
        out.push_str(&names.shape(key));
        out.push(':');
        value_pb(out, value)?;
        out.push(',');
    }
    out.push('}');
    Some(())
}

fn value_json(out: &mut String, value: &Value, order: &KeyOrder, pointer: &str) -> Option<()> {
    let Some(object) = value.as_object().filter(|o| o.len() == 1) else {
        out.push_str(&raw("value", value));
        return Some(());
    };
    let (kind, inner) = object.iter().next()?;
    let inner_pointer = format!("{pointer}/{}", json_syntax::pointer_segment(kind));
    match kind.as_str() {
        "nullValue" => out.push_str("null"),
        "booleanValue" => out.push_str("boolean"),
        "integerValue" => out.push_str("integer"),
        "doubleValue" => out.push_str("double"),
        "timestampValue" => out.push_str("timestamp"),
        "stringValue" => out.push_str("string"),
        "bytesValue" => out.push_str("bytes"),
        "referenceValue" => out.push_str("reference"),
        "geoPointValue" => out.push_str("geoPoint"),
        "fieldReferenceValue" => out.push_str(&field_shape(inner.as_str().unwrap_or_default())),
        "variableReferenceValue" => out.push_str("variable"),
        "arrayValue" => {
            out.push('[');
            let array = inner.as_object()?;
            for (key, values) in array {
                if key != "values" {
                    let _ = write!(out, "+{}", raw(key, values));
                    continue;
                }
                for (at, element) in values.as_array()?.iter().enumerate() {
                    value_json(out, element, order, &format!("{inner_pointer}/values/{at}"))?;
                    out.push(',');
                }
            }
            out.push(']');
        }
        "mapValue" => {
            out.push_str("map");
            let map = inner.as_object()?;
            match map.get("fields") {
                Some(fields) => {
                    map_json(
                        out,
                        fields.as_object()?,
                        order,
                        &format!("{inner_pointer}/fields"),
                        Keys::FieldNames,
                    )?;
                }
                None => out.push_str("{}"),
            }
            for (key, value) in map {
                if key != "fields" {
                    let _ = write!(out, "+{}", raw(key, value));
                }
            }
        }
        "functionValue" => function_json(out, inner.as_object()?, order, &inner_pointer)?,
        "pipelineValue" => {
            out.push_str("pipeline[");
            let pipeline = inner.as_object()?;
            for (key, value) in pipeline {
                if key != "stages" {
                    let _ = write!(out, "+{}", raw(key, value));
                    continue;
                }
                for (at, stage) in value.as_array()?.iter().enumerate() {
                    stage_json(out, stage, order, &format!("{inner_pointer}/stages/{at}"))?;
                }
            }
            out.push(']');
        }
        _ => out.push_str(&raw("value", value)),
    }
    Some(())
}

/// A function call: its name, arguments and options.
fn function_json(
    out: &mut String,
    function: &serde_json::Map<String, Value>,
    order: &KeyOrder,
    inner_pointer: &str,
) -> Option<()> {
    let name = function
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let _ = write!(out, "fn {}(", quoted(name));
    if let Some(args) = function.get("args") {
        for (at, arg) in args.as_array()?.iter().enumerate() {
            value_json(out, arg, order, &format!("{inner_pointer}/args/{at}"))?;
            out.push(',');
        }
    }
    out.push(')');
    if let Some(options) = function.get("options").filter(|o| !is_empty_object(o)) {
        out.push_str("options");
        map_json(
            out,
            options.as_object()?,
            order,
            &format!("{inner_pointer}/options"),
            Keys::Literal,
        )?;
    }
    for (key, value) in function {
        if !matches!(key.as_str(), "name" | "args" | "options") {
            let _ = write!(out, "+{}", raw(key, value));
        }
    }
    Some(())
}

fn value_pb(out: &mut String, value: &pb::Value) -> Option<()> {
    use pb::value::ValueType as V;
    match &value.value_type {
        None => out.push_str("none"),
        Some(V::NullValue(_)) => out.push_str("null"),
        Some(V::BooleanValue(_)) => out.push_str("boolean"),
        Some(V::IntegerValue(_)) => out.push_str("integer"),
        Some(V::DoubleValue(_)) => out.push_str("double"),
        Some(V::TimestampValue(_)) => out.push_str("timestamp"),
        Some(V::StringValue(_)) => out.push_str("string"),
        Some(V::BytesValue(_)) => out.push_str("bytes"),
        Some(V::ReferenceValue(_)) => out.push_str("reference"),
        Some(V::GeoPointValue(_)) => out.push_str("geoPoint"),
        Some(V::FieldReferenceValue(path)) => out.push_str(&field_shape(path)),
        Some(V::VariableReferenceValue(_)) => out.push_str("variable"),
        Some(V::ArrayValue(array)) => {
            out.push('[');
            for element in &array.values {
                value_pb(out, element)?;
                out.push(',');
            }
            out.push(']');
        }
        Some(V::MapValue(map)) => {
            out.push_str("map");
            map_pb(out, &map.fields, Keys::FieldNames)?;
        }
        Some(V::FunctionValue(function)) => {
            let _ = write!(out, "fn {}(", quoted(&function.name));
            for arg in &function.args {
                value_pb(out, arg)?;
                out.push(',');
            }
            out.push(')');
            if !function.options.is_empty() {
                out.push_str("options");
                map_pb(out, &function.options, Keys::Literal)?;
            }
        }
        Some(V::PipelineValue(pipeline)) => {
            out.push_str("pipeline[");
            for stage in &pipeline.stages {
                stage_pb(out, stage)?;
            }
            out.push(']');
        }
    }
    Some(())
}

/// An empty options map, which is no options (proto3 reads both alike).
fn is_empty_object(value: &Value) -> bool {
    value.as_object().is_some_and(serde_json::Map::is_empty)
}

/// A part outside the protocol's shapes, kept exactly.
fn raw(key: &str, value: &Value) -> String {
    format!("raw{}={}", quoted(key), value)
}

fn quoted(text: &str) -> String {
    Value::String(text.to_owned()).to_string()
}

/// A refusal text with the project and database it names, and a separator index (which counts
/// their length), put aside.
#[must_use]
pub fn normalized_text(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(at) = rest.find("projects/") {
        out.push_str(&rest[..at]);
        let after = &rest[at + "projects/".len()..];
        let project_end = after.find('/').unwrap_or(after.len());
        let tail = &after[project_end..];
        if let Some(database) = tail.strip_prefix("/databases/") {
            let end = database
                .find(|c: char| c == '/' || c == '"' || c.is_whitespace())
                .unwrap_or(database.len());
            out.push_str("projects/~/databases/~");
            rest = &database[end..];
        } else {
            out.push_str("projects/");
            rest = after;
        }
    }
    out.push_str(rest);
    match out.find(" at index ") {
        Some(at) => {
            let digits = out[at + " at index ".len()..]
                .find(|c: char| !c.is_ascii_digit())
                .map_or(out.len(), |end| at + " at index ".len() + end);
            format!("{} at index ~{}", &out[..at], &out[digits..])
        }
        None => out,
    }
}

/// The recorded refusals: each refused request's shape and its normalized texts.
fn recorded() -> &'static HashMap<String, HashSet<String>> {
    static RECORDED: LazyLock<HashMap<String, HashSet<String>>> =
        LazyLock::new(|| recorded_refusals(REQUESTS, PRODUCTION));
    &RECORDED
}

/// Builds the table from the request and production fixtures' texts.
fn recorded_refusals(requests: &str, production: &str) -> HashMap<String, HashSet<String>> {
    let (requests, order) =
        json_syntax::parse_with_key_order(requests.as_bytes()).expect("request fixture parses");
    let production: Value = serde_json::from_str(production).expect("production fixture parses");
    let mut table: HashMap<String, HashSet<String>> = HashMap::new();
    let programs = requests["programs"].as_array().into_iter().flatten();
    for (p, program) in programs.enumerate() {
        let id = program["id"].as_str().unwrap_or_default();
        for (s, step) in program["steps"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            if step["rpc"] != "executePipeline" {
                continue;
            }
            let step_id = step["id"].as_str().unwrap_or_default();
            let answer = &production["programs"][id]["steps"][step_id];
            if answer["status"] != 400 {
                continue;
            }
            let element = answer["body"]
                .as_array()
                .and_then(|a| a.first())
                .unwrap_or(&answer["body"]);
            // Only an INVALID_ARGUMENT row answers a refusal the gate lets through (another
            // status on HTTP 400, such as FAILED_PRECONDITION, is no evidence for it).
            if element["error"]["status"] != "INVALID_ARGUMENT" {
                continue;
            }
            let Some(message) = element["error"]["message"].as_str() else {
                continue;
            };
            let body_order = order.rebased(&format!("/programs/{p}/steps/{s}/body"), "");
            if let Some(shape) = shape_of_json(&step["body"], &body_order) {
                table
                    .entry(shape)
                    .or_default()
                    .insert(normalized_text(message));
            }
        }
    }
    table
}

#[cfg(test)]
mod tests;
