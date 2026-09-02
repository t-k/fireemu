//! `GET /emulator/v1/projects/{project}:ruleCoverage[.html]` (`RULES-PARITY-04`).
//!
//! The JSON is the official emulator's: the ruleset it has loaded, then a `report` of one
//! tree per top-level expression, each node naming its `sourcePosition` (`line`, `column`,
//! `currentOffset`, `endOffset`) and the `values` it took with a `count` each. An expression
//! that raised contributes `{"undefined": {"sourcePosition": ..., "causeMessage": ...}}`, and
//! one that was never evaluated has `children` and no `values`.
//!
//! `.html` is the same document embedded in a page that underlines every evaluated
//! expression, exactly as the official report does, so the same link works.
//!
//! Neither route takes a credential, because the official ones do not and because
//! `@firebase/rules-unit-testing` fetches them with no headers at all. Both are reachable
//! only from the loopback listener, and both echo the values the ruleset computed -- which
//! is what a coverage report is -- so a session that evaluates rules over sensitive claims
//! should not be exposed beyond the machine running it.

use core::fmt::Write as _;

use fireemu_core_rules::coverage::{report, Coverage, CoverageNode, ExprValue};
use fireemu_core_rules::runtime::LoadedRules;
use serde_json::{json, Map, Value};

/// The key `serve.rs` recognises to send a body as `text/html` instead of JSON.
pub const HTML_KEY: &str = "fireemuHtml";

/// Builds the `:ruleCoverage` body for a loaded ruleset and its accumulated coverage.
#[must_use]
pub fn coverage_json(rules: &LoadedRules, coverage: &Coverage) -> Value {
    let files = match &rules.source {
        Some(source) => json!([{"content": source, "name": "firestore.rules"}]),
        None => json!([]),
    };
    let report = match &rules.ruleset {
        Some(ruleset) => report(ruleset, coverage)
            .iter()
            .map(node_json)
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };
    json!({ "rules": { "files": files }, "report": report })
}

fn node_json(node: &CoverageNode) -> Value {
    let mut out = Map::new();
    out.insert("sourcePosition".to_owned(), position(node));
    if !node.values.is_empty() {
        out.insert(
            "values".to_owned(),
            Value::Array(
                node.values
                    .iter()
                    .map(|(value, count)| json!({"value": value_json(value), "count": count}))
                    .collect(),
            ),
        );
    }
    if !node.children.is_empty() {
        out.insert(
            "children".to_owned(),
            Value::Array(node.children.iter().map(node_json).collect()),
        );
    }
    Value::Object(out)
}

fn position(node: &CoverageNode) -> Value {
    json!({
        "line": node.span.line,
        "column": node.span.column,
        "currentOffset": node.span.offset,
        "endOffset": node.end,
    })
}

fn value_json(value: &ExprValue) -> Value {
    match value {
        ExprValue::Null => json!({ "nullValue": Value::Null }),
        ExprValue::Bool(b) => json!({ "boolValue": b }),
        ExprValue::Int(i) => json!({ "intValue": i.to_string() }),
        ExprValue::Float(f) => json!({ "floatValue": f }),
        ExprValue::String(s) => json!({ "stringValue": s }),
        ExprValue::Composite(kind) => json!({ "typeValue": kind }),
        ExprValue::Undefined(cause) => json!({
            "undefined": {
                "sourcePosition": {
                    "line": cause.span.line,
                    "column": cause.span.column,
                    "currentOffset": cause.span.offset,
                    "endOffset": cause.end,
                },
                "causeMessage": cause.message,
            }
        }),
    }
}

/// The HTML report: the source with every evaluated expression underlined, and the JSON the
/// `:ruleCoverage` route serves embedded for a reader that wants the numbers.
#[must_use]
pub fn coverage_html(rules: &LoadedRules, coverage: &Coverage) -> String {
    let data = coverage_json(rules, coverage);
    let source = rules.source.clone().unwrap_or_default();
    let mut spans: Vec<(usize, usize, String)> = Vec::new();
    collect_spans(&data, &mut spans);
    // Innermost last, so the outermost wrapper opens first at a shared start offset.
    spans.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let mut body = String::new();
    let mut cursor = 0usize;
    let mut open: Vec<usize> = Vec::new();
    let bytes = source.as_bytes();
    for (start, end, title) in &spans {
        if *start > bytes.len() || *end > bytes.len() || start > end {
            continue;
        }
        while open.last().is_some_and(|close| *close <= *start) {
            let close = open.pop().unwrap_or(cursor);
            push_escaped(&mut body, &source[cursor..close.max(cursor)]);
            body.push_str("</span>");
            cursor = close.max(cursor);
        }
        if *start < cursor {
            continue;
        }
        push_escaped(&mut body, &source[cursor..*start]);
        let _ = write!(
            body,
            "<span class=\"coverage-expr\" title=\"{}\">",
            escape(title)
        );
        cursor = *start;
        open.push(*end);
    }
    while let Some(close) = open.pop() {
        push_escaped(&mut body, &source[cursor..close.max(cursor)]);
        body.push_str("</span>");
        cursor = close.max(cursor);
    }
    push_escaped(&mut body, &source[cursor..]);
    format!(
        "<!DOCTYPE html>\n<meta charset=\"utf-8\">\n<title>Firestore Rule Coverage Report</title>\n\
         <style>\n\
         body {{ font: 13px ui-monospace, SFMono-Regular, Menlo, monospace; margin: 24px; }}\n\
         pre {{ line-height: 1.9; }}\n\
         .coverage-expr {{ padding-bottom: 4px; display: inline-block; border-bottom: 3px solid black; vertical-align: top; }}\n\
         .coverage-expr:hover {{ background-color: rgba(255, 100, 100, 0.2); cursor: default; border-bottom: 3px solid red; }}\n\
         .never {{ border-bottom-color: #bbb; }}\n\
         </style>\n\
         <h1>Firestore Rule Coverage Report</h1>\n\
         <p>Every underlined expression was evaluated at least once; hover one to see the values it took. Grey means it was never reached.</p>\n\
         <pre>{body}</pre>\n\
         <script id=\"coverage-data\" type=\"application/json\">{data}</script>\n"
    )
}

/// Flattens the report into `(start, end, hover text)`, skipping nodes with no values so
/// that an unevaluated expression is not underlined as if it had been reached.
fn collect_spans(data: &Value, out: &mut Vec<(usize, usize, String)>) {
    let mut stack: Vec<&Value> = data["report"]
        .as_array()
        .map(|nodes| nodes.iter().collect())
        .unwrap_or_default();
    while let Some(node) = stack.pop() {
        if let Some(children) = node["children"].as_array() {
            stack.extend(children);
        }
        let Some(values) = node["values"].as_array() else {
            continue;
        };
        let (Some(start), Some(end)) = (
            node["sourcePosition"]["currentOffset"].as_u64(),
            node["sourcePosition"]["endOffset"].as_u64(),
        ) else {
            continue;
        };
        let title = values
            .iter()
            .map(|v| {
                format!(
                    "{} x{}",
                    describe_value(&v["value"]),
                    v["count"].as_u64().unwrap_or(0)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let (Ok(start), Ok(end)) = (usize::try_from(start), usize::try_from(end)) else {
            continue;
        };
        out.push((start, end, title));
    }
}

fn describe_value(value: &Value) -> String {
    for key in [
        "boolValue",
        "intValue",
        "floatValue",
        "stringValue",
        "typeValue",
    ] {
        if let Some(v) = value.get(key) {
            return format!("{v}");
        }
    }
    if value.get("nullValue").is_some() {
        return "null".to_owned();
    }
    match value["undefined"]["causeMessage"].as_str() {
        Some(message) => format!("undefined: {message}"),
        None => "undefined".to_owned(),
    }
}

fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    push_escaped(&mut out, text);
    out
}

fn push_escaped(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use fireemu_core_rules::coverage::Coverage;
    use fireemu_core_rules::parse::MAX_EXPR_TREE_DEPTH;
    use fireemu_core_rules::runtime::LoadedRules;

    use super::coverage_json;

    #[test]
    fn coverage_json_handles_the_maximum_expression_depth_on_a_worker_stack() {
        std::thread::Builder::new()
            .name("rules-coverage-stack-regression".to_owned())
            .stack_size(2 * 1024 * 1024)
            .spawn(|| {
                let condition = vec!["true"; MAX_EXPR_TREE_DEPTH as usize].join(" && ");
                let source = format!(
                    "rules_version = '2'; service cloud.firestore {{ match /databases/{{database}}/documents {{ match /{{document=**}} {{ allow read: if {condition}; }} }} }}"
                );
                let loaded = LoadedRules::from_source(&source).expect("boundary ruleset loads");
                let json = coverage_json(&loaded, &Coverage::default());
                assert_eq!(
                    json["report"].as_array().map(Vec::len),
                    Some(1),
                    "coverage contains the boundary expression"
                );
                drop(json);
                drop(loaded);
            })
            .expect("spawn worker-sized stack")
            .join()
            .expect("coverage generation does not overflow");
    }
}
