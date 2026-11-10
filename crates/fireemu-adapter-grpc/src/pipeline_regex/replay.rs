//! Replays the recorded production answers of the Pipeline regex observation
//! (FS-PIPELINE-REGEX-20261110-01) through the evaluator in both profiles.
//!
//! `production_rows.json` is generated from `conformance/fs-ent-pipeline-regex-production.json`
//! by `conformance/src/fs-ent-pipeline/regex-rows.mjs`; a Node test keeps the two equal.

use super::resolve;
use fireemu_core_firestore::field_path::FieldPath;
use fireemu_core_firestore::pipeline_exec::{
    Eval, EvalError, Expr, Placement, Row, RuntimeContext, Unrecorded,
};
use fireemu_core_firestore::value::Value;
use serde_json::{json, Value as Json};
use std::collections::BTreeMap;

pub(super) const FUNCTIONS: [&str; 4] = [
    "regex_contains",
    "regex_match",
    "regex_find",
    "regex_find_all",
];

pub(super) struct Row_ {
    pub(super) label: String,
    pub(super) subject: String,
    pub(super) pattern: String,
    pub(super) answers: Json,
}

pub(super) fn rows() -> Vec<Row_> {
    let table: Json = serde_json::from_str(include_str!("production_rows.json")).unwrap();
    table
        .as_array()
        .unwrap()
        .iter()
        .map(|row| Row_ {
            label: row["label"].as_str().unwrap().to_owned(),
            subject: row["subject"].as_str().unwrap().to_owned(),
            pattern: row["pattern"].as_str().unwrap().to_owned(),
            answers: row["answers"].clone(),
        })
        .collect()
}

/// What the evaluator answers, in the encoding of the table. A refusal as unobserved is
/// `{"kind":"unimplemented"}`; any other error is `{"kind":"error", ...}`.
pub(super) fn outcome(name: &str, subject: &str, pattern: &str, mode: Unrecorded) -> Json {
    let row = Row::derived(BTreeMap::from([(
        "s".to_owned(),
        Value::String(subject.to_owned()),
    )]));
    let args = vec![
        Expr::Field(FieldPath::parse("s").unwrap()),
        Expr::Constant(Value::String(pattern.to_owned())),
    ];
    let eval = Expr::call(name, args, Placement::Value)
        .unwrap()
        .eval_in_with_runtime(
            &row,
            mode,
            RuntimeContext {
                regex_resolver: Some(resolve),
                ..RuntimeContext::default()
            },
        );
    encode(&eval)
}

fn encode(eval: &Eval) -> Json {
    match eval {
        Eval::Value(Value::Boolean(value)) => json!({"kind": "bool", "value": value}),
        Eval::Value(Value::String(value)) => json!({"kind": "string", "value": value}),
        Eval::Value(Value::Null) => json!({"kind": "null"}),
        Eval::Value(Value::Array(items)) => json!({
            "kind": "array",
            "items": items.iter().map(|item| encode(&Eval::Value(item.clone()))).collect::<Vec<_>>(),
        }),
        Eval::Error(EvalError::Invalid(message)) if message == "Unsupported regex syntax." => {
            json!({"kind": "refused-syntax"})
        }
        Eval::Error(EvalError::Invalid(message))
            if message == "At most one capture group is supported." =>
        {
            json!({"kind": "refused-captures"})
        }
        Eval::Error(EvalError::Unobserved { .. }) => json!({"kind": "unimplemented"}),
        other => json!({"kind": "error", "detail": format!("{other:?}")}),
    }
}

const PROFILES: [(&str, Unrecorded); 2] = [
    ("strict", Unrecorded::Refuse),
    ("emulator", Unrecorded::OfficialEmulator),
];

#[test]
fn the_table_holds_every_recorded_pair_of_every_function() {
    let rows = rows();
    assert_eq!(rows.len(), 68);
    assert_eq!(rows.len() * FUNCTIONS.len(), 272);
    for row in &rows {
        for name in FUNCTIONS {
            assert!(row.answers.get(name).is_some(), "{} {name}", row.label);
        }
    }
}

#[test]
fn strict_and_emulator_answer_every_recorded_production_row() {
    let mut differing = Vec::new();
    for row in rows() {
        for name in FUNCTIONS {
            for (profile, mode) in PROFILES {
                let got = outcome(name, &row.subject, &row.pattern, mode);
                if got != row.answers[name] {
                    differing.push(format!(
                        "{profile} {name} {} {:?} {:?}: production {} got {got}",
                        row.label, row.subject, row.pattern, row.answers[name]
                    ));
                }
            }
        }
    }
    assert!(
        differing.is_empty(),
        "{} of 544 replays differ:\n{}",
        differing.len(),
        differing.join("\n")
    );
}
