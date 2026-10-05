//! The strict Eventarc surface against what production answered to the stage A recordings (EVENTARC,
//! 2026-10-05, the second recording). `fixtures/eventarc-stage-a/rows.json` holds every recorded
//! Eventarc and Eventarc Publishing exchange of that recording; the Service Usage ones are a different
//! product and are not served. Each row is replayed through the pure evaluator and its answer is compared
//! with the recorded one.
//!
//! The rows the strict surface does not reproduce are named in `NOT_REPRODUCED` with the reason; the test
//! fails when a row not named there diverges, and when a named row stops diverging.

use std::collections::BTreeMap;

use fireemu_adapter_functions::eventarc_strict::{evaluate, route, Input, Outcome, World};
use fireemu_adapter_functions::ordered_json::{parse, Ordered};
use serde_json::{json, Value};

const PROJECT: &str = "fireemu-oracle-idp";
const MASKED: &str = "<requestId>";

/// Rows of the recording the strict surface answers differently, by row number.
///
/// - 82 and 83: the recorded credential was "invalid" (a made-up bearer token). Whether a bearer token
///   is valid is Google's state; a local listener cannot verify an OAuth access token, so the surface
///   accepts any bearer token and only refuses a request without one.
const NOT_REPRODUCED: &[(u64, &str)] = &[
    (82, "invalid bearer token: unverifiable locally"),
    (83, "invalid bearer token: unverifiable locally"),
];

/// One recorded exchange, read with the members of its request body in the order they were written
/// (an attribute's position in the map is part of what production reports).
struct Row {
    n: u64,
    case: String,
    op: String,
    token: String,
    method: String,
    path: String,
    body: Option<String>,
    status: u64,
    answer: Value,
}

fn member<'a>(value: &'a Ordered, name: &str) -> Option<&'a Ordered> {
    value
        .members()?
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, item)| item)
}

fn text(value: &Ordered) -> String {
    match value {
        Ordered::String(text) => text.clone(),
        other => panic!("not a string: {other:?}"),
    }
}

/// The JSON text of a recorded body: text the capture omitted is rebuilt as the recorder built it, an
/// event list the fixture compressed is expanded, and every object keeps its member order.
fn body_text(value: &Ordered) -> String {
    match value {
        Ordered::Array(items) => {
            format!(
                "[{}]",
                items.iter().map(body_text).collect::<Vec<_>>().join(",")
            )
        }
        Ordered::Object(members) => {
            if let [(name, omitted)] = members.as_slice() {
                if name == "omitted" {
                    let length = member(omitted, "length")
                        .and_then(|n| match n {
                            Ordered::Number(n) => n.as_u64(),
                            _ => None,
                        })
                        .expect("a length");
                    let text = serde_json::to_string(
                        &"x".repeat(usize::try_from(length).expect("a small length") - 2),
                    )
                    .expect("a string");
                    assert_eq!(
                        text.len() as u64,
                        length,
                        "the rebuilt text has the recorded length"
                    );
                    return serde_json::to_string(&text).expect("a string");
                }
                if name == "$repeat" {
                    let count = match member(omitted, "count") {
                        Some(Ordered::Number(n)) => n.as_u64().expect("a count"),
                        _ => panic!("a count"),
                    };
                    let template = body_text(member(omitted, "template").expect("a template"));
                    return format!(
                        "[{}]",
                        vec![template; usize::try_from(count).unwrap()].join(",")
                    );
                }
            }
            format!(
                "{{{}}}",
                members
                    .iter()
                    .map(|(key, item)| format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("a key"),
                        body_text(item)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        other => other.to_value().to_string(),
    }
}

fn rows() -> Vec<Row> {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/eventarc-stage-a/rows.json"
    ))
    .expect("the fixture exists");
    let Ordered::Array(rows) = parse(&bytes).expect("the fixture is JSON") else {
        panic!("rows");
    };
    rows.iter()
        .map(|row| {
            let request = member(row, "request").expect("a request");
            let response = member(row, "response").expect("a response");
            let status = match member(response, "status") {
                Some(Ordered::Number(n)) => n.as_u64().expect("a status"),
                _ => panic!("a status"),
            };
            Row {
                n: match member(row, "n") {
                    Some(Ordered::Number(n)) => n.as_u64().expect("a number"),
                    _ => panic!("n"),
                },
                case: text(member(row, "case").expect("a case")),
                op: text(member(row, "op").expect("an op")),
                token: text(member(row, "token").expect("a token")),
                method: text(member(request, "method").expect("a method")),
                path: text(member(request, "path").expect("a path")),
                body: member(request, "body").map(body_text),
                status,
                answer: member(response, "body").expect("a body").to_value(),
            }
        })
        .collect()
}

fn mask_request_ids(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(mask_request_ids).collect()),
        Value::Object(members) => Value::Object(
            members
                .iter()
                .map(|(key, item)| {
                    let is_id = key == "requestId"
                        && item.as_str().is_some_and(|text| {
                            text.len() == 16 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
                        });
                    (
                        key.clone(),
                        if is_id {
                            Value::String(MASKED.to_owned())
                        } else {
                            mask_request_ids(item)
                        },
                    )
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The answer the strict surface gives to one recorded request, in a world where `declared` channels exist.
fn answer_of(row: &Row, declared: &dyn Fn(&str) -> bool) -> (u16, Value) {
    let (path, query) = row
        .path
        .split_once('?')
        .map_or((row.path.as_str(), None), |(path, query)| {
            (path, Some(query))
        });
    let route = route(&row.method, path).unwrap_or_else(|| panic!("row {} has a route", row.n));
    let body = row.body.clone().unwrap_or_default().into_bytes();
    let nothing = |_: &str, _: &str| false;
    let input = Input {
        route: &route,
        query,
        authorized: row.token != "none",
        body: &body,
    };
    let world = World {
        project: PROJECT,
        request_id: "0123456789abcdef",
        declared_channel: declared,
        declared_in: &nothing,
    };
    match evaluate(&input, &world) {
        Outcome::Answer(answer) => (answer.status, answer.body),
        Outcome::Deliver { .. } => (200, json!({"delivered": true})),
    }
}

#[test]
fn every_recorded_exchange_is_answered_as_production_answered() {
    let known: BTreeMap<u64, &str> = NOT_REPRODUCED.iter().copied().collect();
    let none = |_: &str| false;
    let mut checked = 0;
    let mut diverged = Vec::new();
    for row in rows() {
        let (status, body) = answer_of(&row, &none);
        let same = u64::from(status) == row.status
            && mask_request_ids(&body) == mask_request_ids(&row.answer);
        checked += 1;
        if !same {
            diverged.push(row.n);
        }
        assert_eq!(
            same,
            !known.contains_key(&row.n),
            "row {} ({} {}): recorded {} {}; answered {status} {body}",
            row.n,
            row.case,
            row.op,
            row.status,
            row.answer,
        );
    }
    assert_eq!(checked, 87, "the whole recording is replayed");
    assert_eq!(diverged, known.keys().copied().collect::<Vec<_>>());
}
