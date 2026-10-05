//! The strict Eventarc surface against what production answered to the stage A recordings (EVENTARC,
//! 2026-10-05, the second recording). `fixtures/eventarc-stage-a/rows.json` holds every recorded
//! Eventarc and Eventarc Publishing exchange of that recording; the Service Usage ones are a different
//! product and are not served. Each row is replayed through the pure evaluator and its answer is compared
//! with the recorded one, member order included: production's order is recorded (the recorder keeps the
//! order of the parsed body) and is reproduced. The one exemption is the `metadata` of an `ErrorInfo`, a
//! proto map whose order varies between answers of the same request (six places in r1 against r2).
//!
//! The bytes are pinned against the two raw bodies of preflight 002 (`preflight-002-*.json`): the 404 of
//! `channels/firebase` (373 bytes, pretty-printed, trailing newline) and the empty list (`{}` + newline).
//!
//! The rows the strict surface does not reproduce are named in `NOT_REPRODUCED` with the reason; the test
//! fails when a row not named there diverges, and when a named row stops diverging.

use std::collections::BTreeMap;

use fireemu_adapter_functions::eventarc_strict::{evaluate, route, Input, Outcome, World};
use fireemu_adapter_functions::ordered_json::{parse, Ordered};

const PROJECT: &str = "fireemu-oracle-idp";
const MASKED: &str = "<requestId>";

/// Rows of the recording the strict surface answers differently, by row number. None: the recorded
/// invalid token (`invalid-token-for-the-recording`, rows 82 and 83) is neither an access token (`ya29.`)
/// nor a JWT in shape, and the surface refuses exactly that shape with the recorded 401.
const NOT_REPRODUCED: &[(u64, &str)] = &[];

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
    answer: Ordered,
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
                answer: member(response, "body").expect("a body").clone(),
            }
        })
        .collect()
}

fn mask_request_ids(value: &Ordered) -> Ordered {
    match value {
        Ordered::Array(items) => Ordered::Array(items.iter().map(mask_request_ids).collect()),
        Ordered::Object(members) => Ordered::Object(
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
                            Ordered::text(MASKED)
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

/// Whether two bodies are the same, member order included. The one exemption is the `metadata` of an
/// `ErrorInfo` (a proto map: its order varies in production), whose members are compared as a set.
fn same_layout(a: &Ordered, b: &Ordered) -> bool {
    match (a, b) {
        (Ordered::Array(x), Ordered::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same_layout(x, y))
        }
        (Ordered::Object(x), Ordered::Object(y)) => {
            let error_info = a["@type"] == "type.googleapis.com/google.rpc.ErrorInfo";
            x.len() == y.len()
                && x.iter().zip(y).all(|((xk, xv), (yk, yv))| {
                    if xk != yk {
                        return false;
                    }
                    if error_info && xk == "metadata" {
                        return same_set(xv, yv);
                    }
                    same_layout(xv, yv)
                })
        }
        (x, y) => x == y,
    }
}

fn same_set(a: &Ordered, b: &Ordered) -> bool {
    match (a, b) {
        (Ordered::Object(x), Ordered::Object(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(key, value)| y.iter().any(|(k, v)| k == key && v == value))
        }
        (x, y) => x == y,
    }
}

/// The answer the strict surface gives to one recorded request, in a world where `declared` channels exist.
fn answer_of(row: &Row, declared: &dyn Fn(&str) -> bool) -> (u16, Ordered) {
    let (path, query) = row
        .path
        .split_once('?')
        .map_or((row.path.as_str(), None), |(path, query)| {
            (path, Some(query))
        });
    let route = route(&row.method, path).unwrap_or_else(|| panic!("row {} has a route", row.n));
    let body = row.body.clone().unwrap_or_default().into_bytes();
    let nothing = |_: &str, _: &str| false;
    // The credential of each row: none, the recorder's invalid token, or the shape a real client sends.
    let bearer = match row.token.as_str() {
        "none" => None,
        "invalid" => Some("invalid-token-for-the-recording"),
        _ => Some("ya29.replay-token"),
    };
    let input = Input {
        route: &route,
        query,
        bearer,
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
        Outcome::Deliver { .. } => (200, Ordered::object([("delivered", Ordered::Bool(true))])),
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
            && same_layout(&mask_request_ids(&body), &mask_request_ids(&row.answer));
        checked += 1;
        if !same {
            diverged.push(row.n);
        }
        assert_eq!(
            same,
            !known.contains_key(&row.n),
            "row {} ({} {}): recorded {} {}; answered {status} {}",
            row.n,
            row.case,
            row.op,
            row.status,
            row.answer.to_value(),
            body.to_value(),
        );
    }
    assert_eq!(checked, 87, "the whole recording is replayed");
    assert_eq!(diverged, known.keys().copied().collect::<Vec<_>>());
}

#[test]
fn the_comparison_checks_member_order_except_inside_an_error_infos_metadata() {
    let info = |metadata: &str| {
        parse(
            format!(
                r#"{{"error":{{"code":403,"message":"m","status":"S","details":[{{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"R","domain":"d","metadata":{metadata}}}]}}}}"#
            )
            .as_bytes(),
        )
        .unwrap()
    };
    let one = info(r#"{"a":"1","b":"2"}"#);
    // The metadata of an ErrorInfo is a map: any order is the same.
    assert!(same_layout(&one, &info(r#"{"b":"2","a":"1"}"#)));
    // But not a different member, a missing one, or a different value.
    assert!(!same_layout(&one, &info(r#"{"a":"1","c":"2"}"#)));
    assert!(!same_layout(&one, &info(r#"{"a":"1"}"#)));
    assert!(!same_layout(&one, &info(r#"{"a":"1","b":"3"}"#)));
    // Everywhere else the order counts: the top of the error, the members of an ErrorInfo, an array.
    let swapped = parse(br#"{"error":{"code":403,"status":"S","message":"m"}}"#).unwrap();
    let plain = parse(br#"{"error":{"code":403,"message":"m","status":"S"}}"#).unwrap();
    assert!(!same_layout(&plain, &swapped));
    assert!(same_layout(&plain, &plain.clone()));
    let reordered_info = parse(
        br#"{"error":{"code":403,"message":"m","status":"S","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","domain":"d","reason":"R","metadata":{"a":"1","b":"2"}}]}}"#,
    )
    .unwrap();
    assert!(!same_layout(&one, &reordered_info));
    // A metadata outside an ErrorInfo is an ordinary member.
    let other = |metadata: &str| {
        parse(format!(r#"{{"@type":"x","metadata":{metadata}}}"#).as_bytes()).unwrap()
    };
    assert!(!same_layout(
        &other(r#"{"a":1,"b":2}"#),
        &other(r#"{"b":2,"a":1}"#)
    ));
    assert!(!same_layout(
        &parse(b"[1,2]").unwrap(),
        &parse(b"[2,1]").unwrap()
    ));
}

fn raw_fixture(name: &str) -> (u16, String) {
    let text = std::fs::read_to_string(format!(
        "{}/tests/fixtures/eventarc-stage-a/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the fixture exists");
    let fixture: serde_json::Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!(fixture["contentType"], "application/json; charset=UTF-8");
    (
        u16::try_from(fixture["status"].as_u64().expect("a status")).expect("a status"),
        fixture["body"].as_str().expect("a body").to_owned(),
    )
}

/// The bytes production wrote for two answers of preflight 002 (the raw bodies of the lane's fixtures).
#[test]
fn the_bytes_of_the_two_raw_production_bodies_are_reproduced_exactly() {
    let get = |method: &str, path: &str| {
        let (path, query) = path
            .split_once('?')
            .map_or((path, None), |(path, query)| (path, Some(query)));
        let route = route(method, path).expect("a route");
        let nothing = |_: &str| false;
        let nowhere = |_: &str, _: &str| false;
        let input = Input {
            route: &route,
            query,
            bearer: Some("ya29.replay-token"),
            body: b"",
        };
        let world = World {
            project: PROJECT,
            request_id: "0123456789abcdef",
            declared_channel: &nothing,
            declared_in: &nowhere,
        };
        match evaluate(&input, &world) {
            Outcome::Answer(answer) => (answer.status, answer.text()),
            Outcome::Deliver { .. } => panic!("an answer"),
        }
    };
    let (status, raw) = raw_fixture("preflight-002-channel-firebase-404.json");
    assert_eq!(raw.len(), 373);
    let missing = get(
        "GET",
        "/v1/projects/fireemu-oracle-idp/locations/us-central1/channels/firebase",
    );
    assert_eq!(missing, (status, raw));
    let (status, raw) = raw_fixture("preflight-002-channels-list.json");
    assert_eq!(raw, "{}\n");
    assert_eq!(
        get(
            "GET",
            "/v1/projects/fireemu-oracle-idp/locations/us-central1/channels?pageSize=100"
        ),
        (status, raw)
    );
}
