//! The replay of a recording of production through the strict Eventarc surface, shared by the stage B and stage C tests:
//! the rows of a fixture are replayed in order through one server's state, each at the instant the server saw it,
//! and compared with what production answered (format masks on values only; every byte of layout compared).
#![allow(dead_code)]

use std::collections::BTreeMap;

use fireemu_adapter_functions::eventarc_channels::{ChannelStore, SystemEntropy, Timing};
use fireemu_adapter_functions::eventarc_strict::{evaluate, route, Input, Outcome, World};
use fireemu_adapter_functions::ordered_json::{parse, Ordered};

pub const PROJECT: &str = "fireemu-oracle-idp";
const NANOS_PER_MILLI: u64 = 1_000_000;

pub struct Row {
    pub n: u64,
    pub case: String,
    pub step: String,
    pub op: String,
    pub token: String,
    pub server_at_nanos: u64,
    pub method: String,
    pub path: String,
    pub body: Option<String>,
    pub status: u64,
    pub raw: String,
    pub bytes: usize,
}

pub fn member<'a>(value: &'a Ordered, name: &str) -> Option<&'a Ordered> {
    value
        .members()?
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, item)| item)
}

pub fn text(value: &Ordered) -> String {
    match value {
        Ordered::String(text) => text.clone(),
        other => panic!("not a string: {other:?}"),
    }
}

pub fn number(value: Option<&Ordered>) -> u64 {
    match value {
        Some(Ordered::Number(n)) => n.as_u64().expect("an unsigned number"),
        other => panic!("not a number: {other:?}"),
    }
}

/// The JSON text of a recorded request body: text the capture omitted is rebuilt as the recorder built
/// it, and every object keeps its member order.
pub fn body_text(value: &Ordered) -> String {
    match value {
        Ordered::Array(items) => format!(
            "[{}]",
            items.iter().map(body_text).collect::<Vec<_>>().join(",")
        ),
        Ordered::Object(members) => {
            if let [(name, omitted)] = members.as_slice() {
                if name == "omitted" {
                    let length = number(member(omitted, "length"));
                    let text = serde_json::to_string(
                        &"x".repeat(usize::try_from(length).expect("a small length") - 2),
                    )
                    .expect("a string");
                    assert_eq!(text.len() as u64, length, "the rebuilt text has its length");
                    return serde_json::to_string(&text).expect("a string");
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

pub fn instant(text: &str) -> u64 {
    let parsed = chrono::DateTime::parse_from_rfc3339(text).expect("a timestamp");
    u64::try_from(parsed.timestamp_millis()).expect("after the epoch")
}

/// The nanoseconds since the epoch at which the server saw the request of a row.
pub fn server_instant(row: &Ordered, answered_at_ms: u64) -> u64 {
    let op = text(member(row, "op").expect("an op"));
    let response = member(row, "response").expect("a response");
    if (op == "createChannel" || op == "deleteChannel") && number(member(response, "status")) == 200
    {
        let answer =
            parse(text(member(response, "rawBody").expect("a body")).as_bytes()).expect("JSON");
        let metadata = member(&answer, "metadata").expect("metadata");
        let created = chrono::DateTime::parse_from_rfc3339(&text(
            member(metadata, "createTime").expect("createTime"),
        ))
        .expect("a time");
        return u64::try_from(created.timestamp_nanos_opt().expect("nanoseconds"))
            .expect("positive");
    }
    // Millisecond precision from the recording; the sub-millisecond digits keep every timestamp at nine
    // fractional digits, as production wrote them.
    (answered_at_ms.saturating_sub(120)) * NANOS_PER_MILLI + 123_457
}

pub fn rows(fixture: &str) -> Vec<Row> {
    let bytes = std::fs::read(format!(
        "{}/tests/fixtures/{fixture}/rows.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("the fixture exists");
    let Ordered::Array(rows) = parse(&bytes).expect("the fixture is JSON") else {
        panic!("rows");
    };
    rows.iter()
        .map(|row| {
            let request = member(row, "request").expect("a request");
            let response = member(row, "response").expect("a response");
            let answered_at = instant(&text(member(row, "at").expect("a time")));
            Row {
                n: number(member(row, "n")),
                case: text(member(row, "case").expect("a case")),
                step: text(member(row, "step").expect("a step")),
                op: text(member(row, "op").expect("an op")),
                token: text(member(row, "token").expect("a token")),
                server_at_nanos: server_instant(row, answered_at),
                method: text(member(request, "method").expect("a method")),
                path: text(member(request, "path").expect("a path")),
                body: member(request, "body").map(body_text),
                status: number(member(response, "status")),
                raw: text(member(response, "rawBody").expect("a body")),
                bytes: usize::try_from(number(member(response, "bodyBytes"))).expect("a size"),
            }
        })
        .collect()
}

// --- masks by format ---------------------------------------------------------------------------------

pub fn digits(text: &str, count: usize) -> bool {
    text.len() == count && text.bytes().all(|b| b.is_ascii_digit())
}

pub fn hex(text: &str, count: usize) -> bool {
    text.len() == count && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `2026-10-05T11:11:29.877140422Z`: nine fractional digits.
pub fn timestamp9(text: &str) -> bool {
    let bytes = text.as_bytes();
    text.len() == 30
        && text.ends_with('Z')
        && bytes[10] == b'T'
        && bytes[19] == b'.'
        && chrono::DateTime::parse_from_rfc3339(text).is_ok()
        && digits(&text[20..29], 9)
}

/// A version 4 UUID in its canonical lower-case form.
pub fn uuid4(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    parts.len() == 5
        && hex(parts[0], 8)
        && hex(parts[1], 4)
        && hex(parts[2], 4)
        && hex(parts[3], 4)
        && hex(parts[4], 12)
        && parts[2].starts_with('4')
        && matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b')
}

/// `operation-<13 digits>-<13 hex>-<8 hex>-<8 hex>`.
pub fn operation_id(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    parts.len() == 5
        && parts[0] == "operation"
        && digits(parts[1], 13)
        && hex(parts[2], 13)
        && hex(parts[3], 8)
        && hex(parts[4], 8)
}

pub fn base64url(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn normalize(value: &Ordered, key: Option<&str>) -> Ordered {
    match value {
        Ordered::Array(items) => {
            Ordered::Array(items.iter().map(|item| normalize(item, key)).collect())
        }
        Ordered::Object(members) => Ordered::Object(
            members
                .iter()
                .map(|(name, item)| (name.clone(), normalize(item, Some(name))))
                .collect(),
        ),
        Ordered::String(text) => Ordered::text(mask(text, key)),
        other => other.clone(),
    }
}

pub fn mask(text: &str, key: Option<&str>) -> String {
    match key {
        Some("requestId") if hex_any(text, 16) => "<requestId>".to_owned(),
        Some("uid") if uuid4(text) => "<uid>".to_owned(),
        Some("createTime" | "updateTime" | "endTime") if timestamp9(text) => "<time9>".to_owned(),
        Some("nextPageToken") if base64url(text) => format!("<token:{}>", text.len()),
        Some("message") => match text
            .strip_prefix("An internal error has occurred (")
            .and_then(|rest| rest.strip_suffix(')'))
        {
            Some(id) if hex_uuid(id) => "An internal error has occurred (<errorId>)".to_owned(),
            _ => text.to_owned(),
        },
        Some("name") if text.contains("/operations/") => match text.rsplit_once("/operations/") {
            Some((parent, id)) if operation_id(id) => format!("{parent}/operations/<operation>"),
            _ => text.to_owned(),
        },
        Some("pubsubTopic") => match text.rsplit_once('-') {
            Some((head, suffix)) if digits(suffix, 3) && text.starts_with("projects/") => {
                format!("{head}-<NNN>")
            }
            _ => text.to_owned(),
        },
        _ => text.to_owned(),
    }
}

/// The text of an answer with every masked value replaced by its format mask, and nothing else touched: every
/// byte of the layout (indentation, line breaks, spacing, the trailing newline) is still compared. The one
/// exemption is the order of the members of an `ErrorInfo`'s `metadata` (a proto map: production varies it),
/// whose entries are sorted on both sides.
pub fn mask_text(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut key: Option<String> = None;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'"' {
            let ch = raw[i..].chars().next().expect("a character");
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let mut j = i + 1;
        while j < bytes.len() && bytes[j] != b'"' {
            if bytes[j] == b'\\' {
                j += 1;
            }
            j += 1;
        }
        let inner = &raw[i + 1..j];
        let mut k = j + 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if bytes.get(k) == Some(&b':') {
            key = Some(inner.to_owned());
            out.push_str(&raw[i..=j]);
        } else {
            out.push('"');
            out.push_str(&mask(inner, key.as_deref()));
            out.push('"');
        }
        i = j + 1;
    }
    sort_metadata(&out)
}

/// Sorts the entries of every `"metadata": {...}` block (flat, string values) and keeps its whitespace.
pub fn sort_metadata(text: &str) -> String {
    const OPEN: &str = "\"metadata\": {";
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(OPEN) {
        let start = at + OPEN.len();
        let end = start + rest[start..].find('}').expect("a closing brace");
        out.push_str(&rest[..start]);
        let inner = &rest[start..end];
        let lead = &inner[..inner.len() - inner.trim_start().len()];
        let trail = &inner[inner.trim_end().len()..];
        let mut entries: Vec<&str> = inner.trim().split(",\n").map(str::trim).collect();
        entries.sort_unstable();
        out.push_str(lead);
        out.push_str(&entries.join(&format!(",\n{}", lead.trim_start_matches('\n'))));
        out.push_str(trail);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// A UUID-shaped identifier (8-4-4-4-12 hex digits; no version is claimed).
/// The channels of a list answer, by name.
fn channel_names(body: &Ordered) -> Option<Vec<String>> {
    match member(body, "channels")? {
        Ordered::Array(items) => items
            .iter()
            .map(|item| member(item, "name").map(text))
            .collect(),
        _ => None,
    }
}

/// Whether two list answers differ only in the order of production's pages.
fn order_equivalent(row: &Row, recorded: &Ordered, got: &Replayed) -> bool {
    if u64::from(got.status) != row.status {
        return false;
    }
    let (Some(mut theirs), Some(mut ours)) = (channel_names(recorded), channel_names(&got.body))
    else {
        return false;
    };
    let paged = row.path.contains("pageToken=")
        || (row.path.contains("pageSize=") && member(recorded, "nextPageToken").is_some());
    let last_page = member(recorded, "nextPageToken").is_none();
    if theirs.len() != ours.len()
        || member(recorded, "nextPageToken").is_some()
            != member(&got.body, "nextPageToken").is_some()
    {
        return false;
    }
    if !paged || (last_page && !row.path.contains("pageToken=")) {
        theirs.sort();
        ours.sort();
        return theirs == ours;
    }
    true
}

pub fn hex_uuid(text: &str) -> bool {
    let parts: Vec<&str> = text.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(count, part)| hex_any(part, *count))
}

pub fn hex_any(text: &str, count: usize) -> bool {
    text.len() == count && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether two bodies are the same, member order included. The one exemption is the `metadata` of an
/// `ErrorInfo` (a proto map: its order varies in production), whose members are compared as a set.
pub fn same_layout(a: &Ordered, b: &Ordered) -> bool {
    match (a, b) {
        (Ordered::Array(x), Ordered::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(x, y)| same_layout(x, y))
        }
        (Ordered::Object(x), Ordered::Object(y)) => {
            let error_info = a["@type"] == "type.googleapis.com/google.rpc.ErrorInfo";
            x.len() == y.len()
                && x.iter().zip(y).all(|((xk, xv), (yk, yv))| {
                    xk == yk
                        && if error_info && xk == "metadata" {
                            same_set(xv, yv)
                        } else {
                            same_layout(xv, yv)
                        }
                })
        }
        (x, y) => x == y,
    }
}

pub fn same_set(a: &Ordered, b: &Ordered) -> bool {
    match (a, b) {
        (Ordered::Object(x), Ordered::Object(y)) => {
            let count = |members: &[(String, Ordered)], key: &str, value: &Ordered| {
                members
                    .iter()
                    .filter(|(k, v)| k == key && v == value)
                    .count()
            };
            x.len() == y.len()
                && x.iter()
                    .all(|(key, value)| count(x, key, value) == count(y, key, value))
        }
        (x, y) => x == y,
    }
}

// --- the replay --------------------------------------------------------------------------------------

/// How long each operation of the recording took, by operation name.
pub fn recorded_durations(rows: &[Row]) -> BTreeMap<String, u64> {
    let mut durations = BTreeMap::new();
    for row in rows.iter().filter(|row| row.op == "getOperation") {
        let Ok(answer) = parse(row.raw.as_bytes()) else {
            continue;
        };
        if member(&answer, "done").is_some_and(|done| *done == Ordered::Bool(true)) {
            let metadata = member(&answer, "metadata").expect("metadata");
            let start = chrono::DateTime::parse_from_rfc3339(&text(
                member(metadata, "createTime").expect("createTime"),
            ))
            .expect("a time");
            let end = chrono::DateTime::parse_from_rfc3339(&text(
                member(metadata, "endTime").expect("endTime"),
            ))
            .expect("a time");
            durations.insert(
                text(member(&answer, "name").expect("a name")),
                u64::try_from((end - start).num_nanoseconds().expect("nanoseconds"))
                    .expect("positive"),
            );
        }
    }
    durations
}

pub struct Replayed {
    pub status: u16,
    pub body: Ordered,
    pub text: String,
}

pub fn bearer_of(token: &str) -> Option<&'static str> {
    match token {
        "none" => None,
        "invalid" => Some("invalid-token-for-the-recording"),
        "ya29-garbage" => Some("ya29.fireemu-recorder-not-a-token-0000000000000000"),
        "jwt-garbage" | "jwt-expired-unsigned" => {
            Some("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.signature")
        }
        "wrong-scope" => Some("ya29.a-token-of-another-scope"),
        _ => Some("ya29.replay-token"),
    }
}

pub fn replay_all(rows: &[Row]) -> Vec<Replayed> {
    let durations = recorded_durations(rows);
    let store = ChannelStore::new(Box::new(SystemEntropy::default()), Timing::default());
    let nothing = |_: &str| false;
    let none_declared = |_: &str, _: &str| Vec::new();
    let mut replayed = Vec::new();
    // The operations this server started, by the name production gave the operation of the same request:
    // a later read names the recorded operation, and asks this server for its own.
    let mut operations: BTreeMap<String, String> = BTreeMap::new();
    // The same for page tokens: a token of production is opaque, and not valid for another server.
    let mut tokens: BTreeMap<String, String> = BTreeMap::new();
    for row in rows {
        let request_path = if row.op == "getOperation" {
            let recorded = row.path.trim_start_matches("/v1/");
            operations
                .get(recorded)
                .map_or_else(|| row.path.clone(), |ours| format!("/v1/{ours}"))
        } else {
            row.path.clone()
        };
        let request_path = match request_path.split_once("pageToken=") {
            Some((head, token)) => {
                let token = token.split('&').next().unwrap_or_default();
                format!(
                    "{head}pageToken={}",
                    tokens.get(token).map_or(token, String::as_str)
                )
            }
            None => request_path,
        };
        let (path, query) = request_path
            .split_once('?')
            .map_or((request_path.as_str(), None), |(path, query)| {
                (path, Some(query))
            });
        let route = route(&row.method, path).unwrap_or_else(|| panic!("row {} has a route", row.n));
        // The operation the recording started takes as long as the recorded one did.
        if (row.op == "createChannel" || row.op == "deleteChannel") && row.status == 200 {
            let answer = parse(row.raw.as_bytes()).expect("JSON");
            let name = text(member(&answer, "name").expect("an operation"));
            if let Some(duration) = durations.get(&name) {
                let defaults = Timing::default();
                store.set_timing(if row.op == "createChannel" {
                    Timing {
                        create: *duration,
                        ..defaults
                    }
                } else {
                    Timing {
                        delete: *duration,
                        ..defaults
                    }
                });
            }
        }
        let body = row.body.clone().unwrap_or_default().into_bytes();
        let input = Input {
            route: &route,
            query,
            bearer: bearer_of(&row.token),
            body: &body,
        };
        let world = World {
            project: PROJECT,
            request_id: "0123456789abcdef",
            declared_channel: &nothing,
            declared_in: &none_declared,
            channels: &store,
            now: row.server_at_nanos,
        };
        replayed.push(match evaluate(&input, &world) {
            Outcome::Answer(answer) => {
                if (row.op == "createChannel" || row.op == "deleteChannel") && answer.status == 200
                {
                    let recorded = parse(row.raw.as_bytes()).expect("JSON");
                    // A 200 that names no operation is a divergence of that row (reported by the comparison).
                    if let (Some(theirs), Some(ours)) =
                        (member(&recorded, "name"), member(&answer.body, "name"))
                    {
                        operations.insert(text(theirs), text(ours));
                    }
                }
                if let (Some(Ordered::String(ours)), Ok(recorded)) = (
                    member(&answer.body, "nextPageToken"),
                    parse(row.raw.as_bytes()),
                ) {
                    if let Some(Ordered::String(theirs)) = member(&recorded, "nextPageToken") {
                        tokens.insert(theirs.clone(), ours.clone());
                    }
                }
                Replayed {
                    status: answer.status,
                    text: answer.text(),
                    body: answer.body,
                }
            }
            Outcome::Deliver { .. } => {
                panic!("row {}: nothing is declared, nothing is delivered", row.n)
            }
        });
    }
    replayed
}

/// Replays the fixture and fails when a row not named in `known` diverges, or a named row stops diverging.
pub fn check(fixture: &str, expected_rows: usize, known_rows: &[(u64, &str)]) {
    let known: BTreeMap<u64, &str> = known_rows.iter().copied().collect();
    let rows = rows(fixture);
    assert_eq!(rows.len(), expected_rows, "the whole recording is replayed");
    let replayed = replay_all(&rows);
    let mut diverged = Vec::new();
    let mut details = Vec::new();
    let mut order_only = Vec::new();
    for (row, got) in rows.iter().zip(&replayed) {
        let recorded = parse(row.raw.as_bytes()).expect("the recorded body is JSON");
        let same = u64::from(got.status) == row.status
            && same_layout(&normalize(&got.body, None), &normalize(&recorded, None))
            && got.text.len() == row.bytes
            && mask_text(&got.text) == mask_text(&row.raw);
        if !same {
            // A row named for the order of a list must differ in nothing else: the same status, the same number of
            // channels, a next-page token or none as recorded, and, for a whole list (no paging), the same channels.
            if known
                .get(&row.n)
                .is_some_and(|reason| reason.starts_with("ORDER:"))
            {
                assert!(
                    order_equivalent(row, &recorded, got),
                    "row {} is named for the order of a list but differs in more",
                    row.n
                );
                order_only.push(row.n);
            }
            diverged.push(row.n);
            if !known.contains_key(&row.n) {
                details.push(format!(
                    "row {} ({}/{} {}): recorded {} {} ({} bytes); answered {} {} ({} bytes)",
                    row.n,
                    row.case,
                    row.step,
                    row.op,
                    row.status,
                    normalize(&recorded, None).to_value(),
                    row.bytes,
                    got.status,
                    normalize(&got.body, None).to_value(),
                    got.text.len(),
                ));
            }
        }
    }
    let unexpected: Vec<u64> = diverged
        .iter()
        .copied()
        .filter(|n| !known.contains_key(n))
        .collect();
    let fixed: Vec<u64> = known
        .keys()
        .copied()
        .filter(|n| !diverged.contains(n))
        .collect();
    if std::env::var_os("EVENTARC_REPLAY_LIST").is_some() {
        let mut per_case: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for row in &rows {
            let entry = per_case.entry(row.case.as_str()).or_default();
            entry.1 += 1;
            if !diverged.contains(&row.n) {
                entry.0 += 1;
            }
        }
        for (case, (matched, total)) in &per_case {
            eprintln!("per-case {fixture} {case}: {matched} of {total}");
        }
        eprintln!("diverging rows: {diverged:?}");
        for row in rows
            .iter()
            .zip(&replayed)
            .filter(|(r, _)| diverged.contains(&r.n))
        {
            eprintln!(
                "row {} ({}/{} {}): recorded {} ({} bytes) answered {} ({} bytes)",
                row.0.n,
                row.0.case,
                row.0.step,
                row.0.op,
                row.0.status,
                row.0.bytes,
                row.1.status,
                row.1.text.len()
            );
        }
    }
    assert!(
        unexpected.is_empty() && fixed.is_empty(),
        "diverging rows not named: {unexpected:?}; named rows that no longer diverge: {fixed:?}\n{}",
        details.iter().take(8).cloned().collect::<Vec<_>>().join("\n")
    );
    eprintln!(
        "{fixture}: {} of {} rows reproduced, {} named ({} of them differ only in the order of a list)",
        rows.len() - diverged.len(),
        rows.len(),
        diverged.len(),
        order_only.len()
    );
}
