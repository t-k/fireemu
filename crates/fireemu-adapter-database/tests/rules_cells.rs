//! Rules expressions judged in every rule context (ruling 15), against what the official
//! emulator (firebase-database-emulator v4.11.2) answered. Each row of
//! `fixtures/rules-cells-official-emulator-4.11.2.json` was recorded by
//! `tools/rtdb-regex-fuzz/probe.mjs`: the expression as `.read` (with an `.indexOn`), as
//! `.write`, and as `.validate` beside `.write: true` at `/t/$k`, the load answer of each, and
//! the status of a read of `/t/o` without and with a query, of an event stream without and
//! with the query, of a listen and of a write to `/t/o`, each signed in and anonymously. Rows
//! recorded before the event stream with the query (`xa`, `xu`) was a cell hold null there. A row fireemu answers otherwise carries fireemu's answers and
//! why the difference is listed; none of them lets a request through that the official
//! emulator refuses.

use fireemu_adapter_database::realtime::{Opened, Session};
use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};

const NOW: i64 = 1_792_464_733_000;
const CELLS: [&str; 14] = [
    "ra", "ru", "qa", "qu", "sa", "su", "xa", "xu", "la", "lu", "wa", "wu", "va", "vu",
];
/// The cells of the `.read` context, and the event streams with the query among them.
const READ_CELLS: usize = 10;
const QUERY_STREAMS: [usize; 2] = [6, 7];
const SEED: &str = r#"{"t":{"o":{"s":"Hello","n":5,"d":2.5,"b":true,"z":0,"e":"","num":"5","k":"v","m":1,"o":{"k":"v","m":1,".priority":3},"arr":{"0":"a","1":"b"},".priority":7},"p":{"m":2}},"u":"u1"}"#;
const WRITTEN: &str = r#"{"k":"w","m":2,"s":"Hi","b":false}"#;
const QUERY: &str = "orderBy=%22m%22&startAt=0&limitToFirst=2";

fn b64(text: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in text.as_bytes().chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// The unsigned token the probe sends: user `u1` with custom claims.
fn token() -> String {
    format!(
        "{}.{}.",
        b64(r#"{"alg":"none","typ":"JWT"}"#),
        b64(
            r#"{"sub":"u1","uid":"u1","iat":1,"exp":9999999999,"email":"A@b.co","admin":true,"n":3,"roles":["x","y"]}"#
        )
    )
}

fn status(db: &mut Database, method: &str, target: &str, owner: bool, body: &str) -> (u16, String) {
    let headers = if owner {
        vec![("Authorization".to_owned(), "Bearer owner".to_owned())]
    } else {
        Vec::new()
    };
    let request = HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        headers,
        body: body.as_bytes().to_vec(),
    };
    match db.handle(&request, NOW) {
        Handled::Response { response, .. } => (
            response.status,
            String::from_utf8_lossy(&response.body).into_owned(),
        ),
        Handled::Stream { .. } => panic!("unexpected stream"),
    }
}

/// The status of an event stream of `/t/o`: 200 when it opens.
fn stream(db: &mut Database, target: &str) -> u16 {
    let request = HttpRequest {
        method: "GET".to_owned(),
        target: target.to_owned(),
        headers: vec![("Accept".to_owned(), "text/event-stream".to_owned())],
        body: Vec::new(),
    };
    match db.handle(&request, NOW) {
        Handled::Stream { .. } => 200,
        Handled::Response { response, .. } => response.status,
    }
}

/// A realtime listen of `/t/o`, signed in with `token` when given: 200 for `ok`, 401 for
/// `permission_denied`.
fn listen(db: &mut Database, token: Option<&str>) -> u16 {
    let Ok(Opened::Session(mut session, _)) =
        db.open_realtime("/.ws?v=5&ns=c", Some("127.0.0.1:9000"), NOW)
    else {
        panic!("no session");
    };
    let send = |session: &mut Session, db: &mut Database, frame: String| {
        session.receive(db, &frame, NOW).replies
    };
    if let Some(token) = token {
        send(
            &mut session,
            db,
            format!(r#"{{"t":"d","d":{{"r":1,"a":"auth","b":{{"cred":"{token}"}}}}}}"#),
        );
    }
    let replies = send(
        &mut session,
        db,
        r#"{"t":"d","d":{"r":2,"a":"q","b":{"p":"/t/o","h":""}}}"#.to_owned(),
    );
    let status = if replies.iter().any(|f| f.contains(r#""r":2,"b":{"s":"ok""#)) {
        200
    } else if replies
        .iter()
        .any(|f| f.contains(r#""s":"permission_denied""#))
    {
        401
    } else {
        panic!("no listen answer: {replies:?}")
    };
    db.close_realtime(session.client(), NOW);
    status
}

/// fireemu's answers for `expr`: the load answer and refusal text of each context, and each
/// cell's status (`None` when its context's rules were refused).
fn judge(expr: &str) -> (Vec<u16>, Vec<Option<String>>, Vec<Option<u16>>) {
    let token = token();
    let mut db = Database::new(RestOptions::default(), 1);
    // Written as the probe's JSON.stringify writes them, so refusals point at the same
    // columns.
    let rule = serde_json::to_string(expr).unwrap();
    let contexts = [
        format!(r#"{{"rules":{{"t":{{"$k":{{".read":{rule},".indexOn":["m"]}}}}}}}}"#),
        format!(r#"{{"rules":{{"t":{{"$k":{{".read":true,".write":{rule}}}}}}}}}"#),
        format!(
            r#"{{"rules":{{"t":{{"$k":{{".read":true,".write":true,".validate":{rule}}}}}}}}}"#
        ),
    ];
    let (mut loads, mut errors, mut cells) = (Vec::new(), Vec::new(), Vec::new());
    for (i, text) in contexts.iter().enumerate() {
        status(&mut db, "PUT", "/.json?ns=c", true, SEED);
        let (load, body) = status(&mut db, "PUT", "/.settings/rules.json?ns=c", true, text);
        loads.push(load);
        if load != 200 {
            let error: serde_json::Value = serde_json::from_str(&body).unwrap();
            errors.push(error["error"].as_str().map(str::to_owned));
            cells.extend(std::iter::repeat_n(
                None,
                if i == 0 { READ_CELLS } else { 2 },
            ));
            continue;
        }
        errors.push(None);
        if i == 0 {
            for target in [
                format!("/t/o.json?ns=c&auth={token}"),
                "/t/o.json?ns=c".to_owned(),
                format!("/t/o.json?ns=c&{QUERY}&auth={token}"),
                format!("/t/o.json?ns=c&{QUERY}"),
            ] {
                cells.push(Some(status(&mut db, "GET", &target, false, "").0));
            }
            cells.push(Some(stream(
                &mut db,
                &format!("/t/o.json?ns=c&auth={token}"),
            )));
            cells.push(Some(stream(&mut db, "/t/o.json?ns=c")));
            cells.push(Some(stream(
                &mut db,
                &format!("/t/o.json?ns=c&{QUERY}&auth={token}"),
            )));
            cells.push(Some(stream(&mut db, &format!("/t/o.json?ns=c&{QUERY}"))));
            cells.push(Some(listen(&mut db, Some(&token))));
            cells.push(Some(listen(&mut db, None)));
        } else {
            cells.push(Some(
                status(
                    &mut db,
                    "PUT",
                    &format!("/t/o.json?ns=c&auth={token}"),
                    false,
                    WRITTEN,
                )
                .0,
            ));
            status(&mut db, "PUT", "/.json?ns=c", true, SEED);
            cells.push(Some(
                status(&mut db, "PUT", "/t/o.json?ns=c", false, WRITTEN).0,
            ));
        }
    }
    (loads, errors, cells)
}

fn statuses(value: &serde_json::Value) -> Vec<Option<u16>> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_u64().map(|s| u16::try_from(s).unwrap()))
        .collect()
}

fn texts(value: &serde_json::Value) -> Vec<Option<String>> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().map(str::to_owned))
        .collect()
}

fn loads(value: &serde_json::Value) -> Vec<u16> {
    statuses(value).into_iter().map(Option::unwrap).collect()
}

#[test]
fn every_loaded_context_records_every_required_cell() {
    let corpus: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "fixtures/rules-cells-official-emulator-4.11.2.json"
    ))
    .unwrap();
    let mut missing = 0;
    let mut examples = Vec::new();
    for row in &corpus {
        for (name, recorded) in [("jar", Some(row)), ("fireemu", row.get("fireemu"))] {
            let Some(recorded) = recorded else { continue };
            assert_eq!(recorded["cells"].as_array().unwrap().len(), CELLS.len());
            for (i, cell) in CELLS.iter().enumerate() {
                let context = if i < READ_CELLS {
                    0
                } else {
                    1 + (i - READ_CELLS) / 2
                };
                let outcome = &recorded["cells"][i];
                let recorded_status = matches!(outcome.as_u64(), Some(200 | 401 | 500));
                // The oracle records this explicit realtime error instead of an HTTP status.
                // It is an observed refusal, unlike a missing cell or a probe timeout.
                let recorded_realtime_error =
                    name == "jar" && matches!(*cell, "la" | "lu") && outcome == "internal_error";
                if recorded["load"][context] == 200 && !(recorded_status || recorded_realtime_error)
                {
                    missing += 1;
                    if examples.len() < 5 {
                        examples.push(format!("{name} {cell}: {}", row["expr"]));
                    }
                }
            }
        }
    }
    assert_eq!(missing, 0, "unrecorded loaded cells: {examples:?}");
}

#[test]
fn every_recorded_expression_is_judged_as_the_official_emulator_in_every_cell() {
    let corpus: Vec<serde_json::Value> = serde_json::from_str(include_str!(
        "fixtures/rules-cells-official-emulator-4.11.2.json"
    ))
    .unwrap();
    assert!(corpus.len() > 13_000);
    let mut failures = Vec::new();
    let mut listed = 0;
    for row in &corpus {
        let expr = row["expr"].as_str().unwrap();
        let jar = (
            loads(&row["load"]),
            texts(&row["error"]),
            statuses(&row["cells"]),
        );
        let expected = match row.get("fireemu") {
            None => jar.clone(),
            Some(fireemu) => {
                listed += 1;
                let expected = (
                    loads(&fireemu["load"]),
                    texts(&fireemu["error"]),
                    statuses(&fireemu["cells"]),
                );
                // A listed difference never lets through what the official emulator refuses.
                for (i, cell) in CELLS.iter().enumerate() {
                    let context = if i < READ_CELLS {
                        0
                    } else {
                        1 + (i - READ_CELLS) / 2
                    };
                    let allowed = |(loads, _, cells): &(Vec<u16>, _, Vec<Option<u16>>)| {
                        loads[context] == 200 && cells[i] == Some(200)
                    };
                    assert!(!allowed(&expected) || allowed(&jar), "{expr} {cell}: {row}");
                }
                expected
            }
        };
        let mut got = judge(expr);
        // A row recorded before the event streams with the query were cells has none there.
        for i in QUERY_STREAMS {
            if expected.2[i].is_none() {
                got.2[i] = None;
            }
        }
        if got != expected {
            failures.push(format!("{expr:?}: got {got:?}, expected {expected:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} rows differ: {failures:#?}",
        failures.len()
    );
    assert!(listed > 0);
}
