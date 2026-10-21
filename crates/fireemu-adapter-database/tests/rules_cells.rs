//! Rules expressions judged in every rule context (ruling 15), against what the official
//! emulator (firebase-database-emulator v4.11.2) answered. Each row of
//! `fixtures/rules-cells-official-emulator-4.11.2.json` was recorded by
//! `tools/rtdb-regex-fuzz/probe.mjs`: the expression as `.read` (with an `.indexOn`), as
//! `.write`, and as `.validate` beside `.write: true` at `/t/$k`, the load answer of each, and
//! the status of a read of `/t/o` without and with a query and of a write to `/t/o`, each
//! signed in and anonymously. A row fireemu answers otherwise carries fireemu's answers and
//! why the difference is listed; none of them lets a request through that the official
//! emulator refuses.

use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};

const NOW: i64 = 1_792_464_733_000;
const CELLS: [&str; 8] = ["ra", "ru", "qa", "qu", "wa", "wu", "va", "vu"];
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
            cells.extend(std::iter::repeat_n(None, if i == 0 { 4 } else { 2 }));
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
                // A listed difference never lets through what the official emulator refuses,
                // except a pattern it cannot determinize: its own resource limit, which loads
                // here (ruling M14).
                let determinize = jar
                    .1
                    .iter()
                    .flatten()
                    .any(|error| error.contains("could not determinize efficiently"));
                for (i, cell) in CELLS.iter().enumerate().filter(|_| !determinize) {
                    let context = if i < 4 { 0 } else { 1 + (i - 4) / 2 };
                    let allowed = |(loads, _, cells): &(Vec<u16>, _, Vec<Option<u16>>)| {
                        loads[context] == 200 && cells[i] == Some(200)
                    };
                    assert!(!allowed(&expected) || allowed(&jar), "{expr} {cell}: {row}");
                }
                expected
            }
        };
        let got = judge(expr);
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
