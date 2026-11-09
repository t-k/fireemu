//! The Rules constructs production was recorded loading and evaluating (run
//! RTDB-RULES-SYNTAX-20261108-01, owner 2350): `query.endBefore`, `query.isOrderByChild()`, the
//! `OrderByKey`, `OrderByValue` and `OrderByPriority` names, `http.encodeURL()`, a method read
//! without a call (directly and through a ternary) and a call whose callee is a ternary. Every
//! recorded row is replayed in both profiles, in the recorded order, and must give the recorded
//! status and body. Production answered as the official emulator 4.11.2 in all 86 rows, so the two
//! profiles do not differ here.

use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};

const NOW: i64 = 1_794_000_000_000;
const FIXTURE: &str =
    include_str!("../../../tools/sdk-smoke-database/fixtures/production-sdk-rules-syntax.json");
/// The production scope root: the rows name `{scope}` for `<prefix>/rules-syntax/<profile>`.
const PREFIX: &str = "sdkrulesyntax/rules-syntax";

fn send(db: &mut Database, method: &str, target: &str, owner: bool, body: &str) -> (u16, String) {
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
            String::from_utf8(response.body).expect("UTF-8 answer"),
        ),
        Handled::Stream { .. } => panic!("unexpected stream for {method} {target}"),
    }
}

fn replay(strict: bool) -> Vec<String> {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    assert_eq!(
        fixture["provenance"]["runId"],
        "RTDB-RULES-SYNTAX-20261108-01"
    );
    assert_eq!(fixture["result"]["observed"], 86);
    let mut db = Database::new(
        RestOptions {
            production_shapes: strict,
            ..RestOptions::default()
        },
        42,
    );
    let mut differences = Vec::new();
    let mut replayed = 0;
    for profile in fixture["profiles"].as_array().unwrap() {
        let name = profile["name"].as_str().unwrap();
        for row in profile["rows"].as_array().unwrap() {
            let id = row["id"].as_str().unwrap();
            if row["outcome"] == "not-loaded" {
                differences.push(format!("{name}/{id}: production refused a document"));
                continue;
            }
            let path = row["path"]
                .as_str()
                .unwrap()
                .replace("{scope}", &format!("/{PREFIX}/{name}"));
            let query = row["query"].as_str().unwrap();
            let target = format!(
                "{path}?ns=syntax{}{query}",
                if query.is_empty() { "" } else { "&" }
            );
            let identity = row["identity"].as_str().unwrap();
            let body = row["requestBody"].as_str().unwrap_or("");
            let (status, answer) = send(
                &mut db,
                row["method"].as_str().unwrap(),
                &target,
                identity != "anonymous",
                body,
            );
            replayed += 1;
            let want = (
                u16::try_from(row["status"].as_u64().unwrap()).unwrap(),
                row["body"].as_str().unwrap(),
            );
            if (status, answer.as_str()) != want {
                differences.push(format!(
                    "{name}/{id} ({}): got {status} {answer:?}, recorded {} {:?}",
                    if strict { "strict" } else { "emulator" },
                    want.0,
                    want.1
                ));
            }
        }
    }
    assert_eq!(replayed, 86);
    differences
}

#[test]
fn the_emulator_profile_answers_every_recorded_row_as_production() {
    let differences = replay(false);
    assert!(differences.is_empty(), "{differences:#?}");
}

#[test]
fn the_strict_profile_answers_every_recorded_row_as_production() {
    let differences = replay(true);
    assert!(differences.is_empty(), "{differences:#?}");
}
