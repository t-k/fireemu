//! What an ending connection fires when a registered onDisconnect value that carries a priority was split by a
//! cancel (order review S5). Production (RTDB-S5-20261027-01, two rounds, 2026-10-27) answered that nothing fires: the
//! whole update of the connection is dropped, the unrelated write registered next to it included. The other cases are
//! what the official emulator (firebase-database-emulator v4.11.2) does for the same raw realtime frames, probed
//! offline: the split leaves the connection's registrations broken until the value is cancelled or registered again.

use fireemu_adapter_database::realtime::{Opened, Session};
use fireemu_adapter_database::rest::{Database, RestOptions};

const NOW: i64 = 1_792_417_166_902;

fn open(db: &mut Database, ns: &str) -> Session {
    match db.open_realtime(&format!("/.ws?v=5&ns={ns}"), Some("127.0.0.1:9000"), NOW) {
        Ok(Opened::Session(session, _)) => session,
        other => panic!("{other:?}"),
    }
}

fn send(db: &mut Database, session: &mut Session, frame: &str) {
    session.receive(db, frame, NOW);
}

/// `d:k/e5` or `m:k{a,b}` for a pushed frame.
fn summary(frame: &str) -> String {
    let action = frame
        .rsplit(r#""a":""#)
        .next()
        .unwrap()
        .trim_end_matches(['}', '"'])
        .to_owned();
    let path = frame
        .split(r#""p":""#)
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    // `{"t":"d","d":{"b":{"p":"<path>","d":<DATA>},"a":"<action>"}}`: DATA ends before `},"a":"..."}}`.
    let after_path = frame.find(r#""p":""#).unwrap();
    let start = after_path + frame[after_path..].find(r#"","d":"#).unwrap() + r#"","d":"#.len();
    let end = frame.len() - format!(r#"}},"a":"{action}"}}}}"#).len();
    let data = &frame[start..end];
    if action == "m" {
        // The members in the order the frame lists them.
        let inner = data.trim_start_matches('{');
        let mut names = Vec::new();
        let mut depth = 0;
        let mut quote = false;
        let mut current = String::new();
        let mut key = true;
        for ch in inner.chars() {
            match ch {
                '"' => {
                    quote = !quote;
                    if !quote && depth == 0 && key {
                        names.push(std::mem::take(&mut current));
                        key = false;
                    }
                }
                '{' if !quote => depth += 1,
                '}' if !quote => depth -= 1,
                ',' if !quote && depth == 0 => key = true,
                c if quote && depth == 0 && key => current.push(c),
                _ => {}
            }
        }
        format!("m:{path}{{{}}}", names.join(","))
    } else {
        format!("d:{path}")
    }
}

/// What a connection that listens at `listens` (below `/k`) hears when the connections register `connections` (each a
/// list of `o`/`oc` operations at paths below `/k`) and then end, in that order.
fn after_registrations(
    ns: &str,
    listens: &[String],
    connections: &[Vec<(String, String, Option<serde_json::Value>)>],
) -> Vec<String> {
    let mut db = Database::new(RestOptions::default(), 1);
    let mut observer = open(&mut db, ns);
    for (r, listen) in (1..).zip(listens) {
        send(
            &mut db,
            &mut observer,
            &format!(r#"{{"t":"d","d":{{"r":{r},"a":"q","b":{{"p":"/k/{listen}","h":""}}}}}}"#),
        );
    }
    db.drain_pushes();
    let mut writers = Vec::new();
    for ops in connections {
        let mut writer = open(&mut db, ns);
        for (r, (action, path, data)) in (1..).zip(ops) {
            let at = if path.is_empty() {
                "/k".to_owned()
            } else {
                format!("/k/{path}")
            };
            let body = data.as_ref().map_or_else(
                || format!(r#"{{"p":"{at}"}}"#),
                |d| format!(r#"{{"p":"{at}","d":{d}}}"#),
            );
            send(
                &mut db,
                &mut writer,
                &format!(r#"{{"t":"d","d":{{"r":{r},"a":"{action}","b":{body}}}}}"#),
            );
        }
        db.drain_pushes();
        writers.push(writer);
    }
    for writer in writers {
        db.close_realtime(writer.client(), NOW + 1);
    }
    db.drain_pushes()
        .into_iter()
        .filter(|(client, _)| *client == observer.client())
        .map(|(_, frame)| summary(&frame))
        .collect()
}

fn cases() -> serde_json::Value {
    let text = include_str!("fixtures/ondisconnect-priority-drop-official-emulator-4.11.2.json");
    serde_json::from_str(text).unwrap()
}

#[test]
fn every_recorded_case_fires_what_the_official_emulator_fired() {
    let cases = cases();
    let all = cases["cases"].as_array().unwrap();
    assert!(all.len() >= 22, "{} cases", all.len());
    for (n, case) in all.iter().enumerate() {
        let connections: Vec<Vec<(String, String, Option<serde_json::Value>)>> = case
            ["connections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ops| {
                ops.as_array()
                    .unwrap()
                    .iter()
                    .map(|op| {
                        (
                            op[0].as_str().unwrap().to_owned(),
                            op[1].as_str().unwrap().to_owned(),
                            op.get(2).cloned(),
                        )
                    })
                    .collect()
            })
            .collect();
        let listens: Vec<String> = case["listens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap().to_owned())
            .collect();
        let want: Vec<String> = case["order"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                let (kind, rest) = f.as_str().unwrap().split_once(':').unwrap();
                format!("{kind}:k/{rest}")
            })
            .collect();
        assert_eq!(
            after_registrations(&format!("p{n}"), &listens, &connections),
            want,
            "{}",
            case["name"]
        );
    }
}

#[test]
fn the_production_shape_fires_nothing_not_even_the_write_beside_it() {
    let listens: Vec<String> = ["s", "t"].iter().map(|s| (*s).to_owned()).collect();
    let ops = vec![
        (
            "o".to_owned(),
            "s".to_owned(),
            Some(serde_json::json!({".priority": 1, "b": 1, "c": 2})),
        ),
        ("oc".to_owned(), "s/b".to_owned(), None),
        ("o".to_owned(), "t".to_owned(), Some(serde_json::json!(1))),
    ];
    assert!(after_registrations("production", &listens, &[ops]).is_empty());
}
