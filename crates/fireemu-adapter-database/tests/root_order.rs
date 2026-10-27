//! The order in which the per-path listens of one connection hear a single write that covers all of them: a REST
//! `PUT`/`PATCH`, a realtime `p`/`m`, and an `onDisconnect` value fired when the writer's connection ends. Every
//! expectation is what the official emulator (firebase-database-emulator v4.11.2) sent for the same raw frames,
//! probed offline (docs.local/runs/rtdb-root-order); production has not observed these shapes. Listens that the
//! write covers hear in the text order of their paths, a listen above another before it; the entries of a
//! multi-path write keep the order of the entries.

use fireemu_adapter_database::realtime::{Opened, Session};
use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};

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

fn rest(db: &mut Database, method: &str, target: &str, body: &str) {
    let request = HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
    };
    match db.handle(&request, NOW) {
        Handled::Response { response, .. } => assert!(response.status < 300, "{response:?}"),
        Handled::Stream { .. } => panic!("unexpected stream"),
    }
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

fn cases() -> serde_json::Value {
    let text = include_str!("fixtures/root-order-official-emulator-4.11.2.json");
    serde_json::from_str(text).unwrap()
}

/// What an observer that listens at `listens` (below `/k`; `""` is `/k` itself) hears when `write` happens.
fn heard(ns: &str, write: &serde_json::Value, listens: &[String]) -> Vec<String> {
    let mut db = Database::new(RestOptions::default(), 1);
    let mut observer = open(&mut db, ns);
    for (r, listen) in (1..).zip(listens) {
        let path = if listen.is_empty() {
            "/k".to_owned()
        } else {
            format!("/k/{listen}")
        };
        send(
            &mut db,
            &mut observer,
            &format!(r#"{{"t":"d","d":{{"r":{r},"a":"q","b":{{"p":"{path}","h":""}}}}}}"#),
        );
    }
    db.drain_pushes();
    let below = write["path"].as_str().unwrap();
    let at = if below.is_empty() {
        "/k".to_owned()
    } else {
        format!("/k/{below}")
    };
    let data = write["data"].to_string();
    match write["kind"].as_str().unwrap() {
        "rest-put" => rest(&mut db, "PUT", &format!("{at}.json?ns={ns}"), &data),
        "rest-patch" => rest(&mut db, "PATCH", &format!("{at}.json?ns={ns}"), &data),
        kind => {
            let mut writer = open(&mut db, ns);
            let action = match kind {
                "realtime-p" => "p",
                "realtime-m" => "m",
                "ondisconnect" => "o",
                other => panic!("{other}"),
            };
            send(
                &mut db,
                &mut writer,
                &format!(
                    r#"{{"t":"d","d":{{"r":1,"a":"{action}","b":{{"p":"{at}","d":{data}}}}}}}"#
                ),
            );
            if kind == "ondisconnect" {
                db.drain_pushes();
                db.close_realtime(writer.client(), NOW + 1);
            }
        }
    }
    db.drain_pushes()
        .into_iter()
        .filter(|(client, _)| *client == observer.client())
        .map(|(_, frame)| summary(&frame))
        .collect()
}

#[test]
fn every_recorded_write_is_heard_in_the_order_the_official_emulator_sent_it() {
    let cases = cases();
    let all = cases["cases"].as_array().unwrap();
    assert!(all.len() >= 70, "{} cases", all.len());
    let mut wrong = Vec::new();
    for (n, case) in all.iter().enumerate() {
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
                format!(
                    "{kind}:k{}{rest}",
                    if rest.is_empty() || rest.starts_with('{') {
                        ""
                    } else {
                        "/"
                    }
                )
            })
            .collect();
        let got = heard(&format!("o{n}"), &case["write"], &listens);
        if got != want {
            wrong.push(format!("{}: got {got:?}, want {want:?}", case["name"]));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} cases differ:\n{}",
        wrong.len(),
        all.len(),
        wrong.join("\n")
    );
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    fn text_order(listens: &[String]) -> Vec<String> {
        let mut sorted: Vec<Vec<&str>> = listens.iter().map(|l| l.split('/').collect()).collect();
        sorted.sort();
        sorted
            .iter()
            .map(|keys| format!("d:k/{}", keys.join("/")))
            .collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(300))]

        /// One written path that covers every listen is heard in the path order by text, a listen above another
        /// before it, whatever the order the listens were registered in and whichever way the write arrives.
        #[test]
        fn a_write_that_covers_the_listens_is_heard_in_path_order(
            listens in prop::collection::btree_set(
                prop::collection::vec(prop::sample::select(vec!["a", "b", "c", "9", "10", "q10", "q9"]), 1..4).prop_map(|keys| keys.join("/")),
                1..7,
            ),
            shuffle in any::<u64>(),
            kind in prop::sample::select(vec!["rest-put", "realtime-p", "ondisconnect"]),
        ) {
            let mut registered: Vec<String> = listens.iter().cloned().collect();
            // A deterministic shuffle: the registration order must not matter.
            let mut seed = shuffle;
            for i in (1..registered.len()).rev() {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                registered.swap(i, (seed >> 33) as usize % (i + 1));
            }
            let write = serde_json::json!({"kind": kind, "path": "", "data": {"z": 1}});
            prop_assert_eq!(heard("prop", &write, &registered), text_order(&listens.iter().cloned().collect::<Vec<_>>()));
        }
    }
}
