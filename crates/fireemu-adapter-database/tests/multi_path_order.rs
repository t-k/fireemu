//! The order in which the frames of one multi-path write reach a connection's listens, and the
//! order of the members inside a merge frame. Every expectation is what the official emulator
//! (firebase-database-emulator v4.11.2) sent for the same listens and writes, probed offline
//! with raw realtime frames; the six-key onDisconnect case is also what production sent
//! (RTDB-RESIDUAL-20261026-05). The entries of the write are ordered like a Scala map
//! (see `scala_map`): insertion order up to four, by key hash from five.

use fireemu_adapter_database::realtime::{Opened, Session};
use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};

const NOW: i64 = 1_792_417_166_902;
const SIX: [&str; 6] = ["e2", "e3", "e4", "e5", "e6", "marker"];

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

/// `{"c1":"init",...}` for the given children.
fn init(children: &[&str]) -> String {
    let members: Vec<String> = children
        .iter()
        .map(|c| format!(r#""{c}":"init""#))
        .collect();
    format!("{{{}}}", members.join(","))
}

/// What a connection that listens at `listens` (below `/k`; `""` is `/k` itself) receives, as
/// `action:path` and the members of a merge, when `write` is sent after the data `data` was put at `/k`.
fn received(
    ns: &str,
    data: &str,
    listens: &[&str],
    write: impl FnOnce(&mut Database, &mut Session),
) -> Vec<String> {
    let mut db = Database::new(RestOptions::default(), 1);
    rest(&mut db, "PUT", &format!("/k.json?ns={ns}"), data);
    let mut a = open(&mut db, ns);
    for (r, listen) in (1..).zip(listens) {
        let path = if listen.is_empty() {
            "/k".to_owned()
        } else {
            format!("/k/{listen}")
        };
        send(
            &mut db,
            &mut a,
            &format!(r#"{{"t":"d","d":{{"r":{r},"a":"q","b":{{"p":"{path}","h":""}}}}}}"#),
        );
    }
    db.drain_pushes();
    let mut b = open(&mut db, ns);
    write(&mut db, &mut b);
    db.drain_pushes()
        .into_iter()
        .filter(|(client, _)| *client == a.client())
        .map(|(_, frame)| summary(&frame))
        .collect()
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
    let data = frame.split(r#""d":"#).nth(2).unwrap_or("");
    if action == "m" {
        // The members in the order the frame lists them.
        let inner = data
            .split(r#"},"a":"#)
            .next()
            .unwrap()
            .trim_start_matches('{');
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

fn merge(body: &'static str) -> impl FnOnce(&mut Database, &mut Session) {
    move |db, b| {
        send(
            db,
            b,
            &format!(r#"{{"t":"d","d":{{"r":1,"a":"m","b":{{"p":"/k","d":{body}}}}}}}"#),
        );
    }
}

#[test]
fn per_path_listens_hear_a_six_key_merge_in_the_scala_map_order_whatever_the_listen_order() {
    let write = r#"{"e2":"z","e3":"z","e4":"z","e5":"z","e6":"z","marker":"z"}"#;
    let want = [
        "d:k/e6",
        "d:k/e5",
        "d:k/marker",
        "d:k/e4",
        "d:k/e3",
        "d:k/e2",
    ];
    let mut reversed = SIX;
    reversed.reverse();
    assert_eq!(received("m1", &init(&SIX), &SIX, merge(write)), want);
    assert_eq!(received("m2", &init(&SIX), &reversed, merge(write)), want);
    assert_eq!(
        received("m3", &init(&SIX), &reversed, patch_to("m3", write)),
        want
    );
}

fn patch_to(ns: &'static str, body: &'static str) -> impl FnOnce(&mut Database, &mut Session) {
    move |db, _| rest(db, "PATCH", &format!("/k.json?ns={ns}"), body)
}

#[test]
fn a_subset_of_the_listens_keeps_the_order_of_the_keys_written() {
    let write = r#"{"e2":"z","e3":"z","e4":"z","e5":"z","e6":"z","marker":"z"}"#;
    assert_eq!(
        received("m4", &init(&SIX), &["e5", "e2", "marker"], merge(write)),
        ["d:k/e5", "d:k/marker", "d:k/e2"]
    );
}

#[test]
fn up_to_four_keys_are_heard_in_the_order_they_were_sent() {
    assert_eq!(
        received(
            "m5",
            &init(&["a", "b", "c"]),
            &["a", "b", "c"],
            merge(r#"{"c":"z","b":"z","a":"z"}"#)
        ),
        ["d:k/c", "d:k/b", "d:k/a"]
    );
}

#[test]
fn paths_are_gathered_by_their_parents_and_a_parent_hears_before_its_child() {
    let data = r#"{"p":{"a":1,"b":1},"q":1,"r":{"x":1},"s":1,"t":1,"u":1}"#;
    let write = r#"{"p/a":2,"q":2,"r/x":2,"s":2,"t":2,"u":2}"#;
    // The probe of the jar: s, t, u, q, then the parents p (its own listen first, then the listen at p/a) and r.
    let want = [
        "d:k/s", "d:k/t", "d:k/u", "d:k/q", "m:k/p{a}", "d:k/p/a", "m:k/r{x}",
    ];
    assert_eq!(
        received(
            "m6",
            data,
            &["p", "q", "r", "s", "t", "u", "p/a"],
            merge(write)
        ),
        want
    );
    assert_eq!(
        received(
            "m7",
            data,
            &["p/a", "u", "t", "s", "r", "q", "p"],
            merge(write)
        ),
        want
    );
}

#[test]
fn a_listen_above_the_write_hears_first_and_the_others_follow_in_key_order() {
    let data = r#"{"p":{"a":1,"b":1},"q":1,"r":{"x":1},"s":1,"t":1,"u":1}"#;
    let write = r#"{"p/a":2,"q":2,"r/x":2,"s":2,"t":2,"u":2}"#;
    // The members of the merge frame are in the map's order too.
    let want = [
        "m:k{s,t,u,q,p/a,r/x}",
        "m:k/p{a}",
        "d:k/p/a",
        "d:k/q",
        "m:k/r{x}",
        "d:k/s",
        "d:k/t",
        "d:k/u",
    ];
    assert_eq!(
        received(
            "m8",
            data,
            &["p/a", "u", "t", "s", "r", "q", "p", ""],
            merge(write)
        ),
        want
    );
    assert_eq!(
        received(
            "m9",
            data,
            &["", "p/a", "u", "t", "s", "r", "q", "p"],
            merge(write)
        ),
        want
    );
}

#[test]
fn a_root_listen_hears_the_six_keys_in_map_order_then_the_per_path_listens_in_key_order() {
    let write = r#"{"e2":"z","e3":"z","e4":"z","e5":"z","e6":"z","marker":"z"}"#;
    let mut reversed = SIX;
    reversed.reverse();
    let mut listens = vec![""];
    listens.extend(reversed);
    let want = [
        "m:k{e6,e5,marker,e4,e3,e2}",
        "d:k/e2",
        "d:k/e3",
        "d:k/e4",
        "d:k/e5",
        "d:k/e6",
        "d:k/marker",
    ];
    assert_eq!(received("m10", &init(&SIX), &listens, merge(write)), want);
    listens.rotate_left(1);
    assert_eq!(received("m11", &init(&SIX), &listens, merge(write)), want);
}

#[test]
fn a_merge_below_the_root_listen_is_one_merge_frame_then_the_per_path_listens() {
    let data = r#"{"p":{"a":1,"b":1},"q":1}"#;
    assert_eq!(
        received(
            "m12",
            data,
            &["", "p/a", "p/b"],
            merge_at("p", r#"{"b":3,"a":3}"#)
        ),
        ["m:k/p{b,a}", "d:k/p/a", "d:k/p/b"]
    );
    assert_eq!(
        received(
            "m13",
            data,
            &["p/b", "p/a"],
            merge_at("p", r#"{"a":3,"b":3}"#)
        ),
        ["d:k/p/a", "d:k/p/b"]
    );
}

fn merge_at(path: &'static str, body: &'static str) -> impl FnOnce(&mut Database, &mut Session) {
    move |db, b| {
        send(
            db,
            b,
            &format!(r#"{{"t":"d","d":{{"r":1,"a":"m","b":{{"p":"/k/{path}","d":{body}}}}}}}"#),
        );
    }
}

/// A connection that registers `paths` with `o` in this order and ends: what `listens` hear.
fn after_ending(ns: &str, data: &str, listens: &[&str], paths: &[&str]) -> Vec<String> {
    let paths: Vec<String> = paths.iter().map(|p| (*p).to_owned()).collect();
    let ns = ns.to_owned();
    let mut db = Database::new(RestOptions::default(), 1);
    rest(&mut db, "PUT", &format!("/k.json?ns={ns}"), data);
    let mut a = open(&mut db, &ns);
    for (r, listen) in (1..).zip(listens) {
        send(
            &mut db,
            &mut a,
            &format!(r#"{{"t":"d","d":{{"r":{r},"a":"q","b":{{"p":"/k/{listen}","h":""}}}}}}"#),
        );
    }
    db.drain_pushes();
    let mut b = open(&mut db, &ns);
    for (r, path) in (1..).zip(&paths) {
        send(
            &mut db,
            &mut b,
            &format!(r#"{{"t":"d","d":{{"r":{r},"a":"o","b":{{"p":"/k/{path}","d":"fired"}}}}}}"#),
        );
    }
    db.drain_pushes();
    db.close_realtime(b.client(), NOW + 1);
    db.drain_pushes()
        .into_iter()
        .filter(|(client, _)| *client == a.client())
        .map(|(_, frame)| summary(&frame))
        .collect()
}

#[test]
fn an_ending_connection_fires_production_fives_six_keys_as_e6_e5_marker_e4_e3_e2() {
    let want = [
        "d:k/e6",
        "d:k/e5",
        "d:k/marker",
        "d:k/e4",
        "d:k/e3",
        "d:k/e2",
    ];
    let mut reversed = SIX;
    reversed.reverse();
    assert_eq!(after_ending("o1", &init(&SIX), &SIX, &SIX), want);
    assert_eq!(after_ending("o2", &init(&SIX), &reversed, &reversed), want);
}

#[test]
fn an_ending_connection_with_few_registrations_fires_them_in_registration_order() {
    assert_eq!(
        after_ending(
            "o3",
            &init(&["a", "b", "c", "x"]),
            &["a", "b", "c", "x"],
            &["c", "b", "a", "x"]
        ),
        ["d:k/c", "d:k/b", "d:k/a", "d:k/x"]
    );
    assert_eq!(
        after_ending(
            "o4",
            r#"{"q":"init","p":{"a":"init","b":"init"}}"#,
            &["q", "p/b", "p/a"],
            &["q", "p/b", "p/a"]
        ),
        ["d:k/q", "d:k/p/b", "d:k/p/a"]
    );
}

/// The recorded orders of the jar for 123 random key sets (1 to 40 keys), shared with the unit tests.
fn recorded_sets() -> Vec<(Vec<String>, Vec<String>)> {
    let text = include_str!("fixtures/multi-path-order-official-emulator-4.11.2.json");
    let fixture: serde_json::Value = serde_json::from_str(text).unwrap();
    let strings = |value: &serde_json::Value| -> Vec<String> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect()
    };
    fixture["flat"]
        .as_array()
        .unwrap()
        .iter()
        .map(|set| (strings(&set["keys"]), strings(&set["order"])))
        .collect()
}

/// `keys` shuffled by `seed` (xorshift).
fn shuffled(keys: &[String], seed: u64) -> Vec<String> {
    let mut keys = keys.to_vec();
    let mut state = seed | 1;
    for i in (1..keys.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        keys.swap(
            i,
            usize::try_from(state % (u64::try_from(i).unwrap() + 1)).unwrap(),
        );
    }
    keys
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Whatever the order the listens were registered in, a connection that listens at every
        /// key hears a merge, a PATCH and an ending connection's writes in the order the jar
        /// recorded for that key set.
        #[test]
        fn every_recorded_key_set_is_heard_in_the_recorded_order(index in 0usize..123, seed in any::<u64>()) {
            let sets = recorded_sets();
            let (keys, order) = &sets[index % sets.len()];
            let heard: Vec<String> = order.iter().map(|k| format!("d:k/{k}")).collect();
            let listens: Vec<String> = shuffled(keys, seed);
            let listens: Vec<&str> = listens.iter().map(String::as_str).collect();
            let data = init(&keys.iter().map(String::as_str).collect::<Vec<_>>());
            let body: String = {
                let members: Vec<String> = keys.iter().map(|k| format!(r#""{k}":"z""#)).collect();
                format!("{{{}}}", members.join(","))
            };
            let body: &'static str = Box::leak(body.into_boxed_str());
            prop_assert_eq!(&received("p1", &data, &listens, merge(body)), &heard);
            prop_assert_eq!(&received("p2", &data, &listens, patch_to("p2", body)), &heard);
            let registered: Vec<&str> = keys.iter().map(String::as_str).collect();
            prop_assert_eq!(&after_ending("p3", &data, &listens, &registered), &heard);
        }
    }
}

/// A connection that registers (`o`) and cancels (`oc`) `ops` on children of `/k`, then ends: what its listens hear.
fn after_ops(ns: &str, keys: &[String], ops: &[(bool, String)]) -> Vec<String> {
    let mut db = Database::new(RestOptions::default(), 1);
    let data = init(&keys.iter().map(String::as_str).collect::<Vec<_>>());
    rest(&mut db, "PUT", &format!("/k.json?ns={ns}"), &data);
    let mut a = open(&mut db, ns);
    for (r, key) in (1..).zip(keys) {
        send(
            &mut db,
            &mut a,
            &format!(r#"{{"t":"d","d":{{"r":{r},"a":"q","b":{{"p":"/k/{key}","h":""}}}}}}"#),
        );
    }
    db.drain_pushes();
    let mut b = open(&mut db, ns);
    for (r, (register, key)) in (1..).zip(ops) {
        let frame = if *register {
            format!(r#"{{"t":"d","d":{{"r":{r},"a":"o","b":{{"p":"/k/{key}","d":"fired"}}}}}}"#)
        } else {
            format!(r#"{{"t":"d","d":{{"r":{r},"a":"oc","b":{{"p":"/k/{key}"}}}}}}"#)
        };
        send(&mut db, &mut b, &frame);
    }
    db.drain_pushes();
    db.close_realtime(b.client(), NOW + 1);
    db.drain_pushes()
        .into_iter()
        .filter(|(client, _)| *client == a.client())
        .map(|(_, frame)| summary(&frame))
        .collect()
}

mod model {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Registering and cancelling children of one node: up to four registered children fire in
        /// the order they were registered (a cancelled one that registers again goes last); once the
        /// node has held five it stays a hash map and fires by the fixed hash order of the keys,
        /// which the jar recorded for a 40-key set.
        #[test]
        fn registrations_and_cancels_fire_as_the_model_says(
            ops in prop::collection::vec((any::<bool>(), 0usize..9), 1..24),
            sticky_seed in any::<u8>(),
        ) {
            let sets = recorded_sets();
            let (keys, order) = sets.iter().max_by_key(|(k, _)| k.len()).unwrap();
            let pool: Vec<String> = keys.iter().take(9).cloned().collect();
            let position = |key: &String| order.iter().position(|k| k == key).unwrap();
            // Make the node hashed sometimes at the start, so both regimes are covered.
            let mut ops: Vec<(bool, String)> = ops.into_iter().map(|(register, i)| (register, pool[i].clone())).collect();
            if sticky_seed % 3 == 0 {
                let warm: Vec<(bool, String)> = pool.iter().take(5).map(|k| (true, k.clone())).collect();
                ops.splice(0..0, warm);
            }
            let mut held: Vec<String> = Vec::new();
            let mut hashed = false;
            for (register, key) in &ops {
                if *register {
                    if !held.contains(key) {
                        held.push(key.clone());
                        hashed |= held.len() >= 5;
                    }
                } else {
                    held.retain(|k| k != key);
                }
            }
            let mut want = held.clone();
            if hashed {
                want.sort_by_key(position);
            }
            let want: Vec<String> = want.into_iter().map(|k| format!("d:k/{k}")).collect();
            prop_assert_eq!(after_ops("q1", &pool, &ops), want);
        }
    }
}
