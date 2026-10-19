//! The realtime wire protocol (`/.ws?v=5`), message by message. Unless a test says
//! otherwise, every expected frame is what the official emulator (firebase-database-emulator
//! v4.11.2) sent for the same frames, as recorded in the lane's exploration logs.

#![allow(clippy::too_many_lines)]

use fireemu_adapter_database::realtime::{Opened, Session};
use fireemu_adapter_database::rest::{Database, RestOptions, RulesMode};

const NOW: i64 = 1_792_412_750_466;
/// The first session id of a database seeded with 1.
const PINNED_SESSION_ID: &str = "rWHi3m9zEB1MxPtFkoXJ7WZXMKo2A2mC";

fn open(db: &mut Database, target: &str) -> (Session, Vec<String>) {
    match db.open_realtime(target, Some("127.0.0.1:9000"), NOW) {
        Ok(Opened::Session(session, frames)) => (session, frames),
        other => panic!("{other:?}"),
    }
}

fn send(db: &mut Database, session: &mut Session, frame: &str) -> Vec<String> {
    session.receive(db, frame, NOW).replies
}

fn reply(r: u64, status: &str, data: &str) -> String {
    format!(r#"{{"t":"d","d":{{"r":{r},"b":{{"s":"{status}","d":{data}}}}}}}"#)
}

fn request(r: u64, action: &str, body: &str) -> String {
    format!(r#"{{"t":"d","d":{{"r":{r},"a":"{action}","b":{body}}}}}"#)
}

#[test]
fn the_handshake_names_the_time_version_host_and_session() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (_, frames) = open(&mut db, "/.ws?v=5&ns=w1");
    assert_eq!(frames.len(), 1);
    let prefix =
        format!(r#"{{"t":"c","d":{{"t":"h","d":{{"ts":{NOW},"v":"5","h":"127.0.0.1:9000","s":""#);
    assert!(frames[0].starts_with(&prefix), "{}", frames[0]);
    let session_id = frames[0][prefix.len()..].trim_end_matches(r#""}}}"#);
    assert_eq!(session_id.len(), 32);
    // Session ids come from the database seed, so the seed reproduces them.
    assert_eq!(session_id, PINNED_SESSION_ID);
    assert!(session_id.bytes().all(|b| b.is_ascii_alphanumeric()));
    let (_, again) = open(&mut db, "/.ws?v=5&ns=w1");
    assert_ne!(
        frames[0], again[0],
        "every connection gets its own session id"
    );
}

#[test]
fn a_wrong_or_missing_version_is_shut_down() {
    let mut db = Database::new(RestOptions::default(), 1);
    for target in ["/.ws?v=4&ns=w3", "/.ws?ns=w3", "/.ws"] {
        match db.open_realtime(target, None, NOW) {
            Ok(Opened::Shutdown(frames)) => assert_eq!(
                frames,
                vec![r#"{"t":"c","d":{"t":"s","d":"Version error. Please make sure you are using the latest Firebase library"}}"#.to_owned()],
                "{target}"
            ),
            other => panic!("{target}: {other:?}"),
        }
    }
}

#[test]
fn an_invalid_namespace_is_refused_before_the_upgrade() {
    let mut db = Database::new(RestOptions::default(), 1);
    let refused = db
        .open_realtime("/.ws?v=5&ns=Bad_NS", None, NOW)
        .unwrap_err();
    assert_eq!(refused.status, 403);
    assert_eq!(refused.message, "Invalid Firebase database name");
}

#[test]
fn put_get_merge_and_server_values() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w1");
    let mut go = |frame: &str| send(&mut db, &mut s, frame);
    assert_eq!(
        go(&request(1, "s", r#"{"c":{"sdk.js.12-18-0":1}}"#)),
        vec![reply(1, "ok", r#""""#)]
    );
    assert_eq!(
        go(&request(2, "p", r#"{"p":"/a","d":{"x":1,"y":"s"}}"#)),
        vec![reply(2, "ok", r#""""#)]
    );
    assert_eq!(
        go(&request(3, "g", r#"{"p":"/a","q":{}}"#)),
        vec![reply(3, "ok", r#"{"x":1,"y":"s"}"#)]
    );
    assert_eq!(
        go(&request(4, "m", r#"{"p":"/a","d":{"z":2,"x":null}}"#)),
        vec![reply(4, "ok", r#""""#)]
    );
    assert_eq!(
        go(&request(5, "g", r#"{"p":"/a","q":{}}"#)),
        vec![reply(5, "ok", r#"{"y":"s","z":2}"#)]
    );
    assert_eq!(
        go(&request(12, "p", r#"{"p":"/ts","d":{".sv":"timestamp"}}"#)),
        vec![reply(12, "ok", r#""""#)]
    );
    assert_eq!(
        go(&request(13, "g", r#"{"p":"/ts"}"#)),
        vec![reply(13, "ok", &NOW.to_string())]
    );
    assert_eq!(
        go(&request(14, "g", r#"{"p":"/missing","q":{}}"#)),
        vec![reply(14, "ok", "null")]
    );
    // A put without data deletes; a request without an id is answered as id 0.
    assert_eq!(
        go(&request(19, "p", r#"{"p":"/a"}"#)),
        vec![reply(19, "ok", r#""""#)]
    );
    assert_eq!(
        go(r#"{"t":"d","d":{"a":"g","b":{"p":"/a"}}}"#),
        vec![reply(0, "ok", "null")]
    );
}

#[test]
fn reads_use_the_export_form_without_arrays() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w4");
    let mut go = |frame: &str| send(&mut db, &mut s, frame);
    go(&request(
        1,
        "p",
        r#"{"p":"/p","d":{".value":1,".priority":2}}"#,
    ));
    assert_eq!(
        go(&request(2, "g", r#"{"p":"/p","q":{}}"#)),
        vec![reply(2, "ok", r#"{".value":1,".priority":2.0}"#)]
    );
    go(&request(3, "p", r#"{"p":"/l","d":["a","b"]}"#));
    assert_eq!(
        go(&request(4, "g", r#"{"p":"/l","q":{}}"#)),
        vec![reply(4, "ok", r#"{"0":"a","1":"b"}"#)]
    );
    assert_eq!(
        go(&request(
            9,
            "g",
            r#"{"p":"/l","q":{"i":".key","sp":"0","sin":false}}"#
        )),
        vec![reply(9, "ok", r#"{"1":"b"}"#)]
    );
    assert_eq!(
        go(&request(
            10,
            "g",
            r#"{"p":"/l","q":{"i":".key","l":0,"vf":"l"}}"#
        )),
        vec![reply(10, "invalid_parameters", r#""Invalid query limit""#)]
    );
}

#[test]
fn queries_need_an_index_for_children_and_values() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w2");
    let mut go = |frame: &str| send(&mut db, &mut s, frame);
    go(&request(
        7,
        "p",
        r#"{"p":"/d","d":{"a":{"h":1},"b":{"h":2}}}"#,
    ));
    assert_eq!(
        go(&request(
            8,
            "g",
            r#"{"p":"/d","q":{"i":"h","l":1,"vf":"l"}}"#
        )),
        vec![reply(
            8,
            "no_index",
            r#""Index not defined, add \".indexOn\": \"h\", for path \"/d\", to the rules""#
        )]
    );
    assert_eq!(
        go(&request(
            9,
            "g",
            r#"{"p":"/d","q":{"i":".key","l":1,"vf":"r"}}"#
        )),
        vec![reply(9, "ok", r#"{"b":{"h":2}}"#)]
    );
}

#[test]
fn wire_bounds_map_to_query_bounds() {
    // Not observed on the official emulator: the SDK's encodings of startAfter (sn
    // "[MAX_NAME]", sin false) and endBefore (en "[MIN_NAME]", ein false).
    let mut db = Database::new(RestOptions::default(), 1);
    db.declare_index("w5", &fireemu_core_database::Path::from_keys(["d"]), "h");
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w5");
    let mut go = |frame: &str| send(&mut db, &mut s, frame);
    go(&request(
        1,
        "p",
        r#"{"p":"/d","d":{"a":{"h":1},"b":{"h":2},"c":{"h":2},"e":{"h":3}}}"#,
    ));
    assert_eq!(
        go(&request(
            2,
            "g",
            r#"{"p":"/d","q":{"i":"h","sp":2,"sn":"[MAX_NAME]","sin":false}}"#
        )),
        vec![reply(2, "ok", r#"{"e":{"h":3}}"#)]
    );
    assert_eq!(
        go(&request(
            3,
            "g",
            r#"{"p":"/d","q":{"i":"h","ep":2,"en":"[MIN_NAME]","ein":false}}"#
        )),
        vec![reply(3, "ok", r#"{"a":{"h":1}}"#)]
    );
    assert_eq!(
        go(&request(
            4,
            "g",
            r#"{"p":"/d","q":{"i":"h","sp":2,"sn":"c","ep":3,"l":1,"vf":"r"}}"#
        )),
        vec![reply(4, "ok", r#"{"e":{"h":3}}"#)]
    );
    assert_eq!(
        go(&request(
            5,
            "g",
            r#"{"p":"/d","q":{"i":".value","sp":null}}"#
        )),
        vec![reply(
            5,
            "no_index",
            r#""Index not defined, add \".indexOn\": \".value\", for path \"/d\", to the rules""#
        )]
    );
}

#[test]
fn refused_writes_answer_their_status() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w2");
    let mut go = |frame: &str| send(&mut db, &mut s, frame);
    assert_eq!(
        go(&request(1, "m", r#"{"p":"/a","d":{"q":1,"q/r":2}}"#)),
        vec![reply(
            1,
            "invalid_parameters",
            r#""Path 'q' is ancestor of 'q/r'""#
        )]
    );
    assert_eq!(
        go(&request(2, "p", r#"{"p":"/a$","d":1}"#)),
        vec![reply(2, "invalid_parameters", r#""Invalid token in path""#)]
    );
    assert_eq!(
        go(&request(15, "p", r#"{"p":"/.info/x","d":1}"#)),
        vec![reply(
            15,
            "invalid_parameters",
            r#""Invalid token in path""#
        )]
    );
    assert_eq!(
        go(&request(
            12,
            "g",
            r#"{"p":"/.info/serverTimeOffset","q":{}}"#
        )),
        vec![reply(
            12,
            "invalid_parameters",
            r#""Invalid token in path""#
        )]
    );
    let deep = (0..33)
        .map(|i| format!("k{i}"))
        .collect::<Vec<_>>()
        .join("/");
    assert_eq!(
        go(&request(5, "p", &format!(r#"{{"p":"/{deep}","d":1}}"#))),
        vec![reply(
            5,
            "invalid_parameters",
            r#""Path specified exceeds the maximum depth that can be written (32).""#
        )]
    );
    assert_eq!(
        go(&request(13, "p", r#"{"p":"/missing/.priority","d":1}"#)),
        vec![reply(
            13,
            "invalid_parameters",
            r#""could not set priority on non-existent node""#
        )]
    );
    assert_eq!(
        go(&request(11, "m", r#"{"p":"/m","d":{"x/.priority":1}}"#)),
        vec![reply(
            11,
            "invalid_parameters",
            r#""could not set priority on non-existent node""#
        )]
    );
}

#[test]
fn malformed_messages_and_data_get_a_connection_error() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut first, _) = open(&mut db, "/.ws?v=5&ns=w1");
    let (mut second, _) = open(&mut db, "/.ws?v=5&ns=w1");
    let error = |client: u64, id: u64| {
        format!(
            r#"{{"t":"c","d":{{"t":"e","d":"ClientId[{client}]:ErrorId[{id}]: Error on incoming message"}}}}"#
        )
    };
    assert_eq!(
        send(
            &mut db,
            &mut first,
            &request(6, "p", r#"{"p":"/a/x","d":{"a.b":1}}"#)
        ),
        vec![error(1, 1)]
    );
    assert_eq!(
        send(&mut db, &mut second, &request(11, "bogus", "{}")),
        vec![error(2, 2)]
    );
    assert_eq!(send(&mut db, &mut first, "not json"), vec![error(1, 3)]);
    assert_eq!(
        send(&mut db, &mut first, &request(6, "m", r#"{"p":"/a","d":5}"#)),
        vec![error(1, 4)]
    );
    assert_eq!(
        send(
            &mut db,
            &mut first,
            &request(12, "p", r#"{"p":"/n","d":{".priority":1}}"#)
        ),
        vec![error(1, 5)]
    );
    // The connection keeps serving.
    assert_eq!(
        send(&mut db, &mut first, &request(7, "echo", r#"{"d":"hi"}"#)),
        vec![reply(7, "ok", r#""hi""#)]
    );
}

#[test]
fn transactions_compare_the_current_hash() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w2");
    let mut go = |frame: &str| send(&mut db, &mut s, frame);
    let stale = reply(14, "datastale", r#""Transaction ETag does not match""#);
    assert_eq!(
        go(&request(
            14,
            "p",
            r#"{"p":"/a","d":1,"h":"YPVfR2bXt/lcDjiQZ8pOkAd3qkQ="}"#
        )),
        vec![stale]
    );
    assert_eq!(
        go(&request(16, "p", r#"{"p":"/nn","d":2,"h":""}"#)),
        vec![reply(16, "ok", "2")]
    );
    assert_eq!(
        go(&request(17, "p", r#"{"p":"/nn","d":3,"h":""}"#)),
        vec![reply(
            17,
            "datastale",
            r#""Transaction ETag does not match""#
        )]
    );
    assert_eq!(
        go(&request(7, "p", r#"{"p":"/t","d":{"x":1},"h":""}"#)),
        vec![reply(7, "ok", r#"{"x":1}"#)]
    );
    assert_eq!(
        go(&request(
            8,
            "p",
            r#"{"p":"/t2","d":{".sv":"timestamp"},"h":""}"#
        )),
        vec![reply(8, "ok", &NOW.to_string())]
    );
}

#[test]
fn a_matching_hash_writes() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w6");
    send(&mut db, &mut s, &request(1, "p", r#"{"p":"/a","d":1}"#));
    // The SDK node hash of the number 1.
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(
                2,
                "p",
                r#"{"p":"/a","d":2,"h":"YPVfR2bXt/lcDjiQZ8pOkAd3qkQ="}"#
            )
        ),
        vec![reply(2, "ok", "2")]
    );
}

#[test]
fn auth_messages() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w3");
    let jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vZGVtbyIsImF1ZCI6ImRlbW8iLCJhdXRoX3RpbWUiOjE3OTI0MTI4MDAsInVzZXJfaWQiOiJ1MSIsInN1YiI6InUxIiwiaWF0IjoxNzkyNDEyODAwLCJleHAiOjE3OTI0MTY0MDAsImZpcmViYXNlIjp7ImlkZW50aXRpZXMiOnt9LCJzaWduX2luX3Byb3ZpZGVyIjoiYW5vbnltb3VzIn19.";
    let mut go = |frame: &str| send(&mut db, &mut s, frame);
    assert_eq!(
        go(&request(7, "auth", r#"{"cred":"garbage"}"#)),
        vec![reply(
            7,
            "invalid_token",
            r#""Could not parse auth token.""#
        )]
    );
    // The official emulator writes the claims in its own member order; this server writes
    // them in key order, which is the same JSON.
    assert_eq!(
        go(&request(1, "auth", &format!(r#"{{"cred":"{jwt}"}}"#))),
        vec![reply(
            1,
            "ok",
            r#"{"auth":{"provider":"anonymous","token":{"aud":"demo","auth_time":1792412800,"exp":1792416400,"firebase":{"identities":{},"sign_in_provider":"anonymous"},"iat":1792412800,"iss":"https://securetoken.google.com/demo","sub":"u1","user_id":"u1"},"uid":"u1","user_id":"u1"},"expires":null}"#
        )]
    );
    let expires = NOW / 1000 + 3600;
    assert_eq!(
        go(&request(8, "gauth", r#"{"cred":"owner"}"#)),
        vec![reply(
            8,
            "ok",
            &format!(r#"{{"auth":null,"expires":{expires}}}"#)
        )]
    );
    assert_eq!(
        go(&request(9, "unauth", "{}")),
        vec![reply(9, "ok", r#""unauthenticated""#)]
    );
    assert_eq!(
        go(&request(10, "appcheck", r#"{"token":"x"}"#)),
        vec![reply(10, "invalid_token", r#""Could not parse token.""#)]
    );
}

#[test]
fn control_pings_get_pongs_and_keepalives_are_ignored() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w1");
    assert_eq!(
        send(&mut db, &mut s, r#"{"t":"c","d":{"t":"p","d":{}}}"#),
        vec![r#"{"t":"c","d":{"t":"o","d":null}}"#.to_owned()]
    );
    assert!(send(&mut db, &mut s, "0").is_empty());
}

#[test]
fn split_frames_reassemble_and_long_answers_split() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w2");
    assert!(send(&mut db, &mut s, "2").is_empty());
    assert!(send(
        &mut db,
        &mut s,
        r#"{"t":"d","d":{"r":4,"a":"p","b":{"p":"/sp"#
    )
    .is_empty());
    assert_eq!(
        send(&mut db, &mut s, r#"lit","d":5}}}"#),
        vec![reply(4, "ok", r#""""#)]
    );
    let big = "x".repeat(20_000);
    send(
        &mut db,
        &mut s,
        &request(3, "p", &format!(r#"{{"p":"/big","d":"{big}"}}"#)),
    );
    let frames = send(&mut db, &mut s, &request(5, "g", r#"{"p":"/big","q":{}}"#));
    assert_eq!(frames[0], "2");
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[1].len(), 16_384);
    assert_eq!(frames[1..].concat(), reply(5, "ok", &format!("\"{big}\"")));
}

#[test]
fn deny_all_rules_refuse_everyone_but_the_owner() {
    // Not observed on the official emulator (it has no rules here): productionExact
    // without rules (ledger 1471 Q4). Production's refusal status is "permission_denied".
    let options = RestOptions {
        rules: RulesMode::DenyAll,
        ..RestOptions::default()
    };
    let mut db = Database::new(options, 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w7");
    let denied = |r| reply(r, "permission_denied", r#""Permission denied""#);
    assert_eq!(
        send(&mut db, &mut s, &request(1, "p", r#"{"p":"/a","d":1}"#)),
        vec![denied(1)]
    );
    assert_eq!(
        send(&mut db, &mut s, &request(2, "g", r#"{"p":"/a"}"#)),
        vec![denied(2)]
    );
    send(&mut db, &mut s, &request(3, "gauth", r#"{"cred":"owner"}"#));
    assert_eq!(
        send(&mut db, &mut s, &request(4, "p", r#"{"p":"/a","d":1}"#)),
        vec![reply(4, "ok", r#""""#)]
    );
    send(&mut db, &mut s, &request(5, "unauth", "{}"));
    assert_eq!(
        send(&mut db, &mut s, &request(6, "g", r#"{"p":"/a"}"#)),
        vec![denied(6)]
    );
}

#[test]
fn realtime_writes_reach_event_streams() {
    let mut db = Database::new(RestOptions::default(), 1);
    let stream = match db.handle(
        &fireemu_adapter_database::rest::HttpRequest {
            method: "GET".to_owned(),
            target: "/a.json?ns=w8".to_owned(),
            headers: vec![("Accept".to_owned(), "text/event-stream".to_owned())],
            body: Vec::new(),
        },
        NOW,
    ) {
        fireemu_adapter_database::rest::Handled::Stream { id, .. } => id,
        fireemu_adapter_database::rest::Handled::Response { .. } => panic!("no stream"),
    };
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w8");
    let received = s.receive(&mut db, &request(1, "p", r#"{"p":"/a/b","d":1}"#), NOW);
    assert_eq!(received.events.len(), 1);
    assert_eq!(received.events[0].0, stream);
    assert_eq!(received.events[0].1.data, r#"{"path":"/b","data":1}"#);
}

#[test]
fn auth_tokens_need_a_subject_and_an_issue_time() {
    // The official emulator's answers for unsigned tokens with these claims.
    let token = |claims: &str| {
        let encode = |text: &str| {
            let mut out = String::new();
            let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            for chunk in text.as_bytes().chunks(3) {
                let b = [
                    chunk[0],
                    *chunk.get(1).unwrap_or(&0),
                    *chunk.get(2).unwrap_or(&0),
                ];
                let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
                for i in 0..=chunk.len() {
                    out.push(char::from(table[((n >> (18 - 6 * i)) & 63) as usize]));
                }
            }
            out
        };
        format!("{}.{}.", encode(r#"{"alg":"none"}"#), encode(claims))
    };
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=jw");
    let mut auth = |r: u64, claims: &str| {
        send(
            &mut db,
            &mut s,
            &request(r, "auth", &format!(r#"{{"cred":"{}"}}"#, token(claims))),
        )
    };
    assert_eq!(
        auth(1, r#"{"sub":"u1","iat":1}"#),
        vec![reply(
            1,
            "ok",
            r#"{"auth":{"provider":"anonymous","token":{"iat":1,"sub":"u1"},"uid":"u1"},"expires":null}"#
        )]
    );
    assert_eq!(
        auth(2, r#"{"iat":1}"#),
        vec![reply(
            2,
            "invalid_token",
            r#""Missing claim 'sub' in auth token.""#
        )]
    );
    assert_eq!(
        auth(3, r#"{"sub":"u1","iat":1,"exp":1}"#),
        vec![reply(
            3,
            "ok",
            r#"{"auth":{"provider":"anonymous","token":{"exp":1,"iat":1,"sub":"u1"},"uid":"u1"},"expires":null}"#
        )]
    );
    assert_eq!(
        auth(6, r#"{"sub":"u1","iat":"x"}"#),
        vec![reply(
            6,
            "invalid_token",
            r#""Missing claim 'iat' in auth token.""#
        )]
    );
    assert_eq!(
        auth(7, r#"{"user_id":"u1","iat":1}"#),
        vec![reply(
            7,
            "invalid_token",
            r#""Missing claim 'sub' in auth token.""#
        )]
    );
    assert_eq!(
        auth(9, "[1]"),
        vec![reply(
            9,
            "invalid_token",
            r#""Could not parse auth token.""#
        )]
    );
}

mod properties {
    use super::*;
    use fireemu_adapter_database::realtime::{split_frames, MAX_FRAME_CHARS};
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Any message survives being split into frames and reassembled by a session, and
        /// only messages longer than the frame limit are split.
        #[test]
        fn split_messages_reassemble(text in "[a-z\u{e9}\u{1F600}]{0,40000}") {
            let message = request(1, "echo", &format!(r#"{{"d":"{text}"}}"#));
            let frames = split_frames(message.clone());
            let chars = message.chars().count();
            if chars <= MAX_FRAME_CHARS {
                prop_assert_eq!(frames.len(), 1);
            } else {
                prop_assert_eq!(frames[0].parse::<usize>().unwrap(), frames.len() - 1);
                prop_assert!(frames[1..].iter().all(|f| f.chars().count() <= MAX_FRAME_CHARS));
                prop_assert_eq!(frames[1..].concat(), message.clone());
            }
            let mut db = Database::new(RestOptions::default(), 1);
            let (mut s, _) = open(&mut db, "/.ws?v=5&ns=p1");
            let mut replies = Vec::new();
            for frame in &frames {
                replies.extend(send(&mut db, &mut s, frame));
            }
            let joined = if replies.len() == 1 { replies[0].clone() } else { replies[1..].concat() };
            prop_assert_eq!(joined, reply(1, "ok", &format!("\"{text}\"")));
        }
    }
}

#[test]
fn edge_messages_follow_the_official_emulator() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=mx");
    let error = |id: u64| {
        format!(
            r#"{{"t":"c","d":{{"t":"e","d":"ClientId[1]:ErrorId[{id}]: Error on incoming message"}}}}"#
        )
    };
    // An unknown message type is a connection error.
    assert_eq!(
        send(
            &mut db,
            &mut s,
            r#"{"t":"x","d":{"r":8,"a":"g","b":{"p":"/leaf"}}}"#
        ),
        vec![error(1)]
    );
    // gauth without a credential is not answered.
    assert!(send(&mut db, &mut s, &request(9, "gauth", "{}")).is_empty());
    // A non-string path is read as its text; a non-string hash never matches.
    assert_eq!(
        send(&mut db, &mut s, &request(11, "g", r#"{"p":5}"#)),
        vec![reply(11, "ok", "null")]
    );
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(12, "p", r#"{"p":"/x","d":1,"h":5}"#)
        ),
        vec![reply(
            12,
            "datastale",
            r#""Transaction ETag does not match""#
        )]
    );
    // A query on a leaf answers null.
    send(&mut db, &mut s, &request(3, "p", r#"{"p":"/leaf","d":5}"#));
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(4, "g", r#"{"p":"/leaf","q":{"i":".key","l":1,"vf":"l"}}"#)
        ),
        vec![reply(4, "ok", "null")]
    );
    let long = "a".repeat(769);
    let too_long = reply(
        7,
        "invalid_parameters",
        r#""Path specified exceeds the maximum length that can be written (768 bytes).""#,
    );
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(7, "g", &format!(r#"{{"p":"/{long}"}}"#))
        ),
        vec![too_long]
    );
    // Depth 32 is writable; 33 is not.
    let deep = (0..32)
        .map(|i| format!("k{i}"))
        .collect::<Vec<_>>()
        .join("/");
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(13, "p", &format!(r#"{{"p":"/{deep}","d":1}}"#))
        ),
        vec![reply(13, "ok", r#""""#)]
    );
    // A long all-digit frame is a message, not a frame count.
    assert_eq!(send(&mut db, &mut s, "1234567"), vec![error(2)]);
    // A keepalive does not open a split message.
    assert!(send(&mut db, &mut s, "0").is_empty());
    assert!(send(&mut db, &mut s, "2").is_empty());
    assert!(send(&mut db, &mut s, r#"{"t":"d","d":{"r":14,"a":"echo","#).is_empty());
    assert_eq!(
        send(&mut db, &mut s, r#""b":{"d":1}}}"#),
        vec![reply(14, "ok", r#""1""#)]
    );
}

#[test]
fn a_get_without_a_path_drops_the_connection() {
    // The official emulator drops the connection (1006) for a get without `p`.
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=mx");
    let received = s.receive(&mut db, &request(5, "g", "{}"), NOW);
    assert!(received.replies.is_empty());
    assert!(received.drop_connection);
}

#[test]
fn the_sign_in_provider_and_session_ids_are_reported() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, frames) = open(&mut db, "/.ws?v=5&ns=mx");
    assert!(frames[0].contains(PINNED_SESSION_ID), "{}", frames[0]);
    // A payload whose base64url text holds '-' and '_' (from "~~~" and "???").
    let jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ-fn4_Pz8iLCJpYXQiOjEsImZpcmViYXNlIjp7InNpZ25faW5fcHJvdmlkZXIiOiJwYXNzd29yZCJ9fQ.";
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(1, "auth", &format!(r#"{{"cred":"{jwt}"}}"#))
        ),
        vec![reply(
            1,
            "ok",
            r#"{"auth":{"provider":"password","token":{"firebase":{"sign_in_provider":"password"},"iat":1,"sub":"~~~???"},"uid":"~~~???"},"expires":null}"#
        )]
    );
    let unsigned = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4IiwiaWF0IjoxfQ.";
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(2, "appcheck", &format!(r#"{{"token":"{unsigned}"}}"#))
        ),
        vec![reply(
            2,
            "invalid_token",
            r#""Unsupported jwt algorithm: none""#
        )]
    );
}

#[test]
fn deny_all_accepts_only_the_owner_credential() {
    let options = RestOptions {
        rules: RulesMode::DenyAll,
        ..RestOptions::default()
    };
    let mut db = Database::new(options, 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w9");
    send(
        &mut db,
        &mut s,
        &request(1, "gauth", r#"{"cred":"not-owner"}"#),
    );
    assert_eq!(
        send(&mut db, &mut s, &request(2, "g", r#"{"p":"/a"}"#)),
        vec![reply(2, "permission_denied", r#""Permission denied""#)]
    );
}

#[test]
fn named_bounds_and_view_sides() {
    // Not observed on the official emulator; the SDK's encodings over a declared index.
    let mut db = Database::new(RestOptions::default(), 1);
    db.declare_index("w10", &fireemu_core_database::Path::from_keys(["d"]), "h");
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=w10");
    let mut go = |frame: &str| send(&mut db, &mut s, frame);
    go(&request(
        1,
        "p",
        r#"{"p":"/d","d":{"B":{"h":2},"a":{"h":1},"c":{"h":2},"e":{"h":3}}}"#,
    ));
    assert_eq!(
        go(&request(
            2,
            "g",
            r#"{"p":"/d","q":{"i":"h","sp":2,"sn":"c"}}"#
        )),
        vec![reply(2, "ok", r#"{"c":{"h":2},"e":{"h":3}}"#)]
    );
    assert_eq!(
        go(&request(
            3,
            "g",
            r#"{"p":"/d","q":{"i":"h","ep":2,"en":"[MIN_NAME]","ein":false}}"#
        )),
        vec![reply(3, "ok", r#"{"a":{"h":1}}"#)]
    );
    assert_eq!(
        go(&request(
            4,
            "g",
            r#"{"p":"/d","q":{"i":"h","l":2,"vf":"l"}}"#
        )),
        vec![reply(4, "ok", r#"{"B":{"h":2},"a":{"h":1}}"#)]
    );
}

#[test]
fn numbers_beyond_the_double_range_never_panic() {
    // The official emulator stores and reads back the string "Infinity"; its echo returns
    // the integer's digits, which this server answers as "Infinity" (echo is a diagnostic).
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=wr2");
    let huge = format!("1{}", "0".repeat(400));
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(2, "p", &format!(r#"{{"p":"/n","d":{huge}}}"#))
        ),
        vec![reply(2, "ok", r#""""#)]
    );
    assert_eq!(
        send(&mut db, &mut s, &request(3, "g", r#"{"p":"/n"}"#)),
        vec![reply(3, "ok", r#""Infinity""#)]
    );
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(4, "p", r#"{"p":"/n","d":1,"h":1e400}"#)
        ),
        vec![reply(
            4,
            "datastale",
            r#""Transaction ETag does not match""#
        )]
    );
    assert_eq!(
        send(&mut db, &mut s, &request(5, "echo", r#"{"d":1e400}"#)),
        vec![reply(5, "ok", r#""Infinity""#)]
    );
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(1, "echo", &format!(r#"{{"d":{huge}}}"#))
        ),
        vec![reply(1, "ok", r#""Infinity""#)]
    );
}

#[test]
fn split_messages_are_capped_at_the_realtime_limit() {
    // Not observed on the official emulator: a split message longer than the realtime
    // message limit closes the connection with 1009 as soon as it crosses the limit.
    let options = RestOptions {
        realtime_message_bytes: 100,
        ..RestOptions::default()
    };
    let mut db = Database::new(options, 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=cap");
    // Exactly the limit is accepted.
    assert!(s.receive(&mut db, "2", NOW).close.is_none());
    assert!(s.receive(&mut db, &"x".repeat(50), NOW).close.is_none());
    assert_eq!(s.receive(&mut db, &"y".repeat(50), NOW).replies.len(), 1);
    assert!(s.receive(&mut db, "999999", NOW).close.is_none());
    assert!(s.receive(&mut db, &"x".repeat(60), NOW).close.is_none());
    let received = s.receive(&mut db, &"x".repeat(60), NOW);
    assert_eq!(
        received.close,
        Some(fireemu_adapter_database::websocket::CloseCode::TooBig)
    );
}

#[test]
fn messages_are_prepared_without_the_database() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=prep");
    // Reassembly and parsing need no database; only dispatch does.
    assert!(s.prepare("2").is_none());
    assert!(s.prepare(r#"{"t":"d","d":{"r":1,"a":"echo","#).is_none());
    let prepared = s.prepare(r#""b":{"d":"x"}}}"#).unwrap();
    assert_eq!(
        s.dispatch_prepared(&mut db, prepared, NOW).replies,
        vec![reply(1, "ok", r#""x""#)]
    );
}

#[test]
fn large_messages_parse_in_linear_time() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (mut s, _) = open(&mut db, "/.ws?v=5&ns=big");
    let data = format!(
        "{{{}}}",
        (0..100_000)
            .map(|i| format!("\"k{i}\":{i}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let started = std::time::Instant::now();
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(1, "p", &format!(r#"{{"p":"/m","d":{data}}}"#))
        ),
        vec![reply(1, "ok", r#""""#)]
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
}
