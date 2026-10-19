//! Listening over the realtime protocol (`q`, `n`) and the data the server pushes. Unless a
//! test says otherwise, every expected frame is what the official emulator
//! (firebase-database-emulator v4.11.2) sent for the same frames and writes.

use fireemu_adapter_database::realtime::{Opened, Session};
use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};

const NOW: i64 = 1_792_417_166_902;

fn open(db: &mut Database, ns: &str) -> Session {
    match db.open_realtime(&format!("/.ws?v=5&ns={ns}"), Some("127.0.0.1:9000"), NOW) {
        Ok(Opened::Session(session, _)) => session,
        other => panic!("{other:?}"),
    }
}

fn send(db: &mut Database, session: &mut Session, frame: &str) -> Vec<String> {
    session.receive(db, frame, NOW).replies
}

fn request(r: u64, action: &str, body: &str) -> String {
    format!(r#"{{"t":"d","d":{{"r":{r},"a":"{action}","b":{body}}}}}"#)
}

fn reply(r: u64, status: &str, data: &str) -> String {
    format!(r#"{{"t":"d","d":{{"r":{r},"b":{{"s":"{status}","d":{data}}}}}}}"#)
}

/// A pushed data (`d`) or merge (`m`) message, as the server writes it: `b` before `a`.
fn push(action: &str, path: &str, data: &str, tag: Option<u64>) -> String {
    let tag = tag.map(|t| format!(r#","t":{t}"#)).unwrap_or_default();
    format!(r#"{{"t":"d","d":{{"b":{{"p":"{path}","d":{data}{tag}}},"a":"{action}"}}}}"#)
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

#[test]
fn a_listen_sends_the_value_then_follows_writes_at_and_below_it() {
    let mut db = Database::new(RestOptions::default(), 1);
    rest(
        &mut db,
        "PUT",
        "/s.json?ns=l1",
        r#"{"a":{"h":1},"b":{"h":2},"c":{"h":3}}"#,
    );
    let mut s = open(&mut db, "l1");
    assert_eq!(
        send(&mut db, &mut s, &request(1, "q", r#"{"p":"/s","h":""}"#)),
        vec![
            push("d", "s", r#"{"a":{"h":1},"b":{"h":2},"c":{"h":3}}"#, None),
            reply(1, "ok", "{}"),
        ]
    );
    // The writer's own listen gets the push before the acknowledgement.
    assert_eq!(
        send(&mut db, &mut s, &request(2, "p", r#"{"p":"/s/a/h","d":5}"#)),
        vec![push("d", "s/a/h", "5", None), reply(2, "ok", r#""""#)]
    );
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(3, "m", r#"{"p":"/s","d":{"b":null,"d":{"h":0}}}"#)
        ),
        vec![
            push("m", "s", r#"{"b":null,"d":{"h":0}}"#, None),
            reply(3, "ok", r#""""#)
        ]
    );
    // Writing what is already there pushes nothing.
    assert_eq!(
        send(&mut db, &mut s, &request(4, "p", r#"{"p":"/s/a/h","d":5}"#)),
        vec![reply(4, "ok", r#""""#)]
    );
    // After unlisten, writes push nothing.
    assert_eq!(
        send(&mut db, &mut s, &request(9, "n", r#"{"p":"/s"}"#)),
        vec![reply(9, "ok", r#""""#)]
    );
    assert_eq!(
        send(&mut db, &mut s, &request(10, "p", r#"{"p":"/s/x","d":1}"#)),
        vec![reply(10, "ok", r#""""#)]
    );
}

#[test]
fn writes_above_a_listen_push_its_part_and_siblings_push_nothing() {
    let mut db = Database::new(RestOptions::default(), 1);
    rest(&mut db, "PUT", "/s.json?ns=l2", r#"{"a":{"x":1},"b":2}"#);
    let mut s = open(&mut db, "l2");
    send(&mut db, &mut s, &request(1, "q", r#"{"p":"/s/a","h":""}"#));
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(2, "p", r#"{"p":"/s","d":{"a":{"x":2},"b":3}}"#)
        ),
        vec![
            push("d", "s/a", r#"{"x":2}"#, None),
            reply(2, "ok", r#""""#)
        ]
    );
    assert_eq!(
        send(&mut db, &mut s, &request(3, "p", r#"{"p":"/s/b","d":4}"#)),
        vec![reply(3, "ok", r#""""#)]
    );
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(4, "m", r#"{"p":"/s","d":{"a/y":5,"b":6}}"#)
        ),
        vec![
            push("m", "s/a", r#"{"y":5}"#, None),
            reply(4, "ok", r#""""#)
        ]
    );
    assert_eq!(
        send(&mut db, &mut s, &request(5, "p", r#"{"p":"/","d":null}"#)),
        vec![push("d", "s/a", "null", None), reply(5, "ok", r#""""#)]
    );
}

#[test]
fn a_matching_hash_skips_the_first_value() {
    let mut db = Database::new(RestOptions::default(), 1);
    rest(&mut db, "PUT", "/k.json?ns=l3", r#"{"x":1}"#);
    let mut s = open(&mut db, "l3");
    let hash = "LkoDN24bwRWG2p4jGZoe8M/Acf8=";
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(1, "q", &format!(r#"{{"p":"/k","h":"{hash}"}}"#))
        ),
        vec![reply(1, "ok", "{}")]
    );
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(2, "q", r#"{"p":"/k/x","h":"wrong"}"#)
        ),
        vec![push("d", "k/x", "1", None), reply(2, "ok", "{}")]
    );
    // Nothing stored and no hash: no value is sent.
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(12, "q", r#"{"p":"/missing","h":""}"#)
        ),
        vec![reply(12, "ok", "{}")]
    );
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(11, "q", r#"{"p":"/.info/connected","h":""}"#)
        ),
        vec![reply(
            11,
            "invalid_parameters",
            r#""Invalid token in path""#
        )]
    );
}

#[test]
fn a_tagged_query_follows_its_window() {
    let mut db = Database::new(RestOptions::default(), 1);
    rest(&mut db, "PUT", "/s.json?ns=l4", r#"{"a":1,"b":2,"c":3}"#);
    let mut s = open(&mut db, "l4");
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(
                1,
                "q",
                r#"{"p":"/s","q":{"i":".key","l":2,"vf":"l"},"t":7,"h":""}"#
            )
        ),
        vec![
            push("d", "s", r#"{"a":1,"b":2}"#, Some(7)),
            reply(1, "ok", "{}")
        ]
    );
    // A child outside the window pushes nothing.
    rest(&mut db, "PUT", "/s/z.json?ns=l4", "9");
    assert!(s.receive(&mut db, "0", NOW).replies.is_empty());
    assert!(db.drain_pushes().is_empty());
    // A deletion inside the window: the child that enters and the one that left.
    rest(&mut db, "DELETE", "/s/a.json?ns=l4", "");
    let id = s.client();
    assert_eq!(
        db.drain_pushes(),
        vec![(id, push("m", "s", r#"{"a":null,"c":3}"#, Some(7)))]
    );
    // A change inside the window, with another child outside it.
    rest(&mut db, "PATCH", "/s.json?ns=l4", r#"{"b":20,"y":1}"#);
    assert_eq!(
        db.drain_pushes(),
        vec![(id, push("d", "s/b", "20", Some(7)))]
    );
    // A child that enters at the front: only it is sent; the client trims the window.
    rest(&mut db, "PUT", "/s/0.json?ns=l4", "0");
    assert_eq!(
        db.drain_pushes(),
        vec![(id, push("d", "s/0", "0", Some(7)))]
    );
    // Unlistening the tagged query stops it.
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(
                2,
                "n",
                r#"{"p":"/s","q":{"i":".key","l":2,"vf":"l"},"t":7}"#
            )
        ),
        vec![reply(2, "ok", r#""""#)]
    );
    rest(&mut db, "PUT", "/s/0.json?ns=l4", "1");
    assert!(db.drain_pushes().is_empty());
}

#[test]
fn a_query_without_its_index_is_served_whole_with_a_warning() {
    let mut db = Database::new(RestOptions::default(), 1);
    rest(
        &mut db,
        "PUT",
        "/s.json?ns=l5",
        r#"{"a":{"h":5},"c":{"h":3}}"#,
    );
    let mut s = open(&mut db, "l5");
    assert_eq!(
        send(
            &mut db,
            &mut s,
            &request(
                6,
                "q",
                r#"{"p":"/s","q":{"i":"h","l":1,"vf":"l"},"t":2,"h":""}"#
            )
        ),
        vec![
            push("d", "s", r#"{"a":{"h":5},"c":{"h":3}}"#, None),
            reply(6, "ok", r#"{"w":["no_index"]}"#),
        ]
    );
    // It is followed like a plain listen, without its tag.
    assert_eq!(
        send(&mut db, &mut s, &request(8, "p", r#"{"p":"/s/00","d":1}"#)),
        vec![push("d", "s/00", "1", None), reply(8, "ok", r#""""#)]
    );
}

#[test]
fn other_connections_receive_pushes_and_closing_ends_their_listens() {
    let mut db = Database::new(RestOptions::default(), 1);
    let mut writer = open(&mut db, "l6");
    let mut reader = open(&mut db, "l6");
    send(
        &mut db,
        &mut reader,
        &request(1, "q", r#"{"p":"/a","h":""}"#),
    );
    assert_eq!(
        send(
            &mut db,
            &mut writer,
            &request(1, "p", r#"{"p":"/a/b","d":1}"#)
        ),
        vec![reply(1, "ok", r#""""#)]
    );
    assert_eq!(
        db.drain_pushes(),
        vec![(reader.client(), push("d", "a/b", "1", None))]
    );
    // A REST write reaches the realtime listener too.
    rest(&mut db, "PUT", "/a/c.json?ns=l6", "2");
    assert_eq!(
        db.drain_pushes(),
        vec![(reader.client(), push("d", "a/c", "2", None))]
    );
    // Another namespace pushes nothing.
    rest(&mut db, "PUT", "/a/c.json?ns=other", "2");
    assert!(db.drain_pushes().is_empty());
    db.close_realtime(reader.client());
    rest(&mut db, "PUT", "/a/d.json?ns=l6", "3");
    assert!(db.drain_pushes().is_empty());
}
