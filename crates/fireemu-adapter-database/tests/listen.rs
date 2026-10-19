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
    // What entered goes before what was deleted, as the official emulator orders them.
    assert_eq!(
        db.drain_pushes(),
        vec![(id, push("m", "s", r#"{"c":3,"a":null}"#, Some(7)))]
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

/// One step of a recorded exchange: who acts (`A` and `B` are realtime connections, `REST`
/// a request written `METHOD path body`) and every frame `A` received for it, in order.
type Step = ((&'static str, &'static str), &'static [&'static str]);

/// Replays steps recorded against the official emulator and compares what `A` receives.
fn replay(ns: &str, steps: &[Step]) {
    replay_indexed(ns, &[], steps);
}

/// [`replay`] with `.indexOn` declarations, `(path, child)`.
fn replay_indexed(ns: &str, indexes: &[(&str, &str)], steps: &[Step]) {
    let mut db = Database::new(RestOptions::default(), 1);
    for (path, child) in indexes {
        db.declare_index(ns, &fireemu_core_database::Path::from_keys([*path]), child);
    }
    let mut a = open(&mut db, ns);
    let mut b = open(&mut db, ns);
    for (index, ((who, text), expected)) in steps.iter().enumerate() {
        let mut got = match *who {
            "A" => send(&mut db, &mut a, &format!(r#"{{"t":"d","d":{text}}}"#)),
            "B" => {
                send(&mut db, &mut b, &format!(r#"{{"t":"d","d":{text}}}"#));
                Vec::new()
            }
            _ => {
                let mut parts = text.splitn(3, ' ');
                let (method, path, body) = (
                    parts.next().unwrap(),
                    parts.next().unwrap(),
                    parts.next().unwrap_or(""),
                );
                rest(
                    &mut db,
                    method,
                    &format!("{path}?ns={ns}&print=silent"),
                    body,
                );
                Vec::new()
            }
        };
        got.extend(
            db.drain_pushes()
                .into_iter()
                .filter(|(client, _)| *client == a.client())
                .map(|(_, frame)| frame),
        );
        assert_eq!(got, *expected, "step {index}: {who} {text}");
    }
}

/// Writes at, above and below plain listens: a write that changes nothing pushes nothing
/// unless it writes null, and a write at or above a listen pushes its value even when that
/// value did not change.
#[test]
#[rustfmt::skip]
fn plain_listens_follow_writes_as_the_official_emulator_pushes_them() {
    replay("r1", &[
        (("REST", r#"PUT /m.json {"y":1,"z":{"h":6}}"#), &[]),
        (("A", r#"{"r":1,"a":"q","b":{"p":"/m/x","h":""}}"#), &[r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":{}}}}"#]),
        (("A", r#"{"r":2,"a":"q","b":{"p":"/m/z/h","h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"m/z/h","d":6},"a":"d"}}"#, r#"{"t":"d","d":{"r":2,"b":{"s":"ok","d":{}}}}"#]),
        (("B", r#"{"r":1,"a":"p","b":{"p":"/m/y","d":2}}"#), &[]),
        (("B", r#"{"r":2,"a":"p","b":{"p":"/m","d":{"y":3,"z":{"h":6}}}}"#), &[r#"{"t":"d","d":{"b":{"p":"m/x","d":null},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"m/z/h","d":6},"a":"d"}}"#]),
        (("B", r#"{"r":3,"a":"p","b":{"p":"/m/x/deep","d":null}}"#), &[r#"{"t":"d","d":{"b":{"p":"m/x/deep","d":null},"a":"d"}}"#]),
        (("B", r#"{"r":4,"a":"m","b":{"p":"/m","d":{"y":4}}}"#), &[]),
        (("B", r#"{"r":5,"a":"m","b":{"p":"/","d":{"m/y":5}}}"#), &[]),
        (("B", r#"{"r":6,"a":"p","b":{"p":"/m/x","d":null}}"#), &[r#"{"t":"d","d":{"b":{"p":"m/x","d":null},"a":"d"}}"#]),
        (("B", r#"{"r":7,"a":"p","b":{"p":"/","d":{"m":{"y":3,"z":{"h":6}}}}}"#), &[r#"{"t":"d","d":{"b":{"p":"m/x","d":null},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"m/z/h","d":6},"a":"d"}}"#]),
        (("B", r#"{"r":8,"a":"m","b":{"p":"/m","d":{"x":null}}}"#), &[r#"{"t":"d","d":{"b":{"p":"m/x","d":null},"a":"d"}}"#]),
        (("B", r#"{"r":9,"a":"m","b":{"p":"/m","d":{"z":{"h":6}}}}"#), &[]),
        (("B", r#"{"r":10,"a":"m","b":{"p":"/m","d":{"z/h":6,"y":9}}}"#), &[]),
        (("A", r#"{"r":3,"a":"n","b":{"p":"/m/x"}}"#), &[r#"{"t":"d","d":{"r":3,"b":{"s":"ok","d":""}}}"#]),
        (("A", r#"{"r":4,"a":"q","b":{"p":"/m","h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"m","d":{"y":9,"z":{"h":6}}},"a":"d"}}"#, r#"{"t":"d","d":{"r":4,"b":{"s":"ok","d":{}}}}"#]),
        (("A", r#"{"r":5,"a":"q","b":{"p":"/m/z","h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"m/z","d":{"h":6}},"a":"d"}}"#, r#"{"t":"d","d":{"r":5,"b":{"s":"ok","d":{}}}}"#]),
        (("A", r#"{"r":6,"a":"n","b":{"p":"/m"}}"#), &[r#"{"t":"d","d":{"r":6,"b":{"s":"ok","d":""}}}"#]),
        (("B", r#"{"r":11,"a":"p","b":{"p":"/m/q","d":1}}"#), &[]),
    ]);
}

/// Merges: entries that change nothing are left out unless they write null, entries keep
/// the order they were sent in, priorities and server values count once resolved.
#[test]
#[rustfmt::skip]
fn merges_push_their_effective_entries_in_request_order() {
    replay("r2", &[
        (("REST", r#"PUT /s.json {"a":1,"b":2,"c":{"d":3}}"#), &[]),
        (("A", r#"{"r":1,"a":"q","b":{"p":"/s","h":"x"}}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"a":1,"b":2,"c":{"d":3}}},"a":"d"}}"#, r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":{}}}}"#]),
        (("A", r#"{"r":2,"a":"q","b":{"p":"/s/c/d","h":"x"}}"#), &[r#"{"t":"d","d":{"b":{"p":"s/c/d","d":3},"a":"d"}}"#, r#"{"t":"d","d":{"r":2,"b":{"s":"ok","d":{}}}}"#]),
        (("B", r#"{"r":1,"a":"m","b":{"p":"/s","d":{"a":1,"b":20}}}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"b":20}},"a":"m"}}"#]),
        (("B", r#"{"r":2,"a":"m","b":{"p":"/s","d":{"x":null,"y":2,"a":1}}}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"x":null,"y":2}},"a":"m"}}"#]),
        (("B", r#"{"r":3,"a":"m","b":{"p":"/s","d":{"y":null,"x":null}}}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"y":null,"x":null}},"a":"m"}}"#]),
        (("B", r#"{"r":4,"a":"m","b":{"p":"/","d":{"s/a":1,"s/b":21}}}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"b":21}},"a":"m"}}"#]),
        (("B", r#"{"r":5,"a":"m","b":{"p":"/","d":{"s/c":{"d":3},"t":1}}}"#), &[]),
        (("B", r#"{"r":6,"a":"m","b":{"p":"/s","d":{"c/d":4,"c/e":5}}}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"c/d":4,"c/e":5}},"a":"m"}}"#, r#"{"t":"d","d":{"b":{"p":"s/c/d","d":4},"a":"d"}}"#]),
        (("B", r#"{"r":7,"a":"m","b":{"p":"/s/c","d":{"d":4,"e":null}}}"#), &[r#"{"t":"d","d":{"b":{"p":"s/c","d":{"e":null}},"a":"m"}}"#]),
        (("B", r#"{"r":8,"a":"m","b":{"p":"/s/c/d","d":{"z":1}}}"#), &[r#"{"t":"d","d":{"b":{"p":"s/c/d","d":{"z":1}},"a":"m"}}"#, r#"{"t":"d","d":{"b":{"p":"s/c/d","d":{"z":1}},"a":"m"}}"#]),
        (("B", r#"{"r":9,"a":"p","b":{"p":"/s/c","d":{"d":{"z":1}}}}"#), &[]),
        (("B", r#"{"r":10,"a":"p","b":{"p":"/s/c/d/z","d":1}}"#), &[]),
        (("B", r#"{"r":11,"a":"p","b":{"p":"/s/c/d/.priority","d":1}}"#), &[r#"{"t":"d","d":{"b":{"p":"s/c/d/.priority","d":1},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"s/c/d/.priority","d":1},"a":"d"}}"#]),
        (("B", r#"{"r":12,"a":"p","b":{"p":"/s/c/d/.priority","d":1}}"#), &[]),
        (("B", r#"{"r":13,"a":"p","b":{"p":"/s/b","d":{".sv":"timestamp"}}}"#), &[r#"{"t":"d","d":{"b":{"p":"s/b","d":1792417166902},"a":"d"}}"#]),
        (("B", r#"{"r":14,"a":"p","b":{"p":"/s/b","d":{".sv":{"increment":0}}}}"#), &[]),
        (("B", r#"{"r":15,"a":"m","b":{"p":"/s","d":{"b":{".sv":{"increment":0}}}}}"#), &[]),
        (("B", r#"{"r":16,"a":"p","b":{"p":"/s/c/d","d":{"z":1},"h":"wrong"}}"#), &[]),
        (("B", r#"{"r":17,"a":"p","b":{"p":"/s/c/q","d":{".priority":2}}}"#), &[]),
        (("B", r#"{"r":18,"a":"p","b":{"p":"/s/a","d":1}}"#), &[]),
    ]);
}

/// Tagged windows: a write at or above the location sends the window; a write inside it
/// sends what entered, changed or was deleted (entries first, deletions last).
#[test]
#[rustfmt::skip]
fn tagged_windows_follow_writes_as_the_official_emulator_pushes_them() {
    replay("r3", &[
        (("REST", r#"PUT /w.json {"a":1,"b":2,"c":3,"d":4}"#), &[]),
        (("A", r#"{"r":1,"a":"q","b":{"p":"/w","q":{"i":".key","l":2,"vf":"l"},"t":1,"h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"a":1,"b":2},"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":{}}}}"#]),
        (("A", r#"{"r":2,"a":"q","b":{"p":"/w","q":{"i":".key","sp":"b","ep":"c"},"t":3,"h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"b":2,"c":3},"t":3},"a":"d"}}"#, r#"{"t":"d","d":{"r":2,"b":{"s":"ok","d":{}}}}"#]),
        (("B", r#"{"r":1,"a":"p","b":{"p":"/w/b","d":2}}"#), &[]),
        (("B", r#"{"r":2,"a":"p","b":{"p":"/w/b","d":null}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"c":3,"b":null},"t":1},"a":"m"}}"#, r#"{"t":"d","d":{"b":{"p":"w/b","d":null,"t":3},"a":"d"}}"#]),
        (("B", r#"{"r":3,"a":"p","b":{"p":"/w/b","d":2}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/b","d":2,"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"w/b","d":2,"t":3},"a":"d"}}"#]),
        (("B", r#"{"r":4,"a":"m","b":{"p":"/w","d":{"b":5}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"b":5},"t":1},"a":"m"}}"#, r#"{"t":"d","d":{"b":{"p":"w","d":{"b":5},"t":3},"a":"m"}}"#]),
        (("B", r#"{"r":5,"a":"m","b":{"p":"/w","d":{"b":6,"a":7}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"a":7,"b":6},"t":1},"a":"m"}}"#, r#"{"t":"d","d":{"b":{"p":"w","d":{"b":6},"t":3},"a":"m"}}"#]),
        (("B", r#"{"r":6,"a":"m","b":{"p":"/w","d":{"a":null,"c":null}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"d":4,"a":null},"t":1},"a":"m"}}"#, r#"{"t":"d","d":{"b":{"p":"w","d":{"c":null},"t":3},"a":"m"}}"#]),
        (("B", r#"{"r":7,"a":"m","b":{"p":"/w","d":{"a":1,"c":3}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"c":3,"a":1},"t":1},"a":"m"}}"#, r#"{"t":"d","d":{"b":{"p":"w","d":{"c":3},"t":3},"a":"m"}}"#]),
        (("B", r#"{"r":8,"a":"p","b":{"p":"/w/z","d":null}}"#), &[]),
        (("B", r#"{"r":9,"a":"p","b":{"p":"/w/b/x","d":1}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/b/x","d":1,"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"w/b/x","d":1,"t":3},"a":"d"}}"#]),
        (("B", r#"{"r":10,"a":"p","b":{"p":"/w/b/x","d":null}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"c":3,"b":null},"t":1},"a":"m"}}"#, r#"{"t":"d","d":{"b":{"p":"w/b/x","d":null,"t":3},"a":"d"}}"#]),
        (("B", r#"{"r":11,"a":"p","b":{"p":"/w","d":{"a":1,"b":6,"c":3,"d":4}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"a":1,"b":6},"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"w","d":{"b":6,"c":3},"t":3},"a":"d"}}"#]),
        (("B", r#"{"r":12,"a":"p","b":{"p":"/w","d":{"a":1,"b":6,"c":30,"d":4}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"a":1,"b":6},"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"w","d":{"b":6,"c":30},"t":3},"a":"d"}}"#]),
        (("B", r#"{"r":13,"a":"p","b":{"p":"/","d":{"w":{"a":1,"b":6,"c":31,"d":4}}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"a":1,"b":6},"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"w","d":{"b":6,"c":31},"t":3},"a":"d"}}"#]),
        (("B", r#"{"r":14,"a":"m","b":{"p":"/","d":{"w/a":2,"w/c":32}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/a","d":2,"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"w","d":{"c":32},"t":3},"a":"m"}}"#]),
        (("B", r#"{"r":15,"a":"m","b":{"p":"/","d":{"w":{"b":1}}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"b":1},"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"w","d":{"b":1},"t":3},"a":"d"}}"#]),
        (("B", r#"{"r":16,"a":"p","b":{"p":"/w","d":null}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":null,"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"w","d":{},"t":3},"a":"d"}}"#]),
        (("B", r#"{"r":17,"a":"p","b":{"p":"/w","d":null}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":null,"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"w","d":{},"t":3},"a":"d"}}"#]),
        (("B", r#"{"r":18,"a":"p","b":{"p":"/w/a","d":null}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/a","d":null,"t":1},"a":"d"}}"#]),
        (("B", r#"{"r":19,"a":"p","b":{"p":"/w/c","d":1}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/c","d":1,"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"w/c","d":1,"t":3},"a":"d"}}"#]),
        (("A", r#"{"r":3,"a":"q","b":{"p":"/w","q":{"i":".key","sp":"x"},"t":4,"h":""}}"#), &[r#"{"t":"d","d":{"r":3,"b":{"s":"ok","d":{}}}}"#]),
        (("A", r#"{"r":4,"a":"q","b":{"p":"/w","q":{"i":".key","l":1,"vf":"r"},"t":5,"h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"c":1},"t":5},"a":"d"}}"#, r#"{"t":"d","d":{"r":4,"b":{"s":"ok","d":{}}}}"#]),
        (("A", r#"{"r":5,"a":"q","b":{"p":"/w/c","q":{"i":".key","l":1,"vf":"r"},"t":6,"h":""}}"#), &[r#"{"t":"d","d":{"r":5,"b":{"s":"ok","d":{}}}}"#]),
        (("A", r#"{"r":6,"a":"q","b":{"p":"/nothing","q":{"i":".key","l":1,"vf":"r"},"t":7,"h":""}}"#), &[r#"{"t":"d","d":{"r":6,"b":{"s":"ok","d":{}}}}"#]),
    ]);
}

/// REST writes reach realtime listens the same way, a `PATCH` with its members in sent order.
#[test]
#[rustfmt::skip]
fn rest_writes_push_like_realtime_writes() {
    replay("r4", &[
        (("REST", r#"PUT /s.json {"a":1,"b":2,"c":3}"#), &[]),
        (("A", r#"{"r":1,"a":"q","b":{"p":"/s","q":{"i":".key","l":2,"vf":"l"},"t":7,"h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"a":1,"b":2},"t":7},"a":"d"}}"#, r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":{}}}}"#]),
        (("REST", r"PUT /s/z.json 9"), &[]),
        (("REST", r"DELETE /s/a.json "), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"c":3,"a":null},"t":7},"a":"m"}}"#]),
        (("REST", r#"PATCH /s.json {"b":20,"y":1}"#), &[r#"{"t":"d","d":{"b":{"p":"s/b","d":20,"t":7},"a":"d"}}"#]),
        (("REST", r"PUT /s/0.json 0"), &[r#"{"t":"d","d":{"b":{"p":"s/0","d":0,"t":7},"a":"d"}}"#]),
        (("A", r#"{"r":2,"a":"n","b":{"p":"/s","q":{"i":".key","l":2,"vf":"l"},"t":7}}"#), &[r#"{"t":"d","d":{"r":2,"b":{"s":"ok","d":""}}}"#]),
        (("REST", r"PUT /s/0.json 1"), &[]),
        (("A", r#"{"r":3,"a":"q","b":{"p":"/s","h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"0":1,"b":20,"c":3,"y":1,"z":9}},"a":"d"}}"#, r#"{"t":"d","d":{"r":3,"b":{"s":"ok","d":{}}}}"#]),
        (("REST", r#"PATCH /s.json {"y":null,"b":21,"a":5}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"y":null,"b":21,"a":5}},"a":"m"}}"#]),
        (("REST", r#"PATCH /s.json {"y":null,"b":21}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"y":null}},"a":"m"}}"#]),
    ]);
}

/// Merges into a limit window: entries that all touch the window arrive as sent, last
/// first, with the children that entered; otherwise only what changed in the window.
#[test]
#[rustfmt::skip]
fn merges_into_a_limit_window_follow_the_official_emulator() {
    replay("r5", &[
        (("REST", r#"PUT /w.json {"a":1,"b":2,"c":3,"d":4}"#), &[]),
        (("A", r#"{"r":1,"a":"q","b":{"p":"/w","q":{"i":".key","l":2,"vf":"l"},"t":1,"h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"a":1,"b":2},"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":{}}}}"#]),
        (("B", r#"{"r":1,"a":"m","b":{"p":"/w","d":{"a":5,"b":6}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"b":6,"a":5},"t":1},"a":"m"}}"#]),
        (("B", r#"{"r":2,"a":"m","b":{"p":"/w/b","d":{"x":1,"y":2}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/b","d":{"x":1,"y":2},"t":1},"a":"m"}}"#]),
        (("B", r#"{"r":3,"a":"m","b":{"p":"/w","d":{"b/x":3}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"b/x":3},"t":1},"a":"m"}}"#]),
        (("B", r#"{"r":4,"a":"m","b":{"p":"/w","d":{"b/y":4,"z":1}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/b","d":{"x":3,"y":4},"t":1},"a":"d"}}"#]),
        (("B", r#"{"r":5,"a":"m","b":{"p":"/w","d":{"z":2,"b/y":5}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/b","d":{"x":3,"y":5},"t":1},"a":"d"}}"#]),
        (("B", r#"{"r":6,"a":"m","b":{"p":"/w","d":{"0":0,"z":3}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/0","d":0,"t":1},"a":"d"}}"#]),
        (("B", r#"{"r":7,"a":"m","b":{"p":"/w","d":{"0":null,"z":4}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"b":{"x":3,"y":5},"0":null},"t":1},"a":"m"}}"#]),
        (("B", r#"{"r":8,"a":"m","b":{"p":"/w","d":{"0":0,"1":1}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"1":1,"0":0},"t":1},"a":"m"}}"#]),
        (("B", r#"{"r":9,"a":"m","b":{"p":"/w","d":{"0":null,"1":null}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"b":{"x":3,"y":5},"a":5,"1":null,"0":null},"t":1},"a":"m"}}"#]),
        (("B", r#"{"r":10,"a":"m","b":{"p":"/","d":{"w/a":9,"w/z":5}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/a","d":9,"t":1},"a":"d"}}"#]),
        (("B", r#"{"r":11,"a":"m","b":{"p":"/","d":{"w/z":6,"w/a":10}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/a","d":10,"t":1},"a":"d"}}"#]),
        (("B", r#"{"r":12,"a":"m","b":{"p":"/w/b","d":{"x":7}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/b","d":{"x":7},"t":1},"a":"m"}}"#]),
        (("B", r#"{"r":13,"a":"m","b":{"p":"/w","d":{"0":12,"a":11}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"a":11,"0":12},"t":1},"a":"m"}}"#]),
    ]);
}

/// Priorities written to a leaf's `.priority` read as doubles in values, while the
/// messages for the write carry it as written; a `g` of a `.priority` path reads it.
#[test]
#[rustfmt::skip]
fn priorities_written_to_leaves_read_as_doubles() {
    replay("r7", &[
        (("REST", r#"PUT /x.json {"a":1}"#), &[]),
        (("A", r#"{"r":1,"a":"p","b":{"p":"/x/.priority","d":5}}"#), &[r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":""}}}"#]),
        (("A", r#"{"r":2,"a":"g","b":{"p":"/x","q":{}}}"#), &[r#"{"t":"d","d":{"r":2,"b":{"s":"ok","d":{".priority":5,"a":1}}}}"#]),
        (("A", r#"{"r":3,"a":"g","b":{"p":"/x/.priority","q":{}}}"#), &[r#"{"t":"d","d":{"r":3,"b":{"s":"ok","d":5}}}"#]),
        (("A", r#"{"r":4,"a":"q","b":{"p":"/x","h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"x","d":{".priority":5,"a":1}},"a":"d"}}"#, r#"{"t":"d","d":{"r":4,"b":{"s":"ok","d":{}}}}"#]),
        (("A", r#"{"r":5,"a":"p","b":{"p":"/y","d":{".value":1,".priority":7}}}"#), &[r#"{"t":"d","d":{"r":5,"b":{"s":"ok","d":""}}}"#]),
        (("A", r#"{"r":6,"a":"p","b":{"p":"/y/.priority","d":8}}"#), &[r#"{"t":"d","d":{"r":6,"b":{"s":"ok","d":""}}}"#]),
        (("A", r#"{"r":7,"a":"g","b":{"p":"/y","q":{}}}"#), &[r#"{"t":"d","d":{"r":7,"b":{"s":"ok","d":{".value":1,".priority":8.0}}}}"#]),
    ]);
    replay("r8", &[
        (("REST", r"PUT /y.json 1"), &[]),
        (("A", r#"{"r":1,"a":"p","b":{"p":"/y/.priority","d":8}}"#), &[r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":""}}}"#]),
        (("A", r#"{"r":2,"a":"g","b":{"p":"/y/.priority","q":{}}}"#), &[r#"{"t":"d","d":{"r":2,"b":{"s":"ok","d":8.0}}}"#]),
        (("A", r#"{"r":3,"a":"g","b":{"p":"/nope/.priority","q":{}}}"#), &[r#"{"t":"d","d":{"r":3,"b":{"s":"ok","d":null}}}"#]),
        (("A", r#"{"r":4,"a":"q","b":{"p":"/y/.priority","h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"y/.priority","d":8.0},"a":"d"}}"#, r#"{"t":"d","d":{"r":4,"b":{"s":"ok","d":{}}}}"#]),
    ]);
    replay("r6", &[
        (("REST", r#"PUT /s.json {"a":{".value":1,".priority":1},"b":{".value":2,".priority":2},"c":{".value":3,".priority":3}}"#), &[]),
        (("A", r#"{"r":1,"a":"q","b":{"p":"/s","q":{"l":1,"vf":"l"},"t":1,"h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"a":{".value":1,".priority":1.0}},"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":{}}}}"#]),
        (("B", r#"{"r":1,"a":"p","b":{"p":"/s/a/.priority","d":5}}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"b":{".value":2,".priority":2.0},"a":{".value":1,".priority":5.0}},"t":1},"a":"m"}}"#]),
        (("B", r#"{"r":2,"a":"p","b":{"p":"/s/a","d":{".value":0,".priority":0}}}"#), &[r#"{"t":"d","d":{"b":{"p":"s/a","d":{".value":0,".priority":0.0},"t":1},"a":"d"}}"#]),
        (("B", r#"{"r":3,"a":"m","b":{"p":"/s","d":{"a":{".value":7,".priority":9},"z":1}}}"#), &[r#"{"t":"d","d":{"b":{"p":"s","d":{"z":1,"a":{".value":7,".priority":9.0}},"t":1},"a":"m"}}"#]),
        (("B", r#"{"r":4,"a":"m","b":{"p":"/s","d":{"b":{".value":7,".priority":9},"c/.priority":8}}}"#), &[]),
    ]);
}

/// Nulls that change nothing: sent where a window shows a child, or where a window that is
/// not full would show one in its range; zero and negative limits are refused.
#[test]
#[rustfmt::skip]
fn nulls_reach_the_places_a_window_shows() {
    replay_indexed("r9", &[("t", "x")], &[
        (("REST", r#"PUT /w.json {"c":1}"#), &[]),
        (("A", r#"{"r":1,"a":"q","b":{"p":"/w","q":{"i":".key","sp":"b","ep":"c"},"t":1,"h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"c":1},"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":{}}}}"#]),
        (("B", r#"{"r":1,"a":"p","b":{"p":"/w/b","d":null}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/b","d":null,"t":1},"a":"d"}}"#]),
        (("B", r#"{"r":2,"a":"p","b":{"p":"/w/a","d":null}}"#), &[]),
        (("A", r#"{"r":2,"a":"q","b":{"p":"/w","q":{"i":".key","l":0,"vf":"l"},"t":2,"h":""}}"#), &[r#"{"t":"d","d":{"r":2,"b":{"s":"invalid_parameters","d":"Invalid query limit"}}}"#]),
        (("B", r#"{"r":3,"a":"m","b":{"p":"/w","d":{"d":1}}}"#), &[]),
        (("B", r#"{"r":4,"a":"p","b":{"p":"/w/e","d":2}}"#), &[]),
        (("B", r#"{"r":5,"a":"p","b":{"p":"/w/f","d":null}}"#), &[]),
        (("B", r#"{"r":6,"a":"p","b":{"p":"/x/a","d":null}}"#), &[]),
        (("A", r#"{"r":3,"a":"q","b":{"p":"/t","q":{"i":"x","sp":1},"t":3,"h":""}}"#), &[r#"{"t":"d","d":{"r":3,"b":{"s":"ok","d":{}}}}"#]),
        (("B", r#"{"r":7,"a":"p","b":{"p":"/t/a","d":null}}"#), &[]),
        (("A", r#"{"r":4,"a":"q","b":{"p":"/t","q":{"i":"x","l":2,"vf":"l"},"t":4,"h":""}}"#), &[r#"{"t":"d","d":{"r":4,"b":{"s":"ok","d":{}}}}"#]),
        (("B", r#"{"r":8,"a":"p","b":{"p":"/t/b","d":null}}"#), &[r#"{"t":"d","d":{"b":{"p":"t/b","d":null,"t":4},"a":"d"}}"#]),
    ]);
    replay("r10", &[
        (("REST", r#"PUT /w.json {"a":1,"c":3,"d":4}"#), &[]),
        (("A", r#"{"r":1,"a":"q","b":{"p":"/w","q":{"i":".key","l":2,"vf":"l"},"t":1,"h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"a":1,"c":3},"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":{}}}}"#]),
        (("B", r#"{"r":1,"a":"p","b":{"p":"/w/b","d":null}}"#), &[]),
        (("B", r#"{"r":2,"a":"p","b":{"p":"/w/0","d":null}}"#), &[]),
        (("B", r#"{"r":3,"a":"p","b":{"p":"/w/e","d":null}}"#), &[]),
        (("A", r#"{"r":2,"a":"q","b":{"p":"/w","q":{"i":".key","l":0,"vf":"r"},"t":2,"h":""}}"#), &[r#"{"t":"d","d":{"r":2,"b":{"s":"invalid_parameters","d":"Invalid query limit"}}}"#]),
        (("A", r#"{"r":3,"a":"q","b":{"p":"/w","q":{"i":".key","l":-1,"vf":"l"},"t":3,"h":""}}"#), &[r#"{"t":"d","d":{"r":3,"b":{"s":"invalid_parameters","d":"Invalid query limit"}}}"#]),
        (("A", r#"{"r":4,"a":"g","b":{"p":"/w","q":{"i":".key","l":0,"vf":"l"}}}"#), &[r#"{"t":"d","d":{"r":4,"b":{"s":"invalid_parameters","d":"Invalid query limit"}}}"#]),
    ]);
    replay("r11", &[
        (("REST", r#"PUT /w.json {"a":1,"b":{"y":1},"c":3}"#), &[]),
        (("A", r#"{"r":1,"a":"q","b":{"p":"/w","q":{"i":".key","l":2,"vf":"l"},"t":1,"h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"a":1,"b":{"y":1}},"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":{}}}}"#]),
        (("B", r#"{"r":1,"a":"p","b":{"p":"/w/b/x","d":null}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/b/x","d":null,"t":1},"a":"d"}}"#]),
        (("B", r#"{"r":2,"a":"p","b":{"p":"/w/a/x","d":null}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/a/x","d":null,"t":1},"a":"d"}}"#]),
        (("B", r#"{"r":3,"a":"p","b":{"p":"/w/c/x","d":null}}"#), &[]),
        (("A", r#"{"r":2,"a":"q","b":{"p":"/w","q":{"i":".key","l":5,"vf":"l"},"t":2,"h":""}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"a":1,"b":{"y":1},"c":3},"t":2},"a":"d"}}"#, r#"{"t":"d","d":{"r":2,"b":{"s":"ok","d":{}}}}"#]),
        (("B", r#"{"r":4,"a":"p","b":{"p":"/w/b/x","d":null}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/b/x","d":null,"t":1},"a":"d"}}"#, r#"{"t":"d","d":{"b":{"p":"w/b/x","d":null,"t":2},"a":"d"}}"#]),
        (("B", r#"{"r":5,"a":"m","b":{"p":"/w","d":{"b/x":null}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w","d":{"b/x":null},"t":1},"a":"m"}}"#, r#"{"t":"d","d":{"b":{"p":"w","d":{"b/x":null},"t":2},"a":"m"}}"#]),
        (("B", r#"{"r":6,"a":"m","b":{"p":"/w","d":{"q":null}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/q","d":null,"t":2},"a":"d"}}"#]),
        (("B", r#"{"r":7,"a":"m","b":{"p":"/w/b","d":{"x":null}}}"#), &[r#"{"t":"d","d":{"b":{"p":"w/b","d":{"x":null},"t":1},"a":"m"}}"#, r#"{"t":"d","d":{"b":{"p":"w/b","d":{"x":null},"t":2},"a":"m"}}"#]),
    ]);
}

#[test]
fn merge_members_keep_their_order_beside_other_objects() {
    let mut db = Database::new(RestOptions::default(), 1);
    rest(&mut db, "PUT", "/s.json?ns=l7", r#"{"a":0,"b":0}"#);
    let mut s = open(&mut db, "l7");
    send(&mut db, &mut s, &request(1, "q", r#"{"p":"/s","h":""}"#));
    // Another object member of the body, before `d`, lists the same keys the other way.
    assert_eq!(
        send(
            &mut db,
            &mut s,
            r#"{"t":"d","d":{"r":2,"a":"m","b":{"z":{"b":1,"a":1},"p":"/s","d":{"a":1,"b":2}}}}"#
        ),
        vec![
            push("m", "s", r#"{"a":1,"b":2}"#, None),
            reply(2, "ok", r#""""#)
        ]
    );
}

#[test]
fn closing_one_connection_keeps_the_pushes_queued_for_others() {
    let mut db = Database::new(RestOptions::default(), 1);
    let mut writer = open(&mut db, "l8");
    let mut reader = open(&mut db, "l8");
    send(
        &mut db,
        &mut reader,
        &request(1, "q", r#"{"p":"/a","h":""}"#),
    );
    send(
        &mut db,
        &mut writer,
        &request(1, "p", r#"{"p":"/a","d":1}"#),
    );
    db.close_realtime(writer.client());
    assert_eq!(
        db.drain_pushes(),
        vec![(reader.client(), push("d", "a", "1", None))]
    );
}
