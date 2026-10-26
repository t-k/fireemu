//! onDisconnect (`o`, `om`, `oc`): what registering answers, and what a connection's end
//! writes. Unless a test says otherwise, every expected frame and value is what the official
//! emulator (firebase-database-emulator v4.11.2) sent or stored for the same frames.

#![allow(clippy::too_many_lines)]

use fireemu_adapter_database::realtime::{Opened, Session};
use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions, RulesMode};

const NOW: i64 = 1_792_464_733_000;
/// When the connections in these tests end.
const LATER: i64 = NOW + 1_234;

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

fn ok(r: u64) -> String {
    reply(r, "ok", r#""""#)
}

fn rest(db: &mut Database, method: &str, target: &str, body: &str) -> String {
    let request = HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
    };
    match db.handle(&request, NOW) {
        Handled::Response { response, .. } => String::from_utf8(response.body).unwrap(),
        Handled::Stream { .. } => panic!("stream"),
    }
}

/// Opens a listener of the whole namespace, then a connection that sends `frames` and ends
/// at `LATER`. Returns the replies, what the listener received after the end, and the
/// namespace's value.
fn run(
    ns: &str,
    writes: &[(&str, &str)],
    frames: &[(&str, &str)],
) -> (Vec<String>, Vec<String>, String) {
    let mut db = Database::new(RestOptions::default(), 1);
    for (path, value) in writes {
        rest(&mut db, "PUT", &format!("{path}.json?ns={ns}"), value);
    }
    let mut listener = open(&mut db, ns);
    send(
        &mut db,
        &mut listener,
        &request(1, "q", r#"{"p":"/","h":""}"#),
    );
    let mut session = open(&mut db, ns);
    let mut replies = Vec::new();
    for (r, (action, body)) in (1..).zip(frames) {
        replies.extend(send(&mut db, &mut session, &request(r, action, body)));
    }
    db.drain_pushes();
    db.close_realtime(session.client(), LATER);
    let pushes = db
        .drain_pushes()
        .into_iter()
        .filter(|(to, _)| *to == listener.client())
        .map(|(_, frame)| frame)
        .collect();
    let value = rest(&mut db, "GET", &format!("/.json?ns={ns}&format=export"), "");
    (replies, pushes, value)
}

fn merge_push(data: &str) -> String {
    format!(r#"{{"t":"d","d":{{"b":{{"p":"","d":{data}}},"a":"m"}}}}"#)
}

#[test]
fn registering_answers_ok_and_refuses_bad_paths() {
    let (replies, pushes, value) = run(
        "od1",
        &[],
        &[
            ("o", r#"{"p":"/c1","d":{"x":1}}"#),
            ("om", r#"{"p":"/c2","d":{"b":3}}"#),
            ("oc", r#"{"p":"/nothing"}"#),
            ("o", r#"{"p":"/a.b","d":1}"#),
            ("o", r#"{"p":"/.info/x","d":1}"#),
            ("om", r#"{"p":"/c3","d":{}}"#),
            ("om", r#"{"p":"/c4","d":{"a/b":1,"a":2}}"#),
        ],
    );
    assert_eq!(
        replies,
        vec![
            ok(1),
            ok(2),
            ok(3),
            reply(4, "invalid_parameters", r#""Invalid token in path""#),
            reply(5, "invalid_parameters", r#""Invalid token in path""#),
            ok(6),
            reply(
                7,
                "invalid_parameters",
                r#""Path 'a' is ancestor of 'a/b'""#
            ),
        ]
    );
    assert_eq!(pushes, vec![merge_push(r#"{"c1":{"x":1},"c2/b":3}"#)]);
    assert_eq!(value, r#"{"c1":{"x":1},"c2":{"b":3}}"#);
}

#[test]
fn requests_without_a_path_are_not_answered_and_bad_data_is_a_connection_error() {
    let mut db = Database::new(RestOptions::default(), 1);
    let mut session = open(&mut db, "od2");
    assert!(send(&mut db, &mut session, &request(1, "o", r#"{"d":1}"#)).is_empty());
    assert!(send(&mut db, &mut session, &request(2, "oc", "{}")).is_empty());
    for (r, (action, body)) in (3..).zip([
        ("om", r#"{"p":"/c","d":5}"#),
        ("o", r#"{"p":"/c","d":{"a.b":1}}"#),
        ("o", r#"{"p":"/c","d":{"a":{".sv":"nope"}}}"#),
        ("o", r#"{"p":"/c","d":1,"h":"abc"}"#),
    ]) {
        let replies = send(&mut db, &mut session, &request(r, action, body));
        assert_eq!(replies.len(), 1, "{body}");
        assert!(
            replies[0].starts_with(r#"{"t":"c","d":{"t":"e","d":"ClientId["#),
            "{body}: {replies:?}"
        );
    }
    // The connection goes on, and nothing above was registered.
    assert_eq!(
        send(
            &mut db,
            &mut session,
            &request(7, "o", r#"{"p":"/k","d":1}"#)
        ),
        vec![ok(7)]
    );
    db.close_realtime(session.client(), LATER);
    assert_eq!(rest(&mut db, "GET", "/.json?ns=od2", ""), r#"{"k":1}"#);
}

#[test]
fn a_connection_end_writes_its_operations_as_one_update() {
    for (ns, writes, frames, push, value) in [
        (
            "e1",
            vec![("/c2", r#"{"a":1,"b":2}"#)],
            vec![("om", r#"{"p":"/c2","d":{"b":3,"c/d":4}}"#)],
            merge_push(r#"{"c2/b":3,"c2/c/d":4}"#),
            r#"{"c2":{"a":1,"b":3,"c":{"d":4}}}"#,
        ),
        (
            "e2",
            vec![("/c3", "5")],
            vec![("o", r#"{"p":"/c3","d":null}"#)],
            merge_push(r#"{"c3":null}"#),
            "null",
        ),
        // Without data the operation removes.
        (
            "e3",
            vec![("/c13", "5")],
            vec![("o", r#"{"p":"/c13"}"#)],
            merge_push(r#"{"c13":null}"#),
            "null",
        ),
        // Cancelling removes what was registered at and below the path.
        (
            "e4",
            vec![],
            vec![
                ("o", r#"{"p":"/c4/a","d":1}"#),
                ("o", r#"{"p":"/c4/b/c","d":2}"#),
                ("o", r#"{"p":"/c5","d":3}"#),
                ("oc", r#"{"p":"/c4"}"#),
            ],
            merge_push(r#"{"c5":3}"#),
            r#"{"c5":3}"#,
        ),
        // A later write replaces an earlier one at or below its path; a write below an
        // earlier one changes it.
        (
            "e5",
            vec![],
            vec![
                ("o", r#"{"p":"/c7","d":{"a":1}}"#),
                ("o", r#"{"p":"/c7/a","d":2}"#),
                ("o", r#"{"p":"/c7","d":{"b":3}}"#),
                ("o", r#"{"p":"/c8/a","d":2}"#),
                ("o", r#"{"p":"/c8","d":{"b":3}}"#),
                ("om", r#"{"p":"/c25","d":{"a":1}}"#),
                ("o", r#"{"p":"/c25","d":{"b":2}}"#),
                ("om", r#"{"p":"/c25","d":{"c":3}}"#),
                ("o", r#"{"p":"/c26","d":5}"#),
                ("om", r#"{"p":"/c26","d":{"c":3}}"#),
            ],
            // Four children come out in the order they were registered (probed again on the jar,
            // 2026-10-27, with these frames and a listener at the root; production-5 agrees on a
            // six-key set): not in key order.
            merge_push(r#"{"c7":{"b":3},"c8":{"b":3},"c25":{"b":2,"c":3},"c26":{"c":3}}"#),
            r#"{"c25":{"b":2,"c":3},"c26":{"c":3},"c7":{"b":3},"c8":{"b":3}}"#,
        ),
        // Cancelling below a registered value splits it into its children; below a leaf it
        // changes nothing.
        (
            "e6",
            vec![],
            vec![
                ("o", r#"{"p":"/c6","d":{"a":1}}"#),
                ("oc", r#"{"p":"/c6/a"}"#),
                ("o", r#"{"p":"/c30","d":5}"#),
                ("oc", r#"{"p":"/c30/x"}"#),
                ("o", r#"{"p":"/c31","d":{"a":{"b":1,"c":2},"d":3}}"#),
                ("oc", r#"{"p":"/c31/a/b"}"#),
                // A value replaces what was registered below it, for good.
                ("o", r#"{"p":"/p/a","d":1}"#),
                ("o", r#"{"p":"/p","d":{"b":2}}"#),
                ("oc", r#"{"p":"/p/b"}"#),
            ],
            merge_push(r#"{"c30":5,"c31/a/c":2,"c31/d":3}"#),
            r#"{"c30":5,"c31":{"a":{"c":2},"d":3}}"#,
        ),
        (
            "e7",
            vec![("/c16", r#"{"a":1,"b":2}"#)],
            vec![
                ("om", r#"{"p":"/c16","d":{"a":null}}"#),
                ("om", r#"{"p":"/c32","d":{"x/y":1,"z":{"w":2}}}"#),
            ],
            merge_push(r#"{"c16/a":null,"c32/x/y":1,"c32/z":{"w":2}}"#),
            r#"{"c16":{"b":2},"c32":{"x":{"y":1},"z":{"w":2}}}"#,
        ),
        // Priorities: on a value, on an existing node, kept when a leaf becomes a parent.
        (
            "e8",
            vec![("/c21", "1")],
            vec![
                ("o", r#"{"p":"/c10","d":{".value":1,".priority":7}}"#),
                ("o", r#"{"p":"/c21/.priority","d":3}"#),
                ("o", r#"{"p":"/c33","d":{".value":5,".priority":2}}"#),
                ("om", r#"{"p":"/c33","d":{"c":3}}"#),
            ],
            merge_push(
                r#"{"c10":{".value":1,".priority":7.0},"c21/.priority":3,"c33":{".priority":2.0,"c":3}}"#,
            ),
            r#"{"c10":{".value":1,".priority":7.0},"c21":{".value":1,".priority":3.0},"c33":{".priority":2.0,"c":3}}"#,
        ),
    ] {
        let (replies, pushes, stored) = run(ns, &writes, &frames);
        assert!(
            replies.iter().all(|r| r.contains(r#""s":"ok""#)),
            "{ns}: {replies:?}"
        );
        assert_eq!(pushes, vec![push], "{ns}");
        assert_eq!(stored, value, "{ns}");
    }
}

#[test]
fn server_values_resolve_when_the_connection_ends() {
    let (_, pushes, value) = run(
        "sv",
        &[],
        &[
            (
                "o",
                r#"{"p":"/c9","d":{"t":{".sv":"timestamp"},"n":{".sv":{"increment":2}}}}"#,
            ),
            ("p", r#"{"p":"/c9","d":{"n":5}}"#),
        ],
    );
    assert_eq!(
        pushes,
        vec![merge_push(&format!(r#"{{"c9":{{"n":7,"t":{LATER}}}}}"#))]
    );
    assert_eq!(value, format!(r#"{{"c9":{{"n":7,"t":{LATER}}}}}"#));
}

#[test]
fn a_registered_write_replaces_what_was_written_since() {
    let (_, pushes, value) = run(
        "ow",
        &[],
        &[
            ("o", r#"{"p":"/c15","d":"gone"}"#),
            ("p", r#"{"p":"/c15","d":"live"}"#),
        ],
    );
    assert_eq!(pushes, vec![merge_push(r#"{"c15":"gone"}"#)]);
    assert_eq!(value, r#"{"c15":"gone"}"#);
}

#[test]
fn a_value_at_the_root_is_written_as_a_put() {
    let (_, pushes, value) = run("rt", &[("/k", "1")], &[("o", r#"{"p":"/","d":{"r":1}}"#)]);
    assert_eq!(
        pushes,
        vec![r#"{"t":"d","d":{"b":{"p":"","d":{"r":1}},"a":"d"}}"#.to_owned()]
    );
    assert_eq!(value, r#"{"r":1}"#);
}

#[test]
fn an_update_that_fails_writes_nothing_at_all() {
    // A priority for a node that is not there fails the whole update.
    let (replies, pushes, value) = run(
        "fb",
        &[],
        &[
            ("o", r#"{"p":"/c27","d":1}"#),
            ("o", r#"{"p":"/c28/.priority","d":3}"#),
        ],
    );
    assert_eq!(replies, vec![ok(1), ok(2)]);
    assert!(pushes.is_empty());
    assert_eq!(value, "null");
}

#[test]
fn a_priority_registered_for_a_prioritized_leaf_changes_only_its_priority() {
    let (_, pushes, value) = run(
        "pl",
        &[],
        &[
            ("o", r#"{"p":"/m","d":{".value":5,".priority":2}}"#),
            ("o", r#"{"p":"/m/.priority","d":3}"#),
            ("o", r#"{"p":"/n","d":{".value":5,".priority":2}}"#),
            ("o", r#"{"p":"/n/.priority","d":null}"#),
        ],
    );
    assert_eq!(
        pushes,
        vec![merge_push(r#"{"m":{".value":5,".priority":3.0},"n":5}"#)]
    );
    assert_eq!(value, r#"{"m":{".value":5,".priority":3.0},"n":5}"#);
}

#[test]
fn a_priority_is_checked_only_when_the_connection_ends() {
    // An object is no priority: registering it is answered ok, and the update it joins
    // fails whole when the connection ends.
    let (replies, pushes, value) = run(
        "bp",
        &[("/c40", "1")],
        &[
            ("o", r#"{"p":"/c40/.priority","d":{"a":1}}"#),
            ("o", r#"{"p":"/c22","d":1}"#),
        ],
    );
    assert_eq!(replies, vec![ok(1), ok(2)]);
    assert!(pushes.is_empty());
    assert_eq!(value, r#"{"c40":1}"#);
}

#[test]
fn a_priority_with_a_key_that_cannot_be_read_is_a_connection_error() {
    let mut db = Database::new(RestOptions::default(), 1);
    let mut session = open(&mut db, "bk");
    let replies = send(
        &mut db,
        &mut session,
        &request(1, "o", r#"{"p":"/c40/.priority","d":{"a.b":1}}"#),
    );
    assert_eq!(replies.len(), 1);
    assert!(
        replies[0].starts_with(r#"{"t":"c","d":{"t":"e""#),
        "{replies:?}"
    );
    assert_eq!(
        send(
            &mut db,
            &mut session,
            &request(2, "o", r#"{"p":"/c22","d":1}"#)
        ),
        vec![ok(2)]
    );
    db.close_realtime(session.client(), LATER);
    assert_eq!(rest(&mut db, "GET", "/.json?ns=bk", ""), r#"{"c22":1}"#);
}

#[test]
fn a_request_without_a_path_keeps_the_connection() {
    let mut db = Database::new(RestOptions::default(), 1);
    let mut session = open(&mut db, "np");
    for frame in [request(1, "o", r#"{"d":1}"#), request(2, "oc", "{}")] {
        let received = session.receive(&mut db, &frame, NOW);
        assert!(received.replies.is_empty());
        assert!(!received.drop_connection, "{frame}");
        assert!(received.close.is_none(), "{frame}");
    }
}

#[test]
fn operations_run_once_and_the_ending_connection_receives_nothing() {
    let mut db = Database::new(RestOptions::default(), 1);
    let mut session = open(&mut db, "once");
    send(
        &mut db,
        &mut session,
        &request(1, "q", r#"{"p":"/","h":""}"#),
    );
    send(
        &mut db,
        &mut session,
        &request(2, "o", r#"{"p":"/a","d":1}"#),
    );
    db.drain_pushes();
    db.close_realtime(session.client(), LATER);
    assert!(db.drain_pushes().is_empty());
    assert_eq!(rest(&mut db, "GET", "/.json?ns=once", ""), r#"{"a":1}"#);
    rest(&mut db, "DELETE", "/a.json?ns=once", "");
    db.close_realtime(session.client(), LATER);
    assert_eq!(rest(&mut db, "GET", "/.json?ns=once", ""), "null");
}

#[test]
fn a_connection_end_wakes_the_server_and_reaches_event_streams() {
    let mut db = Database::new(RestOptions::default(), 1);
    let woken = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&woken);
    db.set_waker(std::sync::Arc::new(move || {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }));
    let stream = HttpRequest {
        method: "GET".to_owned(),
        target: "/s.json?ns=wk".to_owned(),
        headers: vec![("Accept".to_owned(), "text/event-stream".to_owned())],
        body: Vec::new(),
    };
    let Handled::Stream { id, .. } = db.handle(&stream, NOW) else {
        panic!("no stream")
    };
    let mut quiet = open(&mut db, "wk");
    db.close_realtime(quiet.client(), LATER);
    assert_eq!(
        woken.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing to write"
    );
    let _ = &mut quiet;
    let mut session = open(&mut db, "wk");
    send(
        &mut db,
        &mut session,
        &request(1, "o", r#"{"p":"/s/a","d":1}"#),
    );
    db.close_realtime(session.client(), LATER);
    assert_eq!(woken.load(std::sync::atomic::Ordering::SeqCst), 1);
    let events = db.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, id);
    assert_eq!(events[0].1.data, r#"{"path":"/","data":{"a":1}}"#);
}

#[test]
fn under_deny_all_only_the_owner_registers() {
    // Registering is a write, so it is refused where a write is (owner decision Q4). A
    // cancel (`oc`) is not checked: the official emulator answers it under rules that refuse
    // every write (`.write: false`), and the locked default is those rules.
    let mut db = Database::new(
        RestOptions {
            rules: RulesMode::DenyAll,
            ..RestOptions::default()
        },
        1,
    );
    let mut anonymous = open(&mut db, "deny");
    for (r, (action, body)) in (1..).zip([
        ("o", r#"{"p":"/a","d":1}"#),
        ("om", r#"{"p":"/a","d":{"b":1}}"#),
    ]) {
        assert_eq!(
            send(&mut db, &mut anonymous, &request(r, action, body)),
            vec![reply(r, "permission_denied", r#""Permission denied""#)],
            "{action}"
        );
    }
    assert_eq!(
        send(&mut db, &mut anonymous, &request(3, "oc", r#"{"p":"/a"}"#)),
        vec![ok(3)]
    );
    db.close_realtime(anonymous.client(), LATER);
    let mut owner = open(&mut db, "deny");
    send(
        &mut db,
        &mut owner,
        &request(1, "gauth", r#"{"cred":"owner"}"#),
    );
    assert_eq!(
        send(&mut db, &mut owner, &request(2, "o", r#"{"p":"/a","d":1}"#)),
        vec![ok(2)]
    );
    db.close_realtime(owner.client(), LATER);
    let read = HttpRequest {
        method: "GET".to_owned(),
        target: "/.json?ns=deny".to_owned(),
        headers: vec![("Authorization".to_owned(), "Bearer owner".to_owned())],
        body: Vec::new(),
    };
    let Handled::Response { response, .. } = db.handle(&read, NOW) else {
        panic!()
    };
    assert_eq!(String::from_utf8(response.body).unwrap(), r#"{"a":1}"#);
}

#[test]
fn a_session_reset_drops_the_registrations_of_the_namespaces_it_clears() {
    // A connection from the previous test must not write into the new session.
    let mut db = Database::new(RestOptions::default(), 1);
    let mut cleared = open(&mut db, "demo-default-rtdb");
    let mut kept = open(&mut db, "other");
    send(
        &mut db,
        &mut cleared,
        &request(1, "o", r#"{"p":"/a","d":1}"#),
    );
    send(&mut db, &mut kept, &request(1, "o", r#"{"p":"/b","d":2}"#));
    db.clear_namespaces_where(|ns| fireemu_adapter_database::namespace::project_of(ns) == "demo");
    db.drain_events();
    db.close_realtime(cleared.client(), LATER);
    db.close_realtime(kept.client(), LATER);
    assert_eq!(
        rest(&mut db, "GET", "/.json?ns=demo-default-rtdb", ""),
        "null"
    );
    assert!(db.drain_events().is_empty());
    assert_eq!(rest(&mut db, "GET", "/.json?ns=other", ""), r#"{"b":2}"#);
}

#[test]
fn a_snapshot_restore_drops_the_registrations_of_the_namespaces_it_restores() {
    // As a reset does: a connection from before the restore never writes into it when it ends.
    let mut db = Database::new(RestOptions::default(), 1);
    let owned = |ns: &str| fireemu_adapter_database::namespace::project_of(ns) == "demo";
    let snapshot = db.capture_namespaces_where(owned);
    let mut restored = open(&mut db, "demo-default-rtdb");
    let mut kept = open(&mut db, "other");
    send(
        &mut db,
        &mut restored,
        &request(1, "o", r#"{"p":"/a","d":1}"#),
    );
    send(&mut db, &mut kept, &request(1, "o", r#"{"p":"/b","d":2}"#));
    db.restore_namespaces_where(owned, &snapshot);
    db.drain_events();
    db.close_realtime(restored.client(), LATER);
    db.close_realtime(kept.client(), LATER);
    assert_eq!(
        rest(&mut db, "GET", "/.json?ns=demo-default-rtdb", ""),
        "null"
    );
    assert!(db.drain_events().is_empty());
    assert_eq!(rest(&mut db, "GET", "/.json?ns=other", ""), r#"{"b":2}"#);
}
