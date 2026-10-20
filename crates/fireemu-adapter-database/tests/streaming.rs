//! Event streams (`Accept: text/event-stream`). The expected events are what the official
//! emulator (firebase-database-emulator v4.11.2) streamed for the same writes, except where a
//! test says otherwise.

use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions, SseEvent};

const NOW: i64 = 1_792_408_594_894;

fn request(method: &str, target: &str, accept_stream: bool, body: &str) -> HttpRequest {
    let headers = if accept_stream {
        vec![("Accept".to_owned(), "text/event-stream".to_owned())]
    } else {
        Vec::new()
    };
    HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        headers,
        body: body.as_bytes().to_vec(),
    }
}

fn open(db: &mut Database, target: &str) -> (u64, SseEvent) {
    match db.handle(&request("GET", target, true, ""), NOW) {
        Handled::Stream {
            id,
            response,
            initial,
        } => {
            assert_eq!(response.status, 200);
            assert!(response
                .headers
                .iter()
                .any(|(k, v)| k == "Content-Type" && v == "text/event-stream; charset=utf-8"));
            (id, initial)
        }
        Handled::Response { response, .. } => panic!("no stream: {response:?}"),
    }
}

fn write(db: &mut Database, method: &str, target: &str, body: &str) -> Vec<(u64, SseEvent)> {
    match db.handle(&request(method, target, false, body), NOW) {
        Handled::Response { response, events } => {
            assert!(response.status < 300, "{method} {target}: {response:?}");
            events
        }
        Handled::Stream { .. } => panic!("unexpected stream"),
    }
}

fn put(path: &str, data: &str) -> SseEvent {
    SseEvent {
        event: "put".to_owned(),
        data: format!("{{\"path\":\"{path}\",\"data\":{data}}}"),
    }
}

#[test]
fn a_stream_starts_with_the_value_and_follows_changes_below_it() {
    let mut db = Database::new(RestOptions::default(), 1);
    write(&mut db, "PUT", "/s.json?ns=e1", r#"{"a":{"b":1},"c":2}"#);
    let (id, initial) = open(&mut db, "/s.json?ns=e1");
    assert_eq!(initial, put("/", r#"{"a":{"b":1},"c":2}"#));
    assert_eq!(
        initial.to_text(),
        "event: put\ndata: {\"path\":\"/\",\"data\":{\"a\":{\"b\":1},\"c\":2}}\n\n"
    );

    assert_eq!(
        write(&mut db, "PUT", "/s/a/b.json?ns=e1", "5"),
        vec![(id, put("/a/b", "5"))]
    );
    assert_eq!(
        write(&mut db, "PATCH", "/s.json?ns=e1", r#"{"c":3,"a/d":4}"#),
        vec![(
            id,
            SseEvent {
                event: "patch".to_owned(),
                data: r#"{"path":"/","data":{"a/d":4,"c":3}}"#.to_owned(),
            }
        )]
    );
    // Writing the value it already has sends nothing.
    assert!(write(&mut db, "PUT", "/s/a/b.json?ns=e1", "5").is_empty());
    // Not observed: the official emulator dropped this event when it came within a few
    // milliseconds of the next one; every change is sent here.
    assert_eq!(
        write(&mut db, "PUT", "/.json?ns=e1", r#"{"s":{"x":1}}"#),
        vec![(id, put("/", r#"{"x":1}"#))]
    );
    assert_eq!(
        write(&mut db, "DELETE", "/s.json?ns=e1", ""),
        vec![(id, put("/", "null"))]
    );
    let events = write(
        &mut db,
        "POST",
        "/s.json?ns=e1",
        r#"{"p":{".sv":"timestamp"}}"#,
    );
    assert_eq!(events.len(), 1);
    assert!(
        events[0].1.data.starts_with("{\"path\":\"/-"),
        "{:?}",
        events[0]
    );
    assert!(events[0]
        .1
        .data
        .ends_with(&format!("\"data\":{{\"p\":{NOW}}}}}")));
    assert!(write(&mut db, "PUT", "/other.json?ns=e1", "1").is_empty());
    assert!(write(&mut db, "PUT", "/s.json?ns=e2", "1").is_empty());
}

#[test]
fn a_query_stream_follows_its_window() {
    let mut db = Database::new(RestOptions::default(), 1);
    write(&mut db, "PUT", "/s.json?ns=e1", r#"{"a":{"b":1},"c":2}"#);
    let (id, initial) = open(&mut db, "/s/a.json?ns=e1&orderBy=\"$key\"&limitToFirst=1");
    assert_eq!(initial, put("/", r#"{"b":1}"#));
    assert_eq!(
        write(&mut db, "PUT", "/s/a/b.json?ns=e1", "5"),
        vec![(id, put("/b", "5"))]
    );
    // A child outside the window changes nothing the stream shows.
    assert!(write(&mut db, "PATCH", "/s.json?ns=e1", r#"{"c":3,"a/d":4}"#).is_empty());
    assert_eq!(
        write(&mut db, "PUT", "/.json?ns=e1", r#"{"s":{"x":1}}"#),
        vec![(id, put("/", "null"))]
    );
    // Not observed: a child that enters the window resends the window.
    assert_eq!(
        write(&mut db, "PUT", "/s/a/a.json?ns=e1", "0"),
        vec![(id, put("/", r#"{"a":0}"#))]
    );
}

#[test]
fn closed_streams_receive_nothing() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (id, initial) = open(&mut db, "/s.json?ns=e1");
    assert_eq!(initial, put("/", "null"));
    assert_eq!(db.subscription_count(), 1);
    db.unsubscribe(id);
    assert_eq!(db.subscription_count(), 0);
    assert!(write(&mut db, "PUT", "/s.json?ns=e1", "1").is_empty());
}

#[test]
fn invalid_stream_requests_are_refused_like_reads() {
    let mut db = Database::new(RestOptions::default(), 1);
    match db.handle(
        &request("GET", "/s.json?ns=e1&orderBy=\"h\"", true, ""),
        NOW,
    ) {
        Handled::Response { response, .. } => assert_eq!(response.status, 400),
        Handled::Stream { .. } => panic!("a query without an index must not stream"),
    }
    assert_eq!(db.subscription_count(), 0);
}

#[test]
fn keep_alive_events_carry_null() {
    assert_eq!(
        SseEvent::keep_alive().to_text(),
        "event: keep-alive\ndata: null\n\n"
    );
}

#[test]
fn every_stream_gets_its_own_id() {
    let mut db = Database::new(RestOptions::default(), 1);
    let (first, _) = open(&mut db, "/s.json?ns=e1");
    let (second, _) = open(&mut db, "/s.json?ns=e1");
    assert_ne!(first, second);
    let events = write(&mut db, "PUT", "/s.json?ns=e1", "1");
    assert_eq!(
        events,
        vec![(first, put("/", "1")), (second, put("/", "1"))]
    );
}

#[test]
fn a_child_entering_a_query_window_resends_the_window() {
    let mut db = Database::new(RestOptions::default(), 1);
    write(&mut db, "PUT", "/s.json?ns=e1", r#"{"b":1,"c":2}"#);
    let (id, initial) = open(&mut db, "/s.json?ns=e1&orderBy=\"$key\"&limitToFirst=1");
    assert_eq!(initial, put("/", r#"{"b":1}"#));
    assert_eq!(
        write(&mut db, "PUT", "/s/a.json?ns=e1", "0"),
        vec![(id, put("/", r#"{"a":0}"#))]
    );
    assert_eq!(
        write(&mut db, "PUT", "/s/a.json?ns=e1", "5"),
        vec![(id, put("/a", "5"))]
    );
    // A multipath write to a query stream resends the window.
    assert_eq!(
        write(&mut db, "PATCH", "/s.json?ns=e1", r#"{"a":6,"c":3}"#),
        vec![(id, put("/", r#"{"a":6}"#))]
    );
}

#[test]
fn a_multipath_write_above_a_stream_sends_the_entries_inside_it() {
    let mut db = Database::new(RestOptions::default(), 1);
    write(&mut db, "PUT", "/s.json?ns=e1", r#"{"a":{"b":1,"x":0}}"#);
    let (id, _) = open(&mut db, "/s/a.json?ns=e1");
    for (body, data) in [
        (r#"{"a/b":2,"c":3}"#, r#"{"b":2}"#),
        (r#"{"a/b":3}"#, r#"{"b":3}"#),
        (r#"{"a/b":4,"a/x":5}"#, r#"{"b":4,"x":5}"#),
        (r#"{"a/b":4,"a/x":6,"c":1}"#, r#"{"x":6}"#),
        (r#"{"a/b/q":1,"c":2}"#, r#"{"b/q":1}"#),
    ] {
        assert_eq!(
            write(&mut db, "PATCH", "/s.json?ns=e1", body),
            vec![(
                id,
                SseEvent {
                    event: "patch".to_owned(),
                    data: format!("{{\"path\":\"/\",\"data\":{data}}}"),
                }
            )],
            "{body}"
        );
    }
}

#[test]
fn a_priority_in_a_patch_event_carries_its_value() {
    let mut db = Database::new(RestOptions::default(), 1);
    write(&mut db, "PUT", "/a.json?ns=e3", "1");
    let (id, _) = open(&mut db, "/.json?ns=e3&format=export");
    assert_eq!(
        write(&mut db, "PATCH", "/.json?ns=e3", r#"{"a/.priority":3}"#),
        vec![(
            id,
            SseEvent {
                event: "patch".to_owned(),
                data: r#"{"path":"/","data":{"a/.priority":3}}"#.to_owned(),
            }
        )]
    );
}

#[test]
fn a_write_of_an_equal_number_is_no_write() {
    // The official emulator keeps 1 when 1.0 is written over it and sends no event; -0.0
    // over 1 is a change, and 0 over -0.0 is not.
    let mut db = Database::new(RestOptions::default(), 1);
    write(&mut db, "PUT", "/s.json?ns=e9", "1");
    let (id, _) = open(&mut db, "/s.json?ns=e9");
    assert!(write(&mut db, "PUT", "/s.json?ns=e9", "1.0").is_empty());
    assert_eq!(
        write(&mut db, "PUT", "/s.json?ns=e9", "-0.0"),
        vec![(id, put("/", "-0.0"))]
    );
    assert!(write(&mut db, "PUT", "/s.json?ns=e9", "0").is_empty());
    let read = db.handle(&request("GET", "/s.json?ns=e9", false, ""), 0);
    match read {
        fireemu_adapter_database::rest::Handled::Response { response, .. } => {
            assert_eq!(String::from_utf8(response.body).unwrap(), "-0.0");
        }
        fireemu_adapter_database::rest::Handled::Stream { .. } => panic!("stream"),
    }
}

fn patch(path: &str, data: &str) -> SseEvent {
    SseEvent {
        event: "patch".to_owned(),
        data: format!("{{\"path\":\"{path}\",\"data\":{data}}}"),
    }
}

#[test]
fn a_stream_sees_a_number_change_its_form_inside_a_larger_write() {
    let mut db = Database::new(RestOptions::default(), 1);
    write(&mut db, "PUT", "/s.json?ns=f1", r#"{"a":1,"b":2}"#);
    let (a, _) = open(&mut db, "/s/a.json?ns=f1");
    let (s, _) = open(&mut db, "/s.json?ns=f1");
    // b changes, so the node is rewritten and a is stored as written: 1.0.
    assert_eq!(
        write(&mut db, "PUT", "/s.json?ns=f1", r#"{"a":1.0,"b":3}"#),
        vec![(a, put("/", "1.0")), (s, put("/", r#"{"a":1.0,"b":3}"#))]
    );
    // Equal writes keep the stored form and send nothing.
    assert!(write(&mut db, "PUT", "/s.json?ns=f1", r#"{"a":1.0,"b":3}"#).is_empty());
    assert!(write(&mut db, "PUT", "/s/a.json?ns=f1", "1").is_empty());
    assert_eq!(
        write(&mut db, "PATCH", "/s.json?ns=f1", r#"{"a":1,"b":4}"#),
        vec![(s, patch("/", r#"{"b":4}"#))]
    );
    assert_eq!(
        write(&mut db, "PUT", "/s.json?ns=f1", r#"{"a":2.0,"b":4}"#),
        vec![(a, put("/", "2.0")), (s, put("/", r#"{"a":2.0,"b":4}"#))]
    );
}

#[test]
fn a_patch_event_lists_only_the_entries_that_changed() {
    let mut db = Database::new(RestOptions::default(), 1);
    write(
        &mut db,
        "PUT",
        "/s.json?ns=f2",
        r#"{"a":1,"b":3,"c":{"x":1}}"#,
    );
    let (s, _) = open(&mut db, "/s.json?ns=f2");
    for (body, expected) in [
        (r#"{"a":5,"b":3}"#, Some(r#"{"a":5}"#)),
        // A null entry always counts, even where nothing was.
        (r#"{"zz":null}"#, Some(r#"{"zz":null}"#)),
        (r#"{"a":6,"zz":null}"#, Some(r#"{"a":6,"zz":null}"#)),
        (r#"{"c/x":1.0,"b":4}"#, Some(r#"{"b":4}"#)),
        (r#"{"c":{"x":1.0}}"#, None),
        (r#"{"c":{"x":1,"y":2}}"#, Some(r#"{"c":{"x":1,"y":2}}"#)),
        (r#"{"a":6,"b":4}"#, None),
        (r#"{"a":{".sv":{"increment":0}},"b":7}"#, Some(r#"{"b":7}"#)),
        (r#"{"b/.priority":3}"#, Some(r#"{"b/.priority":3}"#)),
        (r#"{"b/.priority":3,"a":8}"#, Some(r#"{"a":8}"#)),
    ] {
        let events = write(&mut db, "PATCH", "/s.json?ns=f2", body);
        let expected: Vec<(u64, SseEvent)> = expected
            .map(|data| (s, patch("/", data)))
            .into_iter()
            .collect();
        assert_eq!(events, expected, "{body}");
    }
}

#[test]
fn a_patch_above_a_stream_sends_the_entries_inside_it() {
    let mut db = Database::new(RestOptions::default(), 1);
    write(&mut db, "PUT", "/s.json?ns=f3", r#"{"a":1}"#);
    let (s, _) = open(&mut db, "/s.json?ns=f3");
    let (c, _) = open(&mut db, "/s/c.json?ns=f3");
    // A null write always counts, as for the realtime listens.
    assert_eq!(
        write(&mut db, "PUT", "/s/zz.json?ns=f3", "null"),
        vec![(s, put("/zz", "null"))]
    );
    assert_eq!(
        write(&mut db, "DELETE", "/s/zz.json?ns=f3", ""),
        vec![(s, put("/zz", "null"))]
    );
    assert_eq!(
        write(&mut db, "PATCH", "/.json?ns=f3", r#"{"s/c/zz":null}"#),
        vec![
            (s, patch("/", r#"{"c/zz":null}"#)),
            (c, patch("/", r#"{"zz":null}"#))
        ]
    );
    assert!(write(&mut db, "PATCH", "/.json?ns=f3", r#"{"s/a":1}"#).is_empty());
    assert_eq!(
        write(&mut db, "PATCH", "/.json?ns=f3", r#"{"s/a":2,"q":1}"#),
        vec![(s, patch("/", r#"{"a":2}"#))]
    );
}

#[test]
fn a_patch_entry_at_or_above_a_stream_sends_its_whole_value() {
    let mut db = Database::new(RestOptions::default(), 1);
    write(&mut db, "PUT", "/s.json?ns=f4", r#"{"a":1,"c":{"x":1}}"#);
    let (c, _) = open(&mut db, "/s/c.json?ns=f4");
    for (body, expected) in [
        (r#"{"s/c":{"k":1}}"#, put("/", r#"{"k":1}"#)),
        (r#"{"s":{"c":{"k":2},"a":1}}"#, put("/", r#"{"k":2}"#)),
        (
            r#"{"s/c/k":3,"s/c/m":4,"s/a":5}"#,
            patch("/", r#"{"k":3,"m":4}"#),
        ),
        (r#"{"s/c/k":3,"s/c/m":5}"#, patch("/", r#"{"m":5}"#)),
        (
            r#"{"s/c/k":null,"s/c/m":null}"#,
            patch("/", r#"{"k":null,"m":null}"#),
        ),
    ] {
        assert_eq!(
            write(&mut db, "PATCH", "/.json?ns=f4", body),
            vec![(c, expected)],
            "{body}"
        );
    }
}

#[test]
fn a_reset_queues_the_emptied_value_for_streams_until_drained() {
    let mut db = Database::new(RestOptions::default(), 1);
    write(&mut db, "PUT", "/s.json?ns=f6", r#"{"a":1}"#);
    let (id, _) = open(&mut db, "/s.json?ns=f6");
    db.clear_namespaces_where(|ns| ns == "f6");
    assert_eq!(db.drain_events(), vec![(id, put("/", "null"))]);
    assert!(db.drain_events().is_empty());
}

#[test]
fn a_null_write_beside_a_full_limit_window_sends_nothing() {
    // The official emulator sends nothing to a full limit window for null written to an
    // absent child. (It sends the null to a range window whose range holds the key; this
    // server does not, see the module notes of rest.rs.)
    let mut db = Database::new(RestOptions::default(), 1);
    write(&mut db, "PUT", "/q.json?ns=f5", r#"{"a":1,"b":2,"c":3}"#);
    let (_, initial) = open(&mut db, "/q.json?ns=f5&orderBy=%22%24key%22&limitToFirst=2");
    assert_eq!(initial, put("/", r#"{"a":1,"b":2}"#));
    assert!(write(&mut db, "PUT", "/q/zz.json?ns=f5", "null").is_empty());
    assert!(write(&mut db, "PUT", "/q/a0.json?ns=f5", "null").is_empty());
}
