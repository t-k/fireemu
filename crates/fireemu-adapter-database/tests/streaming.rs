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
fn a_multipath_write_above_a_stream_resends_its_value() {
    let mut db = Database::new(RestOptions::default(), 1);
    write(&mut db, "PUT", "/s.json?ns=e1", r#"{"a":{"b":1}}"#);
    let (id, _) = open(&mut db, "/s/a.json?ns=e1");
    assert_eq!(
        write(&mut db, "PATCH", "/s.json?ns=e1", r#"{"a/b":2,"c":3}"#),
        vec![(id, put("/", r#"{"b":2}"#))]
    );
}
