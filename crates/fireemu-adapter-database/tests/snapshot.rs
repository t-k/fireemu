//! Session snapshots of the namespaces a session owns: what a capture holds, what a restore
//! puts back, and what open streams see. The official emulator has no snapshots; these follow
//! fireemu's session model (a restore behaves like a reset followed by an import).

use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions, SseEvent};
use proptest::prelude::*;

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

fn open(db: &mut Database, target: &str) -> u64 {
    match db.handle(&request("GET", target, true, ""), NOW) {
        Handled::Stream { id, .. } => id,
        Handled::Response { response, .. } => panic!("no stream: {response:?}"),
    }
}

fn put_value(db: &mut Database, ns: &str, body: &str) {
    match db.handle(
        &request("PUT", &format!("/.json?ns={ns}"), false, body),
        NOW,
    ) {
        Handled::Response { response, .. } => assert_eq!(response.status, 200, "{response:?}"),
        Handled::Stream { .. } => panic!("unexpected stream"),
    }
}

fn get_value(db: &mut Database, ns: &str) -> String {
    match db.handle(&request("GET", &format!("/.json?ns={ns}"), false, ""), NOW) {
        Handled::Response { response, .. } => String::from_utf8(response.body).unwrap(),
        Handled::Stream { .. } => panic!("unexpected stream"),
    }
}

fn put(path: &str, data: &str) -> SseEvent {
    SseEvent {
        event: "put".to_owned(),
        data: format!("{{\"path\":\"{path}\",\"data\":{data}}}"),
    }
}

fn owned_by_p(ns: &str) -> bool {
    ns == "p" || ns == "p-default-rtdb"
}

#[test]
fn a_restore_puts_back_the_owned_namespaces_and_leaves_the_others() {
    let mut db = Database::new(RestOptions::default(), 1);
    put_value(&mut db, "p-default-rtdb", r#"{"a":1}"#);
    put_value(&mut db, "q", r#"{"b":2}"#);
    let snapshot = db.capture_namespaces_where(owned_by_p);

    put_value(&mut db, "p-default-rtdb", r#"{"a":9}"#);
    put_value(&mut db, "p", r#"{"later":true}"#);
    put_value(&mut db, "q", r#"{"b":3}"#);
    db.restore_namespaces_where(owned_by_p, &snapshot);

    assert_eq!(get_value(&mut db, "p-default-rtdb"), r#"{"a":1}"#);
    assert_eq!(get_value(&mut db, "p"), "null");
    assert_eq!(get_value(&mut db, "q"), r#"{"b":3}"#);
}

#[test]
fn a_capture_holds_only_the_owned_namespaces() {
    let mut db = Database::new(RestOptions::default(), 1);
    put_value(&mut db, "p", r#"{"a":1}"#);
    put_value(&mut db, "q", r#"{"b":2}"#);
    let snapshot = db.capture_namespaces_where(owned_by_p);

    // Restoring it where every namespace is owned empties q: the capture never held it.
    db.restore_namespaces_where(|_| true, &snapshot);
    assert_eq!(get_value(&mut db, "p"), r#"{"a":1}"#);
    assert_eq!(get_value(&mut db, "q"), "null");
}

#[test]
fn a_restore_streams_the_restored_value_to_open_streams() {
    let mut db = Database::new(RestOptions::default(), 1);
    put_value(&mut db, "p", r#"{"s":{"a":1}}"#);
    let snapshot = db.capture_namespaces_where(owned_by_p);
    put_value(&mut db, "p", r#"{"s":{"a":2}}"#);
    let stream = open(&mut db, "/s.json?ns=p");
    let other = open(&mut db, "/s.json?ns=q");

    db.restore_namespaces_where(owned_by_p, &snapshot);
    assert_eq!(db.drain_events(), vec![(stream, put("/", r#"{"a":1}"#))]);
    let _ = other;
}

#[test]
fn an_imported_namespace_stays_exported_only_while_a_restore_says_so() {
    let mut db = Database::new(RestOptions::default(), 1);
    let empty = db.capture_namespaces_where(owned_by_p);
    db.import_text("p", "null", NOW).unwrap();
    let imported = db.capture_namespaces_where(owned_by_p);
    assert_eq!(db.export_texts(), vec![("p".to_owned(), "null".to_owned())]);

    db.restore_namespaces_where(owned_by_p, &empty);
    assert!(db.export_texts().is_empty());
    db.restore_namespaces_where(owned_by_p, &imported);
    assert_eq!(db.export_texts(), vec![("p".to_owned(), "null".to_owned())]);
}

#[test]
fn a_reset_forgets_that_a_namespace_was_imported() {
    let mut db = Database::new(RestOptions::default(), 1);
    db.import_text("p", "null", NOW).unwrap();
    db.import_text("q", "null", NOW).unwrap();
    db.clear_namespaces_where(owned_by_p);
    assert_eq!(db.export_texts(), vec![("q".to_owned(), "null".to_owned())]);
}

#[test]
fn the_retained_bytes_grow_with_the_captured_data() {
    let mut db = Database::new(RestOptions::default(), 1);
    let empty = db.capture_namespaces_where(owned_by_p).retained_bytes();
    put_value(
        &mut db,
        "p",
        &format!(r#"{{"a":"{}"}}"#, "x".repeat(10_000)),
    );
    let full = db.capture_namespaces_where(owned_by_p).retained_bytes();
    assert!(full >= empty + 10_000, "{empty} -> {full}");
    // A namespace the session does not own costs it nothing.
    put_value(
        &mut db,
        "q",
        &format!(r#"{{"a":"{}"}}"#, "x".repeat(10_000)),
    );
    assert_eq!(
        db.capture_namespaces_where(owned_by_p).retained_bytes(),
        full
    );
}

fn small_value() -> impl Strategy<Value = String> {
    prop::collection::btree_map("[a-c]", 0u8..4, 0..4).prop_map(|map| {
        if map.is_empty() {
            "null".to_owned()
        } else {
            let fields: Vec<String> = map.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
            format!("{{{}}}", fields.join(","))
        }
    })
}

proptest! {
    /// Whatever is written after a capture, restoring it gives back every owned namespace as
    /// captured and leaves every other namespace as it is now.
    #[test]
    fn a_restore_gives_back_the_capture_for_owned_namespaces_only(
        before in prop::collection::vec((0usize..4, small_value()), 0..6),
        after in prop::collection::vec((0usize..4, small_value()), 0..6),
    ) {
        const NAMES: [&str; 4] = ["p", "p-default-rtdb", "q", "q-default-rtdb"];
        let mut db = Database::new(RestOptions::default(), 1);
        for (i, value) in &before {
            put_value(&mut db, NAMES[*i], value);
        }
        let captured: Vec<String> = NAMES.iter().map(|ns| get_value(&mut db, ns)).collect();
        let snapshot = db.capture_namespaces_where(owned_by_p);
        for (i, value) in &after {
            put_value(&mut db, NAMES[*i], value);
        }
        let current: Vec<String> = NAMES.iter().map(|ns| get_value(&mut db, ns)).collect();
        db.restore_namespaces_where(owned_by_p, &snapshot);
        for (i, ns) in NAMES.iter().enumerate() {
            let expected = if owned_by_p(ns) { &captured[i] } else { &current[i] };
            prop_assert_eq!(&get_value(&mut db, ns), expected, "{}", ns);
        }
    }
}
