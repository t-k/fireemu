//! A change sink is asked whether a write can reach a trigger before any capture work (review
//! S3, 2026-10-25): a write the sink does not watch is applied in place, with no candidate
//! tree, no snapshot comparison and no reservation.

use std::sync::{Arc, Mutex};

use fireemu_adapter_database::changes::{
    ChangeData, ChangeSink, CommittedChange, Path, Publication, Tree,
};
use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, RestOptions};
use fireemu_core_types::admission::EventAdmissionError;

/// Watches `/watched` and everything below it.
#[derive(Debug, Default)]
struct Watching {
    asked: Mutex<Vec<String>>,
    captured: Mutex<Vec<String>>,
    reserved: Mutex<Vec<CommittedChange>>,
}

struct Nothing;
impl Publication for Nothing {
    fn publish(self: Box<Self>) {}
}

fn watched(path: &Path) -> bool {
    path.keys().first().is_none_or(|key| key == "watched")
}

impl ChangeSink for Watching {
    fn affects(&self, _namespace: &str, scope: &Path) -> bool {
        self.asked.lock().unwrap().push(scope.to_string());
        watched(scope)
    }

    fn capture_references_within(
        &self,
        _namespace: &str,
        _before: &Tree,
        _after: &Tree,
        scope: &Path,
    ) -> Result<Option<Vec<Path>>, EventAdmissionError> {
        self.captured.lock().unwrap().push(scope.to_string());
        Ok(Some(vec![Path::from_keys(["watched"])]))
    }

    fn reserve(
        &self,
        change: &CommittedChange,
    ) -> Result<Box<dyn Publication>, EventAdmissionError> {
        self.reserved.lock().unwrap().push(change.clone());
        Ok(Box::new(Nothing))
    }
}

fn call(db: &mut Database, method: &str, target: &str, body: &str) -> u16 {
    let request = HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
    };
    match db.handle(&request, 1234) {
        Handled::Response { response, .. } => response.status,
        Handled::Stream { .. } => panic!("unexpected stream"),
    }
}

#[test]
fn unwatched_writes_skip_capture_and_watched_writes_capture_within_their_path() {
    let mut db = Database::new(RestOptions::default(), 42);
    let sink = Arc::new(Watching::default());
    db.set_change_sink(sink.clone());
    assert_eq!(call(&mut db, "PUT", "/other/a.json?ns=ns", "1"), 200);
    assert_eq!(
        call(&mut db, "PATCH", "/other.json?ns=ns", r#"{"b":2}"#),
        200
    );
    assert_eq!(
        call(&mut db, "PUT", "/other/.priority.json?ns=ns", "5"),
        200
    );
    assert_eq!(call(&mut db, "DELETE", "/other/a.json?ns=ns", ""), 200);
    assert!(sink.captured.lock().unwrap().is_empty());
    assert!(sink.reserved.lock().unwrap().is_empty());
    assert_eq!(
        *sink.asked.lock().unwrap(),
        ["/other/a", "/other", "/other", "/other/a"],
        "a priority write is scoped to the node whose priority it sets"
    );
    assert_eq!(call(&mut db, "PUT", "/watched/x.json?ns=ns", "1"), 200);
    assert_eq!(call(&mut db, "PUT", "/watched/x.json?ns=ns", "1"), 200);
    assert_eq!(*sink.captured.lock().unwrap(), ["/watched/x"]);
    let reserved = sink.reserved.lock().unwrap();
    assert_eq!(reserved.len(), 1, "an unchanged write reserves nothing");
    let ChangeData::References(references) = &reserved[0].data else {
        panic!("references")
    };
    assert_eq!(references[0].after, serde_json::json!({"x": 1}));
    drop(reserved);
    let tree = db.tree("ns").unwrap();
    assert!(tree.get(&Path::from_keys(["watched", "x"])).is_some());
    assert!(tree.get(&Path::from_keys(["other", "b"])).is_some());
    assert!(tree.get(&Path::from_keys(["other", "a"])).is_none());
    assert!(tree
        .get(&Path::from_keys(["other"]))
        .is_some_and(|node| node.priority.is_some()));
}
