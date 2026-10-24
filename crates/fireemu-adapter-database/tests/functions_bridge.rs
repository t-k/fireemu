//! Committed source changes are coupled to admission, independently of client listeners.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use fireemu_adapter_database::changes::{ChangeData, ChangeSink, CommittedChange, Publication};
use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, HttpResponse, RestOptions};
use fireemu_core_types::admission::EventAdmissionError;
use serde_json::{json, Value};

#[derive(Debug, Default)]
struct Sink {
    reject: AtomicBool,
    published: Arc<Mutex<Vec<CommittedChange>>>,
}

struct Reserved {
    published: Arc<Mutex<Vec<CommittedChange>>>,
    change: CommittedChange,
}

impl Publication for Reserved {
    fn publish(self: Box<Self>) {
        self.published.lock().unwrap().push(self.change);
    }
}

impl ChangeSink for Sink {
    fn reserve(
        &self,
        change: &CommittedChange,
    ) -> Result<Box<dyn Publication>, EventAdmissionError> {
        if self.reject.load(Ordering::SeqCst) {
            return Err(EventAdmissionError::Capacity("test capacity".to_owned()));
        }
        Ok(Box::new(Reserved {
            published: Arc::clone(&self.published),
            change: change.clone(),
        }))
    }
}

fn call(
    db: &mut Database,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> HttpResponse {
    let request = HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        headers: headers
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
        body: body.as_bytes().to_vec(),
    };
    match db.handle(&request, 1234) {
        Handled::Response { response, .. } => response,
        Handled::Stream { .. } => panic!("unexpected stream"),
    }
}

fn fixture() -> (Database, Arc<Sink>) {
    let mut db = Database::new(RestOptions::default(), 42);
    let sink = Arc::new(Sink::default());
    db.set_change_sink(sink.clone());
    (db, sink)
}

fn whole(change: &CommittedChange) -> (&Value, &Value) {
    match &change.data {
        ChangeData::Whole { before, after } => (before, after),
        ChangeData::References(_) => panic!("this test sink requests complete snapshots"),
    }
}

#[test]
fn rest_commits_publish_without_listeners_and_keep_immutable_snapshots() {
    let (mut db, sink) = fixture();
    assert_eq!(
        call(&mut db, "PUT", "/x.json?ns=ns", &[], r#"{"a":1}"#).status,
        200
    );
    assert_eq!(sink.published.lock().unwrap().len(), 1);
    assert_eq!(
        call(&mut db, "PATCH", "/x.json?ns=ns", &[], r#"{"b":2}"#).status,
        200
    );
    assert_eq!(call(&mut db, "POST", "/x.json?ns=ns", &[], "3").status, 200);
    assert_eq!(
        call(&mut db, "DELETE", "/x/a.json?ns=ns", &[], "").status,
        200
    );
    let changes = sink.published.lock().unwrap();
    assert_eq!(changes.len(), 4);
    assert_eq!(whole(&changes[0]).0, &Value::Null);
    assert_eq!(whole(&changes[0]).1, &json!({"x":{"a":1}}));
    assert_eq!(whole(&changes[1]).0, whole(&changes[0]).1);
    assert_eq!(whole(&changes[1]).1, &json!({"x":{"a":1,"b":2}}));
    assert!(changes
        .windows(2)
        .all(|pair| pair[0].context.sequence < pair[1].context.sequence));
    assert!(changes
        .iter()
        .all(|change| change.context.namespace == "ns" && change.context.now_millis == 1234));
}

#[test]
fn no_op_invalid_and_conditional_refusals_publish_nothing() {
    let (mut db, sink) = fixture();
    assert_eq!(
        call(&mut db, "DELETE", "/absent.json?ns=ns", &[], "").status,
        200
    );
    assert!(sink.published.lock().unwrap().is_empty());
    assert_eq!(call(&mut db, "PUT", "/x.json?ns=ns", &[], "1").status, 200);
    assert_eq!(call(&mut db, "PUT", "/x.json?ns=ns", &[], "1").status, 200);
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/x.json?ns=ns",
            &[("if-match", "mismatch")],
            "2"
        )
        .status,
        412
    );
    assert_eq!(call(&mut db, "PUT", "/x.json?ns=ns", &[], "[").status, 400);
    assert_eq!(sink.published.lock().unwrap().len(), 1);
}

#[test]
fn admission_refusal_preserves_source_and_never_activates_an_event() {
    let (mut db, sink) = fixture();
    sink.reject.store(true, Ordering::SeqCst);
    assert_eq!(call(&mut db, "PUT", "/x.json?ns=ns", &[], "1").status, 503);
    assert_eq!(
        serde_json::from_slice::<Value>(&call(&mut db, "GET", "/x.json?ns=ns", &[], "").body)
            .unwrap(),
        Value::Null
    );
    assert!(sink.published.lock().unwrap().is_empty());
    sink.reject.store(false, Ordering::SeqCst);
    assert_eq!(call(&mut db, "PUT", "/x.json?ns=ns", &[], "1").status, 200);
    assert_eq!(sink.published.lock().unwrap().len(), 1);
}

#[test]
fn administrative_suppression_is_explicit_and_override_keeps_admin_origin() {
    let (mut db, sink) = fixture();
    let owner = [("Authorization", "Bearer owner")];
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/x.json?ns=ns&disableTriggers=true",
            &owner,
            "1"
        )
        .status,
        200
    );
    assert!(sink.published.lock().unwrap().is_empty());
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/x.json?ns=ns&auth_variable_override=null",
            &owner,
            "2"
        )
        .status,
        200
    );
    let changes = sink.published.lock().unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].context.principal.auth_type, "ADMIN");
    assert!(changes[0].context.principal.auth_id.is_none());
    assert!(changes[0].context.principal.auth.is_none());
}

fn disconnect_write(db: &mut Database) {
    disconnect_write_in(db, "ns");
}

fn disconnect_write_in(db: &mut Database, namespace: &str) {
    use fireemu_adapter_database::realtime::Opened;
    let mut session = match db
        .open_realtime(
            &format!("/.ws?v=5&ns={namespace}"),
            Some("127.0.0.1:9000"),
            1234,
        )
        .unwrap()
    {
        Opened::Session(session, _) => session,
        other @ Opened::Shutdown(_) => panic!("unexpected connection: {other:?}"),
    };
    let received = session.receive(
        db,
        r#"{"t":"d","d":{"r":1,"a":"o","b":{"p":"/x","d":1}}}"#,
        1234,
    );
    assert_eq!(received.replies.len(), 1);
    let reply: Value = serde_json::from_str(&received.replies[0]).unwrap();
    assert_eq!(reply["d"]["b"]["s"], "ok");
    db.close_realtime(session.client(), 1235);
}

#[test]
fn disconnect_admission_backpressure_retains_work_until_capacity_recovers() {
    let (mut db, sink) = fixture();
    sink.reject.store(true, Ordering::SeqCst);
    disconnect_write(&mut db);
    assert_eq!(
        serde_json::from_slice::<Value>(&call(&mut db, "GET", "/x.json?ns=ns", &[], "").body)
            .unwrap(),
        Value::Null
    );
    assert!(sink.published.lock().unwrap().is_empty());
    sink.reject.store(false, Ordering::SeqCst);
    db.drain_events();
    assert_eq!(
        serde_json::from_slice::<Value>(&call(&mut db, "GET", "/x.json?ns=ns", &[], "").body)
            .unwrap(),
        json!(1)
    );
    assert_eq!(sink.published.lock().unwrap().len(), 1);
    db.drain_events();
    assert_eq!(sink.published.lock().unwrap().len(), 1);
}

#[test]
fn reset_retires_deferred_disconnect_work() {
    let (mut db, sink) = fixture();
    sink.reject.store(true, Ordering::SeqCst);
    disconnect_write(&mut db);
    db.clear_namespaces_where(|namespace| namespace == "ns");
    sink.reject.store(false, Ordering::SeqCst);
    db.drain_events();
    assert_eq!(
        serde_json::from_slice::<Value>(&call(&mut db, "GET", "/x.json?ns=ns", &[], "").body)
            .unwrap(),
        Value::Null
    );
    assert!(sink.published.lock().unwrap().is_empty());
}

#[test]
fn deferred_disconnect_rechecks_current_rules_before_publication() {
    let (mut db, sink) = fixture();
    sink.reject.store(true, Ordering::SeqCst);
    disconnect_write(&mut db);
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/.settings/rules.json?ns=ns",
            &[("Authorization", "Bearer owner")],
            r#"{"rules":{".read":true,".write":false}}"#
        )
        .status,
        200
    );
    sink.reject.store(false, Ordering::SeqCst);
    db.drain_events();
    assert_eq!(
        serde_json::from_slice::<Value>(&call(&mut db, "GET", "/x.json?ns=ns", &[], "").body)
            .unwrap(),
        Value::Null
    );
    assert!(sink.published.lock().unwrap().is_empty());
}

#[test]
fn only_administrator_credentials_can_request_trigger_suppression() {
    use fireemu_adapter_database::rest::Credentials;
    let mut db = Database::new(
        RestOptions {
            credentials: Credentials {
                strict: true,
                id_tokens: Some(Arc::new(|token, _, _| {
                    (token == "verified-user").then(|| r#"{"sub":"alice","iat":1}"#.to_owned())
                })),
            },
            ..RestOptions::default()
        },
        42,
    );
    let sink = Arc::new(Sink::default());
    db.set_change_sink(sink.clone());
    for query in ["", "&auth=verified-user"] {
        assert_eq!(
            call(
                &mut db,
                "PUT",
                &format!("/x.json?ns=ns&disableTriggers=true{query}"),
                &[],
                "1"
            )
            .status,
            400
        );
    }
    assert_eq!(
        call(
            &mut db,
            "PUT",
            "/x.json?ns=ns&disableTriggers=true",
            &[("Authorization", "Bearer verified-user")],
            "1"
        )
        .status,
        401
    );
    assert!(sink.published.lock().unwrap().is_empty());
    assert_eq!(
        call(&mut db, "PUT", "/x.json?ns=ns&auth=verified-user", &[], "1").status,
        200
    );
    assert_eq!(
        sink.published.lock().unwrap()[0]
            .context
            .principal
            .auth_type,
        "USER"
    );
}

#[test]
fn restore_retires_only_owned_deferred_disconnects() {
    let (mut db, sink) = fixture();
    let snapshot = db.capture_namespaces_where(|ns| ns == "ns");
    sink.reject.store(true, Ordering::SeqCst);
    disconnect_write_in(&mut db, "ns");
    disconnect_write_in(&mut db, "other");
    db.restore_namespaces_where(|ns| ns == "ns", &snapshot);
    sink.reject.store(false, Ordering::SeqCst);
    db.drain_events();
    let changes = sink.published.lock().unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].context.namespace, "other");
    assert_eq!(
        serde_json::from_slice::<Value>(&call(&mut db, "GET", "/x.json?ns=ns", &[], "").body)
            .unwrap(),
        Value::Null
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&call(&mut db, "GET", "/x.json?ns=other", &[], "").body)
            .unwrap(),
        json!(1)
    );
}
