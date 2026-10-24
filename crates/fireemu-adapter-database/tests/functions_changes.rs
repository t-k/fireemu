//! Staged RTDB mutations reserve their complete event batch before data is visible.

use std::sync::{Arc, Mutex};

use fireemu_adapter_database::changes;

use changes::{prepare, ChangeContext, ChangeSink, CommittedChange, Principal, Publication};
use fireemu_core_database::{Json, Path, ServerValueContext, Tree};
use fireemu_core_types::admission::EventAdmissionError;

#[derive(Debug, Default)]
struct Sink {
    captured: Mutex<Vec<CommittedChange>>,
    published: Arc<Mutex<usize>>,
    reject: bool,
    references: Option<Vec<Path>>,
}
struct Reserved(Arc<Mutex<usize>>);
impl Publication for Reserved {
    fn publish(self: Box<Self>) {
        *self.0.lock().unwrap() += 1;
    }
}
impl ChangeSink for Sink {
    fn capture_references(
        &self,
        _: &str,
        _: &Tree,
        _: &Tree,
    ) -> Result<Option<Vec<Path>>, EventAdmissionError> {
        Ok(self.references.clone())
    }
    fn reserve(
        &self,
        change: &CommittedChange,
    ) -> Result<Box<dyn Publication>, EventAdmissionError> {
        if self.reject {
            return Err(EventAdmissionError::Capacity("test capacity".to_owned()));
        }
        self.captured.lock().unwrap().push(change.clone());
        Ok(Box::new(Reserved(self.published.clone())))
    }
}
fn context() -> ChangeContext {
    ChangeContext {
        namespace: "app-second".to_owned(),
        sequence: 7,
        now_millis: 100,
        principal: Principal {
            auth_type: "UNAUTHENTICATED".to_owned(),
            auth_id: None,
            auth: None,
        },
    }
}
#[test]
fn a_reservation_is_not_published_until_the_candidate_is_committed() {
    let mut tree = Tree::default();
    let sink = Sink::default();
    let (_, candidate) = prepare(&tree, context(), Some(&sink), |tree| {
        tree.set(
            &Path::root(),
            &Json::Bool(true),
            ServerValueContext { now_millis: 100 },
        )
    })
    .unwrap();
    assert!(tree.root().is_none());
    assert_eq!(*sink.published.lock().unwrap(), 0);
    candidate.commit(&mut tree);
    assert_eq!(
        tree.get_json(&Path::root(), fireemu_core_database::Format::Export),
        Json::Bool(true)
    );
    assert_eq!(*sink.published.lock().unwrap(), 1);
    let captured = sink.captured.lock().unwrap();
    assert_eq!(captured[0].context.namespace, "app-second");
    assert_eq!(captured[0].context.sequence, 7);
    let changes::ChangeData::Whole { before, after } = &captured[0].data else {
        panic!("whole capture expected")
    };
    assert_eq!(before, &serde_json::Value::Null);
    assert_eq!(after, &true);
}
#[test]
fn refusing_the_complete_batch_leaves_the_original_tree_unchanged() {
    let tree = Tree::default();
    let sink = Sink {
        reject: true,
        ..Sink::default()
    };
    assert!(prepare(&tree, context(), Some(&sink), |tree| {
        tree.set(
            &Path::root(),
            &Json::Bool(true),
            ServerValueContext { now_millis: 100 },
        )
    })
    .is_err());
    assert!(tree.root().is_none());
    assert_eq!(*sink.published.lock().unwrap(), 0);
}
#[test]
fn null_to_null_and_empty_updates_do_not_reserve_even_without_listeners() {
    let mut tree = Tree::default();
    let sink = Sink::default();
    for _ in 0..3 {
        let (_, candidate) = prepare(&tree, context(), Some(&sink), |tree| {
            tree.set(
                &Path::root(),
                &Json::Null,
                ServerValueContext { now_millis: 100 },
            )
        })
        .unwrap();
        candidate.commit(&mut tree);
    }
    let ((), candidate) = prepare(&tree, context(), Some(&sink), |tree| {
        tree.update(&Path::root(), &[], ServerValueContext { now_millis: 100 })
    })
    .unwrap();
    candidate.commit(&mut tree);
    assert!(sink.captured.lock().unwrap().is_empty());
    assert_eq!(*sink.published.lock().unwrap(), 0);
}

#[test]
fn projected_snapshots_deduplicate_refs_keep_ancestors_and_exclude_unrelated_data() {
    let mut tree = Tree::default();
    let limits = *tree.limits();
    let path = |value| Path::parse(value, &limits).unwrap();
    tree.set(
        &Path::root(),
        &Json::object([
            (
                "users",
                Json::object([("a", Json::int(1)), ("b", Json::int(2))]),
            ),
            ("unrelated", Json::string("x".repeat(1_000_000))),
        ]),
        ServerValueContext { now_millis: 100 },
    )
    .unwrap();
    let sink = Sink {
        references: Some(vec![
            path("/users/a"),
            path("/users"),
            path("/users/a"),
            path("/unmodified"),
        ]),
        ..Sink::default()
    };
    let (_, candidate) = prepare(&tree, context(), Some(&sink), |tree| {
        tree.set(
            &path("/users/a"),
            &Json::int(3),
            ServerValueContext { now_millis: 100 },
        )
    })
    .unwrap();
    candidate.commit(&mut tree);
    let captured = sink.captured.lock().unwrap();
    let changes::ChangeData::References(refs) = &captured[0].data else {
        panic!("projected capture expected")
    };
    assert_eq!(refs.len(), 2);
    assert_eq!(refs[0].reference, path("/users"));
    assert_eq!(refs[0].before, serde_json::json!({"a":1,"b":2}));
    assert_eq!(refs[0].after, serde_json::json!({"a":3,"b":2}));
    assert_eq!(refs[1].reference, path("/users/a"));
    assert_eq!(refs[1].before, 1);
    assert_eq!(refs[1].after, 3);
}

#[test]
fn projected_empty_selection_and_invalid_candidates_never_reserve() {
    let tree = Tree::default();
    let sink = Sink {
        references: Some(Vec::new()),
        ..Sink::default()
    };
    let (_, candidate) = prepare(&tree, context(), Some(&sink), |tree| {
        tree.set(
            &Path::root(),
            &Json::Bool(true),
            ServerValueContext { now_millis: 100 },
        )
    })
    .unwrap();
    drop(candidate);
    assert!(sink.captured.lock().unwrap().is_empty());
    assert!(prepare(&tree, context(), Some(&sink), |tree| tree.update(
        &Path::root(),
        &[
            ("a".to_owned(), Json::Bool(true)),
            ("a/x".to_owned(), Json::int(1))
        ],
        ServerValueContext { now_millis: 100 },
    ))
    .is_err());
    assert!(tree.root().is_none());
    assert!(sink.captured.lock().unwrap().is_empty());
}

#[test]
fn priority_only_changes_preserve_both_export_snapshots() {
    let mut tree = Tree::default();
    let value =
        |priority| Json::object([(".value", Json::int(1)), (".priority", Json::int(priority))]);
    tree.set(
        &Path::root(),
        &value(2),
        ServerValueContext { now_millis: 100 },
    )
    .unwrap();
    let sink = Sink {
        references: Some(vec![Path::root()]),
        ..Sink::default()
    };
    let (_, candidate) = prepare(&tree, context(), Some(&sink), |tree| {
        tree.set(
            &Path::root(),
            &value(3),
            ServerValueContext { now_millis: 100 },
        )
    })
    .unwrap();
    candidate.commit(&mut tree);
    let captured = sink.captured.lock().unwrap();
    let changes::ChangeData::References(refs) = &captured[0].data else {
        panic!("projected capture expected")
    };
    assert_eq!(
        refs[0].before,
        serde_json::json!({".value":1,".priority":2.0})
    );
    assert_eq!(
        refs[0].after,
        serde_json::json!({".value":1,".priority":3.0})
    );
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn staged_operation_sequences_match_a_simple_commit_or_refusal_model(
        operations in proptest::collection::vec((proptest::option::of(proptest::bool::ANY), proptest::bool::ANY), 1..40)
    ) {
        let mut tree = Tree::default();
        let mut expected = None;
        let mut published = 0;
        for (value, reject) in operations {
            let sink = Sink { reject, ..Sink::default() };
            let json = value.map_or(Json::Null, Json::Bool);
            let result = prepare(&tree, context(), Some(&sink), |tree| tree.set(&Path::root(), &json, ServerValueContext {now_millis:100}));
            let changes = expected != value;
            if reject && changes {
                proptest::prop_assert!(matches!(result, Err(changes::ChangeError::Admission(_))));
            } else {
                result.unwrap().1.commit(&mut tree);
                expected = value;
                published += usize::from(changes);
            }
            proptest::prop_assert_eq!(tree.get_json(&Path::root(), fireemu_core_database::Format::Export), expected.map_or(Json::Null, Json::Bool));
            proptest::prop_assert_eq!(*sink.published.lock().unwrap(), usize::from(changes && !reject));
        }
        proptest::prop_assert!(published <= 40);
    }
}

use fireemu_adapter_database::realtime::{Opened, Session};
use fireemu_adapter_database::rest::{Database, RestOptions};

fn open(db: &mut Database) -> Session {
    match db
        .open_realtime("/.ws?v=5&ns=app-second", None, 100)
        .unwrap()
    {
        Opened::Session(session, _) => session,
        other @ Opened::Shutdown(_) => panic!("unexpected realtime open: {other:?}"),
    }
}
fn request(
    session: &mut Session,
    db: &mut Database,
    action: &str,
    body: &serde_json::Value,
) -> serde_json::Value {
    let frame = serde_json::json!({"t":"d","d":{"r":1,"a":action,"b":body}}).to_string();
    let received = session.receive(db, &frame, 100);
    assert!(!received.drop_connection);
    serde_json::from_str(&received.replies[0]).unwrap()
}

#[test]
fn realtime_mutations_capture_successes_only_and_preserve_transaction_causality() {
    let mut db = Database::new(RestOptions::default(), 1);
    let sink = Arc::new(Sink::default());
    db.set_change_sink(sink.clone());
    let mut session = open(&mut db);
    assert_eq!(
        request(
            &mut session,
            &mut db,
            "p",
            &serde_json::json!({"p":"/a","d":{"old":1}})
        )["d"]["b"]["s"],
        "ok"
    );
    assert_eq!(
        request(
            &mut session,
            &mut db,
            "m",
            &serde_json::json!({"p":"/a","d":{"old":null,"new":2}})
        )["d"]["b"]["s"],
        "ok"
    );
    assert_eq!(
        request(
            &mut session,
            &mut db,
            "p",
            &serde_json::json!({"p":"/a","d":{"new":2}})
        )["d"]["b"]["s"],
        "ok"
    );
    assert_eq!(
        request(
            &mut session,
            &mut db,
            "p",
            &serde_json::json!({"p":"/a","h":"stale","d":3})
        )["d"]["b"]["s"],
        "datastale"
    );
    let captured = sink.captured.lock().unwrap();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].context.principal.auth_type, "UNAUTHENTICATED");
    assert_eq!(captured[0].context.namespace, "app-second");
    assert!(captured[0].context.sequence < captured[1].context.sequence);
    let changes::ChangeData::Whole { before, after } = &captured[1].data else {
        panic!("whole capture expected")
    };
    assert_eq!(before, &serde_json::json!({"a":{"old":1}}));
    assert_eq!(after, &serde_json::json!({"a":{"new":2}}));
}

#[test]
fn realtime_admission_refusal_keeps_source_and_listener_events_unpublished() {
    let mut db = Database::new(RestOptions::default(), 1);
    let sink = Arc::new(Sink {
        reject: true,
        ..Sink::default()
    });
    db.set_change_sink(sink.clone());
    let mut session = open(&mut db);
    for action in ["p", "m"] {
        let frame = serde_json::json!({"t":"d","d":{"r":1,"a":action,"b":{"p":"/a","d":{"v":1}}}})
            .to_string();
        let received = session.receive(&mut db, &frame, 100);
        let reply: serde_json::Value = serde_json::from_str(&received.replies[0]).unwrap();
        assert_eq!(reply["d"]["b"]["s"], "unavailable");
        assert!(received.events.is_empty());
    }
    assert!(db.tree("app-second").unwrap().root().is_none());
    assert_eq!(*sink.published.lock().unwrap(), 0);
}

#[test]
fn realtime_admin_rules_override_keeps_originating_admin_and_never_bypasses_rules() {
    let mut db = Database::new(RestOptions::default(), 1);
    db.load_rules(
        "app-second",
        r#"{"rules":{".read":true,".write":"auth != null && auth.uid === 'member'"}}"#,
        100,
    )
    .unwrap();
    let sink = Arc::new(Sink::default());
    db.set_change_sink(sink.clone());
    let mut session = open(&mut db);
    assert_eq!(
        request(
            &mut session,
            &mut db,
            "gauth",
            &serde_json::json!({"cred":"owner","authvar":{"uid":"member"}})
        )["d"]["b"]["s"],
        "ok"
    );
    assert_eq!(
        request(
            &mut session,
            &mut db,
            "p",
            &serde_json::json!({"p":"/a","d":1})
        )["d"]["b"]["s"],
        "ok"
    );
    assert_eq!(
        request(
            &mut session,
            &mut db,
            "gauth",
            &serde_json::json!({"cred":"owner","authvar":null})
        )["d"]["b"]["s"],
        "ok"
    );
    assert_eq!(
        request(
            &mut session,
            &mut db,
            "p",
            &serde_json::json!({"p":"/a","d":2})
        )["d"]["b"]["s"],
        "permission_denied"
    );
    let captured = sink.captured.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].context.principal.auth_type, "ADMIN");
    assert_eq!(captured[0].context.principal.auth_id, None);
    assert_eq!(captured[0].context.principal.auth, None);
}
