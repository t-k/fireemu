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

/// The snapshots a trigger event carries, as the old path built them: the export JSON rendered
/// to compact text and parsed back by `serde_json`. Kept as the oracle for byte identity.
fn rendered_snapshot(tree: &Tree, path: &Path) -> serde_json::Value {
    let json = tree.get_json(path, fireemu_core_database::Format::Export);
    serde_json::from_str(&fireemu_adapter_database::json_text::render(
        &json,
        fireemu_adapter_database::json_text::Style::Compact,
    ))
    .unwrap()
}

/// A captured reference with the compact JSON of its before and after snapshots.
type Snapshot = (Path, String, String);

/// Captures the before and after snapshots of `references` for one write of `next` at the root.
fn captured_snapshots(
    tree: &Tree,
    references: Vec<Path>,
    next: &Json,
) -> Option<(Tree, Vec<Snapshot>)> {
    let sink = Sink {
        references: Some(references),
        ..Sink::default()
    };
    let (_, prepared) = prepare(tree, context(), Some(&sink), |tree| {
        tree.set(&Path::root(), next, ServerValueContext { now_millis: 100 })
    })
    .ok()?;
    let mut after = tree.clone();
    prepared.commit(&mut after);
    let captured = sink.captured.lock().unwrap();
    let snapshots = captured
        .iter()
        .flat_map(|change| match &change.data {
            changes::ChangeData::References(references) => references.clone(),
            changes::ChangeData::Whole { .. } => panic!("reference capture expected"),
        })
        .map(|change| {
            (
                change.reference,
                serde_json::to_string(&change.before).unwrap(),
                serde_json::to_string(&change.after).unwrap(),
            )
        })
        .collect();
    Some((after, snapshots))
}

/// Pins the bytes of the snapshots handed to the trigger runtime, recorded before snapshots
/// were exported without rendering text: priorities, `.value` leaves, index-keyed children
/// (objects in the export form), escapes, integers beyond 2^53 and doubles, among them
/// `394301.33835633675`, which `serde_json`'s default float parser reads one ULP lower.
#[test]
fn trigger_snapshots_keep_their_exact_bytes() {
    let fixture = fireemu_adapter_database::json_text::parse(
        r#"{"room":{".priority":1.5,"n":394301.33835633675,"z":-0.0,"e":1e-7,"tiny":1.0715660391465826e-75,
            "i":-42,"u":9007199254740993,"d":5.0,"s":"q\"\\\n\u0001é😀 ",
            "list":["x","y"],"sparse":{"0":1,"5":2},
            "flag":{".value":true,".priority":"p"},"num":{".value":2,".priority":3}}}"#,
    )
    .unwrap();
    let mut tree = Tree::default();
    tree.set(
        &Path::root(),
        &fixture,
        ServerValueContext { now_millis: 100 },
    )
    .unwrap();
    let mut next = fixture.clone();
    let Json::Object(top) = &mut next else {
        unreachable!()
    };
    let Some(Json::Object(room)) = top.get_mut("room") else {
        unreachable!()
    };
    room.insert(
        "added".to_owned(),
        Json::Number(fireemu_core_database::Number::Double(0.1)),
    );
    let (_, snapshots) = captured_snapshots(&tree, vec![Path::from_keys(["room"])], &next).unwrap();
    let before = "{\".priority\":1.5,\"d\":5.0,\"e\":1e-7,\"flag\":{\".priority\":\"p\",\".value\":true},\"i\":-42,\"list\":{\"0\":\"x\",\"1\":\"y\"},\"n\":394301.3383563367,\"num\":{\".priority\":3.0,\".value\":2},\"s\":\"q\\\"\\\\\\n\\u0001é😀\u{2028}\",\"sparse\":{\"0\":1,\"5\":2},\"tiny\":1.0715660391465825e-75,\"u\":9007199254740993,\"z\":-0.0}";
    let after = "{\".priority\":1.5,\"added\":0.1,\"d\":5.0,\"e\":1e-7,\"flag\":{\".priority\":\"p\",\".value\":true},\"i\":-42,\"list\":{\"0\":\"x\",\"1\":\"y\"},\"n\":394301.3383563367,\"num\":{\".priority\":3.0,\".value\":2},\"s\":\"q\\\"\\\\\\n\\u0001é😀\u{2028}\",\"sparse\":{\"0\":1,\"5\":2},\"tiny\":1.0715660391465825e-75,\"u\":9007199254740993,\"z\":-0.0}";
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].1, before);
    assert_eq!(snapshots[0].2, after);
}

fn arbitrary_json() -> impl proptest::strategy::Strategy<Value = Json> {
    use fireemu_core_database::Number;
    use proptest::prelude::*;
    let leaf = prop_oneof![
        Just(Json::Null),
        any::<bool>().prop_map(Json::Bool),
        any::<i64>().prop_map(Json::int),
        // Every finite double, including subnormals and both zeros.
        any::<u64>().prop_filter_map("a finite double", |bits| {
            let value = f64::from_bits(bits);
            value
                .is_finite()
                .then_some(Json::Number(Number::Double(value)))
        }),
        (-1.0e9f64..1.0e9).prop_map(|value| Json::Number(Number::Double(value))),
        "[a-z\"\\\\\u{0}-\u{1f}é😀\u{2028}]{0,6}".prop_map(Json::String),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        let key = prop_oneof![
            Just("a".to_owned()),
            Just("b".to_owned()),
            Just("0".to_owned()),
            Just("1".to_owned()),
            Just("3".to_owned()),
            Just("z-é".to_owned()),
        ];
        let priority = prop_oneof![
            Just(Json::Null),
            any::<i64>().prop_map(Json::int),
            (-1.0e9f64..1.0e9)
                .prop_map(|value| Json::Number(fireemu_core_database::Number::Double(value))),
            "[a-z]{0,3}".prop_map(Json::String),
        ];
        prop_oneof![
            (
                proptest::collection::btree_map(key, inner.clone(), 0..5),
                priority.clone()
            )
                .prop_map(|(mut map, priority)| {
                    if priority != Json::Null {
                        map.insert(".priority".to_owned(), priority);
                    }
                    Json::Object(map)
                }),
            (inner, priority).prop_map(|(value, priority)| {
                Json::object([(".value", value), (".priority", priority)])
            }),
        ]
    })
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(512))]
    /// Every captured snapshot serializes to exactly the bytes of the rendered-and-parsed
    /// export JSON, whatever the tree holds.
    #[test]
    fn trigger_snapshots_match_the_rendered_export_json(
        first in arbitrary_json(),
        second in arbitrary_json(),
    ) {
        let mut tree = Tree::default();
        proptest::prop_assume!(tree.set(&Path::root(), &first, ServerValueContext { now_millis: 100 }).is_ok());
        let references = vec![
            Path::root(),
            Path::from_keys(["a"]),
            Path::from_keys(["0"]),
            Path::from_keys(["a", "b"]),
            Path::from_keys(["a", ".priority"]),
            Path::from_keys([".priority"]),
        ];
        let Some((after, snapshots)) = captured_snapshots(&tree, references, &second) else {
            return Ok(());
        };
        for (reference, before, after_text) in snapshots {
            proptest::prop_assert_eq!(before, serde_json::to_string(&rendered_snapshot(&tree, &reference)).unwrap());
            proptest::prop_assert_eq!(after_text, serde_json::to_string(&rendered_snapshot(&after, &reference)).unwrap());
        }
    }
}
