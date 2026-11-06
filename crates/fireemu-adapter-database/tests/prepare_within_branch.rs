//! `prepare_within` on a large namespace: the published change and the resulting tree of an
//! accepted write, the unchanged tree after a rejected one, and the cost of one preparation.
//!
//! These pin the behavior that a cheaper preparation (one that does not clone the whole
//! namespace tree) must keep byte for byte.

use std::sync::Mutex;
use std::time::Instant;

use fireemu_adapter_database::changes::{
    prepare_within, ChangeContext, ChangeData, ChangeError, ChangeSink, CommittedChange, Principal,
    Publication,
};
use fireemu_adapter_database::json_text::{render, Style};
use fireemu_core_database::{
    DatabaseError, ErrorKind, Format, Json, Path, ServerValueContext, Tree,
};
use fireemu_core_types::admission::EventAdmissionError;
use serde_json::Value;

/// Objects under `/items`, as in the issue: about 7 MB of export JSON.
const ITEMS: usize = 130_000;
const NOW: ServerValueContext = ServerValueContext { now_millis: 100 };

#[derive(Debug, Default)]
struct Sink {
    captured: Mutex<Vec<CommittedChange>>,
    references: Vec<&'static str>,
    reject: bool,
}
struct Reserved;
impl Publication for Reserved {
    fn publish(self: Box<Self>) {}
}
impl ChangeSink for Sink {
    fn capture_references(
        &self,
        _: &str,
        before: fireemu_adapter_database::changes::ScopeView<'_>,
        _: &Tree,
    ) -> Result<Option<Vec<Path>>, EventAdmissionError> {
        let limits = before.limits();
        Ok(Some(
            self.references
                .iter()
                .map(|reference| Path::parse(reference, limits).unwrap())
                .collect(),
        ))
    }
    fn reserve(
        &self,
        change: &CommittedChange,
    ) -> Result<Box<dyn Publication>, EventAdmissionError> {
        if self.reject {
            return Err(EventAdmissionError::Capacity("test capacity".to_owned()));
        }
        self.captured.lock().unwrap().push(change.clone());
        Ok(Box::new(Reserved))
    }
}

fn context() -> ChangeContext {
    ChangeContext {
        namespace: "large".to_owned(),
        sequence: 1,
        now_millis: NOW.now_millis,
        principal: Principal {
            auth_type: "ADMIN".to_owned(),
            auth_id: None,
            auth: None,
        },
    }
}

fn path(tree: &Tree, text: &str) -> Path {
    Path::parse(text, tree.limits()).unwrap()
}

fn item(index: usize) -> Json {
    Json::object([
        ("name", Json::string(format!("user-{index:06}"))),
        ("score", Json::int(i64::try_from(index % 1000).unwrap())),
        ("active", Json::Bool(index % 2 == 0)),
    ])
}

/// `/items` with [`ITEMS`] small objects, and a small unrelated `/config`.
fn large_tree() -> Tree {
    let mut tree = Tree::default();
    let items = Json::object((0..ITEMS).map(|index| (format!("k{index:06}"), item(index))));
    tree.set(
        &Path::root(),
        &Json::object([
            ("items", items),
            ("config", Json::object([("mode", Json::string("on"))])),
        ]),
        NOW,
    )
    .unwrap();
    tree
}

/// The published change as compact JSON text: the bytes an event body is built from.
fn publication_text(change: &CommittedChange) -> String {
    let data = match &change.data {
        ChangeData::Whole { before, after } => {
            serde_json::json!({ "whole": { "before": before, "after": after } })
        }
        ChangeData::References(references) => Value::Array(
            references
                .iter()
                .map(|reference| {
                    serde_json::json!({
                        "reference": reference.reference.to_string(),
                        "before": reference.before,
                        "after": reference.after,
                    })
                })
                .collect(),
        ),
    };
    serde_json::to_string(&serde_json::json!({
        "namespace": change.context.namespace,
        "sequence": change.context.sequence,
        "now": change.context.now_millis,
        "data": data,
    }))
    .unwrap()
}

fn export(tree: &Tree, text: &str) -> String {
    render(
        &tree.get_json(&path(tree, text), Format::Export),
        Style::Compact,
    )
}

#[test]
fn an_accepted_branch_write_publishes_the_same_bytes_and_tree() {
    let mut tree = large_tree();
    let original = tree.clone();
    let sink = Sink {
        references: vec!["/items/k000042", "/items/k000043", "/config"],
        ..Sink::default()
    };
    let scope = path(&tree, "/items/k000042");
    let (written, prepared) = prepare_within(&mut tree, &scope, context(), Some(&sink), |tree| {
        tree.set(
            &scope,
            &Json::object([
                ("name", Json::string("renamed")),
                ("score", Json::object([(".sv", Json::string("timestamp"))])),
            ]),
            NOW,
        )
    })
    .unwrap();
    assert!(written.is_some());
    // Successful preparation applies source data before publication.
    assert_ne!(tree, original);
    prepared.commit();

    let captured = sink.captured.lock().unwrap();
    assert_eq!(captured.len(), 1);
    // Only the changed reference is published; the unchanged sibling and `/config` are not.
    assert_eq!(
        publication_text(&captured[0]),
        r#"{"data":[{"after":{"name":"renamed","score":100},"before":{"active":true,"name":"user-000042","score":42},"reference":"/items/k000042"}],"namespace":"large","now":100,"sequence":1}"#
    );
    assert_eq!(
        export(&tree, "/items/k000042"),
        r#"{"name":"renamed","score":100}"#
    );
    assert_eq!(
        export(&tree, "/items/k000043"),
        r#"{"active":false,"name":"user-000043","score":43}"#
    );
    // The resulting tree equals the original with only that branch replaced.
    let mut expected = original;
    expected
        .set(
            &scope,
            &Json::object([("name", Json::string("renamed")), ("score", Json::int(100))]),
            NOW,
        )
        .unwrap();
    assert_eq!(tree, expected);
}

#[test]
fn an_admission_rejected_branch_write_leaves_the_tree_and_publishes_nothing() {
    let mut tree = large_tree();
    let before = tree.clone();
    let sink = Sink {
        references: vec!["/items/k000042"],
        reject: true,
        ..Sink::default()
    };
    let scope = path(&tree, "/items/k000042");
    let result = prepare_within(&mut tree, &scope, context(), Some(&sink), |tree| {
        tree.set(&scope, &Json::string("replaced"), NOW)
    });
    assert!(matches!(result, Err(ChangeError::Admission(_))));
    assert!(sink.captured.lock().unwrap().is_empty());
    assert_eq!(tree, before);
    assert_eq!(
        export(&tree, "/items/k000042"),
        r#"{"active":true,"name":"user-000042","score":42}"#
    );
}

#[test]
fn a_database_rejected_branch_write_leaves_the_tree_and_publishes_nothing() {
    let mut tree = large_tree();
    let before = tree.clone();
    let sink = Sink {
        references: vec!["/items/k000042"],
        ..Sink::default()
    };
    let scope = path(&tree, "/items/k000042");
    // Overlapping update paths are refused before any entry is applied.
    let result = prepare_within(&mut tree, &scope, context(), Some(&sink), |tree| {
        tree.update(
            &scope,
            &[
                ("name".to_owned(), Json::string("a")),
                ("name/deep".to_owned(), Json::string("b")),
            ],
            NOW,
        )
    });
    assert!(matches!(result, Err(ChangeError::Database(_))));
    assert!(sink.captured.lock().unwrap().is_empty());
    assert_eq!(tree, before);
}

/// An operation that writes below `scope` and then fails, as a partially applied operation
/// would: the rejection must not leave the partial write behind.
fn write_then_fail(tree: &mut Tree, at: &Path) -> Result<(), DatabaseError> {
    tree.set(at, &Json::string("partial"), NOW)?;
    Err(DatabaseError::new(
        ErrorKind::ReadOnlyPath,
        "refused after writing",
    ))
}

#[test]
fn a_rejected_write_deep_under_the_scope_rolls_back() {
    let mut tree = large_tree();
    let before = tree.clone();
    let sink = Sink::default();
    let scope = path(&tree, "/items/k000042");
    let deep = path(&tree, "/items/k000042/nested/deeper/leaf");
    let result = prepare_within(&mut tree, &scope, context(), Some(&sink), |tree| {
        write_then_fail(tree, &deep)
    });
    assert!(matches!(result, Err(ChangeError::Database(_))));
    assert!(sink.captured.lock().unwrap().is_empty());
    assert_eq!(tree, before);
}

#[test]
fn a_rejected_write_to_an_absent_scope_rolls_back() {
    let mut tree = large_tree();
    let before = tree.clone();
    let sink = Sink::default();
    // Neither the scope nor its parent exists before the write.
    let scope = path(&tree, "/absent/branch");
    assert!(tree.get(&scope).is_none());
    assert!(tree.get(&path(&tree, "/absent")).is_none());
    let deep = path(&tree, "/absent/branch/child");
    let result = prepare_within(&mut tree, &scope, context(), Some(&sink), |tree| {
        write_then_fail(tree, &deep)
    });
    assert!(matches!(result, Err(ChangeError::Database(_))));
    assert!(sink.captured.lock().unwrap().is_empty());
    assert_eq!(tree, before);
    assert!(tree.get(&path(&tree, "/absent")).is_none());
}

#[test]
fn a_rejected_write_through_a_leaf_ancestor_rolls_back() {
    let mut tree = large_tree();
    // A leaf at `/config/mode`: a write below it turns the leaf into a branch.
    let scope = path(&tree, "/config/mode/child");
    tree.set(&path(&tree, "/config/mode/.priority"), &Json::int(3), NOW)
        .unwrap();
    let before = tree.clone();
    let sink = Sink::default();
    let result = prepare_within(&mut tree, &scope, context(), Some(&sink), |tree| {
        write_then_fail(tree, &scope)
    });
    assert!(matches!(result, Err(ChangeError::Database(_))));
    assert_eq!(tree, before);
    assert_eq!(
        export(&tree, "/config/mode"),
        r#"{".value":"on",".priority":3}"#
    );
}

/// Prints the time of one `prepare_within` call for a write to one object of a 7 MB branch.
/// Run with `cargo test --release -p fireemu-adapter-database --test prepare_within_branch
/// -- --ignored --nocapture`.
#[test]
#[ignore = "timing evidence, not a check"]
fn time_prepare_within_on_a_seven_megabyte_branch() {
    let mut tree = large_tree();
    let bytes = export(&tree, "/items").len();
    let sink = Sink {
        references: vec!["/items/k000042"],
        ..Sink::default()
    };
    let scope = path(&tree, "/items/k000042");
    let rounds = 20;
    let mut total = std::time::Duration::ZERO;
    for round in 0..rounds {
        let started = Instant::now();
        let prepared = prepare_within(&mut tree, &scope, context(), Some(&sink), |tree| {
            tree.set(&scope, &Json::int(i64::from(round)), NOW)
        })
        .unwrap();
        total += started.elapsed();
        drop(prepared);
    }
    println!(
        "prepare_within: {bytes} bytes under /items, {:?} per call over {rounds} calls",
        total / rounds
    );
}

/// Separates unrelated namespace size from the saved branch size. Each sample
/// alternates real writes and drains captured events outside the timed interval.
#[test]
#[ignore = "release timing evidence; run under an enforced memory limit"]
fn time_preparation_by_unrelated_and_written_branch_size() {
    for (unrelated, branch) in [
        (1_000, 16),
        (10_000, 16),
        (130_000, 16),
        (1_000, 1),
        (1_000, 256),
    ] {
        let mut tree = Tree::default();
        tree.set(
            &Path::root(),
            &Json::object([
                (
                    "items",
                    Json::object((0..unrelated).map(|i| (format!("k{i:06}"), item(i)))),
                ),
                ("changed", Json::int(0)),
            ]),
            NOW,
        )
        .unwrap();
        let scope = path(&tree, "/changed");
        let sink = Sink {
            references: vec!["/changed"],
            ..Sink::default()
        };
        let values = [0, 1]
            .map(|value| Json::object((0..branch).map(|i| (format!("k{i:04}"), Json::int(value)))));
        tree.set(&scope, &values[0], NOW).unwrap();
        for sample in 0..3 {
            let rounds = 50;
            let mut total = std::time::Duration::ZERO;
            for round in 0..rounds {
                let next = &values[(round + 1) % 2];
                let start = Instant::now();
                let (_, publication) =
                    prepare_within(&mut tree, &scope, context(), Some(&sink), |tree| {
                        tree.set(&scope, next, NOW)
                    })
                    .unwrap();
                publication.commit();
                total += start.elapsed();
                sink.captured.lock().unwrap().clear();
            }
            println!("scoped timing: unrelated={unrelated} branch={branch} sample={sample} rounds={rounds} ns_per_write={}", total.as_nanos() / rounds as u128);
        }
    }
}
