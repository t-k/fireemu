//! Priorities in an RTDB trigger event, as production delivered them (RTDB-TRIGGERS-KINDS-20261108-01, writes
//! k7 to k10 on a nested pattern, both generations, the any-instance and the group handler).
//!
//! Recorded: the event's `data` (the node before the write) never carries a priority, whether the node had
//! one or not (a leaf with a priority reads as the plain value, an object without its `.priority`); the
//! delta of a created node is its plain value; a write that changes only a priority sends the delta
//! `{".priority": <new>}`, which the SDK merges into the unchanged value (`after` of the 2nd gen written
//! event), and the delta of a deleted node is null. The emulator profile keeps the shape it always had.

use fireemu_adapter_functions::events::{
    database_event_payloads_for, DatabaseChangeData, DatabaseCommit, DatabaseEventShape,
};
use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;
use serde_json::{json, Map, Value};

fn commit(before: Value, after: Value) -> DatabaseCommit {
    DatabaseCommit {
        project: "demo-db".to_owned(),
        instance: "fireemu-q-rtdb2".to_owned(),
        location: "us-central1".to_owned(),
        host: "firebaseio.com".to_owned(),
        sequence: 5,
        time: LogicalInstant::from_nanos(1_793_103_130_146_789_012),
        data: DatabaseChangeData::Whole { before, after },
        auth_type: "ADMIN".to_owned(),
        auth_id: None,
        auth: None,
    }
}

fn manifest(
    generation: u8,
    event: &str,
    reference: &str,
) -> fireemu_core_functions::manifest::FunctionManifest {
    parse_manifest(
        &json!({"functions": [{"name":"db", "generation": generation, "trigger": {
            "type":"database", "eventType":format!("google.firebase.database.ref.v1.{event}"),
            "instance":"fireemu-q-rtdb2", "ref":reference
        }}]}),
    )
    .unwrap()
}

/// The `data` and `delta` of the one event of a root-level write of `before` to `after`.
fn event_data(
    shape: DatabaseEventShape,
    event: &str,
    reference: &str,
    before: Value,
    after: Value,
) -> (Value, Value) {
    let function = manifest(2, event, reference);
    let events = database_event_payloads_for(&commit(before, after), &function.functions[0], shape);
    assert_eq!(events.len(), 1, "{events:?}");
    let data = &events[0].1["data"];
    (data["data"].clone(), data["delta"].clone())
}

const ITEM: &str = "/gp/items/{id}";
const GROUP: &str = "/gp";
const PRODUCTION: DatabaseEventShape = DatabaseEventShape::Production;
const OFFICIAL: DatabaseEventShape = DatabaseEventShape::Official;

fn tree(item: Value) -> Value {
    json!({"gp": {"items": {"p1": item}}})
}

#[test]
fn a_created_object_with_a_priority_is_sent_without_it() {
    let after = tree(json!({".priority": 7, "run": "r", "value": 1}));
    let (data, delta) = event_data(PRODUCTION, "created", ITEM, tree(Value::Null), after);
    assert_eq!(data, Value::Null);
    assert_eq!(delta, json!({"run": "r", "value": 1}));
}

#[test]
fn a_created_leaf_with_a_priority_is_sent_as_the_plain_value() {
    let after = json!({"gp": {"items": {"p2": {".value": 3, ".priority": 2}}}});
    let (data, delta) = event_data(PRODUCTION, "created", ITEM, json!({}), after);
    assert_eq!(data, Value::Null);
    assert_eq!(delta, json!(3));
}

#[test]
fn a_priority_only_write_is_an_update_with_the_new_priority_as_its_delta() {
    let before = tree(json!({".priority": 7, "run": "r", "value": 1}));
    let after = tree(json!({".priority": 9, "run": "r", "value": 1}));
    let (data, delta) = event_data(PRODUCTION, "updated", ITEM, before, after);
    assert_eq!(data, json!({"run": "r", "value": 1}));
    assert_eq!(delta, json!({".priority": 9}));
}

#[test]
fn a_deleted_node_is_sent_without_its_priorities_and_with_a_null_delta() {
    let before = tree(json!({".priority": 9, "run": "r", "value": 1}));
    let (data, delta) = event_data(PRODUCTION, "deleted", ITEM, before, tree(Value::Null));
    assert_eq!(data, json!({"run": "r", "value": 1}));
    assert_eq!(delta, Value::Null);
    let before = json!({"gp": {"items": {"p1": {".value": 3, ".priority": 2}}}});
    let (data, _) = event_data(PRODUCTION, "deleted", ITEM, before, json!({}));
    assert_eq!(data, json!(3));
}

#[test]
fn an_ancestor_handler_sees_the_nested_priority_change_at_its_place_and_no_other_priority() {
    let before = tree(json!({".priority": 7, "run": "r", "value": 1}));
    let after = tree(json!({".priority": 9, "run": "r", "value": 1}));
    let (data, delta) = event_data(PRODUCTION, "written", GROUP, before, after);
    assert_eq!(data, json!({"items": {"p1": {"run": "r", "value": 1}}}));
    assert_eq!(delta, json!({"items": {"p1": {".priority": 9}}}));
    // a whole subtree created at once carries none
    let after = json!({"gp": {"items": {"p1": {".priority": 7, "run": "r"}, "p2": {".value": 3, ".priority": 2}}}});
    let (data, delta) = event_data(PRODUCTION, "written", GROUP, json!({}), after);
    assert_eq!(data, Value::Null);
    assert_eq!(delta, json!({"items": {"p1": {"run": "r"}, "p2": 3}}));
}

#[test]
fn a_changed_value_next_to_an_unchanged_priority_sends_the_value_change_only() {
    let before = tree(json!({".priority": 7, "run": "r", "value": 1}));
    let after = tree(json!({".priority": 7, "run": "r", "value": 2}));
    let (data, delta) = event_data(PRODUCTION, "updated", ITEM, before, after);
    assert_eq!(data, json!({"run": "r", "value": 1}));
    assert_eq!(delta, json!({"value": 2}));
}

#[test]
fn the_emulator_profile_keeps_the_priorities_it_always_sent() {
    let before = tree(json!({".priority": 7, "run": "r", "value": 1}));
    let after = tree(json!({".priority": 9, "run": "r", "value": 1}));
    let (data, delta) = event_data(OFFICIAL, "updated", ITEM, before, after);
    assert_eq!(data, json!({".priority": 7, "run": "r", "value": 1}));
    assert_eq!(delta, json!({".priority": 9}));
    let after = json!({"gp": {"items": {"p2": {".value": 3, ".priority": 2}}}});
    let (data, delta) = event_data(OFFICIAL, "created", ITEM, json!({}), after);
    assert_eq!(data, Value::Null);
    assert_eq!(delta, json!({".value": 3, ".priority": 2}));
}

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        any::<i32>().prop_map(|n| json!(n)),
        "[a-z]{0,4}".prop_map(Value::String),
        any::<bool>().prop_map(Value::Bool),
    ]
}

fn priority() -> impl Strategy<Value = Option<Value>> {
    prop_oneof![
        Just(None),
        (0..20i32).prop_map(|n| Some(json!(n))),
        "[a-z]{1,3}".prop_map(|s| Some(Value::String(s)))
    ]
}

/// A node in the database's export form: leaves are a bare value or `{".value", ".priority"}`, objects
/// carry an optional `.priority` next to children.
fn node() -> impl Strategy<Value = Value> {
    let base = (leaf(), priority()).prop_map(|(value, priority)| match priority {
        Some(p) => json!({".value": value, ".priority": p}),
        None => value,
    });
    base.prop_recursive(3, 12, 3, |inner| {
        (
            proptest::collection::btree_map("[a-d]", inner, 1..4),
            priority(),
        )
            .prop_map(|(children, priority)| {
                let mut map: Map<String, Value> = children.into_iter().collect();
                if let Some(p) = priority {
                    map.insert(".priority".to_owned(), p);
                }
                Value::Object(map)
            })
    })
}

fn has_priority_key(value: &Value) -> bool {
    match value {
        Value::Object(map) => map
            .iter()
            .any(|(key, child)| key == ".priority" || key == ".value" || has_priority_key(child)),
        _ => false,
    }
}

proptest! {
    // The recorded rule for every shape of node: `data` has no priority at any depth, and the delta of a
    // created or a deleted node has none either.
    #[test]
    fn production_events_of_creates_and_deletes_carry_no_priority(node in node()) {
        let rooted = json!({"gp": {"items": {"p1": node}}});
        let (data, delta) = event_data(PRODUCTION, "created", ITEM, json!({}), rooted.clone());
        prop_assert_eq!(data, Value::Null);
        prop_assert!(!has_priority_key(&delta), "{delta}");
        let (data, delta) = event_data(PRODUCTION, "deleted", ITEM, rooted, json!({}));
        prop_assert!(!has_priority_key(&data), "{data}");
        prop_assert_eq!(delta, Value::Null);
    }

    // A write that changes any node still sends `data` without priorities, and the SDK's merge of the
    // delta into `data` is the plain value of the node after the write, except for a priority change,
    // which shows as a `.priority` member.
    #[test]
    fn production_update_data_never_carries_a_priority(before in node(), after in node()) {
        prop_assume!(before != after);
        prop_assume!(before.is_object() && after.is_object());
        prop_assume!(before.get(".value").is_none() && after.get(".value").is_none());
        let before = json!({"gp": {"items": {"p1": before}}});
        let after = json!({"gp": {"items": {"p1": after}}});
        let (data, _delta) = event_data(PRODUCTION, "written", ITEM, before, after);
        prop_assert!(!has_priority_key(&data), "{data}");
    }
}

proptest! {
    // The size an event counts against the source's limit is the compact JSON of `data` plus `delta`, in
    // both shapes, whatever the nodes hold.
    #[test]
    fn the_event_size_is_the_compact_json_of_data_plus_delta(before in node(), after in node(), strict in any::<bool>()) {
        use fireemu_adapter_functions::events::database_event_data_bytes;
        prop_assume!(before != after);
        let shape = if strict { PRODUCTION } else { OFFICIAL };
        let function = manifest(2, "written", ITEM);
        let commit = commit(
            json!({"gp": {"items": {"p1": before}}}),
            json!({"gp": {"items": {"p1": after}}}),
        );
        for (_, event) in database_event_payloads_for(&commit, &function.functions[0], shape) {
            let expected = serde_json::to_vec(&event["data"]["data"]).unwrap().len()
                + serde_json::to_vec(&event["data"]["delta"]).unwrap().len();
            prop_assert_eq!(database_event_data_bytes(&event), expected);
        }
        prop_assert_eq!(database_event_data_bytes(&json!({})), 0);
    }
}
