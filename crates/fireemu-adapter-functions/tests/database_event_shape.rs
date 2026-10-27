//! The RTDB trigger event as production delivered it (CV14, recorded 2026-10-27, 28 frames of 8 handlers over
//! 9 writes) against the official emulator's shape, by profile. Production: `source` names the project `_`,
//! `time` has three fraction digits, there is no `datacontenttype`, a 2nd gen event names no `authtype` for
//! an admin or an unauthenticated write (the SDK then reports `unknown`), a 1st gen event keeps it (its
//! context is `ADMIN` or `UNAUTHENTICATED`), and the id is the base64 of twenty bytes.

use fireemu_adapter_functions::events::{
    database_event_id, database_event_payloads, database_event_payloads_for, DatabaseChangeData,
    DatabaseCommit, DatabaseEventShape,
};
use fireemu_adapter_functions::manifest_json::parse_manifest;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

fn commit(auth_type: &str, auth_id: Option<&str>) -> DatabaseCommit {
    DatabaseCommit {
        project: "demo-db".to_owned(),
        instance: "fireemu-q-rtdb2".to_owned(),
        location: "us-central1".to_owned(),
        host: "firebaseio.com".to_owned(),
        sequence: 5,
        // 2026-10-27T12:12:10.146789012Z
        time: LogicalInstant::from_nanos(1_793_103_130_146_789_012),
        data: DatabaseChangeData::Whole {
            before: json!({"cv14-rtdb": {"items": {}}}),
            after: json!({"cv14-rtdb": {"items": {"a": {"n": 1}}}}),
        },
        auth_type: auth_type.to_owned(),
        auth_id: auth_id.map(str::to_owned),
        auth: None,
    }
}

fn function(generation: u8) -> fireemu_core_functions::manifest::FunctionManifest {
    parse_manifest(
        &json!({"functions": [{"name":"db", "generation": generation, "trigger": {
            "type":"database", "eventType":"google.firebase.database.ref.v1.created",
            "instance":"fireemu-q-rtdb2", "ref":"/cv14-rtdb/items/{id}"
        }}]}),
    )
    .unwrap()
}

fn payload(
    generation: u8,
    shape: DatabaseEventShape,
    auth_type: &str,
    auth_id: Option<&str>,
) -> Value {
    let manifest = function(generation);
    let mut all =
        database_event_payloads_for(&commit(auth_type, auth_id), &manifest.functions[0], shape);
    assert_eq!(all.len(), 1);
    all.remove(0).1
}

#[test]
fn the_production_shape_names_the_project_underscore_and_cuts_the_time_to_milliseconds() {
    for generation in [1, 2] {
        let event = payload(generation, DatabaseEventShape::Production, "ADMIN", None);
        assert_eq!(
            event["source"],
            "//firebasedatabase.googleapis.com/projects/_/locations/us-central1/instances/fireemu-q-rtdb2"
        );
        assert_eq!(
            event["time"], "2026-10-27T12:12:10.146Z",
            "generation {generation}"
        );
        assert_eq!(event["subject"], "refs/cv14-rtdb/items/a");
        assert_eq!(event["ref"], "cv14-rtdb/items/a");
        assert_eq!(event["firebasedatabasehost"], "firebaseio.com");
    }
}

#[test]
fn the_production_shape_carries_no_datacontenttype() {
    for generation in [1, 2] {
        let event = payload(generation, DatabaseEventShape::Production, "ADMIN", None);
        assert!(
            event.get("datacontenttype").is_none(),
            "generation {generation}: {event}"
        );
    }
}

#[test]
fn a_second_gen_event_names_no_auth_for_an_admin_or_unauthenticated_write_and_a_first_gen_event_keeps_it(
) {
    for auth_type in ["ADMIN", "UNAUTHENTICATED"] {
        let second = payload(2, DatabaseEventShape::Production, auth_type, None);
        assert!(second.get("authtype").is_none(), "{auth_type}: {second}");
        assert!(second.get("authid").is_none(), "{auth_type}: {second}");
        let first = payload(1, DatabaseEventShape::Production, auth_type, None);
        assert_eq!(
            first["authtype"],
            auth_type.to_lowercase(),
            "{auth_type}: {first}"
        );
    }
    // an end user's write was not recorded: the event keeps what it names today
    let user = payload(
        2,
        DatabaseEventShape::Production,
        "USER",
        Some("verified-user"),
    );
    assert_eq!(user["authtype"], "app_user");
    assert_eq!(user["authid"], "verified-user");
}

#[test]
fn the_official_shape_is_the_one_the_emulator_profile_always_had() {
    let event = payload(2, DatabaseEventShape::Official, "ADMIN", None);
    assert_eq!(
        event["source"],
        "//firebasedatabase.googleapis.com/projects/demo-db/locations/us-central1/instances/fireemu-q-rtdb2"
    );
    assert_eq!(event["datacontenttype"], "application/json");
    assert_eq!(event["authtype"], "admin");
    assert!(
        event["time"].as_str().unwrap().ends_with("146789012Z"),
        "{event}"
    );
    // the unshaped entry point is that shape
    let manifest = function(2);
    let plain = database_event_payloads(&commit("ADMIN", None), &manifest.functions[0]);
    assert_eq!(plain[0].1, event);
}

#[test]
fn the_default_shape_is_production() {
    assert_eq!(
        DatabaseEventShape::default(),
        DatabaseEventShape::Production
    );
}

#[test]
fn a_database_event_id_is_twenty_bytes_in_base64_and_stable() {
    let id = database_event_id("42-1");
    assert_eq!(id.len(), 28, "{id}");
    assert!(id.ends_with('='), "{id}");
    assert!(
        id[..27]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/'),
        "{id}"
    );
    assert_eq!(id, database_event_id("42-1"));
    let ids: std::collections::BTreeSet<String> = (1..=500)
        .map(|n| database_event_id(&format!("42-{n}")))
        .collect();
    assert_eq!(ids.len(), 500);
    assert_ne!(database_event_id("42-1"), database_event_id("43-1"));
}

#[test]
fn a_database_event_id_is_a_stable_function_of_the_seed() {
    // Golden values, cross-checked against an independent implementation (the seeded stream and the
    // base64 of its first twenty bytes): a recorded local run must replay with the same ids in every build.
    for (seed, expected) in [
        ("42-1", "N2tCyNOcFGeqilsx+SB18g3Rjy0="),
        ("42-2", "Y3qF2eWCE7ngGrVqNOsFcYyyMac="),
        ("", "w4F8AWuk/zAQDNqswLyTFlTDpWk="),
        ("a", "5rheMiL7kF+qczXF+3U1jxLfw4o="),
    ] {
        assert_eq!(database_event_id(seed), expected, "seed {seed:?}");
    }
}

#[test]
fn only_a_first_gen_event_of_an_end_user_write_carries_the_auth_token() {
    let mut user = commit("USER", Some("verified-user"));
    user.auth = Some(json!({"uid": "verified-user", "token": {"role": "member"}}));
    for shape in [DatabaseEventShape::Production, DatabaseEventShape::Official] {
        let first = function(1);
        let events = database_event_payloads_for(&user, &first.functions[0], shape);
        assert_eq!(
            events[0].1["auth"],
            json!({"uid": "verified-user", "token": {"role": "member"}}),
            "{shape:?}"
        );
        let second = function(2);
        let events = database_event_payloads_for(&user, &second.functions[0], shape);
        assert!(events[0].1.get("auth").is_none(), "{shape:?}");
        let mut admin = commit("ADMIN", None);
        admin.auth = user.auth.clone();
        let events = database_event_payloads_for(&admin, &first.functions[0], shape);
        assert!(events[0].1.get("auth").is_none(), "{shape:?}");
    }
}

#[test]
fn the_runtime_config_shows_its_database_event_shape() {
    let config =
        fireemu_adapter_functions::runtime::FunctionsConfig::for_tests(1000, "test".to_owned());
    assert!(format!("{config:?}").contains("database_event_shape: Production"));
}
