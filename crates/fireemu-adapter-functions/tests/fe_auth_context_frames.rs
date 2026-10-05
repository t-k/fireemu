//! The `authtype` and `authid` of a 2nd gen Firestore event with auth context, against the 16
//! frames of two FE production recordings: v5 (run `functions-events-formal-20261004T182904Z-
//! a9621bfae74fe9bc`) and v7 (run `functions-events-formal-20261005T041505Z-d3fd3faa3e0dc702`), two
//! passes each, handler `fsWrittenWithAuthContextV2`. Frames are quoted by run and index in that
//! run's `production-run.json` `frames` array; the fixture holds them with the insert ids.
//!
//! What production printed, in both runs and both passes: a write with the Firebase ID token of a
//! user (`fs-auth-client`) is `api_key` with the user's uid as the id; every write made with the
//! recorder's user credential (the admin writes, and the deletes of the client scenario) is `unknown`
//! with that credential's email as the id.
//!
//! The official emulator's Firestore emulator (`cloud-firestore-emulator-v1.22.0.jar`, class
//! `com.google.cloud.datastore.emulator.impl.events.FunctionsEmulatorEventPublisher`) sends the
//! constants `ce-authtype: unknown` and `ce-authid: fake-auth-id@gmail.com` for every event of this
//! kind, whoever wrote.

use fireemu_adapter_functions::events::{auth_context_for, AuthContextNaming};
use serde_json::Value;

fn frames() -> Vec<Value> {
    let text = include_str!("fixtures/production-firestore-auth-context-v5-v7-frames.json");
    let doc: Value = serde_json::from_str(text).unwrap();
    doc["frames"].as_array().unwrap().clone()
}

fn label(frame: &Value) -> String {
    format!(
        "{} frame {} ({})",
        frame["run"], frame["index"], frame["scenario"]
    )
}

#[test]
fn the_fixture_holds_two_passes_of_both_scenarios_in_both_recordings() {
    let frames = frames();
    assert_eq!(frames.len(), 16);
    for run in ["v5", "v7"] {
        let of = |scenario: &str| {
            frames
                .iter()
                .filter(|frame| frame["run"] == run && frame["scenario"] == scenario)
                .count()
        };
        // Two passes: the admin scenario writes and deletes with one credential, the client
        // scenario creates with an ID token and deletes with the credential.
        assert_eq!(of("fs-auth-admin"), 4, "{run}");
        assert_eq!(of("fs-auth-client"), 4, "{run}");
    }
}

#[test]
fn production_is_stable_across_both_recordings_and_all_four_passes() {
    let frames = frames();
    let types = |run: &str, scenario: &str| {
        let mut found: Vec<String> = frames
            .iter()
            .filter(|f| f["run"] == run && f["scenario"] == scenario)
            .map(|f| f["authType"].as_str().unwrap().to_owned())
            .collect();
        found.sort();
        found
    };
    for run in ["v5", "v7"] {
        assert_eq!(types(run, "fs-auth-admin"), ["unknown"; 4], "{run}");
        assert_eq!(
            types(run, "fs-auth-client"),
            ["api_key", "api_key", "unknown", "unknown"],
            "{run}"
        );
    }
    // The ids: a Firebase uid (28 characters) for every api_key frame, the operator's email for
    // every unknown one.
    for frame in &frames {
        let id = frame["authId"].as_str().unwrap();
        match frame["authType"].as_str().unwrap() {
            "api_key" => assert!(
                id.len() == 28 && id.bytes().all(|b| b.is_ascii_alphanumeric()),
                "{}: {id}",
                label(frame)
            ),
            _ => assert_eq!(id, "<operator email>", "{}", label(frame)),
        }
    }
}

#[test]
fn production_naming_prints_an_id_token_writer_as_api_key_with_the_uid() {
    for frame in frames().iter().filter(|f| f["authType"] == "api_key") {
        let uid = frame["authId"].as_str().unwrap();
        // The local principal of an ID-token write is an `app_user` carrying the uid.
        assert_eq!(
            auth_context_for(AuthContextNaming::Production, "app_user", Some(uid)),
            ("api_key", Some(uid)),
            "{}",
            label(frame)
        );
    }
}

#[test]
fn production_naming_prints_the_owner_credential_as_unknown_with_its_id() {
    for frame in frames().iter().filter(|f| f["authType"] == "unknown") {
        // The local owner principal is a `service_account` with the id `owner`; its own id is kept.
        assert_eq!(
            auth_context_for(
                AuthContextNaming::Production,
                "service_account",
                Some("owner")
            ),
            ("unknown", Some("owner")),
            "{}",
            label(frame)
        );
    }
}

#[test]
fn production_naming_keeps_the_principals_it_has_no_recording_for() {
    for (kind, id) in [
        ("unauthenticated", None),
        ("system", None),
        ("system", Some("u1")),
    ] {
        assert_eq!(
            auth_context_for(AuthContextNaming::Production, kind, id),
            (kind, id)
        );
    }
}

#[test]
fn official_naming_is_the_two_constants_the_official_emulator_sends_for_every_writer() {
    for (kind, id) in [
        ("app_user", Some("alice")),
        ("service_account", Some("owner")),
        ("unauthenticated", None),
        ("system", None),
    ] {
        assert_eq!(
            auth_context_for(AuthContextNaming::Official, kind, id),
            ("unknown", Some("fake-auth-id@gmail.com")),
            "{kind}"
        );
    }
}

/// Production prints the credential's own identity: the operator's email for a user credential
/// (recorded) and, as documented but unrecorded, a service account's email. A principal that
/// carries such an identity keeps it; the local `owner` bearer has none and keeps `owner`, which
/// is the declared divergence of the admin-write row (the comparator masks the value of an
/// `unknown` row's id; see FUNCTIONS-EVENTS scope decision E10).
#[test]
fn a_credential_that_carries_an_identity_is_named_by_it_and_the_owner_bearer_stays_owner() {
    let email = "ops@demo-project.iam.gserviceaccount.com";
    assert_eq!(
        auth_context_for(
            AuthContextNaming::Production,
            "service_account",
            Some(email)
        ),
        ("unknown", Some(email))
    );
    assert_eq!(
        auth_context_for(
            AuthContextNaming::Production,
            "service_account",
            Some("owner")
        ),
        ("unknown", Some("owner"))
    );
    // Near misses: the id is never swapped for the other form, and a missing id stays missing.
    assert_ne!(
        auth_context_for(
            AuthContextNaming::Production,
            "service_account",
            Some(email)
        )
        .1,
        Some("owner")
    );
    assert_eq!(
        auth_context_for(AuthContextNaming::Production, "service_account", None),
        ("unknown", None)
    );
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Strict never changes the id it is given, only the type, for the two recorded kinds; the
        // emulator profile ignores the id altogether and sends the official constants.
        #[test]
        fn the_id_is_kept_by_the_production_naming_and_dropped_by_the_official_one(
            id in "[ -~]{0,40}",
        ) {
            prop_assert_eq!(
                auth_context_for(AuthContextNaming::Production, "service_account", Some(&id)),
                ("unknown", Some(id.as_str()))
            );
            prop_assert_eq!(
                auth_context_for(AuthContextNaming::Production, "app_user", Some(&id)),
                ("api_key", Some(id.as_str()))
            );
            for kind in ["app_user", "service_account", "unauthenticated", "system"] {
                prop_assert_eq!(
                    auth_context_for(AuthContextNaming::Official, kind, Some(&id)),
                    ("unknown", Some("fake-auth-id@gmail.com"))
                );
            }
        }
    }
}
