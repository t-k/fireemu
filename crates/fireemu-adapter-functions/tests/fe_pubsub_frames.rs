//! The Pub/Sub event the runtime builds, against the 16 Pub/Sub frames of two FE production
//! recordings: v5 (run `functions-events-formal-20261004T182904Z-a9621bfae74fe9bc`) and v7 (run
//! `functions-events-formal-20261005T041505Z-d3fd3faa3e0dc702`), 4 messages each, every message seen
//! by a 1st gen handler (`pubsubPublishedV1`) and a 2nd gen one (`pubsubPublishedV2`). Frames are
//! quoted by run and index in that run's `production-run.json` `frames` array; the fixture
//! `fixtures/production-pubsub-v5-v7-frames.json` holds them with the insert ids.
//!
//! Compared: the wire members and their forms, not the instants or ids of the recording, which the
//! test feeds back in. Known divergence, not tested away: production's `CloudEvent` carries a
//! `traceparent` extension attribute (the runtime sends none, as for Storage).

use fireemu_adapter_functions::events::{eventarc_subscription_id, pubsub_event};
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;
use serde_json::{json, Value};

fn fixture() -> Vec<Value> {
    let text = include_str!("fixtures/production-pubsub-v5-v7-frames.json");
    let doc: Value = serde_json::from_str(text).unwrap();
    doc["frames"].as_array().unwrap().clone()
}

fn of_handler(frames: &[Value], handler: &str) -> Vec<Value> {
    frames
        .iter()
        .filter(|frame| frame["handler"] == handler)
        .cloned()
        .collect()
}

fn digits(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|byte| byte.is_ascii_digit())
}

/// `2026-10-04T19:09:46.102Z`: exactly three fraction digits and a `Z`.
fn millisecond_iso(text: &str) -> bool {
    let Some((whole, fraction)) = text.strip_suffix('Z').and_then(|t| t.rsplit_once('.')) else {
        return false;
    };
    digits(fraction, 3) && whole.len() == 19 && whole.as_bytes()[10] == b'T'
}

/// `eventarc-<region>-<function lowercased>-<6 digits>-sub-<3 digits>` with the two numbers masked.
fn masked_subscription(id: &str) -> Option<String> {
    let rest = id.strip_prefix("eventarc-")?;
    let (head, sub) = rest.rsplit_once("-sub-")?;
    let (head, function_number) = head.rsplit_once('-')?;
    (digits(function_number, 6) && digits(sub, 3))
        .then(|| format!("eventarc-{head}-<6 digits>-sub-<3 digits>"))
}

fn topic_of(source: &str) -> &str {
    source
        .strip_prefix("//pubsub.googleapis.com/projects/fireemu-oracle-events/topics/")
        .unwrap()
}

/// The event the runtime builds for the message a recorded 2nd gen frame shows.
fn rebuilt(event: &Value) -> Value {
    let message = &event["data"]["message"];
    let mut input = json!({"data": message["data"], "attributes": message["attributes"]});
    if let Some(key) = message.get("orderingKey") {
        input["orderingKey"] = key.clone();
    }
    pubsub_event(
        event["id"].as_str().unwrap(),
        "fireemu-oracle-events",
        "us-central1",
        "pubsubPublishedV2",
        topic_of(event["source"].as_str().unwrap()),
        &input,
        LogicalInstant::parse_rfc3339(event["time"].as_str().unwrap()).unwrap(),
    )
}

fn sorted_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

fn names(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key.as_str().unwrap().to_owned())
        .collect();
    keys.sort();
    keys
}

#[test]
fn the_fixture_holds_four_messages_of_each_recording_seen_by_both_handlers() {
    let frames = fixture();
    assert_eq!(frames.len(), 16);
    for run in ["v5", "v7"] {
        for handler in ["pubsubPublishedV1", "pubsubPublishedV2"] {
            let count = frames
                .iter()
                .filter(|frame| frame["run"] == run && frame["handler"] == handler)
                .count();
            assert_eq!(count, 4, "{run} {handler}");
        }
    }
    // A 1st gen frame and the 2nd gen frame right after it show the same message.
    for pair in frames.chunks(2) {
        assert_eq!(pair[0]["handler"], "pubsubPublishedV1");
        assert_eq!(pair[1]["handler"], "pubsubPublishedV2");
        assert_eq!(
            pair[0]["index"].as_u64().unwrap() + 1,
            pair[1]["index"].as_u64().unwrap()
        );
        assert_eq!(
            pair[0]["event"]["context"]["eventId"],
            pair[1]["event"]["id"]
        );
        assert_eq!(
            pair[0]["event"]["context"]["timestamp"],
            pair[1]["event"]["time"]
        );
    }
}

#[test]
fn production_ids_are_seventeen_decimal_digits_in_every_frame() {
    // v5 frames 133 to 136 and 270 to 273, v7 frames 135 to 138 and 274 to 277.
    for frame in fixture() {
        let (id, message_id) = if frame["handler"] == "pubsubPublishedV1" {
            (frame["event"]["context"]["eventId"].clone(), Value::Null)
        } else {
            (
                frame["event"]["id"].clone(),
                frame["event"]["data"]["message"]["messageId"].clone(),
            )
        };
        let label = format!("{} frame {}", frame["run"], frame["index"]);
        assert!(digits(id.as_str().unwrap(), 17), "{label}: {id}");
        if !message_id.is_null() {
            assert_eq!(message_id, id, "{label}: messageId is the event id");
        }
    }
}

#[test]
fn the_runtime_event_has_the_wire_members_of_every_recorded_v2_frame() {
    for frame in of_handler(&fixture(), "pubsubPublishedV2") {
        let recorded = &frame["event"];
        let label = format!("{} frame {}", frame["run"], frame["index"]);
        let built = rebuilt(recorded);
        // The members of the CloudEvent as it arrives: the SDK adds `context` and `message` for the
        // handler, and the delivery adds `traceparent`.
        let mut wire = names(&recorded["eventKeys"]);
        wire.retain(|key| !["context", "message", "traceparent"].contains(&key.as_str()));
        assert_eq!(sorted_keys(&built), wire, "{label}");
        for key in ["id", "time", "type", "source", "specversion"] {
            assert_eq!(built[key], recorded[key], "{label}: {key}");
        }
        // No `datacontenttype`: the handler's `event.datacontenttype` is null and not a key.
        assert!(recorded["datacontenttype"].is_null(), "{label}");
        assert!(
            !names(&recorded["eventKeys"]).contains(&"datacontenttype".to_owned()),
            "{label}"
        );
        assert!(built.get("datacontenttype").is_none(), "{label}: {built}");
        // The message: id, publish time as time, and the members of the SDK's `Message` (it adds
        // `json` and `toJSON`). The frames show the message as the SDK's `toJSON` prints it, so this
        // is the handler-visible form; production's wire form of the message is not itself recorded.
        let mut message_members = names(&recorded["extensionAttributes"]["message"]["keys"]);
        message_members.retain(|key| !["json", "toJSON"].contains(&key.as_str()));
        assert_eq!(
            sorted_keys(&built["data"]["message"]),
            message_members,
            "{label}"
        );
        assert_eq!(
            built["data"]["message"], recorded["data"]["message"],
            "{label}"
        );
        assert_eq!(
            recorded["time"], recorded["data"]["message"]["publishTime"],
            "{label}"
        );
        assert!(
            millisecond_iso(recorded["time"].as_str().unwrap()),
            "{label}"
        );
        assert!(millisecond_iso(built["time"].as_str().unwrap()), "{label}");
    }
}

#[test]
fn the_subscription_has_the_masked_shape_production_gives_and_the_numbers_are_per_deployment() {
    let frames = of_handler(&fixture(), "pubsubPublishedV2");
    let mut per_run = std::collections::BTreeMap::new();
    for frame in &frames {
        let recorded = frame["event"]["data"]["subscription"].as_str().unwrap();
        let id = recorded
            .strip_prefix("projects/fireemu-oracle-events/subscriptions/")
            .unwrap();
        let built = rebuilt(&frame["event"]);
        let built_id = built["data"]["subscription"]
            .as_str()
            .unwrap()
            .strip_prefix("projects/fireemu-oracle-events/subscriptions/")
            .unwrap()
            .to_owned();
        assert_eq!(
            masked_subscription(&built_id),
            masked_subscription(id),
            "{} frame {}",
            frame["run"],
            frame["index"]
        );
        assert_eq!(
            masked_subscription(id).unwrap(),
            "eventarc-us-central1-pubsubpublishedv2-<6 digits>-sub-<3 digits>"
        );
        per_run
            .entry(frame["run"].as_str().unwrap().to_owned())
            .or_insert_with(std::collections::BTreeSet::new)
            .insert(id.to_owned());
    }
    // One deployment keeps one subscription; the two deployments drew different numbers, so the
    // numbers are not a property of the function name and the emulator may derive them.
    assert_eq!(per_run["v5"].len(), 1);
    assert_eq!(per_run["v7"].len(), 1);
    assert_ne!(per_run["v5"], per_run["v7"]);
    assert_eq!(
        per_run["v5"].iter().next().unwrap(),
        "eventarc-us-central1-pubsubpublishedv2-834054-sub-834"
    );
    assert_eq!(
        per_run["v7"].iter().next().unwrap(),
        "eventarc-us-central1-pubsubpublishedv2-293232-sub-576"
    );
    assert_eq!(
        masked_subscription(&eventarc_subscription_id(
            "fireemu-oracle-events",
            "us-central1",
            "pubsubPublishedV2"
        ))
        .unwrap(),
        "eventarc-us-central1-pubsubpublishedv2-<6 digits>-sub-<3 digits>"
    );
}

#[test]
fn an_ordering_key_appears_exactly_when_the_message_has_one() {
    let frames = of_handler(&fixture(), "pubsubPublishedV2");
    let keyed = frames
        .iter()
        .filter(|frame| {
            frame["event"]["data"]["message"]
                .get("orderingKey")
                .is_some()
        })
        .count();
    assert_eq!(
        keyed, 4,
        "two messages of each recording were published with an ordering key"
    );
    for frame in &frames {
        let built = rebuilt(&frame["event"]);
        assert_eq!(
            built["data"]["message"].get("orderingKey"),
            frame["event"]["data"]["message"].get("orderingKey"),
            "{} frame {}",
            frame["run"],
            frame["index"]
        );
    }
}

proptest! {
    /// Whatever the instant, `time` and `publishTime` are one value with exactly three fraction
    /// digits, cut (not rounded) from the instant.
    #[test]
    fn the_event_time_is_the_publish_instant_cut_to_the_millisecond(
        seconds in 0_i64..4_000_000_000,
        nanos in 0_i128..1_000_000_000,
    ) {
        let instant = LogicalInstant::from_nanos(i128::from(seconds) * 1_000_000_000 + nanos);
        let event = pubsub_event("1", "p", "us-central1", "f", "t", &json!({}), instant);
        let time = event["time"].as_str().unwrap();
        prop_assert!(millisecond_iso(time), "{time}");
        prop_assert_eq!(&event["data"]["message"]["publishTime"], &event["time"]);
        let cut = LogicalInstant::parse_rfc3339(time).unwrap();
        let floor = i128::from(seconds) * 1_000_000_000 + nanos / 1_000_000 * 1_000_000;
        prop_assert_eq!(cut, LogicalInstant::from_nanos(floor));
    }

    /// Whatever the project, region and function, the subscription id has the recorded shape and
    /// is a fixed function of them.
    #[test]
    fn the_subscription_id_has_the_recorded_shape(
        project in "[a-z][a-z0-9-]{4,20}",
        region in "(us|europe|asia)-[a-z]{4,9}[1-9]",
        function in "[a-zA-Z][a-zA-Z0-9]{0,30}",
    ) {
        let id = eventarc_subscription_id(&project, &region, &function);
        let masked = masked_subscription(&id);
        prop_assert_eq!(
            masked,
            Some(format!("eventarc-{region}-{}-<6 digits>-sub-<3 digits>", function.to_lowercase()))
        );
        prop_assert_eq!(id, eventarc_subscription_id(&project, &region, &function));
    }
}
