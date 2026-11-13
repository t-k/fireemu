use base64::Engine as _;
use serde_json::{json, Value};

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn enqueue_body(encoded: &str) -> Value {
    json!({"task": {"httpRequest": {"url": "", "body": encoded}}})
}

#[test]
fn emulator_deadline_keeps_the_previous_integer_or_default_interpretation() {
    for (input, expected) in [("15.5s", 60), ("-1s", 60), ("NaNs", 60), ("17s", 17)] {
        let mut body = enqueue_body(&encode(b"null"));
        body["task"]["dispatchDeadline"] = json!(input);
        let task = crate::tasks::accept("demo", "us-central1", "q", "unused", &body, 1).unwrap();
        assert_eq!(task.dispatch_deadline_seconds, expected, "input {input}");
    }
}

#[test]
fn response_view_defaults_to_basic_and_decodes_known_enum_values() {
    assert_eq!(crate::tasks::response_view("/task"), Ok(false));
    assert_eq!(
        crate::tasks::response_view("/task?responseView=BASIC"),
        Ok(false)
    );
    assert_eq!(
        crate::tasks::response_view("/task?responseView=VIEW_UNSPECIFIED"),
        Ok(false)
    );
    assert_eq!(
        crate::tasks::response_view("/task?responseView=%46ULL"),
        Ok(true)
    );
    assert_eq!(
        crate::tasks::response_view("/task?other=x&responseView=FULL"),
        Ok(true)
    );
    assert!(crate::tasks::response_view("/task?responseView=bad").is_err());
    assert!(crate::tasks::response_view("/task?responseView=%XZ").is_err());
}

#[test]
fn valid_json_null_is_distinct_from_an_invalid_raw_body() {
    let task = crate::tasks::accept(
        "demo",
        "us-central1",
        "q",
        "http://unused",
        &enqueue_body(&encode(b"null")),
        1,
    )
    .unwrap();
    assert_eq!(task.body, Value::Null);
    assert_eq!(task.body_json_error, None);
}

#[test]
fn empty_body_bytes_are_preserved() {
    let task = crate::tasks::accept(
        "demo",
        "us-central1",
        "q",
        "http://unused",
        &enqueue_body(&encode(b"")),
        1,
    )
    .unwrap();
    assert_eq!(task.delivery_body(), b"");
    assert!(task.body_json_error.is_some());
}

#[test]
fn arbitrary_non_json_body_bytes_are_preserved_for_dispatch() {
    let raw = [0xff, 0xfe, 0x00];
    let task = crate::tasks::accept(
        "demo",
        "us-central1",
        "q",
        "http://unused",
        &enqueue_body(&encode(&raw)),
        1,
    )
    .expect("strict tasks retain arbitrary HTTP body bytes");
    assert_eq!(task.delivery_body(), raw);
    assert!(task.body_json_error.is_some());
}

proptest::proptest! {
    #[test]
    fn base64_encoding_matches_standard_for_arbitrary_bytes(
        bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)
    ) {
        proptest::prop_assert_eq!(
            crate::tasks::encode_base64(&bytes),
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        );
    }
}

#[test]
fn generated_pict_rows_drive_body_and_view_contracts() {
    const CASES: &str = include_str!("../tests/data/task-get-raw-body-pict.tsv");
    let mut lines = CASES.lines();
    assert_eq!(lines.next(), Some("Operation\tBody\tView\tProfile"));
    let mut rows = 0;
    for line in lines {
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(fields.len(), 4, "malformed generated row: {line}");
        let [operation, body_kind, view, profile] = fields.as_slice() else {
            unreachable!();
        };
        let raw = match *body_kind {
            "json" => br#"{"data":1}"#.as_slice(),
            "non_json_utf8" => b"plain text".as_slice(),
            "binary" => &[0xff, 0x00, 0x7f],
            "empty" => b"".as_slice(),
            other => panic!("unexpected body value {other}"),
        };
        let request = enqueue_body(&encode(raw));
        let task = crate::tasks::accept("p", "us-central1", "q", "http://function", &request, 1)
            .expect("PICT body is base64");
        assert_eq!(task.delivery_body(), raw, "{line}");
        if *profile == "emulator" && *body_kind != "json" {
            assert!(task.body_json_error.is_some(), "{line}");
        }
        let target = match *view {
            "BASIC" => "/task?responseView=BASIC",
            "FULL" => "/task?responseView=FULL",
            "invalid_or_absent" => "/task",
            other => panic!("unexpected view value {other}"),
        };
        let full = crate::tasks::response_view(target).unwrap_or(false);
        if *operation != "get_missing" {
            let observation = crate::task_scheduler::TaskObservation {
                task: std::sync::Arc::new(task),
                schedule_time: None,
                dispatch_count: 0,
                response_count: 0,
                first_attempt: None,
                last_attempt: None,
            };
            let answer = crate::tasks_production::get_answer(&observation, full);
            if full {
                assert_eq!(answer["httpRequest"]["body"], encode(raw), "{line}");
            } else {
                assert!(answer["httpRequest"].get("body").is_none(), "{line}");
            }
        }
        rows += 1;
    }
    assert_eq!(rows, 21);
}
