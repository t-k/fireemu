//! Regressions for malformed REST bytes and transaction payloads.

use std::sync::{Arc, Mutex};

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::json::{base64_decode, base64_decode_field, base64_encode};
use fireemu_adapter_grpc::rest::{RestRequest, RestResponse, RestState};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const DOCS: &str = "/v1/projects/demo-app/databases/(default)/documents";
const RESOURCE: &str = "projects/demo-app/databases/(default)/documents";

fn state(strict: bool) -> RestState {
    let gateway = Gateway {
        enforce_limits: strict,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: if strict {
                IndexValidationPolicy::Production
            } else {
                IndexValidationPolicy::Emulator
            },
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(Mutex::new(VirtualClock::new(
        LogicalInstant::from_unix_seconds(1_788_004_860),
    )));
    RestState {
        local: Arc::new(LocalBackend::new(gateway.clone(), clock, 7)),
        gateway: Arc::new(gateway),
        rules: None,
        app_check: None,
        control_token: None,
    }
}

fn call(state: &RestState, method: &str, path: &str, body: Value) -> RestResponse {
    state.handle(&RestRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        query: String::new(),
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        remote_peer: false,
        browser_metadata: false,
        app_check: Vec::new(),
        body,
        batch_field_order: Vec::new(),
        key_order: fireemu_adapter_grpc::rest::json_syntax::KeyOrder::default(),
    })
}

fn require_base64_refusal(response: &RestResponse) {
    assert_eq!(response.status, 400, "{:?}", response.body);
    assert_eq!(response.body["error"]["status"], "INVALID_ARGUMENT");
    assert!(response.body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Base64 decoding failed"));
}

#[test]
fn decoder_rejects_truncated_and_malformed_padding() {
    for input in [
        "A", "A=", "A==", "AAAAA", "Zm9vA", "=Zg", "Z=g=", "Zg=", "Zg===", "Zm8==", "Zm9v=",
        "Zg==YQ==",
    ] {
        assert!(base64_decode(input).is_err(), "accepted {input:?}");
    }
}

#[test]
fn decoder_preserves_valid_empty_optional_padding_and_url_safe_bytes() {
    for (encoded, expected) in [
        ("", b"".as_slice()),
        ("Zg", b"f".as_slice()),
        ("Zg==", b"f".as_slice()),
        ("_w", &[255][..]),
        ("-_8", &[251, 255][..]),
    ] {
        assert_eq!(base64_decode(encoded).unwrap(), expected, "{encoded:?}");
    }
}

#[test]
fn decoder_preserves_crlf_and_unused_low_bit_behavior() {
    for input in ["Z\rg\n==\r\n", "Zg=\r=", "Zh==", "Zh"] {
        assert_eq!(base64_decode(input).unwrap(), b"f", "{input:?}");
    }
    assert_eq!(base64_decode("\r\n").unwrap(), Vec::<u8>::new());
}

#[test]
fn decoder_roundtrips_encoded_byte_domain() {
    for length in 0..=1024 {
        let bytes: Vec<u8> = (0_u8..=255).cycle().take(length).collect();
        let encoded = base64_encode(&bytes);
        let unpadded = encoded.trim_end_matches('=');
        let url_safe = encoded.replace('+', "-").replace('/', "_");
        for input in [
            encoded.as_str(),
            unpadded,
            url_safe.as_str(),
            url_safe.trim_end_matches('='),
        ] {
            assert_eq!(base64_decode(input).unwrap(), bytes, "length {length}");
        }
    }
}

#[test]
fn decoder_error_keeps_proto_field_context() {
    let error = base64_decode_field("transaction", "A").unwrap_err();
    assert_eq!(
        error.0,
        "Invalid value at 'transaction' (TYPE_BYTES), Base64 decoding failed for \"A\""
    );
}

#[test]
fn malformed_transaction_is_refused_before_commit_writes() {
    for strict in [false, true] {
        for encoded in ["A", "AAAAA", "====", "Zg==YQ=="] {
            let s = state(strict);
            let original = json!({"fields": {"v": {"integerValue": "7"}}});
            assert_eq!(
                call(
                    &s,
                    "PATCH",
                    &format!("{DOCS}/base64/existing"),
                    original.clone()
                )
                .status,
                200
            );

            let response = call(
                &s,
                "POST",
                &format!("{DOCS}:commit"),
                json!({
                    "transaction": encoded,
                    "writes": [
                        {"update": {"name": format!("{RESOURCE}/base64/existing"),
                                    "fields": {"v": {"integerValue": "8"}}}},
                        {"update": {"name": format!("{RESOURCE}/base64/new"),
                                    "fields": {"v": {"integerValue": "9"}}}}
                    ]
                }),
            );
            require_base64_refusal(&response);

            let existing = call(&s, "GET", &format!("{DOCS}/base64/existing"), json!({}));
            assert_eq!(existing.body["fields"], original["fields"]);
            assert_eq!(
                call(&s, "GET", &format!("{DOCS}/base64/new"), json!({})).status,
                404
            );
        }
    }
}

#[test]
fn malformed_bytes_are_refused_without_mutating_document() {
    for strict in [false, true] {
        for encoded in ["A", "AAAAA", "Zg=", "Zg==YQ=="] {
            let s = state(strict);
            let original = json!({"fields": {"blob": {"bytesValue": "AQID"}}});
            assert_eq!(
                call(
                    &s,
                    "PATCH",
                    &format!("{DOCS}/base64/existing"),
                    original.clone()
                )
                .status,
                200
            );
            let response = call(
                &s,
                "PATCH",
                &format!("{DOCS}/base64/existing"),
                json!({"fields": {"blob": {"bytesValue": encoded}}}),
            );
            require_base64_refusal(&response);
            let existing = call(&s, "GET", &format!("{DOCS}/base64/existing"), json!({}));
            assert_eq!(existing.body["fields"], original["fields"]);
        }
    }
}

#[test]
fn malformed_second_commit_write_does_not_publish_first_write() {
    let s = state(true);
    let response = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [
            {"update": {"name": format!("{RESOURCE}/base64/first"),
                        "fields": {"v": {"integerValue": "1"}}}},
            {"update": {"name": format!("{RESOURCE}/base64/second"),
                        "fields": {"blob": {"bytesValue": "A"}}}}
        ]}),
    );
    require_base64_refusal(&response);
    for name in ["first", "second"] {
        assert_eq!(
            call(&s, "GET", &format!("{DOCS}/base64/{name}"), json!({})).status,
            404
        );
    }
}

#[test]
fn malformed_commit_bytes_match_saved_production_error_message() {
    let s = state(true);
    let response = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes": [{"update": {
            "name": format!("{RESOURCE}/base64/exact-error"),
            "fields": {"value": {"bytesValue": "!!!"}}
        }}]}),
    );

    assert_eq!(response.status, 400);
    assert_eq!(response.body["error"]["status"], "INVALID_ARGUMENT");
    assert_eq!(
        response.body["error"]["message"],
        "Invalid value at 'writes[0].update.fields[0].value.bytes_value' (TYPE_BYTES), Base64 decoding failed for \"!!!\""
    );
}

#[test]
fn valid_empty_and_absent_transaction_and_token_commit_remain_accepted() {
    for transaction in [None, Some("")] {
        let s = state(true);
        let mut body = json!({"writes": [{"update": {
            "name": format!("{RESOURCE}/base64/valid"),
            "fields": {"blob": {"bytesValue": "_w"}}
        }}]});
        if let Some(transaction) = transaction {
            body["transaction"] = json!(transaction);
        }
        let response = call(&s, "POST", &format!("{DOCS}:commit"), body);
        assert_eq!(response.status, 200, "{:?}", response.body);
        let got = call(&s, "GET", &format!("{DOCS}/base64/valid"), json!({}));
        assert_eq!(got.status, 200);
        assert_eq!(got.body["fields"]["blob"]["bytesValue"], "/w==");
    }

    let s = state(true);
    let begun = call(
        &s,
        "POST",
        &format!("{DOCS}:beginTransaction"),
        json!({"options": {"readWrite": {}}}),
    );
    assert_eq!(begun.status, 200, "{:?}", begun.body);
    let token = begun.body["transaction"].as_str().unwrap();
    assert!(!base64_decode(token).unwrap().is_empty());
    let committed = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({
            "transaction": token,
            "writes": [{"update": {"name": format!("{RESOURCE}/base64/transactional"),
                                   "fields": {"v": {"integerValue": "1"}}}}]
        }),
    );
    assert_eq!(committed.status, 200, "{:?}", committed.body);
    assert_eq!(
        call(
            &s,
            "GET",
            &format!("{DOCS}/base64/transactional"),
            json!({})
        )
        .status,
        200
    );
}

#[test]
fn typed_bytes_recorded_strict_rejections_preserve_ordinary_behavior() {
    for text in [
        "QUJD\nQUJD",
        "QUJD\rQUJD",
        "QUJD\r\nQUJD",
        "+_AA",
        "-/AA",
        "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0\r\nQUJD",
        "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0\nQUJD",
    ] {
        for strict in [true, false] {
            let s = state(strict);
            let response = call(
                &s,
                "POST",
                &format!("{DOCS}:commit"),
                json!({"writes": [{"update": {
                    "name": format!("{RESOURCE}/base64/test"), "fields": {"b": {"bytesValue": text}}
                }}]}),
            );
            if strict {
                let field = "writes[0].update.fields[0].value.bytes_value";
                let message = format!("Invalid value at '{field}' (TYPE_BYTES), Base64 decoding failed for \"{text}\"");
                assert_eq!(response.status, 400, "{text:?}");
                assert_eq!(response.body["error"]["message"], message);
                assert_eq!(
                    response.body["error"]["details"][0]["fieldViolations"][0],
                    json!({"field":field,"description":message})
                );
            } else {
                assert_eq!(response.status, 200, "{text:?}: {:?}", response.body);
            }
            let got = call(&s, "GET", &format!("{DOCS}/base64/test"), Value::Null);
            assert_eq!(got.status, if strict { 404 } else { 200 }, "{text:?}");
        }
    }
}

#[test]
fn typed_bytes_proto_alias_is_accepted_in_both_profiles() {
    for strict in [true, false] {
        let s = state(strict);
        let response = call(
            &s,
            "POST",
            &format!("{DOCS}:commit"),
            json!({"writes": [{"update": {
                "name": format!("{RESOURCE}/base64/alias"), "fields": {"b": {"bytes_value": "QUJD"}}
            }}]}),
        );
        assert_eq!(response.status, 200, "{:?}", response.body);
        let got = call(&s, "GET", &format!("{DOCS}/base64/alias"), Value::Null);
        assert_eq!(got.body["fields"]["b"]["bytesValue"], "QUJD");
    }
}

#[test]
fn typed_bytes_cursor_refusal_uses_streamed_bad_request() {
    let s = state(true);
    let text = "Ag==\n";
    let response = call(
        &s,
        "POST",
        &format!("{DOCS}:runQuery"),
        json!({"structuredQuery": {
            "from":[{"collectionId":"bq"}], "orderBy":[{"field":{"fieldPath":"b"},"direction":"ASCENDING"}],
            "startAt":{"values":[{"bytesValue":text}],"before":true}
        }}),
    );
    let field = "structured_query.start_at.values[0].bytes_value";
    let message =
        format!("Invalid value at '{field}' (TYPE_BYTES), Base64 decoding failed for \"{text}\"");
    assert_eq!(response.status, 400);
    assert_eq!(response.body[0]["error"]["message"], message);
    assert_eq!(
        response.body[0]["error"]["details"][0]["fieldViolations"][0],
        json!({"field":field,"description":message})
    );
}

#[test]
fn typed_bytes_pict_generated_cases() {
    let cases = [
        ("strict", "lf", "camel", "commit"),
        ("strict", "cr", "camel", "commit"),
        ("strict", "crlf", "camel", "cursor"),
        ("strict", "mixed_plus", "camel", "commit"),
        ("strict", "mixed_minus", "camel", "commit"),
        ("ordinary", "lf", "camel", "commit"),
        ("ordinary", "mixed_plus", "camel", "commit"),
        ("strict", "standard", "snake", "commit"),
        ("ordinary", "standard", "snake", "commit"),
        ("strict", "urlsafe", "camel", "commit"),
        ("strict", "unpadded", "camel", "commit"),
        ("strict", "standard", "camel", "cursor"),
        ("ordinary", "crlf", "snake", "cursor"),
        ("ordinary", "urlsafe", "snake", "cursor"),
        ("strict", "mixed_plus", "snake", "cursor"),
        ("ordinary", "mixed_minus", "snake", "cursor"),
        ("strict", "crlf", "snake", "commit"),
        ("ordinary", "unpadded", "snake", "cursor"),
        ("ordinary", "lf", "snake", "cursor"),
        ("ordinary", "cr", "snake", "cursor"),
    ];
    for (profile, kind, spelling, surface) in cases {
        let strict = profile == "strict";
        let text = match kind {
            "standard" => "QUJD",
            "urlsafe" => "_w==",
            "unpadded" => "_w",
            "lf" => "QUJD\nQUJD",
            "cr" => "QUJD\rQUJD",
            "crlf" => "QUJD\r\nQUJD",
            "mixed_plus" => "+_AA",
            "mixed_minus" => "-/AA",
            _ => unreachable!(),
        };
        let key = if spelling == "snake" {
            "bytes_value"
        } else {
            "bytesValue"
        };
        let v = json!({key: text});
        let s = state(strict);
        let response = if surface == "commit" {
            call(
                &s,
                "POST",
                &format!("{DOCS}:commit"),
                json!({"writes":[{"update":{"name":format!("{RESOURCE}/pict/a"),"fields":{"b":v}}}]}),
            )
        } else {
            call(
                &s,
                "POST",
                &format!("{DOCS}:runQuery"),
                json!({"structuredQuery":{"from":[{"collectionId":"pict"}],"orderBy":[{"field":{"fieldPath":"b"},"direction":"ASCENDING"}],"startAt":{"values":[v],"before":true}}}),
            )
        };
        let invalid = matches!(kind, "lf" | "cr" | "crlf" | "mixed_plus" | "mixed_minus");
        assert_eq!(
            response.status,
            if strict && invalid { 400 } else { 200 },
            "{profile} {kind} {spelling} {surface}: {:?}",
            response.body
        );
    }
}

#[test]
fn typed_bytes_invalid_later_write_is_atomic() {
    let s = state(true);
    let existing = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes":[{"update":{"name":format!("{RESOURCE}/atomic/existing"),"fields":{"b":{"bytesValue":"AQID"}}}}]}),
    );
    assert_eq!(existing.status, 200);
    let failed = call(
        &s,
        "POST",
        &format!("{DOCS}:commit"),
        json!({"writes":[
            {"update":{"name":format!("{RESOURCE}/atomic/existing"),"fields":{"b":{"bytesValue":"BAUG"}}}},
            {"update":{"name":format!("{RESOURCE}/atomic/new"),"fields":{"b":{"bytesValue":"QUJD\nQUJD"}}}}
        ]}),
    );
    assert_eq!(failed.status, 400);
    assert_eq!(
        failed.body["error"]["details"][0]["fieldViolations"][0]["field"],
        "writes[1].update.fields[0].value.bytes_value"
    );
    let existing = call(&s, "GET", &format!("{DOCS}/atomic/existing"), Value::Null);
    assert_eq!(existing.body["fields"]["b"]["bytesValue"], "AQID");
    let new = call(&s, "GET", &format!("{DOCS}/atomic/new"), Value::Null);
    assert_eq!(new.status, 404);
}

proptest::proptest! {
    #[test]
    fn typed_bytes_roundtrip_and_inserted_newline(bytes in proptest::collection::vec(proptest::num::u8::ANY, 3..48)) {
        let encoded = base64_encode(&bytes);
        let broken = format!("{}\n{}", &encoded[..4], &encoded[4..]);
        for strict in [true, false] {
            let s = state(strict);
            let valid = call(&s, "POST", &format!("{DOCS}:commit"), json!({"writes":[{"update":{"name":format!("{RESOURCE}/property/valid"),"fields":{"b":{"bytesValue":encoded}}}}]}));
            proptest::prop_assert_eq!(valid.status, 200);
            let got = call(&s, "GET", &format!("{DOCS}/property/valid"), Value::Null);
            proptest::prop_assert_eq!(&got.body["fields"]["b"]["bytesValue"], &json!(encoded));
            let changed = call(&s, "POST", &format!("{DOCS}:commit"), json!({"writes":[{"update":{"name":format!("{RESOURCE}/property/broken"),"fields":{"b":{"bytesValue":broken}}}}]}));
            proptest::prop_assert_eq!(changed.status, if strict {400} else {200});
        }
    }
}
