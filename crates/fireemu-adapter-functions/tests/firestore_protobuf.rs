//! Rust-produced Firestore event data: independent decoder and real SDK corpus.
use base64::Engine as _;
use fireemu_adapter_functions::events::firestore_event_data_encoded;
use fireemu_adapter_grpc::encode::decode_document_name;
use fireemu_adapter_grpc::encode::encode_document;
use fireemu_core_firestore::store::{CommitVersion, Document};
use fireemu_core_firestore::value::{GeoPoint, Timestamp, Value};
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_firestore::google::firestore::v1 as pb;
use proptest::prelude::*;
use prost::Message as _;
use std::collections::BTreeMap;

fn document(n: i64) -> Document {
    Document {
        path: decode_document_name("projects/demo-proj/databases/(default)/documents/items/a")
            .unwrap(),
        fields: BTreeMap::from([("integer".into(), Value::Integer(n))]),
        create_time: LogicalInstant::from_nanos(1_000_000_000),
        update_time: LogicalInstant::from_nanos(2_123_456_000),
        version: CommitVersion::default(),
    }
}

#[test]
fn strict_data_is_binary_without_json_number_conversion() {
    let doc = document(i64::MAX);
    let encoded = firestore_event_data_encoded(None, Some(&doc), true);
    assert!(
        encoded.is_string(),
        "strict Gen2 IPC must carry base64 protobuf: {encoded}"
    );
}

#[test]
fn legacy_data_remains_json() {
    let doc = document(i64::MAX);
    let encoded = firestore_event_data_encoded(None, Some(&doc), false);
    assert_eq!(
        encoded["value"]["fields"]["integer"]["integerValue"],
        i64::MAX.to_string()
    );
}

#[derive(Clone, PartialEq, prost::Message)]
struct DecodedEvent {
    #[prost(message, optional, tag = "1")]
    after: Option<pb::Document>,
    #[prost(message, optional, tag = "2")]
    before: Option<pb::Document>,
    #[prost(message, optional, tag = "3")]
    mask: Option<pb::DocumentMask>,
}

fn decode(encoded: &serde_json::Value) -> DecodedEvent {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_str().unwrap())
        .unwrap();
    DecodedEvent::decode(bytes.as_slice()).unwrap()
}

fn all_values(n: i64) -> Document {
    let mut doc = document(n);
    doc.fields.extend(BTreeMap::from([
        ("null".into(), Value::Null),
        ("boolean".into(), Value::Boolean(true)),
        ("double".into(), Value::Double(1.5)),
        (
            "timestamp".into(),
            Value::Timestamp(Timestamp::new(-1, 123_456_789).unwrap()),
        ),
        ("string".into(), Value::String("é snow 雪".into())),
        ("bytes".into(), Value::Bytes(vec![0, 1, 255])),
        (
            "reference".into(),
            Value::Reference("projects/demo-proj/databases/(default)/documents/items/ref".into()),
        ),
        (
            "geo".into(),
            Value::GeoPoint(GeoPoint::new(-90.0, 180.0).unwrap()),
        ),
        (
            "array".into(),
            Value::Array(vec![
                Value::Integer(n),
                Value::Map(BTreeMap::from([(
                    "nested".into(),
                    Value::String("value".into()),
                )])),
            ]),
        ),
        (
            "map".into(),
            Value::Map(BTreeMap::from([(
                "a.b".into(),
                Value::Array(vec![Value::Boolean(false)]),
            )])),
        ),
        ("vector".into(), Value::Vector(vec![1.0, -2.5])),
    ]));
    doc
}

#[test]
fn all_event_sides_roundtrip_and_export_the_real_sdk_corpus() {
    let before = all_values(41);
    let after = all_values(42);
    let mut rows = Vec::new();
    for (kind, old, new) in [
        ("created", None, Some(&after)),
        ("deleted", Some(&before), None),
        ("updated", Some(&before), Some(&after)),
        ("written-create", None, Some(&after)),
        ("written-update", Some(&before), Some(&after)),
        ("written-delete", Some(&before), None),
    ] {
        let binary = firestore_event_data_encoded(old, new, true);
        let decoded = decode(&binary);
        assert_eq!(decoded.before, old.map(encode_document));
        assert_eq!(decoded.after, new.map(encode_document));
        assert_eq!(decoded.mask.is_some(), old.is_some() && new.is_some());
        if let Some(mask) = decoded.mask {
            assert_eq!(mask.field_paths, ["array", "integer"]);
        }
        rows.push(serde_json::json!({"kind":kind,"json":firestore_event_data_encoded(old,new,false),"protobuf":binary}));
    }
    if let Ok(path) = std::env::var("FE_FIRESTORE_CORPUS") {
        // Export evidence only once; repeated checks must choose a new artifact path.
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        serde_json::to_writer(file, &rows).unwrap();
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]
    #[test]
    fn encoded_documents_roundtrip(n in any::<i64>(), bytes in prop::collection::vec(any::<u8>(), 0..64), text in ".{0,40}", before in any::<bool>(), after in any::<bool>()) {
        let mut doc = all_values(n);
        doc.fields.insert("bytes".into(), Value::Bytes(bytes));
        doc.fields.insert("string".into(), Value::String(text));
        let old = before.then_some(&doc);
        let new = after.then_some(&doc);
        let decoded = decode(&firestore_event_data_encoded(old, new, true));
        prop_assert_eq!(decoded.before, old.map(encode_document));
        prop_assert_eq!(decoded.after, new.map(encode_document));
    }
}

#[test]
fn floating_point_and_empty_container_boundaries_survive() {
    for number in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        -0.0,
        f64::MIN_POSITIVE,
    ] {
        let mut doc = document(i64::MIN);
        doc.fields.insert("double".into(), Value::Double(number));
        doc.fields.insert("map".into(), Value::Map(BTreeMap::new()));
        doc.fields.insert("array".into(), Value::Array(Vec::new()));
        doc.fields
            .insert("vector".into(), Value::Vector(Vec::new()));
        let mut decoded = decode(&firestore_event_data_encoded(None, Some(&doc), true))
            .after
            .unwrap();
        let double = decoded.fields.remove("double").unwrap();
        let Some(pb::value::ValueType::DoubleValue(actual)) = double.value_type else {
            panic!("double type lost")
        };
        assert_eq!(actual.to_bits(), number.to_bits());
        doc.fields.remove("double");
        assert_eq!(decoded, encode_document(&doc));
    }
}
