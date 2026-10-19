//! Property tests of the text layer: number formatting, rendering and parsing round trips,
//! namespace routing and percent decoding.

use fireemu_adapter_database::json_text::{java_double, output_json, parse, render, Style};
use fireemu_adapter_database::namespace::route;
use fireemu_adapter_database::request::percent_decode;
use fireemu_core_database::{Format, Json, Limits, Number, Path, ServerValueContext, Tree};
use proptest::prelude::*;

const NOW: ServerValueContext = ServerValueContext { now_millis: 1 };

fn key() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(vec![
            "a",
            "b",
            "0",
            "1",
            "2",
            "10",
            "-1",
            "01",
            "a b",
            "é",
            "\u{1F600}"
        ])
        .prop_map(str::to_owned),
        "[a-z0-9]{1,4}",
    ]
}

fn leaf() -> impl Strategy<Value = Json> {
    prop_oneof![
        any::<bool>().prop_map(Json::Bool),
        any::<i64>().prop_map(Json::int),
        any::<f64>()
            .prop_filter_map("finite", Number::from_f64)
            .prop_map(Json::Number),
        "[ -~\u{0}-\u{1f}é\u{1F600}]{0,6}".prop_map(Json::String),
    ]
}

fn priority() -> impl Strategy<Value = Option<Json>> {
    prop_oneof![
        3 => Just(None),
        1 => any::<i32>().prop_map(|n| Some(Json::int(i64::from(n)))),
        1 => "[a-z]{1,3}".prop_map(|s| Some(Json::String(s))),
    ]
}

fn value() -> impl Strategy<Value = Json> {
    let leafy = (leaf(), priority()).prop_map(|(leaf, priority)| match priority {
        None => leaf,
        Some(p) => Json::object([(".value", leaf), (".priority", p)]),
    });
    leafy.prop_recursive(3, 32, 5, |inner| {
        (prop::collection::btree_map(key(), inner, 1..5), priority()).prop_map(|(mut map, p)| {
            if let Some(p) = p {
                map.insert(".priority".to_owned(), p);
            }
            Json::Object(map)
        })
    })
}

fn store(value: &Json) -> Tree {
    let mut tree = Tree::new(Limits::default());
    tree.set(&Path::root(), value, NOW).unwrap();
    tree
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn java_doubles_read_back_to_the_same_double(value in any::<f64>().prop_filter("finite", |v| v.is_finite())) {
        let text = java_double(value);
        let back: f64 = text.parse().unwrap();
        prop_assert_eq!(back.to_bits(), value.to_bits(), "{}", text);
        // Exactly one point, a digit on both sides of it, and an exponent only outside
        // [10^-3, 10^7).
        let mantissa = text.split('E').next().unwrap();
        let (whole, fraction) = mantissa.trim_start_matches('-').split_once('.').unwrap();
        prop_assert!(!whole.is_empty() && !fraction.is_empty());
        let plain = value == 0.0 || (1e-3..1e7).contains(&value.abs());
        prop_assert_eq!(text.contains('E'), !plain, "{}", text);
        if !plain {
            prop_assert_eq!(whole.len(), 1, "{}", text);
        }
    }

    #[test]
    fn exported_text_reads_back_to_the_same_tree(v in value(), pretty in any::<bool>()) {
        let tree = store(&v);
        let style = if pretty { Style::Pretty } else { Style::Compact };
        let text = render(&output_json(tree.root(), Format::Export), style);
        let copy = store(&parse(&text).unwrap());
        prop_assert_eq!(copy, tree);
    }

    #[test]
    fn plain_text_reads_back_to_the_values_without_priorities(v in value()) {
        let tree = store(&v);
        let plain = render(&output_json(tree.root(), Format::Plain), Style::Compact);
        let copy = store(&parse(&plain).unwrap());
        prop_assert_eq!(
            render(&output_json(copy.root(), Format::Export), Style::Compact),
            plain
        );
    }

    #[test]
    fn compact_and_pretty_text_parse_to_the_same_json(v in value()) {
        let json = output_json(store(&v).root(), Format::Export);
        prop_assert_eq!(parse(&render(&json, Style::Pretty)).unwrap(), parse(&render(&json, Style::Compact)).unwrap());
    }

    #[test]
    fn routing_prefers_ns_then_host_and_accepts_only_lowercase_names(
        ns in prop::option::of("[A-Za-z0-9_.-]{0,8}"),
        label in "[A-Za-z0-9_-]{1,8}",
        suffix in prop::sample::select(vec![".firebaseio.com", ".europe-west1.firebasedatabase.app", ".localhost:9000", ""]),
    ) {
        let host = format!("{label}{suffix}");
        let routed = route(ns.as_deref(), Some(&host), "fake-server");
        let named = ns.clone().or_else(|| (!suffix.is_empty()).then(|| label.clone()));
        match (named, routed) {
            (None, Ok(name)) => prop_assert_eq!(name, "fake-server"),
            (None, Err(_)) => prop_assert!(false, "the default namespace was refused"),
            (Some(name), Ok(routed)) => {
                prop_assert_eq!(&routed, &name.to_ascii_lowercase());
                prop_assert!(routed.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'));
                prop_assert!(!routed.starts_with('-'));
            }
            (Some(name), Err(_)) => {
                let valid = name.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
                prop_assert!(!valid, "{} was refused", name);
            }
        }
    }

    #[test]
    fn percent_encoding_round_trips(text in "\\PC{0,12}") {
        let encoded = text.bytes().fold(String::new(), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
            out
        });
        prop_assert_eq!(percent_decode(&encoded), text.clone());
        // Text without `%` decodes to itself.
        let clean = text.replace('%', "");
        prop_assert_eq!(percent_decode(&clean), clean.clone());
    }
}

fn serde_value() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(serde_json::Value::from),
        any::<f64>()
            .prop_filter("finite", |v| v.is_finite())
            .prop_map(serde_json::Value::from),
        "\\PC{0,6}".prop_map(serde_json::Value::String),
        "[\u{0}-\u{1f}\"\\\\]{0,4}".prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(serde_json::Value::Array),
            prop::collection::btree_map("\\PC{0,4}", inner, 0..4)
                .prop_map(|m| serde_json::Value::Object(m.into_iter().collect())),
        ]
    })
}

fn from_serde(value: &serde_json::Value) -> Json {
    match value {
        serde_json::Value::Null => Json::Null,
        serde_json::Value::Bool(b) => Json::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Json::int(i),
            None => Json::Number(Number::from_f64(n.as_f64().unwrap()).unwrap()),
        },
        serde_json::Value::String(s) => Json::String(s.clone()),
        serde_json::Value::Array(items) => Json::Array(items.iter().map(from_serde).collect()),
        serde_json::Value::Object(map) => Json::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), from_serde(v)))
                .collect(),
        ),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn the_parser_agrees_with_serde_on_serde_text(value in serde_value(), pretty in any::<bool>()) {
        let text = if pretty {
            serde_json::to_string_pretty(&value).unwrap()
        } else {
            serde_json::to_string(&value).unwrap()
        };
        // serde writes the shortest round-trip digits, so the exact parse and serde's own
        // value agree.
        prop_assert_eq!(parse(&text).unwrap(), from_serde(&value));
    }
}

#[test]
fn malformed_escapes_stay_as_they_are() {
    assert_eq!(percent_decode("%4"), "%4");
    assert_eq!(percent_decode("a%"), "a%");
    assert_eq!(percent_decode("%zz%41"), "%zzA");
    assert_eq!(percent_decode("%41%"), "A%");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn java_double_never_panics(bits in any::<u64>()) {
        let text = java_double(f64::from_bits(bits));
        prop_assert!(!text.is_empty());
    }

    #[test]
    fn parsed_numbers_are_finite(digits in "-?[0-9]{1,500}(\\.[0-9]{1,5})?([eE][+-]?[0-9]{1,4})?") {
        if let Ok(Json::Number(number)) = parse(&digits) {
            prop_assert!(number.as_f64().is_finite());
        }
    }

    #[test]
    fn handle_never_panics_on_arbitrary_text(
        target in "/[ -~]{0,40}",
        body in "[ -~\\n\u{e9}]{0,80}",
        method in prop::sample::select(vec!["GET", "PUT", "POST", "PATCH", "DELETE"]),
    ) {
        let mut db = fireemu_adapter_database::rest::Database::new(
            fireemu_adapter_database::rest::RestOptions::default(), 1);
        let request = fireemu_adapter_database::rest::HttpRequest {
            method: method.to_owned(),
            target: target.clone(),
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        };
        let _ = db.handle(&request, 1);
        let read = fireemu_adapter_database::rest::HttpRequest {
            method: "GET".to_owned(),
            target: "/.json?print=pretty".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let _ = db.handle(&read, 2);
    }
}
