//! An import read once: [`prepare_import`] checks a file and builds its tree, and
//! [`Database::install_import`] puts that tree in place. Together they must do exactly what
//! [`Database::import_text`] (a `PUT /.json` as the owner) does, so `--import` can parse each
//! file once and still refuse a bad file before anything is installed.

use fireemu_adapter_database::realtime::Opened;
use fireemu_adapter_database::rest::{prepare_import, Database, Handled, HttpRequest, RestOptions};
use std::fmt::Write as _;

use fireemu_core_database::Limits;
use proptest::prelude::*;

const NOW: i64 = 1_792_464_733_000;

fn put(db: &mut Database, namespace: &str, body: &str) {
    let request = HttpRequest {
        method: "PUT".to_owned(),
        target: format!("/.json?ns={namespace}"),
        headers: vec![("Authorization".to_owned(), "Bearer owner".to_owned())],
        body: body.as_bytes().to_vec(),
    };
    match db.handle(&request, NOW) {
        Handled::Response { response, .. } => assert_eq!(response.status, 200, "seed {body}"),
        Handled::Stream { .. } => panic!("stream"),
    }
}

/// Imports `text` both ways into databases seeded alike; returns both outcomes and exports.
#[allow(clippy::type_complexity)]
fn both(
    seed: Option<&str>,
    namespace: &str,
    text: &str,
) -> (
    (Result<(), String>, Vec<(String, String)>),
    (Result<(), String>, Vec<(String, String)>),
) {
    let mut direct = Database::new(RestOptions::default(), 1);
    let mut prepared = Database::new(RestOptions::default(), 1);
    if let Some(seed) = seed {
        put(&mut direct, "seeded", seed);
        put(&mut prepared, "seeded", seed);
    }
    let a = direct.import_text(namespace, text, NOW);
    let b = prepare_import(namespace, text.to_owned(), &Limits::default())
        .and_then(|import| prepared.install_import(import, NOW));
    ((a, direct.export_texts()), (b, prepared.export_texts()))
}

#[test]
fn a_prepared_import_writes_what_the_import_request_writes() {
    for (seed, namespace, text) in [
        (
            None,
            "a-default-rtdb",
            r#"{"a":{".priority":3.0,"b":1},"s":"x"}"#,
        ),
        (None, "leaf", r#"{".value":5,".priority":1}"#),
        (None, "empty", "null"),
        (None, "arr", r#"[1,null,{"x":[true]}]"#),
        (None, "Upper", r#"{"k":"v"}"#),
        // A write of what is stored keeps the stored form (1.0 over 1 leaves 1).
        (Some("1"), "seeded", "1.0"),
        (Some(r#"{"a":1}"#), "seeded", r#"{"a":1.0}"#),
        (Some(r#"{"a":1}"#), "seeded", r#"{"b":2}"#),
        (Some(r#"{"a":1}"#), "seeded", "null"),
    ] {
        let (direct, prepared) = both(seed, namespace, text);
        assert_eq!(prepared, direct, "{text}");
        assert!(direct.0.is_ok(), "{text}: {:?}", direct.0);
    }
}

#[test]
fn a_prepared_import_refuses_what_the_import_request_refuses() {
    for (namespace, text) in [
        ("p3", "{bad"),
        ("p3", ""),
        ("bad.ns", "1"),
        ("p", r#"{"a.b":1}"#),
        ("p", r#"{"a":{"":1}}"#),
        ("p", r#"{".priority":1}"#),
        ("p", r#"{".value":1,"x":2}"#),
        ("p", r#"{"a":{".priority":true,"b":1}}"#),
        ("p", r#"{"a":{".sv":"nope"}}"#),
        ("p", r#"{"a":{".sv":{"increment":"x"}}}"#),
    ] {
        let (direct, prepared) = both(None, namespace, text);
        assert!(direct.0.is_err(), "{text}");
        assert_eq!(prepared, direct, "{text}");
    }
}

#[test]
fn server_values_in_a_prepared_import_resolve_when_it_is_installed() {
    let import = prepare_import(
        "p",
        r#"{"t":{".sv":"timestamp"},"n":{".sv":{"increment":2}}}"#.to_owned(),
        &Limits::default(),
    )
    .unwrap();
    let mut db = Database::new(RestOptions::default(), 1);
    put(&mut db, "p", r#"{"n":5}"#);
    db.install_import(import, NOW + 7).unwrap();
    assert_eq!(
        db.export_texts(),
        vec![("p".to_owned(), format!(r#"{{"n":7,"t":{}}}"#, NOW + 7))]
    );
}

#[test]
fn listeners_hear_a_prepared_import_as_they_hear_the_import_request() {
    for (seed, text) in [
        ("1", r#"{"a":{"b":2}}"#),
        (r#"{"a":{"b":2}}"#, r#"{"a":{"b":2.0}}"#),
        (r#"{"a":1}"#, "null"),
    ] {
        let mut pushed = Vec::new();
        for prepared in [false, true] {
            let mut db = Database::new(RestOptions::default(), 1);
            put(&mut db, "p", seed);
            let Ok(Opened::Session(mut session, _)) =
                db.open_realtime("/.ws?v=5&ns=p", Some("127.0.0.1:9000"), NOW)
            else {
                panic!("no session");
            };
            for path in ["/", "/a"] {
                let frame =
                    format!(r#"{{"t":"d","d":{{"r":1,"a":"q","b":{{"p":"{path}","h":""}}}}}}"#);
                session.receive(&mut db, &frame, NOW);
            }
            db.drain_pushes();
            if prepared {
                let import = prepare_import("p", text.to_owned(), &Limits::default()).unwrap();
                db.install_import(import, NOW).unwrap();
            } else {
                db.import_text("p", text, NOW).unwrap();
            }
            pushed.push(db.drain_pushes());
        }
        assert_eq!(pushed[1], pushed[0], "{seed} then {text}");
        assert!(
            !pushed[0].is_empty() || seed == r#"{"a":{"b":2}}"#,
            "{text}"
        );
    }
}

#[test]
fn a_prepared_import_names_its_namespace_as_the_server_keeps_it() {
    let import = prepare_import("Demo-App", "1".to_owned(), &Limits::default()).unwrap();
    assert_eq!(import.namespace(), "demo-app");
    let deferred = prepare_import(
        "Demo-App",
        r#"{".sv":"timestamp"}"#.to_owned(),
        &Limits::default(),
    )
    .unwrap();
    assert_eq!(deferred.namespace(), "demo-app");
}

#[test]
fn a_file_with_server_values_is_checked_against_the_given_limits() {
    let limits = Limits {
        max_depth: 2,
        ..Limits::default()
    };
    let deep = r#"{"a":{"b":{"c":{".sv":"timestamp"}}}}"#;
    assert!(prepare_import("p", deep.to_owned(), &Limits::default()).is_ok());
    assert!(prepare_import("p", deep.to_owned(), &limits).is_err());
    let shallow = prepare_import("p", r#"{"a":{".sv":"timestamp"}}"#.to_owned(), &limits).unwrap();
    // Until it is installed it holds the text, whose server values resolve then.
    assert_eq!(shallow.retained_bytes(), 25);
}

#[test]
fn an_import_checked_against_other_limits_is_not_installed() {
    let limits = Limits {
        max_depth: 3,
        ..Limits::default()
    };
    let import = prepare_import("p", r#"{"a":1}"#.to_owned(), &limits).unwrap();
    let mut db = Database::new(RestOptions::default(), 1);
    assert!(db.install_import(import, NOW).is_err());
    assert!(db.export_texts().is_empty());
}

#[test]
fn a_prepared_import_holds_its_tree_in_a_bounded_size() {
    // A size regression check on what `--import` keeps between reading and installing: the
    // built tree, not the text or a parsed copy. 2,000 objects of five members each.
    let mut text = String::from("{\"users\":{");
    for i in 0..2_000 {
        if i > 0 {
            text.push(',');
        }
        write!(
            text,
            r#""u{i:07}":{{"name":"user {i}","age":{},"active":{},"score":{},"email":"u{i}@x.io"}}"#,
            i % 97,
            i % 3 == 0,
            f64::from(i) / 7.0
        )
        .unwrap();
    }
    text.push_str("}}");
    let import = prepare_import("p", text.clone(), &Limits::default()).unwrap();
    let held = import.retained_bytes();
    // At least every key and string it holds, at most a few times the text.
    assert!(held >= text.len() as u64, "{held}");
    assert!(
        held <= 8 * text.len() as u64,
        "{held} bytes held for {} bytes of text",
        text.len()
    );
}

fn key() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "a",
        "b",
        "0",
        "1",
        "10",
        "-1",
        "00",
        "",
        "a.b",
        "$x",
        "#",
        "[",
        ".priority",
        ".value",
        ".sv",
        "\u{1F600}",
    ])
    .prop_map(str::to_owned)
}

fn leaf() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("null".to_owned()),
        Just("true".to_owned()),
        Just("false".to_owned()),
        (-3i64..4).prop_map(|n| n.to_string()),
        (-3i64..4).prop_map(|n| format!("{n}.0")),
        Just("2.5".to_owned()),
        Just(r#""s""#.to_owned()),
        Just(r#""""#.to_owned()),
        Just(r#""timestamp""#.to_owned()),
        Just(r#"{"increment":1}"#.to_owned()),
        Just(r#"{".sv":"timestamp"}"#.to_owned()),
        Just(r#"{".sv":{"increment":2}}"#.to_owned()),
    ]
}

fn text() -> impl Strategy<Value = String> {
    let value = leaf().prop_recursive(4, 32, 4, |inner| {
        prop_oneof![
            prop::collection::vec((key(), inner.clone()), 0..4).prop_map(|members| {
                let members: Vec<String> = members
                    .into_iter()
                    .map(|(k, v)| format!("\"{k}\":{v}"))
                    .collect();
                format!("{{{}}}", members.join(","))
            }),
            prop::collection::vec(inner, 0..3).prop_map(|items| format!("[{}]", items.join(","))),
        ]
    });
    prop_oneof![
        8 => value,
        1 => Just("{bad".to_owned()),
        1 => Just(String::new()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn any_prepared_import_matches_the_import_request(
        seed in prop::option::of(text()),
        namespace in prop::sample::select(vec!["seeded", "other", "Mixed", "bad.ns"]),
        text in text(),
    ) {
        let seed = seed.filter(|seed| {
            let mut db = Database::new(RestOptions::default(), 1);
            db.import_text("seeded", seed, NOW).is_ok()
        });
        let (direct, prepared) = both(seed.as_deref(), namespace, &text);
        prop_assert_eq!(prepared, direct);
    }
}
