//! Reading a file straight into a tree: [`parse_node`] must build exactly the tree that
//! parsing the file to a [`Json`] value and building that value does, with the same refusals,
//! so an import need not hold the parsed value next to the tree. It may decline a file it
//! cannot read that way (server values, an error to report); the caller then reads it the
//! long way.

use fireemu_adapter_database::json_parse::{parse_node, parse_replacing, Read};
use fireemu_adapter_database::json_text::parse;
use fireemu_core_database::server_value::has_server_value;
use fireemu_core_database::{Limits, Node, Path};
use proptest::prelude::*;

/// What parsing a file to a value and building that value gives.
#[derive(Debug, PartialEq)]
enum Long {
    ParseError,
    /// The file has server values, which resolve when it is installed.
    ServerValues,
    /// The tree refuses the value.
    Refused,
    Tree(Option<Node>),
}

fn long_way(text: &str, limits: &Limits, lone: Option<char>) -> Long {
    let parsed = match lone {
        Some(with) => parse_replacing(text, with).map(|(json, _)| json),
        None => parse(text),
    };
    let Ok(json) = parsed else {
        return Long::ParseError;
    };
    if has_server_value(&json) {
        return Long::ServerValues;
    }
    Node::from_json_owned(json, &Path::root(), limits).map_or(Long::Refused, Long::Tree)
}

fn read(text: &str, limits: &Limits, lone: Option<char>) -> Result<Read, ()> {
    parse_node(text, limits, lone).map_err(|_| ())
}

/// The streamed reading never builds another tree than the long way, declines what the long way refuses or
/// resolves later, and reports a parse error only where the file does not parse (it may decline such a file
/// first). It may decline a file the long way builds: a bad key overwritten by a repeated key, a `.priority`
/// string beyond the string limit.
#[track_caller]
fn agree(text: &str, limits: &Limits, lone: Option<char>) {
    let got = read(text, limits, lone);
    match long_way(text, limits, lone) {
        Long::ParseError => assert!(
            matches!(got, Err(()) | Ok(Read::Declined)),
            "{text}: {got:?}"
        ),
        Long::ServerValues | Long::Refused => assert_eq!(got, Ok(Read::Declined), "{text}"),
        Long::Tree(root) => assert!(
            got == Ok(Read::Tree(root)) || got == Ok(Read::Declined),
            "{text}: {got:?}"
        ),
    }
}

/// [`agree`] where nothing is declined that the long way builds.
#[track_caller]
fn agree_exactly(text: &str, limits: &Limits, lone: Option<char>) {
    agree(text, limits, lone);
    if let Long::Tree(root) = long_way(text, limits, lone) {
        assert_eq!(read(text, limits, lone), Ok(Read::Tree(root)), "{text}");
    }
}

#[test]
fn a_plain_file_is_built_without_a_parsed_value() {
    let limits = Limits::default();
    for text in [
        "null",
        "{}",
        "[]",
        "5",
        "\"s\"",
        r#"{"a":{"b":[1,null,{"c":true}],"d":2.5},"e":"x"}"#,
        r#"{"a":1,"a":null}"#,
        r#"{"a":null,"a":1}"#,
        r#"{"a":{"b":null}}"#,
        r#"{".priority":1,"a":1}"#,
        r#"{"a":{".value":"x",".priority":"p"}}"#,
        r#"{".value":3}"#,
        " \n[ 1 , 2 ]\t",
        "1e400",
        "-1e400",
        "12345678901234567890",
    ] {
        agree(text, &limits, None);
        assert!(
            matches!(read(text, &limits, None), Ok(Read::Tree(_))),
            "{text}"
        );
    }
}

#[test]
fn what_the_long_way_refuses_or_resolves_is_declined_not_built() {
    let limits = Limits::default();
    for text in [
        r#"{".sv":"timestamp"}"#,
        r#"{"a":{".sv":{"increment":1}}}"#,
        r#"{"a.b":1}"#,
        r#"{"":1}"#,
        r#"{".priority":1}"#,
        r#"{".value":1,"x":2}"#,
        r#"{".value":1,"x":null}"#,
        r#"{".value":{}}"#,
        r#"{".value":[],".priority":1}"#,
        r#"{".value":null,".priority":1}"#,
        r#"{".priority":true,"a":1}"#,
        r#"{".priority":{"a":1},"b":1}"#,
        r#"{".priority":[1],"b":1}"#,
        r#"{".priority":{".value":1},"b":1}"#,
        r#"{"a":{".value":{".value":1}}}"#,
    ] {
        assert_eq!(read(text, &limits, None), Ok(Read::Declined), "{text}");
        agree(text, &limits, None);
    }
}

#[test]
fn a_syntax_error_is_a_parse_error_and_nothing_else() {
    let limits = Limits::default();
    for text in [
        "",
        "{",
        "{\"a\"}",
        "{\"a\":}",
        "[1,]",
        "{\"a\":1,}",
        "nul",
        "1 2",
        "{\"a\":1}x",
        "\"\\q\"",
        "01",
    ] {
        assert_eq!(read(text, &limits, None), Err(()), "{text}");
    }
    // A syntax error after the point a file is declined is the long way's to report.
    assert!(matches!(
        read(r#"{".sv":1,"#, &limits, None),
        Ok(Read::Declined)
    ));
}

#[test]
fn the_limits_decline_a_file_instead_of_building_it() {
    let tight = Limits {
        max_depth: 2,
        max_path_bytes: 5,
        max_string_bytes: 3,
    };
    for text in [
        r#"{"a":{"b":1}}"#,
        r#"{"a":{"b":{"c":1}}}"#,
        r#"{"a":{"b":{"c":null}}}"#,
        r#"{"abcde":1}"#,
        r#"{"abcdef":1}"#,
        r#"{"ab":{"cd":1}}"#,
        r#"{"ab":{"cde":1}}"#,
        r#"{"a":"abc"}"#,
        r#"{"a":"abcd"}"#,
        "[[[1]]]",
        r#"{".value":"abcd"}"#,
    ] {
        agree_exactly(text, &tight, None);
    }
    // The long way stores a priority past the string limit; the streamed reading hands it back.
    agree(r#"{".priority":"abcd","a":1}"#, &tight, None);
}

#[test]
fn a_lone_surrogate_is_read_as_the_profile_reads_it() {
    let limits = Limits::default();
    for text in [
        r#"{"a":"x\ud83d"}"#,
        r#"{"a\ud83d":1}"#,
        r#"["\ude00"]"#,
        r#"{".priority":"\ud83d","a":1}"#,
    ] {
        for lone in [None, Some('?')] {
            agree_exactly(text, &limits, lone);
        }
    }
    assert_eq!(read(r#"{"a":"x\ud83d"}"#, &limits, None), Err(()));
    assert!(matches!(
        read(r#"{"a":"x\ud83d"}"#, &limits, Some('?')),
        Ok(Read::Tree(Some(_)))
    ));
}

fn key() -> impl Strategy<Value = String> + Clone {
    prop::sample::select(vec![
        "a",
        "b",
        "c",
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
        "abcdef",
        "k\\ud83d",
    ])
    .prop_map(str::to_owned)
}

/// Keys that make priorities and prioritized leaves likely.
fn priority_keys() -> impl Strategy<Value = String> + Clone {
    prop::sample::select(vec!["a", "b", ".priority", ".value", ".priority", ".value"])
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
        Just("1e999".to_owned()),
        Just(r#""s""#.to_owned()),
        Just(r#""""#.to_owned()),
        Just(r#""long string""#.to_owned()),
        Just(r#""x\ud83d""#.to_owned()),
        Just(r#"{".sv":"timestamp"}"#.to_owned()),
    ]
}

fn space() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec!["", "", "", " ", "\n", "\t "])
}

fn document(key: impl Strategy<Value = String> + Clone + 'static) -> impl Strategy<Value = String> {
    leaf().prop_recursive(5, 48, 4, move |inner| {
        prop_oneof![
            prop::collection::vec((key.clone(), space(), inner.clone()), 0..4).prop_map(
                |members| {
                    let members: Vec<String> = members
                        .into_iter()
                        .map(|(k, s, v)| format!("\"{k}\"{s}:{s}{v}"))
                        .collect();
                    format!("{{{}}}", members.join(","))
                }
            ),
            prop::collection::vec(inner, 0..4).prop_map(|items| format!("[{}]", items.join(","))),
        ]
    })
}

/// A document in which no object repeats a key.
fn unique_document(
    key: impl Strategy<Value = String> + Clone + 'static,
) -> impl Strategy<Value = String> {
    leaf().prop_recursive(5, 48, 4, move |inner| {
        prop_oneof![
            prop::collection::btree_map(key.clone(), (space(), inner.clone()), 0..4).prop_map(
                |members| {
                    let members: Vec<String> = members
                        .into_iter()
                        .map(|(k, (s, v))| format!("\"{k}\"{s}:{s}{v}"))
                        .collect();
                    format!("{{{}}}", members.join(","))
                }
            ),
            prop::collection::vec(inner, 0..4).prop_map(|items| format!("[{}]", items.join(","))),
        ]
    })
}

/// A document, sometimes broken by cutting it short or dropping a character.
fn text() -> impl Strategy<Value = String> {
    (
        prop_oneof![document(key()), document(priority_keys())],
        0usize..8,
        any::<prop::sample::Index>(),
    )
        .prop_map(|(text, damage, at)| {
            let chars: Vec<char> = text.chars().collect();
            if chars.is_empty() || damage > 1 {
                return text;
            }
            let at = at.index(chars.len());
            if damage == 0 {
                chars[..at].iter().collect()
            } else {
                chars
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != at)
                    .map(|(_, c)| c)
                    .collect()
            }
        })
}

fn limits() -> impl Strategy<Value = Limits> {
    prop_oneof![
        3 => Just(Limits::default()),
        1 => (1usize..5, 1usize..12, 1usize..8).prop_map(|(max_depth, max_path_bytes, max_string_bytes)| Limits {
            max_depth,
            max_path_bytes,
            max_string_bytes,
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// Whatever is built is what the long way builds, nothing the long way builds is declined, and a
    /// parse error is a parse error.
    #[test]
    fn a_streamed_tree_is_the_tree_of_the_parsed_value(
        text in text(),
        limits in limits(),
        lone in prop::sample::select(vec![None, Some('?')]),
    ) {
        agree(&text, &limits, lone);
    }

    /// Without a repeated key, nothing the long way builds is declined either.
    #[test]
    fn nothing_the_long_way_builds_is_declined(
        text in prop_oneof![unique_document(key()), unique_document(priority_keys())],
        lone in prop::sample::select(vec![None, Some('?')]),
    ) {
        agree_exactly(&text, &Limits::default(), lone);
    }
}
