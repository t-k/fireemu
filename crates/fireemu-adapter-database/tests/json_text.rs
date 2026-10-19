//! JSON text: parsing request bodies and rendering answers the way the official emulator
//! (firebase-database-emulator v4.11.2) renders them. Expected texts are its answers,
//! recorded in the lane's exploration logs.

use fireemu_adapter_database::json_text::{java_double, output_json, parse, render, Style};
use fireemu_core_database::{Format, Json, Limits, Number, Path, ServerValueContext, Tree};

const NOW: ServerValueContext = ServerValueContext { now_millis: 1 };

fn stored(text: &str) -> Tree {
    let mut tree = Tree::new(Limits::default());
    tree.set(&Path::root(), &parse(text).unwrap(), NOW).unwrap();
    tree
}

fn get(tree: &Tree, format: Format, style: Style) -> String {
    render(&output_json(tree.root(), format), style)
}

#[test]
fn parse_keeps_integers_and_doubles() {
    assert_eq!(
        parse("9007199254740993").unwrap(),
        Json::Number(Number::Int(9_007_199_254_740_993))
    );
    assert_eq!(parse("-0").unwrap(), Json::Number(Number::Int(0)));
    assert!(
        matches!(parse("1.5").unwrap(), Json::Number(Number::Double(d)) if (d - 1.5).abs() < f64::EPSILON)
    );
    assert!(matches!(
        parse("12345678901234567890").unwrap(),
        Json::Number(Number::Double(_))
    ));
    assert!(matches!(
        parse("1e300").unwrap(),
        Json::Number(Number::Double(_))
    ));
    assert!(parse("{bad json").is_err());
    assert!(parse("").is_err());
    assert!(parse("1 2").is_err());
}

#[test]
fn doubles_print_in_java_form() {
    let cases = [
        (1e300, "1.0E300"),
        (1.5, "1.5"),
        (-2.5, "-2.5"),
        (1e20, "1.0E20"),
        (1e-5, "1.0E-5"),
        (0.0001, "1.0E-4"),
        (0.001, "0.001"),
        (1e7, "1.0E7"),
        (12_345_678.9, "1.23456789E7"),
        (0.1, "0.1"),
        (1.234_567_890_123_456_7e19, "1.2345678901234567E19"),
        (9_999_999.5, "9999999.5"),
        (-1e-300, "-1.0E-300"),
        (0.0, "0.0"),
        (-0.0, "-0.0"),
        (123.456, "123.456"),
    ];
    for (value, text) in cases {
        assert_eq!(java_double(value), text, "{value:e}");
    }
}

#[test]
fn compact_output_orders_keys_like_the_server() {
    let tree = stored(r#"{"z":1,"-1":2,"01":3,"1":4,"a":5,".priority":"p"}"#);
    assert_eq!(
        get(&tree, Format::Export, Style::Compact),
        r#"{"-1":2,"1":4,"01":3,".priority":"p","a":5,"z":1}"#
    );
    assert_eq!(
        get(&tree, Format::Plain, Style::Compact),
        r#"{"-1":2,"1":4,"01":3,"a":5,"z":1}"#
    );
}

#[test]
fn numbers_and_strings_render_like_the_server() {
    let tree = stored(
        r#"{"b":1.5,"c":9007199254740993,"e":1e300,"f":12345678901234567890,"s":"\u0000x😀\"/"}"#,
    );
    assert_eq!(
        get(&tree, Format::Plain, Style::Compact),
        r#"{"b":1.5,"c":9007199254740993,"e":1.0E300,"f":1.2345678901234567E19,"s":"\u0000x😀\"/"}"#
    );
}

#[test]
fn integer_keyed_children_render_as_arrays_when_dense_enough() {
    assert_eq!(
        get(
            &stored(r#"["a","b",null,"d"]"#),
            Format::Plain,
            Style::Compact
        ),
        r#"["a","b",null,"d"]"#
    );
    assert_eq!(
        get(
            &stored(r#"{"0":"a","3":"d"}"#),
            Format::Plain,
            Style::Compact
        ),
        r#"["a",null,null,"d"]"#
    );
    assert_eq!(
        get(
            &stored(r#"{"0":"a","4":"d"}"#),
            Format::Plain,
            Style::Compact
        ),
        r#"{"0":"a","4":"d"}"#
    );
    assert_eq!(
        get(
            &stored(r#"{"01":"a","1":"d"}"#),
            Format::Plain,
            Style::Compact
        ),
        r#"{"1":"d","01":"a"}"#
    );
    assert_eq!(
        get(
            &stored(r#"{"2":{"h":5},"10":{"h":5}}"#),
            Format::Plain,
            Style::Compact
        ),
        r#"{"2":{"h":5},"10":{"h":5}}"#
    );
    let prioritized = stored(r#"{"l":{"0":{".value":"a",".priority":1},"1":"b"}}"#);
    assert_eq!(
        get(&prioritized, Format::Export, Style::Compact),
        r#"{"l":[{".value":"a",".priority":1},"b"]}"#
    );
    assert_eq!(
        get(&prioritized, Format::Plain, Style::Compact),
        r#"{"l":["a","b"]}"#
    );
}

#[test]
fn an_array_with_its_own_priority_stays_an_object_in_the_export() {
    let tree = stored(r#"{"l":{"0":"a",".priority":2}}"#);
    assert_eq!(
        get(&tree, Format::Export, Style::Compact),
        r#"{"l":{"0":"a",".priority":2}}"#
    );
    assert_eq!(get(&tree, Format::Plain, Style::Compact), r#"{"l":["a"]}"#);
}

#[test]
fn pretty_output_follows_the_server_layout() {
    let tree = stored(r#"{"w":3,"x":1,"y":{"z":"t"}}"#);
    assert_eq!(
        get(&tree, Format::Plain, Style::Pretty),
        "{\n  \"w\" : 3,\n  \"x\" : 1,\n  \"y\" : {\n    \"z\" : \"t\"\n  }\n}"
    );
    let tree = stored(r#"{"l":["a",{"b":1}]}"#);
    assert_eq!(
        get(&tree, Format::Plain, Style::Pretty),
        "{\n  \"l\" : [ \"a\", {\n    \"b\" : 1\n  } ]\n}"
    );
    assert_eq!(
        get(&stored("[1,[2,3]]"), Format::Plain, Style::Pretty),
        "[ 1, [ 2, 3 ] ]"
    );
    assert_eq!(
        render(
            &Json::Object(std::collections::BTreeMap::default()),
            Style::Pretty
        ),
        "{ }"
    );
    assert_eq!(render(&Json::Array(vec![]), Style::Pretty), "[ ]");
    assert_eq!(render(&Json::Null, Style::Pretty), "null");
    assert_eq!(output_json(None, Format::Plain), Json::Null);
}

#[test]
fn the_parser_follows_the_json_grammar() {
    use fireemu_adapter_database::json_parse::parse_with_keys;
    for bad in [
        "01",
        "1.",
        ".5",
        "-",
        "1e",
        "+1",
        "[1,]",
        "{\"a\":1,}",
        "{a:1}",
        "'a'",
        "\"\\x\"",
        "\"a\nb\"",
        "nul",
        "tru",
        "[",
        "{",
        "\"\\ud83d\"",
        "\"\\ud83dx\"",
        "1e400",
        "{\"a\" 1}",
        "[1 2]",
    ] {
        assert!(parse(bad).is_err(), "{bad:?}");
    }
    assert_eq!(parse(" \t\r\n[ ]\n").unwrap(), Json::Array(vec![]));
    assert_eq!(
        parse(r#""\"\\\/\b\f\n\r\t\u00e9\ud83d\ude00""#).unwrap(),
        Json::String("\"\\/\u{8}\u{c}\n\r\té\u{1F600}".to_owned())
    );
    assert_eq!(
        parse(r#"{"a":1,"a":2}"#).unwrap(),
        Json::object([("a", Json::int(2))])
    );
    assert_eq!(
        parse("-9223372036854775808").unwrap(),
        Json::Number(Number::Int(i64::MIN))
    );
    assert!(matches!(
        parse("9223372036854775808").unwrap(),
        Json::Number(Number::Double(_))
    ));
    assert!(
        matches!(parse("2.5E-3").unwrap(), Json::Number(Number::Double(d)) if (d - 0.0025).abs() < 1e-18)
    );
    let deep = format!("{}{}", "[".repeat(600), "]".repeat(600));
    assert!(parse(&deep).is_err());
    let fine = format!("{}{}", "[".repeat(100), "]".repeat(100));
    assert!(parse(&fine).is_ok());

    let (_, keys) = parse_with_keys("{\"a\":{\n  \"bé\" : [ {\"c\":1} ] }}").unwrap();
    let found: Vec<(String, usize, usize)> = keys
        .into_iter()
        .map(|k| (k.key, k.line, k.column))
        .collect();
    assert_eq!(
        found,
        vec![
            ("a".to_owned(), 1, 2),
            ("bé".to_owned(), 2, 3),
            ("c".to_owned(), 2, 13)
        ]
    );
}
