//! A lone surrogate escape in a JSON string value read as the official emulator stores it: `?` for each lone
//! unit, a high surrogate followed by an escaped low one a single character. Keys are never read so.

use fireemu_adapter_database::json_parse::{
    parse, parse_frame, parse_replacing, parse_with_keys_replacing,
};
use fireemu_core_database::Json;
use proptest::prelude::*;

/// What Java makes of a run of UTF-16 units: a valid pair is a character, anything else alone is `?`.
fn java_text(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied())
        .map(|decoded| decoded.unwrap_or('?'))
        .collect()
}

fn unit() -> impl Strategy<Value = u16> {
    prop::sample::select(vec![
        0x61_u16, 0x41, 0xD83D, 0xDE00, 0xD800, 0xDBFF, 0xDC00, 0xDFFF, 0x20AC, 0x3F,
    ])
}

/// The JSON string body that spells `units`, each as a `\u` escape.
fn spelled(units: &[u16]) -> String {
    use std::fmt::Write as _;
    units.iter().fold(String::new(), |mut out, unit| {
        write!(out, "\\u{unit:04x}").unwrap();
        out
    })
}

proptest! {
    #![proptest_config(ProptestConfig {cases: 500, rng_seed: proptest::test_runner::RngSeed::Fixed(0x2276), ..ProptestConfig::default()})]

    #[test]
    fn a_value_reads_as_java_reads_the_units(units in prop::collection::vec(unit(), 0..8)) {
        let text = format!("\"{}\"", spelled(&units));
        let expected = java_text(&units);
        let lone = char::decode_utf16(units.iter().copied()).any(|d| d.is_err());
        prop_assert_eq!(parse_replacing(&text, '?').unwrap(), (Json::String(expected.clone()), lone));
        // Nested in an object value and an array, and the strict parser refuses exactly the lone ones.
        let object = format!("{{\"k\":[{text}]}}");
        let (value, _, replaced) = parse_with_keys_replacing(&object, '?').unwrap();
        prop_assert_eq!(replaced, lone);
        prop_assert_eq!(value, Json::object([("k".to_owned(), Json::Array(vec![Json::String(expected)]))]));
        prop_assert_eq!(parse(&text).is_err(), lone);
        // A key holding the same units is refused when a unit is lone.
        let key = format!("{{\"{}\":1}}", spelled(&units));
        prop_assert_eq!(parse_with_keys_replacing(&key, '?').is_err(), lone);
    }
}

/// Every escape of JSON reads as the character it names, in a value and in a key, in every mode.
#[test]
fn every_json_escape_reads_as_the_character_it_names() {
    for (escape, expected) in [
        ("\\\"", '"'),
        ("\\\\", '\\'),
        ("\\/", '/'),
        ("\\b", '\u{8}'),
        ("\\f", '\u{c}'),
        ("\\n", '\n'),
        ("\\r", '\r'),
        ("\\t", '\t'),
        ("\\u0041", 'A'),
    ] {
        let text = format!("\"x{escape}y\"");
        let want = Json::String(format!("x{expected}y"));
        assert_eq!(parse(&text).unwrap(), want, "{escape}");
        assert_eq!(parse_replacing(&text, '?').unwrap().0, want, "{escape}");
        assert_eq!(parse_frame(&text).unwrap().0, want, "{escape}");
        assert!(parse(&format!("\"x\\{}y\"", 'q')).is_err());
    }
}

/// The path of a frame (`d.b.p`) is still found after values nested deeper than the levels the frame parse tracks:
/// the tracking of those deeper levels leaves the position as it found it, in an array and in an object.
#[test]
fn a_frame_path_is_found_after_values_nested_deeper_than_the_tracked_levels() {
    let text = r#"{"t":"d","d":{"x":{"y":{"z":{"w":[1,{"v":"\ud83d"}]}}},"b":{"q":{"r":{"s":[[{"t":1}]]}},"p":"/a\ud83d","d":"v\ud83d"}}}"#;
    let want = r#"{"t":"d","d":{"x":{"y":{"z":{"w":[1,{"v":"?"}]}}},"b":{"q":{"r":{"s":[[{"t":1}]]}},"p":"/a\u0000","d":"v?"}}}"#;
    let (value, replaced) = parse_frame(text).unwrap();
    assert!(replaced);
    assert_eq!(value, parse(want).unwrap());
    // The same frame with the path first reads the same way.
    let first = r#"{"t":"d","d":{"b":{"p":"/a\ud83d","q":{"r":{"s":[[{"t":1}]]}}},"x":{"y":{"z":{"w":[1,{"v":"\ud83d"}]}}}}}"#;
    let want_first = r#"{"t":"d","d":{"b":{"p":"/a\u0000","q":{"r":{"s":[[{"t":1}]]}}},"x":{"y":{"z":{"w":[1,{"v":"?"}]}}}}}"#;
    assert_eq!(parse_frame(first).unwrap().0, parse(want_first).unwrap());
}

/// A document nested 512 levels deep is read and one nested 513 levels is refused, whether the levels are arrays or
/// objects.
#[test]
fn the_nesting_bound_holds_for_arrays_and_objects() {
    let arrays = |n: usize| format!("{}1{}", "[".repeat(n), "]".repeat(n));
    let objects = |n: usize| format!("{}1{}", "{\"a\":".repeat(n), "}".repeat(n));
    for read in [parse, |text: &str| {
        parse_frame(text).map(|(value, _)| value)
    }] {
        assert!(read(&arrays(512)).is_ok());
        assert!(read(&arrays(513)).is_err());
        assert!(read(&objects(512)).is_ok());
        assert!(read(&objects(513)).is_err());
    }
}

/// A lone surrogate in the path of a frame or in a key is the character no key and no path may hold, never the dot of
/// `.priority`; one inside the `authvar` of the frame refuses the whole message, as before the frame was read so.
#[test]
fn a_lone_surrogate_in_a_path_or_key_is_never_a_valid_one_and_authvar_refuses_it() {
    use fireemu_adapter_database::json_parse::INVALID;
    let (value, replaced) =
        parse_frame(r#"{"d":{"b":{"p":"/t/\ud83dpriority","d":{"\ud83dpriority":7}}}}"#).unwrap();
    assert!(replaced);
    assert_eq!(INVALID, '\u{0}');
    let want = r#"{"d":{"b":{"p":"/t/\u0000priority","d":{"\u0000priority":7}}}}"#;
    assert_eq!(value, parse(want).unwrap());
    for text in [
        r#"{"d":{"b":{"authvar":{"uid":"\ud83d"}}}}"#,
        r#"{"d":{"b":{"authvar":{"k\ud83d":1}}}}"#,
        r#"{"d":{"b":{"authvar":{"a":{"b":[{"c":"\ude00"}]}}}}}"#,
    ] {
        assert!(parse_frame(text).is_err(), "{text}");
    }
    // A lone surrogate elsewhere in the same frame is a value read as `?`.
    assert_eq!(
        parse_frame(r#"{"d":{"b":{"authvar":{"uid":"u"},"d":"\ud83d"}}}"#)
            .unwrap()
            .0,
        parse(r#"{"d":{"b":{"authvar":{"uid":"u"},"d":"?"}}}"#).unwrap()
    );
}
