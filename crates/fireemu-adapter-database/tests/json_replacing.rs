//! A lone surrogate escape in a JSON string value read as the official emulator stores it: `?` for each lone
//! unit, a high surrogate followed by an escaped low one a single character. Keys are never read so.

use fireemu_adapter_database::json_parse::{
    parse, parse_claims, parse_frame, parse_replacing, parse_with_keys_replacing,
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
        assert_eq!(parse_claims(&text).unwrap().0, want, "{escape}");
        assert_eq!(parse_frame(&text).unwrap().0, want, "{escape}");
        assert!(parse(&format!("\"x\\{}y\"", 'q')).is_err());
    }
}

/// The claims read as an ordinary document: a lone surrogate is `?` there, in a value and in a name, and the table says
/// which strings really held one, by location; a real character is itself, whatever it looks like.
#[test]
fn claims_are_an_ordinary_document_and_a_table_of_their_lone_surrogates() {
    use fireemu_core_database::lone::Step;
    let text = "{\"k\\ud83d\":\"v\\ud83d\\ude00\\ud83d\",\"o\":{\"a\":[\"x\",\"\\ude00y\"]},\"real\":\"\u{10FFFF}\u{10F03D}\"}";
    let (json, table) = parse_claims(text).unwrap();
    assert_eq!(
        json,
        parse(
            "{\"k?\":\"v\u{1F600}?\",\"o\":{\"a\":[\"x\",\"?y\"]},\"real\":\"\u{10FFFF}\u{10F03D}\"}"
        )
        .unwrap()
    );
    let mut expected = fireemu_core_database::lone::LoneClaims::default();
    expected.record_name(&[Step::Key("k?".into())], vec![0x6B, 0xD83D]);
    expected.record_value(
        &[Step::Key("k?".into())],
        vec![0x76, 0xD83D, 0xDE00, 0xD83D],
    );
    expected.record_value(
        &[Step::Key("o".into()), Step::Key("a".into()), Step::Index(1)],
        vec![0xDE00, 0x79],
    );
    assert_eq!(table, expected);
    // A document without a lone surrogate has an empty table, however its characters look.
    let (_, empty) = parse_claims("{\"real\":\"\u{10FFFF}\u{10F03D}\"}").unwrap();
    assert!(empty.is_empty());
}

proptest! {
    #![proptest_config(ProptestConfig {cases: 300, rng_seed: proptest::test_runner::RngSeed::Fixed(0x2277), ..ProptestConfig::default()})]

    /// A claim string reads `?` for each lone unit and the table keeps its units exactly, for any units.
    #[test]
    fn the_table_keeps_the_units_of_a_claim(units in prop::collection::vec(unit(), 0..8)) {
        use fireemu_core_database::lone::Step;
        let text = format!("{{\"x\":\"{}\"}}", spelled(&units));
        let (json, table) = parse_claims(&text).unwrap();
        let ordinary: String = char::decode_utf16(units.iter().copied()).map(|d| d.unwrap_or('?')).collect();
        prop_assert_eq!(json, Json::object([("x", Json::String(ordinary))]));
        let lone = char::decode_utf16(units.iter().copied()).any(|d| d.is_err());
        let mut expected = fireemu_core_database::lone::LoneClaims::default();
        if lone {
            expected.record_value(&[Step::Key("x".into())], units.clone());
        }
        prop_assert_eq!(table, expected);
    }
}

/// The path of a frame (`d.b.p`) is still found after values nested deeper than the levels the frame parse tracks:
/// the tracking of those deeper levels leaves the position as it found it, in an array and in an object.
#[test]
fn a_frame_path_is_found_after_values_nested_deeper_than_the_tracked_levels() {
    let text = r#"{"t":"d","d":{"x":{"y":{"z":{"w":[1,{"v":"\ud83d"}]}}},"b":{"q":{"r":{"s":[[{"t":1}]]}},"p":"/a\ud83d","d":"v\ud83d"}}}"#;
    let want = r#"{"t":"d","d":{"x":{"y":{"z":{"w":[1,{"v":"?"}]}}},"b":{"q":{"r":{"s":[[{"t":1}]]}},"p":"/a.","d":"v?"}}}"#;
    let (value, replaced) = parse_frame(text).unwrap();
    assert!(replaced);
    assert_eq!(value, parse(want).unwrap());
    // The same frame with the path first reads the same way.
    let first = r#"{"t":"d","d":{"b":{"p":"/a\ud83d","q":{"r":{"s":[[{"t":1}]]}}},"x":{"y":{"z":{"w":[1,{"v":"\ud83d"}]}}}}}"#;
    let want_first = r#"{"t":"d","d":{"b":{"p":"/a.","q":{"r":{"s":[[{"t":1}]]}}},"x":{"y":{"z":{"w":[1,{"v":"?"}]}}}}}"#;
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
