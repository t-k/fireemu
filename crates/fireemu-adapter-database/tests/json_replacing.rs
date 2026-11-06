//! A lone surrogate escape in a JSON string value read as the official emulator stores it: `?` for each lone
//! unit, a high surrogate followed by an escaped low one a single character. Keys are never read so.

use fireemu_adapter_database::json_parse::{parse, parse_replacing, parse_with_keys_replacing};
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
