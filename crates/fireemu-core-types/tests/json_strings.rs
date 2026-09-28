//! JSON string grammar and UTF-8 cursor regressions (CORE-JSON-STRINGS-010).
//!
//! No external JSON parser is used as the expected-value source. Escapes are checked
//! against RFC 8259 section 7; unpaired-surrogate rejection is an existing local rule.

use fireemu_core_types::json::{parse, JsonValue, MAX_DEPTH};

fn expect_string(source: &str, expected: &str) {
    assert_eq!(
        parse(source),
        Ok(JsonValue::String(expected.to_owned())),
        "{source:?}"
    );
}

#[test]
fn a_sign_is_not_a_json_unicode_hex_digit() {
    for digits in [
        "+000", "+041", "+061", "+07f", "+FFF", "-041", "004+", "0+41", " 041",
    ] {
        let source = format!(r#""\u{digits}""#);
        let error = parse(&source).expect_err("four unsigned hexadecimal digits required");
        assert_eq!(error.offset, 3, "{source:?}");
        assert_eq!(error.expected, "4 hex digits");
    }
}

#[test]
fn every_plus_prefixed_three_digit_escape_is_rejected() {
    // These 4,096 spellings all reached from_str_radix as a valid unsigned integer.
    for value in 0..=0xfff_u32 {
        let source = format!(r#""\u+{value:03x}""#);
        assert!(parse(&source).is_err(), "{source}");
    }
}

#[test]
fn malformed_escapes_cannot_create_object_member_names() {
    for source in [
        r#"{"\u+061lg":"none"}"#,
        r#"{"su\u+062":"alice"}"#,
        r#"{"outer":{"\u+075id":"alice"}}"#,
        r#"[{"ok":1},{"\u+061dmin":true}]"#,
    ] {
        assert!(parse(source).is_err(), "{source}");
    }
    assert_eq!(
        parse(r#"{"\u0061lg":"none"}"#)
            .unwrap()
            .get("alg")
            .and_then(JsonValue::as_str),
        Some("none")
    );
}

#[test]
fn a_literal_backslash_or_plus_remains_ordinary_data() {
    expect_string(r#""\\u+041""#, r"\u+041");
    expect_string(r#""+041""#, "+041");
    expect_string(r#""\u002b041""#, "+041");
    expect_string(r#""prefix\\u0041suffix""#, r"prefix\u0041suffix");
    assert_eq!(
        parse(r#"{"+041":"\\u+041"}"#)
            .unwrap()
            .get("+041")
            .and_then(JsonValue::as_str),
        Some(r"\u+041")
    );
}

#[test]
fn every_bmp_scalar_retains_lower_and_uppercase_escape_spellings() {
    for value in 0..=0xffff_u32 {
        let Some(character) = char::from_u32(value) else {
            continue;
        };
        let expected = character.to_string();
        expect_string(&format!(r#""\u{value:04x}""#), &expected);
        expect_string(&format!(r#""\u{value:04X}""#), &expected);
    }
}

#[test]
fn surrogate_pairs_still_decode_at_both_unicode_boundaries() {
    for (source, expected) in [
        (r#""\ud800\udc00""#, "\u{10000}"),
        (r#""\uDBFF\uDFFF""#, "\u{10ffff}"),
        (r#""\uD83d\udE00""#, "😀"),
        (r#""日\ud83d\ude00本""#, "日😀本"),
    ] {
        expect_string(source, expected);
    }
}

#[test]
fn incomplete_escapes_and_unpaired_surrogates_stay_errors() {
    for source in [
        r#""\u""#,
        r#""\u0""#,
        r#""\u00""#,
        r#""\u000""#,
        r#""\u0g00""#,
        r#""\uD800""#,
        r#""\uDC00""#,
        r#""\uD800\u+041""#,
        r#""\uD800\uD800""#,
        r#""\uD800\u0041""#,
        r#""\uDC00\uD800""#,
        r#""\U0041""#,
        r#""\x41""#,
    ] {
        assert!(parse(source).is_err(), "{source}");
    }
}

#[test]
fn non_ascii_hex_slots_are_errors_without_slicing_panics() {
    for source in [r#""\ué00""#, r#""\u😀""#, r#""\u０00""#, r#""\u日0""#] {
        assert!(parse(source).is_err(), "{source}");
    }
}

#[test]
fn mixed_utf8_and_every_short_escape_preserve_their_values() {
    expect_string(
        r#""é日😀\"\\\/\b\f\n\r\t尾""#,
        "é日😀\"\\/\u{8}\u{c}\n\r\t尾",
    );
    expect_string(r#""\u0022\u005C\u002F""#, "\"\\/");
    expect_string(r#""e\u0301""#, "e\u{301}");
    expect_string(r#""é""#, "é");
    // No normalization: a decomposed accent is not precomposed by this change.
    assert_ne!(parse(r#""e\u0301""#), parse(r#""é""#));
}

#[test]
fn raw_controls_remain_refused_but_escaped_controls_are_retained() {
    for byte in 0..=0x1f_u8 {
        let source = format!("\"start{}end\"", char::from(byte));
        let error = parse(&source).expect_err("unescaped C0 control");
        assert_eq!(error.offset, 6);
        expect_string(&format!(r#""\u{byte:04x}""#), &char::from(byte).to_string());
    }
}

#[test]
fn errors_after_multibyte_input_keep_byte_offsets() {
    let source = r#""日😀\u+041""#;
    assert_eq!(parse(source).unwrap_err().offset, 10);
    let source = "\"日😀\n\"";
    assert_eq!(parse(source).unwrap_err().offset, 8);
    let source = r#""日😀"extra"#;
    assert_eq!(parse(source).unwrap_err().offset, 9);
    let source = "\"日😀";
    assert_eq!(parse(source).unwrap_err().offset, source.len());
}

#[test]
fn long_utf8_strings_and_long_keys_preserve_content() {
    let text = "aé日😀".repeat(8_192);
    expect_string(&format!("\"{text}\""), &text);
    let source = format!("{{\"{text}\":\"ok\",\"tail\":7}}");
    let value = parse(&source).unwrap();
    assert_eq!(value.get(&text).and_then(JsonValue::as_str), Some("ok"));
    assert_eq!(value.get("tail").and_then(JsonValue::as_i64), Some(7));
}

#[test]
fn many_short_strings_and_alternating_escapes_keep_cursor_boundaries() {
    let source = format!("[{}]", vec![r#""a日😀\u0041\n""#; 2_048].join(","));
    let value = parse(&source).unwrap();
    let JsonValue::Array(items) = value else {
        panic!("array required");
    };
    assert_eq!(items.len(), 2_048);
    assert!(items.iter().all(|item| item.as_str() == Some("a日😀A\n")));
}

#[test]
fn non_string_contracts_are_unchanged() {
    assert_eq!(parse("1e+2"), Ok(JsonValue::Float(100.0)));
    assert_eq!(parse("0"), Ok(JsonValue::Int(0)));
    assert_eq!(parse("true"), Ok(JsonValue::Bool(true)));
    assert_eq!(parse("null"), Ok(JsonValue::Null));
    // Duplicate-key and depth policies are deliberately not changed in this patch.
    assert_eq!(
        parse(r#"{"a":1,"a":2}"#)
            .unwrap()
            .get("a")
            .and_then(JsonValue::as_i64),
        Some(2)
    );
    let deep = "[".repeat(MAX_DEPTH + 2) + &"]".repeat(MAX_DEPTH + 2);
    assert!(parse(&deep).is_err());
    for source in ["[1,]", "{\"a\":1,}", "01", "+1", "{\"a\":1}tail"] {
        assert!(parse(source).is_err(), "{source}");
    }
}
