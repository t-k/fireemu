//! Keys, paths and numbers.

mod support;

use std::cmp::Ordering;

use fireemu_core_database::key::{key_as_int, name_compare, utf16_cmp, validate_key};
use fireemu_core_database::{ErrorKind, Limits, Number, Path};
use support::p;

#[test]
fn keys_refuse_the_documented_characters_and_the_empty_key() {
    let limits = Limits::default();
    for bad in ["", "a.b", "a$", "#", "[x", "x]", "a/b", "\u{0}", "a\u{1f}", "\u{7f}"] {
        let err = validate_key(bad, &limits).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidKey, "{bad:?}");
    }
    for good in ["a", "-1", "with space", "日本語", "\u{80}", "emoji\u{1F600}", "a-b_c:d"] {
        validate_key(good, &limits).unwrap();
    }
}

#[test]
fn keys_are_limited_to_768_utf8_bytes() {
    let limits = Limits::default();
    validate_key(&"a".repeat(768), &limits).unwrap();
    let err = validate_key(&"a".repeat(769), &limits).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyTooLong);
    // 256 three-byte characters are 768 bytes; one more is too long.
    validate_key(&"あ".repeat(256), &limits).unwrap();
    let err = validate_key(&"あ".repeat(257), &limits).unwrap_err();
    assert_eq!(err.kind, ErrorKind::KeyTooLong);
}

#[test]
fn int_keys_are_32_bit_integers_with_optional_sign_and_leading_zeros() {
    assert_eq!(key_as_int("0"), Some(0));
    assert_eq!(key_as_int("-1"), Some(-1));
    assert_eq!(key_as_int("007"), Some(7));
    assert_eq!(key_as_int("2147483647"), Some(i32::MAX));
    assert_eq!(key_as_int("-2147483648"), Some(i32::MIN));
    assert_eq!(key_as_int("2147483648"), None);
    assert_eq!(key_as_int("12345678901"), None);
    assert_eq!(key_as_int("+1"), None);
    assert_eq!(key_as_int("1a"), None);
    assert_eq!(key_as_int(""), None);
    assert_eq!(key_as_int("-"), None);
    // Leading zeros do not count towards the ten digits.
    assert_eq!(key_as_int("0000000000001"), Some(1));
}

#[test]
fn integer_keys_sort_numerically_before_string_keys() {
    let mut keys = vec!["b", "10", "a", "-5", "2", "01", "1", "2147483648", "A", "-"];
    keys.sort_by(|a, b| name_compare(a, b));
    assert_eq!(
        keys,
        vec!["-5", "1", "01", "2", "10", "-", "2147483648", "A", "a", "b"]
    );
    assert_eq!(name_compare("x", "x"), Ordering::Equal);
}

#[test]
fn string_keys_compare_in_utf16_order_not_code_point_order() {
    // U+FF61 is above the surrogate range in UTF-16 order only if compared by code point;
    // UTF-16 puts the surrogate pair of U+1F600 (0xD83D...) below U+FF61.
    assert_eq!(utf16_cmp("\u{1F600}", "\u{FF61}"), Ordering::Less);
    assert_eq!(name_compare("\u{1F600}", "\u{FF61}"), Ordering::Less);
    assert_eq!("\u{1F600}".cmp("\u{FF61}"), Ordering::Greater);
}

#[test]
fn paths_drop_empty_segments() {
    assert_eq!(p("/a//b/").keys(), ["a", "b"]);
    assert!(p("").is_root());
    assert!(p("/").is_root());
    assert_eq!(p("a/b").to_string(), "/a/b");
    assert_eq!(Path::root().to_string(), "/");
}

#[test]
fn paths_allow_info_first_and_priority_last_only() {
    let limits = Limits::default();
    assert!(p("/.info/connected").is_info());
    assert!(p("/a/.priority").is_priority());
    assert!(p("/.priority").is_priority());
    for bad in ["/a/.info", "/.priority/a", "/a/.value", "/a.b", "/a$", "/a/\u{0}"] {
        let err = Path::parse(bad, &limits).unwrap_err();
        assert!(
            matches!(err.kind, ErrorKind::InvalidPath | ErrorKind::InvalidKey),
            "{bad:?}: {err:?}"
        );
    }
}

#[test]
fn path_relations() {
    assert!(p("/a").contains(&p("/a/b")));
    assert!(p("/a").contains(&p("/a")));
    assert!(Path::root().contains(&p("/a")));
    assert!(!p("/a/b").contains(&p("/a")));
    assert!(!p("/a").contains(&p("/ab")));
    assert_eq!(p("/a/b").parent(), Some(p("/a")));
    assert_eq!(p("/a").parent(), Some(Path::root()));
    assert_eq!(Path::root().parent(), None);
}

#[test]
fn integral_doubles_in_the_safe_range_are_integers() {
    assert!(matches!(Number::from_f64(1.0), Some(Number::Int(1))));
    assert!(matches!(Number::from_f64(-0.0), Some(Number::Int(0))));
    assert!(matches!(Number::from_f64(1.5), Some(Number::Double(_))));
    assert!(matches!(
        Number::from_f64(9_007_199_254_740_992.0),
        Some(Number::Int(9_007_199_254_740_992))
    ));
    assert!(matches!(Number::from_f64(1e300), Some(Number::Double(_))));
    assert!(Number::from_f64(f64::NAN).is_none());
    assert!(Number::from_f64(f64::INFINITY).is_none());
}

#[test]
fn numbers_compare_exactly_across_representations() {
    let big = Number::Int(i64::MAX);
    assert_eq!(big.total_cmp(Number::Double(9.3e18)), Ordering::Less);
    assert_eq!(Number::Int(i64::MIN).total_cmp(Number::Double(-9.3e18)), Ordering::Greater);
    assert_eq!(Number::Int(1).total_cmp(Number::Double(1.5)), Ordering::Less);
    assert_eq!(Number::Int(2).total_cmp(Number::Double(1.5)), Ordering::Greater);
    assert_eq!(Number::Int(-1).total_cmp(Number::Double(-1.5)), Ordering::Greater);
    assert_eq!(Number::Double(0.25).total_cmp(Number::Double(0.5)), Ordering::Less);
    assert_eq!(Number::Double(1e300).total_cmp(Number::Int(5)), Ordering::Greater);
    // 2^63 as a double is above every i64.
    assert_eq!(Number::Int(i64::MAX).total_cmp(Number::Double(9_223_372_036_854_775_808.0)), Ordering::Less);
}

#[test]
fn increment_adds_integers_exactly_and_falls_back_to_doubles_on_overflow() {
    assert!(matches!(Number::Int(2).add(Number::Int(3)), Some(Number::Int(5))));
    assert!(matches!(
        Number::Int(i64::MAX).add(Number::Int(1)),
        Some(Number::Double(d)) if d == 9_223_372_036_854_775_808.0
    ));
    assert!(matches!(Number::Int(1).add(Number::Double(0.5)), Some(Number::Double(d)) if d == 1.5));
    assert!(matches!(Number::Double(0.5).add(Number::Double(0.5)), Some(Number::Int(1))));
    assert!(Number::Double(f64::MAX).add(Number::Double(f64::MAX)).is_none());
}
