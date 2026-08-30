//! Field paths: canonical dotted form with backtick quoting, UTF-8 byte limits, reserved names.

use fireemu_core_firestore::field_path::{FieldPath, FieldPathError};

#[test]
fn parses_simple_and_quoted_segments() {
    let p = FieldPath::parse("address.city").unwrap();
    assert_eq!(p.segments(), ["address", "city"]);
    assert_eq!(p.canonical(), "address.city");

    let q = FieldPath::parse("`first name`.`a.b`").unwrap();
    assert_eq!(q.segments(), ["first name", "a.b"]);
    assert_eq!(q.canonical(), "`first name`.`a.b`");

    let esc = FieldPath::parse("`back\\`tick`.`slash\\\\`").unwrap();
    assert_eq!(esc.segments(), ["back`tick", "slash\\"]);
}

#[test]
fn from_segments_quotes_when_needed() {
    let p = FieldPath::from_segments(["plain", "needs quote", "日本語", "1st"]).unwrap();
    assert_eq!(p.canonical(), "plain.`needs quote`.`日本語`.`1st`");
    assert_eq!(FieldPath::parse(&p.canonical()).unwrap(), p);
}

#[test]
fn rejects_malformed_paths() {
    assert_eq!(FieldPath::parse(""), Err(FieldPathError::Empty));
    assert_eq!(
        FieldPath::parse("a..b"),
        Err(FieldPathError::EmptySegment { index: 1 })
    );
    assert_eq!(
        FieldPath::parse(".a"),
        Err(FieldPathError::EmptySegment { index: 0 })
    );
    assert_eq!(
        FieldPath::parse("a."),
        Err(FieldPathError::EmptySegment { index: 1 })
    );
    assert!(matches!(
        FieldPath::parse("`unterminated"),
        Err(FieldPathError::UnterminatedQuote { .. })
    ));
    assert!(matches!(
        FieldPath::parse("a b"),
        Err(FieldPathError::UnquotedSpecialCharacter { .. })
    ));
    assert!(matches!(
        FieldPath::parse("a\u{0}"),
        Err(FieldPathError::ControlCharacter { .. })
    ));
}

#[test]
fn reserved_dunder_names_are_rejected_except_name() {
    assert_eq!(
        FieldPath::parse("__name__").unwrap(),
        FieldPath::document_name()
    );
    assert!(FieldPath::document_name().is_document_name());
    assert_eq!(
        FieldPath::parse("__foo__"),
        Err(FieldPathError::ReservedSegment { index: 0 })
    );
    assert_eq!(
        FieldPath::parse("a.__x__"),
        Err(FieldPathError::ReservedSegment { index: 1 })
    );
}

#[test]
fn byte_limits_are_utf8_bytes() {
    let long_segment = "あ".repeat(500); // 1,500 bytes
    assert!(FieldPath::from_segments([long_segment.as_str()]).is_ok());
    let over = "あ".repeat(501);
    assert!(matches!(
        FieldPath::from_segments([over.as_str()]),
        Err(FieldPathError::SegmentTooLong {
            index: 0,
            bytes: 1503,
            maximum: 1500
        })
    ));
    // Two 700-byte segments fit individually but the canonical path exceeds 1,500 bytes.
    let seg = "a".repeat(700);
    let mut segs = vec![seg.clone(), seg.clone(), "b".repeat(101)];
    let err = FieldPath::from_segments(segs.iter().map(String::as_str)).unwrap_err();
    assert!(matches!(
        err,
        FieldPathError::PathTooLong {
            bytes: 1503,
            maximum: 1500
        }
    ));
    segs.pop();
    assert!(FieldPath::from_segments(segs.iter().map(String::as_str)).is_ok());
}

#[test]
fn prefix_relation() {
    let a = FieldPath::parse("a.b").unwrap();
    let ab = FieldPath::parse("a.b.c").unwrap();
    assert!(a.is_prefix_of(&ab));
    assert!(!ab.is_prefix_of(&a));
    assert!(a.is_prefix_of(&a));
}
