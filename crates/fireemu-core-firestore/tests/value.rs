//! Firestore value model and total ordering (official type order and per-type rules).

use std::cmp::Ordering;
use std::collections::BTreeMap;

use fireemu_core_firestore::value::{GeoPoint, IndexValue, Timestamp, Value, ValueKind};

fn map(entries: &[(&str, Value)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
    )
}

#[test]
fn type_order_follows_the_documented_sequence() {
    let ordered = vec![
        Value::Null,
        Value::Boolean(false),
        Value::Boolean(true),
        Value::Double(f64::NAN),
        Value::Integer(-1),
        Value::Double(0.5),
        Value::Integer(1),
        Value::Timestamp(Timestamp::new(0, 0).unwrap()),
        Value::String("a".to_owned()),
        Value::Bytes(vec![0]),
        Value::Reference("projects/p/databases/(default)/documents/c/d".to_owned()),
        Value::GeoPoint(GeoPoint::new(0.0, 0.0).unwrap()),
        Value::Array(vec![]),
        Value::Vector(vec![0.0]),
        map(&[]),
    ];
    for (i, a) in ordered.iter().enumerate() {
        for (j, b) in ordered.iter().enumerate() {
            assert_eq!(a.canonical_cmp(b), i.cmp(&j), "{a:?} vs {b:?}");
        }
    }
    assert_eq!(Value::Double(f64::NAN).kind(), ValueKind::Nan);
    assert_eq!(Value::Double(1.0).kind(), ValueKind::Number);
}

#[test]
fn numbers_compare_numerically_across_integer_and_double() {
    assert_eq!(
        Value::Integer(1).canonical_cmp(&Value::Double(1.0)),
        Ordering::Equal
    );
    assert_eq!(
        Value::Integer(2).canonical_cmp(&Value::Double(1.5)),
        Ordering::Greater
    );
    assert_eq!(
        Value::Double(-0.0).canonical_cmp(&Value::Double(0.0)),
        Ordering::Equal
    );
    assert_eq!(
        Value::Double(f64::NAN).canonical_cmp(&Value::Double(f64::NAN)),
        Ordering::Equal
    );
    assert_eq!(
        Value::Double(f64::NEG_INFINITY).canonical_cmp(&Value::Integer(i64::MIN)),
        Ordering::Less
    );
    // i64::MAX is not exactly representable as f64; comparison must still be exact.
    assert_eq!(
        Value::Integer(i64::MAX).canonical_cmp(&Value::Double(9_223_372_036_854_775_807.0)),
        Ordering::Less
    );
    assert_eq!(
        Value::Integer(i64::MAX - 1).canonical_cmp(&Value::Double(9_223_372_036_854_775_807.0)),
        Ordering::Less
    );
    assert_eq!(
        Value::Integer(1 << 53).canonical_cmp(&Value::Double(9_007_199_254_740_992.0)),
        Ordering::Equal
    );
    assert_eq!(
        Value::Integer((1 << 53) + 1).canonical_cmp(&Value::Double(9_007_199_254_740_992.0)),
        Ordering::Greater
    );
}

#[test]
fn strings_compare_by_utf8_bytes_not_code_units() {
    // U+FF10 (EF BC 90) vs U+10000 (F0 90 80 80): byte order puts U+FF10 first, UTF-16 would not.
    let a = Value::String("\u{FF10}".to_owned());
    let b = Value::String("\u{10000}".to_owned());
    assert_eq!(a.canonical_cmp(&b), Ordering::Less);
    // NFC and NFD forms are distinct values.
    assert_ne!(
        Value::String("\u{304C}".to_owned())
            .canonical_cmp(&Value::String("\u{304B}\u{3099}".to_owned())),
        Ordering::Equal
    );
}

#[test]
fn composite_values_compare_lexicographically() {
    let short = Value::Array(vec![Value::Integer(1)]);
    let long = Value::Array(vec![Value::Integer(1), Value::Integer(0)]);
    assert_eq!(short.canonical_cmp(&long), Ordering::Less);
    assert_eq!(
        map(&[("a", Value::Integer(1))]).canonical_cmp(&map(&[("b", Value::Integer(0))])),
        Ordering::Less
    );
    assert_eq!(
        map(&[("a", Value::Integer(1))]).canonical_cmp(&map(&[("a", Value::Integer(2))])),
        Ordering::Less
    );
    assert_eq!(
        map(&[("a", Value::Integer(1))])
            .canonical_cmp(&map(&[("a", Value::Integer(1)), ("b", Value::Null)])),
        Ordering::Less
    );
    // Vectors: dimension first, then elements.
    assert_eq!(
        Value::Vector(vec![9.0]).canonical_cmp(&Value::Vector(vec![0.0, 0.0])),
        Ordering::Less
    );
    assert_eq!(
        GeoPoint::new(1.0, 0.0)
            .unwrap()
            .cmp(&GeoPoint::new(0.0, 5.0).unwrap()),
        Ordering::Greater
    );
}

#[test]
fn timestamps_and_geopoints_validate_their_ranges() {
    assert!(Timestamp::new(0, 999_999_999).is_ok());
    assert!(Timestamp::new(0, 1_000_000_000).is_err());
    assert!(Timestamp::new(253_402_300_800, 0).is_err()); // year 10000
    assert!(Timestamp::new(-62_135_596_801, 0).is_err()); // before year 1
    assert!(GeoPoint::new(90.0, 180.0).is_ok());
    assert!(GeoPoint::new(90.1, 0.0).is_err());
    assert!(GeoPoint::new(0.0, -180.1).is_err());
    assert!(GeoPoint::new(f64::NAN, 0.0).is_err());
}

#[test]
fn nesting_depth_is_counted_per_map_and_array_level() {
    let mut v = Value::Integer(0);
    for _ in 0..20 {
        v = Value::Array(vec![v]);
    }
    assert_eq!(v.nesting_depth(), 20);
    let deeper = Value::Map(BTreeMap::from([("k".to_owned(), v)]));
    assert_eq!(deeper.nesting_depth(), 21);
    assert_eq!(Value::Integer(1).nesting_depth(), 0);
}

#[test]
fn stored_equality_unifies_nan_but_keeps_numeric_representation() {
    let nan = Value::Double(f64::NAN);
    assert!(nan.stored_eq(&Value::Double(-f64::NAN)));
    assert!(Value::Array(vec![nan.clone()]).stored_eq(&Value::Array(vec![nan.clone()])));
    assert!(Value::Vector(vec![f64::NAN]).stored_eq(&Value::Vector(vec![f64::NAN])));
    let map = |v: Value| Value::Map([("k".to_owned(), v)].into_iter().collect());
    assert!(map(nan.clone()).stored_eq(&map(nan.clone())));
    assert!(!Value::Integer(1).stored_eq(&Value::Double(1.0)));
    assert!(!Value::Double(0.0).stored_eq(&Value::Double(-0.0)));
    assert!(!map(nan.clone()).stored_eq(&map(Value::Null)));
    assert!(!Value::Array(vec![nan.clone()]).stored_eq(&Value::Array(vec![nan, Value::Null])));
    // Ordinary values keep plain equality.
    assert!(Value::String("a".into()).stored_eq(&Value::String("a".into())));
    assert!(!Value::String("a".into()).stored_eq(&Value::String("b".into())));
}

#[test]
fn storage_normalization_truncates_timestamps_to_microseconds_recursively() {
    let ts = |n: u32| Value::Timestamp(Timestamp::new(1, n).unwrap());
    assert_eq!(
        Timestamp::new(1, 999_999_999)
            .unwrap()
            .truncated_to_micros(),
        Timestamp::new(1, 999_999_000).unwrap()
    );
    assert_eq!(
        Timestamp::new(1, 1_000).unwrap().truncated_to_micros(),
        Timestamp::new(1, 1_000).unwrap()
    );
    let mut value = Value::Map(
        [
            ("at".to_owned(), ts(123_456_789)),
            (
                "list".to_owned(),
                Value::Array(vec![ts(999), Value::Integer(1)]),
            ),
        ]
        .into_iter()
        .collect(),
    );
    value.normalize_for_storage();
    assert_eq!(
        value,
        Value::Map(
            [
                ("at".to_owned(), ts(123_456_000)),
                (
                    "list".to_owned(),
                    Value::Array(vec![ts(0), Value::Integer(1)])
                ),
            ]
            .into_iter()
            .collect(),
        )
    );
}

#[test]
fn canonical_order_is_total_over_vectors_with_nan_components() {
    // Elementwise comparison must not treat NaN as equal to every number: with
    // A=[NaN,0], B=[0,1], C=[1,-1] that gave A<B, B<C, A>C.
    let a = Value::Vector(vec![f64::NAN, 0.0]);
    let b = Value::Vector(vec![0.0, 1.0]);
    let c = Value::Vector(vec![1.0, -1.0]);
    assert_eq!(a.canonical_cmp(&b), Ordering::Less);
    assert_eq!(b.canonical_cmp(&c), Ordering::Less);
    assert_eq!(a.canonical_cmp(&c), Ordering::Less);
    assert_eq!(
        Value::Vector(vec![f64::NAN]).canonical_cmp(&Value::Vector(vec![-f64::NAN])),
        Ordering::Equal
    );
    assert_eq!(
        Value::Vector(vec![f64::NEG_INFINITY]).canonical_cmp(&Value::Vector(vec![f64::NAN])),
        Ordering::Greater
    );

    let values = [
        a,
        b,
        c,
        Value::Vector(vec![f64::NAN, f64::NAN]),
        Value::Vector(vec![f64::NAN]),
        Value::Vector(vec![0.0, -0.0]),
        Value::Vector(vec![-0.0, 0.0]),
        Value::Vector(vec![f64::INFINITY, 0.0]),
        Value::Vector(vec![0.0, f64::NEG_INFINITY]),
        Value::Double(f64::NAN),
        Value::Double(0.0),
        Value::Integer(0),
        Value::Array(vec![Value::Double(f64::NAN), Value::Integer(1)]),
        Value::Array(vec![Value::Integer(0), Value::Integer(1)]),
    ];
    for x in &values {
        assert_eq!(x.canonical_cmp(x), Ordering::Equal, "reflexive: {x:?}");
        for y in &values {
            assert_eq!(
                x.canonical_cmp(y),
                y.canonical_cmp(x).reverse(),
                "antisymmetric: {x:?} {y:?}"
            );
            for z in &values {
                if x.canonical_cmp(y) != Ordering::Greater
                    && y.canonical_cmp(z) != Ordering::Greater
                {
                    assert_ne!(
                        x.canonical_cmp(z),
                        Ordering::Greater,
                        "transitive: {x:?} {y:?} {z:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn index_equality_agrees_with_ordering() {
    let values = [
        Value::Integer(1),
        Value::Double(1.0),
        Value::Double(f64::NAN),
        Value::Double(-f64::NAN),
        Value::Double(-0.0),
        Value::Double(0.0),
        Value::GeoPoint(GeoPoint::new(-0.0, 0.0).unwrap()),
        Value::GeoPoint(GeoPoint::new(0.0, -0.0).unwrap()),
        Value::Array(vec![Value::Double(f64::NAN)]),
        Value::Array(vec![Value::Integer(1)]),
        Value::Array(vec![Value::Double(1.0)]),
        Value::Vector(vec![f64::NAN, -0.0]),
        Value::Vector(vec![-f64::NAN, 0.0]),
        Value::Map(
            [("n".to_owned(), Value::Double(f64::NAN))]
                .into_iter()
                .collect(),
        ),
    ];
    for a in &values {
        assert_eq!(IndexValue(a), IndexValue(a));
        for b in &values {
            assert_eq!(
                IndexValue(a).partial_cmp(&IndexValue(b)),
                Some(a.canonical_cmp(b))
            );
            assert_eq!(
                IndexValue(a) == IndexValue(b),
                IndexValue(a).cmp(&IndexValue(b)) == Ordering::Equal,
                "{a:?}, {b:?}"
            );
        }
    }
}

#[test]
fn geopoint_order_treats_signed_zero_as_equal_on_both_axes() {
    for (a, b) in [((-0.0, 0.0), (0.0, 0.0)), ((1.0, -0.0), (1.0, 0.0))] {
        let a = GeoPoint::new(a.0, a.1).unwrap();
        let b = GeoPoint::new(b.0, b.1).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.cmp(&b), Ordering::Equal);
    }
    assert!(GeoPoint::new(-0.0, 1.0).unwrap() > GeoPoint::new(0.0, 0.0).unwrap());
}
