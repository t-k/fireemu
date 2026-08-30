//! Canonical `X-Firebase-AppCheck` classification (specification section 7.3, `AC-HEADER-001`).
//!
//! The property-style cases drive a seeded `SplitMix64` rather than a random generator, so a
//! failure is reproducible from the seed printed in the assertion.

mod support;

use fireemu_core_app_check::header::{
    classify_app_check_header, collect_values, is_app_check_header, HeaderClassification,
};
use fireemu_core_app_check::limits::MAX_TOKEN_BYTES;
use fireemu_core_types::determinism::{DeterministicRng, SplitMix64};

const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhcHAifQ.c2ln";

/// A bounded index from the seeded generator, without a lossy cast.
fn below(rng: &mut SplitMix64, bound: usize) -> usize {
    usize::try_from(rng.next_below(bound as u64)).unwrap_or(0)
}

#[test]
fn zero_values_are_missing_and_exactly_one_eligible_value_is_present() {
    let none: [&str; 0] = [];
    assert_eq!(
        classify_app_check_header(&none),
        HeaderClassification::Missing
    );
    assert_eq!(
        classify_app_check_header(&[TOKEN]),
        HeaderClassification::Present(TOKEN.to_owned())
    );
}

#[test]
fn duplicate_folded_empty_and_oversized_values_are_malformed() {
    // Several field instances: no adapter may pick the first or the last.
    assert_eq!(
        classify_app_check_header(&[TOKEN, TOKEN]),
        HeaderClassification::Malformed
    );
    assert_eq!(
        classify_app_check_header(&[TOKEN, "garbage"]),
        HeaderClassification::Malformed
    );
    assert_eq!(
        classify_app_check_header(&["garbage", TOKEN]),
        HeaderClassification::Malformed
    );
    assert_eq!(
        classify_app_check_header(&[TOKEN, TOKEN, TOKEN]),
        HeaderClassification::Malformed
    );
    // Comma folding is exactly as ambiguous as two instances.
    assert_eq!(
        classify_app_check_header(&[format!("{TOKEN},{TOKEN}").as_str()]),
        HeaderClassification::Malformed
    );
    assert_eq!(
        classify_app_check_header(&[format!("{TOKEN}, {TOKEN}").as_str()]),
        HeaderClassification::Malformed
    );
    // Empty, whitespace, control characters and non-ASCII text.
    for bad in [
        "",
        " ",
        "\t",
        &format!("{TOKEN} "),
        &format!(" {TOKEN}"),
        "tökén",
    ] {
        assert_eq!(
            classify_app_check_header(&[bad]),
            HeaderClassification::Malformed,
            "{bad:?} must not be an eligible value"
        );
    }
    // Exactly at the bound is eligible; one byte more is not.
    let at_bound = "a".repeat(MAX_TOKEN_BYTES);
    assert!(matches!(
        classify_app_check_header(&[at_bound.as_str()]),
        HeaderClassification::Present(_)
    ));
    let over_bound = "a".repeat(MAX_TOKEN_BYTES + 1);
    assert_eq!(
        classify_app_check_header(&[over_bound.as_str()]),
        HeaderClassification::Malformed
    );
}

#[test]
fn the_field_name_is_matched_case_insensitively_and_nothing_else_is_collected() {
    for name in [
        "x-firebase-appcheck",
        "X-Firebase-AppCheck",
        "X-FIREBASE-APPCHECK",
        "x-FiReBaSe-aPpChEcK",
    ] {
        assert!(
            is_app_check_header(name),
            "{name} names the App Check field"
        );
    }
    for name in [
        "x-firebase-app-check",
        "x-firebase-appcheck-token",
        "authorization",
        "",
    ] {
        assert!(!is_app_check_header(name));
    }

    let fields = [
        ("Authorization", "Bearer x"),
        ("X-Firebase-AppCheck", TOKEN),
        ("content-type", "application/json"),
        ("x-firebase-appcheck", "second"),
    ];
    let values = collect_values(fields.iter().copied());
    assert_eq!(values, vec![TOKEN, "second"]);
    assert_eq!(
        classify_app_check_header(&values),
        HeaderClassification::Malformed,
        "mixed-case duplicates are duplicates"
    );
}

#[test]
fn prop_app_check_header_classification_is_canonical() {
    // For every generated list of values, the classification is fully determined by the list:
    // zero values are missing, one eligible value is present and everything else is malformed.
    // The result never depends on the position of a value in the list.
    let mut rng = SplitMix64::new(0x00A9_C11E_C4EC_0001);
    let alphabet: Vec<char> = "abzAZ09-_.,: \t\u{7f}\u{e9}".chars().collect();
    for case in 0..2000u64 {
        let count = below(&mut rng, 4);
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let len = below(&mut rng, 6);
            let value: String = (0..len)
                .map(|_| alphabet[below(&mut rng, alphabet.len())])
                .collect();
            values.push(value);
        }
        let classification = classify_app_check_header(&values);
        let eligible = |v: &String| {
            !v.is_empty()
                && v.len() <= MAX_TOKEN_BYTES
                && v.bytes().all(|b| (0x21..=0x7E).contains(&b) && b != b',')
        };
        let expected = match values.as_slice() {
            [] => HeaderClassification::Missing,
            [only] if eligible(only) => HeaderClassification::Present(only.clone()),
            _ => HeaderClassification::Malformed,
        };
        assert_eq!(classification, expected, "case {case}: {values:?}");

        // Reversing the wire order never changes the answer: no adapter may prefer a value.
        let mut reversed = values.clone();
        reversed.reverse();
        if values.len() != 1 {
            assert_eq!(
                classify_app_check_header(&reversed),
                classification,
                "case {case}: order must not matter for {values:?}"
            );
        }
        // A duplicate of any single value is always malformed.
        if let [only] = values.as_slice() {
            assert_eq!(
                classify_app_check_header(&[only.clone(), only.clone()]),
                HeaderClassification::Malformed,
                "case {case}"
            );
        }
    }
}
