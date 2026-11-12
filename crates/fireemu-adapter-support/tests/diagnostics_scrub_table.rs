//! Each credential shape that `scrub` masks, on its own, with its near misses. The shapes are
//! built at run time so no source line holds a complete credential-shaped literal.

use fireemu_adapter_support::diagnostics::redact::scrub;

fn masked(text: &str) -> bool {
    let (out, count) = scrub(text);
    assert_eq!(
        out == "[redacted]",
        count == 1,
        "count and output disagree for {text:?}"
    );
    count == 1
}

#[test]
fn each_credential_shape_is_masked_on_its_own() {
    let api_key = format!("{}{}", "AIza", "a".repeat(35));
    let jwt = format!(
        "{}.{}.{}",
        "eyJ".to_owned() + &"a".repeat(10),
        "b".repeat(10),
        "c".repeat(10)
    );
    let cases = [
        format!("{}{}", "Author", "ization: header"),
        format!("{}{}", "use Bear", "er abcdefgh"),
        format!("{}{}", "ya", "29.token-value"),
        api_key,
        format!("{}{}", "-----BEG", "IN PRIVATE KEY-----"),
        format!("{}{}", "\"private", "_key\": 1"),
        jwt,
        format!(
            "{}.{}.{}",
            "eyJ".to_owned() + &"a".repeat(5),
            "b".repeat(4),
            ""
        ),
        format!("refreshToken\":\"{}", "r".repeat(60)),
    ];
    for case in &cases {
        assert!(masked(case), "not masked: {case:?}");
    }
}

#[test]
fn near_misses_of_each_shape_are_kept() {
    let kept = [
        "authority of the site".to_owned(),
        "Bearer".to_owned(),
        "Bearer  token".to_owned(),
        format!("{}{}", "AIza", "a".repeat(34)),
        format!("{}{}", "ya", "30.token-value"),
        format!("{}{}", "BEGIN ", "PRIVATE KEY"),
        format!(
            "{}.{}.{}",
            "eyJ".to_owned() + &"a".repeat(3),
            "b".repeat(10),
            "c".repeat(10)
        ),
        format!(
            "{}.{}.{}",
            "xyz".to_owned() + &"a".repeat(10),
            "b".repeat(10),
            "c".repeat(10)
        ),
        "plain log line with no credential".to_owned(),
    ];
    for text in &kept {
        assert!(!masked(text), "wrongly masked: {text:?}");
        assert_eq!(scrub(text).0, *text);
    }
}

#[test]
fn a_home_directory_path_is_rewritten_and_counted() {
    assert_eq!(
        scrub("/Users/alice/project/src/lib.rs"),
        ("~/project/src/lib.rs".to_owned(), 1)
    );
    assert_eq!(scrub("/home/bob/x"), ("~/x".to_owned(), 1));
    assert_eq!(scrub("C:\\Users\\carol\\y.txt"), ("~/y.txt".to_owned(), 1));
    assert_eq!(scrub("/Users/alice"), ("~/".to_owned(), 1));
    assert_eq!(scrub("/usr/local/bin").1, 0);
}
