//! Cloud Storage's bucket naming rules, which the strict profile applies to a name a client sends
//! (`BucketName::try_new` is wider on purpose).

use fireemu_core_storage::name::bucket_name_violation;
use proptest::prelude::*;

#[test]
fn names_cloud_storage_accepts() {
    for name in [
        "abc",
        "demo-app.appspot.com",
        "demo-app.firebasestorage.app",
        "a-b_c.d9",
        "123",
        "1.2.3",
        "1.2.3.4.5",
        "256.1.1.1",
        "my-goo-bucket",
        "goo-gle-bucket",
        &"a".repeat(63),
        &format!("{}.{}", "a".repeat(63), "b".repeat(63)),
    ] {
        assert_eq!(bucket_name_violation(name), None, "{name}");
    }
}

#[test]
fn names_cloud_storage_refuses() {
    let long_component = "a".repeat(64);
    let too_long = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(40)
    );
    for name in [
        "",
        "a",
        "ab",
        "Abc",
        "ab c",
        "ab/c",
        "-abc",
        "abc-",
        "_abc",
        "abc_",
        ".abc",
        "abc.",
        "a..b",
        "goog-bucket",
        "googlebucket",
        "my-google-bucket",
        "1.2.3.4",
        "255.255.255.255",
        "0.0.0.0",
        &long_component,
        &too_long,
        "bücket",
    ] {
        assert!(bucket_name_violation(name).is_some(), "{name:?}");
    }
    // The boundaries: 3 characters pass and 2 do not; 222 pass and 223 do not.
    assert_eq!(bucket_name_violation("abc"), None);
    assert!(bucket_name_violation("ab").is_some());
    let at_limit = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(30)
    );
    assert_eq!(at_limit.len(), 222);
    assert_eq!(bucket_name_violation(&at_limit), None);
    assert!(bucket_name_violation(&format!("{at_limit}d")).is_some());
    // An address-shaped name is refused only when all four parts are 0 to 255.
    assert!(bucket_name_violation("10.0.0.1").is_some());
    assert_eq!(bucket_name_violation("10.0.0.256"), None);
}

/// The rules written out again, apart from the implementation.
fn reference_valid(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() < 3 || bytes.len() > 222 {
        return false;
    }
    let edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !edge(bytes[0]) || !edge(bytes[bytes.len() - 1]) {
        return false;
    }
    if !bytes
        .iter()
        .all(|b| edge(*b) || matches!(b, b'-' | b'_' | b'.'))
    {
        return false;
    }
    if name
        .split('.')
        .any(|part| part.is_empty() || part.len() > 63)
    {
        return false;
    }
    if name.starts_with("goog") || name.contains("google") {
        return false;
    }
    let parts: Vec<&str> = name.split('.').collect();
    !(parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn the_rules_agree_with_the_reference(
        name in "[a-z0-9._-]{0,80}|goog[a-z0-9.-]{0,20}|[a-z0-9-]{0,5}google[a-z0-9-]{0,5}|[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}|[a-z0-9]{60,70}(\\.[a-z0-9]{1,70}){0,3}|[A-Z a-z0-9/]{0,8}"
    ) {
        prop_assert_eq!(bucket_name_violation(&name).is_none(), reference_valid(&name), "{}", name);
    }
}
