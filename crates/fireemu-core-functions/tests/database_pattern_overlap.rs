//! Whether a write at a path can change an RTDB trigger reference (review S3, 2026-10-25): a
//! write changes a reference when one path is a prefix of the other, so a pattern overlaps a
//! path when the shorter of the two matches the other's leading segments.

use fireemu_core_functions::manifest::DatabasePattern;
use proptest::prelude::*;

#[test]
fn a_pattern_overlaps_its_ancestors_its_matches_and_their_descendants_only() {
    let pattern = DatabasePattern::parse("/users/{uid}/posts/{post=p-*}").unwrap();
    for path in [
        "/",
        "/users",
        "/users/a",
        "/users/a/posts",
        "/users/a/posts/p-1",
        "/users/a/posts/p-1/title",
        "/users/a/posts/p-1/title/deep",
    ] {
        assert!(pattern.overlaps(path), "{path}");
    }
    for path in [
        "/other",
        "/userz/a",
        "/users/a/likes",
        "/users/a/posts/q-1",
        "/users/a/likes/p-1/title",
    ] {
        assert!(!pattern.overlaps(path), "{path}");
    }
    let root = DatabasePattern::parse("/").unwrap();
    assert!(root.overlaps("/"));
    assert!(root.overlaps("/anything/below"));
}

fn segment() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["a", "b", "ab", "p-1", "q-1", "users"]).prop_map(str::to_owned)
}

fn pattern_segment() -> impl Strategy<Value = String> {
    prop_oneof![
        segment(),
        Just("{id}".to_owned()),
        Just("*".to_owned()),
        Just("{id=p-*}".to_owned()),
        Just("a*".to_owned()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// `overlaps` agrees with matching the shorter side's prefix pattern, built by parsing.
    #[test]
    fn overlap_is_a_prefix_match_of_the_shorter_side(
        pattern in prop::collection::vec(pattern_segment(), 0..4),
        path in prop::collection::vec(segment(), 0..6),
    ) {
        // Capture names must be unique; number them.
        let pattern: Vec<String> = pattern
            .into_iter()
            .enumerate()
            .map(|(index, part)| part.replace("{id", &format!("{{id{index}")))
            .collect();
        let parsed = DatabasePattern::parse(&format!("/{}", pattern.join("/"))).unwrap();
        let shared = pattern.len().min(path.len());
        let prefix = DatabasePattern::parse(&format!("/{}", pattern[..shared].join("/"))).unwrap();
        let expected = prefix.matches(&format!("/{}", path[..shared].join("/"))).is_some();
        prop_assert_eq!(parsed.overlaps(&format!("/{}", path.join("/"))), expected);
    }
}
