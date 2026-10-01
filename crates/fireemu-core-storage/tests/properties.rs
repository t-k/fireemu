//! Property tests of the object store: listing and paging against a reference listing, and the
//! store's state against a reference model under random sequences of writes and guards.

// Two-armed `match`es keep the property walks symmetric (a token continues, none ends).
#![allow(clippy::single_match_else)]

use std::collections::{BTreeMap, BTreeSet};

use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{
    CustomMetadataPatch, ListPage, MetadataPatch, NewMetadata, Precondition, StorageError,
    StorageState,
};
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;

fn at(n: i64) -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_000_000 + n)
}

fn bucket() -> BucketName {
    BucketName::try_new("demo-app.appspot.com").unwrap()
}

fn object(name: &str) -> ObjectName {
    ObjectName::try_new(name).unwrap()
}

const SEGMENTS: &[&str] = &["a", "b", "c", "dir", "dir2", "x", "a.txt", "Z"];

/// Object names of one to three segments from a small alphabet, so that prefixes repeat.
fn names() -> impl Strategy<Value = BTreeSet<String>> {
    proptest::collection::btree_set(
        proptest::collection::vec(proptest::sample::select(SEGMENTS), 1..=3)
            .prop_map(|segments| segments.join("/")),
        0..=24,
    )
}

fn store_with(names: &BTreeSet<String>) -> StorageState {
    let mut store = StorageState::new(7);
    for (index, name) in names.iter().enumerate() {
        store
            .put(
                &bucket(),
                &object(name),
                vec![u8::try_from(index % 251).unwrap()],
                NewMetadata::default(),
                Precondition::default(),
                at(1),
            )
            .unwrap();
    }
    store
}

/// Every entry of a page, items and prefixes together, in name order.
fn entries(page: &ListPage) -> Vec<String> {
    let mut all: Vec<String> = page
        .items
        .iter()
        .map(|item| item.name.as_str().to_owned())
        .chain(page.prefixes.iter().cloned())
        .collect();
    all.sort();
    all
}

/// The reference listing: every name under `prefix`, folded at the first delimiter after it,
/// each folded prefix once, in byte order.
fn reference_entries(
    names: &BTreeSet<String>,
    prefix: &str,
    delimiter: Option<&str>,
) -> Vec<String> {
    let mut entries = BTreeSet::new();
    for name in names {
        let Some(rest) = name.strip_prefix(prefix) else {
            continue;
        };
        match delimiter.and_then(|d| rest.find(d).map(|i| (i, d))) {
            Some((i, d)) => {
                entries.insert(format!("{prefix}{}{d}", &rest[..i]));
            }
            None => {
                entries.insert(name.clone());
            }
        }
    }
    entries.into_iter().collect()
}

fn prefixes() -> impl Strategy<Value = &'static str> {
    proptest::sample::select(&["", "a", "a/", "dir/", "dir2/", "x/b", "Z/"][..])
}

fn delimiters() -> impl Strategy<Value = Option<&'static str>> {
    proptest::sample::select(&[None, Some("/")][..])
}

proptest! {
    /// Walking a listing with `list_after` (the Firebase dialect's paging: the token names the last
    /// entry returned) yields exactly the reference listing: no entry twice, none missing, in
    /// name order, never more than `max` per page, and a token exactly when more entries follow.
    #[test]
    fn list_after_pages_concatenate_to_the_reference_listing(
        names in names(),
        prefix in prefixes(),
        delimiter in delimiters(),
        max in 1usize..=5,
    ) {
        let store = store_with(&names);
        let expected = reference_entries(&names, prefix, delimiter);
        let mut seen = Vec::new();
        let mut after: Option<String> = None;
        for _ in 0..expected.len() + 2 {
            let page = store.list_after(&bucket(), prefix, delimiter, after.as_deref(), max);
            let page_entries = entries(&page);
            prop_assert!(page_entries.len() <= max);
            seen.extend(page_entries.clone());
            match page.next_page_token {
                Some(token) => {
                    prop_assert_eq!(page_entries.len(), max, "a token only follows a full page");
                    prop_assert_eq!(Some(&token), page_entries.last(), "the token is the last entry");
                    after = Some(token);
                }
                None => {
                    prop_assert_eq!(seen, expected);
                    return Ok(());
                }
            }
        }
        prop_assert!(false, "the walk did not end");
    }

    /// The same for `list`, whose token names the first entry of the next page (the JSON API's).
    #[test]
    fn list_pages_concatenate_to_the_reference_listing(
        names in names(),
        prefix in prefixes(),
        delimiter in delimiters(),
        max in 1usize..=5,
    ) {
        let store = store_with(&names);
        let expected = reference_entries(&names, prefix, delimiter);
        let mut seen = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..expected.len() + 2 {
            let page = store.list(&bucket(), prefix, delimiter, token.as_deref(), Some(max));
            let page_entries = entries(&page);
            prop_assert!(page_entries.len() <= max);
            seen.extend(page_entries);
            match page.next_page_token {
                Some(next) => {
                    prop_assert!(!seen.contains(&next), "the token names an entry not yet listed");
                    token = Some(next);
                }
                None => {
                    prop_assert_eq!(seen, expected);
                    return Ok(());
                }
            }
        }
        prop_assert!(false, "the walk did not end");
    }

    /// A page with a token starts exactly where the reference listing resumes after it.
    #[test]
    fn list_after_resumes_after_any_point(
        names in names(),
        prefix in prefixes(),
        delimiter in delimiters(),
        point in proptest::sample::select(&["", "a", "a/b", "b", "dir/", "dir/x", "dir2/", "zz"][..]),
    ) {
        let store = store_with(&names);
        let expected = reference_entries(&names, prefix, delimiter);
        let page = store.list_after(&bucket(), prefix, delimiter, Some(point), 1000);
        let resumed: Vec<String> = expected.into_iter().filter(|entry| entry.as_str() > point).collect();
        prop_assert_eq!(entries(&page), resumed);
        prop_assert_eq!(page.next_page_token, None);
    }
}

// ------------------------------------------------------------------------------------------
// glob and filtered listing against reference implementations
// ------------------------------------------------------------------------------------------

/// A reference matcher for the documented glob syntax, structured differently from the
/// implementation: braces are expanded to brace-free patterns, each of which is matched by a
/// dynamic programme over (pattern element, name position).
mod reference_glob {
    #[derive(Clone, Debug)]
    enum Element {
        Literal(char),
        Segment,
        Any,
        One,
        Class(Vec<(char, char)>, bool),
    }

    /// Every brace-free pattern a pattern stands for; an unterminated brace is a literal.
    pub fn expand(pattern: &[char]) -> Vec<Vec<char>> {
        let mut i = 0;
        while i < pattern.len() {
            match pattern[i] {
                '\\' => i += 2,
                '[' => {
                    // A set hides braces from the expansion only if it is terminated.
                    match set_end(pattern, i) {
                        Some(end) => i = end,
                        None => i += 1,
                    }
                }
                '{' => {
                    if let Some((alternatives, end)) = alternatives(pattern, i) {
                        let mut out = Vec::new();
                        for alternative in alternatives {
                            let mut joined = pattern[..i].to_vec();
                            glue(&mut joined, &alternative);
                            glue(&mut joined, &pattern[end..]);
                            out.extend(expand(&joined));
                        }
                        return out;
                    }
                    // Unterminated: keep the brace literally by escaping it, then go on.
                    let mut escaped = pattern[..i].to_vec();
                    escaped.push('\\');
                    escaped.push('{');
                    escaped.extend_from_slice(&pattern[i + 1..]);
                    return expand(&escaped);
                }
                _ => i += 1,
            }
        }
        vec![pattern.to_vec()]
    }

    /// Appends `right` to `left`. Two stars that come from different syntactic places stay two
    /// segment stars: a marker keeps them from reading as one `**` (`*{x,}*` is not `**`).
    fn glue(left: &mut Vec<char>, right: &[char]) {
        if left.last() == Some(&'*') && right.first() == Some(&'*') {
            left.push('\u{1}');
        }
        left.extend_from_slice(right);
    }

    fn set_end(pattern: &[char], start: usize) -> Option<usize> {
        let mut at = start + 1;
        if matches!(pattern.get(at), Some('!' | '^')) {
            at += 1;
        }
        let mut first = true;
        while let Some(&c) = pattern.get(at) {
            if c == ']' && !first {
                return Some(at + 1);
            }
            first = false;
            at += if c == '\\' { 2 } else { 1 };
        }
        None
    }

    /// The alternatives of a brace group starting at `start` and the index after its `}`.
    fn alternatives(pattern: &[char], start: usize) -> Option<(Vec<Vec<char>>, usize)> {
        let mut depth = 0;
        let mut parts = vec![Vec::new()];
        let mut i = start;
        while i < pattern.len() {
            let c = pattern[i];
            match c {
                '\\' => {
                    parts.last_mut().unwrap().push(c);
                    parts.last_mut().unwrap().push(*pattern.get(i + 1)?);
                    i += 2;
                    continue;
                }
                '{' => {
                    depth += 1;
                    if depth > 1 {
                        parts.last_mut().unwrap().push(c);
                    }
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some((parts, i + 1));
                    }
                    parts.last_mut().unwrap().push(c);
                }
                ',' if depth == 1 => parts.push(Vec::new()),
                _ => parts.last_mut().unwrap().push(c),
            }
            i += 1;
        }
        None
    }

    fn elements(pattern: &[char]) -> Vec<Element> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < pattern.len() {
            match pattern[i] {
                '\\' => {
                    out.push(Element::Literal(*pattern.get(i + 1).unwrap_or(&'\\')));
                    i += 2;
                }
                '*' => {
                    let mut run = 1;
                    while pattern.get(i + run) == Some(&'*') {
                        run += 1;
                    }
                    out.push(if run >= 2 {
                        Element::Any
                    } else {
                        Element::Segment
                    });
                    i += run;
                }
                '?' => {
                    out.push(Element::One);
                    i += 1;
                }
                '\u{1}' => i += 1,
                '[' => match set_end(pattern, i) {
                    Some(end) => {
                        let mut at = i + 1;
                        let negated = matches!(pattern.get(at), Some('!' | '^'));
                        if negated {
                            at += 1;
                        }
                        let mut ranges = Vec::new();
                        let mut first = true;
                        while at < end - 1 || (first && at < end) {
                            if pattern[at] == ']' && !first {
                                break;
                            }
                            first = false;
                            let mut low = pattern[at];
                            if low == '\\' {
                                at += 1;
                                low = pattern[at];
                            }
                            at += 1;
                            if pattern.get(at) == Some(&'-') && at + 1 < end - 1 {
                                let mut high = pattern[at + 1];
                                at += 2;
                                if high == '\\' {
                                    high = pattern[at];
                                    at += 1;
                                }
                                ranges.push((low, high));
                            } else {
                                ranges.push((low, low));
                            }
                        }
                        out.push(Element::Class(ranges, negated));
                        i = end;
                    }
                    None => {
                        out.push(Element::Literal('['));
                        i += 1;
                    }
                },
                c => {
                    out.push(Element::Literal(c));
                    i += 1;
                }
            }
        }
        out
    }

    fn matches_simple(pattern: &[char], name: &[char]) -> bool {
        let elements = elements(pattern);
        // table[i][j]: elements[i..] match name[j..].
        let mut table = vec![vec![false; name.len() + 1]; elements.len() + 1];
        table[elements.len()][name.len()] = true;
        for i in (0..elements.len()).rev() {
            for j in (0..=name.len()).rev() {
                table[i][j] = match &elements[i] {
                    Element::Literal(c) => name.get(j) == Some(c) && table[i + 1][j + 1],
                    Element::One => name.get(j).is_some_and(|&c| c != '/') && table[i + 1][j + 1],
                    Element::Class(ranges, negated) => {
                        name.get(j).is_some_and(|&c| {
                            c != '/'
                                && (ranges.iter().any(|&(low, high)| low <= c && c <= high)
                                    != *negated)
                        }) && table[i + 1][j + 1]
                    }
                    Element::Segment => {
                        let mut ok = table[i + 1][j];
                        let mut k = j;
                        while !ok && k < name.len() && name[k] != '/' {
                            k += 1;
                            ok = table[i + 1][k];
                        }
                        ok
                    }
                    Element::Any => (j..=name.len()).any(|k| table[i + 1][k]),
                };
            }
        }
        table[0][0]
    }

    pub fn matches(pattern: &str, name: &str) -> bool {
        let pattern: Vec<char> = pattern.chars().collect();
        let name: Vec<char> = name.chars().collect();
        expand(&pattern)
            .iter()
            .any(|simple| matches_simple(simple, &name))
    }
}

fn glob_fragments() -> impl Strategy<Value = String> {
    proptest::collection::vec(
        proptest::sample::select(
            &[
                "a",
                "b",
                "dir",
                "dir2",
                "/",
                "x",
                ".txt",
                "*",
                "**",
                "?",
                "[ab]",
                "[!a]",
                "[a-c]",
                "[^b]",
                "{a,b}",
                "{dir,dir2}",
                "{x,}",
                "\\*",
                "\\?",
                "[",
                "{",
                "}",
                ",",
            ][..],
        ),
        0..=6,
    )
    .prop_map(|fragments| fragments.concat())
}

fn glob_names() -> impl Strategy<Value = String> {
    "[abcx/.]{0,10}"
}

/// Constructs the random patterns reach only rarely: a `**` after a long literal, escapes and
/// ranges inside sets, a leading `]`, a trailing dash and several ranges.
#[test]
fn glob_constructs_match_as_documented() {
    use fireemu_core_storage::glob::glob_matches;
    for (pattern, name, expected) in [
        ("abc**d", "abcxx/yd", true),
        ("abc**d", "abcxx/y", false),
        ("abcd**e", "abcdXe", true),
        ("abcd**e", "abcdX", false),
        ("a**b**c", "a/x/b/y/c", true),
        ("a***b", "a/b", true),
        ("*{x,}*", "/", false),
        ("*{x,}*", "x", true),
        ("*{x,}*", "", true),
        ("{a,}*", "/", false),
        ("*{,a}", "/", false),
        ("[a-c]", "b", true),
        ("[a-c]", "d", false),
        ("[a-c0-9]", "5", true),
        ("[a-c0-9]", "e", false),
        ("[a\\-c]", "-", true),
        ("[a\\-c]", "b", false),
        ("[]a]", "]", true),
        ("[]a]", "a", true),
        ("[]a]", "b", false),
        ("[a-]", "-", true),
        ("[a-]", "b", false),
        ("[\\]x]", "]", true),
        ("[\\]x]", "\\", false),
        ("[a-\\z]", "m", true),
        // An escaped upper bound ends the range and nothing else: the cursor moves past it once.
        ("[Z-\\]]x", "[x", true),
        ("[Z-\\]]x", "]x", true),
        ("[Z-\\]]x", "Zx", true),
        ("[Z-\\]]x", "^x", false),
        ("[Z-\\]]x", "]]x", false),
        ("[z-\\a]", "a", false),
        ("[z-\\a]", "z", false),
        ("[!a-c]", "d", true),
        ("[!a-c]", "b", false),
        ("[^x]", "y", true),
        ("[^x]", "x", false),
        ("[a-c]", "/", false),
        ("[!a]", "/", false),
        ("[!a]", "!", true),
        ("[^a]", "^", true),
        ("[!a]", "[", true),
        ("[^a]", "a", false),
        ("{a,bc}d", "bcd", true),
        ("{a,bc}d", "ad", true),
        ("{a,bc}d", "bd", false),
        ("x{a,{b,c}}y", "xcy", true),
        ("{a", "{a", true),
        ("a}", "a}", true),
        ("a,b", "a,b", true),
        ("a\\", "a\\", true),
        ("\\a", "a", true),
        ("?", "/", false),
        ("?*", "a/b", false),
        ("*", "", true),
        ("**", "", true),
        ("*/*", "a/b", true),
        ("*/*", "a/b/c", false),
    ] {
        assert_eq!(
            glob_matches(pattern, name),
            expected,
            "{pattern:?} against {name:?}"
        );
        assert_eq!(
            reference_glob::matches(pattern, name),
            expected,
            "reference {pattern:?} against {name:?}"
        );
    }
}

#[test]
fn the_recorded_globs_match_as_production_listed_them() {
    use fireemu_core_storage::glob::glob_matches;
    // Recorded, lean-v5: `<prefix>dir/*` lists `dir/c.txt` and `dir/d.txt` and nothing else.
    for (name, expected) in [
        ("list/gcs/dir/c.txt", true),
        ("list/gcs/dir/d.txt", true),
        ("list/gcs/dir2/e.txt", false),
        ("list/gcs/a.txt", false),
        ("list/gcs/zz.txt", false),
        ("list/gcs/dir/x/y.txt", false),
    ] {
        assert_eq!(glob_matches("list/gcs/dir/*", name), expected, "{name}");
    }
    assert!(glob_matches("list/**", "list/gcs/dir/x/y.txt"));
    assert!(glob_matches("a?c", "abc") && !glob_matches("a?c", "a/c"));
    assert!(glob_matches("{x,y}.txt", "y.txt") && !glob_matches("{x,y}.txt", "z.txt"));
    assert!(glob_matches("[a-c]*", "bee") && !glob_matches("[!a-c]*", "bee"));
    assert!(glob_matches("a\\*b", "a*b") && !glob_matches("a\\*b", "axb"));
    // An unterminated set or group is literal.
    assert!(glob_matches("a[b", "a[b") && glob_matches("a{b", "a{b"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// The implementation agrees with the reference matcher on random patterns and names.
    #[test]
    fn glob_matching_agrees_with_the_reference(pattern in glob_fragments(), name in glob_names()) {
        prop_assert_eq!(
            fireemu_core_storage::glob::glob_matches(&pattern, &name),
            reference_glob::matches(&pattern, &name),
            "pattern {:?} name {:?}", pattern, name
        );
    }

    /// A filtered listing walked page by page equals the reference listing of the names the
    /// reference filter accepts (offsets inclusive and exclusive, glob over the whole name).
    #[test]
    fn filtered_listing_pages_equal_the_filtered_reference(
        names in names(),
        prefix in prefixes(),
        delimiter in delimiters(),
        max in 1usize..=5,
        start in proptest::option::of(proptest::sample::select(&["", "a", "b", "dir/", "dir2/", "x"][..])),
        end in proptest::option::of(proptest::sample::select(&["b", "dir/", "dir2", "x", "zz"][..])),
        pattern in proptest::option::of(glob_fragments()),
    ) {
        let store = store_with(&names);
        let accepted = |name: &str| {
            start.is_none_or(|s| name >= s)
                && end.is_none_or(|e| name < e)
                && pattern.as_deref().is_none_or(|p| reference_glob::matches(p, name))
        };
        let kept: BTreeSet<String> = names.iter().filter(|n| accepted(n)).cloned().collect();
        let expected = reference_entries(&kept, prefix, delimiter);
        let filter = |name: &str| {
            start.is_none_or(|s| name >= s)
                && end.is_none_or(|e| name < e)
                && pattern.as_deref().is_none_or(|p| fireemu_core_storage::glob::glob_matches(p, name))
        };
        let mut seen = Vec::new();
        let mut token: Option<String> = None;
        for _ in 0..expected.len() + 2 {
            let page = store.list_matching(&bucket(), prefix, delimiter, token.as_deref(), Some(max), &filter);
            let page_entries = entries(&page);
            prop_assert!(page_entries.len() <= max);
            seen.extend(page_entries);
            match page.next_page_token {
                Some(next) => token = Some(next),
                None => {
                    prop_assert_eq!(seen, expected);
                    return Ok(());
                }
            }
        }
        prop_assert!(false, "the walk did not end");
    }
}

// ------------------------------------------------------------------------------------------
// a reference model of the store
// ------------------------------------------------------------------------------------------

const UNIVERSE: &[&str] = &["a", "b", "dir/c"];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelObject {
    generation: u64,
    metageneration: u64,
    bytes: Vec<u8>,
    custom: BTreeMap<String, String>,
}

/// Which guard an operation carries; its value is resolved against the model at run time so that
/// matching and non-matching values are both exercised.
#[derive(Debug, Clone, Copy)]
enum Guard {
    None,
    GenerationMatchesCurrent,
    GenerationMatchesOther,
    GenerationMatchesAbsent,
    MetagenerationMatchesCurrent,
    MetagenerationMatchesOther,
    GenerationNotMatchCurrent,
    GenerationNotMatchOther,
    MetagenerationNotMatchCurrent,
}

#[derive(Debug, Clone)]
enum Op {
    Put {
        name: usize,
        byte: u8,
        custom: Option<(u8, u8)>,
        guard: Guard,
    },
    Patch {
        name: usize,
        key: u8,
        value: Option<u8>,
        guard: Guard,
    },
    Replace {
        name: usize,
        key: u8,
        value: u8,
        guard: Guard,
    },
    Delete {
        name: usize,
        guard: Guard,
    },
}

fn guards() -> impl Strategy<Value = Guard> {
    prop_oneof![
        3 => Just(Guard::None),
        1 => Just(Guard::GenerationMatchesCurrent),
        1 => Just(Guard::GenerationMatchesOther),
        1 => Just(Guard::GenerationMatchesAbsent),
        1 => Just(Guard::MetagenerationMatchesCurrent),
        1 => Just(Guard::MetagenerationMatchesOther),
        1 => Just(Guard::GenerationNotMatchCurrent),
        1 => Just(Guard::GenerationNotMatchOther),
        1 => Just(Guard::MetagenerationNotMatchCurrent),
    ]
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    let name = 0..UNIVERSE.len();
    proptest::collection::vec(
        prop_oneof![
            (
                name.clone(),
                any::<u8>(),
                proptest::option::of((0u8..3, any::<u8>())),
                guards()
            )
                .prop_map(|(name, byte, custom, guard)| Op::Put {
                    name,
                    byte,
                    custom,
                    guard
                }),
            (
                name.clone(),
                0u8..3,
                proptest::option::of(any::<u8>()),
                guards()
            )
                .prop_map(|(name, key, value, guard)| Op::Patch {
                    name,
                    key,
                    value,
                    guard
                }),
            (name.clone(), 0u8..3, any::<u8>(), guards()).prop_map(|(name, key, value, guard)| {
                Op::Replace {
                    name,
                    key,
                    value,
                    guard,
                }
            }),
            (name, guards()).prop_map(|(name, guard)| Op::Delete { name, guard }),
        ],
        1..=40,
    )
}

fn key_name(key: u8) -> String {
    format!("k{key}")
}

/// The precondition a guard stands for against the model's current object (`None` = absent).
fn precondition(guard: Guard, current: Option<&ModelObject>) -> Precondition {
    let generation = current.map_or(0, |object| object.generation);
    let metageneration = current.map_or(0, |object| object.metageneration);
    let mut pre = Precondition::default();
    match guard {
        Guard::None => {}
        Guard::GenerationMatchesCurrent => pre.if_generation_match = Some(generation),
        Guard::GenerationMatchesOther => pre.if_generation_match = Some(generation + 1000),
        Guard::GenerationMatchesAbsent => pre.if_generation_match = Some(0),
        Guard::MetagenerationMatchesCurrent => pre.if_metageneration_match = Some(metageneration),
        Guard::MetagenerationMatchesOther => {
            pre.if_metageneration_match = Some(metageneration + 1000);
        }
        Guard::GenerationNotMatchCurrent => pre.if_generation_not_match = Some(generation),
        Guard::GenerationNotMatchOther => pre.if_generation_not_match = Some(generation + 1000),
        Guard::MetagenerationNotMatchCurrent => {
            pre.if_metageneration_not_match = Some(metageneration);
        }
    }
    pre
}

/// What the guards document, written independently of `Precondition::check`: a match guard that
/// does not hold is a refusal, a not-match guard that names the current value is "not modified",
/// and an absent object satisfies only `ifGenerationMatch = 0` (and no guard at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Applies,
    Refused,
    NotModified,
}

fn verdict(pre: &Precondition, current: Option<&ModelObject>) -> Verdict {
    let Some(object) = current else {
        let only_absent_match = pre.if_metageneration_match.is_none()
            && pre.if_generation_not_match.is_none()
            && pre.if_metageneration_not_match.is_none()
            && matches!(pre.if_generation_match, None | Some(0));
        return if only_absent_match {
            Verdict::Applies
        } else {
            Verdict::Refused
        };
    };
    if pre
        .if_generation_match
        .is_some_and(|g| g != object.generation)
        || pre
            .if_metageneration_match
            .is_some_and(|m| m != object.metageneration)
    {
        return Verdict::Refused;
    }
    if pre.if_generation_not_match == Some(object.generation)
        || pre.if_metageneration_not_match == Some(object.metageneration)
    {
        return Verdict::NotModified;
    }
    Verdict::Applies
}

fn classify(result: &Result<(), StorageError>) -> Verdict {
    match result {
        Ok(()) => Verdict::Applies,
        Err(StorageError::PreconditionFailed(_)) => Verdict::Refused,
        Err(StorageError::NotModified(_)) => Verdict::NotModified,
        Err(other) => panic!("unexpected error {other:?}"),
    }
}

proptest! {
    /// The store agrees with a small reference model under random sequences of puts (with and
    /// without custom metadata), merging patches, replacing updates and deletes, each under a
    /// random guard: the same refusals, and after every step the same objects with the same
    /// generation, metageneration, bytes and custom metadata.
    #[test]
    fn the_store_agrees_with_a_reference_model(ops in ops()) {
        let mut store = StorageState::new(11);
        let mut model: BTreeMap<usize, ModelObject> = BTreeMap::new();
        let mut generations = 0u64;
        for (step, op) in ops.iter().enumerate() {
            let now = at(i64::try_from(step).unwrap());
            match op {
                Op::Put { name, byte, custom, guard } => {
                    let pre = precondition(*guard, model.get(name));
                    let expected = verdict(&pre, model.get(name));
                    let metadata = NewMetadata {
                        custom: custom.map(|(key, value)| {
                            BTreeMap::from([(key_name(key), value.to_string())])
                        }),
                        ..NewMetadata::default()
                    };
                    let result = store
                        .put(&bucket(), &object(UNIVERSE[*name]), vec![*byte], metadata, pre, now)
                        .map(|_| ());
                    prop_assert_eq!(classify(&result), expected, "{:?}", op);
                    if expected == Verdict::Applies {
                        generations += 1;
                        model.insert(*name, ModelObject {
                            generation: generations,
                            metageneration: 1,
                            bytes: vec![*byte],
                            custom: custom
                                .map(|(key, value)| BTreeMap::from([(key_name(key), value.to_string())]))
                                .unwrap_or_default(),
                        });
                    }
                }
                Op::Patch { .. } | Op::Replace { .. } => {
                    let (name, key, guard, entry, is_replace) = match op {
                        Op::Patch { name, key, value, guard } => {
                            (*name, *key, *guard, value.map(|v| v.to_string()), false)
                        }
                        Op::Replace { name, key, value, guard } => {
                            (*name, *key, *guard, Some(value.to_string()), true)
                        }
                        _ => unreachable!(),
                    };
                    // An update of an absent object is a plain 404 whatever the guard says
                    // (guards are only meaningful against a live object here).
                    let Some(current) = model.get(&name).cloned() else {
                        let result = store.update_metadata(
                            &bucket(),
                            &object(UNIVERSE[name]),
                            &MetadataPatch::default(),
                            Precondition::default(),
                            now,
                        );
                        prop_assert_eq!(result.err(), Some(StorageError::NotFound));
                        continue;
                    };
                    let pre = precondition(guard, Some(&current));
                    let expected = verdict(&pre, Some(&current));
                    let (patch, applied) = if is_replace {
                        let value = entry.clone().unwrap();
                        (
                            MetadataPatch {
                                custom: Some(CustomMetadataPatch::Replace(BTreeMap::from([(
                                    key_name(key),
                                    value.clone(),
                                )]))),
                                ..MetadataPatch::default()
                            },
                            BTreeMap::from([(key_name(key), value)]),
                        )
                    } else {
                        let mut merged = current.custom.clone();
                        match &entry {
                            Some(v) => {
                                merged.insert(key_name(key), v.clone());
                            }
                            None => {
                                merged.remove(&key_name(key));
                            }
                        }
                        (
                            MetadataPatch {
                                custom: Some(CustomMetadataPatch::Merge(BTreeMap::from([(
                                    key_name(key),
                                    entry.clone(),
                                )]))),
                                ..MetadataPatch::default()
                            },
                            merged,
                        )
                    };
                    let result = store
                        .update_metadata(&bucket(), &object(UNIVERSE[name]), &patch, pre, now)
                        .map(|_| ());
                    prop_assert_eq!(classify(&result), expected, "{:?}", op);
                    if expected == Verdict::Applies {
                        let object = model.get_mut(&name).unwrap();
                        object.metageneration += 1;
                        object.custom = applied;
                    }
                }
                Op::Delete { name, guard } => {
                    let Some(current) = model.get(name).cloned() else {
                        let result = store.delete(
                            &bucket(),
                            &object(UNIVERSE[*name]),
                            Precondition::default(),
                        );
                        prop_assert_eq!(result.err(), Some(StorageError::NotFound));
                        continue;
                    };
                    let pre = precondition(*guard, Some(&current));
                    let expected = verdict(&pre, Some(&current));
                    let result = store
                        .delete(&bucket(), &object(UNIVERSE[*name]), pre)
                        .map(|_| ());
                    prop_assert_eq!(classify(&result), expected, "{:?}", op);
                    if expected == Verdict::Applies {
                        model.remove(name);
                    }
                }
            }
            // The whole state agrees after every step.
            for (index, name) in UNIVERSE.iter().enumerate() {
                let actual = store.get(&bucket(), &object(name));
                match (actual, model.get(&index)) {
                    (None, None) => {}
                    (Some(actual), Some(expected)) => {
                        prop_assert_eq!(actual.generation, expected.generation);
                        prop_assert_eq!(actual.metageneration, expected.metageneration);
                        prop_assert_eq!(&actual.custom, &expected.custom);
                        prop_assert_eq!(store.bytes(actual), expected.bytes.as_slice());
                    }
                    (actual, expected) => {
                        prop_assert!(false, "{name}: store {actual:?} model {expected:?}");
                    }
                }
            }
        }
    }
}

proptest! {
    /// Under production's numbering a generation is the commit's microsecond timestamp, never
    /// below the previous generation plus one, whatever the clock does (it may run backwards or
    /// repeat), and the preview a rules evaluation sees is the generation the commit draws.
    #[test]
    fn production_generations_are_monotonic_timestamps(
        clock in proptest::collection::vec(0i64..4_000, 1..=30),
    ) {
        let mut store = StorageState::new(5);
        store.set_production_order(true);
        let mut last = 0u64;
        for (index, seconds) in clock.iter().enumerate() {
            let now = at(*seconds);
            let preview = store.next_generation_preview(now).unwrap();
            let put = store
                .put(
                    &bucket(),
                    &object(UNIVERSE[index % UNIVERSE.len()]),
                    vec![1],
                    NewMetadata::default(),
                    Precondition::default(),
                    now,
                )
                .unwrap();
            prop_assert_eq!(put.generation, preview);
            prop_assert!(put.generation > last);
            let micros = u64::try_from(now.as_nanos() / 1_000).unwrap();
            prop_assert!(put.generation >= micros);
            last = put.generation;
        }
    }

    /// A minted download token is listed first under production's ordering and last otherwise.
    #[test]
    fn minted_tokens_are_listed_by_the_active_ordering(count in 1usize..=5, production in any::<bool>()) {
        let mut store = StorageState::new(9);
        store.set_production_order(production);
        let name = object("a");
        store
            .put(&bucket(), &name, vec![1], NewMetadata::default(), Precondition::default(), at(0))
            .unwrap();
        let mut minted = Vec::new();
        for step in 0..count {
            let meta = store
                .add_download_token(&bucket(), &name, at(i64::try_from(step).unwrap() + 1))
                .unwrap();
            let newest = if production { meta.download_tokens[0].clone() } else { meta.download_tokens.last().unwrap().clone() };
            minted.push(newest);
        }
        let listed = store.get(&bucket(), &name).unwrap().download_tokens.clone();
        let mut expected = minted.clone();
        if production {
            expected.reverse();
        }
        prop_assert_eq!(listed, expected);
    }
}
