//! Hosting production behaviour that the strict profile reproduces. The pure rules live here; the
//! recorded answers they come from are runs 658bb2 and 9a8d57 of the HOSTING production recording
//! (`conformance/src/hosting-production`). Each rule names the corpus rows that show it.

use std::time::SystemTime;

/// The `Content-Type` production sends for a deployed file. `known` is what the pinned oracle's
/// table says (`None` for an extension it has no type for). Rows `v01.ct-*` (runs 658bb2 and
/// 9a8d57): JSON types carry no charset, scripts are `text/javascript`, `.ico` is `image/x-icon`,
/// and a file with no known type is `text/plain` where the oracle sends `application/octet-stream`.
pub(super) fn content_type(known: Option<&str>) -> String {
    let Some(local) = known else {
        return "text/plain; charset=utf-8".to_owned();
    };
    let base = local.split(';').next().unwrap_or(local).trim();
    match base {
        "application/javascript" => "text/javascript; charset=utf-8".to_owned(),
        "image/vnd.microsoft.icon" => "image/x-icon".to_owned(),
        json if json == "application/json" || json.ends_with("+json") => json.to_owned(),
        _ => local.to_owned(),
    }
}

/// One `Range` request as production answered it: a single `bytes=` range.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RangeOutcome {
    /// No usable `Range` header: the whole file answers.
    Whole,
    /// A satisfiable range, inclusive of both ends.
    Partial { start: u64, end: u64 },
    /// A single range that starts past the end (or an empty file).
    Unsatisfiable,
}

/// `v01.range` (`bytes=0-3` -> `206`, `bytes 0-3/17`) and `v01.range-suffix` (`bytes=-3` -> `bytes 14-16/17`).
/// More than one range, or anything else that is not `bytes=`, is answered whole (production
/// recordings have no multi-range case; this is the RFC 9110 permission to ignore the header).
pub(super) fn range(header: Option<&str>, length: u64) -> RangeOutcome {
    let Some(spec) = header.and_then(|value| value.trim().strip_prefix("bytes=")) else {
        return RangeOutcome::Whole;
    };
    if spec.contains(',') {
        return RangeOutcome::Whole;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return RangeOutcome::Whole;
    };
    let (first, last) = (first.trim(), last.trim());
    // digits only (`parse` refuses the empty text and accepts no sign once this holds)
    let number = |text: &str| -> Option<u64> {
        text.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| text.parse().ok())
            .flatten()
    };
    if first.is_empty() {
        // suffix: the last N bytes
        let Some(suffix) = number(last) else {
            return RangeOutcome::Whole;
        };
        if suffix == 0 || length == 0 {
            return RangeOutcome::Unsatisfiable;
        }
        return RangeOutcome::Partial {
            start: length.saturating_sub(suffix),
            end: length - 1,
        };
    }
    let Some(start) = number(first) else {
        return RangeOutcome::Whole;
    };
    let end = if last.is_empty() {
        None
    } else {
        match number(last) {
            Some(end) => Some(end),
            None => return RangeOutcome::Whole,
        }
    };
    if end.is_some_and(|end| end < start) {
        return RangeOutcome::Whole;
    }
    if start >= length {
        return RangeOutcome::Unsatisfiable;
    }
    RangeOutcome::Partial {
        start,
        end: end.map_or(length - 1, |end| end.min(length - 1)),
    }
}

/// Whether an `If-None-Match` list names `etag`: `*`, or any member equal to it ignoring a weak
/// prefix.
pub(super) fn if_none_match(header: &str, etag: &str) -> bool {
    let strong = |tag: &str| tag.trim().trim_start_matches("W/").to_owned();
    header.trim() == "*" || header.split(',').any(|tag| strong(tag) == strong(etag))
}

/// `v01.cond-etag` and `v01.cond-since-future` (`304` for both). `If-None-Match` decides when it is
/// present, as in RFC 9110; `If-Modified-Since` otherwise, at one second resolution.
pub(super) fn not_modified(
    if_none: Option<&str>,
    since: Option<&str>,
    etag: &str,
    modified: Option<SystemTime>,
) -> bool {
    if let Some(list) = if_none {
        return if_none_match(list, etag);
    }
    let (Some(since), Some(modified)) = (
        since.and_then(|v| httpdate::parse_http_date(v).ok()),
        modified,
    ) else {
        return false;
    };
    let seconds = |time: SystemTime| {
        time.duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    };
    seconds(modified) <= seconds(since)
}

/// The languages of an `Accept-Language` header in preference order (`v07.quality`:
/// `de;q=0.9, fr;q=0.8` finds `fr` when there is no `de`): by descending quality, ties in header
/// order, `q=0` dropped, only the primary subtag kept (`v07.region-tag`: `fr-CA` finds `fr`).
pub(super) fn accept_languages(header: &str) -> Vec<String> {
    let mut entries: Vec<(f32, usize, String)> = Vec::new();
    for (index, part) in header.split(',').enumerate() {
        let mut pieces = part.split(';');
        let tag = pieces.next().unwrap_or("").trim();
        let primary = tag.split('-').next().unwrap_or("");
        if primary.is_empty() || primary == "*" {
            continue;
        }
        let quality = pieces
            .find_map(|p| p.trim().strip_prefix("q=").map(str::trim))
            .map_or(Some(1.0), |q| q.parse::<f32>().ok());
        let Some(quality) = quality.filter(|q| *q > 0.0 && *q <= 1.0) else {
            continue;
        };
        entries.push((quality, index, primary.to_owned()));
    }
    entries.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
    entries.into_iter().map(|(_, _, tag)| tag).collect()
}

/// The normalized path of a request target that climbs with dot segments, or `None` when it has
/// none (`v01.safety-parent`: `/../outside.txt` and `/%2e%2e/outside.txt` both give
/// `/outside.txt`). It follows RFC 3986 `remove_dot_segments`: a `..` with nothing to remove stays
/// at the root, `.` and empty parts vanish, a trailing slash stays, and a path that ends in a dot
/// segment ends in a slash (`/a/b/..` gives `/a/`). The parts keep their escapes.
///
/// A part that holds a raw backslash, a control character or a space gives `None`, so the request is
/// answered as any other path (a 404): a browser reads `\` in a URL as `/`, and `/\evil.example`
/// would be a redirect to another site. Production's answer for such a part was not recorded, and
/// a refusal is the safe one. The result is therefore a path that starts with exactly one `/`
/// followed by a part that is neither empty nor starts with `/` or `\`.
pub(super) fn dot_segment_target(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('/').collect();
    let dots =
        |part: &str| super::files::decode_uri_full(part).filter(|text| text == ".." || text == ".");
    if !parts.iter().any(|part| dots(part).is_some()) {
        return None;
    }
    if path
        .chars()
        .any(|ch| ch == '\\' || ch.is_ascii_control() || ch == ' ')
    {
        return None;
    }
    let mut kept: Vec<&str> = Vec::new();
    for part in &parts {
        match dots(part).as_deref() {
            Some("..") => {
                kept.pop();
            }
            Some(_) => {}
            None if part.is_empty() => {}
            None => kept.push(part),
        }
    }
    let ends_in_dot_segment = parts.last().is_some_and(|part| dots(part).is_some());
    let mut target = format!("/{}", kept.join("/"));
    if (path.ends_with('/') || ends_in_dot_segment) && !kept.is_empty() {
        target.push('/');
    }
    Some(target)
}

/// `appAssociation: "AUTO"` serves these two documents when the site has no file of the name
/// (`v02.assetlinks`, `v02.apple-app-site-association`).
pub(super) fn app_association(path: &str) -> Option<&'static str> {
    match path {
        "/.well-known/assetlinks.json" => Some("[]"),
        "/.well-known/apple-app-site-association" => {
            Some(r#"{"applinks":{"apps":[],"details":[]}}"#)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_recorded_ranges() {
        assert_eq!(
            range(Some("bytes=0-3"), 17),
            RangeOutcome::Partial { start: 0, end: 3 }
        );
        assert_eq!(
            range(Some("bytes=-3"), 17),
            RangeOutcome::Partial { start: 14, end: 16 }
        );
        assert_eq!(
            range(Some("bytes=5-"), 17),
            RangeOutcome::Partial { start: 5, end: 16 }
        );
        assert_eq!(
            range(Some("bytes=10-99"), 17),
            RangeOutcome::Partial { start: 10, end: 16 }
        );
        assert_eq!(
            range(Some("bytes=-99"), 17),
            RangeOutcome::Partial { start: 0, end: 16 }
        );
    }

    #[test]
    fn unusable_or_unsatisfiable_ranges() {
        assert_eq!(range(None, 17), RangeOutcome::Whole);
        assert_eq!(range(Some("items=0-3"), 17), RangeOutcome::Whole);
        assert_eq!(range(Some("bytes=0-3,5-6"), 17), RangeOutcome::Whole);
        assert_eq!(range(Some("bytes=3-1"), 17), RangeOutcome::Whole);
        assert_eq!(range(Some("bytes=a-3"), 17), RangeOutcome::Whole);
        assert_eq!(range(Some("bytes=17-"), 17), RangeOutcome::Unsatisfiable);
        assert_eq!(range(Some("bytes=-0"), 17), RangeOutcome::Unsatisfiable);
        assert_eq!(range(Some("bytes=0-0"), 0), RangeOutcome::Unsatisfiable);
    }

    #[test]
    fn conditional_requests() {
        let etag = "\"abc\"";
        assert!(if_none_match("\"abc\"", etag));
        assert!(if_none_match("W/\"abc\", \"zzz\"", etag));
        assert!(if_none_match("*", etag));
        assert!(!if_none_match("\"abd\"", etag));
        let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let date =
            |secs: u64| httpdate::fmt_http_date(SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
        // If-None-Match wins when present: a matching date does not save a different tag
        assert!(!not_modified(
            Some("\"zzz\""),
            Some(&date(1_800_000_000)),
            etag,
            Some(modified)
        ));
        assert!(not_modified(
            None,
            Some(&date(1_800_000_000)),
            etag,
            Some(modified)
        ));
        assert!(not_modified(
            None,
            Some(&date(1_700_000_000)),
            etag,
            Some(modified)
        ));
        assert!(!not_modified(
            None,
            Some(&date(1_699_999_999)),
            etag,
            Some(modified)
        ));
        assert!(!not_modified(
            None,
            Some("not a date"),
            etag,
            Some(modified)
        ));
        assert!(!not_modified(None, None, etag, Some(modified)));
    }

    #[test]
    fn accept_language_by_quality() {
        assert_eq!(accept_languages("fr"), ["fr"]);
        assert_eq!(accept_languages("de;q=0.9, fr;q=0.8"), ["de", "fr"]);
        assert_eq!(accept_languages("fr;q=0.5, de"), ["de", "fr"]);
        assert_eq!(accept_languages("fr-CA,en;q=0.7"), ["fr", "en"]);
        assert_eq!(accept_languages("en;q=0, fr"), ["fr"]);
        assert_eq!(accept_languages("*, fr"), ["fr"]);
        assert_eq!(accept_languages("a;q=2, b;q=x, c"), ["c"]);
        assert!(accept_languages("").is_empty());
    }

    #[test]
    fn the_recorded_content_types() {
        assert_eq!(
            content_type(Some("application/json; charset=utf-8")),
            "application/json"
        );
        assert_eq!(
            content_type(Some("application/manifest+json; charset=utf-8")),
            "application/manifest+json"
        );
        assert_eq!(
            content_type(Some("application/javascript; charset=utf-8")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type(Some("image/vnd.microsoft.icon")),
            "image/x-icon"
        );
        assert_eq!(content_type(None), "text/plain; charset=utf-8");
        // the rest is the oracle's table
        assert_eq!(
            content_type(Some("text/html; charset=utf-8")),
            "text/html; charset=utf-8"
        );
        assert_eq!(content_type(Some("image/png")), "image/png");
    }

    use proptest::prelude::*;

    proptest! {
        // Whatever the header says, a partial range lies inside the file and is never empty.
        #[test]
        fn a_partial_range_lies_inside_the_file(
            header in "(bytes=)?[-0-9, a-z]{0,12}",
            length in 0u64..1000,
        ) {
            if let RangeOutcome::Partial { start, end } = range(Some(&header), length) {
                prop_assert!(start <= end);
                prop_assert!(end < length);
            }
        }

        // A well-formed single range is exactly the bytes it names, clamped to the file.
        #[test]
        fn a_closed_range_is_clamped_to_the_file(
            first in 0u64..200,
            last in 0u64..400,
            length in 1u64..300,
        ) {
            let outcome = range(Some(&format!("bytes={first}-{last}")), length);
            if last < first {
                prop_assert_eq!(outcome, RangeOutcome::Whole);
            } else if first >= length {
                prop_assert_eq!(outcome, RangeOutcome::Unsatisfiable);
            } else {
                prop_assert_eq!(outcome, RangeOutcome::Partial { start: first, end: last.min(length - 1) });
            }
        }

        // A suffix range names the last bytes, never more than the file has.
        #[test]
        fn a_suffix_range_is_the_tail(suffix in 1u64..400, length in 1u64..300) {
            prop_assert_eq!(
                range(Some(&format!("bytes=-{suffix}")), length),
                RangeOutcome::Partial { start: length.saturating_sub(suffix), end: length - 1 }
            );
        }

        // The languages come out by descending quality, ties in header order, only the ones kept.
        #[test]
        fn languages_are_ordered_by_quality(
            entries in proptest::collection::vec(("[a-z]{2}", 0u8..=10), 0..6),
        ) {
            let header = entries
                .iter()
                .map(|(tag, q)| format!("{tag};q={}", f32::from(*q) / 10.0))
                .collect::<Vec<_>>()
                .join(", ");
            let mut expected: Vec<(usize, &(String, u8))> = entries.iter().enumerate().filter(|(_, (_, q))| *q > 0).collect();
            expected.sort_by(|a, b| b.1 .1.cmp(&a.1 .1).then(a.0.cmp(&b.0)));
            let expected: Vec<String> = expected.into_iter().map(|(_, (tag, _))| tag.clone()).collect();
            prop_assert_eq!(accept_languages(&header), expected);
        }

        // Any list that holds the tag (weak or strong, among others) matches it; one that does not, does not.
        #[test]
        fn an_etag_list_matches_exactly_when_it_holds_the_tag(
            others in proptest::collection::vec("\"[a-f0-9]{4}\"", 0..4),
            weak in any::<bool>(),
            position in 0usize..4,
        ) {
            let tag = "\"ffff\"";
            let mut members: Vec<String> = others.into_iter().filter(|member| member != tag).collect();
            prop_assert!(!if_none_match(&members.join(", "), tag));
            let held = if weak { format!("W/{tag}") } else { tag.to_owned() };
            members.insert(position.min(members.len()), held);
            prop_assert!(if_none_match(&members.join(", "), tag));
        }
    }

    #[test]
    fn dot_segments_are_normalized_the_way_the_recorded_rows_were() {
        for (path, expected) in [
            ("/../outside.txt", Some("/outside.txt")),
            ("/%2e%2e/outside.txt", Some("/outside.txt")),
            ("/%2E%2e/outside.txt", Some("/outside.txt")),
            ("/a/../b", Some("/b")),
            ("/a/b/../../../c/", Some("/c/")),
            ("/a/./b", Some("/a/b")),
            // RFC 3986: a path that ends in a dot segment ends in a slash
            ("/a/b/..", Some("/a/")),
            ("/a/b/.", Some("/a/b/")),
            ("/a/.", Some("/a/")),
            ("/a/..", Some("/")),
            ("/%2e%2e", Some("/")),
            ("/..", Some("/")),
            ("/a/%2e%2e/", Some("/")),
            ("/a/b%2fc/../d", Some("/a/d")),
            ("/a/..b/c", None),
            ("/a/b.c/d", None),
            ("/a%2e%2eb", None),
            ("/", None),
            ("/%2e%2e%2foutside.txt", None),
        ] {
            assert_eq!(dot_segment_target(path).as_deref(), expected, "{path}");
        }
    }

    #[test]
    fn a_backslash_or_a_control_character_is_never_redirected_to() {
        // `/./\evil.example` would be `Location: /\evil.example`, which a browser reads as
        // `//evil.example`; the request is left to the ordinary path handling (a 404)
        for path in [
            "/./\\evil.example",
            "/a/../\\\\evil.example/",
            "/./\\\\evil.example",
            "/a/.\\b/../c",
            "/../a\\b",
            "/../a b",
            "/../a\tb",
            "/../a\u{7f}b",
        ] {
            assert_eq!(dot_segment_target(path), None, "{path:?}");
        }
        // the escaped forms stay escaped and are safe
        assert_eq!(
            dot_segment_target("/./%5cevil.example").as_deref(),
            Some("/%5cevil.example")
        );
        assert_eq!(
            dot_segment_target("/./%2f%2fevil.example").as_deref(),
            Some("/%2f%2fevil.example")
        );
    }

    proptest! {
        // For any request path: no redirect, or a path-absolute target on this origin. It starts with
        // exactly one `/` that no `/` or `\` follows, holds no backslash, control character or space,
        // and so carries no scheme and no host whatever a browser does with the text.
        #[test]
        fn the_dot_segment_redirect_never_leaves_the_origin(path in "/?[a-z.%0-9A-F/\\\\ \t:@]{0,24}") {
            if let Some(target) = dot_segment_target(&path) {
                prop_assert!(target.starts_with('/'), "{target:?}");
                prop_assert!(!target.starts_with("//") && !target.starts_with("/\\"), "{target:?}");
                prop_assert!(!target.contains('\\') && !target.contains(' '), "{target:?}");
                prop_assert!(!target.chars().any(|ch| ch.is_ascii_control()), "{target:?}");
                // normalized: no dot segment remains
                prop_assert!(target.split('/').all(|part| part != ".." && part != "."), "{target:?}");
            }
        }

        // The same for paths that are mostly dots, slashes and escapes of them.
        #[test]
        fn dot_heavy_paths_stay_on_the_origin(
            parts in proptest::collection::vec(
                prop_oneof![
                    Just("..".to_owned()),
                    Just(".".to_owned()),
                    Just("%2e%2e".to_owned()),
                    Just("%2E".to_owned()),
                    Just(String::new()),
                    Just("%5c".to_owned()),
                    Just("%2f".to_owned()),
                    "[a-z]{1,3}",
                ],
                1..8,
            ),
        ) {
            let path = format!("/{}", parts.join("/"));
            if let Some(target) = dot_segment_target(&path) {
                prop_assert!(target.starts_with('/') && !target.starts_with("//"), "{path} -> {target}");
                prop_assert!(!target.contains('\\'), "{path} -> {target}");
            }
        }
    }

    #[test]
    fn the_association_documents() {
        assert_eq!(app_association("/.well-known/assetlinks.json"), Some("[]"));
        assert_eq!(
            app_association("/.well-known/apple-app-site-association"),
            Some("{\"applinks\":{\"apps\":[],\"details\":[]}}")
        );
        assert_eq!(app_association("/.well-known/other"), None);
    }
}
