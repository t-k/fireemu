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

/// The normalized path of a request target that has dot segments, or `None` when it has none.
/// Production answers such a request with a `302` to the normalized path on its content origin
/// (`v01.safety-parent`, `v11.dot-*`, `v11.backslash-*` of the follow-up recording).
///
/// What the recordings show: a raw `\` is read as `/` before dot segments are looked for
/// (`/.\b` gives `/b`, `/a/./\evil.example` gives `/a//evil.example`, `/./\evil` gives `//evil`),
/// while a path with no dot segment is not redirected whatever it holds (`/a\b` is a 404 page);
/// the segments follow RFC 3986 `remove_dot_segments` (empty segments stay, `..` at the root stays at
/// the root, a path that ends in a dot segment ends in a slash: `/a/b/..` gives `/a/`); an escaped
/// dot (`%2e`) is a dot; the hex digits of the escapes that stay are upper case (`%5c` gives `%5C`).
///
/// The result is a path that starts with `/`. It may start with `//` (`/./\evil`): the caller makes it
/// the path of an absolute URL on the request's own origin, where it cannot name another host. A
/// path with a control character or a space gives `None`: production's answer was not recorded.
pub(super) fn dot_segment_target(path: &str) -> Option<String> {
    if path.chars().any(|ch| ch.is_ascii_control() || ch == ' ') {
        return None;
    }
    let slashed = path.replace('\\', "/");
    let parts: Vec<&str> = slashed.split('/').collect();
    let is_dot =
        |part: &str| super::files::decode_uri_full(part).filter(|text| text == "." || text == "..");
    if !parts.iter().any(|part| is_dot(part).is_some()) {
        return None;
    }
    let segments = if parts.first() == Some(&"") {
        &parts[1..]
    } else {
        &parts[..]
    };
    let mut kept: Vec<String> = Vec::new();
    for (index, part) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        match is_dot(part).as_deref() {
            Some(".") => {
                if last {
                    kept.push(String::new());
                }
            }
            Some(_) => {
                kept.pop();
                if last {
                    kept.push(String::new());
                }
            }
            None => kept.push(upper_escapes(part)),
        }
    }
    Some(format!("/{}", kept.join("/")))
}

/// `part` with the two hex digits of every `%xx` escape in upper case (`%5c` gives `%5C`, as the
/// follow-up recording shows production writing it).
fn upper_escapes(part: &str) -> String {
    let mut out = String::with_capacity(part.len());
    let mut rest = part;
    while let Some(at) = rest.find('%') {
        out.push_str(&rest[..at]);
        let escape = rest
            .get(at + 1..at + 3)
            .filter(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()));
        out.push('%');
        if let Some(hex) = escape {
            out.push_str(&hex.to_ascii_uppercase());
            rest = &rest[at + 3..];
        } else {
            rest = &rest[at + 1..];
        }
    }
    out.push_str(rest);
    out
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
            // v01.safety-parent, v01.safety-encoded-parent
            ("/../outside.txt", Some("/outside.txt")),
            ("/%2e%2e/outside.txt", Some("/outside.txt")),
            ("/%2E%2e/outside.txt", Some("/outside.txt")),
            // the follow-up recording, v11 (production's Location path, row by row)
            ("/a/b/..", Some("/a/")),
            ("/a/./b", Some("/a/b")),
            ("/a/b/.", Some("/a/b/")),
            ("/a/.", Some("/a/")),
            ("/a/..", Some("/")),
            ("/a/../a/b", Some("/a/b")),
            ("/./a/b", Some("/a/b")),
            ("/a/%2e/b", Some("/a/b")),
            ("/a/b/%2e%2e", Some("/a/")),
            ("/a/b/../", Some("/a/")),
            ("/a/./b/", Some("/a/b/")),
            // a raw backslash is a slash before the dot segments are looked for
            ("/a/./\\evil.example", Some("/a//evil.example")),
            ("/.\\b", Some("/b")),
            ("/./\\evil", Some("//evil")),
            // an escape that stays has upper case hex digits
            ("/a/./%5cevil.example", Some("/a/%5Cevil.example")),
            // RFC 3986 for the rest
            ("/a/b/../../../c/", Some("/c/")),
            ("/%2e%2e", Some("/")),
            ("/..", Some("/")),
            ("/a/%2e%2e/", Some("/")),
            ("/a/b%2fc/../d", Some("/a/d")),
            ("/a//b/../c", Some("/a//c")),
            // no dot segment: not redirected, whatever else the path holds (v11.backslash-mid, -in-name)
            ("/a\\b", None),
            ("/a/\\b", None),
            ("/a/..b/c", None),
            ("/a/b.c/d", None),
            ("/a%2e%2eb", None),
            ("/", None),
            ("/%2e%2e%2foutside.txt", None),
            // a control character or a space was not recorded
            ("/../a b", None),
            ("/../a\tb", None),
            ("/../a\u{7f}b", None),
        ] {
            assert_eq!(dot_segment_target(path).as_deref(), expected, "{path:?}");
        }
    }

    #[test]
    fn escapes_are_upper_cased_and_a_lone_percent_is_kept() {
        assert_eq!(upper_escapes("a%5cb%2fc"), "a%5Cb%2Fc");
        assert_eq!(upper_escapes("%e6%97%a5"), "%E6%97%A5");
        assert_eq!(upper_escapes("100%"), "100%");
        assert_eq!(upper_escapes("%zz%5"), "%zz%5");
        assert_eq!(upper_escapes("日本%3a"), "日本%3A");
        assert_eq!(upper_escapes(""), "");
    }

    proptest! {
        // For any request path: no redirect, or a path that starts with `/`, holds no backslash,
        // control character or space and has no dot segment left. The caller puts it after the
        // request's own host in an absolute URL, so a leading `//` names no other host.
        #[test]
        fn the_dot_segment_target_is_a_clean_path(path in "/?[a-z.%0-9A-F/\\\\ \t:@]{0,24}") {
            if let Some(target) = dot_segment_target(&path) {
                prop_assert!(target.starts_with('/'), "{target:?}");
                prop_assert!(!target.contains('\\') && !target.contains(' '), "{target:?}");
                prop_assert!(!target.chars().any(|ch| ch.is_ascii_control()), "{target:?}");
                prop_assert!(
                    target.split('/').all(|part| {
                        super::super::files::decode_uri_full(part).is_none_or(|text| text != ".." && text != ".")
                    }),
                    "{target:?}"
                );
                // escapes that stay are upper case
                prop_assert_eq!(upper_escapes(&target), target.clone());
            }
        }

        // Normalizing twice changes nothing: the target of a target is no redirect.
        #[test]
        fn a_normalized_target_has_nothing_left_to_normalize(
            parts in proptest::collection::vec(
                prop_oneof![
                    Just("..".to_owned()),
                    Just(".".to_owned()),
                    Just("%2e%2e".to_owned()),
                    Just("%2E".to_owned()),
                    Just(String::new()),
                    Just("%5c".to_owned()),
                    Just("%2f".to_owned()),
                    Just("\\".to_owned()),
                    "[a-z]{1,3}",
                ],
                1..8,
            ),
        ) {
            let path = format!("/{}", parts.join("/"));
            if let Some(target) = dot_segment_target(&path) {
                prop_assert_eq!(dot_segment_target(&target), None, "{} -> {}", path, target);
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
