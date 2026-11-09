//! Ordered Hosting source matching. Glob segments never consume a path separator.

use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

#[derive(Clone, Debug)]
enum Token {
    Literal(char),
    Any,
    Star,
    Class(Vec<(char, char)>, bool),
    Group(char, Vec<Vec<Token>>),
}

fn tokens(chars: &[char], at: &mut usize, nested: bool) -> Vec<Token> {
    let mut out = Vec::new();
    while *at < chars.len() {
        let ch = chars[*at];
        if nested && matches!(ch, '|' | ')') {
            break;
        }
        *at += 1;
        if matches!(ch, '?' | '*' | '+' | '@' | '!') && chars.get(*at) == Some(&'(') {
            *at += 1;
            let mut alternatives = Vec::new();
            loop {
                alternatives.push(tokens(chars, at, true));
                if chars.get(*at) == Some(&'|') {
                    *at += 1;
                } else {
                    break;
                }
            }
            if chars.get(*at) == Some(&')') {
                *at += 1;
            }
            out.push(Token::Group(ch, alternatives));
        } else {
            match ch {
                '\\' => {
                    out.push(Token::Literal(chars.get(*at).copied().unwrap_or('\\')));
                    *at += usize::from(*at < chars.len());
                }
                '?' => out.push(Token::Any),
                '*' => out.push(Token::Star),
                '[' => {
                    let start = *at;
                    let mut negative = false;
                    if matches!(chars.get(*at), Some('!' | '^')) {
                        negative = true;
                        *at += 1;
                    }
                    let mut ranges = Vec::new();
                    while *at < chars.len() && chars[*at] != ']' {
                        let first = chars[*at];
                        *at += 1;
                        if chars.get(*at) == Some(&'-')
                            && chars.get(*at + 1).is_some_and(|c| *c != ']')
                        {
                            ranges.push((first, chars[*at + 1]));
                            *at += 2;
                        } else {
                            ranges.push((first, first));
                        }
                    }
                    if chars.get(*at) == Some(&']') && !ranges.is_empty() {
                        *at += 1;
                        out.push(Token::Class(ranges, negative));
                    } else {
                        *at = start;
                        out.push(Token::Literal('['));
                    }
                }
                other => out.push(Token::Literal(other)),
            }
        }
    }
    out
}

/// The canonical form a JavaScript regular expression with the `i` flag and without the `u` flag
/// compares (ECMAScript Canonicalize, as in glob 10.5.0's Ignore): the one-unit `toUpperCase` of a
/// BMP character, unless that maps a non-ASCII character to ASCII or needs several units. So U+00DF
/// stays itself and never meets `S`, U+212A never meets `k`, and U+03C2 meets U+03C3 through U+03A3.
/// Astral characters are two surrogate units there and never fold.
fn canonical(ch: char) -> char {
    if ch.len_utf16() > 1 {
        return ch;
    }
    let mut upper = ch.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(single), None) if ch.is_ascii() || !single.is_ascii() => single,
        _ => ch,
    }
}

/// Every BMP character that is not its own canonical form, grouped by that form.
fn canonical_classes() -> &'static HashMap<char, Vec<char>> {
    static CLASSES: OnceLock<HashMap<char, Vec<char>>> = OnceLock::new();
    CLASSES.get_or_init(|| {
        let mut classes: HashMap<char, Vec<char>> = HashMap::new();
        for ch in (0..=0xFFFFu32).filter_map(char::from_u32) {
            let form = canonical(ch);
            if form != ch {
                classes.entry(form).or_default().push(ch);
            }
        }
        classes
    })
}

/// Whether `ch` is in the character set of ranges when case is ignored: some member of the set has
/// the same canonical form (a range is every character in it, not only its ends).
fn class_contains_ignoring_case(ranges: &[(char, char)], ch: char) -> bool {
    let form = canonical(ch);
    let inside = |c: char| ranges.iter().any(|(a, b)| *a <= c && c <= *b);
    inside(form)
        || canonical_classes()
            .get(&form)
            .is_some_and(|members| members.iter().any(|member| inside(*member)))
}

fn ends(sequence: &[Token], input: &[char], start: usize, nocase: bool) -> BTreeSet<usize> {
    let mut positions = BTreeSet::from([start]);
    for token in sequence {
        let mut next = BTreeSet::new();
        for pos in positions {
            match token {
                Token::Literal(ch)
                    if input.get(pos).is_some_and(|value| {
                        value == ch || (nocase && canonical(*value) == canonical(*ch))
                    }) =>
                {
                    next.insert(pos + 1);
                }
                Token::Any if pos < input.len() => {
                    next.insert(pos + 1);
                }
                Token::Star => next.extend(pos..=input.len()),
                Token::Class(ranges, negative) => {
                    if input.get(pos).is_some_and(|ch| {
                        let contains = |c: char| ranges.iter().any(|(a, b)| *a <= c && c <= *b);
                        (contains(*ch) || (nocase && class_contains_ignoring_case(ranges, *ch)))
                            != *negative
                    }) {
                        next.insert(pos + 1);
                    }
                }
                Token::Group(kind, alternatives) => {
                    let once: BTreeSet<_> = alternatives
                        .iter()
                        .flat_map(|alt| ends(alt, input, pos, nocase))
                        .collect();
                    match kind {
                        '!' => next.extend((pos..=input.len()).filter(|end| !once.contains(end))),
                        '@' => next.extend(once),
                        '?' => {
                            next.insert(pos);
                            next.extend(once);
                        }
                        '*' | '+' => {
                            let mut reached = once;
                            if *kind == '*' {
                                reached.insert(pos);
                            }
                            loop {
                                let more: BTreeSet<_> = reached
                                    .iter()
                                    .flat_map(|p| {
                                        alternatives
                                            .iter()
                                            .flat_map(move |alt| ends(alt, input, *p, nocase))
                                    })
                                    .collect();
                                let before = reached.len();
                                reached.extend(more);
                                if before == reached.len() {
                                    break;
                                }
                            }
                            next.extend(reached);
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        positions = next;
        if positions.is_empty() {
            break;
        }
    }
    positions
}

fn segment(pattern: &str, value: &str, dot: bool, nocase: bool) -> bool {
    if !dot && value.starts_with('.') && !pattern.starts_with('.') && !pattern.starts_with("\\.") {
        return false;
    }
    if value.is_empty() {
        return pattern.is_empty();
    }
    let chars: Vec<_> = pattern.chars().collect();
    let value: Vec<_> = value.chars().collect();
    ends(&tokens(&chars, &mut 0, false), &value, 0, nocase).contains(&value.len())
}

/// Splits like minimatch (`/\/+/`): a run of slashes is one separator, while a leading or trailing
/// slash still leaves its empty first or last part.
fn slash_split(text: &str) -> Vec<&str> {
    let parts: Vec<_> = text.split('/').collect();
    let last = parts.len() - 1;
    parts
        .into_iter()
        .enumerate()
        .filter(|(index, part)| !part.is_empty() || *index == 0 || *index == last)
        .map(|(_, part)| part)
        .collect()
}

fn path_match(pattern: &[&str], path: &[&str], dot: bool, nocase: bool) -> bool {
    let Some(first) = pattern.first() else {
        // minimatch lets a pattern also match a path with one trailing slash.
        return path.is_empty() || path == [""];
    };
    if *first == "**" {
        for take in 0..=path.len() {
            if !dot && path[..take].iter().any(|part| part.starts_with('.')) {
                break;
            }
            if path_match(&pattern[1..], &path[take..], dot, nocase) {
                return true;
            }
        }
        false
    } else {
        path.first().is_some_and(|part| {
            segment(first, part, dot, nocase) && path_match(&pattern[1..], &path[1..], dot, nocase)
        })
    }
}

fn comma_alternatives(content: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut escaped = false;
    for (offset, ch) in content.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(content[start..offset].to_owned());
                start = offset + 1;
            }
            _ => {}
        }
    }
    parts.push(content[start..].to_owned());
    parts
}

/// One `{a..b}` or `{a..b..step}` range as the brace-expansion library expands it for minimatch:
/// numeric (with zero padding when a bound is padded) or single ASCII letters. `None` when the
/// content is not such a range or spans more than 1000 values.
fn brace_range(content: &str) -> Option<Vec<String>> {
    let bounds: Vec<&str> = content.split("..").collect();
    if !(2..=3).contains(&bounds.len()) {
        return None;
    }
    let step = match bounds.get(2) {
        Some(text) => text.parse::<i64>().ok()?.unsigned_abs().max(1),
        None => 1,
    };
    let values = |a: i64, b: i64| -> Option<Vec<i64>> {
        let span = a.abs_diff(b);
        if span > 1000 {
            return None;
        }
        let direction = if a <= b { 1 } else { -1 };
        (0..=span / step)
            .map(|i| {
                i64::try_from(i * step)
                    .ok()
                    .map(|offset| a + direction * offset)
            })
            .collect()
    };
    if let (Ok(a), Ok(b)) = (bounds[0].parse::<i32>(), bounds[1].parse::<i32>()) {
        let width = bounds[0].len().max(bounds[1].len());
        let padded = bounds[..2].iter().any(|s| {
            let digits = s.trim_start_matches('-');
            digits.len() > 1 && digits.starts_with('0')
        });
        let numbers = values(i64::from(a), i64::from(b))?;
        return Some(
            numbers
                .into_iter()
                .map(|n| match (padded, n < 0) {
                    (true, true) => format!("-{:0width$}", -n, width = width - 1),
                    (true, false) => format!("{n:0width$}"),
                    (false, _) => n.to_string(),
                })
                .collect(),
        );
    }
    let letter = |s: &str| match s.as_bytes() {
        [byte] if byte.is_ascii_alphabetic() => Some(i64::from(*byte)),
        _ => None,
    };
    let letters = values(letter(bounds[0])?, letter(bounds[1])?)?;
    letters
        .into_iter()
        .map(|code| {
            u8::try_from(code)
                .ok()
                .map(|byte| char::from(byte).to_string())
        })
        .collect()
}

fn alternatives(pattern: &str, deploy_ignore: bool) -> Vec<String> {
    let start = if deploy_ignore {
        let mut escaped = false;
        pattern.char_indices().find_map(|(i, ch)| {
            if escaped {
                escaped = false;
                None
            } else if ch == '\\' {
                escaped = true;
                None
            } else {
                (ch == '{').then_some(i)
            }
        })
    } else {
        pattern.find('{')
    };
    let Some(start) = start else {
        return vec![pattern.to_owned()];
    };
    let mut depth = 0;
    let mut end = None;
    let mut escaped = false;
    for (offset, ch) in pattern[start..].char_indices() {
        if deploy_ignore && escaped {
            escaped = false;
            continue;
        }
        if deploy_ignore && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '{' {
            depth += 1;
        }
        if ch == '}' {
            depth -= 1;
            if depth == 0 {
                end = Some(start + offset);
                break;
            }
        }
    }
    let Some(end) = end else {
        return vec![pattern.to_owned()];
    };
    let content = &pattern[start + 1..end];
    let parts: Vec<String> = if deploy_ignore && content.contains("..") && !content.contains(',') {
        brace_range(content).unwrap_or_else(|| comma_alternatives(content))
    } else if let Some((a, b)) = content.split_once("..") {
        match (a.parse::<i32>(), b.parse::<i32>()) {
            (Ok(a), Ok(b)) if (i64::from(a) - i64::from(b)).abs() <= 1000 => {
                if a <= b {
                    (a..=b).map(|n| n.to_string()).collect()
                } else {
                    (b..=a).rev().map(|n| n.to_string()).collect()
                }
            }
            _ if deploy_ignore
                && a.len() == 1
                && b.len() == 1
                && a.as_bytes()[0].is_ascii_alphabetic()
                && b.as_bytes()[0].is_ascii_alphabetic() =>
            {
                let (a, b) = (a.as_bytes()[0], b.as_bytes()[0]);
                if a <= b {
                    (a..=b).map(|c| char::from(c).to_string()).collect()
                } else {
                    (b..=a).rev().map(|c| char::from(c).to_string()).collect()
                }
            }
            _ => comma_alternatives(content),
        }
    } else {
        comma_alternatives(content)
    };
    if parts.len() < 2 && !(deploy_ignore && content.contains("..") && parts[0] != content) {
        return vec![pattern.to_owned()];
    }
    parts
        .into_iter()
        .flat_map(|part| {
            alternatives(
                &format!("{}{}{}", &pattern[..start], part, &pattern[end + 1..]),
                deploy_ignore,
            )
        })
        .collect()
}

pub(super) fn glob(pattern: &str, path: &str) -> bool {
    glob_with_dot(pattern, path, false)
}

pub(super) fn glob_with_dot(pattern: &str, path: &str, dot: bool) -> bool {
    // superstatic's configMatcher tests `config.glob || config.source`, so an empty pattern is no
    // pattern at all and matches nothing (not even `/`, which the trailing-slash rule would allow).
    if pattern.is_empty() || pattern.starts_with('#') {
        return false;
    }
    let negative = pattern.chars().take_while(|ch| *ch == '!').count();
    let pattern = &pattern[negative..];
    let matched = alternatives(pattern, false)
        .iter()
        .any(|pattern| path_match(&slash_split(pattern), &slash_split(path), dot, false));
    matched != (negative % 2 == 1)
}

pub(super) fn deploy_ignore(pattern: &str, path: &str, public_root: &str) -> bool {
    let absolute_path = format!("{}/{}", public_root.trim_end_matches('/'), path);
    alternatives(pattern, true).iter().any(|expanded| {
        let expanded = expanded.trim_start_matches("./");
        // Brace expansion unescapes these characters before Ignore parses globParts again.
        let mut reconstructed = String::new();
        let brace_expansion = pattern
            .find('{')
            .is_some_and(|i| pattern[i + 1..].contains('}'));
        let mut chars = expanded.chars().peekable();
        while let Some(ch) = chars.next() {
            if brace_expansion
                && ch == '\\'
                && chars
                    .peek()
                    .is_some_and(|c| matches!(c, '\\' | '{' | '}' | ',' | '.'))
            {
                reconstructed.push(chars.next().unwrap());
            } else {
                reconstructed.push(ch);
            }
        }
        let expanded = reconstructed;
        alternatives(&expanded, true).iter().any(|pattern| {
            let path = if pattern.starts_with('/')
                || (cfg!(windows) && pattern.as_bytes().get(1) == Some(&b':'))
            {
                &absolute_path
            } else {
                path
            };
            let pattern = slash_split(pattern);
            let slash_path = format!("{path}/");
            let nocase = cfg!(any(target_os = "macos", windows));
            path_match(&pattern, &slash_split(path), true, nocase)
                || path_match(&pattern, &slash_split(&slash_path), true, nocase)
        })
    })
}

pub(super) fn matches(rule: &serde_json::Value, path: &str) -> bool {
    // The first non-empty of `glob` and `source`, as in `config.glob || config.source`.
    if let Some(pattern) = ["glob", "source"]
        .iter()
        .filter_map(|key| rule.get(*key).and_then(serde_json::Value::as_str))
        .find(|pattern| !pattern.is_empty())
    {
        glob(pattern, path)
    } else {
        rule.get("regex")
            .and_then(serde_json::Value::as_str)
            .and_then(|text| regex::Regex::new(text).ok())
            .is_some_and(|pattern| pattern.is_match(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deploy_ignore_agrees_with_minimatch_fixture() {
        // Generated with generate-deploy-ignore-fixture.mjs and firebase-tools listFiles (glob 10.5.0).
        // `expected` is the result where matching ignores case; `caseSensitive` overrides it on Linux.
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("deploy-ignore-fixture.json")).unwrap();
        let mut failures = Vec::new();
        for row in rows {
            let pattern = row["pattern"]
                .as_str()
                .unwrap()
                .replace("{PUBLIC_ROOT}", "/public/root");
            let path = row["path"].as_str().unwrap();
            let expected = if cfg!(any(target_os = "macos", windows)) {
                row["expected"].as_bool().unwrap()
            } else {
                row["caseSensitive"]
                    .as_bool()
                    .unwrap_or_else(|| row["expected"].as_bool().unwrap())
            };
            if deploy_ignore(&pattern, path, "/public/root") != expected {
                failures.push(row);
            }
        }
        assert!(
            failures.is_empty(),
            "{} mismatches: {failures:?}",
            failures.len()
        );
    }
    fn corpus() -> Vec<serde_json::Value> {
        serde_json::from_str(include_str!(
            "../../../../conformance/hosting-fixtures/official-globs.json"
        ))
        .unwrap()
    }
    #[test]
    fn every_observed_glob_fixture_matches() {
        for row in corpus() {
            assert_eq!(
                glob(
                    row["pattern"].as_str().unwrap(),
                    row["path"].as_str().unwrap()
                ),
                row["matches"].as_bool().unwrap(),
                "{row}"
            );
        }
    }
    // Measured offline with the pinned superstatic 10.0.0 configMatcher (its minimatch 6.2.3 splits
    // pattern and path on runs of slashes). Route, rewrite and header matching see the raw path.
    #[test]
    fn repeated_slashes_collapse_like_the_pinned_minimatch() {
        let rows: &[(&str, &str, bool)] = &[
            ("", "/", false),
            ("", "//", false),
            ("", "", false),
            ("", "/a", false),
            ("/", "/", true),
            ("/", "//", true),
            ("//", "/", true),
            ("/a/b", "/a/b/", true),
            ("/data.json", "/data.json/", true),
            ("/a", "/a/", true),
            ("/a/*", "/a/b/", true),
            ("/a/b/", "/a/b/", true),
            ("/data.json", "//data.json", true),
            ("/data.json", "///data.json", true),
            ("//data.json", "/data.json", true),
            ("/a/b.json", "/a//b.json", true),
            ("/a//b.json", "/a/b.json", true),
            ("/a/*", "/a//b", true),
            ("/a/*", "//a/b", true),
            ("/a/**", "/a//b/c", true),
            ("/**", "//", true),
            ("/", "//", true),
            ("//", "/", true),
            ("/a/b/", "/a//b//", true),
            ("/a/b", "/a//b//", true),
            ("/a/b/", "/a/b", false),
            ("/a/*", "/a//", false),
            ("/a/b.json", "/a/b.json//", true),
            ("/a/?", "/a//", false),
            ("/a/?", "/a//x", true),
            ("/**/x", "//x", true),
            ("/{a,b}/x", "//b//x", true),
            ("/a/*/c", "/a///c", false),
            ("/a/*/c", "/a//b//c", true),
            ("/a/*/c", "/a//b/c", true),
            ("/a/*/c", "/a/b//c", true),
            ("/a/!(x)", "/a//y", true),
            ("/a/!(x)", "/a//", false),
        ];
        for (pattern, path, expected) in rows {
            assert_eq!(glob(pattern, path), *expected, "{pattern} against {path}");
        }
    }
    #[test]
    fn canonical_form_follows_the_one_unit_uppercase_rule() {
        // Each pair was measured against glob 10.5.0's Ignore under nocase (fixture rows u000-u134).
        for (a, b, same) in [
            ('s', 'S', true),
            ('\u{e9}', '\u{c9}', true),
            ('\u{3c2}', '\u{3c3}', true),
            ('\u{1c5}', '\u{1c6}', true),
            ('\u{1c5}', '\u{1c4}', true),
            ('\u{df}', 'S', false),
            ('\u{df}', '\u{1e9e}', false),
            ('\u{17f}', 's', false),
            ('\u{212a}', 'k', false),
            ('\u{130}', 'i', false),
            ('\u{131}', 'I', false),
            ('\u{10428}', '\u{10400}', false),
        ] {
            assert_eq!(canonical(a) == canonical(b), same, "{a:?} {b:?}");
        }
        for ch in (0..=0xFFFFu32).filter_map(char::from_u32) {
            let form = canonical(ch);
            assert_eq!(canonical(form), form, "{ch:?} is not folded once");
            if ch.is_ascii() {
                assert!(form.is_ascii(), "{ch:?} folds out of ASCII");
            }
        }
    }
    // Every character of a case class matches every other through a one-character class and range,
    // in both directions (the class holds either the folded form or one of its variants).
    #[test]
    fn every_pair_in_a_case_class_matches_through_a_class_in_both_directions() {
        let mut classes = 0;
        for (form, members) in canonical_classes() {
            let class: Vec<char> = std::iter::once(*form)
                .chain(members.iter().copied())
                .collect();
            for first in &class {
                for second in &class {
                    for pattern in [format!("[{first}]"), format!("[{first}-{first}]")] {
                        assert!(
                            segment(&pattern, &second.to_string(), true, true),
                            "{pattern} {second:?}"
                        );
                        assert!(
                            !segment(
                                &pattern.replacen('[', "[^", 1),
                                &second.to_string(),
                                true,
                                true
                            ),
                            "{pattern} {second:?}"
                        );
                    }
                }
            }
            classes += 1;
        }
        assert!(classes > 1000, "only {classes} case classes");
    }
    proptest::proptest! {
        // Reference model: a class matches when some member of its range has the input's canonical form.
        #[test]
        fn class_matching_ignoring_case_equals_the_brute_force_definition(
            region in 0usize..6, low in 0u32..0x180, span in 0u32..0x180, probe in 0u32..0x180, negative: bool, nocase: bool,
        ) {
            let base = [0x20u32, 0x100, 0x370, 0x1E00, 0x2100, 0xFF00][region];
            let pick = |offset: u32| char::from_u32(base + offset).unwrap();
            let (first, last, ch) = (pick(low), pick(low + span), pick(probe));
            proptest::prop_assume!(![']', '[', '\\', '-', '^', '!'].iter().any(|bad| [first, last].contains(bad)));
            let class = format!("[{}{first}-{last}]", if negative { "^" } else { "" });
            let member = (u32::from(first)..=u32::from(last)).filter_map(char::from_u32).any(|z| {
                z == ch || (nocase && canonical(z) == canonical(ch))
            });
            proptest::prop_assert_eq!(
                segment(&class, &ch.to_string(), true, nocase),
                member != negative,
                "{} against {:?} nocase={}", class, ch, nocase
            );
        }
        #[test]
        fn literals_ignoring_case_compare_canonical_forms(a in 0x20u32..0x2200, b in 0x20u32..0x2200, nocase: bool) {
            let (a, b) = (char::from_u32(a).unwrap(), char::from_u32(b).unwrap());
            proptest::prop_assume!(!"[]\\*?+@!(){}|.^-/".contains(a));
            proptest::prop_assert_eq!(
                segment(&a.to_string(), &b.to_string(), true, nocase),
                a == b || (nocase && canonical(a) == canonical(b))
            );
        }
        #[test]
        fn repeated_slashes_never_change_a_glob_result(
            names in proptest::collection::vec("[a-c]{1,2}", 1..4), extra in proptest::collection::vec(0usize..3, 4), tail: bool,
        ) {
            let plain = format!("/{}", names.join("/"));
            let padded = names.iter().zip(&extra).fold(String::from("/"), |out, (name, more)| {
                format!("{out}{}{name}/", "/".repeat(*more))
            });
            let padded = if tail { padded } else { padded.trim_end_matches('/').to_owned() };
            for pattern in [plain.as_str(), "/**", "/a*", "/*/**"] {
                proptest::prop_assert_eq!(glob(pattern, &padded), glob(pattern, &format!("{plain}{}", if tail { "/" } else { "" })));
            }
        }
    }
    #[test]
    fn an_empty_source_falls_through_to_the_regex_like_superstatic() {
        let rule = |value: serde_json::Value| matches(&value, "/a");
        assert!(!rule(serde_json::json!({"source": ""})));
        assert!(!rule(serde_json::json!({"glob": "", "source": ""})));
        assert!(rule(serde_json::json!({"source": "", "regex": "^/a$"})));
        assert!(rule(serde_json::json!({"glob": "", "source": "/a"})));
        assert!(!matches(&serde_json::json!({"source": ""}), "/"));
    }
    // glob 10.5.0 matches by UTF-16 unit: `?` takes half of an astral character. Measured with the
    // real listFiles (docs.local probe, 2026-11-09). fireemu counts characters; tracked by the open
    // issue hosting-ignore-astral-utf16-units.
    #[test]
    #[ignore = "known gap: hosting-ignore-astral-utf16-units"]
    fn astral_characters_count_as_two_utf16_units_in_deploy_ignore() {
        for (pattern, ignored) in [
            ("?.json", false),
            ("??.json", true),
            ("[\u{1f600}].json", false),
            ("*.json", true),
        ] {
            assert_eq!(
                deploy_ignore(pattern, "\u{1f600}.json", "/public/root"),
                ignored,
                "{pattern}"
            );
        }
    }
    proptest::proptest! {
        #[test]
        fn renaming_literal_segments_preserves_observed_glob_boundaries(prefix in "[a-z]{1,8}", leaf in "[a-z0-9]{1,8}") {
            let rows=corpus();
            let observed=|pattern:&str,path:&str| rows.iter().find(|row|row["pattern"]==pattern&&row["path"]==path).unwrap()["matches"].as_bool().unwrap();
            proptest::prop_assert_eq!(glob(&format!("/{prefix}/*"),&format!("/{prefix}/{leaf}")),observed("/a/*","/a/x"));
            proptest::prop_assert_eq!(glob(&format!("/{prefix}/*"),&format!("/{prefix}/nested/{leaf}")),observed("/a/*","/a/n/x"));
            proptest::prop_assert_eq!(glob(&format!("/{prefix}/**"),&format!("/{prefix}/nested/{leaf}")),observed("/a/**","/a/n/x"));
        }
    }
    proptest::proptest! {
        #[test]
        fn generated_fixture_selection_preserves_first_match(indices in proptest::collection::vec(0usize..135,1..20), path_index in 0usize..135) {
            let rows=corpus();let path=rows[path_index]["path"].as_str().unwrap();
            let expected=indices.iter().position(|idx| {
                let pattern=rows[*idx]["pattern"].as_str().unwrap();
                rows.iter().find(|row|row["pattern"]==pattern && row["path"]==path).unwrap()["matches"].as_bool().unwrap()
            });
            let actual=indices.iter().position(|idx|glob(rows[*idx]["pattern"].as_str().unwrap(),path));
            proptest::prop_assert_eq!(actual,expected);
        }
    }
}
