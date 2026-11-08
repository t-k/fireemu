//! Ordered Hosting source matching. Glob segments never consume a path separator.

use std::collections::BTreeSet;

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

fn ends(sequence: &[Token], input: &[char], start: usize, nocase: bool) -> BTreeSet<usize> {
    let mut positions = BTreeSet::from([start]);
    for token in sequence {
        let mut next = BTreeSet::new();
        for pos in positions {
            match token {
                Token::Literal(ch)
                    if input.get(pos).is_some_and(|value| {
                        value == ch || (nocase && value.to_lowercase().eq(ch.to_lowercase()))
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
                        (contains(*ch)
                            || (nocase && ch.to_lowercase().chain(ch.to_uppercase()).any(contains)))
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

fn path_match(pattern: &[&str], path: &[&str], dot: bool, nocase: bool) -> bool {
    let Some(first) = pattern.first() else {
        return path.is_empty();
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
    if pattern.starts_with('#') {
        return false;
    }
    let negative = pattern.chars().take_while(|ch| *ch == '!').count();
    let pattern = &pattern[negative..];
    let matched = alternatives(pattern, false).iter().any(|pattern| {
        let pattern: Vec<_> = pattern.split('/').collect();
        let path: Vec<_> = path.split('/').collect();
        path_match(&pattern, &path, dot, false)
    });
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
            let pattern: Vec<_> = pattern.split('/').collect();
            let slash_path = format!("{path}/");
            let nocase = cfg!(any(target_os = "macos", windows));
            path_match(&pattern, &path.split('/').collect::<Vec<_>>(), true, nocase)
                || path_match(
                    &pattern,
                    &slash_path.split('/').collect::<Vec<_>>(),
                    true,
                    nocase,
                )
        })
    })
}

pub(super) fn matches(rule: &serde_json::Value, path: &str) -> bool {
    if let Some(pattern) = rule
        .get("glob")
        .or_else(|| rule.get("source"))
        .and_then(serde_json::Value::as_str)
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
        // Generated on macOS with generate-deploy-ignore-fixture.mjs and firebase-tools listFiles.
        let rows: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("deploy-ignore-fixture.json")).unwrap();
        let mut failures = Vec::new();
        for row in rows {
            let pattern = row["pattern"]
                .as_str()
                .unwrap()
                .replace("{PUBLIC_ROOT}", "/public/root");
            let path = row["path"].as_str().unwrap();
            let expected = if row["nocase"] == true {
                cfg!(any(target_os = "macos", windows))
            } else {
                row["expected"].as_bool().unwrap()
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
