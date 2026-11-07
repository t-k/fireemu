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

fn ends(sequence: &[Token], input: &[char], start: usize) -> BTreeSet<usize> {
    let mut positions = BTreeSet::from([start]);
    for token in sequence {
        let mut next = BTreeSet::new();
        for pos in positions {
            match token {
                Token::Literal(ch) if input.get(pos) == Some(ch) => {
                    next.insert(pos + 1);
                }
                Token::Any if pos < input.len() => {
                    next.insert(pos + 1);
                }
                Token::Star => next.extend(pos..=input.len()),
                Token::Class(ranges, negative) => {
                    if input.get(pos).is_some_and(|ch| {
                        ranges.iter().any(|(a, b)| a <= ch && ch <= b) != *negative
                    }) {
                        next.insert(pos + 1);
                    }
                }
                Token::Group(kind, alternatives) => {
                    let once: BTreeSet<_> = alternatives
                        .iter()
                        .flat_map(|alt| ends(alt, input, pos))
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
                                            .flat_map(move |alt| ends(alt, input, *p))
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

fn segment(pattern: &str, value: &str) -> bool {
    if value.starts_with('.') && !pattern.starts_with('.') && !pattern.starts_with("\\.") {
        return false;
    }
    if value.is_empty() {
        return pattern.is_empty();
    }
    let chars: Vec<_> = pattern.chars().collect();
    let value: Vec<_> = value.chars().collect();
    ends(&tokens(&chars, &mut 0, false), &value, 0).contains(&value.len())
}

fn path_match(pattern: &[&str], path: &[&str]) -> bool {
    let Some(first) = pattern.first() else {
        return path.is_empty();
    };
    if *first == "**" {
        for take in 0..=path.len() {
            if path[..take].iter().any(|part| part.starts_with('.')) {
                break;
            }
            if path_match(&pattern[1..], &path[take..]) {
                return true;
            }
        }
        false
    } else {
        path.first()
            .is_some_and(|part| segment(first, part) && path_match(&pattern[1..], &path[1..]))
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

fn alternatives(pattern: &str) -> Vec<String> {
    let Some(start) = pattern.find('{') else {
        return vec![pattern.to_owned()];
    };
    let mut depth = 0;
    let mut end = None;
    for (offset, ch) in pattern[start..].char_indices() {
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
    let parts: Vec<String> = if let Some((a, b)) = content.split_once("..") {
        match (a.parse::<i32>(), b.parse::<i32>()) {
            (Ok(a), Ok(b)) if (i64::from(a) - i64::from(b)).abs() <= 1000 => {
                if a <= b {
                    (a..=b).map(|n| n.to_string()).collect()
                } else {
                    (b..=a).rev().map(|n| n.to_string()).collect()
                }
            }
            _ => comma_alternatives(content),
        }
    } else {
        comma_alternatives(content)
    };
    if parts.len() < 2 {
        return vec![pattern.to_owned()];
    }
    parts
        .into_iter()
        .flat_map(|part| {
            alternatives(&format!(
                "{}{}{}",
                &pattern[..start],
                part,
                &pattern[end + 1..]
            ))
        })
        .collect()
}

pub(super) fn glob(pattern: &str, path: &str) -> bool {
    if pattern.starts_with('#') {
        return false;
    }
    let negative = pattern.chars().take_while(|ch| *ch == '!').count();
    let pattern = &pattern[negative..];
    let matched = alternatives(pattern).iter().any(|pattern| {
        let pattern: Vec<_> = pattern.split('/').collect();
        let path: Vec<_> = path.split('/').collect();
        path_match(&pattern, &path)
    });
    matched != (negative % 2 == 1)
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
    fn corpus() -> Vec<serde_json::Value> {
        serde_json::from_str(include_str!(
            "../../../../conformance/fixtures/hosting/official-globs.json"
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
