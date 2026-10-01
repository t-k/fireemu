//! The glob syntax of the JSON API's `matchGlob` list filter.
//!
//! <https://cloud.google.com/storage/docs/json_api/v1/objects/list>: `*` matches any run of
//! characters except `/`, `**` any run including `/`, `?` one character except `/`, `[...]` one
//! character of a set or range (`[!...]` and `[^...]` negate it; a set never matches `/`),
//! `{a,b}` any of the alternatives, and `\` takes the next character literally. Only the pattern
//! `dir/*` was recorded in production; every other construct follows the documentation. An
//! unterminated `[` or `{` is taken literally (production's answer to one was not recorded).

/// One element of a parsed pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Literal(char),
    /// `*`.
    Segment,
    /// `**`.
    Any,
    /// `?`.
    One,
    /// `[...]`: the ranges of the set and whether it is negated.
    Class(Vec<(char, char)>, bool),
    /// `{a,b}`: each alternative is itself a token list.
    Alternatives(Vec<Vec<Token>>),
}

/// Whether `name` matches the glob `pattern` in full.
#[must_use]
pub fn glob_matches(pattern: &str, name: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let tokens = parse(&chars, &mut 0, false);
    let name: Vec<char> = name.chars().collect();
    matches(&tokens, &name)
}

/// Parses until the end of the pattern or, inside braces, until an unnested `,` or `}` (left
/// for the caller).
fn parse(chars: &[char], at: &mut usize, in_braces: bool) -> Vec<Token> {
    let mut tokens = Vec::new();
    // Every pass consumes at least one character, so `chars.len()` passes are the most there can
    // be; the bound keeps a cursor that stopped advancing from growing `tokens` without end.
    for _ in 0..=chars.len() {
        let Some(&c) = chars.get(*at) else { break };
        match c {
            ',' | '}' if in_braces => break,
            '\\' => {
                *at += 1;
                match chars.get(*at) {
                    Some(&escaped) => {
                        tokens.push(Token::Literal(escaped));
                        *at += 1;
                    }
                    None => tokens.push(Token::Literal('\\')),
                }
            }
            '*' => {
                if chars.get(*at + 1) == Some(&'*') {
                    tokens.push(Token::Any);
                    *at += 2;
                    while chars.get(*at) == Some(&'*') {
                        *at += 1;
                    }
                } else {
                    tokens.push(Token::Segment);
                    *at += 1;
                }
            }
            '?' => {
                tokens.push(Token::One);
                *at += 1;
            }
            '[' => {
                if let Some((class, next)) = parse_class(chars, *at) {
                    tokens.push(class);
                    *at = next;
                } else {
                    tokens.push(Token::Literal('['));
                    *at += 1;
                }
            }
            '{' => {
                let start = *at;
                *at += 1;
                let mut alternatives = vec![parse(chars, at, true)];
                // One alternative per comma at most: the bound keeps a cursor that stopped
                // advancing from collecting alternatives without end.
                for _ in 0..chars.len() {
                    if chars.get(*at) != Some(&',') {
                        break;
                    }
                    *at += 1;
                    alternatives.push(parse(chars, at, true));
                }
                if chars.get(*at) == Some(&'}') {
                    *at += 1;
                    tokens.push(Token::Alternatives(alternatives));
                } else {
                    // Unterminated: the brace is a literal and the rest parses again.
                    tokens.push(Token::Literal('{'));
                    *at = start + 1;
                }
            }
            other => {
                tokens.push(Token::Literal(other));
                *at += 1;
            }
        }
    }
    tokens
}

/// A `[...]` set starting at `start`, and the index after its `]`, or `None` when unterminated.
fn parse_class(chars: &[char], start: usize) -> Option<(Token, usize)> {
    let mut at = start + 1;
    let negated = matches!(chars.get(at), Some('!' | '^'));
    if negated {
        at += 1;
    }
    let mut ranges = Vec::new();
    let mut first = true;
    // As in `parse`, each pass consumes a character, so the pattern's length bounds the passes.
    for _ in 0..=chars.len() {
        let &c = chars.get(at)?;
        if c == ']' && !first {
            return Some((Token::Class(ranges, negated), at + 1));
        }
        first = false;
        let low = if c == '\\' {
            at += 1;
            *chars.get(at)?
        } else {
            c
        };
        at += 1;
        if chars.get(at) == Some(&'-') && chars.get(at + 1).is_some_and(|&next| next != ']') {
            let mut high = chars[at + 1];
            at += 2;
            if high == '\\' {
                high = *chars.get(at)?;
                at += 1;
            }
            ranges.push((low, high));
        } else {
            ranges.push((low, low));
        }
    }
    None
}

fn matches(tokens: &[Token], name: &[char]) -> bool {
    let Some((first, rest)) = tokens.split_first() else {
        return name.is_empty();
    };
    match first {
        Token::Literal(c) => name.first() == Some(c) && matches(rest, &name[1..]),
        Token::One => name.first().is_some_and(|&c| c != '/') && matches(rest, &name[1..]),
        Token::Class(ranges, negated) => {
            name.first().is_some_and(|&c| {
                c != '/' && (ranges.iter().any(|&(low, high)| low <= c && c <= high) != *negated)
            }) && matches(rest, &name[1..])
        }
        Token::Segment => (0..=name.len())
            .take_while(|&taken| taken == 0 || name[taken - 1] != '/')
            .any(|taken| matches(rest, &name[taken..])),
        Token::Any => (0..=name.len()).any(|taken| matches(rest, &name[taken..])),
        Token::Alternatives(alternatives) => alternatives.iter().any(|alternative| {
            let mut joined = alternative.clone();
            joined.extend_from_slice(rest);
            matches(&joined, name)
        }),
    }
}
