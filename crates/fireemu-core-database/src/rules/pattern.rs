//! `matches()` patterns, compiled once when the rules load.

use std::sync::Arc;

use fireemu_core_rules::regex::Regex;

/// A `/pattern/flags` literal and its compiled search.
#[derive(Debug, Clone)]
pub struct Pattern {
    text: String,
    flags: String,
    /// `None` for a pattern that never matches.
    search: Option<Arc<Regex>>,
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text && self.flags == other.flags
    }
}

impl Pattern {
    /// Compiles `/text/flags` as a search: unanchored unless the pattern anchors itself (a
    /// final `$` is the end anchor), `i` ignoring case.
    ///
    /// The official emulator reads its own dialect, where `(?…)` groups and `[[:class:]]` do
    /// not mean what they mean to the RE2 engine used here; it answered false for every
    /// recorded pattern with them. Until that dialect is followed (RTDB-03c) such a pattern
    /// never matches, so a rule never passes here that the official emulator denies. A pattern
    /// the engine cannot compile never matches either.
    pub fn new(text: String, flags: String) -> Self {
        let dialect_only = opens_special_group(&text) || text.contains("[[:");
        let search = (!dialect_only)
            .then(|| Regex::new(&search_source(&text, &flags)).ok())
            .flatten()
            .map(Arc::new);
        Self {
            text,
            flags,
            search,
        }
    }

    /// Whether `subject` matches; `None` when the engine gives up on it.
    pub fn matches(&self, subject: &str) -> Option<bool> {
        match &self.search {
            Some(search) => search.is_full_match(subject).ok(),
            None => Some(false),
        }
    }
}

/// Whether an unescaped `(` is followed by `?`.
fn opens_special_group(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 1,
            '(' if chars.get(i + 1) == Some(&'?') => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

fn search_source(text: &str, flags: &str) -> String {
    let mut source = String::new();
    if flags.contains('i') {
        source.push_str("(?i)");
    }
    if !text.starts_with('^') {
        source.push_str("(?s:.)*?");
    }
    source.push_str("(?:");
    source.push_str(text);
    source.push(')');
    if !text.ends_with('$') {
        source.push_str("(?s:.)*");
    }
    source
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(text: &str, subject: &str) -> Option<bool> {
        Pattern::new(text.to_owned(), String::new()).matches(subject)
    }

    #[test]
    fn the_official_dialect_s_groups_never_match_and_escaped_ones_are_plain() {
        assert_eq!(matches("(?:a)", "a"), Some(false));
        assert_eq!(matches("x(?i)a", "xa"), Some(false));
        assert_eq!(matches("[[:alpha:]]", "a"), Some(false));
        assert_eq!(matches(r"a\(?b", "ab"), Some(true));
        assert_eq!(matches(r"a\(?b", "a(b"), Some(true));
        assert_eq!(matches("a(b)?", "a"), Some(true));
    }

    #[test]
    fn patterns_are_equal_by_text_and_flags() {
        let pattern = |text: &str, flags: &str| Pattern::new(text.to_owned(), flags.to_owned());
        assert_eq!(pattern("a", ""), pattern("a", ""));
        assert_ne!(pattern("a", ""), pattern("a", "i"));
        assert_ne!(pattern("a", ""), pattern("b", ""));
    }

    #[test]
    fn patterns_search_unless_anchored() {
        assert_eq!(matches("b", "abc"), Some(true));
        assert_eq!(matches("^b", "abc"), Some(false));
        assert_eq!(matches("b$", "abc"), Some(false));
        assert_eq!(matches("c$", "abc"), Some(true));
        assert_eq!(
            Pattern::new("B".to_owned(), "i".to_owned()).matches("abc"),
            Some(true)
        );
        assert_eq!(matches("(", "("), Some(false));
    }
}
