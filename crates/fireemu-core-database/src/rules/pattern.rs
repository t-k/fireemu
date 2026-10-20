//! `matches()` patterns, compiled once when the rules load.

use std::sync::Arc;

use fireemu_core_rules::regex::Regex;

/// A `/pattern/flags` literal and its compiled search.
#[derive(Debug, Clone)]
pub struct Pattern {
    text: String,
    flags: String,
    /// `None` for a pattern this engine does not read as the official emulator does.
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
    /// The official emulator reads its own dialect (an automaton grammar): `(?` opens a group
    /// whose first character is a literal `?`, `[[:alpha:]]` is a class followed by a literal
    /// `]`, an escaped letter or digit other than `\d`, `\D`, `\w` and `\W` is that character
    /// itself, and `x**` is allowed. Until that dialect is followed (RTDB-03c), a pattern with
    /// any of these, or one this engine cannot compile, is not read at all: matching with it is
    /// an error, so the rule is false whether or not it is negated, and never passes here where
    /// the official emulator denies. `.` matches any character, a newline included, as there.
    pub fn new(text: String, flags: String) -> Self {
        let dialect_only =
            opens_special_group(&text) || text.contains("[[:") || escapes_a_letter(&text);
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

    /// Whether `subject` matches; `None` (an error) for a pattern not read, or when the
    /// engine gives up on it.
    pub fn matches(&self, subject: &str) -> Option<bool> {
        self.search.as_ref()?.is_full_match(subject).ok()
    }
}

/// Whether an escape names a letter or digit other than the classes `\d`, `\D`, `\w` and
/// `\W`, which both dialects read alike.
fn escapes_a_letter(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' {
            if let Some(next) = chars.get(i + 1) {
                if next.is_ascii_alphanumeric() && !matches!(next, 'd' | 'D' | 'w' | 'W') {
                    return true;
                }
            }
            i += 1;
        }
        i += 1;
    }
    false
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
    // `.` matches any character, a newline included.
    let mut source = String::from("(?s)");
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
    fn the_official_dialect_s_constructs_are_errors_and_escaped_parentheses_are_plain() {
        for (text, subject) in [
            ("(?:a)", "?:a"),
            ("x(?i)a", "x?ia"),
            ("[[:alpha:]]", "a]"),
            (r"^\n$", "n"),
            (r"^\n$", "\n"),
            (r"^\1$", "1"),
            (r"^\b$", "b"),
            ("^a**$", "a"),
        ] {
            assert_eq!(matches(text, subject), None, "{text}");
        }
        assert_eq!(matches(r"^\d\D\w\W$", "1a_-"), Some(true));
        // An escaped backslash is a backslash, also first: what follows it is plain.
        assert_eq!(matches(r"\\n", r"\n"), Some(true));
        assert_eq!(matches(r"x\\n", r"x\n"), Some(true));
        assert_eq!(matches("^a.b$", "a\nb"), Some(true));
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
        assert_eq!(
            matches("(", "("),
            None,
            "a pattern the engine cannot compile is an error"
        );
    }
}
