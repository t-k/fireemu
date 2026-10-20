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
    /// `]`, an escaped letter or digit other than `\d` and `\w` is that character itself,
    /// `\W` and `\D` are the complement of a language (`'abc'` matches `/\W/`), and `x**` is
    /// allowed. Until that dialect is followed (RTDB-03c), a pattern with any of these, or one
    /// this engine cannot compile, is not read at all: matching with it is an error, so the
    /// rule is false whether or not it is negated, and never passes here where the official
    /// emulator denies. `.` matches any character, a newline included, as there.
    ///
    /// `i` is read only for a pattern of ASCII characters, as the official emulator folds it:
    /// see [`fold_case`]. The subject is never transformed.
    pub fn new(text: String, flags: String) -> Self {
        let dialect_only = opens_special_group(&text)
            || text.contains("[[:")
            || escapes_a_letter(&text)
            || escapes_a_backslash_in_a_class(&text)
            || super::parse::regex_shape(&text) != Ok(false)
            || repeats_the_search_prefix(&text);
        let search = (!dialect_only)
            .then(|| {
                let source = if flags.contains('i') {
                    fold_case(&text)?
                } else {
                    utf16_view(&text)
                };
                Regex::new(&search_source(&source)).ok()
            })
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
        self.search
            .as_ref()?
            .is_full_match(&utf16_view(subject))
            .ok()
    }
}

/// Text as a sequence of UTF-16 units, which is what the official emulator (Java) matches:
/// a character outside the Basic Multilingual Plane becomes its two surrogates. Every unit
/// from U+D800 up (the surrogates and U+E000–U+FFFF alike) is written as the private-use
/// character U+F0000 plus its offset from U+D800, so each surrogate is a character of its own
/// (`.` and a class take one, a literal both) and ranges keep Java's order: surrogates below
/// U+E000, U+FFFF last. Nothing else in the text is that high once it is written so, so
/// nothing collides.
fn utf16_view(text: &str) -> String {
    if text.chars().all(|c| u32::from(c) < 0xD800) {
        return text.to_owned();
    }
    text.encode_utf16()
        .map(|unit| {
            let code = match unit {
                0xD800.. => 0xF_0000 + u32::from(unit - 0xD800),
                _ => u32::from(unit),
            };
            char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER)
        })
        .collect()
}

/// Whether an escape names a letter or digit other than the classes `\d` and `\w`, which
/// both dialects read alike (`\D` and `\W` they do not).
fn escapes_a_letter(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' {
            if let Some(next) = chars.get(i + 1) {
                if next.is_ascii_alphanumeric() && !matches!(next, 'd' | 'w') {
                    return true;
                }
            }
            i += 1;
        }
        i += 1;
    }
    false
}

/// Whether a class holds `\\`. The official emulator reads `\\x` in a class as `x` (the
/// second backslash escapes what follows), so `[\\a]` holds no backslash there.
fn escapes_a_backslash_in_a_class(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    let mut in_class = false;
    let mut first = false;
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' if in_class && chars.get(i + 1) == Some(&'\\') => return true,
            '\\' => i += 1,
            '[' if !in_class => {
                in_class = true;
                first = true;
                if chars.get(i + 1) == Some(&'^') {
                    i += 1;
                }
                i += 1;
                continue;
            }
            ']' if in_class && !first => in_class = false,
            _ => {}
        }
        first = false;
        i += 1;
    }
    false
}

/// Whether an unanchored pattern starts with a repetition. The official emulator searches by
/// writing `.*` before such a pattern, so `/{2}/` repeats that `.*` and matches anything; here
/// the search is a separate group.
fn repeats_the_search_prefix(text: &str) -> bool {
    text.starts_with(['*', '+', '?', '{'])
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

/// The pattern as the official emulator reads it under `i`, written for a case-sensitive
/// match; `None` (an error) for what is not read so.
///
/// There, a letter `c` of the pattern stands for `toLowerCase(c)` and `toUpperCase(c)`, and
/// a range is split where letters begin or end: each run adds `[lo-end]` when it holds no
/// letters and `[upper(lo)-upper(end)]` and `[lower(lo)-lower(end)]` when it does, `lo`
/// staying the range's first character for every run. `\w`, `\d` and `.` are not folded,
/// and the subject is left as it is. Only ASCII patterns are read: beyond ASCII, Java's case
/// tables and this text's differ (KELVIN SIGN, dotless i, full-width letters), so a
/// pattern with any other character is an error, as is a range a fold reverses, a class
/// that opens with `]` and a `[` inside a class.
fn fold_case(text: &str) -> Option<String> {
    if !text.is_ascii() {
        return None;
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len() * 2);
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                out.push('\\');
                out.extend(chars.get(i + 1));
                i += 2;
            }
            '[' => i = fold_class(&chars, i + 1, &mut out)?,
            c if c.is_ascii_alphabetic() => {
                let (lower, upper) = (c.to_ascii_lowercase(), c.to_ascii_uppercase());
                push_class(&mut out, &[(lower, lower), (upper, upper)]);
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out)
}

/// One item of a class: a character, or the escape of a class (`\d`, `\w`).
enum ClassItem {
    Char(char),
    Escape(char),
}

/// The item at `chars[i]` and the index after it.
fn class_item(chars: &[char], i: usize) -> Option<(ClassItem, usize)> {
    match chars.get(i)? {
        '\\' => {
            let escaped = *chars.get(i + 1)?;
            let item = if escaped.is_ascii_alphanumeric() {
                ClassItem::Escape(escaped)
            } else {
                ClassItem::Char(escaped)
            };
            Some((item, i + 2))
        }
        '[' => None,
        c => Some((ClassItem::Char(*c), i + 1)),
    }
}

/// Folds the class whose body starts at `chars[start]` (after `[`) into `out`; the index
/// after its `]`.
fn fold_class(chars: &[char], start: usize, out: &mut String) -> Option<usize> {
    let mut i = start;
    let negated = chars.get(i) == Some(&'^');
    if negated {
        i += 1;
    }
    if chars.get(i) == Some(&']') {
        return None;
    }
    let mut ranges = Vec::new();
    let mut escapes = String::new();
    while chars.get(i)? != &']' {
        let (item, next) = class_item(chars, i)?;
        i = next;
        let in_range = chars.get(i) == Some(&'-') && chars.get(i + 1).is_some_and(|c| *c != ']');
        match item {
            ClassItem::Escape(name) if !in_range => {
                escapes.push('\\');
                escapes.push(name);
            }
            ClassItem::Escape(_) => return None,
            ClassItem::Char(lo) if in_range => {
                let (ClassItem::Char(hi), next) = class_item(chars, i + 1)? else {
                    return None;
                };
                i = next;
                ranges.extend(fold_range(lo, hi)?);
            }
            ClassItem::Char(c) if c.is_ascii_alphabetic() => {
                ranges.push((c.to_ascii_lowercase(), c.to_ascii_lowercase()));
                ranges.push((c.to_ascii_uppercase(), c.to_ascii_uppercase()));
            }
            ClassItem::Char(c) => ranges.push((c, c)),
        }
    }
    out.push('[');
    if negated {
        out.push('^');
    }
    out.push_str(&escapes);
    push_ranges(out, &ranges);
    out.push(']');
    Some(i + 1)
}

/// The ranges `[lo-hi]` stands for under `i`, as the official emulator splits it; `None` for
/// a range reversed before or after the fold.
fn fold_range(lo: char, hi: char) -> Option<Vec<(char, char)>> {
    if lo > hi {
        return None;
    }
    let mut ranges = Vec::new();
    let mut c = lo;
    loop {
        let letters = c.is_ascii_alphabetic();
        let mut end = c;
        while end < hi && next_char(end).is_ascii_alphabetic() == letters {
            end = next_char(end);
        }
        if letters {
            ranges.push((lo.to_ascii_uppercase(), end.to_ascii_uppercase()));
            ranges.push((lo.to_ascii_lowercase(), end.to_ascii_lowercase()));
        } else {
            ranges.push((lo, end));
        }
        if end == hi {
            break;
        }
        c = next_char(end);
    }
    ranges.iter().all(|(a, b)| a <= b).then_some(ranges)
}

/// The ASCII character after `c` (`c` is below `hi`, so ASCII too).
fn next_char(c: char) -> char {
    char::from_u32(u32::from(c) + 1).unwrap_or(c)
}

fn push_class(out: &mut String, ranges: &[(char, char)]) {
    out.push('[');
    push_ranges(out, ranges);
    out.push(']');
}

/// Each range as `a-b` (or `a`), punctuation escaped.
fn push_ranges(out: &mut String, ranges: &[(char, char)]) {
    let push = |out: &mut String, c: char| {
        if !c.is_ascii_alphanumeric() {
            out.push('\\');
        }
        out.push(c);
    };
    for &(a, b) in ranges {
        push(out, a);
        if a != b {
            out.push('-');
            push(out, b);
        }
    }
}

fn search_source(text: &str) -> String {
    // `.` matches any character, a newline included.
    let mut source = String::from("(?s)");
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
        assert_eq!(matches(r"^\d\w$", "1a"), Some(true));
        // An escaped backslash is a backslash, also first: what follows it is plain.
        assert_eq!(matches(r"\\n", r"\n"), Some(true));
        assert_eq!(matches(r"x\\n", r"x\n"), Some(true));
        assert_eq!(matches("^a.b$", "a\nb"), Some(true));
        assert_eq!(matches(r"a\(?b", "ab"), Some(true));
        assert_eq!(matches(r"a\(?b", "a(b"), Some(true));
        assert_eq!(matches("a(b)?", "a"), Some(true));
    }

    fn matches_i(text: &str, subject: &str) -> Option<bool> {
        Pattern::new(text.to_owned(), "i".to_owned()).matches(subject)
    }

    #[test]
    fn complemented_classes_are_errors_wherever_they_appear() {
        // The official emulator reads `\W` and `\D` as the complement of a language, not of a
        // character set (`'abc'` matches `/\W/` there): not read here (RTDB-03c).
        for text in [r"\W", r"\D", r"^a\W$", r"[\W]", r"[a\D]", r"[^\W]", r"\\\W"] {
            assert_eq!(matches(text, "abc"), None, "{text}");
            assert_eq!(matches_i(text, "abc"), None, "{text}");
        }
        assert_eq!(matches(r"^\d\w$", "1a"), Some(true));
        assert_eq!(matches(r"^[\d\w]$", "_"), Some(true));
        // An escaped backslash before W leaves a plain W.
        assert_eq!(matches(r"^\\W$", r"\W"), Some(true));
    }

    #[test]
    fn ignoring_case_folds_only_ascii_letters_of_the_pattern() {
        // The subject is never transformed: a character that folds to an ASCII letter in
        // Unicode does not match it.
        assert_eq!(matches_i("^k$", "K"), Some(true));
        assert_eq!(matches_i("^K$", "k"), Some(true));
        assert_eq!(matches_i("^k$", "\u{212a}"), Some(false), "KELVIN SIGN");
        assert_eq!(matches_i("^s$", "\u{17f}"), Some(false), "LONG S");
        assert_eq!(matches_i("^[A-Z]$", "\u{131}"), Some(false), "dotless i");
        assert_eq!(matches_i("^[a-z]$", "\u{130}"), Some(false), "dotted I");
        assert_eq!(matches_i(r"^\w$", "\u{212a}"), Some(false));
        assert_eq!(matches_i(r"^\w$", "\u{17f}"), Some(false));
        assert_eq!(matches_i("^[^a-z]$", "\u{212a}"), Some(true));
        assert_eq!(matches_i("^[^a-z]$", "K"), Some(false));
        assert_eq!(matches_i("^[K]$", "k"), Some(true));
        assert_eq!(matches_i("^[k-m]+$", "KlM"), Some(true));
        assert_eq!(matches_i("^ab[c]d$", "ABCD"), Some(true));
        // `\w`, `\d` and `.` are not folded, and escapes keep their character.
        assert_eq!(matches_i(r"^\.\w\d.$", ".A1b"), Some(true));
        assert_eq!(matches_i(r"^a\-b$", "A-B"), Some(true));
        assert_eq!(matches_i(r"^[\]a]$", "A"), Some(true));
        assert_eq!(matches_i(r"^[\]a]$", "]"), Some(true));
        assert_eq!(matches_i(r"^[a\-c]$", "-"), Some(true));
        assert_eq!(matches_i(r"^[a\-c]$", "B"), Some(false));
        assert_eq!(matches_i("^[-a]$", "-"), Some(true));
        assert_eq!(matches_i("^[a-]$", "A"), Some(true));
        assert_eq!(matches_i("^a{2}$", "aA"), Some(true));
    }

    #[test]
    fn a_folded_range_keeps_its_first_character_as_every_run_s_start() {
        // The official emulator splits a range where letters begin or end and never advances
        // the start: under `i`, `[!-Z]` is `[!-@]`, `[!-Z]` and `[!-z]`.
        assert_eq!(matches_i("^[!-Z]$", "b"), Some(true));
        assert_eq!(matches_i("^[!-Z]$", "`"), Some(true));
        assert_eq!(matches_i("^[!-Z]$", "{"), Some(false));
        assert_eq!(matches_i("^[0-9]$", "5"), Some(true));
        assert_eq!(matches_i("^[0-9]$", "a"), Some(false));
        assert_eq!(matches_i("^[a-z]$", "Q"), Some(true));
        assert_eq!(matches_i("^[a-z]$", "["), Some(false));
        assert_eq!(matches_i("^[A-z]$", "_"), Some(true));
        // `[Z-a]` folds to a run `[Z-A]`, which is reversed: an error.
        assert_eq!(matches_i("^[Z-a]$", "Z"), None);
        // A range reversed before folding is an error too.
        assert_eq!(matches_i("^[z-a]$", "b"), None);
    }

    #[test]
    fn ignoring_case_with_anything_beyond_ascii_in_the_pattern_is_an_error() {
        for text in [
            "^\u{e9}$",
            "^\u{212a}$",
            "^\u{df}$",
            "^[\u{ff41}-\u{ff3a}]$",
            "^[\u{ff40}-\u{ff5f}]$",
            "^[a-\u{e9}]$",
            "^\u{1f600}$",
            "^\u{1c5}$",
        ] {
            assert_eq!(matches_i(text, "a"), None, "{text}");
        }
        // Without `i` the same patterns are read.
        assert_eq!(matches("^\u{e9}$", "\u{e9}"), Some(true));
        // A class that starts with `]` or holds `[` is not folded either.
        assert_eq!(matches_i("^[]a]$", "a"), None);
        assert_eq!(matches_i("^[a[]$", "a"), None);
    }

    #[test]
    fn an_escaped_backslash_in_a_class_is_an_error() {
        // There `[\\a]` is `[a]`.
        for text in [
            r"^[\\a]$",
            r"^[a\\b]$",
            r"^[^\\a]$",
            r"^[]\\a]$",
            r"x[\\-a]",
        ] {
            assert_eq!(matches(text, "a"), None, "{text}");
        }
        // Outside a class both read it as a backslash.
        assert_eq!(matches(r"^\\[a]$", r"\a"), Some(true));
        assert_eq!(matches(r"^[a]\\$", r"a\"), Some(true));
        assert_eq!(matches(r"^[\]]\\$", r"]\"), Some(true));
    }

    #[test]
    fn an_operator_that_starts_an_alternative_is_an_error() {
        // There it is a literal character: `(|a)` is `|a`, `(a|))` is `a` or `)`.
        for text in [
            "^(|a)$",
            "^(a|))$",
            "^(|)$",
            "^|a$",
            "^a||b$",
            "^*$",
            "^(a|*)$",
            "^(a|{2})$",
            "^)$",
        ] {
            assert_eq!(matches(text, "a"), None, "{text}");
        }
        // An unanchored pattern that starts with a repetition repeats the search's `.*` there.
        for text in ["{2}", "+a", "?a", "{1,2}b"] {
            assert_eq!(matches(text, "a"), None, "{text}");
        }
        // An empty group and an unanchored trailing `|` are read alike.
        assert_eq!(matches("^x()$", "x"), Some(true));
        assert_eq!(matches("a|", "zz"), Some(true));
        assert_eq!(matches("^(a)*$", "aa"), Some(true));
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
