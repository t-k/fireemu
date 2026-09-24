//! Shared wire codecs with explicit surface-specific compatibility choices.

/// How an unescaped plus sign is interpreted while percent-decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlusMode {
    /// HTML form semantics: `+` is a space.
    Space,
    /// URI path/query-component semantics: `+` remains a plus.
    Literal,
}

/// How backspace and form-feed are represented in a JSON string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonControlEscape {
    /// Use the short RFC 8259 escapes (`\b` and `\f`).
    Short,
    /// Use four-digit Unicode escapes (`\u0008` and `\u000c`).
    Unicode,
}

/// Appends RFC 8259 escaping for string contents, without surrounding quotes.
pub fn json_escape_into(output: &mut String, text: &str, control: JsonControlEscape) {
    use core::fmt::Write as _;

    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{08}' if control == JsonControlEscape::Short => output.push_str("\\b"),
            '\u{0c}' if control == JsonControlEscape::Short => output.push_str("\\f"),
            character if (character as u32) < 0x20 => {
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
}

/// Appends one quoted RFC 8259 string.
pub fn write_json_string(output: &mut String, text: &str, control: JsonControlEscape) {
    output.push('"');
    json_escape_into(output, text, control);
    output.push('"');
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decodes strict `%XX` sequences while preserving malformed input byte-for-byte.
///
/// The caller chooses whether `+` is form-encoded space or a literal character. Only two
/// ASCII hexadecimal digits form an escape; signs and other `from_str_radix` extensions are
/// never accepted.
#[must_use]
pub fn percent_decode(value: &str, plus: PlusMode) -> String {
    String::from_utf8_lossy(&percent_decode_bytes(value, plus)).into_owned()
}

/// Decodes a lowercase or uppercase hexadecimal string into bytes.
///
/// Every byte must be spelled by exactly two ASCII hexadecimal digits; an odd length, a
/// sign, whitespace or any other character yields `None`. Adapters that carry opaque
/// hexadecimal tokens decode them here so the nibble rule lives in one place.
#[must_use]
pub fn hex_decode(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some((hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?))
        .collect()
}

/// The bytes [`percent_decode`] decodes, before any UTF-8 interpretation.
///
/// A caller that must refuse a sequence which is not UTF-8, rather than replace it, decodes
/// through this and validates the bytes itself. The escape semantics stay in one place.
#[must_use]
pub fn percent_decode_bytes(value: &str, plus: PlusMode) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_nibble(bytes[index + 1]), hex_nibble(bytes[index + 2]))
            {
                output.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        if bytes[index] == b'+' && plus == PlusMode::Space {
            output.push(b' ');
        } else {
            output.push(bytes[index]);
        }
        index += 1;
    }
    output
}

/// Whether every `%` in `value` introduces a complete escape of two ASCII hexadecimal
/// digits.
///
/// [`percent_decode`] keeps a malformed escape byte-for-byte, which is what a lenient
/// surface wants. A surface that refuses one instead asks this first, so both agree on what
/// an escape is: `%2f` is well formed, and `%`, `%2`, `%2G` and `%+f` are not.
#[must_use]
pub fn percent_escapes_are_well_formed(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len()
                || hex_nibble(bytes[index + 1]).is_none()
                || hex_nibble(bytes[index + 2]).is_none()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

/// The most bytes of client input a refusal text echoes. A refusal is produced before
/// authorization and can travel in a `grpc-message` header, so a request must not grow its
/// answer with the size of what it sent; production's own truncation is unobserved, so this
/// is a local safety bound (`spec/compatibility/contract.json`).
pub const MAX_ECHO_BYTES: usize = 1024;

/// `text` as a refusal echoes it: whole when it is at most [`MAX_ECHO_BYTES`], else its first
/// bytes up to a character boundary followed by `...`.
#[must_use]
pub fn echo(text: &str) -> std::borrow::Cow<'_, str> {
    if text.len() <= MAX_ECHO_BYTES {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut end = MAX_ECHO_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    std::borrow::Cow::Owned(format!("{}...", &text[..end]))
}

#[cfg(test)]
mod tests {

    #[test]
    fn echo_keeps_short_text_and_cuts_long_text_at_a_character_boundary() {
        assert_eq!(super::echo("abc"), "abc");
        let exact = "x".repeat(super::MAX_ECHO_BYTES);
        assert_eq!(super::echo(&exact), exact);
        let long = "\u{e9}".repeat(super::MAX_ECHO_BYTES);
        let echoed = super::echo(&long);
        assert!(echoed.ends_with("..."));
        assert!(echoed.len() <= super::MAX_ECHO_BYTES + 3);
        assert!(echoed
            .trim_end_matches("...")
            .chars()
            .all(|c| c == '\u{e9}'));
    }
    use super::{
        json_escape_into, percent_decode, percent_decode_bytes, percent_escapes_are_well_formed,
        write_json_string, JsonControlEscape, PlusMode,
    };

    #[test]
    fn percent_decode_has_explicit_plus_semantics_and_strict_hex_digits() {
        assert_eq!(percent_decode("a%20b+c", PlusMode::Space), "a b c");
        assert_eq!(percent_decode("a%20b+c", PlusMode::Literal), "a b+c");
        assert_eq!(percent_decode("%+f%2G%", PlusMode::Literal), "%+f%2G%");
        assert_eq!(percent_decode("%2f%2F", PlusMode::Literal), "//");
    }

    #[test]
    fn malformed_escapes_are_recognised_by_the_same_rule_that_decodes_them() {
        for well_formed in ["", "plain", "%2f", "%2F%20", "a%00b"] {
            assert!(
                percent_escapes_are_well_formed(well_formed),
                "{well_formed}"
            );
        }
        for malformed in ["%", "%2", "%2G", "%+f", "%-1", "a%zzb"] {
            assert!(!percent_escapes_are_well_formed(malformed), "{malformed}");
            // The lenient decoder keeps exactly what the strict check refuses.
            assert_eq!(percent_decode(malformed, PlusMode::Literal), malformed);
        }
    }

    #[test]
    fn decoded_bytes_are_returned_before_any_utf8_interpretation() {
        // A lone 0x80 is not UTF-8: the lossy decoder replaces it, the byte decoder does not.
        assert_eq!(percent_decode_bytes("%80", PlusMode::Literal), vec![0x80]);
        assert_eq!(percent_decode("%80", PlusMode::Literal), "\u{fffd}");
        assert_eq!(
            percent_decode_bytes("a+b", PlusMode::Space),
            b"a b".to_vec()
        );
    }

    #[test]
    fn json_escaping_preserves_each_existing_control_character_dialect() {
        let text = "a\u{1}\u{8}\u{c}\"\\\n";
        let mut unicode = String::new();
        write_json_string(&mut unicode, text, JsonControlEscape::Unicode);
        assert_eq!(unicode, "\"a\\u0001\\u0008\\u000c\\\"\\\\\\n\"");

        let mut short = String::new();
        write_json_string(&mut short, text, JsonControlEscape::Short);
        assert_eq!(short, "\"a\\u0001\\b\\f\\\"\\\\\\n\"");

        let mut unquoted = String::new();
        json_escape_into(&mut unquoted, text, JsonControlEscape::Unicode);
        assert_eq!(unquoted, &unicode[1..unicode.len() - 1]);
    }
}

#[cfg(test)]
mod hex_decode_tests {
    use super::hex_decode;

    #[test]
    fn decodes_exactly_two_digits_per_byte_in_either_case() {
        assert_eq!(hex_decode("00ff7Fa0"), Some(vec![0x00, 0xff, 0x7f, 0xa0]));
        assert_eq!(hex_decode(""), Some(Vec::new()));
    }

    #[test]
    fn refuses_odd_length_signs_and_non_hex() {
        assert_eq!(hex_decode("abc"), None);
        assert_eq!(hex_decode("+f"), None);
        assert_eq!(hex_decode(" f"), None);
        assert_eq!(hex_decode("zz"), None);
    }
}
