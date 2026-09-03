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
    String::from_utf8_lossy(&output).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{json_escape_into, percent_decode, write_json_string, JsonControlEscape, PlusMode};

    #[test]
    fn percent_decode_has_explicit_plus_semantics_and_strict_hex_digits() {
        assert_eq!(percent_decode("a%20b+c", PlusMode::Space), "a b c");
        assert_eq!(percent_decode("a%20b+c", PlusMode::Literal), "a b+c");
        assert_eq!(percent_decode("%+f%2G%", PlusMode::Literal), "%+f%2G%");
        assert_eq!(percent_decode("%2f%2F", PlusMode::Literal), "//");
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
