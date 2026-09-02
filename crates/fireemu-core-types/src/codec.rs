//! Shared wire codecs with explicit surface-specific compatibility choices.

/// How an unescaped plus sign is interpreted while percent-decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlusMode {
    /// HTML form semantics: `+` is a space.
    Space,
    /// URI path/query-component semantics: `+` remains a plus.
    Literal,
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
    use super::{percent_decode, PlusMode};

    #[test]
    fn percent_decode_has_explicit_plus_semantics_and_strict_hex_digits() {
        assert_eq!(percent_decode("a%20b+c", PlusMode::Space), "a b c");
        assert_eq!(percent_decode("a%20b+c", PlusMode::Literal), "a b+c");
        assert_eq!(percent_decode("%+f%2G%", PlusMode::Literal), "%+f%2G%");
        assert_eq!(percent_decode("%2f%2F", PlusMode::Literal), "//");
    }
}
