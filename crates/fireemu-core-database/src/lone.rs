//! Text that can hold a lone surrogate, inside a Rust `String`.
//!
//! The Realtime Database emulator profile reads the claims of an ID token as the official emulator does, and
//! Java strings hold a lone surrogate (`"\ud83d"` in a claim) where a Rust `String` cannot. The claims the
//! adapter hands to the Rules as `auth` are therefore written in this encoding when the emulator profile reads
//! them: a lone surrogate unit is one of 2048 stand-in characters at the top of plane 16, and a real character
//! that is a stand-in or the escape character itself follows the escape character. The Rules decode a string
//! of `auth` back to UTF-16 units. The encoding exists only between the claims parser and the Rules
//! evaluator, and only on the emulator profile; no other component reads it.

/// The escape character: it precedes a real character that is a stand-in or itself.
pub const ESCAPE: char = '\u{10FFFF}';
const FIRST: u32 = 0x10_F000;
const COUNT: u32 = 0x800;

/// Whether `c` is the escape character or a stand-in (a character the encoding gives a meaning).
#[must_use]
pub fn is_reserved(c: char) -> bool {
    c == ESCAPE || (FIRST..FIRST + COUNT).contains(&u32::from(c))
}

/// The stand-in for a lone surrogate `unit` (U+D800 to U+DFFF).
///
/// # Panics
///
/// Panics when `unit` is not a surrogate.
#[must_use]
pub fn stand_in(unit: u16) -> char {
    assert!((0xD800..=0xDFFF).contains(&unit), "not a surrogate");
    char::from_u32(FIRST + u32::from(unit - 0xD800)).expect("a plane 16 character")
}

/// Whether `text` holds a character the encoding gives a meaning (so it is not plain text).
#[must_use]
pub fn is_encoded(text: &str) -> bool {
    text.chars().any(is_reserved)
}

/// `text`, a real string, in the encoding: each reserved character after the escape.
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_reserved(c) {
            out.push(ESCAPE);
        }
        out.push(c);
    }
    out
}

/// `units` in the encoding.
#[must_use]
pub fn encode(units: &[u16]) -> String {
    let mut out = String::with_capacity(units.len());
    for decoded in char::decode_utf16(units.iter().copied()) {
        match decoded {
            Ok(c) if is_reserved(c) => {
                out.push(ESCAPE);
                out.push(c);
            }
            Ok(c) => out.push(c),
            Err(lone) => out.push(stand_in(lone.unpaired_surrogate())),
        }
    }
    out
}

/// The UTF-16 units of an encoded `text`.
#[must_use]
pub fn decode(text: &str) -> Vec<u16> {
    let mut units = Vec::with_capacity(text.len());
    let mut escaped = false;
    let mut buffer = [0_u16; 2];
    for c in text.chars() {
        if !escaped && c == ESCAPE {
            escaped = true;
            continue;
        }
        let stand_in_unit = (FIRST..FIRST + COUNT)
            .contains(&u32::from(c))
            .then(|| u16::try_from(u32::from(c) - FIRST + 0xD800).expect("a surrogate"));
        match (escaped, stand_in_unit) {
            (false, Some(unit)) => units.push(unit),
            _ => units.extend_from_slice(c.encode_utf16(&mut buffer)),
        }
        escaped = false;
    }
    units
}

/// `text` for a JSON document: a stand-in is written as the escape of its surrogate, a protected character as
/// itself. What a client sees of a claim that holds a lone surrogate.
#[must_use]
pub fn json_text(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    let mut escaped = false;
    for c in text.chars() {
        if !escaped && c == ESCAPE {
            escaped = true;
            continue;
        }
        let stand_in_unit = (FIRST..FIRST + COUNT).contains(&u32::from(c));
        if !escaped && stand_in_unit {
            write!(out, "\\u{:04X}", u32::from(c) - FIRST + 0xD800).expect("a string");
        } else {
            out.push(c);
        }
        escaped = false;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_round_trip_through_the_encoding() {
        let cases: [&[u16]; 6] = [
            &[],
            &[0x61, 0xD83D],
            &[0xDE00, 0xD83D],
            &[0xD83D, 0xDE00],
            &[0xD800, 0xDFFF, 0x62],
            &[0x20AC],
        ];
        for units in cases {
            assert_eq!(decode(&encode(units)), units);
        }
        // A real character that is reserved survives.
        for real in [ESCAPE, stand_in(0xD800), stand_in(0xDFFF), '\u{10F7FF}'] {
            let text: String = ['a', real, 'b'].iter().collect();
            let units: Vec<u16> = text.encode_utf16().collect();
            assert_eq!(decode(&encode(&units)), units);
            assert_eq!(decode(&escape(&text)), units);
        }
    }

    #[test]
    fn a_lone_surrogate_is_a_stand_in_and_text_without_one_is_unchanged() {
        assert_eq!(encode(&[0x61, 0xD83D]), format!("a{}", stand_in(0xD83D)));
        assert_eq!(encode(&[0x61, 0x62]), "ab");
        assert!(!is_encoded("ab😀"));
        assert!(is_encoded(&encode(&[0xDE00])));
        assert_eq!(json_text(&encode(&[0x61, 0xD83D, 0x62])), "a\\uD83Db");
        assert_eq!(json_text(&escape("\u{10F83D}")), "\u{10F83D}");
    }
}
