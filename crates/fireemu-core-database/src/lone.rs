//! Text that can hold a lone surrogate, where a Rust `String` cannot.
//!
//! The Realtime Database emulator profile reads the claims of an ID token as the official emulator does, and
//! Java strings hold a lone surrogate (`"\ud83d"` in a claim) where a Rust `String` cannot. The claims are an
//! ordinary document (a lone surrogate reads `?`), and a [`LoneClaims`] table says where the strings really held
//! one. For one Rules evaluation, or to write the answer of an `auth` frame, the document is turned into a view in
//! the encoding of this module: a lone surrogate unit is one of 2048 stand-in characters at the top of plane 16,
//! and every real character that is a stand-in or the escape character follows the escape character, in every
//! string of the view, so nothing collides. The view is built for the use and dropped; it is never stored, never
//! reaches an event or a log, and no other component reads the encoding.

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

use std::collections::BTreeMap;

use crate::json::Json;

/// One step of the location of a value inside a document.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    /// A member of an object, by its ordinary name.
    Key(String),
    /// An item of an array.
    Index(usize),
}

/// The strings of a document that hold a lone surrogate, which a Rust `String` cannot hold.
///
/// The claims of a token are an ordinary document in which each lone surrogate is `?` (what every other
/// component sees: events, logs). This table says, by location, which strings and which member names were
/// really UTF-16 text with a lone surrogate; only the Rules binding reads it, and turns those strings into Java
/// strings. It is empty for every document that holds none, and exists only on the emulator profile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoneClaims {
    values: BTreeMap<Vec<Step>, Vec<u16>>,
    names: BTreeMap<Vec<Step>, Vec<u16>>,
}

impl LoneClaims {
    /// Whether no string holds a lone surrogate.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty() && self.names.is_empty()
    }

    /// Records that the string at `path` is `units`.
    pub fn record_value(&mut self, path: &[Step], units: Vec<u16>) {
        self.values.insert(path.to_vec(), units);
    }

    /// Records that the member whose ordinary location is `path` (its last step the ordinary name) is named `units`.
    pub fn record_name(&mut self, path: &[Step], units: Vec<u16>) {
        self.names.insert(path.to_vec(), units);
    }

    /// The entries at or below `from`, with `from` replaced by `to` (a sub-document moved elsewhere).
    #[must_use]
    pub fn moved(&self, from: &[Step], to: &[Step]) -> Self {
        let carry = |map: &BTreeMap<Vec<Step>, Vec<u16>>| {
            map.iter()
                .filter_map(|(path, units)| {
                    path.strip_prefix(from).map(|rest| {
                        (
                            to.iter().cloned().chain(rest.iter().cloned()).collect(),
                            units.clone(),
                        )
                    })
                })
                .collect()
        };
        Self {
            values: carry(&self.values),
            names: carry(&self.names),
        }
    }

    /// The table with every location moved below `prefix`.
    #[must_use]
    pub fn below(&self, prefix: &[Step]) -> Self {
        let lift = |map: &BTreeMap<Vec<Step>, Vec<u16>>| {
            map.iter()
                .map(|(path, units)| {
                    (
                        prefix.iter().cloned().chain(path.iter().cloned()).collect(),
                        units.clone(),
                    )
                })
                .collect()
        };
        Self {
            values: lift(&self.values),
            names: lift(&self.names),
        }
    }

    /// The table with the locations of `other` added.
    pub fn merge(&mut self, other: Self) {
        self.values.extend(other.values);
        self.names.extend(other.names);
    }

    /// `json` with each of its strings and member names written in the encoding of this module: a string or name
    /// this table lists as holding a lone surrogate by [`encode`], any other by [`escape`], so that a real
    /// character the encoding reserves stays what it is. The Rules evaluator decodes it. It is built for one
    /// evaluation and never stored or shown.
    #[must_use]
    pub fn encoded_view(&self, json: &Json) -> Json {
        self.view(json, &mut Vec::new())
    }

    fn view(&self, json: &Json, path: &mut Vec<Step>) -> Json {
        match json {
            Json::String(text) => Json::String(
                self.values
                    .get(path.as_slice())
                    .map_or_else(|| escape(text), |units| encode(units)),
            ),
            Json::Object(members) => Json::Object(
                members
                    .iter()
                    .map(|(name, value)| {
                        path.push(Step::Key(name.clone()));
                        let key = self
                            .names
                            .get(path.as_slice())
                            .map_or_else(|| escape(name), |units| encode(units));
                        let value = self.view(value, path);
                        path.pop();
                        (key, value)
                    })
                    .collect(),
            ),
            Json::Array(items) => Json::Array(
                items
                    .iter()
                    .enumerate()
                    .map(|(index, value)| {
                        path.push(Step::Index(index));
                        let value = self.view(value, path);
                        path.pop();
                        value
                    })
                    .collect(),
            ),
            other => other.clone(),
        }
    }
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
    fn the_stand_ins_are_exactly_the_2048_characters_below_the_escape() {
        assert!(!is_reserved('\u{10EFFF}'));
        assert!(is_reserved('\u{10F000}'));
        assert!(is_reserved('\u{10F7FF}'));
        assert!(!is_reserved('\u{10F800}'));
        assert!(!is_reserved('\u{10FFFE}'));
        assert!(is_reserved(ESCAPE));
        assert_eq!(stand_in(0xD800), '\u{10F000}');
        assert_eq!(stand_in(0xDFFF), '\u{10F7FF}');
    }

    #[test]
    fn a_lone_surrogate_is_a_stand_in_and_text_without_one_is_unchanged() {
        assert_eq!(encode(&[0x61, 0xD83D]), format!("a{}", stand_in(0xD83D)));
        assert_eq!(encode(&[0x61, 0x62]), "ab");
        assert!(!is_encoded("ab😀"));
        assert!(is_encoded(&encode(&[0xDE00])));
        assert_eq!(json_text(&encode(&[0x61, 0xD83D, 0x62])), "a\\uD83Db");
        assert_eq!(json_text(&escape("\u{10F03D}")), "\u{10F03D}");
        // A protected stand-in stays the character; a character just above the range is not one.
        let protected = stand_in(0xD83D).to_string();
        assert_eq!(json_text(&escape(&protected)), protected);
        assert_eq!(json_text("\u{10F800}x\u{10FFFD}"), "\u{10F800}x\u{10FFFD}");
    }
    fn key(name: &str) -> Step {
        Step::Key(name.to_owned())
    }

    #[test]
    fn a_table_is_empty_only_without_values_and_without_names() {
        let mut table = LoneClaims::default();
        assert!(table.is_empty());
        table.record_value(&[key("a")], vec![0xD800]);
        assert!(!table.is_empty());
        let mut names = LoneClaims::default();
        names.record_name(&[key("a")], vec![0xD800]);
        assert!(!names.is_empty());
    }

    #[test]
    fn a_table_moves_its_locations_below_a_prefix_and_between_places() {
        let mut table = LoneClaims::default();
        table.record_value(&[key("a"), Step::Index(1)], vec![0xD800]);
        table.record_name(&[key("a"), key("n")], vec![0x61, 0xDC00]);
        table.record_value(&[key("b")], vec![0xD83D]);
        let below = table.below(&[key("t")]);
        let mut want = LoneClaims::default();
        want.record_value(&[key("t"), key("a"), Step::Index(1)], vec![0xD800]);
        want.record_name(&[key("t"), key("a"), key("n")], vec![0x61, 0xDC00]);
        want.record_value(&[key("t"), key("b")], vec![0xD83D]);
        assert_eq!(below, want);
        let moved = table.moved(&[key("a")], &[key("x"), key("y")]);
        let mut want = LoneClaims::default();
        want.record_value(&[key("x"), key("y"), Step::Index(1)], vec![0xD800]);
        want.record_name(&[key("x"), key("y"), key("n")], vec![0x61, 0xDC00]);
        assert_eq!(moved, want, "only what is at or below the source moves");
        assert!(table.moved(&[key("zzz")], &[key("x")]).is_empty());
    }

    #[test]
    fn merging_adds_the_locations_of_the_other_table() {
        let mut one = LoneClaims::default();
        one.record_value(&[key("a")], vec![0xD800]);
        let mut other = LoneClaims::default();
        other.record_name(&[key("b")], vec![0xDC00]);
        one.merge(other);
        let mut want = LoneClaims::default();
        want.record_value(&[key("a")], vec![0xD800]);
        want.record_name(&[key("b")], vec![0xDC00]);
        assert_eq!(one, want);
    }
}
