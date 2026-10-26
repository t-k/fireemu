//! No committed fixture may hold the number of a sandbox project, in the clear or encoded.
//!
//! A page token, a cursor or any other opaque protobuf value that a service hands out can carry a project
//! number as a varint inside base64: the plain-digit checks of the repository (the pre-commit hook, a search)
//! do not see it. This test reads every file under `crates/` and `conformance/` (`node_modules`, `target` and
//! `.git` excluded), decodes every run of base64 or base64url characters that parses as a protobuf message,
//! and refuses a 12-digit number among its varints (a project number: timestamps are 10 digits in seconds and
//! 13 in milliseconds) unless it is the mask `123456789012` that the fixtures use.
//!
//! The same files are also searched for a project number written as ASCII decimal digits inside base64 (a GCF
//! v2 `sourceToken` carried the events project number that way): a whole run of 10 to 13 digits in the decoded
//! bytes that is not the mask, does not start with a zero, has no letter or digit next to it and is not an
//! epoch instant of 2020 to 2036.
//!
//! The scan is deliberately general: it is not limited to one fixture or to the Eventarc page token.
//!
//! Who checks what (the first two live on the maintainers' machines, outside this repository, and read the
//! exact sandbox numbers from a private list):
//! - A pre-commit hook refuses a staged line that adds one of those numbers in the clear.
//! - A pre-push scan looks for the same exact numbers hidden in base64, as a varint and as ASCII digits. It is
//!   exact: it has no exemptions and no false positives.
//! - This test needs no private list, so it runs in CI and for everyone who clones the repository, and it
//!   refuses any number shaped like a project number, one of a project the private list does not know yet
//!   included. Its price is the exemptions above, which keep it free of false positives on the real corpus;
//!   a number that falls inside one of them (an instant-shaped one, or one hidden inside an identifier) is
//!   left to the pre-push scan.

use std::path::{Path, PathBuf};

/// The number the fixtures use in place of a project number.
const MASK: u64 = 123_456_789_012;
const MIN_RUN: usize = 24;
const MAX_FILE_BYTES: u64 = 40 * 1024 * 1024;

fn value_of(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' | b'+' => Some(62),
        b'_' | b'/' => Some(63),
        _ => None,
    }
}

/// The bytes a run of base64 (either alphabet, padding ignored) decodes to.
fn decode(run: &[u8]) -> Vec<u8> {
    let mut bits = 0u32;
    let mut count = 0u32;
    let mut out = Vec::with_capacity(run.len() * 3 / 4);
    for byte in run {
        let Some(value) = value_of(*byte) else {
            continue;
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(((bits >> count) & 0xff) as u8);
        }
    }
    out
}

fn varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for shift in 0..10 {
        let byte = *bytes.get(*at)?;
        *at += 1;
        value |= u64::from(byte & 0x7f) << (7 * shift);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// The varints that `bytes` yields as a protobuf message, best effort, and how many bytes parsed cleanly:
/// parsing stops at the first byte that does not fit, and the varints read until then are kept. Length-delimited fields are entered as sub-messages, to a depth of four.
fn varints(bytes: &[u8], depth: u32, out: &mut Vec<u64>) -> usize {
    let mut at = 0;
    while at < bytes.len() {
        let before = at;
        let Some(tag) = varint(bytes, &mut at) else {
            return before;
        };
        let (field, wire) = (tag >> 3, tag & 7);
        if field == 0 || field > 1000 {
            return before;
        }
        match wire {
            0 => {
                let Some(value) = varint(bytes, &mut at) else {
                    return before;
                };
                out.push(value);
            }
            1 => at += 8,
            5 => at += 4,
            2 => {
                let Some(length) = varint(bytes, &mut at) else {
                    return before;
                };
                let Ok(length) = usize::try_from(length) else {
                    return before;
                };
                let Some(end) = at.checked_add(length).filter(|end| *end <= bytes.len()) else {
                    return before;
                };
                if depth < 4 {
                    varints(&bytes[at..end], depth + 1, out);
                }
                at = end;
            }
            _ => return before,
        }
        if at > bytes.len() {
            return before;
        }
    }
    at
}

/// A hit counts when the run parses as a message, give or take a short tail. A page token parses to its last
/// byte (its checksum is a fixed64 field); a hash, a signature or any other random run fails that almost
/// always, because every tag has to be valid.
fn parses_as_a_message(parsed: usize, total: usize) -> bool {
    total - parsed <= 2 && parsed * 10 >= total * 9
}

/// Runs longer than this are decoded from their first four offsets only (a run is tried from every offset
/// otherwise: a token can follow a word with no delimiter, as in `pageToken/<token>`).
const EVERY_OFFSET_UP_TO: usize = 512;

fn is_project_number(number: u64) -> bool {
    (100_000_000_000..1_000_000_000_000).contains(&number)
}

/// The maximal runs of base64 or base64url characters in `text` that are at least `min_len` long.
fn base64_runs(text: &[u8], min_len: usize) -> Vec<&[u8]> {
    let mut runs = Vec::new();
    let mut start = None;
    for (index, byte) in text
        .iter()
        .copied()
        .chain(std::iter::once(b' '))
        .enumerate()
    {
        match (value_of(byte).is_some(), start) {
            (true, None) => start = Some(index),
            (false, Some(from)) => {
                start = None;
                if index - from >= min_len {
                    runs.push(&text[from..index]);
                }
            }
            _ => {}
        }
    }
    runs
}

/// The 12-digit numbers that the base64 runs of `text` carry as protobuf varints.
fn project_numbers_in(text: &[u8]) -> Vec<u64> {
    let mut numbers = Vec::new();
    for run in base64_runs(text, MIN_RUN) {
        let offsets = if run.len() <= EVERY_OFFSET_UP_TO {
            run.len() - MIN_RUN
        } else {
            3
        };
        for offset in 0..=offsets {
            let bytes = decode(&run[offset..]);
            let mut found = Vec::new();
            let parsed = varints(&bytes, 0, &mut found);
            if parses_as_a_message(parsed, bytes.len()) {
                numbers.extend(found.into_iter().filter(|n| is_project_number(*n)));
            }
        }
    }
    numbers.sort_unstable();
    numbers.dedup();
    numbers
}

/// A project number is 10 to 13 digits (the sandbox numbers the hook lists are 10 to 13).
const ASCII_DIGITS: std::ops::RangeInclusive<usize> = 10..=13;
/// Ten digits take 14 base64 characters.
const MIN_ASCII_RUN: usize = 14;
/// Fixtures hold recent instants: epoch seconds (10 digits) and milliseconds (13 digits) from 2020 up to 2036
/// are not project numbers (a JWT `iat`, the time in an operation name). Every sandbox number the hook lists
/// is outside both windows; those that are not 12 digits long would otherwise be exempted, so the exact
/// numbers stay with `scan-encoded-numbers`.
const SECONDS_WINDOW: std::ops::Range<u64> = 1_600_000_000..2_100_000_000;
const MILLIS_WINDOW: std::ops::Range<u64> = 1_600_000_000_000..2_100_000_000_000;

fn is_instant(digits: &[u8]) -> bool {
    let Some(value) = std::str::from_utf8(digits)
        .ok()
        .and_then(|text| text.parse::<u64>().ok())
    else {
        return false;
    };
    match digits.len() {
        10 => SECONDS_WINDOW.contains(&value),
        13 => MILLIS_WINDOW.contains(&value),
        _ => false,
    }
}

/// The numbers that the base64 runs of `text` carry as ASCII decimal digits (a GCF v2 `sourceToken` held the
/// events project number this way): a whole run of 10 to 13 digits, with no letter or digit next to it (a hex
/// id that starts with digits and an X.509 `UTCTime` such as `261015000000Z` are not numbers), that is not an
/// instant, and does not start with a zero. The mask is returned as the mask. A run is decoded from each of
/// its first four characters, so that every byte alignment and a word glued to the front of the token (`pageToken/<token>`) is covered.
fn ascii_numbers_in(text: &[u8]) -> Vec<String> {
    let mut numbers = Vec::new();
    for run in base64_runs(text, MIN_ASCII_RUN) {
        for offset in 0..4 {
            let bytes = decode(&run[offset..]);
            let mut at = 0;
            while at < bytes.len() {
                if !bytes[at].is_ascii_digit() {
                    at += 1;
                    continue;
                }
                let end = bytes[at..]
                    .iter()
                    .position(|byte| !byte.is_ascii_digit())
                    .map_or(bytes.len(), |length| at + length);
                let digits = &bytes[at..end];
                let flanked = (at > 0 && bytes[at - 1].is_ascii_alphanumeric())
                    || bytes.get(end).is_some_and(u8::is_ascii_alphanumeric);
                if ASCII_DIGITS.contains(&digits.len())
                    && digits[0] != b'0'
                    && !flanked
                    && !is_instant(digits)
                {
                    numbers.push(String::from_utf8_lossy(digits).into_owned());
                }
                at = end;
            }
        }
    }
    numbers.sort_unstable();
    numbers.dedup();
    numbers
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if matches!(name.as_ref(), "node_modules" | "target" | ".git") {
            continue;
        }
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            files(&path, out);
        } else if kind.is_file() && entry.metadata().is_ok_and(|m| m.len() <= MAX_FILE_BYTES) {
            out.push(path);
        }
    }
}

#[test]
fn no_file_under_crates_or_conformance_holds_a_project_number_inside_an_encoded_value() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut all = Vec::new();
    for top in ["crates", "conformance"] {
        files(&root.join(top), &mut all);
    }
    assert!(
        all.len() > 100,
        "the scan found the repository: {} files",
        all.len()
    );
    let mut with_mask = 0;
    let mut refused = Vec::new();
    for path in &all {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        for number in project_numbers_in(&bytes) {
            if number == MASK {
                with_mask += 1;
            } else {
                refused.push(format!("{} (varint)", path.display()));
            }
        }
        for number in ascii_numbers_in(&bytes) {
            if number == MASK.to_string() {
                with_mask += 1;
            } else {
                refused.push(format!("{} (ASCII digits)", path.display()));
            }
        }
    }
    assert!(
        refused.is_empty(),
        "an encoded number that is not the mask is in (the number is not printed): {refused:?}"
    );
    // The scan sees what it is meant to see: the Eventarc fixtures hold page tokens that name the mask.
    assert!(
        with_mask >= 1,
        "files with a token naming the mask: {with_mask}"
    );
}

/// Base64 of `bytes` in the standard or the URL-safe alphabet, with or without padding.
fn encode(bytes: &[u8], url_safe: bool, padded: bool) -> String {
    let alphabet: &[u8; 64] = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(alphabet[((n >> (18 - 6 * i)) & 63) as usize]));
        }
        if padded {
            out.extend(std::iter::repeat_n('=', 3 - chunk.len()));
        }
    }
    out
}

fn token_of(number: u64) -> String {
    let mut inner = vec![0x18, 0x01, 0x20];
    let mut value = number;
    loop {
        let byte = u8::try_from(value & 0x7f).expect("seven bits");
        value >>= 7;
        if value == 0 {
            inner.push(byte);
            break;
        }
        inner.push(byte | 0x80);
    }
    inner.extend_from_slice(b"*\x08channels");
    let mut bytes = vec![0x0a, u8::try_from(inner.len()).expect("a short message")];
    bytes.extend(inner);
    // A checksum as a fixed64 field, as the page tokens have it.
    bytes.extend_from_slice(&[0x21, 1, 2, 3, 4, 5, 6, 7, 8]);
    encode(&bytes, true, false)
}

#[test]
fn the_scan_sees_a_number_inside_a_token_in_any_context_and_ignores_what_is_not_one() {
    // A number that is not the mask, alone, in JSON, in a URL, standard or URL-safe alphabet.
    let other = token_of(111_111_111_111);
    assert_eq!(project_numbers_in(other.as_bytes()), [111_111_111_111]);
    assert_eq!(
        project_numbers_in(format!("\"nextPageToken\": \"{other}\"").as_bytes()),
        [111_111_111_111]
    );
    assert_eq!(
        project_numbers_in(format!("?pageToken={other}&x=1").as_bytes()),
        [111_111_111_111]
    );
    let standard = other.replace('-', "+").replace('_', "/");
    assert_eq!(project_numbers_in(standard.as_bytes()), [111_111_111_111]);
    // The mask is found as the mask.
    assert_eq!(project_numbers_in(token_of(MASK).as_bytes()), [MASK]);
    // A timestamp (10 digits in seconds, 13 in milliseconds), a short number, words and a hash are not numbers.
    for number in [
        1_791_200_000,
        1_791_200_000_000,
        99_999_999_999,
        1_000_000_000_000,
    ] {
        assert!(
            project_numbers_in(token_of(number).as_bytes()).is_empty(),
            "{number}"
        );
    }
    // A word with no delimiter before the token, and a hash, are handled.
    assert_eq!(
        project_numbers_in(format!("pageToken/{other}").as_bytes()),
        [111_111_111_111]
    );
    assert!(project_numbers_in(b"sha512-r1w81DpR+KyRWd3f+rk6TNqMgedmAxZP5v5KWlXQWlgMUUtyEJch0DKEci1SorPMiSeM8XPl7MZ3miJ60JIpQg==").is_empty());
    assert!(
        project_numbers_in(b"just some words and spaces of ordinary text, nothing encoded")
            .is_empty()
    );
    assert!(project_numbers_in(b"d41d8cd98f00b204e9800998ecf8427e").is_empty());
    assert!(project_numbers_in(b"").is_empty());
}

/// A synthetic number (never a real project number) written as ASCII digits inside a message, then encoded.
const SYNTHETIC: &str = "111111111111";

/// `lead` bytes of 0xfb first: they shift the alignment of what follows by 0, 1 or 2 bytes, and they make the
/// standard and the URL-safe alphabets differ (`+`, `/` against `-`, `_`) in the encoded text.
fn ascii_token(lead: usize, middle: &str, url_safe: bool, padded: bool) -> String {
    let mut bytes = vec![0xfb; 4 + lead];
    bytes.extend_from_slice(format!("{{\"name\":\"projects/{middle}/locations/x\"}}").as_bytes());
    encode(&bytes, url_safe, padded)
}

#[test]
fn the_scan_sees_ascii_digits_inside_base64_at_every_alignment_alphabet_and_padding() {
    for lead in 0..3 {
        for url_safe in [false, true] {
            for padded in [false, true] {
                let token = ascii_token(lead, SYNTHETIC, url_safe, padded);
                let marker = if url_safe { ['-', '_'] } else { ['+', '/'] };
                assert!(token.contains(marker), "{token}");
                let context = format!("lead {lead}, url_safe {url_safe}, padded {padded}");
                assert_eq!(ascii_numbers_in(token.as_bytes()), [SYNTHETIC], "{context}");
                // In JSON, in a URL, and after a word with no delimiter, at any phase of the run.
                for glue in ["", "a", "ab", "abc", "pageToken/"] {
                    assert_eq!(
                        ascii_numbers_in(format!("\"v\": \"{glue}{token}\"").as_bytes()),
                        [SYNTHETIC],
                        "{context}, glue {glue:?}"
                    );
                }
                assert_eq!(
                    ascii_numbers_in(format!("?t={token}&x=1").as_bytes()),
                    [SYNTHETIC],
                    "{context}"
                );
            }
        }
    }
}

#[test]
fn the_scan_counts_a_digit_run_of_ten_to_thirteen_digits() {
    for (digits, found) in [
        ("987654321", false),
        ("2987654321", true),
        ("39876543210", true),
        ("498765432101", true),
        ("5987654321012", true),
        ("69876543210123", false),
        ("798765432101234", false),
        // No project number starts with a zero (the fixtures hold `0123456789` as a made-up value).
        ("0123456789", false),
        ("0123456789012", false),
        ("0000000000", false),
        ("1234567890", true),
    ] {
        let token = ascii_token(0, digits, true, false);
        let expected: Vec<String> = found.then(|| digits.to_string()).into_iter().collect();
        assert_eq!(ascii_numbers_in(token.as_bytes()), expected, "{digits}");
    }
}

#[test]
fn the_scan_finds_the_mask_as_the_mask() {
    let token = ascii_token(1, "123456789012", true, true);
    assert_eq!(ascii_numbers_in(token.as_bytes()), ["123456789012"]);
}

#[test]
fn the_scan_ignores_timestamps_inside_their_window_and_finds_them_just_outside() {
    // 10 digits as epoch seconds and 13 as epoch milliseconds, from 2020 up to 2036 (fixtures hold recent
    // instants: a JWT iat and exp, the time in an operation name).
    for (value, found) in [
        ("1599999999", true),
        ("1600000000", false),
        ("1791200000", false),
        ("2099999999", false),
        ("2100000000", true),
        ("1599999999999", true),
        ("1600000000000", false),
        ("1791200000000", false),
        ("2099999999999", false),
        ("2100000000000", true),
        // 11 and 12 digits have no reading as an instant of that window.
        ("16000000000", true),
        ("160000000000", true),
    ] {
        let token = ascii_token(0, value, true, false);
        assert_eq!(
            !ascii_numbers_in(token.as_bytes()).is_empty(),
            found,
            "{value}"
        );
    }
    let jwt_payload = encode(
        br#"{"iat":1791200000,"exp":1791203600,"auth_time":1791200000}"#,
        true,
        false,
    );
    assert!(ascii_numbers_in(jwt_payload.as_bytes()).is_empty());
}

#[test]
fn the_scan_ignores_a_digit_run_inside_a_longer_identifier() {
    // A hex id that starts with digits, an X.509 UTCTime (YYMMDDHHMMSSZ), and a word that ends in digits.
    for text in [
        "id-65d1609123456-b91bb",
        "\"requestId\": \"8586123456789de3\"",
        "validity 261015000000Z end",
        "CANARY0123456789abcd",
    ] {
        let token = encode(text.as_bytes(), true, false);
        assert!(ascii_numbers_in(token.as_bytes()).is_empty(), "{text}");
    }
    // Any delimiter, or the edge of the data, still counts.
    for text in [
        "592603257417",
        "a/592603257417/b",
        "a-592603257417-b",
        "a 592603257417\n",
        "\"592603257417\"",
        "p=592603257417&q=1",
        "a_592603257417_b",
    ] {
        let token = encode(text.as_bytes(), false, true);
        let expected = ["592603257417"];
        assert_eq!(ascii_numbers_in(token.as_bytes()), expected, "{text}");
    }
}

#[test]
fn the_scan_ignores_noise_and_ordinary_text() {
    assert!(ascii_numbers_in(b"").is_empty());
    assert!(ascii_numbers_in(b"592603257417").is_empty());
    assert!(
        ascii_numbers_in(b"just some words and spaces of ordinary text, nothing encoded")
            .is_empty()
    );
    assert!(ascii_numbers_in(b"d41d8cd98f00b204e9800998ecf8427e").is_empty());
    assert!(ascii_numbers_in(b"sha512-r1w81DpR+KyRWd3f+rk6TNqMgedmAxZP5v5KWlXQWlgMUUtyEJch0DKEci1SorPMiSeM8XPl7MZ3miJ60JIpQg==").is_empty());
}

mod properties {
    use super::*;
    use proptest::prelude::*;

    /// A 10 to 13 digit number that is not the mask and is not an instant in the timestamp window.
    fn project_like_digits() -> impl Strategy<Value = String> {
        (10usize..=13, 1u8..=9).prop_flat_map(|(len, lead)| {
            proptest::collection::vec(0u8..=9, len - 1).prop_filter_map(
                "not an instant, not the mask",
                move |tail| {
                    let digits: String = std::iter::once(lead)
                        .chain(tail)
                        .map(|d| char::from(b'0' + d))
                        .collect();
                    let value: u64 = digits.parse().expect("digits");
                    let instant = (len == 10 && (1_600_000_000..2_100_000_000).contains(&value))
                        || (len == 13 && (1_600_000_000_000..2_100_000_000_000).contains(&value));
                    (!instant && digits != "123456789012").then_some(digits)
                },
            )
        })
    }

    proptest! {
        /// Random digits, hidden as ASCII at a random offset of a random message, in either alphabet, padded
        /// or not, after a glued word of any length: always found.
        #[test]
        fn digits_hidden_at_any_offset_are_found(
            digits in project_like_digits(),
            head in proptest::collection::vec(any::<u8>(), 0..24),
            tail in proptest::collection::vec(any::<u8>(), 0..24),
            before in prop::sample::select(vec![b'/', b' ', b'"', b'=', b':', b'-']),
            after in prop::sample::select(vec![b'/', b' ', b'"', b'&', b',', b'\n']),
            url_safe in any::<bool>(),
            padded in any::<bool>(),
            glue in "[A-Za-z0-9]{0,3}",
        ) {
            let mut bytes = head;
            bytes.push(before);
            bytes.extend_from_slice(digits.as_bytes());
            bytes.push(after);
            bytes.extend(tail);
            let text = format!("\"{glue}{}\"", encode(&bytes, url_safe, padded));
            prop_assert!(ascii_numbers_in(text.as_bytes()).contains(&digits));
        }

        /// The same digits flanked by a letter or digit on either side are an identifier, never a number.
        #[test]
        fn digits_inside_an_identifier_are_not_found(
            digits in project_like_digits(),
            letter in prop::sample::select(b"abcdefABCDEFZxyz".to_vec()),
            on_left in any::<bool>(),
            url_safe in any::<bool>(),
        ) {
            let text = if on_left {
                format!("id/{}{digits}/end", char::from(letter))
            } else {
                format!("id/{digits}{}/end", char::from(letter))
            };
            let token = encode(text.as_bytes(), url_safe, false);
            prop_assert!(ascii_numbers_in(token.as_bytes()).is_empty());
        }

        /// An instant of the window, as seconds or milliseconds, is not a number.
        #[test]
        fn instants_in_the_window_are_not_found(
            seconds in 1_600_000_000u64..2_100_000_000,
            millis in any::<bool>(),
            url_safe in any::<bool>(),
        ) {
            let text = if millis {
                format!("{{\"t\":{}}}", seconds * 1000 + 999)
            } else {
                format!("{{\"t\":{seconds}}}")
            };
            let token = encode(text.as_bytes(), url_safe, false);
            prop_assert!(ascii_numbers_in(token.as_bytes()).is_empty());
        }

        /// Binary noise that holds no digit run is never a number (the test is not a lottery).
        #[test]
        fn noise_without_digits_is_not_found(
            bytes in proptest::collection::vec(any::<u8>().prop_filter("no digit", |b| !b.is_ascii_digit()), 0..200),
            url_safe in any::<bool>(),
        ) {
            prop_assert!(ascii_numbers_in(encode(&bytes, url_safe, false).as_bytes()).is_empty());
        }
    }
}
