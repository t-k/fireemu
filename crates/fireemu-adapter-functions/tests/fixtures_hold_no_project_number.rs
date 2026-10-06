//! No committed fixture may hold the number of a sandbox project, in the clear or encoded.
//!
//! A page token, a cursor or any other opaque protobuf value that a service hands out can carry a project
//! number as a varint inside base64: the plain-digit checks of the repository (the pre-commit hook, a search)
//! do not see it. This test reads every file under `crates/` and `conformance/` (`node_modules`, `target` and
//! `.git` excluded), decodes every run of base64 or base64url characters that parses as a protobuf message,
//! and refuses a 12-digit number among its varints (a project number: timestamps are 10 digits in seconds and
//! 13 in milliseconds) unless it is the mask `123456789012` that the fixtures use.
//!
//! The scan is deliberately general: it is not limited to one fixture or to the Eventarc page token.

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

/// The 12-digit numbers that the base64 runs of `text` carry as protobuf varints.
fn project_numbers_in(text: &[u8]) -> Vec<u64> {
    let mut numbers = Vec::new();
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
                let run = &text[from..index];
                if run.len() < MIN_RUN {
                    continue;
                }
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
            _ => {}
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
                refused.push(path.display().to_string());
            }
        }
    }
    assert!(
        refused.is_empty(),
        "an encoded 12-digit number that is not the mask is in (the number is not printed): {refused:?}"
    );
    // The scan sees what it is meant to see: the Eventarc fixtures hold page tokens that name the mask.
    assert!(
        with_mask >= 1,
        "files with a token naming the mask: {with_mask}"
    );
}

fn token_of(number: u64) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
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
