//! The strict Eventarc surface against what production answered to the stage C recording (EVENTARC, 2026-10-05,
//! run `fe404dee592e` of `fireemu-oracle-idp`): the second recording of the stage B cases and the first of the
//! states stage B did not reach (a list of eleven channels in production's order, page sizes, the answers of a
//! channel while its operation runs, the edges of a channel ID, locations that exist and that do not, an operation
//! that was never issued, the exact limits of an event). See `eventarc_replay/mod.rs` for the method.

mod eventarc_replay;

use eventarc_replay::check;

const ORDER: &str = "ORDER: the order of a list of two channels or more (and so where its pages end): production's order is stable between two lists of the same channels but follows no rule the recordings reveal (not the name, the time of creation or update, the UID, nor the hashes tried), so fireemu lists in the order of creation; the rows differ in nothing else";
const PROJECT_NUMBER: &str = "the project in the path is the project number: fireemu has no project number for a project";
const TOKEN: &str = "a token Google never issued (a ya29.-prefixed string) or a real token of another scope: whether a token is valid, and what it may do, is Google's state";
const PROPAGATION: &str = "a publication to a channel whose creation finished a few seconds earlier: production answered 404 `Associated channel does not exist.` while it propagated and 200 later (the same channel answered 200 at row 306, 404 at row 307 and 200 at row 309), so the answer is not deterministic; fireemu publishes from the end of the creation";

fn known() -> Vec<(u64, &'static str)> {
    let mut rows: Vec<(u64, &'static str)> = Vec::new();
    for n in [26, 27, 28, 29, 31, 73, 130, 144, 331, 337, 127, 121, 122, 123] {
        rows.push((n, ORDER));
    }
    for n in 100..=119 {
        rows.push((n, ORDER));
    }
    for n in [35, 36] {
        rows.push((n, PROJECT_NUMBER));
    }
    for n in [322, 323, 329, 330] {
        rows.push((n, TOKEN));
    }
    for n in [182, 183, 307] {
        rows.push((n, PROPAGATION));
    }
    rows
}

#[test]
fn every_recorded_exchange_of_stage_c_is_answered_as_production_answered() {
    check("eventarc-stage-c", 424, &known());
}

const MASK: u64 = 123_456_789_012;

fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate().take(10) {
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

fn base64url(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut count = 0u32;
    let mut out = Vec::new();
    for ch in text.bytes() {
        let value = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// The project number a page token carries (a protobuf varint after the bytes `18 01 20`), when it carries one.
fn project_number_in(token: &str) -> Option<u64> {
    let bytes = base64url(token)?;
    let at = bytes.windows(3).position(|w| w == [0x18, 0x01, 0x20])?;
    varint(&bytes[at + 3..]).map(|(number, _)| number)
}

/// A page token carries the project number; no fixture may hold the number of the sandbox project, in the
/// clear or inside a token: every token of the fixtures names the mask.
#[test]
fn the_fixtures_hold_no_project_number_inside_a_page_token() {
    let mut tokens = 0;
    for fixture in ["eventarc-stage-b", "eventarc-stage-c"] {
        let text = std::fs::read_to_string(format!(
            "{}/tests/fixtures/{fixture}/rows.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .expect("the fixture exists");
        let mut rest = text.as_str();
        while let Some(at) = rest.find('C') {
            let candidate: String = rest[at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            rest = &rest[at + 1..];
            if candidate.len() < 60 {
                continue;
            }
            let Some(number) = project_number_in(&candidate) else { continue };
            assert_eq!(number, MASK, "{fixture}: a page token names a project number that is not the mask");
            tokens += 1;
        }
    }
    assert!(tokens >= 20, "the fixtures hold page tokens: {tokens}");
}

#[test]
fn the_token_check_sees_a_number_that_is_not_the_mask_and_a_token_that_has_none() {
    fn token_of(number: u64) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut inner = vec![0x18, 0x01, 0x20];
        let mut value = number;
        loop {
            let byte = u8::try_from(value & 0x7f).unwrap();
            value >>= 7;
            if value == 0 {
                inner.push(byte);
                break;
            }
            inner.push(byte | 0x80);
        }
        inner.extend_from_slice(b"*\x08channels");
        let mut bytes = vec![0x0a, u8::try_from(inner.len()).unwrap()];
        bytes.extend(inner);
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..=chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            }
        }
        out
    }
    assert_eq!(project_number_in(&token_of(MASK)), Some(MASK));
    assert_eq!(project_number_in(&token_of(111_111_111_111)), Some(111_111_111_111));
    assert_ne!(project_number_in(&token_of(111_111_111_111)), Some(MASK));
    assert_eq!(project_number_in("garbage"), None);
}
