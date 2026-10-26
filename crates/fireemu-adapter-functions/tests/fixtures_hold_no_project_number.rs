//! No committed fixture may hold the number of a sandbox project, in the clear or encoded.
//!
//! This test reads every file of the repository that git tracks, and the files under `crates/` and
//! `conformance/` that are not tracked or ignored yet (a recording is scanned before it is committed), and
//! decodes every run of base64 or base64url characters in two ways. A file larger than 128 MB is not skipped:
//! the test fails and names it, so that a large production-derived fixture cannot go unread.
//! A number that is not the mask `123456789012` that the fixtures use is refused in these two forms:
//! - As a protobuf varint. A page token, a cursor or any other opaque value that a service hands out can carry
//!   a project number this way. A run counts when it parses as a protobuf message (it is tried from every
//!   offset), and the varint has 12 or 13 digits, or 10 digits outside the seconds window of 2020 to 2036
//!   (the real `sourceToken` holds a timestamp's seconds). 11 digit varints are not refused here: random bytes
//!   that parse as a message produce them. A run that is a
//!   subresource integrity digest (`sha512-...`) or a lower case identifier or path (`snake_case`, `kebab-case`, `dir/file`) is not decoded as a message:
//!   random bytes parse as one now and then. No instant is exempt as a varint, so a token that holds an epoch
//!   in milliseconds as a varint would be refused.
//! - As ASCII decimal digits (a GCF v2 `sourceToken` carried the events project number this way): a whole run
//!   of 10 to 13 digits in the decoded bytes (each run is decoded from its first four characters, so that
//!   every byte alignment and a word glued to the token are covered). It is not refused when it starts with a
//!   zero, when it is inside an identifier (a letter beside it that has a letter or a digit behind it: a hex
//!   id that starts with digits), when it is an X.509 `UTCTime` (`YYMMDDHHMMSSZ`) (neither applies to digits
//!   that are a whole protobuf string field: the byte before them is their count), or when it is an instant in
//!   the context in which the corpus holds one: epoch seconds of 2020 to 2036 as the value of a JWT time claim
//!   (`"iat":`, `"exp":`, `"nbf":`, `"auth_time":`), and epoch milliseconds of the same years as the time
//!   segment of an operation name (`operation-<ms>-`). Those windows are a known blind spot for a new 10 or 13
//!   digit project number that falls inside one and sits in such a context.
//!
//! The scan is deliberately general: it is not limited to one fixture or to the Eventarc page token. It needs
//! no private list, so it runs in CI and for everyone who clones the repository, and it refuses a number of a
//! project that nobody has listed yet.
//!
//! Beside it, on the maintainers' machines and outside this repository, two checks read the exact sandbox
//! numbers from a private list: a pre-commit hook refuses a staged line that adds one in the clear, and a
//! pre-push scan looks for them in base64 tokens, as varints and as ASCII digits. They know only the listed
//! numbers; this test knows only the shape of a number. A number that this test exempts (inside an
//! identifier, an instant in its context) is left to them.

use std::path::{Path, PathBuf};

/// The number the fixtures use in place of a project number.
const MASK: u64 = 123_456_789_012;
const MIN_RUN: usize = 24;
/// A file larger than this is not scanned, and the test fails naming it.
const MAX_FILE_BYTES: u64 = 128 * 1024 * 1024;

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

/// A hit counts when the run parses as a message to its last byte. A page token does (its checksum is a
/// fixed64 field); a hash, a signature, a file name or any other run that is not a message fails that almost
/// always, because every tag has to be valid. (A tolerance of a short tail was tried on the whole repository:
/// prose and identifiers parse by chance often enough that documents, specs and tools were refused.)
fn parses_as_a_message(parsed: usize, total: usize) -> bool {
    parsed == total
}

/// Runs longer than this are decoded from their first four offsets only (a run is tried from every offset
/// otherwise: a token can follow a word with no delimiter, as in `pageToken/<token>`).
const EVERY_OFFSET_UP_TO: usize = 512;

/// 12 and 13 digits, and 10 digits outside the seconds window (the real `sourceToken` of the corpus holds the
/// seconds of a timestamp, and no corpus file holds another 10 digit varint). 11 digit varints are left to the
/// ASCII scan and the pre-push scan: random bytes that parse as a message produce them.
fn is_project_number(number: u64) -> bool {
    (100_000_000_000..10_000_000_000_000).contains(&number)
        || ((1_000_000_000..10_000_000_000).contains(&number) && !SECONDS_WINDOW.contains(&number))
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

const LONG_WORDS_FROM: usize = 32;

/// A run that is not a token: a subresource integrity digest (`sha512-` and the like, as in a lockfile) or a
/// lower case identifier or path (lower case letters, digits, `_`, `-` and `/` only: a random token of 24
/// characters has no upper case letter and no `+` once in 250,000, and a hex digest is one of these). Random
/// bytes parse as a message now and then, and across a corpus of hashes, identifiers and file names they do,
/// so these runs are not decoded as protobuf.
///
/// A long run of letters and separators with no digit and no `+` is words too (`CamelCaseNames`, a slug with
/// a repeated letter): a random token of 32 characters is one in 500.
fn is_digest_or_identifier(run: &[u8]) -> bool {
    let digest = run.strip_prefix(b"sha").is_some_and(|rest| {
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        digits > 0 && rest.get(digits) == Some(&b'-')
    });
    digest
        || run
            .iter()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'/'))
        || (run.len() >= LONG_WORDS_FROM
            && run
                .iter()
                .all(|b| b.is_ascii_alphabetic() || matches!(b, b'_' | b'-' | b'/')))
}

/// The 12-digit numbers that the base64 runs of `text` carry as protobuf varints.
fn project_numbers_in(text: &[u8]) -> Vec<u64> {
    let mut numbers = Vec::new();
    for run in base64_runs(text, MIN_RUN) {
        if is_digest_or_identifier(run) {
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
    numbers.sort_unstable();
    numbers.dedup();
    numbers
}

/// A project number is 10 to 13 digits (the sandbox numbers the hook lists are 10 to 13).
const ASCII_DIGITS: std::ops::RangeInclusive<usize> = 10..=13;
/// Ten digits take 14 base64 characters.
const MIN_ASCII_RUN: usize = 14;
/// Instants the real corpus holds as ASCII digits, and only in the contexts it holds them in: epoch seconds
/// (10 digits) as the value of a JWT time claim, and epoch milliseconds (13 digits) as the time segment of an
/// operation name (`operation-<ms>-<id>`). The windows (2020 to 2036) are a known blind spot for a new 10 or
/// 13 digit project number that falls inside one of them and sits in such a context.
const SECONDS_WINDOW: std::ops::Range<u64> = 1_600_000_000..2_100_000_000;
const MILLIS_WINDOW: std::ops::Range<u64> = 1_600_000_000_000..2_100_000_000_000;
const TIME_KEYS: [&[u8]; 4] = [b"\"iat\":", b"\"exp\":", b"\"nbf\":", b"\"auth_time\":"];

fn is_instant(before: &[u8], digits: &[u8], after: &[u8]) -> bool {
    let value = || {
        digits
            .iter()
            .fold(0u64, |acc, digit| acc * 10 + u64::from(digit - b'0'))
    };
    match digits.len() {
        10 => {
            let before = before.strip_suffix(b" ").unwrap_or(before);
            SECONDS_WINDOW.contains(&value()) && TIME_KEYS.iter().any(|key| before.ends_with(key))
        }
        13 => {
            MILLIS_WINDOW.contains(&value())
                && before.ends_with(b"operation-")
                && after.first() == Some(&b'-')
        }
        _ => false,
    }
}

/// An X.509 `UTCTime`: twelve digits `YYMMDDHHMMSS` that form a date and a time, then `Z`.
fn is_utc_time(digits: &[u8], after: &[u8]) -> bool {
    let part =
        |from: usize| u32::from(digits[from] - b'0') * 10 + u32::from(digits[from + 1] - b'0');
    digits.len() == 12
        && after.first() == Some(&b'Z')
        && (1..=12).contains(&part(2))
        && (1..=31).contains(&part(4))
        && part(6) < 24
        && part(8) < 60
        && part(10) < 60
}

/// A letter beside the digits counts as part of an identifier (a hex id that starts with digits, `65d1609...`)
/// only if that letter has another letter or digit on its far side. A letter that stands alone beside the
/// digits is a delimiter byte: the tag of the next protobuf field after a string field is one for 28 of the
/// 60 tags of fields 1 to 15, and `A`, `B`, `Z`, `a`, `b`, `z` and the like are among them.
fn inside_identifier(bytes: &[u8], at: usize, end: usize) -> bool {
    let left =
        at >= 2 && bytes[at - 1].is_ascii_alphabetic() && bytes[at - 2].is_ascii_alphanumeric();
    let right = bytes.get(end).is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(end + 1).is_some_and(u8::is_ascii_alphanumeric);
    left || right
}

/// The byte before a run of digits is their count when they are a whole protobuf string field (`0a 0c <12
/// digits>`). Then the digits are exactly that many, even if the tag of the next field is a digit (fields 6
/// and 7) and the byte after it is one too: up to two digits may follow the field. The neighbours of a whole
/// field are a tag and a length, not text, so it is never inside an identifier.
fn field_length(bytes: &[u8], at: usize, run: usize) -> Option<usize> {
    let count = usize::from(*bytes.get(at.checked_sub(1)?)?);
    (ASCII_DIGITS.contains(&count) && (count..=count + 2).contains(&run)).then_some(count)
}

/// The numbers that the base64 runs of `text` carry as ASCII decimal digits (a GCF v2 `sourceToken` held the
/// events project number this way): a whole run of 10 to 13 digits that does not start with a zero, that is
/// not inside an identifier, an `UTCTime` or an instant in the context of a time claim or an operation name.
/// The mask is returned as the mask. A run is decoded from each of its first four characters, so that every
/// byte alignment and a word glued to the front of the token (`pageToken/<token>`) is covered.
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
                let run_end = bytes[at..]
                    .iter()
                    .position(|byte| !byte.is_ascii_digit())
                    .map_or(bytes.len(), |length| at + length);
                let field = field_length(&bytes, at, run_end - at);
                let end = field.map_or(run_end, |count| at + count);
                let digits = &bytes[at..end];
                if ASCII_DIGITS.contains(&digits.len())
                    && digits[0] != b'0'
                    && (field.is_some()
                        || (!inside_identifier(&bytes, at, end)
                            && !is_utc_time(digits, &bytes[end..])))
                    && !is_instant(&bytes[..at], digits, &bytes[end..])
                {
                    numbers.push(String::from_utf8_lossy(digits).into_owned());
                }
                at = run_end;
            }
        }
    }
    numbers.sort_unstable();
    numbers.dedup();
    numbers
}

/// The files the scan reads, as git lists them from `root`: every tracked file, and the files under `crates/`
/// and `conformance/` that are not tracked and not ignored yet (a recording is scanned before it is
/// committed). Git's own ignore rules replace a list of excluded directories (`node_modules`, `target`,
/// worktrees). A tracked file that was deleted from the work tree is listed; the scan skips what it cannot read.
fn corpus_files(root: &Path) -> Vec<PathBuf> {
    let list = |args: &[&str]| {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["ls-files", "-z"])
            .args(args)
            .output()
            .expect("git runs");
        assert!(output.status.success(), "git ls-files {args:?}");
        output.stdout
    };
    let mut names = list(&["--cached"]);
    names.extend(list(&[
        "--others",
        "--exclude-standard",
        "--",
        "crates",
        "conformance",
    ]));
    let mut paths: Vec<PathBuf> = names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| root.join(String::from_utf8_lossy(name).as_ref()))
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// What the scan makes of one file: the forms in which a number that is not the mask was found, and how many
/// times each form named the mask.
#[derive(Debug, Default, PartialEq, Eq)]
struct Verdict {
    refused: Vec<&'static str>,
    varint_masks: usize,
    ascii_masks: usize,
}

fn judge(text: &[u8]) -> Verdict {
    let mut verdict = Verdict::default();
    for number in project_numbers_in(text) {
        if number == MASK {
            verdict.varint_masks += 1;
        } else {
            verdict.refused.push("varint");
        }
    }
    for number in ascii_numbers_in(text) {
        if number == MASK.to_string() {
            verdict.ascii_masks += 1;
        } else {
            verdict.refused.push("ASCII digits");
        }
    }
    verdict
}

/// What the scan makes of a set of files.
#[derive(Debug, Default, PartialEq, Eq)]
struct Corpus {
    /// `path (form)` for each number that is not the mask (the number itself is never kept).
    refused: Vec<String>,
    /// Files larger than the limit, which were not scanned.
    oversize: Vec<String>,
    varint_masks: usize,
    ascii_masks: usize,
}

/// Scans the files on a few threads (the repository holds 250 MB of fixtures, one of them 56 MB); the result
/// lists the files in the order given.
fn scan(paths: &[PathBuf], max_bytes: u64) -> Corpus {
    let threads = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(8);
    let chunk = paths.len().div_ceil(threads).max(1);
    let parts: Vec<Corpus> = std::thread::scope(|scope| {
        let workers: Vec<_> = paths
            .chunks(chunk)
            .map(|part| scope.spawn(move || scan_in_order(part, max_bytes)))
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("a scan thread"))
            .collect()
    });
    let mut corpus = Corpus::default();
    for part in parts {
        corpus.refused.extend(part.refused);
        corpus.oversize.extend(part.oversize);
        corpus.varint_masks += part.varint_masks;
        corpus.ascii_masks += part.ascii_masks;
    }
    corpus
}

fn scan_in_order(paths: &[PathBuf], max_bytes: u64) -> Corpus {
    let mut corpus = Corpus::default();
    for path in paths {
        if std::fs::metadata(path).is_ok_and(|meta| meta.len() > max_bytes) {
            corpus.oversize.push(path.display().to_string());
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let verdict = judge(&bytes);
        corpus.varint_masks += verdict.varint_masks;
        corpus.ascii_masks += verdict.ascii_masks;
        for form in verdict.refused {
            corpus.refused.push(format!("{} ({form})", path.display()));
        }
    }
    corpus
}

#[test]
fn no_tracked_file_holds_a_project_number_inside_an_encoded_value() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let all = corpus_files(&root);
    assert!(
        all.len() > 100,
        "the scan found the repository: {} files",
        all.len()
    );
    // Beyond crates/ and conformance/: a root file, a tool, a spec file, and the largest fixture.
    for needle in [
        "Cargo.toml",
        "tools/",
        "spec/",
        "conformance/fs-data-write-production-matrix.json",
        "crates/fireemu-adapter-functions/tests/fixtures_hold_no_project_number.rs",
    ] {
        assert!(
            all.iter().any(|path| path
                .strip_prefix(&root)
                .is_ok_and(|rel| rel.to_string_lossy().contains(needle))),
            "the scan lists {needle}"
        );
    }
    assert_corpus_clean(&scan(&all, MAX_FILE_BYTES));
}

/// The assertions on what the scan made of the corpus: nothing refused, and both forms saw the mask.
fn assert_corpus_clean(corpus: &Corpus) {
    assert!(
        corpus.oversize.is_empty(),
        "a file is larger than the scan limit and was not scanned: {:?}",
        corpus.oversize
    );
    assert!(
        corpus.refused.is_empty(),
        "an encoded number that is not the mask is in (the number is not printed): {:?}",
        corpus.refused
    );
    // The scan sees what it is meant to see: the Eventarc fixtures hold page tokens that name the mask.
    assert!(
        corpus.varint_masks >= 1,
        "files with a token naming the mask: {}",
        corpus.varint_masks
    );
    // So does the ASCII scan: recorded response bodies stored as base64 name the mask in the clear.
    assert!(
        corpus.ascii_masks >= 1,
        "files with base64 naming the mask in ASCII digits: {}",
        corpus.ascii_masks
    );
}

#[test]
fn a_clean_corpus_that_saw_the_mask_in_both_forms_passes() {
    assert_corpus_clean(&Corpus {
        refused: vec![],
        oversize: vec![],
        varint_masks: 1,
        ascii_masks: 1,
    });
}

#[test]
#[should_panic(expected = "an encoded number that is not the mask is in")]
fn a_corpus_with_a_refused_number_fails() {
    assert_corpus_clean(&Corpus {
        refused: vec!["a.json (ASCII digits)".to_string()],
        oversize: vec![],
        varint_masks: 1,
        ascii_masks: 1,
    });
}

#[test]
#[should_panic(expected = "files with a token naming the mask: 0")]
fn a_corpus_that_never_saw_the_mask_as_a_varint_fails() {
    assert_corpus_clean(&Corpus {
        refused: vec![],
        oversize: vec![],
        varint_masks: 0,
        ascii_masks: 1,
    });
}

#[test]
#[should_panic(expected = "files with base64 naming the mask in ASCII digits: 0")]
fn a_corpus_that_never_saw_the_mask_in_ascii_digits_fails() {
    assert_corpus_clean(&Corpus {
        refused: vec![],
        oversize: vec![],
        varint_masks: 1,
        ascii_masks: 0,
    });
}

#[test]
fn a_dirty_file_is_named_and_a_clean_or_masked_one_is_not() {
    let dir = std::env::temp_dir().join(format!("fixtures-hold-no-number-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    let write = |name: &str, text: &str| {
        let path = dir.join(name);
        std::fs::write(&path, text).expect("scratch file");
        path
    };
    let clean = write("clean.json", "{\"a\": 1}");
    let masked = write("masked.json", &token_of(MASK));
    let in_ascii = write("ascii.json", &ascii_token(0, "123456789012", true, false));
    let dirty_varint = write("varint.json", &token_of(111_111_111_111));
    let dirty_ascii = write("dirty.json", &ascii_token(1, "111111111111", false, true));
    let corpus = scan(
        &[
            clean,
            dir.join("missing.json"),
            masked,
            in_ascii,
            dirty_varint.clone(),
            dirty_ascii.clone(),
        ],
        MAX_FILE_BYTES,
    );
    std::fs::remove_dir_all(&dir).expect("remove the scratch directory");
    assert_eq!(
        corpus,
        Corpus {
            refused: vec![
                format!("{} (varint)", dirty_varint.display()),
                format!("{} (ASCII digits)", dirty_ascii.display()),
            ],
            oversize: vec![],
            varint_masks: 1,
            ascii_masks: 1,
        }
    );
}

#[test]
fn the_threaded_scan_equals_the_scan_in_order() {
    let dir = std::env::temp_dir().join(format!(
        "fixtures-hold-no-number-order-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    let mut paths = Vec::new();
    for index in 0..37 {
        let path = dir.join(format!("{index:02}.json"));
        let text = match index % 4 {
            0 => ascii_token(0, "111111111111", true, false),
            1 => token_of(MASK),
            2 => ascii_token(1, "123456789012", false, true),
            _ => "{}".to_string(),
        };
        std::fs::write(&path, text).expect("scratch file");
        paths.push(path);
    }
    let threaded = scan(&paths, MAX_FILE_BYTES);
    let in_order = scan_in_order(&paths, MAX_FILE_BYTES);
    std::fs::remove_dir_all(&dir).expect("remove the scratch directory");
    assert_eq!(threaded, in_order);
    assert_eq!(
        (
            threaded.refused.len(),
            threaded.varint_masks,
            threaded.ascii_masks
        ),
        (10, 9, 9)
    );
}

#[test]
fn a_file_over_the_limit_is_named_not_skipped_and_one_at_the_limit_is_scanned() {
    let dir = std::env::temp_dir().join(format!(
        "fixtures-hold-no-number-cap-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    let write = |name: &str, text: &str| {
        let path = dir.join(name);
        std::fs::write(&path, text).expect("scratch file");
        path
    };
    // A dirty file of exactly 64 bytes (the limit below), one of 65 bytes, and a clean small one.
    let dirty = ascii_token(0, "111111111111", true, false);
    let pad = |total: usize| format!("{dirty}{}", " ".repeat(total - dirty.len()));
    let at_limit = write("at.json", &pad(64));
    let over = write("over.json", &pad(65));
    let small = write("small.json", "{}");
    let corpus = scan(&[at_limit.clone(), over.clone(), small], 64);
    std::fs::remove_dir_all(&dir).expect("remove the scratch directory");
    assert_eq!(
        corpus,
        Corpus {
            refused: vec![format!("{} (ASCII digits)", at_limit.display())],
            oversize: vec![over.display().to_string()],
            varint_masks: 0,
            ascii_masks: 0,
        }
    );
}

#[test]
#[should_panic(
    expected = "a file is larger than the scan limit and was not scanned: [\"big.json\"]"
)]
fn a_corpus_with_an_unscanned_file_fails_and_names_it() {
    assert_corpus_clean(&Corpus {
        refused: vec![],
        oversize: vec!["big.json".to_string()],
        varint_masks: 1,
        ascii_masks: 1,
    });
}

/// A scratch git repository whose index and work tree hold the given files (nothing is committed).
fn scratch_repository(name: &str, tracked: &[&str], untracked: &[&str], ignore: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "fixtures-hold-no-number-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    let git = |args: &[&str]| {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(args)
            .stdout(std::process::Stdio::null())
            .status()
            .expect("git runs");
        assert!(status.success(), "git {args:?}");
    };
    git(&["init", "-q"]);
    std::fs::write(dir.join(".gitignore"), ignore).expect("ignore file");
    for path in tracked.iter().chain(untracked) {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().expect("a parent")).expect("directories");
        std::fs::write(file, "x").expect("file");
    }
    for path in tracked {
        git(&["add", path]);
    }
    dir
}

#[test]
fn the_listing_holds_every_tracked_file_and_the_unignored_new_files_of_crates_and_conformance_only()
{
    let dir = scratch_repository(
        "listing",
        &[
            "Cargo.toml",
            "tools/a.txt",
            "spec/b/c.json",
            "crates/x/t.rs",
            "conformance/y.json",
        ],
        &[
            "conformance/new/rec.json",
            "crates/new/rec.json",
            "tools/new.txt",
            "scratch.txt",
            "crates/ignored/skip.json",
            "node_modules/pkg/i.js",
        ],
        "crates/ignored/\nnode_modules/\n",
    );
    let mut listed: Vec<String> = corpus_files(&dir)
        .iter()
        .map(|path| {
            path.strip_prefix(&dir)
                .expect("under the root")
                .display()
                .to_string()
        })
        .collect();
    listed.sort();
    // A tracked file that was deleted from the work tree is listed too: the scan skips what it cannot read.
    std::fs::remove_file(dir.join("tools/a.txt")).expect("remove");
    let after = corpus_files(&dir).len();
    std::fs::remove_dir_all(&dir).expect("remove the scratch repository");
    assert_eq!(
        listed,
        [
            "Cargo.toml",
            "conformance/new/rec.json",
            "conformance/y.json",
            "crates/new/rec.json",
            "crates/x/t.rs",
            "spec/b/c.json",
            "tools/a.txt",
        ],
        "untracked files outside crates/ and conformance/ (tools/new.txt, scratch.txt, .gitignore) and ignored ones are not listed"
    );
    assert_eq!(after, 7, "the deleted tracked file is still listed");
}

#[test]
fn the_verdict_refuses_each_form_and_counts_the_mask_apart() {
    let ascii = |number: &str| ascii_token(0, number, true, false);
    // Neither form: nothing to refuse, nothing counted.
    assert_eq!(judge(b"{\"a\": 1}"), Verdict::default());
    // A number that is not the mask is refused in the form in which it is hidden, and only in that form.
    let other = judge(token_of(111_111_111_111).as_bytes());
    assert_eq!((other.refused, other.varint_masks), (["varint"].into(), 0));
    let other = judge(ascii("111111111111").as_bytes());
    assert_eq!(
        (other.refused, other.ascii_masks),
        (["ASCII digits"].into(), 0)
    );
    // The mask is counted in the form in which it is hidden, and only in that form, and is never refused.
    let masked = judge(token_of(MASK).as_bytes());
    assert_eq!(
        masked,
        Verdict {
            refused: vec![],
            varint_masks: 1,
            ascii_masks: 0
        }
    );
    let masked = judge(ascii("123456789012").as_bytes());
    assert_eq!(
        masked,
        Verdict {
            refused: vec![],
            varint_masks: 0,
            ascii_masks: 1
        }
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
    // 12 and 13 digits are numbers (no instant is exempt as a varint: there is no context to tell it by);
    // 10 and 11 digits and 14 digits are not.
    for number in [
        100_000_000_000,
        999_999_999_999,
        1_000_000_000_000,
        1_791_200_000_000,
        9_999_999_999_999,
    ] {
        assert_eq!(
            project_numbers_in(token_of(number).as_bytes()),
            [number],
            "{number}"
        );
    }
    for number in [
        1_791_200_000,
        99_999_999_999,
        10_000_000_000_000,
        99_999_999,
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

/// `text` as the decoded bytes of a base64 token, so that the scan sees what precedes and follows the number.
fn numbers_in_text(text: &str) -> Vec<String> {
    ascii_numbers_in(encode(text.as_bytes(), true, false).as_bytes())
}

#[test]
fn the_scan_ignores_an_instant_only_in_the_context_the_corpus_holds_it_in() {
    // Epoch seconds as the value of a JWT time claim, and epoch milliseconds as the time segment of an
    // operation name, from 2020 up to 2036; the edges of the windows.
    for (value, exempt) in [
        ("1599999999", false),
        ("1600000000", true),
        ("1791200000", true),
        ("2099999999", true),
        ("2100000000", false),
    ] {
        for key in ["iat", "exp", "nbf", "auth_time"] {
            for text in [
                format!("{{\"{key}\":{value},\"z\":1}}"),
                format!("{{\"{key}\": {value},\"z\":1}}"),
            ] {
                assert_eq!(numbers_in_text(&text).is_empty(), exempt, "{text}");
            }
        }
    }
    for (value, exempt) in [
        ("1599999999999", false),
        ("1600000000000", true),
        ("1791200000000", true),
        ("2099999999999", true),
        ("2100000000000", false),
    ] {
        let text = format!("operations/operation-{value}-65d29513a209a");
        assert_eq!(numbers_in_text(&text).is_empty(), exempt, "{text}");
    }
    // The same values anywhere else are numbers: another key, no key, a bare value, a different segment, the
    // wrong digit count for the context, a missing closing hyphen.
    for text in [
        "{\"t\":1791200000,\"z\":1}",
        "{\"iat\":[1791200000],\"z\":1}",
        "{\"iat\":\"1791200000\",\"z\":1}",
        "{\"iat\":  1791200000,\"z\":1}",
        "/1791200000/",
        "{\"exp\":1791200000000,\"z\":1}",
        "operations/operation-1791200000-65d29513a209a",
        "operations/op-1791200000000-65d29513a209a",
        "operations/operation-1791200000000/65d29513a209a",
        "operations/operation-1791200000000",
        "operations/operation-1791200000000 65d29513a209a",
    ] {
        assert_eq!(numbers_in_text(text).len(), 1, "{text}");
    }
    // 11 and 12 digits have no reading as an instant.
    for text in [
        "{\"iat\":16000000000,\"z\":1}",
        "{\"iat\":160000000000,\"z\":1}",
    ] {
        assert_eq!(numbers_in_text(text).len(), 1, "{text}");
    }
    // A whole JWT payload.
    assert!(numbers_in_text(
        r#"{"iat":1791200000,"exp":1791203600,"auth_time":1791200000,"x":"y"}"#
    )
    .is_empty());
}

#[test]
fn the_scan_ignores_an_x509_utc_time_and_nothing_that_only_looks_like_one() {
    // YYMMDDHHMMSS then Z, as in a certificate's validity (the tag and length bytes around it are not alnum).
    for text in [
        "\u{17}\r261015000000Z\u{18}\u{f}",
        "261015235959Z\u{1}",
        "260101000000Z\u{1}",
    ] {
        assert!(numbers_in_text(text).is_empty(), "{text:?}");
    }
    // Not a date, not a time, not followed by Z, or not 12 digits.
    for text in [
        "\u{17}\r261315000000Z\u{18}", // month 13
        "\u{17}\r260015000000Z\u{18}", // month 00
        "\u{17}\r261032000000Z\u{18}", // day 32
        "\u{17}\r261000000000Z\u{18}", // day 00
        "\u{17}\r261015240000Z\u{18}", // hour 24
        "\u{17}\r261015006000Z\u{18}", // minute 60
        "\u{17}\r261015000060Z\u{18}", // second 60
        "\u{17}\r261015000000Y\u{18}",
        "\u{17}\r261015000000\u{18}",
        "\u{17}\r2610150000000Z\u{18}", // 13 digits
    ] {
        assert_eq!(numbers_in_text(text).len(), 1, "{text:?}");
    }
    // Every part at its edge is still a date.
    for text in [
        "261231235959Z\u{1}",
        "260101000000Z\u{1}",
        "260228000059Z\u{1}",
    ] {
        assert!(numbers_in_text(text).is_empty(), "{text:?}");
    }
}

#[test]
fn the_scan_ignores_a_digit_run_inside_a_longer_identifier() {
    // A letter beside the digits is part of an identifier only when it has a letter or a digit on its far side.
    for text in [
        "id-65d1609123456-b91bb",
        "\"requestId\": \"8586123456789de3\"",
        "CANARY1987654321abcd",
        "q-ab407182936504/b",
        "a/407182936504zy",
        "id/ab407182936504",
        "407182936504zy/id",
        "x1a407182936504",
        "ab407182936504/x",
    ] {
        let token = encode(text.as_bytes(), true, false);
        assert!(ascii_numbers_in(token.as_bytes()).is_empty(), "{text}");
    }
    // A letter on its own beside the digits is a delimiter (a protobuf tag), at either side or at an edge.
    for text in [
        "x407182936504/b",
        "a/407182936504z",
        "z407182936504",
        "407182936504z",
        "Z407182936504A/",
    ] {
        assert_eq!(numbers_in_text(text), ["407182936504"], "{text}");
    }
    // Any delimiter, or the edge of the data, still counts.
    for (text, number) in [
        ("407182936504", "407182936504"),
        ("a/407182936504/b", "407182936504"),
        ("a-407182936504-b", "407182936504"),
        ("a 407182936504\n", "407182936504"),
        ("\"407182936504\"", "407182936504"),
        ("p=407182936504&q=1", "407182936504"),
        ("a_407182936504_b", "407182936504"),
        ("2987654321", "2987654321"),
        ("5987654321012", "5987654321012"),
    ] {
        let token = encode(text.as_bytes(), false, true);
        assert_eq!(ascii_numbers_in(token.as_bytes()), [number], "{text}");
    }
}

#[test]
fn a_number_in_a_protobuf_string_field_is_found_before_the_tag_of_any_next_field() {
    // `0a 0c <12 digits>`, then the tag of the next field (fields 1 to 15, every wire type but groups) and a
    // short payload. 28 of the 60 tags are ASCII letters (fields 8 to 15), which must not hide the number.
    let number = "407182936504";
    let mut letters = 0;
    for field in 1u8..=15 {
        for wire in [0u8, 1, 2, 5] {
            let tag = field << 3 | wire;
            let payload: &[u8] = match wire {
                0 => &[1],
                1 => &[0; 8],
                2 => &[3, 0, 0, 0],
                _ => &[0; 4],
            };
            let mut bytes = vec![0x0a, 0x0c];
            bytes.extend_from_slice(number.as_bytes());
            bytes.push(tag);
            bytes.extend_from_slice(payload);
            for (url_safe, padded) in [(false, false), (true, true)] {
                let found = ascii_numbers_in(encode(&bytes, url_safe, padded).as_bytes());
                assert_eq!(found.len(), 1, "field {field}, wire {wire}: {found:?}");
                // A tag that is a digit (fields 6 and 7) makes the run one digit longer.
                assert!(found[0].starts_with(number), "field {field}, wire {wire}");
            }
            letters += usize::from(tag.is_ascii_alphabetic());
        }
    }
    assert_eq!(letters, 28);
}

#[test]
fn the_number_in_the_committed_source_token_shape_is_found_when_it_is_not_the_mask() {
    // The shape of the issue: a recorded GCF v2 `sourceToken` that holds the number as ASCII digits. Put
    // another number in the place of the mask in the committed fixture and the scan must refuse it, in
    // either alphabet, padded or not, glued to a word or not.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = root.join("conformance/src/eventarc-production/fixtures/h-fe/h-readiness.json");
    let text = std::fs::read(path).expect("the committed fixture");
    let mut replaced = 0;
    for run in base64_runs(&text, MIN_ASCII_RUN) {
        for offset in 0..4 {
            let bytes = decode(&run[offset..]);
            let mask = MASK.to_string();
            let Some(at) = bytes
                .windows(mask.len())
                .position(|window| window == mask.as_bytes())
            else {
                continue;
            };
            let mut other = bytes.clone();
            other[at..at + mask.len()].copy_from_slice(b"407182936504");
            for (url_safe, padded) in [(false, false), (false, true), (true, false), (true, true)] {
                for glue in ["", "pageToken/"] {
                    let token = format!("{glue}{}", encode(&other, url_safe, padded));
                    assert!(
                        ascii_numbers_in(token.as_bytes()).contains(&"407182936504".to_string()),
                        "url_safe {url_safe}, padded {padded}, glue {glue:?}"
                    );
                }
            }
            replaced += 1;
        }
    }
    assert!(replaced >= 1, "the fixture names the mask in ASCII digits");
}

#[test]
fn a_digest_or_an_identifier_is_not_decoded_as_a_message_but_a_token_is() {
    for run in [
        "sha512-r1w81DpR".as_bytes(),
        b"sha1-x",
        b"sha256-",
        b"a_snake_case_identifier_9",
        b"auth-refusal-precedence-comparison-approval",
        b"tools/compat-check/src/inventory/render",
        b"zzz_aaa",
        b"changed-ccccccccccccccccccccccccccccccccPrincipal",
        b"schemasGoogleFirestoreAdminIndexConfigDelta",
        b"Words/With/Upper_And_Lower-Case_Only_Here",
        b"___",
        b"0123456789",
    ] {
        assert!(
            is_digest_or_identifier(run),
            "{}",
            String::from_utf8_lossy(run)
        );
    }
    for run in [
        "shasum-r1w81DpR".as_bytes(),
        b"sha-r1w81DpR",
        b"sha512r1w81DpR",
        b"xsha512-r1w81DpR",
        b"a_snake_Case_identifier_9",
        b"a_snake_case+identifier_9",
        b"A_SNAKE",
        b"ShortWordsOnlyHereLessThanThirt",
        b"WordsWithOneDigit1AndLongEnoughToCount",
        b"WordsWithAPlusAndLongEnough+ToCountOk",
    ] {
        assert!(
            !is_digest_or_identifier(run),
            "{}",
            String::from_utf8_lossy(run)
        );
    }
    // A token behind a digest prefix is not scanned; the same token alone, or glued to another word, is.
    let token = token_of(111_111_111_111);
    assert!(project_numbers_in(format!("sha512-{token}").as_bytes()).is_empty());
    assert_eq!(
        project_numbers_in(format!("shasum-{token}").as_bytes()),
        [111_111_111_111]
    );
    assert_eq!(project_numbers_in(token.as_bytes()), [111_111_111_111]);
}

#[test]
fn a_whole_string_field_is_found_whatever_byte_follows_its_tag() {
    // `0a 0c <12 digits>`, the tag of a next field and any byte after it: the digits are a whole string field
    // (the byte before them is their length), so a letter beside them is a tag, never part of an identifier.
    let number = "407182936504";
    let mut cases = 0;
    for field in 6u8..=15 {
        for wire in [0u8, 1, 2, 5] {
            let tag = field << 3 | wire;
            if !(tag.is_ascii_alphanumeric()) {
                continue;
            }
            for second in 0u8..=255 {
                let mut bytes = vec![0x0a, 0x0c];
                bytes.extend_from_slice(number.as_bytes());
                bytes.extend_from_slice(&[tag, second]);
                bytes.extend_from_slice(b"projects/p/locations/l/functions/f");
                for (url_safe, padded) in [(false, false), (true, true)] {
                    for glue in ["", "x", "pageToken/", "abc"] {
                        let text = format!("{glue}{}", encode(&bytes, url_safe, padded));
                        assert!(
                            !ascii_numbers_in(text.as_bytes()).is_empty(),
                            "field {field}, wire {wire}, next byte {second}, glue {glue:?}"
                        );
                    }
                }
                cases += 1;
            }
        }
    }
    assert!(cases > 5000, "{cases}");
    // The realistic case: a field-8 string of length 80 (`B`, `P`) after the number.
    let mut bytes = vec![0x0a, 0x0c];
    bytes.extend_from_slice(number.as_bytes());
    bytes.extend_from_slice(&[0x42, 80]);
    bytes.extend(std::iter::repeat_n(b'a', 80));
    assert_eq!(
        ascii_numbers_in(encode(&bytes, true, false).as_bytes()),
        [number]
    );
}

#[test]
fn the_length_byte_decides_whether_a_letter_beside_the_digits_is_a_tag() {
    // Digits that are not a whole string field stay inside an identifier when a letter with a letter or a
    // digit behind it is beside them; the same digits with their length in front are a field.
    assert!(numbers_in_text("q-ab407182936504/b").is_empty());
    assert!(numbers_in_text("q-407182936504ab/b").is_empty());
    assert_eq!(numbers_in_text("q-\u{c}407182936504ab/b"), ["407182936504"]);
    assert_eq!(numbers_in_text("q-\u{c}ab407182936504/b").len(), 0);
    // A length that is not the digit count does not make a field; one more digit (the tag of field 6 or 7 is
    // a digit) still does.
    assert!(numbers_in_text("q-\u{9}407182936504ab/b").is_empty());
    assert!(numbers_in_text("q-\u{e}407182936504ab/b").is_empty());
    assert!(numbers_in_text("q-\u{9}4071829365041ab/b").is_empty());
    assert_eq!(
        numbers_in_text("q-\u{c}4071829365041ab/b"),
        ["407182936504"]
    );
    assert_eq!(
        numbers_in_text("q-\u{c}40718293650412ab/b"),
        ["407182936504"]
    );
    assert!(numbers_in_text("q-\u{c}407182936504123ab/b").is_empty());
    // A UTCTime is not a field either: with its length in front it is a number.
    assert!(numbers_in_text("\u{17}\r261015000000Z\u{18}").is_empty());
    assert_eq!(numbers_in_text("\u{c}261015000000Z\u{18}").len(), 1);
}

#[test]
fn a_ten_digit_varint_outside_the_seconds_window_is_a_number_and_an_eleven_digit_one_is_not() {
    for number in [1_000_000_000, 1_599_999_999, 2_100_000_000, 9_999_999_999] {
        assert_eq!(
            project_numbers_in(token_of(number).as_bytes()),
            [number],
            "{number}"
        );
    }
    for number in [
        1_600_000_000,
        1_791_200_000,
        2_099_999_999,
        999_999_999,
        10_000_000_000,
    ] {
        assert!(
            project_numbers_in(token_of(number).as_bytes()).is_empty(),
            "{number}"
        );
    }
}

#[test]
fn the_scan_lists_each_number_once_in_order() {
    let first = encode(b"projects/222222222222/", true, false);
    let second = encode(b"projects/111111111111/", true, false);
    let text = format!("{first} {second} {first}");
    assert_eq!(
        ascii_numbers_in(text.as_bytes()),
        ["111111111111", "222222222222"]
    );
}

/// A protobuf message: field 1 is `number` as a varint, field 2 is `filler` bytes of `x`.
fn message_of(number: u64, filler: usize) -> Vec<u8> {
    let mut bytes = vec![0x08];
    let mut value = number;
    loop {
        let byte = u8::try_from(value & 0x7f).expect("seven bits");
        value >>= 7;
        if value == 0 {
            bytes.push(byte);
            break;
        }
        bytes.push(byte | 0x80);
    }
    bytes.push(0x12);
    let mut length = filler;
    loop {
        let byte = u8::try_from(length & 0x7f).expect("seven bits");
        length >>= 7;
        if length == 0 {
            bytes.push(byte);
            break;
        }
        bytes.push(byte | 0x80);
    }
    bytes.extend(std::iter::repeat_n(b'x', filler));
    bytes
}

#[test]
fn the_varint_scan_covers_the_shortest_run_and_a_long_run_behind_a_glued_word() {
    // The shortest run that is tried is 24 characters: 18 bytes, a 6-byte varint plus nine bytes of filler.
    let bytes = message_of(111_111_111_111, 9);
    assert_eq!(bytes.len(), 18);
    let token = encode(&bytes, true, false);
    assert_eq!(token.len(), MIN_RUN);
    assert_eq!(project_numbers_in(token.as_bytes()), [111_111_111_111]);
    // A run longer than EVERY_OFFSET_UP_TO is decoded from its first four characters only, which covers a
    // word of up to three characters glued to the front.
    let bytes = message_of(111_111_111_111, 480);
    for glue in ["", "a", "ab", "abc"] {
        let text = format!("{glue}{}", encode(&bytes, true, false));
        assert!(text.len() > EVERY_OFFSET_UP_TO, "{}", text.len());
        assert_eq!(
            project_numbers_in(text.as_bytes()),
            [111_111_111_111],
            "glue {glue:?}"
        );
    }
}

#[test]
fn the_scan_ignores_noise_and_ordinary_text() {
    assert!(ascii_numbers_in(b"").is_empty());
    assert!(ascii_numbers_in(b"407182936504").is_empty());
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

    /// A 10 to 13 digit number that is not the mask.
    fn project_like_digits() -> impl Strategy<Value = String> {
        (10usize..=13, 1u8..=9).prop_flat_map(|(len, lead)| {
            proptest::collection::vec(0u8..=9, len - 1).prop_filter_map(
                "not the mask",
                move |tail| {
                    let digits: String = std::iter::once(lead)
                        .chain(tail)
                        .map(|d| char::from(b'0' + d))
                        .collect();
                    (digits != "123456789012").then_some(digits)
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

        /// The same digits beside a letter that has a letter or a digit behind it are an identifier, never a number.
        #[test]
        fn digits_inside_an_identifier_are_not_found(
            digits in project_like_digits(),
            letter in prop::sample::select(b"abcdefABCDEFZxyz".to_vec()),
            behind in prop::sample::select(b"abcXYZ019".to_vec()),
            on_left in any::<bool>(),
            url_safe in any::<bool>(),
        ) {
            let (letter, behind) = (char::from(letter), char::from(behind));
            let text = if on_left {
                format!("id/{behind}{letter}{digits}/end")
            } else {
                format!("id/{digits}{letter}{behind}/end")
            };
            let token = encode(text.as_bytes(), url_safe, false);
            prop_assert!(ascii_numbers_in(token.as_bytes()).is_empty());
        }

        /// An instant of the window, in its context (a time claim for seconds, an operation name for
        /// milliseconds), is not a number; the same value in the other context is.
        #[test]
        fn instants_in_their_context_are_not_found(
            seconds in 1_600_000_000u64..2_100_000_000,
            sub_second in 0u64..1000,
            key in prop::sample::select(vec!["iat", "exp", "nbf", "auth_time"]),
            url_safe in any::<bool>(),
        ) {
            let millis = seconds * 1000 + sub_second;
            let claim = format!("{{\"{key}\":{seconds},\"z\":1}}");
            let name = format!("operations/operation-{millis}-65d29513a209a");
            let crossed = format!("{{\"{key}\":{millis},\"z\":1}}");
            let encoded = |text: &str| encode(text.as_bytes(), url_safe, false);
            prop_assert!(ascii_numbers_in(encoded(&claim).as_bytes()).is_empty());
            prop_assert!(ascii_numbers_in(encoded(&name).as_bytes()).is_empty());
            prop_assert_eq!(ascii_numbers_in(encoded(&crossed).as_bytes()), [millis.to_string()]);
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
