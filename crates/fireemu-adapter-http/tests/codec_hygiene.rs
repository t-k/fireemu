//! PCT-2. Percent escapes are decoded in one place.
//!
//! `fireemu_core_types::codec` owns what a percent escape is: two ASCII hexadecimal digits
//! and nothing else. Every hand-rolled copy this repository has had went through
//! `u8::from_str_radix`, which also accepts a leading sign, so `%+f` decoded to U+000F
//! instead of staying literal. That is a silent input-validation difference between
//! surfaces, and it has come back once already after the codecs were first consolidated, so
//! it is pinned by a test rather than by review.
//!
//! The rule: no adapter crate calls `u8::from_str_radix` or defines its own hex-nibble
//! helper. `usize::from_str_radix` is untouched, because chunked-transfer sizes are a
//! different thing parsed from hexadecimal.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Files that still hold a hand-rolled decoder, with the issue that removes each one.
///
/// Temporary. Two other lanes are editing these files as this is written, so converting them
/// here would collide; the entries come out with those lanes.
/// See `docs.local/issues/open/hand-rolled-percent-decoder-regression-in-adapters.md`.
const ALLOWED: &[&str] = &[
    "fireemu-adapter-http/src/storage.rs",
    "fireemu-adapter-grpc/src/webchannel.rs",
];

/// The markers a hand-rolled percent decoder leaves behind.
const MARKERS: &[&str] = &["u8::from_str_radix", "fn hex_nibble", "fn from_hex_digit"];

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate lives under crates/")
        .to_path_buf()
}

fn adapter_sources(root: &Path) -> Vec<PathBuf> {
    let mut sources = Vec::new();
    let mut pending: Vec<PathBuf> = std::fs::read_dir(root)
        .expect("the crates directory is readable")
        .map(|entry| entry.expect("a readable directory entry").path())
        .filter(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("fireemu-adapter-"))
        })
        .map(|path| path.join("src"))
        .filter(|path| path.is_dir())
        .collect();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("a readable source directory") {
            let path = entry.expect("a readable directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    sources
}

fn relative(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn no_adapter_crate_decodes_percent_escapes_by_hand() {
    let root = crates_dir();
    let sources = adapter_sources(&root);
    assert!(
        sources.len() > 20,
        "the scan found only {} files; the walk is broken, not the repository",
        sources.len()
    );
    let mut offenders = BTreeSet::new();
    for path in &sources {
        let text = std::fs::read_to_string(path).expect("a readable source file");
        if MARKERS.iter().any(|marker| text.contains(marker)) {
            offenders.insert(relative(path, &root));
        }
    }
    let allowed: BTreeSet<String> = ALLOWED.iter().map(|path| (*path).to_owned()).collect();
    let unexpected: Vec<&String> = offenders.difference(&allowed).collect();
    assert!(
        unexpected.is_empty(),
        "these adapter sources decode percent escapes by hand; use \
         fireemu_core_types::codec::percent_decode (or percent_decode_bytes with \
         percent_escapes_are_well_formed when a malformed escape must be refused): {unexpected:?}"
    );
    // The allowlist is temporary, so it must not outlive the files it names.
    let stale: Vec<&String> = allowed.difference(&offenders).collect();
    assert!(
        stale.is_empty(),
        "these allowlist entries no longer hold a hand-rolled decoder and should be removed \
         from ALLOWED: {stale:?}"
    );
}
