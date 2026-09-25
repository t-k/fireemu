//! Source hygiene for the targets the distribution claims.
//!
//! `README.md` and the npm packages promise Windows as well as Unix, so no start-up path may
//! reach for a device file that only exists on Unix. Entropy goes through the operating system
//! CSPRNG helper in `fireemu-adapter-support` instead.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the workspace root is two levels above crates/fireemu")
        .to_path_buf()
}

fn rust_sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            rust_sources(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn no_source_file_opens_the_unix_random_device() {
    let crates = workspace_root().join("crates");
    let mut sources = Vec::new();
    rust_sources(&crates, &mut sources);
    assert!(
        sources.len() > 100,
        "expected to scan the whole workspace, scanned {}",
        sources.len()
    );

    // Spelled in parts so that this scanner is not its own first offender.
    let needles = [format!("/dev/{}", "urandom"), format!("/dev/{}", "random")];
    let mut offenders = Vec::new();
    for path in sources {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        for (line_number, line) in text.lines().enumerate() {
            if needles.iter().any(|needle| line.contains(needle)) {
                offenders.push(format!("{}:{}", path.display(), line_number + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these sources still name a Unix-only random device, which makes the Windows package fail at start-up: {offenders:?}"
    );
}
