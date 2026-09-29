//! Tests that run a script name the shell by path.
//!
//! `sh` on `PATH` is whatever the machine puts first. A Nix `sh` is bash without `xpg_echo`,
//! so an `echo '{...\n...}'` keeps its backslash there, while the `/bin/sh` of Linux (dash) and
//! macOS expands it. A test that passed locally then failed on CI. Naming `/bin/sh` gives every
//! machine the same POSIX shell.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The lines of `source` that name the shell through `PATH`: a `"sh"` string literal outside a
/// comment.
fn path_resolved_shell_lines(source: &str) -> Vec<usize> {
    source
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim_start().starts_with("//") && line.contains("\"sh\""))
        .map(|(index, _)| index + 1)
        .collect()
}

#[test]
fn the_detector_flags_a_path_resolved_shell_and_not_a_pinned_one() {
    assert_eq!(
        path_resolved_shell_lines("Command::new(\"sh\")\n.args([\"--\", \"sh\", \"-c\"])"),
        [1, 2]
    );
    assert!(path_resolved_shell_lines("Command::new(\"/bin/sh\")").is_empty());
    assert!(path_resolved_shell_lines("// run \"sh\" here").is_empty());
}

#[test]
fn no_test_resolves_the_shell_through_path() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for entry in fs::read_dir(&crates).expect("crates directory").flatten() {
        rust_files(&entry.path().join("tests"), &mut files);
    }
    assert!(
        files.len() > 20,
        "the scan must see the test files: {}",
        files.len()
    );
    let offenders: Vec<String> = files
        .iter()
        .filter(|path| !path.ends_with("shell_pinning.rs"))
        .flat_map(|path| {
            let source = fs::read_to_string(path).expect("test source");
            path_resolved_shell_lines(&source)
                .into_iter()
                .map(|line| format!("{}:{line}", path.display()))
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "name /bin/sh instead of a PATH-resolved \"sh\":\n{}",
        offenders.join("\n")
    );
}
