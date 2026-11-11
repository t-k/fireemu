//! The test helper that finds Node never executes a Volta shim and never returns one.
//!
//! The shim respawns itself without limit when `VOLTA_HOME` or `HOME` point at a directory
//! without a Volta install (2026-11-12: about 9,500 processes). Every fake shim below writes a
//! marker file when it is executed, so a resolution that runs it fails the test.

#![cfg(unix)]

#[path = "../../../tests/support/real_node.rs"]
mod real_node;

use proptest::prelude::*;
use real_node::{child_path, is_volta_shim, resolve, Env};
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fireemu-real-node-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn script(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A node that answers `--version` and `-p process.execPath` like a real one.
fn fake_real_node(path: &Path) {
    script(
        path,
        "if [ \"$1\" = \"--version\" ]; then echo v22.1.0; else echo \"$0\"; fi",
    );
}

/// `<root>/.volta/bin/node`, which records that it was executed.
fn fake_shim(root: &Path) -> (PathBuf, PathBuf) {
    let marker = root.join("shim-was-executed");
    let shim = root.join(".volta/bin/node");
    script(
        &shim,
        &format!("echo ran >> '{}'\nexit 99", marker.display()),
    );
    (shim.parent().unwrap().to_path_buf(), marker)
}

fn env(path: &[&Path], volta_home: Option<&Path>, home: Option<&Path>) -> Env {
    Env {
        path: std::env::join_paths(path).unwrap(),
        volta_home: volta_home.map(Path::to_path_buf),
        home: home.map(Path::to_path_buf),
    }
}

#[test]
fn the_real_node_for_this_process_is_not_the_volta_shim() {
    let node = real_node::real_node();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    assert!(
        node.path.is_absolute() && node.path.is_file(),
        "{:?}",
        node.path
    );
    assert_ne!(node.path.file_name(), Some("volta-shim".as_ref()));
    if let Some(home) = home {
        assert!(
            !node.path.starts_with(home.join(".volta/bin")),
            "{:?}",
            node.path
        );
    }
    assert!(
        !node
            .path
            .components()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| { pair[0].as_os_str() == ".volta" && pair[1].as_os_str() == "bin" }),
        "{:?}",
        node.path
    );
    assert!(
        !is_volta_shim(&node.path, &Env::from_process()),
        "{:?}",
        node.path
    );
}

#[test]
fn a_shim_without_a_volta_install_is_refused_and_never_executed() {
    let root = Scratch::new("no-install");
    let (shim_dir, marker) = fake_shim(&root.0);
    let empty_home = root.0.join("empty-home");
    std::fs::create_dir_all(&empty_home).unwrap();
    let env = env(
        &[&shim_dir],
        Some(&empty_home.join("volta")),
        Some(&empty_home),
    );
    let message = resolve(&env).expect_err("a bare shim must be refused");
    assert!(message.contains("Volta shim"), "{message}");
    assert!(!marker.exists(), "the shim was executed");
}

#[test]
fn a_shim_with_a_volta_image_resolves_to_the_image_without_running_the_shim() {
    let root = Scratch::new("image");
    let (shim_dir, marker) = fake_shim(&root.0);
    let volta = root.0.join("volta");
    for version in ["20.1.0", "22.1.0"] {
        fake_real_node(&volta.join(format!("tools/image/node/{version}/bin/node")));
    }
    std::fs::create_dir_all(volta.join("tools/user")).unwrap();
    std::fs::write(
        volta.join("tools/user/platform.json"),
        r#"{"node":{"runtime":"20.1.0"}}"#,
    )
    .unwrap();
    let env = env(&[&shim_dir], Some(&volta), None);
    let node = resolve(&env).unwrap();
    assert!(
        node.path.ends_with("tools/image/node/20.1.0/bin/node"),
        "{:?}",
        node.path
    );
    assert!(!marker.exists(), "the shim was executed");
}

#[test]
fn without_a_pinned_default_the_newest_numbered_image_is_used() {
    let root = Scratch::new("newest");
    let (shim_dir, marker) = fake_shim(&root.0);
    let volta = root.0.join("volta");
    for version in ["9.0.0", "20.1.0", "22.10.0", "22.9.9", "latest", "99.1"] {
        fake_real_node(&volta.join(format!("tools/image/node/{version}/bin/node")));
    }
    let node = resolve(&env(&[&shim_dir], Some(&volta), None)).unwrap();
    assert!(
        node.path.ends_with("tools/image/node/22.10.0/bin/node"),
        "{:?}",
        node.path
    );
    assert!(!marker.exists(), "the shim was executed");
}

#[test]
fn an_image_directory_that_is_itself_a_shim_is_not_used() {
    let root = Scratch::new("image-shim");
    let (shim_dir, marker) = fake_shim(&root.0);
    let volta = root.0.join("volta");
    std::os::unix::fs::symlink(shim_dir.join("node"), {
        std::fs::create_dir_all(volta.join("tools/image/node/9.9.9/bin")).unwrap();
        volta.join("tools/image/node/9.9.9/bin/node")
    })
    .unwrap();
    let env = env(&[&shim_dir], Some(&volta), None);
    resolve(&env).expect_err("an image that is a shim must be refused");
    assert!(!marker.exists(), "the shim was executed");
}

#[test]
fn a_real_node_after_a_shim_on_path_is_used() {
    let root = Scratch::new("shim-then-real");
    let (shim_dir, marker) = fake_shim(&root.0);
    let real = root.0.join("real/bin/node");
    fake_real_node(&real);
    let env = env(&[&shim_dir, real.parent().unwrap()], None, None);
    let node = resolve(&env).unwrap();
    assert_eq!(node.path, std::fs::canonicalize(&real).unwrap());
    assert_eq!(node.major, 22);
    assert!(!marker.exists(), "the shim was executed");
}

#[test]
fn a_node_that_reports_a_shim_as_its_executable_is_refused() {
    let root = Scratch::new("reports-shim");
    let (shim_dir, marker) = fake_shim(&root.0);
    let liar = root.0.join("liar/bin/node");
    script(
        &liar,
        &format!("echo '{}'", shim_dir.join("node").display()),
    );
    let env = env(&[liar.parent().unwrap()], None, None);
    let message = resolve(&env).expect_err("a reported shim must be refused");
    assert!(message.contains("Volta shim"), "{message}");
    assert!(!marker.exists(), "the shim was executed");
}

#[test]
fn a_shim_under_volta_home_bin_is_recognised_even_when_it_is_not_in_a_dot_volta_directory() {
    let root = Scratch::new("volta-home-bin");
    let shim = root.0.join("custom-volta/bin/node");
    script(&shim, "exit 99");
    let env = env(
        &[shim.parent().unwrap()],
        Some(&root.0.join("custom-volta")),
        None,
    );
    assert!(is_volta_shim(&shim, &env));
    assert!(!is_volta_shim(
        &shim,
        &Env {
            volta_home: None,
            ..env.clone()
        }
    ));
}

#[test]
fn a_symlink_to_volta_shim_is_recognised_by_name() {
    let root = Scratch::new("symlink");
    let target = root.0.join("store/volta-shim");
    script(&target, "exit 99");
    let link = root.0.join("bin/node");
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(is_volta_shim(&link, &env(&[], None, None)));
}

#[test]
fn child_path_drops_a_shim_directory_and_puts_the_real_node_first() {
    let root = Scratch::new("child-path");
    let (shim_dir, marker) = fake_shim(&root.0);
    let real = root.0.join("real/bin/node");
    fake_real_node(&real);
    let other = root.0.join("other");
    std::fs::create_dir_all(&other).unwrap();
    let env = env(&[&shim_dir, &other, real.parent().unwrap()], None, None);
    let entries: Vec<PathBuf> = std::env::split_paths(&child_path(&env)).collect();
    assert_eq!(
        entries[0],
        std::fs::canonicalize(real.parent().unwrap()).unwrap()
    );
    assert!(!entries.contains(&shim_dir), "{entries:?}");
    assert!(entries.contains(&other), "{entries:?}");
    assert!(!marker.exists(), "the shim was executed");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Whatever the layout, a resolution never runs the shim, never answers with one, and
    /// succeeds exactly when a real Node or a usable Volta image is reachable.
    #[test]
    fn resolution_never_executes_or_returns_a_shim(
        shim_first in any::<bool>(),
        real_on_path in any::<bool>(),
        image_installed in any::<bool>(),
        use_volta_home in any::<bool>(),
        use_home in any::<bool>(),
        shim_in_volta_home_bin in any::<bool>(),
    ) {
        let root = Scratch::new("prop");
        let volta = root.0.join("home/.volta");
        let (shim_dir, marker) = if shim_in_volta_home_bin {
            let shim = volta.join("bin/node");
            let marker = root.0.join("shim-was-executed");
            script(&shim, &format!("echo ran >> '{}'\nexit 99", marker.display()));
            (volta.join("bin"), marker)
        } else {
            fake_shim(&root.0)
        };
        let real = root.0.join("real/bin/node");
        fake_real_node(&real);
        if image_installed {
            fake_real_node(&volta.join("tools/image/node/22.1.0/bin/node"));
        }
        let mut path: Vec<&Path> = Vec::new();
        if shim_first {
            path.push(&shim_dir);
        }
        if real_on_path {
            path.push(real.parent().unwrap());
        }
        if !shim_first {
            path.push(&shim_dir);
        }
        let home = root.0.join("home");
        let env = env(
            &path,
            use_volta_home.then_some(volta.as_path()),
            use_home.then_some(home.as_path()),
        );
        let image_visible = image_installed && (use_volta_home || use_home);
        // A shim is only replaced by an image when it precedes any real node on PATH.
        let outcome = resolve(&env);
        prop_assert!(!marker.exists(), "the shim was executed");
        match outcome {
            Ok(node) => {
                prop_assert!(!is_volta_shim(&node.path, &env), "{:?}", node.path);
                prop_assert!(
                    !node.path.components().any(|part| part.as_os_str() == ".volta")
                        || node.path.starts_with(
                        std::fs::canonicalize(&root.0).unwrap().join("home/.volta/tools/image")
                    ),
                    "{:?}",
                    node.path
                );
                prop_assert!(real_on_path || image_visible);
            }
            Err(message) => {
                prop_assert!(!real_on_path && !image_visible, "{message}");
            }
        }
        let child: OsString = child_path(&env);
        for directory in std::env::split_paths(&child) {
            let node = directory.join("node");
            prop_assert!(!(node.is_file() && is_volta_shim(&node, &env)), "{directory:?}");
        }
        prop_assert!(!marker.exists(), "the shim was executed");
    }
}
