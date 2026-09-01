//! Node executable selection happens before a Functions codebase is imported.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn current_node() -> Option<(PathBuf, u32)> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join("node");
        if !candidate.is_file() {
            continue;
        }
        let program = std::fs::canonicalize(candidate).ok()?;
        let output = Command::new(&program).arg("--version").output().ok()?;
        let major = String::from_utf8_lossy(&output.stdout)
            .trim()
            .trim_start_matches('v')
            .split('.')
            .next()?
            .parse()
            .ok()?;
        return Some((program, major));
    }
    None
}

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/sdk-smoke/functions-project/fixtures/runtime-selection-cjs")
}

fn copy_tree(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn sibling_node(program: &Path, current_major: u32) -> Option<(PathBuf, u32, String)> {
    let root = program.parent()?.parent()?.parent()?;
    if root.file_name()?.to_str()? != "node" {
        return None;
    }
    for entry in std::fs::read_dir(root).ok()? {
        let candidate = entry.ok()?.path().join("bin/node");
        if !candidate.is_file() {
            continue;
        }
        let output = Command::new(&candidate).arg("--version").output().ok()?;
        let version = String::from_utf8_lossy(&output.stdout)
            .trim()
            .trim_start_matches('v')
            .to_owned();
        let major = version.split('.').next()?.parse().ok()?;
        if major != current_major {
            return Some((candidate, major, version));
        }
    }
    None
}

#[test]
fn an_unsatisfied_engine_fails_before_the_commonjs_graph_reaches_esm_only_code() {
    let Some((node, current_major)) = current_node() else {
        return;
    };
    let required_major = if current_major == 20 { 22 } else { 20 };
    let root =
        std::env::temp_dir().join(format!("fireemu-runtime-selection-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    copy_tree(&fixture(), &root);
    let package_path = root.join("package.json");
    let mut package: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&package_path).unwrap()).unwrap();
    package["engines"]["node"] = serde_json::json!(required_major.to_string());
    std::fs::write(&package_path, serde_json::to_vec_pretty(&package).unwrap()).unwrap();
    let marker = root.join("loaded.marker");

    let out = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--storage-port",
            "0",
            "--functions-port",
            "0",
            "--pubsub-port",
            "0",
            "--hub-port",
            "0",
            "--logging-port",
            "0",
            "--ui-port",
            "0",
            "--functions",
        ])
        .arg(&root)
        .args(["--", "true"])
        .env("PATH", node.parent().unwrap())
        .env("LOAD_MARKER", &marker)
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.contains("engines.node"), "{error}");
    assert!(error.contains(&format!("v{current_major}.")), "{error}");
    assert!(error.contains("FIREEMU_NODE"), "{error}");
    assert!(!marker.exists(), "the user module graph was imported");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_compatible_absolute_path_candidate_is_selected() {
    let Some((node, current_major)) = current_node() else {
        return;
    };
    let Some((compatible_node, compatible_major, compatible_version)) =
        sibling_node(&node, current_major)
    else {
        return;
    };
    let root =
        std::env::temp_dir().join(format!("fireemu-runtime-fallback-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    copy_tree(&fixture(), &root);
    let package_path = root.join("package.json");
    let mut package: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&package_path).unwrap()).unwrap();
    package["engines"]["node"] = serde_json::json!(compatible_major.to_string());
    std::fs::write(&package_path, serde_json::to_vec_pretty(&package).unwrap()).unwrap();
    let marker = root.join("loaded.marker");
    std::fs::write(
        root.join("index.js"),
        "require('fs').writeFileSync(process.env.LOAD_MARKER, process.version); module.exports = {};\n",
    )
    .unwrap();
    std::fs::write(
        root.join(".env"),
        format!("LOAD_MARKER={}\n", marker.display()),
    )
    .unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
            "--firestore-port",
            "0",
            "--http-port",
            "0",
            "--storage-port",
            "0",
            "--functions-port",
            "0",
            "--pubsub-port",
            "0",
            "--hub-port",
            "0",
            "--logging-port",
            "0",
            "--ui-port",
            "0",
            "--functions",
        ])
        .arg(&root)
        .args(["--", "node", "--version"])
        .env(
            "PATH",
            std::env::join_paths([node.parent().unwrap(), compatible_node.parent().unwrap()])
                .unwrap(),
        )
        .stdin(Stdio::null())
        .output()
        .unwrap();

    let error = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{error}");
    assert!(
        error.contains(&format!("selected Node v{compatible_version}")),
        "{error}"
    );
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        format!("v{compatible_version}")
    );
    std::fs::remove_dir_all(root).unwrap();
}
