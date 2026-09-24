//! Node executable selection happens before a Functions codebase is imported.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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

#[cfg(unix)]
fn write_node_wrapper(
    path: &Path,
    actual_node: &Path,
    reported_version: &str,
    disable_require_module: bool,
) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let flag = if disable_require_module {
        "--no-experimental-require-module "
    } else {
        ""
    };
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  echo '{reported_version}'\n  exit 0\nfi\nexec '{}' {flag}\"$@\"\n",
        actual_node.display()
    );
    std::fs::write(path, script).unwrap();
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).unwrap();
}

#[cfg(unix)]
#[test]
fn an_explicit_node_override_is_not_replaced_by_an_automatic_fallback() {
    let (actual_node, _) = current_node().expect("Node is required for runtime selection tests");
    let feature = Command::new(&actual_node)
        .args(["-p", "String(process.features.require_module)"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&feature.stdout).trim(),
        "true",
        "Node must support require_module for runtime selection tests"
    );

    let root = std::env::temp_dir().join(format!(
        "fireemu-runtime-explicit-override-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let source = root.join("functions");
    copy_tree(&fixture(), &source);
    let package_path = source.join("package.json");
    let mut package: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&package_path).unwrap()).unwrap();
    package["engines"]["node"] = serde_json::json!("22");
    std::fs::write(&package_path, serde_json::to_vec_pretty(&package).unwrap()).unwrap();
    let marker = source.join("loaded.marker");
    std::fs::write(
        source.join(".env"),
        format!("LOAD_MARKER={}\n", marker.display()),
    )
    .unwrap();
    let explicit_node = root.join("node-22/bin/node");
    let fallback_node = root.join("node-20/bin/node");
    write_node_wrapper(&explicit_node, &actual_node, "v22.11.0", true);
    write_node_wrapper(&fallback_node, &actual_node, "v20.19.5", false);

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
            "--eventarc-port",
            "0",
            "--tasks-port",
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
        .arg(&source)
        .args(["--", "true"])
        .env("FIREEMU_NODE", &explicit_node)
        .env("PATH", fallback_node.parent().unwrap())
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.contains("selected Node v22.11.0"), "{error}");
    assert!(error.contains("ERR_REQUIRE_ESM"), "{error}");
    assert!(!marker.exists(), "the dependency graph completed loading");
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn a_compatible_absolute_path_candidate_is_selected() {
    let (actual_node, _) = current_node().expect("Node is required for runtime selection tests");
    let root =
        std::env::temp_dir().join(format!("fireemu-runtime-fallback-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let source = root.join("functions");
    copy_tree(&fixture(), &source);
    let package_path = source.join("package.json");
    let mut package: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&package_path).unwrap()).unwrap();
    package["engines"]["node"] = serde_json::json!("20");
    std::fs::write(&package_path, serde_json::to_vec_pretty(&package).unwrap()).unwrap();
    let marker = source.join("loaded.marker");
    std::fs::write(
        source.join("index.js"),
        "require('fs').writeFileSync(process.env.LOAD_MARKER, process.version); module.exports = {};\n",
    )
    .unwrap();
    std::fs::write(
        source.join(".env"),
        format!("LOAD_MARKER={}\n", marker.display()),
    )
    .unwrap();
    let path_node = root.join("node-22/bin/node");
    let volta_home = root.join("volta");
    let compatible_node = volta_home.join("tools/image/node/20.19.5/bin/node");
    write_node_wrapper(&path_node, &actual_node, "v22.11.0", false);
    write_node_wrapper(&compatible_node, &actual_node, "v20.19.5", false);

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
            "--eventarc-port",
            "0",
            "--tasks-port",
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
        .arg(&source)
        .args(["--", "node", "--version"])
        .env("PATH", path_node.parent().unwrap())
        .env("VOLTA_HOME", volta_home)
        .stdin(Stdio::null())
        .output()
        .unwrap();

    let error = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{error}");
    assert!(error.contains("selected Node v20.19.5"), "{error}");
    let actual_version = Command::new(actual_node).arg("--version").output().unwrap();
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        String::from_utf8_lossy(&actual_version.stdout).trim()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn a_loader_capable_node_is_selected_before_user_code_is_loaded() {
    let (actual_node, _) = current_node().expect("Node is required for runtime selection tests");
    let feature = Command::new(&actual_node)
        .args(["-p", "String(process.features.require_module)"])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&feature.stdout).trim(),
        "true",
        "Node must support require_module for runtime selection tests"
    );

    let root = std::env::temp_dir().join(format!(
        "fireemu-runtime-loader-capability-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let source = root.join("functions");
    copy_tree(&fixture(), &source);
    let package_path = source.join("package.json");
    let mut package: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&package_path).unwrap()).unwrap();
    package["engines"]["node"] = serde_json::json!("22");
    std::fs::write(&package_path, serde_json::to_vec_pretty(&package).unwrap()).unwrap();
    let marker = source.join("loaded.marker");
    std::fs::write(
        source.join(".env"),
        format!("LOAD_MARKER={}\n", marker.display()),
    )
    .unwrap();

    let node_22 = root.join("node-22/bin/node");
    let volta_home = root.join("volta");
    let node_20 = volta_home.join("tools/image/node/20.19.5/bin/node");
    write_node_wrapper(&node_22, &actual_node, "v22.11.0", true);
    write_node_wrapper(&node_20, &actual_node, "v20.19.5", false);
    let path = std::env::join_paths([node_22.parent().unwrap()]).unwrap();

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
            "--eventarc-port",
            "0",
            "--tasks-port",
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
        .arg(&source)
        .args(["--", "node", "--version"])
        .env("PATH", path)
        .env("VOLTA_HOME", volta_home)
        .stdin(Stdio::null())
        .output()
        .unwrap();

    let error = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{error}");
    assert!(error.contains("selected Node v20.19.5"), "{error}");
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "loaded\n");
    std::fs::remove_dir_all(root).unwrap();
}
