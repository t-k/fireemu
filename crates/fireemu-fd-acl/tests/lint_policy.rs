//! Keeps this crate the workspace's only exception to `unsafe_code = "forbid"`.

use std::path::{Path, PathBuf};

const THIS_CRATE: &str = "crates/fireemu-fd-acl";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The `key = value` lines of one TOML table, without comments and blank lines.
fn table_lines<'a>(manifest: &'a str, table: &str) -> Vec<&'a str> {
    let header = format!("[{table}]");
    let mut lines = manifest.lines().map(str::trim);
    assert!(
        lines.by_ref().any(|line| line == header),
        "missing table {header}"
    );
    lines
        .take_while(|line| !line.starts_with('['))
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

fn workspace_members(manifest: &str) -> Vec<String> {
    let mut lines = manifest.lines().map(str::trim);
    assert!(lines.by_ref().any(|line| line == "members = ["));
    lines
        .take_while(|line| *line != "]")
        .map(|line| line.trim_end_matches(',').trim_matches('"').to_owned())
        .collect()
}

#[test]
fn every_other_workspace_member_inherits_the_forbidding_workspace_lints() {
    let root = workspace_root();
    let manifest = read(&root.join("Cargo.toml"));
    assert!(table_lines(&manifest, "workspace.lints.rust").contains(&"unsafe_code = \"forbid\""));

    let members = workspace_members(&manifest);
    assert!(members.iter().any(|member| member == THIS_CRATE));
    for member in members.iter().filter(|member| *member != THIS_CRATE) {
        let member_manifest = read(&root.join(member).join("Cargo.toml"));
        assert_eq!(
            table_lines(&member_manifest, "lints"),
            ["workspace = true"],
            "{member} must inherit the workspace lints"
        );
    }
}

#[test]
fn this_crate_restates_the_workspace_lints_with_unsafe_code_denied() {
    let root = workspace_root();
    let workspace = read(&root.join("Cargo.toml"));
    let own = read(&root.join(THIS_CRATE).join("Cargo.toml"));

    for (workspace_table, own_table) in [
        ("workspace.lints.rust", "lints.rust"),
        ("workspace.lints.clippy", "lints.clippy"),
    ] {
        let own_lines = table_lines(&own, own_table);
        for line in table_lines(&workspace, workspace_table) {
            let expected = if line == "unsafe_code = \"forbid\"" {
                "unsafe_code = \"deny\""
            } else {
                line
            };
            assert!(
                own_lines.contains(&expected),
                "{own_table} must contain {expected:?}"
            );
        }
    }
    let rust = table_lines(&own, "lints.rust");
    assert!(rust.contains(&"unsafe_op_in_unsafe_fn = \"deny\""));
    let clippy = table_lines(&own, "lints.clippy");
    for lint in [
        "undocumented_unsafe_blocks = \"deny\"",
        "multiple_unsafe_ops_per_block = \"deny\"",
        "missing_safety_doc = \"deny\"",
    ] {
        assert!(clippy.contains(&lint), "lints.clippy must contain {lint:?}");
    }
}

#[test]
fn unsafe_code_is_allowed_in_exactly_one_module() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut allowances = Vec::new();
    for entry in std::fs::read_dir(&source).unwrap() {
        let path = entry.unwrap().path();
        let text = read(&path);
        let count = text.matches("allow(unsafe_code)").count();
        if count > 0 {
            allowances.push((path.file_name().unwrap().to_owned(), count));
        }
    }
    assert_eq!(allowances, [("macos.rs".into(), 1)]);
}
