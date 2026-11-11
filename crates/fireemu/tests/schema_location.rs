//! The configuration schema a project points its editor at is the one the installed binary
//! validates with: `fireemu config schema` prints the embedded bytes, `fireemu init` pins the
//! release tag of the running version, and the loader still accepts the older locations.
mod scratch;

use scratch::Scratch;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PREFIX: &str = "https://raw.githubusercontent.com/fireemu/fireemu";
const SUFFIX: &str = "spec/config/fireemu.schema.json";
const LEGACY: &str = "https://fireemu.dev/spec/config/fireemu.schema.json";

fn tagged(version: &str) -> String {
    format!("{PREFIX}/v{version}/{SUFFIX}")
}

/// The URL `init` writes: the release tag in a binary built by the release workflow
/// (`FIREEMU_RELEASE_BUILD=1` at compile time), `main` in every other build.
fn installed() -> String {
    if option_env!("FIREEMU_RELEASE_BUILD") == Some("1") {
        tagged(VERSION)
    } else {
        format!("{PREFIX}/main/{SUFFIX}")
    }
}

fn run(dir: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn repository_schema() -> Vec<u8> {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "../../spec/config/fireemu.schema.json",
    ]
    .iter()
    .collect();
    std::fs::read(path).unwrap()
}

#[test]
fn init_writes_the_schema_url_of_the_build() {
    let dir = Scratch::new("schema-location", "init");
    let output = run(&dir, &["init", "--yes"]);
    assert!(output.status.success(), "{output:?}");
    let generated = std::fs::read_to_string(dir.join("fireemu.toml")).unwrap();
    assert!(
        generated.starts_with(&format!("#:schema {}\n", installed())),
        "{generated}"
    );
    let document: serde_json::Value = toml::from_str(&generated).unwrap();
    assert_eq!(document["$schema"], installed());
    // The file it generates loads.
    let output = run(&dir, &["capabilities", "--config", "fireemu.toml"]);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn init_reference_writes_the_schema_url_of_the_build() {
    let dir = Scratch::new("schema-location", "reference");
    let output = run(&dir, &["init", "--yes", "--reference"]);
    assert!(output.status.success(), "{output:?}");
    let reference = std::fs::read_to_string(dir.join("fireemu.reference.toml")).unwrap();
    assert!(
        reference.starts_with(&format!("#:schema {}\n", installed())),
        "{reference}"
    );
}

#[test]
fn config_schema_prints_the_embedded_schema_byte_for_byte() {
    let dir = Scratch::new("schema-location", "print");
    let output = run(&dir, &["config", "schema"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, repository_schema());
    assert_eq!(
        format!("{:x}", Sha256::digest(&output.stdout)),
        format!("{:x}", Sha256::digest(repository_schema()))
    );
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn config_schema_out_writes_the_same_bytes_and_prints_nothing() {
    let dir = Scratch::new("schema-location", "out");
    let output = run(&dir, &["config", "schema", "--out", "schema.json"]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(
        std::fs::read(dir.join("schema.json")).unwrap(),
        repository_schema()
    );
    // A second run replaces the file, so the schema follows an upgrade.
    std::fs::write(dir.join("schema.json"), b"stale").unwrap();
    let output = run(&dir, &["config", "schema", "--out", "schema.json"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read(dir.join("schema.json")).unwrap(),
        repository_schema()
    );
}

#[test]
fn config_schema_out_replaces_a_file_atomically_and_keeps_its_permissions() {
    let dir = Scratch::new("schema-location", "atomic");
    let target = dir.join("schema.json");
    std::fs::write(&target, b"old").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
    }
    let output = run(&dir, &["config", "schema", "--out", "schema.json"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(&target).unwrap(), repository_schema());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
    // No temporary sibling is left behind.
    let names: Vec<_> = std::fs::read_dir(&*dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["schema.json"]);
}

/// A failed write leaves the existing file as it was and no temporary file behind.
#[cfg(unix)]
#[test]
fn config_schema_out_leaves_the_existing_file_intact_when_the_write_fails() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = Scratch::new("schema-location", "failure");
    let target = dir.join("schema.json");
    std::fs::write(&target, b"old").unwrap();
    std::fs::set_permissions(&*dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let writable = std::fs::File::create(dir.join("probe")).is_ok();
    let output = run(&dir, &["config", "schema", "--out", "schema.json"]);
    std::fs::set_permissions(&*dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    if writable {
        // Running as a user the directory mode does not bind (root): nothing to assert.
        let _ = std::fs::remove_file(dir.join("probe"));
        return;
    }
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(std::fs::read(&target).unwrap(), b"old");
    let names: Vec<_> = std::fs::read_dir(&*dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["schema.json"]);
}

/// `--out` refuses a symbolic link, as `init --force` does, and writes nothing through it:
/// a link to a file, a dangling link and a link to a directory.
#[cfg(unix)]
#[test]
fn config_schema_out_refuses_symbolic_links_without_touching_their_targets() {
    use std::os::unix::fs::symlink;
    let dir = Scratch::new("schema-location", "symlink");
    std::fs::write(dir.join("real.json"), b"precious").unwrap();
    std::fs::create_dir(dir.join("directory")).unwrap();
    symlink("real.json", dir.join("to-file.json")).unwrap();
    symlink("missing.json", dir.join("dangling.json")).unwrap();
    symlink("directory", dir.join("to-directory.json")).unwrap();
    for link in ["to-file.json", "dangling.json", "to-directory.json"] {
        let output = run(&dir, &["config", "schema", "--out", link]);
        assert!(!output.status.success(), "{link}: {output:?}");
        assert!(output.stdout.is_empty(), "{link}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("symbolic link"),
            "{link}: {output:?}"
        );
        assert!(
            std::fs::symlink_metadata(dir.join(link))
                .unwrap()
                .file_type()
                .is_symlink(),
            "{link} is still a link"
        );
    }
    assert_eq!(std::fs::read(dir.join("real.json")).unwrap(), b"precious");
    assert!(!dir.join("missing.json").exists());
    assert_eq!(std::fs::read_dir(dir.join("directory")).unwrap().count(), 0);
}

/// A directory is not a file to replace.
#[test]
fn config_schema_out_refuses_a_directory() {
    let dir = Scratch::new("schema-location", "directory");
    std::fs::create_dir(dir.join("target")).unwrap();
    let output = run(&dir, &["config", "schema", "--out", "target"]);
    assert!(!output.status.success(), "{output:?}");
    assert!(dir.join("target").is_dir());
}

#[test]
fn config_schema_refuses_bad_usage_and_unwritable_destinations() {
    let dir = Scratch::new("schema-location", "usage");
    for args in [
        &["config", "schema", "--out"][..],
        &["config", "schema", "--bogus"],
        &["config", "schema", "extra"],
        &["config", "schema", "--out", "a.json", "--out", "b.json"],
        &["config", "schema", "--out", "missing-directory/schema.json"],
        &["config", "schema", "--json"],
    ] {
        let output = run(&dir, args);
        assert!(!output.status.success(), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {output:?}");
        assert!(!output.stderr.is_empty(), "{args:?}: {output:?}");
    }
    assert!(!dir.join("a.json").exists() && !dir.join("b.json").exists());
    let output = run(&dir, &["config"]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("config schema"),
        "{output:?}"
    );
}

/// Format x URL form x command, the full product of `schema-url.pict` in the coverage ledger.
#[test]
fn the_loader_accepts_the_main_legacy_and_any_tagged_location_and_refuses_near_misses() {
    let dir = Scratch::new("schema-location", "loader");
    let accepted = [
        ("tagged-current", tagged(VERSION)),
        ("tagged-other", tagged("0.1.0")),
        ("tagged-large", tagged("12.345.6789")),
        ("main", format!("{PREFIX}/main/{SUFFIX}")),
        ("legacy", LEGACY.to_owned()),
    ];
    let refused = [
        (
            "bad-owner",
            format!("https://raw.githubusercontent.com/other/fireemu/v{VERSION}/{SUFFIX}"),
        ),
        (
            "bad-scheme",
            format!("http://raw.githubusercontent.com/fireemu/fireemu/v{VERSION}/{SUFFIX}"),
        ),
        ("bad-leading-zero", tagged("01.2.3")),
        ("bad-prerelease", tagged("1.2.3-rc.1")),
        ("bad-short", tagged("1.2")),
        ("bad-prefix", format!("{PREFIX}/1.2.3/{SUFFIX}")),
        ("bad-branch", format!("{PREFIX}/develop/{SUFFIX}")),
        ("bad-trailing-slash", format!("{}/", tagged("1.2.3"))),
        ("bad-query", format!("{}?x=1", tagged("1.2.3"))),
    ];
    for (format, extension) in [("toml", "toml"), ("json", "json")] {
        for (expected, cases) in [(true, &accepted[..]), (false, &refused[..])] {
            for (name, url) in cases {
                let path = format!("config-{name}.{extension}");
                let body = if format == "toml" {
                    format!("\"$schema\" = {url:?}\nschemaVersion = 1\n")
                } else {
                    serde_json::json!({"schemaVersion": 1, "$schema": url}).to_string()
                };
                std::fs::write(dir.join(&path), body).unwrap();
                for command in [
                    vec!["capabilities", "--config", &path],
                    vec!["config", "show", "--config", &path],
                ] {
                    let output = run(&dir, &command);
                    assert_eq!(
                        output.status.success(),
                        expected,
                        "{format} {name} {command:?}: {output:?}"
                    );
                    if !expected {
                        assert!(
                            String::from_utf8_lossy(&output.stderr).contains("$schema"),
                            "{name}: {output:?}"
                        );
                    }
                }
            }
        }
    }
}
