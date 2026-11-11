//! The real Node binary for tests, never the Volta shim.
//!
//! `~/.volta/bin/node` is a launcher (`volta-shim`). When `VOLTA_HOME` or `HOME` point somewhere
//! without a Volta install (a temporary directory, an emptied `HOME`), the shim re-executes
//! itself without limit: on 2026-11-12 two tests run by cargo-mutants forked about 9,500
//! processes. A test must therefore never execute a candidate that is a shim, and must never
//! hand a shim to a child whose environment it changes. This module finds the real binary on
//! disk (the same way the Functions runner's supervisor does, without running Volta), and only
//! executes a candidate that is not a shim.
//!
//! Include it with `#[path = "../../../tests/support/real_node.rs"] mod real_node;`.

#![allow(dead_code)]

use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The environment a resolution reads, so a test can supply its own.
#[derive(Clone, Debug)]
pub struct Env {
    pub path: OsString,
    pub volta_home: Option<PathBuf>,
    pub home: Option<PathBuf>,
}

impl Env {
    pub fn from_process() -> Self {
        Self {
            path: std::env::var_os("PATH").unwrap_or_default(),
            volta_home: std::env::var_os("VOLTA_HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            home: std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
        }
    }

    fn volta_root(&self) -> Option<PathBuf> {
        self.volta_home
            .clone()
            .or_else(|| self.home.as_ref().map(|home| home.join(".volta")))
    }
}

#[derive(Clone, Debug)]
pub struct RealNode {
    pub path: PathBuf,
    pub major: u32,
}

fn executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

fn in_volta_bin(path: &Path) -> bool {
    let parent = path.parent().unwrap_or(Path::new(""));
    let mut tail = parent.components().rev();
    matches!(
        (tail.next(), tail.next()),
        (Some(Component::Normal(bin)), Some(Component::Normal(volta))) if bin == "bin" && volta == ".volta"
    )
}

/// Decides without executing anything: a file named `volta-shim` after symlinks, a file in a
/// `.volta/bin` directory, or a file in `$VOLTA_HOME/bin`.
pub fn is_volta_shim(path: &Path, env: &Env) -> bool {
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if real.file_name() == Some(OsStr::new("volta-shim")) {
        return true;
    }
    if in_volta_bin(path) || in_volta_bin(&real) {
        return true;
    }
    if let Some(home) = &env.volta_home {
        let bin = home.join("bin");
        let bin_real = std::fs::canonicalize(&bin).unwrap_or(bin.clone());
        let parent = path.parent();
        let parent_real = real.parent();
        if parent == Some(bin.as_path()) || parent_real == Some(bin_real.as_path()) {
            return true;
        }
    }
    false
}

/// The Node image Volta would run, found on disk: the pinned default first, then the newest.
fn volta_image_node(env: &Env) -> Option<PathBuf> {
    let root = env.volta_root()?;
    let images = root.join("tools/image/node");
    let mut versions: Vec<String> = Vec::new();
    if let Ok(bytes) = std::fs::read(root.join("tools/user/platform.json")) {
        if let Some(runtime) = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| value["node"]["runtime"].as_str().map(str::to_owned))
        {
            versions.push(runtime);
        }
    }
    let mut found: Vec<(Vec<u64>, String)> = std::fs::read_dir(&images)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| {
            let parts: Option<Vec<u64>> = name.split('.').map(|part| part.parse().ok()).collect();
            parts
                .filter(|parts| parts.len() == 3)
                .map(|parts| (parts, name))
        })
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0));
    versions.extend(found.into_iter().map(|(_, name)| name));
    versions
        .into_iter()
        .map(|version| images.join(version).join("bin/node"))
        .find(|binary| executable_file(binary) && !is_volta_shim(binary, env))
}

fn major_of(program: &Path) -> Result<u32, String> {
    let output = Command::new(program)
        .arg("--version")
        .output()
        .map_err(|error| format!("{} --version: {error}", program.display()))?;
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .trim_start_matches('v')
        .split('.')
        .next()
        .and_then(|major| major.parse().ok())
        .ok_or_else(|| format!("{} --version printed no version", program.display()))
}

/// Resolves the real Node from `env`. A candidate that is a shim is never executed.
pub fn resolve(env: &Env) -> Result<RealNode, String> {
    let mut shim_seen: Option<PathBuf> = None;
    for directory in std::env::split_paths(&env.path) {
        let candidate = directory.join("node");
        if !candidate.is_file() {
            continue;
        }
        if is_volta_shim(&candidate, env) {
            if let Some(image) = volta_image_node(env) {
                let path = std::fs::canonicalize(&image).unwrap_or(image);
                let major = major_of(&path)?;
                return Ok(RealNode { path, major });
            }
            shim_seen.get_or_insert(candidate);
            continue;
        }
        let resolved = Command::new(&candidate)
            .args(["-p", "process.execPath"])
            .output()
            .map_err(|error| format!("{}: {error}", candidate.display()))?;
        if !resolved.status.success() {
            return Err(format!(
                "{} -p process.execPath failed",
                candidate.display()
            ));
        }
        let program = PathBuf::from(String::from_utf8_lossy(&resolved.stdout).trim());
        let path = std::fs::canonicalize(&program)
            .map_err(|error| format!("{}: {error}", program.display()))?;
        if is_volta_shim(&path, env) || is_volta_shim(&program, env) {
            return Err(format!(
                "{} reports a Volta shim ({}) as its executable",
                candidate.display(),
                program.display()
            ));
        }
        let major = major_of(&path)?;
        return Ok(RealNode { path, major });
    }
    Err(match shim_seen {
        Some(shim) => format!(
            "the node on PATH is a Volta shim ({}) and no Node image was found under {}; \
             put the real Node directory (for example ~/.volta/tools/image/node/<version>/bin) \
             first on PATH. The shim is never run here: with an empty HOME or VOLTA_HOME it \
             respawns without limit",
            shim.display(),
            env.volta_root().map_or_else(
                || "(no VOLTA_HOME or HOME)".to_owned(),
                |root| root.display().to_string()
            )
        ),
        None => "no node on PATH".to_owned(),
    })
}

static PROCESS_NODE: OnceLock<Result<RealNode, String>> = OnceLock::new();

/// The real Node for this process, resolved once from the unmodified environment.
pub fn try_real_node() -> Result<RealNode, String> {
    PROCESS_NODE
        .get_or_init(|| resolve(&Env::from_process()))
        .clone()
}

/// Panics with a clear message when no real Node can be found.
pub fn real_node() -> RealNode {
    try_real_node().unwrap_or_else(|message| panic!("real Node is required: {message}"))
}

/// `PATH` for a child whose environment the test changes: PATH entries holding a Volta shim
/// are dropped, and the real Node's directory comes first when one is found.
pub fn child_path(env: &Env) -> OsString {
    let mut entries: Vec<PathBuf> = Vec::new();
    if let Ok(node) = resolve(env) {
        if let Some(dir) = node.path.parent() {
            entries.push(dir.to_path_buf());
        }
    }
    entries.extend(std::env::split_paths(&env.path).filter(|directory| {
        let node = directory.join("node");
        !(node.is_file() && is_volta_shim(&node, env))
    }));
    std::env::join_paths(entries).expect("a PATH entry contains the separator")
}

/// Points `command` at the real Node and away from the shim.
pub fn use_real_node(command: &mut Command) -> &mut Command {
    command.env("PATH", child_path(&Env::from_process()))
}
