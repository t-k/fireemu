//! `fireemu doctor`: what this particular binary actually ships.
//!
//! A release is a binary plus the things that have to travel with it -- the compiled-in
//! Emulator UI, the Node runner that hosts a Functions codebase, and the versioned catalogs
//! the gateway validates against. Each of those can be absent in a way that only shows up much
//! later, so `doctor` inspects the installed artifact rather than the source tree it was built
//! from, names what it found, and says what to do about anything it did not.
//!
//! Output is plain `label: value` lines followed by a remediation block. Nothing it prints is
//! a secret: versions, catalog identifiers and file paths only -- never tokens, keys or the
//! contents of a configuration file.

use std::fmt::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::functions::{locate_runner, runner_candidates};

/// The outcome of one check.
enum Status {
    /// The thing is present and usable.
    Ok,
    /// The thing is absent but optional; `String` says what that costs.
    Absent(String),
    /// The thing is absent or broken and something the user asked for will not work.
    Problem(String),
}

/// One reported line plus its remediation, if any.
struct Check {
    label: &'static str,
    value: String,
    status: Status,
}

impl Check {
    fn ok(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
            status: Status::Ok,
        }
    }

    fn absent(label: &'static str, value: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
            status: Status::Absent(remedy.into()),
        }
    }

    fn problem(label: &'static str, value: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
            status: Status::Problem(remedy.into()),
        }
    }
}

/// `node --version`, or `None` when Node is not on `PATH` (or does not answer).
fn node_version() -> Option<String> {
    let out = Command::new("node")
        .arg("--version")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let version = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (!version.is_empty()).then_some(version)
}

/// The `firebase-functions` majors the located runner instruments, read out of the runner
/// itself so the answer describes the shipped file rather than a constant compiled in beside
/// it. The declaration is a single line, `const SUPPORTED_MAJORS = [6, 7];`.
fn runner_supported_majors(index: &Path) -> Option<String> {
    let source = std::fs::read_to_string(index.parent()?.join("callable-app-check.mjs")).ok()?;
    let line = source
        .lines()
        .find(|l| l.trim_start().starts_with("const SUPPORTED_MAJORS"))?;
    let list = line.split_once('[')?.1.split_once(']')?.0;
    let majors: Vec<String> = list
        .split(',')
        .map(str::trim)
        .filter(|m| !m.is_empty() && m.chars().all(|c| c.is_ascii_digit()))
        .map(str::to_owned)
        .collect();
    (!majors.is_empty()).then(|| majors.join(", "))
}

/// The Emulator UI check: a binary built without `ui/dist` serves a placeholder page.
fn ui_check() -> Check {
    if fireemu_adapter_ui::assets::bundled() {
        Check::ok("ui bundle", "bundled")
    } else {
        Check::absent(
            "ui bundle",
            "not bundled (placeholder page)",
            "this binary was compiled without the single-page app. A release build embeds it; \
             from a source tree run `pnpm -C ui install && pnpm -C ui build` and rebuild",
        )
    }
}

/// The Node runner check, and the `firebase-functions` range it can instrument.
fn runner_checks() -> Vec<Check> {
    match locate_runner() {
        Ok(script) => {
            let path = script.path.display().to_string();
            let mut checks = vec![Check::ok(
                "functions runner",
                format!("{path} ({})", script.source.describe()),
            )];
            checks.push(match runner_supported_majors(&script.path) {
                Some(majors) => Check::ok("firebase-functions support", format!("majors {majors}")),
                None => Check::problem(
                    "firebase-functions support",
                    "unknown",
                    "the runner beside this binary does not declare SUPPORTED_MAJORS; its \
                     callable-app-check.mjs is missing or truncated. Reinstall the platform \
                     package",
                ),
            });
            checks
        }
        Err(e) => vec![
            Check::problem(
                "functions runner",
                "not found",
                format!(
                    "{e}. Functions (`--functions <dir>`) cannot start without it; every other \
                     service works"
                ),
            ),
            Check::absent(
                "firebase-functions support",
                "unknown (no runner)",
                format!(
                    "looked in: {}",
                    runner_candidates()
                        .iter()
                        .map(|(_, p)| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ),
        ],
    }
}

/// Everything `doctor` reports, in the order it prints it.
fn checks() -> Vec<Check> {
    let mut checks = vec![
        Check::ok("fireemu", env!("CARGO_PKG_VERSION")),
        Check::ok("target", target()),
        Check::ok(
            "vendored googleapis commit",
            fireemu_proto_firestore::UPSTREAM_COMMIT.trim(),
        ),
        Check::ok(
            "limit catalogs",
            fireemu_core_limits::catalogs::ALL_CATALOGS
                .iter()
                .map(|c| c.meta.id)
                .collect::<Vec<_>>()
                .join(", "),
        ),
        ui_check(),
    ];
    checks.extend(runner_checks());
    checks.push(match node_version() {
        Some(version) => Check::ok("node", version),
        None => Check::absent(
            "node",
            "not found on PATH",
            "Node is needed only to run a Functions codebase; install Node 20 or newer if you \
             use `--functions`",
        ),
    });
    // Said explicitly because the Firebase Emulator Suite does need a JVM, and the first
    // question about a drop-in replacement is whether this one does too.
    checks.push(Check::ok(
        "java",
        "not required (fireemu runs no JVM emulator)",
    ));
    checks
}

/// The platform this binary was built for, spelled the way the npm platform packages are
/// (`darwin-arm64`, `linux-x64`, ...), so a report from a mis-installed package is obvious at
/// a glance.
fn target() -> String {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "windows" => "win32",
        other => other,
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    format!("{os}-{arch}")
}

/// Renders the report. Returns the text and whether any check reported a problem.
fn report() -> (String, bool) {
    let checks = checks();
    let width = checks.iter().map(|c| c.label.len()).max().unwrap_or(0);
    let mut out = String::new();
    for check in &checks {
        let mark = match check.status {
            Status::Ok => "ok",
            Status::Absent(_) => "--",
            Status::Problem(_) => "!!",
        };
        let _ = writeln!(out, "{mark} {:width$}  {}", check.label, check.value);
    }
    let remedies: Vec<(&str, &str)> = checks
        .iter()
        .filter_map(|c| match &c.status {
            Status::Ok => None,
            Status::Absent(r) | Status::Problem(r) => Some((c.label, r.as_str())),
        })
        .collect();
    if !remedies.is_empty() {
        out.push('\n');
        for (label, remedy) in &remedies {
            let _ = writeln!(out, "{label}: {remedy}");
        }
    }
    let problem = checks
        .iter()
        .any(|c| matches!(c.status, Status::Problem(_)));
    (out, problem)
}

/// Prints the report. The exit status is success unless a check found something broken rather
/// than merely optional and absent, so `doctor` can gate an install in a script.
pub fn run() -> std::process::ExitCode {
    let (text, problem) = report();
    print!("{text}");
    if problem {
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::{report, runner_supported_majors};

    /// The report always names the binary, the UI bundle, the runner and the runtimes a user
    /// has to provide, whichever of them this build happens to carry.
    #[test]
    fn the_report_covers_every_shipped_component() {
        let (text, _) = report();
        for label in [
            "fireemu",
            "target",
            "limit catalogs",
            "ui bundle",
            "functions runner",
            "firebase-functions support",
            "node",
            "java",
        ] {
            assert!(text.contains(label), "{label} is missing from:\n{text}");
        }
        assert!(
            text.contains("not required"),
            "doctor says Java is not needed:\n{text}"
        );
    }

    /// The supported range is read out of the runner that will actually be spawned, so a
    /// package shipping an older runner reports the older range.
    #[test]
    fn the_supported_range_is_read_from_the_runner_beside_the_index() {
        let dir = std::env::temp_dir().join(format!("fireemu-doctor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let index = dir.join("index.mjs");
        std::fs::write(&index, "// runner\n").expect("write index");
        assert_eq!(runner_supported_majors(&index), None);
        std::fs::write(
            dir.join("callable-app-check.mjs"),
            "// header\nconst SUPPORTED_MAJORS = [4, 5];\n",
        )
        .expect("write instrumentation");
        assert_eq!(
            runner_supported_majors(&index).as_deref(),
            Some("4, 5"),
            "the declared majors are reported verbatim"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
