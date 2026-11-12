//! Python Functions codebases: language selection, the virtual-environment preflight, and the
//! launch details that differ from the Node runner.
//!
//! The design is `docs.local/design/python-functions-runtime-v2.md`. In short: a codebase is
//! Python when it declares `python310` to `python314`, or declares no runtime, has no
//! `package.json` and has a `requirements.txt` (firebase-tools tries the Node delegate first, then
//! Python: `src/deploy/functions/runtimes/index.ts:74-78`). The interpreter is always
//! `<source>/venv/bin/python`, the fixed `venv` directory firebase-tools uses
//! (`src/functions/python.ts:10`); fireemu never creates the environment or installs packages.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::{FunctionsCodebase, RuntimeLanguage};

/// The name of the virtual-environment directory inside the codebase source.
const VENV_DIR: &str = "venv";

/// How long the SDK probe may run before the preflight gives up.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);

/// The probe the interpreter runs: first its `major.minor`, then the SDK's version. The version
/// line comes first so that a wrong interpreter is reported as such even when the SDK is missing
/// from it.
const PROBE: &str = "import sys\n\
print('%d.%d' % sys.version_info[:2])\n\
sys.stdout.flush()\n\
import firebase_functions, functions_framework\n\
from importlib.metadata import version\n\
print(version('firebase-functions'))\n";

/// The loader a codebase uses: the declared `runtime` when there is one; otherwise `package.json`
/// means Node, a `requirements.txt` without one means Python, and anything else stays Node (so
/// the Node runner reports a codebase that is neither, as before).
#[must_use]
pub fn codebase_language(codebase: &FunctionsCodebase) -> RuntimeLanguage {
    language_of(codebase.runtime.as_deref(), Path::new(&codebase.source))
}

fn language_of(runtime: Option<&str>, source: &Path) -> RuntimeLanguage {
    if let Some(language) = runtime.and_then(crate::config::runtime_language) {
        return language;
    }
    if runtime.is_none()
        && !source.join("package.json").exists()
        && source.join("requirements.txt").exists()
    {
        RuntimeLanguage::Python
    } else {
        RuntimeLanguage::Node
    }
}

/// What the preflight learned about a codebase's virtual environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonEnvironment {
    /// `<source>/venv`.
    pub venv: PathBuf,
    /// `<source>/venv/bin/python`.
    pub interpreter: PathBuf,
    /// `major.minor` the interpreter reported.
    pub python: String,
    /// The installed `firebase-functions` version.
    pub sdk_version: String,
}

/// `python3.12` for `python312`, `python3` when the codebase declares no runtime: the command a
/// message tells the developer to run.
fn interpreter_name(runtime: Option<&str>) -> String {
    match runtime.and_then(|runtime| runtime.strip_prefix("python3")) {
        Some(minor) if !minor.is_empty() => format!("python3.{minor}"),
        _ => "python3".to_owned(),
    }
}

/// The `major.minor` a Python runtime name stands for (`python312` is `3.12`).
fn runtime_minor(runtime: &str) -> Option<String> {
    runtime
        .strip_prefix("python3")
        .filter(|minor| !minor.is_empty())
        .map(|minor| format!("3.{minor}"))
}

/// Checks the codebase's virtual environment before any runner is spawned, with firebase-tools'
/// messages where it has them (`src/deploy/functions/runtimes/python/index.ts:117-129`).
///
/// # Errors
///
/// A message naming what is missing and the command that fixes it.
pub async fn preflight(source: &Path, runtime: Option<&str>) -> Result<PythonEnvironment, String> {
    if cfg!(windows) {
        return Err(
            "Python Functions codebases are not supported on Windows; use Linux or macOS"
                .to_owned(),
        );
    }
    let venv = source.join(VENV_DIR);
    let interpreter = venv.join("bin").join("python");
    let bin = interpreter_name(runtime);
    if !interpreter.is_file() {
        return Err(format!(
            "Failed to find location of Firebase Functions SDK: Missing virtual environment at \
             venv directory. Did you forget to run '{bin} -m venv venv'?"
        ));
    }
    let mut command = tokio::process::Command::new(&interpreter);
    command
        .arg("-I")
        .arg("-B")
        .arg("-c")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(PROBE)
        .current_dir(source)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(PROBE_TIMEOUT, command.output())
        .await
        .map_err(|_| {
            format!(
                "the interpreter {} did not answer within {} seconds",
                interpreter.display(),
                PROBE_TIMEOUT.as_secs()
            )
        })?
        .map_err(|error| format!("cannot run {}: {error}", interpreter.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines();
    let python = lines.next().unwrap_or_default().trim().to_owned();
    if let Some(declared) = runtime.and_then(runtime_minor) {
        if !python.is_empty() && python != declared {
            return Err(format!(
                "the virtual environment {} runs Python {python}, but the runtime {} needs Python \
                 {declared}. Recreate it with '{bin} -m venv venv' and install the requirements \
                 again",
                venv.display(),
                runtime.unwrap_or_default()
            ));
        }
    }
    let sdk_version = lines.next().unwrap_or_default().trim().to_owned();
    if !output.status.success() || python.is_empty() || sdk_version.is_empty() {
        let detail = String::from_utf8_lossy(&output.stderr)
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .map(|line| format!(" ({})", line.trim()))
            .unwrap_or_default();
        return Err(format!(
            "Failed to find location of Firebase Functions SDK. Did you forget to run '. \"{}/bin/activate\" \
             && {bin} -m pip install -r requirements.txt'?{detail}",
            venv.display()
        ));
    }
    Ok(PythonEnvironment {
        venv,
        interpreter,
        python,
        sdk_version,
    })
}

/// The environment `. venv/bin/activate` gives firebase-tools' Python commands
/// (`src/functions/python.ts:15-22`) plus `PYTHONUNBUFFERED=1`, which its emulator sets for the
/// worker (`src/emulator/functionsEmulator.ts:1747-1748`): `VIRTUAL_ENV`, and the environment's
/// `bin` first in `PATH`.
#[must_use]
pub fn launch_environment(
    environment: &PythonEnvironment,
    parent_path: Option<&std::ffi::OsStr>,
) -> Vec<(String, String)> {
    let bin = environment.venv.join("bin");
    let mut paths = vec![bin];
    if let Some(parent) = parent_path {
        paths.extend(std::env::split_paths(parent));
    }
    let path = std::env::join_paths(paths).map_or_else(
        |_| environment.venv.join("bin").to_string_lossy().into_owned(),
        |joined| joined.to_string_lossy().into_owned(),
    );
    vec![
        (
            "VIRTUAL_ENV".to_owned(),
            environment.venv.to_string_lossy().into_owned(),
        ),
        ("PATH".to_owned(), path),
        ("PYTHONUNBUFFERED".to_owned(), "1".to_owned()),
    ]
}

/// The runner command: the environment's interpreter and the bundled runner script.
#[must_use]
pub fn runner_command(environment: &PythonEnvironment, script: &Path) -> Vec<String> {
    vec![
        environment.interpreter.to_string_lossy().into_owned(),
        script.to_string_lossy().into_owned(),
    ]
}

/// Locates the bundled Python runner, or explains every place that was tried.
///
/// # Errors
///
/// The environment override naming a missing file, or no candidate existing.
pub fn locate_runner() -> Result<PathBuf, String> {
    crate::functions::locate_runner_for(
        "FIREEMU_RUNNER_PYTHON",
        "runner-python",
        "runner.py",
        "the bundled Python runner",
    )
    .map(|script| script.path)
}

// Python Functions are Linux and macOS only, and the tests build fake interpreters from shell scripts.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::config::runtime_language;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A scratch codebase source directory, removed when dropped (also when a test panics).
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "fireemu-python-functions-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Installs `venv/bin/python` as a shell script that prints `stdout` and `stderr` and exits
    /// with `code`, whatever it is asked to run.
    fn fake_interpreter(source: &Path, stdout: &str, stderr: &str, code: i32) {
        use std::os::unix::fs::PermissionsExt;
        let bin = source.join("venv/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("stdout.txt"), stdout).unwrap();
        std::fs::write(bin.join("stderr.txt"), stderr).unwrap();
        let script = bin.join("python");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ncd \"$(dirname \"$0\")\" || exit 9\ncat stdout.txt\ncat stderr.txt >&2\nexit {code}\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[tokio::test]
    async fn preflight_disables_bytecode_writes() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = Scratch::new();
        let bin = scratch.path().join("venv/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let interpreter = bin.join("python");
        std::fs::write(&interpreter, "#!/bin/sh\ncd \"$(dirname \"$0\")\" || exit 1\nprintf '%s\\n' \"$1\" \"$2\" \"$PYTHONDONTWRITEBYTECODE\" > recorded\nprintf '3.12\\n0.6.0\\n'\n").unwrap();
        std::fs::set_permissions(&interpreter, std::fs::Permissions::from_mode(0o755)).unwrap();
        preflight(scratch.path(), None).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(bin.join("recorded")).unwrap(),
            "-I\n-B\n1\n"
        );
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        /// The config refuses the runtime by name.
        Refused,
        Node,
        PythonMissingVenv,
        PythonNoSdk,
        PythonWrongMinor,
        PythonReady,
    }

    /// The oracle, written from the memo (section 4) and firebase-tools' delegate order, not from
    /// the implementation.
    fn expected(runtime: &str, package_json: bool, requirements: bool, venv: &str) -> Outcome {
        match runtime {
            "python39" | "dart3" => Outcome::Refused,
            "nodejs20" => Outcome::Node,
            declared_or_absent => {
                let python = declared_or_absent.starts_with("python")
                    || (declared_or_absent == "absent" && !package_json && requirements);
                if !python {
                    return Outcome::Node;
                }
                match venv {
                    "none" => Outcome::PythonMissingVenv,
                    "no_sdk" => Outcome::PythonNoSdk,
                    // The fake interpreter reports 3.11: a mismatch only when 3.12 is declared.
                    "wrong_minor" if declared_or_absent == "python312" => Outcome::PythonWrongMinor,
                    _ => Outcome::PythonReady,
                }
            }
        }
    }

    fn actual(runtime: &str, package_json: bool, requirements: bool, venv: &str) -> Outcome {
        let scratch = Scratch::new();
        let source = scratch.path().to_path_buf();
        if package_json {
            std::fs::write(source.join("package.json"), "{}").unwrap();
        }
        if requirements {
            std::fs::write(source.join("requirements.txt"), "firebase-functions\n").unwrap();
        }
        match venv {
            "none" => {}
            "no_sdk" => fake_interpreter(
                &source,
                "3.12\n",
                "Traceback\nModuleNotFoundError: No module named 'firebase_functions'\n",
                1,
            ),
            "wrong_minor" => fake_interpreter(&source, "3.11\n0.6.0\n", "", 0),
            "ok" => fake_interpreter(&source, "3.12\n0.6.0\n", "", 0),
            other => panic!("unknown venv state {other}"),
        }
        let declared = (runtime != "absent").then(|| runtime.to_owned());
        if let Some(runtime) = &declared {
            if runtime_language(runtime).is_none() {
                return Outcome::Refused;
            }
        }
        let codebase = FunctionsCodebase {
            codebase: "default".to_owned(),
            source: source.to_string_lossy().into_owned(),
            runtime: declared.clone(),
            ignore: Vec::new(),
        };
        let outcome = match codebase_language(&codebase) {
            RuntimeLanguage::Node => Outcome::Node,
            RuntimeLanguage::Python => {
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(preflight(&source, declared.as_deref()));
                match result {
                    Ok(_) => Outcome::PythonReady,
                    Err(message) if message.contains("Missing virtual environment") => {
                        Outcome::PythonMissingVenv
                    }
                    Err(message) if message.contains("needs Python") => Outcome::PythonWrongMinor,
                    Err(message) if message.contains("pip install -r requirements.txt") => {
                        Outcome::PythonNoSdk
                    }
                    Err(message) => panic!("unexpected preflight error: {message}"),
                }
            }
        };
        outcome
    }

    /// Detection and preflight over the whole product of the four axes of the coverage ledger
    /// (80 rows; the PICT table is a subset).
    #[test]
    fn every_combination_of_runtime_files_and_venv_state_has_the_expected_outcome() {
        let mut checked = 0;
        for runtime in ["absent", "nodejs20", "python312", "python39", "dart3"] {
            for package_json in [true, false] {
                for requirements in [true, false] {
                    for venv in ["none", "no_sdk", "wrong_minor", "ok"] {
                        assert_eq!(
                            actual(runtime, package_json, requirements, venv),
                            expected(runtime, package_json, requirements, venv),
                            "runtime={runtime} package.json={package_json} requirements={requirements} venv={venv}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 80);
    }

    #[test]
    fn the_messages_are_firebase_tools_wording_with_the_fix_named() {
        let scratch = Scratch::new();
        let source = scratch.path().to_path_buf();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let missing = runtime
            .block_on(preflight(&source, Some("python312")))
            .unwrap_err();
        assert_eq!(
            missing,
            "Failed to find location of Firebase Functions SDK: Missing virtual environment at \
             venv directory. Did you forget to run 'python3.12 -m venv venv'?"
        );
        assert!(runtime
            .block_on(preflight(&source, None))
            .unwrap_err()
            .ends_with("'python3 -m venv venv'?"));
        fake_interpreter(
            &source,
            "3.12\n",
            "ModuleNotFoundError: No module named 'firebase_functions'\n",
            1,
        );
        let no_sdk = runtime
            .block_on(preflight(&source, Some("python312")))
            .unwrap_err();
        assert!(
            no_sdk.starts_with(
                "Failed to find location of Firebase Functions SDK. Did you forget to run '. \""
            ),
            "{no_sdk}"
        );
        assert!(
            no_sdk
                .contains("venv/bin/activate\" && python3.12 -m pip install -r requirements.txt'?"),
            "{no_sdk}"
        );
        assert!(
            no_sdk.ends_with("(ModuleNotFoundError: No module named 'firebase_functions')"),
            "{no_sdk}"
        );
        fake_interpreter(&source, "3.11\n0.6.0\n", "", 0);
        let wrong = runtime
            .block_on(preflight(&source, Some("python312")))
            .unwrap_err();
        assert!(wrong.contains("runs Python 3.11"), "{wrong}");
        assert!(wrong.contains("needs Python 3.12"), "{wrong}");
        assert!(wrong.contains("python3.12 -m venv venv"), "{wrong}");
        // A wrong minor is reported even when the SDK is missing from that interpreter.
        fake_interpreter(&source, "3.11\n", "ModuleNotFoundError: x\n", 1);
        assert!(runtime
            .block_on(preflight(&source, Some("python312")))
            .unwrap_err()
            .contains("needs Python 3.12"));
    }

    #[test]
    fn a_ready_environment_reports_the_interpreter_and_the_sdk_version() {
        let scratch = Scratch::new();
        let source = scratch.path().to_path_buf();
        fake_interpreter(&source, "3.12\n0.6.0\n", "", 0);
        let environment = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(preflight(&source, Some("python312")))
            .unwrap();
        assert_eq!(environment.python, "3.12");
        assert_eq!(environment.sdk_version, "0.6.0");
        assert_eq!(environment.venv, source.join("venv"));
        assert_eq!(environment.interpreter, source.join("venv/bin/python"));
    }

    #[test]
    fn the_command_to_run_is_named_for_the_runtime_and_python3_without_one() {
        assert_eq!(interpreter_name(Some("python312")), "python3.12");
        assert_eq!(interpreter_name(Some("python310")), "python3.10");
        assert_eq!(interpreter_name(Some("python3")), "python3");
        assert_eq!(interpreter_name(Some("nodejs20")), "python3");
        assert_eq!(interpreter_name(None), "python3");
        assert_eq!(runtime_minor("python312").as_deref(), Some("3.12"));
        assert_eq!(runtime_minor("python3"), None);
        assert_eq!(runtime_minor("nodejs20"), None);
    }

    /// An interpreter that exits 0 but says too little is a broken environment, not a ready one.
    #[test]
    fn an_environment_that_answers_incompletely_is_not_ready() {
        let scratch = Scratch::new();
        let source = scratch.path().to_path_buf();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        for (stdout, code) in [
            ("3.12\n", 0),
            ("", 0),
            ("\n0.6.0\n", 0),
            ("3.12\n0.6.0\n", 1),
        ] {
            fake_interpreter(&source, stdout, "", code);
            let error = runtime
                .block_on(preflight(&source, Some("python312")))
                .unwrap_err();
            assert!(
                error.contains("pip install -r requirements.txt"),
                "{stdout:?} {code}: {error}"
            );
        }
    }

    #[test]
    fn the_bundled_runner_is_found_in_the_workspace() {
        let path = locate_runner().unwrap();
        assert!(path.is_file(), "{}", path.display());
        assert!(
            path.ends_with("runner-python/runner.py"),
            "{}",
            path.display()
        );
    }

    #[test]
    fn the_launch_environment_is_what_activate_gives() {
        let environment = PythonEnvironment {
            venv: PathBuf::from("/code/venv"),
            interpreter: PathBuf::from("/code/venv/bin/python"),
            python: "3.12".to_owned(),
            sdk_version: "0.6.0".to_owned(),
        };
        let launch = launch_environment(&environment, Some(std::ffi::OsStr::new("/usr/bin:/bin")));
        let get = |name: &str| {
            launch
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(get("VIRTUAL_ENV"), Some("/code/venv"));
        assert_eq!(get("PATH"), Some("/code/venv/bin:/usr/bin:/bin"));
        assert_eq!(get("PYTHONUNBUFFERED"), Some("1"));
        let without_parent = launch_environment(&environment, None);
        assert!(without_parent.contains(&("PATH".to_owned(), "/code/venv/bin".to_owned())));
        assert_eq!(
            runner_command(&environment, Path::new("/r/runner.py")),
            vec![
                "/code/venv/bin/python".to_owned(),
                "/r/runner.py".to_owned()
            ]
        );
    }
}
