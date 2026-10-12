//! `fireemu --help`, `fireemu <command> --help` and `fireemu help [command]`.
//!
//! The option tables below are the one description of the daemon options. The help text is
//! rendered from them, and the tests in this module check them against `parse_raw_options`
//! (every flag the parser accepts is described, and every described flag is accepted), so the
//! help cannot drift from the parser without a test failing.

use std::fmt::Write as _;

/// How an option takes its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// A switch.
    None,
    /// The next argument is the value, whatever it looks like.
    Required(&'static str),
    /// The next argument is the value unless it starts with `-`.
    Optional(&'static str),
}

/// One command-line option.
pub struct OptionSpec {
    /// Every spelling, the long one last.
    pub flags: &'static [&'static str],
    /// The value it takes.
    pub value: Value,
    /// Accepted by `exec` only.
    pub exec_only: bool,
    /// One-line explanation including the default.
    pub text: &'static str,
}

const fn opt(flags: &'static [&'static str], value: Value, text: &'static str) -> OptionSpec {
    OptionSpec {
        flags,
        value,
        exec_only: false,
        text,
    }
}

/// The options of `up` and `exec` (and, parsed the same way, `capabilities`).
pub const DAEMON_OPTIONS: &[OptionSpec] = &[
    opt(
        &["--config"],
        Value::Required("<file>"),
        "Configuration file: a fireemu.json (schemaVersion 1) or a firebase.json. Default: none, the built-in defaults.",
    ),
    opt(
        &["--firebase-json"],
        Value::Required("<file>"),
        "Read ports, rules, indexes and Functions codebases from this firebase.json. Takes precedence over one referenced by --config. Default: none; firebase.json is not searched for.",
    ),
    opt(
        &["-P", "--project"],
        Value::Required("<id|alias>"),
        "Project ID, or an alias from the .firebaserc next to the firebase.json (else the current directory). Default: the .firebaserc default, else daemon.authProject from --config, else demo-app.",
    ),
    opt(
        &["--only"],
        Value::Required("<list>"),
        "Comma-separated services to start: auth, firestore, storage, functions (or functions:<codebase>), eventarc, tasks, pubsub, appcheck. Default: Firestore, Auth, Storage and App Check; Functions when a codebase is configured (firebase.json or --functions), and with it Eventarc and Cloud Tasks; Pub/Sub when configured (emulators.pubsub, daemon.pubsubPort or --pubsub-port).",
    ),
    opt(
        &["--firestore-port"],
        Value::Required("<n>"),
        "Firestore port. Default: 8080 (0 picks a free port).",
    ),
    opt(
        &["--http-port"],
        Value::Required("<n>"),
        "Auth (Identity Toolkit) port. Default: 9099 (0 picks a free port).",
    ),
    opt(
        &["--storage-port"],
        Value::Required("<n>"),
        "Storage port. Default: 9199 (0 picks a free port).",
    ),
    opt(
        &["--functions-port"],
        Value::Required("<n>"),
        "Functions port, used when a codebase is loaded. Default: 5001 (0 picks a free port).",
    ),
    opt(
        &["--eventarc-port"],
        Value::Required("<n>"),
        "Eventarc port. Eventarc starts exactly when a Functions backend is loaded; this option only sets the port. Default: 9299.",
    ),
    opt(
        &["--tasks-port"],
        Value::Required("<n>"),
        "Cloud Tasks port. Cloud Tasks starts exactly when a Functions backend is loaded; this option only sets the port. Default: 9499.",
    ),
    opt(
        &["--pubsub-port"],
        Value::Required("<n>"),
        "Pub/Sub port; giving it also enables Pub/Sub, which otherwise starts only when configured or named by --only. Default: 8085.",
    ),
    opt(
        &["--functions"],
        Value::Required("<dir>"),
        "Load exactly one Functions codebase from this directory, whatever firebase.json declares. Default: the codebases firebase.json declares.",
    ),
    OptionSpec {
        flags: &["--ui"],
        value: Value::None,
        exec_only: true,
        text: "Start the UI while the command runs (exec does not start it otherwise, as in `firebase emulators:exec`). --ui-port overrides.",
    },
    opt(
        &["--ui-port"],
        Value::Required("<n>"),
        "UI port; 0 disables the UI. Default: 4000 for up (the UI is skipped if that port is busy), off for exec.",
    ),
    opt(
        &["--hub-port"],
        Value::Required("<n>"),
        "Emulator Hub port. Default: 4400.",
    ),
    opt(
        &["--logging-port"],
        Value::Required("<n>"),
        "Logging emulator port; 0 disables it. Default: 4500.",
    ),
    opt(
        &["--inspect-functions"],
        Value::Optional("[port]"),
        "Run the Functions runner under the Node inspector on this port (1024-65535); without a port, or with `true`, a free port. Refused when functions.runner is not node. Default: off.",
    ),
    opt(
        &["--log-verbosity"],
        Value::Required("quiet|silent|info|debug"),
        "quiet and silent print errors only; info adds the banner and notices; debug also prints the resolved configuration. Case-insensitive. Default: info.",
    ),
    opt(
        &["--import"],
        Value::Required("<dir>"),
        "Import an export directory (from --export-on-exit or emulators:export) at start; it must exist. Default: start empty.",
    ),
    opt(
        &["--export-on-exit"],
        Value::Optional("[dir]"),
        "Export all state to this directory when the emulators stop; without a directory, the --import directory. Refused for the working directory or a parent of it, and unavailable on Windows. Default: no export.",
    ),
    opt(
        &["--ready-file"],
        Value::Required("<file>"),
        "Publish endpoint discovery, including a control capability, to this private file once every listener is bound, and remove it on graceful shutdown. For tooling such as fireemu/testing. Default: none.",
    ),
    opt(
        &["--owner-stdin"],
        Value::None,
        "Shut down when standard input is closed. For tooling such as fireemu/testing. Default: off.",
    ),
];

const HELP_OPTION: &str = "  -h, --help\n        Print this help and exit.\n";

const INIT_OPTIONS: &[OptionSpec] = &[
    opt(
        &["--profile"],
        Value::Required("strict|emulator"),
        "Compatibility profile. strict follows production Firebase and is recommended, including when migrating from the official emulator; emulator is only for checking alignment with the pinned official emulator and is not needed when migrating. Default: strict (asked interactively).",
    ),
    opt(
        &["--firebase-json"],
        Value::Required("<file>"),
        "Reference this firebase.json from fireemu.json, so rules, indexes, Functions and ports are read from it on every start. Default: ./firebase.json when it exists (asked interactively).",
    ),
    opt(
        &["--interactive"],
        Value::None,
        "Ask for the missing choices. Default: only when stdin and stdout are terminals.",
    ),
    opt(
        &["--yes", "--no-interactive"],
        Value::None,
        "Never ask; use the defaults for what is not given.",
    ),
    opt(
        &["--force"],
        Value::None,
        "Replace an existing fireemu.json. Default: an existing file is an error.",
    ),
];

const EXPORT_OPTIONS: &[OptionSpec] = &[
    opt(
        &["-P", "--project"],
        Value::Required("<id>"),
        "Project of the running suite. Default: the .firebaserc default in the current directory, else demo-app.",
    ),
    opt(
        &["-f", "--force"],
        Value::None,
        "Overwrite a non-empty destination. Default: refused.",
    ),
];

const DOCTOR_OPTIONS: &[OptionSpec] = &[opt(
    &["--connect"],
    Value::Required("http://127.0.0.1:<port>"),
    "Also report what a running suite says, through its control URL (the control port is printed at startup). Default: only the offline report.",
)];

/// A command with its own help page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topic {
    Init,
    Up,
    Exec,
    Export,
    Doctor,
    Capabilities,
}

/// Every topic, in the order the overall help lists them.
pub const TOPICS: [Topic; 6] = [
    Topic::Init,
    Topic::Up,
    Topic::Exec,
    Topic::Export,
    Topic::Doctor,
    Topic::Capabilities,
];

impl Topic {
    /// The topic a command name (or alias) selects.
    pub fn for_command(name: &str) -> Option<Self> {
        match name {
            "init" => Some(Self::Init),
            "up" | "emulators:start" => Some(Self::Up),
            "exec" | "emulators:exec" => Some(Self::Exec),
            "emulators:export" => Some(Self::Export),
            "doctor" => Some(Self::Doctor),
            "capabilities" => Some(Self::Capabilities),
            _ => None,
        }
    }

    /// The command name the help page is filed under.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Up => "up",
            Self::Exec => "exec",
            Self::Export => "emulators:export",
            Self::Doctor => "doctor",
            Self::Capabilities => "capabilities",
        }
    }

    const fn summary(self) -> &'static str {
        match self {
            Self::Init => "create fireemu.json in the current directory",
            Self::Up => {
                "start the emulators and keep them running until Ctrl-C (alias: emulators:start)"
            }
            Self::Exec => "start the emulators, run a command, stop them (alias: emulators:exec)",
            Self::Export => "export the state of a running suite to a directory",
            Self::Doctor => "check the installation: binary, UI, Functions runner, Node.js",
            Self::Capabilities => "print the capability manifest of the resolved profile as JSON",
        }
    }

    const fn options(self) -> &'static [OptionSpec] {
        match self {
            Self::Init => INIT_OPTIONS,
            Self::Up | Self::Exec | Self::Capabilities => DAEMON_OPTIONS,
            Self::Export => EXPORT_OPTIONS,
            Self::Doctor => DOCTOR_OPTIONS,
        }
    }

    const fn synopsis(self) -> &'static str {
        match self {
            Self::Init => "  fireemu init [options]\n",
            Self::Up => "  fireemu up [options]\n  fireemu emulators:start [options]\n",
            Self::Exec => "  fireemu exec [options] \"shell script\"\n  fireemu exec [options] -- <command...>\n  fireemu emulators:exec [options] \"shell script\"\n  fireemu emulators:exec [options] -- <command...>\n",
            Self::Export => "  fireemu emulators:export <dir> [options]\n",
            Self::Doctor => "  fireemu doctor [--connect <control url>]\n",
            Self::Capabilities => "  fireemu capabilities [options]\n",
        }
    }

    const fn description(self) -> &'static str {
        match self {
            Self::Init => "Creates fireemu.json in the current directory and prints the command to start with it. It never overwrites an existing file unless --force is given.",
            Self::Up => "Serves the selected emulators (Firestore, Auth, Storage and App Check; Functions when a codebase is configured, and with it Eventarc and Cloud Tasks; Pub/Sub when configured) plus the control API, the Emulator Hub and the UI on loopback until Ctrl-C.",
            Self::Exec => "Starts the same emulators as `up`, runs the command with the emulator host environment variables (FIRESTORE_EMULATOR_HOST, FIREBASE_AUTH_EMULATOR_HOST, and so on) once every listener is bound, stops everything when the command exits, and exits with the command's status. On Unix, a command ended by signal n gives 128 + n, and SIGINT and SIGTERM are forwarded to it.\n\nWith \"shell script\" (the official form) the script is run by the system shell. With `--` the command is run as exactly that program and argv, without a shell. Everything after `--` belongs to the command, including --help; a `--help` inside the script text is script text.",
            Self::Export => "Asks the suite that is already running for the project (found through its Emulator Hub locator file) to write its state to <dir>, in the format --import reads. Not available on Windows.",
            Self::Doctor => "Reports the Fireemu binary, UI, Functions runner and Node.js that this installation finds, and suggests a remedy for each problem.",
            Self::Capabilities => "Prints the capability manifest for the profile the options resolve to. It accepts the same options as `up` and validates them the same way, but only --config (the profile it names) changes the result.",
        }
    }
}

fn render_option(spec: &OptionSpec) -> String {
    let mut names = spec.flags.join(", ");
    match spec.value {
        Value::None => {}
        Value::Required(v) | Value::Optional(v) => {
            names.push(' ');
            names.push_str(v);
        }
    }
    format!("  {names}\n        {}\n", spec.text)
}

/// The help page of a command.
pub fn command_help(topic: Topic) -> String {
    let mut text = format!(
        "fireemu {} - {}\n\nusage:\n{}\n{}\n\noptions:\n",
        topic.name(),
        topic.summary(),
        topic.synopsis(),
        topic.description()
    );
    for spec in topic.options() {
        if spec.exec_only && topic != Topic::Exec {
            continue;
        }
        text.push_str(&render_option(spec));
    }
    text.push_str(HELP_OPTION);
    text.push_str("\nSee also: fireemu --help\n");
    text
}

/// The overall help page.
pub fn overall_help() -> String {
    let mut text = String::from(
        "fireemu - a local Firebase emulator\n\nusage:\n  fireemu <command> [options]\n  fireemu --help | -h | help\n  fireemu help <command>\n  fireemu <command> --help\n  fireemu --version\n\ncommands:\n",
    );
    for topic in TOPICS {
        let _ = writeln!(text, "  {:<17} {}", topic.name(), topic.summary());
    }
    text.push_str(
        "\nRun `fireemu help <command>` or `fireemu <command> --help` for the options of a command. `--version` prints the version.\n",
    );
    text
}

/// The names `fireemu help <command>` accepts, for the error that lists them.
pub fn command_names() -> String {
    let mut names: Vec<&str> = TOPICS.iter().map(|t| t.name()).collect();
    names.extend(["emulators:start", "emulators:exec"]);
    names.join(", ")
}

/// Whether `arg` is an option of `topic` whose next argument is always its value. An optional
/// value never starts with `-`, so it can never be `--help`, `-h` or `--` and needs no skipping.
fn consumes_next(topic: Topic, arg: &str) -> bool {
    topic
        .options()
        .iter()
        .any(|spec| matches!(spec.value, Value::Required(_)) && spec.flags.contains(&arg))
}

/// Whether `args` (the arguments after the command name) ask for help: a standalone
/// `--help` or `-h` that is not the value of an option before it and, for `exec`, comes
/// before `--`.
pub fn requested(topic: Topic, args: &[String]) -> bool {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--help" || arg == "-h" {
            return true;
        }
        if arg == "--" && topic == Topic::Exec {
            return false;
        }
        i += if consumes_next(topic, arg) { 2 } else { 1 };
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_raw_options, OptionContext};
    use proptest::prelude::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// A value the parser accepts for `flag`.
    fn sample(flag: &str) -> &'static str {
        match flag {
            "--only" => "auth",
            "--log-verbosity" => "info",
            "--inspect-functions" => "9229",
            f if f.ends_with("-port") => "1",
            _ => "x",
        }
    }

    fn context(spec: &OptionSpec) -> OptionContext {
        if spec.exec_only {
            OptionContext::Exec
        } else {
            OptionContext::Start
        }
    }

    #[test]
    fn the_parser_accepts_every_documented_spelling_the_documented_way() {
        for spec in DAEMON_OPTIONS {
            for flag in spec.flags {
                let ctx = context(spec);
                match spec.value {
                    Value::None => {
                        let raw = parse_raw_options(&args(&[flag, "script"]), OptionContext::Exec);
                        assert_eq!(
                            raw.ok().unwrap().positional_script.as_deref(),
                            Some("script"),
                            "{flag} is a switch and must not consume the next argument"
                        );
                        assert!(parse_raw_options(&args(&[flag]), ctx).is_ok(), "{flag}");
                    }
                    Value::Required(_) => {
                        assert!(
                            parse_raw_options(&args(&[flag, sample(flag)]), ctx).is_ok(),
                            "{flag}"
                        );
                        assert!(
                            parse_raw_options(&args(&[flag]), ctx).is_err(),
                            "{flag} needs a value"
                        );
                    }
                    Value::Optional(_) => {
                        assert!(parse_raw_options(&args(&[flag]), ctx).is_ok(), "{flag}");
                        assert!(
                            parse_raw_options(&args(&[flag, sample(flag)]), ctx).is_ok(),
                            "{flag}"
                        );
                        // The next flag is not its value.
                        assert!(
                            parse_raw_options(&args(&[flag, "--hub-port", "1"]), ctx).is_ok(),
                            "{flag}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_exec_only_options_are_refused_by_start_and_nothing_else_is() {
        for spec in DAEMON_OPTIONS {
            let flag = spec.flags[spec.flags.len() - 1];
            let given = if spec.value == Value::None {
                args(&[flag])
            } else {
                args(&[flag, sample(flag)])
            };
            let refused = parse_raw_options(&given, OptionContext::Start).is_err();
            assert_eq!(refused, spec.exec_only, "{flag}");
        }
    }

    /// Every flag spelled as a match arm of the function `name` in `source`.
    fn arm_flags(source: &str, name: &str) -> Vec<String> {
        let start = source.find(&format!("fn {name}")).expect("parser present");
        let body = &source[start..];
        let end = body.find("\n}\n").expect("parser ends");
        let mut flags = Vec::new();
        for line in body[..end].lines() {
            let arm = line.trim_start();
            if !arm.starts_with("\"-") || !arm.contains("=>") {
                continue;
            }
            let patterns = arm.split("=>").next().unwrap_or_default();
            for pattern in patterns.split('|') {
                let pattern = pattern.trim();
                if let Some(flag) = pattern
                    .strip_prefix('"')
                    .and_then(|rest| rest.split('"').next())
                {
                    flags.push(flag.to_owned());
                }
            }
        }
        flags
    }

    /// Every flag spelled as a match arm of `parse_raw_options`.
    fn parser_flags() -> Vec<String> {
        arm_flags(include_str!("main.rs"), "parse_raw_options")
    }

    fn documented(options: &[OptionSpec]) -> Vec<&'static str> {
        options
            .iter()
            .flat_map(|spec| spec.flags.iter().copied())
            .collect()
    }

    /// Both directions: every arm is described and every described flag has an arm.
    fn assert_table_matches_arms(label: &str, options: &[OptionSpec], arms: &[String]) {
        assert!(!arms.is_empty(), "{label}: the scan found no arms");
        let documented = documented(options);
        for flag in arms {
            assert!(
                documented.contains(&flag.as_str()),
                "{label}: {flag} is undocumented"
            );
        }
        for flag in documented {
            assert!(
                arms.iter().any(|p| p == flag),
                "{label}: {flag} has no parser arm"
            );
        }
    }

    #[test]
    fn the_init_export_and_doctor_tables_match_their_parsers() {
        assert_table_matches_arms(
            "init",
            INIT_OPTIONS,
            &arm_flags(include_str!("init.rs"), "parse_args"),
        );
        assert_table_matches_arms(
            "emulators:export",
            EXPORT_OPTIONS,
            &arm_flags(include_str!("main.rs"), "export_command"),
        );
        // `doctor` is parsed inline in `main`: its one option is the `Some("--connect")` arm.
        let main = include_str!("main.rs");
        let start = main.find("Some(\"doctor\") =>").expect("doctor arm");
        let block = &main[start..main[start..].find("Some(\"capabilities\")").unwrap() + start];
        let mut arms: Vec<String> = Vec::new();
        for part in block.split("Some(\"-").skip(1) {
            arms.push(format!("-{}", part.split('"').next().unwrap()));
        }
        assert_table_matches_arms("doctor", DOCTOR_OPTIONS, &arms);
    }

    #[test]
    fn every_command_help_lists_every_flag_its_parser_accepts() {
        for (topic, options) in [
            (Topic::Init, INIT_OPTIONS),
            (Topic::Export, EXPORT_OPTIONS),
            (Topic::Doctor, DOCTOR_OPTIONS),
        ] {
            let text = command_help(topic);
            for flag in documented(options) {
                assert!(text.contains(flag), "{}: {flag}", topic.name());
            }
        }
    }

    #[test]
    fn every_flag_the_parser_has_an_arm_for_is_documented() {
        let parsed = parser_flags();
        assert!(parsed.len() >= 20, "the scan found {parsed:?}");
        assert_table_matches_arms("up/exec", DAEMON_OPTIONS, &parsed);
    }

    #[test]
    fn the_up_and_exec_help_describe_every_flag_the_parser_accepts() {
        let up = command_help(Topic::Up);
        let exec = command_help(Topic::Exec);
        for flag in parser_flags() {
            assert!(exec.contains(&flag), "exec help lacks {flag}");
            if flag != "--ui" {
                assert!(up.contains(&flag), "up help lacks {flag}");
            }
        }
        let capabilities = command_help(Topic::Capabilities);
        assert!(capabilities.contains("--config") && !capabilities.contains("\n  --ui\n"));
    }

    #[test]
    fn every_option_is_rendered_with_its_value_and_text() {
        let exec = command_help(Topic::Exec);
        assert!(exec.contains("  -P, --project <id|alias>\n        Project ID"));
        assert!(exec.contains("  --inspect-functions [port]\n"));
        assert!(exec.contains("  --export-on-exit [dir]\n"));
        assert!(exec.contains("  --ui\n        Start the UI"));
        assert!(exec.contains("  -h, --help\n"));
        let init = command_help(Topic::Init);
        assert!(init.contains("  --yes, --no-interactive\n"));
        assert!(init.contains("recommended, including when migrating from the official emulator"));
        assert!(init.contains("not needed when migrating"));
    }

    #[test]
    fn the_defaults_in_the_help_match_the_runtime_defaults() {
        let cfg = crate::config::RuntimeConfig::default();
        let help = command_help(Topic::Up);
        for (flag, addr) in [
            ("--firestore-port", &cfg.firestore_addr),
            ("--http-port", &cfg.http_addr),
            ("--storage-port", &cfg.storage_addr),
            ("--functions-port", &cfg.functions_addr),
            ("--eventarc-port", &cfg.eventarc_addr),
            ("--tasks-port", &cfg.tasks_addr),
            ("--pubsub-port", &cfg.pubsub_addr),
            ("--ui-port", &cfg.ui_addr),
            ("--hub-port", &cfg.hub_addr),
            ("--logging-port", &cfg.logging_addr),
        ] {
            let port = addr.rsplit_once(':').unwrap().1;
            let at = help
                .find(&format!("\n  {flag} "))
                .unwrap_or_else(|| panic!("{flag}"));
            let rest = &help[at + 1..];
            let entry = &rest[..rest.find("\n  -").unwrap_or(rest.len())];
            assert!(
                entry.contains(&format!("Default: {port}")),
                "{flag}: {entry}"
            );
        }
        assert!(help.contains(&cfg.auth_project));
    }

    #[test]
    fn the_service_start_wording_matches_the_start_conditions() {
        // The conditions in `bind_listeners`/`child_environment`: Firestore, Auth and Storage
        // are selected by default and always start; Functions is selected but needs a codebase;
        // Pub/Sub is selected but needs configuration; Eventarc and Cloud Tasks are never
        // selected by default and start exactly with a loaded Functions backend.
        let selection = crate::config::Selection::default();
        let cfg = crate::config::RuntimeConfig::default();
        assert!(selection.firestore && selection.auth && selection.storage && selection.appcheck);
        assert!(selection.functions && cfg.functions_source.is_none());
        assert!(selection.pubsub && !cfg.pubsub_enabled);
        assert!(!selection.eventarc && !selection.tasks);

        let only = DAEMON_OPTIONS
            .iter()
            .find(|spec| spec.flags == ["--only"])
            .unwrap()
            .text;
        let default = only.split("Default: ").nth(1).expect("a default is stated");
        assert!(
            default.starts_with("Firestore, Auth, Storage and App Check;"),
            "{default}"
        );
        assert!(
            default.contains("Functions when a codebase is configured"),
            "{default}"
        );
        assert!(
            default.contains("and with it Eventarc and Cloud Tasks"),
            "{default}"
        );
        assert!(default.contains("Pub/Sub when configured"), "{default}");
        let up = command_help(Topic::Up);
        assert!(up.contains("Pub/Sub when configured"), "{up}");
        assert!(
            up.contains("Functions when a codebase is configured"),
            "{up}"
        );
        for flag in ["--eventarc-port", "--tasks-port"] {
            let spec = DAEMON_OPTIONS.iter().find(|s| s.flags == [flag]).unwrap();
            assert!(spec
                .text
                .contains("starts exactly when a Functions backend is loaded"));
            assert!(!spec.text.contains("also enables"), "{}", spec.text);
        }
    }

    #[test]
    fn command_names_resolve_and_aliases_share_a_topic() {
        for topic in TOPICS {
            assert_eq!(Topic::for_command(topic.name()), Some(topic));
        }
        assert_eq!(Topic::for_command("emulators:start"), Some(Topic::Up));
        assert_eq!(Topic::for_command("emulators:exec"), Some(Topic::Exec));
        assert_eq!(Topic::for_command("emulators"), None);
        assert_eq!(Topic::for_command(""), None);
        let names = command_names();
        for name in [
            "init",
            "up",
            "exec",
            "emulators:export",
            "doctor",
            "capabilities",
            "emulators:start",
            "emulators:exec",
        ] {
            assert!(names.contains(name), "{name}");
        }
    }

    #[test]
    fn requested_follows_the_documented_rules() {
        assert!(requested(Topic::Up, &args(&["--help"])));
        assert!(requested(Topic::Up, &args(&["-h"])));
        assert!(requested(Topic::Up, &args(&["--only", "auth", "--help"])));
        assert!(requested(
            Topic::Up,
            &args(&["--inspect-functions", "--help"])
        ));
        assert!(requested(Topic::Up, &args(&["--export-on-exit", "--help"])));
        assert!(!requested(Topic::Up, &args(&["--config", "--help"])));
        assert!(!requested(Topic::Up, &args(&["--export-on-exit", "-help"])));
        assert!(!requested(
            Topic::Up,
            &args(&["--inspect-functions", "9229"])
        ));
        assert!(!requested(Topic::Up, &args(&["--only"])));
        assert!(!requested(Topic::Up, &args(&["--helpx", "-hh", "help"])));
        assert!(requested(Topic::Exec, &args(&["x", "--help"])));
        assert!(!requested(Topic::Exec, &args(&["echo --help"])));
        assert!(!requested(Topic::Exec, &args(&["--", "--help"])));
        assert!(!requested(Topic::Exec, &args(&["--ui", "--", "x", "-h"])));
        assert!(requested(Topic::Exec, &args(&["--help", "--", "x"])));
        assert!(requested(Topic::Export, &args(&["dir", "-h"])));
        assert!(!requested(Topic::Export, &args(&["--project", "-h"])));
        assert!(requested(Topic::Export, &args(&["-f", "-h"])));
        assert!(!requested(Topic::Doctor, &args(&["--connect", "--help"])));
        assert!(requested(Topic::Doctor, &args(&["--help"])));
        assert!(!requested(Topic::Init, &args(&["--profile", "-h"])));
        assert!(requested(
            Topic::Init,
            &args(&["--profile", "strict", "-h"])
        ));
        // Only exec treats `--` as the end of its options.
        assert!(requested(Topic::Up, &args(&["--", "--help"])));
    }

    fn word() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("--ui".to_owned()),
            Just("--owner-stdin".to_owned()),
            Just("script".to_owned()),
            Just("echo --help".to_owned()),
            Just("-x".to_owned()),
            "[a-z]{1,6}",
        ]
    }

    proptest! {
        /// Appending a standalone help flag after switches and positionals always asks for
        /// help, and the same flag after `--` never does for `exec`.
        #[test]
        fn help_is_found_before_the_double_dash_and_never_after(
            before in proptest::collection::vec(word(), 0..6),
            after in proptest::collection::vec(prop_oneof![word(), Just("--help".to_owned()), Just("-h".to_owned())], 0..6),
            flag in prop_oneof![Just("--help"), Just("-h")],
        ) {
            let mut with_help = before.clone();
            with_help.push(flag.to_owned());
            with_help.push("--".to_owned());
            with_help.extend(after.clone());
            prop_assert!(requested(Topic::Exec, &with_help));

            let mut without = before;
            without.push("--".to_owned());
            without.extend(after);
            prop_assert!(!requested(Topic::Exec, &without));
        }
    }
}
