//! `up --plan` and `exec --plan`: what a run would do, resolved by the code start-up uses.
//!
//! A plan is not a second implementation of start-up. The options are parsed by
//! [`crate::parse_options`], which `up` and `exec` call; which services start is decided by
//! [`ServiceStarts::resolve`], which the listener binding calls; each Functions codebase's
//! runner is chosen by `functions::select_runner`, which start-up calls. The plan only reads
//! the results and prints them (text, or JSON with `--json`). It runs the probes start-up runs
//! (`node --version`, and a Python codebase's own interpreter) but binds no port and starts
//! no emulator.
//!
//! The module also owns the policy for emulator variables inherited from the parent
//! environment (`--deny-inherited-emulator-env`), because the plan and the start-up check
//! classify the same variables the same way.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{json, Value};

use crate::config::{RuntimeConfig, Selection};
use crate::{diagnostic_text, CliError, ExecCommand, ExecPlan, Options, Verbosity};

/// How `--plan` prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanFormat {
    Text,
    Json,
}

/// What to do about an emulator variable inherited from the parent environment that names a
/// service this run does not start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InheritedEnvPolicy {
    /// `--deny-inherited-emulator-env`: refuse the run (default: warn and keep the variable).
    pub deny: bool,
    /// `--allow-inherited-emulator-env <NAME>`: variables kept on purpose.
    pub allow: Vec<String>,
}

/// What option resolution decided besides the configuration itself, and where it came from.
#[derive(Debug, Clone)]
pub(crate) struct Facts {
    /// The working directory the paths of the canonical configuration resolve against.
    pub working_directory: Option<PathBuf>,
    /// The directory the paths of `firebase.json` resolve against.
    pub project_root: PathBuf,
    /// The rule that chose the project ID.
    pub project_source: String,
    /// The canonical configuration file, when one was loaded.
    pub canonical: Option<PathBuf>,
    /// Its parsed document.
    pub canonical_document: Option<Value>,
    /// The `firebase.json` that was loaded: its path, whether the canonical configuration's
    /// `firebaseJson` entry named it, and its parsed document.
    pub firebase: Option<(PathBuf, bool, Value)>,
    /// The command-line options that override the files, as typed.
    pub overrides: Vec<(String, String)>,
    /// The UI listener selection used by start-up.
    pub ui: crate::UiSelection,
}

// ---------------------------------------------------------------------------------------------
// Which services start
// ---------------------------------------------------------------------------------------------

/// Whether Hosting starts. `--only hosting` without `hosting.public` is an error rather than a
/// quiet no-op.
pub(crate) fn hosting_starts(cfg: &RuntimeConfig, only: &Selection) -> Result<bool, String> {
    if only.explicit && only.hosting && cfg.hosting.is_none() {
        return Err("--only hosting requires hosting.public in firebase.json".to_owned());
    }
    Ok(only.hosting && cfg.hosting.is_some())
}

/// The product listeners a run starts. The listener binding and the plan both read this, so
/// the plan cannot name a service the start-up would not start, or the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one flag per service, read independently
pub(crate) struct ServiceStarts {
    pub firestore: bool,
    pub auth: bool,
    pub storage: bool,
    pub hosting: bool,
    pub functions: bool,
    pub eventarc: bool,
    pub tasks: bool,
    pub pubsub: bool,
    pub database: bool,
}

impl ServiceStarts {
    /// Decides the listeners from the resolved configuration and selection.
    pub(crate) fn resolve(cfg: &RuntimeConfig, only: &Selection) -> Result<Self, String> {
        let hosting = hosting_starts(cfg, only)?;
        // The pinned Firebase CLI starts both support emulators whenever a Functions backend is
        // loaded, even if `--only` did not name them. Naming either one without Functions is an
        // accepted no-op and binds neither listener.
        let functions = only.functions && cfg.functions_source.is_some();
        Ok(Self {
            firestore: only.firestore,
            auth: only.auth,
            storage: only.storage,
            hosting,
            functions,
            eventarc: functions,
            tasks: functions,
            // Like the official suite, Pub/Sub and the Realtime Database start only when they
            // were configured or explicitly asked for.
            pubsub: only.pubsub && (cfg.pubsub_enabled || only.explicit),
            database: only.database && (cfg.database_enabled || only.explicit),
        })
    }
}

/// One listener of the plan.
struct ServiceRow {
    name: &'static str,
    start: bool,
    address: Option<String>,
    /// Why it does not start.
    reason: Option<String>,
    /// How its port behaves.
    note: Option<&'static str>,
    /// The Hub, the UI and the Logging emulator are not `--only` services.
    auxiliary: bool,
}

fn port_of(address: &str) -> Option<u16> {
    address.rsplit_once(':')?.1.parse().ok()
}

fn not_in_only(only_flag: bool) -> Option<String> {
    (!only_flag).then(|| "not in --only".to_owned())
}

#[allow(clippy::too_many_lines)]
fn service_rows(
    cfg: &RuntimeConfig,
    only: &Selection,
    starts: &ServiceStarts,
    ui: crate::UiSelection,
) -> Vec<ServiceRow> {
    let port_note = |address: &str, relocatable: bool| -> Option<&'static str> {
        if port_of(address) == Some(0) {
            Some("a free port is chosen at start")
        } else if relocatable {
            Some("moves up to the next free port when busy")
        } else {
            None
        }
    };
    let row =
        |name: &'static str, start: bool, address: &str, reason: Option<String>, relocatable| {
            ServiceRow {
                name,
                start,
                address: Some(address.to_owned()),
                reason: if start { None } else { reason },
                note: if start {
                    port_note(address, relocatable)
                } else {
                    None
                },
                auxiliary: false,
            }
        };
    let mut rows = vec![
        row("firestore", starts.firestore, &cfg.firestore_addr, not_in_only(only.firestore), false),
        row("auth", starts.auth, &cfg.http_addr, not_in_only(only.auth), false),
        row("storage", starts.storage, &cfg.storage_addr, not_in_only(only.storage), false),
        row(
            "functions",
            starts.functions,
            &cfg.functions_addr,
            not_in_only(only.functions).or_else(|| {
                Some("no Functions codebase is configured (functions in firebase.json, or --functions <dir>)".to_owned())
            }),
            false,
        ),
        row(
            "hosting",
            starts.hosting,
            &cfg.hosting_addr,
            not_in_only(only.hosting)
                .or_else(|| Some("firebase.json has no hosting.public".to_owned())),
            !cfg.hosting_addr_explicit,
        ),
        row(
            "eventarc",
            starts.eventarc,
            &cfg.eventarc_addr,
            Some("starts only with a loaded Functions codebase".to_owned()),
            !cfg.eventarc_addr_explicit,
        ),
        row(
            "tasks",
            starts.tasks,
            &cfg.tasks_addr,
            Some("starts only with a loaded Functions codebase".to_owned()),
            !cfg.tasks_addr_explicit,
        ),
        row(
            "pubsub",
            starts.pubsub,
            &cfg.pubsub_addr,
            not_in_only(only.pubsub).or_else(|| {
                Some("not configured (emulators.pubsub in firebase.json, daemon.pubsubPort, or --pubsub-port)".to_owned())
            }),
            false,
        ),
        row(
            "database",
            starts.database,
            &cfg.database_addr,
            not_in_only(only.database).or_else(|| {
                Some("not configured (emulators.database in firebase.json, daemon.databasePort, or --database-port)".to_owned())
            }),
            false,
        ),
    ];
    let app_check = only.app_check_available(&cfg.app_check);
    rows.push(ServiceRow {
        name: "appcheck",
        start: app_check,
        address: app_check.then(|| {
            if starts.auth {
                cfg.http_addr.clone()
            } else {
                "127.0.0.1 (the control listener, a free port)".to_owned()
            }
        }),
        reason: (!app_check).then(|| {
            not_in_only(only.appcheck)
                .unwrap_or_else(|| "App Check is not available for this selection".to_owned())
        }),
        note: app_check.then_some("shares the Auth or control listener"),
        auxiliary: false,
    });
    let hub_off = cfg.hub_addr_explicit && !cfg.hub_auto_port && port_of(&cfg.hub_addr) == Some(0);
    rows.push(ServiceRow {
        name: "hub",
        start: !hub_off,
        address: (!hub_off).then(|| cfg.hub_addr.clone()),
        reason: hub_off.then(|| "--hub-port 0 turns it off".to_owned()),
        note: (!hub_off && !cfg.hub_addr_explicit)
            .then_some("best effort: a busy default port only disables discovery"),
        auxiliary: true,
    });
    let (ui_address, ui_note) = match ui {
        crate::UiSelection::Disabled => (None, None),
        crate::UiSelection::Auto => (
            Some("127.0.0.1:0".to_owned()),
            Some("a free port is chosen at start"),
        ),
        crate::UiSelection::Default => (
            Some(format!("127.0.0.1:{}", crate::config::DEFAULT_UI_PORT)),
            Some("best effort unless the port was asked for"),
        ),
        crate::UiSelection::Fixed(port) => (
            Some(format!("127.0.0.1:{port}")),
            Some("best effort unless the port was asked for"),
        ),
    };
    rows.push(ServiceRow {
        name: "ui",
        start: ui_address.is_some(),
        address: ui_address,
        reason: (ui == crate::UiSelection::Disabled).then(|| "off (exec starts it only with --ui; --ui-port 0 and emulators.ui.port 0 turn it off)".to_owned()),
        note: ui_note,
        auxiliary: true,
    });
    rows.push(ServiceRow {
        name: "logging",
        start: cfg.logging_enabled,
        address: cfg.logging_enabled.then(|| cfg.logging_addr.clone()),
        reason: (!cfg.logging_enabled).then(|| "turned off (port 0)".to_owned()),
        note: cfg
            .logging_enabled
            .then_some("best effort unless the port was asked for"),
        auxiliary: true,
    });
    rows
}

// ---------------------------------------------------------------------------------------------
// Inherited emulator variables
// ---------------------------------------------------------------------------------------------

/// The variables a run exports for its services, with the service each one belongs to. The
/// service names are the ones the plan prints. A test keeps this table equal to what
/// `child_environment` writes.
pub(crate) const EMULATOR_ENV: &[(&str, &str, bool)] = &[
    ("FIRESTORE_EMULATOR_HOST", "firestore", true),
    ("FIREBASE_FIRESTORE_EMULATOR_ADDRESS", "firestore", true),
    ("FIREBASE_AUTH_EMULATOR_HOST", "auth", true),
    ("FIREBASE_STORAGE_EMULATOR_HOST", "storage", true),
    ("STORAGE_EMULATOR_HOST", "storage", true),
    ("FIREEMU_FUNCTIONS_HOST", "functions", true),
    ("CLOUD_EVENTARC_EMULATOR_HOST", "eventarc", true),
    ("CLOUD_TASKS_EMULATOR_HOST", "tasks", true),
    ("PUBSUB_EMULATOR_HOST", "pubsub", true),
    ("FIREBASE_DATABASE_EMULATOR_HOST", "database", true),
    ("FIREBASE_EMULATOR_HUB", "hub", true),
    ("FIREBASE_LOGGING_EMULATOR_HOST", "logging", true),
    ("FIREEMU_APP_CHECK_EMULATOR_HOST", "appcheck", true),
    ("FIREEMU_APP_CHECK_JWKS_URL", "appcheck", true),
    ("FIREBASE_DATA_CONNECT_EMULATOR_HOST", "dataconnect", false),
    ("DATA_CONNECT_EMULATOR_HOST", "dataconnect", false),
    ("FIREBASE_DATACONNECT_EMULATOR_HOST", "dataconnect", false),
];

/// Refuses an `--allow-inherited-emulator-env` name that is no emulator variable: a misspelt
/// name would otherwise allow nothing and look as if it allowed something.
pub(crate) fn check_allowed_names(names: &[String]) -> Result<(), String> {
    for name in names {
        if !EMULATOR_ENV.iter().any(|(known, _, _)| known == name) {
            return Err(format!(
                "--allow-inherited-emulator-env {}: not an emulator variable; the names are {}",
                diagnostic_text(name),
                EMULATOR_ENV
                    .iter()
                    .map(|(name, _, _)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    Ok(())
}

/// The emulator variables of the parent environment, in table order. Nothing else is read.
pub(crate) fn parent_environment() -> Vec<(String, String)> {
    EMULATOR_ENV
        .iter()
        .filter_map(|(name, _, _)| {
            std::env::var_os(name)
                .map(|value| ((*name).to_owned(), value.to_string_lossy().into_owned()))
        })
        .collect()
}

/// What happens to one inherited variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Disposition {
    /// The run starts the service and exports its own value over it.
    Overridden,
    /// The run does not start the service; the value stays and points somewhere else.
    KeptServiceNotStarted,
    /// As above, and `--allow-inherited-emulator-env` names it.
    KeptAllowed,
}

impl Disposition {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Overridden => "overridden",
            Self::KeptServiceNotStarted => "kept-service-not-started",
            Self::KeptAllowed => "kept-allowed",
        }
    }
}

/// An emulator variable the parent environment carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Inherited {
    pub name: &'static str,
    pub service: &'static str,
    /// The value with any credential removed.
    pub value: String,
    pub disposition: Disposition,
}

/// Removes the credential of an endpoint value: everything before the last `@` of the
/// authority (`http://user:secret@host:9199` becomes `http://***@host:9199`). A Storage
/// endpoint can carry the per-run Admin capability that way, and the plan must not print it.
pub(crate) fn redact_userinfo(value: &str) -> String {
    let (scheme, rest) = match value.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, value),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let authority = match authority.rfind('@') {
        Some(at) => format!("***@{}", &authority[at + 1..]),
        None => authority.to_owned(),
    };
    match scheme {
        Some(scheme) => format!("{scheme}://{authority}{tail}"),
        None => format!("{authority}{tail}"),
    }
}

/// Classifies the parent's emulator variables for a run that starts `started` services.
pub(crate) fn classify_inherited(
    parent: &[(String, String)],
    started: &BTreeSet<&'static str>,
    allow: &[String],
) -> Vec<Inherited> {
    EMULATOR_ENV
        .iter()
        .filter_map(|(name, service, _)| {
            let (_, value) = parent.iter().find(|(parent_name, _)| parent_name == name)?;
            let disposition = if started.contains(service) {
                Disposition::Overridden
            } else if allow.iter().any(|allowed| allowed == name) {
                Disposition::KeptAllowed
            } else {
                Disposition::KeptServiceNotStarted
            };
            Some(Inherited {
                name,
                service,
                value: redact_userinfo(value),
                disposition,
            })
        })
        .collect()
}

fn started_services(rows: &[ServiceRow]) -> BTreeSet<&'static str> {
    rows.iter()
        .filter(|row| row.start)
        .map(|row| row.name)
        .collect()
}

/// The variables the policy refuses: inherited, for a service this run does not start, and not
/// allowed. Empty unless `--deny-inherited-emulator-env`.
pub(crate) fn denied<'a>(
    inherited: &'a [Inherited],
    policy: &InheritedEnvPolicy,
) -> Vec<&'a Inherited> {
    if !policy.deny {
        return Vec::new();
    }
    inherited
        .iter()
        .filter(|entry| entry.disposition == Disposition::KeptServiceNotStarted)
        .collect()
}

fn stale_warning(entry: &Inherited) -> String {
    format!(
        "{}={} is inherited from the environment, but this run does not start {}; the command keeps the value and reaches whatever listens there. Pass --deny-inherited-emulator-env to refuse such a run, or --allow-inherited-emulator-env {} if this is intended",
        entry.name,
        diagnostic_text(&entry.value),
        entry.service,
        entry.name
    )
}

fn denial(denied: &[&Inherited]) -> String {
    let names: Vec<&str> = denied.iter().map(|entry| entry.name).collect();
    let plural = names.len() > 1;
    format!(
        "{} {} set in the environment for a service this run does not start ({}), so the command would talk to whatever listens there; unset {}, start the service, or keep {} with --allow-inherited-emulator-env <NAME>",
        names.join(", "),
        if plural { "are" } else { "is" },
        denied
            .iter()
            .map(|entry| entry.service)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", "),
        if plural { "them" } else { "it" },
        if plural { "them" } else { "it" },
    )
}

/// The check `up` and `exec` make before they start: refuses the run under
/// `--deny-inherited-emulator-env`, otherwise warns about each inherited variable of a service
/// this run does not start.
pub(crate) fn guard_inherited_env(
    options: &Options,
    parent: &[(String, String)],
) -> Result<(), CliError> {
    // A selection the listener binding refuses is reported there, with its own message.
    let Ok(starts) = ServiceStarts::resolve(&options.cfg, &options.only) else {
        return Ok(());
    };
    let rows = service_rows(&options.cfg, &options.only, &starts, options.facts.ui);
    let inherited = classify_inherited(
        parent,
        &started_services(&rows),
        &options.inherited_env.allow,
    );
    let refused = denied(&inherited, &options.inherited_env);
    if !refused.is_empty() {
        return Err(CliError::refused(denial(&refused)));
    }
    if options.verbosity > Verbosity::Quiet {
        for entry in inherited
            .iter()
            .filter(|entry| entry.disposition == Disposition::KeptServiceNotStarted)
        {
            eprintln!("warning: {}", stale_warning(entry));
        }
    }
    Ok(())
}

/// Checks inherited variables against the listeners that actually bound.
pub(crate) fn check_bound_listeners(
    policy: &InheritedEnvPolicy,
    addrs: &crate::BoundAddrs,
    appcheck: bool,
    quiet: bool,
    parent: &[(String, String)],
) -> Result<(), String> {
    let started: BTreeSet<&'static str> = [
        ("firestore", addrs.firestore.is_some()),
        ("auth", addrs.auth.is_some()),
        ("storage", addrs.storage.is_some()),
        ("functions", addrs.functions.is_some()),
        ("eventarc", addrs.eventarc.is_some()),
        ("tasks", addrs.tasks.is_some()),
        ("pubsub", addrs.pubsub.is_some()),
        ("database", addrs.database.is_some()),
        ("hub", addrs.hub.is_some()),
        ("logging", addrs.logging.is_some()),
        ("appcheck", appcheck),
    ]
    .into_iter()
    .filter_map(|(name, started)| started.then_some(name))
    .collect();
    let inherited = classify_inherited(parent, &started, &policy.allow);
    let refused = denied(&inherited, policy);
    if !refused.is_empty() {
        return Err(denial(&refused));
    }
    if !quiet {
        for warning in bound_warnings(&inherited) {
            eprintln!("warning: {warning}");
        }
    }
    Ok(())
}

/// The warnings the post-bind check adds: only for the best-effort listeners (the Hub and the
/// Logging emulator), because the pre-start check already warned about every other service.
fn bound_warnings(inherited: &[Inherited]) -> Vec<String> {
    inherited
        .iter()
        .filter(|entry| {
            matches!(entry.service, "hub" | "logging")
                && entry.disposition == Disposition::KeptServiceNotStarted
        })
        .map(stale_warning)
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------------------------

/// One file or directory setting, with the base its relative form resolves against.
struct PathRow {
    setting: String,
    written: String,
    resolved: String,
    base: &'static str,
    base_directory: Option<String>,
    /// The canonical configuration file that wrote it, when it did.
    canonical_file: Option<PathBuf>,
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Attributes the resolved value of a path setting to the file that wrote it: the canonical
/// configuration (relative to the working directory), `firebase.json` (relative to its own
/// directory, already joined onto it), or the command line.
fn path_row(setting: &str, value: &str, canonical_pointer: Option<&str>, facts: &Facts) -> PathRow {
    let from_canonical = canonical_pointer
        .zip(facts.canonical_document.as_ref())
        .is_some_and(|(pointer, document)| {
            document.pointer(pointer).and_then(Value::as_str) == Some(value)
        });
    if from_canonical {
        return PathRow {
            setting: setting.to_owned(),
            written: value.to_owned(),
            resolved: absolute(Path::new(value)).display().to_string(),
            base: "working directory",
            base_directory: facts
                .working_directory
                .as_ref()
                .map(|dir| dir.display().to_string()),
            canonical_file: facts.canonical.clone(),
        };
    }
    if facts.firebase.is_some() {
        if let Ok(written) = Path::new(value).strip_prefix(&facts.project_root) {
            return PathRow {
                setting: setting.to_owned(),
                written: written.display().to_string(),
                resolved: absolute(Path::new(value)).display().to_string(),
                base: "firebase.json directory",
                base_directory: Some(absolute(&facts.project_root).display().to_string()),
                canonical_file: None,
            };
        }
    }
    PathRow {
        setting: setting.to_owned(),
        written: value.to_owned(),
        resolved: absolute(Path::new(value)).display().to_string(),
        base: "working directory",
        base_directory: facts
            .working_directory
            .as_ref()
            .map(|dir| dir.display().to_string()),
        canonical_file: None,
    }
}

fn path_rows(cfg: &RuntimeConfig, facts: &Facts, starts: &ServiceStarts) -> Vec<PathRow> {
    let mut rows = Vec::new();
    if let Some((path, true, _)) = &facts.firebase {
        let written = facts
            .canonical_document
            .as_ref()
            .and_then(|document| document.get("firebaseJson"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let directory = facts
            .canonical
            .as_deref()
            .map(|canonical| absolute(&crate::project_dir(canonical)));
        rows.push(PathRow {
            setting: "firebaseJson".to_owned(),
            written: written.to_owned(),
            resolved: absolute(path).display().to_string(),
            base: "configuration file directory",
            base_directory: directory.map(|dir| dir.display().to_string()),
            canonical_file: None,
        });
    }
    let mut single = |setting: &str, value: &Option<String>, pointer: &str| {
        if let Some(value) = value {
            rows.push(path_row(setting, value, Some(pointer), facts));
        }
    };
    single("rules.source", &cfg.rules_file, "/rules/source");
    single(
        "firestore.indexFile",
        &cfg.index_file,
        "/firestore/indexFile",
    );
    single(
        "firestore.textIndexDefinitionFile",
        &cfg.text_index_file,
        "/firestore/textIndexDefinitionFile",
    );
    single("storage.rules", &cfg.storage_rules_file, "/storage/rules");
    if cfg.functions_loaded.is_empty() {
        single(
            "functions.source",
            &cfg.functions_source,
            "/functions/source",
        );
    }
    for (database, files) in &cfg.firestore_databases {
        for (kind, file, top_level) in [
            ("rules", &files.rules, &cfg.rules_file),
            ("indexes", &files.indexes, &cfg.index_file),
        ] {
            // The default database's files are the top-level rules and index settings above.
            if database == fireemu_core_types::ids::DatabaseId::DEFAULT && file == top_level {
                continue;
            }
            if let Some(file) = file {
                rows.push(path_row(
                    &format!("firestore[{database}].{kind}"),
                    file,
                    None,
                    facts,
                ));
            }
        }
    }
    for (target, file) in &cfg.storage_rules_by_target {
        let setting = format!("storage[{target}].rules");
        rows.push(path_row(&setting, file, None, facts));
    }
    for entry in &cfg.database_rules {
        let scope = match &entry.scope {
            crate::config::DatabaseRulesScope::Default => "database.rules".to_owned(),
            crate::config::DatabaseRulesScope::Instance(name)
            | crate::config::DatabaseRulesScope::Target(name) => format!("database[{name}].rules"),
        };
        rows.push(path_row(&scope, &entry.file, None, facts));
    }
    if starts.functions {
        for codebase in &cfg.functions_loaded {
            rows.push(path_row(
                &format!("functions[{}].source", codebase.codebase),
                &codebase.source,
                None,
                facts,
            ));
        }
    }
    if let Some(hosting) = &cfg.hosting {
        for (index, site) in hosting.iter().enumerate() {
            let setting = if hosting.len() == 1 {
                "hosting.public".to_owned()
            } else {
                format!("hosting[{index}].public")
            };
            let public = site.public().to_string_lossy();
            rows.push(path_row(&setting, &public, None, facts));
        }
    }
    rows
}

/// The warning for a relative path the canonical configuration wrote while the working
/// directory is not the directory of that file: `firebase.json` paths follow the file, these
/// follow the directory `fireemu` runs in, so the same configuration run from the file's own
/// directory reads other files.
fn cwd_warning(row: &PathRow, facts: &Facts) -> Option<String> {
    let file = row.canonical_file.as_ref()?;
    if Path::new(&row.written).is_absolute() {
        return None;
    }
    let file_directory = absolute(&crate::project_dir(file));
    let cwd = facts.working_directory.as_ref()?;
    if &file_directory == cwd {
        return None;
    }
    Some(format!(
        "{} is written as {} in {}, which is in {}; a path in the canonical configuration resolves against the working directory ({}), so this run reads {}, and a run from {} would read {}",
        row.setting,
        diagnostic_text(&row.written),
        file.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
        file_directory.display(),
        cwd.display(),
        diagnostic_text(&row.resolved),
        file_directory.display(),
        file_directory.join(&row.written).display(),
    ))
}

// ---------------------------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------------------------

fn services_json(rows: &[ServiceRow]) -> Value {
    Value::Array(
        rows.iter()
            .map(|row| {
                json!({
                    "name": row.name,
                    "start": row.start,
                    "address": row.address,
                    "reason": row.reason,
                    "note": row.note,
                    "auxiliary": row.auxiliary,
                })
            })
            .collect(),
    )
}

fn environment_set(rows: &[ServiceRow]) -> Vec<Value> {
    let mut out = Vec::new();
    for row in rows.iter().filter(|row| row.start) {
        let names: Vec<&str> = EMULATOR_ENV
            .iter()
            .filter(|(_, service, exported)| *exported && *service == row.name)
            .map(|(name, _, _)| *name)
            .collect();
        if names.is_empty() {
            continue;
        }
        out.push(json!({
            "service": row.name,
            "names": names,
            "address": row.address,
        }));
    }
    out
}

fn codebase_json(
    cfg: &RuntimeConfig,
    codebase: &crate::config::FunctionsCodebase,
    trusted: bool,
) -> Value {
    let plan = crate::functions::plan_codebase(cfg, codebase, trusted);
    let (interpreter, version, notes) = match &plan.runner {
        Some(selection) => match (&selection.node, &selection.python_environment) {
            (Some(node), _) => (
                Some(node.program.display().to_string()),
                node.version.clone(),
                node.notes.clone(),
            ),
            (None, Some(environment)) => (
                Some(environment.interpreter.display().to_string()),
                Some(environment.python.clone()),
                Vec::new(),
            ),
            (None, None) => (None, None, Vec::new()),
        },
        None => (None, None, Vec::new()),
    };
    json!({
        "codebase": codebase.codebase,
        "source": plan.source,
        "declaredRuntime": codebase.runtime,
        "language": plan.language,
        "runner": {
            "override": cfg.functions_runner.is_some(),
            "command": plan.runner.as_ref().map(|selection| selection.command.iter().enumerate().map(|(index, arg)| if cfg.functions_runner.is_some() && index > 0 { "[redacted]".to_owned() } else { arg.clone() }).collect::<Vec<_>>()),
            "interpreter": interpreter,
            "version": version,
        },
        "sdk": plan.sdk,
        "notes": notes,
        "error": plan.error,
    })
}

/// Builds the plan as a JSON value (the `--json` output; the text form reads the same value).
/// The second result is the list of problems that make the run fail.
#[allow(clippy::too_many_lines)] // one JSON document, built top to bottom
fn build(
    options: &Options,
    exec: Option<&ExecPlan>,
    command: &str,
    parent: &[(String, String)],
) -> Result<(Value, Vec<String>), CliError> {
    let cfg = &options.cfg;
    let facts = &options.facts;
    let starts = ServiceStarts::resolve(cfg, &options.only).map_err(CliError::refused)?;
    let rows = service_rows(cfg, &options.only, &starts, facts.ui);
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    let inherited = classify_inherited(
        parent,
        &started_services(&rows),
        &options.inherited_env.allow,
    );
    let refused = denied(&inherited, &options.inherited_env);
    for entry in inherited
        .iter()
        .filter(|entry| entry.disposition == Disposition::KeptServiceNotStarted)
    {
        warnings.push(stale_warning(entry));
    }
    if !refused.is_empty() {
        errors.push(denial(&refused));
    }

    let path_rows = path_rows(cfg, facts, &starts);
    warnings.extend(path_rows.iter().filter_map(|row| cwd_warning(row, facts)));

    let mut functions = Vec::new();
    if starts.functions {
        let want_app_check = options.only.app_check_available(&cfg.app_check);
        let codebases = cfg.functions_to_load();
        let trusted = want_app_check
            && (!cfg.app_check.implicit()
                || codebases
                    .iter()
                    .all(|codebase| crate::functions::codebase_callable_trust(codebase).is_ok()));
        for codebase in &codebases {
            let value = codebase_json(cfg, codebase, trusted);
            if let Some(error) = value["error"].as_str() {
                errors.push(error.to_owned());
            }
            functions.push(value);
        }
    }

    let input = facts.canonical_document.clone().unwrap_or(Value::Null);
    let ineffective: Vec<Value> = crate::config::ineffective_settings(&input, &[])
        .into_iter()
        .map(|setting| json!({"key": setting.key, "note": setting.note}))
        .collect();
    let development_defaults: Vec<Value> = cfg
        .development_defaults
        .iter()
        .map(|entry| {
            json!({
                "key": entry["key"],
                "value": entry["value"],
                "source": entry["source"],
                "relaxed": entry["source"] == "default" && !cfg.production_exact,
            })
        })
        .collect();

    let mut exec_json = Value::Null;
    if let Some(exec) = exec {
        exec_json = match &exec.command {
            ExecCommand::Argv(argv) => json!({"argv": argv}),
            ExecCommand::Shell(script) => json!({"script": script}),
        };
    }
    let plan = json!({
        "planVersion": 1,
        "command": command,
        "exec": exec_json,
        "project": {"id": cfg.auth_project, "source": facts.project_source},
        "configuration": {
            "summary": options.config_origin,
            "canonical": facts.canonical.as_ref().map(|path| absolute(path).display().to_string()),
            "firebaseJson": facts.firebase.as_ref().map(|(path, _, _)| absolute(path).display().to_string()),
            "workingDirectory": facts.working_directory.as_ref().map(|dir| dir.display().to_string()),
        },
        "overrides": facts.overrides.iter().map(|(flag, value)| json!({"flag": flag, "value": value})).collect::<Vec<_>>(),
        "profile": match cfg.profile {
            crate::config::CompatibilityProfile::Strict => "strict",
            crate::config::CompatibilityProfile::Emulator => "emulator",
        },
        "productionExact": cfg.production_exact,
        "services": services_json(&rows),
        "environment": {
            "policy": if options.inherited_env.deny { "deny" } else { "warn" },
            "allowed": options.inherited_env.allow,
            "set": environment_set(&rows),
            "inherited": inherited.iter().map(|entry| json!({
                "name": entry.name,
                "service": entry.service,
                "value": entry.value,
                "disposition": entry.disposition.as_str(),
            })).collect::<Vec<_>>(),
            "denied": refused.iter().map(|entry| entry.name).collect::<Vec<_>>(),
        },
        "paths": path_rows.iter().map(|row| json!({
            "setting": row.setting,
            "written": row.written,
            "resolved": row.resolved,
            "base": row.base,
            "baseDirectory": row.base_directory,
        })).collect::<Vec<_>>(),
        "functions": functions,
        "developmentDefaults": development_defaults,
        "ineffective": ineffective,
        "warnings": warnings,
        "errors": errors,
    });
    Ok((plan, errors))
}

#[allow(clippy::too_many_lines)] // one section per key of the plan
fn text(plan: &Value) -> String {
    let mut out = String::new();
    let s = |value: &Value| diagnostic_text(value.as_str().unwrap_or("")).to_string();
    let _ = writeln!(out, "fireemu plan ({})", s(&plan["command"]));
    let _ = writeln!(
        out,
        "project:         {} ({})",
        s(&plan["project"]["id"]),
        s(&plan["project"]["source"])
    );
    let _ = writeln!(
        out,
        "profile:         {}{}",
        s(&plan["profile"]),
        if plan["productionExact"] == true {
            ", productionExact"
        } else {
            ""
        }
    );
    let _ = writeln!(
        out,
        "configuration:   {}",
        s(&plan["configuration"]["summary"])
    );
    if let Some(cwd) = plan["configuration"]["workingDirectory"].as_str() {
        let _ = writeln!(out, "working dir:     {}", diagnostic_text(cwd));
    }
    for entry in plan["overrides"].as_array().into_iter().flatten() {
        let _ = writeln!(
            out,
            "override:        {} {}",
            s(&entry["flag"]),
            s(&entry["value"])
        );
    }
    if let Some(argv) = plan["exec"]["argv"].as_array() {
        let words: Vec<String> = argv.iter().map(s).collect();
        let _ = writeln!(out, "command:         {}", words.join(" "));
    } else if plan["exec"]["script"].is_string() {
        let _ = writeln!(out, "script:          {}", s(&plan["exec"]["script"]));
    }
    out.push_str("\nservices\n");
    for service in plan["services"].as_array().into_iter().flatten() {
        let start = service["start"] == true;
        let detail = if start {
            let mut detail = s(&service["address"]);
            if let Some(note) = service["note"].as_str() {
                let _ = write!(detail, " ({note})");
            }
            detail
        } else {
            s(&service["reason"])
        };
        let _ = writeln!(
            out,
            "  {:<10} {:<5} {}",
            s(&service["name"]),
            if start { "start" } else { "off" },
            detail
        );
    }
    out.push_str("\nenvironment\n");
    for entry in plan["environment"]["set"].as_array().into_iter().flatten() {
        let names: Vec<&str> = entry["names"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let _ = writeln!(
            out,
            "  sets {} = {}",
            names.join(", "),
            s(&entry["address"])
        );
    }
    for entry in plan["environment"]["inherited"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let what = match entry["disposition"].as_str() {
            Some("overridden") => "inherited, replaced by this run's value",
            Some("kept-allowed") => "inherited, kept (allowed)",
            _ => "inherited, kept: this run does not start the service",
        };
        let _ = writeln!(
            out,
            "  {}={} ({what})",
            s(&entry["name"]),
            s(&entry["value"])
        );
    }
    let _ = writeln!(
        out,
        "  inherited emulator variables of services this run does not start: {}",
        s(&plan["environment"]["policy"])
    );
    if !plan["paths"].as_array().is_none_or(Vec::is_empty) {
        out.push_str("\npaths (resolved as the run opens them)\n");
        for row in plan["paths"].as_array().into_iter().flatten() {
            let _ = writeln!(
                out,
                "  {}: {} (written {}, relative to the {}{})",
                s(&row["setting"]),
                s(&row["resolved"]),
                s(&row["written"]),
                s(&row["base"]),
                row["baseDirectory"]
                    .as_str()
                    .map_or_else(String::new, |dir| format!(" {}", diagnostic_text(dir)))
            );
        }
    }
    if !plan["functions"].as_array().is_none_or(Vec::is_empty) {
        out.push_str("\nfunctions\n");
        for codebase in plan["functions"].as_array().into_iter().flatten() {
            let runner = &codebase["runner"];
            let interpreter = if runner["interpreter"].is_string() {
                format!(
                    "{} {} ({})",
                    s(&codebase["language"]),
                    runner["version"]
                        .as_str()
                        .map_or_else(|| "version not probed".to_owned(), ToOwned::to_owned),
                    s(&runner["interpreter"])
                )
            } else if runner["override"] == true {
                "functions.runner override".to_owned()
            } else {
                "no interpreter selected".to_owned()
            };
            let _ = writeln!(
                out,
                "  {}: {} on {}",
                s(&codebase["codebase"]),
                codebase["source"]
                    .as_str()
                    .map_or_else(String::new, |p| diagnostic_text(p).to_string()),
                interpreter
            );
            if let Some(sdk) = codebase["sdk"].as_object() {
                for (name, version) in sdk {
                    let _ = writeln!(out, "      {name} {}", s(version));
                }
            }
            for note in codebase["notes"].as_array().into_iter().flatten() {
                let _ = writeln!(out, "      {}", s(note));
            }
            if let Some(error) = codebase["error"].as_str() {
                let _ = writeln!(out, "      cannot start: {}", diagnostic_text(error));
            }
        }
    }
    out.push_str("\ndevelopment defaults in effect (productionExact switches the relaxed ones to production's value)\n");
    for entry in plan["developmentDefaults"].as_array().into_iter().flatten() {
        let _ = writeln!(
            out,
            "  {} = {} ({}){}",
            s(&entry["key"]),
            s(&entry["value"]),
            s(&entry["source"]),
            if entry["relaxed"] == true {
                " relaxed"
            } else {
                ""
            }
        );
    }
    let ineffective = plan["ineffective"].as_array().cloned().unwrap_or_default();
    if !ineffective.is_empty() {
        out.push_str("\nsettings accepted but with no effect\n");
        for entry in &ineffective {
            let _ = writeln!(out, "  {}", s(&entry["note"]));
        }
    }
    for warning in plan["warnings"].as_array().into_iter().flatten() {
        let _ = writeln!(out, "\nwarning: {}", s(warning));
    }
    for error in plan["errors"].as_array().into_iter().flatten() {
        let _ = writeln!(out, "\nerror: {}", s(error));
    }
    out.push_str(
        "\nNo port was probed and nothing was started; the run binds its ports when it starts.\n",
    );
    out
}

/// `up --plan` and `exec --plan`: prints the plan and starts nothing. Exits 1 when the run
/// would fail for a reason the plan can see (a codebase that cannot start, a variable the
/// policy denies), with the plan still printed.
pub(crate) fn run(
    options: &Options,
    exec: Option<&ExecPlan>,
    command: &str,
    format: PlanFormat,
    parent: &[(String, String)],
) -> ExitCode {
    match build(options, exec, command, parent) {
        Ok((plan, errors)) => {
            match format {
                PlanFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&plan).expect("the plan is JSON")
                ),
                PlanFormat::Text => print!("{}", text(&plan)),
            }
            if errors.is_empty() {
                ExitCode::SUCCESS
            } else {
                for error in &errors {
                    eprintln!("error: {}", diagnostic_text(error));
                }
                ExitCode::FAILURE
            }
        }
        Err(error) => crate::fail(&error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn services() -> Vec<&'static str> {
        let mut services: Vec<&'static str> = EMULATOR_ENV
            .iter()
            .map(|(_, service, _)| *service)
            .collect();
        services.dedup();
        services
    }

    #[test]
    fn redaction_removes_the_credential_and_nothing_else() {
        for (value, expected) in [
            (
                "http://fireemu:s3cret@127.0.0.1:9199",
                "http://***@127.0.0.1:9199",
            ),
            (
                "http://fireemu:s3cret@127.0.0.1:9199/b/o?x=a@b",
                "http://***@127.0.0.1:9199/b/o?x=a@b",
            ),
            ("user:pw@localhost:8080", "***@localhost:8080"),
            ("a@b@host:1", "***@host:1"),
            ("127.0.0.1:8080", "127.0.0.1:8080"),
            ("http://127.0.0.1:9199", "http://127.0.0.1:9199"),
            ("http://[::1]:9199/p@q", "http://[::1]:9199/p@q"),
            ("", ""),
        ] {
            assert_eq!(redact_userinfo(value), expected, "{value}");
        }
    }

    proptest! {
        /// Whatever the credential and the rest of the endpoint look like, the secret is gone.
        #[test]
        fn a_credential_never_survives_redaction(
            scheme in prop_oneof![Just(""), Just("http://"), Just("https://")],
            user in "[A-Za-z0-9._~-]{1,12}",
            secret in "[A-Za-z0-9]{8,24}",
            host in "[a-z0-9.]{1,12}",
            port in 1_u16..,
            tail in prop_oneof![Just(String::new()), "/[a-z/]{0,10}", "\\?[a-z=@]{0,10}"],
        ) {
            let value = format!("{scheme}{user}:{secret}@{host}:{port}{tail}");
            let redacted = redact_userinfo(&value);
            let expected_tail = format!("***@{host}:{port}{tail}");
            prop_assert!(!redacted.contains(&secret));
            prop_assert!(redacted.contains(&expected_tail));
        }

        /// A value without a credential is returned unchanged.
        #[test]
        fn a_value_without_a_credential_is_unchanged(
            scheme in prop_oneof![Just(""), Just("http://")],
            host in "[a-z0-9.]{1,12}",
            port in 1_u16..,
            tail in prop_oneof![Just(String::new()), "/[a-z/]{0,10}"],
        ) {
            let value = format!("{scheme}{host}:{port}{tail}");
            prop_assert_eq!(redact_userinfo(&value), value);
        }

        /// Each inherited variable is classified once, by the documented rule, in table order,
        /// and a variable the parent does not carry is never reported.
        #[test]
        fn classification_follows_the_rule_for_every_combination(
            present in proptest::collection::vec(any::<bool>(), EMULATOR_ENV.len()),
            started_picks in proptest::collection::vec(any::<bool>(), services().len()),
            allowed_picks in proptest::collection::vec(any::<bool>(), EMULATOR_ENV.len()),
            deny in any::<bool>(),
        ) {
            let parent: Vec<(String, String)> = EMULATOR_ENV
                .iter()
                .zip(&present)
                .filter(|(_, present)| **present)
                .map(|((name, _, _), _)| ((*name).to_owned(), format!("host-of-{name}:1")))
                .collect();
            let started: BTreeSet<&'static str> = services()
                .into_iter()
                .zip(&started_picks)
                .filter(|(_, picked)| **picked)
                .map(|(service, _)| service)
                .collect();
            let allow: Vec<String> = EMULATOR_ENV
                .iter()
                .zip(&allowed_picks)
                .filter(|(_, picked)| **picked)
                .map(|((name, _, _), _)| (*name).to_owned())
                .collect();
            let policy = InheritedEnvPolicy { deny, allow: allow.clone() };
            let inherited = classify_inherited(&parent, &started, &allow);

            let expected_names: Vec<&str> = EMULATOR_ENV
                .iter()
                .zip(&present)
                .filter(|(_, present)| **present)
                .map(|((name, _, _), _)| *name)
                .collect();
            prop_assert_eq!(inherited.iter().map(|entry| entry.name).collect::<Vec<_>>(), expected_names);
            for entry in &inherited {
                let expected = if started.contains(entry.service) {
                    Disposition::Overridden
                } else if allow.iter().any(|name| name == entry.name) {
                    Disposition::KeptAllowed
                } else {
                    Disposition::KeptServiceNotStarted
                };
                prop_assert_eq!(entry.disposition, expected, "{}", entry.name);
            }
            let refused: Vec<&str> = denied(&inherited, &policy).iter().map(|entry| entry.name).collect();
            let stale: Vec<&str> = inherited
                .iter()
                .filter(|entry| entry.disposition == Disposition::KeptServiceNotStarted)
                .map(|entry| entry.name)
                .collect();
            prop_assert_eq!(refused, if deny { stale } else { Vec::new() });
        }
    }

    #[test]
    fn the_allowed_names_are_exactly_the_table() {
        let names: Vec<String> = EMULATOR_ENV
            .iter()
            .map(|(name, _, _)| (*name).to_owned())
            .collect();
        assert!(check_allowed_names(&names).is_ok());
        for refused in [
            "",
            "PUBSUB_EMULATOR_HOSTT",
            "pubsub_emulator_host",
            "GCLOUD_PROJECT",
            " PUBSUB_EMULATOR_HOST",
            "PUBSUB_EMULATOR_HOST ",
        ] {
            assert!(
                check_allowed_names(&[refused.to_owned()]).is_err(),
                "{refused:?}"
            );
        }
        assert!(check_allowed_names(&[]).is_ok());
    }

    /// The table of variables and the variables `exec` really exports are one list: a service
    /// that gains a variable in `child_environment` must gain a row here, or the plan and the
    /// inherited-variable policy would not know it.
    #[test]
    fn the_table_is_what_child_environment_exports() {
        let loopback = |port: u16| Some(std::net::SocketAddr::from(([127, 0, 0, 1], port)));
        let addrs = crate::BoundAddrs {
            firestore: loopback(8080),
            auth: loopback(9099),
            storage: loopback(9199),
            functions: loopback(5001),
            hosting: loopback(5000),
            hosting_sites: Vec::new(),
            eventarc: loopback(9299),
            tasks: loopback(9499),
            pubsub: loopback(8085),
            database: loopback(9000),
            hub: loopback(4400),
            ui: loopback(4000),
            logging: loopback(4500),
            control: std::net::SocketAddr::from(([127, 0, 0, 1], 9099)),
        };
        let cfg = RuntimeConfig::default();
        let only = Selection::default();
        assert!(
            only.app_check_available(&cfg.app_check),
            "the default run serves App Check"
        );
        let exported: BTreeSet<String> = crate::child_environment(&cfg, &only, &addrs, "t", "c")
            .into_iter()
            .map(|(name, _)| name)
            .filter(|name| {
                !matches!(
                    name.as_str(),
                    "GOOGLE_CLOUD_PROJECT"
                        | "GCLOUD_PROJECT"
                        | "FIREEMU_CONTROL_TOKEN"
                        | "FIREEMU_CONTROL_URL"
                        | "FIREBASE_CONFIG"
                )
            })
            .collect();
        let table: BTreeSet<String> = EMULATOR_ENV
            .iter()
            .filter(|(_, _, exported)| *exported)
            .map(|(name, _, _)| (*name).to_owned())
            .collect();
        assert_eq!(exported, table);
    }

    #[test]
    fn sdk_emulator_variables_are_in_the_table() {
        const NOT_ENV_VARIABLES: &[(&str, &str)] = &[];
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/node_modules");
        if !root.join("firebase-admin").exists()
            && !root.join("firebase-tools/lib/emulator").exists()
            && cfg!(windows)
        {
            // The Windows CI job does not install the conformance dependencies.
            eprintln!("skipped: conformance/node_modules is not installed on this Windows job (the Windows test job does not run pnpm install); the scan runs on ubuntu and macOS");
            return;
        }
        assert!(root.join("firebase-admin").exists() || root.join("firebase-tools/lib/emulator").exists(), "the pinned conformance install is required (pnpm -C conformance install --frozen-lockfile)");
        let pattern = regex::Regex::new(
            r#"["']([A-Z][A-Z0-9_]*_EMULATOR_(?:HOST|ADDRESS)|FIREBASE_EMULATOR_HUB)["']"#,
        )
        .unwrap();
        let mut names = BTreeSet::new();
        for directory in [
            "firebase-admin",
            "firebase-functions",
            "firebase-tools/lib/emulator",
            "@firebase/data-connect",
            "@firebase/database",
            "@firebase/firestore",
            "@firebase/storage",
            "@google-cloud/firestore",
            "@google-cloud/storage",
            "@google-cloud/pubsub",
        ] {
            let mut pending = vec![(root.join(directory), 0)];
            while let Some((path, depth)) = pending.pop() {
                if depth > 8 {
                    continue;
                }
                let Ok(entries) = std::fs::read_dir(path) else {
                    continue;
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        if entry.file_name() != "node_modules" {
                            pending.push((path, depth + 1));
                        }
                    } else {
                        if !path
                            .extension()
                            .is_some_and(|ext| matches!(ext.to_str(), Some("js" | "cjs" | "mjs")))
                        {
                            continue;
                        }
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            for captures in pattern.captures_iter(&content) {
                                names.insert(captures[1].to_owned());
                            }
                        }
                    }
                }
            }
        }
        assert!(names.contains("DATA_CONNECT_EMULATOR_HOST"));
        assert!(names.contains("FIRESTORE_EMULATOR_HOST"));
        for name in &names {
            assert!(
                EMULATOR_ENV
                    .iter()
                    .any(|(known, _, _)| name.as_str() == *known)
                    || NOT_ENV_VARIABLES
                        .iter()
                        .any(|(exception, _)| name.as_str() == *exception),
                "unknown emulator variable: {name}"
            );
        }
    }

    #[test]
    fn the_post_bind_check_warns_only_about_hub_and_logging() {
        let started = BTreeSet::from(["hub"]);
        let parent: Vec<(String, String)> = [
            "FIREBASE_EMULATOR_HUB",
            "FIREBASE_LOGGING_EMULATOR_HOST",
            "PUBSUB_EMULATOR_HOST",
            "DATA_CONNECT_EMULATOR_HOST",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), "localhost:1".to_owned()))
        .collect();
        let inherited = classify_inherited(&parent, &started, &[]);
        let warnings = bound_warnings(&inherited);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].starts_with("FIREBASE_LOGGING_EMULATOR_HOST=localhost:1 "));
        // An allowed best-effort variable is not warned about either.
        let allowed = classify_inherited(
            &parent,
            &started,
            &["FIREBASE_LOGGING_EMULATOR_HOST".to_owned()],
        );
        assert!(bound_warnings(&allowed).is_empty());
    }

    #[test]
    fn bound_listener_policy_tracks_hub_and_logging() {
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], 1234));
        for hub in [false, true] {
            for logging in [false, true] {
                for deny in [false, true] {
                    let addrs = crate::BoundAddrs {
                        firestore: None,
                        auth: None,
                        storage: None,
                        functions: None,
                        hosting: None,
                        hosting_sites: Vec::new(),
                        eventarc: None,
                        tasks: None,
                        pubsub: None,
                        database: None,
                        hub: hub.then_some(address),
                        ui: None,
                        logging: logging.then_some(address),
                        control: address,
                    };
                    let parent = vec![
                        ("FIREBASE_EMULATOR_HUB".to_owned(), "localhost:1".to_owned()),
                        (
                            "FIREBASE_LOGGING_EMULATOR_HOST".to_owned(),
                            "localhost:1".to_owned(),
                        ),
                    ];
                    let result = check_bound_listeners(
                        &InheritedEnvPolicy {
                            deny,
                            allow: vec![],
                        },
                        &addrs,
                        false,
                        true,
                        &parent,
                    );
                    assert_eq!(result.is_err(), deny && (!hub || !logging));
                    if let Err(message) = result {
                        assert_eq!(message.contains("FIREBASE_EMULATOR_HUB"), !hub);
                        assert_eq!(message.contains("FIREBASE_LOGGING_EMULATOR_HOST"), !logging);
                    }
                }
            }
        }
    }

    fn sample_selection(picks: &[bool], explicit: bool) -> Selection {
        Selection {
            firestore: picks[0],
            auth: picks[1],
            storage: picks[2],
            functions: picks[3],
            hosting: picks[4],
            eventarc: false,
            tasks: false,
            pubsub: picks[5],
            database: picks[6],
            appcheck: picks[7],
            explicit,
            functions_codebase: None,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// The plan and the listener binding read one decision: for every selection and
        /// configuration, a service the plan says starts has a listener and one it says does not
        /// has none, and a selection one refuses the other refuses.
        #[test]
        fn the_plan_and_the_listener_binding_start_the_same_services(
            picks in proptest::collection::vec(any::<bool>(), 8),
            explicit in any::<bool>(),
            functions_source in any::<bool>(),
            hosting in any::<bool>(),
            pubsub_enabled in any::<bool>(),
            database_enabled in any::<bool>(),
        ) {
            let only = sample_selection(&picks, explicit);
            let mut cfg = RuntimeConfig::default();
            for address in [
                &mut cfg.firestore_addr, &mut cfg.http_addr, &mut cfg.storage_addr,
                &mut cfg.functions_addr, &mut cfg.hosting_addr, &mut cfg.eventarc_addr,
                &mut cfg.tasks_addr, &mut cfg.pubsub_addr, &mut cfg.database_addr,
            ] {
                *address = "127.0.0.1:0".to_owned();
            }
            cfg.hosting_addr_explicit = true;
            cfg.eventarc_addr_explicit = true;
            cfg.tasks_addr_explicit = true;
            // The Hub and the Logging emulator are best effort and not part of the decision.
            cfg.hub_addr = "127.0.0.1:0".to_owned();
            cfg.hub_addr_explicit = true;
            cfg.logging_enabled = false;
            cfg.pubsub_enabled = pubsub_enabled;
            cfg.database_enabled = database_enabled;
            cfg.functions_source = functions_source.then(|| ".".to_owned());
            cfg.hosting = hosting.then(|| {
                vec![crate::hosting::Config::parse(&json!({"public": "public"}), Path::new(".")).unwrap()]
            });

            let decided = ServiceStarts::resolve(&cfg, &only);
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let bound = runtime.block_on(crate::bind_listeners_with(&cfg, &only, crate::kernel_pick));
            match (decided, bound) {
                (Err(_), Err(_)) => {}
                (Ok(starts), Ok(listeners)) => {
                    prop_assert_eq!(starts.firestore, listeners.firestore.is_some());
                    prop_assert_eq!(starts.auth, listeners.auth_selected);
                    prop_assert_eq!(starts.storage, listeners.storage.is_some());
                    prop_assert_eq!(starts.functions, listeners.functions.is_some());
                    prop_assert_eq!(starts.hosting, !listeners.hosting.is_empty());
                    prop_assert_eq!(starts.eventarc, listeners.eventarc.is_some());
                    prop_assert_eq!(starts.tasks, listeners.tasks.is_some());
                    prop_assert_eq!(starts.pubsub, listeners.pubsub.is_some());
                    prop_assert_eq!(starts.database, listeners.database.is_some());
                    // The rows the plan prints carry the same flags.
                    let rows = service_rows(&cfg, &only, &starts, crate::UiSelection::Default);
                    let row = |name: &str| rows.iter().find(|row| row.name == name).unwrap().start;
                    prop_assert_eq!(row("firestore"), listeners.firestore.is_some());
                    prop_assert_eq!(row("functions"), listeners.functions.is_some());
                    prop_assert_eq!(row("pubsub"), listeners.pubsub.is_some());
                }
                (decided, bound) => prop_assert!(false, "disagree: {:?} vs {:?}", decided.map(|_| ()), bound.map(|_| ())),
            }
        }
    }
}
