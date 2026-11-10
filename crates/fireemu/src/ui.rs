//! The Emulator UI listener (`--ui-port`, default 4000): the embedded app and its API.

use std::sync::{Arc, OnceLock};

use fireemu_adapter_functions::runtime::FunctionsRuntime;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rest::RestState;
use fireemu_adapter_http::control::ControlState;
use fireemu_adapter_http::identity_toolkit::AuthState;
use fireemu_adapter_http::storage::StorageState;
use fireemu_adapter_ui::{
    AppCheckInfo, CodebaseInfo, HostingInfo, HostsInfo, RuntimeInfo, UiState,
};

use crate::config::{AppCheckService, RuntimeConfig, Selection};

/// Explicit listener selection: `None` disables the UI, `Some(0)` requests an OS-assigned port.
static UI_PORT: OnceLock<Option<u16>> = OnceLock::new();

/// The default port (the Firebase Emulator UI's).
pub const DEFAULT_PORT: u16 = 4000;

/// Records `--ui-port` (the first value wins).
pub fn set_port(port: u16) {
    let _ = UI_PORT.set((port != 0).then_some(port));
}

/// Requests an OS-assigned port without disabling the UI.
pub fn set_auto_port() {
    let _ = UI_PORT.set(Some(0));
}

/// The outcome of binding the UI listener.
pub enum Ui {
    /// Bound; serve it.
    Bound(tokio::net::TcpListener),
    /// `--ui-port 0`.
    Disabled,
    /// The default port is busy: the UI is off, with the note to print after the banner.
    Unavailable(String),
}

/// Binds the UI listener. Without `--ui-port` the default port is tried and a busy port
/// only disables the UI; an explicit port that cannot be bound is an error.
pub async fn bind() -> Result<Ui, String> {
    let (port, explicit) = UI_PORT
        .get()
        .map_or((Some(DEFAULT_PORT), false), |p| (*p, true));
    let Some(port) = port else {
        return Ok(Ui::Disabled);
    };
    let addr = format!("127.0.0.1:{port}");
    match tokio::net::TcpListener::bind(&addr).await {
        Ok(listener) => Ok(Ui::Bound(listener)),
        Err(e) if explicit => Err(format!("bind {addr}: {e}")),
        Err(e) => Ok(Ui::Unavailable(format!(
            "  ui:               disabled (cannot bind {addr}: {e}; choose one with --ui-port <n>)"
        ))),
    }
}

/// Everything the UI state is built from.
pub struct Parts<'a> {
    /// Runtime configuration.
    pub cfg: &'a RuntimeConfig,
    /// The selected services (`--only`): a configured baseline mode only applies while both
    /// App Check and the product itself are selected, so the page shows what the runtime is
    /// actually doing rather than what the file asked for.
    pub only: &'a Selection,
    /// The control token browser pages must present.
    pub control_token: String,
    /// Firestore REST layer.
    pub rest: Arc<RestState>,
    /// Firestore backend.
    pub backend: Arc<LocalBackend>,
    /// Identity Toolkit.
    pub auth: Arc<AuthState>,
    /// Storage.
    pub storage: Arc<StorageState>,
    /// The actual RTDB listener and trusted instance ownership, when enabled.
    pub database: Option<fireemu_adapter_ui::database::DatabaseEndpoint>,
    /// Control API.
    pub control: Arc<ControlState>,
    /// Functions runtime, when configured.
    pub functions: Option<Arc<FunctionsRuntime>>,
    /// The served Hosting site, when Hosting runs.
    pub hosting: Option<HostingInfo>,
    /// App Check, when enabled: the UI fronts its privileged debug-token management.
    pub app_check: Option<Arc<fireemu_adapter_http::app_check::AppCheckState>>,
    /// Bound addresses: Firestore, HTTP (Auth + control), Storage, Functions, UI.
    pub addrs: (
        std::net::SocketAddr,
        std::net::SocketAddr,
        std::net::SocketAddr,
        Option<std::net::SocketAddr>,
        std::net::SocketAddr,
    ),
}

/// The shared UI state.
pub fn state(parts: Parts<'_>) -> Arc<UiState> {
    let (firestore, http, storage, functions, ui) = parts.addrs;
    let app_check_info = parts.app_check.as_ref().map(|_| AppCheckInfo {
        modes: [
            ("auth", AppCheckService::Auth),
            ("firestore", AppCheckService::Firestore),
            ("storage", AppCheckService::Storage),
        ]
        .into_iter()
        .map(|(name, service)| {
            (
                name.to_owned(),
                parts
                    .only
                    .app_check_mode(&parts.cfg.app_check, service)
                    .as_config_str()
                    .to_owned(),
            )
        })
        .collect(),
    });
    Arc::new(UiState {
        database: parts.database,
        stream_limiter: Arc::new(fireemu_adapter_ui::sse::StreamLimiter::default()),
        control_token: parts.control_token,
        info: RuntimeInfo {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            project: parts.cfg.auth_project.clone(),
            edition: parts.cfg.edition.as_config_str().to_owned(),
            firestore_addr: firestore.to_string(),
            http_addr: http.to_string(),
            storage_addr: storage.to_string(),
            functions_addr: functions.map(|a| a.to_string()),
            functions_source: parts.cfg.functions_source.clone(),
            ui_addr: ui.to_string(),
            rules_enforced: parts.cfg.rules_enforced,
            clock_pinned: parts.cfg.clock_start_pinned,
            clock_frozen: parts.cfg.clock_frozen(),
            hosts: hosts_info(parts.cfg),
            hosting: parts.hosting,
            codebases: codebases_info(parts.cfg),
            app_check: app_check_info,
        },
        rest: parts.rest,
        backend: parts.backend,
        auth: parts.auth,
        storage: parts.storage,
        control: parts.control,
        functions: parts.functions,
        app_check: parts.app_check,
    })
}

/// The `Host` names the product listeners answer, as configured and by default.
fn hosts_info(cfg: &RuntimeConfig) -> HostsInfo {
    HostsInfo {
        allowed: cfg.allowed_host_entries(),
        allow_non_loopback_hosts: cfg.allow_non_loopback_hosts,
        default_names: fireemu_core_session::host_guard::default_names()
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        default_suffixes: fireemu_core_session::host_guard::default_suffixes()
            .iter()
            .map(|suffix| (*suffix).to_owned())
            .collect(),
    }
}

/// The loader of each codebase this run loads, as the launcher chose it.
fn codebases_info(cfg: &RuntimeConfig) -> Vec<CodebaseInfo> {
    cfg.functions_to_load()
        .iter()
        .map(|codebase| CodebaseInfo {
            name: codebase.codebase.clone(),
            language: match crate::python_functions::codebase_language(codebase) {
                crate::config::RuntimeLanguage::Node => "node",
                crate::config::RuntimeLanguage::Python => "python",
            }
            .to_owned(),
            declared: codebase.runtime.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{codebases_info, hosts_info};
    use crate::config::{FunctionsCodebase, RuntimeConfig};
    use fireemu_core_session::host_guard::AllowedHost;

    fn codebase(name: &str, source: &str, runtime: Option<&str>) -> FunctionsCodebase {
        FunctionsCodebase {
            codebase: name.to_owned(),
            source: source.to_owned(),
            runtime: runtime.map(str::to_owned),
            ignore: Vec::new(),
        }
    }

    #[test]
    fn each_loaded_codebase_reports_the_loader_the_launcher_picks_in_load_order() {
        let scratch =
            std::env::temp_dir().join(format!("fireemu-ui-codebases-{}", std::process::id()));
        let python_only = scratch.join("python-only");
        let both = scratch.join("both");
        std::fs::create_dir_all(&python_only).unwrap();
        std::fs::create_dir_all(&both).unwrap();
        std::fs::write(python_only.join("requirements.txt"), "firebase-functions\n").unwrap();
        std::fs::write(both.join("requirements.txt"), "firebase-functions\n").unwrap();
        std::fs::write(both.join("package.json"), "{}").unwrap();
        let cfg = RuntimeConfig {
            functions_loaded: vec![
                codebase("declared-py", "/nonexistent/a", Some("python312")),
                codebase("declared-js", "/nonexistent/b", Some("nodejs22")),
                codebase("sniffed-py", python_only.to_str().unwrap(), None),
                codebase("sniffed-js", both.to_str().unwrap(), None),
                codebase("bare", "/nonexistent/c", None),
            ],
            ..RuntimeConfig::default()
        };
        let seen: Vec<(String, String, Option<String>)> = codebases_info(&cfg)
            .into_iter()
            .map(|c| (c.name, c.language, c.declared))
            .collect();
        let _ = std::fs::remove_dir_all(&scratch);
        let expected = |name: &str, language: &str, declared: Option<&str>| {
            (
                name.to_owned(),
                language.to_owned(),
                declared.map(str::to_owned),
            )
        };
        assert_eq!(
            seen,
            vec![
                expected("declared-py", "python", Some("python312")),
                expected("declared-js", "node", Some("nodejs22")),
                expected("sniffed-py", "python", None),
                expected("sniffed-js", "node", None),
                expected("bare", "node", None),
            ]
        );
    }

    #[test]
    fn the_host_names_are_the_configured_entries_the_flag_and_the_guards_defaults() {
        let cfg = RuntimeConfig {
            allowed_hosts: vec![
                AllowedHost::parse("CI.example").unwrap(),
                AllowedHost::parse(".svc.cluster.local").unwrap(),
            ],
            allow_non_loopback_hosts: true,
            ..RuntimeConfig::default()
        };
        let info = hosts_info(&cfg);
        assert_eq!(info.allowed, ["ci.example", ".svc.cluster.local"]);
        assert!(info.allow_non_loopback_hosts);
        assert!(info.default_names.iter().any(|n| n == "localhost"));
        assert!(info.default_suffixes.iter().any(|s| s == ".internal"));
        let plain = hosts_info(&RuntimeConfig::default());
        assert!(plain.allowed.is_empty() && !plain.allow_non_loopback_hosts);
    }
}
