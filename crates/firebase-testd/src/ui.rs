//! The Emulator UI listener (`--ui-port`, default 4000): the embedded app and its API.

use std::sync::{Arc, OnceLock};

use ftd_adapter_functions::runtime::FunctionsRuntime;
use ftd_adapter_grpc::local::LocalBackend;
use ftd_adapter_grpc::rest::RestState;
use ftd_adapter_http::control::ControlState;
use ftd_adapter_http::identity_toolkit::AuthState;
use ftd_adapter_http::storage::StorageState;
use ftd_adapter_ui::{RuntimeInfo, UiState};

use crate::config::RuntimeConfig;

/// Port of the UI listener as given on the command line; `0` disables the UI.
static UI_PORT: OnceLock<u16> = OnceLock::new();

/// The default port (the Firebase Emulator UI's).
pub const DEFAULT_PORT: u16 = 4000;

/// Records `--ui-port` (the first value wins).
pub fn set_port(port: u16) {
    let _ = UI_PORT.set(port);
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
    let (port, explicit) = UI_PORT.get().map_or((DEFAULT_PORT, false), |p| (*p, true));
    if port == 0 {
        return Ok(Ui::Disabled);
    }
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
    /// Control API.
    pub control: Arc<ControlState>,
    /// Functions runtime, when configured.
    pub functions: Option<Arc<FunctionsRuntime>>,
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
    Arc::new(UiState {
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
        },
        rest: parts.rest,
        backend: parts.backend,
        auth: parts.auth,
        storage: parts.storage,
        control: parts.control,
        functions: parts.functions,
    })
}
