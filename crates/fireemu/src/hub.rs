//! The Emulator Hub: the discovery and control surface official tooling looks for.
//!
//! `@firebase/rules-unit-testing`, the Emulator UI and `firebase emulators:exec` scripts all
//! find a running suite the same way: they read `FIREBASE_EMULATOR_HUB` (or the locator file
//! the Hub writes into the OS temp directory), ask it `GET /emulators`, and take each
//! product's host and port from the answer. Serving that contract is what lets an existing
//! project point its tests at fireemu without naming a single port.
//!
//! Routes (the pinned `firebase-tools@15.28.2` `src/emulator/hub.ts` set):
//!
//! ```text
//! GET  /                                     the locator plus this listener's host and port
//! GET  /emulators                            every running emulator, keyed by name
//! PUT  /functions/disableBackgroundTriggers   {"enabled": false}
//! PUT  /functions/enableBackgroundTriggers    {"enabled": true}
//! POST /_admin/export                        writes an export directory (emulators:export)
//! ```
//!
//! # Background triggers
//!
//! Disabling background triggers **drops** the events that would have been delivered; it does
//! not hold them for a later replay. That is exactly what the official emulator does: its
//! background-trigger route answers `204 "Background triggers are currently disabled."` and
//! discards the body (`functionsEmulator.ts`, the `!record.enabled` gate), while the producing
//! emulators keep posting. Re-enabling reloads the triggers rather than flushing a queue, so
//! nothing that happened while they were off is ever delivered retroactively. A test that
//! disables triggers, seeds data and re-enables therefore sees no invocations from the seed --
//! which is the property the feature exists for.
//!
//! HTTPS, callable and scheduled functions are unaffected, again as upstream: only records
//! carrying an event trigger are disabled.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use fireemu_adapter_functions::runtime::FunctionsRuntime;

/// The project ID the locator file uses when none is configured, as upstream.
const MISSING_PROJECT_PLACEHOLDER: &str = "demo-no-project";

/// One emulator entry of `GET /emulators`.
pub struct EmulatorInfo {
    /// The official emulator name (`firestore`, `auth`, `storage`, `functions`, `hub`, `ui`).
    pub name: &'static str,
    /// The bound address.
    pub addr: SocketAddr,
    /// The process serving it. Upstream reports one only for the emulators that run in their
    /// own process; every fireemu surface is served by this process, so every entry carries it.
    pub pid: u32,
}

impl EmulatorInfo {
    /// The upstream JSON shape: `name`, `host`, `port`, `pid` and the `listen` specs.
    fn to_json(&self) -> Value {
        let host = self.addr.ip().to_string();
        json!({
            "name": self.name,
            "host": host,
            "port": self.addr.port(),
            "pid": self.pid,
            "listen": [{
                "address": host,
                "family": if self.addr.is_ipv6() { "IPv6" } else { "IPv4" },
                "port": self.addr.port(),
            }],
        })
    }
}

/// Writes an export directory from the live state. `main` implements it; the Hub only knows
/// that `POST /_admin/export` calls it.
pub trait ExportRunner: Send + Sync {
    /// Writes the export at `path`, attributing it to `initiated_by`.
    fn export(&self, path: &std::path::Path, initiated_by: &str) -> Result<(), String>;
}

/// Everything the Hub answers from.
pub struct HubState {
    /// The project the locator file is named after.
    pub project: String,
    /// The Hub's own bound address.
    pub addr: SocketAddr,
    /// Every running emulator, in a stable order.
    pub emulators: Vec<EmulatorInfo>,
    /// The functions runtime, when one is loaded: the background-trigger switch.
    pub functions: Option<Arc<FunctionsRuntime>>,
    /// The export writer `POST /_admin/export` drives.
    pub export: Option<Arc<dyn ExportRunner>>,
}

impl HubState {
    /// The locator document: the version, the origins the Hub answers on, and this process.
    fn locator(&self) -> Value {
        let host = self.addr.ip().to_string();
        let origin = if self.addr.is_ipv6() {
            format!("http://[{host}]:{}", self.addr.port())
        } else {
            format!("http://{host}:{}", self.addr.port())
        };
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "origins": [origin],
            "pid": std::process::id(),
        })
    }

    /// `GET /emulators`: an object keyed by emulator name, as upstream returns it.
    fn running(&self) -> Value {
        let mut map = serde_json::Map::new();
        for info in &self.emulators {
            map.insert(info.name.to_owned(), info.to_json());
        }
        Value::Object(map)
    }
}

/// The locator file `hub-<project>.json` in the OS temp directory, removed when the daemon
/// stops.
///
/// A locator whose recorded process is still alive is left alone and this daemon writes
/// none: two suites for one project would otherwise fight over the same file and the
/// second one would capture discovery from the first. Removal is likewise conditional on
/// the file still naming this process, so a daemon that outlives another one's exit keeps
/// its own locator.
pub struct Locator {
    /// The file, when this daemon wrote it.
    path: Option<PathBuf>,
}

impl Locator {
    /// The path upstream uses: `<temp dir>/hub-<project>.json`.
    #[must_use]
    pub fn path_for(project: &str) -> PathBuf {
        let project = if project.is_empty() {
            MISSING_PROJECT_PLACEHOLDER
        } else {
            project
        };
        std::env::temp_dir().join(format!("hub-{project}.json"))
    }

    /// Writes the locator unless a live one is already there. Returns the notice to print
    /// when it declined, so the operator learns that discovery still points elsewhere.
    pub fn write(state: &HubState) -> (Self, Option<String>) {
        let path = Self::path_for(&state.project);
        if let Some(pid) = existing_live_pid(&path) {
            return (
                Self { path: None },
                Some(format!(
                    "another fireemu or Firebase emulator suite for {} is still running (pid {pid}); {} was left alone, so FIREBASE_EMULATOR_HUB discovery keeps pointing at it",
                    state.project,
                    path.display()
                )),
            );
        }
        let body = serde_json::to_string(&state.locator()).unwrap_or_default();
        match std::fs::write(&path, body) {
            Ok(()) => (Self { path: Some(path) }, None),
            Err(e) => (
                Self { path: None },
                Some(format!("cannot write {}: {e}", path.display())),
            ),
        }
    }
}

impl Drop for Locator {
    fn drop(&mut self) {
        let Some(path) = &self.path else {
            return;
        };
        // Only this daemon's own locator is removed: a file another process has since
        // claimed must survive.
        if existing_pid(path) == Some(std::process::id()) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The `pid` a locator file records, if it parses.
fn existing_pid(path: &std::path::Path) -> Option<u32> {
    let text = std::fs::read_to_string(path).ok()?;
    let json: Value = serde_json::from_str(&text).ok()?;
    json.get("pid")
        .and_then(Value::as_u64)
        .and_then(|p| u32::try_from(p).ok())
}

/// The `pid` of a locator file whose process still exists.
fn existing_live_pid(path: &std::path::Path) -> Option<u32> {
    let pid = existing_pid(path)?;
    // `kill -0` reports existence without signalling; a permission error still means alive.
    let alive = std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    alive.then_some(pid)
}

/// A JSON response with the upstream two-space indentation.
fn json_response(status: StatusCode, body: &Value, origin: Option<&str>) -> Response<Full<Bytes>> {
    let text = serde_json::to_string_pretty(body).unwrap_or_else(|_| "{}".to_owned());
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store");
    if let Some(origin) = origin {
        builder = builder
            .header("access-control-allow-origin", origin)
            .header("access-control-allow-methods", "GET, PUT, POST, OPTIONS")
            .header("access-control-allow-headers", "content-type")
            .header("access-control-allow-private-network", "true");
    }
    builder
        .body(Full::new(Bytes::from(text)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// Whether the `Host` header names loopback. The Hub can disable background triggers, so a
/// page on a routable name must not reach it through DNS rebinding; every fireemu listener
/// applies the same rule.
fn host_is_local(req: &Request<Incoming>) -> bool {
    let Some(host) = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
    else {
        // HTTP/1.0 without a Host header cannot be a browser request.
        return true;
    };
    let name = host.rsplit_once(':').map_or(host, |(h, _)| h);
    let name = name.trim_start_matches('[').trim_end_matches(']');
    matches!(name, "localhost" | "127.0.0.1" | "::1") || name.starts_with("127.")
}

async fn respond(
    state: Arc<HubState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let origin = req
        .headers()
        .get(hyper::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if !host_is_local(&req) {
        return Ok(json_response(
            StatusCode::FORBIDDEN,
            &json!({"error": "the Emulator Hub answers loopback Hosts only"}),
            origin.as_deref(),
        ));
    }
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    if method == Method::OPTIONS {
        return Ok(json_response(
            StatusCode::NO_CONTENT,
            &json!({}),
            origin.as_deref(),
        ));
    }
    if (&method, path.as_str()) == (&Method::POST, "/_admin/export") {
        return Ok(run_export(&state, req, origin.as_deref()).await);
    }
    let origin = origin.as_deref();
    let response = match (&method, path.as_str()) {
        (&Method::GET, "/") => {
            let mut locator = state.locator();
            if let Some(obj) = locator.as_object_mut() {
                obj.insert("host".to_owned(), json!(state.addr.ip().to_string()));
                obj.insert("port".to_owned(), json!(state.addr.port()));
            }
            json_response(StatusCode::OK, &locator, origin)
        }
        (&Method::GET, "/emulators") => json_response(StatusCode::OK, &state.running(), origin),
        (&Method::PUT, "/functions/disableBackgroundTriggers") => {
            set_background_triggers(&state, false, origin)
        }
        (&Method::PUT, "/functions/enableBackgroundTriggers") => {
            set_background_triggers(&state, true, origin)
        }
        _ => json_response(
            StatusCode::NOT_FOUND,
            &json!({"error": format!("{method} {path} is not a Emulator Hub route")}),
            origin,
        ),
    };
    Ok(response)
}

/// `POST /_admin/export`: the route `firebase emulators:export` and `--export-on-exit`
/// drive.
///
/// The body is the official one (`hub.ts`): `{"path": "<absolute directory>", "initiatedBy":
/// "<who asked>"}`. A request that carries an `Origin` header is refused exactly as upstream
/// refuses it -- a page must not be able to make the suite write its state to disk.
async fn run_export(
    state: &Arc<HubState>,
    req: Request<Incoming>,
    origin: Option<&str>,
) -> Response<Full<Bytes>> {
    if origin.is_some() {
        return json_response(
            StatusCode::FORBIDDEN,
            &json!({"message": "Export cannot be triggered by external callers."}),
            origin,
        );
    }
    let Some(runner) = &state.export else {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({"message": "No running emulators support import/export."}),
            origin,
        );
    };
    let body = match http_body_util::BodyExt::collect(req.into_body()).await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &json!({"message": format!("the export request body could not be read: {e}")}),
                origin,
            )
        }
    };
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &json!({"message": format!("the export request body is not JSON: {e}")}),
                origin,
            )
        }
    };
    let Some(path) = parsed.get("path").and_then(Value::as_str) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({"message": "the export request has no \"path\""}),
            origin,
        );
    };
    let initiated_by = parsed
        .get("initiatedBy")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    match runner.export(std::path::Path::new(path), initiated_by) {
        Ok(()) => json_response(StatusCode::OK, &json!({"message": "OK"}), origin),
        Err(message) => json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &json!({ "message": message }),
            origin,
        ),
    }
}

/// The enable / disable background-trigger routes.
fn set_background_triggers(
    state: &HubState,
    enabled: bool,
    origin: Option<&str>,
) -> Response<Full<Bytes>> {
    let Some(runtime) = &state.functions else {
        return json_response(
            StatusCode::BAD_REQUEST,
            &json!({"error": "The Cloud Functions emulator is not running."}),
            origin,
        );
    };
    runtime.set_background_triggers(enabled);
    json_response(StatusCode::OK, &json!({"enabled": enabled}), origin)
}

/// Serves the Hub on `listener` until the task is aborted.
pub async fn serve(listener: TcpListener, state: Arc<HubState>) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| respond(state.clone(), req));
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}

/// Binds the Hub listener. Like the UI's, the default port is best effort -- a busy 4400
/// only disables discovery -- while a port that was asked for explicitly must be free.
pub async fn bind(addr: &str, explicit: bool) -> Result<Option<TcpListener>, String> {
    let port = addr
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok());
    if port == Some(0) && explicit {
        return Ok(None);
    }
    match TcpListener::bind(addr).await {
        Ok(listener) => Ok(Some(listener)),
        Err(e) if explicit => Err(format!("bind {addr}: {e}")),
        Err(_) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> HubState {
        HubState {
            project: "demo-app".to_owned(),
            addr: "127.0.0.1:4400".parse().unwrap(),
            emulators: vec![
                EmulatorInfo {
                    name: "firestore",
                    addr: "127.0.0.1:8080".parse().unwrap(),
                    pid: 7,
                },
                EmulatorInfo {
                    name: "hub",
                    addr: "127.0.0.1:4400".parse().unwrap(),
                    pid: 7,
                },
            ],
            functions: None,
            export: None,
        }
    }

    #[test]
    fn the_running_map_is_keyed_by_emulator_name_with_the_official_fields() {
        let running = state().running();
        let firestore = &running["firestore"];
        assert_eq!(firestore["name"], "firestore");
        assert_eq!(firestore["host"], "127.0.0.1");
        assert_eq!(firestore["port"], 8080);
        assert_eq!(firestore["pid"], 7);
        assert_eq!(firestore["listen"][0]["address"], "127.0.0.1");
        assert_eq!(firestore["listen"][0]["family"], "IPv4");
        assert_eq!(firestore["listen"][0]["port"], 8080);
        // The Hub lists itself, exactly as the official one does.
        assert_eq!(running["hub"]["port"], 4400);
    }

    #[test]
    fn the_locator_carries_the_version_the_origins_and_this_process() {
        let locator = state().locator();
        assert_eq!(locator["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(locator["origins"][0], "http://127.0.0.1:4400");
        assert_eq!(locator["pid"], std::process::id());
    }

    #[test]
    fn the_locator_file_is_named_after_the_project_in_the_temp_directory() {
        let path = Locator::path_for("demo-app");
        assert_eq!(path.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(path.file_name().unwrap(), "hub-demo-app.json");
        assert_eq!(
            Locator::path_for("").file_name().unwrap(),
            "hub-demo-no-project.json"
        );
    }
}
