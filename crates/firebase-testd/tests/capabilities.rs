//! `AC-CAP-001`: what `GET /v1/capabilities` publishes about App Check.
//!
//! The manifest is the project's public answer to "what is actually supported", and the
//! acceptance criteria of specification section 22 require it to state the exact surfaces,
//! the precision, the known divergences and the replay status. This test reads the manifest
//! the shipped binary serves -- not the constant behind it -- so a capability entry cannot
//! drift from the daemon that publishes it.

mod census;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use serde_json::Value;

/// The nine App Check capabilities of specification section 6, with the status and the
/// precision each of them is allowed to publish today.
const APP_CHECK_CAPABILITIES: [(&str, &str, &str); 9] = [
    (
        "APPCHECK-CORE-1",
        "implemented",
        "exact-for-local-semantics",
    ),
    (
        "APPCHECK-DEBUG-EXCHANGE-1",
        "implemented",
        "boundary-conformance",
    ),
    (
        "APPCHECK-JWKS-1",
        "implemented",
        "exact-for-local-semantics",
    ),
    ("APPCHECK-ENFORCE-1", "implemented", "boundary-conformance"),
    (
        "APPCHECK-FUNCTIONS-1",
        "implemented",
        "boundary-conformance",
    ),
    // Partial while the retained observations are one ring for the runtime, not one per
    // project. The Emulator UI page of milestone AC3 exists.
    ("APPCHECK-OBSERVE-1", "partial", "exact-for-local-semantics"),
    ("APPCHECK-SDK-WEB-1", "implemented", "boundary-conformance"),
    ("APPCHECK-REPLAY-1", "unsupported", "unsupported"),
    (
        "APPCHECK-PROVIDER-ATTESTATION-0",
        "unsupported",
        "not-applicable",
    ),
];

/// A daemon on ephemeral ports, and the control API port it printed.
struct Daemon {
    child: Child,
    control_port: u16,
    /// The banner pipe stays open for the daemon's lifetime: closing it would make the
    /// daemon's next write to stdout fail.
    _banner: BufReader<std::process::ChildStdout>,
}

impl Daemon {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_firebase-testd"))
            .args([
                "up",
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--storage-port",
                "0",
                "--ui-port",
                "0",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the daemon binary starts");
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut reader = BufReader::new(stdout);
        let mut banner = String::new();
        let mut port = None;
        for _ in 0..40 {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            banner.push_str(&line);
            if line.trim_start().starts_with("control API:") {
                port = line
                    .split("http://127.0.0.1:")
                    .nth(1)
                    .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
                    .and_then(|digits| digits.parse::<u16>().ok());
                break;
            }
        }
        let Some(control_port) = port else {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the daemon printed no control API line:\n{banner}");
        };
        Self {
            child,
            control_port,
            _banner: reader,
        }
    }

    /// `GET path` over a fresh connection, without an `Origin` (a command-line client).
    fn get(&self, path: &str) -> String {
        let mut socket = TcpStream::connect(("127.0.0.1", self.control_port))
            .expect("the control listener accepts");
        socket
            .set_read_timeout(Some(Duration::from_secs(20)))
            .expect("the read timeout is set");
        write!(
            socket,
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        .expect("the request is written");
        let mut response = String::new();
        socket
            .read_to_string(&mut response)
            .expect("the response is read");
        let (head, body) = response
            .split_once("\r\n\r\n")
            .expect("the response has a header block");
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        body.to_owned()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Every string anywhere inside a capability entry, so a claim can be looked for without
/// pinning which of `implemented` / `unimplemented` / `notes` carries it.
fn text_of(entry: &Value) -> String {
    let mut out = String::new();
    match entry {
        Value::String(s) => {
            out.push_str(s);
            out.push('\n');
        }
        Value::Array(items) => {
            for item in items {
                out.push_str(&text_of(item));
            }
        }
        Value::Object(fields) => {
            for value in fields.values() {
                out.push_str(&text_of(value));
            }
        }
        _ => {}
    }
    out
}

/// The manifest the shipped binary serves. One daemon per test binary: with `cargo test` the
/// scenarios share a process, so starting one each would make the process census below see
/// another scenario's daemon.
fn manifest() -> &'static Value {
    static MANIFEST: OnceLock<Value> = OnceLock::new();
    MANIFEST.get_or_init(|| {
        let daemon = Daemon::start();
        let body = daemon.get("/v1/capabilities");
        let parsed = serde_json::from_str(&body).expect("the manifest is JSON");
        drop(daemon);
        census::assert_no_owned_descendants(
            "the capability manifest daemon",
            Duration::from_secs(10),
        );
        parsed
    })
}

#[test]
fn the_manifest_states_every_app_check_capability_with_its_status_and_precision() {
    let manifest = manifest();
    let capabilities = manifest["capabilities"]
        .as_object()
        .expect("the manifest has a capability map");
    for (id, status, precision) in APP_CHECK_CAPABILITIES {
        let entry = capabilities
            .get(id)
            .unwrap_or_else(|| panic!("the manifest publishes {id}"));
        assert_eq!(entry["status"], status, "{id} status");
        assert_eq!(entry["precision"], precision, "{id} precision");
    }
    // Nothing else may call itself an App Check capability: a new one has to be declared in
    // specification section 6 and added here first.
    let published: Vec<&String> = capabilities
        .keys()
        .filter(|k| k.starts_with("APPCHECK-"))
        .collect();
    assert_eq!(
        published.len(),
        APP_CHECK_CAPABILITIES.len(),
        "unexpected App Check capabilities: {published:?}"
    );
}

#[test]
fn the_unsupported_app_check_capabilities_say_so_and_say_why() {
    let manifest = manifest();
    let replay = &manifest["capabilities"]["APPCHECK-REPLAY-1"];
    assert_eq!(replay["status"], "unsupported");
    assert_eq!(replay["precision"], "unsupported");
    let replay_text = text_of(replay);
    assert!(
        replay_text.contains("limited-use"),
        "the replay entry names what it would cover: {replay_text}"
    );
    assert!(
        replay_text.contains("APP_CHECK_REPLAY_UNSUPPORTED") && replay_text.contains("501"),
        "the replay entry states how it fails closed: {replay_text}"
    );

    let attestation = &manifest["capabilities"]["APPCHECK-PROVIDER-ATTESTATION-0"];
    assert_eq!(attestation["status"], "unsupported");
    assert_eq!(attestation["precision"], "not-applicable");
    let attestation_text = text_of(attestation);
    for provider in ["Play Integrity", "App Attest", "DeviceCheck", "reCAPTCHA"] {
        assert!(
            attestation_text.contains(provider),
            "the attestation entry names {provider}: {attestation_text}"
        );
    }
}

#[test]
fn the_enforcement_capability_names_its_surfaces_its_modes_and_its_bypasses() {
    let manifest = manifest();
    let enforce = text_of(&manifest["capabilities"]["APPCHECK-ENFORCE-1"]);

    // The three baseline modes of specification section 12, by name.
    for mode in ["off", "unenforced", "enforced"] {
        assert!(
            enforce.contains(mode),
            "the mode {mode} is named: {enforce}"
        );
    }

    // The supported surfaces: which product, over which transport.
    for surface in [
        "Firebase Authentication",
        "Cloud Firestore",
        "Cloud Storage",
        "unary gRPC",
        "REST",
        "Listen",
        "WebChannel",
        "resumable upload",
    ] {
        assert!(
            enforce.contains(surface),
            "the surface {surface} is listed: {enforce}"
        );
    }

    // Every row of the bypass matrix of specification section 12.2 names the credential it
    // requires, so no reader can mistake a path shape for a bypass.
    for row in [
        "owner credential",
        "Identity Toolkit Admin routes",
        "emulator inspection routes with the control token",
        "Storage JSON API dialect",
        "download URL",
    ] {
        assert!(
            enforce.contains(row),
            "the bypass row {row} is listed: {enforce}"
        );
    }

    // The published divergences: what stays boundary-conformance and why.
    assert!(
        enforce.contains("boundary-conformance"),
        "the enforcement entry states its precision debt: {enforce}"
    );
    assert!(
        enforce.contains("appCheck.services.functions"),
        "the entry says there is no Functions baseline mode: {enforce}"
    );
}

#[test]
fn the_local_divergences_and_the_observation_surface_are_published() {
    let manifest = manifest();
    let capabilities = &manifest["capabilities"];

    // The token is deliberately not portable across daemon instances.
    let core = text_of(&capabilities["APPCHECK-CORE-1"]);
    assert!(
        core.contains("ftd_epoch") && core.contains("divergence"),
        "the ftd_epoch divergence is published: {core}"
    );
    assert!(
        core.contains("instance") && core.contains("kid ftd-app-check-"),
        "the per-instance signing key is published: {core}"
    );

    // A restart changes the key behind the same loopback URL, so the JWKS may not be cached.
    let jwks = text_of(&capabilities["APPCHECK-JWKS-1"]);
    assert!(
        jwks.contains("no-store") && jwks.contains("divergence"),
        "the JWKS caching divergence is published: {jwks}"
    );

    // Milestone AC3: the observation surface, including the Emulator UI page, and the one
    // thing that keeps the capability partial.
    let observe = &capabilities["APPCHECK-OBSERVE-1"];
    assert_eq!(observe["status"], "partial");
    let observe_text = text_of(observe);
    for claim in [
        "/v1/sessions/{session}/appCheck/observations",
        "/ui/appcheck",
        "/ui/api/appcheck/config",
        "Cache-Control: no-store",
        "unknown bucket",
    ] {
        assert!(
            observe_text.contains(claim),
            "the observation entry states {claim}: {observe_text}"
        );
    }
    assert!(
        observe_text.contains("one bounded ring for the runtime"),
        "the entry says why it is still partial: {observe_text}"
    );
    assert!(
        observe_text.contains("never in a list, a log, window.__FTD__ or an observation"),
        "the entry states where a raw debug secret may appear: {observe_text}"
    );
}
