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
    (
        "APPCHECK-OBSERVE-1",
        "implemented",
        "exact-for-local-semantics",
    ),
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--storage-port",
                "0",
                "--logging-port",
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
    &published().0
}

/// What `GET /v1/limits` serves, from the same daemon as the manifest.
fn limits() -> &'static Value {
    &published().1
}

fn published() -> &'static (Value, Value) {
    static PUBLISHED: OnceLock<(Value, Value)> = OnceLock::new();
    PUBLISHED.get_or_init(|| {
        let daemon = Daemon::start();
        let manifest = daemon.get("/v1/capabilities");
        let limits = daemon.get("/v1/limits");
        let manifest = serde_json::from_str(&manifest).expect("the manifest is JSON");
        let limits = serde_json::from_str(&limits).expect("the limits route serves JSON");
        drop(daemon);
        census::assert_no_owned_descendants(
            "the capability manifest daemon",
            Duration::from_secs(10),
        );
        (manifest, limits)
    })
}

/// The synchronous Auth-to-Functions bridge and the two public metadata authorities must agree
/// on the Blocking Functions surface. This keeps an implemented trigger from returning to a
/// whole-feature gap after the runtime and its integration coverage move ahead.
#[test]
fn blocking_functions_metadata_matches_the_served_runtime() {
    let published = manifest();
    let implemented = text_of(&published["capabilities"]["FN-EVT-1"]["implemented"]);
    let unimplemented = text_of(&published["capabilities"]["FN-EVT-1"]["unimplemented"]);
    for name in [
        "beforeUserCreated",
        "beforeUserSignedIn",
        "beforeCreate",
        "beforeSignIn",
    ] {
        assert!(
            implemented.contains(name),
            "FN-EVT-1 does not publish {name} as implemented"
        );
        assert!(
            !unimplemented.contains(name),
            "FN-EVT-1 still publishes {name} as unimplemented"
        );
    }
    let notes = text_of(&published["capabilities"]["FN-EVT-1"]["notes"]);
    for term in ["seven-second", "503", "Error code: 47"] {
        assert!(notes.contains(term), "FN-EVT-1 does not publish {term}");
    }

    let contract: Value =
        serde_json::from_str(include_str!("../../../spec/compatibility/contract.json"))
            .expect("the compatibility contract is JSON");
    for (surface_id, claim_id, required_statement_terms) in [
        (
            "auth",
            "AUTH-CLAIM-BLOCKING-FUNCTIONS",
            ["synchronously", "roll", "sessionclaims"],
        ),
        (
            "functions",
            "FN-CLAIM-BLOCKING-AUTH",
            [
                "served synchronous triggers",
                "guarded runner endpoint",
                "invoked by auth",
            ],
        ),
    ] {
        let surface = contract["surfaces"]
            .as_array()
            .expect("the contract lists surfaces")
            .iter()
            .find(|surface| surface["id"] == surface_id)
            .unwrap_or_else(|| panic!("the contract lists the {surface_id} surface"));
        assert!(
            !text_of(&surface["gaps"])
                .to_ascii_lowercase()
                .contains("blocking"),
            "the {surface_id} surface still publishes Blocking Functions as a gap"
        );
        let claim = surface["claims"]
            .as_array()
            .expect("an active surface lists claims")
            .iter()
            .find(|claim| claim["id"] == claim_id)
            .unwrap_or_else(|| panic!("the {surface_id} surface lists claim {claim_id}"));
        assert!(
            claim["capabilities"]
                .as_array()
                .is_some_and(|capabilities| capabilities.iter().any(|capability| {
                    capability["id"] == "FN-EVT-1" && capability["status"] == "implemented"
                })),
            "claim {claim_id} does not publish FN-EVT-1 as implemented"
        );
        let evidence = text_of(&claim["evidence"]);
        assert!(
            evidence.contains("crates/fireemu-adapter-http/tests/identity_toolkit.rs")
                && evidence.contains("crates/fireemu/tests/functions_discovery.rs"),
            "claim {claim_id} does not bind both Blocking Functions integration paths"
        );
        assert!(
            evidence.contains("auth/blocking-function-error-status"),
            "claim {claim_id} does not bind the production differential fixture"
        );
        let statement = claim["statement"]
            .as_str()
            .unwrap_or_else(|| panic!("claim {claim_id} has a statement"))
            .to_ascii_lowercase();
        for term in required_statement_terms {
            assert!(
                statement.contains(term),
                "claim {claim_id} does not publish the required semantic term {term}"
            );
        }
    }
}

/// Streaming callables are a distinct wire contract from buffered HTTPS responses. Public
/// metadata must name progressive chunks, the final result, cancellation, and the real-SDK
/// evidence that prevents a buffered proxy from being described as compatible.
#[test]
fn functions_http_metadata_publishes_the_streaming_callable_contract() {
    let published = manifest();
    let capability = text_of(&published["capabilities"]["FN-HTTP-1"]).to_ascii_lowercase();
    for term in [
        "sendchunk",
        "progressively",
        "final result",
        "client disconnect",
        "10 mib",
        "oncallgenkit",
    ] {
        assert!(
            capability.contains(term),
            "FN-HTTP-1 does not publish the streaming callable term {term}"
        );
    }

    let contract: Value =
        serde_json::from_str(include_str!("../../../spec/compatibility/contract.json"))
            .expect("the compatibility contract is JSON");
    let functions = contract["surfaces"]
        .as_array()
        .expect("the contract lists surfaces")
        .iter()
        .find(|surface| surface["id"] == "functions")
        .expect("the contract lists Functions");
    let claim = functions["claims"]
        .as_array()
        .expect("Functions lists claims")
        .iter()
        .find(|claim| claim["id"] == "FN-CLAIM-HTTP")
        .expect("Functions lists its HTTP claim");
    let statement = claim["statement"]
        .as_str()
        .expect("the claim has a statement")
        .to_ascii_lowercase();
    for term in ["progressive", "stream", "disconnect"] {
        assert!(
            statement.contains(term),
            "FN-CLAIM-HTTP does not publish the streaming semantic term {term}"
        );
    }
    assert!(
        text_of(&claim["evidence"]).contains("crates/fireemu/tests/functions_discovery.rs"),
        "FN-CLAIM-HTTP does not bind the real Web SDK streaming test"
    );
}

/// The active Firestore transaction implementation locks what a read-write transaction read,
/// as production does. Public metadata must say so, name the official Local Emulator Suite's
/// matching lock model, and publish every pinned semantics row with its production backing.
#[test]
fn firestore_transaction_metadata_matches_the_pessimistic_runtime() {
    let transaction = text_of(&manifest()["capabilities"]["FS-TXN-1"]).to_ascii_lowercase();
    for term in [
        "pessimistic",
        "official local emulator",
        "locks",
        "production",
    ] {
        assert!(
            transaction.contains(term),
            "FS-TXN-1 does not publish the required transaction term {term}"
        );
    }

    let contract: Value =
        serde_json::from_str(include_str!("../../../spec/compatibility/contract.json"))
            .expect("the compatibility contract is JSON");
    let semantics = contract["profiles"]["emulator"]["officialEmulatorDivergences"]
        .as_array()
        .expect("the emulator profile lists official-emulator divergences")
        .iter()
        .find(|entry| entry["key"] == "firestore.semantics")
        .expect("the emulator profile publishes the Firestore semantics matrix");
    assert!(
        semantics["profileValue"]
            .as_str()
            .is_some_and(|value| value.contains("118 rows")),
        "the Firestore semantics profile does not publish all 118 measured divergence rows"
    );
    let semantics_note = text_of(&semantics["note"]).to_ascii_lowercase();
    for term in [
        "production observation",
        "lock what they read",
        "five families",
    ] {
        assert!(
            semantics_note.contains(term),
            "the Firestore semantics profile does not publish {term}"
        );
    }

    let firestore = contract["surfaces"]
        .as_array()
        .expect("the contract lists surfaces")
        .iter()
        .find(|surface| surface["id"] == "firestore")
        .expect("the contract lists Firestore");
    let rpc_claim = firestore["claims"]
        .as_array()
        .expect("Firestore lists claims")
        .iter()
        .find(|claim| claim["id"] == "FS-CLAIM-RPC")
        .expect("Firestore lists FS-CLAIM-RPC");
    let statement = rpc_claim["statement"]
        .as_str()
        .expect("FS-CLAIM-RPC has a statement")
        .to_ascii_lowercase();
    assert!(
        statement.contains("except") && statement.contains("conformance/divergences.json"),
        "FS-CLAIM-RPC does not exclude the rows pinned in the divergence register"
    );
    assert!(
        statement.contains("lock what they read"),
        "FS-CLAIM-RPC does not publish the pessimistic transaction model"
    );
}

/// `LIMIT-META-03`: the `FS-LIM-1` capability entry, the Standard catalog and `/v1/limits`
/// name the same set of enforced limits, and it is exactly the set the runtime enforces
/// (`fireemu_core_firestore::limits::ENFORCED_LIMIT_IDS`). A limit the runtime can refuse a
/// request over is therefore never published as unsupported anywhere.
#[test]
fn the_limit_metadata_agrees_with_the_enforcement() {
    use fireemu_core_firestore::limits::{ENFORCED_LIMIT_IDS, ENFORCED_QUERY_LIMIT_IDS};
    use fireemu_core_limits::catalogs::{
        FIRESTORE_STANDARD_2026_08_25, FIRESTORE_STANDARD_QUERY_2026_08_25,
    };
    use fireemu_core_limits::model::ImplementationStatus;
    use std::collections::BTreeSet;

    let enforced: BTreeSet<&str> = ENFORCED_LIMIT_IDS
        .iter()
        .chain(ENFORCED_QUERY_LIMIT_IDS)
        .copied()
        .collect();

    let manifest = manifest();
    let listed: BTreeSet<&str> = manifest["capabilities"]["FS-LIM-1"]["implemented"]
        .as_array()
        .expect("FS-LIM-1 lists its implemented limits")
        .iter()
        .map(|v| v.as_str().expect("a limit id"))
        .collect();
    assert_eq!(
        listed, enforced,
        "FS-LIM-1.implemented and the enforced set differ"
    );

    for (catalog, expected) in [
        (
            &FIRESTORE_STANDARD_2026_08_25,
            ENFORCED_LIMIT_IDS.iter().copied().collect::<BTreeSet<_>>(),
        ),
        (
            &FIRESTORE_STANDARD_QUERY_2026_08_25,
            ENFORCED_QUERY_LIMIT_IDS.iter().copied().collect(),
        ),
    ] {
        let implemented: BTreeSet<&str> = catalog
            .limits
            .iter()
            .filter(|l| l.implemented == ImplementationStatus::Implemented)
            .map(|l| l.id)
            .collect();
        assert_eq!(
            implemented, expected,
            "{}: the catalog's implemented set and the enforced set differ",
            catalog.meta.id
        );

        let served = limits()["catalogs"]
            .as_array()
            .expect("catalogs are listed")
            .iter()
            .find(|c| c["id"] == catalog.meta.id)
            .unwrap_or_else(|| panic!("{} is served by /v1/limits", catalog.meta.id));
        let mut reported = BTreeSet::new();
        for limit in served["limits"].as_array().expect("limits are listed") {
            let id = limit["id"].as_str().expect("a limit id");
            let status = limit["implemented"].as_str().expect("a status");
            if expected.contains(id) {
                assert_eq!(status, "Implemented", "/v1/limits reports {id} as {status}");
                reported.insert(id);
            } else {
                assert_ne!(
                    status, "Implemented",
                    "/v1/limits reports {id} implemented but nothing enforces it"
                );
            }
        }
        assert_eq!(
            reported, expected,
            "/v1/limits does not name every enforced limit of {}",
            catalog.meta.id
        );
    }
}

#[test]
fn firestore_rest_capability_matches_the_served_production_wire() {
    let text = text_of(&manifest()["capabilities"]["FS-REST-1"]);
    assert!(
        text.contains("readTime selectors are validated and served through REST"),
        "FS-REST-1 must describe the implemented readTime behavior: {text}"
    );
    assert!(
        text.contains("without a synthetic done marker"),
        "FS-REST-1 must describe the implemented terminal response shape: {text}"
    );
    assert!(
        !text.contains("readTime selectors and findNearest are refused explicitly"),
        "FS-REST-1 must not claim that readTime is refused: {text}"
    );
    assert!(
        !text.contains("the last RunQuery response says done"),
        "FS-REST-1 must not claim a done marker: {text}"
    );
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
        core.contains("fireemu_epoch") && core.contains("divergence"),
        "the fireemu_epoch divergence is published: {core}"
    );
    assert!(
        core.contains("instance") && core.contains("kid fireemu-app-check-"),
        "the per-instance signing key is published: {core}"
    );

    // A restart changes the key behind the same loopback URL, so the JWKS may not be cached.
    let jwks = text_of(&capabilities["APPCHECK-JWKS-1"]);
    assert!(
        jwks.contains("no-store") && jwks.contains("divergence"),
        "the JWKS caching divergence is published: {jwks}"
    );

    // The observation surface, including the Emulator UI page and the per-project scoping
    // that makes what one session reads independent of what another session did.
    let observe = &capabilities["APPCHECK-OBSERVE-1"];
    assert_eq!(observe["status"], "implemented");
    let observe_text = text_of(observe);
    for claim in [
        "/v1/sessions/{session}/appCheck/observations",
        "/ui/appcheck",
        "/ui/api/appcheck/config",
        "Cache-Control: no-store",
        "unknown bucket",
        "callable function name for the functions service",
    ] {
        assert!(
            observe_text.contains(claim),
            "the observation entry states {claim}: {observe_text}"
        );
    }
    assert!(
        observe_text.contains("one bounded ring and one set of counters per project"),
        "the entry states the per-project scoping: {observe_text}"
    );
    assert!(
        observe_text.contains("at most 256 projects hold a ring at once"),
        "the entry states the bound on the table of rings: {observe_text}"
    );
    assert!(
        observe_text.contains("never in a list, a log, window.__FIREEMU__ or an observation"),
        "the entry states where a raw debug secret may appear: {observe_text}"
    );
}
