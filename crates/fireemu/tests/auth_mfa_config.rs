//! `auth.mfa`: the project's initial multi-factor configuration, in the Identity Platform
//! `Config.mfa` shape. Under the strict profile TOTP is on only through the project's MFA
//! config, so a file that declares it starts a daemon that enrolls TOTP factors without an Admin
//! API call. The runtime is unchanged: an Admin update wins over the seed, and a control-plane
//! reset returns to the seed only when the file declared one.

#![cfg(unix)]

mod census;
#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use trusted_temp::TrustedTempDir;

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";
const PROJECT: &str = "demo-mfa-seed";
const NOT_ENABLED: &str = "OPERATION_NOT_ALLOWED : TOTP based MFA not enabled.";
const SMS_NOT_ENABLED: &str = "OPERATION_NOT_ALLOWED : SMS based MFA not enabled.";

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn http(port: u16, method: &str, path: &str, headers: &str, body: &Value) -> (u16, Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the daemon accepts");
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let body = body.to_string();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    stream.flush().unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

const OWNER: &str = "Authorization: Bearer owner\r\n";

struct Daemon {
    child: Child,
    banner: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    hub_port: u16,
    _dir: TrustedTempDir,
}

impl Daemon {
    /// A daemon under `profile` whose `auth` section is `auth`.
    fn start(name: &str, profile: &str, auth: &Value) -> Self {
        Self::start_with_args(name, profile, auth, &[])
    }

    fn start_with_args(name: &str, profile: &str, auth: &Value, extra: &[&str]) -> Self {
        let dir = TrustedTempDir::new(&format!("auth-mfa-config-{name}"));
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            json!({"schemaVersion": 1, "profile": profile, "auth": auth}).to_string(),
        )
        .unwrap();
        let hub_port = free_port();
        let mut child = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--config",
                config.to_str().unwrap(),
                "--project",
                PROJECT,
                "--only",
                "auth",
                "--firestore-port",
                "0",
                "--http-port",
                "0",
                "--storage-port",
                "0",
                "--functions-port",
                "0",
                "--logging-port",
                "0",
                "--ui-port",
                "0",
                "--hub-port",
            ])
            .arg(hub_port.to_string())
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        // The child is owned (and killed on drop) before anything below can panic.
        let daemon = Self {
            child,
            banner: Arc::new(Mutex::new(String::new())),
            stderr: Arc::new(Mutex::new(String::new())),
            hub_port,
            _dir: dir,
        };
        let collected = Arc::clone(&daemon.stderr);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stderr);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                collected.lock().unwrap().push_str(&line);
            }
        });
        let collected = Arc::clone(&daemon.banner);
        let (tx, rx) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut ready = Some(tx);
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                collected.lock().unwrap().push_str(&line);
                if line.contains("control API:") {
                    if let Some(tx) = ready.take() {
                        let _ = tx.send(());
                    }
                }
            }
        });
        if extra.contains(&"quiet") {
            // A quiet daemon prints no banner: ready is when the Hub answers.
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            while TcpStream::connect(("127.0.0.1", hub_port)).is_err() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the daemon became ready"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = rx;
        } else {
            rx.recv_timeout(Duration::from_secs(60))
                .expect("the daemon became ready");
        }
        daemon
    }

    fn auth_port(&self) -> u16 {
        let (status, emulators) = http(self.hub_port, "GET", "/emulators", "", &Value::Null);
        assert_eq!(status, 200, "{emulators}");
        u16::try_from(emulators["auth"]["port"].as_u64().unwrap()).unwrap()
    }

    fn control_port(&self) -> u16 {
        let banner = self.banner.lock().unwrap().clone();
        banner
            .lines()
            .find(|line| line.trim_start().starts_with("control API:"))
            .and_then(|line| line.split("http://127.0.0.1:").nth(1))
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse().ok())
            .expect("the banner names the control API")
    }

    fn stderr(&self) -> String {
        std::thread::sleep(Duration::from_millis(300));
        self.stderr.lock().unwrap().clone()
    }

    /// Wipes the default session as `POST /v1/sessions/default/reset` does.
    fn reset(&self) {
        let (status, body) = http(
            self.control_port(),
            "POST",
            "/v1/sessions/default/reset",
            "",
            &json!({}),
        );
        assert_eq!(status, 200, "{body}");
    }

    /// The answer to a TOTP enrollment start for a fresh verified account.
    fn totp_start(&self, email: &str) -> (u16, String) {
        self.enrollment_start(email, &json!({"totpEnrollmentInfo": {}}), None)
    }

    /// The answer to a phone enrollment start for a fresh verified account.
    fn phone_start(&self, email: &str) -> (u16, String) {
        self.enrollment_start(
            email,
            &json!({"phoneEnrollmentInfo": {"phoneNumber": "+16505550101"}}),
            None,
        )
    }

    /// `mfaEnrollment:start` with `info` for a fresh verified account, in `tenant` when given.
    fn enrollment_start(&self, email: &str, info: &Value, tenant: Option<&str>) -> (u16, String) {
        let port = self.auth_port();
        let scope = tenant.map_or_else(
            || format!("{V1}/projects/{PROJECT}"),
            |tenant| format!("{V1}/projects/{PROJECT}/tenants/{tenant}"),
        );
        let (status, created) = http(
            port,
            "POST",
            &format!("{scope}/accounts"),
            OWNER,
            &json!({"email": email, "password": "password123", "emailVerified": true}),
        );
        assert_eq!(status, 200, "{created}");
        let mut sign_in =
            json!({"email": email, "password": "password123", "returnSecureToken": true});
        if let Some(tenant) = tenant {
            sign_in["tenantId"] = json!(tenant);
        }
        let (status, signed) = http(
            port,
            "POST",
            &format!("{V1}/accounts:signInWithPassword?key=fake-api-key"),
            "",
            &sign_in,
        );
        assert_eq!(status, 200, "{signed}");
        let mut body = info.clone();
        body["idToken"] = signed["idToken"].clone();
        if let Some(tenant) = tenant {
            body["tenantId"] = json!(tenant);
        }
        let (status, started) = http(
            port,
            "POST",
            &format!("{V2}/accounts/mfaEnrollment:start?key=fake-api-key"),
            "",
            &body,
        );
        (
            status,
            started["error"]["message"]
                .as_str()
                .unwrap_or("")
                .to_owned(),
        )
    }

    /// The Admin API's config update of the project's `mfa` member.
    fn set_mfa(&self, mfa: &Value) {
        let (status, body) = http(
            self.auth_port(),
            "PATCH",
            &format!(
                "/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config?updateMask=mfa"
            ),
            OWNER,
            &json!({"mfa": mfa}),
        );
        assert_eq!(status, 200, "{body}");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn totp_on() -> Value {
    json!({
        "state": "ENABLED",
        "providerConfigs": [{"state": "ENABLED", "totpProviderConfig": {"adjacentIntervals": 1}}]
    })
}

fn base() -> Value {
    json!({"apiKeys": ["fake-api-key"]})
}

fn with_mfa(mfa: &Value) -> Value {
    let mut auth = base();
    auth["mfa"] = mfa.clone();
    auth
}

const ENROLLING: (u16, &str) = (200, "");

#[test]
fn strict_auth_mfa_starts_the_project_with_totp_enabled() {
    let daemon = Daemon::start("seeded", "strict", &with_mfa(&totp_on()));
    assert_eq!(
        daemon.totp_start("a@example.com"),
        (ENROLLING.0, ENROLLING.1.to_owned())
    );
    // The read-back is the Identity Platform config document.
    let (status, config) = http(
        daemon.auth_port(),
        "GET",
        &format!("/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config"),
        OWNER,
        &Value::Null,
    );
    assert_eq!(status, 200, "{config}");
    assert_eq!(config["mfa"], totp_on());
}

/// The seed enables SMS second factors as the Admin API's update does: strict phone enrollment is
/// gated on the same project config (`OPERATION_NOT_ALLOWED : SMS based MFA not enabled.`).
#[test]
fn strict_auth_mfa_with_phone_sms_enables_phone_enrollment() {
    let sms = json!({"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]});
    let daemon = Daemon::start("sms", "strict", &with_mfa(&sms));
    assert_eq!(daemon.phone_start("a@example.com"), (200, String::new()));
    // A provider that is not on refuses, and so does a project that declares nothing.
    daemon.set_mfa(&json!({"state": "DISABLED", "enabledProviders": ["PHONE_SMS"]}));
    assert_eq!(
        daemon.phone_start("b@example.com"),
        (400, SMS_NOT_ENABLED.to_owned())
    );
    drop(daemon);
    let daemon = Daemon::start("no-sms", "strict", &base());
    assert_eq!(
        daemon.phone_start("a@example.com"),
        (400, SMS_NOT_ENABLED.to_owned())
    );
    drop(daemon);
    // SMS in the seed does not enable TOTP: each provider follows its own entry.
    let daemon = Daemon::start("sms-only", "strict", &with_mfa(&sms));
    assert_eq!(
        daemon.totp_start("a@example.com"),
        (400, NOT_ENABLED.to_owned())
    );
}

/// A tenant's second factors follow the tenant's own `mfaConfig` (sandbox recording 2026-09-27),
/// so the project's seed enables nothing inside a tenant: it is a project-level configuration.
#[test]
fn the_projects_seed_does_not_enable_second_factors_inside_a_tenant() {
    let both = json!({
        "state": "ENABLED",
        "enabledProviders": ["PHONE_SMS"],
        "providerConfigs": [{"state": "ENABLED", "totpProviderConfig": {}}]
    });
    let daemon = Daemon::start("tenant", "strict", &with_mfa(&both));
    let port = daemon.auth_port();
    let (status, body) = http(
        port,
        "PATCH",
        &format!(
            "/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config?updateMask=multiTenant.allowTenants"
        ),
        OWNER,
        &json!({"multiTenant": {"allowTenants": true}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, tenant) = http(
        port,
        "POST",
        &format!("{V2}/projects/{PROJECT}/tenants"),
        OWNER,
        &json!({"displayName": "customer", "allowPasswordSignup": true}),
    );
    assert_eq!(status, 200, "{tenant}");
    let id = tenant["name"]
        .as_str()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        daemon.enrollment_start(
            "a@example.com",
            &json!({"phoneEnrollmentInfo": {"phoneNumber": "+16505550101"}}),
            Some(&id)
        ),
        (400, SMS_NOT_ENABLED.to_owned())
    );
    assert_eq!(
        daemon.enrollment_start(
            "b@example.com",
            &json!({"totpEnrollmentInfo": {}}),
            Some(&id)
        ),
        (400, NOT_ENABLED.to_owned())
    );
    // The project itself enrolls both.
    assert_eq!(daemon.phone_start("c@example.com"), (200, String::new()));
    assert_eq!(daemon.totp_start("d@example.com"), (200, String::new()));
}

#[test]
fn strict_without_auth_mfa_still_refuses_totp_enrollment() {
    let daemon = Daemon::start("unseeded", "strict", &base());
    assert_eq!(
        daemon.totp_start("a@example.com"),
        (400, NOT_ENABLED.to_owned())
    );
}

#[test]
fn an_admin_update_wins_over_the_seed_and_disabling_refuses_as_in_production() {
    let daemon = Daemon::start("admin-wins", "strict", &with_mfa(&totp_on()));
    assert_eq!(daemon.totp_start("a@example.com").0, 200);
    daemon.set_mfa(&json!({"state": "DISABLED"}));
    assert_eq!(
        daemon.totp_start("b@example.com"),
        (400, NOT_ENABLED.to_owned())
    );
}

#[test]
fn a_reset_returns_to_a_declared_seed() {
    let daemon = Daemon::start("reset-seeded", "strict", &with_mfa(&totp_on()));
    daemon.set_mfa(&json!({"state": "DISABLED"}));
    assert_eq!(daemon.totp_start("a@example.com").0, 400);
    daemon.reset();
    assert_eq!(daemon.totp_start("b@example.com").0, 200);
}

#[test]
fn a_reset_without_a_declared_seed_keeps_an_admin_set_config_as_before() {
    let daemon = Daemon::start("reset-unseeded", "strict", &base());
    daemon.set_mfa(&totp_on());
    assert_eq!(daemon.totp_start("a@example.com").0, 200);
    daemon.reset();
    assert_eq!(daemon.totp_start("b@example.com").0, 200);
}

#[test]
fn a_declared_seed_that_disables_mfa_is_what_a_reset_returns_to() {
    let daemon = Daemon::start(
        "reset-off",
        "strict",
        &with_mfa(&json!({"state": "DISABLED"})),
    );
    daemon.set_mfa(&totp_on());
    assert_eq!(daemon.totp_start("a@example.com").0, 200);
    daemon.reset();
    assert_eq!(daemon.totp_start("b@example.com").0, 400);
}

/// The `mfa` member of a project's config, read as the owner.
fn mfa_of(daemon: &Daemon, project: &str) -> Value {
    let (status, config) = http(
        daemon.auth_port(),
        "GET",
        &format!("/identitytoolkit.googleapis.com/admin/v2/projects/{project}/config"),
        OWNER,
        &Value::Null,
    );
    assert_eq!(status, 200, "{config}");
    config["mfa"].clone()
}

#[test]
fn a_project_created_later_starts_with_the_seed_not_the_default_projects_live_config() {
    let daemon = Daemon::start("created", "strict", &with_mfa(&totp_on()));
    // The default project's live configuration moves away from the seed.
    daemon.set_mfa(&json!({"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}));
    let (status, created) = http(
        daemon.control_port(),
        "POST",
        "/v1/sessions",
        "",
        &json!({"project": "demo-second"}),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(mfa_of(&daemon, "demo-second"), totp_on());
    // A reset of that session returns it to the seed after an Admin change.
    let (status, body) = http(
        daemon.auth_port(),
        "PATCH",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-second/config?updateMask=mfa",
        OWNER,
        &json!({"mfa": {"state": "DISABLED"}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = http(
        daemon.control_port(),
        "POST",
        "/v1/sessions/demo-second/reset",
        "",
        &json!({}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(mfa_of(&daemon, "demo-second"), totp_on());
}

#[test]
fn a_project_created_without_a_declared_seed_starts_with_mfa_off() {
    let daemon = Daemon::start("created-plain", "strict", &base());
    daemon.set_mfa(&totp_on());
    let (status, created) = http(
        daemon.control_port(),
        "POST",
        "/v1/sessions",
        "",
        &json!({"project": "demo-second"}),
    );
    assert_eq!(status, 200, "{created}");
    assert_eq!(mfa_of(&daemon, "demo-second"), json!({"state": "DISABLED"}));
}

#[test]
fn wiping_accounts_through_the_emulator_route_leaves_the_mfa_config_alone() {
    // Like the official emulator, `DELETE /emulator/v1/projects/{p}/accounts` clears accounts only;
    // it is not the control-plane reset that returns to the seed.
    for profile in ["strict", "emulator"] {
        let daemon = Daemon::start("wipe", profile, &with_mfa(&totp_on()));
        let admin_set = json!({"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]});
        daemon.set_mfa(&admin_set);
        let (status, body) = http(
            daemon.auth_port(),
            "DELETE",
            &format!("/emulator/v1/projects/{PROJECT}/accounts"),
            "",
            &Value::Null,
        );
        assert_eq!(status, 200, "{profile}: {body}");
        let (status, config) = http(
            daemon.auth_port(),
            "GET",
            &format!("/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config"),
            OWNER,
            &Value::Null,
        );
        assert_eq!(status, 200, "{config}");
        assert_eq!(config["mfa"], admin_set, "{profile}: {config}");
    }
}

#[test]
fn the_emulator_profile_keeps_auth_totp_and_accepts_auth_mfa_as_well() {
    // auth.totp alone still enables TOTP there, as before.
    let mut auth = base();
    auth["totp"] = json!({});
    let daemon = Daemon::start("emulator-totp", "emulator", &auth);
    assert_eq!(daemon.totp_start("a@example.com").0, 200);
    drop(daemon);
    // The seed works in both profiles.
    let daemon = Daemon::start("emulator-mfa", "emulator", &with_mfa(&totp_on()));
    assert_eq!(daemon.totp_start("a@example.com").0, 200);
}

#[test]
fn strict_auth_totp_without_an_mfa_enabling_it_warns_naming_auth_mfa() {
    let mut auth = base();
    auth["totp"] = json!({});
    let warned = Daemon::start("warn", "strict", &auth);
    let stderr = warned.stderr();
    assert!(
        stderr.contains("warning: auth.totp does not enable TOTP under the strict profile"),
        "{stderr}"
    );
    assert!(stderr.contains("auth.mfa"), "{stderr}");
    drop(warned);

    // No warning once the seed enables TOTP, without auth.totp, or under the emulator profile.
    let mut seeded = auth.clone();
    seeded["mfa"] = totp_on();
    let quiet = Daemon::start("nowarn-seeded", "strict", &seeded);
    assert!(!quiet.stderr().contains("auth.totp does not enable"));
    drop(quiet);
    let quiet = Daemon::start("nowarn-plain", "strict", &base());
    assert!(!quiet.stderr().contains("auth.totp does not enable"));
    drop(quiet);
    let quiet = Daemon::start("nowarn-emulator", "emulator", &auth);
    assert!(!quiet.stderr().contains("auth.totp does not enable"));
    drop(quiet);
    // A quiet daemon prints no warning either.
    let quiet = Daemon::start_with_args(
        "nowarn-quiet",
        "strict",
        &auth,
        &["--log-verbosity", "quiet"],
    );
    assert!(!quiet.stderr().contains("auth.totp does not enable"));
    drop(quiet);
    census::assert_no_owned_descendants("the auth mfa daemons", Duration::from_secs(10));
}

#[test]
fn an_invalid_auth_mfa_stops_the_daemon_before_it_starts() {
    let dir = TrustedTempDir::new("auth-mfa-config-invalid");
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        json!({"schemaVersion": 1, "auth": {"mfa": {"state": "ON"}}}).to_string(),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args(["up", "--config", config.to_str().unwrap(), "--only", "auth"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("auth.mfa"), "{text}");
    assert!(text.contains("config.mfa.state"), "{text}");
}
