//! Startup authorized-domain declarations and their live project lifecycle.

#![cfg(unix)]

mod census;
#[path = "../../../tests/support/trusted_temp.rs"]
mod trusted_temp;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use trusted_temp::TrustedTempDir;

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const PROJECT: &str = "demo-domain-seed";
const OWNER: &str = "Authorization: Bearer owner\r\n";

struct StartupChild(Child);

impl Drop for StartupChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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

struct Daemon {
    child: Child,
    banner: Arc<Mutex<String>>,
    stderr: Arc<Mutex<String>>,
    _dir: TrustedTempDir,
}

impl Daemon {
    /// A daemon under `profile` whose `auth` section is `auth`. Every port is chosen by the daemon (`0`) and read from its banner, so no port is picked here and released before the daemon binds it.
    fn start(name: &str, profile: &str, auth: &Value) -> Self {
        Self::spawn(name, profile, auth, &[])
    }

    fn spawn(name: &str, profile: &str, auth: &Value, extra: &[&str]) -> Self {
        let dir = TrustedTempDir::new(&format!("auth-authorized-domains-{name}"));
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            json!({"schemaVersion": 1, "profile": profile, "auth": auth}).to_string(),
        )
        .unwrap();
        let http_port = "0";
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
                http_port,
                "--storage-port",
                "0",
                "--functions-port",
                "0",
                "--logging-port",
                "0",
                "--ui-port",
                "0",
                "--hub-port",
                "0",
            ])
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
        rx.recv_timeout(Duration::from_secs(60))
            .expect("the daemon became ready");
        daemon
    }

    /// The port a banner line names: `<label> ... 127.0.0.1:PORT`.
    fn banner_port(&self, label: &str) -> u16 {
        let banner = self.banner.lock().unwrap().clone();
        banner
            .lines()
            .find(|line| line.trim_start().starts_with(label))
            .and_then(|line| line.split("127.0.0.1:").nth(1))
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse().ok())
            .unwrap_or_else(|| panic!("the banner names no {label}: {banner}"))
    }

    fn auth_port(&self) -> u16 {
        self.banner_port("auth (REST):")
    }

    fn control_port(&self) -> u16 {
        self.banner_port("control API:")
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
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn domains_of(daemon: &Daemon, project: &str) -> Value {
    let (status, body) = http(
        daemon.auth_port(),
        "GET",
        &format!("/identitytoolkit.googleapis.com/admin/v2/projects/{project}/config"),
        OWNER,
        &Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    body["authorizedDomains"].clone()
}

fn set_domains(daemon: &Daemon, project: &str, domains: &Value) {
    let (status, body) = http(daemon.auth_port(), "PATCH", &format!("/identitytoolkit.googleapis.com/admin/v2/projects/{project}/config?updateMask=authorizedDomains"), OWNER, &json!({"authorizedDomains": domains}));
    assert_eq!(status, 200, "{body}");
}

fn link(daemon: &Daemon, host: &str) -> (u16, Value) {
    http(
        daemon.auth_port(),
        "POST",
        &format!("{V1}/projects/{PROJECT}/accounts:sendOobCode"),
        OWNER,
        &json!({"requestType": "EMAIL_SIGNIN", "email": "a@example.com", "continueUrl": format!("https://{host}/done"), "returnOobLink": true}),
    )
}

fn auth(domains: &Value) -> Value {
    json!({"apiKeys": ["fake-api-key"], "authorizedDomains": domains})
}

#[test]
fn auth_authorized_domains_strict_seed_and_admin_update_use_the_live_list() {
    let daemon = Daemon::start("strict-live", "strict", &auth(&json!(["app.test"])));
    assert_eq!(domains_of(&daemon, PROJECT), json!(["app.test"]));
    assert_eq!(link(&daemon, "APP.test").0, 200);
    let (status, refused) = link(&daemon, "localhost");
    assert_eq!(status, 400, "{refused}");
    assert_eq!(
        refused["error"]["message"],
        "UNAUTHORIZED_DOMAIN : Domain not allowlisted by project"
    );
    set_domains(&daemon, PROJECT, &json!(["changed.test"]));
    assert_eq!(link(&daemon, "app.test").0, 400);
    assert_eq!(link(&daemon, "changed.test").0, 200);
    daemon.reset();
    assert_eq!(domains_of(&daemon, PROJECT), json!(["app.test"]));
    assert_eq!(link(&daemon, "app.test").0, 200);
}

#[test]
fn auth_authorized_domains_absent_and_null_keep_defaults_and_admin_config_on_reset() {
    for settings in [json!({"apiKeys": ["fake-api-key"]}), auth(&Value::Null)] {
        let daemon = Daemon::start("unseeded", "strict", &settings);
        assert_eq!(
            domains_of(&daemon, PROJECT),
            json!([
                "localhost",
                format!("{PROJECT}.firebaseapp.com"),
                format!("{PROJECT}.web.app")
            ])
        );
        assert_eq!(link(&daemon, "localhost").0, 200);
        set_domains(&daemon, PROJECT, &json!(["runtime.test"]));
        daemon.reset();
        assert_eq!(domains_of(&daemon, PROJECT), json!(["runtime.test"]));
    }
}

#[test]
fn auth_authorized_domains_empty_seed_denies_all_hosts_after_reset() {
    let daemon = Daemon::start("empty", "strict", &auth(&json!([])));
    assert_eq!(link(&daemon, "localhost").0, 400);
    set_domains(&daemon, PROJECT, &json!(["localhost"]));
    assert_eq!(link(&daemon, "localhost").0, 200);
    daemon.reset();
    assert_eq!(domains_of(&daemon, PROJECT), json!([]));
    assert_eq!(link(&daemon, "localhost").0, 400);
}

#[test]
fn auth_authorized_domains_emulator_exposes_seed_without_enforcing_it_and_routes_new_projects() {
    let daemon = Daemon::start("emulator", "emulator", &auth(&json!([])));
    assert_eq!(domains_of(&daemon, PROJECT), json!([]));
    assert_eq!(link(&daemon, "outside.test").0, 200);
    set_domains(&daemon, PROJECT, &json!(["runtime.test"]));
    assert_eq!(domains_of(&daemon, "routed-project"), json!([]));
    daemon.reset();
    assert_eq!(domains_of(&daemon, "routed-project"), json!([]));
}

#[test]
fn auth_authorized_domains_later_session_projects_start_and_reset_to_seed() {
    let daemon = Daemon::start("sessions", "strict", &auth(&json!(["app.test"])));
    set_domains(&daemon, PROJECT, &json!(["runtime.test"]));
    let (status, body) = http(
        daemon.control_port(),
        "POST",
        "/v1/sessions",
        "",
        &json!({"project": "demo-second"}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(domains_of(&daemon, "demo-second"), json!(["app.test"]));
    set_domains(&daemon, "demo-second", &json!(["changed.test"]));
    let (status, body) = http(
        daemon.control_port(),
        "POST",
        "/v1/sessions/demo-second/reset",
        "",
        &json!({}),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(domains_of(&daemon, "demo-second"), json!(["app.test"]));
}

#[test]
fn auth_authorized_domains_accounts_delete_keeps_runtime_domains() {
    for profile in ["strict", "emulator"] {
        let daemon = Daemon::start("delete", profile, &auth(&json!(["seed.test"])));
        set_domains(&daemon, PROJECT, &json!(["live.test"]));
        let (status, body) = http(
            daemon.auth_port(),
            "DELETE",
            &format!("/emulator/v1/projects/{PROJECT}/accounts"),
            "",
            &Value::Null,
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(domains_of(&daemon, PROJECT), json!(["live.test"]));
        daemon.reset();
        assert_eq!(domains_of(&daemon, PROJECT), json!(["seed.test"]));
    }
}

#[test]
fn auth_authorized_domains_invalid_admin_patch_keeps_exact_refusal_and_live_list() {
    let daemon = Daemon::start(
        "invalid-admin",
        "strict",
        &json!({"apiKeys": ["fake-api-key"]}),
    );
    let before = domains_of(&daemon, PROJECT);
    for value in [json!(true), json!({}), json!("app.test"), json!([{}])] {
        let (status, body) = http(daemon.auth_port(), "PATCH", &format!("/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config?updateMask=authorizedDomains"), OWNER, &json!({"authorizedDomains": value}));
        assert_eq!(status, 400, "{value}: {body}");
        let (field, description) = if value.is_array() {
            (
                "config.authorized_domains[0]",
                "Invalid value at 'config.authorized_domains[0]' (TYPE_STRING), {}",
            )
        } else {
            ("config.authorized_domains", "Invalid value at 'config.authorized_domains', Proto field is repeated but value is not a list")
        };
        assert_eq!(
            body,
            json!({"error": {"code": 400, "message": description, "status": "INVALID_ARGUMENT", "details": [{"@type": "type.googleapis.com/google.rpc.BadRequest", "fieldViolations": [{"field": field, "description": description}]}]}})
        );
        assert_eq!(domains_of(&daemon, PROJECT), before);
    }
    for (value, message) in [
        (
            json!([""]),
            "INVALID_AUTHORIZED_DOMAIN : An authorized domain is empty.",
        ),
        (
            json!(["https://app.test"]),
            "INVALID_AUTHORIZED_DOMAIN : https://app.test should only contain the valid domain.",
        ),
    ] {
        let (status, body) = http(daemon.auth_port(), "PATCH", &format!("/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config?updateMask=authorizedDomains"), OWNER, &json!({"authorizedDomains": value}));
        assert_eq!(status, 400);
        assert_eq!(
            body,
            json!({"error": {"code": 400, "message": message, "status": "INVALID_ARGUMENT"}})
        );
        assert_eq!(domains_of(&daemon, PROJECT), before);
    }
    set_domains(
        &daemon,
        PROJECT,
        &json!([1, true, null, "APP.test", "APP.test"]),
    );
    assert_eq!(
        domains_of(&daemon, PROJECT),
        json!(["1", "true", "APP.test", "APP.test"])
    );
    set_domains(&daemon, PROJECT, &Value::Null);
    assert_eq!(domains_of(&daemon, PROJECT), json!([]));
}

#[test]
fn auth_authorized_domains_invalid_startup_names_the_key() {
    let dir = TrustedTempDir::new("auth-domains-invalid");
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        json!({"schemaVersion": 1, "auth": {"authorizedDomains": [""]}}).to_string(),
    )
    .unwrap();
    let mut child = StartupChild(
        Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args([
                "up",
                "--config",
                config.to_str().unwrap(),
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
                "0",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "invalid domain config did not stop startup"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let mut stderr = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(!status.success());
    assert!(stderr.contains("auth.authorizedDomains"));
}

#[test]
fn auth_authorized_domains_startup_import_keeps_declared_domains_and_imports_accounts() {
    let dir = TrustedTempDir::new("auth-domains-import");
    std::fs::create_dir(dir.join("auth_export")).unwrap();
    std::fs::write(
        dir.join("firebase-export-metadata.json"),
        json!({"version": "15.28.2", "auth": {"version": "15.28.2", "path": "auth_export"}})
            .to_string(),
    )
    .unwrap();
    std::fs::write(
        dir.join("auth_export/config.json"),
        json!({"signIn": {"allowDuplicateEmails": false}}).to_string(),
    )
    .unwrap();
    std::fs::write(dir.join("auth_export/accounts.json"), json!({"users": [{"localId": "imported-user", "email": "imported@example.com", "createdAt": "100000"}]}).to_string()).unwrap();
    for settings in [
        auth(&json!(["seed.test"])),
        json!({"apiKeys": ["fake-api-key"]}),
    ] {
        let daemon = Daemon::spawn(
            "import",
            "strict",
            &settings,
            &["--import", dir.path().to_str().unwrap()],
        );
        assert_eq!(
            domains_of(&daemon, PROJECT),
            settings
                .get("authorizedDomains")
                .cloned()
                .unwrap_or_else(|| json!([
                    "localhost",
                    format!("{PROJECT}.firebaseapp.com"),
                    format!("{PROJECT}.web.app")
                ]))
        );
        let (status, body) = http(
            daemon.auth_port(),
            "POST",
            &format!("{V1}/projects/{PROJECT}/accounts:lookup"),
            OWNER,
            &json!({"localId": ["imported-user"]}),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["users"][0]["localId"], "imported-user");
    }
    census::assert_no_owned_descendants(
        "authorized-domain import daemons",
        Duration::from_secs(10),
    );
}
