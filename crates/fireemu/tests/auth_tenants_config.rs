//! `auth.multiTenant` and `auth.tenants[]`: the default project's multi-tenancy switch and its
//! tenants, declared in the configuration file. A tenant is created as the Admin create route
//! creates one, with the id the file names; the runtime is unchanged. A control-plane reset
//! creates the declared tenants again, empty, and an `--import` is authoritative for a tenant of
//! the same id.

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
const PROJECT: &str = "demo-tenant-seed";
const OWNER: &str = "Authorization: Bearer owner\r\n";

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
    _dir: TrustedTempDir,
}

impl Daemon {
    /// A daemon under `profile` whose `auth` section is `auth`. Every port is chosen by the
    /// daemon (`0`) and read from its banner, so no port is picked here and released before the
    /// daemon binds it.
    fn start(name: &str, profile: &str, auth: &Value) -> Self {
        let dir = TrustedTempDir::new(&format!("auth-tenants-config-{name}"));
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            json!({"schemaVersion": 1, "profile": profile, "auth": auth}).to_string(),
        )
        .unwrap();
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
                "0",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        // The child is owned (and killed on drop) before anything below can panic.
        let daemon = Self {
            child,
            banner: Arc::new(Mutex::new(String::new())),
            _dir: dir,
        };
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

    fn admin(&self, method: &str, path: &str, body: &Value) -> (u16, Value) {
        http(self.auth_port(), method, path, OWNER, body)
    }

    /// The tenant ids the Admin list route returns, sorted.
    fn tenant_ids(&self) -> Vec<String> {
        let (status, listed) = self.admin(
            "GET",
            &format!("{V2}/projects/{PROJECT}/tenants"),
            &json!({}),
        );
        assert_eq!(status, 200, "{listed}");
        let mut ids: Vec<String> = listed["tenants"]
            .as_array()
            .map(|tenants| {
                tenants
                    .iter()
                    .filter_map(|t| t["name"].as_str())
                    .filter_map(|name| name.rsplit('/').next())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        ids.sort();
        ids
    }

    fn tenant(&self, id: &str) -> (u16, Value) {
        self.admin(
            "GET",
            &format!("{V2}/projects/{PROJECT}/tenants/{id}"),
            &json!({}),
        )
    }

    fn multi_tenant(&self) -> Value {
        let (status, config) = self.admin(
            "GET",
            &format!("/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config"),
            &json!({}),
        );
        assert_eq!(status, 200, "{config}");
        config["multiTenant"].clone()
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

    /// Creates an account in `tenant`.
    fn add_user(&self, tenant: &str, email: &str) {
        let (status, created) = self.admin(
            "POST",
            &format!("{V1}/projects/{PROJECT}/tenants/{tenant}/accounts"),
            &json!({"email": email, "password": "password123"}),
        );
        assert_eq!(status, 200, "{created}");
    }

    /// The number of accounts `tenant` holds.
    fn user_count(&self, tenant: &str) -> usize {
        let (status, listed) = self.admin(
            "POST",
            &format!("{V1}/projects/{PROJECT}/tenants/{tenant}/accounts:query"),
            &json!({"returnUserInfo": false}),
        );
        assert_eq!(status, 200, "{listed}");
        listed["recordsCount"]
            .as_str()
            .and_then(|count| count.parse().ok())
            .unwrap_or(0)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn acme() -> Value {
    json!({
        "tenantId": "acme-x7k2q",
        "displayName": "acme",
        "allowPasswordSignup": true,
        "mfaConfig": {"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}
    })
}

fn beta() -> Value {
    json!({"tenantId": "beta-a1b2c", "displayName": "beta"})
}

fn declared(allow: bool) -> Value {
    json!({
        "apiKeys": ["fake-api-key"],
        "multiTenant": {"allowTenants": allow},
        "tenants": [acme(), beta()]
    })
}

#[test]
fn both_profiles_start_with_the_declared_tenants_under_the_ids_of_the_file() {
    for profile in ["strict", "emulator"] {
        let daemon = Daemon::start(profile, profile, &declared(true));
        assert_eq!(
            daemon.tenant_ids(),
            ["acme-x7k2q", "beta-a1b2c"],
            "{profile}"
        );
        let (status, document) = daemon.tenant("acme-x7k2q");
        assert_eq!(status, 200, "{profile}: {document}");
        assert_eq!(document["displayName"], "acme", "{profile}: {document}");
        assert_eq!(
            document["allowPasswordSignup"], true,
            "{profile}: {document}"
        );
        assert_eq!(
            document["mfaConfig"],
            json!({"state": "ENABLED", "enabledProviders": ["PHONE_SMS"]}),
            "{profile}: {document}"
        );
        assert_eq!(
            daemon.multi_tenant(),
            json!({"allowTenants": true}),
            "{profile}"
        );
        // The tenants are empty, and usable as any tenant is.
        assert_eq!(daemon.user_count("acme-x7k2q"), 0, "{profile}");
        daemon.add_user("acme-x7k2q", "a@example.test");
        assert_eq!(daemon.user_count("acme-x7k2q"), 1, "{profile}");
        assert_eq!(daemon.user_count("beta-a1b2c"), 0, "{profile}");
    }
    census::assert_no_owned_descendants("the auth tenants daemons", Duration::from_secs(10));
}

#[test]
fn the_profile_decides_how_a_tenant_document_reads_back() {
    // The emulator profile keeps a tenant's emailPrivacyConfig as the official emulator does (a
    // create keeps none); strict keeps what production keeps. The seed follows the profile as the
    // create route does.
    let mut with_privacy = acme();
    with_privacy["emailPrivacyConfig"] = json!({"enableImprovedEmailPrivacy": true});
    let auth = json!({
        "apiKeys": ["fake-api-key"],
        "multiTenant": {"allowTenants": true},
        "tenants": [with_privacy]
    });
    let strict = Daemon::start("privacy-strict", "strict", &auth);
    let (status, document) = strict.tenant("acme-x7k2q");
    assert_eq!(status, 200, "{document}");
    assert_eq!(
        document["emailPrivacyConfig"],
        json!({"enableImprovedEmailPrivacy": true}),
        "{document}"
    );
    let emulator = Daemon::start("privacy-emulator", "emulator", &auth);
    let (status, document) = emulator.tenant("acme-x7k2q");
    assert_eq!(status, 200, "{document}");
    assert!(document.get("emailPrivacyConfig").is_none(), "{document}");
}

#[test]
fn the_emulator_profile_takes_tenants_without_the_switch() {
    let mut auth = declared(true);
    auth.as_object_mut().unwrap().remove("multiTenant");
    let daemon = Daemon::start("no-switch", "emulator", &auth);
    assert_eq!(daemon.tenant_ids(), ["acme-x7k2q", "beta-a1b2c"]);
}

#[test]
fn strict_refuses_tenants_without_the_switch_before_it_starts() {
    let dir = TrustedTempDir::new("auth-tenants-config-refused");
    for auth in [
        json!({"tenants": [acme()]}),
        json!({"multiTenant": {"allowTenants": false}, "tenants": [acme()]}),
        json!({"multiTenant": {"allowTenants": true}, "tenants": [{"tenantId": "wrong", "displayName": "acme"}]}),
    ] {
        let config = dir.join("fireemu.json");
        std::fs::write(
            &config,
            json!({"schemaVersion": 1, "profile": "strict", "auth": auth}).to_string(),
        )
        .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_fireemu"))
            .args(["up", "--config", config.to_str().unwrap(), "--only", "auth"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!out.status.success(), "{auth}");
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(text.contains("auth."), "{auth}: {text}");
    }
}

#[test]
fn a_reset_creates_the_declared_tenants_again_empty_and_restores_the_declared_switch() {
    let daemon = Daemon::start("reset", "strict", &declared(true));
    daemon.add_user("acme-x7k2q", "a@example.test");
    let (status, extra) = daemon.admin(
        "POST",
        &format!("{V2}/projects/{PROJECT}/tenants"),
        &json!({"displayName": "extra"}),
    );
    assert_eq!(status, 200, "{extra}");
    assert_eq!(daemon.tenant_ids().len(), 3);
    // An Admin update turns the switch off.
    let (status, updated) = daemon.admin(
        "PATCH",
        &format!(
            "/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config?updateMask=multiTenant.allowTenants"
        ),
        &json!({"multiTenant": {"allowTenants": false}}),
    );
    assert_eq!(status, 200, "{updated}");
    daemon.reset();
    assert_eq!(daemon.tenant_ids(), ["acme-x7k2q", "beta-a1b2c"]);
    assert_eq!(daemon.user_count("acme-x7k2q"), 0);
    assert_eq!(daemon.multi_tenant(), json!({"allowTenants": true}));
    let (status, document) = daemon.tenant("acme-x7k2q");
    assert_eq!(status, 200, "{document}");
    assert_eq!(document["displayName"], "acme");
}

#[test]
fn a_reset_without_a_declared_switch_keeps_an_admin_set_one_and_drops_the_run_s_tenants() {
    let mut auth = declared(true);
    auth.as_object_mut().unwrap().remove("multiTenant");
    let daemon = Daemon::start("reset-undeclared", "emulator", &auth);
    let (status, updated) = daemon.admin(
        "PATCH",
        &format!(
            "/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/config?updateMask=multiTenant.allowTenants"
        ),
        &json!({"multiTenant": {"allowTenants": true}}),
    );
    assert_eq!(status, 200, "{updated}");
    daemon.reset();
    assert_eq!(daemon.tenant_ids(), ["acme-x7k2q", "beta-a1b2c"]);
    assert_eq!(daemon.multi_tenant(), json!({"allowTenants": true}));
}

fn exec(config: &std::path::Path, extra: &[&str], script: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .args([
            "exec",
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
            "--logging-port",
            "0",
            "--ui-port",
            "0",
            "--hub-port",
            "0",
        ])
        .args(extra)
        .args(["--", "/bin/sh", "-c", script])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "{log}");
    log
}

#[test]
fn an_import_is_authoritative_for_a_tenant_of_the_same_id_and_the_seed_keeps_the_others() {
    let dir = TrustedTempDir::new("auth-tenants-config-import");
    let out = dir.join("out");
    let base = "http://$FIREBASE_AUTH_EMULATOR_HOST/identitytoolkit.googleapis.com";
    let admin = "-H 'Authorization: Bearer owner' -H 'Content-Type: application/json'";
    let tenant = |id: &str| format!("{base}/v2/projects/{PROJECT}/tenants/{id}");
    let write_config = |name: &str, tenants: &Value| {
        let path = dir.join(name);
        std::fs::write(
            &path,
            json!({
                "schemaVersion": 1,
                "profile": "emulator",
                "auth": {"multiTenant": {"allowTenants": true}, "tenants": tenants}
            })
            .to_string(),
        )
        .unwrap();
        path
    };
    // Run 1 exports acme, whose file document says signup is allowed, with one account.
    let first = write_config("first.json", &json!([acme()]));
    let seed_user = format!(
        r#"curl -s -X POST "{base}/v1/projects/{PROJECT}/tenants/acme-x7k2q/accounts" {admin} -d '{{"email":"kept@example.test","password":"password123"}}' >/dev/null"#
    );
    exec(
        &first,
        &["--export-on-exit", out.to_str().unwrap()],
        &seed_user,
    );
    // Run 2 declares acme differently and a second tenant, and imports run 1.
    let mut changed = acme();
    changed["allowPasswordSignup"] = json!(false);
    let second = write_config("second.json", &json!([changed, beta()]));
    let read = format!(
        r#"printf '%s\n' "LIST $(curl -s "{base}/v2/projects/{PROJECT}/tenants" {admin})"; printf '%s\n' "ACME $(curl -s "{acme}" {admin})"; printf '%s\n' "BETA $(curl -s "{beta}" {admin})""#,
        acme = tenant("acme-x7k2q"),
        beta = tenant("beta-a1b2c"),
    );
    let log = exec(&second, &["--import", out.to_str().unwrap()], &read);
    let field = |prefix: &str| -> Value {
        log.lines()
            .find_map(|line| line.strip_prefix(prefix))
            .map(|rest| serde_json::from_str(rest).unwrap_or(Value::Null))
            .unwrap_or_else(|| panic!("{prefix} was printed: {log}"))
    };
    let listed = field("LIST ");
    let mut ids: Vec<&str> = listed["tenants"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .filter_map(|name| name.rsplit('/').next())
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, ["acme-x7k2q", "beta-a1b2c"], "{log}");
    // The imported document wins for the tenant of the same id.
    assert_eq!(field("ACME ")["allowPasswordSignup"], true, "{log}");
    // The tenant only the seed declares is still there.
    assert_eq!(field("BETA ")["displayName"], "beta", "{log}");
}
