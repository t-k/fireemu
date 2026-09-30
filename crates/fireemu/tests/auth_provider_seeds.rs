//! Startup provider declarations and their project lifecycle.

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

const PROJECT: &str = "demo-provider-seed";
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
    stderr: Arc<Mutex<String>>,
    _dir: TrustedTempDir,
}

impl Daemon {
    /// A daemon under `profile` whose `auth` section is `auth`. Every port is chosen by the daemon (`0`) and read from its banner, so no port is picked here and released before the daemon binds it.
    fn start(name: &str, profile: &str, auth: &Value) -> Self {
        Self::spawn(name, profile, auth, &[])
    }

    fn spawn(name: &str, profile: &str, auth: &Value, extra: &[&str]) -> Self {
        let dir = TrustedTempDir::new(&format!("auth-provider-seeds-{name}"));
        let config = dir.join("fireemu.json");
        let mut auth = auth.clone();
        auth["apiKeys"] = json!(["provider-fixture-key"]);
        std::fs::write(
            &config,
            json!({"schemaVersion": 1, "profile": profile, "auth": auth, "daemon":{"clockStart":"2027-01-15T08:00:30Z"}}).to_string(),
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

fn oidc(name: &str) -> Value {
    json!({"name":name,"enabled":true,"clientId":"local-client","issuer":"https://issuer.test"})
}
fn providers(daemon: &Daemon, project: &str, kind: &str) -> Value {
    let (status, body) = http(
        daemon.auth_port(),
        "GET",
        &format!("/identitytoolkit.googleapis.com/admin/v2/projects/{project}/{kind}"),
        OWNER,
        &Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    body.get(kind).cloned().unwrap_or_else(|| json!([]))
}
#[test]
fn auth_provider_seeds_default_reset_restores_declaration_and_undeclared_saml() {
    let daemon = Daemon::start(
        "seed-reset",
        "strict",
        &json!({"providers":{"oidc":[oidc("oidc.seed")]}}),
    );
    assert_eq!(
        providers(&daemon, PROJECT, "oauthIdpConfigs")[0]["name"],
        format!("projects/{PROJECT}/oauthIdpConfigs/oidc.seed")
    );
    let path = format!(
        "/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/oauthIdpConfigs/oidc.seed"
    );
    assert_eq!(
        http(daemon.auth_port(), "DELETE", &path, OWNER, &Value::Null).0,
        200
    );
    assert_eq!(providers(&daemon, PROJECT, "oauthIdpConfigs"), json!([]));
    daemon.reset();
    assert_eq!(
        providers(&daemon, PROJECT, "oauthIdpConfigs")
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

const V1: &str = "/identitytoolkit.googleapis.com/v1";
fn patch_enabled(daemon: &Daemon, project: &str, kind: &str, id: &str, enabled: bool) {
    let (status,body)=http(daemon.auth_port(),"PATCH",&format!("/identitytoolkit.googleapis.com/admin/v2/projects/{project}/{kind}/{id}?updateMask=enabled"),OWNER,&json!({"enabled":enabled}));
    assert_eq!(status, 200, "{body}");
}
fn saml(name: &str) -> Value {
    json!({"name":name,"enabled":true,"idpConfig":{"idpEntityId":"https://idp.example.test/saml/fixture","ssoUrl":"https://idp.example.test/saml/fixture/sso","idpCertificates":[{"x509Certificate":"fixture-certificate"}]},"spConfig":{"spEntityId":"fireemu-fixture-sp","callbackUri":"https://demo-project.firebaseapp.com/__/auth/handler"}})
}
#[test]
fn auth_provider_seeds_partial_reset_preserves_admin_saml_and_builtin_resources() {
    let daemon = Daemon::start("partial", "strict", &json!({"providers":{"oidc":[]}}));
    let base = format!("/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}");
    assert_eq!(
        http(
            daemon.auth_port(),
            "POST",
            &format!("{base}/inboundSamlConfigs?inboundSamlConfigId=saml.live"),
            OWNER,
            &saml("saml.live")
        )
        .0,
        200
    );
    assert_eq!(
        http(
            daemon.auth_port(),
            "POST",
            &format!("{base}/oauthIdpConfigs?oauthIdpConfigId=oidc.live"),
            OWNER,
            &oidc("oidc.live")
        )
        .0,
        200
    );
    let (status, body) = http(
        daemon.auth_port(),
        "POST",
        &format!("{base}/defaultSupportedIdpConfigs?idpId=google.com"),
        OWNER,
        &json!({"enabled":true,"clientId":"builtin-client"}),
    );
    assert_eq!(status, 200, "{body}");
    daemon.reset();
    assert_eq!(providers(&daemon, PROJECT, "oauthIdpConfigs"), json!([]));
    assert_eq!(
        providers(&daemon, PROJECT, "inboundSamlConfigs")
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        http(
            daemon.auth_port(),
            "GET",
            &format!("{base}/defaultSupportedIdpConfigs/google.com"),
            OWNER,
            &Value::Null
        )
        .1["clientId"],
        "builtin-client"
    );
}
#[test]
fn auth_provider_seeds_unseeded_reset_preserves_admin_and_delete_accounts_keeps_live_config() {
    for settings in [
        json!({}),
        json!({"providers":null}),
        json!({"providers":{"oidc":null}}),
    ] {
        let daemon = Daemon::start("undeclared", "strict", &settings);
        let base =
            format!("/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}/oauthIdpConfigs");
        assert_eq!(
            http(
                daemon.auth_port(),
                "POST",
                &format!("{base}?oauthIdpConfigId=oidc.live"),
                OWNER,
                &oidc("oidc.live")
            )
            .0,
            200
        );
        daemon.reset();
        assert_eq!(
            providers(&daemon, PROJECT, "oauthIdpConfigs")
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }
    let daemon = Daemon::start(
        "clear",
        "strict",
        &json!({"providers":{"oidc":[oidc("oidc.seed")]}}),
    );
    patch_enabled(&daemon, PROJECT, "oauthIdpConfigs", "oidc.seed", false);
    assert_eq!(
        http(
            daemon.auth_port(),
            "DELETE",
            &format!("/emulator/v1/projects/{PROJECT}/accounts"),
            "",
            &Value::Null
        )
        .0,
        200
    );
    assert!(
        !providers(&daemon, PROJECT, "oauthIdpConfigs")[0]["enabled"]
            .as_bool()
            .unwrap_or(false)
    );
    daemon.reset();
    assert_eq!(
        providers(&daemon, PROJECT, "oauthIdpConfigs")[0]["enabled"],
        true
    );
}
#[test]
fn auth_provider_seeds_later_session_project_and_reset_use_declaration() {
    let daemon = Daemon::start(
        "session",
        "strict",
        &json!({"providers":{"oidc":[oidc("oidc.seed")]}}),
    );
    patch_enabled(&daemon, PROJECT, "oauthIdpConfigs", "oidc.seed", false);
    assert_eq!(
        http(
            daemon.control_port(),
            "POST",
            "/v1/sessions",
            "",
            &json!({"project":"demo-second"})
        )
        .0,
        200
    );
    assert_eq!(
        providers(&daemon, "demo-second", "oauthIdpConfigs")[0]["enabled"],
        true
    );
    patch_enabled(
        &daemon,
        "demo-second",
        "oauthIdpConfigs",
        "oidc.seed",
        false,
    );
    assert_eq!(
        http(
            daemon.control_port(),
            "POST",
            "/v1/sessions/demo-second/reset",
            "",
            &json!({})
        )
        .0,
        200
    );
    assert_eq!(
        providers(&daemon, "demo-second", "oauthIdpConfigs")[0]["enabled"],
        true
    );
}
#[test]
fn auth_provider_seeds_emulator_fixture_answers_do_not_require_enabled_resource() {
    let unsigned = fireemu_core_auth::jwt::encode_payload_with(
        &json!({"sub":"fixture-sub","email":"fixture@example.test"}).to_string(),
        None,
    );
    for settings in [
        json!({}),
        json!({"providers":{"oidc":[]}}),
        json!({"providers":{"oidc":[{"name":"oidc.seed","enabled":false,"clientId":"other","issuer":"http://other.test"}]}}),
    ] {
        let daemon = Daemon::start("emulator", "emulator", &settings);
        let (status, body) = http(
            daemon.auth_port(),
            "POST",
            &format!("{V1}/accounts:signInWithIdp?key=provider-fixture-key"),
            "",
            &json!({"requestUri":"http://localhost","postBody":format!("providerId=oidc.seed&id_token={unsigned}"),"returnSecureToken":true}),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["providerId"], "oidc.seed");
        if settings.get("providers").is_some() {
            assert_eq!(
                providers(&daemon, "routed-project", "oauthIdpConfigs")
                    .as_array()
                    .unwrap()
                    .len(),
                usize::from(
                    settings["providers"]["oidc"]
                        .as_array()
                        .is_some_and(|v| !v.is_empty())
                )
            );
        }
    }
}
#[test]
fn auth_provider_seeds_strict_oidc_requires_live_enabled_config_and_local_signature() {
    use fireemu_adapter_http::signing::RsaSigner;
    let signer = RsaSigner::from_seed(4401).unwrap();
    let auth = json!({"providers":{"oidc":[oidc("oidc.seed")]},"idpSigners":{"https://issuer.test":signer.jwks()}});
    let daemon = Daemon::start("oidc-trust", "strict", &auth);
    let token=fireemu_core_auth::jwt::encode_payload_with(&json!({"sub":"signed-sub","iss":"https://issuer.test","aud":"local-client","iat":1_800_000_030,"exp":1_800_000_090}).to_string(),Some(signer.as_ref()));
    let request = json!({"requestUri":"http://localhost","postBody":format!("providerId=oidc.seed&id_token={token}"),"returnSecureToken":true});
    let (status, body) = http(
        daemon.auth_port(),
        "POST",
        &format!("{V1}/accounts:signInWithIdp?key=provider-fixture-key"),
        "",
        &request,
    );
    assert_eq!(status, 200, "{body}");
    assert!(body["idToken"].is_string());
    patch_enabled(&daemon, PROJECT, "oauthIdpConfigs", "oidc.seed", false);
    let (status, body) = http(
        daemon.auth_port(),
        "POST",
        &format!("{V1}/accounts:signInWithIdp?key=provider-fixture-key"),
        "",
        &request,
    );
    assert_eq!(status, 400);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("configuration is disabled"));
}
#[test]
fn auth_provider_seeds_strict_saml_uses_seeded_resource_without_relaxing_signatures() {
    let config = saml("saml.seed");
    let daemon = Daemon::start("saml", "strict", &json!({"providers":{"saml":[config]}}));
    let (status, body) = http(
        daemon.auth_port(),
        "POST",
        &format!("{V1}/accounts:createAuthUri?key=provider-fixture-key"),
        "",
        &json!({"providerId":"saml.seed","continueUri":"http://localhost"}),
    );
    assert_eq!(status, 200, "{body}");
    assert!(body["authUri"]
        .as_str()
        .unwrap()
        .starts_with("https://idp.example.test/saml/fixture/sso?SAMLRequest="));
    let (status, body) = http(
        daemon.auth_port(),
        "POST",
        &format!("{V1}/accounts:signInWithIdp?key=provider-fixture-key"),
        "",
        &json!({"requestUri":"http://localhost","postBody":"providerId=saml.seed&SAMLResponse=invalid","returnSecureToken":true}),
    );
    assert_eq!(status, 400, "{body}");
    assert!(body["idToken"].is_null());
    patch_enabled(&daemon, PROJECT, "inboundSamlConfigs", "saml.seed", false);
    assert_eq!(
        http(
            daemon.auth_port(),
            "POST",
            &format!("{V1}/accounts:createAuthUri?key=provider-fixture-key"),
            "",
            &json!({"providerId":"saml.seed","continueUri":"http://localhost"})
        )
        .0,
        400
    );
}
#[test]
fn auth_provider_seeds_tenant_resources_remain_separate() {
    let daemon = Daemon::start(
        "tenants",
        "strict",
        &json!({"providers":{"oidc":[oidc("oidc.seed")]}}),
    );
    let base = format!("/identitytoolkit.googleapis.com/admin/v2/projects/{PROJECT}");
    let (status, body) = http(
        daemon.auth_port(),
        "PATCH",
        &format!("{base}/config?updateMask=multiTenant.allowTenants"),
        OWNER,
        &json!({"multiTenant":{"allowTenants":true}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = http(
        daemon.auth_port(),
        "POST",
        &format!("/identitytoolkit.googleapis.com/v2/projects/{PROJECT}/tenants"),
        OWNER,
        &json!({"displayName":"fixture"}),
    );
    assert_eq!(status, 200, "{body}");
    let name = body["name"].as_str().unwrap();
    let tenant = name.rsplit('/').next().unwrap();
    let (status, body) = http(
        daemon.auth_port(),
        "GET",
        &format!("/identitytoolkit.googleapis.com/v2/projects/{PROJECT}/tenants/{tenant}/oauthIdpConfigs"),
        OWNER,
        &Value::Null,
    );
    assert_eq!(status, 200, "{body}");
    assert!(body
        .get("oauthIdpConfigs")
        .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)));
}

struct StartupChild(Child);
impl Drop for StartupChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn auth_provider_seeds_invalid_startup_names_the_key() {
    let dir = TrustedTempDir::new("auth-providers-invalid");
    let config = dir.join("fireemu.json");
    std::fs::write(
        &config,
        json!({"schemaVersion": 1, "auth": {"providers": {"oidc": [{"name":"oidc.fixture", "clientSecret":"DO-NOT-LOG-SECRET"}]}}}).to_string(),
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
            "invalid provider config did not stop startup"
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
    assert!(stderr.contains("auth.providers.oidc[0]"));
    assert!(!stderr.contains("DO-NOT-LOG-SECRET"));
}

#[test]
fn auth_provider_seeds_startup_account_import_keeps_current_declaration() {
    let dir = TrustedTempDir::new("auth-providers-import");
    std::fs::create_dir(dir.join("auth_export")).unwrap();
    std::fs::write(
        dir.join("firebase-export-metadata.json"),
        json!({"version":"15.28.2","auth":{"version":"15.28.2","path":"auth_export"}}).to_string(),
    )
    .unwrap();
    std::fs::write(
        dir.join("auth_export/config.json"),
        json!({"signIn":{"allowDuplicateEmails":false}}).to_string(),
    )
    .unwrap();
    std::fs::write(dir.join("auth_export/accounts.json"),json!({"users":[{"localId":"imported-user","email":"imported@example.test","createdAt":"100000"}]}).to_string()).unwrap();
    for settings in [json!({}), json!({"providers":{"oidc":[oidc("oidc.seed")]}})] {
        let daemon = Daemon::spawn(
            "import",
            "strict",
            &settings,
            &["--import", dir.path().to_str().unwrap()],
        );
        assert_eq!(
            providers(&daemon, PROJECT, "oauthIdpConfigs")
                .as_array()
                .unwrap()
                .len(),
            usize::from(settings.get("providers").is_some())
        );
        let (status, body) = http(
            daemon.auth_port(),
            "POST",
            &format!("{V1}/projects/{PROJECT}/accounts:lookup"),
            OWNER,
            &json!({"localId":["imported-user"]}),
        );
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["users"][0]["localId"], "imported-user");
    }
    census::assert_no_owned_descendants("provider seed daemon children", Duration::from_secs(3));
}

#[test]
fn auth_provider_seeds_strict_saml_signed_fixture_uses_declared_certificate() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fireemu-adapter-http/tests/data/saml");
    let mut config = saml("saml.seed");
    config["idpConfig"]["idpCertificates"] =
        json!([{"x509Certificate":std::fs::read_to_string(root.join("idp.cert.pem")).unwrap()}]);
    let daemon = Daemon::start(
        "saml-signed",
        "strict",
        &json!({"providers":{"saml":[config]}}),
    );
    for (file, expected) in [
        ("assertion-signed.xml", 200),
        ("tampered-signature.xml", 400),
    ] {
        let xml = std::fs::read_to_string(root.join(file)).unwrap();
        let encoded = fireemu_core_types::hash::base64_standard(xml.as_bytes())
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        let (status, body) = http(
            daemon.auth_port(),
            "POST",
            &format!("{V1}/accounts:signInWithIdp?key=provider-fixture-key"),
            "",
            &json!({"requestUri":"https://demo-app.firebaseapp.com/__/auth/handler","postBody":format!("providerId=saml.seed&SAMLResponse={encoded}"),"returnSecureToken":true}),
        );
        assert_eq!(status, expected, "{file}: {body}");
        if expected == 200 {
            assert_eq!(body["providerId"], "saml.seed");
            assert_eq!(body["email"], "fixture-user@example.com");
        } else {
            assert!(body["idToken"].is_null());
        }
    }
}
