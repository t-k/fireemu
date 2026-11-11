//! `fireemu config show --json` and `fireemu config lint --json` never print a secret value
//! that the configuration carries. The sentinels are built at run time, so the source holds
//! no complete token-shaped literal.

mod scratch;

use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use scratch::Scratch;

fn fireemu(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fireemu"))
        .current_dir(cwd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn sentinel(name: &str) -> String {
    format!("{}{}", "sentinel-", name)
}

fn planted_config() -> String {
    let digest = "cd".repeat(32);
    format!(
        r#"{{
  "schemaVersion": 1,
  "pubsub": {{"authentication": {{"localBearerToken": "{bearer}"}}}},
  "auth": {{
    "apiKeys": ["{api_key}"],
    "providers": {{"oidc": [{{
      "name": "oidc.fixture",
      "enabled": true,
      "clientId": "visible-client-id",
      "issuer": "https://issuer.test",
      "clientSecret": "{oidc}"
    }}]}}
  }},
  "appCheck": {{"enabled": true, "apps": [{{
    "projectId": "demo-app",
    "projectNumber": "1234567890",
    "appId": "1:1234567890:web:abc",
    "debugTokenSha256": ["{digest}"]
  }}]}}
}}
"#,
        bearer = sentinel("bearer-0001"),
        api_key = sentinel("api-key-0002"),
        oidc = sentinel("oidc-secret-0003"),
        digest = digest,
    )
}

#[test]
fn config_show_and_lint_json_succeed_with_the_expected_shape_and_never_print_planted_secrets() {
    let dir = Scratch::new("config-secret", "planted");
    std::fs::write(dir.join("fireemu.json"), planted_config()).unwrap();
    let show = fireemu(
        &dir,
        &["config", "show", "--config", "fireemu.json", "--json"],
    );
    let lint = fireemu(
        &dir,
        &["config", "lint", "--config", "fireemu.json", "--json"],
    );
    let planted = [
        sentinel("bearer-0001"),
        sentinel("api-key-0002"),
        sentinel("oidc-secret-0003"),
        "cd".repeat(32),
    ];
    // Both commands must succeed and print the documented JSON, so an early failure cannot
    // pass the absence checks below.
    assert!(
        show.status.success(),
        "show failed: {}",
        String::from_utf8_lossy(&show.stderr)
    );
    assert!(
        lint.status.success(),
        "lint failed: {}",
        String::from_utf8_lossy(&lint.stderr)
    );
    let rows: Value = serde_json::from_slice(&show.stdout).expect("config show --json is JSON");
    let rows = rows
        .as_array()
        .expect("config show --json is an array of rows");
    let row = |key: &str| {
        rows.iter()
            .find(|row| row["key"] == key)
            .unwrap_or_else(|| panic!("config show has no {key} row"))
    };
    assert_eq!(
        row("pubsub.authentication.localBearerToken")["value"],
        "[redacted]"
    );
    assert_eq!(
        row("auth.apiKeys")["value"],
        serde_json::json!(["[redacted]"])
    );
    assert_eq!(
        row("auth.providers.oidc")["value"][0]["clientSecret"],
        "[redacted]"
    );
    assert_eq!(
        row("auth.providers.oidc")["value"][0]["clientId"],
        "visible-client-id"
    );
    let report: Value = serde_json::from_slice(&lint.stdout).expect("config lint --json is JSON");
    assert!(
        report["config"].is_string(),
        "lint report names the config: {report}"
    );
    assert!(
        report["ineffective"].is_array(),
        "lint report lists ineffective settings: {report}"
    );
    assert!(
        report["denied"].is_array(),
        "lint report lists denied settings: {report}"
    );
    for output in [&show, &lint] {
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for secret in &planted {
            assert!(!text.contains(secret.as_str()), "{secret} printed:\n{text}");
        }
    }
}
