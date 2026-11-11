//! `fireemu config show --json` and `fireemu config lint --json` never print a secret value
//! that the configuration carries. The sentinels are built at run time, so the source holds
//! no complete token-shaped literal.

mod scratch;

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
fn config_show_and_lint_json_never_print_planted_secrets() {
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
    let shown = String::from_utf8_lossy(&show.stdout);
    assert!(shown.contains("[redacted]"), "{shown}");
    assert!(shown.contains("visible-client-id"), "{shown}");
}
