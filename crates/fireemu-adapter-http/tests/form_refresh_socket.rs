//! The Secure Token refresh posted as `application/x-www-form-urlencoded` over a real socket.
//!
//! The Firebase SDKs send the token refresh as a form (RFC 6749 style). The HTTP server turns
//! the form into the JSON object the Identity Toolkit handler expects, so these tests drive
//! that decoder through `server::serve` on a loopback listener instead of calling the handler
//! with an already decoded body. The form decoder is an input-validation boundary: a value
//! with a malformed percent escape or invalid UTF-8 in a field the refresh reads is refused
//! with a 4xx JSON error, never a panic and never a 200.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::AuthState;
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const REFRESH: &str = "/securetoken.googleapis.com/v1/token";
const FORM: &str = "application/x-www-form-urlencoded";

fn auth_state(stateless_refresh_tokens: bool) -> Arc<AuthState> {
    Arc::new(AuthState {
        store: Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(5),
            TotpPolicy::default(),
        ))),
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        notices: None,
        blocking: None,
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens,
        idp_continuations: fireemu_adapter_http::identity_toolkit::IdpContinuationPolicy::Disabled,
        query_limits: fireemu_adapter_http::identity_toolkit::AuthQueryLimits::EmulatorUnbounded,
        client_api_key: fireemu_adapter_http::identity_toolkit::ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry:
            fireemu_adapter_http::identity_toolkit::FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
        allow_unsigned_custom_tokens: true,
        idp_assertions: fireemu_adapter_http::identity_toolkit::IdpAssertionPolicy::Fixture,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    })
}

/// A server on an ephemeral loopback port; aborted when dropped.
struct Server {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Server {
    async fn start() -> Self {
        Self::start_with(true).await
    }

    async fn start_with(stateless_refresh_tokens: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(fireemu_adapter_http::server::serve(
            listener,
            auth_state(stateless_refresh_tokens),
        ));
        Self { addr, task }
    }

    /// Sends one request with `body` as raw bytes and returns the status and JSON body.
    async fn post(&self, path: &str, content_type: &str, body: &[u8]) -> (u16, Value) {
        let mut request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        let mut stream = tokio::net::TcpStream::connect(self.addr).await.unwrap();
        stream.write_all(&request).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let text = String::from_utf8_lossy(&response).into_owned();
        let status = text
            .strip_prefix("HTTP/1.1 ")
            .and_then(|rest| rest.get(..3))
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("no status line: {text}"));
        let start = text.find("\r\n\r\n").expect("a header/body split") + 4;
        let body = serde_json::from_str(&text[start..])
            .unwrap_or_else(|e| panic!("a JSON body ({e}): {text}"));
        (status, body)
    }

    async fn post_json(&self, path: &str, body: &Value) -> (u16, Value) {
        self.post(path, "application/json", body.to_string().as_bytes())
            .await
    }

    async fn post_form(&self, path: &str, body: impl AsRef<[u8]>) -> (u16, Value) {
        self.post(path, FORM, body.as_ref()).await
    }

    /// Signs up an account over JSON and returns its refresh token.
    async fn sign_up(&self, email: &str, password: &str) -> String {
        let (status, body) = self
            .post_json(
                &format!("{V1}/accounts:signUp"),
                &json!({"email": email, "password": password, "returnSecureToken": true}),
            )
            .await;
        assert_eq!(status, 200, "{body}");
        body["refreshToken"].as_str().unwrap().to_owned()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Every byte of `value` as a `%XX` escape, mixing upper and lower case hex digits.
fn percent_encode_all(value: &str) -> String {
    value
        .bytes()
        .enumerate()
        .map(|(i, b)| {
            if i % 2 == 0 {
                format!("%{b:02X}")
            } else {
                format!("%{b:02x}")
            }
        })
        .collect()
}

fn assert_id_token(status: u16, body: &Value) {
    assert_eq!(status, 200, "{body}");
    let id_token = body["id_token"].as_str().expect("an id_token");
    assert_eq!(id_token.split('.').count(), 3, "{body}");
}

fn assert_json_refusal(status: u16, body: &Value, case: &str) {
    assert!(
        (400..500).contains(&status),
        "{case}: expected a 4xx, got {status}: {body}"
    );
    assert!(
        body["error"]["message"].is_string(),
        "{case}: expected a JSON error body: {body}"
    );
}

#[tokio::test]
async fn form_encoded_refresh_over_a_socket_returns_an_id_token() {
    let server = Server::start().await;
    let refresh = server.sign_up("form@example.com", "password1").await;

    let (status, body) = server
        .post_form(
            REFRESH,
            format!("grant_type=refresh_token&refresh_token={refresh}"),
        )
        .await;
    assert_id_token(status, &body);
    assert_eq!(body["refresh_token"], refresh.as_str());

    // A charset parameter on the content type is still a form.
    let (status, body) = server
        .post(
            REFRESH,
            "application/x-www-form-urlencoded; charset=utf-8",
            format!("refresh_token={refresh}&grant_type=refresh_token").as_bytes(),
        )
        .await;
    assert_id_token(status, &body);
}

#[tokio::test]
async fn percent_encoded_form_values_and_keys_are_decoded() {
    let server = Server::start().await;
    let refresh = server.sign_up("percent@example.com", "password1").await;

    // Every byte of the token escaped, and the keys and grant type partly escaped.
    let (status, body) = server
        .post_form(
            REFRESH,
            format!(
                "grant%5Ftype=refresh%5ftoken&refresh_token={}",
                percent_encode_all(&refresh)
            ),
        )
        .await;
    assert_id_token(status, &body);
    // The echoed token is the decoded one, as the JSON path would read it.
    assert_eq!(body["refresh_token"], refresh.as_str());

    // The undecoded spelling would not be a valid token: decoding is what made it pass.
    assert_ne!(percent_encode_all(&refresh), refresh);
}

#[tokio::test]
async fn plus_and_escaped_plus_decode_as_the_json_path_reads_them() {
    let server = Server::start().await;
    // The account's password contains both a space and a plus sign.
    server.sign_up("plus@example.com", "pass word+1").await;

    // `+` is a space and `%2B` is a literal plus, so this form spells the JSON password.
    let sign_in = format!("{V1}/accounts:signInWithPassword");
    let (status, body) = server
        .post_form(
            &sign_in,
            "email=plus%40example.com&password=pass+word%2B1&returnSecureToken=true",
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["email"], "plus@example.com");
    let refresh = body["refreshToken"].as_str().unwrap().to_owned();

    // The same form read with `+` kept literally is a different password.
    let (status, body) = server
        .post_form(
            &sign_in,
            "email=plus%40example.com&password=pass%2Bword%2B1&returnSecureToken=true",
        )
        .await;
    assert_json_refusal(status, &body, "literal plus in the password");

    // On the refresh route, `refresh+token` is "refresh token", which is refused exactly as the
    // JSON spelling is, and the token obtained through the form refreshes.
    let form = server
        .post_form(
            REFRESH,
            format!("grant_type=refresh+token&refresh_token={refresh}"),
        )
        .await;
    let json = server
        .post_json(
            REFRESH,
            &json!({"grant_type": "refresh token", "refresh_token": refresh}),
        )
        .await;
    assert_eq!(form, json);
    assert_eq!(form.1["error"]["message"], "INVALID_GRANT_TYPE");
    let (status, body) = server
        .post_form(
            REFRESH,
            format!("grant_type=refresh_token&refresh_token={refresh}"),
        )
        .await;
    assert_id_token(status, &body);
}

#[tokio::test]
async fn malformed_escapes_and_invalid_utf8_are_refused_with_a_json_4xx() {
    let server = Server::start().await;
    let refresh = server.sign_up("malformed@example.com", "password1").await;
    let valid = format!("grant_type=refresh_token&refresh_token={refresh}");

    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "%zz token",
            b"grant_type=refresh_token&refresh_token=%zz".to_vec(),
        ),
        (
            "lone % token",
            b"grant_type=refresh_token&refresh_token=%".to_vec(),
        ),
        (
            "short escape",
            b"grant_type=refresh_token&refresh_token=%2".to_vec(),
        ),
        (
            "signed escape",
            b"grant_type=refresh_token&refresh_token=%+f".to_vec(),
        ),
        (
            "malformed grant type",
            format!("grant_type=refresh_token%&refresh_token={refresh}").into_bytes(),
        ),
        (
            "escaped invalid UTF-8 token",
            b"grant_type=refresh_token&refresh_token=%FF%FE".to_vec(),
        ),
        (
            "escaped lone continuation byte",
            b"grant_type=refresh_token&refresh_token=%80".to_vec(),
        ),
        (
            "escaped truncated sequence",
            b"grant_type=refresh_token&refresh_token=%E2%82".to_vec(),
        ),
        (
            "raw invalid UTF-8 token",
            b"grant_type=refresh_token&refresh_token=\xff\xfe".to_vec(),
        ),
    ];
    // A valid token spoiled by a malformed escape or invalid UTF-8 is no longer that token.
    for (case, suffix) in [
        ("valid token with a %zz suffix", &b"%zz"[..]),
        ("valid token with a lone % suffix", b"%"),
        ("valid token with an escaped invalid UTF-8 suffix", b"%FF"),
        ("valid token with a raw invalid UTF-8 suffix", b"\xc3\x28"),
    ] {
        let mut body = valid.clone().into_bytes();
        body.extend_from_slice(suffix);
        cases.push((case, body));
    }
    // Not pinned here: a malformed escape or invalid UTF-8 in a field the refresh does not
    // read (`&extra=%zz`) is kept literally or replaced with U+FFFD by the lenient decoder,
    // and the refresh still answers 200. The JSON path refuses such a body outright. That
    // leniency is pinned by `a_form_encoded_body_decodes_percent_escapes_strictly` (PCT-1)
    // in identity_toolkit.rs, so changing it is an owner decision, not a test-only change.

    for (case, body) in &cases {
        let (status, response) = server.post_form(REFRESH, body).await;
        assert_json_refusal(status, &response, case);
    }

    // The server kept serving after every refusal: the valid form still refreshes.
    let (status, body) = server.post_form(REFRESH, &valid).await;
    assert_id_token(status, &body);
}

/// The pinned Firebase Android SDK (firebase-auth 23.2.0) posts the refresh as
/// `application/json; charset=UTF-8` with camelCase members (`grantType`, `refreshToken`) to
/// `<emulator>/securetoken.googleapis.com/v1/token?key=<apiKey>`. The official emulator
/// camel-cases every body key, so it accepts this and the `snake_case` form alike; the SDK itself
/// is what is known to work against production (production's own reading of the camelCase JSON
/// was not recorded here). Both profiles answer it.
#[tokio::test]
async fn android_sdk_camel_case_json_refresh_returns_an_id_token_in_both_profiles() {
    for stateless in [true, false] {
        let server = Server::start_with(stateless).await;
        let refresh = server.sign_up("android@example.com", "password1").await;

        let (status, body) = server
            .post(
                &format!("{REFRESH}?key=fake-api-key"),
                "application/json; charset=UTF-8",
                json!({"grantType": "refresh_token", "refreshToken": refresh})
                    .to_string()
                    .as_bytes(),
            )
            .await;
        assert_id_token(status, &body);
        assert_eq!(
            body["refresh_token"],
            refresh.as_str(),
            "stateless={stateless}"
        );
        assert!(body["user_id"].is_string(), "{body}");

        // A form with camelCase keys reads the same (the official emulator camel-cases them too).
        let (status, body) = server
            .post_form(
                REFRESH,
                format!("grantType=refresh_token&refreshToken={refresh}"),
            )
            .await;
        assert_id_token(status, &body);
    }
}

/// The camelCase reading adds no leniency: a wrong grant type or an empty token is still refused
/// with the Secure Token's own messages.
#[tokio::test]
async fn camel_case_json_refresh_keeps_its_refusals() {
    let server = Server::start().await;
    let refresh = server.sign_up("android2@example.com", "password1").await;
    for (body, message) in [
        (json!({"refreshToken": refresh}), "MISSING_GRANT_TYPE"),
        (
            json!({"grantType": "password", "refreshToken": refresh}),
            "INVALID_GRANT_TYPE",
        ),
        (
            json!({"grantType": "refresh_token"}),
            "MISSING_REFRESH_TOKEN",
        ),
        (
            json!({"grantType": "refresh_token", "refreshToken": ""}),
            "MISSING_REFRESH_TOKEN",
        ),
    ] {
        let (status, got) = server.post_json(REFRESH, &body).await;
        assert_eq!(status, 400, "{body}: {got}");
        assert!(
            got["error"]["message"]
                .as_str()
                .is_some_and(|m| m.starts_with(message)),
            "{body}: {got}"
        );
    }
}
