//! hyper glue: reads the body (bounded), dispatches to the JSON handlers, writes the response.

use std::sync::Arc;

use bytes::Bytes;
use fireemu_adapter_support::connection::{DrainBounds, GracefulClose};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Semaphore};

use crate::control::{self, ControlState};
use crate::identity_toolkit::{handle_with, AuthState, RequestHeaders};

/// Maximum accepted request body (spec 33.3 input budget).
pub const MAX_BODY_BYTES: usize = 256 * 1024;
const MAX_BLOCKING_AUTH_TASKS: usize = 64;

#[allow(clippy::too_many_lines)]
async fn respond(
    state: Arc<AuthState>,
    control: Option<Arc<ControlState>>,
    blocking_auth_slots: Option<Arc<Semaphore>>,
    peer_ip: Option<String>,
    remote_peer: bool,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if let Err(refusal) = fireemu_core_session::host_guard::admits_request(
        req.version() == hyper::Version::HTTP_2,
        req.headers()
            .get_all(hyper::header::HOST)
            .iter()
            .map(hyper::header::HeaderValue::as_bytes),
    ) {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(
                "content-type",
                fireemu_core_session::host_guard::REFUSAL_CONTENT_TYPE,
            )
            .body(Full::new(Bytes::from(refusal.body())))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
    }
    let method = req.method().as_str().to_owned();
    // The control API answers loopback peers only. The listener is on loopback unless
    // `network.allowNonLoopbackHosts` exposed the Auth emulator, and then a peer on another
    // host reaches Identity Toolkit but never the control surface.
    if refuses_remote_control(remote_peer, control.is_some(), req.uri().path()) {
        return Ok(finish(
            403,
            &serde_json::json!({
                "error": "this route answers loopback peers only: network.allowNonLoopbackHosts exposes the emulators, not the control API, rule loading, data clearing or App Check debug-token management"
            }),
            None,
            false,
        ));
    }
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if origin
        .as_deref()
        .is_some_and(|o| !crate::identity_toolkit::origin_is_local(o))
    {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from_static(b"forbidden origin")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
    }
    if method == "OPTIONS" {
        // Browser preflight (the Auth SDK sends JSON with an Authorization header).
        let requested = req
            .headers()
            .get("access-control-request-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("authorization, content-type, x-firebase-appcheck")
            .to_owned();
        return Ok(
            with_cors(Response::builder().status(204), origin.as_deref())
                .header("access-control-allow-headers", requested)
                .header("access-control-max-age", "3600")
                .body(Full::new(Bytes::new()))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
        );
    }
    let path = req
        .uri()
        .path_and_query()
        .map_or_else(|| req.uri().path().to_owned(), |pq| pq.as_str().to_owned());
    if method == "GET" && path == "/" {
        return Ok(finish(
            200,
            &serde_json::json!({"emulator": "auth"}),
            origin.as_deref(),
            true,
        ));
    }
    // The IdP login widget pages are HTML, served on GET, outside the JSON pipeline. The
    // loopback origin guard above still applies; the pages carry no secret and mint no
    // credential (that is `signInWithIdp`, guarded on its own).
    {
        let (widget_path, widget_query) = match path.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (path.as_str(), None),
        };
        if crate::identity_toolkit::widget::is_widget_path(widget_path) {
            if method != "GET" {
                return Ok(finish(
                    405,
                    &fireemu_adapter_support::api_error::firebase_minimal(
                        405,
                        "METHOD_NOT_ALLOWED",
                    ),
                    origin.as_deref(),
                    false,
                ));
            }
            let rendered =
                crate::identity_toolkit::widget::render(&state, widget_path, widget_query);
            let builder = with_cors(
                Response::builder()
                    .status(StatusCode::from_u16(rendered.status).unwrap_or(StatusCode::OK)),
                origin.as_deref(),
            )
            .header("content-type", rendered.content_type)
            .header("cache-control", "no-store");
            return Ok(builder
                .body(Full::new(Bytes::from(rendered.body)))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
        }
    }
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let accept_encoding = header("accept-encoding");
    let headers = RequestHeaders {
        authorization: header("authorization"),
        origin: header("origin"),
        content_type: header("content-type"),
        host: header("host"),
        // Every instance, in wire order: duplicates and folded values must survive to the
        // classifier, which refuses them (spec 7.3). An unrenderable value becomes an empty
        // string, which is malformed too.
        app_check: req
            .headers()
            .get_all(fireemu_core_app_check::header::APP_CHECK_HEADER)
            .iter()
            .map(|v| v.to_str().unwrap_or_default().to_owned())
            .collect(),
        peer_ip,
    };
    if let Some(refusal) = control
        .as_ref()
        .and_then(|control| control::remote_config_guard(control, &method, &path, &headers))
    {
        return Ok(finish(
            refusal.status,
            &refusal.body,
            origin.as_deref(),
            true,
        ));
    }
    // Bound the body before reading it (spec 33.3): oversized payloads never allocate fully.
    let collected =
        fireemu_adapter_support::body::collect_limited(req.into_body(), MAX_BODY_BYTES).await;
    let (status, body) = match collected {
        Err(_) => (
            413,
            fireemu_adapter_support::api_error::firebase_minimal(413, "PAYLOAD_TOO_LARGE"),
        ),
        Ok(bytes) => {
            // Dispatched before the control API: the exchange and the JWKS are public on
            // loopback, while every debug-token management route checks the control token
            // itself, for every method and whatever the Origin.
            if crate::app_check::is_app_check_path(&path) {
                // App Check responses must never be cached (spec 9, 10.1 and 10.2).
                let r = match &state.app_check {
                    Some(app_check) => crate::app_check::handle_raw(
                        app_check,
                        &crate::app_check::RawRequest {
                            method: &method,
                            path: &path,
                            headers: &headers,
                            body: &bytes,
                        },
                    ),
                    None => crate::identity_toolkit::JsonResponse {
                        status: 404,
                        body: fireemu_adapter_support::api_error::google_rpc(
                            404,
                            "App Check is not enabled in this runtime (appCheck.enabled)",
                            "NOT_FOUND",
                        ),
                    },
                };
                return Ok(finish(r.status, &r.body, origin.as_deref(), true));
            }
            let is_form = headers
                .content_type
                .as_deref()
                .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));
            let json: Option<serde_json::Value> = if bytes.is_empty() {
                Some(serde_json::Value::Object(serde_json::Map::new()))
            } else if is_form {
                Some(form_to_json(
                    &String::from_utf8_lossy(&bytes),
                    path.starts_with("/securetoken.googleapis.com/"),
                ))
            } else if path.starts_with("/securetoken.googleapis.com/") {
                // Read fields in wire order so serde_json's RawValue marker remains an ordinary field.
                serde_json::from_slice(&bytes)
                    .ok()
                    .map(|value| ordered_refresh_json(&bytes).unwrap_or(value))
            } else {
                serde_json::from_slice(&bytes).ok()
            };
            match json {
                // Identity Platform's v2 API refuses a malformed body with its own shape
                // (AUTH-CONFIG-SDK sandbox recording 2026-09-25); the parser's diagnostic that
                // production appends is a known difference (owner decision).
                None if path.starts_with("/identitytoolkit.googleapis.com/v2/")
                    || path.starts_with("/identitytoolkit.googleapis.com/admin/v2/") =>
                {
                    (
                        400,
                        fireemu_adapter_support::api_error::google_rpc(
                            400,
                            "Invalid JSON payload received.",
                            "INVALID_ARGUMENT",
                        ),
                    )
                }
                None => (
                    400,
                    fireemu_adapter_support::api_error::firebase_minimal(
                        400,
                        "INVALID_JSON_PAYLOAD",
                    ),
                ),
                Some(json) => {
                    let r = match &control {
                        Some(c) if method == "POST" && control::is_await_idle_path(&path) => {
                            match control::browser_guard(c, &method, &path, &headers) {
                                Some(refusal) => refusal,
                                None => control::await_idle(c, &json).await,
                            }
                        }
                        Some(c) if control::is_control_path(&path) => {
                            control::handle_async(c, &method, &path, &headers, &json).await
                        }
                        _ if crate::identity_toolkit::request_may_invoke_blocking_auth(
                            state.blocking.as_deref(),
                            &method,
                            &path,
                        ) =>
                        {
                            let permit = blocking_auth_slots
                                .as_ref()
                                .and_then(|slots| slots.clone().try_acquire_owned().ok());
                            let Some(permit) = permit else {
                                let refusal =
                                    crate::identity_toolkit::blocking_auth_overload_response();
                                return Ok(finish(
                                    refusal.status,
                                    &refusal.body,
                                    origin.as_deref(),
                                    false,
                                ));
                            };
                            let dispatch_state = state.clone();
                            let dispatch_method = method.clone();
                            let dispatch_path = path.clone();
                            let runtime_handle = tokio::runtime::Handle::current();
                            let (result_tx, result_rx) = oneshot::channel();
                            let spawned = std::thread::Builder::new()
                                .name("fireemu-blocking-auth".to_owned())
                                .spawn(move || {
                                    let _permit = permit;
                                    let _runtime_context = runtime_handle.enter();
                                    let result = handle_with(
                                        &dispatch_state,
                                        &dispatch_method,
                                        &dispatch_path,
                                        &headers,
                                        &json,
                                    );
                                    let _ = result_tx.send(result);
                                });
                            if spawned.is_err() {
                                crate::identity_toolkit::blocking_auth_overload_response()
                            } else {
                                result_rx.await.unwrap_or_else(|_| {
                                    crate::identity_toolkit::blocking_auth_overload_response()
                                })
                            }
                        }
                        _ => handle_with(&state, &method, &path, &headers, &json),
                    };
                    (r.status, r.body)
                }
            }
        }
    };
    // The email action link redirects to its `continueUrl` once it has acted, as the
    // official emulator does; only that route builds a 303.
    if status == 303 {
        if let Some(location) = crate::identity_toolkit::redirect_location(&body) {
            return Ok(
                with_cors(Response::builder().status(303), origin.as_deref())
                    .header("location", location)
                    .header("cache-control", "no-store")
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))),
            );
        }
    }
    // Production Identity Toolkit uses an HTML 404 for unknown methods. Match only the
    // route-miss envelope: missing tenants and other API errors must remain JSON.
    if status == 404 && body == fireemu_adapter_support::api_error::identity_not_found() {
        return Ok(with_cors(Response::builder().status(404), origin.as_deref())
            .header("content-type", "text/html; charset=UTF-8")
            .body(Full::new(Bytes::from_static(
                b"<!DOCTYPE html><html lang=en><title>Error 404 (Not Found)</title><p>Not Found</p></html>",
            )))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
    }
    // The strict profile frames the answers the STORAGE-OBJECT recordings cover as production does
    // (headers, member order, layout, gzip); every other answer keeps the official emulator's.
    if !state.stateless_refresh_tokens
        && status == 200
        && crate::identity_framing::is_recorded_route(&method, &path)
    {
        return Ok(crate::identity_framing::respond(
            &body,
            origin.as_deref(),
            accept_encoding.as_deref(),
        ));
    }
    // Privileged App Check observations must never be cached (spec 15).
    Ok(finish(
        status,
        &body,
        origin.as_deref(),
        crate::control::is_no_store_path(&path),
    ))
}

/// Renders one JSON response, optionally forbidding every cache.
fn finish(
    status: u16,
    body: &serde_json::Value,
    origin: Option<&str>,
    no_store: bool,
) -> Response<Full<Bytes>> {
    let text = serde_json::to_vec(body).unwrap_or_default();
    let mut builder = with_cors(
        Response::builder()
            .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)),
        origin,
    )
    .header("content-type", "application/json; charset=utf-8");
    if no_store {
        builder = builder.header("cache-control", "no-store");
    }
    builder
        .body(Full::new(Bytes::from(text)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

/// `k=v&k=v` (percent-encoded) → JSON object of strings.
fn form_to_json(text: &str, refresh: bool) -> serde_json::Value {
    fn decode(s: &str) -> String {
        fireemu_core_types::codec::percent_decode(s, fireemu_core_types::codec::PlusMode::Space)
    }
    let mut map = serde_json::Map::new();
    for kv in text.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        let key = decode(k);
        let key = if refresh {
            match key.as_str() {
                "grantType" => "grant_type",
                "refreshToken" => "refresh_token",
                _ => &key,
            }
        } else {
            &key
        };
        map.insert(key.to_owned(), serde_json::Value::String(decode(v)));
    }
    serde_json::Value::Object(map)
}

/// A JSON value read without `serde_json`'s `RawValue` handling. `serde_json::Value` treats an
/// object whose first key is `$serde_json::private::RawValue` as its embedded JSON text when the
/// `raw_value` feature is on (it is, in the full binary), so `{"grant_type":{"$serde_json::...":
/// "\"refresh_token\""}}` would read as the string `refresh_token`. Production reads that key as
/// an ordinary member, which makes the value an object, so every level here is read as a plain
/// JSON value: only the value shapes, never the marker.
struct PlainJson(serde_json::Value);

impl<'de> serde::Deserialize<'de> for PlainJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{MapAccess, SeqAccess, Visitor};
        use serde_json::Value;

        struct PlainVisitor;
        impl<'de> Visitor<'de> for PlainVisitor {
            type Value = PlainJson;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("any valid JSON value")
            }

            fn visit_bool<E>(self, value: bool) -> Result<PlainJson, E> {
                Ok(PlainJson(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<PlainJson, E> {
                Ok(PlainJson(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<PlainJson, E> {
                Ok(PlainJson(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<PlainJson, E> {
                Ok(PlainJson(
                    serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number),
                ))
            }

            fn visit_str<E>(self, value: &str) -> Result<PlainJson, E> {
                Ok(PlainJson(Value::String(value.to_owned())))
            }

            fn visit_unit<E>(self) -> Result<PlainJson, E> {
                Ok(PlainJson(Value::Null))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<PlainJson, A::Error> {
                let mut values = Vec::new();
                while let Some(PlainJson(value)) = items.next_element()? {
                    values.push(value);
                }
                Ok(PlainJson(Value::Array(values)))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<PlainJson, A::Error> {
                let mut members = serde_json::Map::new();
                while let Some((key, PlainJson(value))) =
                    entries.next_entry::<String, PlainJson>()?
                {
                    members.insert(key, value);
                }
                Ok(PlainJson(Value::Object(members)))
            }
        }

        deserializer.deserialize_any(PlainVisitor)
    }
}

fn ordered_refresh_json(bytes: &[u8]) -> Option<serde_json::Value> {
    use serde::de::{Deserializer, MapAccess, Visitor};

    struct RefreshVisitor;
    impl<'de> Visitor<'de> for RefreshVisitor {
        type Value = serde_json::Value;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a JSON object")
        }

        fn visit_map<M: MapAccess<'de>>(self, mut entries: M) -> Result<Self::Value, M::Error> {
            let mut fields = serde_json::Map::new();
            while let Some((key, PlainJson(value))) = entries.next_entry::<String, PlainJson>()? {
                let key = match key.as_str() {
                    "grantType" => "grant_type",
                    "refreshToken" => "refresh_token",
                    _ => &key,
                };
                fields.insert(key.to_owned(), value);
            }
            Ok(serde_json::Value::Object(fields))
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = deserializer.deserialize_map(RefreshVisitor).ok()?;
    deserializer.end().ok()?;
    Some(value)
}

/// Permissive CORS for a loopback test runtime (browser SDKs call these endpoints directly;
/// privileged routes still check the `Origin` themselves).
fn with_cors(
    builder: hyper::http::response::Builder,
    origin: Option<&str>,
) -> hyper::http::response::Builder {
    let mut b = builder
        .header("access-control-allow-origin", origin.unwrap_or("*"))
        .header("access-control-allow-credentials", "true")
        .header(
            "access-control-allow-methods",
            "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        );
    if origin.is_some() {
        b = b.header("vary", "origin");
    }
    b
}

/// Whether a request is refused because a remote peer asks for a privileged route: the control
/// API, or App Check's debug-token management. `remote_peer` is a peer whose address is not
/// loopback (an IPv4-mapped loopback address is loopback). App Check's token exchange and JWKS
/// are product routes under `/v1/` and stay reachable.
fn refuses_remote_control(remote_peer: bool, serves_control: bool, path: &str) -> bool {
    if !remote_peer {
        return false;
    }
    if crate::app_check::is_app_check_path(path) {
        return crate::app_check::is_management_path(path);
    }
    serves_control && control::is_control_path(path)
}

/// Whether a connection from `peer` comes from another host.
fn is_remote_peer(peer: std::net::IpAddr) -> bool {
    !peer.to_canonical().is_loopback()
}

/// Serves the Identity Toolkit surface on `listener` until the task is aborted.
pub async fn serve(listener: TcpListener, state: Arc<AuthState>) -> std::io::Result<()> {
    serve_inner(listener, state, None).await
}

/// Serves the Identity Toolkit surface plus the control API.
pub async fn serve_with_control(
    listener: TcpListener,
    state: Arc<AuthState>,
    control: Arc<ControlState>,
) -> std::io::Result<()> {
    serve_inner(listener, state, Some(control)).await
}

async fn serve_inner(
    listener: TcpListener,
    state: Arc<AuthState>,
    control: Option<Arc<ControlState>>,
) -> std::io::Result<()> {
    let blocking_auth_slots = state.blocking.as_ref().map(|blocking| {
        Arc::new(Semaphore::new(
            blocking
                .request_concurrency_limit()
                .clamp(1, MAX_BLOCKING_AUTH_TASKS),
        ))
    });
    loop {
        let (stream, peer_addr) =
            fireemu_adapter_support::accept::accept_with_backoff("http", || listener.accept())
                .await?;
        let peer_ip = Some(peer_addr.ip().to_string());
        let remote_peer = is_remote_peer(peer_addr.ip());
        let state = state.clone();
        let control = control.clone();
        let blocking_auth_slots = blocking_auth_slots.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(GracefulClose::new(
                stream,
                DrainBounds::for_largest_body(MAX_BODY_BYTES),
            ));
            let svc = service_fn(move |req| {
                respond(
                    state.clone(),
                    control.clone(),
                    blocking_auth_slots.clone(),
                    peer_ip.clone(),
                    remote_peer,
                    req,
                )
            });
            // Connection errors are per-client; the accept loop keeps running.
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::{is_remote_peer, refuses_remote_control};
    use proptest::prelude::*;
    use serde_json::json;
    use std::net::IpAddr;

    #[test]
    fn refresh_fields_keep_the_last_wire_value() {
        for body in [
            r#"{"refresh_token":"first","refreshToken":"second","refresh_token":"last","grantType":"password","grant_type":"refresh_token"}"#,
            r#"{"refreshToken":"first","refreshToken":"second","refresh_token":"last","grantType":"password","grant_type":"refresh_token"}"#,
        ] {
            let value = super::ordered_refresh_json(body.as_bytes()).unwrap();
            assert_eq!(value["refresh_token"], "last");
            assert_eq!(value["grant_type"], "refresh_token");
        }
        let value = super::form_to_json("refresh_token=first&refreshToken=second&refresh_token=last&grantType=password&grant_type=refresh_token", true);
        assert_eq!(value["refresh_token"], "last");
        assert_eq!(value["grant_type"], "refresh_token");
        assert!(super::ordered_refresh_json(br"{} trailing").is_none());
    }

    const RAW_VALUE_MARKER: &str = "$serde_json::private::RawValue";

    #[test]
    fn a_nested_raw_value_marker_is_an_ordinary_object_member() {
        // `serde_json::Value` alone would read each of these as the embedded JSON text.
        for (body, field, expected) in [
            (
                r#"{"grant_type":{"$serde_json::private::RawValue":"\"refresh_token\""}}"#,
                "grant_type",
                json!({"$serde_json::private::RawValue":"\"refresh_token\""}),
            ),
            (
                r#"{"grantType":[{"$serde_json::private::RawValue":"1"}]}"#,
                "grant_type",
                json!([{"$serde_json::private::RawValue":"1"}]),
            ),
            (
                r#"{"refreshToken":{"x":{"$serde_json::private::RawValue":"null"}}}"#,
                "refresh_token",
                json!({"x":{"$serde_json::private::RawValue":"null"}}),
            ),
        ] {
            let value = super::ordered_refresh_json(body.as_bytes()).unwrap();
            assert_eq!(value[field], expected, "{body}");
            assert!(
                value[field].is_object() || value[field].is_array(),
                "{body}"
            );
        }
        // The marker with a payload that is not JSON text is still read as the member it is.
        let value = super::ordered_refresh_json(
            br#"{"a":{"$serde_json::private::RawValue":null},"b":{"$serde_json::private::RawValue":"nope"}}"#,
        )
        .unwrap();
        assert_eq!(value["a"], json!({RAW_VALUE_MARKER: null}));
        assert_eq!(value["b"], json!({RAW_VALUE_MARKER: "nope"}));
    }

    /// A JSON tree whose objects keep their members in wire order, duplicates included.
    #[derive(Clone, Debug)]
    enum Tree {
        Null,
        Bool(bool),
        Int(i64),
        /// Only in marker-free trees: its rendering is compared with `serde_json::Value`.
        Float(f64),
        Text(String),
        List(Vec<Tree>),
        Object(Vec<(String, Tree)>),
    }

    impl Tree {
        fn render(&self, out: &mut String) {
            match self {
                Tree::Null => out.push_str("null"),
                Tree::Bool(b) => out.push_str(&b.to_string()),
                Tree::Int(n) => out.push_str(&n.to_string()),
                Tree::Float(f) => {
                    let _ = std::fmt::Write::write_fmt(out, format_args!("{f:e}"));
                }
                Tree::Text(t) => out.push_str(&serde_json::to_string(t).unwrap()),
                Tree::List(items) => {
                    out.push('[');
                    for (i, item) in items.iter().enumerate() {
                        if i > 0 {
                            out.push(',');
                        }
                        item.render(out);
                    }
                    out.push(']');
                }
                Tree::Object(members) => {
                    out.push('{');
                    for (i, (key, value)) in members.iter().enumerate() {
                        if i > 0 {
                            out.push(',');
                        }
                        out.push_str(&serde_json::to_string(key).unwrap());
                        out.push(':');
                        value.render(out);
                    }
                    out.push('}');
                }
            }
        }

        /// What a reader without any marker handling builds; the later duplicate wins.
        fn plain(&self) -> serde_json::Value {
            match self {
                Tree::Null => serde_json::Value::Null,
                Tree::Bool(b) => json!(b),
                Tree::Int(n) => json!(n),
                Tree::Float(_) => unreachable!("floats are compared with serde_json::Value"),
                Tree::Text(t) => json!(t),
                Tree::List(items) => items.iter().map(Tree::plain).collect(),
                Tree::Object(members) => {
                    let mut map = serde_json::Map::new();
                    for (key, value) in members {
                        map.insert(key.clone(), value.plain());
                    }
                    serde_json::Value::Object(map)
                }
            }
        }
    }

    fn tree(with_floats: bool) -> impl Strategy<Value = Tree> {
        let float = if with_floats {
            proptest::num::f64::NORMAL.prop_map(Tree::Float).boxed()
        } else {
            Just(Tree::Null).boxed()
        };
        let leaf = prop_oneof![
            Just(Tree::Null),
            float,
            any::<bool>().prop_map(Tree::Bool),
            any::<i64>().prop_map(Tree::Int),
            any::<u64>().prop_map(|n| Tree::Text(n.to_string())),
            // Often valid JSON text, so a reader that unwraps the marker would accept it.
            prop_oneof![
                "[a-z\"\\\\{}\\[\\]0-9,:]{0,8}",
                Just("\"refresh_token\"".to_owned()),
                Just("{\"a\":1}".to_owned()),
            ]
            .prop_map(Tree::Text),
        ];
        leaf.prop_recursive(4, 32, 4, move |inner| {
            let key = prop_oneof![
                Just("a".to_owned()),
                Just("grant_type".to_owned()),
                Just("grantType".to_owned()),
                Just(if with_floats { "b" } else { RAW_VALUE_MARKER }.to_owned()),
            ];
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..4).prop_map(Tree::List),
                proptest::collection::vec((key, inner), 0..4).prop_map(Tree::Object),
            ]
        })
    }

    proptest! {
        /// Without a marker the reader is `serde_json::Value`'s: same numbers, strings, nesting
        /// and last-duplicate-wins, so the fix changes nothing but the marker.
        #[test]
        fn without_a_marker_the_ordered_reader_matches_serde_json_value(
            members in proptest::collection::vec(
                (
                    prop_oneof![
                        Just("a".to_owned()),
                        Just("grant_type".to_owned()),
                        Just("refresh_token".to_owned()),
                    ],
                    tree(true),
                ),
                0..5,
            )
        ) {
            let mut text = String::new();
            Tree::Object(members).render(&mut text);
            let expected: serde_json::Value = serde_json::from_str(&text).unwrap();
            prop_assert_eq!(super::ordered_refresh_json(text.as_bytes()), Some(expected), "{}", text);
        }

        /// Only the two top-level spellings are renamed; every nested level, marker included,
        /// reads as plain JSON.
        #[test]
        fn the_ordered_reader_matches_a_plain_reader_at_every_depth(
            members in proptest::collection::vec(
                (
                    prop_oneof![
                        Just("a".to_owned()),
                        Just("grant_type".to_owned()),
                        Just("grantType".to_owned()),
                        Just("refresh_token".to_owned()),
                        Just("refreshToken".to_owned()),
                        Just(RAW_VALUE_MARKER.to_owned()),
                    ],
                    tree(false),
                ),
                0..5,
            )
        ) {
            let mut text = String::new();
            Tree::Object(members.clone()).render(&mut text);
            let mut expected = serde_json::Map::new();
            for (key, value) in &members {
                let key = match key.as_str() {
                    "grantType" => "grant_type",
                    "refreshToken" => "refresh_token",
                    other => other,
                };
                expected.insert(key.to_owned(), value.plain());
            }
            prop_assert_eq!(
                super::ordered_refresh_json(text.as_bytes()),
                Some(serde_json::Value::Object(expected)),
                "{}",
                text
            );
        }
    }

    #[test]
    fn only_a_remote_peer_asking_the_control_listener_for_a_control_path_is_refused() {
        for path in [
            "/v1/sessions",
            "/v1/sessions/default:awaitIdle",
            "/health/live",
        ] {
            assert!(refuses_remote_control(true, true, path), "{path}");
            assert!(!refuses_remote_control(false, true, path), "{path}");
            assert!(!refuses_remote_control(true, false, path), "{path}");
        }
        for path in [
            "/identitytoolkit.googleapis.com/v1/accounts:signUp",
            "/emulator/v1/projects/demo/accounts",
            "/",
            // App Check's product routes are not control routes.
            "/v1/jwks",
            "/v1/projects/demo/apps/1:123:web:abc:exchangeDebugToken",
            "/v1beta/jwks",
        ] {
            assert!(!refuses_remote_control(true, true, path), "{path}");
        }
        // App Check's debug-token management is refused to a remote peer, on any listener.
        for path in [
            "/emulator/v1/projects/demo/apps/1:123:web:abc/debugTokens",
            "/emulator/v1/projects/demo/apps/1:123:web:abc/debugTokens/t1",
            "/emulator/v1/projects/demo/apps/1:123:web:abc/debugTokens?x=1",
        ] {
            assert!(refuses_remote_control(true, true, path), "{path}");
            assert!(refuses_remote_control(true, false, path), "{path}");
            assert!(!refuses_remote_control(false, true, path), "{path}");
        }
    }

    #[test]
    fn loopback_peers_of_either_family_are_local_and_every_other_address_is_remote() {
        for local in ["127.0.0.1", "127.8.9.10", "::1", "::ffff:127.0.0.1"] {
            assert!(!is_remote_peer(local.parse::<IpAddr>().unwrap()), "{local}");
        }
        for remote in [
            "192.168.1.2",
            "10.88.0.1",
            "::ffff:10.0.0.1",
            "fe80::1",
            "0.0.0.0",
        ] {
            assert!(
                is_remote_peer(remote.parse::<IpAddr>().unwrap()),
                "{remote}"
            );
        }
    }
}
