//! hyper glue: reads the body (bounded), dispatches to the JSON handlers, writes the response.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::control::{self, ControlState};
use crate::identity_toolkit::{handle_with, AuthState, RequestHeaders};

/// Maximum accepted request body (spec 33.3 input budget).
pub const MAX_BODY_BYTES: usize = 256 * 1024;

#[allow(clippy::too_many_lines)]
async fn respond(
    state: Arc<AuthState>,
    control: Option<Arc<ControlState>>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().as_str().to_owned();
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
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
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
            .get_all(ftd_core_app_check::header::APP_CHECK_HEADER)
            .iter()
            .map(|v| v.to_str().unwrap_or_default().to_owned())
            .collect(),
    };
    // Bound the body before reading it (spec 33.3): oversized payloads never allocate fully.
    let collected = Limited::new(req.into_body(), MAX_BODY_BYTES)
        .collect()
        .await;
    let (status, body) = match collected {
        Err(_) => (
            413,
            serde_json::json!({"error": {"code": 413, "message": "PAYLOAD_TOO_LARGE"}}),
        ),
        Ok(collected) => {
            let bytes = collected.to_bytes();
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
                        body: serde_json::json!({"error": {
                            "code": 404,
                            "message": "App Check is not enabled in this runtime (appCheck.enabled)",
                            "status": "NOT_FOUND"
                        }}),
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
                // The Firebase SDKs post the token refresh as a form (RFC 6749 style).
                Some(form_to_json(&String::from_utf8_lossy(&bytes)))
            } else {
                serde_json::from_slice(&bytes).ok()
            };
            match json {
                None => (
                    400,
                    serde_json::json!({"error": {"code": 400, "message": "INVALID_JSON_PAYLOAD"}}),
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
                            control::handle_with(c, &method, &path, &headers, &json)
                        }
                        _ => handle_with(&state, &method, &path, &headers, &json),
                    };
                    (r.status, r.body)
                }
            }
        }
    };
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
fn form_to_json(text: &str) -> serde_json::Value {
    fn decode(s: &str) -> String {
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Some(b) = s
                    .get(i + 1..i + 3)
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
            out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }
    let mut map = serde_json::Map::new();
    for kv in text.split('&').filter(|s| !s.is_empty()) {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        map.insert(decode(k), serde_json::Value::String(decode(v)));
    }
    serde_json::Value::Object(map)
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
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        let control = control.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| respond(state.clone(), control.clone(), req));
            // Connection errors are per-client; the accept loop keeps running.
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}
