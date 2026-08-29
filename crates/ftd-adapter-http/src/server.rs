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
    if method == "OPTIONS" {
        // Browser preflight (the Auth SDK sends JSON with an Authorization header).
        let requested = req
            .headers()
            .get("access-control-request-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("authorization, content-type")
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
            let json: Option<serde_json::Value> = if bytes.is_empty() {
                Some(serde_json::Value::Object(serde_json::Map::new()))
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
    let text = serde_json::to_vec(&body).unwrap_or_default();
    Ok(with_cors(
        Response::builder()
            .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)),
        origin.as_deref(),
    )
    .header("content-type", "application/json; charset=utf-8")
    .body(Full::new(Bytes::from(text)))
    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
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
