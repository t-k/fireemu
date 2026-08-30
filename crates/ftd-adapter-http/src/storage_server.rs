//! hyper glue for the Storage surface: raw bodies (uploads), CORS for the browser SDK,
//! loopback-only origins.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::identity_toolkit::origin_is_local;
use crate::storage::{handle, StorageRequest, StorageState};

/// Maximum accepted upload body (object limit plus multipart overhead).
pub const MAX_STORAGE_BODY_BYTES: usize = 260 * 1024 * 1024;

const FORWARDED_HEADERS: &[&str] = &[
    "authorization",
    "content-type",
    "content-range",
    "range",
    "x-goog-hash",
    "content-md5",
    "x-goog-upload-protocol",
    "x-goog-upload-command",
    "x-goog-upload-offset",
    "x-goog-upload-header-content-type",
    "x-goog-upload-header-content-length",
    "x-upload-content-type",
    "x-upload-content-length",
];

fn cors(
    builder: hyper::http::response::Builder,
    origin: Option<&str>,
) -> hyper::http::response::Builder {
    let mut b = builder
        .header("access-control-allow-origin", origin.unwrap_or("*"))
        .header("access-control-allow-credentials", "true")
        .header("access-control-allow-methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        .header(
            "access-control-expose-headers",
            "x-goog-upload-url, x-goog-upload-status, x-goog-upload-size-received, x-goog-upload-chunk-granularity, x-goog-upload-control-url, location, range, x-goog-hash, x-goog-generation, x-goog-metageneration, content-range, etag",
        );
    if origin.is_some() {
        b = b.header("vary", "origin");
    }
    b
}

async fn respond(
    state: Arc<StorageState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if origin.as_deref().is_some_and(|o| !origin_is_local(o)) {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Full::new(Bytes::from_static(b"forbidden origin")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
    }
    if req.method() == hyper::Method::OPTIONS {
        let requested = req
            .headers()
            .get("access-control-request-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("authorization, content-type, x-goog-upload-protocol, x-goog-upload-command, x-goog-upload-offset, x-goog-upload-header-content-type, x-goog-upload-header-content-length, x-firebase-storage-version, x-firebase-gmpid")
            .to_owned();
        return Ok(cors(Response::builder().status(204), origin.as_deref())
            .header("access-control-allow-headers", requested)
            .header("access-control-max-age", "3600")
            .body(Full::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
    }
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut headers = std::collections::BTreeMap::new();
    for name in FORWARDED_HEADERS {
        if let Some(v) = req.headers().get(*name).and_then(|v| v.to_str().ok()) {
            headers.insert((*name).to_owned(), v.to_owned());
        }
    }
    let body = match Limited::new(req.into_body(), MAX_STORAGE_BODY_BYTES)
        .collect()
        .await
    {
        Ok(c) => c.to_bytes().to_vec(),
        Err(_) => {
            return Ok(cors(Response::builder().status(413), origin.as_deref())
                .body(Full::new(Bytes::from_static(b"payload too large")))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))));
        }
    };
    let trace = std::env::var_os("FTD_TRACE_STORAGE").is_some();
    let (trace_method, trace_path, trace_query, trace_len) =
        (method.clone(), path.clone(), query.clone(), body.len());
    let response = handle(
        &state,
        &StorageRequest {
            method,
            path,
            query,
            host,
            headers,
            body,
        },
    );
    if trace {
        eprintln!(
            "[storage] {trace_method} {trace_path}?{trace_query} body={trace_len} -> {} {}",
            response.status,
            if response.status >= 400 {
                String::from_utf8_lossy(&response.body).into_owned()
            } else {
                String::new()
            }
        );
    }
    if response
        .headers
        .iter()
        .any(|(k, _)| k == crate::storage::DROP_CONNECTION_HEADER)
    {
        // A `dropConnection` fault: the connection closes without a response.
        return Err(std::io::Error::other("fault plan: connection dropped"));
    }
    let mut builder = cors(
        Response::builder().status(
            StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        ),
        origin.as_deref(),
    );
    for (k, v) in response.headers {
        builder = builder.header(k, v);
    }
    Ok(builder
        .body(Full::new(Bytes::from(response.body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()))))
}

/// Serves the Storage surface on `listener` until the task is aborted.
pub async fn serve_storage(listener: TcpListener, state: Arc<StorageState>) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| respond(state.clone(), req));
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}
