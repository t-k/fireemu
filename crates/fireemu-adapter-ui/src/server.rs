//! hyper glue for the UI listener: bounded bodies, the router, streaming responses.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt as _;

use crate::{guard, handle, UiBody, UiRequest, UiResponse, UiState};

type OutBody = BoxBody<Bytes, Infallible>;

/// Headers the router looks at.
const FORWARDED_HEADERS: &[&str] = &[
    "host",
    "origin",
    "authorization",
    "content-type",
    "content-range",
    "range",
    "x-upload-content-type",
    "accept",
];

fn body_limit(path: &str) -> usize {
    if path.starts_with("/ui/api/storage/") {
        fireemu_adapter_http::storage_server::MAX_STORAGE_BODY_BYTES
    } else {
        crate::MAX_JSON_BODY_BYTES
    }
}

fn to_hyper(response: UiResponse) -> Response<OutBody> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    for (k, v) in response.headers {
        builder = builder.header(k, v);
    }
    let body: OutBody = match response.body {
        UiBody::Full(bytes) => Full::new(Bytes::from(bytes)).boxed(),
        UiBody::Stream(rx) => {
            StreamBody::new(ReceiverStream::new(rx).map(|chunk| Ok(Frame::data(chunk)))).boxed()
        }
    };
    builder
        .body(body)
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()))
}

async fn respond(
    state: Arc<UiState>,
    req: Request<Incoming>,
) -> Result<Response<OutBody>, std::io::Error> {
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    if method == "OPTIONS" {
        // Same-origin pages never preflight; a foreign page gets nothing useful.
        return Ok(to_hyper(UiResponse::error(403, "FORBIDDEN_ORIGIN")));
    }
    let mut headers = std::collections::BTreeMap::new();
    for name in FORWARDED_HEADERS {
        if let Some(v) = req.headers().get(*name).and_then(|v| v.to_str().ok()) {
            headers.insert((*name).to_owned(), v.to_owned());
        }
    }
    // Host, origin and token are checked before a byte of the body is read: a refused
    // request never makes the listener buffer an upload.
    let mut request = UiRequest {
        method,
        path,
        query,
        headers,
        body: Vec::new(),
    };
    if let Some(refusal) = guard(&state, &request) {
        return Ok(to_hyper(refusal));
    }
    let limit = body_limit(&request.path);
    request.body = match Limited::new(req.into_body(), limit).collect().await {
        Ok(c) => c.to_bytes().to_vec(),
        Err(_) => return Ok(to_hyper(UiResponse::error(413, "PAYLOAD_TOO_LARGE"))),
    };
    let response = handle(&state, &request).await;
    if response
        .headers
        .iter()
        .any(|(k, _)| k == crate::DROP_CONNECTION_HEADER)
    {
        // A `dropConnection` fault behind the front: the connection closes without a
        // response, as on the port the SDKs use.
        return Err(std::io::Error::other("fault plan: connection dropped"));
    }
    Ok(to_hyper(response))
}

/// Serves the UI on `listener` until the task is aborted.
pub async fn serve_ui(listener: TcpListener, state: Arc<UiState>) -> std::io::Result<()> {
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
