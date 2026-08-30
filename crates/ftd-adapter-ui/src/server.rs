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

use crate::{handle, UiBody, UiRequest, UiResponse, UiState};

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
        ftd_adapter_http::storage_server::MAX_STORAGE_BODY_BYTES
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
) -> Result<Response<OutBody>, hyper::Error> {
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
    let limit = body_limit(&path);
    let body = match Limited::new(req.into_body(), limit).collect().await {
        Ok(c) => c.to_bytes().to_vec(),
        Err(_) => return Ok(to_hyper(UiResponse::error(413, "PAYLOAD_TOO_LARGE"))),
    };
    let request = UiRequest {
        method,
        path,
        query,
        headers,
        body,
    };
    Ok(to_hyper(handle(&state, &request).await))
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
