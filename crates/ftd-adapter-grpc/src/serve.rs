//! One listener, three protocols: gRPC (HTTP/2, `application/grpc`), the `WebChannel`
//! transport of the web SDK (`/google.firestore.v1.Firestore/{Listen,Write}/channel`) and
//! the REST JSON API share the Firestore port, as the official Emulator does. Browser
//! requests get permissive CORS answers (loopback test runtime).

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tonic::codegen::Service;
use tonic::Status;

use crate::rest::{RestRequest, RestResponse, RestState};
use crate::webchannel::{ChannelRequest, ChannelResponse, Hub, StreamKind};

/// Maximum accepted REST request body.
pub const MAX_REST_BODY_BYTES: usize = 10 * 1024 * 1024;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type OutBody = UnsyncBoxBody<Bytes, BoxError>;

fn full(bytes: Bytes) -> OutBody {
    Full::new(bytes)
        .map_err(|e: Infallible| match e {})
        .boxed_unsync()
}

fn cors_headers(
    builder: hyper::http::response::Builder,
    origin: Option<&str>,
) -> hyper::http::response::Builder {
    let mut b = builder
        .header("access-control-allow-origin", origin.unwrap_or("*"))
        .header("access-control-allow-credentials", "true")
        .header(
            "access-control-allow-methods",
            "GET, POST, PUT, PATCH, DELETE, OPTIONS",
        )
        .header(
            "access-control-expose-headers",
            "x-http-session-id, x-http-initial-response, content-type",
        );
    if origin.is_some() {
        b = b.header("vary", "origin");
    }
    b
}

fn json_response(r: &RestResponse, origin: Option<&str>) -> Response<OutBody> {
    let text = serde_json::to_vec(&r.body).unwrap_or_default();
    cors_headers(Response::builder().status(r.status), origin)
        .header("content-type", "application/json; charset=utf-8")
        .body(full(Bytes::from(text)))
        .unwrap_or_else(|_| Response::new(full(Bytes::new())))
}

/// The error that makes hyper close the connection (or reset the stream) for a
/// `dropConnection` fault.
fn dropped() -> std::io::Error {
    std::io::Error::other("fault plan: connection dropped")
}

fn header<'a>(req: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

async fn read_body(req: Request<Incoming>, limit: usize) -> Result<Bytes, ()> {
    Limited::new(req.into_body(), limit)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .map_err(|_| ())
}

async fn rest_call(
    state: Arc<RestState>,
    req: Request<Incoming>,
) -> Result<Response<OutBody>, std::io::Error> {
    let origin = header(&req, "origin").map(str::to_owned);
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let authorization = header(&req, "authorization").map(str::to_owned);
    // Every instance, in wire order: duplicates and folded values must survive to the
    // classifier, which refuses them (spec 7.3).
    let app_check: Vec<String> = req
        .headers()
        .get_all(ftd_core_app_check::header::APP_CHECK_HEADER)
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_owned())
        .collect();
    let Ok(bytes) = read_body(req, MAX_REST_BODY_BYTES).await else {
        return Ok(json_response(
            &RestResponse {
                status: 413,
                body: serde_json::json!({"error": {"code": 413, "message": "request body too large", "status": "INVALID_ARGUMENT"}}),
            },
            origin.as_deref(),
        ));
    };
    let body = if bytes.is_empty() {
        serde_json::Value::Object(serde_json::Map::new())
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => {
                return Ok(json_response(
                    &crate::rest::error_response(&Status::invalid_argument(format!(
                        "invalid JSON body: {e}"
                    ))),
                    origin.as_deref(),
                ))
            }
        }
    };
    let response = state.handle(&RestRequest {
        method,
        path,
        query,
        authorization,
        app_check,
        body,
    });
    if crate::rest::drops_connection(&response) {
        // A `dropConnection` fault: the connection closes without a response.
        return Err(dropped());
    }
    Ok(json_response(&response, origin.as_deref()))
}

async fn channel_call(
    hub: Arc<Hub>,
    kind: StreamKind,
    req: Request<Incoming>,
) -> Response<OutBody> {
    let origin = header(&req, "origin").map(str::to_owned);
    let method = req.method().as_str().to_owned();
    let params = crate::webchannel::parse_form(req.uri().query().unwrap_or(""));
    let authorization = header(&req, "authorization").map(str::to_owned);
    // Every instance, in wire order, as on the REST path: the classifier refuses duplicates
    // and folded values, so no caller gets to pick one of several (spec 7.3).
    let app_check: Vec<String> = req
        .headers()
        .get_all(ftd_core_app_check::header::APP_CHECK_HEADER)
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_owned())
        .collect();
    let Ok(bytes) = read_body(req, crate::webchannel::MAX_FORM_BYTES).await else {
        return json_response(
            &RestResponse {
                status: 413,
                body: serde_json::json!({"error": {"code": 413, "message": "request body too large", "status": "INVALID_ARGUMENT"}}),
            },
            origin.as_deref(),
        );
    };
    let body = String::from_utf8_lossy(&bytes).into_owned();
    let response = hub.handle(&ChannelRequest {
        kind,
        method,
        params,
        authorization,
        app_check,
        origin: origin.clone(),
        body,
    });
    match response {
        ChannelResponse::Full {
            status,
            headers,
            body,
        } => {
            let mut b = cors_headers(Response::builder().status(status), origin.as_deref());
            for (k, v) in headers {
                b = b.header(k, v);
            }
            b.body(full(Bytes::from(body)))
                .unwrap_or_else(|_| Response::new(full(Bytes::new())))
        }
        ChannelResponse::Stream { headers, body } => {
            let mut b = cors_headers(Response::builder().status(200), origin.as_deref());
            for (k, v) in headers {
                b = b.header(k, v);
            }
            let frames =
                body.map(|item| item.map(Frame::data).map_err(|e| Box::new(e) as BoxError));
            b.body(StreamBody::new(frames).boxed_unsync())
                .unwrap_or_else(|_| Response::new(full(Bytes::new())))
        }
    }
}

fn preflight(req: &Request<Incoming>) -> Response<OutBody> {
    let origin = header(req, "origin");
    let requested = header(req, "access-control-request-headers")
        .unwrap_or("authorization, content-type, x-firebase-appcheck");
    cors_headers(Response::builder().status(204), origin)
        .header("access-control-allow-headers", requested)
        .header("access-control-max-age", "3600")
        .body(full(Bytes::new()))
        .unwrap_or_else(|_| Response::new(full(Bytes::new())))
}

fn is_grpc(req: &Request<Incoming>) -> bool {
    header(req, "content-type").is_some_and(|ct| ct.starts_with("application/grpc"))
}

fn channel_kind(path: &str) -> Option<StreamKind> {
    match path {
        "/google.firestore.v1.Firestore/Listen/channel" => Some(StreamKind::Listen),
        "/google.firestore.v1.Firestore/Write/channel" => Some(StreamKind::Write),
        _ => None,
    }
}

/// Serves gRPC, `WebChannel` and REST on `listener` until the task is aborted.
pub async fn serve_multiplexed<S>(
    listener: TcpListener,
    grpc: S,
    rest: Arc<RestState>,
) -> std::io::Result<()>
where
    S: Service<
            Request<tonic::body::Body>,
            Response = Response<tonic::body::Body>,
            Error = Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let hub = Arc::new(Hub::new(rest.clone()));
    loop {
        let (stream, _) = listener.accept().await?;
        let grpc = grpc.clone();
        let rest = rest.clone();
        let hub = hub.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<Incoming>| {
                let mut grpc = grpc.clone();
                let rest = rest.clone();
                let hub = hub.clone();
                async move {
                    if is_grpc(&req) {
                        let req = req.map(|b| {
                            tonic::body::Body::new(b.map_err(|e| Status::internal(e.to_string())))
                        });
                        let response = match grpc.call(req).await {
                            Ok(r) => r,
                            Err(never) => match never {},
                        };
                        if response
                            .headers()
                            .contains_key(crate::local::DROP_CONNECTION_KEY)
                        {
                            // A `dropConnection` fault: the stream is reset (HTTP/2) or
                            // the connection closed (HTTP/1) instead of delivering it.
                            return Err(dropped());
                        }
                        return Ok::<_, std::io::Error>(
                            response.map(|b| b.map_err(|e| Box::new(e) as BoxError).boxed_unsync()),
                        );
                    }
                    if let Some(origin) = header(&req, "origin") {
                        if !crate::webchannel::origin_is_local(origin) {
                            // A page on another site must not drive this credentialed
                            // loopback runtime (simple requests need no preflight).
                            return Ok(Response::builder()
                                .status(403)
                                .body(full(Bytes::from_static(b"forbidden origin")))
                                .unwrap_or_else(|_| Response::new(full(Bytes::new()))));
                        }
                    }
                    if req.method() == hyper::Method::OPTIONS {
                        return Ok(preflight(&req));
                    }
                    if let Some(kind) = channel_kind(req.uri().path()) {
                        return Ok(channel_call(hub, kind, req).await);
                    }
                    rest_call(rest, req).await
                }
            });
            // Connection errors are per-client; the accept loop keeps running.
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}
