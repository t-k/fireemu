//! One listener, three protocols: gRPC (HTTP/2, `application/grpc`), the `WebChannel`
//! transport of the web SDK (`/google.firestore.v1.Firestore/{Listen,Write}/channel`) and
//! the REST JSON API share the Firestore port, as the official Emulator does. Browser
//! requests get permissive CORS answers (loopback test runtime).

use std::convert::Infallible;
use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::HeaderMap;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use tonic::codegen::Service;
use tonic::Status;

use crate::rest::{RestRequest, RestResponse, RestState};
use crate::webchannel::{ChannelRequest, ChannelResponse, Hub, StreamKind};

/// Maximum accepted REST request body.
pub const MAX_REST_BODY_BYTES: usize = 10 * 1024 * 1024;
/// Maximum Firestore REST requests that may retain bodies while waiting for synchronous work.
pub const MAX_BLOCKING_REST_REQUESTS: usize = 64;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type OutBody = UnsyncBoxBody<Bytes, BoxError>;

fn rest_work_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIMITER: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    LIMITER.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_BLOCKING_REST_REQUESTS)))
}

fn try_admit_rest_work(
    limiter: &Arc<tokio::sync::Semaphore>,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    limiter.clone().try_acquire_owned().ok()
}

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
    // `:ruleCoverage.html` is the one route whose body is a page rather than JSON; it says
    // so with a single key, exactly as a `dropConnection` fault does.
    if let Some(html) = r.body[crate::rest::coverage::HTML_KEY].as_str() {
        return cors_headers(Response::builder().status(r.status), origin)
            .header("content-type", "text/html; charset=utf-8")
            .body(full(Bytes::from(html.to_owned())))
            .unwrap_or_else(|_| Response::new(full(Bytes::new())));
    }
    // An unknown route answers plain text, as the official emulator's HTTP adapter does.
    if let Some(text) = r.body[crate::rest::TEXT_KEY].as_str() {
        return cors_headers(Response::builder().status(r.status), origin)
            .header("content-type", "text/plain; charset=utf-8")
            .body(full(Bytes::from(text.to_owned())))
            .unwrap_or_else(|_| Response::new(full(Bytes::new())));
    }
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
    fireemu_adapter_support::body::collect_limited(req.into_body(), limit)
        .await
        .map_err(|_| ())
}

async fn rest_call(
    state: Arc<RestState>,
    req: Request<Incoming>,
) -> Result<Response<OutBody>, std::io::Error> {
    let origin = header(&req, "origin").map(str::to_owned);
    let Some(permit) = try_admit_rest_work(rest_work_limiter()) else {
        return Ok(json_response(
            &RestResponse {
                status: 503,
                body: fireemu_adapter_support::api_error::google_rpc(
                    503,
                    "too many concurrent Firestore REST requests",
                    "RESOURCE_EXHAUSTED",
                ),
            },
            origin.as_deref(),
        ));
    };
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let authorization = header(&req, "authorization").map(str::to_owned);
    // Every instance, in wire order: duplicates and folded values must survive to the
    // classifier, which refuses them (spec 7.3).
    let app_check: Vec<String> = req
        .headers()
        .get_all(fireemu_core_app_check::header::APP_CHECK_HEADER)
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_owned())
        .collect();
    let Ok(bytes) = read_body(req, MAX_REST_BODY_BYTES).await else {
        return Ok(json_response(
            &RestResponse {
                status: 413,
                body: fireemu_adapter_support::api_error::google_rpc(
                    413,
                    "request body too large",
                    "INVALID_ARGUMENT",
                ),
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
    let request = RestRequest {
        method,
        path,
        query,
        authorization,
        app_check,
        body,
    };
    // A write refused for lock contention does not wait on the blocking-pool thread (that
    // would hold one of the few slots for the whole wait); the slot is released, this task
    // waits for a transaction to finish, then runs the request again.
    let request = Arc::new(request);
    let deadline = std::time::Instant::now() + state.local.contention_wait();
    let mut permit = permit;
    let response = loop {
        let attempt_permit = permit;
        let seen = state.local.release_count();
        let (attempt_state, attempt_request) = (Arc::clone(&state), Arc::clone(&request));
        let (response, contended) = tokio::task::spawn_blocking(move || {
            let _permit = attempt_permit;
            crate::local::LocalBackend::without_waiting(|| attempt_state.handle(&attempt_request))
        })
        .await
        .map_err(|error| std::io::Error::other(format!("Firestore REST task failed: {error}")))?;
        if !contended || std::time::Instant::now() >= deadline {
            break response;
        }
        state.local.await_any_release(seen, deadline).await;
        // Re-admitted for the retry; an exhausted pool answers the retry as it answers a new
        // request.
        match try_admit_rest_work(rest_work_limiter()) {
            Some(admitted) => permit = admitted,
            None => {
                return Ok(json_response(
                    &RestResponse {
                        status: 503,
                        body: fireemu_adapter_support::api_error::google_rpc(
                            503,
                            "too many concurrent Firestore REST requests",
                            "RESOURCE_EXHAUSTED",
                        ),
                    },
                    origin.as_deref(),
                ));
            }
        }
    };
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
        .get_all(fireemu_core_app_check::header::APP_CHECK_HEADER)
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_owned())
        .collect();
    let Ok(bytes) = read_body(req, crate::webchannel::MAX_FORM_BYTES).await else {
        return json_response(
            &RestResponse {
                status: 413,
                body: fireemu_adapter_support::api_error::google_rpc(
                    413,
                    "request body too large",
                    "INVALID_ARGUMENT",
                ),
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

fn readiness(origin: Option<&str>) -> Response<OutBody> {
    cors_headers(Response::builder().status(200), origin)
        .header("content-type", "application/json; charset=utf-8")
        .header("cache-control", "no-store")
        .body(full(Bytes::from_static(b"{\"emulator\":\"firestore\"}")))
        .unwrap_or_else(|_| Response::new(full(Bytes::new())))
}

fn is_grpc(req: &Request<Incoming>) -> bool {
    header(req, "content-type").is_some_and(|ct| ct.starts_with("application/grpc"))
}

fn normalize_prost_recursion_status(headers: &mut HeaderMap) {
    let Some(status) = Status::from_header_map(headers) else {
        return;
    };
    if status.code() != tonic::Code::Internal
        || !status
            .message()
            .starts_with("failed to decode Protobuf message:")
        || !status.message().ends_with("recursion limit reached")
    {
        return;
    }
    let replacement = Status::invalid_argument(status.message().to_owned());
    let mut replacement_headers = HeaderMap::new();
    if replacement.add_header(&mut replacement_headers).is_err() {
        return;
    }
    headers.remove(Status::GRPC_STATUS_DETAILS);
    if let Some(value) = replacement_headers.remove(Status::GRPC_STATUS) {
        headers.insert(Status::GRPC_STATUS, value);
    }
    if let Some(value) = replacement_headers.remove(Status::GRPC_MESSAGE) {
        headers.insert(Status::GRPC_MESSAGE, value);
    }
}

fn normalize_prost_recursion_frame(mut frame: Frame<Bytes>) -> Frame<Bytes> {
    if let Some(trailers) = frame.trailers_mut() {
        normalize_prost_recursion_status(trailers);
    }
    frame
}

fn channel_kind(path: &str) -> Option<StreamKind> {
    match path {
        "/google.firestore.v1.Firestore/Listen/channel" => Some(StreamKind::Listen),
        "/google.firestore.v1.Firestore/Write/channel" => Some(StreamKind::Write),
        _ => None,
    }
}

async fn accept_connection(listener: &TcpListener) -> std::io::Result<TcpStream> {
    let (stream, _) = listener.accept().await?;
    // Streaming gRPC frames must not wait for a delayed ACK before flushing.
    stream.set_nodelay(true)?;
    Ok(stream)
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
        let stream = accept_connection(&listener).await?;
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
                        let mut response = match grpc.call(req).await {
                            Ok(r) => r,
                            Err(never) => match never {},
                        };
                        normalize_prost_recursion_status(response.headers_mut());
                        if response
                            .headers()
                            .contains_key(crate::local::DROP_CONNECTION_KEY)
                        {
                            // A `dropConnection` fault: the stream is reset (HTTP/2) or
                            // the connection closed (HTTP/1) instead of delivering it.
                            return Err(dropped());
                        }
                        return Ok::<_, std::io::Error>(response.map(|b| {
                            b.map_frame(normalize_prost_recursion_frame)
                                .map_err(|e| Box::new(e) as BoxError)
                                .boxed_unsync()
                        }));
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
                    if req.method() == hyper::Method::GET
                        && req.uri().path() == "/"
                        && req.uri().query().is_none()
                    {
                        return Ok(readiness(header(&req, "origin")));
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[tokio::test]
    async fn accepted_connections_send_small_responses_without_nagle_delay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let accepted = super::accept_connection(&listener).await.unwrap();
        assert!(accepted.nodelay().unwrap());
        drop(peer);
    }

    use super::{normalize_prost_recursion_status, try_admit_rest_work};
    use bytes::Bytes;
    use hyper::HeaderMap;
    use tonic::{Code, Status};

    fn headers(status: &Status) -> HeaderMap {
        let mut headers = HeaderMap::new();
        status.add_header(&mut headers).unwrap();
        headers
    }

    #[test]
    fn only_the_prost_recursion_failure_is_normalized() {
        let ordinary = Status::with_details(
            Code::Internal,
            "backend failed",
            Bytes::from_static(b"details"),
        );
        let mut ordinary_headers = headers(&ordinary);
        normalize_prost_recursion_status(&mut ordinary_headers);
        let unchanged = Status::from_header_map(&ordinary_headers).unwrap();
        assert_eq!(unchanged.code(), Code::Internal);
        assert_eq!(unchanged.message(), "backend failed");
        assert_eq!(unchanged.details(), b"details");

        let already_client_error =
            Status::invalid_argument("failed to decode Protobuf message: recursion limit reached");
        let mut client_headers = headers(&already_client_error);
        normalize_prost_recursion_status(&mut client_headers);
        assert_eq!(
            Status::from_header_map(&client_headers).unwrap().message(),
            already_client_error.message()
        );

        let prost = Status::with_details(
            Code::Internal,
            "failed to decode Protobuf message: Value.value_type: recursion limit reached",
            Bytes::from_static(b"stale-internal-details"),
        );
        let mut prost_headers = headers(&prost);
        normalize_prost_recursion_status(&mut prost_headers);
        let normalized = Status::from_header_map(&prost_headers).unwrap();
        assert_eq!(normalized.code(), Code::InvalidArgument);
        assert_eq!(
            normalized.message(),
            "failed to decode Protobuf message: Value.value_type: recursion limit reached"
        );
        assert!(normalized.details().is_empty());
    }

    #[test]
    fn blocking_rest_admission_is_bounded_and_released_by_raii() {
        let limiter = Arc::new(tokio::sync::Semaphore::new(2));
        let first = try_admit_rest_work(&limiter).expect("first request is admitted");
        let second = try_admit_rest_work(&limiter).expect("second request is admitted");
        assert!(try_admit_rest_work(&limiter).is_none());

        drop(first);
        let replacement = try_admit_rest_work(&limiter).expect("a dropped request releases one");
        drop((second, replacement));
        assert_eq!(limiter.available_permits(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelling_the_waiter_does_not_release_running_blocking_work() {
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = try_admit_rest_work(&limiter).expect("the request is admitted");
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();

        task.abort();
        assert!(try_admit_rest_work(&limiter).is_none());
        release_tx.send(()).unwrap();
        task.await.unwrap();
        assert!(try_admit_rest_work(&limiter).is_some());
    }
}
