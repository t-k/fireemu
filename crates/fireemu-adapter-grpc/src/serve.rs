//! One listener, three protocols: gRPC (HTTP/2, `application/grpc`), the `WebChannel`
//! transport of the web SDK (`/google.firestore.v1.Firestore/{Listen,Write}/channel`) and
//! the REST JSON API share the Firestore port, as the official Emulator does. Browser
//! requests get permissive CORS answers (loopback test runtime).

use std::convert::Infallible;
use std::sync::{Arc, OnceLock};

use bytes::{Bytes, BytesMut};
use fireemu_adapter_support::connection::{DrainBounds, GracefulClose};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Body, Frame, Incoming};
use hyper::header::HeaderValue;
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

/// `FS-LIMIT-API-REQUEST-BYTES` as the limits catalog publishes it: 10 MiB. Production does
/// not refuse there (it accepted 10,485,761 bytes on every transport, FS-DATA-WRITE partial
/// supplement), so no transport enforces this figure; [`MAX_REQUEST_BYTES`] is the bound.
pub const API_REQUEST_BYTES: usize = 10 * 1024 * 1024;

/// Production accepts an 11 MiB raw REST Commit body and refuses one more byte.
pub const MAX_COMMIT_RAW_BYTES: usize = 11 * 1024 * 1024;

/// The request bound every transport applies at its own decode boundary, in both profiles:
/// [`MAX_REST_BODY_BYTES`] on a REST body and [`MAX_GRPC_MESSAGE_BYTES`] on a gRPC message. It
/// is an inclusive maximum measured before protocol decode. `WebChannel` has its own bound,
/// [`crate::webchannel::max_form_bytes`].
///
/// Owner decision D4 (2026-09-25) reuses the one production-observed figure, REST `:commit`,
/// as the estimate for the transports whose own limit is unobserved. Decision D (2026-09-27)
/// applies it in the emulator profile too: a lower local bound would refuse requests
/// production accepts, and the emulator profile adds no refusal.
pub const MAX_REQUEST_BYTES: usize = MAX_COMMIT_RAW_BYTES;

/// Maximum accepted REST request body. The body is read through a bounded stream, so an
/// over-long request is refused without ever being held whole in memory.
pub const MAX_REST_BODY_BYTES: usize = MAX_REQUEST_BYTES;

const MAX_COMMIT_REJECTION_DRAIN_BYTES: usize = 32 * 1024 * 1024;

/// Maximum accepted gRPC message, applied by tonic before the protobuf is decoded. This is
/// the request direction only.
pub const MAX_GRPC_MESSAGE_BYTES: usize = MAX_REQUEST_BYTES;

/// Maximum gRPC message this runtime will encode in a response.
///
/// **This is not a catalog limit.** `FS-LIMIT-API-REQUEST-BYTES` bounds a request; production
/// publishes no equivalent bound on a response, and nothing here claims one. It is a local
/// memory guard, kept at the request figure only because that is the number it has always
/// had. Changing it changes nothing about `FS-LIMIT-API-REQUEST-BYTES`, and a response
/// refused by it is a local failure rather than a modelled production refusal, which is why
/// `normalize_transport_status` reshapes only the decode direction.
pub const MAX_GRPC_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Maximum Firestore REST requests that may retain bodies while waiting for synchronous work.
pub const MAX_BLOCKING_REST_REQUESTS: usize = 64;
const REST_PAYLOAD_UNITS: usize = 640;
const REST_PAYLOAD_UNIT_BYTES: usize = 1024 * 1024;

/// How long a request body may take to arrive once a permit has been taken for it.
///
/// The permit is taken before the read so that peak body memory stays bounded, which means a
/// client that opens a request and then trickles its body would otherwise hold a permit for
/// as long as it liked; enough of them would stall every write surface. Loopback transfers of
/// the largest accepted body finish in milliseconds, so this is generous by orders of
/// magnitude and only ever fires on a stalled or malicious sender.
pub const BODY_READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// The refusal a request over [`MAX_REQUEST_BYTES`] gets, in both profiles and on every
/// transport: production's recorded REST `:commit` answer, HTTP 400 `INVALID_ARGUMENT` (gRPC
/// code 3) with this message. No official-emulator recording shows another shape, so the
/// emulator profile answers the same (decision D, 2026-09-27).
fn api_request_too_large_message() -> String {
    format!("Request payload size exceeds the limit: {MAX_REQUEST_BYTES} bytes.")
}

fn api_request_too_large() -> RestResponse {
    RestResponse {
        status: 400,
        body: fireemu_adapter_support::api_error::google_rpc(
            400,
            &api_request_too_large_message(),
            "INVALID_ARGUMENT",
        ),
    }
}

/// The refusal a Firestore request gets when the runtime already holds as many request
/// bodies as it admits ([`MAX_BLOCKING_REST_REQUESTS`]).
///
/// Every surface that reads a body answers this, so the admission bound is one pool with one
/// answer rather than a per-transport accident. The wording is the one the REST path has
/// always used.
fn too_many_concurrent_requests() -> RestResponse {
    RestResponse {
        status: 503,
        body: fireemu_adapter_support::api_error::google_rpc(
            503,
            "too many concurrent Firestore REST requests",
            "RESOURCE_EXHAUSTED",
        ),
    }
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type OutBody = UnsyncBoxBody<Bytes, BoxError>;

fn rest_work_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIMITER: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    LIMITER.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_BLOCKING_REST_REQUESTS)))
}

fn rest_payload_limiter() -> &'static Arc<tokio::sync::Semaphore> {
    static LIMITER: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    LIMITER.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(REST_PAYLOAD_UNITS)))
}

fn try_admit_rest_payload_from(
    limiter: &Arc<tokio::sync::Semaphore>,
    units: usize,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    let units = u32::try_from(units).expect("REST payload permit units fit in u32");
    limiter.clone().try_acquire_many_owned(units).ok()
}

fn try_admit_rest_payload(units: usize) -> Option<tokio::sync::OwnedSemaphorePermit> {
    try_admit_rest_payload_from(rest_payload_limiter(), units)
}

struct RestEnvelope {
    request: RestRequest,
    _payload_permit: Option<tokio::sync::OwnedSemaphorePermit>,
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
    json_response_with_layout(r, origin, false, false)
}

fn json_response_with_layout(
    r: &RestResponse,
    origin: Option<&str>,
    document_not_found: bool,
    production_json: bool,
) -> Response<OutBody> {
    json_response_with_document_layout(r, origin, document_not_found, production_json, false)
}

fn json_response_with_document_layout(
    r: &RestResponse,
    origin: Option<&str>,
    document_not_found: bool,
    production_json: bool,
    document_success: bool,
) -> Response<OutBody> {
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
    let text = if document_success {
        crate::rest::document_response::to_vec(&r.body).unwrap_or_default()
    } else if document_not_found {
        let mut bytes = serde_json::to_vec_pretty(&r.body).unwrap_or_default();
        bytes.push(b'\n');
        bytes
    } else {
        serde_json::to_vec(&r.body).unwrap_or_default()
    };
    // The observed production REST JSON header uses this literal charset spelling.
    // Strict local administration shares this styling; its native behavior is unobserved.
    let content_type = if production_json {
        "application/json; charset=UTF-8"
    } else {
        "application/json; charset=utf-8"
    };
    cors_headers(Response::builder().status(r.status), origin)
        .header("content-type", content_type)
        .body(full(Bytes::from(text)))
        .unwrap_or_else(|_| Response::new(full(Bytes::new())))
}

/// The error that makes hyper close the connection (or reset the stream) for a
/// `dropConnection` fault.
fn dropped() -> std::io::Error {
    std::io::Error::other("fault plan: connection dropped")
}

fn header<'a, B>(req: &'a Request<B>, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

/// Why a request body was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyRejection {
    /// Over [`MAX_REQUEST_BYTES`], or the connection failed mid-body. A broken connection has
    /// always been answered this way and keeps that answer; nothing reaches the client anyway.
    TooLarge,
    /// The sender held the request open past [`BODY_READ_DEADLINE`] without finishing it.
    Deadline,
    /// The request declared no body and sent one anyway. Distinct from [`Self::TooLarge`] so
    /// that a single stray byte is not reported as an 11 MiB overflow.
    Undeclared,
}

/// Whether a request *declares* a body.
///
/// A `GET` does not, and a declared length of zero says there is nothing to read. Deciding
/// this before admission keeps a body-less request off the pool: a `Listen` back channel is a
/// bare `GET`, and refusing one because writers are busy would be a load-caused refusal
/// neither production nor the official emulator has.
///
/// This is a statement about the declaration, not a guarantee about the wire: a chunked `GET`
/// declares nothing and can still send bytes. So the declaration only decides admission, and
/// a request that declares no body is read with a limit of zero
/// ([`body_limit_for`]) rather than trusted. An empty body satisfies that limit, so the back
/// channel is unchanged, and a request that sends bytes it never declared is refused instead
/// of buffered off the pool.
fn declares_a_body<B>(req: &Request<B>) -> bool {
    req.method() != hyper::Method::GET && header(req, "content-length") != Some("0")
}

/// How much body a request is allowed to send, and what it means to exceed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyAllowance {
    /// The request declared a body and took a permit for it; this many bytes are accepted.
    Declared(usize),
    /// The request declared no body, so it took no permit. An empty body satisfies this;
    /// anything else is refused rather than buffered off the pool.
    Undeclared,
}

impl BodyAllowance {
    const fn limit(self) -> usize {
        match self {
            Self::Declared(maximum) => maximum,
            Self::Undeclared => 0,
        }
    }

    const fn exceeded(self) -> BodyRejection {
        match self {
            Self::Declared(_) => BodyRejection::TooLarge,
            Self::Undeclared => BodyRejection::Undeclared,
        }
    }
}

async fn read_body<B>(
    req: Request<B>,
    allowance: BodyAllowance,
    deadline: std::time::Duration,
) -> Result<Bytes, BodyRejection>
where
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    let read = fireemu_adapter_support::body::collect_limited(req.into_body(), allowance.limit());
    match tokio::time::timeout(deadline, read).await {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(_)) => Err(allowance.exceeded()),
        Err(_) => Err(BodyRejection::Deadline),
    }
}

/// A Commit over its raw limit is drained without retaining the overflow. Replying while the
/// client is still uploading can reset the HTTP/1 connection before it sees the
/// production-shaped 400. The finite drain cap and deadline still bound hostile senders.
///
/// Only `:commit` drains while it reads. Other REST routes and `WebChannel` stop reading at the
/// bound, and the connection then ends with the drain of the listener (`GracefulClose`: FIN, then
/// up to `MAX_REST_BODY_BYTES` plus an eighth, 500 ms idle, 2 s in all), so a body over that
/// may still reset the connection instead of delivering the 400; production's answer there is
/// unobserved beyond one byte over.
async fn read_commit_body(
    req: Request<Incoming>,
    deadline: std::time::Duration,
) -> Result<Bytes, BodyRejection> {
    read_drained_body(
        req.into_body(),
        MAX_COMMIT_RAW_BYTES,
        MAX_COMMIT_REJECTION_DRAIN_BYTES,
        deadline,
    )
    .await
}

/// Reads a body of at most `limit` bytes. A body over it is drained up to `drain` bytes without
/// retaining the overflow, so the refusal reaches the client instead of a connection reset.
async fn read_drained_body<B>(
    body: B,
    limit: usize,
    drain: usize,
    deadline: std::time::Duration,
) -> Result<Bytes, BodyRejection>
where
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    let mut body = std::pin::pin!(body);
    let read = async {
        let mut retained = BytesMut::new();
        let mut total = 0usize;
        let mut too_large = false;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| BodyRejection::TooLarge)?;
            if let Ok(data) = frame.into_data() {
                total = total.saturating_add(data.len());
                if total > drain {
                    return Err(BodyRejection::TooLarge);
                }
                if total > limit {
                    too_large = true;
                    retained.clear();
                } else if !too_large {
                    retained.extend_from_slice(&data);
                }
            }
        }
        if too_large {
            Err(BodyRejection::TooLarge)
        } else {
            Ok(retained.freeze())
        }
    };
    tokio::time::timeout(deadline, read)
        .await
        .unwrap_or(Err(BodyRejection::Deadline))
}

/// The refusal a body that never finished arriving gets.
///
/// `408` is the HTTP answer for a request the client did not finish sending;
/// `DEADLINE_EXCEEDED` is its canonical `google.rpc.Code`. Local only: production has no
/// published behaviour here, and this fires on a stalled sender rather than on anything a
/// well-behaved client does.
fn body_read_deadline_exceeded() -> RestResponse {
    RestResponse {
        status: 408,
        body: fireemu_adapter_support::api_error::google_rpc(
            408,
            "request body was not received within the deadline",
            "DEADLINE_EXCEEDED",
        ),
    }
}

/// The refusal a request that declared no body and sent one anyway gets.
///
/// It is not an over-boundary answer: the request sent one byte more than the zero it
/// declared, which says nothing about `FS-LIMIT-API-REQUEST-BYTES`. Local only.
fn undeclared_body() -> RestResponse {
    RestResponse {
        status: 400,
        body: fireemu_adapter_support::api_error::google_rpc(
            400,
            "request body was not declared",
            "INVALID_ARGUMENT",
        ),
    }
}

fn body_rejection_response(rejection: BodyRejection) -> RestResponse {
    match rejection {
        BodyRejection::TooLarge => api_request_too_large(),
        BodyRejection::Deadline => body_read_deadline_exceeded(),
        BodyRejection::Undeclared => undeclared_body(),
    }
}

#[allow(clippy::too_many_lines)]
async fn rest_call(
    state: Arc<RestState>,
    req: Request<Incoming>,
    body_deadline: std::time::Duration,
) -> Result<Response<OutBody>, std::io::Error> {
    let origin = header(&req, "origin").map(str::to_owned);
    let production_json = state.gateway.production_refusals();
    let json = |response: &RestResponse| {
        json_response_with_layout(response, origin.as_deref(), false, production_json)
    };
    // REST admits every request, body or not: the permit covers the `spawn_blocking`
    // execution below as well as the body, so it bounds the blocking pool and not only
    // memory. The channel path has no such execution and admits only a declared body.
    let Some(permit) = try_admit_rest_work(rest_work_limiter()) else {
        return Ok(json(&too_many_concurrent_requests()));
    };
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let authorization = header(&req, "authorization").map(str::to_owned);
    let browser_metadata =
        fireemu_core_session::loopback::carries_browser_metadata(|name| header(&req, name));
    // Every instance, in wire order: duplicates and folded values must survive to the
    // classifier, which refuses them (spec 7.3).
    let app_check: Vec<String> = req
        .headers()
        .get_all(fireemu_core_app_check::header::APP_CHECK_HEADER)
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_owned())
        .collect();
    let commit = crate::rest::is_commit_route(&method, &path);
    let body_limit = if commit {
        MAX_COMMIT_RAW_BYTES
    } else {
        MAX_REST_BODY_BYTES
    };
    // REST reads the request body for every method, including GET and an explicit
    // Content-Length: 0. Charge the full allowance before the read so a body that was not
    // advertised cannot bypass the retained-payload bound.
    let payload_units = body_limit.div_ceil(REST_PAYLOAD_UNIT_BYTES);
    let payload_permit = match try_admit_rest_payload(payload_units) {
        Some(permit) => Some(permit),
        None => {
            return Ok(json(&too_many_concurrent_requests()));
        }
    };
    let bytes = match if commit {
        read_commit_body(req, body_deadline).await
    } else {
        read_body(req, BodyAllowance::Declared(body_limit), body_deadline).await
    } {
        Ok(bytes) => bytes,
        Err(rejection) => {
            return Ok(json(&body_rejection_response(rejection)));
        }
    };
    let (body, batch_field_order) =
        match request_body(&bytes, &path, state.gateway.production_refusals()) {
            Ok(body) => body,
            Err(response) => return Ok(json(&response)),
        };
    drop(bytes);
    let request = RestEnvelope {
        request: RestRequest {
            method,
            path,
            query,
            authorization,
            origin: origin.clone(),
            // The privileged emulator routes need to know whether a browser issued the request;
            // the set of fields that says so is the shared one.
            browser_metadata,
            app_check,
            body,
            batch_field_order,
        },
        _payload_permit: payload_permit,
    };
    // A write refused for lock contention does not wait on the blocking-pool thread (that
    // would hold one of the few slots for the whole wait); the slot is released, this task
    // waits for a transaction to finish, then runs the request again.
    let request = Arc::new(request);
    let deadline = state.local.contention_deadline();
    let mut permit = permit;
    let response = loop {
        let attempt_permit = permit;
        let seen = state.local.release_count();
        let (attempt_state, attempt_request) = (Arc::clone(&state), Arc::clone(&request));
        let (response, contended) = tokio::task::spawn_blocking(move || {
            let _permit = attempt_permit;
            crate::local::LocalBackend::without_waiting(|| {
                attempt_state.handle(&attempt_request.request)
            })
        })
        .await
        .map_err(|error| std::io::Error::other(format!("Firestore REST task failed: {error}")))?;
        if !contended || deadline.expired() {
            break response;
        }
        state.local.await_any_release_until(seen, &deadline).await;
        // Re-admitted for the retry; an exhausted pool answers the retry as it answers a new
        // request.
        match try_admit_rest_work(rest_work_limiter()) {
            Some(admitted) => permit = admitted,
            None => {
                return Ok(json(&too_many_concurrent_requests()));
            }
        }
    };
    if crate::rest::drops_connection(&response) {
        // A `dropConnection` fault: the connection closes without a response.
        return Err(dropped());
    }
    let document_not_found =
        crate::rest::production_document_not_found(&state, &request.request, &response);
    let document_success =
        crate::rest::production_document_success(&state, &request.request, &response);
    Ok(json_response_with_document_layout(
        &response,
        origin.as_deref(),
        document_not_found,
        production_json,
        document_success,
    ))
}

async fn channel_call<B>(
    hub: Arc<Hub>,
    kind: StreamKind,
    req: Request<B>,
    limiter: &Arc<tokio::sync::Semaphore>,
    body_deadline: std::time::Duration,
) -> Response<OutBody>
where
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    let origin = header(&req, "origin").map(str::to_owned);
    // A form body is admitted from the same pool as a REST body: without this, peak body
    // memory on this path was bounded only by how fast clients connect.
    //
    // Only a request that declares a body takes a permit. A `Listen` back channel is a bare
    // `GET` and reads nothing, so it must never be refused because writers are busy: that
    // would be a load-caused refusal on a surface where neither production nor the official
    // emulator has one.
    //
    // A declaration is not a promise, so one that declared no body is read with a limit of
    // zero: an empty body passes, and a chunked `GET` that sends bytes anyway is refused
    // rather than buffered outside the pool it never joined.
    //
    // The permit covers reading and parsing the body and the synchronous `Hub::handle`, and
    // is released when this function returns. A streaming back channel produces its frames
    // from the body returned here, after the permit is gone, so a `Listen` client long-polling
    // for up to `LONG_POLL_MAX` never holds one -- which would otherwise let a handful of
    // idle listeners starve every write surface.
    let declared = declares_a_body(&req);
    let _permit = if declared {
        match try_admit_rest_work(limiter) {
            Some(permit) => Some(permit),
            None => return json_response(&too_many_concurrent_requests(), origin.as_deref()),
        }
    } else {
        None
    };
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
    let read = if declared {
        read_drained_body(
            req.into_body(),
            crate::webchannel::max_form_bytes(hub.enforce_limits()),
            crate::webchannel::MAX_FORM_DRAIN_BYTES,
            body_deadline,
        )
        .await
    } else {
        read_body(req, BodyAllowance::Undeclared, body_deadline).await
    };
    let bytes = match read {
        Ok(bytes) => bytes,
        Err(BodyRejection::TooLarge) if declared => {
            let sid = params.get("SID").map(String::as_str);
            return channel_http_response(hub.oversized_form(sid), origin.as_deref());
        }
        Err(rejection) => {
            return json_response(&body_rejection_response(rejection), origin.as_deref());
        }
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
    channel_http_response(response, origin.as_deref())
}

fn channel_http_response(response: ChannelResponse, origin: Option<&str>) -> Response<OutBody> {
    match response {
        ChannelResponse::Full {
            status,
            headers,
            body,
        } => {
            let mut b = cors_headers(Response::builder().status(status), origin);
            for (k, v) in headers {
                b = b.header(k, v);
            }
            b.body(full(Bytes::from(body)))
                .unwrap_or_else(|_| Response::new(full(Bytes::new())))
        }
        ChannelResponse::Stream { headers, body } => {
            let mut b = cors_headers(Response::builder().status(200), origin);
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

/// Whether a status is prost's recursion guard firing while it decoded a request.
fn is_prost_recursion(status: &Status) -> bool {
    status.code() == tonic::Code::Internal
        && status
            .message()
            .starts_with("failed to decode Protobuf message:")
        && status.message().ends_with("recursion limit reached")
}

/// Whether a status is tonic refusing a message over [`MAX_GRPC_MESSAGE_BYTES`].
///
/// tonic answers `OUT_OF_RANGE` with its own wording. The boundary is right and the refusal
/// happens before prost decodes anything, so only the shape is rewritten, and only in the
/// strict profile. Matching tonic's text is how this module already recognises prost's
/// recursion guard; `tests/request_bytes.rs` asserts both the raw and the rewritten wording,
/// so a tonic upgrade that changes it fails there rather than silently passing the raw status
/// through.
/// A REST request body as production's front end reads it: an empty body is the empty
/// message, and a body that is not JSON is refused in the front end's words, inside the result
/// array for a streaming method. Without `production_refusals` (the emulator profile) a body
/// that grammar refuses but standard JSON admits (one nested deeper than its limit) is read as
/// standard JSON, as fireemu read every body before, so the profile adds no rejection.
fn request_body(
    bytes: &[u8],
    path: &str,
    production_refusals: bool,
) -> Result<(serde_json::Value, Vec<Vec<String>>), crate::rest::RestResponse> {
    if bytes.is_empty() {
        return Ok((
            serde_json::Value::Object(serde_json::Map::new()),
            Vec::new(),
        ));
    }
    let parsed = if path.ends_with(":batchWrite") {
        crate::rest::json_syntax::parse_with_batch_field_order(bytes)
    } else {
        crate::rest::transcode::parse_body(bytes).map(|value| (value, Vec::new()))
    };
    parsed
        .or_else(|error| {
            if !production_refusals {
                if let Ok(value) = serde_json::from_slice(bytes) {
                    return Ok((value, Vec::new()));
                }
            }
            Err(error)
        })
        .map_err(|error| {
            let mut response = crate::rest::error_response(&Status::invalid_argument(
                crate::rest::transcode::syntax_error_message(bytes, &error),
            ));
            if crate::rest::transcode::is_streaming_method(path) {
                response.body = serde_json::Value::Array(vec![response.body]);
            }
            response
        })
}

fn is_decoded_message_too_large(status: &Status) -> bool {
    status.code() == tonic::Code::OutOfRange
        && status
            .message()
            .starts_with("Error, decoded message length too large")
}

fn normalize_transport_status(headers: &mut HeaderMap) {
    crate::production_status::respec_grpc_message(headers);
    let Some(status) = Status::from_header_map(headers) else {
        return;
    };
    let replacement = if is_prost_recursion(&status) {
        Status::invalid_argument(status.message().to_owned())
    } else if is_decoded_message_too_large(&status) {
        Status::invalid_argument(api_request_too_large_message())
    } else {
        return;
    };
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

/// Shapes a gRPC answer as production's front end sends it: an error trailers-only answer is
/// split into headers and trailers (FS-DATA-WRITE decision 1, 2026-09-25), and every trailers
/// frame is normalized.
fn shape_grpc_response(
    mut response: Response<tonic::body::Body>,
    enforce_limits: bool,
    write_stream: bool,
) -> Response<http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>> {
    if enforce_limits && response.headers().contains_key(Status::GRPC_STATUS) {
        let trailers = split_trailers_only(response.headers_mut());
        let frame = normalize_transport_frame(
            Frame::trailers(trailers),
            enforce_limits,
            write_stream,
            false,
        );
        let body = http_body_util::StreamBody::new(tokio_stream::once(Ok::<_, BoxError>(frame)))
            .boxed_unsync();
        return response.map(|_| body);
    }
    response.map(|b| {
        let mut responded = false;
        b.map_frame(move |frame| {
            responded |= frame.is_data();
            normalize_transport_frame(frame, enforce_limits, write_stream, responded)
        })
        .map_err(|e| Box::new(e) as BoxError)
        .boxed_unsync()
    })
}

/// Moves a trailers-only answer's status and metadata out of its headers, leaving only the
/// content type, and returns them as the trailers of the same answer.
fn split_trailers_only(headers: &mut HeaderMap) -> HeaderMap {
    let content_type = headers.remove(hyper::header::CONTENT_TYPE);
    let trailers = std::mem::take(headers);
    if let Some(value) = content_type {
        headers.insert(hyper::header::CONTENT_TYPE, value);
    }
    trailers
}

/// `responded` says whether the stream sent any response message. Production closes a `Write`
/// stream with `content-disposition: attachment` after a response
/// (`write-stream-terminal/*`), but not when it ends without one
/// (`grpc-stream-request-bytes/*`, recorded twice).
fn normalize_transport_frame(
    mut frame: Frame<Bytes>,
    enforce_limits: bool,
    write_stream: bool,
    responded: bool,
) -> Frame<Bytes> {
    if let Some(trailers) = frame.trailers_mut() {
        normalize_transport_status(trailers);
        let write_terminal = enforce_limits
            && write_stream
            && Status::from_header_map(trailers).is_some_and(|status| {
                status.code() == tonic::Code::Ok
                    || (status.code() == tonic::Code::InvalidArgument
                        && status.message() == "empty write operation")
            });
        if write_terminal && responded && !trailers.contains_key("content-disposition") {
            trailers.insert(
                "content-disposition",
                HeaderValue::from_static("attachment"),
            );
        }
        if write_terminal {
            trailers.remove("fireemu-reason");
        }
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
    serve_multiplexed_with(listener, grpc, rest, BODY_READ_DEADLINE).await
}

/// [`serve_multiplexed`] with an explicit body-read deadline.
///
/// The deadline is a parameter so that a test can watch a stalled sender give its permit back
/// without waiting out [`BODY_READ_DEADLINE`], which is sized for a real client on a real
/// connection. Production callers use [`serve_multiplexed`].
pub async fn serve_multiplexed_with<S>(
    listener: TcpListener,
    grpc: S,
    rest: Arc<RestState>,
    body_deadline: std::time::Duration,
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
            let io = TokioIo::new(GracefulClose::new(
                stream,
                DrainBounds::for_largest_body(MAX_REST_BODY_BYTES),
            ));
            let svc = service_fn(move |req: Request<Incoming>| {
                let mut grpc = grpc.clone();
                let rest = rest.clone();
                let hub = hub.clone();
                async move {
                    if is_grpc(&req) {
                        let write_stream =
                            req.uri().path() == "/google.firestore.v1.Firestore/Write";
                        let req = req.map(|b| {
                            tonic::body::Body::new(b.map_err(|e| Status::internal(e.to_string())))
                        });
                        let mut response = match grpc.call(req).await {
                            Ok(r) => r,
                            Err(never) => match never {},
                        };
                        let enforce_limits = rest.gateway.enforce_limits;
                        normalize_transport_status(response.headers_mut());
                        if response
                            .headers()
                            .contains_key(crate::local::DROP_CONNECTION_KEY)
                        {
                            // A `dropConnection` fault: the stream is reset (HTTP/2) or
                            // the connection closed (HTTP/1) instead of delivering it.
                            return Err(dropped());
                        }
                        return Ok::<_, std::io::Error>(shape_grpc_response(
                            response,
                            enforce_limits,
                            write_stream,
                        ));
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
                        return Ok(channel_call(
                            hub,
                            kind,
                            req,
                            rest_work_limiter(),
                            body_deadline,
                        )
                        .await);
                    }
                    rest_call(rest, req, body_deadline).await
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

    /// FS-QUERY-INDEX request-shape/rest: a trailing comma is accepted, a truncated body and a
    /// bare word are refused in the front end's words, inside the result array of a streaming
    /// method and bare otherwise, and an empty body is the empty message.
    #[test]
    fn request_bodies_are_read_as_production_reads_them() {
        use serde_json::json;
        let query = "/v1/projects/p/databases/(default)/documents:runQuery";
        let commit = "/v1/projects/p/databases/(default)/documents:commit";
        assert_eq!(
            super::request_body(br#"{"structuredQuery": {"limit": 1,},}"#, query, true)
                .unwrap()
                .0,
            json!({"structuredQuery": {"limit": 1}})
        );
        assert_eq!(super::request_body(b"", commit, true).unwrap().0, json!({}));
        let batch = "/v1/projects/p/databases/(default)/documents:batchWrite";
        let (_, field_order) = super::request_body(
            br"{writes:[{update:{fields:{z:{stringValue:'ok'},a:{integerValue:'bad'}}}}]}",
            batch,
            true,
        )
        .unwrap();
        assert_eq!(field_order, vec![vec!["z".to_owned(), "a".to_owned()]]);
        let truncated = super::request_body(br#"{"structuredQuery":"#, query, true).unwrap_err();
        assert_eq!(truncated.status, 400);
        assert_eq!(
            truncated.body[0]["error"]["message"],
            "Invalid JSON payload received. Unexpected end of string. Expected a value.\n\n^"
        );
        let bare = super::request_body(b"not json", commit, true).unwrap_err();
        assert_eq!(
            bare.body["error"]["message"],
            "Invalid JSON payload received. Unexpected token.\nnot json\n^"
        );
        // Nesting past production's limit: refused under strict, read as standard JSON under
        // the emulator profile; what neither grammar admits keeps production's words.
        let deep = format!("{}{}", "[".repeat(110), "]".repeat(110));
        let refused = super::request_body(deep.as_bytes(), commit, true).unwrap_err();
        assert!(refused.body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Message too deep"));
        let read = super::request_body(deep.as_bytes(), commit, false).unwrap();
        assert!(read.0.is_array());
        let bare = super::request_body(b"not json", commit, false).unwrap_err();
        assert_eq!(
            bare.body["error"]["message"],
            "Invalid JSON payload received. Unexpected token.\nnot json\n^"
        );
    }
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

    use super::{
        api_request_too_large_message, normalize_transport_frame, normalize_transport_status,
        try_admit_rest_payload_from, try_admit_rest_work, RestEnvelope, MAX_COMMIT_RAW_BYTES,
        MAX_REST_BODY_BYTES, REST_PAYLOAD_UNIT_BYTES,
    };
    use bytes::Bytes;
    use hyper::body::Frame;
    use hyper::HeaderMap;
    use tonic::{Code, Status};

    fn headers(status: &Status) -> HeaderMap {
        let mut headers = HeaderMap::new();
        status.add_header(&mut headers).unwrap();
        headers
    }

    #[test]
    fn successful_write_terminal_retains_stable_content_disposition() {
        let frame: Frame<Bytes> = Frame::trailers(headers(&Status::new(Code::Ok, "")));
        let trailers = normalize_transport_frame(frame, true, true, true)
            .into_trailers()
            .expect("terminal trailers");
        assert_eq!(
            trailers
                .get("content-disposition")
                .and_then(|value| value.to_str().ok()),
            Some("attachment")
        );
        for (strict, write_stream, code, responded) in [
            (false, true, Code::Ok, true),
            (true, false, Code::Ok, true),
            (true, true, Code::InvalidArgument, true),
            // A stream that ends without any response carries no content-disposition.
            (true, true, Code::Ok, false),
        ] {
            let frame: Frame<Bytes> = Frame::trailers(headers(&Status::new(code, "refused")));
            let trailers = normalize_transport_frame(frame, strict, write_stream, responded)
                .into_trailers()
                .expect("terminal trailers");
            assert!(!trailers.contains_key("content-disposition"));
        }
    }

    #[test]
    fn only_the_prost_recursion_failure_is_normalized() {
        let ordinary = Status::with_details(
            Code::Internal,
            "backend failed",
            Bytes::from_static(b"details"),
        );
        let mut ordinary_headers = headers(&ordinary);
        normalize_transport_status(&mut ordinary_headers);
        let unchanged = Status::from_header_map(&ordinary_headers).unwrap();
        assert_eq!(unchanged.code(), Code::Internal);
        assert_eq!(unchanged.message(), "backend failed");
        assert_eq!(unchanged.details(), b"details");

        let already_client_error =
            Status::invalid_argument("failed to decode Protobuf message: recursion limit reached");
        let mut client_headers = headers(&already_client_error);
        normalize_transport_status(&mut client_headers);
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
        normalize_transport_status(&mut prost_headers);
        let normalized = Status::from_header_map(&prost_headers).unwrap();
        assert_eq!(normalized.code(), Code::InvalidArgument);
        assert_eq!(
            normalized.message(),
            "failed to decode Protobuf message: Value.value_type: recursion limit reached"
        );
        assert!(normalized.details().is_empty());
    }

    /// The decode-size refusal takes production's shape in both profiles (decision D,
    /// 2026-09-27): the bound tonic enforces is the same either way.
    #[test]
    fn the_decode_size_refusal_is_reshaped_in_both_profiles() {
        let tonic_wording =
            "Error, decoded message length too large: found 11534337 bytes, the limit is: 11534336 bytes";
        let mut decoded = headers(&Status::new(Code::OutOfRange, tonic_wording));
        normalize_transport_status(&mut decoded);
        let reshaped = Status::from_header_map(&decoded).unwrap();
        assert_eq!(reshaped.code(), Code::InvalidArgument);
        assert_eq!(reshaped.message(), api_request_too_large_message());
        // The message states the enforced bound, not the 10 MiB catalog figure.
        assert_eq!(
            api_request_too_large_message(),
            "Request payload size exceeds the limit: 11534336 bytes."
        );

        // The encode direction is never touched. `MAX_GRPC_RESPONSE_BYTES` is a local memory
        // guard, not `FS-LIMIT-API-REQUEST-BYTES`, so a response this runtime could not encode
        // must not be dressed up as production refusing the client's request.
        let encode_side = "Error, encoded message length too large: found 10485761 bytes, the limit is: 10485760 bytes";
        let mut encoded = headers(&Status::new(Code::OutOfRange, encode_side));
        normalize_transport_status(&mut encoded);
        let kept = Status::from_header_map(&encoded).unwrap();
        assert_eq!(kept.code(), Code::OutOfRange);
        assert_eq!(kept.message(), encode_side);

        // An unrelated OUT_OF_RANGE is never touched.
        let mut unrelated = headers(&Status::new(Code::OutOfRange, "cursor past the end"));
        normalize_transport_status(&mut unrelated);
        let kept = Status::from_header_map(&unrelated).unwrap();
        assert_eq!(kept.code(), Code::OutOfRange);
        assert_eq!(kept.message(), "cursor past the end");
    }

    /// A `WebChannel` form body is up to 16 MiB (`max_form_bytes`), larger than a REST body,
    /// and draws on the same admission pool. Before this, `channel_call` had no gate at all
    /// and peak body memory on that path was bounded only by the connection rate.
    mod channel_admission {
        use super::super::{
            channel_call, rest_work_limiter, too_many_concurrent_requests, BODY_READ_DEADLINE,
            MAX_BLOCKING_REST_REQUESTS,
        };
        use crate::gateway::Gateway;
        use crate::local::LocalBackend;
        use crate::rest::RestState;
        use crate::webchannel::{Hub, StreamKind};
        use bytes::Bytes;
        use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
        use fireemu_core_types::time::LogicalInstant;
        use http_body_util::{BodyExt, Full};
        use hyper::body::{Body, Frame};
        use hyper::{Request, Response};
        use std::convert::Infallible;
        use std::pin::Pin;
        use std::sync::{Arc, Mutex};
        use std::task::{Context, Poll};

        /// A stalled sender: one byte, then silence forever. It is never over-long and never
        /// finishes, so only the deadline can end the read.
        struct TricklingBody {
            sent: bool,
        }

        impl Body for TricklingBody {
            type Data = Bytes;
            type Error = Infallible;

            fn poll_frame(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
                if self.sent {
                    // No waker is registered: nothing will ever finish this body.
                    return Poll::Pending;
                }
                self.sent = true;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"c")))))
            }
        }

        fn hub() -> Arc<Hub> {
            hub_with(true)
        }

        fn hub_with(enforce_limits: bool) -> Arc<Hub> {
            let gateway = Gateway {
                enforce_limits,
                ctx: PlanningContext {
                    edition: FirestoreEdition::Standard,
                    api_mode: FirestoreApiMode::Native,
                    policy: if enforce_limits {
                        IndexValidationPolicy::Production
                    } else {
                        IndexValidationPolicy::Emulator
                    },
                },
                indexes: IndexSet::default(),
            };
            let clock = Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(1_788_004_860),
            )));
            let local = Arc::new(LocalBackend::new(gateway.clone(), clock, 7));
            Arc::new(Hub::new(Arc::new(RestState {
                local,
                gateway: Arc::new(gateway),
                rules: None,
                app_check: None,
                control_token: None,
            })))
        }

        const DB: &str = "projects/demo-app/databases/(default)";

        /// A forward-channel POST carrying a real form body.
        fn forward_channel_request() -> Request<Full<Bytes>> {
            Request::builder()
                .method("POST")
                .uri("/google.firestore.v1.Firestore/Write/channel?VER=8&RID=1&CI=0")
                .body(Full::new(Bytes::from_static(
                    b"count=1&ofs=0&req0___data__=%7B%7D",
                )))
                .expect("a well-formed forward-channel request")
        }

        /// Percent-encodes every byte, which is always a valid form or query encoding.
        fn percent_encode(value: &str) -> String {
            use std::fmt::Write as _;
            value.bytes().fold(String::new(), |mut out, byte| {
                let _ = write!(out, "%{byte:02X}");
                out
            })
        }

        /// A `Listen` handshake POST, which opens a session and names it in a response header.
        fn listen_handshake_request() -> Request<Full<Bytes>> {
            let target = serde_json::json!({
                "database": DB,
                "addTarget": {
                    "targetId": 2,
                    "query": {
                        "parent": format!("{DB}/documents"),
                        "structuredQuery": {"from": [{"collectionId": "open"}]},
                    },
                },
            })
            .to_string();
            let body = format!("count=1&ofs=0&req0___data__={}", percent_encode(&target));
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/google.firestore.v1.Firestore/Listen/channel?database={}&VER=8&RID=1&CVER=22",
                    percent_encode(DB)
                ))
                .body(Full::new(Bytes::from(body)))
                .expect("a well-formed handshake")
        }

        /// A long-polling `Listen` back channel on an open session. This is the request whose
        /// response streams for up to `LONG_POLL_MAX`.
        fn backchannel_request(session: &str) -> Request<Full<Bytes>> {
            Request::builder()
                .method("GET")
                .uri(format!(
                    "/google.firestore.v1.Firestore/Listen/channel?SID={session}&RID=rpc&AID=0&CI=1&TYPE=xmlhttp"
                ))
                .body(Full::new(Bytes::new()))
                .expect("a well-formed back channel")
        }

        async fn body_of(response: Response<super::super::OutBody>) -> (u16, serde_json::Value) {
            let status = response.status().as_u16();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice(&bytes).unwrap_or_default())
        }

        /// The process-wide pool that every body-reading surface now shares. Adding the
        /// `WebChannel` path must not change how many requests are admitted.
        #[test]
        fn the_admitted_count_is_unchanged() {
            assert_eq!(MAX_BLOCKING_REST_REQUESTS, 64);
            assert_eq!(
                rest_work_limiter().available_permits(),
                MAX_BLOCKING_REST_REQUESTS,
                "the shared pool is still one pool of MAX_BLOCKING_REST_REQUESTS permits"
            );
        }

        /// An exhausted pool refuses a form body with the answer the REST path gives, and
        /// never reads the body.
        #[test]
        fn an_over_admission_form_body_is_refused_exactly_as_a_rest_body_is() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let exhausted = Arc::new(tokio::sync::Semaphore::new(0));
                let response = channel_call(
                    hub(),
                    StreamKind::Write,
                    forward_channel_request(),
                    &exhausted,
                    BODY_READ_DEADLINE,
                )
                .await;
                let (status, body) = body_of(response).await;
                assert_eq!(status, 503);
                assert_eq!(body, too_many_concurrent_requests().body);
                assert_eq!(body["error"]["status"], "RESOURCE_EXHAUSTED");
            });
        }

        /// A form body over the profile's bound: strict answers production's HTML 400 and the
        /// session is gone afterwards; the emulator profile answers the official emulator's
        /// empty 413 and the session keeps working.
        #[test]
        fn an_oversized_form_ends_the_session_only_in_the_strict_profile() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                for enforce_limits in [true, false] {
                    let permits = Arc::new(tokio::sync::Semaphore::new(4));
                    let hub = hub_with(enforce_limits);
                    let handshake = channel_call(
                        hub.clone(),
                        StreamKind::Listen,
                        listen_handshake_request(),
                        &permits,
                        BODY_READ_DEADLINE,
                    )
                    .await;
                    assert_eq!(handshake.status().as_u16(), 200);
                    let session = handshake
                        .headers()
                        .get("x-http-session-id")
                        .and_then(|v| v.to_str().ok())
                        .expect("the handshake names its session")
                        .to_owned();
                    let forward = |bytes: usize| {
                        let body = format!("count=0&pad={}", "a".repeat(bytes - 12));
                        Request::builder()
                            .method("POST")
                            .uri(format!(
                                "/google.firestore.v1.Firestore/Listen/channel?SID={session}&VER=8&RID=2&AID=0"
                            ))
                            .body(Full::new(Bytes::from(body)))
                            .expect("a well-formed forward request")
                    };
                    let over = channel_call(
                        hub.clone(),
                        StreamKind::Listen,
                        forward(crate::webchannel::max_form_bytes(enforce_limits) + 1),
                        &permits,
                        BODY_READ_DEADLINE,
                    )
                    .await;
                    let status = over.status().as_u16();
                    let text = over.into_body().collect().await.unwrap().to_bytes();
                    let after = channel_call(
                        hub.clone(),
                        StreamKind::Listen,
                        forward(13),
                        &permits,
                        BODY_READ_DEADLINE,
                    )
                    .await;
                    let terminate = channel_call(
                        hub.clone(),
                        StreamKind::Listen,
                        Request::builder()
                            .method("GET")
                            .uri(format!(
                                "/google.firestore.v1.Firestore/Listen/channel?SID={session}&VER=8&RID=3&AID=0&TYPE=terminate"
                            ))
                            .body(Full::new(Bytes::new()))
                            .expect("a well-formed terminate"),
                        &permits,
                        BODY_READ_DEADLINE,
                    )
                    .await;
                    if enforce_limits {
                        assert_eq!(status, 400);
                        assert_eq!(
                            text.as_ref(),
                            crate::webchannel::STRICT_UNKNOWN_SESSION_BODY.as_bytes()
                        );
                        assert_eq!(after.status().as_u16(), 400, "the session is gone");
                        // Production's terminate of the ended session answered the same page.
                        assert_eq!(terminate.status().as_u16(), 400);
                    } else {
                        assert_eq!(status, 413);
                        assert!(text.is_empty());
                        assert_eq!(after.status().as_u16(), 200, "the session keeps working");
                        assert_eq!(terminate.status().as_u16(), 200);
                    }
                }
            });
        }

        /// The starvation case the bound exists to prevent: a long-polling back channel holds
        /// its response open for up to `LONG_POLL_MAX`, but `Hub::handle` spawns that loop and
        /// returns at once, so the permit is gone before a single frame is produced. One
        /// permit is enough to open a back channel and then still serve a write.
        #[test]
        fn a_long_polling_back_channel_holds_no_permit_while_it_streams() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let one = Arc::new(tokio::sync::Semaphore::new(1));
                let hub = hub();

                let handshake = channel_call(
                    hub.clone(),
                    StreamKind::Listen,
                    listen_handshake_request(),
                    &one,
                    BODY_READ_DEADLINE,
                )
                .await;
                assert_eq!(handshake.status().as_u16(), 200);
                let session = handshake
                    .headers()
                    .get("x-http-session-id")
                    .and_then(|v| v.to_str().ok())
                    .expect("the handshake names its session")
                    .to_owned();
                assert_eq!(one.available_permits(), 1);

                let streaming = channel_call(
                    hub.clone(),
                    StreamKind::Listen,
                    backchannel_request(&session),
                    &one,
                    BODY_READ_DEADLINE,
                )
                .await;
                assert_eq!(streaming.status().as_u16(), 200);
                assert_eq!(
                    one.available_permits(),
                    1,
                    "a streaming back channel must not hold a permit for its poll"
                );

                // The write surface is still served while that back channel is open and
                // unconsumed.
                let write = channel_call(
                    hub,
                    StreamKind::Write,
                    forward_channel_request(),
                    &one,
                    BODY_READ_DEADLINE,
                )
                .await;
                assert_ne!(write.status().as_u16(), 503);
                drop(streaming);
            });
        }

        /// A back channel reads no body, so it takes no permit and can never be refused for
        /// load. Before this it took one before looking at the method, which meant 64 writes
        /// in flight turned every `Listen` reconnect into a 503 that neither production nor
        /// the official emulator answers.
        #[test]
        fn a_body_less_back_channel_is_served_from_an_exhausted_pool() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let hub = hub();
                let open = Arc::new(tokio::sync::Semaphore::new(1));
                let handshake = channel_call(
                    hub.clone(),
                    StreamKind::Listen,
                    listen_handshake_request(),
                    &open,
                    BODY_READ_DEADLINE,
                )
                .await;
                let session = handshake
                    .headers()
                    .get("x-http-session-id")
                    .and_then(|v| v.to_str().ok())
                    .expect("the handshake names its session")
                    .to_owned();

                let exhausted = Arc::new(tokio::sync::Semaphore::new(0));
                let streaming = channel_call(
                    hub,
                    StreamKind::Listen,
                    backchannel_request(&session),
                    &exhausted,
                    BODY_READ_DEADLINE,
                )
                .await;
                assert_eq!(
                    streaming.status().as_u16(),
                    200,
                    "a back channel reads no body and must not need a permit"
                );
            });
        }

        /// A declaration is not a promise. A chunked `GET` declares no body, so it takes no
        /// permit; before this it was then read with the full transport limit and could buffer
        /// a megabyte outside the pool it never joined. It is read with a limit of zero now, so
        /// bytes it never declared are refused rather than buffered.
        #[test]
        fn an_undeclared_body_is_refused_rather_than_buffered_off_the_pool() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let exhausted = Arc::new(tokio::sync::Semaphore::new(0));
                let request = Request::builder()
                    .method("GET")
                    .uri("/google.firestore.v1.Firestore/Listen/channel?SID=none&RID=rpc&AID=0&CI=1&TYPE=xmlhttp")
                    .header("transfer-encoding", "chunked")
                    .body(Full::new(Bytes::from(vec![b'x'; 1024 * 1024])))
                    .expect("a chunked GET that carries bytes anyway");

                let (status, body) = body_of(
                    channel_call(
                        hub(),
                        StreamKind::Listen,
                        request,
                        &exhausted,
                        BODY_READ_DEADLINE,
                    )
                    .await,
                )
                .await;
                assert_ne!(status, 503, "it declared no body, so it needs no permit");
                assert_eq!(status, 400, "{body}");
                assert_eq!(body["error"]["status"], "INVALID_ARGUMENT");
                // Not the over-boundary wording: one stray byte past a declared zero says
                // nothing about FS-LIMIT-API-REQUEST-BYTES.
                assert_eq!(body["error"]["message"], "request body was not declared");
                assert_eq!(
                    exhausted.available_permits(),
                    0,
                    "no permit was taken and none was returned"
                );
            });
        }

        /// A `POST` that declares an empty body declares no body, so it takes no permit and
        /// is served from an empty pool like the back channel is.
        #[test]
        fn a_zero_length_post_takes_no_permit_and_is_served_from_an_exhausted_pool() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let exhausted = Arc::new(tokio::sync::Semaphore::new(0));
                let request = Request::builder()
                    .method("POST")
                    .uri("/google.firestore.v1.Firestore/Write/channel?VER=8&RID=1&CI=0")
                    .header("content-length", "0")
                    .body(Full::new(Bytes::new()))
                    .expect("a declared-empty forward channel request");

                let (status, body) = body_of(
                    channel_call(
                        hub(),
                        StreamKind::Write,
                        request,
                        &exhausted,
                        BODY_READ_DEADLINE,
                    )
                    .await,
                )
                .await;
                assert_ne!(status, 503, "a declared-empty body needs no permit");
                assert_eq!(status, 200, "{body}");
                assert_eq!(exhausted.available_permits(), 0);
            });
        }

        /// A request declaring both a length and a chunked encoding still declares a body, so
        /// it is admitted. This pins the input shape the admission check reads; hyper decides
        /// separately whether such a request reaches a handler at all.
        #[test]
        fn a_request_declaring_both_a_length_and_an_encoding_takes_a_permit() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let exhausted = Arc::new(tokio::sync::Semaphore::new(0));
                let request = Request::builder()
                    .method("POST")
                    .uri("/google.firestore.v1.Firestore/Write/channel?VER=8&RID=1&CI=0")
                    .header("content-length", "5")
                    .header("transfer-encoding", "chunked")
                    .body(Full::new(Bytes::from_static(b"count=1&ofs=0")))
                    .expect("a request declaring both");

                let (status, _) = body_of(
                    channel_call(
                        hub(),
                        StreamKind::Write,
                        request,
                        &exhausted,
                        BODY_READ_DEADLINE,
                    )
                    .await,
                )
                .await;
                assert_eq!(
                    status, 503,
                    "a declared body must be admitted, so an empty pool refuses it"
                );
            });
        }

        /// A sender that opens a request and then trickles its body holds a permit for as
        /// long as the deadline allows and no longer. Without the deadline, enough of them
        /// would hold every permit indefinitely and stall every write surface.
        #[test]
        fn a_trickling_body_releases_its_permit_at_the_deadline() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let one = Arc::new(tokio::sync::Semaphore::new(1));
                let request = Request::builder()
                    .method("POST")
                    .uri("/google.firestore.v1.Firestore/Write/channel?VER=8&RID=1&CI=0")
                    .body(TricklingBody { sent: false })
                    .expect("a well-formed stalled request");

                let started = tokio::time::Instant::now();
                let response = channel_call(
                    hub(),
                    StreamKind::Write,
                    request,
                    &one,
                    std::time::Duration::from_millis(50),
                )
                .await;
                let (status, body) = body_of(response).await;
                assert_eq!(status, 408);
                assert_eq!(body["error"]["status"], "DEADLINE_EXCEEDED");
                assert!(
                    started.elapsed() < std::time::Duration::from_secs(5),
                    "the read must end at the deadline, not when the sender gives up"
                );
                assert_eq!(
                    one.available_permits(),
                    1,
                    "the permit must come back when the deadline fires"
                );
            });
        }

        /// The permit is released when `channel_call` returns. A streaming back channel
        /// produces its frames after that, so a long-polling `Listen` client cannot hold a
        /// permit for its poll and starve every other write surface.
        #[test]
        fn a_permit_is_released_when_the_call_returns() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let one = Arc::new(tokio::sync::Semaphore::new(1));
                let hub = hub();
                for _ in 0..3 {
                    let response = channel_call(
                        hub.clone(),
                        StreamKind::Write,
                        forward_channel_request(),
                        &one,
                        BODY_READ_DEADLINE,
                    )
                    .await;
                    assert_ne!(
                        response.status().as_u16(),
                        503,
                        "a released permit must admit the next request"
                    );
                    assert_eq!(one.available_permits(), 1);
                }
            });
        }
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

    fn envelope_with_permit(permit: tokio::sync::OwnedSemaphorePermit) -> RestEnvelope {
        RestEnvelope {
            request: crate::rest::RestRequest {
                method: "GET".to_owned(),
                path: "/v1/projects/demo/databases/(default)/documents".to_owned(),
                query: String::new(),
                authorization: None,
                origin: None,
                browser_metadata: false,
                app_check: Vec::new(),
                body: serde_json::Value::Object(serde_json::Map::new()),
                batch_field_order: Vec::new(),
            },
            _payload_permit: Some(permit),
        }
    }

    #[test]
    fn rest_payload_admission_is_weighted_and_released_after_envelope_drop() {
        let limiter = Arc::new(tokio::sync::Semaphore::new(2));
        let permit = try_admit_rest_payload_from(&limiter, 2).expect("payload is admitted");
        let envelope = std::sync::Arc::new(envelope_with_permit(permit));
        assert!(try_admit_rest_payload_from(&limiter, 1).is_none());
        drop(envelope);
        assert_eq!(limiter.available_permits(), 2);
        assert!(try_admit_rest_payload_from(&limiter, 1).is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelling_the_rest_waiter_keeps_payload_charge_until_worker_finishes() {
        let limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = try_admit_rest_payload_from(&limiter, 1).expect("payload is admitted");
        let envelope = std::sync::Arc::new(envelope_with_permit(permit));
        let worker_envelope = std::sync::Arc::clone(&envelope);
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let task = tokio::task::spawn_blocking(move || {
            let _envelope = worker_envelope;
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        drop(envelope);
        task.abort();
        assert!(try_admit_rest_payload_from(&limiter, 1).is_none());
        release_tx.send(()).unwrap();
        task.await.unwrap();
        assert!(try_admit_rest_payload_from(&limiter, 1).is_some());
    }

    #[test]
    fn every_rest_body_read_is_charged_at_its_selected_wire_limit() {
        assert_eq!(MAX_REST_BODY_BYTES.div_ceil(REST_PAYLOAD_UNIT_BYTES), 11);
        assert_eq!(MAX_COMMIT_RAW_BYTES.div_ceil(REST_PAYLOAD_UNIT_BYTES), 11);
    }
}

#[cfg(test)]
mod document_not_found_layout_tests {
    use super::*;
    use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
    use fireemu_core_session::clock::VirtualClock;
    use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
    use fireemu_core_types::time::LogicalInstant;
    use std::fmt::Write as _;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PATH: &str = "/v1/projects/demo-app/databases/(default)/documents/cases/missing";
    const PRETTY: &[u8] = b"{\n  \"error\": {\n    \"code\": 404,\n    \"message\": \"Document \\\"projects/demo-app/databases/(default)/documents/cases/missing\\\" not found.\",\n    \"status\": \"NOT_FOUND\"\n  }\n}\n";
    const COMPACT: &[u8] = br#"{"error":{"code":404,"message":"Document \"projects/demo-app/databases/(default)/documents/cases/missing\" not found.","status":"NOT_FOUND"}}"#;

    fn state(production: bool, enforce_limits: bool) -> Arc<RestState> {
        let gateway = crate::gateway::Gateway {
            enforce_limits,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: if production {
                    IndexValidationPolicy::Production
                } else {
                    IndexValidationPolicy::Emulator
                },
            },
            indexes: IndexSet::default(),
        };
        let clock = Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        )));
        Arc::new(RestState {
            local: Arc::new(crate::local::LocalBackend::new(gateway.clone(), clock, 7)),
            gateway: Arc::new(gateway),
            rules: None,
            control_token: None,
            app_check: None,
        })
    }

    async fn wire(state: Arc<RestState>, method: &str, path: &str) -> (String, Vec<u8>) {
        wire_request(state, method, path, b"").await
    }

    struct WireServer(Option<tokio::task::JoinHandle<()>>);

    impl Drop for WireServer {
        fn drop(&mut self) {
            if let Some(server) = self.0.take() {
                server.abort();
            }
        }
    }

    async fn wire_request(
        state: Arc<RestState>,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> (String, Vec<u8>) {
        wire_exchange(state, method, path, body, body.len(), BODY_READ_DEADLINE).await
    }

    async fn wire_exchange(
        state: Arc<RestState>,
        method: &str,
        path: &str,
        body: &[u8],
        declared_bytes: usize,
        deadline: std::time::Duration,
    ) -> (String, Vec<u8>) {
        let port = std::env::var("PORT").unwrap_or_else(|_| "0".to_owned());
        let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let mut server = WireServer(Some(tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = hyper::service::service_fn(move |request| {
                super::rest_call(Arc::clone(&state), request, deadline)
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        })));
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {declared_bytes}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        client.write_all(body).await.unwrap();
        let mut bytes = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.read_to_end(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        server.0.take().unwrap().await.unwrap();
        println!("wire request={method} {path} raw-response={bytes:?}");
        let split = bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap();
        (
            String::from_utf8(bytes[..split].to_vec()).unwrap(),
            bytes[split + 4..].to_vec(),
        )
    }

    fn assert_json_headers(headers: &str, bytes: &[u8], production: bool, status: u16) {
        assert!(
            headers.starts_with(&format!("HTTP/1.1 {status} ")),
            "{headers}"
        );
        let values: Vec<_> = headers
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-type")
                    .then(|| value.trim())
            })
            .collect();
        let expected = if production {
            "application/json; charset=UTF-8"
        } else {
            "application/json; charset=utf-8"
        };
        assert_eq!(values, [expected], "{headers}");
        assert!(
            headers.contains(&format!("content-length: {}\r\n", bytes.len())),
            "{headers}"
        );
    }

    // Synthetic scalar literals retain each saved production case's root byte layout.
    fn check_saved_document_success_layout(
        id: &str,
        allowed: bool,
        updated: &str,
        expected: &[u8],
    ) {
        let name = format!("projects/demo-app/databases/(default)/documents/cases/{id}");
        let method = if id.ends_with("-create") {
            "POST"
        } else if id.ends_with("-update") {
            "PATCH"
        } else {
            "GET"
        };
        let (path, query) = if method == "POST" {
            (
                "/v1/projects/demo-app/databases/(default)/documents/cases".to_owned(),
                format!("documentId={id}"),
            )
        } else {
            (format!("/v1/{name}"), String::new())
        };
        let mut req = request(method, &path);
        req.query = query;
        let response = RestResponse {
            status: 200,
            body: serde_json::json!({
                "name": name, "fields": {"allowed": {"booleanValue": allowed}},
                "createTime": "2000-01-02T03:04:05.123456Z", "updateTime": updated,
            }),
        };
        for production in [true, false] {
            for enforce_limits in [true, false] {
                let actual = render(&state(production, enforce_limits), &req, &response);
                println!("saved-case={id} production={production} limits={enforce_limits} expected={expected:?} actual={actual:?}");
                let compact = serde_json::to_vec(&response.body).unwrap();
                assert_eq!(
                    actual,
                    if production {
                        expected
                    } else {
                        compact.as_slice()
                    }
                );
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&actual).unwrap(),
                    response.body
                );
            }
        }
    }

    #[test]
    fn saved_document_success_layout_01_get() {
        check_saved_document_success_layout(
            "saved-01-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-01-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_02_get() {
        check_saved_document_success_layout(
            "saved-02-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-02-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_03_create() {
        check_saved_document_success_layout(
            "saved-03-create",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-03-create",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_04_create() {
        check_saved_document_success_layout(
            "saved-04-create",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-04-create",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_05_get() {
        check_saved_document_success_layout(
            "saved-05-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-05-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_06_get() {
        check_saved_document_success_layout(
            "saved-06-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-06-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_07_get() {
        check_saved_document_success_layout(
            "saved-07-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-07-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_08_get() {
        check_saved_document_success_layout(
            "saved-08-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-08-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_09_get() {
        check_saved_document_success_layout(
            "saved-09-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-09-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_10_create() {
        check_saved_document_success_layout(
            "saved-10-create",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-10-create",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_11_create() {
        check_saved_document_success_layout(
            "saved-11-create",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-11-create",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_12_create() {
        check_saved_document_success_layout(
            "saved-12-create",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-12-create",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_13_get() {
        check_saved_document_success_layout(
            "saved-13-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-13-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_14_get() {
        check_saved_document_success_layout(
            "saved-14-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-14-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_15_get() {
        check_saved_document_success_layout(
            "saved-15-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-15-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_16_get() {
        check_saved_document_success_layout(
            "saved-16-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-16-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_17_get() {
        check_saved_document_success_layout(
            "saved-17-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-17-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_18_create() {
        check_saved_document_success_layout(
            "saved-18-create",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-18-create",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_19_create() {
        check_saved_document_success_layout(
            "saved-19-create",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-19-create",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_20_get() {
        check_saved_document_success_layout(
            "saved-20-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-20-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_21_get() {
        check_saved_document_success_layout(
            "saved-21-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-21-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_22_create() {
        check_saved_document_success_layout(
            "saved-22-create",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-22-create",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_23_get() {
        check_saved_document_success_layout(
            "saved-23-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-23-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_24_create() {
        check_saved_document_success_layout(
            "saved-24-create",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-24-create",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_25_get() {
        check_saved_document_success_layout(
            "saved-25-get",
            false,
            "2000-01-02T03:04:06.654321Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-25-get",
  "fields": {
    "allowed": {
      "booleanValue": false
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:06.654321Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_26_get() {
        check_saved_document_success_layout(
            "saved-26-get",
            true,
            "2000-01-02T03:04:05.123456Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-26-get",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:05.123456Z"
}
"#,
        );
    }

    #[test]
    fn saved_document_success_layout_27_update() {
        check_saved_document_success_layout(
            "saved-27-update",
            false,
            "2000-01-02T03:04:06.654321Z",
            br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/saved-27-update",
  "fields": {
    "allowed": {
      "booleanValue": false
    }
  },
  "createTime": "2000-01-02T03:04:05.123456Z",
  "updateTime": "2000-01-02T03:04:06.654321Z"
}
"#,
        );
    }

    const WIRE_DOCUMENT_TRUE: &[u8] = br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/owned",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2026-08-29T12:01:00Z",
  "updateTime": "2026-08-29T12:01:00Z"
}
"#;
    const WIRE_DOCUMENT_FALSE: &[u8] = br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/owned",
  "fields": {
    "allowed": {
      "booleanValue": false
    }
  },
  "createTime": "2026-08-29T12:01:00Z",
  "updateTime": "2026-08-29T12:01:00.000001Z"
}
"#;

    #[tokio::test]
    async fn document_success_wire_crud_and_commit_readback_preserve_exact_layout() {
        const COLLECTION: &str = "/v1/projects/demo-app/databases/(default)/documents/cases";
        const DOCUMENT: &str = "/v1/projects/demo-app/databases/(default)/documents/cases/owned";
        const COMMIT: &[u8] = br#"{"writes":[{"update":{"name":"projects/demo-app/databases/(default)/documents/cases/owned","fields":{"allowed":{"booleanValue":true}}}}]}"#;
        for production in [true, false] {
            for limits in [true, false] {
                let state = state(production, limits);
                for (method, path, payload, literal) in [
                    (
                        "POST",
                        format!("{COLLECTION}?documentId=owned"),
                        br#"{"fields":{"allowed":{"booleanValue":true}}}"#.as_slice(),
                        WIRE_DOCUMENT_TRUE,
                    ),
                    (
                        "GET",
                        DOCUMENT.to_owned(),
                        b"".as_slice(),
                        WIRE_DOCUMENT_TRUE,
                    ),
                    (
                        "PATCH",
                        DOCUMENT.to_owned(),
                        br#"{"fields":{"allowed":{"booleanValue":false}}}"#.as_slice(),
                        WIRE_DOCUMENT_FALSE,
                    ),
                ] {
                    let (headers, actual) =
                        wire_request(Arc::clone(&state), method, &path, payload).await;
                    assert_json_headers(&headers, &actual, production, 200);
                    let compact = serde_json::to_vec(
                        &serde_json::from_slice::<serde_json::Value>(literal).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(
                        actual,
                        if production {
                            literal
                        } else {
                            compact.as_slice()
                        }
                    );
                    assert_eq!(actual.ends_with(b"\n"), production);
                    assert!(!actual.ends_with(b"\n\n"));
                    assert!(headers.contains("access-control-allow-origin: *\r\n"));
                }
                let (headers, body) = wire_request(
                    Arc::clone(&state),
                    "POST",
                    "/v1/projects/demo-app/databases/(default)/documents:commit",
                    COMMIT,
                )
                .await;
                assert_json_headers(&headers, &body, production, 200);
                assert_eq!(body, br#"{"commitTime":"2026-08-29T12:01:00.000002Z","writeResults":[{"updateTime":"2026-08-29T12:01:00.000002Z"}]}"#);
                let (headers, actual) = wire(Arc::clone(&state), "GET", DOCUMENT).await;
                assert_json_headers(&headers, &actual, production, 200);
                let compact = br#"{"createTime":"2026-08-29T12:01:00Z","fields":{"allowed":{"booleanValue":true}},"name":"projects/demo-app/databases/(default)/documents/cases/owned","updateTime":"2026-08-29T12:01:00.000002Z"}"#;
                assert_eq!(
                    actual,
                    if production {
                        br#"{
  "name": "projects/demo-app/databases/(default)/documents/cases/owned",
  "fields": {
    "allowed": {
      "booleanValue": true
    }
  },
  "createTime": "2026-08-29T12:01:00Z",
  "updateTime": "2026-08-29T12:01:00.000002Z"
}
"#
                    } else {
                        compact.as_slice()
                    }
                );
            }
        }
    }

    #[tokio::test]
    async fn document_success_wire_masks_auto_ids_encoded_paths_and_query_create_are_selected() {
        const COLLECTION: &str = "/v1/projects/demo-app/databases/(default)/documents/cases";
        for production in [true, false] {
            for limits in [true, false] {
                let state = state(production, limits);
                for query in [
                    "",
                    "?documentId=",
                    "?documentId=colon%3Ainside&mask.fieldPaths=missing",
                ] {
                    let (headers, bytes) = wire_request(
                        Arc::clone(&state),
                        "POST",
                        &format!("{COLLECTION}{query}"),
                        br#"{"fields":{"allowed":{"booleanValue":true}}}"#,
                    )
                    .await;
                    assert_json_headers(&headers, &bytes, production, 200);
                    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    assert!(value["name"]
                        .as_str()
                        .unwrap()
                        .starts_with("projects/demo-app/databases/(default)/documents/cases/"));
                    if query.contains("mask") {
                        assert!(value.get("fields").is_none());
                    }
                    let expected = if production {
                        reference_document_body(&value)
                    } else {
                        serde_json::to_vec(&value).unwrap()
                    };
                    assert_eq!(bytes, expected);
                    let id = value["name"].as_str().unwrap().rsplit('/').next().unwrap();
                    let path = format!(
                        "{COLLECTION}/{}?mask.fieldPaths=missing",
                        encoded_segment(id)
                    );
                    let (headers, bytes) = wire(Arc::clone(&state), "GET", &path).await;
                    assert_json_headers(&headers, &bytes, production, 200);
                    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    assert!(value.get("fields").is_none());
                    assert_eq!(
                        bytes,
                        if production {
                            reference_document_body(&value)
                        } else {
                            serde_json::to_vec(&value).unwrap()
                        }
                    );
                }
                for action in ["runQuery", "runAggregationQuery", "partitionQuery"] {
                    let path = format!("{COLLECTION}:{action}?documentId=owned");
                    let (headers, bytes) =
                        wire_request(Arc::clone(&state), "POST", &path, b"{}").await;
                    if production {
                        assert_json_headers(&headers, &bytes, true, 200);
                        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                        assert_eq!(value["name"], format!("projects/demo-app/databases/(default)/documents/cases:{action}/owned"));
                        assert!(value.get("fields").is_none());
                        assert_eq!(bytes, reference_document_body(&value));
                    } else {
                        assert!(!headers.starts_with("HTTP/1.1 200 "));
                        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                        assert_eq!(bytes, serde_json::to_vec(&value).unwrap());
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn document_success_wire_non_document_successes_stay_compact() {
        const COLLECTION: &str = "/v1/projects/demo-app/databases/(default)/documents/cases";
        const ROOT: &str = "/v1/projects/demo-app/databases/(default)/documents";
        for production in [false, true] {
            for limits in [false, true] {
                let expected_state = state(production, limits);
                let state = state(production, limits);
                let payload = br#"{"fields":{"allowed":{"booleanValue":true}}}"#;
                let mut seed = request("POST", COLLECTION);
                seed.query = "documentId=owned".to_owned();
                seed.body = serde_json::from_slice(payload).unwrap();
                let seeded = expected_state.handle(&seed);
                assert_eq!(seeded.status, 200);
                let (_, created) = wire_request(
                    Arc::clone(&state),
                    "POST",
                    &format!("{COLLECTION}?documentId=owned"),
                    payload,
                )
                .await;
                let document: serde_json::Value = serde_json::from_slice(&created).unwrap();
                assert_eq!(document, seeded.body);
                for (method, path, payload) in [
                ("GET", COLLECTION.to_owned(), b"".as_slice()),
                ("POST", format!("{ROOT}:runQuery"), br#"{"structuredQuery":{"from":[{"collectionId":"cases"}]}}"#.as_slice()),
                ("POST", format!("{ROOT}:batchGet"), br#"{"documents":["projects/demo-app/databases/(default)/documents/cases/owned"]}"#.as_slice()),
                ("POST", format!("{ROOT}:batchWrite"), br#"{"writes":[]}"#.as_slice()),
                ("POST", format!("{ROOT}:commit"), br#"{"writes":[]}"#.as_slice()),
            ] {
                let mut req = request(method, &path); req.body = serde_json::from_slice(payload).unwrap_or(serde_json::json!({}));
                let response = expected_state.handle(&req);
                let expected = serde_json::to_vec(&response.body).unwrap();
                assert_eq!(response.status, 200, "{response:?}");
                let (headers, actual) = wire_request(Arc::clone(&state), method, &path, payload).await;
                assert_json_headers(&headers, &actual, production, 200);
                assert_eq!(actual, expected, "{path}");
                assert!(!actual.ends_with(b"\n"));
                if path.ends_with(":commit") {
                    assert_eq!(actual, if production && !limits {
                        br#"{"commitTime":"2026-08-29T12:01:00.000001Z"}"#.as_slice()
                    } else { b"{}".as_slice() });
                }
                let value: serde_json::Value = serde_json::from_slice(&actual).unwrap();
                if method == "GET" { assert_eq!(value["documents"][0], document); }
                if path.ends_with(":runQuery") { assert_eq!(value[0]["document"], document); }
                if path.ends_with(":batchGet") { assert_eq!(value[0]["found"], document); }
            }
            }
        }
    }

    #[tokio::test]
    async fn rest_json_charset_follows_policy_through_document_lifecycle() {
        const COLLECTION: &str = "/v1/projects/demo-app/databases/(default)/documents/cases";
        const DOCUMENT: &str = "/v1/projects/demo-app/databases/(default)/documents/cases/owned";
        for production in [true, false] {
            for enforce_limits in [false, true] {
                let state = state(production, enforce_limits);
                for (method, path, payload, expected_status) in [
                    ("GET", DOCUMENT.to_owned(), b"".as_slice(), 404),
                    (
                        "POST",
                        format!("{COLLECTION}?documentId=owned"),
                        br#"{"fields":{"allowed":{"booleanValue":true}}}"#.as_slice(),
                        200,
                    ),
                    ("GET", DOCUMENT.to_owned(), b"".as_slice(), 200),
                    (
                        "PATCH",
                        DOCUMENT.to_owned(),
                        br#"{"fields":{"allowed":{"booleanValue":false}}}"#.as_slice(),
                        200,
                    ),
                    ("DELETE", DOCUMENT.to_owned(), b"".as_slice(), 200),
                    ("GET", DOCUMENT.to_owned(), b"".as_slice(), 404),
                ] {
                    let (headers, bytes) =
                        wire_request(Arc::clone(&state), method, &path, payload).await;
                    assert_json_headers(&headers, &bytes, production, expected_status);
                    let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                    match method {
                        "POST" => assert_eq!(response["fields"]["allowed"]["booleanValue"], true),
                        "PATCH" => assert_eq!(response["fields"]["allowed"]["booleanValue"], false),
                        "DELETE" => assert_eq!(bytes, b"{}"),
                        _ => {}
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn rest_json_charset_follows_policy_on_early_parse_rejection() {
        let path = "/v1/projects/demo-app/databases/(default)/documents:commit";
        let expected = super::request_body(b"not json", path, true).unwrap_err();
        let expected_bytes = serde_json::to_vec(&expected.body).unwrap();
        for production in [true, false] {
            for enforce_limits in [false, true] {
                let (headers, bytes) =
                    wire_request(state(production, enforce_limits), "POST", path, b"not json")
                        .await;
                assert_json_headers(&headers, &bytes, production, 400);
                assert_eq!(bytes, expected_bytes);
            }
        }
    }

    #[tokio::test]
    async fn rest_json_charset_follows_policy_on_body_read_rejection() {
        let expected = serde_json::to_vec(&body_read_deadline_exceeded().body).unwrap();
        for production in [true, false] {
            for enforce_limits in [false, true] {
                // An incomplete declared body reaches the real Incoming-body refusal.
                // Only this test service gets a short deadline; production keeps its bound.
                let (headers, bytes) = wire_exchange(
                    state(production, enforce_limits),
                    "POST",
                    PATH,
                    b"",
                    1,
                    std::time::Duration::from_millis(20),
                )
                .await;
                assert_json_headers(&headers, &bytes, production, 408);
                assert_eq!(bytes, expected);
            }
        }
    }

    #[tokio::test]
    async fn rest_json_charset_follows_policy_on_admission_refusals() {
        let expected = serde_json::to_vec(&too_many_concurrent_requests().body).unwrap();
        for (limiter, units) in [
            (rest_work_limiter(), MAX_BLOCKING_REST_REQUESTS),
            (rest_payload_limiter(), REST_PAYLOAD_UNITS),
        ] {
            let held = Arc::clone(limiter)
                .try_acquire_many_owned(u32::try_from(units).unwrap())
                .unwrap();
            for production in [true, false] {
                for enforce_limits in [false, true] {
                    let (headers, bytes) =
                        wire(state(production, enforce_limits), "GET", PATH).await;
                    assert_json_headers(&headers, &bytes, production, 503);
                    assert_eq!(bytes, expected);
                }
            }
            drop(held);
            assert_eq!(limiter.available_permits(), units);
        }
    }

    fn check_transport_projection(
        production: bool,
        enforce_limits: bool,
        status: u16,
        layout: bool,
        kind: u8,
        text: &str,
        origin: Option<&str>,
    ) {
        let body = match kind {
            1 => serde_json::json!({crate::rest::coverage::HTML_KEY:text}),
            2 => serde_json::json!({crate::rest::TEXT_KEY:text}),
            _ => serde_json::json!({"value":text,"number":17,"nested":[true,null]}),
        };
        let response = RestResponse { status, body };
        let reference = json_response(&response, origin);
        let profile = state(production, enforce_limits);
        let actual = json_response_with_layout(
            &response,
            origin,
            layout,
            profile.gateway.production_refusals(),
        );
        assert_eq!(actual.status(), reference.status());
        let expected_type = match kind {
            1 => "text/html; charset=utf-8",
            2 => "text/plain; charset=utf-8",
            _ if production => "application/json; charset=UTF-8",
            _ => "application/json; charset=utf-8",
        };
        assert_eq!(actual.headers()["content-type"], expected_type);
        if kind == 0 {
            assert_eq!(
                reference.headers()["content-type"],
                "application/json; charset=utf-8"
            );
        }
        let mut actual_headers = actual.headers().clone();
        let mut reference_headers = reference.headers().clone();
        actual_headers.remove("content-type");
        reference_headers.remove("content-type");
        assert_eq!(actual_headers, reference_headers);
        let expected_bytes = match kind {
            1 | 2 => text.as_bytes().to_vec(),
            _ if layout => {
                let mut bytes = serde_json::to_vec_pretty(&response.body).unwrap();
                bytes.push(b'\n');
                bytes
            }
            _ => serde_json::to_vec(&response.body).unwrap(),
        };
        let bytes = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async { actual.into_body().collect().await.unwrap().to_bytes() });
        assert_eq!(bytes.as_ref(), expected_bytes);
    }

    #[test]
    fn rest_json_transport_matches_finite_profile_model() {
        let mut cases = 0;
        for production in [false, true] {
            for enforce_limits in [false, true] {
                for status in [200, 400, 404, 429] {
                    for layout in [false, true] {
                        for kind in 0..3 {
                            for origin in [None, Some("http://localhost:4321")] {
                                check_transport_projection(
                                    production,
                                    enforce_limits,
                                    status,
                                    layout,
                                    kind,
                                    "雪\"\\😀",
                                    origin,
                                );
                                cases += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(cases, 192);
        println!("finite transport model cases={cases}");
    }

    #[tokio::test]
    async fn shared_default_and_readiness_keep_existing_json_styling() {
        let ready = readiness(Some("http://localhost:4321"));
        assert_eq!(ready.status(), 200);
        assert_eq!(
            ready.headers()["content-type"],
            "application/json; charset=utf-8"
        );
        assert_eq!(ready.headers()["cache-control"], "no-store");
        assert_eq!(
            ready.into_body().collect().await.unwrap().to_bytes(),
            br#"{"emulator":"firestore"}"#.as_slice()
        );
        for response in [
            too_many_concurrent_requests(),
            body_rejection_response(BodyRejection::Deadline),
        ] {
            let body = serde_json::to_vec(&response.body).unwrap();
            let shared = json_response(&response, None);
            assert_eq!(
                shared.headers()["content-type"],
                "application/json; charset=utf-8"
            );
            assert_eq!(shared.status().as_u16(), response.status);
            assert_eq!(shared.into_body().collect().await.unwrap().to_bytes(), body);
        }
    }

    #[tokio::test]
    async fn production_document_404_has_literal_wire_layout_and_policy_controls() {
        for enforce_limits in [false, true] {
            for production in [true, false] {
                let (headers, bytes) = wire(state(production, enforce_limits), "GET", PATH).await;
                assert!(headers.starts_with("HTTP/1.1 404 Not Found\r\n"));
                assert_json_headers(&headers, &bytes, production, 404);
                let expected = if production { PRETTY } else { COMPACT };
                assert_eq!(
                    bytes, expected,
                    "production={production}, enforce_limits={enforce_limits}"
                );
                assert!(headers.contains(&format!("content-length: {}\r\n", expected.len())));
            }
        }
        for id in ["colon:inside", "documents", "quote\"slash\\", "雪😀"] {
            let name = format!("projects/demo-app/databases/(default)/documents/cases/{id}");
            let path = format!(
                "/v1/projects/demo-app/databases/(default)/documents/cases/{}",
                encoded_segment(id)
            );
            let (headers, bytes) = wire(state(true, true), "GET", &path).await;
            assert!(headers.starts_with("HTTP/1.1 404 Not Found\r\n"));
            assert_eq!(bytes, expected_layout(&name));
        }
        let (_, bytes) = wire(
            state(true, true),
            "GET",
            &format!("{PATH}?mask.fieldPaths=value"),
        )
        .await;
        assert_eq!(bytes, PRETTY);
        root_and_uri_wire_controls().await;
        other_routes_keep_literal_compact_or_plain_wire_bodies().await;
    }

    async fn root_and_uri_wire_controls() {
        for (path, name) in [
            (
                "/v1/projects/demo-app/databases/(default)/documents",
                "projects/demo-app/databases/(default)/documents",
            ),
            (
                "/v1/projects/documents/databases/(default)/documents",
                "projects/documents/databases/(default)/documents",
            ),
            (
                "/v1/projects/demo-app/databases/documents/documents",
                "projects/demo-app/databases/documents/documents",
            ),
            (
                "/v1/projects/documents/databases/documents/documents/",
                "projects/documents/databases/documents/documents",
            ),
            (
                "/v1/projects/%64ocuments/databases/documents/%64ocuments",
                "projects/documents/databases/documents/documents",
            ),
        ] {
            for production in [false, true] {
                let (headers, bytes) = wire(state(production, true), "GET", path).await;
                assert!(headers.starts_with("HTTP/1.1 400 Bad Request\r\n"));
                let message =
                    json_string(&format!("invalid parent: {name} is not a document name"));
                let expected = format!("{{\"error\":{{\"code\":400,\"message\":{message},\"status\":\"INVALID_ARGUMENT\"}}}}").into_bytes();
                assert_eq!(bytes, expected);
            }
        }
        for suffix in ["missing:runQuery", "missing:unknown"] {
            let (_, bytes) = wire(
                state(true, true),
                "GET",
                &format!("/v1/projects/demo-app/databases/(default)/documents/cases/{suffix}"),
            )
            .await;
            assert_eq!(bytes, b"Not Found\n");
        }
        for (id, message) in [
            ("missing%2Finside", "encoded '/' in a path segment"),
            ("missing%2finside", "encoded '/' in a path segment"),
            ("%GG", "malformed percent escape in path"),
            ("%FF", "path segment is not UTF-8"),
        ] {
            let (headers, bytes) = wire(
                state(true, true),
                "GET",
                &format!("/v1/projects/demo-app/databases/(default)/documents/cases/{id}"),
            )
            .await;
            assert!(headers.starts_with("HTTP/1.1 400 Bad Request\r\n"));
            let expected = format!(
                "{{\"error\":{{\"code\":400,\"message\":{},\"status\":\"INVALID_ARGUMENT\"}}}}",
                json_string(message)
            )
            .into_bytes();
            assert_eq!(bytes, expected);
        }
    }

    async fn other_routes_keep_literal_compact_or_plain_wire_bodies() {
        for production in [true, false] {
            let (_, bytes) = wire(
                state(production, true),
                "PATCH",
                &format!("{PATH}?currentDocument.exists=true"),
            )
            .await;
            assert_eq!(bytes, COMPACT);
            let (headers, bytes) = wire(state(production, true), "GET", "/unknown").await;
            assert!(headers.contains("content-type: text/plain; charset=utf-8\r\n"));
            assert_eq!(bytes, b"Not Found\n");
            let (_, bytes) = wire(
                state(production, true),
                "GET",
                "/v1/projects/demo-app/databases/(default)/documents/cases",
            )
            .await;
            assert_eq!(bytes, b"{}");
        }
    }

    fn request(method: &str, path: &str) -> RestRequest {
        RestRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            query: String::new(),
            authorization: None,
            origin: None,
            browser_metadata: false,
            app_check: Vec::new(),
            body: serde_json::json!({}),
            batch_field_order: Vec::new(),
        }
    }

    fn missing(name: &str) -> RestResponse {
        crate::rest::error_response(&tonic::Status::not_found(format!(
            "Document \"{name}\" not found."
        )))
    }

    fn render(state: &RestState, req: &RestRequest, response: &RestResponse) -> Vec<u8> {
        let selected = crate::rest::production_document_not_found(state, req, response);
        let success = crate::rest::production_document_success(state, req, response);
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                json_response_with_document_layout(
                    response,
                    None,
                    selected,
                    state.gateway.production_refusals(),
                    success,
                )
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec()
            })
    }

    #[test]
    fn only_the_observed_document_envelope_selects_the_layout() {
        let state = state(true, false);
        let req = request("GET", PATH);
        let canonical = missing(PATH.strip_prefix("/v1/").unwrap());
        assert_eq!(render(&state, &req, &canonical), PRETTY);
        for path in [
            "/unknown",
            "/emulator/v1/projects/demo-app/databases/(default)/documents/cases/missing",
            "/v1/projects/demo-app/databases/(default)",
            "/v1/projects/demo-app/databases/(default)/operations/missing",
            "/v1/projects/demo-app/databases/(default)/collectionGroups/cases/fields/missing",
            "/v1/projects/demo-app/databases/(default)/documents",
            "/v1/projects/documents/databases/(default)/documents",
            "/v1/projects/demo-app/databases/documents/documents",
            "/v1/projects/documents/databases/documents/documents",
            "/v1/projects/documents/databases/documents/documents/",
            "/v1/projects/%64ocuments/databases/documents/documents",
            "/v1/projects/documents/databases/%64ocuments/documents",
            "/v1/projects/demo-app/databases/(default)/documents/cases",
            "/v1/projects/demo-app/databases/(default)/documents/cases/missing:runQuery",
            "/v1/projects/demo-app/databases/(default)/documents/cases/missing:unknown",
            "/v1/projects/demo-app/databases/(default)/documents/cases/missing%2Finside",
            "/v1/projects/demo-app/databases/(default)/documents/cases/%FF",
            "/v1/projects/demo-app/databases/(default)/documents/cases/%GG",
            "/v1/projects/demo-app/databases/(default)/documents//missing",
        ] {
            // Even a matching message cannot turn a non-document route into a document GET.
            let body = missing(
                path.strip_prefix("/v1/")
                    .unwrap_or(path)
                    .trim_end_matches('/')
                    .replace("%64", "d")
                    .split('?')
                    .next()
                    .unwrap(),
            );
            let bytes = render(&state, &request("GET", path), &body);
            assert_eq!(
                bytes,
                expected_compact(body.body["error"]["message"].as_str().unwrap()),
                "{path}"
            );
        }
        for query in [
            "prettyPrint=true",
            "x=documents:runQuery",
            "mask.fieldPaths=value",
        ] {
            let mut with_query = req.clone();
            with_query.query = query.to_owned();
            assert_eq!(render(&state, &with_query, &canonical), PRETTY);
            with_query.path = "/v1/projects/documents/databases/documents/documents/".to_owned();
            let root = missing("projects/documents/databases/documents/documents");
            assert_eq!(
                render(&state, &with_query, &root),
                expected_compact(
                    "Document \"projects/documents/databases/documents/documents\" not found."
                )
            );
        }
        for method in ["POST", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
            assert_eq!(
                render(&state, &request(method, PATH), &canonical),
                COMPACT,
                "{method}"
            );
        }
    }

    #[test]
    fn unrelated_envelopes_stay_compact() {
        let state = state(true, false);
        let req = request("GET", PATH);
        let canonical = missing(PATH.strip_prefix("/v1/").unwrap());
        let mut alternatives = Vec::new();
        for status in [200, 400, 403, 409, 500] {
            let mut body = canonical.clone();
            body.status = status;
            alternatives.push(body);
        }
        for (key, value) in [
            ("code", serde_json::json!("404")),
            ("code", serde_json::json!(404.0)),
            ("code", serde_json::json!(403)),
            ("status", serde_json::json!("PERMISSION_DENIED")),
            ("message", serde_json::json!("Document not found")),
            ("message", serde_json::json!(null)),
            ("message", serde_json::json!("Document \"projects/other/databases/(default)/documents/cases/missing\" not found.")),
            ("details", serde_json::json!([])),
            ("ftdDropConnection", serde_json::json!(true)),
        ] {
            let mut body = canonical.clone(); body.body["error"][key] = value; alternatives.push(body);
        }
        let mut extra = canonical.clone();
        extra.body["extra"] = serde_json::json!(true);
        alternatives.push(extra);
        for body in [
            serde_json::json!([canonical.body]),
            serde_json::json!({"error":[]}),
            serde_json::json!({}),
            serde_json::json!({"name":"ok"}),
        ] {
            alternatives.push(RestResponse { status: 404, body });
        }
        for body in alternatives {
            assert_eq!(
                render(&state, &req, &body),
                serde_json::to_vec(&body.body).unwrap(),
                "{body:?}"
            );
        }
        let html = RestResponse {
            status: 404,
            body: serde_json::json!({crate::rest::coverage::HTML_KEY:"<p>missing</p>"}),
        };
        assert_eq!(render(&state, &req, &html), b"<p>missing</p>");
        let text = crate::rest::not_found_text();
        assert_eq!(render(&state, &req, &text), b"Not Found\n");
    }

    fn success(name: &str) -> RestResponse {
        RestResponse {
            status: 200,
            body: serde_json::json!({
                "name": name, "fields": {"allowed": {"booleanValue": true}},
                "createTime": "2000-01-02T03:04:05.123456Z", "updateTime": "2000-01-02T03:04:05.123456Z",
            }),
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Keep the independent route matrix beside its oracle.
    fn document_success_selector_matches_finite_route_and_envelope_model() {
        const NAME: &str = "projects/demo-app/databases/(default)/documents/cases/owned";
        const COLLECTION: &str = "/v1/projects/demo-app/databases/(default)/documents/cases";
        let mut routes = vec![
            ("GET", format!("/v1/{NAME}"), "", NAME.to_owned(), true),
            (
                "PATCH",
                format!("/v1/{NAME}"),
                "mask.fieldPaths=missing",
                NAME.to_owned(),
                true,
            ),
            (
                "POST",
                COLLECTION.to_owned(),
                "documentId=owned",
                NAME.to_owned(),
                true,
            ),
            ("POST", COLLECTION.to_owned(), "", NAME.to_owned(), true),
            (
                "POST",
                COLLECTION.to_owned(),
                "documentId=",
                NAME.to_owned(),
                true,
            ),
            (
                "POST",
                COLLECTION.to_owned(),
                "documentId=owned&documentId=other",
                NAME.to_owned(),
                true,
            ),
            (
                "POST",
                COLLECTION.to_owned(),
                "document%49d=%6fwned",
                NAME.to_owned(),
                true,
            ),
            (
                "POST",
                COLLECTION.to_owned(),
                "documentId=other",
                NAME.to_owned(),
                false,
            ),
            (
                "POST",
                COLLECTION.to_owned(),
                "",
                format!("{NAME}/sub/doc"),
                false,
            ),
            (
                "POST",
                COLLECTION.to_owned(),
                "",
                "projects/other/databases/(default)/documents/cases/owned".to_owned(),
                false,
            ),
            (
                "POST",
                COLLECTION.to_owned(),
                "",
                "projects/demo-app/databases/(default)/documents/cases/".to_owned(),
                false,
            ),
            ("GET", COLLECTION.to_owned(), "", NAME.to_owned(), false),
            ("PATCH", COLLECTION.to_owned(), "", NAME.to_owned(), false),
            ("POST", format!("/v1/{NAME}"), "", NAME.to_owned(), false),
            ("DELETE", format!("/v1/{NAME}"), "", NAME.to_owned(), false),
            ("HEAD", format!("/v1/{NAME}"), "", NAME.to_owned(), false),
            (
                "GET",
                "/v1/projects/demo-app/databases/(default)/documents".to_owned(),
                "",
                "projects/demo-app/databases/(default)/documents".to_owned(),
                false,
            ),
            (
                "GET",
                format!("/v1/{NAME}:runQuery"),
                "",
                NAME.to_owned(),
                false,
            ),
            (
                "GET",
                format!("/v1/{NAME}:unknown"),
                "",
                NAME.to_owned(),
                false,
            ),
            (
                "GET",
                format!("/v1/{NAME}%2Finside"),
                "",
                format!("{NAME}/inside"),
                false,
            ),
            ("GET", format!("/v1/{NAME}%FF"), "", NAME.to_owned(), false),
            (
                "GET",
                format!("/emulator/v1/{NAME}"),
                "",
                NAME.to_owned(),
                false,
            ),
            ("GET", "/unknown".to_owned(), "", NAME.to_owned(), false),
        ];
        for action in ["runQuery", "runAggregationQuery", "partitionQuery"] {
            routes.push((
                "POST",
                format!("{COLLECTION}:{action}"),
                "documentId=owned",
                format!("projects/demo-app/databases/(default)/documents/cases:{action}/owned"),
                true,
            ));
        }
        for id in ["colon:inside", "quote\"slash\\", "雪😀", "+% ?#"] {
            routes.push((
                "GET",
                format!("{COLLECTION}/{}", encoded_segment(id)),
                "",
                format!("projects/demo-app/databases/(default)/documents/cases/{id}"),
                true,
            ));
        }
        let mut count = 0;
        for production in [false, true] {
            for limits in [false, true] {
                let state = state(production, limits);
                for (method, path, query, name, route_matches) in &routes {
                    for status in [200, 201, 400, 404, 500] {
                        for shape in 0..12 {
                            let mut req = request(method, path);
                            req.query = (*query).to_owned();
                            let mut response = success(name);
                            response.status = status;
                            let shape_matches = match shape {
                                0 => true,
                                1 => {
                                    response.body.as_object_mut().unwrap().remove("fields");
                                    true
                                }
                                2 => {
                                    response.body.as_object_mut().unwrap().remove("createTime");
                                    true
                                }
                                3 => {
                                    response.body = serde_json::json!({"name": name});
                                    true
                                }
                                4 => {
                                    response.body["extra"] = serde_json::json!(true);
                                    false
                                }
                                5 => {
                                    response.body["fields"] = serde_json::json!([]);
                                    false
                                }
                                6 => {
                                    response.body["createTime"] = serde_json::json!(null);
                                    false
                                }
                                7 => {
                                    response.body["updateTime"] = serde_json::json!(17);
                                    false
                                }
                                8 => {
                                    response.body["name"] = serde_json::json!(false);
                                    false
                                }
                                9 => {
                                    response.body["name"] = serde_json::json!("projects/demo-app/databases/(default)/documents/other/name");
                                    false
                                }
                                10 => {
                                    response.body = serde_json::json!([response.body]);
                                    false
                                }
                                _ => {
                                    response.body.as_object_mut().unwrap().remove("name");
                                    false
                                }
                            };
                            let selected =
                                production && status == 200 && *route_matches && shape_matches;
                            assert_eq!(
                                crate::rest::production_document_success(&state, &req, &response),
                                selected,
                                "{req:?} {response:?}"
                            );
                            let actual = render(&state, &req, &response);
                            if selected {
                                assert_eq!(actual, reference_document_body(&response.body));
                            } else {
                                assert_eq!(actual, serde_json::to_vec(&response.body).unwrap());
                            }
                            count += 1;
                        }
                    }
                }
            }
        }
        println!("document success finite selector cases={count}");
    }

    // A separate recursive oracle tests framing without calling the production framer.
    fn reference_json(value: &serde_json::Value, depth: usize) -> String {
        match value {
            serde_json::Value::Null => "null".to_owned(),
            serde_json::Value::Bool(value) => value.to_string(),
            serde_json::Value::Number(value) => value.to_string(),
            serde_json::Value::String(value) => json_string(value),
            serde_json::Value::Array(values) if values.is_empty() => "[]".to_owned(),
            serde_json::Value::Array(values) => {
                let lines: Vec<_> = values
                    .iter()
                    .map(|value| {
                        format!(
                            "{}{}",
                            "  ".repeat(depth + 1),
                            reference_json(value, depth + 1)
                        )
                    })
                    .collect();
                format!("[\n{}\n{}]", lines.join(",\n"), "  ".repeat(depth))
            }
            serde_json::Value::Object(values) if values.is_empty() => "{}".to_owned(),
            serde_json::Value::Object(values) => {
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort();
                let lines: Vec<_> = keys
                    .into_iter()
                    .map(|key| {
                        format!(
                            "{}{}: {}",
                            "  ".repeat(depth + 1),
                            json_string(key),
                            reference_json(&values[key], depth + 1)
                        )
                    })
                    .collect();
                format!("{{\n{}\n{}}}", lines.join(",\n"), "  ".repeat(depth))
            }
        }
    }

    fn reference_document_body(value: &serde_json::Value) -> Vec<u8> {
        let members: Vec<_> = ["name", "fields", "createTime", "updateTime"]
            .into_iter()
            .filter_map(|key| {
                value
                    .get(key)
                    .map(|value| format!("  {}: {}", json_string(key), reference_json(value, 1)))
            })
            .collect();
        format!("{{\n{}\n}}\n", members.join(",\n")).into_bytes()
    }

    fn arbitrary_nested_json() -> impl proptest::strategy::Strategy<Value = serde_json::Value> {
        use proptest::prelude::*;
        prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::Bool),
            any::<i64>().prop_map(|n| serde_json::json!(n)),
            proptest::collection::vec(any::<char>(), 0..24)
                .prop_map(|chars| serde_json::Value::String(chars.into_iter().collect())),
        ]
        .prop_recursive(3, 32, 5, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..5).prop_map(serde_json::Value::Array),
                proptest::collection::btree_map(".{0,12}", inner, 0..5)
                    .prop_map(|entries| serde_json::Value::Object(entries.into_iter().collect())),
            ]
        })
    }

    // Independent JSON string oracle: it does not use the production serializer.
    fn json_string(text: &str) -> String {
        let mut escaped = String::from("\"");
        for character in text.chars() {
            match character {
                '"' => escaped.push_str("\\\""),
                '\\' => escaped.push_str("\\\\"),
                '\n' => escaped.push_str("\\n"),
                '\r' => escaped.push_str("\\r"),
                '\t' => escaped.push_str("\\t"),
                '\u{08}' => escaped.push_str("\\b"),
                '\u{0c}' => escaped.push_str("\\f"),
                c if c <= '\u{1f}' => write!(escaped, "\\u{:04x}", u32::from(c)).unwrap(),
                c => escaped.push(c),
            }
        }
        escaped.push('"');
        escaped
    }

    fn encoded_segment(segment: &str) -> String {
        let mut encoded = String::with_capacity(segment.len() * 3);
        for byte in segment.as_bytes() {
            write!(encoded, "%{byte:02X}").unwrap();
        }
        encoded
    }

    fn expected_compact(message: &str) -> Vec<u8> {
        format!(
            "{{\"error\":{{\"code\":404,\"message\":{},\"status\":\"NOT_FOUND\"}}}}",
            json_string(message)
        )
        .into_bytes()
    }

    fn expected_layout(name: &str) -> Vec<u8> {
        let message = json_string(&format!("Document \"{name}\" not found."));
        format!("{{\n  \"error\": {{\n    \"code\": 404,\n    \"message\": {message},\n    \"status\": \"NOT_FOUND\"\n  }}\n}}\n").into_bytes()
    }

    #[test]
    fn invalid_http_status_keeps_the_existing_empty_response_fallback() {
        for production in [false, true] {
            for status in [0, 99, 1000, u16::MAX] {
                let mut response = missing(PATH.strip_prefix("/v1/").unwrap());
                response.status = status;
                assert_eq!(
                    render(&state(production, true), &request("GET", PATH), &response),
                    b""
                );
            }
        }
    }

    #[test]
    fn escaped_document_ids_keep_the_observed_layout() {
        let state = state(true, true);
        for id in [
            "colon:inside",
            "documents",
            "quote\"slash\\",
            "雪😀",
            "line\n\t\u{00}\u{08}\u{0c}\r",
            "+% ?#",
        ] {
            let name = format!("projects/demo-app/databases/(default)/documents/cases/{id}");
            let path = format!(
                "/v1/projects/demo-app/databases/(default)/documents/cases/{}",
                encoded_segment(id)
            );
            assert_eq!(
                render(&state, &request("GET", &path), &missing(&name)),
                expected_layout(&name)
            );
        }
    }

    use proptest::prelude::*;
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]
        #[test]
        fn generated_success_framing_preserves_nested_order_arrays_and_escaping(
            id in proptest::collection::vec(any::<char>().prop_filter("document segment", |c| *c != '/'), 1..25),
            text in proptest::collection::vec(any::<char>(), 0..32),
            value in arbitrary_nested_json(), omission in 0u8..8,
        ) {
            let id: String = id.into_iter().collect(); let text: String = text.into_iter().collect();
            let name = format!("projects/demo-app/databases/(default)/documents/cases/{id}");
            let req = request("GET", &format!("/v1/projects/demo-app/databases/(default)/documents/cases/{}", encoded_segment(&id)));
            let mut response = success(&name);
            response.body["fields"] = serde_json::json!({
                "a": {"arrayValue": {"values": [{"integerValue": "7"}, {"integerValue": "2"}, {"stringValue": text}]}},
                "z": {"mapValue": {"fields": {"z": {"stringValue": "last"}, "a": {"stringValue": "first"}}}},
                "synthetic": value,
            });
            for (index, member) in ["fields", "createTime", "updateTime"].into_iter().enumerate() {
                if omission & (1 << index) != 0 { response.body.as_object_mut().unwrap().remove(member); }
            }
            let state = state(true, false);
            prop_assert!(crate::rest::production_document_success(&state, &req, &response));
            let actual = render(&state, &req, &response);
            prop_assert_eq!(&actual, &reference_document_body(&response.body));
            prop_assert_eq!(serde_json::from_slice::<serde_json::Value>(&actual).unwrap(), response.body);
            prop_assert!(actual.ends_with(b"}\n"), "expected one final LF");
            prop_assert!(!actual.ends_with(b"\n\n"));
        }

        #[test]
        fn generated_document_success_matches_independent_reference(
            id in "[a-zA-Z0-9]{1,24}", key in proptest::collection::vec(any::<char>(), 0..24),
            value in arbitrary_nested_json(), method_index in 0u8..3, omission in 0u8..8,
            production in any::<bool>(), enforce_limits in any::<bool>(), variant in 0u8..10,
        ) {
            let name = format!("projects/demo-app/databases/(default)/documents/cases/{id}");
            let method = ["GET", "PATCH", "POST"][usize::from(method_index)];
            let path = if method == "POST" { "/v1/projects/demo-app/databases/(default)/documents/cases".to_owned() } else { format!("/v1/{name}") };
            let mut req = request(method, &path);
            if method == "POST" { req.query = format!("documentId={id}"); }
            let mut response = success(&name);
            let key: String = key.into_iter().collect();
            response.body["fields"] = serde_json::Value::Object([(key, value)].into_iter().collect());
            for (index, member) in ["fields", "createTime", "updateTime"].into_iter().enumerate() {
                if omission & (1 << index) != 0 { response.body.as_object_mut().unwrap().remove(member); }
            }
            match variant {
                0 => {},
                1 => response.status = 201,
                2 => req.method = "DELETE".to_owned(),
                3 => req.path.push_str(":unknown"),
                4 => response.body["name"] = serde_json::json!(format!("{name}-other")),
                5 => response.body["extra"] = serde_json::json!(true),
                6 => response.body["fields"] = serde_json::json!([]),
                7 => response.body["createTime"] = serde_json::json!(null),
                8 => response.body = serde_json::json!({"document": response.body}),
                _ => req.path = "/unknown".to_owned(),
            }
            let state = state(production, enforce_limits);
            let selected = production && variant == 0;
            prop_assert_eq!(crate::rest::production_document_success(&state, &req, &response), selected);
            let actual = render(&state, &req, &response);
            let expected = if selected { reference_document_body(&response.body) } else { serde_json::to_vec(&response.body).unwrap() };
            prop_assert_eq!(&actual, &expected);
            prop_assert_eq!(serde_json::from_slice::<serde_json::Value>(&actual).unwrap(), response.body.clone());
            prop_assert_eq!(&actual, &render(&state, &req, &response));
            prop_assert_eq!(actual.ends_with(b"\n"), selected);
            prop_assert!(!actual.ends_with(b"\n\n"));
        }

        #[test]
        fn generated_transport_projection_preserves_profile_body_and_cors(
            production in any::<bool>(), enforce_limits in any::<bool>(),
            status in prop::sample::select(vec![200u16, 400, 404, 429, 500]),
            layout in any::<bool>(), kind in 0u8..3,
            text in proptest::collection::vec(any::<char>(), 0..64), origin in any::<bool>(),
        ) {
            let text: String = text.into_iter().collect();
            check_transport_projection(production, enforce_limits, status, layout, kind, &text, origin.then_some("http://localhost:4321"));
        }
        #[test]
        fn generated_document_layout_preserves_strings_policy_and_shape(
            id in proptest::collection::vec(any::<char>().prop_filter("document segment", |c| *c != '/'), 1..25),
            production in any::<bool>(), enforce_limits in any::<bool>(), extra in any::<bool>(),
        ) {
            let id: String = id.into_iter().collect();
            let name = format!("projects/demo-app/databases/(default)/documents/cases/{id}");
            let path = format!("/v1/projects/demo-app/databases/(default)/documents/cases/{}", encoded_segment(&id));
            let req = request("GET", &path);
            let mut response = missing(&name);
            if extra { response.body["error"]["details"] = serde_json::json!([]); }
            let state = state(production, enforce_limits);
            let bytes = render(&state, &req, &response);
            let expected = if production && !extra { expected_layout(&name) } else { serde_json::to_vec(&response.body).unwrap() };
            prop_assert_eq!(&bytes, &expected);
            prop_assert_eq!(&bytes, &render(&state, &req, &response));
            prop_assert_eq!(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(), response.body);
            prop_assert_eq!(bytes.ends_with(b"\n"), production && !extra);
            prop_assert!(!bytes.ends_with(b"\n\n"));
        }
        #[test]
        fn generated_nearby_envelopes_and_routes_stay_compact(
            id in "[a-zA-Z0-9]{1,24}", variant in 0u8..10,
            unknown in ".{0,32}", status in (100u16..600).prop_filter("not 404", |code| *code != 404),
        ) {
            let name = format!("projects/demo-app/databases/(default)/documents/cases/{id}");
            let mut req = request("GET", &format!("/v1/{name}"));
            let mut response = missing(&name);
            match variant {
                0 => response.status = status,
                1 => response.body["error"]["code"] = serde_json::json!(status),
                2 => response.body["error"]["status"] = serde_json::json!(format!("UNKNOWN{unknown}")),
                3 => response.body["error"]["message"] = serde_json::json!(format!("unknown {unknown}")),
                4 => response.body["extra"] = serde_json::json!(unknown),
                5 => response.body["error"]["details"] = serde_json::json!(unknown),
                6 => req.method = "PATCH".to_owned(),
                7 => { req.path = req.path.rsplit_once('/').unwrap().0.to_owned(); response = missing(req.path.strip_prefix("/v1/").unwrap()); },
                8 => req.path.push_str(":runQuery"),
                _ => req.path.push_str(":unknown"),
            }
            let bytes = render(&state(true, true), &req, &response);
            prop_assert_eq!(bytes, serde_json::to_vec(&response.body).unwrap());
        }

        #[test]
        fn generated_database_roots_stay_compact(
            project in prop_oneof![Just("documents".to_owned()), "[a-z]{1,12}"],
            database in prop_oneof![Just("documents".to_owned()), Just("(default)".to_owned()), "[a-z]{1,12}"],
            production in any::<bool>(), enforce_limits in any::<bool>(),
        ) {
            let name = format!("projects/{project}/databases/{database}/documents");
            let path = format!("/v1/projects/{}/databases/{}/documents", encoded_segment(&project), encoded_segment(&database));
            let response = missing(&name);
            prop_assert_eq!(render(&state(production, enforce_limits), &request("GET", &path), &response), serde_json::to_vec(&response.body).unwrap());
        }

    }
}
