//! One listener, three protocols: gRPC (HTTP/2, `application/grpc`), the `WebChannel`
//! transport of the web SDK (`/google.firestore.v1.Firestore/{Listen,Write}/channel`) and
//! the REST JSON API share the Firestore port, as the official Emulator does. Browser
//! requests get permissive CORS answers (loopback test runtime).

use std::convert::Infallible;
use std::sync::{Arc, OnceLock};

use bytes::{Bytes, BytesMut};
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

/// `FS-LIMIT-API-REQUEST-BYTES`: the largest API request Firestore accepts, measured on the
/// message payload before protocol decode. It is an inclusive maximum, so a request of
/// exactly this many bytes is accepted and one more byte is refused.
///
/// The normal REST, `WebChannel`, and gRPC paths each apply it at their own decode boundary:
/// [`MAX_REST_BODY_BYTES`] on a REST body, [`crate::webchannel::MAX_FORM_BYTES`] on a
/// `WebChannel` form body, and [`MAX_GRPC_MESSAGE_BYTES`] on a gRPC message. The strict REST
/// `:commit` route has a separate production-observed raw allowance; it does not apply a
/// second decoded-protobuf bound.
pub const API_REQUEST_BYTES: usize = 10 * 1024 * 1024;

/// Maximum accepted REST request body (`FS-LIMIT-API-REQUEST-BYTES`). The body is read
/// through a bounded stream, so an over-long request is refused without ever being held
/// whole in memory.
pub const MAX_REST_BODY_BYTES: usize = API_REQUEST_BYTES;

/// Production accepts an 11 MiB raw REST Commit body and refuses one more byte.
pub const MAX_STRICT_COMMIT_RAW_BYTES: usize = 11 * 1024 * 1024;
const MAX_STRICT_COMMIT_REJECTION_DRAIN_BYTES: usize = 32 * 1024 * 1024;

/// Maximum accepted gRPC message (`FS-LIMIT-API-REQUEST-BYTES`), applied by tonic before the
/// protobuf is decoded. This is the request direction only.
pub const MAX_GRPC_MESSAGE_BYTES: usize = API_REQUEST_BYTES;

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

/// The refusal a request over [`API_REQUEST_BYTES`] gets.
///
/// Documented, production observation pending. The Firestore quotas page states the 10 MiB
/// maximum but not the answer to exceeding it, and no production receipt for that refusal
/// exists in this repository (`tools/compat-broad/fs-request-bytes-boundary/README.md` says
/// as much about its own sources). The strict profile therefore answers, on every transport,
/// the shape Google's API infrastructure documents for an oversized payload: HTTP 400 with
/// the canonical code `INVALID_ARGUMENT`, which is the `google.rpc.Code` that maps to 400.
/// One shape on all three transports is one thing for the request-byte campaign to confirm
/// or correct.
///
/// The `emulator` profile keeps the 413 the local runtime has always answered. The boundary
/// is identical under both: only the shape of the refusal differs.
fn api_request_too_large_message() -> String {
    format!("Request payload size exceeds the limit: {API_REQUEST_BYTES} bytes.")
}

/// The legacy refusal, kept for the `emulator` profile.
pub const API_REQUEST_TOO_LARGE_LEGACY: &str = "request body too large";

fn api_request_too_large(enforce_limits: bool) -> RestResponse {
    if enforce_limits {
        RestResponse {
            status: 400,
            body: fireemu_adapter_support::api_error::google_rpc(
                400,
                &api_request_too_large_message(),
                "INVALID_ARGUMENT",
            ),
        }
    } else {
        RestResponse {
            status: 413,
            body: fireemu_adapter_support::api_error::google_rpc(
                413,
                API_REQUEST_TOO_LARGE_LEGACY,
                "INVALID_ARGUMENT",
            ),
        }
    }
}

fn strict_commit_raw_too_large() -> RestResponse {
    RestResponse {
        status: 400,
        body: fireemu_adapter_support::api_error::google_rpc(
            400,
            &format!(
                "Request payload size exceeds the limit: {MAX_STRICT_COMMIT_RAW_BYTES} bytes."
            ),
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

fn header<'a, B>(req: &'a Request<B>, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

/// Why a request body was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyRejection {
    /// Over [`API_REQUEST_BYTES`], or the connection failed mid-body. A broken connection has
    /// always been answered this way and keeps that answer; nothing reaches the client anyway.
    TooLarge,
    /// The sender held the request open past [`BODY_READ_DEADLINE`] without finishing it.
    Deadline,
    /// The request declared no body and sent one anyway. Distinct from [`Self::TooLarge`] so
    /// that a single stray byte is not reported as a 10 MiB overflow.
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

    const fn for_request(declared: bool, maximum: usize) -> Self {
        if declared {
            Self::Declared(maximum)
        } else {
            Self::Undeclared
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

/// A strict Commit over its raw limit is drained without retaining the overflow. Replying
/// while the client is still uploading can reset the HTTP/1 connection before it sees the
/// production-shaped 400. The finite drain cap and deadline still bound hostile senders.
async fn read_strict_commit_body(
    req: Request<Incoming>,
    deadline: std::time::Duration,
) -> Result<Bytes, BodyRejection> {
    let mut body = req.into_body();
    let read = async {
        let mut retained = BytesMut::new();
        let mut total = 0usize;
        let mut too_large = false;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| BodyRejection::TooLarge)?;
            if let Ok(data) = frame.into_data() {
                total = total.saturating_add(data.len());
                if total > MAX_STRICT_COMMIT_REJECTION_DRAIN_BYTES {
                    return Err(BodyRejection::TooLarge);
                }
                if total > MAX_STRICT_COMMIT_RAW_BYTES {
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

fn body_rejection_response(
    rejection: BodyRejection,
    enforce_limits: bool,
    strict_commit: bool,
) -> RestResponse {
    match rejection {
        BodyRejection::TooLarge if strict_commit => strict_commit_raw_too_large(),
        BodyRejection::TooLarge => api_request_too_large(enforce_limits),
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
    // REST admits every request, body or not: the permit covers the `spawn_blocking`
    // execution below as well as the body, so it bounds the blocking pool and not only
    // memory. The channel path has no such execution and admits only a declared body.
    let Some(permit) = try_admit_rest_work(rest_work_limiter()) else {
        return Ok(json_response(
            &too_many_concurrent_requests(),
            origin.as_deref(),
        ));
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
    let strict_commit =
        state.gateway.enforce_limits && crate::rest::is_strict_commit_route(&method, &path);
    let body_limit = if strict_commit {
        MAX_STRICT_COMMIT_RAW_BYTES
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
            return Ok(json_response(
                &too_many_concurrent_requests(),
                origin.as_deref(),
            ));
        }
    };
    let bytes = match if strict_commit {
        read_strict_commit_body(req, body_deadline).await
    } else {
        read_body(req, BodyAllowance::Declared(body_limit), body_deadline).await
    } {
        Ok(bytes) => bytes,
        Err(rejection) => {
            return Ok(json_response(
                &body_rejection_response(rejection, state.gateway.enforce_limits, strict_commit),
                origin.as_deref(),
            ));
        }
    };
    let body = match request_body(&bytes, &path, state.gateway.production_refusals()) {
        Ok(body) => body,
        Err(response) => return Ok(json_response(&response, origin.as_deref())),
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
        },
        _payload_permit: payload_permit,
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
            crate::local::LocalBackend::without_waiting(|| {
                attempt_state.handle(&attempt_request.request)
            })
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
                    &too_many_concurrent_requests(),
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

async fn channel_call<B>(
    hub: Arc<Hub>,
    kind: StreamKind,
    req: Request<B>,
    enforce_limits: bool,
    limiter: &Arc<tokio::sync::Semaphore>,
    body_deadline: std::time::Duration,
) -> Response<OutBody>
where
    B: Body<Data = Bytes>,
    B::Error: Into<BoxError>,
{
    let origin = header(&req, "origin").map(str::to_owned);
    // A form body is up to `MAX_FORM_BYTES`, the same as a REST body, so it is admitted from
    // the same pool: without this, peak body memory on this path was bounded only by how
    // fast clients connect.
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
    let allowance = BodyAllowance::for_request(declared, crate::webchannel::MAX_FORM_BYTES);
    let bytes = match read_body(req, allowance, body_deadline).await {
        Ok(bytes) => bytes,
        Err(rejection) => {
            return json_response(
                &body_rejection_response(rejection, enforce_limits, false),
                origin.as_deref(),
            );
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
) -> Result<serde_json::Value, crate::rest::RestResponse> {
    if bytes.is_empty() {
        return Ok(serde_json::Value::Object(serde_json::Map::new()));
    }
    crate::rest::transcode::parse_body(bytes)
        .or_else(|error| {
            if !production_refusals {
                if let Ok(value) = serde_json::from_slice(bytes) {
                    return Ok(value);
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

fn normalize_transport_status(headers: &mut HeaderMap, enforce_limits: bool) {
    crate::production_status::respec_grpc_message(headers);
    let Some(status) = Status::from_header_map(headers) else {
        return;
    };
    let replacement = if is_prost_recursion(&status) {
        Status::invalid_argument(status.message().to_owned())
    } else if enforce_limits && is_decoded_message_too_large(&status) {
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

fn normalize_transport_frame(
    mut frame: Frame<Bytes>,
    enforce_limits: bool,
    write_stream: bool,
) -> Frame<Bytes> {
    if let Some(trailers) = frame.trailers_mut() {
        normalize_transport_status(trailers, enforce_limits);
        if enforce_limits
            && write_stream
            && Status::from_header_map(trailers)
                .is_some_and(|status| status.code() == tonic::Code::Ok)
            && !trailers.contains_key("content-disposition")
        {
            trailers.insert(
                "content-disposition",
                HeaderValue::from_static("attachment"),
            );
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
            let io = TokioIo::new(stream);
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
                        normalize_transport_status(response.headers_mut(), enforce_limits);
                        if response
                            .headers()
                            .contains_key(crate::local::DROP_CONNECTION_KEY)
                        {
                            // A `dropConnection` fault: the stream is reset (HTTP/2) or
                            // the connection closed (HTTP/1) instead of delivering it.
                            return Err(dropped());
                        }
                        return Ok::<_, std::io::Error>(response.map(|b| {
                            b.map_frame(move |frame| {
                                normalize_transport_frame(frame, enforce_limits, write_stream)
                            })
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
                        let enforce_limits = rest.gateway.enforce_limits;
                        return Ok(channel_call(
                            hub,
                            kind,
                            req,
                            enforce_limits,
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
            super::request_body(br#"{"structuredQuery": {"limit": 1,},}"#, query, true).unwrap(),
            json!({"structuredQuery": {"limit": 1}})
        );
        assert_eq!(super::request_body(b"", commit, true).unwrap(), json!({}));
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
        assert!(read.is_array());
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
        try_admit_rest_payload_from, try_admit_rest_work, RestEnvelope, MAX_REST_BODY_BYTES,
        MAX_STRICT_COMMIT_RAW_BYTES, REST_PAYLOAD_UNIT_BYTES,
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
        let trailers = normalize_transport_frame(frame, true, true)
            .into_trailers()
            .expect("terminal trailers");
        assert_eq!(
            trailers
                .get("content-disposition")
                .and_then(|value| value.to_str().ok()),
            Some("attachment")
        );
        for (strict, write_stream, code) in [
            (false, true, Code::Ok),
            (true, false, Code::Ok),
            (true, true, Code::InvalidArgument),
        ] {
            let frame: Frame<Bytes> = Frame::trailers(headers(&Status::new(code, "refused")));
            let trailers = normalize_transport_frame(frame, strict, write_stream)
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
        normalize_transport_status(&mut ordinary_headers, true);
        let unchanged = Status::from_header_map(&ordinary_headers).unwrap();
        assert_eq!(unchanged.code(), Code::Internal);
        assert_eq!(unchanged.message(), "backend failed");
        assert_eq!(unchanged.details(), b"details");

        let already_client_error =
            Status::invalid_argument("failed to decode Protobuf message: recursion limit reached");
        let mut client_headers = headers(&already_client_error);
        normalize_transport_status(&mut client_headers, true);
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
        normalize_transport_status(&mut prost_headers, true);
        let normalized = Status::from_header_map(&prost_headers).unwrap();
        assert_eq!(normalized.code(), Code::InvalidArgument);
        assert_eq!(
            normalized.message(),
            "failed to decode Protobuf message: Value.value_type: recursion limit reached"
        );
        assert!(normalized.details().is_empty());
    }

    /// The decode-size refusal keeps tonic's own answer under the `emulator` profile and
    /// takes the documented production shape under `strict`. Only the shape changes: the
    /// boundary tonic enforces is the same one either way.
    #[test]
    fn the_decode_size_refusal_is_reshaped_only_in_the_strict_profile() {
        let tonic_wording =
            "Error, decoded message length too large: found 10485761 bytes, the limit is: 10485760 bytes";
        let too_large = || Status::new(Code::OutOfRange, tonic_wording);

        let mut emulator = headers(&too_large());
        normalize_transport_status(&mut emulator, false);
        let kept = Status::from_header_map(&emulator).unwrap();
        assert_eq!(kept.code(), Code::OutOfRange);
        assert_eq!(kept.message(), tonic_wording);

        let mut strict = headers(&too_large());
        normalize_transport_status(&mut strict, true);
        let reshaped = Status::from_header_map(&strict).unwrap();
        assert_eq!(reshaped.code(), Code::InvalidArgument);
        assert_eq!(reshaped.message(), api_request_too_large_message());
        assert_eq!(
            api_request_too_large_message(),
            "Request payload size exceeds the limit: 10485760 bytes."
        );

        // The encode direction is never touched. `MAX_GRPC_RESPONSE_BYTES` is a local memory
        // guard, not `FS-LIMIT-API-REQUEST-BYTES`, so a response this runtime could not encode
        // must not be dressed up as production refusing the client's request.
        for enforce_limits in [true, false] {
            let encode_side = "Error, encoded message length too large: found 10485761 bytes, the limit is: 10485760 bytes";
            let mut encoded = headers(&Status::new(Code::OutOfRange, encode_side));
            normalize_transport_status(&mut encoded, enforce_limits);
            let kept = Status::from_header_map(&encoded).unwrap();
            assert_eq!(kept.code(), Code::OutOfRange);
            assert_eq!(kept.message(), encode_side);
        }

        // An unrelated OUT_OF_RANGE is never touched, in either profile.
        for enforce_limits in [true, false] {
            let mut unrelated = headers(&Status::new(Code::OutOfRange, "cursor past the end"));
            normalize_transport_status(&mut unrelated, enforce_limits);
            let kept = Status::from_header_map(&unrelated).unwrap();
            assert_eq!(kept.code(), Code::OutOfRange);
            assert_eq!(kept.message(), "cursor past the end");
        }
    }

    /// A `WebChannel` form body is up to the same 10 MiB a REST body is, so it draws on the
    /// same admission pool. Before this, `channel_call` had no gate at all and peak body
    /// memory on that path was bounded only by the connection rate.
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
            let gateway = Gateway {
                enforce_limits: true,
                ctx: PlanningContext {
                    edition: FirestoreEdition::Standard,
                    api_mode: FirestoreApiMode::Native,
                    policy: IndexValidationPolicy::Production,
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
                    true,
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
                    true,
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
                    true,
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
                    true,
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
                    true,
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
                    true,
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
                        true,
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
                        true,
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
                        true,
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
                    true,
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
                        true,
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
        assert_eq!(MAX_REST_BODY_BYTES.div_ceil(REST_PAYLOAD_UNIT_BYTES), 10);
        assert_eq!(
            MAX_STRICT_COMMIT_RAW_BYTES.div_ceil(REST_PAYLOAD_UNIT_BYTES),
            11
        );
    }
}
