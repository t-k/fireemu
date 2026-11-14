//! hyper glue for the Storage surface: raw bodies (uploads), CORS for the browser SDK,
//! loopback-only origins.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use fireemu_adapter_support::connection::{DrainBounds, GracefulClose};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::identity_toolkit::origin_is_local;
use crate::storage::{handle_framed, StorageRequest, StorageState};

/// Room a request body has beyond the object limit for multipart framing and metadata.
pub const BODY_OVERHEAD_BYTES: usize = 4 * 1024 * 1024;

/// Default maximum accepted upload body (the default object limit plus [`BODY_OVERHEAD_BYTES`]).
pub const MAX_STORAGE_BODY_BYTES: usize = 260 * 1024 * 1024;

/// Largest `storage.bufferedBodyBudgetBytes`; a body this long still fits a 32-bit `usize`.
pub const MAX_CONFIGURED_BUDGET_BYTES: u64 = i32::MAX as u64;

/// Largest `storage.maxObjectBytes`; the body limit derived from it stays within
/// [`MAX_CONFIGURED_BUDGET_BYTES`].
pub const MAX_CONFIGURED_OBJECT_BYTES: u64 =
    MAX_CONFIGURED_BUDGET_BYTES - BODY_OVERHEAD_BYTES as u64;

/// The longest request body for an object limit, or `None` when it does not fit a `usize`.
#[must_use]
pub fn body_cap_for_object_limit(max_object_bytes: u64) -> Option<usize> {
    usize::try_from(max_object_bytes)
        .ok()?
        .checked_add(BODY_OVERHEAD_BYTES)
}

/// Default process-wide budget for concurrently buffered upload bodies.
/// Requests exceeding the budget receive 503 and `Retry-After: 1`.
pub const DEFAULT_BODY_BUDGET_BYTES: usize = 1024 * 1024 * 1024;

/// Granularity of budget charges for bodies that arrive without a `Content-Length`.
const CHARGE_GRANULARITY: usize = 1024 * 1024;

/// The budget [`serve_storage`] admits request bodies against.
pub static BODY_BUDGET: BodyBudget = BodyBudget::new(DEFAULT_BODY_BUDGET_BYTES);

/// Bounds concurrent synchronous Storage handlers, including requests waiting on a store
/// lock. Body collection does not hold a slot, so slow clients cannot occupy the pool.
const BLOCKING_HANDLER_LIMIT: usize = 16;
static BLOCKING_HANDLER_SLOTS: Semaphore = Semaphore::const_new(BLOCKING_HANDLER_LIMIT);

/// Bounds the list requests that carry a `matchGlob`, whose cost depends on a pattern the caller
/// writes. A request waits for one of these slots before it takes a handler slot, and waits
/// without holding a thread, so a flood of them leaves the handler slots to the other requests.
const GLOB_HANDLER_LIMIT: usize = 2;
static GLOB_HANDLER_SLOTS: Semaphore = Semaphore::const_new(GLOB_HANDLER_LIMIT);

/// Sets its flag when dropped: the request future that owns it was dropped (the client has gone) or
/// has finished.
struct SetOnDrop(Arc<AtomicBool>);

impl Drop for SetOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// An admission budget for the request bodies buffered in memory at the same time.
///
/// Charges are held by the buffer that owns the bytes and released when it is dropped, so
/// a rejected, failed or finished upload gives its budget back immediately.
#[derive(Debug)]
pub struct BodyBudget {
    limit: AtomicUsize,
    in_flight: AtomicUsize,
}

impl BodyBudget {
    /// A budget of `limit` bytes.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            limit: AtomicUsize::new(limit),
            in_flight: AtomicUsize::new(0),
        }
    }

    /// The configured limit.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Acquire)
    }

    /// Configures the budget before accepting requests.
    pub fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::Release);
    }

    /// Bytes charged to the budget right now.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Charges `bytes`; `false` (nothing charged) when they no longer fit.
    fn charge(&self, bytes: usize) -> bool {
        let mut current = self.in_flight.load(Ordering::Relaxed);
        loop {
            let next = match current.checked_add(bytes) {
                Some(n) if n <= self.limit() => n,
                _ => return false,
            };
            match self.in_flight.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn release(&self, bytes: usize) {
        self.in_flight.fetch_sub(bytes, Ordering::AcqRel);
    }
}

/// Why a request body was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyError {
    /// Larger than [`MAX_STORAGE_BODY_BYTES`].
    TooLarge,
    /// The in-flight budget is exhausted.
    BudgetExhausted,
    /// The connection failed before the body was complete.
    Incomplete,
}

/// A request body buffer that holds its charge against a [`BodyBudget`] for as long as it
/// lives. The bytes are handed to the handler by value; the charge is released when the
/// buffer is dropped, which is after the handler returns (also on every error path).
struct BudgetedBody {
    budget: &'static BodyBudget,
    /// The longest body this request may have. Data routes use the configured object limit plus
    /// multipart overhead; the privileged rules route uses the control port's limit. It is applied
    /// as the bytes arrive, so a client that declares no length cannot buffer more than it.
    cap: usize,
    charged: usize,
    bytes: Vec<u8>,
}

impl BudgetedBody {
    fn new(budget: &'static BodyBudget, cap: usize) -> Self {
        Self {
            budget,
            cap,
            charged: 0,
            bytes: Vec::new(),
        }
    }

    /// Charges the budget up to `needed` bytes (rounded up to [`CHARGE_GRANULARITY`] so
    /// that a streamed body does not touch the counter per frame).
    fn reserve(&mut self, needed: usize) -> Result<(), BodyError> {
        if needed <= self.charged {
            return Ok(());
        }
        let target = needed
            .checked_next_multiple_of(CHARGE_GRANULARITY)
            .unwrap_or(needed)
            .min(self.budget.limit())
            .max(needed);
        if !self.budget.charge(target - self.charged) {
            return Err(BodyError::BudgetExhausted);
        }
        self.charged = target;
        Ok(())
    }

    /// Reserves the declared body size up front: one allocation for the whole body.
    fn reserve_declared(&mut self, declared: usize) -> Result<(), BodyError> {
        if declared > self.cap {
            return Err(BodyError::TooLarge);
        }
        self.reserve(declared)?;
        self.bytes.reserve_exact(declared);
        Ok(())
    }

    fn extend(&mut self, chunk: &[u8]) -> Result<(), BodyError> {
        let end = self
            .bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(BodyError::TooLarge)?;
        if end > self.cap {
            return Err(BodyError::TooLarge);
        }
        self.reserve(end)?;
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    /// Moves the bytes out; the charge stays until this buffer is dropped.
    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for BudgetedBody {
    fn drop(&mut self) {
        if self.charged > 0 {
            self.budget.release(self.charged);
        }
    }
}

/// Buffers the whole request body under the budget and the body limit.
async fn collect_body(
    budget: &'static BodyBudget,
    cap: usize,
    declared: Option<usize>,
    mut body: Incoming,
) -> Result<BudgetedBody, BodyError> {
    let mut buffer = BudgetedBody::new(budget, cap);
    if let Some(declared) = declared {
        buffer.reserve_declared(declared)?;
    }
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| BodyError::Incomplete)?;
        if let Ok(data) = frame.into_data() {
            buffer.extend(&data)?;
        }
    }
    Ok(buffer)
}

/// The request headers the Storage surface accepts.
///
/// `x-firebase-appcheck` is listed because a client may send it, but it is never copied into
/// the single-valued header map below: a map collapses duplicates, and the canonical contract
/// of specification section 7.3 has to refuse them. It travels in
/// [`StorageRequest::app_check`] instead, with every instance in wire order.
const FORWARDED_HEADERS: &[&str] = &[
    "authorization",
    "content-type",
    fireemu_core_app_check::header::APP_CHECK_HEADER,
    "content-range",
    "x-goog-content-length-range",
    "range",
    "x-goog-hash",
    "content-md5",
    "x-goog-upload-protocol",
    "x-goog-upload-command",
    "x-goog-upload-offset",
    "x-http-method-override",
    "x-goog-upload-header-content-type",
    "x-goog-upload-header-content-length",
    "x-upload-content-type",
    "x-upload-content-length",
    "origin",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-dest",
    // Browser metadata older than `Sec-Fetch-*`: the privileged rules route must not depend
    // on one header an unusual browser may omit (see `loopback::BROWSER_METADATA_HEADERS`).
    "referer",
    "cookie",
    // The Google client libraries' marker: the anonymous XML read of the Go library is admitted
    // on it (`storage::has_client_library_marker`).
    "x-goog-api-client",
];

/// The header set the official emulator's `cors` middleware exposes, verbatim.
pub(crate) const EXPOSED_HEADERS: &str = "content-type,x-firebase-storage-version,X-Goog-Upload-Size-Received,x-goog-upload-url,x-goog-upload-command,x-gupload-uploadid,x-goog-upload-header-content-length,x-goog-upload-header-content-type,x-goog-upload-protocol,x-goog-upload-status,x-goog-upload-chunk-granularity,x-goog-upload-control-url";

/// The CORS headers of an ordinary (non-preflight) response, as the official emulator's
/// `cors({origin: true, exposedHeaders})` middleware stamps them: the origin reflected when
/// one was sent, the exposed-header list always, and `Vary: Origin`.
fn cors(
    builder: hyper::http::response::Builder,
    origin: Option<&str>,
) -> hyper::http::response::Builder {
    let mut b = builder
        .header("access-control-expose-headers", EXPOSED_HEADERS)
        .header("vary", "Origin");
    if let Some(origin) = origin {
        b = b.header("access-control-allow-origin", origin);
    }
    b
}

/// The bucket CORS configuration that decides the CORS headers of a request: under the strict
/// profile, the one `storage.cors` lists for an XML or Firebase media request. The JSON API has
/// its own default CORS policy and does not consult the bucket configuration.
fn bucket_cors_for(
    state: &StorageState,
    method: &str,
    path: &str,
    query: &str,
) -> Option<crate::storage_cors::BucketCors> {
    if !state.is_strict() {
        return None;
    }
    let (bucket, firebase, json_api) = crate::storage::cors_bucket(method, path)?;
    if json_api {
        return None;
    }
    if firebase
        && crate::storage::query_params(query)
            .get("alt")
            .map(String::as_str)
            != Some("media")
    {
        return None;
    }
    state.rules.bucket_cors(&bucket)
}

/// `headers` with their CORS headers replaced by `matched`, the headers the bucket's rules gave
/// the request (none when no rule matched). A `Vary: Origin` the answer already carries is not
/// repeated.
fn with_bucket_cors(
    mut headers: Vec<(String, String)>,
    matched: Option<crate::storage_cors::CorsHeaders>,
) -> Vec<(String, String)> {
    headers.retain(|(name, _)| !name.to_ascii_lowercase().starts_with("access-control-"));
    for (name, value) in matched.unwrap_or_default() {
        let repeated_vary = name == "vary"
            && headers.iter().any(|(existing, listed)| {
                existing.eq_ignore_ascii_case("vary")
                    && listed.split(',').any(|part| part.trim() == "Origin")
            });
        if !repeated_vary {
            headers.push((name, value));
        }
    }
    headers
}

/// The answer to a preflight on a bucket `storage.cors` configures: the `200` with no body that
/// Cloud Storage's XML API gave a preflight on a bucket without CORS (recorded), plus the CORS
/// headers of the first rule that matches the request, if any.
fn configured_preflight(
    cors: &crate::storage_cors::BucketCors,
    origin: Option<&str>,
    headers: &hyper::HeaderMap,
) -> Response<StorageBody> {
    let mut builder = Response::builder()
        .status(200)
        .header("cache-control", "private, max-age=0")
        .header("content-type", "text/html; charset=UTF-8");
    let text = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if let (Some(origin), Some(method)) = (origin, text("access-control-request-method")) {
        if let Some(matched) =
            cors.preflight(origin, method, text("access-control-request-headers"))
        {
            for (name, value) in matched {
                builder = builder.header(name, value);
            }
        } else if !cors.is_empty() {
            // RECORDED (STORAGE-STRICTNESS-OBS run ss-48adbd8e, case C3); R3 has no Vary after removing all rules.
            builder = builder.header("vary", "Origin");
        }
    }
    builder
        .body(plain(Bytes::new()))
        .unwrap_or_else(|_| Response::new(plain(Bytes::new())))
}

/// The refusal a body that was not accepted turns into.
/// The body of every Storage answer.
type StorageBody = BoxBody<Bytes, std::convert::Infallible>;

fn plain(bytes: Bytes) -> StorageBody {
    Full::new(bytes).boxed()
}

/// An empty body that tells hyper its length is known to be zero. hyper drops a `Content-Length: 0`
/// from a `204` whose body is already at its end, and production's JSON API object delete sends one
/// (recorded); a body that still has one (empty) frame to give keeps the header on the wire.
struct ZeroLength {
    sent: bool,
}

impl hyper::body::Body for ZeroLength {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        if self.sent {
            return std::task::Poll::Ready(None);
        }
        self.sent = true;
        std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::new()))))
    }

    fn is_end_stream(&self) -> bool {
        self.sent
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(0)
    }
}

/// The body of `response`: [`ZeroLength`] for the one shape that needs it (an empty `204` that
/// carries an explicit `Content-Length: 0`), the plain bytes for every other answer.
fn body_of(response: &crate::storage::StorageResponse) -> StorageBody {
    let explicit_zero = response.status == 204
        && response.body.is_empty()
        && response
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("content-length") && value == "0");
    if explicit_zero {
        ZeroLength { sent: false }.boxed()
    } else {
        plain(response.body.clone())
    }
}

fn body_error_response(e: BodyError, origin: Option<&str>) -> Response<StorageBody> {
    let (status, message, retry_after) = match e {
        BodyError::TooLarge => (413, &b"payload too large"[..], false),
        BodyError::BudgetExhausted => (503, &b"storage upload memory budget exhausted"[..], true),
        BodyError::Incomplete => (400, &b"incomplete request body"[..], false),
    };
    let mut builder = cors(Response::builder().status(status), origin);
    if retry_after {
        builder = builder.header("retry-after", "1");
    }
    builder
        .body(plain(Bytes::from_static(message)))
        .unwrap_or_else(|_| Response::new(plain(Bytes::new())))
}

fn handler_error_response(
    status: StatusCode,
    message: &'static [u8],
    origin: Option<&str>,
    retry: bool,
) -> Response<StorageBody> {
    let mut builder = cors(Response::builder().status(status), origin);
    if retry {
        builder = builder.header("retry-after", "1");
    }
    builder
        .body(plain(Bytes::from_static(message)))
        .unwrap_or_else(|_| Response::new(plain(Bytes::new())))
}

#[allow(clippy::too_many_lines)]
async fn respond(
    state: Arc<StorageState>,
    budget: &'static BodyBudget,
    remote_peer: bool,
    body_cap: usize,
    req: Request<Incoming>,
) -> Result<Response<StorageBody>, std::io::Error> {
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
            .body(plain(Bytes::from(refusal.body())))
            .unwrap_or_else(|_| Response::new(plain(Bytes::new()))));
    }
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if origin.as_deref().is_some_and(|o| !origin_is_local(o)) {
        return Ok(Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(plain(Bytes::from_static(b"forbidden origin")))
            .unwrap_or_else(|_| Response::new(plain(Bytes::new()))));
    }
    // A bucket `storage.cors` lists decides its own CORS headers, a preflight included.
    let bucket_cors = bucket_cors_for(
        &state,
        req.method().as_str(),
        req.uri().path(),
        req.uri().query().unwrap_or(""),
    );
    let json_api_cors = state.is_strict()
        && crate::storage::is_json_api_request(req.method().as_str(), req.uri().path());
    if req.method() == hyper::Method::OPTIONS {
        if json_api_cors {
            // The JSON API's built-in CORS policy applies regardless of bucket storage.cors.
            let mut builder = Response::builder()
                .status(200)
                .header("content-type", "application/octet-stream")
                .header("vary", "Origin, X-Origin")
                .header("access-control-allow-credentials", "true")
                .header(
                    "access-control-allow-methods",
                    "DELETE,GET,HEAD,PATCH,POST,PUT",
                )
                .header("access-control-max-age", "3600");
            if let Some(origin) = origin.as_deref() {
                builder = builder.header("access-control-allow-origin", origin);
            }
            if let Some(requested) = req.headers().get("access-control-request-headers") {
                builder = builder.header("access-control-allow-headers", requested);
            }
            return Ok(builder
                .body(plain(Bytes::new()))
                .unwrap_or_else(|_| Response::new(plain(Bytes::new()))));
        }
        if let Some(cors) = &bucket_cors {
            let mut response = configured_preflight(cors, origin.as_deref(), req.headers());
            // Configured Firebase media preflights were not recorded; preserve their existing reflection of methods and requested headers.
            if req.uri().path().starts_with("/v0/") {
                if response
                    .headers()
                    .contains_key("access-control-allow-origin")
                {
                    if let Some(method) = req.headers().get("access-control-request-method") {
                        response
                            .headers_mut()
                            .insert("access-control-allow-methods", method.clone());
                    }
                    response
                        .headers_mut()
                        .remove("access-control-allow-headers");
                    if let Some(requested) = req
                        .headers()
                        .get("access-control-request-headers")
                        .filter(|value| {
                            value.to_str().is_ok_and(|text| {
                                text.split(',').any(|part| !part.trim().is_empty())
                            })
                        })
                    {
                        response
                            .headers_mut()
                            .insert("access-control-allow-headers", requested.clone());
                    }
                } else {
                    response.headers_mut().remove("vary");
                }
            }
            return Ok(response);
        }
        // The preflight the official emulator's `cors` middleware answers: the requested
        // headers reflected, the express method list, and both Vary members.
        //
        // The one exception is the privileged rules route. `PUT` there replaces the
        // authorization policy of the whole run, and a browser will not send a request its
        // preflight did not admit, so withholding the method blocks every compliant browser
        // without reading a single request header. The handler's control-token guard stays as
        // the answer for a client that ignores the preflight. Browsers that legitimately need
        // to replace rules use the control port's `PUT /v1/storage/rules`.
        let privileged_rules_route = req.uri().path() == "/internal/setRules";
        let mut builder = Response::builder()
            .status(204)
            .header(
                "access-control-allow-methods",
                if privileged_rules_route {
                    "GET,HEAD,PATCH,POST,DELETE"
                } else {
                    "GET,HEAD,PUT,PATCH,POST,DELETE"
                },
            )
            .header("access-control-expose-headers", EXPOSED_HEADERS)
            .header("vary", "Origin, Access-Control-Request-Headers");
        if let Some(origin) = origin.as_deref() {
            builder = builder.header("access-control-allow-origin", origin);
        }
        if let Some(requested) = req
            .headers()
            .get("access-control-request-headers")
            .and_then(|v| v.to_str().ok())
        {
            builder = builder.header("access-control-allow-headers", requested.to_owned());
        }
        return Ok(builder
            .body(plain(Bytes::new()))
            .unwrap_or_else(|_| Response::new(plain(Bytes::new()))));
    }
    let method = req.method().as_str().to_owned();
    let request_method = method.clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut headers = std::collections::BTreeMap::new();
    let mut duplicated: Vec<&str> = Vec::new();
    for name in FORWARDED_HEADERS {
        // The App Check field is the one multi-valued member: a collapsed single value would
        // hide a duplicate, which must classify as malformed (spec 7.3).
        if fireemu_core_app_check::header::is_app_check_header(name) {
            continue;
        }
        let values = req.headers().get_all(*name);
        let mut values = values.iter();
        let first = values.next();
        // Browser evidence is decided by the header being present, not by its bytes being
        // text: a value `to_str` refuses (non-ASCII) is kept, lossily, so it still counts. The
        // same holds for `Authorization`, whose scheme decides whether a request is the client
        // SDK's. Every other header with such a value stays absent, as before.
        let value = first.and_then(|v| match v.to_str() {
            Ok(text) => Some(text.to_owned()),
            Err(_)
                if *name == "authorization"
                    || fireemu_core_session::loopback::BROWSER_METADATA_HEADERS.contains(name) =>
            {
                Some(String::from_utf8_lossy(v.as_bytes()).into_owned())
            }
            Err(_) => None,
        });
        if values.next().is_some() {
            headers.insert((*name).to_owned(), String::new());
            duplicated.push(*name);
        } else if let Some(value) = value {
            headers.insert((*name).to_owned(), value);
        }
    }
    if !duplicated.is_empty() {
        headers.insert(
            crate::storage::DUPLICATED_HEADERS_KEY.to_owned(),
            duplicated.join(","),
        );
    }
    let app_check: Vec<String> = req
        .headers()
        .get_all(fireemu_core_app_check::header::APP_CHECK_HEADER)
        .iter()
        .map(|v| v.to_str().unwrap_or_default().to_owned())
        .collect();
    let declared = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<usize>().ok());
    // The privileged rules route is bounded at the control port's limit rather than the
    // object-upload limit, and the bound is applied as the body streams in, so a client that
    // withholds its Content-Length cannot make this port buffer a rules body up to 260 MiB.
    let cap = if method == "PUT" && path == "/internal/setRules" {
        crate::storage::MAX_SET_RULES_BODY_BYTES
    } else {
        body_cap
    };
    // The buffer moves into the blocking handler and holds its budget charge until that
    // handler finishes, even if the connection is closed while it runs.
    let mut buffer = match collect_body(budget, cap, declared, req.into_body()).await {
        Ok(buffer) => buffer,
        Err(e) => return Ok(body_error_response(e, origin.as_deref())),
    };
    let glob_permit = if crate::storage::uses_match_glob(state.is_strict(), &method, &path, &query)
    {
        Some(
            GLOB_HANDLER_SLOTS
                .acquire()
                .await
                .expect("storage glob semaphore is never closed"),
        )
    } else {
        None
    };
    let permit = BLOCKING_HANDLER_SLOTS
        .acquire()
        .await
        .expect("storage handler semaphore is never closed");
    let trace = std::env::var_os("FIREEMU_TRACE_STORAGE").is_some();
    let (trace_method, trace_path, trace_query, trace_len) = (
        method.clone(),
        path.clone(),
        query.clone(),
        buffer.bytes.len(),
    );
    // hyper drops this future when the client closes its connection (even while the handler works),
    // which sets the flag: a glob scan stops, mid-name, instead of working through the bucket for
    // nobody, and gives its glob slot back.
    let client_gone = Arc::new(AtomicBool::new(false));
    let _gone_on_drop = SetOnDrop(Arc::clone(&client_gone));
    let response = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _glob_permit = glob_permit;
        let body = buffer.take();
        crate::storage::with_cancellation(client_gone, || {
            handle_framed(
                &state,
                StorageRequest {
                    method,
                    path,
                    query,
                    host,
                    headers,
                    app_check,
                    body,
                    remote_peer,
                },
            )
        })
    })
    .await;
    let Ok((response, framed)) = response else {
        return Ok(handler_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            b"storage handler failed",
            origin.as_deref(),
            false,
        ));
    };
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
    // A response the strict profile framed carries production's own header set; every other
    // response gets the official emulator's CORS and `nosniff` stamps.
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    if !framed {
        // Defence in depth: a body typed text/plain that happens to look like markup is
        // never sniffed as HTML on this origin. It does not change how an explicit
        // text/html content-type renders, so it is not a substitute for typing
        // caller-influenced bodies as text/plain -- see storage::gcs_no_such_object.
        builder = builder.header("x-content-type-options", "nosniff");
        if bucket_cors.is_none() && !(json_api_cors && origin.is_some()) {
            builder = cors(builder, origin.as_deref());
        }
    }
    let body = body_of(&response);
    let mut response_headers = response.headers;
    if let Some(origin) = origin.as_deref().filter(|_| json_api_cors) {
        // Preserve recorded object-read expose headers while applying the JSON API's shared CORS
        // defaults to every JSON route. This changes only CORS headers, not route framing.
        let media = request_method == "GET"
            && crate::storage::query_params(&trace_query)
                .get("alt")
                .map(String::as_str)
                == Some("media");
        response_headers.retain(|(name, _)| !name.eq_ignore_ascii_case("vary"));
        let mut json_headers = vec![
            ("access-control-allow-origin".to_owned(), origin.to_owned()),
            (
                "access-control-allow-credentials".to_owned(),
                "true".to_owned(),
            ),
            ("vary".to_owned(), "Origin, X-Origin".to_owned()),
        ];
        let exposed = if crate::storage::is_recorded_json_cors_shape(&request_method, &trace_path) {
            match (media, request_method.as_str()) {
                (true, _) => "Cache-Control, Content-Disposition, Content-Length, Content-Type, Date, ETag, Expires, Last-Modified, Pragma, Server, Transfer-Encoding, Vary, X-GUploader-UploadID, X-Goog-Gcs-Base-Ts, X-Goog-Generation, X-Goog-Hash, X-Goog-Metageneration, X-Google-Trace",
                (_, "GET") => "Cache-Control, Content-Length, Content-Type, Date, ETag, Expires, Server, Transfer-Encoding, Vary, X-GUploader-UploadID, X-Goog-Gcs-Base-Ts, X-Google-Trace",
                _ => EXPOSED_HEADERS,
            }
        } else {
            EXPOSED_HEADERS
        };
        json_headers.push((
            "access-control-expose-headers".to_owned(),
            exposed.to_owned(),
        ));
        response_headers = with_bucket_cors(response_headers, Some(json_headers));
    }
    if let Some(configured) = &bucket_cors {
        let mut matched = origin
            .as_deref()
            .and_then(|origin| configured.actual(origin, &request_method));
        // RECORDED (STORAGE-STRICTNESS-OBS run ss-48adbd8e, case C5): the XML wildcard expose list includes these standard headers, without Vary.
        if !trace_path.starts_with("/v0/") {
            if let Some(headers) = &mut matched {
                for (name, value) in headers {
                    if name == "access-control-expose-headers" && value == "*" {
                        "*, Content-Length, Date, Server, Transfer-Encoding, X-GUploader-UploadID, X-Google-Trace".clone_into(value);
                    }
                }
            }
        }
        response_headers = with_bucket_cors(response_headers, matched);
    }
    for (k, v) in response_headers {
        builder = builder.header(k, v);
    }
    match builder.body(body) {
        Ok(response) => Ok(response),
        // A header value the handler built is not a valid HTTP header (a metadata string with
        // a control character reached `Builder::header`). The input boundary rejects those, so
        // this is unreachable in practice; if it ever fires, answer 500 rather than the silent
        // "200 with an empty body and no CORS headers" the default builder would produce, which
        // is far harder to diagnose (S-4).
        Err(_) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("content-type", "text/plain; charset=utf-8")
            .header("x-content-type-options", "nosniff")
            .body(plain(Bytes::from_static(
                b"internal error building response",
            )))
            .unwrap_or_else(|_| Response::new(plain(Bytes::new())))),
    }
}

/// Serves the Storage surface on `listener` until the task is aborted. Request bodies are
/// admitted against the process-wide [`BODY_BUDGET`].
pub async fn serve_storage(listener: TcpListener, state: Arc<StorageState>) -> std::io::Result<()> {
    serve_storage_with_budget(listener, state, &BODY_BUDGET).await
}

/// [`serve_storage`] against an explicit body budget (tests).
pub fn serve_storage_with_budget(
    listener: TcpListener,
    state: Arc<StorageState>,
    budget: &'static BodyBudget,
) -> impl std::future::Future<Output = std::io::Result<()>> {
    let body_cap = state
        .store
        .lock()
        .map_err(|_| std::io::Error::other("Storage store lock poisoned"))
        .and_then(|store| {
            body_cap_for_object_limit(store.max_object_bytes())
                .ok_or_else(|| std::io::Error::other("Storage object limit is too large"))
        });
    async move {
        let body_cap = body_cap?;
        loop {
            let (stream, peer) =
                fireemu_adapter_support::accept::accept_with_backoff("storage", || {
                    listener.accept()
                })
                .await?;
            let remote_peer = !peer.ip().to_canonical().is_loopback();
            let state = state.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(GracefulClose::new(
                    stream,
                    DrainBounds::for_largest_body(body_cap),
                ));
                let svc = service_fn(move |req| {
                    respond(state.clone(), budget, remote_peer, body_cap, req)
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    }
}

#[cfg(test)]
mod bucket_cors_merge_tests {
    use super::*;

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    fn matched() -> crate::storage_cors::CorsHeaders {
        vec![
            pair("access-control-allow-origin", "http://localhost:3000"),
            pair("vary", "Origin"),
            pair("access-control-expose-headers", "Content-Type"),
        ]
    }

    #[test]
    fn the_rules_headers_replace_every_cors_header_and_keep_the_others() {
        let merged = with_bucket_cors(
            vec![
                pair("content-type", "text/plain"),
                pair("Access-Control-Allow-Origin", "*"),
                pair("access-control-expose-headers", "x"),
                pair("etag", "\"a\""),
            ],
            Some(matched()),
        );
        assert_eq!(
            merged,
            vec![
                pair("content-type", "text/plain"),
                pair("etag", "\"a\""),
                pair("access-control-allow-origin", "http://localhost:3000"),
                pair("vary", "Origin"),
                pair("access-control-expose-headers", "Content-Type"),
            ]
        );
    }

    #[test]
    fn no_matching_rule_leaves_no_cors_header_at_all() {
        let merged = with_bucket_cors(
            vec![pair("access-control-allow-origin", "*"), pair("etag", "a")],
            None,
        );
        assert_eq!(merged, vec![pair("etag", "a")]);
    }

    #[test]
    fn vary_origin_is_not_repeated_but_another_vary_does_not_hide_it() {
        let count = |headers: &[(String, String)]| {
            headers
                .iter()
                .filter(|(name, value)| name == "vary" && value == "Origin")
                .count()
        };
        // Already present, as a separate line or inside a list, in any case of the name.
        for existing in [
            pair("vary", "Origin"),
            pair("Vary", "Accept, Origin"),
            pair("VARY", "Origin,X-Origin"),
        ] {
            let merged = with_bucket_cors(vec![existing.clone()], Some(matched()));
            let varies = merged
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("vary"))
                .count();
            assert_eq!(varies, 1, "{existing:?} is the only Vary line");
            assert_eq!(
                merged.len(),
                3,
                "{existing:?}: the allow-origin and expose headers follow"
            );
            assert!(merged
                .iter()
                .any(|(n, _)| n == "access-control-allow-origin"));
        }
        // A Vary without Origin does not count.
        let merged = with_bucket_cors(vec![pair("vary", "X-Origin")], Some(matched()));
        assert_eq!(count(&merged), 1);
        // Another header that happens to mention Origin is not a Vary.
        let merged = with_bucket_cors(vec![pair("x-note", "Origin")], Some(matched()));
        assert_eq!(count(&merged), 1);
        assert!(merged
            .iter()
            .any(|(n, v)| n == "access-control-allow-origin" && v == "http://localhost:3000"));
    }
}

#[cfg(test)]
mod handler_error_tests {
    use super::*;

    /// The answer to a handler that failed carries its status, its message, the retry hint only
    /// when asked and the CORS headers of the request's origin.
    #[test]
    fn a_failed_handler_answers_its_status_message_retry_hint_and_origin() {
        let failed = handler_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            b"storage handler failed",
            Some("http://localhost:5173"),
            false,
        );
        assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(failed.headers().get("retry-after").is_none());
        assert!(failed
            .headers()
            .get("access-control-allow-origin")
            .is_some());
        let busy = handler_error_response(StatusCode::SERVICE_UNAVAILABLE, b"busy", None, true);
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(busy.headers().get("retry-after").unwrap(), "1");
    }
}

#[cfg(test)]
mod zero_length_tests {
    use super::*;
    use crate::storage::StorageResponse;
    use hyper::body::Body as _;

    fn answer(status: u16, headers: &[(&str, &str)], body: &'static [u8]) -> StorageResponse {
        StorageResponse {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body: Bytes::from_static(body),
        }
    }

    /// Whether the body of `response` is the zero-length one: it has a frame left to give, where the
    /// plain body of an empty answer is already at its end.
    fn is_zero_length(response: &StorageResponse) -> bool {
        let body = body_of(response);
        !body.is_end_stream() && body.size_hint().exact() == Some(0)
    }

    #[test]
    fn only_an_empty_204_with_an_explicit_zero_length_gets_the_zero_length_body() {
        let zero = [("content-length", "0")];
        assert!(is_zero_length(&answer(204, &zero, b"")));
        assert!(is_zero_length(&answer(
            204,
            &[("Content-Length", "0")],
            b""
        )));
        // Each condition alone is not enough.
        assert!(!is_zero_length(&answer(200, &zero, b"")), "another status");
        assert!(
            !is_zero_length(&answer(204, &[], b"")),
            "no explicit length"
        );
        assert!(
            !is_zero_length(&answer(204, &[("content-length", "1")], b"")),
            "another length"
        );
        assert!(
            !is_zero_length(&answer(204, &[("x-other", "0")], b"")),
            "another header"
        );
        assert!(!is_zero_length(&answer(204, &zero, b"x")), "a body");
        assert!(!is_zero_length(&answer(404, &[], b"gone")));
    }

    #[test]
    fn the_zero_length_body_gives_one_empty_frame_then_ends() {
        use std::task::{Context, Poll, Waker};
        let mut body = ZeroLength { sent: false };
        assert!(!body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        let mut context = Context::from_waker(Waker::noop());
        let first = std::pin::Pin::new(&mut body).poll_frame(&mut context);
        let Poll::Ready(Some(Ok(frame))) = first else {
            panic!("an empty frame first");
        };
        assert_eq!(frame.into_data().unwrap().len(), 0);
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(matches!(
            std::pin::Pin::new(&mut body).poll_frame(&mut context),
            Poll::Ready(None)
        ));
    }
}

#[cfg(test)]
mod body_budget_tests {
    use super::*;

    /// The budget admits a charge exactly up to its limit, refuses the byte past it and a sum
    /// that would overflow, and gives released bytes back. Direct calls, so a mutant that admits
    /// or refuses everything fails here at once instead of through a socket that waits.
    #[test]
    fn the_budget_admits_up_to_its_limit_and_gives_released_bytes_back() {
        let budget = BodyBudget::new(8);
        assert!(budget.charge(5), "5 of 8 fits");
        assert_eq!(budget.in_flight(), 5);
        assert!(budget.charge(3), "5 + 3 is exactly the limit");
        assert_eq!(budget.in_flight(), 8);
        assert!(!budget.charge(1), "one byte past the limit is refused");
        assert_eq!(budget.in_flight(), 8, "a refused charge changes nothing");
        budget.release(5);
        assert_eq!(budget.in_flight(), 3);
        assert!(budget.charge(5), "released bytes are available again");
        budget.release(8);
        assert_eq!(budget.in_flight(), 0);
        assert!(
            !budget.charge(usize::MAX),
            "a sum that overflows is refused"
        );
        assert_eq!(budget.in_flight(), 0);
    }

    /// A reconfigured limit applies to the next charge, in both directions.
    #[test]
    fn a_reconfigured_limit_applies_to_the_next_charge() {
        let budget = BodyBudget::new(8);
        budget.set_limit(2);
        assert!(!budget.charge(3));
        assert!(budget.charge(2));
        budget.set_limit(10);
        assert!(budget.charge(8));
        assert_eq!(budget.in_flight(), 10);
    }
}
