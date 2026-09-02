//! hyper glue for the Storage surface: raw bodies (uploads), CORS for the browser SDK,
//! loopback-only origins.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
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

/// Process-wide budget for the upload bodies buffered at the same time (1 GiB, about four
/// near-limit uploads). It is a documented constant rather than a config key: it bounds a
/// memory failure mode, not a semantic of the emulated service.
///
/// A request that does not fit is rejected with `503` and `Retry-After: 1` before its
/// buffer is allocated, so concurrent clients get a stable rejection instead of exhausting
/// the process (`STG-MEM-03`).
pub const DEFAULT_BODY_BUDGET_BYTES: usize = 1024 * 1024 * 1024;

/// Granularity of budget charges for bodies that arrive without a `Content-Length`.
const CHARGE_GRANULARITY: usize = 1024 * 1024;

/// The budget [`serve_storage`] admits request bodies against.
pub static BODY_BUDGET: BodyBudget = BodyBudget::new(DEFAULT_BODY_BUDGET_BYTES);

/// An admission budget for the request bodies buffered in memory at the same time.
///
/// Charges are held by the buffer that owns the bytes and released when it is dropped, so
/// a rejected, failed or finished upload gives its budget back immediately.
#[derive(Debug)]
pub struct BodyBudget {
    limit: usize,
    in_flight: AtomicUsize,
}

impl BodyBudget {
    /// A budget of `limit` bytes.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            limit,
            in_flight: AtomicUsize::new(0),
        }
    }

    /// The configured limit.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
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
                Some(n) if n <= self.limit => n,
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
    charged: usize,
    bytes: Vec<u8>,
}

impl BudgetedBody {
    fn new(budget: &'static BodyBudget) -> Self {
        Self {
            budget,
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
        if declared > MAX_STORAGE_BODY_BYTES {
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
        if end > MAX_STORAGE_BODY_BYTES {
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
    declared: Option<usize>,
    mut body: Incoming,
) -> Result<BudgetedBody, BodyError> {
    let mut buffer = BudgetedBody::new(budget);
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
];

/// The header set the official emulator's `cors` middleware exposes, verbatim.
const EXPOSED_HEADERS: &str = "content-type,x-firebase-storage-version,X-Goog-Upload-Size-Received,x-goog-upload-url,x-goog-upload-command,x-gupload-uploadid,x-goog-upload-header-content-length,x-goog-upload-header-content-type,x-goog-upload-protocol,x-goog-upload-status,x-goog-upload-chunk-granularity,x-goog-upload-control-url";

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

/// The refusal a body that was not accepted turns into.
fn body_error_response(e: BodyError, origin: Option<&str>) -> Response<Full<Bytes>> {
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
        .body(Full::new(Bytes::from_static(message)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

#[allow(clippy::too_many_lines)]
async fn respond(
    state: Arc<StorageState>,
    budget: &'static BodyBudget,
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
        // The preflight the official emulator's `cors` middleware answers: the requested
        // headers reflected, the express method list, and both Vary members.
        let mut builder = Response::builder()
            .status(204)
            .header(
                "access-control-allow-methods",
                "GET,HEAD,PUT,PATCH,POST,DELETE",
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
        // The App Check field is the one multi-valued member: a collapsed single value would
        // hide a duplicate, which must classify as malformed (spec 7.3).
        if fireemu_core_app_check::header::is_app_check_header(name) {
            continue;
        }
        let values = req.headers().get_all(*name);
        let mut values = values.iter();
        let value = values.next().and_then(|v| v.to_str().ok());
        if values.next().is_some() {
            headers.insert((*name).to_owned(), String::new());
        } else if let Some(value) = value {
            headers.insert((*name).to_owned(), value.to_owned());
        }
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
    // The buffer holds its budget charge until it is dropped at the end of this function,
    // so the bytes the handler works on are accounted for the whole time they exist here.
    let mut buffer = match collect_body(budget, declared, req.into_body()).await {
        Ok(buffer) => buffer,
        Err(e) => return Ok(body_error_response(e, origin.as_deref())),
    };
    let body = buffer.take();
    let trace = std::env::var_os("FIREEMU_TRACE_STORAGE").is_some();
    let (trace_method, trace_path, trace_query, trace_len) =
        (method.clone(), path.clone(), query.clone(), body.len());
    let response = handle(
        &state,
        StorageRequest {
            method,
            path,
            query,
            host,
            headers,
            app_check,
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
        Response::builder()
            .status(
                StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            )
            // Defence in depth: a body typed text/plain that happens to look like markup is
            // never sniffed as HTML on this origin. It does not change how an explicit
            // text/html content-type renders, so it is not a substitute for typing
            // caller-influenced bodies as text/plain -- see storage::gcs_no_such_object.
            .header("x-content-type-options", "nosniff"),
        origin.as_deref(),
    );
    for (k, v) in response.headers {
        builder = builder.header(k, v);
    }
    match builder.body(Full::new(response.body)) {
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
            .body(Full::new(Bytes::from_static(
                b"internal error building response",
            )))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))),
    }
}

/// Serves the Storage surface on `listener` until the task is aborted. Request bodies are
/// admitted against the process-wide [`BODY_BUDGET`].
pub async fn serve_storage(listener: TcpListener, state: Arc<StorageState>) -> std::io::Result<()> {
    serve_storage_with_budget(listener, state, &BODY_BUDGET).await
}

/// [`serve_storage`] against an explicit body budget (tests).
pub async fn serve_storage_with_budget(
    listener: TcpListener,
    state: Arc<StorageState>,
    budget: &'static BodyBudget,
) -> std::io::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| respond(state.clone(), budget, req));
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}
