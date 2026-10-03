//! hyper glue for the Storage surface: raw bodies (uploads), CORS for the browser SDK,
//! loopback-only origins.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use fireemu_adapter_support::connection::{DrainBounds, GracefulClose};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};

use crate::identity_toolkit::origin_is_local;
use crate::storage::{handle_framed_cancellable, GlobEvent, StorageRequest, StorageState};

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

/// Bounds concurrent synchronous Storage handlers, including requests waiting on a store
/// lock. Body collection does not hold a slot, so slow clients cannot occupy the pool.
const BLOCKING_HANDLER_LIMIT: usize = 16;
static BLOCKING_HANDLER_SLOTS: Semaphore = Semaphore::const_new(BLOCKING_HANDLER_LIMIT);

/// Bounds the list requests that carry a `matchGlob`, whose cost depends on a pattern the caller
/// writes. A request waits for one of these slots before it takes a handler slot, and waits
/// without holding a thread, so a flood of them leaves the handler slots to the other requests.
const GLOB_HANDLER_LIMIT: usize = 2;
static GLOB_HANDLER_SLOTS: Semaphore = Semaphore::const_new(GLOB_HANDLER_LIMIT);

#[derive(Default)]
struct Cancellation {
    flag: AtomicBool,
    notify: Notify,
    glob_requests: AtomicUsize,
}

impl Cancellation {
    fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

struct CancelOnDrop(Arc<Cancellation>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Per-server observations of request admission, primitive work and resource cleanup.
#[doc(hidden)]
#[derive(Default)]
pub struct ServerObserver {
    #[cfg(all(test, unix))]
    record_descriptors: bool,
    #[cfg(all(test, unix))]
    descriptors: std::sync::Mutex<Vec<DescriptorWitness>>,
    pub active_globs: AtomicUsize,
    pub queued_globs: AtomicUsize,
    pub general_permits: AtomicUsize,
    pub connections: AtomicUsize,
    pub monitors: AtomicUsize,
    pub workers: AtomicUsize,
    pub compiled_patterns: AtomicUsize,
    pub largest_pattern: AtomicUsize,
    pub matcher_polls: AtomicUsize,
    pub state_polls: AtomicUsize,
    pub epsilon_polls: AtomicUsize,
    pub matching_workers: AtomicUsize,
    pub cancelled_workers: AtomicUsize,
    pub completed_workers: AtomicUsize,
    pub closed_connections: AtomicUsize,
    /// A verification barrier retains worker permits after cancellation until released.
    pub hold_cancelled_workers: AtomicBool,
    cancelled_gate: (std::sync::Mutex<()>, std::sync::Condvar),
}

#[cfg(all(test, unix))]
struct DescriptorWitness {
    fd: std::os::fd::RawFd,
    identity: String,
    peer: std::net::SocketAddr,
    local: std::net::SocketAddr,
}

#[cfg(all(test, target_os = "macos"))]
fn parse_descriptor_fields(
    fields: &str,
) -> std::io::Result<std::collections::BTreeMap<i32, String>> {
    let expected_process = format!("p{}", std::process::id());
    if fields.lines().next() != Some(expected_process.as_str()) {
        return Err(std::io::Error::other("lsof did not identify this process"));
    }
    let mut descriptors = std::collections::BTreeMap::new();
    let mut current = None;
    for line in fields.lines().skip(1) {
        if let Some(fd) = line.strip_prefix('f') {
            current = fd.parse::<i32>().ok();
            if let Some(fd) = current {
                descriptors.insert(fd, String::new());
            }
        } else if line.starts_with(['t', 'n', 'D']) {
            if let Some(fd) = current {
                let identity = descriptors.get_mut(&fd).expect("recorded descriptor");
                identity.push_str(line);
                identity.push('\n');
            }
        } else {
            return Err(std::io::Error::other("unexpected lsof descriptor field"));
        }
    }
    if descriptors.is_empty()
        || descriptors
            .values()
            .any(|identity| !identity.starts_with('t'))
    {
        return Err(std::io::Error::other(
            "lsof descriptor identity is incomplete",
        ));
    }
    Ok(descriptors)
}

/// Only a successful complete OS snapshot may report an absent descriptor.
#[cfg(all(test, unix))]
fn descriptor_snapshot() -> std::io::Result<std::collections::BTreeMap<i32, String>> {
    #[cfg(target_os = "linux")]
    {
        let mut descriptors = std::collections::BTreeMap::new();
        for entry in std::fs::read_dir("/proc/self/fd")? {
            let entry = entry?;
            let fd = entry
                .file_name()
                .to_string_lossy()
                .parse::<i32>()
                .map_err(std::io::Error::other)?;
            match std::fs::read_link(entry.path()) {
                Ok(identity) => {
                    descriptors.insert(fd, identity.to_string_lossy().into_owned());
                }
                // A descriptor may close while the snapshot is enumerated.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(descriptors)
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/usr/sbin/lsof")
            .args([
                "-nP",
                "-a",
                "-p",
                &std::process::id().to_string(),
                "-F",
                "ftnD",
            ])
            .output()?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(std::io::Error::other(format!(
                "lsof observation failed: {:?}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let fields = String::from_utf8(output.stdout).map_err(std::io::Error::other)?;
        parse_descriptor_fields(&fields)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "descriptor identity gate requires Linux or macOS",
        ))
    }
}

#[cfg(all(test, unix))]
fn descriptor_identity(fd: std::os::fd::RawFd) -> std::io::Result<Option<String>> {
    Ok(descriptor_snapshot()?.remove(&fd))
}

impl ServerObserver {
    /// Free worker permits in the process-wide pools.
    #[must_use]
    pub fn free_permits() -> (usize, usize) {
        (
            GLOB_HANDLER_SLOTS.available_permits(),
            BLOCKING_HANDLER_SLOTS.available_permits(),
        )
    }

    /// Releases the verification barrier, including on a test's cleanup path.
    pub fn release_cancelled_workers(&self) {
        let _gate = self
            .cancelled_gate
            .0
            .lock()
            .expect("worker verification gate is not poisoned");
        self.hold_cancelled_workers.store(false, Ordering::Release);
        self.cancelled_gate.1.notify_all();
    }

    fn cancelled_worker(&self) {
        self.cancelled_workers.fetch_add(1, Ordering::AcqRel);
        let mut guard = self
            .cancelled_gate
            .0
            .lock()
            .expect("worker verification gate is not poisoned");
        while self.hold_cancelled_workers.load(Ordering::Acquire) {
            guard = self
                .cancelled_gate
                .1
                .wait(guard)
                .expect("worker verification gate is not poisoned");
        }
    }
}

struct CountGuard<'a>(&'a AtomicUsize);
impl<'a> CountGuard<'a> {
    fn new(count: &'a AtomicUsize) -> Self {
        count.fetch_add(1, Ordering::AcqRel);
        Self(count)
    }
}
impl Drop for CountGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct Runtime {
    shutdown: Arc<Cancellation>,
    observer: Arc<ServerObserver>,
    jobs: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

/// Observes close readiness on its own descriptor without reading Hyper's HTTP bytes.
async fn socket_closed(stream: &TcpStream, cancellation: &Cancellation) -> std::io::Result<()> {
    loop {
        let readiness = stream.ready(tokio::io::Interest::READABLE).await?;
        if (readiness.is_read_closed() || readiness.is_error())
            && cancellation.glob_requests.load(Ordering::Acquire) > 0
        {
            return Ok(());
        }
        // Ordinary readable data stays owned by Hyper. Readiness remains sticky, so a bounded
        // tick prevents a busy loop while still noticing FIN behind pipelined request bytes.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

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
    /// The longest body this request may have. It is [`MAX_STORAGE_BODY_BYTES`] for the data
    /// routes and the control port's limit for the privileged rules route, and it is applied
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

fn handler_error_response(
    status: StatusCode,
    message: &'static [u8],
    origin: Option<&str>,
    retry: bool,
) -> Response<Full<Bytes>> {
    let mut builder = cors(Response::builder().status(status), origin);
    if retry {
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
    runtime: Arc<Runtime>,
    connection: Arc<Cancellation>,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    let request_cancel = Arc::new(Cancellation::default());
    let _request_guard = CancelOnDrop(request_cancel.clone());
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
    // The privileged rules route is bounded at the control port's limit rather than the
    // object-upload limit, and the bound is applied as the body streams in, so a client that
    // withholds its Content-Length cannot make this port buffer a rules body up to 260 MiB.
    let cap = if method == "PUT" && path == "/internal/setRules" {
        crate::storage::MAX_SET_RULES_BODY_BYTES
    } else {
        MAX_STORAGE_BODY_BYTES
    };
    // The buffer moves into the blocking handler and holds its budget charge until that
    // handler finishes, even if the connection is closed while it runs.
    let mut buffer = tokio::select! {
        result = collect_body(budget, cap, declared, req.into_body()) => match result {
            Ok(buffer) => buffer,
            Err(e) => return Ok(body_error_response(e, origin.as_deref())),
        },
        () = connection.cancelled() => return Err(std::io::Error::other("storage connection closed")),
        () = runtime.shutdown.cancelled() => return Err(std::io::Error::other("storage server stopped")),
    };
    let glob_request = crate::storage::uses_match_glob(&method, &query);
    let _cancellable = glob_request.then(|| CountGuard::new(&connection.glob_requests));
    let queued = glob_request.then(|| CountGuard::new(&runtime.observer.queued_globs));
    let glob_permit = if glob_request {
        Some(tokio::select! {
            permit = GLOB_HANDLER_SLOTS.acquire() => permit.expect("storage glob semaphore is never closed"),
            () = connection.cancelled() => return Err(std::io::Error::other("storage connection closed")),
            () = runtime.shutdown.cancelled() => return Err(std::io::Error::other("storage server stopped")),
        })
    } else {
        None
    };
    drop(queued);
    let permit = tokio::select! {
        permit = BLOCKING_HANDLER_SLOTS.acquire() => permit.expect("storage handler semaphore is never closed"),
        () = connection.cancelled() => return Err(std::io::Error::other("storage connection closed")),
        () = runtime.shutdown.cancelled() => return Err(std::io::Error::other("storage server stopped")),
    };
    if connection.is_cancelled() || runtime.shutdown.is_cancelled() || request_cancel.is_cancelled()
    {
        return Err(std::io::Error::other("storage request cancelled"));
    }
    let trace = std::env::var_os("FIREEMU_TRACE_STORAGE").is_some();
    let (trace_method, trace_path, trace_query, trace_len) = (
        method.clone(),
        path.clone(),
        query.clone(),
        buffer.bytes.len(),
    );
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let work_runtime = runtime.clone();
    let work_connection = connection.clone();
    let job = tokio::task::spawn_blocking(move || {
        let observer = &work_runtime.observer;
        let _worker = CountGuard::new(&observer.workers);
        let _general = CountGuard::new(&observer.general_permits);
        let _glob = glob_request.then(|| CountGuard::new(&observer.active_globs));
        let _permit = permit;
        let _glob_permit = glob_permit;
        let body = buffer.take();
        let matching = std::cell::RefCell::new(None);
        let response = handle_framed_cancellable(
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
            &|| {
                request_cancel.is_cancelled()
                    || work_connection.is_cancelled()
                    || work_runtime.shutdown.is_cancelled()
            },
            &|event| match event {
                GlobEvent::Compiled(pattern) => {
                    observer
                        .largest_pattern
                        .fetch_max(pattern.len(), Ordering::Relaxed);
                    observer.compiled_patterns.fetch_add(1, Ordering::AcqRel);
                }
                GlobEvent::MatcherStatePoll => {
                    observer.state_polls.fetch_add(1, Ordering::Relaxed);
                    if matching.borrow().is_none() {
                        matching.replace(Some(CountGuard::new(&observer.matching_workers)));
                    }
                }
                GlobEvent::MatcherEpsilonPoll => {
                    observer.epsilon_polls.fetch_add(1, Ordering::Relaxed);
                }
                GlobEvent::MatcherPoll => {
                    observer.matcher_polls.fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            },
        );
        if response.is_err() {
            observer.cancelled_worker();
        }
        observer.completed_workers.fetch_add(1, Ordering::AcqRel);
        let _ = sender.send(response);
    });
    {
        let mut jobs = runtime
            .jobs
            .lock()
            .expect("storage worker registry is not poisoned");
        jobs.retain(|job| !job.is_finished());
        jobs.push(job);
    }
    let result = tokio::select! {
        result = receiver => result,
        () = connection.cancelled() => return Err(std::io::Error::other("storage connection closed")),
        () = runtime.shutdown.cancelled() => return Err(std::io::Error::other("storage server stopped")),
    };
    let (response, framed) = match result {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => return Err(std::io::Error::other("storage request cancelled")),
        Err(_) => {
            return Ok(handler_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                b"storage handler failed",
                origin.as_deref(),
                false,
            ))
        }
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
        builder = cors(
            // Defence in depth: a body typed text/plain that happens to look like markup is
            // never sniffed as HTML on this origin. It does not change how an explicit
            // text/html content-type renders, so it is not a substitute for typing
            // caller-influenced bodies as text/plain -- see storage::gcs_no_such_object.
            builder.header("x-content-type-options", "nosniff"),
            origin.as_deref(),
        );
    }
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

/// Serves with the normal body budget until `shutdown`, then joins owned request work.
pub async fn serve_storage_until(
    listener: TcpListener,
    state: Arc<StorageState>,
    shutdown: impl std::future::Future<Output = ()>,
) -> std::io::Result<()> {
    serve_storage_with_shutdown(listener, state, &BODY_BUDGET, shutdown, Arc::default()).await
}

/// [`serve_storage`] against an explicit body budget (tests).
pub async fn serve_storage_with_budget(
    listener: TcpListener,
    state: Arc<StorageState>,
    budget: &'static BodyBudget,
) -> std::io::Result<()> {
    serve_storage_with_shutdown(
        listener,
        state,
        budget,
        std::future::pending::<()>(),
        Arc::default(),
    )
    .await
}

/// Stops accepting, cancels requests and joins owned connections and blocking workers.
#[doc(hidden)]
pub async fn serve_storage_with_shutdown(
    listener: TcpListener,
    state: Arc<StorageState>,
    budget: &'static BodyBudget,
    shutdown: impl std::future::Future<Output = ()>,
    observer: Arc<ServerObserver>,
) -> std::io::Result<()> {
    let runtime = Arc::new(Runtime {
        shutdown: Arc::default(),
        observer,
        jobs: std::sync::Mutex::new(Vec::new()),
    });
    let _shutdown_guard = CancelOnDrop(runtime.shutdown.clone());
    let mut connections = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            () = &mut shutdown => break Ok(()),
            accepted = listener.accept() => {
                let (stream, _) = match accepted { Ok(accepted) => accepted, Err(error) => break Err(error) };
                let std_stream = match stream.into_std() { Ok(stream) => stream, Err(error) => break Err(error) };
                let monitor = match std_stream.try_clone().and_then(TcpStream::from_std) {
                    Ok(stream) => stream, Err(error) => break Err(error),
                };
                let stream = match TcpStream::from_std(std_stream) { Ok(stream) => stream, Err(error) => break Err(error) };
                #[cfg(all(test, unix))]
                if runtime.observer.record_descriptors {
                    use std::os::fd::AsRawFd as _;
                    for socket in [&stream, &monitor] {
                        let fd = socket.as_raw_fd();
                        runtime.observer.descriptors.lock().unwrap().push(DescriptorWitness {
                            fd,
                            identity: descriptor_identity(fd).expect("OS descriptor observation must succeed").expect("the owned socket has an OS identity"),
                            local: socket.local_addr().unwrap(),
                            peer: socket.peer_addr().unwrap(),
                        });
                    }
                }
                let state = state.clone();
                let runtime = runtime.clone();
                connections.spawn(async move {
                    let _connection_count = CountGuard::new(&runtime.observer.connections);
                    let _monitor_count = CountGuard::new(&runtime.observer.monitors);
                    let cancellation = Arc::new(Cancellation::default());
                    let _connection_guard = CancelOnDrop(cancellation.clone());
                    let io = TokioIo::new(GracefulClose::new(stream, DrainBounds::for_largest_body(MAX_STORAGE_BODY_BYTES)));
                    let request_runtime = runtime.clone();
                    let request_cancel = cancellation.clone();
                    let svc = service_fn(move |req| respond(state.clone(), budget, req, request_runtime.clone(), request_cancel.clone()));
                    tokio::select! {
                        _ = http1::Builder::new().serve_connection(io, svc) => {},
                        _ = socket_closed(&monitor, &cancellation) => { runtime.observer.closed_connections.fetch_add(1, Ordering::AcqRel); },
                        () = runtime.shutdown.cancelled() => {},
                    }
                });
            },
            _ = connections.join_next(), if !connections.is_empty() => {},
        }
    };
    drop(listener);
    runtime.shutdown.cancel();
    while connections.join_next().await.is_some() {}
    let jobs = std::mem::take(
        &mut *runtime
            .jobs
            .lock()
            .expect("storage worker registry is not poisoned"),
    );
    for job in jobs {
        let _ = job.await;
    }
    result
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

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod descriptor_tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::AsyncWriteExt as _;

    fn state() -> Arc<StorageState> {
        use fireemu_core_auth::{
            mfa::TotpPolicy,
            store::{AuthRegistry, AuthStore},
        };
        use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
        use fireemu_core_storage::{
            name::{BucketName, ObjectName},
            store::{NewMetadata, Precondition},
        };
        use fireemu_core_types::{determinism::SplitMix64, time::LogicalInstant};
        let start = LogicalInstant::from_unix_seconds(1_788_004_860);
        let mut store = fireemu_core_storage::store::StorageState::new(9);
        let bucket = BucketName::try_new("demo-app.appspot.com").unwrap();
        for number in 0..64 {
            let name = ObjectName::try_new(format!("{number:03}{}", "x".repeat(990))).unwrap();
            store
                .put(
                    &bucket,
                    &name,
                    vec![b'x'],
                    NewMetadata::default(),
                    Precondition::default(),
                    start,
                )
                .unwrap();
        }
        Arc::new(StorageState {
            store: Mutex::new(store),
            clock: Arc::new(Mutex::new(fireemu_core_session::clock::VirtualClock::new(
                start,
            ))),
            auth: Arc::new(AuthRegistry::new(
                "demo-app",
                Arc::new(Mutex::new(AuthStore::new(
                    "demo-app",
                    SplitMix64::new(3),
                    TotpPolicy::default(),
                ))),
            )),
            tenancy: None,
            rules: Arc::new(crate::storage::StorageRulesRegistry::global(Arc::new(
                RulesetSlot::new(LoadedRules::default()),
            ))),
            project: "demo-app".to_owned(),
            events: None,
            barrier: None,
            firestore: None,
            faults: None,
            clock_observer: None,
            app_check_policy: None,
            admin_capability: None,
            token_acceptance: fireemu_core_auth::jwt::TokenAcceptance::Verified,
            control_token: None,
        })
    }

    async fn observed(label: &str, predicate: impl Fn() -> bool) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !predicate() {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("observation did not settle: {label}"));
    }

    struct Cleanup(
        Option<tokio::sync::oneshot::Sender<()>>,
        Arc<ServerObserver>,
    );
    impl Drop for Cleanup {
        fn drop(&mut self) {
            self.1.release_cancelled_workers();
            if let Some(stop) = self.0.take() {
                let _ = stop.send(());
            }
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn descriptor_observation_rejects_incomplete_or_wrong_process_fields() {
        assert!(parse_descriptor_fields("").is_err());
        assert!(parse_descriptor_fields("p0\nf8\ntIPv4\nnlocalhost\n").is_err());
        let process = std::process::id();
        assert!(parse_descriptor_fields(&format!("p{process}\nf8\n")).is_err());
        assert!(parse_descriptor_fields(&format!("p{process}\nf8\nxunknown\n")).is_err());
        let snapshot =
            parse_descriptor_fields(&format!("p{process}\nf8\ntIPv4\nnlocalhost\n")).unwrap();
        assert!(!snapshot.contains_key(&9));
        assert!(snapshot.contains_key(&8));
    }

    /// Records each accepted and cloned-monitor FD from the production accept path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn storage_shutdown_closes_each_accepted_and_monitor_descriptor() {
        static BUDGET: BodyBudget = BodyBudget::new(8 * 1024 * 1024);
        for drop_future in [false, true] {
            let port = std::env::var("PORT")
                .ok()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(0);
            let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
            let local = listener.local_addr().unwrap();
            let observer = Arc::new(ServerObserver {
                record_descriptors: true,
                ..ServerObserver::default()
            });
            assert!(observer.record_descriptors);
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let mut cleanup = Cleanup(Some(stop), observer.clone());
            let server = tokio::spawn(serve_storage_with_shutdown(
                listener,
                state(),
                &BUDGET,
                async {
                    let _ = stopped.await;
                },
                observer.clone(),
            ));
            let pattern = format!("{}z", "*{,}".repeat(15_000));
            let mut clients = Vec::new();
            for _ in 0..2 {
                let mut stream = TcpStream::connect(local).await.unwrap();
                let request = format!("GET /storage/v1/b/demo-app.appspot.com/o?matchGlob={pattern} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer owner\r\n\r\nGET /storage/v1/b/demo-app.appspot.com/o HTTP/1.1\r\nHost: localhost\r\n\r\n");
                stream.write_all(request.as_bytes()).await.unwrap();
                clients.push(stream);
            }
            observed("two matching workers", || {
                observer.matching_workers.load(Ordering::Acquire) == 2
                    && observer.state_polls.load(Ordering::Acquire) > 200
            })
            .await;
            {
                let descriptors = observer.descriptors.lock().unwrap();
                assert_eq!(
                    descriptors.len(),
                    4,
                    "both accepted and monitor descriptors must be recorded"
                );
                for witness in descriptors.iter() {
                    assert_eq!(witness.local, local);
                    assert!(clients
                        .iter()
                        .any(|client| client.local_addr().unwrap() == witness.peer));
                    assert!(
                        !witness.identity.is_empty(),
                        "the OS capture must identify this FD"
                    );
                    eprintln!(
                        "owned descriptor fd={} local={} peer={} identity={:?}",
                        witness.fd, witness.local, witness.peer, witness.identity
                    );
                }
            }
            if drop_future {
                server.abort();
                assert!(server.await.unwrap_err().is_cancelled());
            } else {
                cleanup.0.take().unwrap().send(()).unwrap();
                server.await.unwrap().unwrap();
            }
            observed("all own tasks and permits returned", || {
                observer.connections.load(Ordering::Acquire) == 0
                    && observer.monitors.load(Ordering::Acquire) == 0
                    && observer.workers.load(Ordering::Acquire) == 0
                    && ServerObserver::free_permits() == (2, 16)
            })
            .await;
            assert_eq!(BUDGET.in_flight(), 0);
            assert_eq!(observer.completed_workers.load(Ordering::Acquire), 2);
            assert_eq!(observer.cancelled_workers.load(Ordering::Acquire), 2);
            let remaining = descriptor_snapshot().expect("post-stop OS observation must succeed");
            for witness in observer.descriptors.lock().unwrap().iter() {
                assert_ne!(
                    remaining.get(&witness.fd).map(String::as_str),
                    Some(witness.identity.as_str()),
                    "the specific accepted/monitor FD identity must disappear"
                );
                assert!(
                    !remaining
                        .values()
                        .any(|identity| identity == &witness.identity),
                    "no duplicate of the accepted/monitor socket may remain"
                );
            }
            drop(clients);
            drop(TcpListener::bind(local).await.unwrap());
            eprintln!("descriptor cleanup dropFuture={drop_future} accepted=2 monitor=2 identitiesGone=4 permits=2/16 budget=0");
        }
    }
}
