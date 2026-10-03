//! hyper glue for the Storage surface: raw bodies (uploads), CORS for the browser SDK,
//! loopback-only origins.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use fireemu_adapter_support::connection::{DrainBounds, GracefulClose};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};

use crate::identity_toolkit::origin_is_local;
use crate::storage::{handle_framed_cancellable, GlobEvent, StorageRequest, StorageState};

/// Preserves the explicit zero length of an empty 204 without changing other body behavior.
struct StorageBody {
    inner: Full<Bytes>,
    pending_zero: bool,
}

impl StorageBody {
    fn new(bytes: Bytes) -> Self {
        Self {
            inner: Full::new(bytes),
            pending_zero: false,
        }
    }

    fn for_response(status: u16, headers: &[(String, String)], bytes: Bytes) -> Self {
        let mut lengths = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"));
        let pending_zero = status == 204
            && bytes.is_empty()
            && lengths.next().is_some_and(|(_, value)| value == "0")
            && lengths.next().is_none();
        Self {
            inner: Full::new(bytes),
            pending_zero,
        }
    }
}

impl Body for StorageBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.pending_zero {
            self.pending_zero = false;
            return std::task::Poll::Ready(Some(Ok(Frame::data(Bytes::new()))));
        }
        std::pin::Pin::new(&mut self.inner).poll_frame(context)
    }

    fn is_end_stream(&self) -> bool {
        // Hyper's None-body path suppresses explicit CL0 on 204; Known(0) preserves it.
        !self.pending_zero && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

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
    #[cfg(test)]
    publication_gate: WorkerPublicationGate,
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
    /// Handler completions after request-charge release; worker permits may still be held.
    pub completed_workers: AtomicUsize,
    pub closed_connections: AtomicUsize,
    /// A verification barrier retains worker permits after cancellation until released.
    pub hold_cancelled_workers: AtomicBool,
    cancelled_gate: (std::sync::Mutex<()>, std::sync::Condvar),
}

/// Retains a real worker after its response has been sent, without changing production APIs.
#[cfg(test)]
#[derive(Default)]
struct WorkerPublicationGate {
    handler_entries: AtomicUsize,
    panic_on_matcher: AtomicBool,
    hold_unwinding: AtomicBool,
    unwinding: AtomicUsize,
    unwind_budget: AtomicUsize,
    unwind_workers: AtomicUsize,
    unwind_general: AtomicUsize,
    joining_workers: AtomicUsize,
    receiver_disconnected: AtomicUsize,
    completion_budget: AtomicUsize,
    sent: AtomicUsize,
    hold: AtomicBool,
    gate: (std::sync::Mutex<()>, std::sync::Condvar),
}

#[cfg(test)]
impl WorkerPublicationGate {
    fn after_send(&self) {
        self.sent.fetch_add(1, Ordering::AcqRel);
        let mut guard = self
            .gate
            .0
            .lock()
            .expect("publication gate is not poisoned");
        while self.hold.load(Ordering::Acquire) {
            guard = self
                .gate
                .1
                .wait(guard)
                .expect("publication gate is not poisoned");
        }
    }

    fn release(&self) {
        let _guard = self
            .gate
            .0
            .lock()
            .expect("publication gate is not poisoned");
        self.hold.store(false, Ordering::Release);
        self.hold_unwinding.store(false, Ordering::Release);
        self.gate.1.notify_all();
    }
}

/// Records a real handler's unwind without imposing a release-before-response contract.
#[cfg(test)]
struct HandlerUnwindProbe<'a> {
    observer: &'a ServerObserver,
    budget: &'static BodyBudget,
}

#[cfg(test)]
impl Drop for HandlerUnwindProbe<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let gate = &self.observer.publication_gate;
        gate.unwind_budget
            .store(self.budget.in_flight(), Ordering::Release);
        gate.unwind_workers.store(
            self.observer.workers.load(Ordering::Acquire),
            Ordering::Release,
        );
        gate.unwind_general.store(
            self.observer.general_permits.load(Ordering::Acquire),
            Ordering::Release,
        );
        gate.unwinding.fetch_add(1, Ordering::AcqRel);
        let mut guard = gate.gate.0.lock().expect("unwind gate is not poisoned");
        while gate.hold_unwinding.load(Ordering::Acquire) {
            guard = gate
                .gate
                .1
                .wait(guard)
                .expect("unwind gate is not poisoned");
        }
    }
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
        .body(StorageBody::new(Bytes::from_static(message)))
        .unwrap_or_else(|_| Response::new(StorageBody::new(Bytes::new())))
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
        .body(StorageBody::new(Bytes::from_static(message)))
        .unwrap_or_else(|_| Response::new(StorageBody::new(Bytes::new())))
}

#[allow(clippy::too_many_lines)]
async fn respond(
    state: Arc<StorageState>,
    budget: &'static BodyBudget,
    req: Request<Incoming>,
    runtime: Arc<Runtime>,
    connection: Arc<Cancellation>,
) -> Result<Response<StorageBody>, std::io::Error> {
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
            .body(StorageBody::new(Bytes::from_static(b"forbidden origin")))
            .unwrap_or_else(|_| Response::new(StorageBody::new(Bytes::new()))));
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
            .body(StorageBody::new(Bytes::new()))
            .unwrap_or_else(|_| Response::new(StorageBody::new(Bytes::new()))));
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
        #[cfg(test)]
        let _unwind = HandlerUnwindProbe { observer, budget };
        let matching = std::cell::RefCell::new(None);
        #[cfg(test)]
        observer
            .publication_gate
            .handler_entries
            .fetch_add(1, Ordering::AcqRel);
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
                    #[cfg(test)]
                    if observer
                        .publication_gate
                        .panic_on_matcher
                        .load(Ordering::Acquire)
                    {
                        panic!("test-only Storage handler panic inside matcher primitive");
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
        // The handler has consumed the bytes; return the request charge before publishing its result.
        drop(buffer);
        #[cfg(test)]
        observer
            .publication_gate
            .completion_budget
            .store(budget.in_flight(), Ordering::Release);
        observer.completed_workers.fetch_add(1, Ordering::AcqRel);
        let _ = sender.send(response);
        #[cfg(test)]
        observer.publication_gate.after_send();
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
            #[cfg(test)]
            runtime
                .observer
                .publication_gate
                .receiver_disconnected
                .fetch_add(1, Ordering::AcqRel);
            return Ok(handler_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                b"storage handler failed",
                origin.as_deref(),
                false,
            ));
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
    let body = StorageBody::for_response(response.status, &response.headers, response.body);
    for (k, v) in response.headers {
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
            .body(StorageBody::new(Bytes::from_static(
                b"internal error building response",
            )))
            .unwrap_or_else(|_| Response::new(StorageBody::new(Bytes::new())))),
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
    #[cfg(test)]
    runtime
        .observer
        .publication_gate
        .joining_workers
        .store(jobs.len(), Ordering::Release);
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

    pub(super) fn state() -> Arc<StorageState> {
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

#[cfg(all(test, any(target_os = "macos", target_os = "linux")))]
mod budget_publication_tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::time::{Duration, Instant};

    struct Cleanup<'a> {
        runtime: &'a tokio::runtime::Runtime,
        observer: Arc<ServerObserver>,
        stop: Option<tokio::sync::oneshot::Sender<()>>,
        server: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    }
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            self.observer.release_cancelled_workers();
            self.observer.publication_gate.release();
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(server) = self.server.take() {
                self.runtime.block_on(async {
                    let _ = server.await;
                });
            }
        }
    }

    fn observed(label: &str, predicate: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !predicate() {
            assert!(
                Instant::now() < deadline,
                "observation did not settle: {label}"
            );
            std::thread::yield_now();
        }
    }

    fn check_stored_upload(state: &StorageState, status: u16, body_bytes: usize) {
        use fireemu_core_storage::name::{BucketName, ObjectName};
        let store = state.store.lock().unwrap();
        let metadata = store.get(
            &BucketName::try_new("demo-app.appspot.com").unwrap(),
            &ObjectName::try_new(format!("budget-{status}")).unwrap(),
        );
        if status == 200 {
            let bytes = store.bytes(metadata.expect("successful upload remains stored"));
            assert_eq!(bytes.len(), body_bytes);
            assert!(bytes.iter().all(|byte| *byte == 7));
        } else {
            assert!(metadata.is_none(), "a rejected checksum stores no object");
        }
    }

    fn check_upload_response(client: &mut std::net::TcpStream, status: u16) {
        let mut response = [0; 4096];
        let received = client.read(&mut response).unwrap();
        assert!(
            response[..received].starts_with(format!("HTTP/1.1 {status}").as_bytes()),
            "{}",
            String::from_utf8_lossy(&response[..received])
        );
    }

    fn start_charged_matcher<'a>(
        runtime: &'a tokio::runtime::Runtime,
        budget: &'static BodyBudget,
        observer: Arc<ServerObserver>,
    ) -> (Cleanup<'a>, std::net::TcpStream) {
        let port = std::env::var("PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(0);
        let listener = runtime
            .block_on(TcpListener::bind(("127.0.0.1", port)))
            .unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = runtime.spawn(serve_storage_with_shutdown(
            listener,
            super::descriptor_tests::state(),
            budget,
            async {
                let _ = stopped.await;
            },
            observer.clone(),
        ));
        let cleanup = Cleanup {
            runtime,
            observer,
            stop: Some(stop),
            server: Some(server),
        };
        let mut client = std::net::TcpStream::connect(address).unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let pattern = "*{,}".repeat(15_000) + "z";
        write!(client, "GET /storage/v1/b/demo-app.appspot.com/o?matchGlob={pattern} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer owner\r\nContent-Length: {CHARGE_GRANULARITY}\r\nConnection: close\r\n\r\n").unwrap();
        client.write_all(&vec![7; CHARGE_GRANULARITY]).unwrap();
        (cleanup, client)
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn charged_cancellation_retains_charge_through_observer_then_joins_worker() {
        static BUDGET: BodyBudget = BodyBudget::new(4 * CHARGE_GRANULARITY);
        let runtime = runtime();
        let observer = Arc::new(ServerObserver::default());
        observer
            .hold_cancelled_workers
            .store(true, Ordering::Release);
        observer
            .publication_gate
            .hold
            .store(true, Ordering::Release);
        let (mut cleanup, client) = start_charged_matcher(&runtime, &BUDGET, observer.clone());
        observed("charged request reached matcher primitives", || {
            observer.state_polls.load(Ordering::Acquire) > 0
        });
        assert_eq!(BUDGET.in_flight(), CHARGE_GRANULARITY);
        client.shutdown(std::net::Shutdown::Write).unwrap();
        observed("cancel observer holds the charged body", || {
            observer.cancelled_workers.load(Ordering::Acquire) == 1
        });
        assert_eq!(BUDGET.in_flight(), CHARGE_GRANULARITY);
        assert_eq!(observer.completed_workers.load(Ordering::Acquire), 0);
        assert_eq!(observer.publication_gate.sent.load(Ordering::Acquire), 0);
        assert_eq!(observer.workers.load(Ordering::Acquire), 1);
        assert_eq!(observer.general_permits.load(Ordering::Acquire), 1);
        assert_eq!(observer.active_globs.load(Ordering::Acquire), 1);
        observer.release_cancelled_workers();
        observed("cancel result sent while worker retained", || {
            observer.publication_gate.sent.load(Ordering::Acquire) == 1
        });
        assert_eq!(BUDGET.in_flight(), 0);
        assert_eq!(
            observer
                .publication_gate
                .completion_budget
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(observer.completed_workers.load(Ordering::Acquire), 1);
        assert_eq!(observer.workers.load(Ordering::Acquire), 1);
        assert_eq!(observer.general_permits.load(Ordering::Acquire), 1);
        assert_eq!(observer.active_globs.load(Ordering::Acquire), 1);
        assert_eq!(ServerObserver::free_permits(), (1, 15));
        cleanup.stop.take().unwrap().send(()).unwrap();
        observed("shutdown reached its registered worker join", || {
            observer
                .publication_gate
                .joining_workers
                .load(Ordering::Acquire)
                == 1
        });
        assert!(
            !cleanup.server.as_ref().unwrap().is_finished(),
            "held worker keeps shutdown pending"
        );
        drop(client);
        drop(cleanup);
        assert_eq!(BUDGET.in_flight(), 0);
        assert_eq!(observer.workers.load(Ordering::Acquire), 0);
        assert_eq!(ServerObserver::free_permits(), (2, 16));
        eprintln!("charged cancel bodyBytes={CHARGE_GRANULARITY} observerChargeHeld=1 completionCharge=0 workerPermitsHeld=1 shutdownJoined=1 finalPermits=2/16 budget=0");
    }

    #[test]
    fn charged_handler_panic_unwinds_without_completion_and_returns_500() {
        static BUDGET: BodyBudget = BodyBudget::new(4 * CHARGE_GRANULARITY);
        let runtime = runtime();
        let observer = Arc::new(ServerObserver::default());
        observer
            .publication_gate
            .panic_on_matcher
            .store(true, Ordering::Release);
        observer
            .publication_gate
            .hold_unwinding
            .store(true, Ordering::Release);
        let (cleanup, mut client) = start_charged_matcher(&runtime, &BUDGET, observer.clone());
        observed("real handler unwind probe", || {
            observer.publication_gate.unwinding.load(Ordering::Acquire) == 1
        });
        assert!(observer.state_polls.load(Ordering::Acquire) > 0);
        assert_eq!(observer.completed_workers.load(Ordering::Acquire), 0);
        eprintln!(
            "panic unwind snapshot charge={} workers={} generalPermits={}",
            observer
                .publication_gate
                .unwind_budget
                .load(Ordering::Acquire),
            observer
                .publication_gate
                .unwind_workers
                .load(Ordering::Acquire),
            observer
                .publication_gate
                .unwind_general
                .load(Ordering::Acquire)
        );
        observer.publication_gate.release();
        check_upload_response(&mut client, 500);
        observed("receiver observed worker sender disconnection", || {
            observer
                .publication_gate
                .receiver_disconnected
                .load(Ordering::Acquire)
                == 1
        });
        assert_eq!(observer.completed_workers.load(Ordering::Acquire), 0);
        assert_eq!(observer.publication_gate.sent.load(Ordering::Acquire), 0);
        eprintln!(
            "panic HTTP500 snapshot charge={} workers={} generalPermits={}",
            BUDGET.in_flight(),
            observer.workers.load(Ordering::Acquire),
            observer.general_permits.load(Ordering::Acquire)
        );
        drop(client);
        drop(cleanup);
        assert_eq!(
            observer
                .publication_gate
                .joining_workers
                .load(Ordering::Acquire),
            1
        );
        assert_eq!(observer.completed_workers.load(Ordering::Acquire), 0);
        assert_eq!(observer.workers.load(Ordering::Acquire), 0);
        assert_eq!(observer.general_permits.load(Ordering::Acquire), 0);
        assert_eq!(BUDGET.in_flight(), 0);
        assert_eq!(ServerObserver::free_permits(), (2, 16));
        eprintln!("charged handler panic bodyBytes={CHARGE_GRANULARITY} oneshotDisconnected=1 HTTP=500 completed=0 shutdownJoined=1 finalPermits=2/16 budget=0");
    }

    /// A received response must release its body charge while the worker still owns permits.
    #[test]
    fn finished_upload_releases_budget_before_response_with_worker_still_running() {
        static BUDGET: BodyBudget = BodyBudget::new(32 * 1024 * 1024);
        const BODY_BYTES: usize = 8 * 1024 * 1024;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        for status in [200, 400] {
            let state = super::descriptor_tests::state();
            let observer = Arc::new(ServerObserver::default());
            observer
                .publication_gate
                .hold
                .store(true, Ordering::Release);
            let port = std::env::var("PORT")
                .ok()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(0);
            let listener = runtime
                .block_on(TcpListener::bind(("127.0.0.1", port)))
                .unwrap();
            let address = listener.local_addr().unwrap();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let server = runtime.spawn(serve_storage_with_shutdown(
                listener,
                state.clone(),
                &BUDGET,
                async {
                    let _ = stopped.await;
                },
                observer.clone(),
            ));
            let cleanup = Cleanup {
                runtime: &runtime,
                observer: observer.clone(),
                stop: Some(stop),
                server: Some(server),
            };
            // A failed assertion unwinds this guard before Cleanup joins the blocked handler.
            let store_guard = state.store.lock().unwrap();
            let mut client = std::net::TcpStream::connect(address).unwrap();
            client
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let checksum = if status == 400 {
                "x-goog-hash: crc32c=AAAAAA==\r\n"
            } else {
                ""
            };
            write!(client, "POST /upload/storage/v1/b/demo-app.appspot.com/o?uploadType=media&name=budget-{status} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer owner\r\nContent-Type: application/octet-stream\r\nContent-Length: {BODY_BYTES}\r\nConnection: close\r\n{checksum}\r\n").unwrap();
            client.write_all(&vec![7; BODY_BYTES]).unwrap();
            observed("handler entered with its body", || {
                observer
                    .publication_gate
                    .handler_entries
                    .load(Ordering::Acquire)
                    == 1
            });
            // A successful upload waits at this store lock; a checksum rejection may finish earlier.
            if status == 200 {
                assert_eq!(
                    BUDGET.in_flight(),
                    BODY_BYTES,
                    "the body charge must survive through the handler"
                );
            }
            drop(store_guard);
            check_upload_response(&mut client, status);
            observed("worker held after response publication", || {
                observer.publication_gate.sent.load(Ordering::Acquire) == 1
            });
            assert_eq!(observer.workers.load(Ordering::Acquire), 1);
            assert_eq!(observer.general_permits.load(Ordering::Acquire), 1);
            assert_eq!(observer.completed_workers.load(Ordering::Acquire), 1);
            assert_eq!(
                BUDGET.in_flight(),
                0,
                "a published response must not retain its request charge"
            );
            assert_eq!(
                observer
                    .publication_gate
                    .completion_budget
                    .load(Ordering::Acquire),
                0,
                "completion notification must follow request-charge release"
            );
            check_stored_upload(&state, status, BODY_BYTES);
            drop(client);
            drop(cleanup);
            assert_eq!(BUDGET.in_flight(), 0);
            assert_eq!(ServerObserver::free_permits(), (2, 16));
            eprintln!("response budget status={status} handlerCharge={BODY_BYTES} postSendWorkerHeld=1 charge=0 permitsRetained=1 finalPermits=2/16");
        }
    }
}

#[cfg(test)]
mod budget_lifecycle_model_tests {
    use super::*;
    use proptest::prelude::*;

    const REQUESTS: usize = 4;
    const LIMIT_UNITS: usize = 3;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum Phase {
        Fresh,
        Reserved,
        Handling,
        Released,
        Published,
        Cancelled,
        Failed,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct Request {
        phase: Phase,
        units: u8,
        releases: u8,
    }
    impl Default for Request {
        fn default() -> Self {
            Self {
                phase: Phase::Fresh,
                units: 0,
                releases: 0,
            }
        }
    }
    type State = [Request; REQUESTS];

    #[derive(Clone, Copy, Debug)]
    enum Action {
        Reserve(u8),
        Handler,
        Release,
        Publish,
        Cancel,
        Error,
    }

    fn action(number: u8) -> Action {
        match number {
            0 => Action::Reserve(1),
            1 => Action::Reserve(2),
            2 => Action::Handler,
            3 => Action::Release,
            4 => Action::Publish,
            5 => Action::Cancel,
            _ => Action::Error,
        }
    }

    fn total(state: &State) -> usize {
        state.iter().map(|request| usize::from(request.units)).sum()
    }

    fn release(request: &mut Request) {
        if request.units > 0 {
            request.releases += 1;
            request.units = 0;
        }
    }

    /// The reference protocol has independent phases and charges, so early publication violates it.
    fn step(mut state: State, id: usize, action: Action) -> State {
        let before = state[id];
        match action {
            Action::Reserve(units) if matches!(before.phase, Phase::Fresh | Phase::Reserved) => {
                let target = units.max(before.units);
                if total(&state) - usize::from(before.units) + usize::from(target) <= LIMIT_UNITS {
                    state[id].units = target;
                    state[id].phase = Phase::Reserved;
                } else {
                    release(&mut state[id]);
                    state[id].phase = Phase::Failed;
                }
            }
            Action::Handler if before.phase == Phase::Reserved => state[id].phase = Phase::Handling,
            Action::Release if before.phase == Phase::Handling => {
                release(&mut state[id]);
                state[id].phase = Phase::Released;
            }
            Action::Publish if matches!(before.phase, Phase::Released | Phase::Failed) => {
                state[id].phase = Phase::Published;
            }
            Action::Cancel | Action::Error
                if matches!(
                    before.phase,
                    Phase::Fresh | Phase::Reserved | Phase::Handling | Phase::Released
                ) =>
            {
                release(&mut state[id]);
                state[id].phase = if matches!(action, Action::Cancel) {
                    Phase::Cancelled
                } else {
                    Phase::Failed
                };
            }
            _ => {}
        }
        state
    }

    fn valid(state: &State) -> bool {
        total(state) <= LIMIT_UNITS
            && state.iter().all(|request| {
                request.units <= 2
                    && request.releases <= 1
                    && if matches!(request.phase, Phase::Reserved | Phase::Handling) {
                        request.units > 0 && request.releases == 0
                    } else {
                        request.units == 0
                    }
            })
    }

    /// Exhausts every enabled ordering for four requests and all seven lifecycle actions.
    #[test]
    fn budget_lifecycle_model_checks_all_four_request_interleavings() {
        let initial = [Request::default(); REQUESTS];
        let mut visited = std::collections::HashSet::from([initial]);
        let mut pending = std::collections::VecDeque::from([initial]);
        let mut edges = 0usize;
        while let Some(state) = pending.pop_front() {
            assert!(valid(&state), "invalid ownership state: {state:?}");
            for id in 0..REQUESTS {
                for number in 0..7 {
                    let next = step(state, id, action(number));
                    edges += 1;
                    assert!(valid(&next), "{state:?} -- {id}/{number} --> {next:?}");
                    assert!(next
                        .iter()
                        .zip(state)
                        .all(|(after, before)| after.releases >= before.releases));
                    if visited.insert(next) {
                        pending.push_back(next);
                    }
                }
            }
        }
        assert!(
            visited.len() > 1_000,
            "the checker must explore interleavings, not a single trace"
        );
        eprintln!("budget finite model requests={REQUESTS} limitUnits={LIMIT_UNITS} states={} edges={edges} publicationCharged=0 doubleRelease=0", visited.len());
    }

    #[test]
    fn budget_lifecycle_model_rejects_publication_before_release() {
        let state = step(
            step([Request::default(); REQUESTS], 0, Action::Reserve(1)),
            0,
            Action::Handler,
        );
        assert_eq!(
            step(state, 0, Action::Publish),
            state,
            "publication before release is not enabled"
        );
        let mut broken = state;
        broken[0].phase = Phase::Published;
        assert!(
            !valid(&broken),
            "the charged-publication negative control must fail"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        /// Exercises the real budget owner against the reference lifecycle, including failed reserves.
        #[test]
        fn actual_body_budget_follows_four_request_lifecycle(
            actions in prop::collection::vec((0usize..REQUESTS, 0u8..7), 1..160)
        ) {
            static BUDGET: BodyBudget = BodyBudget::new(LIMIT_UNITS * CHARGE_GRANULARITY);
            prop_assert_eq!(BUDGET.in_flight(), 0);
            let mut state = [Request::default(); REQUESTS];
            let mut owners: [Option<BudgetedBody>; REQUESTS] = std::array::from_fn(|_| None);
            let mut moved: [Option<Vec<u8>>; REQUESTS] = std::array::from_fn(|_| None);
            for (id, number) in actions {
                let operation = action(number);
                let before = state[id];
                let next = step(state, id, operation);
                match operation {
                    Action::Reserve(units) if matches!(before.phase, Phase::Fresh | Phase::Reserved) => {
                        let owner = owners[id].get_or_insert_with(|| BudgetedBody::new(&BUDGET, 2 * CHARGE_GRANULARITY));
                        let result = owner.reserve_declared(usize::from(units) * CHARGE_GRANULARITY);
                        if next[id].phase == Phase::Failed {
                            prop_assert_eq!(result, Err(BodyError::BudgetExhausted));
                            drop(owners[id].take());
                        } else {
                            prop_assert_eq!(result, Ok(()));
                            if before.phase == Phase::Fresh { owner.extend(&[u8::try_from(id).unwrap()]).unwrap(); }
                            prop_assert_eq!(owner.charged, usize::from(next[id].units) * CHARGE_GRANULARITY);
                        }
                    }
                    Action::Handler if before.phase == Phase::Reserved => {
                        let owner = owners[id].as_mut().unwrap();
                        moved[id] = Some(owner.take());
                        prop_assert_eq!(owner.charged, usize::from(before.units) * CHARGE_GRANULARITY);
                    }
                    Action::Release if before.phase == Phase::Handling => { drop(owners[id].take()); }
                    Action::Cancel | Action::Error if matches!(before.phase,
                        Phase::Fresh | Phase::Reserved | Phase::Handling | Phase::Released) => { drop(owners[id].take()); }
                    Action::Publish if next[id].phase == Phase::Published => {
                        prop_assert!(owners[id].is_none(), "publication must have no live request charge owner");
                    }
                    _ => {}
                }
                state = next;
                prop_assert!(valid(&state));
                prop_assert_eq!(BUDGET.in_flight(), total(&state) * CHARGE_GRANULARITY);
                for index in 0..REQUESTS {
                    prop_assert_eq!(owners[index].as_ref().map_or(0, |owner| owner.charged),
                        usize::from(state[index].units) * CHARGE_GRANULARITY);
                    if let Some(bytes) = &moved[index] {
                        prop_assert_eq!(bytes.as_slice(), &[u8::try_from(index).unwrap()], "charge release must preserve transferred bytes");
                    }
                }
            }
            drop(owners);
            prop_assert_eq!(BUDGET.in_flight(), 0);
        }
    }
}

#[cfg(test)]
mod storage_body_tests {
    use super::*;
    use proptest::prelude::*;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    fn headers(kind: u8) -> Vec<(String, String)> {
        match kind {
            0 => Vec::new(),
            1 => vec![("content-length".into(), "0".into())],
            2 => vec![("Content-Length".into(), "0".into())],
            3 => vec![
                ("content-length".into(), "0".into()),
                ("Content-Length".into(), "0".into()),
            ],
            4 => vec![("content-length".into(), "1".into())],
            5 => vec![("content-length".into(), "00".into())],
            6 => vec![("content-length".into(), " 0".into())],
            _ => vec![("content-length".into(), "bad".into())],
        }
    }

    fn next(
        body: &mut (impl Body<Data = Bytes, Error = std::convert::Infallible> + Unpin),
    ) -> Option<Bytes> {
        let mut context = Context::from_waker(Waker::noop());
        match Pin::new(body).poll_frame(&mut context) {
            Poll::Ready(frame) => frame.map(|frame| frame.unwrap().into_data().unwrap()),
            Poll::Pending => panic!("a full body must be ready"),
        }
    }

    fn check_traits(status: u16, kind: u8, bytes: Bytes) {
        let marked = status == 204 && bytes.is_empty() && matches!(kind, 1 | 2);
        let mut wrapped = StorageBody::for_response(status, &headers(kind), bytes.clone());
        let mut reference = Full::new(bytes);
        assert_eq!(
            wrapped.is_end_stream(),
            !marked && reference.is_end_stream()
        );
        assert_eq!(wrapped.size_hint().lower(), reference.size_hint().lower());
        assert_eq!(wrapped.size_hint().upper(), reference.size_hint().upper());
        if marked {
            assert_eq!(next(&mut wrapped), Some(Bytes::new()));
        } else {
            assert_eq!(next(&mut wrapped), next(&mut reference));
        }
        assert!(wrapped.is_end_stream());
        assert_eq!(next(&mut wrapped), None);
        assert_eq!(wrapped.size_hint().exact(), Some(0));
    }

    #[test]
    fn body_marker_scope_and_frame_lifecycle_are_finite() {
        let mut inputs = 0;
        for status in [200, 204, 304, 308, 400, 499, 500] {
            for kind in 0..8 {
                for bytes in [
                    Bytes::new(),
                    Bytes::from_static(b"x"),
                    Bytes::from_static(b"abc"),
                ] {
                    check_traits(status, kind, bytes);
                    inputs += 1;
                }
            }
        }
        assert_eq!(inputs, 168);
        eprintln!("body marker finite inputs=168 zeroFrameBytes=0 otherFramesMatchFull=1");
    }

    struct EncodingTask(Option<tokio::task::JoinHandle<()>>);
    impl Drop for EncodingTask {
        fn drop(&mut self) {
            if let Some(task) = self.0.take() {
                task.abort();
            }
        }
    }

    async fn encode<B>(
        status: u16,
        fields: Vec<(String, String)>,
        body: B,
    ) -> (Vec<u8>, Option<std::io::ErrorKind>, bool)
    where
        B: Body<Data = Bytes, Error = std::convert::Infallible> + Send + Unpin + 'static,
    {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let port = std::env::var("PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(0);
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut response = Response::builder().status(status);
        for (name, value) in fields {
            response = response.header(name, value);
        }
        let response = std::sync::Mutex::new(Some(response.body(body).unwrap()));
        let mut task = EncodingTask(Some(tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(move |_| {
                std::future::ready(Ok::<_, std::convert::Infallible>(
                    response.lock().unwrap().take().unwrap(),
                ))
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        })));
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut raw = Vec::new();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut raw),
        )
        .await
        .unwrap();
        let panicked = task
            .0
            .take()
            .unwrap()
            .await
            .err()
            .is_some_and(|error| error.is_panic());
        (raw, result.err().map(|error| error.kind()), panicked)
    }

    fn framing(raw: &[u8]) -> (String, Vec<String>, Vec<u8>) {
        let Some(split) = raw.windows(4).position(|part| part == b"\r\n\r\n") else {
            return (String::new(), Vec::new(), raw.to_vec());
        };
        let head = std::str::from_utf8(&raw[..split]).unwrap();
        let mut lines = head.split("\r\n");
        let status = lines.next().unwrap().to_owned();
        let fields = lines
            .filter(|line| {
                line.starts_with("content-length:") || line.starts_with("transfer-encoding:")
            })
            .map(str::to_owned)
            .collect();
        (status, fields, raw[split + 4..].to_vec())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]
        #[test]
        fn body_marker_traits_and_real_encoder_match_the_closed_scope(
            status in prop::sample::select(vec![200u16,204,304,308,400,499,500]), kind in 0u8..8,
            payload in prop_oneof![3 => Just(Vec::new()), 1 => prop::collection::vec(any::<u8>(), 1..64)]
        ) {
            let bytes = Bytes::from(payload); check_traits(status, kind, bytes.clone());
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let actual = runtime.block_on(encode(status, headers(kind), StorageBody::for_response(status, &headers(kind), bytes.clone())));
            if status == 204 && bytes.is_empty() && matches!(kind, 1 | 2) {
                let (line, fields, body) = framing(&actual.0);
                prop_assert!(line.starts_with("HTTP/1.1 204"));
                prop_assert_eq!(fields, vec!["content-length: 0"]);
                prop_assert!(body.is_empty()); prop_assert!(actual.1.is_none());
            } else {
                let reference = runtime.block_on(encode(status, headers(kind), Full::new(bytes)));
                prop_assert_eq!(framing(&actual.0), framing(&reference.0));
                prop_assert_eq!(actual.1, reference.1);
                prop_assert_eq!(actual.2, reference.2);
            }
        }
    }
}
