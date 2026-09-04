//! The functions HTTP port: `http://HOST:PORT/{project}/{region}/{function}[/path]` is
//! proxied to the runner's HTTP server, which hosts `onRequest` / `onCall` handlers. The
//! proxy speaks plain HTTP/1.1 with `Connection: close` (one request per connection).

use std::convert::Infallible;
use std::future::Future as _;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::fmt::Write as _;

pub use fireemu_core_session::loopback::origin_is_local;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio_stream::{Stream, StreamExt as _};

use crate::runtime::FunctionsRuntime;

/// Maximum request body forwarded to a function.
pub const MAX_FUNCTION_BODY_BYTES: usize = 32 * 1024 * 1024;
/// Express' default JSON limit used by the pinned Cloud Tasks emulator.
pub const MAX_TASK_BODY_BYTES: usize = 100 * 1024;
/// Maximum response body accepted from a function (responses are buffered).
pub const MAX_FUNCTION_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
/// Production's maximum streamed response size for a second-generation function.
pub const MAX_STREAMING_FUNCTION_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;
const MAX_FUNCTION_CONNECTIONS: usize = 128;
const MAX_CONCURRENT_BODY_READS: usize = 64;
const MAX_RESERVED_BODY_BYTES: usize = 64 * 1024 * 1024;
const REQUEST_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type OutBody = UnsyncBoxBody<Bytes, BoxError>;

fn full(bytes: Bytes) -> OutBody {
    Full::new(bytes)
        .map_err(|error: Infallible| match error {})
        .boxed_unsync()
}

#[derive(Clone)]
struct RequestAdmission {
    requests: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
}

struct RequestPermit {
    _request: OwnedSemaphorePermit,
    _bytes: OwnedSemaphorePermit,
}

impl RequestAdmission {
    fn new() -> Self {
        Self::with_limits(MAX_CONCURRENT_BODY_READS, MAX_RESERVED_BODY_BYTES)
    }

    fn with_limits(requests: usize, bytes: usize) -> Self {
        Self {
            requests: Arc::new(Semaphore::new(requests)),
            bytes: Arc::new(Semaphore::new(bytes)),
        }
    }

    async fn acquire(&self, bytes: usize) -> RequestPermit {
        let request = self
            .requests
            .clone()
            .acquire_owned()
            .await
            .expect("the request admission semaphore is never closed");
        let bytes = self
            .bytes
            .clone()
            .acquire_many_owned(
                u32::try_from(bytes).expect("request body limits fit in semaphore permits"),
            )
            .await
            .expect("the request byte semaphore is never closed");
        RequestPermit {
            _request: request,
            _bytes: bytes,
        }
    }
}

fn request_body_limit(path: &str) -> usize {
    if crate::tasks::route(path).is_some() {
        MAX_TASK_BODY_BYTES
    } else {
        MAX_FUNCTION_BODY_BYTES
    }
}

fn request_body_reservation(req: &Request<Incoming>, limit: usize) -> usize {
    let lengths = req.headers().get_all(hyper::header::CONTENT_LENGTH);
    let mut values = lengths.iter();
    let declared = values
        .next()
        .filter(|_| values.next().is_none())
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    // A chunked or otherwise unknown-length body reserves the full route limit. A framed
    // Content-Length cannot deliver more bytes than declared; one permit still bounds an
    // empty request by the concurrent-request ceiling.
    declared.map_or(limit, |bytes| bytes.min(limit).max(1))
}

fn simple(status: StatusCode, text: &str) -> Response<OutBody> {
    typed(status, "text/plain; charset=utf-8", text)
}

/// A plain body with an explicit content type.
///
/// The two 404s the functions port answers carry different ones, because the official
/// emulator produces them two different ways: `res.sendStatus(404)` sends the status text as
/// `text/plain`, and `res.status(404).send("Function ... does not exist ...")` sends a string,
/// which express types as `text/html`.
fn typed(status: StatusCode, content_type: &str, text: &str) -> Response<OutBody> {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(full(Bytes::from(text.to_owned())))
        .unwrap_or_else(|_| Response::new(full(Bytes::new())))
}

fn with_local_cors(mut response: Response<OutBody>, origin: Option<&str>) -> Response<OutBody> {
    let Some(origin) = origin.and_then(|value| hyper::header::HeaderValue::from_str(value).ok())
    else {
        return response;
    };
    response
        .headers_mut()
        .insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    response.headers_mut().insert(
        hyper::header::VARY,
        hyper::header::HeaderValue::from_static("Origin"),
    );
    response
}

/// Encodes a daemon-side callable refusal the same way the v2 SDK wrapper answers a
/// streaming request. The wrapper writes one SSE record without replacing the response's
/// default `200` status, even when token admission fails before the handler starts.
fn streaming_callable_refusal() -> Response<OutBody> {
    let response = crate::callable::unauthenticated_response();
    let mut body = Vec::with_capacity("data: ".len() + response.body.len() + 2);
    body.extend_from_slice(b"data: ");
    body.extend_from_slice(&response.body);
    body.extend_from_slice(b"\n\n");
    Response::new(full(Bytes::from(body)))
}

fn callable_credential_refusal(
    denial: Response<OutBody>,
    streaming: bool,
    origin: Option<&str>,
) -> Response<OutBody> {
    with_local_cors(
        if streaming {
            streaming_callable_refusal()
        } else {
            denial
        },
        origin,
    )
}

fn http_trigger_kinds(runtime: &FunctionsRuntime, function: &str) -> (bool, bool, bool) {
    let entry = runtime.manifest().get(function);
    let trigger = entry.map(|entry| &entry.trigger);
    let callable = matches!(
        trigger,
        Some(fireemu_core_functions::manifest::Trigger::Http { callable: true, .. })
    );
    (
        callable,
        matches!(
            trigger,
            Some(fireemu_core_functions::manifest::Trigger::Http {
                callable: false,
                ..
            })
        ),
        callable
            && entry.is_some_and(|entry| {
                entry.generation == fireemu_core_functions::manifest::FunctionGeneration::Second
            }),
    )
}

fn accepts_callable_stream(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        == Some("text/event-stream")
}

fn local_request_origin(headers: &hyper::HeaderMap) -> Result<Option<String>, Refusal> {
    let origins = field_values(headers, "origin");
    if origins.len() > 1
        || origins
            .first()
            .is_some_and(|origin| !origin_is_local(origin))
    {
        return Err(Box::new(simple(StatusCode::FORBIDDEN, "forbidden origin")));
    }
    Ok(origins.into_iter().next())
}

/// A forwarded response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxiedResponse {
    /// Status.
    pub status: u16,
    /// Headers (hop-by-hop ones removed).
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

/// A runner response whose bytes are forwarded as they arrive.
pub struct ProxiedStreamResponse {
    /// Status received before streaming starts.
    pub status: u16,
    /// Headers with hop-by-hop framing removed.
    pub headers: Vec<(String, String)>,
    /// A bounded, backpressured sequence of response bytes.
    pub body: mpsc::Receiver<Bytes>,
    /// A terminal error channel independent of body backpressure.
    pub terminal: oneshot::Receiver<Result<(), std::io::Error>>,
}

struct StreamResponseBody {
    body: mpsc::Receiver<Bytes>,
    terminal: Option<oneshot::Receiver<Result<(), std::io::Error>>>,
    failed: bool,
}

impl Stream for StreamResponseBody {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(None);
        }
        if let Some(terminal) = &mut this.terminal {
            match Pin::new(terminal).poll(cx) {
                Poll::Ready(Ok(Ok(()))) => this.terminal = None,
                Poll::Ready(Ok(Err(error))) => {
                    this.terminal = None;
                    this.failed = true;
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Err(_)) => {
                    this.terminal = None;
                    this.failed = true;
                    return Poll::Ready(Some(Err(std::io::Error::other(
                        "function stream pump stopped",
                    ))));
                }
                Poll::Pending => {}
            }
        }
        match this.body.poll_recv(cx) {
            Poll::Ready(None) if this.terminal.is_some() => Poll::Pending,
            result => result.map(|item| item.map(Ok)),
        }
    }
}

/// A public stream plus the private lifecycle signal its runtime must retain.
pub struct StartedStream {
    /// Status, headers and body forwarded to the caller.
    pub response: ProxiedStreamResponse,
    /// Terminal state used by the runtime to retain admission and record one outcome.
    pub completion: oneshot::Receiver<StreamCompletion>,
}

/// How a streaming runner response ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamCompletion {
    /// The runner completed the response normally.
    Complete,
    /// The public client stopped consuming the response.
    ClientGone,
    /// The function deadline elapsed after response headers were sent.
    TimedOut,
    /// The cumulative streamed response exceeded the production limit.
    TooLarge,
    /// The runner connection failed while streaming.
    Upstream(String),
}

/// Failure before response headers are available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamStartError {
    /// The function deadline elapsed before the first response headers.
    TimedOut,
    /// The runner could not be reached or returned invalid HTTP.
    Upstream(String),
}

/// Sends one HTTP/1.1 request to `addr` and reads the whole response.
pub async fn forward(
    addr: &str,
    method: &str,
    path_and_query: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<ProxiedResponse, String> {
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("cannot reach the functions runner at {addr}: {e}"))?;
    let mut req = format!("{method} {path_and_query} HTTP/1.1\r\n");
    let mut has_host = false;
    let connection_named = connection_tokens(headers.iter().filter_map(|(name, value)| {
        name.eq_ignore_ascii_case("connection")
            .then_some(value.as_str())
    }))?;
    for (k, v) in headers {
        // This writer frames the request by hand. Everything it is handed today comes from
        // hyper, which already refuses a control character in a field name or value, but the
        // check belongs at the sink: a future caller that builds a field from anywhere else
        // would otherwise turn one header into request smuggling.
        if !is_framable_name(k) || !is_framable_value(v) {
            return Err(format!("refusing to forward the unframable header {k:?}"));
        }
        if is_hop_by_hop(k, &connection_named)
            || k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("expect")
        {
            continue;
        }
        if k.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        let _ = write!(req, "{k}: {v}\r\n");
    }
    if !has_host {
        let _ = write!(req, "host: {addr}\r\n");
    }
    let _ = write!(
        req,
        "content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(body).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream
        .take(MAX_FUNCTION_RESPONSE_BYTES + 1)
        .read_to_end(&mut raw)
        .await
        .map_err(|e| format!("reading the runner's response: {e}"))?;
    if raw.len() as u64 > MAX_FUNCTION_RESPONSE_BYTES {
        return Err(format!(
            "function response exceeds {MAX_FUNCTION_RESPONSE_BYTES} bytes"
        ));
    }
    parse_response(&raw, method)
}

async fn before_stream_deadline<T>(
    deadline: Option<tokio::time::Instant>,
    future: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, StreamStartError> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| StreamStartError::TimedOut)?
            .map_err(StreamStartError::Upstream),
        None => future.await.map_err(StreamStartError::Upstream),
    }
}

fn connection_tokens<'a>(values: impl Iterator<Item = &'a str>) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    for value in values {
        for token in value.split(',').map(str::trim) {
            if !is_framable_name(token) {
                return Err("invalid Connection header".to_owned());
            }
            tokens.push(token.to_ascii_lowercase());
        }
    }
    Ok(tokens)
}

fn header_map_connection_tokens(headers: &hyper::HeaderMap) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for value in headers.get_all(hyper::header::CONNECTION) {
        values.push(
            value
                .to_str()
                .map_err(|_| "invalid Connection header".to_owned())?,
        );
    }
    connection_tokens(values.into_iter())
}

fn is_hop_by_hop(name: &str, connection_named: &[String]) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || connection_named.contains(&lower)
}

fn streaming_request(
    addr: &str,
    method: &str,
    path_and_query: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Request<Full<Bytes>>, String> {
    let mut builder = Request::builder().method(method).uri(path_and_query);
    let mut has_host = false;
    let connection_named = connection_tokens(headers.iter().filter_map(|(name, value)| {
        name.eq_ignore_ascii_case("connection")
            .then_some(value.as_str())
    }))?;
    for (name, value) in headers {
        if !is_framable_name(name) || !is_framable_value(value) {
            return Err(format!(
                "refusing to forward the unframable header {name:?}"
            ));
        }
        if is_hop_by_hop(name, &connection_named)
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("expect")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        builder = builder.header(name, value);
    }
    if !has_host {
        builder = builder.header("host", addr);
    }
    builder
        .header("content-length", body.len())
        .header("connection", "close")
        .body(Full::new(Bytes::copy_from_slice(body)))
        .map_err(|error| format!("building the runner request: {error}"))
}

enum NextStreamFrame {
    Frame(Option<Result<Frame<Bytes>, hyper::Error>>),
    ClientGone,
    TimedOut,
}

enum StreamSend {
    Sent,
    ClientGone,
    TimedOut,
}

async fn next_stream_frame(
    upstream: &mut Incoming,
    body_tx: &mpsc::Sender<Bytes>,
    deadline: Option<tokio::time::Instant>,
) -> NextStreamFrame {
    match deadline {
        Some(deadline) => {
            tokio::select! {
                biased;
                () = body_tx.closed() => NextStreamFrame::ClientGone,
                timed = tokio::time::timeout_at(deadline, upstream.frame()) => {
                    timed.map_or(NextStreamFrame::TimedOut, NextStreamFrame::Frame)
                }
            }
        }
        None => {
            tokio::select! {
                biased;
                () = body_tx.closed() => NextStreamFrame::ClientGone,
                next = upstream.frame() => NextStreamFrame::Frame(next),
            }
        }
    }
}

async fn send_stream_data(
    body_tx: &mpsc::Sender<Bytes>,
    data: Bytes,
    deadline: Option<tokio::time::Instant>,
) -> StreamSend {
    match deadline {
        Some(deadline) => {
            tokio::select! {
                biased;
                () = body_tx.closed() => StreamSend::ClientGone,
                sent = tokio::time::timeout_at(deadline, body_tx.send(data)) => match sent {
                    Ok(Ok(())) => StreamSend::Sent,
                    Ok(Err(_)) => StreamSend::ClientGone,
                    Err(_) => StreamSend::TimedOut,
                }
            }
        }
        None => body_tx
            .send(data)
            .await
            .map_or(StreamSend::ClientGone, |()| StreamSend::Sent),
    }
}

async fn pump_stream(
    mut upstream: Incoming,
    body_tx: mpsc::Sender<Bytes>,
    terminal_tx: oneshot::Sender<Result<(), std::io::Error>>,
    completion_tx: oneshot::Sender<StreamCompletion>,
    connection: tokio::task::JoinHandle<Result<(), hyper::Error>>,
    deadline: Option<tokio::time::Instant>,
    response_limit: u64,
) {
    let mut streamed = 0_u64;
    let outcome = loop {
        match next_stream_frame(&mut upstream, &body_tx, deadline).await {
            NextStreamFrame::ClientGone => break StreamCompletion::ClientGone,
            NextStreamFrame::TimedOut => break StreamCompletion::TimedOut,
            NextStreamFrame::Frame(Some(Ok(frame))) => {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                streamed = streamed.saturating_add(data.len() as u64);
                if streamed > response_limit {
                    break StreamCompletion::TooLarge;
                }
                match send_stream_data(&body_tx, data, deadline).await {
                    StreamSend::Sent => {}
                    StreamSend::ClientGone => break StreamCompletion::ClientGone,
                    StreamSend::TimedOut => break StreamCompletion::TimedOut,
                }
            }
            NextStreamFrame::Frame(Some(Err(error))) => {
                let message = format!("reading the runner's response stream: {error}");
                break StreamCompletion::Upstream(message);
            }
            NextStreamFrame::Frame(None) => break StreamCompletion::Complete,
        }
    };
    connection.abort();
    let _ = connection.await;
    let terminal = match &outcome {
        StreamCompletion::TimedOut => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "function stream timed out",
        )),
        StreamCompletion::TooLarge => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("function stream exceeds {response_limit} bytes"),
        )),
        StreamCompletion::Upstream(error) => Err(std::io::Error::other(error.clone())),
        StreamCompletion::Complete | StreamCompletion::ClientGone => Ok(()),
    };
    let _ = terminal_tx.send(terminal);
    let _ = completion_tx.send(outcome);
}

/// Starts one transparent runner response stream without interpreting its SSE records.
///
/// The single-slot channel makes the public client's body polling the backpressure boundary.
/// Dropping the public body closes the channel, which drops the runner response and aborts its
/// connection driver; Node then fires the callable response's `AbortSignal`.
pub async fn forward_stream(
    addr: &str,
    method: &str,
    path_and_query: &str,
    headers: &[(String, String)],
    body: &[u8],
    deadline: Option<tokio::time::Instant>,
) -> Result<StartedStream, StreamStartError> {
    forward_stream_with_limit(
        addr,
        method,
        path_and_query,
        headers,
        body,
        deadline,
        MAX_STREAMING_FUNCTION_RESPONSE_BYTES,
    )
    .await
}

async fn forward_stream_with_limit(
    addr: &str,
    method: &str,
    path_and_query: &str,
    headers: &[(String, String)],
    body: &[u8],
    deadline: Option<tokio::time::Instant>,
    response_limit: u64,
) -> Result<StartedStream, StreamStartError> {
    let request = streaming_request(addr, method, path_and_query, headers, body)
        .map_err(StreamStartError::Upstream)?;
    let stream = before_stream_deadline(deadline, async {
        TcpStream::connect(addr)
            .await
            .map_err(|error| format!("cannot reach the functions runner at {addr}: {error}"))
    })
    .await?;
    let (mut sender, connection) = before_stream_deadline(deadline, async {
        client_http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| format!("starting the runner HTTP connection: {error}"))
    })
    .await?;
    let connection = tokio::spawn(connection);
    let response = before_stream_deadline(deadline, async {
        sender
            .send_request(request)
            .await
            .map_err(|error| format!("reading the runner's response headers: {error}"))
    })
    .await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            connection.abort();
            let _ = connection.await;
            return Err(error);
        }
    };
    let encoded = response
        .headers()
        .get_all(hyper::header::CONTENT_ENCODING)
        .iter()
        .any(|value| {
            value
                .to_str()
                .map_or(true, |value| !value.eq_ignore_ascii_case("identity"))
        });
    if encoded {
        connection.abort();
        let _ = connection.await;
        return Err(StreamStartError::Upstream(
            "refusing a streamed response with a non-identity content encoding".to_owned(),
        ));
    }
    let status = response.status().as_u16();
    let connection_named = match header_map_connection_tokens(response.headers()) {
        Ok(tokens) => tokens,
        Err(error) => {
            connection.abort();
            let _ = connection.await;
            return Err(StreamStartError::Upstream(error));
        }
    };
    let response_headers = response
        .headers()
        .iter()
        .filter(|(name, _)| {
            !is_hop_by_hop(name.as_str(), &connection_named) && name.as_str() != "content-length"
        })
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    let upstream = response.into_body();
    let (body_tx, body_rx) = mpsc::channel(1);
    let (terminal_tx, terminal_rx) = oneshot::channel();
    let (completion_tx, completion_rx) = oneshot::channel();
    tokio::spawn(pump_stream(
        upstream,
        body_tx,
        terminal_tx,
        completion_tx,
        connection,
        deadline,
        response_limit,
    ));
    Ok(StartedStream {
        response: ProxiedStreamResponse {
            status,
            headers: response_headers,
            body: body_rx,
            terminal: terminal_rx,
        },
        completion: completion_rx,
    })
}

/// A field name that cannot break the framing: an RFC 9110 token.
fn is_framable_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&\'*+-.^_`|~".contains(&b))
}

/// A field value that cannot break the framing: visible ASCII, spaces and tabs only.
fn is_framable_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (0x20..=0x7E).contains(&b))
}

/// Parses a complete HTTP/1.1 response (`Content-Length`, chunked or close-delimited body)
/// to a `method` request; only HEAD responses and body-less statuses may omit a declared
/// body.
pub fn parse_response(raw: &[u8], method: &str) -> Result<ProxiedResponse, String> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed response from the functions runner".to_owned())?;
    let head = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| "malformed response header text".to_owned())?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("malformed status line {status_line:?}"))?;
    let mut raw_headers = Vec::new();
    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            raw_headers.push((k.to_owned(), v.to_owned()));
            match k.to_ascii_lowercase().as_str() {
                "transfer-encoding" => chunked = v.eq_ignore_ascii_case("chunked"),
                "content-length" => content_length = v.parse().ok(),
                _ => {}
            }
        }
    }
    let connection_named = connection_tokens(raw_headers.iter().filter_map(|(name, value)| {
        name.eq_ignore_ascii_case("connection")
            .then_some(value.as_str())
    }))?;
    let headers = raw_headers
        .into_iter()
        .filter(|(name, _)| {
            !is_hop_by_hop(name, &connection_named) && !name.eq_ignore_ascii_case("content-length")
        })
        .collect();
    let rest = &raw[header_end + 4..];
    let bodyless = method.eq_ignore_ascii_case("HEAD")
        || matches!(status, 204 | 304)
        || (100..200).contains(&status);
    let body = if bodyless {
        Vec::new()
    } else if chunked {
        decode_chunked(rest)?
    } else if let Some(n) = content_length {
        rest.get(..n)
            .ok_or_else(|| "truncated response body".to_owned())?
            .to_vec()
    } else {
        rest.to_vec()
    };
    Ok(ProxiedResponse {
        status,
        headers,
        body,
    })
}

fn decode_chunked(mut rest: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "malformed chunked body".to_owned())?;
        let size_text = String::from_utf8_lossy(&rest[..line_end]);
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "malformed chunk size".to_owned())?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        out.extend_from_slice(
            rest.get(..size)
                .ok_or_else(|| "truncated chunk".to_owned())?,
        );
        rest = rest.get(size + 2..).unwrap_or(&[]);
    }
}

/// Answers `POST .../channels/{channel}:publishEvents`.
///
/// The official emulator refuses a `400` for an event with no `type` and otherwise answers a
/// bare `200` -- `res.sendStatus(200)`, so `OK` as text -- whether or not anything was
/// subscribed, because delivery is fire-and-forget from the publisher's point of view
/// (`eventarcEmulator.js` `publishEventsHandler`). A conversion this emulator cannot make is
/// reported the same way an unpublishable event is, with the official sentence, rather than
/// accepted and dropped.
fn publish_events(runtime: &FunctionsRuntime, channel: &str, body: &[u8]) -> Response<OutBody> {
    let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(body) else {
        return simple(StatusCode::BAD_REQUEST, "Bad Request");
    };
    let Some(events) = parsed.get("events").and_then(serde_json::Value::as_array) else {
        return simple(StatusCode::BAD_REQUEST, "Bad Request");
    };
    let google = channel == crate::eventarc::GOOGLE_CHANNEL;
    for event in events {
        // The sentinel `google` channel forwards verbatim; a custom channel converts the
        // proto form the Admin SDK publishes. That branch is the official one, and it is why
        // Firebase alerts -- which have no channel and are indexed under `<type>-google` --
        // arrive as the plain CloudEvent their handlers expect.
        let converted = if google {
            crate::eventarc::accept_verbatim(event)
        } else {
            crate::eventarc::convert(event)
        };
        match converted {
            Ok(published) => {
                let delivered = runtime.publish_custom_event(
                    channel,
                    &published.event_type,
                    &published.attributes,
                    &published.event,
                );
                eprintln!(
                    "[functions] eventarc: {} on {channel} reached {delivered} function(s)",
                    published.event_type
                );
            }
            Err(why) => return simple(StatusCode::BAD_REQUEST, &why),
        }
    }
    simple(StatusCode::OK, "OK")
}

/// An answer produced instead of proxying: a 404, a denial, a refused origin.
type Refusal = Box<Response<OutBody>>;

/// The route a request resolved to: its region, its function name and the runner to reach.
type Route<'a> = (&'a str, &'a str, crate::runtime::HttpTarget);

/// Resolves `/{project}/{region}/{function}` against the manifest, or the 404 the official
/// emulator answers instead.
///
/// There are two of those and they are not the same: a path that is not a function route at
/// all falls through to `hub.all("*")` and gets express's `res.sendStatus(404)` -- the status
/// text as `text/plain` -- while a route whose function does not exist gets
/// `handleHttpsTrigger`'s sentence naming the key it looked for and every key it holds
/// (`functionsEmulator.js:145`, `:1244`).
fn resolve_route<'a>(runtime: &FunctionsRuntime, path: &'a str) -> Result<Route<'a>, Refusal> {
    let segments: Vec<&str> = path.trim_start_matches('/').splitn(4, '/').collect();
    let [project, region, function, ..] = segments.as_slice() else {
        return Err(Box::new(simple(StatusCode::NOT_FOUND, "Not Found")));
    };
    if project.is_empty()
        || region.is_empty()
        || function.is_empty()
        || *project != runtime.project()
    {
        return Err(Box::new(simple(StatusCode::NOT_FOUND, "Not Found")));
    }
    match runtime.http_target(project, region, function) {
        Some(target) => Ok((region, function, target)),
        None => Err(Box::new(typed(
            StatusCode::NOT_FOUND,
            "text/html; charset=utf-8",
            &format!(
                "Function {region}-{function} does not exist, valid functions are: {}",
                runtime.trigger_keys().join(", ")
            ),
        ))),
    }
}

/// Puts a callable's credentials through the trust boundary, or answers the denial.
///
/// An `onRequest` function keeps receiving the raw field list, because application code owns
/// custom-backend verification there (specification section 7.3); a callable only reaches the
/// runner once the daemon has verified and re-inserted both credentials.
fn sanitize_credentials(
    runtime: &FunctionsRuntime,
    function: &str,
    raw: &hyper::HeaderMap,
    headers: Vec<(String, String)>,
) -> Result<Vec<(String, String)>, Refusal> {
    let (Some(trust), Some(enforce_app_check)) = (
        runtime.callable_trust(),
        runtime.callable_enforces_app_check(function),
    ) else {
        return Ok(headers);
    };
    // The credential fields are collected separately and lossily: a value that is not
    // renderable as text must still count as an instance, or a second copy could hide behind
    // one byte the general collection dropped (spec 7.3).
    let presented_app_check = field_values(raw, fireemu_core_app_check::header::APP_CHECK_HEADER);
    let presented_auth = field_values(raw, "authorization");
    match trust.sanitize(&crate::callable::CallableRequest {
        function,
        enforce_app_check,
        headers: &headers,
        app_check: &presented_app_check,
        authorization: &presented_auth,
        now: runtime.now(),
    }) {
        crate::callable::CallableDecision::Forward { headers, .. } => Ok(headers),
        crate::callable::CallableDecision::Unauthenticated { .. } => {
            let denial = crate::callable::unauthenticated_response();
            let mut builder = Response::builder().status(denial.status);
            for (k, v) in denial.headers {
                builder = builder.header(k, v);
            }
            Err(Box::new(
                builder
                    .body(full(Bytes::from(denial.body)))
                    .unwrap_or_else(|_| Response::new(full(Bytes::new()))),
            ))
        }
    }
}

/// Answers the three Cloud Tasks routes.
///
/// There is no queue to create: the official emulator creates one per `onTaskDispatched`
/// function at load time and fireemu's queue *is* the function, so the create route reports
/// what the queue already is rather than storing a second copy of it. Deleting a task is
/// refused rather than silently accepted, because a task is dispatched as soon as it is
/// accepted here and there is no window in which a delete could still take effect.
fn task_route(
    runtime: &Arc<FunctionsRuntime>,
    route: &crate::tasks::Route,
    method: &hyper::Method,
    body: &[u8],
) -> Response<OutBody> {
    use crate::tasks::Route;
    match route {
        Route::CreateQueue {
            project,
            location,
            queue,
        } => {
            if method != hyper::Method::POST {
                return simple(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
            }
            let served = runtime.manifest().get(queue).is_some_and(|f| {
                matches!(
                    f.trigger,
                    fireemu_core_functions::manifest::Trigger::TaskQueue { .. }
                ) && &f.region == location
            });
            if !served || project != runtime.project() {
                return typed(
                    StatusCode::NOT_FOUND,
                    "application/json",
                    &fireemu_adapter_support::api_error::flat(&format!(
                        "no onTaskDispatched function named {queue} in {project}/{location}"
                    ))
                    .to_string(),
                );
            }
            typed(
                StatusCode::OK,
                "application/json",
                &serde_json::json!({"taskQueueConfig": {"queue": queue}}).to_string(),
            )
        }
        Route::Enqueue {
            project,
            location,
            queue,
        } => {
            if method != hyper::Method::POST {
                return simple(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed");
            }
            let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(body) else {
                return simple(StatusCode::BAD_REQUEST, "the request body is not JSON");
            };
            match runtime.enqueue_task(project, location, queue, &parsed) {
                Ok(answer) => typed(StatusCode::OK, "application/json", &answer.to_string()),
                Err(refusal) => typed(
                    StatusCode::from_u16(refusal.status).unwrap_or(StatusCode::BAD_REQUEST),
                    "text/plain; charset=utf-8",
                    &refusal.body,
                ),
            }
        }
        Route::DeleteTask { .. } => simple(
            StatusCode::NOT_FOUND,
            "Tried to remove a task that doesn't exist",
        ),
    }
}

/// Reads a request body up to the forwarding limit, or the 413 that replaces it.
async fn collect_body(body: Incoming, limit: usize) -> Result<Bytes, Refusal> {
    match tokio::time::timeout(
        REQUEST_READ_TIMEOUT,
        fireemu_adapter_support::body::collect_limited(body, limit),
    )
    .await
    {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(_)) => Err(Box::new(simple(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request body too large",
        ))),
        Err(_) => Err(Box::new(simple(
            StatusCode::REQUEST_TIMEOUT,
            "request body timed out",
        ))),
    }
}

/// Drains a refused request without retaining its body. Hyper closes the read side when an
/// `Incoming` is dropped before the body has arrived; a client that is still writing then sees
/// a timing-dependent connection reset instead of the callable's stable error envelope.
async fn drain_refused_body(mut body: Incoming) {
    let drain = async {
        let mut remaining = MAX_FUNCTION_BODY_BYTES;
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else {
                return;
            };
            let Ok(data) = frame.into_data() else {
                continue;
            };
            let len = data.len();
            if len > remaining {
                return;
            }
            remaining -= len;
        }
    };
    let _ = tokio::time::timeout(REQUEST_READ_TIMEOUT, drain).await;
}

fn buffered_response(
    response: ProxiedResponse,
    plain_http: bool,
    origin: Option<&str>,
) -> Response<OutBody> {
    let mut builder = Response::builder().status(response.status);
    let answered_cors = response
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("access-control-allow-origin"));
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    if plain_http && !answered_cors {
        if let Some(origin) = origin {
            builder = builder
                .header("access-control-allow-origin", origin)
                .header("vary", "Origin");
        }
    }
    builder
        .body(full(Bytes::from(response.body)))
        .unwrap_or_else(|_| Response::new(full(Bytes::new())))
}

fn streaming_response(response: ProxiedStreamResponse) -> Response<OutBody> {
    let mut builder = Response::builder().status(response.status);
    for (name, value) in response.headers {
        builder = builder.header(name, value);
    }
    let bytes = StreamResponseBody {
        body: response.body,
        terminal: Some(response.terminal),
        failed: false,
    };
    let frames = bytes.map(|item| {
        item.map(Frame::data)
            .map_err(|error| Box::new(error) as BoxError)
    });
    builder
        .body(StreamBody::new(frames).boxed_unsync())
        .unwrap_or_else(|_| Response::new(full(Bytes::new())))
}

async fn respond(
    runtime: Arc<FunctionsRuntime>,
    req: Request<Incoming>,
    body_limit: usize,
) -> Result<Response<OutBody>, std::io::Error> {
    let path = req.uri().path().to_owned();
    let query = req.uri().query().map(str::to_owned);
    // Like the other ports: a page on another site must not drive this loopback runtime. The
    // official emulator does let it -- its runtime runs with `enableCors: true`, which wraps
    // every handler in `cors({origin: true})` and reflects any origin, so a page anywhere on
    // the internet can POST to a developer's callable and read the result. That is the one
    // documented divergence of this port, recorded in
    // `conformance/fixtures/functions/http-routing-cors-and-timeouts.json`.
    let origin = match local_request_origin(req.headers()) {
        Ok(origin) => origin,
        Err(refusal) => return Ok(*refusal),
    };
    // Eventarc's `publishEvents` shares this port. The official suite gives Eventarc a port
    // of its own; a custom event has nowhere to go without functions, so fireemu serves the
    // route here and points `CLOUD_EVENTARC_EMULATOR_HOST` at this listener. The path forms
    // cannot collide with a function route: both are rooted at a literal segment no project
    // ID reaches, and both end in a literal the function route does not have.
    if req.method() == hyper::Method::POST {
        if let Some(channel) = crate::eventarc::publish_channel(&path) {
            return Ok(match collect_body(req.into_body(), body_limit).await {
                Ok(body) => publish_events(&runtime, &channel, &body),
                Err(answer) => *answer,
            });
        }
    }
    // Cloud Tasks shares this port for the same reason Eventarc does.
    if let Some(route) = crate::tasks::route(&path) {
        let method = req.method().clone();
        return Ok(match collect_body(req.into_body(), body_limit).await {
            Ok(body) => task_route(&runtime, &route, &method, &body),
            Err(answer) => *answer,
        });
    }
    let (_region, function, target) = match resolve_route(&runtime, &path) {
        Ok(resolved) => resolved,
        Err(answer) => return Ok(*answer),
    };
    if let Err(error) = header_map_connection_tokens(req.headers()) {
        drain_refused_body(req.into_body()).await;
        return Ok(simple(StatusCode::BAD_REQUEST, &error));
    }
    let method = req.method().as_str().to_owned();
    // The CORS the official emulator's `enableCors` gives an `onRequest` function, for the
    // loopback origins this port serves. A callable answers its own preflight (v2 `onCall`
    // enables CORS itself, and the recorded oracle shows `POST` where an `onRequest` shows the
    // whole method list), so a callable's request is forwarded untouched.
    let (callable, plain_http, streaming_callable) = http_trigger_kinds(&runtime, function);
    let streaming = streaming_callable && accepts_callable_stream(req.headers());
    if callable && method == "OPTIONS" {
        return Ok(match callable_preflight(req.headers()) {
            Some(answer) => answer,
            None => simple(StatusCode::FORBIDDEN, "forbidden callable preflight"),
        });
    }
    if plain_http && method == "OPTIONS" {
        if let Some(origin) = &origin {
            if req.headers().contains_key("access-control-request-method") {
                return Ok(preflight_answer(origin, req.headers()));
            }
        }
    }
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_owned(), v.to_owned()))
        })
        .collect();
    let headers = match sanitize_credentials(&runtime, function, req.headers(), headers) {
        Ok(headers) => headers,
        Err(denial) => {
            drain_refused_body(req.into_body()).await;
            return Ok(callable_credential_refusal(
                *denial,
                streaming,
                origin.as_deref(),
            ));
        }
    };
    let body = match collect_body(req.into_body(), body_limit).await {
        Ok(body) => body,
        Err(answer) => return Ok(*answer),
    };
    let path_and_query = match query {
        Some(q) => format!("{path}?{q}"),
        None => path,
    };
    if streaming {
        return match runtime
            .invoke_http_stream(&target, &method, &path_and_query, &headers, &body)
            .await
        {
            Ok(crate::runtime::HttpStreamStart::Buffered(response)) => {
                Ok(buffered_response(response, plain_http, origin.as_deref()))
            }
            Ok(crate::runtime::HttpStreamStart::Streaming(response)) => {
                Ok(streaming_response(response))
            }
            Err(error) if error == crate::runtime::DROP_CONNECTION => {
                Err(std::io::Error::other(error))
            }
            Err(error) => Ok(simple(StatusCode::BAD_GATEWAY, &error)),
        };
    }
    match runtime
        .invoke_http(&target, &method, &path_and_query, &headers, &body)
        .await
    {
        Ok(response) => Ok(buffered_response(response, plain_http, origin.as_deref())),
        // A `dropConnection` fault: the connection closes without a response.
        Err(error) if error == crate::runtime::DROP_CONNECTION => Err(std::io::Error::other(error)),
        Err(error) => Ok(simple(StatusCode::BAD_GATEWAY, &error)),
    }
}

/// Every instance of one field, in wire order, with an unrenderable value as an empty string.
///
/// The empty string is not a value anything accepts: it classifies as malformed for App Check
/// and fails ID token verification. What matters is that it still counts as an instance, so a
/// second copy cannot hide behind a byte that does not render.
fn field_values(headers: &hyper::HeaderMap, name: &str) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().map_or_else(|_| String::new(), str::to_owned))
        .collect()
}

/// The preflight answer `cors({origin: true})` produces, which is what the official
/// emulator's `enableCors` debug feature puts in front of every handler.
///
/// Recorded from the oracle: `204`, the origin reflected, the full default method list, the
/// requested headers echoed, and `Vary: Origin, Access-Control-Request-Headers`. The handler
/// is not invoked.
fn preflight_answer(origin: &str, headers: &hyper::HeaderMap) -> Response<OutBody> {
    let mut builder = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("access-control-allow-origin", origin)
        .header(
            "access-control-allow-methods",
            "GET,HEAD,PUT,PATCH,POST,DELETE",
        )
        .header("vary", "Origin, Access-Control-Request-Headers")
        .header("content-length", "0");
    if let Some(requested) = headers
        .get("access-control-request-headers")
        .and_then(|v| v.to_str().ok())
    {
        builder = builder.header("access-control-allow-headers", requested);
    }
    builder
        .body(full(Bytes::new()))
        .unwrap_or_else(|_| Response::new(full(Bytes::new())))
}

/// A proxy-owned callable preflight response.
///
/// Callable preflights never reach Auth/App Check admission or the runner. Unlike the
/// compatibility response for `onRequest`, this accepts only the callable protocol's method
/// and request headers instead of reflecting browser input as authority.
fn callable_preflight(headers: &hyper::HeaderMap) -> Option<Response<OutBody>> {
    let origins = field_values(headers, "origin");
    let [origin] = origins.as_slice() else {
        return None;
    };
    if !origin_is_local(origin) {
        return None;
    }
    let requested_method = field_values(headers, "access-control-request-method");
    if requested_method.len() != 1 || !requested_method[0].eq_ignore_ascii_case("POST") {
        return None;
    }
    let fetch_site = field_values(headers, "sec-fetch-site");
    if fetch_site.len() > 1
        || fetch_site.first().is_some_and(|site| {
            !matches!(
                site.to_ascii_lowercase().as_str(),
                "same-origin" | "same-site" | "none"
            )
        })
    {
        return None;
    }
    let fetch_mode = field_values(headers, "sec-fetch-mode");
    if fetch_mode.len() > 1
        || fetch_mode
            .first()
            .is_some_and(|mode| !mode.eq_ignore_ascii_case("cors"))
    {
        return None;
    }

    let requested_fields = field_values(headers, "access-control-request-headers");
    if requested_fields.len() > 1 {
        return None;
    }
    let mut admitted = Vec::new();
    if let Some(fields) = requested_fields.first() {
        for field in fields.split(',') {
            let field = field.trim().to_ascii_lowercase();
            if field.is_empty()
                || !matches!(
                    field.as_str(),
                    "authorization"
                        | "content-type"
                        | "firebase-instance-id-token"
                        | "x-firebase-appcheck"
                )
                || admitted.contains(&field)
            {
                return None;
            }
            admitted.push(field);
        }
    }

    let mut builder = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header("access-control-allow-origin", origin)
        .header("access-control-allow-methods", "POST")
        .header(
            "vary",
            "Origin, Access-Control-Request-Method, Access-Control-Request-Headers, Sec-Fetch-Site, Sec-Fetch-Mode",
        )
        .header("content-length", "0");
    if !admitted.is_empty() {
        builder = builder.header("access-control-allow-headers", admitted.join(","));
    }
    builder.body(full(Bytes::new())).ok()
}

/// Serves the functions port.
pub async fn serve_functions(
    listener: TcpListener,
    runtime: Arc<FunctionsRuntime>,
) -> std::io::Result<()> {
    let request_admission = RequestAdmission::new();
    let connection_slots = Arc::new(Semaphore::new(MAX_FUNCTION_CONNECTIONS));
    loop {
        let (stream, _) = listener.accept().await?;
        let connection = connection_slots
            .clone()
            .acquire_owned()
            .await
            .expect("the connection semaphore is never closed");
        let runtime = runtime.clone();
        let request_admission = request_admission.clone();
        tokio::spawn(async move {
            let _connection = connection;
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let runtime = runtime.clone();
                let request_admission = request_admission.clone();
                async move {
                    let body_limit = request_body_limit(req.uri().path());
                    let reservation = request_body_reservation(&req, body_limit);
                    let _request = request_admission.acquire(reservation).await;
                    respond(runtime, req, body_limit).await
                }
            });
            let mut builder = http1::Builder::new();
            builder
                .timer(TokioTimer::new())
                .header_read_timeout(REQUEST_READ_TIMEOUT);
            builder.keep_alive(false);
            let _ = builder.serve_connection(io, svc).await;
        });
    }
}

#[cfg(test)]
mod admission_tests {
    use super::{
        request_body_limit, RequestAdmission, MAX_FUNCTION_BODY_BYTES, MAX_TASK_BODY_BYTES,
    };
    use std::time::Duration;

    #[test]
    fn task_routes_use_the_official_json_body_limit() {
        assert_eq!(
            request_body_limit("/projects/demo-app/locations/us-central1/queues/work/tasks"),
            MAX_TASK_BODY_BYTES
        );
        assert_eq!(
            request_body_limit("/demo-app/us-central1/ordinary"),
            MAX_FUNCTION_BODY_BYTES
        );
    }

    #[tokio::test]
    async fn request_admission_bounds_concurrency_and_reserved_bytes() {
        let admission = RequestAdmission::with_limits(1, 8);
        let first = admission.acquire(8).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), admission.acquire(1))
                .await
                .is_err()
        );
        drop(first);
        let second = tokio::time::timeout(Duration::from_millis(20), admission.acquire(1))
            .await
            .expect("dropping an admitted request releases both permits");
        drop(second);
    }

    #[tokio::test]
    async fn cancelled_or_panicked_requests_release_all_admission_permits() {
        let admission = RequestAdmission::with_limits(1, 8);
        let cancelled_admission = admission.clone();
        let (ready, ready_rx) = tokio::sync::oneshot::channel();
        let cancelled = tokio::spawn(async move {
            let _permit = cancelled_admission.acquire(8).await;
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        ready_rx.await.expect("the cancelled request was admitted");
        cancelled.abort();
        let _ = cancelled.await;
        drop(
            tokio::time::timeout(Duration::from_millis(20), admission.acquire(8))
                .await
                .expect("cancellation releases request and byte permits"),
        );

        let panicked_admission = admission.clone();
        let panicked = tokio::spawn(async move {
            let _permit = panicked_admission.acquire(8).await;
            panic!("exercise request-admission unwind cleanup");
        });
        assert!(panicked.await.expect_err("the task panics").is_panic());
        drop(
            tokio::time::timeout(Duration::from_millis(20), admission.acquire(8))
                .await
                .expect("panic cleanup releases request and byte permits"),
        );
    }
}

#[cfg(test)]
mod streaming_tests {
    use super::{
        forward_stream_with_limit, streaming_response, StreamCompletion, StreamStartError,
    };
    use http_body_util::BodyExt as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::{Duration, Instant};

    async fn upstream(
        chunk: &'static [u8],
        finish: bool,
    ) -> (String, tokio::task::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut bytes = [0_u8; 1024];
                let read = stream.read(&mut bytes).await.unwrap();
                assert_ne!(read, 0, "client closed before sending the request");
                request.extend_from_slice(&bytes[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            stream
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .unwrap();
            stream.write_all(chunk).await.unwrap();
            stream.write_all(b"\r\n").await.unwrap();
            stream.flush().await.unwrap();
            if finish {
                stream.write_all(b"0\r\n\r\n").await.unwrap();
                stream.flush().await.unwrap();
            }
            let mut discarded = Vec::new();
            stream.read_to_end(&mut discarded).await.unwrap()
        });
        (address, task)
    }

    async fn upstream_exchange(
        response_headers: &'static [u8],
        chunks: Vec<&'static [u8]>,
        finish: bool,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut bytes = [0_u8; 1024];
                let read = stream.read(&mut bytes).await.unwrap();
                assert_ne!(read, 0, "client closed before sending the request");
                request.extend_from_slice(&bytes[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            stream.write_all(response_headers).await.unwrap();
            for chunk in chunks {
                if stream
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await
                    .is_err()
                    || stream.write_all(chunk).await.is_err()
                    || stream.write_all(b"\r\n").await.is_err()
                    || stream.flush().await.is_err()
                {
                    return String::from_utf8_lossy(&request).into_owned();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if finish {
                let _ = stream.write_all(b"0\r\n\r\n").await;
                let _ = stream.flush().await;
            }
            let mut discarded = Vec::new();
            let _ = stream.read_to_end(&mut discarded).await;
            String::from_utf8_lossy(&request).into_owned()
        });
        (address, task)
    }

    #[tokio::test]
    async fn dropping_the_public_body_cancels_an_idle_upstream_stream() {
        let (address, upstream) = upstream(b"first", false).await;
        let started = forward_stream_with_limit(&address, "POST", "/callable", &[], &[], None, 64)
            .await
            .unwrap();
        let mut body = streaming_response(started.response).into_body();
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "first"
        );
        drop(body);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), started.completion)
                .await
                .expect("downstream cancellation is bounded")
                .unwrap(),
            StreamCompletion::ClientGone
        );
        tokio::time::timeout(Duration::from_secs(1), upstream)
            .await
            .expect("the upstream socket closes with the public body")
            .unwrap();
    }

    #[tokio::test]
    async fn the_stream_limit_is_cumulative_and_does_not_buffer_the_excess() {
        let (address, upstream) = upstream(b"12345", true).await;
        let started = forward_stream_with_limit(&address, "POST", "/callable", &[], &[], None, 4)
            .await
            .unwrap();
        let mut body = streaming_response(started.response).into_body();
        let error = body.frame().await.unwrap().unwrap_err();
        assert!(error.to_string().contains("exceeds 4 bytes"));
        assert_eq!(
            started.completion.await.unwrap(),
            StreamCompletion::TooLarge
        );
        upstream.await.unwrap();
    }

    #[tokio::test]
    async fn a_deadline_after_headers_terminates_the_public_and_upstream_streams() {
        let (address, upstream) = upstream(b"first", false).await;
        let started = forward_stream_with_limit(
            &address,
            "POST",
            "/callable",
            &[],
            &[],
            Some(Instant::now() + Duration::from_millis(100)),
            64,
        )
        .await
        .unwrap();
        let mut body = streaming_response(started.response).into_body();
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "first"
        );
        let error = body.frame().await.unwrap().unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert_eq!(
            started.completion.await.unwrap(),
            StreamCompletion::TimedOut
        );
        tokio::time::timeout(Duration::from_secs(1), upstream)
            .await
            .expect("the timed-out upstream socket closes")
            .unwrap();
    }

    #[tokio::test]
    async fn a_slow_reader_cannot_hold_admission_past_the_absolute_deadline() {
        let (address, upstream) = upstream_exchange(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            vec![b"first", b"second", b"third"],
            false,
        )
        .await;
        let started = forward_stream_with_limit(
            &address,
            "POST",
            "/callable",
            &[],
            &[],
            Some(Instant::now() + Duration::from_millis(100)),
            64,
        )
        .await
        .unwrap();
        let response = started.response;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), started.completion)
                .await
                .expect("a full downstream channel cannot defeat the deadline")
                .unwrap(),
            StreamCompletion::TimedOut
        );
        let mut body = streaming_response(response).into_body();
        let error = body
            .frame()
            .await
            .expect("the timed-out body reports one terminal frame")
            .expect_err("the terminal frame is an error");
        assert!(error.to_string().contains("timed out"));
        tokio::time::timeout(Duration::from_secs(1), upstream)
            .await
            .expect("the slow reader's upstream socket closes")
            .unwrap();
    }

    #[tokio::test]
    async fn streaming_strips_standard_and_connection_named_hop_by_hop_headers() {
        let (address, upstream) = upstream_exchange(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: x-response-hop, keep-alive\r\nx-response-hop: private\r\nUpgrade: websocket\r\nTE: trailers\r\nTrailer: x-checksum\r\nProxy-Authenticate: Basic\r\nProxy-Authorization: Basic private\r\nx-response-keep: public\r\n\r\n",
            vec![b"done"],
            true,
        )
        .await;
        let started = forward_stream_with_limit(
            &address,
            "POST",
            "/callable",
            &[
                ("connection".to_owned(), "x-request-hop, upgrade".to_owned()),
                ("x-request-hop".to_owned(), "private".to_owned()),
                ("upgrade".to_owned(), "websocket".to_owned()),
                ("te".to_owned(), "trailers".to_owned()),
                ("trailer".to_owned(), "x-checksum".to_owned()),
                ("proxy-authenticate".to_owned(), "Basic".to_owned()),
                ("proxy-authorization".to_owned(), "Basic private".to_owned()),
                ("x-request-keep".to_owned(), "public".to_owned()),
            ],
            &[],
            None,
            64,
        )
        .await
        .unwrap();
        assert_eq!(
            started.response.headers,
            vec![("x-response-keep".to_owned(), "public".to_owned())]
        );
        let body = streaming_response(started.response)
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        assert_eq!(body, "done");
        assert_eq!(
            started.completion.await.unwrap(),
            StreamCompletion::Complete
        );
        let request = upstream.await.unwrap().to_ascii_lowercase();
        assert!(request.contains("x-request-keep: public\r\n"));
        assert!(request.contains("connection: close\r\n"));
        for forbidden in [
            "x-request-hop:",
            "upgrade:",
            "te:",
            "trailer:",
            "proxy-authenticate:",
            "proxy-authorization:",
        ] {
            assert!(
                !request.contains(forbidden),
                "forwarded {forbidden}: {request}"
            );
        }
    }

    #[tokio::test]
    async fn an_encoded_stream_is_refused_before_compressed_bytes_can_bypass_the_limit() {
        let (address, upstream) = upstream_exchange(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n",
            vec![b"compressed"],
            true,
        )
        .await;
        let result =
            forward_stream_with_limit(&address, "POST", "/callable", &[], &[], None, 64).await;
        assert!(matches!(
            result,
            Err(StreamStartError::Upstream(error)) if error.contains("content encoding")
        ));
        tokio::time::timeout(Duration::from_secs(1), upstream)
            .await
            .expect("the refused encoded stream closes upstream")
            .unwrap();
    }

    #[tokio::test]
    async fn an_unrenderable_connection_value_fails_closed_before_a_named_header_can_escape() {
        let (address, upstream) = upstream_exchange(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: x-private,\xff\r\nx-private: secret\r\n\r\n",
            vec![],
            false,
        )
        .await;
        let result =
            forward_stream_with_limit(&address, "POST", "/callable", &[], &[], None, 64).await;
        assert!(matches!(
            result,
            Err(StreamStartError::Upstream(error)) if error.contains("Connection header")
        ));
        tokio::time::timeout(Duration::from_secs(1), upstream)
            .await
            .expect("the invalid response closes upstream")
            .unwrap();
    }
}
