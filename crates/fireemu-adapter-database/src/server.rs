//! The REST API behind hyper, with event-stream delivery.
//!
//! Requests are handled one at a time under the database lock, and the events a write
//! causes are queued to their streams before the lock is released, so every stream sees
//! changes in commit order. Bodies are parsed before the lock is taken. A stream whose
//! client went away, or stopped reading until its queue filled, is closed the next time an
//! event or a keep-alive cannot be queued to it. Request heads and bodies have deadlines.
//!
//! Realtime connections receive the data their listens are pushed the same way: queued
//! under the lock, in commit order, to a bounded queue per connection. A connection that
//! stops reading until its queue fills is dropped with its listens, and the SDK reconnects.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt as _;

use crate::realtime::{split_frames, Opened, Prepared, Received, Session};
use crate::rest::{
    parse_body, refusal_response, Database, Handled, HttpRequest, HttpResponse, SseEvent,
};
use crate::target_escape::TargetEscaper;
use crate::websocket::{
    accept_key, decode, encode, Assembler, CloseCode, Decoded, Message, Opcode,
};

/// The server time in milliseconds since the epoch.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// Server settings.
#[derive(Clone)]
pub struct ServerConfig {
    /// How often an open stream receives a `keep-alive` event.
    pub keep_alive: Duration,
    /// The largest request body read (production's REST limit is 256 MB).
    pub max_body_bytes: usize,
    /// How long a client may take to send a request head.
    pub header_timeout: Duration,
    /// How long a client may take to send a request body.
    pub body_timeout: Duration,
    /// How many events a stream, or messages a realtime connection, may have waiting before
    /// it is closed as too slow.
    pub stream_queue: usize,
    /// How many bytes of messages a realtime connection may have waiting before it is
    /// closed as too slow (a whole-location value can be large).
    pub stream_queue_bytes: usize,
    /// How long a realtime connection may stay silent (the SDKs send a keepalive every
    /// 45 s).
    pub realtime_idle: Duration,
    /// The server time.
    pub clock: Clock,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            keep_alive: Duration::from_secs(30),
            max_body_bytes: 256 * 1024 * 1024,
            header_timeout: Duration::from_secs(30),
            body_timeout: Duration::from_secs(120),
            stream_queue: 1024,
            stream_queue_bytes: 64 * 1024 * 1024,
            realtime_idle: Duration::from_secs(120),
            clock: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            }),
        }
    }
}

type Body = BoxBody<Bytes, Infallible>;
type Streams = Arc<Mutex<BTreeMap<u64, mpsc::Sender<SseEvent>>>>;
/// The push queue of each realtime connection.
type Listeners = Mutex<BTreeMap<u64, PushQueue>>;

/// The sending side of a connection's push queue; every entry is one message's frames. It
/// is bounded in messages (`stream_queue`) and in bytes (`stream_queue_bytes`).
struct PushQueue {
    sender: mpsc::Sender<Vec<String>>,
    bytes: Arc<AtomicUsize>,
}

/// The receiving side of a connection's push queue.
pub(crate) struct Pushes {
    receiver: mpsc::Receiver<Vec<String>>,
    bytes: Arc<AtomicUsize>,
}

fn push_queue(messages: usize) -> (PushQueue, Pushes) {
    let (sender, receiver) = mpsc::channel(messages.max(1));
    let bytes = Arc::new(AtomicUsize::new(0));
    (
        PushQueue {
            sender,
            bytes: Arc::clone(&bytes),
        },
        Pushes { receiver, bytes },
    )
}

fn frame_bytes(frames: &[String]) -> usize {
    frames.iter().map(String::len).sum()
}

impl PushQueue {
    /// Queues a message; `false` when the queue is full in messages or in bytes.
    fn offer(&self, frames: Vec<String>, budget: usize) -> bool {
        let size = frame_bytes(&frames);
        let before = self.bytes.fetch_add(size, AtomicOrdering::SeqCst);
        if before.saturating_add(size) > budget || self.sender.try_send(frames).is_err() {
            self.bytes.fetch_sub(size, AtomicOrdering::SeqCst);
            return false;
        }
        true
    }
}

impl Pushes {
    async fn recv(&mut self) -> Option<Vec<String>> {
        let frames = self.receiver.recv().await?;
        self.bytes
            .fetch_sub(frame_bytes(&frames), AtomicOrdering::SeqCst);
        Some(frames)
    }

    fn try_recv(&mut self) -> Option<Vec<String>> {
        let frames = self.receiver.try_recv().ok()?;
        self.bytes
            .fetch_sub(frame_bytes(&frames), AtomicOrdering::SeqCst);
        Some(frames)
    }
}

struct Shared {
    database: Arc<Mutex<Database>>,
    streams: Streams,
    listeners: Listeners,
    config: ServerConfig,
}

/// Serves `database` on `listener` until the task is dropped.
pub async fn serve(listener: TcpListener, database: Arc<Mutex<Database>>, config: ServerConfig) {
    let shared = Arc::new(Shared {
        database,
        streams: Arc::new(Mutex::new(BTreeMap::new())),
        listeners: Mutex::new(BTreeMap::new()),
        config,
    });
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            // Out of file descriptors and the like: back off instead of spinning.
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let shared = Arc::clone(&shared);
        let shared_header_timeout = shared.config.header_timeout;
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let shared = Arc::clone(&shared);
                async move { Ok::<_, Infallible>(answer(&shared, request).await) }
            });
            // A connection error concerns that client only.
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(shared_header_timeout)
                .serve_connection(TokioIo::new(TargetEscaper::new(socket)), service)
                .with_upgrades()
                .await;
        });
    }
}

async fn answer(shared: &Arc<Shared>, request: Request<Incoming>) -> Response<Body> {
    if is_websocket_upgrade(&request) {
        return upgrade(shared, request);
    }
    let (parts, body) = request.into_parts();
    let collecting = Limited::new(body, shared.config.max_body_bytes).collect();
    let Ok(collected) = tokio::time::timeout(shared.config.body_timeout, collecting).await else {
        return plain(408, "Request timeout.");
    };
    let Ok(collected) = collected else {
        return plain(413, "Request body too large.");
    };
    let request = HttpRequest {
        method: parts.method.as_str().to_owned(),
        target: parts
            .uri
            .path_and_query()
            .map_or_else(|| parts.uri.path().to_owned(), |pq| pq.as_str().to_owned()),
        headers: parts
            .headers
            .iter()
            // A value that is not visible ASCII is kept with replacement characters, so a
            // condition such as If-Match fails closed instead of disappearing.
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: collected.to_bytes().into(),
    };
    // Parsing can take long for a large body; it does not need the database.
    let parsed = parse_body(&request);
    let now = (shared.config.clock)();
    let mut database = shared
        .database
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    match database.handle_parsed(&request, parsed, now) {
        Handled::Response { response, events } => {
            deliver(shared, &mut database, events);
            full(response)
        }
        Handled::Stream {
            id,
            response,
            initial,
        } => {
            let (sender, receiver) = mpsc::channel(shared.config.stream_queue.max(1));
            // The queue is empty, so the first event fits.
            let _ = sender.try_send(initial);
            shared
                .streams
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id, sender.clone());
            drop(database);
            spawn_keep_alive(Arc::clone(shared), id, sender);
            streaming(response, receiver)
        }
    }
}

/// Queues events to their streams, closing streams whose client is gone.
fn deliver(shared: &Shared, database: &mut Database, events: Vec<(u64, SseEvent)>) {
    let mut streams = shared
        .streams
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    for (id, event) in events {
        let delivered = streams
            .get(&id)
            .is_some_and(|sender| sender.try_send(event).is_ok());
        if !delivered {
            streams.remove(&id);
            database.unsubscribe(id);
        }
    }
    drop(streams);
    let pushes = database.drain_pushes();
    if pushes.is_empty() {
        return;
    }
    let mut listeners = shared
        .listeners
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    for (client, message) in pushes {
        let delivered = listeners.get(&client).is_some_and(|queue| {
            queue.offer(split_frames(message), shared.config.stream_queue_bytes)
        });
        if !delivered {
            listeners.remove(&client);
            database.close_realtime(client);
        }
    }
}

fn spawn_keep_alive(shared: Arc<Shared>, id: u64, sender: mpsc::Sender<SseEvent>) {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(shared.config.keep_alive);
        ticks.tick().await;
        loop {
            ticks.tick().await;
            if sender.try_send(SseEvent::keep_alive()).is_err() {
                let mut database = shared
                    .database
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                shared
                    .streams
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&id);
                database.unsubscribe(id);
                return;
            }
        }
    });
}

fn with_headers(status: u16, headers: Vec<(String, String)>, body: Body) -> Response<Body> {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder
        .body(body)
        .unwrap_or_else(|_| plain(500, "Invalid response."))
}

fn full(response: HttpResponse) -> Response<Body> {
    let body = Full::new(Bytes::from(response.body)).boxed();
    with_headers(response.status, response.headers, body)
}

fn streaming(head: HttpResponse, receiver: mpsc::Receiver<SseEvent>) -> Response<Body> {
    let frames = ReceiverStream::new(receiver)
        .map(|event| Ok::<_, Infallible>(Frame::data(Bytes::from(event.to_text()))));
    with_headers(head.status, head.headers, StreamBody::new(frames).boxed())
}

fn plain(status: u16, message: &'static str) -> Response<Body> {
    let mut response = Response::new(Full::new(Bytes::from_static(message.as_bytes())).boxed());
    *response.status_mut() =
        hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    response
}

fn header<'a>(request: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    request.headers().get(name).and_then(|v| v.to_str().ok())
}

/// A WebSocket upgrade of `/.ws`; the official emulator upgrades no other path.
fn is_websocket_upgrade(request: &Request<Incoming>) -> bool {
    request.method() == hyper::Method::GET
        && request.uri().path() == "/.ws"
        && header(request, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// Answers a WebSocket upgrade: a refusal before the upgrade, or 101 and a task that
/// serves the realtime protocol on the upgraded connection.
fn upgrade(shared: &Arc<Shared>, mut request: Request<Incoming>) -> Response<Body> {
    // The official emulator upgrades whatever Sec-WebSocket-Version is named; only the
    // key is needed to answer.
    let Some(key) = header(&request, "sec-websocket-key").map(str::to_owned) else {
        return plain(400, "Missing Sec-WebSocket-Key.");
    };
    let target = request.uri().path_and_query().map_or_else(
        || request.uri().path().to_owned(),
        |pq| pq.as_str().to_owned(),
    );
    let host = header(&request, "host").map(str::to_owned);
    let now = (shared.config.clock)();
    let (opened, limit) = {
        let mut database = shared
            .database
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let limit = database.realtime_message_bytes();
        (database.open_realtime(&target, host.as_deref(), now), limit)
    };
    let opened = match opened {
        Ok(opened) => opened,
        Err(refusal) => return full(refusal_response(&refusal)),
    };
    let on_upgrade = hyper::upgrade::on(&mut request);
    let shared = Arc::clone(shared);
    tokio::spawn(async move {
        if let Ok(upgraded) = on_upgrade.await {
            serve_realtime(&shared, TokioIo::new(upgraded), opened, limit).await;
        }
    });
    Response::builder()
        .status(101)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept_key(&key))
        .body(Full::new(Bytes::new()).boxed())
        .unwrap_or_else(|_| plain(500, "Invalid response."))
}

async fn send_text<S: AsyncWrite + Unpin>(
    socket: &mut S,
    frames: &[String],
) -> std::io::Result<()> {
    for frame in frames {
        socket
            .write_all(&encode(Opcode::Text, frame.as_bytes()))
            .await?;
    }
    socket.flush().await
}

async fn send_close<S: AsyncWrite + Unpin>(socket: &mut S, code: CloseCode) {
    // The connection ends either way; a failed close concerns that client only.
    let _ = socket
        .write_all(&encode(Opcode::Close, &code.code().to_be_bytes()))
        .await;
    let _ = socket.shutdown().await;
}

/// Serves one realtime connection until the client closes it or breaks the protocol.
async fn serve_realtime<S: AsyncRead + AsyncWrite + Unpin>(
    shared: &Arc<Shared>,
    mut socket: S,
    opened: Opened,
    limit: usize,
) {
    let session: Session = match opened {
        Opened::Shutdown(frames) => {
            // The official emulator drops the connection after the shutdown message, without
            // a close frame.
            let _ = send_text(&mut socket, &frames).await;
            let _ = socket.shutdown().await;
            return;
        }
        Opened::Session(session, frames) => {
            if send_text(&mut socket, &frames).await.is_err() {
                return;
            }
            session
        }
    };
    let client = session.client();
    let (queue, mut pushes) = push_queue(shared.config.stream_queue);
    shared
        .listeners
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(client, queue);
    run_realtime(shared, &mut socket, session, &mut pushes, limit).await;
    // The database lock first, in the order `deliver` takes them.
    let mut database = shared
        .database
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    shared
        .listeners
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&client);
    database.close_realtime(client);
}

/// Answers one prepared message under the database lock. Pushes already queued for the
/// connection come from earlier commits (every push is queued under this lock), so they go
/// first, ahead of the pushes and answer this message causes.
fn answer_text(
    shared: &Shared,
    session: &mut Session,
    pushes: &mut Pushes,
    prepared: Prepared,
) -> Received {
    let now = (shared.config.clock)();
    let mut database = shared
        .database
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut earlier = Vec::new();
    while let Some(frames) = pushes.try_recv() {
        earlier.extend(frames);
    }
    let mut received = session.dispatch_prepared(&mut database, prepared, now);
    deliver(shared, &mut database, std::mem::take(&mut received.events));
    if !earlier.is_empty() {
        earlier.append(&mut received.replies);
        received.replies = earlier;
    }
    received
}

/// Writes frames, giving up after `limit` on a client that stopped reading.
async fn send_within<S: AsyncWrite + Unpin>(
    socket: &mut S,
    frames: &[String],
    limit: Duration,
) -> std::io::Result<()> {
    tokio::time::timeout(limit, send_text(socket, frames))
        .await
        .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))
}

/// Reads and answers frames, and writes pushed data, until the connection ends.
async fn run_realtime<S: AsyncRead + AsyncWrite + Unpin>(
    shared: &Arc<Shared>,
    socket: &mut S,
    mut session: Session,
    pushes: &mut Pushes,
    limit: usize,
) {
    let idle = shared.config.realtime_idle;
    let mut deadline = tokio::time::Instant::now() + idle;
    let mut assembler = Assembler::new(limit);
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        match decode(&buffer, limit) {
            Err(error) => {
                send_close(socket, error.close_code()).await;
                return;
            }
            // The SDKs send a keepalive every 45 s, so a connection silent for longer than the
            // idle time is gone.
            Ok(Decoded::Incomplete) => {
                tokio::select! {
                    read = tokio::time::timeout_at(deadline, socket.read(&mut chunk)) => {
                        match read {
                            Ok(Ok(0) | Err(_)) => return,
                            Ok(Ok(n)) => {
                                buffer.extend_from_slice(&chunk[..n]);
                                deadline = tokio::time::Instant::now() + idle;
                            }
                            Err(_) => {
                                send_close(socket, CloseCode::Normal).await;
                                return;
                            }
                        }
                    }
                    message = pushes.recv() => {
                        // A closed queue means the connection was dropped for falling behind.
                        let Some(frames) = message else {
                            let _ = socket.shutdown().await;
                            return;
                        };
                        if send_within(socket, &frames, idle).await.is_err() {
                            return;
                        }
                    }
                }
            }
            Ok(Decoded::Frame(frame, used)) => {
                buffer.drain(..used);
                let message = match assembler.push(frame) {
                    Err(error) => {
                        send_close(socket, error.close_code()).await;
                        return;
                    }
                    Ok(None) => continue,
                    Ok(Some(message)) => message,
                };
                let written = match message {
                    Message::Text(text) => {
                        // Reassembly and parsing happen before the lock is taken.
                        let Some(prepared) = session.prepare(&text) else {
                            continue;
                        };
                        let received = answer_text(shared, &mut session, pushes, prepared);
                        if let Some(code) = received.close {
                            send_close(socket, code).await;
                            return;
                        }
                        if received.drop_connection {
                            // Frames to send before dropping (a reset), if any.
                            let _ = send_within(socket, &received.replies, idle).await;
                            let _ = socket.shutdown().await;
                            return;
                        }
                        send_within(socket, &received.replies, idle).await
                    }
                    Message::Ping(payload) => {
                        socket.write_all(&encode(Opcode::Pong, &payload)).await
                    }
                    Message::Binary(_) | Message::Pong => Ok(()),
                    Message::Close(code) => {
                        let payload = code
                            .map(u16::to_be_bytes)
                            .map(Vec::from)
                            .unwrap_or_default();
                        let _ = socket.write_all(&encode(Opcode::Close, &payload)).await;
                        let _ = socket.shutdown().await;
                        return;
                    }
                };
                if written.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rest::RestOptions;

    fn shared() -> Shared {
        Shared {
            database: Arc::new(Mutex::new(Database::new(RestOptions::default(), 1))),
            streams: Arc::new(Mutex::new(BTreeMap::new())),
            listeners: Mutex::new(BTreeMap::new()),
            config: ServerConfig::default(),
        }
    }

    fn connect(shared: &Shared) -> (Session, Pushes) {
        let opened = shared
            .database
            .lock()
            .unwrap()
            .open_realtime("/.ws?v=5&ns=o", Some("h"), 0)
            .unwrap();
        let Opened::Session(session, _) = opened else {
            panic!("no session")
        };
        let (queue, pushes) = push_queue(16);
        shared
            .listeners
            .lock()
            .unwrap()
            .insert(session.client(), queue);
        (session, pushes)
    }

    fn send(
        shared: &Shared,
        session: &mut Session,
        pushes: &mut Pushes,
        frame: &str,
    ) -> Vec<String> {
        let prepared = session.prepare(frame).unwrap();
        answer_text(shared, session, pushes, prepared).replies
    }

    #[test]
    fn queued_pushes_go_before_the_connections_own() {
        let shared = shared();
        let (mut a, mut a_pushes) = connect(&shared);
        let (mut b, mut b_pushes) = connect(&shared);
        send(
            &shared,
            &mut a,
            &mut a_pushes,
            r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/a","h":""}}}"#,
        );
        // B's write queues a push for A that A's task has not written yet.
        send(
            &shared,
            &mut b,
            &mut b_pushes,
            r#"{"t":"d","d":{"r":1,"a":"p","b":{"p":"/a","d":1}}}"#,
        );
        assert_eq!(
            send(
                &shared,
                &mut a,
                &mut a_pushes,
                r#"{"t":"d","d":{"r":2,"a":"p","b":{"p":"/a","d":2}}}"#
            ),
            vec![
                r#"{"t":"d","d":{"b":{"p":"a","d":1},"a":"d"}}"#.to_owned(),
                r#"{"t":"d","d":{"b":{"p":"a","d":2},"a":"d"}}"#.to_owned(),
                r#"{"t":"d","d":{"r":2,"b":{"s":"ok","d":""}}}"#.to_owned(),
            ]
        );
        assert!(a_pushes.try_recv().is_none());
    }

    #[test]
    fn queued_pushes_go_before_a_new_listens_value() {
        let shared = shared();
        let (mut a, mut a_pushes) = connect(&shared);
        let (mut b, mut b_pushes) = connect(&shared);
        send(
            &shared,
            &mut a,
            &mut a_pushes,
            r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/a","h":""}}}"#,
        );
        send(
            &shared,
            &mut b,
            &mut b_pushes,
            r#"{"t":"d","d":{"r":1,"a":"p","b":{"p":"/a/b","d":1}}}"#,
        );
        assert_eq!(
            send(
                &shared,
                &mut a,
                &mut a_pushes,
                r#"{"t":"d","d":{"r":2,"a":"q","b":{"p":"/a/b","h":""}}}"#
            ),
            vec![
                r#"{"t":"d","d":{"b":{"p":"a/b","d":1},"a":"d"}}"#.to_owned(),
                r#"{"t":"d","d":{"b":{"p":"a/b","d":1},"a":"d"}}"#.to_owned(),
                r#"{"t":"d","d":{"r":2,"b":{"s":"ok","d":{}}}}"#.to_owned(),
            ]
        );
    }
}
