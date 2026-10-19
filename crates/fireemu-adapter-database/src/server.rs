//! The REST API behind hyper, with event-stream delivery.
//!
//! Requests are handled one at a time under the database lock, and the events a write
//! causes are queued to their streams before the lock is released, so every stream sees
//! changes in commit order. A stream whose client went away is closed the next time an
//! event or a keep-alive cannot be queued to it.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, Limited, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt as _;

use crate::realtime::{Opened, Session};
use crate::rest::{refusal_response, Database, Handled, HttpRequest, HttpResponse, SseEvent};
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
    /// The server time.
    pub clock: Clock,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            keep_alive: Duration::from_secs(30),
            max_body_bytes: 256 * 1024 * 1024,
            clock: Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            }),
        }
    }
}

type Body = BoxBody<Bytes, Infallible>;
type Streams = Arc<Mutex<BTreeMap<u64, mpsc::UnboundedSender<SseEvent>>>>;

struct Shared {
    database: Arc<Mutex<Database>>,
    streams: Streams,
    config: ServerConfig,
}

/// Serves `database` on `listener` until the task is dropped.
pub async fn serve(listener: TcpListener, database: Arc<Mutex<Database>>, config: ServerConfig) {
    let shared = Arc::new(Shared {
        database,
        streams: Arc::new(Mutex::new(BTreeMap::new())),
        config,
    });
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            continue;
        };
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let shared = Arc::clone(&shared);
                async move { Ok::<_, Infallible>(answer(&shared, request).await) }
            });
            // One request per connection, so only its request line needs escaping. A
            // connection error concerns that client only.
            let _ = http1::Builder::new()
                .keep_alive(false)
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
    let Ok(collected) = Limited::new(body, shared.config.max_body_bytes)
        .collect()
        .await
    else {
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
            .filter_map(|(name, value)| {
                Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
            })
            .collect(),
        body: collected.to_bytes().to_vec(),
    };
    let now = (shared.config.clock)();
    let mut database = shared
        .database
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    match database.handle(&request, now) {
        Handled::Response { response, events } => {
            deliver(shared, &mut database, events);
            full(response)
        }
        Handled::Stream {
            id,
            response,
            initial,
        } => {
            let (sender, receiver) = mpsc::unbounded_channel();
            // The receiver is alive, so the first event is queued.
            let _ = sender.send(initial);
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
            .is_some_and(|sender| sender.send(event).is_ok());
        if !delivered {
            streams.remove(&id);
            database.unsubscribe(id);
        }
    }
}

fn spawn_keep_alive(shared: Arc<Shared>, id: u64, sender: mpsc::UnboundedSender<SseEvent>) {
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(shared.config.keep_alive);
        ticks.tick().await;
        loop {
            ticks.tick().await;
            if sender.send(SseEvent::keep_alive()).is_err() {
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

fn streaming(head: HttpResponse, receiver: mpsc::UnboundedReceiver<SseEvent>) -> Response<Body> {
    let frames = UnboundedReceiverStream::new(receiver)
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

fn is_websocket_upgrade(request: &Request<Incoming>) -> bool {
    request.method() == hyper::Method::GET
        && header(request, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// Answers a WebSocket upgrade: a refusal before the upgrade, or 101 and a task that
/// serves the realtime protocol on the upgraded connection.
fn upgrade(shared: &Arc<Shared>, mut request: Request<Incoming>) -> Response<Body> {
    let Some(key) = header(&request, "sec-websocket-key").map(str::to_owned) else {
        return plain(400, "Missing Sec-WebSocket-Key.");
    };
    if header(&request, "sec-websocket-version") != Some("13") {
        return plain(400, "Unsupported Sec-WebSocket-Version.");
    }
    let target = request.uri().path_and_query().map_or_else(
        || request.uri().path().to_owned(),
        |pq| pq.as_str().to_owned(),
    );
    let host = header(&request, "host").map(str::to_owned);
    let now = (shared.config.clock)();
    let opened = shared
        .database
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .open_realtime(&target, host.as_deref(), now);
    let opened = match opened {
        Ok(opened) => opened,
        Err(refusal) => return full(refusal_response(&refusal)),
    };
    let on_upgrade = hyper::upgrade::on(&mut request);
    let shared = Arc::clone(shared);
    tokio::spawn(async move {
        if let Ok(upgraded) = on_upgrade.await {
            serve_realtime(&shared, TokioIo::new(upgraded), opened).await;
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
) {
    let mut session: Session = match opened {
        Opened::Shutdown(frames) => {
            let _ = send_text(&mut socket, &frames).await;
            send_close(&mut socket, CloseCode::Normal).await;
            return;
        }
        Opened::Session(session, frames) => {
            if send_text(&mut socket, &frames).await.is_err() {
                return;
            }
            session
        }
    };
    let limit = shared.config.max_body_bytes;
    let mut assembler = Assembler::new(limit);
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        match decode(&buffer, limit) {
            Err(error) => {
                send_close(&mut socket, error.close_code()).await;
                return;
            }
            Ok(Decoded::Incomplete) => match socket.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            },
            Ok(Decoded::Frame(frame, used)) => {
                buffer.drain(..used);
                let message = match assembler.push(frame) {
                    Err(error) => {
                        send_close(&mut socket, error.close_code()).await;
                        return;
                    }
                    Ok(None) => continue,
                    Ok(Some(message)) => message,
                };
                let written = match message {
                    Message::Text(text) => {
                        let replies = {
                            let now = (shared.config.clock)();
                            let mut database = shared
                                .database
                                .lock()
                                .unwrap_or_else(PoisonError::into_inner);
                            let received = session.receive(&mut database, &text, now);
                            deliver(shared, &mut database, received.events);
                            received.replies
                        };
                        send_text(&mut socket, &replies).await
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
