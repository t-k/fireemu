//! Long-polling connections (`/.lp`) behind hyper; [`crate::long_poll`] holds the text.
//!
//! Each connection keeps its realtime session, the segments still being joined, the
//! messages waiting to be sent and at most one held request. A new request first releases
//! the held one with what is waiting (possibly nothing), then hands its packets to the
//! session; whatever the session answers, and whatever other connections push, goes to
//! the next request answered. Locks are taken in the order connection, database, listeners.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::sync::{mpsc, oneshot};

use super::{deliver, full, with_headers, Body, Shared};
use crate::long_poll::{
    callbacks, disconnect_frame, packet, parse, reset, start_script, LpRequest, Reassembler,
    Segment, NOTHING,
};
use crate::realtime::{Opened, Session};
use crate::request::{self, Refusal};
use crate::rest::refusal_response;

const SCRIPT: &str = "application/javascript; charset=utf-8";
const HTML: &str = "text/html; charset=utf-8";

/// The open long-polling connections, by client number.
#[derive(Default)]
pub(super) struct Connections(Mutex<BTreeMap<u64, Arc<Connection>>>);

impl Connections {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<u64, Arc<Connection>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub(super) struct Connection {
    client: u64,
    password: String,
    state: Mutex<State>,
}

struct State {
    session: Session,
    segments: Reassembler,
    /// Messages for the next answer.
    outbox: Vec<String>,
    /// The number of the next answer that carries messages.
    next_packet: u64,
    /// The held request: its ticket and where its answer goes.
    held: Option<(u64, oneshot::Sender<String>)>,
    next_ticket: u64,
    last_request: Instant,
    closed: bool,
}

impl Connection {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl State {
    /// The next answer, carrying every waiting message.
    fn take_packet(&mut self) -> String {
        let body = packet(self.next_packet, &std::mem::take(&mut self.outbox));
        self.next_packet += 1;
        body
    }

    /// Answers the held request, if any, with what is waiting.
    fn release(&mut self) {
        if let Some((_, sender)) = self.held.take() {
            let body = self.take_packet();
            // A held request whose client went away has nobody to read it.
            let _ = sender.send(body);
        }
    }
}

fn script(body: String) -> Response<Body> {
    with_headers(
        200,
        vec![("Content-Type".to_owned(), SCRIPT.to_owned())],
        http_body_util::BodyExt::boxed(http_body_util::Full::new(bytes::Bytes::from(body))),
    )
}

fn html(body: String) -> Response<Body> {
    with_headers(
        200,
        vec![("Content-Type".to_owned(), HTML.to_owned())],
        http_body_util::BodyExt::boxed(http_body_util::Full::new(bytes::Bytes::from(body))),
    )
}

/// Answers a request to `/.lp` (any method; the official emulator reads only the query).
pub(super) async fn answer(shared: &Arc<Shared>, request: &Request<Incoming>) -> Response<Body> {
    let target = request.uri().path_and_query().map_or_else(
        || request.uri().path().to_owned(),
        |pq| pq.as_str().to_owned(),
    );
    let host = request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let (_, params) = request::split_target(&target);
    match parse(&params) {
        LpRequest::Start { callback } => start(shared, &target, host.as_deref(), callback),
        LpRequest::Poll {
            id,
            password,
            segments,
        } => {
            let Some(connection) = find(shared, &id, &password) else {
                return script(reset(host.as_deref().unwrap_or_default()));
            };
            poll(shared, &connection, segments).await
        }
        LpRequest::Disconnect { id, password } => {
            if let Some(connection) = find(shared, &id, &password) {
                close(shared, &connection, &mut connection.lock());
            }
            script(NOTHING.to_owned())
        }
        LpRequest::DisconnectFrame { id, password } => html(disconnect_frame(id, &password)),
        LpRequest::Refused => html(String::new()),
    }
}

fn find(shared: &Shared, id: &str, password: &str) -> Option<Arc<Connection>> {
    let client: u64 = id.parse().ok()?;
    let connection = shared.long_polls.lock().get(&client).cloned()?;
    (connection.password == password).then_some(connection)
}

fn start(
    shared: &Arc<Shared>,
    target: &str,
    host: Option<&str>,
    callback: Option<i32>,
) -> Response<Body> {
    let now = (shared.config.clock)();
    let (opened, password, limit) = {
        let mut database = shared
            .database
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let opened = database.open_realtime(target, host, now);
        (
            opened,
            database.long_poll_password(),
            database.realtime_message_bytes(),
        )
    };
    let (session, handshake) = match opened {
        Err(refusal) => return full(refusal_response(&refusal)),
        Ok(Opened::Shutdown(frames)) => {
            // The official emulator never answers a start with another protocol version;
            // this server tells the client why and closes, as over a WebSocket.
            return script(format!(
                "{}{}pLPCommand('close');\n",
                callbacks(callback),
                packet(0, &frames)
            ));
        }
        Ok(Opened::Session(session, frames)) => (
            session.for_long_polling(),
            frames.into_iter().next().unwrap_or_default(),
        ),
    };
    let client = session.client();
    let connection = Arc::new(Connection {
        client,
        password: password.clone(),
        state: Mutex::new(State {
            session,
            segments: Reassembler::new(limit),
            outbox: Vec::new(),
            next_packet: 1,
            held: None,
            next_ticket: 0,
            last_request: Instant::now(),
            closed: false,
        }),
    });
    let (sender, pushes) = mpsc::channel(shared.config.stream_queue.max(1));
    shared
        .listeners
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(client, sender);
    shared
        .long_polls
        .lock()
        .insert(client, Arc::clone(&connection));
    tokio::spawn(forward(Arc::clone(shared), connection, pushes));
    script(start_script(
        callback,
        &client.to_string(),
        &password,
        &handshake,
    ))
}

async fn poll(
    shared: &Arc<Shared>,
    connection: &Arc<Connection>,
    segments: Vec<Segment>,
) -> Response<Body> {
    let receiver = {
        let mut state = connection.lock();
        if state.closed {
            return script(NOTHING.to_owned());
        }
        let Ok(messages) = state.segments.add(segments) else {
            return full(refusal_response(&Refusal::bad("Bad Request")));
        };
        state.last_request = Instant::now();
        state.release();
        for message in messages {
            if !answer_message(shared, &mut state, &message) {
                close(shared, connection, &mut state);
                return script(NOTHING.to_owned());
            }
        }
        if !state.outbox.is_empty() {
            return script(state.take_packet());
        }
        let (sender, receiver) = oneshot::channel();
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        state.held = Some((ticket, sender));
        (ticket, receiver)
    };
    let (ticket, mut receiver) = receiver;
    match tokio::time::timeout(shared.config.long_poll_hold, &mut receiver).await {
        Ok(Ok(body)) => script(body),
        // The connection was closed while the request waited.
        Ok(Err(_)) => script(String::new()),
        Err(_) => {
            let expired = {
                let mut state = connection.lock();
                let expired = state.held.as_ref().is_some_and(|(held, _)| *held == ticket);
                if expired {
                    // Nobody asked again within the hold time: the client is gone.
                    state.held = None;
                    close(shared, connection, &mut state);
                }
                expired
            };
            if expired {
                return script(NOTHING.to_owned());
            }
            // Released just as the hold ended.
            match receiver.await {
                Ok(body) => script(body),
                Err(_) => script(String::new()),
            }
        }
    }
}

/// Hands one message to the session; `false` when the connection must end.
fn answer_message(shared: &Arc<Shared>, state: &mut State, message: &str) -> bool {
    let Some(prepared) = state.session.prepare(message) else {
        return true;
    };
    let now = (shared.config.clock)();
    let mut database = shared
        .database
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let mut received = state
        .session
        .dispatch_prepared(&mut database, prepared, now);
    deliver(shared, &mut database, std::mem::take(&mut received.events));
    drop(database);
    state.outbox.extend(received.replies);
    received.close.is_none() && !received.drop_connection
}

/// Ends a connection: its held request gets an empty answer, its listens go.
fn close(shared: &Shared, connection: &Connection, state: &mut State) {
    if state.closed {
        return;
    }
    state.closed = true;
    state.held = None;
    state.outbox.clear();
    shared.long_polls.lock().remove(&connection.client);
    let mut database = shared
        .database
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    shared
        .listeners
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&connection.client);
    database.close_realtime(connection.client);
}

/// Moves what other connections push into the connection's outbox, releasing a held
/// request; closes the connection when its queue overflowed or no request came for twice
/// the hold time (a held request that runs out closes it sooner).
async fn forward(
    shared: Arc<Shared>,
    connection: Arc<Connection>,
    mut pushes: mpsc::Receiver<String>,
) {
    let hold = shared.config.long_poll_hold;
    let mut ticks = tokio::time::interval(hold);
    ticks.tick().await;
    loop {
        tokio::select! {
            message = pushes.recv() => {
                let mut state = connection.lock();
                let Some(message) = message else {
                    close(&shared, &connection, &mut state);
                    return;
                };
                if state.closed {
                    return;
                }
                state.outbox.push(message);
                if state.outbox.len() > shared.config.stream_queue.max(1) {
                    close(&shared, &connection, &mut state);
                    return;
                }
                state.release();
            }
            _ = ticks.tick() => {
                let mut state = connection.lock();
                if state.closed {
                    return;
                }
                if state.held.is_none() && state.last_request.elapsed() >= hold * 2 {
                    close(&shared, &connection, &mut state);
                    return;
                }
            }
        }
    }
}
