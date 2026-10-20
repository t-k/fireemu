//! Long-polling connections (`/.lp`) behind hyper; [`crate::long_poll`] holds the text.
//!
//! Each connection keeps its realtime session, the segments still being joined, the
//! messages waiting to be sent and at most one held request. Pushes from other connections
//! and REST go straight into the outbox under the database lock, so they keep commit order
//! with the connection's own answers. A new request first releases the held one with what
//! is waiting (possibly nothing), then hands its packets to the session. Locks are taken in
//! the order database, listeners, connection; a connection's state is only locked with the
//! database lock held, and the registry lock is taken alone or last.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use fireemu_adapter_support::entropy;
use hyper::body::Incoming;
use hyper::{Request, Response};
use tokio::sync::oneshot;

use super::{deliver as deliver_events, full, with_headers, Body, Shared, Sink};
use crate::long_poll::{
    callbacks, disconnect_frame, packet, parse, reset, start_script, LpRequest, Reassembler,
    Segment, NOTHING,
};
use crate::realtime::{Opened, Session};
use crate::request::{self, Refusal};
use crate::rest::{refusal_response, Database};

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
    /// Messages that may wait for a request before the connection is dropped as gone.
    queue: usize,
    state: Mutex<State>,
}

struct State {
    session: Session,
    segments: Reassembler,
    /// Messages for the next answer, and their bytes.
    outbox: Vec<String>,
    outbox_bytes: usize,
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
        self.outbox_bytes = 0;
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

    /// Ends the connection's state: its held request gets an empty answer.
    fn end(&mut self) {
        self.closed = true;
        self.held = None;
        self.outbox.clear();
        self.outbox_bytes = 0;
    }
}

/// Puts a message pushed by another connection or REST into the outbox, under the database
/// and listeners locks; `false` when the connection is closed or holds more than it may, so
/// the caller drops it.
pub(super) fn deliver(connection: &Connection, message: String, budget: usize) -> bool {
    let mut state = connection.lock();
    if state.closed {
        return false;
    }
    state.outbox_bytes += message.len();
    state.outbox.push(message);
    if state.outbox_bytes > budget || state.outbox.len() > connection.queue {
        state.end();
        return false;
    }
    state.release();
    true
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

fn lock_database(shared: &Shared) -> MutexGuard<'_, Database> {
    shared
        .database
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
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
        .map(str::to_owned)
        .unwrap_or_default();
    let (_, params) = request::split_target(&target);
    match parse(&params) {
        LpRequest::Start { callback } => start(shared, &target, &host, callback),
        LpRequest::Poll {
            id,
            password,
            segments,
        } => match find(shared, &id, &password) {
            Some(connection) => poll(shared, &connection, segments, &host).await,
            None => script(reset(&host)),
        },
        LpRequest::Disconnect { id, password } => {
            if let Some(connection) = find(shared, &id, &password) {
                let mut database = lock_database(shared);
                close(shared, &mut database, &connection, &mut connection.lock());
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

/// A connection's password: ten letters and digits, as the official emulator's, drawn from
/// the operating system. The password is all that keeps another page from polling the
/// connection (the client number is sequential), so it never comes from the database's
/// seeded generator; `None` when the operating system has no entropy to give.
fn draw_password() -> Option<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut password = String::with_capacity(PASSWORD_LENGTH);
    let mut bytes = [0u8; 32];
    while password.len() < PASSWORD_LENGTH {
        entropy::fill(&mut bytes).ok()?;
        // 248 = 4 * 62: rejecting the rest keeps every character equally likely.
        password.extend(
            bytes
                .iter()
                .filter(|b| **b < 248)
                .map(|b| char::from(ALPHABET[usize::from(*b % 62)]))
                .take(PASSWORD_LENGTH - password.len()),
        );
    }
    Some(password)
}

const PASSWORD_LENGTH: usize = 10;

fn start(shared: &Arc<Shared>, target: &str, host: &str, callback: Option<i32>) -> Response<Body> {
    let Some(password) = draw_password() else {
        return full(refusal_response(&Refusal::new(503, "Service Unavailable")));
    };
    let now = (shared.config.clock)();
    let mut database = lock_database(shared);
    let opened = match database.open_realtime(target, Some(host).filter(|h| !h.is_empty()), now) {
        Err(refusal) => return full(refusal_response(&refusal)),
        Ok(opened) => opened,
    };
    let (session, handshake) = match opened {
        Opened::Shutdown(frames) => {
            // The official emulator never answers a start with another protocol version;
            // this server tells the client why and closes, as over a WebSocket.
            return script(format!(
                "{}{}pLPCommand('close');\n",
                callbacks(callback),
                packet(0, &frames)
            ));
        }
        Opened::Session(session, frames) => (
            session.for_long_polling(),
            frames.into_iter().next().unwrap_or_default(),
        ),
    };
    let limit = database.realtime_message_bytes();
    let client = session.client();
    let connection = Arc::new(Connection {
        client,
        password: password.clone(),
        queue: shared.config.stream_queue.max(1),
        state: Mutex::new(State {
            session,
            segments: Reassembler::new(limit),
            outbox: Vec::new(),
            outbox_bytes: 0,
            next_packet: 1,
            held: None,
            next_ticket: 0,
            last_request: Instant::now(),
            closed: false,
        }),
    });
    shared
        .listeners
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(client, Sink::LongPoll(Arc::clone(&connection)));
    drop(database);
    shared
        .long_polls
        .lock()
        .insert(client, Arc::clone(&connection));
    tokio::spawn(reap(Arc::clone(shared), Arc::clone(&connection)));
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
    host: &str,
) -> Response<Body> {
    let (ticket, mut receiver) = {
        let mut database = lock_database(shared);
        let mut state = connection.lock();
        if state.closed {
            return script(reset(host));
        }
        let Ok(messages) = state.segments.add(segments) else {
            // Segments the client numbered are gone, so its packets can never line up
            // again: end the connection, and the next request gets a reset.
            close(shared, &mut database, connection, &mut state);
            return full(refusal_response(&Refusal::bad("Bad Request")));
        };
        state.last_request = Instant::now();
        state.release();
        for message in messages {
            if !answer_message(shared, &mut database, &mut state, &message) {
                // What the session answered before it ended goes out; the reset reaches
                // the client as the answer to its next request, from an unknown connection.
                let body = if state.outbox.is_empty() {
                    NOTHING.to_owned()
                } else {
                    state.take_packet()
                };
                close(shared, &mut database, connection, &mut state);
                return script(body);
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
    match tokio::time::timeout(shared.config.long_poll_hold, &mut receiver).await {
        Ok(Ok(body)) => script(body),
        // The connection was closed while the request waited.
        Ok(Err(_)) => script(String::new()),
        Err(_) => {
            let expired = {
                let mut database = lock_database(shared);
                let mut state = connection.lock();
                let expired = state.held.as_ref().is_some_and(|(held, _)| *held == ticket);
                if expired {
                    // Nobody asked again within the hold time: the client is gone.
                    close(shared, &mut database, connection, &mut state);
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

/// Hands one message to the session, under the database lock; `false` when the connection
/// must end. The session takes its own pushes; the others go to their connections.
fn answer_message(
    shared: &Shared,
    database: &mut Database,
    state: &mut State,
    message: &str,
) -> bool {
    let Some(prepared) = state.session.prepare(message) else {
        return true;
    };
    let now = (shared.config.clock)();
    let mut received = state.session.dispatch_prepared(database, prepared, now);
    deliver_events(shared, database, std::mem::take(&mut received.events));
    let ends = received.close.is_some() || received.drop_connection;
    if ends {
        // The official emulator sends no reset in the request that ends the connection
        // (over a WebSocket the reset goes before the drop).
        let reset = state.session.reset_control();
        received.replies.retain(|reply| *reply != reset);
    }
    // The request answers these at once, so they do not count against the bounds.
    state.outbox.extend(received.replies);
    !ends
}

/// Ends a connection, with the database lock and its state held: its held request gets an
/// empty answer, its listens go.
fn close(shared: &Shared, database: &mut Database, connection: &Connection, state: &mut State) {
    if !state.closed {
        state.end();
    }
    shared
        .listeners
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&connection.client);
    shared.long_polls.lock().remove(&connection.client);
    database.close_realtime(connection.client);
}

/// Closes a connection that sends no request for twice the hold time (a held request that
/// runs out closes it sooner), and forgets one closed for falling behind.
async fn reap(shared: Arc<Shared>, connection: Arc<Connection>) {
    let hold = shared.config.long_poll_hold;
    let mut ticks = tokio::time::interval(hold);
    ticks.tick().await;
    loop {
        ticks.tick().await;
        let mut database = lock_database(&shared);
        let mut state = connection.lock();
        if state.closed || (state.held.is_none() && state.last_request.elapsed() >= hold * 2) {
            close(&shared, &mut database, &connection, &mut state);
            return;
        }
    }
}
