//! Long-polling connections (`/.lp`) behind hyper; [`crate::long_poll`] holds the text.
//!
//! Each connection keeps its realtime session, the segments still being joined, the
//! messages waiting to be sent and at most one held request. Pushes from other connections
//! and REST go straight into the outbox under the database lock, so they keep commit order
//! with the connection's own answers. A new request first releases the held one with what
//! is waiting (possibly nothing), then hands its packets to the session.
//!
//! Locks: a connection's state is locked only with the database lock held, by every path
//! (`poll`, an expired hold, `disconn`, the reaper and `deliver`), so the database lock
//! serializes them. Under it the order varies: `deliver` takes the listeners and then a
//! connection, `close` a connection and then the listeners and the registry. That cannot
//! deadlock, because neither runs without the database lock. The registry lock is never held
//! while the database lock is taken.

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
    /// Where the held request's answer goes.
    held: Option<oneshot::Sender<String>>,
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

    /// Answers the held request, if any, with what is waiting. A held request whose client
    /// went away takes nothing (its receiver is gone, so the send hands the packet back): its
    /// packet number and messages wait for the next request, since the SDK reads packets
    /// strictly in order.
    fn release(&mut self) {
        let Some(sender) = self.held.take() else {
            return;
        };
        let messages = std::mem::take(&mut self.outbox);
        match sender.send(packet(self.next_packet, &messages)) {
            Ok(()) => {
                self.outbox_bytes = 0;
                self.next_packet += 1;
            }
            Err(_) => self.outbox = messages,
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
    // An empty outbox takes any one message, as an empty push queue does.
    let alone = state.outbox.is_empty();
    state.outbox_bytes += message.len();
    state.outbox.push(message);
    if (!alone && state.outbox_bytes > budget) || state.outbox.len() > connection.queue {
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
    if let Err(refusal) = request::check_escapes(&target) {
        return full(refusal_response(&refusal));
    }
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
    let mut password = String::with_capacity(PASSWORD_LENGTH);
    let mut bytes = [0u8; 32];
    while password.len() < PASSWORD_LENGTH {
        entropy::fill(&mut bytes).ok()?;
        extend_password(&mut password, &bytes);
    }
    Some(password)
}

/// Adds a letter or digit for each usable byte until the password is long enough. Bytes
/// from 248 (4 * 62) up are skipped, which keeps every character equally likely.
fn extend_password(password: &mut String, bytes: &[u8]) {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for byte in bytes {
        if password.len() == PASSWORD_LENGTH {
            return;
        }
        if *byte < 248 {
            password.push(char::from(ALPHABET[usize::from(*byte % 62)]));
        }
    }
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
    let mut receiver = {
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
        state.held = Some(sender);
        receiver
    };
    if let Ok(answer) = tokio::time::timeout(shared.config.long_poll_hold, &mut receiver).await {
        // An error: the connection was closed while the request waited.
        return script(answer.unwrap_or_default());
    }
    let mut database = lock_database(shared);
    let mut state = connection.lock();
    match expiry(&mut receiver) {
        Expiry::Released(body) => script(body),
        Expiry::Closed => script(String::new()),
        Expiry::Held => {
            // Nobody asked again within the hold time: the client is gone.
            close(shared, &mut database, connection, &mut state);
            script(NOTHING.to_owned())
        }
    }
}

/// What became of a held request whose hold time ran out.
#[derive(Debug, PartialEq, Eq)]
enum Expiry {
    /// A later request or a push answered it just as the hold ended.
    Released(String),
    /// The connection was closed.
    Closed,
    /// It is still the held request.
    Held,
}

/// Reads the held request's channel with the connection's state locked: the request is
/// answered and the connection closed only under that lock, so an empty, open channel means
/// the request is still held.
fn expiry(receiver: &mut oneshot::Receiver<String>) -> Expiry {
    match receiver.try_recv() {
        Ok(body) => Expiry::Released(body),
        Err(oneshot::error::TryRecvError::Closed) => Expiry::Closed,
        Err(oneshot::error::TryRecvError::Empty) => Expiry::Held,
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

#[cfg(test)]
mod tests {
    use super::{expiry, extend_password, oneshot, Expiry};

    #[test]
    fn password_bytes_map_to_letters_and_digits_evenly() {
        let mut password = String::new();
        extend_password(&mut password, &[0, 25, 26, 61, 62, 247, 248, 255]);
        // 248 and up are skipped; the rest are taken modulo 62.
        assert_eq!(password, "AZa9A9");
        extend_password(&mut password, &[1, 2, 3, 4, 5, 6]);
        // Ten characters, then nothing more.
        assert_eq!(password, "AZa9A9BCDE");
        let full = password.clone();
        extend_password(&mut password, &[7]);
        assert_eq!(password, full);
    }

    #[test]
    fn an_expired_hold_tells_released_closed_and_held_apart() {
        let (sender, mut receiver) = oneshot::channel();
        sender.send("pRTLPCB(3,[]);\n".to_owned()).unwrap();
        assert_eq!(
            expiry(&mut receiver),
            Expiry::Released("pRTLPCB(3,[]);\n".to_owned())
        );
        let (sender, mut receiver) = oneshot::channel::<String>();
        drop(sender);
        assert_eq!(expiry(&mut receiver), Expiry::Closed);
        let (_sender, mut receiver) = oneshot::channel::<String>();
        assert_eq!(expiry(&mut receiver), Expiry::Held);
    }
}
