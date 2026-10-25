//! The realtime wire protocol the SDKs speak over WebSocket (`/.ws?v=5&ns=<ns>`).
//!
//! Every frame is one JSON message, or a decimal frame count followed by that many frames
//! that join into one message (the SDKs split at 16384 characters, and so does this
//! server). A message is a control message `{"t":"c","d":{"t":<type>,"d":...}}` or a data
//! message `{"t":"d","d":{"r":<request>,"a":<action>,"b":<body>}}`, answered by
//! `{"t":"d","d":{"r":<request>,"b":{"s":<status>,"d":<data>}}}`.
//!
//! This module serves the handshake, keepalive, pings, `s` (stats), `echo`, `auth`, `gauth`,
//! `unauth`, `appcheck`, `g` (get), `p` (put, with `h` as a transaction's compare-and-set),
//! `m` (merge), `q` (listen) and `n` (unlisten); the data a listen receives is computed in
//! the private `listen` module. `onDisconnect` comes with RTDB-02. Every answer follows the official
//! emulator (firebase-database-emulator v4.11.2).

use std::collections::{BTreeMap, BTreeSet};

use fireemu_core_database::hash::node_hash;
use fireemu_core_database::rules::ReadKind;
use fireemu_core_database::server_value::resolve;
use fireemu_core_database::{
    Bound, BoundKey, ErrorKind, Json, Limit, Node, OrderBy, Path, QueryParams, ServerValueContext,
};

use crate::access::{auth_from_claims, Access, WriteOp};
use crate::json_parse::parse_with_keys;
use crate::json_text::{priority_at, render, wire_json, Style};
use crate::listen::Listen;
use crate::namespace::route;
use crate::request::{self, Refusal};
use crate::rest::{Change, Database, Patched, SseEvent};
use crate::websocket::CloseCode;

/// The protocol version this server speaks.
pub const PROTOCOL_VERSION: &str = "5";
/// The longest frame, in characters, before a message is split.
pub const MAX_FRAME_CHARS: usize = 16_384;

const VERSION_ERROR: &str =
    "Version error. Please make sure you are using the latest Firebase library";

/// The result of opening a realtime connection.
#[derive(Debug)]
pub enum Opened {
    /// A session and the frames to send first (the handshake).
    Session(Session, Vec<String>),
    /// The frames to send before closing: the client asked for another protocol version.
    Shutdown(Vec<String>),
}

/// One realtime connection.
#[derive(Debug)]
pub struct Session {
    namespace: String,
    client: u64,
    /// Who the connection is.
    access: Access,
    /// Frames still expected for a split message, and what arrived so far.
    pending: Option<(usize, String)>,
    /// The longest message, split frames joined.
    limit: usize,
    /// The members of the merge being answered, in the order they were sent.
    merge_order: Vec<String>,
    /// Whether answers are split into WebSocket frames (not over long polling).
    split: bool,
    /// The host the client connected to, named in a reset.
    host: String,
}

/// A received frame, reassembled and parsed without the database.
#[derive(Debug)]
pub struct Prepared(Ready);

#[derive(Debug)]
enum Ready {
    /// A whole message, parsed (or not JSON), and for a merge its members in sent order.
    Message(Result<Json, crate::json_parse::ParseError>, Vec<String>),
    /// The connection must close with this code.
    Close(CloseCode),
}

/// What one received frame produced.
#[derive(Debug, Default)]
pub struct Received {
    /// Frames to send back, in order.
    pub replies: Vec<String>,
    /// Events for open REST event streams.
    pub events: Vec<(u64, SseEvent)>,
    /// Whether to drop the connection without a close frame, as the official emulator does
    /// for a request it cannot handle at all.
    pub drop_connection: bool,
    /// A close code to end the connection with.
    pub close: Option<CloseCode>,
}

impl Database {
    /// Opens a realtime connection for the request target `/.ws?...`. An invalid namespace
    /// is refused before the upgrade (403), as the official emulator refuses it.
    pub fn open_realtime(
        &mut self,
        target: &str,
        host: Option<&str>,
        now_millis: i64,
    ) -> Result<Opened, Refusal> {
        request::check_escapes(target)?;
        let (_, params) = request::split_target(target);
        let namespace = route(
            params.get("ns").map(String::as_str),
            host,
            &self.options().default_namespace,
        )
        .map_err(|_| Refusal::new(403, "Invalid Firebase database name"))?;
        if params.get("v").map(String::as_str) != Some(PROTOCOL_VERSION) {
            return Ok(Opened::Shutdown(vec![control(
                "s",
                &Json::string(VERSION_ERROR),
            )]));
        }
        let (client, session_id) = self.next_client();
        let handshake = Json::object([
            ("ts", Json::int(now_millis)),
            ("v", Json::string(PROTOCOL_VERSION)),
            ("h", Json::string(host.unwrap_or_default())),
            ("s", Json::String(session_id)),
        ]);
        // The handshake's members go in the server's order, not in key order.
        let data = format!(
            "{{\"ts\":{},\"v\":{},\"h\":{},\"s\":{}}}",
            render(&handshake_member(&handshake, "ts"), Style::Compact),
            render(&handshake_member(&handshake, "v"), Style::Compact),
            render(&handshake_member(&handshake, "h"), Style::Compact),
            render(&handshake_member(&handshake, "s"), Style::Compact),
        );
        let session = Session {
            namespace,
            client,
            access: Access::Anonymous,
            pending: None,
            limit: self.options().realtime_message_bytes,
            merge_order: Vec::new(),
            split: true,
            host: host.unwrap_or_default().to_owned(),
        };
        Ok(Opened::Session(
            session,
            vec![format!(
                "{{\"t\":\"c\",\"d\":{{\"t\":\"h\",\"d\":{data}}}}}"
            )],
        ))
    }
}

fn handshake_member(handshake: &Json, name: &str) -> Json {
    match handshake {
        Json::Object(map) => map.get(name).cloned().unwrap_or(Json::Null),
        _ => Json::Null,
    }
}

/// A control message.
fn control(kind: &str, data: &Json) -> String {
    format!(
        "{{\"t\":\"c\",\"d\":{{\"t\":{},\"d\":{}}}}}",
        render(&Json::string(kind), Style::Compact),
        render(data, Style::Compact)
    )
}

/// A response to request `r`.
fn response(r: u64, status: &str, data: &Json) -> String {
    format!(
        "{{\"t\":\"d\",\"d\":{{\"r\":{r},\"b\":{{\"s\":{},\"d\":{}}}}}}}",
        render(&Json::string(status), Style::Compact),
        render(data, Style::Compact)
    )
}

/// Splits an outgoing message into frames: one frame, or a frame count and the pieces.
pub fn split_frames(message: String) -> Vec<String> {
    if message.chars().count() <= MAX_FRAME_CHARS {
        return vec![message];
    }
    let chars: Vec<char> = message.chars().collect();
    let pieces: Vec<String> = chars
        .chunks(MAX_FRAME_CHARS)
        .map(|chunk| chunk.iter().collect())
        .collect();
    let mut frames = Vec::with_capacity(pieces.len() + 1);
    frames.push(pieces.len().to_string());
    frames.extend(pieces);
    frames
}

/// A refusal answered with a status, or a message the server cannot read.
enum Failure {
    /// An answer with this status and message.
    Status(&'static str, String),
    /// A connection error control message (`t: "e"`).
    Malformed,
    /// No answer at all.
    Silent,
    /// The connection is dropped.
    Drop,
    /// An internal error answer and a reset to this host, then the connection is dropped.
    InternalReset,
    /// These frames, then the connection is dropped.
    DropAfter(Vec<String>),
}

type Answer = Result<Json, Failure>;

fn invalid(message: impl Into<String>) -> Failure {
    Failure::Status("invalid_parameters", message.into())
}

impl Session {
    /// The session for a long-polling connection: answers stay whole messages, since the
    /// transport carries them in packets rather than WebSocket frames.
    #[must_use]
    pub fn for_long_polling(mut self) -> Self {
        self.split = false;
        self
    }

    /// The connection's number, which the database's queued data messages are addressed to.
    pub fn client(&self) -> u64 {
        self.client
    }

    /// The control that sends the client back to this host to reconnect.
    pub(crate) fn reset_control(&self) -> String {
        control("r", &Json::String(self.host.clone()))
    }

    /// Takes one received text frame.
    pub fn receive(&mut self, db: &mut Database, frame: &str, now_millis: i64) -> Received {
        match self.prepare(frame) {
            Some(prepared) => self.dispatch_prepared(db, prepared, now_millis),
            None => Received::default(),
        }
    }

    /// Reassembles and parses a received text frame; `None` while a split message is still
    /// incomplete. It needs no database, so it runs before the database lock is taken.
    pub fn prepare(&mut self, frame: &str) -> Option<Prepared> {
        match self.reassemble(frame) {
            Err(code) => Some(Prepared(Ready::Close(code))),
            Ok(None) => None,
            Ok(Some(message)) => {
                let parsed = crate::json_parse::parse(&message);
                let order = if is_merge(&parsed) {
                    merge_order(&message)
                } else {
                    Vec::new()
                };
                Some(Prepared(Ready::Message(parsed, order)))
            }
        }
    }

    /// Answers a prepared message.
    pub fn dispatch_prepared(
        &mut self,
        db: &mut Database,
        prepared: Prepared,
        now_millis: i64,
    ) -> Received {
        let mut received = Received::default();
        let parsed = match prepared.0 {
            Ready::Close(code) => {
                received.close = Some(code);
                return received;
            }
            Ready::Message(parsed, order) => {
                self.merge_order = order;
                parsed
            }
        };
        let replies = match parsed {
            Ok(Json::Object(envelope)) => {
                self.dispatch(db, &envelope, now_millis, &mut received.events)
            }
            _ => Err(Failure::Malformed),
        };
        let replies = match replies {
            Ok(replies) => replies,
            Err(Failure::Silent | Failure::Status(..)) => Vec::new(),
            Err(Failure::Drop | Failure::InternalReset) => {
                received.drop_connection = true;
                Vec::new()
            }
            Err(Failure::DropAfter(frames)) => {
                received.drop_connection = true;
                frames
            }
            Err(Failure::Malformed) => vec![self.connection_error(db)],
        };
        // The connection's own data messages go before the answer, as the official
        // emulator sends a listen's value, and a write's change, before acknowledging.
        let own = db.take_pushes(self.client);
        let messages = own.into_iter().chain(replies);
        received.replies = if self.split {
            messages.flat_map(split_frames).collect()
        } else {
            messages.collect()
        };
        received
    }

    /// Joins split frames; a split message longer than the limit closes the connection
    /// (1009) as soon as it crosses it.
    fn reassemble(&mut self, frame: &str) -> Result<Option<String>, CloseCode> {
        if let Some((remaining, mut joined)) = self.pending.take() {
            if joined.len() + frame.len() > self.limit {
                return Err(CloseCode::TooBig);
            }
            joined.push_str(frame);
            if remaining > 1 {
                self.pending = Some((remaining - 1, joined));
                return Ok(None);
            }
            return Ok(Some(joined));
        }
        // A short all-digit frame is a frame count; "0" is the SDK's keepalive.
        if frame.len() <= 6 && !frame.is_empty() && frame.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(count) = frame.parse::<usize>() {
                if count > 0 {
                    self.pending = Some((count, String::new()));
                }
                return Ok(None);
            }
        }
        Ok(Some(frame.to_owned()))
    }

    fn connection_error(&self, db: &mut Database) -> String {
        let error = db.next_error();
        control(
            "e",
            &Json::String(format!(
                "ClientId[{}]:ErrorId[{error}]: Error on incoming message",
                self.client
            )),
        )
    }

    fn dispatch(
        &mut self,
        db: &mut Database,
        envelope: &BTreeMap<String, Json>,
        now_millis: i64,
        events: &mut Vec<(u64, SseEvent)>,
    ) -> Result<Vec<String>, Failure> {
        let Some(Json::Object(body)) = envelope.get("d") else {
            return Err(Failure::Malformed);
        };
        match envelope.get("t") {
            Some(Json::String(kind)) if kind == "c" => {
                let ping = matches!(body.get("t"), Some(Json::String(t)) if t == "p");
                Ok(if ping {
                    vec![control("o", &Json::Null)]
                } else {
                    Vec::new()
                })
            }
            Some(Json::String(kind)) if kind == "d" => {
                let r = match body.get("r") {
                    Some(Json::Number(fireemu_core_database::Number::Int(r))) => {
                        u64::try_from(*r).map_err(|_| Failure::Malformed)?
                    }
                    None => 0,
                    _ => return Err(Failure::Malformed),
                };
                let Some(Json::String(action)) = body.get("a") else {
                    return Err(Failure::Malformed);
                };
                let empty = BTreeMap::new();
                let arguments = match body.get("b") {
                    Some(Json::Object(arguments)) => arguments,
                    None => &empty,
                    _ => return Err(Failure::Malformed),
                };
                let context = ServerValueContext { now_millis };
                let answer = self.act(db, action, arguments, context, events);
                match answer {
                    Ok(data) => Ok(vec![response(r, "ok", &data)]),
                    Err(Failure::Status(status, message)) => {
                        Ok(vec![response(r, status, &Json::String(message))])
                    }
                    Err(Failure::InternalReset) => Err(Failure::DropAfter(vec![
                        response(
                            r,
                            "internal_error",
                            &Json::string("An internal error occurred"),
                        ),
                        self.reset_control(),
                    ])),
                    Err(other) => Err(other),
                }
            }
            _ => Err(Failure::Malformed),
        }
    }

    fn act(
        &mut self,
        db: &mut Database,
        action: &str,
        arguments: &BTreeMap<String, Json>,
        context: ServerValueContext,
        events: &mut Vec<(u64, SseEvent)>,
    ) -> Answer {
        match action {
            "s" => stats(arguments),
            // The official emulator echoes the data as text.
            "echo" => Ok(match arguments.get("d") {
                Some(Json::String(text)) => Json::String(text.clone()),
                Some(other) => Json::String(render(other, Style::Compact)),
                None => Json::Null,
            }),
            "auth" => match authenticate(arguments, db, &self.namespace, context.now_millis) {
                Ok((answer, access)) => {
                    self.become_(db, access, context.now_millis);
                    Ok(answer)
                }
                Err(refusal) => {
                    // A refused token leaves the connection signed out under strict (review
                    // S1); the official emulator, and so the emulator profile, keeps the user
                    // it had (reauth-probe).
                    if db.options().credentials.strict {
                        self.become_(db, Access::Anonymous, context.now_millis);
                    }
                    Err(refusal)
                }
            },
            "gauth" => {
                let access = match arguments.get("cred") {
                    // The official emulator does not answer a gauth without a credential.
                    None => return Err(Failure::Silent),
                    Some(Json::String(cred)) => {
                        Access::administrator(cred, &db.options().credentials)
                    }
                    Some(_) => Access::administrator("", &db.options().credentials),
                };
                // Refused string credentials use the production gauth error; malformed
                // credential values retain the token parsing error.
                let Ok(access) = access else {
                    self.become_(db, Access::Anonymous, context.now_millis);
                    if matches!(arguments.get("cred"), Some(Json::String(_))) {
                        return Err(Failure::Status(
                            "permission_denied",
                            "Permission denied".to_owned(),
                        ));
                    }
                    return Err(unparsable_token());
                };
                let access = match arguments.get("authvar") {
                    None => access,
                    Some(Json::Null) => Access::AdminAsAnonymous,
                    Some(auth @ Json::Object(_)) => Access::AdminAsUser(auth.clone()),
                    Some(_) => return Err(Failure::Malformed),
                };
                self.become_(db, access, context.now_millis);
                let expires = context.now_millis / 1000 + 3600;
                Ok(Json::object([
                    ("auth", Json::Null),
                    ("expires", Json::int(expires)),
                ]))
            }
            "unauth" => {
                self.become_(db, Access::Anonymous, context.now_millis);
                Ok(Json::string("unauthenticated"))
            }
            "appcheck" => app_check(arguments),
            "g" => self.get(db, arguments, context.now_millis),
            "p" => self.put(db, arguments, context, events),
            "m" => self.merge(db, arguments, context, events),
            "q" => self.listen(db, arguments, context.now_millis),
            "o" | "om" | "oc" => {
                // Without a path the official emulator answers nothing and registers nothing.
                if !arguments.contains_key("p") {
                    return Err(Failure::Silent);
                }
                self.on_disconnect(db, action, arguments, context)
            }
            "n" => {
                let path = location(arguments, false, db)?;
                db.remove_listen(self.client, &path, listen_tag(arguments)?);
                Ok(Json::string(""))
            }
            _ => Err(Failure::Malformed),
        }
    }

    /// Registers (`o`, `om`) or cancels (`oc`) writes for the end of this connection. The data
    /// is checked now, as a write of it would be, with its server values resolved against
    /// nothing; they are resolved again when the connection ends. A hash (`h`) is refused:
    /// these are not transactions.
    fn on_disconnect(
        &mut self,
        db: &mut Database,
        action: &str,
        arguments: &BTreeMap<String, Json>,
        context: ServerValueContext,
    ) -> Answer {
        let path = location(arguments, true, db)?;
        if action == "oc" {
            db.forget_on_disconnect(self.client, &path);
            return Ok(Json::string(""));
        }
        if arguments.contains_key("h") {
            return Err(Failure::Malformed);
        }
        let limits = db.options().limits;
        let data = arguments.get("d").cloned().unwrap_or(Json::Null);
        let writes = if action == "o" {
            vec![(path, data)]
        } else {
            let Json::Object(entries) = data else {
                return Err(Failure::Malformed);
            };
            let mut relative = Vec::with_capacity(entries.len());
            for key in entries.keys() {
                let parsed = Path::parse(key, &limits).map_err(|_| Failure::Malformed)?;
                relative.push((key.clone(), parsed));
            }
            refuse_overlap(&relative)?;
            relative
                .into_iter()
                .zip(entries.into_values())
                .map(|((_, relative), value)| (path.join(&relative), value))
                .collect()
        };
        for (path, value) in &writes {
            check_registered(path, value, &limits, context)?;
        }
        // The official emulator checks the rules when a write is registered as well as when it
        // is made (RTDB-03 Q-R1); a merge is checked as its entries, each a set on the current
        // tree, and fails if any fails (review r11 M39).
        let allowed = writes.iter().all(|(path, value)| {
            db.may_write(
                &self.namespace,
                &WriteOp::Set(path, value),
                &self.access,
                context.now_millis,
            )
        });
        if !allowed {
            return Err(Self::denied());
        }
        for (path, value) in writes {
            db.remember_on_disconnect(self.client, &self.namespace, &path, value);
        }
        Ok(Json::string(""))
    }

    /// Records the access of this connection and cancels the listens it no longer allows.
    fn become_(&mut self, db: &mut Database, access: Access, now: i64) {
        self.access = access.clone();
        db.set_client_access(self.client, &self.namespace, access, now);
    }

    fn denied() -> Failure {
        Failure::Status("permission_denied", "Permission denied".to_owned())
    }

    fn get(&mut self, db: &mut Database, arguments: &BTreeMap<String, Json>, now: i64) -> Answer {
        let path = location(arguments, false, db)?;
        let query = match arguments.get("q") {
            Some(Json::Object(q)) => wire_query(q)?,
            _ => None,
        };
        // The rules come before the index, so a caller who may not read learns nothing
        // about it (the official emulator's order, review S6).
        if !db.may_read(
            &self.namespace,
            &path,
            query.as_ref(),
            ReadKind::Stream,
            &self.access,
            now,
        ) {
            return Err(Self::denied());
        }
        if let Some(query) = &query {
            if let Some(message) = db.index_refusal(&self.namespace, &path, query) {
                return Err(Failure::Status("no_index", message));
            }
        }
        let tree = db.tree_mut(&self.namespace);
        if path.is_priority() {
            return Ok(priority_at(tree, &path));
        }
        let node = tree.get(&path);
        let selected = match (&query, node) {
            // The official emulator answers a query on a leaf with null.
            (Some(_), Some(node))
                if matches!(node.content, fireemu_core_database::Content::Leaf(_)) =>
            {
                Json::Null
            }
            (Some(query), Some(node)) => {
                let children: BTreeMap<String, Json> = query
                    .run(Some(node))
                    .into_iter()
                    .map(|(key, child)| (key.to_owned(), wire_json(Some(child))))
                    .collect();
                Json::Object(children)
            }
            _ => wire_json(node),
        };
        Ok(selected)
    }

    /// `q`: a plain listen, or a tagged query listen following its window. A query whose
    /// order needs an undeclared index is followed whole, untagged, with a warning.
    fn listen(
        &mut self,
        db: &mut Database,
        arguments: &BTreeMap<String, Json>,
        now: i64,
    ) -> Answer {
        let path = location(arguments, false, db)?;
        let tag = listen_tag(arguments)?;
        let query = match arguments.get("q") {
            Some(Json::Object(q)) => wire_query(q)?,
            _ => None,
        };
        if !db.may_read(
            &self.namespace,
            &path,
            query.as_ref(),
            ReadKind::Stream,
            &self.access,
            now,
        ) {
            return Err(Self::denied());
        }
        let followed = query.clone();
        let mut warnings = Vec::new();
        let window = match (query, tag) {
            (Some(query), Some(tag)) => {
                if db.index_refusal(&self.namespace, &path, &query).is_some() {
                    warnings.push(Json::string("no_index"));
                    None
                } else {
                    Some((query, tag))
                }
            }
            _ => None,
        };
        let hash = match arguments.get("h") {
            Some(Json::String(hash)) => hash.clone(),
            Some(other) => render(other, Style::Compact),
            None => String::new(),
        };
        let listen = Listen {
            client: self.client,
            namespace: self.namespace.clone(),
            path,
            tag,
            window,
            query: followed,
            last: Json::Null,
        };
        db.add_listen(listen, &hash);
        Ok(if warnings.is_empty() {
            Json::object::<&str>([])
        } else {
            Json::object([("w", Json::Array(warnings))])
        })
    }

    fn put(
        &mut self,
        db: &mut Database,
        arguments: &BTreeMap<String, Json>,
        context: ServerValueContext,
        events: &mut Vec<(u64, SseEvent)>,
    ) -> Answer {
        let path = location(arguments, true, db)?;
        let value = arguments.get("d").cloned().unwrap_or(Json::Null);
        if !db.may_write(
            &self.namespace,
            &WriteOp::Set(&path, &value),
            &self.access,
            context.now_millis,
        ) {
            return Err(Self::denied());
        }
        // A transaction (a put with a hash) answers with the value it compares, so it needs
        // the read too (review M1).
        if arguments.contains_key("h")
            && !db.may_read(
                &self.namespace,
                &path,
                None,
                ReadKind::Check,
                &self.access,
                context.now_millis,
            )
        {
            return Err(Self::denied());
        }
        let paths = [path];
        let before = db.before_write(&self.namespace, &paths);
        let [path] = paths;
        let tree = db.tree_mut(&self.namespace);
        // A hash that is not a string never matches, as the official emulator answers.
        let compare = arguments.get("h").map(|hash| match hash {
            Json::String(hash) => hash.clone(),
            other => render(other, Style::Compact),
        });
        if let Some(hash) = &compare {
            if node_hash(tree.get(&path)) != *hash {
                return Err(Failure::Status(
                    "datastale",
                    "Transaction ETag does not match".to_owned(),
                ));
            }
        }
        db.commit_set(
            &self.namespace,
            &path,
            &value,
            context,
            self.access.principal(),
        )
        .map_err(|err| change_failure(&err))?;
        // A transaction's answer carries the value it wrote.
        let data = if compare.is_some() {
            wire_json(db.tree_mut(&self.namespace).get(&path))
        } else {
            Json::string("")
        };
        let effective = db.effective(&self.namespace, std::slice::from_ref(&path), before)[0];
        events.extend(db.notify(
            &self.namespace,
            &Change::Put { path, effective },
            context.now_millis,
        ));
        Ok(data)
    }

    fn merge(
        &mut self,
        db: &mut Database,
        arguments: &BTreeMap<String, Json>,
        context: ServerValueContext,
        events: &mut Vec<(u64, SseEvent)>,
    ) -> Answer {
        let path = location(arguments, true, db)?;
        let Some(Json::Object(entries)) = arguments.get("d") else {
            return Err(Failure::Malformed);
        };
        let limits = *db.tree_mut(&self.namespace).limits();
        // The entries in the order they were sent; any the order missed follow in key order.
        let sent: Vec<&String> = {
            let mut seen = BTreeSet::new();
            let order = std::mem::take(&mut self.merge_order);
            let mut sent: Vec<&String> = order
                .iter()
                .filter_map(|key| entries.get_key_value(key).map(|(key, _)| key))
                .filter(|key| seen.insert(*key))
                .collect();
            sent.extend(entries.keys().filter(|key| !seen.contains(key)));
            sent
        };
        let mut relative = Vec::with_capacity(entries.len());
        for key in sent {
            let parsed = Path::parse(key, &limits).map_err(|_| Failure::Malformed)?;
            relative.push((key.clone(), parsed));
        }
        refuse_overlap(&relative)?;
        let wire: Vec<(String, Json)> = entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        if !db.may_write(
            &self.namespace,
            &WriteOp::Update(&path, &wire),
            &self.access,
            context.now_millis,
        ) {
            return Err(Self::denied());
        }
        let absolute: Vec<Path> = relative.iter().map(|(_, p)| path.join(p)).collect();
        let before = db.before_write(&self.namespace, &absolute);
        db.commit_update(
            &self.namespace,
            &path,
            &wire,
            context,
            self.access.principal(),
        )
        .map_err(|err| change_failure(&err))?;
        let effective = db.effective(&self.namespace, &absolute, before);
        let entries = relative
            .into_iter()
            .zip(effective)
            .map(|((_, path), effective)| Patched { path, effective })
            .collect();
        let change = Change::Patch {
            base: path,
            entries,
        };
        events.extend(db.notify(&self.namespace, &change, context.now_millis));
        Ok(Json::string(""))
    }
}

/// `s`: the client's counters (`c`). The official emulator answers integer or null
/// counters, ignores other counter values, treats counters that are not an object as a bad
/// message and drops the connection when there are none.
fn stats(arguments: &BTreeMap<String, Json>) -> Answer {
    match arguments.get("c") {
        None => Err(Failure::Drop),
        Some(Json::Object(counters)) => {
            let counted = counters.values().all(|value| {
                matches!(
                    value,
                    Json::Null | Json::Number(fireemu_core_database::Number::Int(_))
                )
            });
            if counted {
                Ok(Json::string(""))
            } else {
                Err(Failure::Silent)
            }
        }
        Some(Json::Null) => Err(Failure::Silent),
        Some(_) => Err(Failure::Malformed),
    }
}

/// Whether a parsed message is a merge (`m`), whose member order is worth reading.
fn is_merge(parsed: &Result<Json, crate::json_parse::ParseError>) -> bool {
    let Ok(Json::Object(envelope)) = parsed else {
        return false;
    };
    let Some(Json::Object(body)) = envelope.get("d") else {
        return false;
    };
    matches!(body.get("a"), Some(Json::String(action)) if action == "m")
}

/// The members of a merge's data (`d.b.d`), in the order they were sent: the official
/// emulator pushes a merge's entries in that order.
fn merge_order(message: &str) -> Vec<String> {
    let Ok((_, keys)) = parse_with_keys(message) else {
        return Vec::new();
    };
    let mut order = Vec::new();
    let mut inside = false;
    for at in keys {
        match at.depth {
            0 | 1 => inside = false,
            2 => inside = at.key == "d",
            3 if inside => order.push(at.key),
            _ => {}
        }
    }
    order
}

/// The tag `t` of a query listen: a 32-bit integer, negative ones included. The official
/// emulator stops answering the connection for any other tag, and answers a null one with
/// an internal error and a reset.
fn listen_tag(arguments: &BTreeMap<String, Json>) -> Result<Option<i64>, Failure> {
    match arguments.get("t") {
        None => Ok(None),
        Some(Json::Number(fireemu_core_database::Number::Int(tag)))
            if i32::try_from(*tag).is_ok() =>
        {
            Ok(Some(*tag))
        }
        Some(Json::Null) => Err(Failure::InternalReset),
        Some(_) => Err(Failure::Drop),
    }
}

/// The path argument `p`, checked as the official emulator checks it.
fn location(
    arguments: &BTreeMap<String, Json>,
    writing: bool,
    db: &mut Database,
) -> Result<Path, Failure> {
    // The official emulator drops the connection for a request without a path, and reads
    // a numeric path as its text.
    let text = match arguments.get("p") {
        Some(Json::String(text)) => text.clone(),
        Some(number @ Json::Number(_)) => render(number, Style::Compact),
        None => return Err(Failure::Drop),
        _ => return Err(Failure::Malformed),
    };
    let text = text.as_str();
    let limits = db.options().limits;
    let path = Path::parse(text, &limits).map_err(|err| match err.kind {
        ErrorKind::PathTooLong => invalid(format!(
            "Path specified exceeds the maximum length that can be written ({} bytes).",
            limits.max_path_bytes
        )),
        _ => invalid("Invalid token in path"),
    })?;
    if path.is_info() {
        return Err(invalid("Invalid token in path"));
    }
    if writing && path.depth() > limits.max_depth {
        return Err(invalid(format!(
            "Path specified exceeds the maximum depth that can be written ({}).",
            limits.max_depth
        )));
    }
    Ok(path)
}

/// Refuses merge entries of which one contains another, the way the server words it, naming
/// the keys as sent.
fn refuse_overlap(relative: &[(String, Path)]) -> Result<(), Failure> {
    let mut sorted: Vec<&(String, Path)> = relative.iter().collect();
    sorted.sort_by(|a, b| a.1.cmp(&b.1));
    for pair in sorted.windows(2) {
        if pair[0].1.contains(&pair[1].1) {
            return Err(invalid(format!(
                "Path '{}' is ancestor of '{}'",
                pair[0].0, pair[1].0
            )));
        }
    }
    Ok(())
}

/// Checks a write registered for a connection's end as the tree would read it now: keys,
/// depth, sizes and server-value placeholders, the same for a `.priority` path. The official
/// emulator answers a value it cannot read with a connection error, as it does for a write;
/// it does not check that a priority is one (an object is accepted), and an unusable one
/// fails the whole update when the connection ends.
fn check_registered(
    path: &Path,
    value: &Json,
    limits: &fireemu_core_database::Limits,
    context: ServerValueContext,
) -> Result<(), Failure> {
    let resolved = resolve(value, None, context).map_err(|_| Failure::Malformed)?;
    Node::from_json(&resolved, path, limits).map_err(|_| Failure::Malformed)?;
    Ok(())
}

/// A write the tree refused: a priority on an absent node is answered; bad data is a
/// connection error, as the official emulator treats it.
fn change_failure(err: &crate::changes::ChangeError) -> Failure {
    match err {
        crate::changes::ChangeError::Database(error) => write_failure(error),
        crate::changes::ChangeError::Admission(error) => {
            Failure::Status("unavailable", error.message().to_owned())
        }
    }
}

fn write_failure(err: &fireemu_core_database::DatabaseError) -> Failure {
    match err.kind {
        ErrorKind::PriorityOnAbsentNode => invalid("could not set priority on non-existent node"),
        _ => Failure::Malformed,
    }
}

/// The SDK's wire query object (`queryParamsGetQueryObject`): `i` index, `sp`/`sn`/`sin`
/// start, `ep`/`en`/`ein` end, `l` limit and `vf` its side. `[MIN_NAME]` and `[MAX_NAME]`
/// are the SDK's key sentinels.
fn wire_query(q: &BTreeMap<String, Json>) -> Result<Option<QueryParams>, Failure> {
    const FIELDS: [&str; 9] = ["i", "sp", "sn", "sin", "ep", "en", "ein", "l", "vf"];
    if q.is_empty() {
        return Ok(None);
    }
    // The official emulator refuses a query with a field it does not know (`FIELDS`), or an inclusive flag that is no boolean (review r11 M42); a limit needs its side. The wire types of the side and key names are checked even without a limit or bound.
    if q.keys().any(|key| !FIELDS.contains(&key.as_str()))
        || ["sin", "ein"]
            .iter()
            .any(|flag| q.get(*flag).is_some_and(|v| !matches!(v, Json::Bool(_))))
        || q.get("vf").is_some_and(|v| !matches!(v, Json::String(_)))
        || ["sn", "en"].iter().any(|name| {
            q.get(*name)
                .is_some_and(|v| !matches!(v, Json::String(_) | Json::Null))
        })
    {
        return Err(Failure::Malformed);
    }
    let order_by = match q.get("i") {
        None => OrderBy::Priority,
        Some(Json::String(index)) => match index.as_str() {
            ".key" => OrderBy::Key,
            ".value" => OrderBy::Value,
            ".priority" => OrderBy::Priority,
            child => OrderBy::Child(
                Path::parse(child, &fireemu_core_database::Limits::default())
                    .map_err(|_| invalid("Invalid query index"))?,
            ),
        },
        Some(_) => return Err(Failure::Malformed),
    };
    let mut query = QueryParams::ordered_by(order_by);
    query.start = wire_bound(q, "sp", "sn", "sin", true)?;
    query.end = wire_bound(q, "ep", "en", "ein", false)?;
    if let Some(limit) = q.get("l") {
        let limit = match limit {
            Json::Number(fireemu_core_database::Number::Int(limit)) => limit,
            // The official emulator answers a limit written as a double (even 2.0) with a
            // connection error.
            Json::Number(_) => return Err(Failure::Malformed),
            _ => return Err(invalid("Invalid query limit")),
        };
        let limit = u32::try_from(*limit)
            .ok()
            .filter(|l| *l > 0)
            .ok_or_else(|| invalid("Invalid query limit"))?;
        // Without `vf` or with another side, the official emulator's rules see neither
        // `limitToFirst` nor `limitToLast`; that is not reproduced, so the query is refused
        // (ruling 18, a listed difference). The SDKs always send the side.
        query.limit = Some(match q.get("vf") {
            Some(Json::String(side)) if side == "r" => Limit::Last(limit),
            Some(Json::String(side)) if side == "l" => Limit::First(limit),
            _ => return Err(Failure::Malformed),
        });
    }
    Ok(Some(query))
}

fn wire_bound(
    q: &BTreeMap<String, Json>,
    value: &str,
    name: &str,
    inclusive: &str,
    start: bool,
) -> Result<Option<Bound>, Failure> {
    let Some(value) = q.get(value) else {
        return Ok(None);
    };
    let inclusive = !matches!(q.get(inclusive), Some(Json::Bool(false)));
    let key = match q.get(name) {
        Some(Json::String(name)) if name == "[MIN_NAME]" => BoundKey::Min,
        Some(Json::String(name)) if name == "[MAX_NAME]" => BoundKey::Max,
        Some(Json::String(name)) => BoundKey::Name(name.clone()),
        // Without a key name a start bound begins before every key of its value and an end bound ends after all of them; exclusive bounds (startAfter, endBefore on the key index) pass the other side. An explicit null name is absent too.
        Some(Json::Null) | None => match (start, inclusive) {
            (true, true) | (false, false) => BoundKey::Min,
            (true, false) | (false, true) => BoundKey::Max,
        },
        Some(_) => return Err(Failure::Malformed),
    };
    Ok(Some(Bound {
        value: value.clone(),
        key,
        inclusive,
    }))
}

/// `auth` with a JWT reads its claims (the official emulator does not verify the
/// signature, check `exp`, or accept anything else) and becomes that user.
fn authenticate(
    arguments: &BTreeMap<String, Json>,
    db: &Database,
    namespace: &str,
    now: i64,
) -> Result<(Json, Access), Failure> {
    let Some(Json::String(cred)) = arguments.get("cred") else {
        return Err(unparsable_token());
    };
    let credentials = &db.options().credentials;
    // A verifier decides alone; without one the claims are read as the official emulator
    // reads them, and a missing claim is named.
    if credentials.id_tokens.is_some() {
        let auth = credentials
            .user(cred, namespace, now)
            .ok_or_else(unparsable_token)?;
        let answer = Json::object([("auth", auth.clone()), ("expires", Json::Null)]);
        return Ok((answer, Access::User(auth)));
    }
    let Some(Json::Object(claims)) = jwt_claims(cred) else {
        return Err(unparsable_token());
    };
    let auth = auth_from_claims(&claims).map_err(|name| {
        Failure::Status(
            "invalid_token",
            format!("Missing claim '{name}' in auth token."),
        )
    })?;
    let answer = Json::object([("auth", auth.clone()), ("expires", Json::Null)]);
    Ok((answer, Access::User(auth)))
}

fn unparsable_token() -> Failure {
    Failure::Status("invalid_token", "Could not parse auth token.".to_owned())
}

/// The claims of a token shaped as a JWT (three base64url parts, the second a JSON
/// object), unverified.
pub(crate) fn jwt_claims(token: &str) -> Option<Json> {
    match jwt_part(token, 1)? {
        claims @ Json::Object(_) => Some(claims),
        _ => None,
    }
}

/// The JSON of part `index` of a three-part token.
fn jwt_part(token: &str, index: usize) -> Option<Json> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let bytes = base64url_decode(parts[index])?;
    let text = String::from_utf8(bytes).ok()?;
    parse_with_keys(&text).ok().map(|(json, _)| json)
}

/// `appcheck`: the official emulator refuses what is not a JWT and unsigned (`alg: none`)
/// tokens, and accepts others. Verifying them against the App Check emulator's keys belongs
/// to RTDB-05.
fn app_check(arguments: &BTreeMap<String, Json>) -> Answer {
    let token = match arguments.get("token") {
        Some(Json::String(token)) => token.as_str(),
        _ => "",
    };
    if jwt_claims(token).is_none() {
        return Err(Failure::Status(
            "invalid_token",
            "Could not parse token.".to_owned(),
        ));
    }
    let algorithm = match jwt_part(token, 0) {
        Some(Json::Object(header)) => header.get("alg").cloned(),
        _ => None,
    };
    if algorithm == Some(Json::string("none")) {
        return Err(Failure::Status(
            "invalid_token",
            "Unsupported jwt algorithm: none".to_owned(),
        ));
    }
    Ok(Json::string(""))
}

fn base64url_decode(text: &str) -> Option<Vec<u8>> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for byte in text.bytes().filter(|b| *b != b'=') {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xFF).ok()?);
        }
    }
    Some(out)
}
