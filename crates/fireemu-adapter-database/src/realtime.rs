//! The realtime wire protocol the SDKs speak over WebSocket (`/.ws?v=5&ns=<ns>`).
//!
//! Every frame is one JSON message, or a decimal frame count followed by that many frames
//! that join into one message (the SDKs split at 16384 characters, and so does this
//! server). A message is a control message `{"t":"c","d":{"t":<type>,"d":...}}` or a data
//! message `{"t":"d","d":{"r":<request>,"a":<action>,"b":<body>}}`, answered by
//! `{"t":"d","d":{"r":<request>,"b":{"s":<status>,"d":<data>}}}`.
//!
//! This module serves the handshake, keepalive, pings, `s` (stats), `echo`, `auth`, `gauth`,
//! `unauth`, `appcheck`, `g` (get), `p` (put, with `h` as a transaction's compare-and-set)
//! and `m` (merge). Listening (`q`, `n`) and `onDisconnect` come with RTDB-LISTEN-ORDER and
//! RTDB-02. Every answer follows the official emulator (firebase-database-emulator v4.11.2).

use std::collections::BTreeMap;

use fireemu_core_database::hash::node_hash;
use fireemu_core_database::{
    Bound, BoundKey, ErrorKind, Json, Limit, OrderBy, Path, QueryParams, ServerValueContext,
};

use crate::json_parse::parse_with_keys;
use crate::json_text::{render, wire_json, Style};
use crate::namespace::route;
use crate::request::{self, Refusal};
use crate::rest::{Change, Database, RulesMode, SseEvent};

/// The protocol version this server speaks.
pub const PROTOCOL_VERSION: &str = "5";
/// The longest frame, in characters, before a message is split.
pub const MAX_FRAME_CHARS: usize = 16_384;

const VERSION_ERROR: &str =
    "Version error. Please make sure you are using the latest Firebase library";
const OWNER: &str = "owner";

/// The result of opening a realtime connection.
#[derive(Debug)]
pub enum Opened {
    /// A session and the frames to send first (the handshake).
    Session(Session, Vec<String>),
    /// The frames to send before closing: the client asked for another protocol version.
    Shutdown(Vec<String>),
}

/// Who a session is authenticated as.
#[derive(Debug, Clone, PartialEq)]
enum Identity {
    /// No credential.
    Anonymous,
    /// The local administrator (`gauth` with `owner`).
    Owner,
    /// A signed-in user or a service credential.
    Credential,
}

/// One realtime connection.
#[derive(Debug)]
pub struct Session {
    namespace: String,
    client: u64,
    identity: Identity,
    /// Frames still expected for a split message, and what arrived so far.
    pending: Option<(usize, String)>,
}

/// What one received frame produced.
#[derive(Debug, Default)]
pub struct Received {
    /// Frames to send back, in order.
    pub replies: Vec<String>,
    /// Events for open REST event streams.
    pub events: Vec<(u64, SseEvent)>,
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
            identity: Identity::Anonymous,
            pending: None,
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
}

type Answer = Result<Json, Failure>;

fn invalid(message: impl Into<String>) -> Failure {
    Failure::Status("invalid_parameters", message.into())
}

impl Session {
    /// The namespace the session addresses.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Takes one received text frame.
    pub fn receive(&mut self, db: &mut Database, frame: &str, now_millis: i64) -> Received {
        let Some(message) = self.reassemble(frame) else {
            return Received::default();
        };
        let mut received = Received::default();
        let replies = match parse_with_keys(&message).map(|(json, _)| json) {
            Ok(Json::Object(envelope)) => {
                self.dispatch(db, &envelope, now_millis, &mut received.events)
            }
            _ => Err(Failure::Malformed),
        };
        let replies = replies.unwrap_or_else(|_| vec![self.connection_error(db)]);
        received.replies = replies.into_iter().flat_map(split_frames).collect();
        received
    }

    fn reassemble(&mut self, frame: &str) -> Option<String> {
        if let Some((remaining, mut joined)) = self.pending.take() {
            joined.push_str(frame);
            if remaining > 1 {
                self.pending = Some((remaining - 1, joined));
                return None;
            }
            return Some(joined);
        }
        // A short all-digit frame is a frame count; "0" is the SDK's keepalive.
        if frame.len() <= 6 && !frame.is_empty() && frame.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(count) = frame.parse::<usize>() {
                if count > 0 {
                    self.pending = Some((count, String::new()));
                }
                return None;
            }
        }
        Some(frame.to_owned())
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
                    Err(Failure::Malformed) => Err(Failure::Malformed),
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
            "s" => Ok(Json::string("")),
            "echo" => Ok(arguments.get("d").cloned().unwrap_or(Json::Null)),
            "auth" => self.authenticate(arguments),
            "gauth" => {
                self.identity = match arguments.get("cred") {
                    Some(Json::String(cred)) if cred == OWNER => Identity::Owner,
                    _ => Identity::Credential,
                };
                let expires = context.now_millis / 1000 + 3600;
                Ok(Json::object([
                    ("auth", Json::Null),
                    ("expires", Json::int(expires)),
                ]))
            }
            "unauth" => {
                self.identity = Identity::Anonymous;
                Ok(Json::string("unauthenticated"))
            }
            "appcheck" => match arguments.get("token") {
                Some(Json::String(token)) if jwt_claims(token).is_some() => Ok(Json::string("")),
                _ => Err(Failure::Status(
                    "invalid_token",
                    "Could not parse token.".to_owned(),
                )),
            },
            "g" => {
                self.authorize(db)?;
                self.get(db, arguments)
            }
            "p" => {
                self.authorize(db)?;
                self.put(db, arguments, context, events)
            }
            "m" => {
                self.authorize(db)?;
                self.merge(db, arguments, context, events)
            }
            _ => Err(Failure::Malformed),
        }
    }

    /// `auth` with a JWT reads its claims (the official emulator does not verify the
    /// signature); anything else is refused.
    fn authenticate(&mut self, arguments: &BTreeMap<String, Json>) -> Answer {
        let Some(Json::String(cred)) = arguments.get("cred") else {
            return Err(Failure::Status(
                "invalid_token",
                "Could not parse auth token.".to_owned(),
            ));
        };
        let Some(Json::Object(claims)) = jwt_claims(cred) else {
            return Err(Failure::Status(
                "invalid_token",
                "Could not parse auth token.".to_owned(),
            ));
        };
        self.identity = Identity::Credential;
        let claim = |name: &str| claims.get(name).cloned().unwrap_or(Json::Null);
        let provider = match claims.get("firebase") {
            Some(Json::Object(firebase)) => firebase
                .get("sign_in_provider")
                .cloned()
                .unwrap_or(Json::Null),
            _ => Json::Null,
        };
        let auth = Json::object([
            ("uid", claim("sub")),
            ("token", Json::Object(claims.clone())),
            ("provider", provider),
            ("user_id", claim("user_id")),
        ]);
        Ok(Json::object([("auth", auth), ("expires", Json::Null)]))
    }

    fn authorize(&self, db: &Database) -> Result<(), Failure> {
        if db.options().rules == RulesMode::DenyAll && self.identity != Identity::Owner {
            return Err(Failure::Status(
                "permission_denied",
                "Permission denied".to_owned(),
            ));
        }
        Ok(())
    }

    fn get(&mut self, db: &mut Database, arguments: &BTreeMap<String, Json>) -> Answer {
        let path = location(arguments, false, db)?;
        let query = match arguments.get("q") {
            Some(Json::Object(q)) => wire_query(q)?,
            _ => None,
        };
        if let Some(query) = &query {
            if let Some(message) = db.index_refusal(&self.namespace, &path, query) {
                return Err(Failure::Status("no_index", message));
            }
        }
        let tree = db.tree_mut(&self.namespace);
        let node = tree.get(&path);
        let selected = match (&query, node) {
            (Some(query), Some(node))
                if matches!(node.content, fireemu_core_database::Content::Children(_)) =>
            {
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

    fn put(
        &mut self,
        db: &mut Database,
        arguments: &BTreeMap<String, Json>,
        context: ServerValueContext,
        events: &mut Vec<(u64, SseEvent)>,
    ) -> Answer {
        let path = location(arguments, true, db)?;
        let value = arguments.get("d").cloned().unwrap_or(Json::Null);
        let tree = db.tree_mut(&self.namespace);
        let compare = match arguments.get("h") {
            Some(Json::String(hash)) => Some(hash.clone()),
            _ => None,
        };
        if let Some(hash) = &compare {
            if node_hash(tree.get(&path)) != *hash {
                return Err(Failure::Status(
                    "datastale",
                    "Transaction ETag does not match".to_owned(),
                ));
            }
        }
        tree.set(&path, &value, context)
            .map_err(|err| write_failure(&err))?;
        // A transaction's answer carries the value it wrote.
        let data = if compare.is_some() {
            wire_json(tree.get(&path))
        } else {
            Json::string("")
        };
        events.extend(db.notify(&self.namespace, &Change::Put(path)));
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
        let mut relative = Vec::with_capacity(entries.len());
        for key in entries.keys() {
            let parsed = Path::parse(key, &limits).map_err(|_| Failure::Malformed)?;
            relative.push((key.clone(), parsed));
        }
        // Report an overlap the way the server words it, naming the keys as sent.
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
        let wire: Vec<(String, Json)> = entries
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        db.tree_mut(&self.namespace)
            .update(&path, &wire, context)
            .map_err(|err| write_failure(&err))?;
        let change = Change::Patch(path, relative.into_iter().map(|(_, p)| p).collect());
        events.extend(db.notify(&self.namespace, &change));
        Ok(Json::string(""))
    }
}

/// The path argument `p`, checked as the official emulator checks it.
fn location(
    arguments: &BTreeMap<String, Json>,
    writing: bool,
    db: &mut Database,
) -> Result<Path, Failure> {
    let text = match arguments.get("p") {
        Some(Json::String(text)) => text.as_str(),
        None => "",
        _ => return Err(Failure::Malformed),
    };
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

/// A write the tree refused: a priority on an absent node is answered; bad data is a
/// connection error, as the official emulator treats it.
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
    if q.is_empty() {
        return Ok(None);
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
        let Json::Number(fireemu_core_database::Number::Int(limit)) = limit else {
            return Err(invalid("Invalid query limit"));
        };
        let limit = u32::try_from(*limit)
            .ok()
            .filter(|l| *l > 0)
            .ok_or_else(|| invalid("Invalid query limit"))?;
        query.limit = Some(match q.get("vf") {
            Some(Json::String(side)) if side == "r" => Limit::Last(limit),
            _ => Limit::First(limit),
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
        Some(_) => return Err(Failure::Malformed),
        // Without a key name a start bound begins before every key of its value and an end
        // bound ends after all of them; exclusive bounds (startAfter, endBefore on the key
        // index) pass the other side.
        None => match (start, inclusive) {
            (true, true) | (false, false) => BoundKey::Min,
            (true, false) | (false, true) => BoundKey::Max,
        },
    };
    Ok(Some(Bound {
        value: value.clone(),
        key,
        inclusive,
    }))
}

/// The claims of a token shaped as a JWT (three base64url parts, the second a JSON
/// object), unverified.
fn jwt_claims(token: &str) -> Option<Json> {
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let bytes = base64url_decode(payload)?;
    let text = String::from_utf8(bytes).ok()?;
    match parse_with_keys(&text) {
        Ok((claims @ Json::Object(_), _)) => Some(claims),
        _ => None,
    }
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
