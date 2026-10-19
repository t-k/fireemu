//! The REST API: `GET`, `PUT`, `POST`, `PATCH` and `DELETE` on `.json` URLs, `ETag`s and
//! `if-match`, the output options, queries, and event streams (`Accept: text/event-stream`).
//!
//! Every answer and refusal follows what the official emulator (firebase-database-emulator
//! v4.11.2, the jar firebase-tools 15.28.2 runs) answers to the same request; the lane's
//! exploration logs hold those answers. Production has not been observed yet.

use std::collections::{BTreeMap, BTreeSet};

use fireemu_core_database::hash::etag;
use fireemu_core_database::key::validate_key;
use fireemu_core_database::node::VALUE_KEY;
use fireemu_core_database::path::PRIORITY_KEY;
use fireemu_core_database::push_id::PushIdGenerator;
use fireemu_core_database::server_value::{resolve, stored_priority, SERVER_VALUE_KEY};
use fireemu_core_database::{
    Content, DatabaseError, ErrorKind, Format, Json, Limits, Node, Path, Priority, QueryParams,
    ServerValueContext, Tree,
};

use crate::json_parse::parse_with_keys;
use crate::json_text::{
    output_json, parse, priority_at, render, value_at, written_priority_at, ParseError, Style,
};
use crate::listen::Listen;
use crate::namespace::route;
use crate::request::{self, Location, Output, Refusal};

/// An HTTP request as the REST layer sees it.
#[derive(Debug, Clone, Default)]
pub struct HttpRequest {
    /// The method.
    pub method: String,
    /// The path and query (`/a/b.json?ns=x`).
    pub target: String,
    /// The headers, `Host` included.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// An HTTP response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// The headers.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// One server-sent event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// The event name (`put`, `patch`, `keep-alive`).
    pub event: String,
    /// The data line.
    pub data: String,
}

impl SseEvent {
    /// The `keep-alive` event the server sends while nothing changes.
    pub fn keep_alive() -> Self {
        Self {
            event: "keep-alive".to_owned(),
            data: "null".to_owned(),
        }
    }

    /// The event as stream text.
    pub fn to_text(&self) -> String {
        format!("event: {}\ndata: {}\n\n", self.event, self.data)
    }
}

/// What a request produced.
#[derive(Debug)]
pub enum Handled {
    /// A complete response, and the events it caused on open streams.
    Response {
        /// The response.
        response: HttpResponse,
        /// Events for open streams, by subscription id.
        events: Vec<(u64, SseEvent)>,
    },
    /// A new event stream.
    Stream {
        /// The subscription id.
        id: u64,
        /// The response head.
        response: HttpResponse,
        /// The first event.
        initial: SseEvent,
    },
}

/// How requests are authorized while no rules are loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RulesMode {
    /// Everything is allowed (emulator and strict, ledger 1471 Q4).
    #[default]
    AllowAll,
    /// Everything but the owner credential is denied (productionExact, ledger 1471 Q4).
    DenyAll,
}

/// Options of the REST layer.
#[derive(Debug, Clone)]
pub struct RestOptions {
    /// The namespace of requests that name none (`fake-server` in the official emulator).
    pub default_namespace: String,
    /// Authorization without rules.
    pub rules: RulesMode,
    /// Write limits.
    pub limits: Limits,
    /// The longest realtime message, split frames joined (the SDKs' 16 MB write limit).
    pub realtime_message_bytes: usize,
}

impl Default for RestOptions {
    fn default() -> Self {
        Self {
            default_namespace: "fake-server".to_owned(),
            rules: RulesMode::AllowAll,
            limits: Limits::default(),
            realtime_message_bytes: 16 * 1024 * 1024,
        }
    }
}

/// The credential of the local administrator (firebase-tools sends `Bearer owner`).
const OWNER: &str = "owner";

const PARSE_ERROR: &str = "Invalid data; couldn't parse JSON object, array, or value.";
const PATCH_ERROR: &str =
    "Invalid data; couldn't parse JSON object. Are you sending a JSON object with valid key names?";
const ALLOWED_METHODS: &str = "OPTIONS,GET,POST,PUT,DELETE,PATCH";

#[derive(Debug)]
struct Namespace {
    tree: Tree,
}

/// An open event stream.
#[derive(Debug)]
struct Subscription {
    namespace: String,
    path: Path,
    query: Option<QueryParams>,
    format: Format,
    /// The view last sent.
    last: Json,
}

/// A checked request, ready to execute.
struct Call<'a> {
    namespace: String,
    path: Path,
    output: Output,
    want_etag: bool,
    condition: Option<Condition<'a>>,
    context: ServerValueContext,
}

/// A conditional request header.
#[derive(Clone, Copy)]
enum Condition<'a> {
    /// `if-match`: write only when the current `ETag` is this one.
    Match(&'a str),
    /// `if-none-match`: read or write only when the current `ETag` is another one.
    NoneMatch(&'a str),
}

/// One entry of a `PATCH` body.
struct PatchEntry {
    key: String,
    path: Path,
    value: Json,
}

/// What a write changed, for the event streams and the realtime listens.
pub(crate) enum Change {
    /// A value was replaced at a path.
    Put {
        /// The written path.
        path: Path,
        /// Whether the write counts for the realtime listens (see [`Database::effective`]).
        effective: bool,
    },
    /// A multipath update at a base path, its entries in the order they were sent.
    Patch {
        /// The base path.
        base: Path,
        /// The entries.
        entries: Vec<Patched>,
    },
}

impl Change {
    /// Whether an effective part of the write lies at, above or below `location`.
    pub(crate) fn touches(&self, location: &Path) -> bool {
        let related = |path: &Path| location.contains(path) || path.contains(location);
        match self {
            Change::Put { path, effective } => *effective && related(path),
            Change::Patch { base, entries } => entries
                .iter()
                .any(|entry| entry.effective && related(&base.join(&entry.path))),
        }
    }
}

/// One entry of a multipath update.
pub(crate) struct Patched {
    /// The entry's path, relative to the base.
    pub path: Path,
    /// Whether the entry counts for the realtime listens.
    pub effective: bool,
}

/// Every namespace of one emulator.
#[derive(Debug)]
pub struct Database {
    options: RestOptions,
    /// One generator for the whole server, so push ids increase across namespaces.
    push_ids: PushIdGenerator,
    namespaces: BTreeMap<String, Namespace>,
    indexes: BTreeMap<String, BTreeMap<Path, BTreeSet<String>>>,
    subscriptions: BTreeMap<u64, Subscription>,
    next_subscription: u64,
    /// The listens of realtime connections, in the order they were made.
    listens: BTreeMap<u64, Listen>,
    next_listen: u64,
    /// Data messages for realtime connections, `(client, frame)`, not yet delivered.
    pushes: Vec<(u64, String)>,
    /// Realtime connections opened so far.
    clients: u64,
    /// Connection errors reported so far.
    errors: u64,
    /// The `SplitMix64` state realtime session ids are drawn from.
    session_rng: u64,
}

impl Database {
    /// An empty database; push ids draw their randomness from `seed`.
    pub fn new(options: RestOptions, seed: u64) -> Self {
        Self {
            options,
            push_ids: PushIdGenerator::new(seed),
            namespaces: BTreeMap::new(),
            indexes: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            next_subscription: 1,
            listens: BTreeMap::new(),
            next_listen: 1,
            pushes: Vec::new(),
            clients: 0,
            errors: 0,
            session_rng: seed ^ 0x5EED_5E55_1011_D5ED,
        }
    }

    /// The tree of `namespace`, if it was ever used.
    pub fn tree(&self, namespace: &str) -> Option<&Tree> {
        self.namespaces.get(namespace).map(|ns| &ns.tree)
    }

    /// Declares the index `.indexOn: spec` at `path` of `namespace` (a child path, or
    /// `.value`). The rules (RTDB-03) will declare them; tests declare them directly.
    pub fn declare_index(&mut self, namespace: &str, path: &Path, spec: &str) {
        self.indexes
            .entry(namespace.to_owned())
            .or_default()
            .entry(path.clone())
            .or_default()
            .insert(spec.to_owned());
    }

    /// Closes an event stream.
    pub fn unsubscribe(&mut self, id: u64) {
        self.subscriptions.remove(&id);
    }

    /// The number of open event streams.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Handles one request at the server time `now_millis`.
    pub fn handle(&mut self, request: &HttpRequest, now_millis: i64) -> Handled {
        let parsed = parse_body(request);
        self.handle_parsed(request, parsed, now_millis)
    }

    /// Handles one request whose body was parsed beforehand with [`parse_body`], so the
    /// parse can run outside the database lock.
    pub fn handle_parsed(
        &mut self,
        request: &HttpRequest,
        parsed: Option<ParsedBody>,
        now_millis: i64,
    ) -> Handled {
        match self.dispatch(request, parsed, now_millis) {
            Ok(handled) => handled,
            Err(refusal) => Handled::Response {
                response: refusal_response(&refusal),
                events: Vec::new(),
            },
        }
    }

    fn dispatch(
        &mut self,
        request: &HttpRequest,
        parsed: Option<ParsedBody>,
        now_millis: i64,
    ) -> Result<Handled, Refusal> {
        let method = request
            .header("X-HTTP-Method-Override")
            .unwrap_or(&request.method)
            .to_ascii_uppercase();
        let (raw_path, params) = request::split_target(&request.target);
        let namespace = route(
            params.get("ns").map(String::as_str),
            request.header("Host"),
            &self.options.default_namespace,
        )
        .map_err(|_| Refusal::new(403, "Invalid Firebase database name"))?;
        if method == "OPTIONS" {
            return Ok(respond(options_response()));
        }
        if !matches!(method.as_str(), "GET" | "PUT" | "POST" | "PATCH" | "DELETE") {
            return Err(Refusal::new(405, "Unsupported request type"));
        }
        let writing = method != "GET";
        let path = match request::location(raw_path, writing, &self.options.limits)? {
            Location::Data(path) => path,
            Location::Settings => return Err(Refusal::new(403, "Permission denied.")),
        };
        let condition = condition(request, &method)?;
        let output = request::output(&params)?;
        let read_shape = !writing && (output.shallow || request::has_query(&params));
        if condition.is_some() && (output.silent || read_shape) {
            return Err(Refusal::bad(
                "Mixing 'shallow', querying parameters or 'print=silent' and if-match or if-none-match requests is not supported",
            ));
        }
        if writing && request::has_query(&params) {
            return Err(Refusal::bad(
                "Querying related parameters not supported on this request type",
            ));
        }
        let query = if writing {
            None
        } else {
            request::query(&params, output.shallow)?
        };
        if let Some(query) = &query {
            self.check_index(&namespace, &path, query)?;
        }
        if self.options.rules == RulesMode::DenyAll && credential(request, &params) != Some(OWNER) {
            return Err(Refusal::new(401, "Permission denied"));
        }
        let want_etag = request
            .header("X-Firebase-ETag")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let streaming = request
            .header("Accept")
            .is_some_and(|v| v.contains("text/event-stream"));
        if method == "GET" && streaming {
            return Ok(self.subscribe(namespace, path, query, &output));
        }
        let call = Call {
            namespace,
            path,
            output,
            want_etag,
            condition,
            context: ServerValueContext { now_millis },
        };
        match method.as_str() {
            "GET" => {
                let tree = &self.namespace(&call.namespace).tree;
                if let Some(Condition::NoneMatch(tag)) = call.condition {
                    if tag_at(tree, &call.path) == tag {
                        return Ok(respond(not_modified()));
                    }
                    return Ok(respond(read(tree, &call.path, None, &call.output, true)));
                }
                Ok(respond(read(
                    tree,
                    &call.path,
                    query.as_ref(),
                    &call.output,
                    call.want_etag,
                )))
            }
            "PUT" => self.put(&call, body(request, parsed)?),
            "DELETE" => self.put(
                &call,
                Body {
                    text: "null",
                    json: Ok(Json::Null),
                    order: Vec::new(),
                },
            ),
            "POST" => self.post(&call, body(request, parsed)?),
            _ => self.patch(&call, body(request, parsed)?),
        }
    }

    fn put(&mut self, call: &Call<'_>, body: Body<'_>) -> Result<Handled, Refusal> {
        let written_paths = [call.path.clone()];
        let before = self.before_write(&call.namespace, &written_paths);
        let tree = &mut self.namespace(&call.namespace).tree;
        let current = tree.get(&call.path);
        let current_tag = tag_at(tree, &call.path);
        match call.condition {
            Some(Condition::Match(tag)) if current_tag != tag => {
                return Ok(respond(precondition_failed(current, &call.output, true)));
            }
            Some(Condition::NoneMatch(tag)) if current_tag == tag => {
                return Ok(respond(precondition_failed(current, &call.output, false)));
            }
            _ => {}
        }
        let value = body.json.map_err(|_| Refusal::bad(PARSE_ERROR))?;
        tree.set(&call.path, &value, call.context)
            .map_err(|err| write_refusal(&err, || data_refusal(body.text)))?;
        let response = written(tree, &call.path, &value, &call.output, call.want_etag);
        let [path] = written_paths;
        let effective = self.effective(&call.namespace, std::slice::from_ref(&path), before)[0];
        Ok(self.after_write(&call.namespace, response, &Change::Put { path, effective }))
    }

    fn post(&mut self, call: &Call<'_>, body: Body<'_>) -> Result<Handled, Refusal> {
        let value = body.json.map_err(|_| Refusal::bad(PARSE_ERROR))?;
        let id = self
            .push_ids
            .next(u64::try_from(call.context.now_millis).unwrap_or(0));
        let child = call.path.child(&id);
        self.namespace(&call.namespace)
            .tree
            .set(&child, &value, call.context)
            .map_err(|err| write_refusal(&err, || data_refusal(body.text)))?;
        let name = Json::object([("name", Json::String(id))]);
        let response = json_response(&name, &call.output, None);
        // A new child: the write always changes something.
        let change = Change::Put {
            path: child,
            effective: true,
        };
        Ok(self.after_write(&call.namespace, response, &change))
    }

    fn patch(&mut self, call: &Call<'_>, body: Body<'_>) -> Result<Handled, Refusal> {
        let entries = patch_entries(body.json, &body.order, &self.options.limits)?;
        let absolute: Vec<Path> = entries.iter().map(|e| call.path.join(&e.path)).collect();
        let before = self.before_write(&call.namespace, &absolute);
        let wire: Vec<(String, Json)> = entries
            .iter()
            .map(|entry| (entry.key.clone(), entry.value.clone()))
            .collect();
        let tree = &mut self.namespace(&call.namespace).tree;
        // The answer echoes the request with its placeholders resolved, read before the
        // update changes what they resolve against.
        let echo = patch_echo(tree, &call.path, &entries, call.context);
        tree.update(&call.path, &wire, call.context)
            .map_err(|err| write_refusal(&err, || Refusal::bad(PATCH_ERROR)))?;
        let effective = self.effective(&call.namespace, &absolute, before);
        let entries = entries
            .into_iter()
            .zip(effective)
            .map(|(entry, effective)| Patched {
                path: entry.path,
                effective,
            })
            .collect();
        let response = json_response(&echo, &call.output, None);
        let change = Change::Patch {
            base: call.path.clone(),
            entries,
        };
        Ok(self.after_write(&call.namespace, response, &change))
    }

    fn namespace(&mut self, name: &str) -> &mut Namespace {
        let limits = self.options.limits;
        self.namespaces
            .entry(name.to_owned())
            .or_insert_with(|| Namespace {
                tree: Tree::new(limits),
            })
    }

    fn check_index(
        &self,
        namespace: &str,
        path: &Path,
        query: &QueryParams,
    ) -> Result<(), Refusal> {
        let Some(spec) = request::required_index(&query.order_by) else {
            return Ok(());
        };
        let declared = self
            .indexes
            .get(namespace)
            .and_then(|by_path| by_path.get(path))
            .is_some_and(|specs| specs.contains(&spec));
        if declared {
            return Ok(());
        }
        Err(Refusal::bad(format!(
            "Index not defined, add \".indexOn\": \"{spec}\", for path \"{path}\", to the rules"
        )))
    }

    fn subscribe(
        &mut self,
        namespace: String,
        path: Path,
        query: Option<QueryParams>,
        output: &Output,
    ) -> Handled {
        let format = if output.export {
            Format::Export
        } else {
            Format::Plain
        };
        let tree = &self.namespace(&namespace).tree;
        let view = view(tree, &path, query.as_ref(), format);
        let initial = put_event(&Path::root(), &view);
        let id = self.next_subscription;
        self.next_subscription += 1;
        self.subscriptions.insert(
            id,
            Subscription {
                namespace,
                path,
                query,
                format,
                last: view,
            },
        );
        let response = HttpResponse {
            status: 200,
            headers: vec![
                header("Content-Type", "text/event-stream; charset=utf-8"),
                header("Cache-Control", "no-cache"),
                header("Access-Control-Allow-Origin", "*"),
            ],
            body: Vec::new(),
        };
        Handled::Stream {
            id,
            response,
            initial,
        }
    }

    fn after_write(&mut self, namespace: &str, response: HttpResponse, change: &Change) -> Handled {
        let events = self.notify(namespace, change);
        Handled::Response { response, events }
    }

    /// The events a change in `namespace` causes on the open streams.
    pub(crate) fn notify(&mut self, namespace: &str, change: &Change) -> Vec<(u64, SseEvent)> {
        let Some(ns) = self.namespaces.get(namespace) else {
            return Vec::new();
        };
        let mut events = Vec::new();
        for (id, subscription) in &mut self.subscriptions {
            if subscription.namespace != namespace {
                continue;
            }
            let fresh = view(
                &ns.tree,
                &subscription.path,
                subscription.query.as_ref(),
                subscription.format,
            );
            if fresh == subscription.last {
                continue;
            }
            let event = stream_event(&ns.tree, subscription, change, &fresh);
            subscription.last = fresh;
            events.push((*id, event));
        }
        // Plain listens go first: an SDK holding the whole location (a query served without
        // its index) then sees each write there before the windows built from it, as the
        // official emulator's order gives it in the cases observed.
        let (plain, windows): (Vec<&mut Listen>, Vec<&mut Listen>) = self
            .listens
            .values_mut()
            .partition(|listen| listen.window.is_none());
        for listen in plain.into_iter().chain(windows) {
            // A write that touches neither the location nor anything above it sends nothing;
            // its view is not rebuilt either.
            if listen.namespace != namespace || !change.touches(&listen.path) {
                continue;
            }
            let fresh = listen.view(&ns.tree);
            let frames = listen.changes(&ns.tree, change, &fresh);
            listen.last = fresh;
            self.pushes
                .extend(frames.into_iter().map(|frame| (listen.client, frame)));
        }
        events
    }

    /// What `paths` hold before a write, so that [`Database::effective`] can tell afterwards
    /// which of them the write changed; `None`, saving the copies, when no realtime
    /// connection listens to `namespace`.
    pub(crate) fn before_write(&self, namespace: &str, paths: &[Path]) -> Option<Vec<Json>> {
        if !self
            .listens
            .values()
            .any(|listen| listen.namespace == namespace)
        {
            return None;
        }
        let tree = self.namespaces.get(namespace).map(|ns| &ns.tree);
        Some(
            paths
                .iter()
                .map(|path| tree.map_or(Json::Null, |tree| value_at(tree, path)))
                .collect(),
        )
    }

    /// Which writes to `paths` count for the realtime listens: the official emulator
    /// notifies a write of null always, and any other write only when it changed the value
    /// (numbers compare by value, so 1.0 rewrites 1 without effect).
    pub(crate) fn effective(
        &self,
        namespace: &str,
        paths: &[Path],
        before: Option<Vec<Json>>,
    ) -> Vec<bool> {
        let (Some(before), Some(ns)) = (before, self.namespaces.get(namespace)) else {
            return vec![true; paths.len()];
        };
        paths
            .iter()
            .zip(before)
            .map(|(path, old)| {
                let new = value_at(&ns.tree, path);
                new == Json::Null || new != old
            })
            .collect()
    }

    /// Adds a realtime listen, replacing the client's listen with the same location and
    /// tag. The current value is queued for the client unless `hash` matches it.
    pub(crate) fn add_listen(&mut self, mut listen: Listen, hash: &str) {
        self.remove_listen(listen.client, &listen.path, listen.tag);
        let tree = self.tree_mut(&listen.namespace.clone());
        let view = listen.view(tree);
        if listen.hash(tree) != hash {
            self.pushes.push((listen.client, listen.snapshot(&view)));
        }
        listen.last = view;
        self.listens.insert(self.next_listen, listen);
        self.next_listen += 1;
    }

    /// Removes the client's listen at `path` registered under `tag`.
    pub(crate) fn remove_listen(&mut self, client: u64, path: &Path, tag: Option<i64>) {
        self.listens.retain(|_, listen| {
            !(listen.client == client && listen.path == *path && listen.tag == tag)
        });
    }

    /// Takes the queued data messages of every realtime connection, in order.
    pub fn drain_pushes(&mut self) -> Vec<(u64, String)> {
        std::mem::take(&mut self.pushes)
    }

    /// Takes the queued data messages of one realtime connection, in order.
    pub(crate) fn take_pushes(&mut self, client: u64) -> Vec<String> {
        let (own, others) = std::mem::take(&mut self.pushes)
            .into_iter()
            .partition(|(to, _)| *to == client);
        self.pushes = others;
        own.into_iter().map(|(_, frame)| frame).collect()
    }

    /// Ends a realtime connection: its listens and undelivered messages go.
    pub fn close_realtime(&mut self, client: u64) {
        self.listens.retain(|_, listen| listen.client != client);
        self.pushes.retain(|(to, _)| *to != client);
    }

    /// The number of realtime listens.
    pub fn listen_count(&self) -> usize {
        self.listens.len()
    }

    /// The tree of `namespace`, created empty on first use.
    pub(crate) fn tree_mut(&mut self, namespace: &str) -> &mut Tree {
        &mut self.namespace(namespace).tree
    }

    /// The longest realtime message.
    pub fn realtime_message_bytes(&self) -> usize {
        self.options.realtime_message_bytes
    }

    /// The options in force.
    pub(crate) fn options(&self) -> &RestOptions {
        &self.options
    }

    /// The refusal for a query whose order needs an index that is not declared.
    pub(crate) fn index_refusal(
        &self,
        namespace: &str,
        path: &Path,
        query: &QueryParams,
    ) -> Option<String> {
        self.check_index(namespace, path, query)
            .err()
            .map(|refusal| refusal.message)
    }

    /// The next realtime client number and session id.
    pub(crate) fn next_client(&mut self) -> (u64, String) {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        self.clients += 1;
        let id = (0..32)
            .map(|_| {
                self.session_rng = self.session_rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.session_rng;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^= z >> 31;
                // 62 letters and digits; the modulo bias is irrelevant for a session id.
                char::from(ALPHABET[usize::try_from(z % 62).unwrap_or(0)])
            })
            .collect();
        (self.clients, id)
    }

    /// The next number of a connection error, counted across connections.
    pub(crate) fn next_error(&mut self) -> u64 {
        self.errors += 1;
        self.errors
    }
}

fn respond(response: HttpResponse) -> Handled {
    Handled::Response {
        response,
        events: Vec::new(),
    }
}

/// The conditional header of a request, refused on the methods the official emulator
/// refuses it on.
fn condition<'a>(request: &'a HttpRequest, method: &str) -> Result<Option<Condition<'a>>, Refusal> {
    let if_match = request.header("if-match");
    if if_match.is_some() && matches!(method, "GET" | "PATCH" | "POST") {
        return Err(Refusal::bad(
            "The 'if-match' header is not supported with GET, PATCH or POST requests",
        ));
    }
    let if_none_match = request.header("if-none-match");
    if if_none_match.is_some() && matches!(method, "DELETE" | "PATCH" | "POST") {
        return Err(Refusal::bad(
            "The 'if-none-match' header is not supported with PUT, POST, PATCH or DELETE requests",
        ));
    }
    Ok(match (if_match, if_none_match) {
        (Some(tag), _) => Some(Condition::Match(tag)),
        (None, Some(tag)) => Some(Condition::NoneMatch(tag)),
        (None, None) => None,
    })
}

/// The token of a request: `auth`, `access_token` or an `Authorization: Bearer` header.
fn credential<'a>(
    request: &'a HttpRequest,
    params: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
    params
        .get("auth")
        .or_else(|| params.get("access_token"))
        .map(String::as_str)
        .or_else(|| {
            request
                .header("Authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
        })
}

/// A request body parsed ahead of the database lock.
#[derive(Debug)]
pub struct ParsedBody {
    json: Result<Json, ParseError>,
    /// The members of an object body in the order they were sent.
    order: Vec<String>,
}

/// Parses the body of `request`, if it has a UTF-8 one. Call it before taking the database
/// lock and pass the result to [`Database::handle_parsed`].
pub fn parse_body(request: &HttpRequest) -> Option<ParsedBody> {
    let text = std::str::from_utf8(&request.body).ok()?;
    (!text.is_empty()).then(|| parse_ordered(text))
}

/// Parses a body and, for an object, notes the order of its members: a `PATCH` notifies
/// its entries in that order.
fn parse_ordered(text: &str) -> ParsedBody {
    if !text.trim_start().starts_with('{') {
        return ParsedBody {
            json: parse(text),
            order: Vec::new(),
        };
    }
    match parse_with_keys(text) {
        Ok((json, keys)) => ParsedBody {
            json: Ok(json),
            order: keys
                .into_iter()
                .filter(|at| at.depth == 0)
                .map(|at| at.key)
                .collect(),
        },
        Err(err) => ParsedBody {
            json: Err(err),
            order: Vec::new(),
        },
    }
}

/// A write body: its text, for refusal positions, and its parsed value.
struct Body<'a> {
    text: &'a str,
    json: Result<Json, ParseError>,
    order: Vec<String>,
}

fn body(request: &HttpRequest, parsed: Option<ParsedBody>) -> Result<Body<'_>, Refusal> {
    if request.body.is_empty() {
        return Err(Refusal::bad("No data supplied."));
    }
    let text = std::str::from_utf8(&request.body).map_err(|_| Refusal::bad(PARSE_ERROR))?;
    let parsed = parsed.unwrap_or_else(|| parse_ordered(text));
    Ok(Body {
        text,
        json: parsed.json,
        order: parsed.order,
    })
}

fn header(name: &str, value: &str) -> (String, String) {
    (name.to_owned(), value.to_owned())
}

fn json_headers() -> Vec<(String, String)> {
    vec![
        header("Content-Type", "application/json; charset=utf-8"),
        header("Access-Control-Allow-Origin", "*"),
        header("Cache-Control", "no-cache"),
    ]
}

pub(crate) fn refusal_response(refusal: &Refusal) -> HttpResponse {
    if refusal.plain {
        return HttpResponse {
            status: refusal.status,
            headers: vec![
                header("Content-Type", "text/plain"),
                header("Access-Control-Allow-Origin", "*"),
            ],
            body: refusal.message.clone().into_bytes(),
        };
    }
    let body = Json::object([("error", Json::String(refusal.message.clone()))]);
    HttpResponse {
        status: refusal.status,
        headers: json_headers(),
        body: pretty_text(&body).into_bytes(),
    }
}

/// Pretty text as the server writes it: Jackson's layout and a final newline.
fn pretty_text(json: &Json) -> String {
    let mut text = render(json, Style::Pretty);
    text.push('\n');
    text
}

fn options_response() -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![
            header("Allow", ALLOWED_METHODS),
            header("Access-Control-Allow-Methods", ALLOWED_METHODS),
            header("Access-Control-Allow-Origin", "*"),
        ],
        body: Vec::new(),
    }
}

/// A JSON answer with the output options applied; `etag` adds the `ETag` header.
fn json_response(json: &Json, output: &Output, etag: Option<String>) -> HttpResponse {
    let mut headers = json_headers();
    let mut body = match output.style {
        Style::Compact => render(json, Style::Compact),
        Style::Pretty => pretty_text(json),
    };
    if let Some(callback) = &output.callback {
        headers[0] = header("Content-Type", "application/javascript; charset=utf-8");
        body = format!("/**/ {callback}({body});");
        headers.push(header("X-Content-Type-Options", "nosniff"));
    } else if let Some(name) = &output.download {
        headers[0] = header("Content-Type", "application/octet-stream; charset=utf-8");
        // The official emulator drops quotes and line breaks from the name; control
        // characters go too, so the header stays one parameter.
        let name: String = name
            .chars()
            .filter(|c| *c != '"' && !c.is_control())
            .collect();
        headers.push(header(
            "Content-Disposition",
            &format!("attachment; filename=\"{name}\""),
        ));
    }
    if let Some(etag) = etag {
        headers.push(header("Access-Control-Expose-Headers", "ETag"));
        headers.push(header("ETag", &etag));
    }
    if output.silent {
        return HttpResponse {
            status: 204,
            headers,
            body: Vec::new(),
        };
    }
    HttpResponse {
        status: 200,
        headers,
        body: body.into_bytes(),
    }
}

fn read(
    tree: &Tree,
    path: &Path,
    query: Option<&QueryParams>,
    output: &Output,
    want_etag: bool,
) -> HttpResponse {
    let format = if output.export {
        Format::Export
    } else {
        Format::Plain
    };
    let node = tree.get(path);
    let json = if path.is_priority() {
        priority_at(tree, path)
    } else if output.shallow {
        shallow(node, format)
    } else {
        view(tree, path, query, format)
    };
    json_response(&json, output, want_etag.then(|| tag_at(tree, path)))
}

/// The `ETag` of a location; for `<location>/.priority`, of its priority as a leaf (the
/// official emulator's answer).
fn tag_at(tree: &Tree, path: &Path) -> String {
    if path.is_priority() {
        let parent = path.parent().unwrap_or_default();
        return etag(stored_priority(tree.get(&parent)).as_ref());
    }
    etag(tree.get(path))
}

/// The `shallow=true` answer; the export format adds `.priority: true`.
fn shallow(node: Option<&Node>, format: Format) -> Json {
    let Some(node) = node else {
        return Json::Null;
    };
    match (node.shallow(), format, &node.priority) {
        (Json::Object(mut map), Format::Export, Some(_)) => {
            map.insert(PRIORITY_KEY.to_owned(), Json::Bool(true));
            Json::Object(map)
        }
        (json, _, _) => json,
    }
}

/// The answer for a location, or the children a query selects there.
fn view(tree: &Tree, path: &Path, query: Option<&QueryParams>, format: Format) -> Json {
    let node = tree.get(path);
    let (
        Some(query),
        Some(Node {
            content: Content::Children(_),
            ..
        }),
    ) = (query, node)
    else {
        return output_json(node, format);
    };
    let selected: BTreeMap<String, Node> = query
        .run(node)
        .into_iter()
        .map(|(key, child)| (key.to_owned(), child.clone()))
        .collect();
    if selected.is_empty() {
        return Json::Object(BTreeMap::new());
    }
    let view = Node {
        content: Content::Children(selected),
        priority: None,
    };
    output_json(Some(&view), format)
}

/// The 412 answer: the current value, with its `ETag` for a failed `if-match`. A
/// conditional request is never silent, so the body is always sent.
fn precondition_failed(current: Option<&Node>, output: &Output, with_etag: bool) -> HttpResponse {
    let tag = with_etag.then(|| etag(current));
    let mut response = json_response(&output_json(current, Format::Plain), output, tag);
    response.status = 412;
    response
}

fn not_modified() -> HttpResponse {
    HttpResponse {
        status: 304,
        headers: json_headers(),
        body: Vec::new(),
    }
}

/// The answer to a `PUT`: what was written, in the form it was written (the official
/// emulator answers `1.0` for 1.0 written over 1, which keeps 1); a value with server values
/// answers what they resolved to.
fn written(
    tree: &Tree,
    path: &Path,
    value: &Json,
    output: &Output,
    want_etag: bool,
) -> HttpResponse {
    let json = if path.is_priority() {
        match Priority::from_json(value) {
            Ok(Some(priority)) => priority.to_json(),
            _ => written_priority_at(tree, path),
        }
    } else {
        match Node::from_json(value, path, tree.limits()) {
            Ok(node) => output_json(node.as_ref(), Format::Export),
            Err(_) => output_json(tree.get(path), Format::Export),
        }
    };
    let tag = want_etag.then(|| tag_at(tree, path));
    json_response(&json, output, tag)
}

/// The refusal for a write the tree did not accept: the official emulator's own text for a
/// priority on an absent node, `otherwise` for anything else.
fn write_refusal(err: &DatabaseError, otherwise: impl FnOnce() -> Refusal) -> Refusal {
    if err.kind == ErrorKind::PriorityOnAbsentNode {
        return Refusal::bad("could not set priority on non-existent node");
    }
    otherwise()
}

/// The refusal for data the tree did not accept: the position of the first key, in
/// document order, that is empty or holds a forbidden character when there is one; the
/// generic parse error otherwise.
fn data_refusal(body: &str) -> Refusal {
    let keys = parse_with_keys(body)
        .map(|(_, keys)| keys)
        .unwrap_or_default();
    let refused = keys.iter().find(|at| {
        let special = matches!(at.key.as_str(), PRIORITY_KEY | VALUE_KEY | SERVER_VALUE_KEY);
        !special && validate_key(&at.key).is_err()
    });
    match refused {
        Some(at) => Refusal::bad(format!(
            "Invalid data; couldn't parse key beginning at {}:{}. Key value can't be empty or contain $ # [ ] / or .",
            at.line, at.column
        )),
        None => Refusal::bad(PARSE_ERROR),
    }
}

/// The entries of a `PATCH` body.
fn patch_entries(
    body: Result<Json, ParseError>,
    order: &[String],
    limits: &Limits,
) -> Result<Vec<PatchEntry>, Refusal> {
    let value = body.map_err(|_| Refusal::bad(PARSE_ERROR))?;
    let Json::Object(mut map) = value else {
        return Err(Refusal::bad(PATCH_ERROR));
    };
    // The members in the order they were sent (a repeated key at its first place).
    let mut sent: Vec<(String, Json)> = Vec::with_capacity(map.len());
    for key in order {
        if let Some(value) = map.remove(key) {
            sent.push((key.clone(), value));
        }
    }
    sent.extend(map);
    sent.into_iter()
        .map(|(key, value)| {
            let path = Path::parse(&key, limits).map_err(|_| Refusal::bad(PATCH_ERROR))?;
            if path.is_root() || path.is_info() {
                return Err(Refusal::bad(PATCH_ERROR));
            }
            Ok(PatchEntry { key, path, value })
        })
        .collect()
}

/// The answer to a `PATCH`: its entries as one nested object, as the official emulator
/// echoes them (the requested values with placeholders resolved, nulls kept).
fn patch_echo(
    tree: &Tree,
    base: &Path,
    entries: &[PatchEntry],
    context: ServerValueContext,
) -> Json {
    let mut echo = Json::Object(BTreeMap::new());
    for entry in entries {
        let target = base.join(&entry.path);
        let stored = if target.is_priority() {
            stored_priority(tree.get(&target.parent().unwrap_or_default()))
        } else {
            tree.get(&target).cloned()
        };
        let value = resolve(&entry.value, stored.as_ref(), context).unwrap_or(Json::Null);
        insert_at(&mut echo, entry.path.keys(), value);
    }
    echo
}

fn insert_at(target: &mut Json, keys: &[String], value: Json) {
    let Json::Object(map) = target else {
        return;
    };
    match keys {
        [] => {}
        [last] => {
            map.insert(last.clone(), value);
        }
        [first, rest @ ..] => {
            let child = map
                .entry(first.clone())
                .or_insert_with(|| Json::Object(BTreeMap::new()));
            insert_at(child, rest, value);
        }
    }
}

fn put_event(relative: &Path, data: &Json) -> SseEvent {
    SseEvent {
        event: "put".to_owned(),
        data: event_data(relative, data),
    }
}

/// `{"path":...,"data":...}`, in that order as the server writes it.
fn event_data(relative: &Path, data: &Json) -> String {
    format!(
        "{{\"path\":{},\"data\":{}}}",
        render(&Json::String(relative.to_string()), Style::Compact),
        render(data, Style::Compact)
    )
}

/// The path of `inner` relative to `outer`, which contains it.
fn relative_to(outer: &Path, inner: &Path) -> Path {
    Path::from_keys(inner.keys()[outer.depth()..].iter().cloned())
}

/// The event a stream receives for a change that altered its view: the changed location
/// when it lies inside the streamed location, the whole view otherwise. A query stream gets
/// the changed location only while the change stays inside one child it already shows.
fn stream_event(
    tree: &Tree,
    subscription: &Subscription,
    change: &Change,
    fresh: &Json,
) -> SseEvent {
    let location = &subscription.path;
    match change {
        Change::Put { path, .. } if location.contains(path) && location != path => {
            let relative = relative_to(location, path);
            let inside_one_child = match (&subscription.query, &subscription.last, fresh) {
                (None, _, _) => true,
                (Some(_), Json::Object(before), Json::Object(after)) => {
                    // A put changes one child; while that child stays shown, the other
                    // children of the window cannot change either.
                    let first = &relative.keys()[0];
                    before.contains_key(first) && after.contains_key(first)
                }
                (Some(_), _, _) => false,
            };
            if inside_one_child {
                let data = if path.is_priority() {
                    written_priority_at(tree, path)
                } else {
                    output_json(tree.get(path), subscription.format)
                };
                return put_event(&relative, &data);
            }
            put_event(&Path::root(), fresh)
        }
        Change::Patch { base, entries }
            if subscription.query.is_none() && location.contains(base) =>
        {
            let mut data = BTreeMap::new();
            for entry in entries.iter().map(|entry| &entry.path) {
                let target = base.join(entry);
                let value = if target.is_priority() {
                    written_priority_at(tree, &target)
                } else {
                    output_json(tree.get(&target), subscription.format)
                };
                data.insert(entry.keys().join("/"), value);
            }
            SseEvent {
                event: "patch".to_owned(),
                data: event_data(&relative_to(location, base), &Json::Object(data)),
            }
        }
        _ => put_event(&Path::root(), fresh),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realtime::Opened;

    #[test]
    fn unrelated_writes_rebuild_no_view() {
        let mut db = Database::new(RestOptions::default(), 1);
        let big: BTreeMap<String, Json> =
            (0..50).map(|i| (format!("k{i}"), Json::int(i))).collect();
        db.tree_mut("u")
            .set(
                &Path::from_keys(["big"]),
                &Json::Object(big),
                ServerValueContext { now_millis: 0 },
            )
            .unwrap();
        let Ok(Opened::Session(mut session, _)) = db.open_realtime("/.ws?v=5&ns=u", Some("h"), 0)
        else {
            panic!("no session")
        };
        session.receive(
            &mut db,
            r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/big","h":""}}}"#,
            0,
        );
        let before = crate::listen::views_built();
        for i in 0..10 {
            session.receive(
                &mut db,
                &format!(
                    r#"{{"t":"d","d":{{"r":{},"a":"p","b":{{"p":"/other","d":{i}}}}}}}"#,
                    i + 2
                ),
                0,
            );
        }
        assert_eq!(crate::listen::views_built(), before);
        session.receive(
            &mut db,
            r#"{"t":"d","d":{"r":20,"a":"p","b":{"p":"/big/k1","d":7}}}"#,
            0,
        );
        assert_eq!(crate::listen::views_built(), before + 1);
    }
}
