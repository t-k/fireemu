//! The REST API: `GET`, `PUT`, `POST`, `PATCH` and `DELETE` on `.json` URLs, `ETag`s and
//! `if-match`, the output options, queries, and event streams (`Accept: text/event-stream`).
//!
//! Every answer and refusal follows what the official emulator (firebase-database-emulator
//! v4.11.2, the jar firebase-tools 15.28.2 runs) answers to the same request; the lane's
//! exploration logs hold those answers. Production has not been observed yet.
//!
//! Not followed: the official emulator streams null written to an absent child to a query
//! stream whose range holds the child's key; a query stream here receives such a null only
//! when its view changes, which matches the official emulator for a full limit window.

use std::collections::{BTreeMap, BTreeSet};

use fireemu_core_database::hash::etag;
use fireemu_core_database::key::validate_key;
use fireemu_core_database::node::VALUE_KEY;
use fireemu_core_database::path::PRIORITY_KEY;
use fireemu_core_database::push_id::PushIdGenerator;
use fireemu_core_database::rules::ReadKind;
use fireemu_core_database::server_value::{
    has_server_value, resolve, stored_priority, SERVER_VALUE_KEY,
};
use fireemu_core_database::{
    Content, DatabaseError, ErrorKind, Format, Json, Limits, Node, Path, Priority, QueryParams,
    ServerValueContext, Tree,
};

use crate::access::{Access, LoadedRules, WriteOp};
pub use crate::access::{Credentials, IdTokenVerifier};
use crate::json_parse::parse_with_keys;
use crate::json_text::{
    output_json, parse, priority_at, render, value_at, written_priority_at, ParseError, Style,
};
use crate::listen::Listen;
use crate::namespace::route;
use crate::on_disconnect::Pending;
use crate::request::{self, Location, Output, Refusal};

/// Where a request comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// A loopback address.
    Loopback,
    /// Any other host.
    Remote,
}

/// The refusal of a loopback-only route to another host, the same as Fireemu's Firestore and
/// Storage rules routes give.
pub const REMOTE_REFUSAL: &str = "this route answers loopback peers only: network.allowNonLoopbackHosts exposes the emulators, not the control API, rule loading, data clearing or App Check debug-token management";

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

    /// The `cancel` event that ends a stream the rules no longer allow to read.
    pub fn cancel() -> Self {
        Self {
            event: "cancel".to_owned(),
            data: "Permission denied".to_owned(),
        }
    }

    /// Whether this is the `cancel` event, after which the stream ends.
    pub fn is_cancel(&self) -> bool {
        self.event == "cancel"
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

/// The limits the served database writes with and imports are checked against.
pub const WRITE_LIMITS: Limits = Limits::PRODUCTION;

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
    /// How credentials are read (the profile's administrators and ID-token checks).
    pub credentials: Credentials,
    /// Whether `/.inspect/databases.json` answers only the owner credential (strict and a
    /// locked database); the official emulator answers anyone.
    pub inspect_needs_owner: bool,
}

impl Default for RestOptions {
    fn default() -> Self {
        Self {
            default_namespace: "fake-server".to_owned(),
            rules: RulesMode::AllowAll,
            limits: WRITE_LIMITS,
            realtime_message_bytes: 16 * 1024 * 1024,
            credentials: Credentials::default(),
            inspect_needs_owner: false,
        }
    }
}

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
    /// Who opened it, for the rules when they change.
    access: Access,
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
    access: Access,
    disable_triggers: bool,
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

/// The namespaces a session owns, as a snapshot captured them: each namespace that held
/// data, and the ones an import filled (exported even while empty).
#[derive(Debug, Clone, Default)]
pub struct NamespacesSnapshot {
    trees: BTreeMap<String, Tree>,
    imported: BTreeSet<String>,
}

impl NamespacesSnapshot {
    /// A cheap, saturating estimate of the heap bytes the snapshot retains.
    pub fn retained_bytes(&self) -> u64 {
        let names = self.trees.keys().chain(&self.imported);
        names.fold(
            self.trees.values().fold(0u64, |bytes, tree| {
                bytes.saturating_add(tree.retained_bytes())
            }),
            |bytes, name| bytes.saturating_add(name.len() as u64),
        )
    }
}

/// Every namespace of one emulator.
#[derive(Debug)]
pub struct Database {
    options: RestOptions,
    change_sink: Option<std::sync::Arc<dyn crate::changes::ChangeSink>>,
    next_change: u64,
    /// One generator for the whole server, so push ids increase across namespaces.
    push_ids: PushIdGenerator,
    namespaces: BTreeMap<String, Namespace>,
    /// The namespaces filled by an import, exported even when they hold nothing.
    imported: std::collections::BTreeSet<String>,
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
    /// Stream events caused outside a request (a reset), not yet delivered.
    events: Vec<(u64, SseEvent)>,
    /// Called when pushes or events wait outside a request, so the server delivers them.
    waker: Waker,
    clock: ServerClock,
    /// The writes each realtime connection registered for its end, with its namespace.
    on_disconnect: BTreeMap<u64, (String, Pending)>,
    deferred_disconnects: std::collections::VecDeque<DeferredDisconnect>,
    /// The rules loaded per namespace.
    rules: BTreeMap<String, LoadedRules>,
    /// Who each realtime connection is (anonymous until it authenticates).
    client_access: BTreeMap<u64, Access>,
}

#[derive(Debug)]
struct DeferredDisconnect {
    namespace: String,
    pending: Pending,
    access: Access,
}

/// The server's callback for messages that wait outside a request.
#[derive(Clone, Default)]
struct Waker(Option<std::sync::Arc<dyn Fn() + Send + Sync>>);

/// The server time for changes made outside a request (a session reset or restore): the
/// server's clock once it serves, the system clock before.
#[derive(Clone, Default)]
struct ServerClock(Option<std::sync::Arc<dyn Fn() -> i64 + Send + Sync>>);

impl ServerClock {
    fn now(&self) -> i64 {
        match &self.0 {
            Some(clock) => clock(),
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX)),
        }
    }
}

impl std::fmt::Debug for ServerClock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "ServerClock(set)"
        } else {
            "ServerClock(system)"
        })
    }
}

impl std::fmt::Debug for Waker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "Waker(set)"
        } else {
            "Waker(none)"
        })
    }
}

impl Database {
    /// An empty database; push ids draw their randomness from `seed`.
    pub fn new(options: RestOptions, seed: u64) -> Self {
        Self {
            options,
            change_sink: None,
            next_change: 1,
            push_ids: PushIdGenerator::new(seed),
            namespaces: BTreeMap::new(),
            imported: std::collections::BTreeSet::new(),
            indexes: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            next_subscription: 1,
            listens: BTreeMap::new(),
            next_listen: 1,
            pushes: Vec::new(),
            clients: 0,
            errors: 0,
            session_rng: seed ^ 0x5EED_5E55_1011_D5ED,
            events: Vec::new(),
            waker: Waker::default(),
            clock: ServerClock::default(),
            on_disconnect: BTreeMap::new(),
            deferred_disconnects: std::collections::VecDeque::new(),
            rules: BTreeMap::new(),
            client_access: BTreeMap::new(),
        }
    }

    /// Installs the coupled Functions event sink before serving writes.
    pub fn set_change_sink(&mut self, sink: std::sync::Arc<dyn crate::changes::ChangeSink>) {
        self.change_sink = Some(sink);
    }

    pub(crate) fn commit_set(
        &mut self,
        namespace: &str,
        path: &Path,
        value: &Json,
        context: ServerValueContext,
        principal: crate::changes::Principal,
    ) -> Result<Option<Node>, crate::changes::ChangeError> {
        self.commit_change(namespace, context, principal, |tree| {
            tree.set(path, value, context)
        })
    }

    pub(crate) fn commit_update(
        &mut self,
        namespace: &str,
        path: &Path,
        entries: &[(String, Json)],
        context: ServerValueContext,
        principal: crate::changes::Principal,
    ) -> Result<(), crate::changes::ChangeError> {
        self.commit_change(namespace, context, principal, |tree| {
            tree.update(path, entries, context)
        })
    }

    fn commit_change<R>(
        &mut self,
        namespace: &str,
        context: ServerValueContext,
        principal: crate::changes::Principal,
        operation: impl FnOnce(&mut Tree) -> Result<R, DatabaseError>,
    ) -> Result<R, crate::changes::ChangeError> {
        let sink = self
            .change_sink
            .clone()
            .filter(|sink| sink.interested(namespace));
        if sink.is_none() {
            return operation(self.tree_mut(namespace))
                .map_err(crate::changes::ChangeError::Database);
        }
        let next = self.next_change.checked_add(1).ok_or_else(|| {
            crate::changes::ChangeError::Admission(
                fireemu_core_types::admission::EventAdmissionError::Unavailable(
                    "RTDB event source sequence exhausted".to_owned(),
                ),
            )
        })?;
        let change = crate::changes::ChangeContext {
            namespace: namespace.to_owned(),
            sequence: self.next_change,
            now_millis: context.now_millis,
            principal,
        };
        let tree = self.tree_mut(namespace);
        let (result, candidate) =
            crate::changes::prepare(tree, change, sink.as_deref(), operation)?;
        candidate.commit(tree);
        self.next_change = next;
        Ok(result)
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

    /// `/.settings/rules.json`: an administrator reads or loads the rules of the namespace.
    /// Who a request is. The strict profile refuses a credential that names no one, as a
    /// denial.
    fn access(
        &self,
        request: &HttpRequest,
        params: &BTreeMap<String, String>,
        namespace: &str,
        streaming: bool,
        now_millis: i64,
    ) -> Result<Access, Refusal> {
        Access::from_rest(
            request.header("Authorization"),
            params,
            &self.options.credentials,
            namespace,
            now_millis,
        )
        .map_err(|_| read_refused(streaming))
    }

    fn settings(
        &mut self,
        raw_path: &str,
        method: &str,
        namespace: &str,
        access: &Access,
        request: &HttpRequest,
        now_millis: i64,
    ) -> Result<Handled, Refusal> {
        let administrator = match access {
            Access::Owner => true,
            Access::Admin => self.options.rules == RulesMode::AllowAll,
            _ => false,
        };
        if !administrator || raw_path.trim_matches('/') != ".settings/rules.json" {
            return Err(Refusal::new(403, "Permission denied."));
        }
        match method {
            "GET" => Ok(respond(HttpResponse {
                status: 200,
                headers: json_headers(),
                body: self.rules_text(namespace).into_bytes(),
            })),
            "PUT" => {
                let text = String::from_utf8_lossy(&request.body).into_owned();
                match self.set_rules(namespace, &text, now_millis) {
                    Ok(events) => Ok(Handled::Response {
                        response: HttpResponse {
                            status: 200,
                            headers: json_headers(),
                            body: br#"{"status":"ok"}"#.to_vec(),
                        },
                        events,
                    }),
                    Err(error) => Err(Refusal::bad(format!("{error}\n"))),
                }
            }
            _ => Err(Refusal::new(405, "Unsupported request type")),
        }
    }

    pub(crate) fn loaded_rules(&self, namespace: &str) -> Option<&LoadedRules> {
        self.rules.get(namespace)
    }

    pub(crate) fn store_rules(&mut self, namespace: &str, loaded: LoadedRules) {
        self.rules.insert(namespace.to_owned(), loaded);
    }

    pub(crate) fn store_client_access(&mut self, client: u64, access: Access) {
        self.client_access.insert(client, access);
    }

    /// Who a realtime connection is.
    pub(crate) fn client_access(&self, client: u64) -> Access {
        self.client_access
            .get(&client)
            .cloned()
            .unwrap_or(Access::Anonymous)
    }

    /// The realtime listens of `namespace`: id, connection, location and query.
    pub(crate) fn listen_entries(
        &self,
        namespace: &str,
    ) -> Vec<(u64, u64, Path, Option<QueryParams>)> {
        self.listens
            .iter()
            .filter(|(_, l)| l.namespace == namespace)
            .map(|(id, l)| (*id, l.client, l.path.clone(), l.query.clone()))
            .collect()
    }

    pub(crate) fn drop_listen(&mut self, id: u64) {
        self.listens.remove(&id);
    }

    /// Queues a data message for a realtime connection.
    pub(crate) fn push_raw(&mut self, client: u64, frame: String) {
        self.pushes.push((client, frame));
    }

    /// The event streams of `namespace`: id, location, query and who opened them.
    pub(crate) fn subscription_entries(
        &self,
        namespace: &str,
    ) -> Vec<(u64, Path, Option<QueryParams>, Access)> {
        self.subscriptions
            .iter()
            .filter(|(_, s)| s.namespace == namespace)
            .map(|(id, s)| (*id, s.path.clone(), s.query.clone(), s.access.clone()))
            .collect()
    }

    /// Asks the server to deliver what waits outside a request.
    pub(crate) fn wake(&self) {
        if let Some(waker) = &self.waker.0 {
            waker();
        }
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
        self.handle_from(request, parsed, now_millis, Peer::Loopback)
    }

    /// [`Database::handle_parsed`] for a request from `peer`: the rules route answers
    /// loopback peers only (ruling 17).
    pub fn handle_from(
        &mut self,
        request: &HttpRequest,
        parsed: Option<ParsedBody>,
        now_millis: i64,
        peer: Peer,
    ) -> Handled {
        let refused = (peer == Peer::Remote)
            .then(|| request::split_target(&request.target).0)
            .filter(|path| request::names_settings(path));
        if refused.is_some() {
            return Handled::Response {
                response: refusal_response(&Refusal::new(403, REMOTE_REFUSAL)),
                events: Vec::new(),
            };
        }
        match self.dispatch(request, parsed, now_millis) {
            Ok(handled) => handled,
            Err(refusal) => Handled::Response {
                response: refusal_response(&refusal),
                events: Vec::new(),
            },
        }
    }

    // One request's path through the checks, in the official emulator's order.
    #[allow(clippy::too_many_lines)]
    fn dispatch(
        &mut self,
        request: &HttpRequest,
        parsed: Option<ParsedBody>,
        now_millis: i64,
    ) -> Result<Handled, Refusal> {
        request::check_escapes(&request.target)?;
        let authorization_count = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("Authorization"))
            .count();
        request::check_ambiguity(&request.target, authorization_count)?;
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
        let streaming = request
            .header("Accept")
            .is_some_and(|v| v.contains("text/event-stream"));
        let access = self.access(request, &params, &namespace, streaming, now_millis)?;
        let path = match request::location(raw_path, writing, &self.options.limits)? {
            Location::Data(path) => path,
            Location::Settings => {
                return self.settings(raw_path, &method, &namespace, &access, request, now_millis);
            }
            Location::Inspect(name) => return self.inspect(&method, &name, &namespace, &access),
        };
        request::check_disable_triggers(&params, writing, request.header("Authorization"))?;
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
        // An event stream whose query only orders loads all the data, and the official
        // emulator follows it as a plain stream: judged without the query, needing no index.
        let query = query.filter(|q| !(streaming && loads_all_data(q)));
        // The rules come before the index (the official emulator's order, review S6).
        let (kind, judged) = read_kind(streaming, output.shallow, query.as_ref());
        if !writing && !self.may_read(&namespace, &path, judged, kind, &access, now_millis) {
            return Err(read_refused(streaming));
        }
        if let Some(query) = &query {
            self.check_index(&namespace, &path, query)?;
        }
        let want_etag = request
            .header("X-Firebase-ETag")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        if method == "GET" && streaming {
            return Ok(self.subscribe(namespace, path, query, &output, access));
        }
        let call = Call {
            namespace,
            path,
            output,
            want_etag,
            condition,
            context: ServerValueContext { now_millis },
            access,
            disable_triggers: params
                .get("disableTriggers")
                .is_some_and(|value| value == "true"),
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
        // A conditional write answers with the value it compares, so it needs the read as
        // well as the write, both checked before the comparison, as the official emulator
        // does (review M1).
        if call.condition.is_some() {
            let now = call.context.now_millis;
            let writable = body.json.as_ref().map_or(true, |value| {
                let op = WriteOp::Set(&call.path, value);
                self.may_write(&call.namespace, &op, &call.access, now)
            });
            if !writable
                || !self.may_read(
                    &call.namespace,
                    &call.path,
                    None,
                    ReadKind::Check,
                    &call.access,
                    now,
                )
            {
                return Err(Refusal::new(401, "Permission denied"));
            }
        }
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
        let op = WriteOp::Set(&call.path, &value);
        if !self.may_write(&call.namespace, &op, &call.access, call.context.now_millis) {
            return Err(Refusal::new(401, "Permission denied"));
        }
        let node = if call.disable_triggers {
            self.tree_mut(&call.namespace)
                .set(&call.path, &value, call.context)
                .map_err(crate::changes::ChangeError::Database)
        } else {
            self.commit_set(
                &call.namespace,
                &call.path,
                &value,
                call.context,
                call.access.principal(),
            )
        }
        .map_err(|err| change_refusal(&err, || data_refusal(body.text)))?;
        let tree = &self.namespace(&call.namespace).tree;
        let response = written(
            tree,
            &call.path,
            &value,
            node.as_ref(),
            &call.output,
            call.want_etag,
        );
        let [path] = written_paths;
        let effective = self.effective(&call.namespace, std::slice::from_ref(&path), before)[0];
        Ok(self.after_write(
            &call.namespace,
            response,
            &Change::Put { path, effective },
            call.context.now_millis,
        ))
    }

    fn post(&mut self, call: &Call<'_>, body: Body<'_>) -> Result<Handled, Refusal> {
        let value = body.json.map_err(|_| Refusal::bad(PARSE_ERROR))?;
        let id = self
            .push_ids
            .next(u64::try_from(call.context.now_millis).unwrap_or(0));
        let child = call.path.child(&id);
        let op = WriteOp::Set(&child, &value);
        if !self.may_write(&call.namespace, &op, &call.access, call.context.now_millis) {
            return Err(Refusal::new(401, "Permission denied"));
        }
        if call.disable_triggers {
            self.tree_mut(&call.namespace)
                .set(&child, &value, call.context)
                .map_err(crate::changes::ChangeError::Database)
        } else {
            self.commit_set(
                &call.namespace,
                &child,
                &value,
                call.context,
                call.access.principal(),
            )
        }
        .map_err(|err| change_refusal(&err, || data_refusal(body.text)))?;
        let name = Json::object([("name", Json::String(id))]);
        let response = json_response(&name, &call.output, None);
        // A new child: the write always changes something.
        let change = Change::Put {
            path: child,
            effective: true,
        };
        Ok(self.after_write(&call.namespace, response, &change, call.context.now_millis))
    }

    fn patch(&mut self, call: &Call<'_>, body: Body<'_>) -> Result<Handled, Refusal> {
        let entries = patch_entries(body.json, &body.order, &self.options.limits)?;
        let absolute: Vec<Path> = entries.iter().map(|e| call.path.join(&e.path)).collect();
        let before = self.before_write(&call.namespace, &absolute);
        let wire: Vec<(String, Json)> = entries
            .iter()
            .map(|entry| (entry.key.clone(), entry.value.clone()))
            .collect();
        let op = WriteOp::Update(&call.path, &wire);
        if !self.may_write(&call.namespace, &op, &call.access, call.context.now_millis) {
            return Err(Refusal::new(401, "Permission denied"));
        }
        let tree = &mut self.namespace(&call.namespace).tree;
        // The answer echoes the request with its placeholders resolved, read before the
        // update changes what they resolve against.
        let echo = patch_echo(tree, &call.path, &entries, call.context);
        if call.disable_triggers {
            self.tree_mut(&call.namespace)
                .update(&call.path, &wire, call.context)
                .map_err(crate::changes::ChangeError::Database)
        } else {
            self.commit_update(
                &call.namespace,
                &call.path,
                &wire,
                call.context,
                call.access.principal(),
            )
        }
        .map_err(|err| change_refusal(&err, || Refusal::bad(PATCH_ERROR)))?;
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
        Ok(self.after_write(&call.namespace, response, &change, call.context.now_millis))
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
        // Loaded rules declare the indexes; without them, what tests declared directly.
        let declared = match self.rules.get(namespace) {
            Some(loaded) => loaded.rules.index_on(path).contains(&spec),
            None => self
                .indexes
                .get(namespace)
                .and_then(|by_path| by_path.get(path))
                .is_some_and(|specs| specs.contains(&spec)),
        };
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
        access: Access,
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
                access,
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

    fn after_write(
        &mut self,
        namespace: &str,
        response: HttpResponse,
        change: &Change,
        now: i64,
    ) -> Handled {
        let events = self.notify(namespace, change, now);
        Handled::Response { response, events }
    }

    /// The events a committed change in `namespace` causes: first the listens and event
    /// streams whose read the rules no longer allow are cancelled (the official emulator
    /// sends the cancellation instead of the change, review M2), then the others hear it.
    pub(crate) fn notify(
        &mut self,
        namespace: &str,
        change: &Change,
        now: i64,
    ) -> Vec<(u64, SseEvent)> {
        let mut events = if self.loaded_rules(namespace).is_some() {
            self.revoke(namespace, None, now)
        } else {
            Vec::new()
        };
        events.extend(self.notify_views(namespace, change));
        events
    }

    /// `/.inspect/<name>`: `databases.json` lists every namespace a request reached, the one
    /// asked about included, by name (the official emulator's order is its own). Any other
    /// name is not found. With [`RestOptions::inspect_needs_owner`] a request without the
    /// owner credential is refused as a denied read is, before the namespace is created.
    fn inspect(
        &mut self,
        method: &str,
        name: &str,
        namespace: &str,
        access: &Access,
    ) -> Result<Handled, Refusal> {
        if method != "GET" {
            return Err(Refusal::new(405, "Unsupported request type"));
        }
        if !matches!(name, "databases.json" | "coverage.json" | "coverage") {
            return Err(Refusal::new(404, "404 Not Found"));
        }
        if self.options.inspect_needs_owner && *access != Access::Owner {
            return Err(Refusal::new(401, "Permission denied"));
        }
        self.namespace(namespace);
        if name == "coverage.json" {
            let report = render(&self.rules_coverage(namespace), Style::Compact);
            return Ok(respond(HttpResponse {
                status: 200,
                headers: json_headers(),
                body: render(&Json::String(report), Style::Compact).into_bytes(),
            }));
        }
        if name == "coverage" {
            return Ok(respond(HttpResponse {
                status: 200,
                headers: vec![(
                    "Content-Type".to_owned(),
                    "text/html; charset=UTF-8".to_owned(),
                )],
                body: coverage_html(&self.rules_coverage(namespace)).into_bytes(),
            }));
        }
        let names: Vec<Json> = self
            .namespaces
            .keys()
            .map(|name| Json::object([("name", Json::String(name.clone()))]))
            .collect();
        Ok(respond(HttpResponse {
            status: 200,
            headers: json_headers(),
            body: render(&Json::Array(names), Style::Compact).into_bytes(),
        }))
    }

    /// The export of every namespace that holds data or was imported, by name: what
    /// `GET /.json?format=export` answers for it, as firebase-tools writes it to
    /// `database_export/<namespace>.json`.
    pub fn export_texts(&self) -> Vec<(String, String)> {
        self.namespaces
            .iter()
            .filter_map(|(name, namespace)| {
                let root = namespace.tree.get(&Path::root());
                (root.is_some() || self.imported.contains(name)).then(|| {
                    let json = output_json(root, Format::Export);
                    (name.clone(), render(&json, Style::Compact))
                })
            })
            .collect()
    }

    /// Imports `text` into `namespace` as firebase-tools does: `PUT /.json` as the owner with
    /// `disableTriggers=true&writeSizeLimit=unlimited`. The error is the request's.
    pub fn import_text(&mut self, namespace: &str, text: &str, now: i64) -> Result<(), String> {
        // A valid name needs no escaping in the query; the server keeps it lowercased.
        let namespace = &route(Some(namespace), None, namespace)
            .map_err(|_| "Invalid Firebase database name".to_owned())?;
        let request = HttpRequest {
            method: "PUT".to_owned(),
            target: format!("/.json?ns={namespace}&disableTriggers=true&writeSizeLimit=unlimited"),
            headers: vec![(
                "Authorization".to_owned(),
                format!("Bearer {}", crate::access::OWNER),
            )],
            body: text.as_bytes().to_vec(),
        };
        let response = match self.handle(&request, now) {
            Handled::Response { response, .. } => response,
            Handled::Stream { .. } => return Err("unexpected stream".to_owned()),
        };
        if response.status == 200 {
            self.imported.insert(namespace.to_owned());
            return Ok(());
        }
        let body = String::from_utf8_lossy(&response.body).into_owned();
        Err(match crate::json_parse::parse(&body) {
            Ok(Json::Object(map)) => match map.get("error") {
                Some(Json::String(message)) => message.clone(),
                _ => body,
            },
            _ => body,
        })
    }

    /// Installs an import [`prepare_import`] checked, as [`Database::import_text`] would
    /// write its text: the tree replaces the namespace's data (an equal value keeps the
    /// stored form), listeners hear the change, and the namespace counts as imported. A file
    /// with server values is written now, so they resolve against this time and the data.
    pub fn install_import(&mut self, import: PreparedImport, now: i64) -> Result<(), String> {
        let (root, limits) = match import.content {
            ImportContent::Deferred(text) => {
                return self.import_text(&import.namespace, &text, now)
            }
            ImportContent::Built { root, limits } => (root, limits),
        };
        if limits != self.options.limits {
            return Err("the import was checked against other write limits".to_owned());
        }
        let paths = [Path::root()];
        let before = self.before_write(&import.namespace, &paths);
        self.namespace(&import.namespace).tree.replace_root(root);
        let effective = self.effective(&import.namespace, &paths, before)[0];
        let [path] = paths;
        // The import request's own stream events: `import_text` leaves them unread too.
        let _ = self.notify(&import.namespace, &Change::Put { path, effective }, now);
        self.imported.insert(import.namespace);
        Ok(())
    }

    /// The events a change in `namespace` causes on the open streams.
    fn notify_views(&mut self, namespace: &str, change: &Change) -> Vec<(u64, SseEvent)> {
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
            let event = match patch_listing(&ns.tree, subscription, change) {
                Listing::Entries(event) => event,
                // Views compare by form: a number rewritten as 1.0 inside a larger write
                // is an event, as on the official emulator.
                Listing::Whole { counts } => (counts || !fresh.same_form(&subscription.last))
                    .then(|| stream_event(&ns.tree, subscription, change, &fresh)),
            };
            subscription.last = fresh;
            if let Some(event) = event {
                events.push((*id, event));
            }
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
            && !self
                .subscriptions
                .values()
                .any(|subscription| subscription.namespace == namespace)
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

    /// Sets what to call when messages wait outside a request (the server delivers them).
    pub fn set_waker(&mut self, waker: std::sync::Arc<dyn Fn() + Send + Sync>) {
        self.waker = Waker(Some(waker));
    }

    /// Sets the server time used for changes made outside a request.
    pub fn set_clock(&mut self, clock: std::sync::Arc<dyn Fn() -> i64 + Send + Sync>) {
        self.clock = ServerClock(Some(clock));
    }

    /// Empties every namespace `cleared` accepts, as a session reset does: their streams and
    /// listens see the data go, through the waker, and the onDisconnect writes registered for
    /// them are dropped, so a connection from before the reset never writes into the new
    /// session when it ends.
    pub fn clear_namespaces_where(&mut self, cleared: impl Fn(&str) -> bool) {
        self.on_disconnect
            .retain(|_, (namespace, _)| !cleared(namespace));
        self.deferred_disconnects
            .retain(|job| !cleared(&job.namespace));
        // A reset session was never imported into, so an export leaves its empty namespaces out.
        self.imported.retain(|namespace| !cleared(namespace));
        let names: Vec<String> = self
            .namespaces
            .keys()
            .filter(|name| cleared(name))
            .cloned()
            .collect();
        if names.is_empty() {
            return;
        }
        let now = self.clock.now();
        for name in names {
            let limits = self.options.limits;
            self.namespace(&name).tree = Tree::new(limits);
            let change = Change::Put {
                path: Path::root(),
                effective: true,
            };
            // As a write would: the reads the rules no longer allow are cancelled first
            // (review r9 M27).
            let events = self.notify(&name, &change, now);
            self.events.extend(events);
        }
        if let Some(waker) = &self.waker.0 {
            waker();
        }
    }

    pub(crate) fn queue_events(&mut self, events: Vec<(u64, SseEvent)>) {
        self.events.extend(events);
        self.wake();
    }

    /// Copies the namespaces `owned` accepts that hold data or were imported, for a session
    /// snapshot. Listens, streams and onDisconnect writes belong to connections, not to the
    /// session's data, and are not captured.
    pub fn capture_namespaces_where(&self, owned: impl Fn(&str) -> bool) -> NamespacesSnapshot {
        let trees = self
            .namespaces
            .iter()
            .filter(|(name, namespace)| owned(name) && namespace.tree.root().is_some())
            .map(|(name, namespace)| (name.clone(), namespace.tree.clone()))
            .collect();
        let imported = self
            .imported
            .iter()
            .filter(|name| owned(name))
            .cloned()
            .collect();
        NamespacesSnapshot { trees, imported }
    }

    /// Puts `snapshot` back for the namespaces `owned` accepts, as a reset followed by an
    /// import would: an owned namespace the snapshot does not hold is emptied, open streams and
    /// listens see the restored values through the waker, and the onDisconnect writes
    /// registered for owned namespaces are dropped. Other namespaces are left as they are.
    pub fn restore_namespaces_where(
        &mut self,
        owned: impl Fn(&str) -> bool,
        snapshot: &NamespacesSnapshot,
    ) {
        self.on_disconnect
            .retain(|_, (namespace, _)| !owned(namespace));
        self.deferred_disconnects
            .retain(|job| !owned(&job.namespace));
        self.imported.retain(|namespace| !owned(namespace));
        self.imported
            .extend(snapshot.imported.iter().filter(|name| owned(name)).cloned());
        let mut names: BTreeSet<String> = self
            .namespaces
            .keys()
            .filter(|name| owned(name))
            .cloned()
            .collect();
        names.extend(snapshot.trees.keys().filter(|name| owned(name)).cloned());
        let now = self.clock.now();
        for name in names {
            let limits = self.options.limits;
            self.namespace(&name).tree = snapshot
                .trees
                .get(&name)
                .cloned()
                .unwrap_or_else(|| Tree::new(limits));
            let change = Change::Put {
                path: Path::root(),
                effective: true,
            };
            // As a write would: the reads the rules no longer allow are cancelled before the
            // restored data reaches the others (review r9 M27).
            let events = self.notify(&name, &change, now);
            self.events.extend(events);
        }
        if let Some(waker) = &self.waker.0 {
            waker();
        }
    }

    /// Takes the stream events caused outside a request, in order.
    pub fn drain_events(&mut self) -> Vec<(u64, SseEvent)> {
        self.retry_disconnects(self.clock.now());
        std::mem::take(&mut self.events)
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

    /// Ends a realtime connection at `now_millis`: its listens and undelivered messages go,
    /// then the writes it registered for its end are applied as one update at the root (a
    /// value registered at the root is written as a put there). An update the tree refuses
    /// (a priority for a node that is not there) writes nothing, as on the official
    /// emulator. What the writes cause waits for the server, which the waker calls.
    pub fn close_realtime(&mut self, client: u64, now_millis: i64) {
        self.listens.retain(|_, listen| listen.client != client);
        self.pushes.retain(|(to, _)| *to != client);
        // The writes are made as the connection was at its end, under the rules then.
        let access = self
            .client_access
            .remove(&client)
            .unwrap_or(Access::Anonymous);
        let Some((namespace, pending)) = self.on_disconnect.remove(&client) else {
            return;
        };
        self.deferred_disconnects.push_back(DeferredDisconnect {
            namespace,
            pending,
            access,
        });
        self.retry_disconnects(now_millis);
        self.wake();
    }

    fn retry_disconnects(&mut self, now_millis: i64) {
        while let Some(job) = self.deferred_disconnects.pop_front() {
            if matches!(
                self.apply_disconnect(&job, now_millis),
                Err(crate::changes::ChangeError::Admission(_))
            ) {
                // Retry at the server's next flush; never spin on unavailable capacity.
                self.deferred_disconnects.push_front(job);
                break;
            }
        }
    }

    fn apply_disconnect(
        &mut self,
        job: &DeferredDisconnect,
        now_millis: i64,
    ) -> Result<(), crate::changes::ChangeError> {
        let namespace = &job.namespace;
        // Recheck current Rules and resolve server values at the actual commit time.
        let entries =
            self.on_disconnect_writes(namespace, job.pending.entries(), &job.access, now_millis);
        if entries.is_empty() {
            return Ok(());
        }
        let context = ServerValueContext { now_millis };
        let root_value = match entries.as_slice() {
            [(keys, value)] if keys.is_empty() => Some(value.clone()),
            _ => None,
        };
        let change = if let Some(value) = root_value {
            let paths = [Path::root()];
            let before = self.before_write(namespace, &paths);
            self.commit_set(
                namespace,
                &paths[0],
                &value,
                context,
                job.access.principal(),
            )?;
            let effective = self.effective(namespace, &paths, before)[0];
            let [path] = paths;
            Change::Put { path, effective }
        } else {
            let paths: Vec<Path> = entries
                .iter()
                .map(|(keys, _)| Path::from_keys(keys.iter().cloned()))
                .collect();
            let wire: Vec<(String, Json)> = entries
                .into_iter()
                .map(|(keys, value)| (keys.join("/"), value))
                .collect();
            let before = self.before_write(namespace, &paths);
            self.commit_update(
                namespace,
                &Path::root(),
                &wire,
                context,
                job.access.principal(),
            )?;
            let effective = self.effective(namespace, &paths, before);
            Change::Patch {
                base: Path::root(),
                entries: paths
                    .into_iter()
                    .zip(effective)
                    .map(|(path, effective)| Patched { path, effective })
                    .collect(),
            }
        };
        let events = self.notify(namespace, &change, now_millis);
        self.events.extend(events);
        Ok(())
    }

    /// Registers `value` to be written at `path` when `client`'s connection ends.
    pub(crate) fn remember_on_disconnect(
        &mut self,
        client: u64,
        namespace: &str,
        path: &Path,
        value: Json,
    ) {
        self.on_disconnect
            .entry(client)
            .or_insert_with(|| (namespace.to_owned(), Pending::default()))
            .1
            .remember(path.keys(), value);
    }

    /// Cancels what `client` registered at and below `path`.
    pub(crate) fn forget_on_disconnect(&mut self, client: u64, path: &Path) {
        if let Some((_, pending)) = self.on_disconnect.get_mut(&client) {
            pending.forget(path.keys());
        }
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
        self.clients += 1;
        (self.clients, self.token(32))
    }

    /// `length` letters and digits drawn from the session generator.
    fn token(&mut self, length: usize) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        (0..length)
            .map(|_| {
                self.session_rng = self.session_rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = self.session_rng;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^= z >> 31;
                // 62 letters and digits; the modulo bias is irrelevant for a session id.
                char::from(ALPHABET[usize::try_from(z % 62).unwrap_or(0)])
            })
            .collect()
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

/// The kind of a REST read and the query its rules see, as the official emulator judges it
/// (review r11 M37, M38): an event stream is a stream with the query it follows (none when
/// its query only orders); a `shallow` GET has no ordering; any other GET is a GET with its
/// query.
fn read_kind(
    streaming: bool,
    shallow: bool,
    query: Option<&QueryParams>,
) -> (ReadKind, Option<&QueryParams>) {
    if streaming {
        (ReadKind::Stream, query)
    } else if shallow {
        (ReadKind::Check, query)
    } else {
        (ReadKind::Get, query)
    }
}

/// Whether a query selects every child: no bound and no limit.
fn loads_all_data(query: &QueryParams) -> bool {
    query.start.is_none() && query.end.is_none() && query.limit.is_none()
}

/// A database file checked for import by [`prepare_import`], ready for
/// [`Database::install_import`].
#[derive(Debug)]
pub struct PreparedImport {
    /// The namespace, lowercased as the server keeps it.
    namespace: String,
    content: ImportContent,
}

#[derive(Debug)]
enum ImportContent {
    /// The data the file describes, built against `limits`.
    Built { root: Option<Node>, limits: Limits },
    /// A file with server values, written again when installed: they resolve against the
    /// time and the stored data then.
    Deferred(String),
}

impl PreparedImport {
    /// The namespace the import fills.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// An estimate of the heap bytes held until it is installed (see
    /// [`Node::retained_bytes`]), or the text's length for a file with server values.
    pub fn retained_bytes(&self) -> u64 {
        match &self.content {
            ImportContent::Built { root, .. } => root.as_ref().map_or(0, Node::retained_bytes),
            ImportContent::Deferred(text) => text.len() as u64,
        }
    }
}

/// Checks the file `text` for `namespace` as `PUT /.json` as the owner checks it, with the
/// same refusals as [`Database::import_text`], and builds its data once: the parsed value is
/// consumed as the tree is built, so the file is never held three times.
pub fn prepare_import(
    namespace: &str,
    text: String,
    limits: &Limits,
) -> Result<PreparedImport, String> {
    let namespace = route(Some(namespace), None, namespace)
        .map_err(|_| "Invalid Firebase database name".to_owned())?;
    if text.is_empty() {
        return Err("No data supplied.".to_owned());
    }
    let json = parse(&text).map_err(|_| PARSE_ERROR.to_owned())?;
    if has_server_value(&json) {
        drop(json);
        let options = RestOptions {
            limits: *limits,
            ..RestOptions::default()
        };
        Database::new(options, 0).import_text(&namespace, &text, 0)?;
        return Ok(PreparedImport {
            namespace,
            content: ImportContent::Deferred(text),
        });
    }
    let root = Node::from_json_owned(json, &Path::root(), limits)
        .map_err(|err| write_refusal(&err, || data_refusal(&text)).message)?;
    Ok(PreparedImport {
        namespace,
        content: ImportContent::Built {
            root,
            limits: *limits,
        },
    })
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
    node: Option<&Node>,
    output: &Output,
    want_etag: bool,
) -> HttpResponse {
    if path.is_priority() {
        let json = match Priority::from_json(value) {
            Ok(Some(priority)) => priority.to_json(),
            _ => written_priority_at(tree, path),
        };
        let tag = want_etag.then(|| tag_at(tree, path));
        return json_response(&json, output, tag);
    }
    // The node as written, server values resolved: an equal value stays stored in its own
    // form, but the answer and its ETag are what was written, as the official emulator's.
    let tag = want_etag.then(|| etag(node));
    json_response(&output_json(node, Format::Export), output, tag)
}

/// The refusal for a write the tree did not accept: the official emulator's own text for a
/// priority on an absent node, `otherwise` for anything else.
fn change_refusal(
    err: &crate::changes::ChangeError,
    otherwise: impl FnOnce() -> Refusal,
) -> Refusal {
    match err {
        crate::changes::ChangeError::Database(error) => write_refusal(error, otherwise),
        crate::changes::ChangeError::Admission(_) => {
            Refusal::new(503, "Functions event admission unavailable")
        }
    }
}

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

/// How a change reaches a stream.
enum Listing {
    /// A patch event of the entries inside the streamed location, or nothing when none of
    /// them counts.
    Entries(Option<SseEvent>),
    /// The stream's event for the whole change, sent when the view changed or when
    /// `counts` (a write inside the location that counts even without changing it: null).
    Whole { counts: bool },
}

/// How `change` reaches `subscription`. The official emulator lists in a patch event only
/// the entries that count (see [`Database::effective`]), relative to the streamed location;
/// an entry at or above that location sends the whole value instead.
fn patch_listing(tree: &Tree, subscription: &Subscription, change: &Change) -> Listing {
    let location = &subscription.path;
    let (base, entries) = match change {
        Change::Put { path, effective } => {
            return Listing::Whole {
                counts: *effective && subscription.query.is_none() && location.contains(path),
            };
        }
        Change::Patch { base, entries } => (base, entries),
    };
    if subscription.query.is_some() {
        return Listing::Whole { counts: false };
    }
    let counting: Vec<(&Patched, Path)> = entries
        .iter()
        .filter(|entry| entry.effective)
        .map(|entry| (entry, base.join(&entry.path)))
        .collect();
    if counting.iter().any(|(_, target)| target.contains(location)) {
        return Listing::Whole { counts: false };
    }
    let mut data = BTreeMap::new();
    for (entry, target) in counting.iter().filter(|(_, t)| location.contains(t)) {
        let key = if location.contains(base) {
            entry.path.clone()
        } else {
            relative_to(location, target)
        };
        let value = if target.is_priority() {
            written_priority_at(tree, target)
        } else {
            output_json(tree.get(target), subscription.format)
        };
        data.insert(key.keys().join("/"), value);
    }
    if data.is_empty() {
        return Listing::Entries(None);
    }
    let path = if location.contains(base) {
        relative_to(location, base)
    } else {
        Path::root()
    };
    Listing::Entries(Some(SseEvent {
        event: "patch".to_owned(),
        data: event_data(&path, &Json::Object(data)),
    }))
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
        _ => put_event(&Path::root(), fresh),
    }
}

/// A refused read: an event stream is answered in plain text, as the official emulator does.
fn read_refused(streaming: bool) -> Refusal {
    if streaming {
        Refusal {
            status: 401,
            message: "Permission denied".to_owned(),
            plain: true,
        }
    } else {
        Refusal::new(401, "Permission denied")
    }
}

/// A self-contained diagnostic viewer; source and values are always inserted as text.
fn coverage_html(data: &Json) -> String {
    let data = render(data, Style::Compact)
        .replace('<', "\\u003c")
        .replace('&', "\\u0026")
        .replace('\u{2028}', "\\u2028")
        .replace('\u{2029}', "\\u2029");
    let mut html = String::from(
        r#"<!doctype html><html lang="en"><meta charset="utf-8"><title>Realtime Database Rules coverage</title>
<style>body{font:16px system-ui;margin:2rem;color:#202124}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:14px ui-monospace,monospace;line-height:1.7}.observed{background:#d8f2dc;text-decoration:underline dotted}.unrecorded{background:#eceff1}.expression:focus,.expression:hover{outline:2px solid #185abc}#details{min-height:4em;padding:1em;background:#f5f5f5}</style>
<h1>Realtime Database Rules coverage</h1><p>Hover or focus a highlighted expression to inspect its recorded results. Empty values can mean an unvisited expression or evaluation failure.</p><pre id="rules"></pre><pre id="details" aria-live="polite">Select an expression.</pre>
<script id="coverage-data" type="application/json">"#,
    );
    html.push_str(&data);
    html.push_str("</script><script>\nconst data = JSON.parse(document.getElementById('coverage-data').textContent)");
    html.push_str(COVERAGE_VIEWER_SCRIPT);
    html
}

const COVERAGE_VIEWER_SCRIPT: &str = r#";
const source = data.rules;
const ranges = [];
let cursor = 0;
function space() {
  for (;;) {
    while (/\s/.test(source[cursor] || '') && cursor < source.length) cursor++;
    if (source.slice(cursor,cursor+2) === '//') { while (cursor < source.length && source[cursor] !== '\n') cursor++; }
    else if (source.slice(cursor,cursor+2) === '/*') { const end=source.indexOf('*/',cursor+2); cursor=end<0?source.length:end+2; }
    else return;
  }
}
function quoted() {
  cursor++;
  const start=cursor, offsets=[], ends=[];
  let decoded='';
  while(cursor<source.length && source[cursor] !== '"') {
    const at=cursor;
    let character=source[cursor++];
    if(character === '\\') {
      const escape=source[cursor++];
      if(escape === 'u') { character=String.fromCharCode(parseInt(source.slice(cursor,cursor+4),16)); cursor+=4; }
      else character=({n:'\n',r:'\r',t:'\t',b:'\b',f:'\f'})[escape] ?? escape;
    }
    decoded+=character; offsets.push(at); ends.push(cursor);
  }
  cursor++;
  return {decoded,offsets,ends,start};
}
function position(index) {
  const lines=source.slice(0,index).split('\n');
  return [lines.length-1,lines[lines.length-1].length];
}
function relative(location,token) {
  const target=location.split(':').map(Number);
  let [row,column]=position(token.start);
  for(let i=0;i<token.decoded.length;i++) {
    if(row===target[0] && column===target[1]) return i;
    if(token.decoded[i]==='\n') { row++;column=0; } else column++;
  }
  return -1;
}
function expressions(node,token) {
  if(!node || typeof node.text !== 'string') return;
  const first=relative(node['location-start'],token),last=relative(node['location-end'],token);
  if(first>=0 && last>=first && token.ends[last]!==undefined) ranges.push({start:token.offsets[first],end:token.ends[last],node});
  for(const child of node.children || []) expressions(child,token);
}
function value(report,root=false) {
  space();
  if(source[cursor]==='{') {
    cursor++;space();
    while(cursor<source.length && source[cursor]!=='}') {
      const key=quoted().decoded;space();cursor++;
      const child=report && Object.hasOwn(report,key)?report[key]:undefined;
      value(root && key==='rules'?data.report:child);space();
      if(source[cursor]!==',') break;
      cursor++;space();
    }
    cursor++;return;
  }
  if(source[cursor]==='"') { const token=quoted();expressions(report,token);return; }
  if(source[cursor]==='[') {
    cursor++;space();
    while(cursor<source.length && source[cursor]!==']') { value(undefined);space();if(source[cursor]!==',')break;cursor++; }
    cursor++;return;
  }
  const start=cursor;
  while(cursor<source.length && !/[\s,}\]]/.test(source[cursor])) cursor++;
  const decoded=source.slice(start,cursor);
  expressions(report,{decoded,start,offsets:Array.from(decoded,(_,i)=>start+i),ends:Array.from(decoded,(_,i)=>start+i+1)});
}
value(undefined,true);
const boundaries=Array.from(new Set([0,source.length,...ranges.flatMap(range=>[range.start,range.end])])).sort((a,b)=>a-b);
const container=document.getElementById('rules'),details=document.getElementById('details');
function description(node) {
  return node.text+'\n'+(node.values.length?node.values.map(item=>JSON.stringify(item.value)+' × '+item.count).join('\n'):'No recorded result');
}
for(let i=0;i<boundaries.length-1;i++) {
  const start=boundaries[i],end=boundaries[i+1];
  const matches=ranges.filter(range=>range.start<=start && range.end>=end).sort((a,b)=>(a.end-a.start)-(b.end-b.start));
  if(!matches.length) { container.append(document.createTextNode(source.slice(start,end)));continue; }
  const node=matches[0].node,span=document.createElement('span');
  span.className='expression '+(node.values.length?'observed':'unrecorded');
  span.textContent=source.slice(start,end);span.title=description(node);span.tabIndex=0;
  span.dataset.start=String(start);span.dataset.end=String(end);
  span.addEventListener('mouseenter',()=>{details.textContent=description(node);});
  span.addEventListener('focus',()=>{details.textContent=description(node);});
  container.append(span);
}
</script></html>"#;

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
        // A write of what is stored changes nothing, so it rebuilds nothing either.
        session.receive(
            &mut db,
            r#"{"t":"d","d":{"r":21,"a":"p","b":{"p":"/big/k1","d":7.0}}}"#,
            0,
        );
        assert_eq!(crate::listen::views_built(), before + 1);
        // Neither does a merge whose only entry there changes nothing.
        session.receive(
            &mut db,
            r#"{"t":"d","d":{"r":22,"a":"m","b":{"p":"/","d":{"other":99,"big/k1":7}}}}"#,
            0,
        );
        assert_eq!(crate::listen::views_built(), before + 1);
    }
}
