//! The channels of the strict Eventarc surface: creation, deletion, their long-running operations and the
//! pages of a list, as production answered them in the EVENTARC stage B recording (2026-10-05, run
//! `43a83839852f` of `fireemu-oracle-idp`; `tests/fixtures/eventarc-stage-b/rows.json` replays it).
//!
//! This module is pure: it knows no clock and no source of randomness. Every call takes the instant it
//! happens at, and the identifiers a channel and an operation carry come from an [`Entropy`], so that a
//! test can drive a store through any sequence of requests and compare it with a reference model.
//!
//! What production did, as recorded, and how it is reproduced here:
//!
//! - A creation answers a long-running operation that is not done. The operation is done after a few
//!   seconds (12 creations took 4.5 to 6.2 seconds, 12 deletions 3.7 to 4.2); the store takes the
//!   duration from a [`Timing`], whose defaults are the means of the recording. A creation's operation
//!   reads as done with the channel in its `response`; the channel then reads `ACTIVE` with an
//!   `updateTime` a little after the end of the operation.
//! - A deletion answers a long-running operation too. It is done after its duration, with the channel as
//!   `INACTIVE` in its `response`; the channel then reads as absent.
//! - What a channel answers while its operation runs was observed in the stage C recording (run
//!   `fe404dee592e`): a channel being created reads (and lists) as a resource with no `state` and an empty
//!   `pubsubTopic`, a creation of its name is a `409`, a publication to it is a `404`; a deletion of it is
//!   accepted (its operation ends as long after the creation's end as a deletion takes); a channel being
//!   deleted still reads as `ACTIVE`, its `updateTime` moved to the deletion, a second deletion of it is a
//!   `404`, and a publication to it is a `404`. The states are [`Lookup::Creating`], [`Lookup::Ready`] and
//!   [`Lookup::Deleting`]. Each was observed once, in one recording.
//! - A list of several channels came back in an order that is neither the name, the creation time, the
//!   update time nor the UID (`a4`, `sd-sdk`, `cd-d2`, `cl-c2`, `cl-c1`, ... in every list, 10 channels at
//!   most). The rule is not recoverable from one recording, so this store lists in the order of creation:
//!   INFERRED. The rows of the replay that list two channels or more are named as not reproduced.
//! - The page token is opaque in production: a protobuf with the location, the service, the project
//!   number, the word `channels`, the ID and the UID of the last channel of the page, and an 8-byte
//!   checksum, in base64url (175 characters for 20-character IDs). This store writes the same structure
//!   with a project number derived from the project ID and a checksum of its own: a token of production
//!   is not valid here, and the other way round, which is what an opaque token allows.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::ordered_json::Ordered;

/// Nanoseconds since the Unix epoch.
pub type Nanos = u64;

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const NANOS_PER_MILLI: u64 = 1_000_000;

/// How long the operations take. The defaults are the means of the 12 creations and 12 deletions of the
/// recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// The duration of a creation's operation.
    pub create: u64,
    /// The duration of a deletion's operation.
    pub delete: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            create: 5_381_000_000,
            delete: 3_880_000_000,
        }
    }
}

/// The identifiers of channels and operations.
pub trait Entropy: Send {
    /// A version 4 UUID in its canonical text form.
    fn uuid(&mut self) -> String;
    /// `digits` lower-case hexadecimal digits.
    fn hex(&mut self, digits: usize) -> String;
    /// A number below 1000, for the suffix of a channel's topic.
    fn topic_suffix(&mut self) -> u16;
}

/// Random identifiers from the standard library's per-process random keys: no new dependency, and
/// nothing a client could predict from a count.
#[derive(Debug, Default)]
pub struct SystemEntropy {
    counter: u64,
}

impl SystemEntropy {
    fn word(&mut self) -> u64 {
        use std::hash::{BuildHasher, Hasher};
        self.counter = self.counter.wrapping_add(1);
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(self.counter);
        hasher.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos()),
        );
        hasher.finish()
    }
}

impl Entropy for SystemEntropy {
    fn uuid(&mut self) -> String {
        let high = self.word();
        let low = self.word();
        uuid_from(high, low)
    }

    fn hex(&mut self, digits: usize) -> String {
        use std::fmt::Write;
        let mut text = String::new();
        while text.len() < digits {
            let _ = write!(text, "{:016x}", self.word());
        }
        text.truncate(digits);
        text
    }

    fn topic_suffix(&mut self) -> u16 {
        u16::try_from(self.word() % 1000).unwrap_or(0)
    }
}

/// A version 4 UUID from 128 bits (the version and variant bits are set).
#[must_use]
pub fn uuid_from(high: u64, low: u64) -> String {
    let high = (high & 0xffff_ffff_ffff_0fff) | 0x0000_0000_0000_4000;
    let low = (low & 0x3fff_ffff_ffff_ffff) | 0x8000_0000_0000_0000;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        high >> 32,
        (high >> 16) & 0xffff,
        high & 0xffff,
        low >> 48,
        low & 0xffff_ffff_ffff
    )
}

/// A timestamp as production wrote it: UTC, nine fractional digits, a final `Z`. Every one of the 106
/// timestamps of the recording had nine digits (a proto timestamp may write fewer when the fraction ends
/// in zeros; that case was not observed, and a store that reads the system clock would produce it for a
/// clock with microsecond resolution), so nine digits are always written.
#[must_use]
pub fn rfc3339(instant: Nanos) -> String {
    let seconds = i64::try_from(instant / NANOS_PER_SECOND).unwrap_or(i64::MAX);
    let nanos = instant % NANOS_PER_SECOND;
    let date = chrono::DateTime::from_timestamp(seconds, 0).unwrap_or_default();
    format!("{}.{nanos:09}Z", date.format("%Y-%m-%dT%H:%M:%S"))
}

/// What a channel is doing at an instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// There is no such channel.
    Absent,
    /// The channel exists and is `ACTIVE`.
    Ready(ChannelView),
    /// Its creation has not finished.
    Creating(ChannelView),
    /// Its deletion has not finished.
    Deleting(ChannelView),
}

impl Lookup {
    /// The channel, when there is one in any state.
    #[must_use]
    pub fn view(&self) -> Option<&ChannelView> {
        match self {
            Self::Absent => None,
            Self::Ready(view) | Self::Creating(view) | Self::Deleting(view) => Some(view),
        }
    }
}

/// A channel as a read shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelView {
    /// The full resource name.
    pub name: String,
    /// The UUID.
    pub uid: String,
    /// When the creation was accepted.
    pub create_time: Nanos,
    /// When it last changed (a little after its creation's operation ended).
    pub update_time: Nanos,
    /// The Pub/Sub topic of the channel (empty while it is being created).
    pub pubsub_topic: String,
    /// Whether the channel reads as `ACTIVE`: false while it is being created.
    pub active: bool,
}

impl ChannelView {
    /// The members of the resource, in production's order (`@type` first when `typed`).
    #[must_use]
    pub fn to_json(&self, typed: bool) -> Ordered {
        let mut members = Vec::new();
        if typed {
            members.push(("@type", Ordered::text(CHANNEL_TYPE)));
        }
        members.push(("name", Ordered::text(&self.name)));
        members.push(("uid", Ordered::text(&self.uid)));
        members.push(("createTime", Ordered::text(rfc3339(self.create_time))));
        members.push(("updateTime", Ordered::text(rfc3339(self.update_time))));
        members.push(("pubsubTopic", Ordered::text(&self.pubsub_topic)));
        if self.active {
            members.push(("state", Ordered::text("ACTIVE")));
        }
        Ordered::Object(
            members
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }
}

const CHANNEL_TYPE: &str = "type.googleapis.com/google.cloud.eventarc.v1.Channel";
const METADATA_TYPE: &str = "type.googleapis.com/google.cloud.eventarc.v1.OperationMetadata";

/// What a creation or a deletion answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    /// The operation's full name.
    pub operation: String,
}

/// The outcome of a creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Created {
    /// The creation was accepted.
    Started(Started),
    /// The channel exists (production: `409 ALREADY_EXISTS`).
    Exists,
}

/// The outcome of a deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deleted {
    /// The deletion was accepted.
    Started(Started),
    /// There is no such channel, or it is already being deleted (production: `404`).
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Creating,
    Active,
    Deleting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    Create,
    Delete,
}

#[derive(Debug, Clone)]
struct Operation {
    name: String,
    verb: Verb,
    target: String,
    create_time: Nanos,
    end_time: Nanos,
    /// What a creation's operation answers when it is done (the channel as it was created).
    response: Option<Ordered>,
}

#[derive(Debug, Clone)]
struct Record {
    uid: String,
    suffix: u16,
    create_time: Nanos,
    ready_at: Nanos,
    update_time: Nanos,
    /// The start and the end of a deletion's operation.
    deleting: Option<(Nanos, Nanos)>,
}

#[derive(Debug, Default)]
struct State {
    /// Channels by full name.
    channels: BTreeMap<String, Record>,
    /// The time of creation of each channel that has been deleted, by UID (for the page tokens that name it).
    retired: BTreeMap<String, Nanos>,
    operations: BTreeMap<String, Operation>,
}

/// The channels of one server.
pub struct ChannelStore {
    state: Mutex<State>,
    entropy: Mutex<Box<dyn Entropy>>,
    timing: Mutex<Timing>,
}

impl std::fmt::Debug for ChannelStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("ChannelStore").finish_non_exhaustive()
    }
}

impl Default for ChannelStore {
    fn default() -> Self {
        Self::new(Box::new(SystemEntropy::default()), Timing::default())
    }
}

/// The part of a channel name the operations of its location share: `projects/{p}/locations/{l}`.
fn parent_of(name: &str) -> &str {
    name.rsplit_once("/channels/").map_or(name, |(parent, _)| parent)
}

fn id_of(name: &str) -> &str {
    name.rsplit_once('/').map_or(name, |(_, id)| id)
}

/// How far after the end of the creation's operation a channel's `updateTime` is: 19 ms in the recording
/// (the 12 creations: 17 to 25 ms).
const UPDATE_AFTER_READY: u64 = 20 * NANOS_PER_MILLI;
/// How far before the operation's `createTime` the channel's own `createTime` is (6 ms in the recording).
const CHANNEL_BEFORE_OPERATION: u64 = 6 * NANOS_PER_MILLI;
/// How far after the deletion's operation `createTime` the channel's `updateTime` moves (2 to 12 ms in the
/// recording: row 143 shows 2 ms).
const UPDATE_AFTER_DELETE: u64 = 2 * NANOS_PER_MILLI;

impl ChannelStore {
    /// A store with the given identifiers and timing.
    #[must_use]
    pub fn new(entropy: Box<dyn Entropy>, timing: Timing) -> Self {
        Self {
            state: Mutex::new(State::default()),
            entropy: Mutex::new(entropy),
            timing: Mutex::new(timing),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn timing(&self) -> Timing {
        *self
            .timing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Changes how long the operations that are accepted from now on take.
    pub fn set_timing(&self, timing: Timing) {
        *self
            .timing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = timing;
    }

    fn entropy(&self) -> std::sync::MutexGuard<'_, Box<dyn Entropy>> {
        self.entropy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Forgets the channels whose deletion has finished.
    fn settle(state: &mut State, now: Nanos) {
        let gone: Vec<String> = state
            .channels
            .iter()
            .filter(|(_, record)| record.deleting.is_some_and(|(_, end)| now >= end))
            .map(|(name, _)| name.clone())
            .collect();
        for name in gone {
            if let Some(record) = state.channels.remove(&name) {
                state.retired.insert(record.uid, record.create_time);
            }
        }
    }

    fn view(name: &str, record: &Record, phase: Phase) -> ChannelView {
        ChannelView {
            name: name.to_owned(),
            uid: record.uid.clone(),
            create_time: record.create_time,
            update_time: match phase {
                // Not updated yet.
                Phase::Creating => record.create_time,
                // The deletion moved it (2 ms after the operation's `createTime` in the recording).
                Phase::Deleting => record
                    .deleting
                    .map_or(record.update_time, |(start, _)| start + UPDATE_AFTER_DELETE),
                Phase::Active => record.update_time,
            },
            pubsub_topic: if phase == Phase::Creating {
                String::new()
            } else {
                topic(name, record.suffix)
            },
            active: phase != Phase::Creating,
        }
    }

    fn lookup_in(state: &State, name: &str, now: Nanos) -> Lookup {
        match state.channels.get(name) {
            None => Lookup::Absent,
            Some(record) if now < record.ready_at => {
                Lookup::Creating(Self::view(name, record, Phase::Creating))
            }
            Some(record) if record.deleting.is_some() => {
                Lookup::Deleting(Self::view(name, record, Phase::Deleting))
            }
            Some(record) => Lookup::Ready(Self::view(name, record, Phase::Active)),
        }
    }

    /// What the channel is at `now`.
    pub fn lookup(&self, name: &str, now: Nanos) -> Lookup {
        let mut state = self.state();
        Self::settle(&mut state, now);
        Self::lookup_in(&state, name, now)
    }

    /// Makes the channel a loaded function declares exist, ready, from `now` (a channel firebase-tools
    /// creates when it deploys a function that triggers on it). Nothing changes when it is known.
    pub fn declare(&self, name: &str, now: Nanos) {
        let mut state = self.state();
        Self::settle(&mut state, now);
        if state.channels.contains_key(name) {
            return;
        }
        let (uid, suffix) = self.identity();
        let record = Record {
            uid,
            suffix,
            create_time: now,
            ready_at: now,
            update_time: now,
            deleting: None,
        };
        state.channels.insert(name.to_owned(), record);
    }

    /// The UID and the topic suffix of a new channel (one lock of the entropy for both).
    fn identity(&self) -> (String, u16) {
        let mut entropy = self.entropy();
        (entropy.uuid(), entropy.topic_suffix())
    }

    fn operation_name(&self, parent: &str, now: Nanos) -> String {
        let mut entropy = self.entropy();
        format!(
            "{parent}/operations/operation-{}-{:013x}-{}-{}",
            now / NANOS_PER_MILLI,
            now / 1000,
            entropy.hex(8),
            entropy.hex(8),
        )
    }

    /// Accepts the creation of the channel `name` (a full resource name) at `now`.
    pub fn create(&self, name: &str, now: Nanos) -> Created {
        let mut state = self.state();
        Self::settle(&mut state, now);
        if Self::lookup_in(&state, name, now).view().is_some() {
            return Created::Exists;
        }
        let operation = self.operation_name(parent_of(name), now);
        let end = now + self.timing().create;
        let (uid, suffix) = self.identity();
        let record = Record {
            uid,
            suffix,
            create_time: now.saturating_sub(CHANNEL_BEFORE_OPERATION),
            ready_at: end,
            update_time: end + UPDATE_AFTER_READY,
            deleting: None,
        };
        let mut response = Self::view(name, &record, Phase::Active);
        // The channel of a creation's response has not been updated yet.
        response.update_time = response.create_time;
        let response = response.to_json(true);
        state.channels.insert(name.to_owned(), record);
        state.operations.insert(
            operation.clone(),
            Operation {
                name: operation.clone(),
                verb: Verb::Create,
                target: name.to_owned(),
                create_time: now,
                end_time: end,
                response: Some(response),
            },
        );
        Created::Started(Started { operation })
    }

    /// Accepts the deletion of the channel `name` at `now`. A channel being created accepts it (its operation
    /// ends as long after the creation's end as a deletion takes: INFERRED for a deletion that arrives early,
    /// one arrived 7 ms before the end in the recording); one already being deleted answers as an absent one
    /// (a `404`, observed).
    pub fn delete(&self, name: &str, now: Nanos) -> Deleted {
        let mut state = self.state();
        Self::settle(&mut state, now);
        match Self::lookup_in(&state, name, now) {
            Lookup::Absent | Lookup::Deleting(_) => return Deleted::Absent,
            Lookup::Creating(_) | Lookup::Ready(_) => {}
        }
        // A deletion already accepted (while the creation still runs) makes a second one a 404 as well.
        if state.channels.get(name).is_some_and(|record| record.deleting.is_some()) {
            return Deleted::Absent;
        }
        let operation = self.operation_name(parent_of(name), now);
        let duration = self.timing().delete;
        let ready_at = state.channels.get(name).map_or(now, |record| record.ready_at);
        let end = now.max(ready_at) + duration;
        let moved = now + UPDATE_AFTER_DELETE;
        if let Some(record) = state.channels.get_mut(name) {
            record.deleting = Some((now, end));
        }
        // The creation's operation shows the channel as the deletion moved it, when it ends after it.
        if now < ready_at {
            for creation in state
                .operations
                .values_mut()
                .filter(|op| op.verb == Verb::Create && op.target == name)
            {
                if let Some(Ordered::Object(members)) = creation.response.as_mut() {
                    for (key, value) in members.iter_mut() {
                        if key == "updateTime" {
                            *value = Ordered::text(rfc3339(moved));
                        }
                    }
                }
            }
        }
        state.operations.insert(
            operation.clone(),
            Operation {
                name: operation.clone(),
                verb: Verb::Delete,
                target: name.to_owned(),
                create_time: now,
                end_time: end,
                response: None,
            },
        );
        Deleted::Started(Started { operation })
    }

    /// The operation `name` as a read shows it at `now`, or `None` when this store never issued it.
    pub fn operation(&self, name: &str, now: Nanos) -> Option<Ordered> {
        let state = self.state();
        let operation = state.operations.get(name)?;
        Some(operation_json(operation, now))
    }

    /// The operation a creation or a deletion answers (not done: it was just accepted).
    pub fn started(&self, started: &Started, now: Nanos) -> Ordered {
        self.operation(&started.operation, now)
            .unwrap_or_else(|| Ordered::Object(Vec::new()))
    }

    /// The channels of `project` in `location` (`-` for every location) in any state, in the order of creation,
    /// after `after` (a position that a page token names), at most `limit` of them, and whether more follow.
    pub fn list(
        &self,
        project: &str,
        location: &str,
        after: Option<&Position>,
        limit: usize,
        now: Nanos,
    ) -> Listing {
        let mut state = self.state();
        Self::settle(&mut state, now);
        let prefix = format!("projects/{project}/locations/");
        let in_scope = |name: &str| {
            name.strip_prefix(&prefix).is_some_and(|rest| {
                location == "-" || rest.split('/').next().is_some_and(|l| l == location)
            })
        };
        let mut items: Vec<ChannelView> = Vec::new();
        for name in state.channels.keys() {
            if !in_scope(name) {
                continue;
            }
            if let Some(view) = Self::lookup_in(&state, name, now).view() {
                items.push(view.clone());
            }
        }
        // Production's order is not known (see the module documentation): this store orders by the time
        // of creation, then the UID. A page token names the UID of the last channel of its page, and the
        // time of that channel is remembered even after it is deleted, so that a page continues after it.
        items.sort_by(|a, b| (a.create_time, &a.uid).cmp(&(b.create_time, &b.uid)));
        if let Some(after) = after {
            let Some(created) = state
                .channels
                .values()
                .find(|record| record.uid == after.uid)
                .map(|record| record.create_time)
                .or_else(|| state.retired.get(&after.uid).copied())
            else {
                return Listing {
                    items: Vec::new(),
                    more: false,
                    unknown_position: true,
                };
            };
            items.retain(|view| (view.create_time, &view.uid) > (created, &after.uid));
        }
        let more = items.len() > limit;
        items.truncate(limit);
        Listing {
            items,
            more,
            unknown_position: false,
        }
    }
}

/// A page of a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// The channels of the page.
    pub items: Vec<ChannelView>,
    /// Whether channels follow the page.
    pub more: bool,
    /// Whether the page token named a channel this store never had.
    pub unknown_position: bool,
}

fn topic(name: &str, suffix: u16) -> String {
    let project = name
        .strip_prefix("projects/")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or_default();
    let location = parent_of(name).rsplit('/').next().unwrap_or_default();
    format!(
        "projects/{project}/topics/eventarc-channel-{location}-{}-{suffix:03}",
        id_of(name)
    )
}

fn operation_json(operation: &Operation, now: Nanos) -> Ordered {
    let done = now >= operation.end_time;
    let mut metadata = vec![
        ("@type", Ordered::text(METADATA_TYPE)),
        ("createTime", Ordered::text(rfc3339(operation.create_time))),
    ];
    if done {
        metadata.push(("endTime", Ordered::text(rfc3339(operation.end_time))));
    }
    metadata.push(("target", Ordered::text(&operation.target)));
    metadata.push((
        "verb",
        Ordered::text(match operation.verb {
            Verb::Create => "create",
            Verb::Delete => "delete",
        }),
    ));
    metadata.push(("requestedCancellation", Ordered::Bool(false)));
    metadata.push(("apiVersion", Ordered::text("v1")));
    let mut members = vec![
        ("name", Ordered::text(&operation.name)),
        (
            "metadata",
            Ordered::Object(
                metadata
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), value))
                    .collect(),
            ),
        ),
    ];
    if done {
        members.push(("done", Ordered::Bool(true)));
        let response = match operation.verb {
            Verb::Create => operation.response.clone(),
            Verb::Delete => Some(Ordered::object([
                ("@type", Ordered::text(CHANNEL_TYPE)),
                ("name", Ordered::text(&operation.target)),
                ("state", Ordered::text("INACTIVE")),
                ("pubsubTopic", Ordered::text("")),
            ])),
        };
        members.push(("response", response.unwrap_or(Ordered::Object(Vec::new()))));
    } else {
        members.push(("done", Ordered::Bool(false)));
    }
    Ordered::Object(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

// --- page tokens ----------------------------------------------------------------------------------

/// Where a page ends: the last channel it showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Position {
    /// The location of the list.
    pub location: String,
    /// The project number the token names.
    pub project_number: u64,
    /// Its ID.
    pub id: String,
    /// Its UID.
    pub uid: String,
}

const SERVICE: &str = "eventarc.googleapis.com";

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(u8::try_from(value & 0x7f).unwrap_or(0) | 0x80);
        value >>= 7;
    }
    out.push(u8::try_from(value).unwrap_or(0));
}

fn push_bytes(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
    out.push(tag);
    push_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// The checksum of a token: FNV-1a of the message, folded with a constant of this implementation.
fn checksum(message: &[u8]) -> [u8; 8] {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in message {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    (hash ^ 0x6669_7265_656d_7531).to_le_bytes()
}

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, byte)| acc | (u32::from(*byte) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(BASE64URL[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

fn unbase64url(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let symbols: Vec<u32> = text
        .trim_end_matches('=')
        .bytes()
        .map(|byte| {
            BASE64URL
                .iter()
                .position(|candidate| *candidate == byte)
                .and_then(|index| u32::try_from(index).ok())
        })
        .collect::<Option<_>>()?;
    for chunk in symbols.chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, symbol)| acc | (symbol << (18 - 6 * i)));
        for i in 0..chunk.len() - 1 {
            out.push(u8::try_from((n >> (16 - 8 * i)) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// A number that stands for a project in a page token: 12 decimal digits derived from the project ID
/// (production writes the project number; a local project has none).
#[must_use]
pub fn project_number(project: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in project.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    100_000_000_000 + hash % 900_000_000_000
}

impl Position {
    /// The token that continues a list after this position.
    #[must_use]
    pub fn token(&self) -> String {
        let mut parent = Vec::new();
        push_bytes(&mut parent, 0x0a, self.location.as_bytes());
        push_bytes(&mut parent, 0x12, SERVICE.as_bytes());
        parent.extend_from_slice(&[0x18, 0x01, 0x20]);
        push_varint(&mut parent, self.project_number);
        push_bytes(&mut parent, 0x2a, b"channels");
        let mut inner = Vec::new();
        push_bytes(&mut inner, 0x0a, &parent);
        push_bytes(&mut inner, 0x12, self.id.as_bytes());
        push_bytes(&mut inner, 0x1a, self.uid.as_bytes());
        // The checksum is the last field of the one message the token holds.
        let sum = checksum(&inner);
        inner.push(0x21);
        inner.extend_from_slice(&sum);
        let mut message = Vec::new();
        push_bytes(&mut message, 0x0a, &inner);
        base64url(&message)
    }

    /// The position a token names, or `None` when it is not a token of this implementation.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        let bytes = unbase64url(token)?;
        let mut reader = Reader::new(&bytes);
        let message = reader.field(0x0a)?;
        if !reader.done() || message.len() < 9 {
            return None;
        }
        let (inner, tail) = message.split_at(message.len() - 9);
        if tail[0] != 0x21 || tail[1..] != checksum(inner) {
            return None;
        }
        let mut reader = Reader::new(inner);
        let parent = reader.field(0x0a)?;
        let id = String::from_utf8(reader.field(0x12)?.to_vec()).ok()?;
        let uid = String::from_utf8(reader.field(0x1a)?.to_vec()).ok()?;
        if !reader.done() {
            return None;
        }
        let mut reader = Reader::new(parent);
        let location = String::from_utf8(reader.field(0x0a)?.to_vec()).ok()?;
        if reader.field(0x12)? != SERVICE.as_bytes() {
            return None;
        }
        if reader.byte()? != 0x18 || reader.byte()? != 0x01 || reader.byte()? != 0x20 {
            return None;
        }
        let project_number = reader.varint()?;
        if reader.field(0x2a)? != b"channels" || !reader.done() {
            return None;
        }
        Some(Self {
            location,
            project_number,
            id,
            uid,
        })
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn byte(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(length)?;
        let slice = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(slice)
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn field(&mut self, tag: u8) -> Option<&'a [u8]> {
        if self.byte()? != tag {
            return None;
        }
        let length = usize::try_from(self.varint()?).ok()?;
        self.take(length)
    }

    const fn done(&self) -> bool {
        self.at == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::{BTreeMap, BTreeSet};

    const PROJECT: &str = "demo";
    const SECOND: u64 = NANOS_PER_SECOND;
    /// 2026-10-05T11:11:29Z.
    const T0: Nanos = 1_791_198_689 * SECOND;

    /// Identifiers from a counter: every channel, operation and topic gets its own.
    #[derive(Default)]
    struct Sequence(u64);

    impl Entropy for Sequence {
        fn uuid(&mut self) -> String {
            self.0 += 1;
            uuid_from(self.0.wrapping_mul(0x9e37_79b9_7f4a_7c15), self.0)
        }

        fn hex(&mut self, digits: usize) -> String {
            self.0 += 1;
            format!("{:0digits$x}", self.0)
        }

        fn topic_suffix(&mut self) -> u16 {
            self.0 += 1;
            u16::try_from(self.0 % 1000).unwrap_or(0)
        }
    }

    fn store() -> ChannelStore {
        ChannelStore::new(
            Box::new(Sequence::default()),
            Timing {
                create: 5 * SECOND,
                delete: 4 * SECOND,
            },
        )
    }

    fn name(location: &str, id: &str) -> String {
        format!("projects/{PROJECT}/locations/{location}/channels/{id}")
    }

    fn started(created: Created) -> Started {
        match created {
            Created::Started(started) => started,
            other @ Created::Exists => panic!("not started: {other:?}"),
        }
    }

    fn done(operation: &Ordered) -> bool {
        operation["done"] == Ordered::Bool(true)
    }

    #[test]
    fn a_creation_is_an_operation_that_ends_after_its_duration_with_the_channel_in_its_response() {
        let store = store();
        let channel = name("us-central1", "c");
        let operation = started(store.create(&channel, T0));
        assert!(operation.operation.starts_with(
            "projects/demo/locations/us-central1/operations/operation-1791198689000-"
        ));
        let pending = store.operation(&operation.operation, T0 + SECOND).unwrap();
        assert!(!done(&pending));
        assert!(pending["metadata"].get("endTime").is_none());
        assert_eq!(pending["metadata"]["verb"], "create");
        assert_eq!(pending["metadata"]["target"], channel.as_str());
        assert!(pending.get("response").is_none());
        let finished = store
            .operation(&operation.operation, T0 + 5 * SECOND)
            .unwrap();
        assert!(done(&finished));
        assert_eq!(finished["metadata"]["endTime"], rfc3339(T0 + 5 * SECOND).as_str());
        assert_eq!(
            finished["response"]["@type"],
            "type.googleapis.com/google.cloud.eventarc.v1.Channel"
        );
        assert_eq!(finished["response"]["name"], channel.as_str());
        assert_eq!(finished["response"]["state"], "ACTIVE");
        // The channel of the response has not been updated since its creation; the read shows the update.
        assert_eq!(
            finished["response"]["createTime"],
            finished["response"]["updateTime"]
        );
        let Lookup::Ready(view) = store.lookup(&channel, T0 + 5 * SECOND) else {
            panic!("ready")
        };
        // 20 ms after the end of the operation (recorded: 17 to 25 ms), and 6 ms before the operation began.
        assert_eq!(view.update_time, T0 + 5 * SECOND + 20_000_000);
        assert_eq!(view.create_time, T0 - 6_000_000);
        assert_eq!(
            view.pubsub_topic,
            format!(
                "projects/demo/topics/eventarc-channel-us-central1-c-{:03}",
                view.pubsub_topic.rsplit('-').next().unwrap().parse::<u16>().unwrap()
            )
        );
        assert_eq!(view.pubsub_topic.rsplit('-').next().unwrap().len(), 3);
    }

    #[test]
    fn the_phases_of_a_channel_are_creating_ready_deleting_absent() {
        let store = store();
        let channel = name("us-central1", "c");
        assert_eq!(store.lookup(&channel, T0), Lookup::Absent);
        let _ = started(store.create(&channel, T0));
        // Stage C: while the creation runs the channel reads without a `state` and with an empty topic, a
        // creation of its name is a conflict.
        let Lookup::Creating(view) = store.lookup(&channel, T0 + 4 * SECOND) else {
            panic!("creating")
        };
        assert!(!view.active);
        assert_eq!(view.pubsub_topic, "");
        assert_eq!(view.update_time, view.create_time);
        let json = view.to_json(false).to_value();
        assert!(json.get("state").is_none());
        assert_eq!(json["pubsubTopic"], "");
        assert_eq!(store.create(&channel, T0 + 4 * SECOND), Created::Exists);
        assert!(matches!(
            store.lookup(&channel, T0 + 5 * SECOND),
            Lookup::Ready(_)
        ));
        // Recorded: a creation of a channel that exists is a conflict.
        assert_eq!(store.create(&channel, T0 + 6 * SECOND), Created::Exists);
        let deletion = match store.delete(&channel, T0 + 7 * SECOND) {
            Deleted::Started(started) => started,
            other @ Deleted::Absent => panic!("not started: {other:?}"),
        };
        // Stage C: while the deletion runs the channel still reads as ACTIVE, its `updateTime` moved to the
        // deletion; a second deletion is a 404 and a creation a conflict.
        let Lookup::Deleting(view) = store.lookup(&channel, T0 + 8 * SECOND) else {
            panic!("deleting")
        };
        assert!(view.active);
        assert_eq!(view.update_time, T0 + 7 * SECOND + 2 * NANOS_PER_MILLI);
        assert_eq!(store.delete(&channel, T0 + 8 * SECOND), Deleted::Absent);
        assert_eq!(store.create(&channel, T0 + 8 * SECOND), Created::Exists);
        let pending = store.operation(&deletion.operation, T0 + 8 * SECOND).unwrap();
        assert!(!done(&pending));
        assert_eq!(pending["metadata"]["verb"], "delete");
        let finished = store.operation(&deletion.operation, T0 + 11 * SECOND).unwrap();
        assert!(done(&finished));
        assert_eq!(finished["response"]["state"], "INACTIVE");
        assert_eq!(finished["response"]["pubsubTopic"], "");
        assert_eq!(finished["response"]["name"], channel.as_str());
        // Recorded: a deleted channel is absent, and a second deletion is a 404.
        assert_eq!(store.lookup(&channel, T0 + 11 * SECOND), Lookup::Absent);
        assert_eq!(store.delete(&channel, T0 + 11 * SECOND), Deleted::Absent);
        // And it can be created again, as another channel.
        let again = started(store.create(&channel, T0 + 12 * SECOND));
        assert_ne!(again.operation, deletion.operation);
    }

    #[test]
    fn a_deletion_accepted_while_the_creation_runs_ends_a_deletion_after_the_creation_and_moves_the_response() {
        // Stage C, rows 128 to 137: the deletion arrived 7 ms before the creation's end and ended 3.9 s after it.
        let store = store();
        let channel = name("us-central1", "c");
        let creation = started(store.create(&channel, T0));
        let deletion = match store.delete(&channel, T0 + 4_900_000_000) {
            Deleted::Started(started) => started,
            other @ Deleted::Absent => panic!("not started: {other:?}"),
        };
        // The creation ends at T0 + 5 s as it was going to; the deletion a deletion (4 s) after that.
        assert!(done(&store.operation(&creation.operation, T0 + 5 * SECOND).unwrap()));
        assert!(!done(&store.operation(&deletion.operation, T0 + 8 * SECOND).unwrap()));
        assert!(done(&store.operation(&deletion.operation, T0 + 9 * SECOND).unwrap()));
        // The creation's response shows the channel as the deletion moved it.
        let response = store.operation(&creation.operation, T0 + 5 * SECOND).unwrap();
        assert_eq!(
            response["response"]["updateTime"],
            rfc3339(T0 + 4_900_000_000 + 2 * NANOS_PER_MILLI).as_str()
        );
        // During the rest of the creation the channel is still being created; then it is being deleted.
        assert!(matches!(store.lookup(&channel, T0 + 4_950_000_000), Lookup::Creating(_)));
        assert!(matches!(store.lookup(&channel, T0 + 6 * SECOND), Lookup::Deleting(_)));
        assert_eq!(store.lookup(&channel, T0 + 9 * SECOND), Lookup::Absent);
    }

    #[test]
    fn a_deletion_moves_only_the_response_of_the_creation_it_cut_short_of_its_own_channel() {
        let store = store();
        let one = name("us-central1", "c1");
        let two = name("us-central1", "c2");
        let first = started(store.create(&one, T0));
        let second = started(store.create(&two, T0));
        let before = store.operation(&second.operation, T0 + 5 * SECOND).unwrap();
        // Deleted while its creation runs: its own creation's response moves, another channel's does not.
        let _ = store.delete(&one, T0 + 4 * SECOND);
        assert_eq!(store.operation(&second.operation, T0 + 5 * SECOND).unwrap(), before);
        assert_ne!(
            store.operation(&first.operation, T0 + 5 * SECOND).unwrap()["response"]["updateTime"],
            before["response"]["updateTime"]
        );
        // Deleted at the very instant its creation ends, the channel is ready: the response does not move.
        let at = store.create(&name("us-central1", "c3"), T0 + 10 * SECOND);
        let third = started(at);
        let unmoved = store.operation(&third.operation, T0 + 15 * SECOND).unwrap();
        let _ = store.delete(&name("us-central1", "c3"), T0 + 15 * SECOND);
        assert_eq!(store.operation(&third.operation, T0 + 15 * SECOND).unwrap(), unmoved);
    }

    #[test]
    fn an_operation_the_store_never_started_is_unknown_and_each_operation_has_its_own_name() {
        let store = store();
        assert!(store
            .operation("projects/demo/locations/us-central1/operations/x", T0)
            .is_none());
        let first = started(store.create(&name("us-central1", "a"), T0));
        let second = started(store.create(&name("us-central1", "b"), T0));
        assert_ne!(first.operation, second.operation);
    }

    #[test]
    fn a_declared_channel_exists_from_its_first_use_and_is_never_replaced() {
        let store = store();
        let channel = name("us-central1", "custom");
        store.declare(&channel, T0);
        let Lookup::Ready(first) = store.lookup(&channel, T0) else {
            panic!("ready")
        };
        store.declare(&channel, T0 + SECOND);
        let Lookup::Ready(second) = store.lookup(&channel, T0 + SECOND) else {
            panic!("ready")
        };
        assert_eq!(first, second);
        assert_eq!(store.create(&channel, T0 + SECOND), Created::Exists);
    }

    fn page(
        store: &ChannelStore,
        location: &str,
        after: Option<&Position>,
        limit: usize,
        now: Nanos,
    ) -> Listing {
        store.list(PROJECT, location, after, limit, now)
    }

    fn position_of(view: &ChannelView) -> Position {
        Position {
            location: view.name.split('/').nth(3).unwrap().to_owned(),
            project_number: project_number(PROJECT),
            id: id_of(&view.name).to_owned(),
            uid: view.uid.clone(),
        }
    }

    #[test]
    fn a_list_shows_the_channels_of_its_scope_in_the_order_of_creation_and_pages_continue_after_a_deleted_one() {
        let store = store();
        for (offset, (location, id)) in [
            ("us-central1", "a"),
            ("europe-west1", "b"),
            ("us-central1", "c"),
            ("us-central1", "d"),
        ]
        .into_iter()
        .enumerate()
        {
            let _ = started(store.create(&name(location, id), T0 + offset as u64 * SECOND));
        }
        let now = T0 + 20 * SECOND;
        let ids = |listing: &Listing| -> Vec<String> {
            listing
                .items
                .iter()
                .map(|view| id_of(&view.name).to_owned())
                .collect()
        };
        assert_eq!(ids(&page(&store, "us-central1", None, 10, now)), ["a", "c", "d"]);
        assert_eq!(ids(&page(&store, "-", None, 10, now)), ["a", "b", "c", "d"]);
        assert_eq!(ids(&page(&store, "europe-west1", None, 10, now)), ["b"]);
        assert!(page(&store, "asia-east1", None, 10, now).items.is_empty());
        let first = page(&store, "us-central1", None, 1, now);
        assert!(first.more);
        let second = page(&store, "us-central1", Some(&position_of(&first.items[0])), 1, now);
        assert_eq!(ids(&second), ["c"]);
        // The channel the token names is deleted: the page continues after its place all the same.
        let _ = store.delete(&name("us-central1", "c"), now);
        let later = now + 5 * SECOND;
        let third = page(&store, "us-central1", Some(&position_of(&second.items[0])), 5, later);
        assert_eq!(ids(&third), ["d"]);
        assert!(!third.more);
        // A token that names a channel this store never had is refused.
        let stranger = Position {
            uid: "00000000-0000-4000-8000-000000000000".to_owned(),
            ..position_of(&first.items[0])
        };
        assert!(page(&store, "us-central1", Some(&stranger), 5, later).unknown_position);
        // A channel being created is listed too (stage C), without a `state`.
        let _ = started(store.create(&name("us-central1", "e"), later));
        let listing = page(&store, "us-central1", None, 5, later);
        let last = listing.items.last().expect("a channel");
        assert!(last.name.ends_with("/e") && !last.active);
        assert_eq!(page(&store, "europe-west1", None, 5, later).items.len(), 1);
    }

    #[test]
    fn the_timestamps_have_nine_digits_and_the_four_recorded_rows_round_trip() {
        assert_eq!(rfc3339(T0), "2026-10-05T11:11:29.000000000Z");
        assert_eq!(rfc3339(T0 + 877_140_422), "2026-10-05T11:11:29.877140422Z");
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000000000Z");
    }

    #[test]
    fn a_uuid_is_a_version_4_one() {
        let text = uuid_from(u64::MAX, u64::MAX);
        assert_eq!(text, "ffffffff-ffff-4fff-bfff-ffffffffffff");
        let text = uuid_from(0, 0);
        assert_eq!(text, "00000000-0000-4000-8000-000000000000");
    }

    #[test]
    fn the_system_entropy_gives_distinct_well_formed_identifiers() {
        let mut entropy = SystemEntropy::default();
        let mut seen = BTreeSet::new();
        for _ in 0..200 {
            let uid = entropy.uuid();
            assert_eq!(uid.len(), 36);
            assert!(seen.insert(uid));
            assert!(entropy.topic_suffix() < 1000);
            let hex = entropy.hex(13);
            assert_eq!(hex.len(), 13);
            assert!(hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        }
        assert_eq!(entropy.hex(40).len(), 40);
    }

    /// The token of production's list of two channels (stage B, row 27), with the project number masked:
    /// the structure and the length are the recorded ones.
    #[test]
    fn a_page_token_has_the_structure_and_the_length_of_the_recorded_one() {
        let position = Position {
            location: "us-central1".to_owned(),
            project_number: 123_456_789_012,
            id: "fe43a83839852f-cl-c2".to_owned(),
            uid: "fe1470e1-3b1a-4dda-8f04-0bbb99d89451".to_owned(),
        };
        let token = position.token();
        assert_eq!(token.len(), 175, "the recorded token for these lengths");
        // The recorded token starts the same way up to the project number: the outer field, the parent
        // with the location and the service, the two constant fields and the start of the number.
        assert!(token.starts_with(
            "CoABCjkKC3VzLWNlbnRyYWwxEhdldmVudGFyYy5nb29nbGVhcGlzLmNvbRgBI"
        ));
        assert!(token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_eq!(Position::parse(&token), Some(position));
    }

    fn arbitrary_position() -> impl Strategy<Value = Position> {
        (
            "[a-z]{2,12}-[a-z]{4,9}[0-9]{1,2}",
            100_000_000_000u64..1_000_000_000_000,
            "[a-z][a-z0-9-]{0,40}[a-z0-9]",
            "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
        )
            .prop_map(|(location, project_number, id, uid)| Position {
                location,
                project_number,
                id,
                uid,
            })
    }

    proptest! {
        #[test]
        fn a_page_token_round_trips(position in arbitrary_position()) {
            let token = position.token();
            prop_assert_eq!(Position::parse(&token), Some(position));
        }

        #[test]
        fn a_page_token_with_one_byte_changed_is_refused(
            position in arbitrary_position(),
            at in any::<prop::sample::Index>(),
            flip in 1u8..=255,
        ) {
            let token = position.token();
            let mut bytes = unbase64url(&token).unwrap();
            let index = at.index(bytes.len());
            bytes[index] ^= flip;
            let changed = base64url(&bytes);
            prop_assert_ne!(Position::parse(&changed), Some(position));
        }

        #[test]
        fn text_that_is_not_a_token_is_refused(text in "[ -~]{0,200}") {
            // Any printable text: refused unless it happens to be a token of this implementation.
            if let Some(position) = Position::parse(&text) {
                prop_assert_eq!(base64url(&unbase64url(&position.token()).unwrap()), position.token());
            }
        }

        #[test]
        fn the_text_of_a_timestamp_is_thirty_characters_and_parses_back(instant in 0u64..4_000_000_000_000_000_000) {
            let text = rfc3339(instant);
            prop_assert_eq!(text.len(), 30);
            let parsed = chrono::DateTime::parse_from_rfc3339(&text).unwrap();
            prop_assert_eq!(
                u64::try_from(parsed.timestamp_nanos_opt().unwrap()).unwrap(),
                instant
            );
        }

        #[test]
        fn a_uuid_is_a_canonical_version_4(high in any::<u64>(), low in any::<u64>()) {
            let text = uuid_from(high, low);
            let parts: Vec<&str> = text.split('-').collect();
            prop_assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), vec![8, 4, 4, 4, 12]);
            prop_assert!(parts[2].starts_with('4'));
            prop_assert!(matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'));
            prop_assert!(text.bytes().all(|b| b == b'-' || b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        }
    }

    #[test]
    fn the_system_entropy_varies_its_topic_suffixes() {
        let mut entropy = SystemEntropy::default();
        let suffixes: BTreeSet<u16> = (0..300).map(|_| entropy.topic_suffix()).collect();
        assert!(suffixes.len() > 50, "{} distinct suffixes", suffixes.len());
        assert!(suffixes.iter().all(|suffix| *suffix < 1000));
    }

    #[test]
    fn a_store_is_debuggable_without_showing_its_state() {
        assert_eq!(format!("{:?}", store()), "ChannelStore { .. }");
    }

    #[test]
    fn varints_have_their_encodings() {
        let encode = |value: u64| {
            let mut out = Vec::new();
            push_varint(&mut out, value);
            out
        };
        assert_eq!(encode(0), [0]);
        assert_eq!(encode(1), [1]);
        assert_eq!(encode(127), [0x7f]);
        assert_eq!(encode(128), [0x80, 0x01]);
        assert_eq!(encode(300), [0xac, 0x02]);
        assert_eq!(encode(16_383), [0xff, 0x7f]);
        assert_eq!(encode(16_384), [0x80, 0x80, 0x01]);
        assert_eq!(encode(u64::MAX).len(), 10);
        for value in [0, 1, 127, 128, 300, 1 << 35, 637_502_084_468, u64::MAX] {
            let bytes = encode(value);
            let mut reader = Reader::new(&bytes);
            assert_eq!(reader.varint(), Some(value));
            assert!(reader.done());
        }
        // A varint that does not end, or is longer than ten bytes, is not one.
        assert_eq!(Reader::new(&[0x80]).varint(), None);
        assert_eq!(Reader::new(&[0x80; 11]).varint(), None);
    }

    #[test]
    fn the_project_number_stands_for_its_project_in_twelve_digits() {
        let numbers: Vec<u64> = ["demo", "demo-app", "fireemu-oracle-idp", "a", "b", "c", "other"]
            .iter()
            .map(|project| project_number(project))
            .collect();
        for number in &numbers {
            assert!((100_000_000_000..1_000_000_000_000).contains(number), "{number}");
        }
        assert_eq!(numbers.iter().collect::<BTreeSet<_>>().len(), numbers.len());
        assert_eq!(project_number("demo"), project_number("demo"));
        // The numbers are spread over the range, not clustered at its start.
        assert!(numbers.iter().max().unwrap() - numbers.iter().min().unwrap() > 100_000_000_000);
    }

    /// A token built by hand, with the checksum it must have: only the structure is wrong when a part is.
    struct Token {
        location: &'static [u8],
        service: &'static [u8],
        constants: &'static [u8],
        number: u64,
        word: &'static [u8],
        id: &'static [u8],
        uid: &'static [u8],
        inner_tail: &'static [u8],
        tail_tag: u8,
        outer_tail: &'static [u8],
        checksum_ok: bool,
    }

    impl Token {
        const fn good() -> Self {
            Self {
                location: b"us-central1",
                service: SERVICE.as_bytes(),
                constants: &[0x18, 0x01, 0x20],
                number: 123_456_789_012,
                word: b"channels",
                id: b"c",
                uid: b"00000000-0000-4000-8000-000000000000",
                inner_tail: b"",
                tail_tag: 0x21,
                outer_tail: b"",
                checksum_ok: true,
            }
        }

        fn text(&self) -> String {
            let mut parent = Vec::new();
            push_bytes(&mut parent, 0x0a, self.location);
            push_bytes(&mut parent, 0x12, self.service);
            parent.extend_from_slice(self.constants);
            push_varint(&mut parent, self.number);
            if !self.word.is_empty() {
                push_bytes(&mut parent, 0x2a, self.word);
            }
            let mut inner = Vec::new();
            push_bytes(&mut inner, 0x0a, &parent);
            push_bytes(&mut inner, 0x12, self.id);
            push_bytes(&mut inner, 0x1a, self.uid);
            inner.extend_from_slice(self.inner_tail);
            let sum = if self.checksum_ok { checksum(&inner) } else { [7; 8] };
            inner.push(self.tail_tag);
            inner.extend_from_slice(&sum);
            let mut message = Vec::new();
            push_bytes(&mut message, 0x0a, &inner);
            message.extend_from_slice(self.outer_tail);
            base64url(&message)
        }
    }

    #[test]
    fn a_token_is_accepted_only_when_every_part_of_its_structure_is_right() {
        let good = Token::good();
        let position = Position::parse(&good.text()).expect("the control parses");
        assert_eq!(position.location, "us-central1");
        assert_eq!(position.project_number, 123_456_789_012);
        assert_eq!((position.id.as_str(), position.uid.len()), ("c", 36));
        let bad: Vec<(&str, Token)> = vec![
            ("a checksum that is wrong", Token { checksum_ok: false, ..Token::good() }),
            ("a tail that is not a checksum field", Token { tail_tag: 0x22, ..Token::good() }),
            ("bytes after the message", Token { outer_tail: b"\x00", ..Token::good() }),
            ("a field after the UID", Token { inner_tail: &[0x28, 0x01], ..Token::good() }),
            ("another service", Token { service: b"pubsub.googleapis.com", ..Token::good() }),
            ("other constants", Token { constants: &[0x18, 0x02, 0x20], ..Token::good() }),
            ("other constants (the first)", Token { constants: &[0x19, 0x01, 0x20], ..Token::good() }),
            ("other constants (the last)", Token { constants: &[0x18, 0x01, 0x21], ..Token::good() }),
            ("another word", Token { word: b"channelz", ..Token::good() }),
            ("no word", Token { word: b"", ..Token::good() }),
            ("an ID that is not UTF-8", Token { id: &[0xff, 0xfe], ..Token::good() }),
            ("a UID that is not UTF-8", Token { uid: &[0xff, 0xfe], ..Token::good() }),
        ];
        for (what, token) in bad {
            assert_eq!(Position::parse(&token.text()), None, "{what}");
        }
        for text in ["", "A", "AA", "AAAA", "CoAB", "CgA", "CgAhAAAAAAAAAAA", "!!!!", "ab cd"] {
            assert_eq!(Position::parse(text), None, "{text:?}");
        }
        // A message too short to hold a checksum, and one that is only a checksum.
        for message in [vec![], vec![0x21; 8], vec![0x21; 9], vec![0x0a, 0x00]] {
            let mut framed = Vec::new();
            push_bytes(&mut framed, 0x0a, &message);
            assert_eq!(Position::parse(&base64url(&framed)), None, "{message:?}");
        }
    }

    #[test]
    fn changing_one_character_of_a_token_that_keeps_its_structure_is_caught_by_the_checksum() {
        let token = Token::good().text();
        let bytes = unbase64url(&token).unwrap();
        // Change one character of the ID, then of the UID, then of the location: the structure holds.
        for needle in [&b"c"[..], &b"00000000-0000-4000"[..], &b"us-central1"[..]] {
            let at = bytes.windows(needle.len()).position(|w| w == needle).unwrap();
            let mut changed = bytes.clone();
            changed[at] = if changed[at] == b'x' { b'y' } else { b'x' };
            assert_eq!(Position::parse(&base64url(&changed)), None, "{needle:?}");
        }
        // And two different positions never share a checksum by accident of the function being constant.
        let other = Position { id: "d".to_owned(), ..Position::parse(&token).unwrap() };
        let tail = |text: &str| text[text.len() - 12..].to_owned();
        assert_ne!(tail(&token), tail(&other.token()));
    }

    // --- a model of the store ----------------------------------------------------------------------

    /// What a channel is, by the rules alone: one record for each name that has not been forgotten.
    #[derive(Debug, Clone, Copy)]
    struct Ref {
        ready_at: Nanos,
        deleting: Option<Nanos>,
        created_at: Nanos,
    }

    #[derive(Debug, Clone)]
    enum Step {
        Create(u8),
        Delete(u8),
        Read(u8),
        Advance(u64),
        List(u8),
    }

    fn steps() -> impl Strategy<Value = Vec<Step>> {
        prop::collection::vec(
            prop_oneof![
                (0u8..4).prop_map(Step::Create),
                (0u8..4).prop_map(Step::Delete),
                (0u8..4).prop_map(Step::Read),
                (0u64..4_000_000_000).prop_map(Step::Advance),
                (1u8..4).prop_map(Step::List),
            ],
            1..60,
        )
    }

    proptest! {
        /// Any sequence of requests at any instants gives, step by step, what the rules say: the phase of
        /// each channel, which requests start and which are refused, when an operation is done, and every
        /// page of a list.
        #[test]
        fn the_store_follows_the_rules_for_any_sequence_of_requests(steps in steps()) {
            let store = store();
            let create = 5 * SECOND;
            let delete = 4 * SECOND;
            let mut model: BTreeMap<String, Ref> = BTreeMap::new();
            let mut operations: Vec<(String, Nanos, Nanos)> = Vec::new();
            let mut now = T0;
            for step in steps {
                // What the model has forgotten by now.
                model.retain(|_, record| record.deleting.is_none_or(|end| now < end));
                match step {
                    Step::Advance(by) => now += by,
                    Step::Create(which) => {
                        let channel = name("us-central1", &format!("c{which}"));
                        let got = store.create(&channel, now);
                        // A channel in any phase is a conflict (stage C: while it is being created; INFERRED while it is being deleted).
                        match model.entry(channel) {
                            std::collections::btree_map::Entry::Occupied(_) => {
                                prop_assert_eq!(got, Created::Exists);
                            }
                            std::collections::btree_map::Entry::Vacant(slot) => {
                                let operation = started(got);
                                slot.insert(Ref { ready_at: now + create, deleting: None, created_at: now });
                                operations.push((operation.operation, now, now + create));
                            }
                        }
                    }
                    Step::Delete(which) => {
                        let channel = name("us-central1", &format!("c{which}"));
                        let got = store.delete(&channel, now);
                        match model.get_mut(&channel) {
                            None => prop_assert_eq!(got, Deleted::Absent),
                            // Already being deleted: as an absent channel (a 404, observed).
                            Some(record) if record.deleting.is_some() => prop_assert_eq!(got, Deleted::Absent),
                            Some(record) => {
                                let Deleted::Started(operation) = got else { panic!("started") };
                                let end = now.max(record.ready_at) + delete;
                                record.deleting = Some(end);
                                operations.push((operation.operation, now, end));
                            }
                        }
                    }
                    Step::Read(which) => {
                        let channel = name("us-central1", &format!("c{which}"));
                        let expected = match model.get(&channel) {
                            None => "absent",
                            Some(record) if now < record.ready_at => "creating",
                            Some(record) if record.deleting.is_some() => "deleting",
                            Some(_) => "ready",
                        };
                        let got = match store.lookup(&channel, now) {
                            Lookup::Absent => "absent",
                            Lookup::Ready(_) => "ready",
                            Lookup::Creating(_) => "creating",
                            Lookup::Deleting(_) => "deleting",
                        };
                        prop_assert_eq!(got, expected);
                    }
                    Step::List(size) => {
                        let ready: Vec<String> = {
                            let mut ready: Vec<(&Ref, &String)> = model
                                .iter()
                                .map(|(n, r)| (r, n))
                                .collect();
                            ready.sort_by_key(|(r, _)| r.created_at);
                            ready.into_iter().map(|(_, n)| n.clone()).collect()
                        };
                        // Walk the pages: no channel twice, none missed, in the order of the unpaged list.
                        let mut seen: Vec<String> = Vec::new();
                        let mut after: Option<Position> = None;
                        loop {
                            let listing = store.list(PROJECT, "us-central1", after.as_ref(), usize::from(size), now);
                            prop_assert!(listing.items.len() <= usize::from(size));
                            seen.extend(listing.items.iter().map(|v| v.name.clone()));
                            match (listing.more, listing.items.last()) {
                                (true, Some(last)) => after = Some(position_of(last)),
                                _ => break,
                            }
                        }
                        // Channels created at the same instant come in the order of their UIDs, which the
                        // model does not know: compare the runs of one instant as sets.
                        let runs = |names: &[String]| -> Vec<(Nanos, BTreeSet<String>)> {
                            let mut runs: Vec<(Nanos, BTreeSet<String>)> = Vec::new();
                            for name in names {
                                let at = model[name].created_at;
                                match runs.last_mut() {
                                    Some((last, set)) if *last == at => {
                                        set.insert(name.clone());
                                    }
                                    _ => runs.push((at, BTreeSet::from([name.clone()]))),
                                }
                            }
                            runs
                        };
                        prop_assert_eq!(runs(&seen), runs(&ready));
                    }
                }
                // Every operation reads done exactly from its end, and never changes its name.
                for (operation, start, end) in &operations {
                    let read = store.operation(operation, now).unwrap();
                    prop_assert_eq!(done(&read), now >= *end, "{} started {} ends {}", operation, start, end);
                }
            }
        }
    }
}
