//! `CloudEvents` JSON for Firestore document changes, Storage object events and scheduled
//! runs, in the shapes the `firebase-functions` v2 SDK decodes with
//! `datacontenttype: application/json` (the SDK's Firestore JSON path requires it and removes
//! it before a handler runs; a production Storage event carries none, and neither does ours).

use fireemu_adapter_grpc::encode::encode_document;
use fireemu_adapter_grpc::rest::json::{document_to_json, shorten_fraction};
use fireemu_core_auth::store::UserRecord;
use fireemu_core_firestore::store::Document;
use fireemu_core_functions::event::{
    auth_attributes, firestore_attributes, pubsub_attributes, schedule_attributes,
    storage_attributes, with_auth_context,
};
use fireemu_core_functions::manifest::{
    AuthEvent, DocumentEvent, FunctionGeneration, FunctionSpec, ObjectEvent, Trigger,
};
use fireemu_core_storage::etag::production_etag;
use fireemu_core_storage::store::{ObjectMetadata, StorageEvent};
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Map, Value};
use std::fmt::Write as _;

fn rfc3339(t: LogicalInstant) -> String {
    t.to_rfc3339()
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

/// An object timestamp as production writes it: RFC 3339 UTC with exactly three fractional
/// digits, the extra ones cut and not rounded (recorded in the object resource of the Storage
/// REST API and again in the object a finalize event carries, 2026-10-01:
/// `2026-10-01T08:49:26.486Z`). The Storage REST writer applies the same rule, and so does the
/// `context.timestamp` of an Auth v1 event (`2026-10-04T18:44:34.537Z`, see [`auth_event`]).
fn object_time(t: LogicalInstant) -> String {
    let full = rfc3339(t);
    let Some(seconds) = full.strip_suffix('Z') else {
        return full;
    };
    let (whole, fraction) = seconds.split_once('.').unwrap_or((seconds, ""));
    format!("{whole}.{fraction:0<3.3}Z")
}

/// The `time` of a Storage `CloudEvent`. Production's finalize event carries the object's
/// creation instant with the microseconds it knows (`2026-10-01T08:49:26.486927Z`, while the
/// object's own `timeCreated` shows `.486Z`), printed as protobuf JSON prints a `Timestamp`.
/// The other kinds were not recorded; they keep the instant the runtime admitted the event, in
/// the same form.
fn storage_time(
    kind: ObjectEvent,
    object: &ObjectMetadata,
    admitted: LogicalInstant,
    time_deleted: Option<LogicalInstant>,
) -> String {
    let instant = match kind {
        ObjectEvent::Finalized => object.time_created,
        // RECORDED (FE v5, `functions-events-formal-20261004T182904Z`, v2 `time` to the
        // microsecond): the event of a generation that became noncurrent is stamped with the
        // instant it stopped being live, which is the creation instant of the generation that
        // replaced it, the same microsecond as that Finalized event.
        ObjectEvent::Archived => time_deleted.unwrap_or(admitted),
        _ => admitted,
    };
    let nanos = instant.as_nanos();
    // An instant the logical clock cannot print stays as it is and takes `rfc3339`'s fallback.
    let cut = nanos
        .checked_sub(nanos.rem_euclid(1_000))
        .map_or(instant, LogicalInstant::from_nanos);
    firestore_time(cut)
}

/// A Firestore event's time as protobuf JSON prints a `Timestamp`: a fraction of zero, three,
/// six or nine digits, whichever is the shortest that is exact (the rule `document_to_json`
/// applies to a document's `createTime`). Production's Firestore create event carries its time
/// this way (`2026-09-30T12:03:18.846431Z`, observed 2026-09-30 in an exploratory probe), where
/// the generic form always prints nine digits.
#[must_use]
pub fn firestore_time(t: LogicalInstant) -> String {
    shorten_fraction(&rfc3339(t))
}

/// A deterministic stream of well-mixed 64-bit values derived from `seed` (FNV-1a over the seed
/// bytes, then a splitmix64 step per value). Not cryptographic: the ids built from it only have
/// to look like, and behave as, opaque unique identifiers.
fn seeded_stream(seed: &str) -> impl FnMut() -> u64 {
    let mut state = seed.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    });
    state ^= (seed.len() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    move || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// The first seventeen-digit decimal number and the count of them: a Storage event id lies in
/// `FIRST..FIRST + ID_SPAN`.
const ID_FIRST: u64 = 10_000_000_000_000_000;
const ID_SPAN: u64 = 90_000_000_000_000_000;
/// The step between the ids of consecutive events of one session. `ID_SPAN` is `2^16 * 3^2 *
/// 5^16`, so any odd step that is neither a multiple of 3 nor of 5 is coprime to it and the
/// ids of `ID_SPAN` consecutive events are all different.
const ID_STEP: u64 = 61_803_398_874_989_483;

/// A Storage event id as production prints it: a decimal string of seventeen digits (observed
/// 2026-10-01 for a 1st gen `context.eventId` and a 2nd gen `CloudEvent` `id` of one object create;
/// the two are unrelated numbers). Other lengths were not recorded.
///
/// The runtime passes `<session>-<n>` as the seed, with `n` counting the events of the session.
/// For that form the id is `ID_FIRST + (offset(session) + n * ID_STEP) mod ID_SPAN`: a fixed
/// function of the seed, so a recorded run replays with the same ids, and, because the step is
/// coprime to the span, the ids of two different events of one session never collide (for fewer
/// than `ID_SPAN` events). The ids of different sessions can collide, as the sessions' offsets
/// are hashes. Any other seed is hashed and may collide.
#[must_use]
pub fn storage_event_id(seed: &str) -> String {
    let counted = seed
        .rsplit_once('-')
        .and_then(|(session, n)| Some((session, n.parse::<u64>().ok()?)));
    let offset_and_count = |session: &str, n: u64| {
        // The whole 64-bit hash is the offset: only the position modulo the span matters.
        let offset = u128::from(seeded_stream(session)());
        (offset + u128::from(n) * u128::from(ID_STEP)) % u128::from(ID_SPAN)
    };
    let position = match counted {
        Some((session, n)) => offset_and_count(session, n),
        None => u128::from(seeded_stream(seed)() % ID_SPAN),
    };
    (u128::from(ID_FIRST) + position).to_string()
}

/// A UUID-shaped (version 4, variant 1) event id derived from `seed`. Production's Firestore
/// events carry random UUIDs; the local ones must stay replayable, so the id is a fixed function
/// of the session and the event counter that the runtime passes as the seed. The mixing is not
/// cryptographic: the id only has to look like, and behave as, an opaque unique identifier.
#[must_use]
pub fn event_id_uuid(seed: &str) -> String {
    let mut next = seeded_stream(seed);
    let mut bytes = [next().to_be_bytes(), next().to_be_bytes()].concat();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .fold(String::with_capacity(32), |mut acc, byte| {
            let _ = write!(acc, "{byte:02x}");
            acc
        });
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The kind of change between `before` and `after`.
#[must_use]
pub fn change_kind(before: Option<&Document>, after: Option<&Document>) -> Option<DocumentEvent> {
    match (before, after) {
        (None, Some(_)) => Some(DocumentEvent::Created),
        (Some(_), Some(_)) => Some(DocumentEvent::Updated),
        (Some(_), None) => Some(DocumentEvent::Deleted),
        (None, None) => None,
    }
}

/// Top-level field paths whose values differ.
fn update_mask(before: &Document, after: &Document) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    for (k, v) in &after.fields {
        if before.fields.get(k) != Some(v) {
            paths.push(k.clone());
        }
    }
    for k in before.fields.keys() {
        if !after.fields.contains_key(k) {
            paths.push(k.clone());
        }
    }
    paths.sort();
    paths
}

/// How the principal behind a Firestore write is named in the `authtype` and `authid` of a 2nd gen
/// event with auth context, by profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthContextNaming {
    /// Production's naming (the strict profile), recorded in FE v5 and v7: a write with a Firebase
    /// ID token is `api_key` with the user's uid; a write with the recorder's user credential (an
    /// operator's OAuth login, which the owner principal stands for here) is `unknown` with the
    /// credential's own id. What was recorded is narrower than what this maps: the ID-token
    /// writes were email-and-password users (anonymous, custom-token and other provider tokens
    /// were not recorded, and also map to `api_key`), and a write by a real service account, which
    /// production documents as `service_account` with the account's email, was not recorded at all
    /// (UNRECORDED; the owner principal still maps to the one recorded `unknown`).
    #[default]
    Production,
    /// The official emulator's (the emulator profile): its Firestore emulator
    /// (`cloud-firestore-emulator-v1.22.0.jar`, `FunctionsEmulatorEventPublisher`) sends the
    /// constants `unknown` and `fake-auth-id@gmail.com` whoever wrote.
    Official,
}

/// The `authid` the official emulator sends for every writer.
pub const OFFICIAL_AUTH_ID: &str = "fake-auth-id@gmail.com";

/// The `(authtype, authid)` an event names for the actor `(auth_type, auth_id)` of a commit.
/// Under [`AuthContextNaming::Production`] an `app_user` is `api_key` and a `service_account` is
/// `unknown`, each keeping its id; the principals production was not recorded with (`unauthenticated`
/// and `system`) are named as they are.
#[must_use]
pub fn auth_context_for<'a>(
    naming: AuthContextNaming,
    auth_type: &'a str,
    auth_id: Option<&'a str>,
) -> (&'a str, Option<&'a str>) {
    match naming {
        AuthContextNaming::Official => ("unknown", Some(OFFICIAL_AUTH_ID)),
        AuthContextNaming::Production => match auth_type {
            "app_user" => ("api_key", auth_id),
            "service_account" => ("unknown", auth_id),
            other => (other, auth_id),
        },
    }
}

/// A Firestore document event (`type` follows `kind`; `Written` triggers receive the
/// concrete kind's data with the written type). `id` seeds the event's UUID-shaped `id`
/// ([`event_id_uuid`]) and `time` prints in [`firestore_time`]'s form.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn firestore_event(
    id: &str,
    project: &str,
    database: &str,
    location: &str,
    document_path: &str,
    kind: DocumentEvent,
    before: Option<&Document>,
    after: Option<&Document>,
    time: LogicalInstant,
    auth: Option<(&str, Option<&str>)>,
) -> Value {
    let mut attrs = firestore_attributes(project, database, document_path, kind, location);
    if let Some((auth_type, auth_id)) = auth {
        with_auth_context(&mut attrs, auth_type, auth_id);
    }
    let mut data = Map::new();
    if let Some(a) = after {
        data.insert("value".into(), document_to_json(&encode_document(a)));
    }
    if let Some(b) = before {
        data.insert("oldValue".into(), document_to_json(&encode_document(b)));
    }
    if let (Some(b), Some(a)) = (before, after) {
        data.insert(
            "updateMask".into(),
            json!({"fieldPaths": update_mask(b, a)}),
        );
    }
    let mut event = json!({
        "specversion": "1.0",
        "id": event_id_uuid(id),
        "source": attrs.source,
        "subject": attrs.subject,
        "type": attrs.event_type,
        "time": firestore_time(time),
        "datacontenttype": "application/json",
        "data": Value::Object(data),
    });
    for (k, v) in attrs.extensions {
        event[k] = Value::String(v);
    }
    event
}

/// Object resource JSON (`StorageObjectData`), as the JSON API reports it.
#[must_use]
pub fn object_json(m: &ObjectMetadata) -> Value {
    let mut v = json!({
        "kind": "storage#object",
        "id": format!("{}/{}/{}", m.bucket.as_str(), m.name.as_str(), m.generation),
        "selfLink": format!("https://www.googleapis.com/storage/v1/b/{}/o/{}", m.bucket.as_str(), percent_encode(m.name.as_str())),
        "mediaLink": format!("https://storage.googleapis.com/download/storage/v1/b/{}/o/{}?generation={}&alt=media", m.bucket.as_str(), percent_encode(m.name.as_str()), m.generation),
        "name": m.name.as_str(),
        "bucket": m.bucket.as_str(),
        "generation": m.generation.to_string(),
        "metageneration": m.metageneration.to_string(),
        "contentType": m.content_type,
        "storageClass": "STANDARD",
        "size": m.size.to_string(),
        "md5Hash": m.md5_base64(),
        "crc32c": m.crc32c_base64(),
        "etag": production_etag(m.generation, m.metageneration),
        "timeCreated": object_time(m.time_created),
        "updated": object_time(m.updated),
        "timeStorageClassUpdated": object_time(m.time_created),
    });
    // Download tokens ride inside `metadata.firebaseStorageDownloadTokens`, and the member
    // is dropped when there is nothing to carry, exactly as the object resource is served.
    let mut metadata = m.custom.clone();
    if !m.download_tokens.is_empty() {
        metadata.insert(
            "firebaseStorageDownloadTokens".to_owned(),
            m.download_tokens.join(","),
        );
    }
    if !metadata.is_empty() {
        v["metadata"] = json!(metadata);
    }
    for (k, val) in [
        ("cacheControl", &m.cache_control),
        ("contentDisposition", &m.content_disposition),
        ("contentEncoding", &m.content_encoding),
        ("contentLanguage", &m.content_language),
    ] {
        if let Some(x) = val {
            v[k] = Value::String(x.clone());
        }
    }
    v
}

fn percent_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// What a core Storage event turns into: the trigger kind, the object, the `timeDeleted` its
/// resource carries and the instant of its `CloudEvent` when that is not the instant it is
/// admitted at.
#[derive(Debug, Clone, Copy)]
pub struct StorageEventParts<'a> {
    /// The trigger kind.
    pub kind: ObjectEvent,
    /// The object as it was.
    pub object: &'a ObjectMetadata,
    /// `data.timeDeleted`, when the event carries one.
    pub time_deleted: Option<LogicalInstant>,
    /// The event's own instant; `None` means the admission instant.
    pub at: Option<LogicalInstant>,
}

/// Splits a core Storage event into what [`storage_event`] needs.
#[must_use]
pub fn storage_event_parts(event: &StorageEvent) -> StorageEventParts<'_> {
    let (kind, object, time_deleted, at) = match event {
        StorageEvent::Finalized(m) => (ObjectEvent::Finalized, m, None, None),
        StorageEvent::Deleted {
            object,
            time_deleted,
            at,
        } => (ObjectEvent::Deleted, object, *time_deleted, *at),
        StorageEvent::MetadataUpdated(m) => (ObjectEvent::MetadataUpdated, m, None, None),
        StorageEvent::Archived {
            object,
            time_deleted,
        } => (ObjectEvent::Archived, object, Some(*time_deleted), None),
    };
    StorageEventParts {
        kind,
        object,
        time_deleted,
        at,
    }
}

/// A Storage object event. `id` seeds the event's seventeen-digit decimal `id`
/// ([`storage_event_id`]); `time` is when the runtime admitted the event (a finalize event's
/// own `time` is the object's creation instant, see `storage_time`).
#[must_use]
pub fn storage_event(
    id: &str,
    kind: ObjectEvent,
    object: &ObjectMetadata,
    time: LogicalInstant,
    time_deleted: Option<LogicalInstant>,
) -> Value {
    let attrs = storage_attributes(object.bucket.as_str(), object.name.as_str(), kind);
    let mut data = object_json(object);
    // RECORDED (FE v5, v1 and v2): the object resource of an Archived event carries `timeDeleted`,
    // the instant the generation stopped being live (three fractional digits), and so does the
    // Deleted event of a noncurrent generation deleted by number, whose own `time` is the
    // deletion instant, not that one. The Deleted event of an overwrite carries none.
    if let Some(at) = time_deleted {
        data["timeDeleted"] = Value::String(object_time(at));
    }
    let mut event = json!({
        "specversion": "1.0",
        "id": storage_event_id(id),
        "source": attrs.source,
        "subject": attrs.subject,
        "type": attrs.event_type,
        "time": storage_time(kind, object, time, time_deleted),
        "data": data,
    });
    for (k, v) in attrs.extensions {
        event[k] = Value::String(v);
    }
    event
}

/// A Pub/Sub message event (`MessagePublishedData` of `onMessagePublished`): `message` is
/// the published message (`data` base64, `attributes`, `orderingKey`).
///
/// The shape is the recorded production one (FUNCTIONS-EVENTS formal record, 2026-10-04, run
/// `a9621bfae74fe9bc`, frame `6ac2a47f0000967f445e8b09`): `id` is the message id, `time` and
/// `message.publishTime` are the publish instant with exactly three fractional digits (cut, not
/// rounded), and the event has no `datacontenttype` (the frame's `event.datacontenttype` is
/// null). The subscription is Eventarc's own one for the function, named as production names it
/// (see [`eventarc_subscription_id`]).
#[must_use]
pub fn pubsub_event(
    id: &str,
    project: &str,
    region: &str,
    function: &str,
    topic: &str,
    message: &Value,
    time: LogicalInstant,
) -> Value {
    pubsub_event_with_subscription(
        id,
        project,
        &eventarc_subscription_id(project, region, function),
        topic,
        message,
        time,
    )
}

/// [`pubsub_event`] with the subscription id the event names given: the provisioned
/// subscription of the function (see [`function_subscription_id`]).
#[must_use]
pub fn pubsub_event_with_subscription(
    id: &str,
    project: &str,
    subscription_id: &str,
    topic: &str,
    message: &Value,
    time: LogicalInstant,
) -> Value {
    let attrs = pubsub_attributes(project, topic);
    let published = object_time(time);
    let mut msg = json!({
        "messageId": id,
        "data": message.get("data").cloned().unwrap_or(Value::String(String::new())),
        "attributes": message.get("attributes").cloned().unwrap_or_else(|| json!({})),
        "publishTime": published,
    });
    if let Some(key) = message.get("orderingKey").and_then(Value::as_str) {
        msg["orderingKey"] = Value::String(key.to_owned());
    }
    json!({
        "specversion": "1.0",
        "id": id,
        "source": attrs.source,
        "type": attrs.event_type,
        "time": published,
        "data": {
            "message": msg,
            "subscription": format!("projects/{project}/subscriptions/{subscription_id}"),
        },
    })
}

/// How the subscription of a Pub/Sub function is named: by profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubscriptionNaming {
    /// Production's name for a 2nd gen Pub/Sub function, `eventarc-<region>-<function
    /// lowercased>-<6 digits>-sub-<3 digits>` (the strict profile). One subscription per function.
    #[default]
    Eventarc,
    /// The official emulator's `emulator-sub-<topic>` (the emulator profile), one per topic.
    EmulatorTopic,
}

/// The id of the subscription provisioned for `function` on `topic`, and named by the events of
/// that function. A 2nd gen Pub/Sub function takes Eventarc's name under
/// [`SubscriptionNaming::Eventarc`] (recorded for 2nd gen only: FE v5 and v7); every other
/// function (a scheduled one included), and every function under
/// [`SubscriptionNaming::EmulatorTopic`], takes
/// `emulator-sub-<topic>`. The numbers of the Eventarc name are derived from the project, the
/// region and the function, so a deployment keeps its name across runs.
#[must_use]
pub fn function_subscription_id(
    naming: SubscriptionNaming,
    project: &str,
    function: &FunctionSpec,
    topic: &str,
) -> String {
    match naming {
        SubscriptionNaming::Eventarc
            if function.generation == FunctionGeneration::Second
                && matches!(function.trigger, Trigger::PubSub { .. }) =>
        {
            eventarc_subscription_id(project, &function.region, &function.name)
        }
        _ => format!("emulator-sub-{topic}"),
    }
}

/// The id of the subscription Eventarc creates for a 2nd gen Pub/Sub function.
///
/// Production names it `eventarc-<region>-<function id, lowercased>-<6 digits>-sub-<3 digits>`
/// (14 samples of the FUNCTIONS-EVENTS formal record, run `a9621bfae74fe9bc` among them:
/// `eventarc-us-central1-pubsubpublishedv2-834054-sub-834`). The two numbers are drawn at random
/// per deployment and are independent of each other. The emulator derives both from a stable
/// hash of (project, region, function id), so a function keeps its name across runs and two
/// functions do not share one. A comparison with production must mask the two numbers and still
/// check the shape: 6 and 3 digits, the lowercased function id, the region.
#[must_use]
pub fn eventarc_subscription_id(project: &str, region: &str, function: &str) -> String {
    let (function_number, subscription_number) =
        subscription_numbers(stable_hash(&[project, region, function]));
    format!(
        "eventarc-{region}-{}-{function_number:06}-sub-{subscription_number:03}",
        function.to_lowercase()
    )
}

/// FNV-1a over the parts, each followed by a zero byte so that `("ab", "c")` and `("a", "bc")`
/// differ.
fn stable_hash(parts: &[&str]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for byte in part.bytes().chain(std::iter::once(0)) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    hash
}

/// The 6-digit and the 3-digit number of an Eventarc subscription id, from one hash.
fn subscription_numbers(hash: u64) -> (u64, u64) {
    (hash % 1_000_000, hash / 1_000_000 % 1_000)
}

/// An Auth wire timestamp as production prints it: RFC 3339 UTC cut to the whole second, with
/// no fraction (recorded in the `metadata` of the Auth v1 events of the FUNCTIONS-EVENTS formal
/// record `functions-events-formal-20261004T182904Z-a9621bfae74fe9bc`, 2026-10-04, e.g.
/// `metadata.creationTime` `2026-10-04T18:44:34Z` in frame 55, whose own `context.timestamp` is
/// `2026-10-04T18:44:34.537Z`). The record shows the whole-second form only; that the seconds
/// are cut and not rounded is a choice (as the store's `whole_second`), because the creation
/// instant behind a recorded time is not recorded.
fn whole_second_time(t: LogicalInstant) -> String {
    let nanos = t.as_nanos();
    rfc3339(LogicalInstant::from_nanos(
        nanos - nanos.rem_euclid(1_000_000_000),
    ))
}

/// One `providerData` entry of the Auth v1 wire: the members that are set. Production's entry of
/// a password account has `email`, `providerId` and `uid` only (record above, frame 55), so an
/// unset profile member is absent, not `null`. A federated entry is built the same way by
/// inference, not recording: it is the same Identity Toolkit `ProviderUserInfo` message as the
/// password entry, and no recorded account was federated (ledger 869).
fn provider_entry(
    uid: &str,
    provider_id: &str,
    email: Option<&str>,
    display_name: Option<&str>,
    photo_url: Option<&str>,
) -> Value {
    let mut entry = Map::new();
    entry.insert("uid".to_owned(), json!(uid));
    entry.insert("providerId".to_owned(), json!(provider_id));
    for (key, value) in [
        ("email", email),
        ("displayName", display_name),
        ("photoURL", photo_url),
    ] {
        if let Some(value) = value {
            entry.insert(key.to_owned(), json!(value));
        }
    }
    Value::Object(entry)
}

/// The v1 `UserRecord` wire shape, as the recorded production events carry it (frames 55, 66,
/// 121-132, 192, 203 and 258-269 of the record named at `whole_second_time`):
///
/// - `metadata.creationTime` and `metadata.lastSignInTime` are cut to the whole second, and
///   `lastSignInTime` is absent while the account never signed in (an account an admin created
///   has none; one signed up through `accounts:signUp` has it equal to the creation, and a later
///   sign-in shows in the delete event);
/// - `tokensValidAfterTime` is `null` for every recorded account, none of which had its tokens
///   revoked. A revoked account keeps printing the revocation second (unrecorded);
/// - a `providerData` entry carries the members that are set and no `null` placeholders.
#[must_use]
pub fn user_record_json(u: &UserRecord) -> Value {
    let mut providers: Vec<Value> = Vec::new();
    if let Some(email) = &u.email {
        providers.push(provider_entry(
            email,
            "password",
            Some(email),
            u.display_name.as_deref(),
            u.photo_url.as_deref(),
        ));
    }
    if let Some(phone) = &u.phone_number {
        providers.push(json!({"uid": phone, "providerId": "phone", "phoneNumber": phone}));
    }
    for f in &u.federated {
        providers.push(provider_entry(
            &f.raw_id,
            &f.provider_id,
            f.email.as_deref(),
            f.display_name.as_deref(),
            f.photo_url.as_deref(),
        ));
    }
    let claims: Value =
        serde_json::from_str(&u.custom_claims.canonical_json()).unwrap_or(json!({}));
    let mut metadata = Map::new();
    metadata.insert(
        "creationTime".to_owned(),
        json!(whole_second_time(u.created_at)),
    );
    if let Some(signed_in) = u.last_sign_in_at {
        metadata.insert(
            "lastSignInTime".to_owned(),
            json!(whole_second_time(signed_in)),
        );
    }
    json!({
        "uid": u.local_id.as_str(),
        "email": u.email,
        "emailVerified": u.email_verified,
        "displayName": u.display_name,
        "photoURL": u.photo_url,
        "phoneNumber": u.phone_number,
        "disabled": u.disabled,
        "metadata": metadata,
        "providerData": providers,
        "customClaims": claims,
        "tokensValidAfterTime": u.tokens_revoked.then(|| rfc3339(u.tokens_valid_after)),
    })
}

/// An Auth user event (`data` is the v1 `UserRecord`). The runner hands `id` and `time` to the
/// 1st gen handler as `context.eventId` and `context.timestamp`; production prints the first as
/// a UUID and the second with exactly three fractional digits (frames 55 and 66 of the record
/// named at `whole_second_time`: `bfcfc370-9507-435b-9ad0-9143ff05c8db`,
/// `2026-10-04T18:44:34.537Z`).
#[must_use]
pub fn auth_event(
    id: &str,
    project: &str,
    kind: AuthEvent,
    user: &UserRecord,
    time: LogicalInstant,
) -> Value {
    let attrs = auth_attributes(project, kind);
    json!({
        "specversion": "1.0",
        "id": event_id_uuid(id),
        "source": attrs.source,
        "type": attrs.event_type,
        "time": object_time(time),
        "datacontenttype": "application/json",
        "data": user_record_json(user),
    })
}

/// A scheduled run (`ScheduledEvent` of `onSchedule`).
#[must_use]
pub fn schedule_event(
    id: &str,
    project: &str,
    region: &str,
    function: &str,
    time: LogicalInstant,
) -> Value {
    let attrs = schedule_attributes(project, region, function);
    json!({
        "specversion": "1.0",
        "id": id,
        "source": attrs.source,
        "type": attrs.event_type,
        "time": rfc3339(time),
        "datacontenttype": "application/json",
        "data": {
            "jobName": format!("projects/{project}/locations/{region}/jobs/firebase-schedule-{function}-{region}"),
            "scheduleTime": rfc3339(time),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::{
        event_id_uuid, eventarc_subscription_id, firestore_time, object_json, pubsub_event,
        stable_hash, storage_event, storage_event_id, storage_time, subscription_numbers,
    };
    use fireemu_core_functions::manifest::ObjectEvent;
    use fireemu_core_storage::name::{BucketName, ObjectName};
    use fireemu_core_storage::store::{NewMetadata, ObjectMetadata, Precondition, StorageState};
    use fireemu_core_types::time::LogicalInstant;

    fn at(seconds: i64, nanos: i128) -> LogicalInstant {
        LogicalInstant::from_nanos(i128::from(seconds) * 1_000_000_000 + nanos)
    }

    /// 2026-09-30T12:03:18Z, the whole second of the recorded production event.
    const RECORDED_SECOND: i64 = 1_790_769_798;

    #[test]
    fn firestore_time_prints_the_protobuf_json_fraction_of_zero_three_six_or_nine_digits() {
        // Production's Firestore events carry `2026-09-30T12:03:18.846431Z` (six digits).
        for (nanos, expected) in [
            (846_431_000, "2026-09-30T12:03:18.846431Z"),
            (846_000_000, "2026-09-30T12:03:18.846Z"),
            (840_000_000, "2026-09-30T12:03:18.840Z"),
            (846_430_000, "2026-09-30T12:03:18.846430Z"),
            (846_431_500, "2026-09-30T12:03:18.846431500Z"),
            (846_431_001, "2026-09-30T12:03:18.846431001Z"),
            (1, "2026-09-30T12:03:18.000000001Z"),
            (0, "2026-09-30T12:03:18Z"),
        ] {
            assert_eq!(firestore_time(at(RECORDED_SECOND, nanos)), expected);
        }
    }

    #[test]
    fn firestore_time_round_trips_through_the_parser() {
        for nanos in [
            0,
            1,
            999,
            1_000,
            999_999,
            1_000_000,
            846_431_000,
            999_999_999,
        ] {
            let instant = at(RECORDED_SECOND, nanos);
            assert_eq!(
                LogicalInstant::parse_rfc3339(&firestore_time(instant)),
                Ok(instant)
            );
        }
    }

    #[test]
    fn firestore_time_keeps_the_fallback_for_an_instant_rfc3339_cannot_print() {
        assert_eq!(firestore_time(LogicalInstant::MAX), "1970-01-01T00:00:00Z");
    }

    fn is_uuid(text: &str) -> bool {
        let parts: Vec<&str> = text.split('-').collect();
        parts.iter().map(|part| part.len()).collect::<Vec<_>>() == [8, 4, 4, 4, 12]
            && text
                .chars()
                .all(|c| c == '-' || c.is_ascii_digit() || ('a'..='f').contains(&c))
    }

    #[test]
    fn event_id_uuid_is_a_lowercase_version_4_variant_1_uuid() {
        for seed in [
            "42-1",
            "42-3",
            "s-0",
            "",
            "a-very-long-session-identifier-12345",
        ] {
            let id = event_id_uuid(seed);
            assert!(is_uuid(&id), "{id}");
            assert_eq!(id.as_bytes()[14], b'4', "version nibble of {id}");
            assert!(
                matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
                "variant of {id}"
            );
        }
    }

    #[test]
    fn event_id_uuid_is_deterministic_and_separates_neighbouring_seeds() {
        assert_eq!(event_id_uuid("42-1"), event_id_uuid("42-1"));
        let ids: Vec<String> = (1..=200)
            .map(|n| event_id_uuid(&format!("42-{n}")))
            .collect();
        let distinct: std::collections::BTreeSet<&String> = ids.iter().collect();
        assert_eq!(distinct.len(), ids.len());
        assert_ne!(event_id_uuid("42-1"), event_id_uuid("43-1"));
        assert_ne!(event_id_uuid("a-b"), event_id_uuid("ab-"));
    }

    #[test]
    fn event_id_uuid_is_a_stable_function_of_the_seed() {
        // Golden values, cross-checked against an independent implementation: a recorded
        // local run must replay with the same ids in every build.
        for (seed, expected) in [
            ("42-1", "376b42c8-d39c-4467-aa8a-5b31f92075f2"),
            ("42-2", "637a85d9-e582-43b9-a01a-b56a34eb0571"),
            ("", "c3817c01-6ba4-4f30-900c-daacc0bc9316"),
            ("a", "e6b85e32-22fb-405f-aa73-35c5fb75358f"),
        ] {
            assert_eq!(event_id_uuid(seed), expected, "seed {seed:?}");
        }
    }

    #[test]
    fn event_id_uuid_spreads_its_bits() {
        // Neighbouring counters must not share a long prefix, or the ids look sequential.
        let (a, b) = (event_id_uuid("7-1"), event_id_uuid("7-2"));
        let shared = a.chars().zip(b.chars()).take_while(|(x, y)| x == y).count();
        assert!(shared < 6, "{a} {b}");
    }
    #[test]
    fn storage_event_id_is_a_seventeen_digit_decimal_string() {
        for n in 1..=500 {
            let id = storage_event_id(&format!("42-{n}"));
            assert_eq!(id.len(), 17, "{id}");
            assert!(id.bytes().all(|b| b.is_ascii_digit()), "{id}");
            assert!(!id.starts_with('0'), "{id}");
        }
    }

    #[test]
    fn storage_event_id_is_deterministic_and_separates_neighbouring_seeds() {
        assert_eq!(storage_event_id("42-1"), storage_event_id("42-1"));
        let ids: Vec<String> = (1..=500)
            .map(|n| storage_event_id(&format!("42-{n}")))
            .collect();
        let distinct: std::collections::BTreeSet<&String> = ids.iter().collect();
        assert_eq!(distinct.len(), ids.len());
        assert_ne!(storage_event_id("42-1"), storage_event_id("43-1"));
        assert_ne!(storage_event_id("a-b"), storage_event_id("ab-"));
    }

    #[test]
    fn storage_event_id_is_a_stable_function_of_the_seed() {
        // Golden values: a recorded local run must replay with the same ids in every build.
        // Cross-checked against an independent implementation of the same stream.
        for (seed, expected) in [
            ("42-1", "72615684452749472"),
            ("42-2", "44419083327738955"),
            ("42-3", "16222482202728438"),
            ("7-1", "11411248863046627"),
            ("abc-0", "15885848759147634"),
            ("", "57677454934409008"),
            ("a", "75141593866473567"),
            ("a-b", "64542345540733686"),
        ] {
            assert_eq!(storage_event_id(seed), expected, "seed {seed:?}");
        }
    }

    fn gcd(a: u64, b: u64) -> u64 {
        if b == 0 {
            a
        } else {
            gcd(b, a % b)
        }
    }

    #[test]
    fn the_id_step_is_coprime_to_the_span_so_one_sessions_ids_cannot_collide() {
        // `n * ID_STEP mod ID_SPAN` is a bijection on `0..ID_SPAN` exactly when the step and the
        // span share no factor; the span is `2^16 * 3^2 * 5^16`.
        assert_eq!(gcd(super::ID_STEP, super::ID_SPAN), 1);
        assert_eq!(super::ID_SPAN, (1_u64 << 16) * 9 * 5_u64.pow(16));
        const { assert!(super::ID_STEP < super::ID_SPAN) };
    }

    #[test]
    fn consecutive_events_of_a_session_get_ids_a_whole_step_apart() {
        let id = |n: u64| storage_event_id(&format!("42-{n}")).parse::<u64>().unwrap();
        for n in [0_u64, 1, 2, 1_000, 89_999_999_999_999_998] {
            let (a, b) = (id(n) - super::ID_FIRST, id(n + 1) - super::ID_FIRST);
            let step = (u128::from(b) + u128::from(super::ID_SPAN) - u128::from(a))
                % u128::from(super::ID_SPAN);
            assert_eq!(step, u128::from(super::ID_STEP), "n {n}");
        }
    }

    #[test]
    fn a_seed_without_a_counter_is_hashed_and_still_has_seventeen_digits() {
        for seed in ["", "a", "a-b", "-", "42-", "42-18446744073709551616"] {
            let id = storage_event_id(seed);
            assert_eq!(id.len(), 17, "{seed:?} {id}");
        }
    }

    fn object_created_at(nanos: i128) -> ObjectMetadata {
        StorageState::new(1)
            .put(
                &BucketName::try_new("demo-app.appspot.com").unwrap(),
                &ObjectName::try_new("a.txt").unwrap(),
                b"abc".to_vec(),
                NewMetadata::default(),
                Precondition::default(),
                LogicalInstant::from_nanos(nanos),
            )
            .unwrap()
    }

    const SECOND: i128 = 1_790_844_566 * 1_000_000_000;

    /// A Storage `CloudEvent` carries no `datacontenttype`, in either profile (FE v5 production run
    /// functions-events-formal-20261004T182904Z-a9621bfae74fe9bc, frames 6ac29fb7000987a59af4b7f6,
    /// 6ac29fd70001a0e4d85cfd12 and 6ac2a0a80000b3d27b4b1db3: the recorded `eventKeys` lack it and
    /// the printed member is null). The Firestore SDK path needs one, so the other events keep it.
    #[test]
    fn a_storage_event_carries_no_datacontenttype_whatever_its_kind() {
        let object = object_created_at(SECOND);
        for kind in [
            ObjectEvent::Finalized,
            ObjectEvent::Deleted,
            ObjectEvent::MetadataUpdated,
            ObjectEvent::Archived,
        ] {
            let event = storage_event(
                "42-1",
                kind,
                &object,
                LogicalInstant::from_nanos(SECOND),
                None,
            );
            assert!(event.get("datacontenttype").is_none(), "{kind:?}: {event}");
            // The other members the recording lists are all there.
            for key in [
                "specversion",
                "id",
                "source",
                "subject",
                "type",
                "time",
                "data",
                "bucket",
            ] {
                assert!(event.get(key).is_some(), "{kind:?} {key}");
            }
        }
    }

    /// The object resource's `etag` is production's protobuf form, not `"<generation>-<n>"`
    /// (FE v5 frame 6ac29fb70006ad918ea2a73d: generation 1791139765427541 at metageneration 1 is
    /// `CNW62MuDoZcDEAE=`, sixteen characters in both the 1st and the 2nd gen frames).
    #[test]
    fn the_object_resource_etag_is_the_production_protobuf_of_its_generation() {
        let mut object = object_created_at(SECOND);
        object.generation = 1_791_139_765_427_541;
        object.metageneration = 1;
        assert_eq!(object_json(&object)["etag"], "CNW62MuDoZcDEAE=");
        object.metageneration = 2;
        assert_eq!(
            object_json(&object)["etag"],
            fireemu_core_storage::etag::production_etag(1_791_139_765_427_541, 2)
        );
        assert_eq!(object_json(&object)["etag"].as_str().unwrap().len(), 16);
    }

    #[test]
    fn storage_times_cut_at_the_boundaries_of_the_calendar_and_the_epoch() {
        // (instant in nanoseconds since the epoch, finalize CloudEvent time, object resource time)
        let second = 1_000_000_000_i128;
        let cases: [(i128, &str, &str); 9] = [
            // Before the epoch the cut still discards the low digits and never rounds up.
            (
                -1,
                "1969-12-31T23:59:59.999999Z",
                "1969-12-31T23:59:59.999Z",
            ),
            (
                -1_000,
                "1969-12-31T23:59:59.999999Z",
                "1969-12-31T23:59:59.999Z",
            ),
            (
                -1_001,
                "1969-12-31T23:59:59.999998Z",
                "1969-12-31T23:59:59.999Z",
            ),
            // The microsecond and the millisecond edges.
            (999, "1970-01-01T00:00:00Z", "1970-01-01T00:00:00.000Z"),
            (
                1_000,
                "1970-01-01T00:00:00.000001Z",
                "1970-01-01T00:00:00.000Z",
            ),
            (
                1_000_000,
                "1970-01-01T00:00:00.001Z",
                "1970-01-01T00:00:00.001Z",
            ),
            // A leap day and a second rollover.
            (
                1_709_251_199 * second + 999_999_999,
                "2024-02-29T23:59:59.999999Z",
                "2024-02-29T23:59:59.999Z",
            ),
            (
                1_709_251_200 * second,
                "2024-03-01T00:00:00Z",
                "2024-03-01T00:00:00.000Z",
            ),
            (
                1_709_251_200 * second + 1,
                "2024-03-01T00:00:00Z",
                "2024-03-01T00:00:00.000Z",
            ),
        ];
        for (nanos, finalize_time, resource_time) in cases {
            let object = object_created_at(nanos);
            assert_eq!(
                storage_time(
                    ObjectEvent::Finalized,
                    &object,
                    LogicalInstant::from_nanos(0),
                    None
                ),
                finalize_time,
                "finalize time at {nanos}"
            );
            let json = object_json(&object);
            for key in ["timeCreated", "updated", "timeStorageClassUpdated"] {
                assert_eq!(json[key], resource_time, "{key} at {nanos}");
            }
        }
    }

    #[test]
    fn an_instant_the_clock_cannot_print_takes_the_fallback_and_never_panics() {
        // `LogicalInstant::MIN` is the case an unchecked subtraction underflows on.
        let object = object_created_at(SECOND);
        for admitted in [LogicalInstant::MIN, LogicalInstant::MAX] {
            for kind in [ObjectEvent::Deleted, ObjectEvent::MetadataUpdated] {
                assert_eq!(
                    storage_time(kind, &object, admitted, None),
                    "1970-01-01T00:00:00Z"
                );
            }
        }
    }

    #[test]
    fn object_resource_times_have_exactly_three_fraction_digits_cut_not_rounded() {
        // Production: `timeCreated` is `2026-10-01T08:49:26.486Z` for a creation at
        // `...26.486927Z`.
        for (nanos, expected) in [
            (486_927_999, "2026-10-01T08:49:26.486Z"),
            (486_000_000, "2026-10-01T08:49:26.486Z"),
            (999_999_999, "2026-10-01T08:49:26.999Z"),
            (5_000_000, "2026-10-01T08:49:26.005Z"),
            (0, "2026-10-01T08:49:26.000Z"),
        ] {
            let json = object_json(&object_created_at(SECOND + nanos));
            for key in ["timeCreated", "updated", "timeStorageClassUpdated"] {
                assert_eq!(json[key], expected, "{key} at {nanos}");
            }
        }
    }

    #[test]
    fn a_finalize_event_time_is_the_creation_instant_to_the_microsecond() {
        let admitted = LogicalInstant::from_nanos(SECOND + 577_000_000);
        for (nanos, expected) in [
            (486_927_000, "2026-10-01T08:49:26.486927Z"),
            // The sub-microsecond digits are not known to the service and are cut.
            (486_927_999, "2026-10-01T08:49:26.486927Z"),
            (486_000_000, "2026-10-01T08:49:26.486Z"),
            (0, "2026-10-01T08:49:26Z"),
        ] {
            let object = object_created_at(SECOND + nanos);
            assert_eq!(
                storage_time(ObjectEvent::Finalized, &object, admitted, None),
                expected,
                "{nanos}"
            );
        }
    }

    #[test]
    fn the_other_storage_kinds_keep_the_admission_instant_in_the_same_form() {
        let object = object_created_at(SECOND + 486_927_000);
        let admitted = LogicalInstant::from_nanos(SECOND + 577_123_456);
        for kind in [ObjectEvent::Deleted, ObjectEvent::MetadataUpdated] {
            assert_eq!(
                storage_time(kind, &object, admitted, None),
                "2026-10-01T08:49:26.577123Z"
            );
        }
    }
    mod properties {
        use super::{object_created_at, SECOND};
        use crate::events::{
            eventarc_subscription_id, firestore_time, object_json, storage_event_id, storage_time,
        };
        use fireemu_core_functions::manifest::ObjectEvent;
        use fireemu_core_types::time::LogicalInstant;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn a_storage_event_id_is_always_seventeen_digits(seed in ".*") {
                let id = storage_event_id(&seed);
                prop_assert_eq!(id.len(), 17);
                prop_assert!(id.bytes().all(|b| b.is_ascii_digit()));
                prop_assert!(!id.starts_with('0'));
                prop_assert_eq!(storage_event_id(&seed), id);
            }

            #[test]
            fn an_eventarc_subscription_id_always_has_the_production_shape(
                project in "[a-z][a-z0-9-]{4,20}",
                region in "[a-z]{2,10}-[a-z]{2,10}[0-9]",
                function in "[a-zA-Z][a-zA-Z0-9]{0,30}",
            ) {
                let id = eventarc_subscription_id(&project, &region, &function);
                prop_assert_eq!(&id, &eventarc_subscription_id(&project, &region, &function));
                let rest = id.strip_prefix(&format!("eventarc-{region}-{}-", function.to_lowercase()));
                prop_assert!(rest.is_some(), "{}", id);
                let rest = rest.unwrap();
                let (first, second) = rest.split_once("-sub-").unwrap();
                prop_assert!(first.len() == 6 && first.bytes().all(|b| b.is_ascii_digit()));
                prop_assert!(second.len() == 3 && second.bytes().all(|b| b.is_ascii_digit()));
            }

            #[test]
            fn two_events_of_one_session_never_share_an_id(session in 0_u64..1_000_000, n in 0_u64..90_000_000_000_000_000, m in 0_u64..90_000_000_000_000_000) {
                prop_assume!(n != m);
                prop_assert_ne!(
                    storage_event_id(&format!("{session}-{n}")),
                    storage_event_id(&format!("{session}-{m}"))
                );
            }

            #[test]
            fn the_object_resource_etag_is_always_the_production_etag_of_the_generations(generation in any::<u64>(), metageneration in any::<u64>()) {
                let mut object = object_created_at(SECOND);
                object.generation = generation;
                object.metageneration = metageneration;
                let json = object_json(&object);
                prop_assert_eq!(
                    json["etag"].as_str().unwrap(),
                    fireemu_core_storage::etag::production_etag(generation, metageneration)
                );
            }

            #[test]
            fn object_resource_times_always_have_three_digits_and_are_cut_not_rounded(nanos in -4_000_000_000_000_000_000_i128..4_000_000_000_000_000_000) {
                let created = SECOND + nanos;
                let json = object_json(&object_created_at(created));
                for key in ["timeCreated", "updated", "timeStorageClassUpdated"] {
                    let text = json[key].as_str().unwrap();
                    let fraction = text.strip_suffix('Z').unwrap().rsplit('.').next().unwrap();
                    prop_assert_eq!(fraction.len(), 3, "{}", text);
                    let parsed = LogicalInstant::parse_rfc3339(text).unwrap().as_nanos();
                    prop_assert!(parsed <= created && created - parsed < 1_000_000, "{} for {}", text, created);
                }
            }

            #[test]
            fn a_finalize_time_is_the_creation_instant_cut_to_the_microsecond(nanos in -4_000_000_000_000_000_000_i128..4_000_000_000_000_000_000, admitted in -4_000_000_000_000_000_000_i128..4_000_000_000_000_000_000) {
                let created = SECOND + nanos;
                let object = object_created_at(created);
                let time = storage_time(ObjectEvent::Finalized, &object, LogicalInstant::from_nanos(SECOND + admitted), None);
                let parsed = LogicalInstant::parse_rfc3339(&time).unwrap().as_nanos();
                prop_assert_eq!(parsed, created - created.rem_euclid(1_000));
                prop_assert_eq!(&time, &firestore_time(LogicalInstant::from_nanos(parsed)));
            }

            #[test]
            fn the_other_kinds_use_the_admission_instant_to_the_microsecond(nanos in -4_000_000_000_000_000_000_i128..4_000_000_000_000_000_000, admitted in -4_000_000_000_000_000_000_i128..4_000_000_000_000_000_000) {
                let object = object_created_at(SECOND + nanos);
                let at = SECOND + admitted;
                for kind in [ObjectEvent::Deleted, ObjectEvent::MetadataUpdated] {
                    let time = storage_time(kind, &object, LogicalInstant::from_nanos(at), None);
                    let parsed = LogicalInstant::parse_rfc3339(&time).unwrap().as_nanos();
                    prop_assert_eq!(parsed, at - at.rem_euclid(1_000));
                }
            }
        }
    }

    /// The Pub/Sub event of the FUNCTIONS-EVENTS formal record of 2026-10-04 (run
    /// `a9621bfae74fe9bc`): the 2nd gen frame `6ac2a47f0000967f445e8b09` and the 1st gen frame
    /// `6ac2a47e0006b2dd7f2584d4` of the same message. `time` and `publishTime` are the publish
    /// instant with exactly three fractional digits, `id` is the message id, and the event has no
    /// `datacontenttype` (the frame's `event.datacontenttype` is null).
    #[test]
    fn a_pubsub_event_has_the_shape_of_the_recorded_production_event() {
        let published = at(1_791_140_986, 102_437_891);
        let message = serde_json::json!({
            "data": "ZWNmNTBhODZhMTQzMzY0ZmQ1NGZjZTUxNm0yNg==",
            "attributes": {"probe": "ecf50a86a143364fd54fce516m26"},
        });
        let event = pubsub_event(
            "22254343790642112",
            "fireemu-oracle-events",
            "us-central1",
            "pubsubPublishedV2",
            "fe-events-primary",
            &message,
            published,
        );
        assert_eq!(event["id"], "22254343790642112");
        assert_eq!(event["time"], "2026-10-04T19:09:46.102Z");
        assert_eq!(
            event["data"]["message"]["publishTime"],
            "2026-10-04T19:09:46.102Z"
        );
        assert_eq!(event["data"]["message"]["messageId"], "22254343790642112");
        assert_eq!(event["specversion"], "1.0");
        assert_eq!(
            event["type"],
            "google.cloud.pubsub.topic.v1.messagePublished"
        );
        assert_eq!(
            event["source"],
            "//pubsub.googleapis.com/projects/fireemu-oracle-events/topics/fe-events-primary"
        );
        assert!(
            event.get("datacontenttype").is_none(),
            "production's event carries no datacontenttype: {event}"
        );
    }

    #[test]
    fn a_pubsub_event_time_is_cut_not_rounded_and_equals_the_publish_time() {
        for (nanos, expected) in [
            (102_999_999, "2026-10-04T19:09:46.102Z"),
            (102_000_000, "2026-10-04T19:09:46.102Z"),
            (999_999_999, "2026-10-04T19:09:46.999Z"),
            (5_000_000, "2026-10-04T19:09:46.005Z"),
            (0, "2026-10-04T19:09:46.000Z"),
        ] {
            let event = pubsub_event(
                "1",
                "p",
                "us-central1",
                "f",
                "t",
                &serde_json::json!({}),
                at(1_791_140_986, nanos),
            );
            assert_eq!(event["time"], expected, "time at {nanos}");
            assert_eq!(
                event["data"]["message"]["publishTime"], expected,
                "publishTime at {nanos}"
            );
        }
    }

    /// The shape of every production sample of the formal record (run `a9621bfae74fe9bc` and the
    /// other deployments of the same run): the two numbers are random per deployment, so a
    /// comparison masks their values and checks the rest. This is that check.
    fn masked_subscription_shape(id: &str) -> Option<String> {
        let rest = id.strip_prefix("eventarc-")?;
        let (head, sub) = rest.rsplit_once("-sub-")?;
        let (head, function_number) = head.rsplit_once('-')?;
        let digits = |text: &str, len: usize| {
            text.len() == len && text.bytes().all(|byte| byte.is_ascii_digit())
        };
        if !digits(function_number, 6) || !digits(sub, 3) {
            return None;
        }
        Some(format!("eventarc-{head}-<6 digits>-sub-<3 digits>"))
    }

    #[test]
    fn the_subscription_masks_to_the_shape_of_the_production_samples() {
        // Production samples (run a9621bfae74fe9bc and its deployments): masked, they all
        // have the shape the emulator's name has.
        for (sample, masked) in [
            (
                "eventarc-us-central1-pubsubpublishedv2-834054-sub-834",
                "eventarc-us-central1-pubsubpublishedv2-<6 digits>-sub-<3 digits>",
            ),
            (
                "eventarc-us-central1-fscreatedv2-302901-sub-783",
                "eventarc-us-central1-fscreatedv2-<6 digits>-sub-<3 digits>",
            ),
            (
                "eventarc-us-central1-storagearchivedv2-494903-sub-488",
                "eventarc-us-central1-storagearchivedv2-<6 digits>-sub-<3 digits>",
            ),
        ] {
            assert_eq!(masked_subscription_shape(sample).as_deref(), Some(masked));
        }
        assert_eq!(
            masked_subscription_shape(&eventarc_subscription_id(
                "fireemu-oracle-events",
                "us-central1",
                "pubsubPublishedV2"
            ))
            .as_deref(),
            Some("eventarc-us-central1-pubsubpublishedv2-<6 digits>-sub-<3 digits>")
        );
        // The mask does not hide a format: a wrong number of digits is not a name.
        for wrong in [
            "eventarc-us-central1-f-83405-sub-834",
            "eventarc-us-central1-f-8340545-sub-834",
            "eventarc-us-central1-f-834054-sub-83",
            "eventarc-us-central1-f-834054-sub-8341",
            "eventarc-us-central1-f-83405a-sub-834",
            "emulator-sub-jobs",
        ] {
            assert_eq!(masked_subscription_shape(wrong), None, "{wrong}");
        }
    }

    #[test]
    fn the_subscription_numbers_are_zero_padded_and_independent() {
        assert_eq!(subscription_numbers(0), (0, 0));
        assert_eq!(subscription_numbers(7), (7, 0));
        assert_eq!(subscription_numbers(1_000_005), (5, 1));
        assert_eq!(subscription_numbers(834_054_834_000_000), (0, 834));
        assert_eq!(subscription_numbers(u64::MAX), (551_615, 709));
    }

    #[test]
    fn the_subscription_id_is_stable_and_names_the_function_the_project_and_the_region() {
        let id = eventarc_subscription_id("demo-app", "us-central1", "onJob");
        assert_eq!(
            id,
            eventarc_subscription_id("demo-app", "us-central1", "onJob")
        );
        assert!(id.starts_with("eventarc-us-central1-onjob-"), "{id}");
        // Another function, region or project is another subscription.
        assert_ne!(
            id,
            eventarc_subscription_id("demo-app", "us-central1", "onJob2")
        );
        assert_ne!(
            id,
            eventarc_subscription_id("demo-app", "europe-west1", "onJob")
        );
        assert_ne!(
            id,
            eventarc_subscription_id("other-app", "us-central1", "onJob")
        );
        // The parts are separated: moving a character between them changes the hash.
        assert_ne!(stable_hash(&["ab", "c"]), stable_hash(&["a", "bc"]));
    }

    #[test]
    fn the_subscription_ids_are_pinned_so_that_a_deployment_keeps_its_name_across_releases() {
        // FNV-1a over the parts, each followed by a zero byte: these values are the algorithm.
        assert_eq!(
            stable_hash(&["demo-app", "us-central1", "onJob"]),
            7_612_220_917_531_147_373
        );
        assert_eq!(stable_hash(&["ab", "c"]), 12_475_682_555_102_643_973);
        assert_eq!(stable_hash(&["a", "bc"]), 4_618_443_601_942_399_609);
        assert_eq!(stable_hash(&[""]), 12_638_153_115_695_167_455);
        assert_eq!(
            eventarc_subscription_id("demo-app", "us-central1", "onJob"),
            "eventarc-us-central1-onjob-147373-sub-531"
        );
        assert_eq!(
            eventarc_subscription_id("fireemu-oracle-events", "us-central1", "pubsubPublishedV2"),
            "eventarc-us-central1-pubsubpublishedv2-147205-sub-779"
        );
    }

    #[test]
    fn a_pubsub_event_names_eventarcs_subscription_for_the_function() {
        let event = pubsub_event(
            "1",
            "demo-app",
            "europe-west1",
            "workerTwo",
            "shared-jobs",
            &serde_json::json!({}),
            at(0, 0),
        );
        assert_eq!(
            event["data"]["subscription"],
            format!(
                "projects/demo-app/subscriptions/{}",
                eventarc_subscription_id("demo-app", "europe-west1", "workerTwo")
            )
        );
    }
}

/// The Auth v1 event wire against the production frames of the FUNCTIONS-EVENTS formal record
/// `functions-events-formal-20261004T182904Z-a9621bfae74fe9bc` (`production-run.json`, `frames`
/// array, 0-based indexes quoted per test). The function receives this wire through the
/// firebase-functions v1 `userRecordConstructor`, so the tests replay the wire through a copy of
/// that constructor's `toJSON` and compare what the handler sees.
#[cfg(test)]
mod auth_event_shapes {
    use super::{auth_event, event_id_uuid, user_record_json};
    use fireemu_core_auth::mfa::TotpPolicy;
    use fireemu_core_auth::store::{AuthStore, NewUser, UserRecord};
    use fireemu_core_functions::manifest::AuthEvent;
    use fireemu_core_types::determinism::SplitMix64;
    use fireemu_core_types::time::LogicalInstant;
    use proptest::prelude::*;
    use serde_json::{json, Map, Value};

    /// 2026-10-04T18:44:34Z, the whole second of the creation in frame 55.
    const FRAME_55_SECOND: i64 = 1_791_139_474;

    fn at(seconds: i64, nanos: i128) -> LogicalInstant {
        LogicalInstant::from_nanos(i128::from(seconds) * 1_000_000_000 + nanos)
    }

    fn password_user(email: &str, created: LogicalInstant) -> UserRecord {
        let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
        let uid = store.create_user(NewUser::email(email), created).unwrap();
        let mut user = store.user(&uid).unwrap().clone();
        user.created_at = created;
        user
    }

    /// `userRecordConstructor(wire).toJSON()` of firebase-functions 7.3.2
    /// (`lib/common/providers/identity.js`, lines 56-104), which is the function that produced
    /// the recorded frames: the falsey defaults fill members the wire lacks, `metadata` is
    /// passed through member by member (an absent member is `undefined` and `JSON.stringify`
    /// drops it, a `null` stays), and each provider entry is copied as it is.
    fn sdk_user_json(wire: &Value) -> Value {
        let mut record = Map::new();
        for (key, default) in [
            ("email", Value::Null),
            ("emailVerified", json!(false)),
            ("displayName", Value::Null),
            ("photoURL", Value::Null),
            ("phoneNumber", Value::Null),
            ("disabled", json!(false)),
            ("providerData", json!([])),
            ("customClaims", json!({})),
            ("passwordSalt", Value::Null),
            ("passwordHash", Value::Null),
            ("tokensValidAfterTime", Value::Null),
        ] {
            record.insert(key.to_owned(), default);
        }
        for (key, value) in wire.as_object().unwrap() {
            record.insert(key.clone(), value.clone());
        }
        let meta = record.get("metadata").and_then(Value::as_object).cloned();
        let mut metadata = Map::new();
        if let Some(meta) = meta {
            if let Some(created) = meta
                .get("createdAt")
                .or_else(|| meta.get("creationTime"))
                .filter(|v| !v.is_null())
            {
                metadata.insert("creationTime".to_owned(), created.clone());
            } else {
                metadata.insert("creationTime".to_owned(), Value::Null);
            }
            let signed_in = meta
                .get("lastSignedInAt")
                .or_else(|| meta.get("lastSignInTime"))
                .filter(|v| !v.is_null());
            match signed_in {
                Some(value) => {
                    metadata.insert("lastSignInTime".to_owned(), value.clone());
                }
                // `meta.lastSignedInAt || meta.lastSignInTime`: a null member gives null, an
                // absent one gives `undefined`, which the JSON drops.
                None if meta.get("lastSignInTime").is_some_and(Value::is_null) => {
                    metadata.insert("lastSignInTime".to_owned(), Value::Null);
                }
                None => {}
            }
        } else {
            metadata.insert("creationTime".to_owned(), Value::Null);
            metadata.insert("lastSignInTime".to_owned(), Value::Null);
        }
        let mut out = Map::new();
        for key in [
            "uid",
            "email",
            "emailVerified",
            "displayName",
            "photoURL",
            "phoneNumber",
            "disabled",
            "passwordHash",
            "passwordSalt",
            "tokensValidAfterTime",
        ] {
            out.insert(
                key.to_owned(),
                record.get(key).cloned().unwrap_or(Value::Null),
            );
        }
        out.insert("metadata".to_owned(), Value::Object(metadata));
        out.insert("customClaims".to_owned(), record["customClaims"].clone());
        out.insert("providerData".to_owned(), record["providerData"].clone());
        Value::Object(out)
    }

    fn is_uuid_v4(text: &str) -> bool {
        let parts: Vec<&str> = text.split('-').collect();
        parts.iter().map(|p| p.len()).collect::<Vec<_>>() == [8, 4, 4, 4, 12]
            && text
                .chars()
                .all(|c| c == '-' || c.is_ascii_digit() || ('a'..='f').contains(&c))
            && text.as_bytes()[14] == b'4'
            && matches!(text.as_bytes()[19], b'8' | b'9' | b'a' | b'b')
    }

    #[test]
    fn the_event_id_is_a_uuid_as_in_frames_55_66_121_and_122() {
        // Production: `context.eventId` "bfcfc370-9507-435b-9ad0-9143ff05c8db" (frame 55),
        // "27180876-bd2b-4b59-8af9-e2f9db23b344" (frame 66, the delete of the same account).
        let user = password_user("a@example.test", at(FRAME_55_SECOND, 0));
        for kind in [AuthEvent::Created, AuthEvent::Deleted] {
            let event = auth_event("42-7", "demo-app", kind, &user, at(FRAME_55_SECOND, 0));
            let id = event["id"].as_str().unwrap();
            assert!(is_uuid_v4(id), "{id}");
            assert_eq!(id, event_id_uuid("42-7"));
        }
    }

    #[test]
    fn the_context_timestamp_has_three_fraction_digits_cut_not_rounded_as_in_frame_55() {
        // Production: `context.timestamp` "2026-10-04T18:44:34.537Z" (frame 55) and
        // "2026-10-04T18:45:09.903Z" (frame 66); every recorded value has exactly three digits.
        let user = password_user("a@example.test", at(FRAME_55_SECOND, 0));
        let event = auth_event(
            "42-1",
            "demo-app",
            AuthEvent::Created,
            &user,
            at(FRAME_55_SECOND, 537_999_999),
        );
        assert_eq!(event["time"], "2026-10-04T18:44:34.537Z");
        let whole = auth_event(
            "42-1",
            "demo-app",
            AuthEvent::Created,
            &user,
            at(FRAME_55_SECOND, 0),
        );
        assert_eq!(whole["time"], "2026-10-04T18:44:34.000Z");
    }

    #[test]
    fn an_account_an_admin_created_has_no_last_sign_in_member_as_in_frames_121_and_122() {
        // Frame 121 (create) and 122 (delete): `metadata` is {"creationTime":
        // "2026-10-04T19:01:43Z"} and nothing else, the creation cut to the second.
        let created = at(1_791_140_503, 528_123_456); // 19:01:43.528...
        let user = password_user("e1046da69e0e78a784a9514ddu19@example.test", created);
        assert_eq!(user.last_sign_in_at, None);
        for kind in [AuthEvent::Created, AuthEvent::Deleted] {
            let wire = auth_event("42-1", "demo-app", kind, &user, created)["data"].clone();
            let seen = sdk_user_json(&wire);
            assert_eq!(
                seen["metadata"],
                json!({"creationTime": "2026-10-04T19:01:43Z"})
            );
        }
    }

    #[test]
    fn a_signed_up_account_shows_its_sign_in_cut_to_the_second_as_in_frame_55() {
        // Frame 55: creationTime and lastSignInTime are both "2026-10-04T18:44:34Z".
        let created = at(FRAME_55_SECOND, 537_000_000);
        let mut user = password_user("e4585e5442efa3439b570ce10f7@example.test", created);
        user.last_sign_in_at = Some(created);
        let wire =
            auth_event("42-1", "demo-app", AuthEvent::Created, &user, created)["data"].clone();
        assert_eq!(
            sdk_user_json(&wire)["metadata"],
            json!({"creationTime": "2026-10-04T18:44:34Z", "lastSignInTime": "2026-10-04T18:44:34Z"})
        );
    }

    #[test]
    fn a_later_sign_in_shows_in_the_delete_event_as_in_frame_126() {
        // Frame 125 (create, no lastSignInTime) then 126 (delete after a sign-in 20 s later):
        // creationTime "2026-10-04T19:03:17Z", lastSignInTime "2026-10-04T19:03:37Z".
        let created = at(1_791_140_597, 289_000_000);
        let mut user = password_user("ea5f2cb63a8734b61feadd712u21@example.test", created);
        let create = auth_event("42-1", "demo-app", AuthEvent::Created, &user, created);
        assert!(sdk_user_json(&create["data"])["metadata"]
            .get("lastSignInTime")
            .is_none());
        user.last_sign_in_at = Some(at(1_791_140_617, 804_000_000));
        let delete = auth_event("42-2", "demo-app", AuthEvent::Deleted, &user, created);
        assert_eq!(
            sdk_user_json(&delete["data"])["metadata"],
            json!({"creationTime": "2026-10-04T19:03:17Z", "lastSignInTime": "2026-10-04T19:03:37Z"})
        );
    }

    #[test]
    fn a_password_provider_entry_has_exactly_email_provider_id_and_uid_as_in_frame_55() {
        // Frame 55 `providerData[0]`: {"email", "providerId": "password", "uid": <the email>}.
        // No displayName or photoURL member, null or otherwise, for an account without them.
        let user = password_user(
            "e4585e5442efa3439b570ce10f7@example.test",
            at(FRAME_55_SECOND, 0),
        );
        let wire = user_record_json(&user);
        let entry = wire["providerData"][0].as_object().unwrap();
        let mut keys: Vec<&str> = entry.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["email", "providerId", "uid"]);
        assert_eq!(entry["uid"], "e4585e5442efa3439b570ce10f7@example.test");
    }

    #[test]
    fn a_password_provider_entry_keeps_a_display_name_and_photo_the_account_has() {
        // Unrecorded: no recorded account had a profile. The members are kept when set
        // (firebase-admin prints them for a profile), only the null placeholders go.
        let mut user = password_user("a@example.test", at(FRAME_55_SECOND, 0));
        user.display_name = Some("Ada".to_owned());
        user.photo_url = Some("https://example.test/a.png".to_owned());
        let wire = user_record_json(&user);
        assert_eq!(wire["providerData"][0]["displayName"], "Ada");
        assert_eq!(
            wire["providerData"][0]["photoURL"],
            "https://example.test/a.png"
        );
    }

    #[test]
    fn creation_and_sign_in_at_a_second_boundary_each_print_their_own_second() {
        // Near miss: the cut is per time, never shared. 18:44:34.999999999 cuts to :34 and the
        // next instant, 18:44:35.000000000, to :35 (rounding would make the first :35).
        let created = at(FRAME_55_SECOND, 999_999_999);
        let mut user = password_user("a@example.test", created);
        user.last_sign_in_at = Some(at(FRAME_55_SECOND + 1, 0));
        let wire = user_record_json(&user);
        assert_eq!(wire["metadata"]["creationTime"], "2026-10-04T18:44:34Z");
        assert_eq!(wire["metadata"]["lastSignInTime"], "2026-10-04T18:44:35Z");
    }

    #[test]
    fn a_password_provider_entry_is_serialized_in_the_recorded_member_order() {
        // Frame 55 `providerData[0]` lists `email`, `providerId`, `uid` in that order. `Value`
        // equality ignores order, so this reads the serialized wire string (it would catch a
        // workspace-wide `serde_json/preserve_order`).
        let user = password_user(
            "e4585e5442efa3439b570ce10f7@example.test",
            at(FRAME_55_SECOND, 0),
        );
        let text = serde_json::to_string(&user_record_json(&user)["providerData"][0]).unwrap();
        assert_eq!(
            text,
            r#"{"email":"e4585e5442efa3439b570ce10f7@example.test","providerId":"password","uid":"e4585e5442efa3439b570ce10f7@example.test"}"#
        );
    }

    #[test]
    fn a_federated_provider_entry_carries_the_members_it_has_and_no_placeholders() {
        // Unrecorded (no recorded account was federated): the entry keeps the members the
        // identity has, and a member it lacks is absent like the password entry's. That is an
        // inference from the recorded password entry (same `ProviderUserInfo` message), accepted
        // in ledger 869; before this change the lacking members were `null`.
        use fireemu_core_auth::store::FederatedIdentity;
        let mut user = password_user("a@example.test", at(FRAME_55_SECOND, 0));
        user.federated = vec![
            FederatedIdentity {
                provider_id: "google.com".to_owned(),
                raw_id: "g-1".to_owned(),
                email: Some("g@example.test".to_owned()),
                display_name: None,
                photo_url: Some("https://example.test/g.png".to_owned()),
            },
            FederatedIdentity {
                provider_id: "github.com".to_owned(),
                raw_id: "h-1".to_owned(),
                email: None,
                display_name: Some("H".to_owned()),
                photo_url: None,
            },
        ];
        let wire = user_record_json(&user);
        assert_eq!(
            wire["providerData"][1],
            json!({"uid": "g-1", "providerId": "google.com", "email": "g@example.test", "photoURL": "https://example.test/g.png"})
        );
        assert_eq!(
            wire["providerData"][2],
            json!({"uid": "h-1", "providerId": "github.com", "displayName": "H"})
        );
    }

    #[test]
    fn tokens_valid_after_time_is_null_for_the_recorded_never_revoked_accounts() {
        // Frames 55, 121, 125, 131 ...: `tokensValidAfterTime` is null for an admin-created and
        // for a signed-up account alike.
        let created = at(FRAME_55_SECOND, 537_000_000);
        for signed_up in [false, true] {
            let mut user = password_user("a@example.test", created);
            if signed_up {
                user.last_sign_in_at = Some(created);
            }
            assert!(!user.tokens_revoked);
            let wire =
                auth_event("42-1", "demo-app", AuthEvent::Created, &user, created)["data"].clone();
            assert_eq!(sdk_user_json(&wire)["tokensValidAfterTime"], Value::Null);
        }
    }

    #[test]
    fn a_revoked_account_keeps_printing_the_revocation_second() {
        // Unrecorded: no recorded account had its tokens revoked, so the member keeps the form
        // it had (RFC 3339, whole second).
        let created = at(FRAME_55_SECOND, 537_000_000);
        let mut user = password_user("a@example.test", created);
        user.tokens_revoked = true;
        user.tokens_valid_after = at(FRAME_55_SECOND + 5, 0);
        let wire = user_record_json(&user);
        assert_eq!(wire["tokensValidAfterTime"], "2026-10-04T18:44:39Z");
    }

    #[test]
    fn the_handler_sees_the_whole_recorded_user_of_frame_121() {
        // Frame 121 `data`, member by member, for an admin-created account.
        let created = at(1_791_140_503, 528_000_000);
        let email = "e1046da69e0e78a784a9514ddu19@example.test";
        let user = password_user(email, created);
        let wire =
            auth_event("42-1", "demo-app", AuthEvent::Created, &user, created)["data"].clone();
        let seen = sdk_user_json(&wire);
        let mut expected = json!({
            "uid": "<uid>",
            "email": email,
            "emailVerified": false,
            "displayName": null,
            "photoURL": null,
            "phoneNumber": null,
            "disabled": false,
            "passwordHash": null,
            "passwordSalt": null,
            "tokensValidAfterTime": null,
            "metadata": {"creationTime": "2026-10-04T19:01:43Z"},
            "customClaims": {},
            "providerData": [{"email": email, "providerId": "password", "uid": email}],
        });
        expected["uid"] = Value::String(user.local_id.as_str().to_owned());
        assert_eq!(seen, expected);
    }

    proptest! {
        #[test]
        fn the_event_id_is_always_a_uuid_and_a_function_of_the_seed(seed in ".*") {
            let user = password_user("a@example.test", at(FRAME_55_SECOND, 0));
            let event = auth_event(&seed, "demo-app", AuthEvent::Created, &user, at(FRAME_55_SECOND, 0));
            let id = event["id"].as_str().unwrap();
            prop_assert!(is_uuid_v4(id), "{}", id);
            prop_assert_eq!(id, event_id_uuid(&seed));
        }

        #[test]
        fn the_context_time_has_three_digits_and_is_cut_not_rounded(
            nanos in -4_000_000_000_000_000_000_i128..4_000_000_000_000_000_000
        ) {
            let instant = LogicalInstant::from_nanos(i128::from(FRAME_55_SECOND) * 1_000_000_000 + nanos);
            let user = password_user("a@example.test", at(FRAME_55_SECOND, 0));
            let event = auth_event("42-1", "demo-app", AuthEvent::Created, &user, instant);
            let text = event["time"].as_str().unwrap();
            let fraction = text.strip_suffix('Z').unwrap().rsplit('.').next().unwrap();
            prop_assert_eq!(fraction.len(), 3, "{}", text);
            prop_assert_eq!(text.len(), 24);
            let parsed = LogicalInstant::parse_rfc3339(text).unwrap().as_nanos();
            prop_assert_eq!(parsed, instant.as_nanos() - instant.as_nanos().rem_euclid(1_000_000));
        }

        // That the seconds are cut and not rounded is a choice: the record shows the format only.
        #[test]
        fn creation_and_sign_in_times_are_the_instant_cut_to_the_whole_second(
            created in -4_000_000_000_000_000_000_i128..4_000_000_000_000_000_000,
            signed_in in proptest::option::of(-4_000_000_000_000_000_000_i128..4_000_000_000_000_000_000),
        ) {
            let mut user = password_user("a@example.test", LogicalInstant::from_nanos(created));
            user.last_sign_in_at = signed_in.map(LogicalInstant::from_nanos);
            let wire = user_record_json(&user);
            let whole = |n: i128| n - n.rem_euclid(1_000_000_000);
            let creation = wire["metadata"]["creationTime"].as_str().unwrap();
            prop_assert_eq!(creation.len(), 20);
            prop_assert_eq!(LogicalInstant::parse_rfc3339(creation).unwrap().as_nanos(), whole(created));
            match signed_in {
                Some(n) => {
                    let text = wire["metadata"]["lastSignInTime"].as_str().unwrap();
                    prop_assert_eq!(text.len(), 20);
                    prop_assert_eq!(LogicalInstant::parse_rfc3339(text).unwrap().as_nanos(), whole(n));
                }
                None => prop_assert!(wire["metadata"].get("lastSignInTime").is_none()),
            }
        }

        #[test]
        fn tokens_valid_after_time_is_present_exactly_when_tokens_were_revoked(
            revoked in any::<bool>(),
            valid_after in 0_i64..4_000_000_000,
        ) {
            let mut user = password_user("a@example.test", at(FRAME_55_SECOND, 0));
            user.tokens_revoked = revoked;
            user.tokens_valid_after = at(valid_after, 0);
            let wire = user_record_json(&user);
            if revoked {
                prop_assert!(wire["tokensValidAfterTime"].is_string());
            } else {
                prop_assert!(wire["tokensValidAfterTime"].is_null());
            }
        }
    }
}
