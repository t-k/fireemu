//! `CloudEvents` JSON for Firestore document changes, Storage object events and scheduled
//! runs, in the shapes the `firebase-functions` v2 SDK decodes with
//! `datacontenttype: application/json`.

use fireemu_adapter_grpc::encode::encode_document;
use fireemu_adapter_grpc::rest::json::{document_to_json, shorten_fraction};
use fireemu_core_auth::store::UserRecord;
use fireemu_core_firestore::store::Document;
use fireemu_core_functions::event::{
    auth_attributes, firestore_attributes, pubsub_attributes, schedule_attributes,
    storage_attributes, with_auth_context,
};
use fireemu_core_functions::manifest::{AuthEvent, DocumentEvent, ObjectEvent};
use fireemu_core_storage::store::ObjectMetadata;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Map, Value};
use std::fmt::Write as _;

fn rfc3339(t: LogicalInstant) -> String {
    t.to_rfc3339()
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
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

/// A UUID-shaped (version 4, variant 1) event id derived from `seed`. Production's Firestore
/// events carry random UUIDs; the local ones must stay replayable, so the id is a fixed function
/// of the session and the event counter that the runtime passes as the seed. The mixing is not
/// cryptographic: the id only has to look like, and behave as, an opaque unique identifier.
#[must_use]
pub fn event_id_uuid(seed: &str) -> String {
    let mut state = seed.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    });
    state ^= (seed.len() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let mut next = || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
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
    // `firebase-functions` decodes JSON payloads with `createSnapshotFromJson(data, source,
    // ...)`, which uses `source` as the document name when a side of the change is absent;
    // it therefore has to be the full document resource name (the protobuf path derives the
    // same name from the `document` attribute).
    let source = format!("projects/{project}/databases/{database}/documents/{document_path}");
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
        "source": source,
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
        "etag": m.etag(),
        "timeCreated": rfc3339(m.time_created),
        "updated": rfc3339(m.updated),
        "timeStorageClassUpdated": rfc3339(m.time_created),
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

/// A Storage object event.
#[must_use]
pub fn storage_event(
    id: &str,
    kind: ObjectEvent,
    object: &ObjectMetadata,
    time: LogicalInstant,
) -> Value {
    let attrs = storage_attributes(object.bucket.as_str(), object.name.as_str(), kind);
    let mut event = json!({
        "specversion": "1.0",
        "id": id,
        "source": attrs.source,
        "subject": attrs.subject,
        "type": attrs.event_type,
        "time": rfc3339(time),
        "datacontenttype": "application/json",
        "data": object_json(object),
    });
    for (k, v) in attrs.extensions {
        event[k] = Value::String(v);
    }
    event
}

/// A Pub/Sub message event (`MessagePublishedData` of `onMessagePublished`): `message` is
/// the published message (`data` base64, `attributes`, `orderingKey`).
#[must_use]
pub fn pubsub_event(
    id: &str,
    project: &str,
    topic: &str,
    message: &Value,
    time: LogicalInstant,
) -> Value {
    let attrs = pubsub_attributes(project, topic);
    let mut msg = json!({
        "messageId": id,
        "data": message.get("data").cloned().unwrap_or(Value::String(String::new())),
        "attributes": message.get("attributes").cloned().unwrap_or_else(|| json!({})),
        "publishTime": rfc3339(time),
    });
    if let Some(key) = message.get("orderingKey").and_then(Value::as_str) {
        msg["orderingKey"] = Value::String(key.to_owned());
    }
    json!({
        "specversion": "1.0",
        "id": id,
        "source": attrs.source,
        "type": attrs.event_type,
        "time": rfc3339(time),
        "datacontenttype": "application/json",
        "data": {
            "message": msg,
            "subscription": format!("projects/{project}/subscriptions/emulator-sub-{topic}"),
        },
    })
}

/// The v1 `UserRecord` wire shape.
#[must_use]
pub fn user_record_json(u: &UserRecord) -> Value {
    let mut providers: Vec<Value> = Vec::new();
    if let Some(email) = &u.email {
        providers.push(json!({"uid": email, "providerId": "password", "email": email, "displayName": u.display_name, "photoURL": u.photo_url}));
    }
    if let Some(phone) = &u.phone_number {
        providers.push(json!({"uid": phone, "providerId": "phone", "phoneNumber": phone}));
    }
    for f in &u.federated {
        providers.push(json!({"uid": f.raw_id, "providerId": f.provider_id, "email": f.email, "displayName": f.display_name, "photoURL": f.photo_url}));
    }
    let claims: Value =
        serde_json::from_str(&u.custom_claims.canonical_json()).unwrap_or(json!({}));
    json!({
        "uid": u.local_id.as_str(),
        "email": u.email,
        "emailVerified": u.email_verified,
        "displayName": u.display_name,
        "photoURL": u.photo_url,
        "phoneNumber": u.phone_number,
        "disabled": u.disabled,
        "metadata": {
            "creationTime": rfc3339(u.created_at),
            "lastSignInTime": u.last_sign_in_at.map(rfc3339),
        },
        "providerData": providers,
        "customClaims": claims,
        "tokensValidAfterTime": rfc3339(u.tokens_valid_after),
    })
}

/// An Auth user event (`data` is the v1 `UserRecord`).
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
        "id": id,
        "source": attrs.source,
        "type": attrs.event_type,
        "time": rfc3339(time),
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
    use super::{event_id_uuid, firestore_time};
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
}
