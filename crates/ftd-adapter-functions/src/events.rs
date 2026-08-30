//! `CloudEvents` JSON for Firestore document changes, Storage object events and scheduled
//! runs, in the shapes the `firebase-functions` v2 SDK decodes with
//! `datacontenttype: application/json`.

use ftd_adapter_grpc::encode::encode_document;
use ftd_adapter_grpc::rest::json::document_to_json;
use ftd_core_auth::store::UserRecord;
use ftd_core_firestore::store::Document;
use ftd_core_functions::event::{
    auth_attributes, firestore_attributes, pubsub_attributes, schedule_attributes,
    storage_attributes, with_auth_context,
};
use ftd_core_functions::manifest::{AuthEvent, DocumentEvent, ObjectEvent};
use ftd_core_storage::store::ObjectMetadata;
use ftd_core_types::time::LogicalInstant;
use serde_json::{json, Map, Value};

fn rfc3339(t: LogicalInstant) -> String {
    t.to_rfc3339()
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
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
/// concrete kind's data with the written type).
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
        "id": id,
        "source": source,
        "subject": attrs.subject,
        "type": attrs.event_type,
        "time": rfc3339(time),
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
        "metadata": m.custom,
    });
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
            "subscription": format!("projects/{project}/subscriptions/firebase-testd-{topic}"),
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
