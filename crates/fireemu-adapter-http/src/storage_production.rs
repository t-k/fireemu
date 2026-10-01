//! The strict profile's framing of Storage answers as production sends them: which headers an
//! answer carries and how its JSON body is laid out and ordered.
//!
//! Everything here comes from the two lean-v5 production recordings of STORAGE-OBJECT (and the
//! lean-v4 and probe-v4 recordings behind them), read through the normalized fixture of the
//! comparison tool: the header names and constant values of 2,446 exchanges per recording, the
//! `bodyBytes` of each JSON body (the recorder stores a compact re-serialization, so the layout is
//! the recorded length minus the compact length) and the member order of every JSON object.
//! The emulator profile never reaches this module: it keeps the official emulator's headers and
//! bodies, which differ from production in all of these.
//!
//! A request shape the recordings do not cover is not framed here at all (the caller passes no
//! [`Shape`] for it) and keeps the headers it had.

use serde_json::Value;

use crate::storage::StorageResponse;

/// Which front end answers: the Google-fronted JSON API or the Firebase Storage v0 API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// `/storage/v1`, `/upload/storage/v1`, `/download/storage/v1` and the short `/b/...` spelling.
    Gcs,
    /// `/v0/b/...`.
    Firebase,
}

/// What the framing needs to know about the request that produced a response.
/// The bools are independent facts of one request, not states of a machine.
#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct Shape {
    /// The front end.
    pub wire: Wire,
    /// The request method.
    pub method: String,
    /// A GET of an object with `alt=media`.
    pub media: bool,
    /// A GET of a bucket (a listing).
    pub list: bool,
    /// A GET of one object, with or without `alt=media`.
    pub object_read: bool,
    /// A read the recordings show production serving to an end user rather than to the owner: a
    /// Firebase ID token or a download token (4 of the 179 recorded v0 media reads).
    pub end_user_read: bool,
    /// The request's `Origin`, when it sent one.
    pub origin: Option<String>,
    /// Seconds since the Unix epoch at the time of the answer (`Expires` on a cacheable answer).
    pub now_unix_seconds: i64,
}

const NO_CACHE: &str = "no-cache, no-store, max-age=0, must-revalidate";
const READ_CACHE: &str = "private, max-age=0, must-revalidate, no-transform";
const PRIVATE: &str = "private, max-age=0";
const EPOCH_EXPIRES: &str = "Mon, 01 Jan 1990 00:00:00 GMT";
const FIREBASE_EXPOSED: &str = "Content-Range, X-Firebase-Storage-XSRF";

/// How an answer is cached, as production states it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Caching {
    /// `no-cache, no-store, max-age=0, must-revalidate`, `Expires` in 1990, `Pragma: no-cache`.
    NoCache,
    /// `private, max-age=0, must-revalidate, no-transform` and an `Expires` of now: JSON API
    /// metadata and list reads.
    Read,
    /// `private, max-age=0` and an `Expires` of now.
    Private,
}

/// The headers an answer is given besides the ones its handler produced.
struct Plan {
    cache: Option<Caching>,
    /// `Vary: Origin, X-Origin` (JSON API).
    vary: bool,
    /// `Access-Control-Allow-Origin: *`, the Firebase expose list and `nosniff` (v0 JSON).
    firebase_cors: bool,
    nosniff: bool,
}

impl Plan {
    const NONE: Self = Self {
        cache: None,
        vary: false,
        firebase_cors: false,
        nosniff: false,
    };
}

fn plan(shape: &Shape, status: u16, is_json: bool, is_text: bool) -> Plan {
    match shape.wire {
        Wire::Gcs => {
            if status == 308 {
                return Plan::NONE;
            }
            let cache = if shape.media {
                if matches!(status, 200 | 206) {
                    Caching::NoCache
                } else {
                    Caching::Private
                }
            } else if (shape.list || shape.object_read) && matches!(status, 200 | 304) {
                Caching::Read
            } else {
                Caching::NoCache
            };
            Plan {
                cache: Some(cache),
                vary: true,
                firebase_cors: false,
                nosniff: false,
            }
        }
        Wire::Firebase => {
            if shape.media && matches!(status, 200 | 206) {
                let cache = if shape.end_user_read {
                    Caching::Private
                } else {
                    Caching::NoCache
                };
                return Plan {
                    cache: Some(cache),
                    ..Plan::NONE
                };
            }
            if shape.media && status == 416 {
                return Plan {
                    cache: Some(Caching::Private),
                    ..Plan::NONE
                };
            }
            // The resumable protocol's own answers (`text/plain`) carry no CORS and no cache
            // headers; its JSON answers (the finalizing one) are ordinary v0 JSON.
            if is_text || !(is_json || status == 204) {
                return Plan::NONE;
            }
            Plan {
                cache: matches!(shape.method.as_str(), "GET" | "DELETE")
                    .then_some(Caching::Private),
                vary: false,
                firebase_cors: true,
                nosniff: status != 204,
            }
        }
    }
}

/// Header names the handlers or the official emulator's conventions add that production does
/// not send with the plan's answer; they are removed before the plan's constants are added.
fn is_replaced(name: &str, is_media: bool) -> bool {
    matches!(
        name,
        "cache-control"
            | "expires"
            | "pragma"
            | "vary"
            | "x-content-type-options"
            | "x-gupload-uploadid"
    ) || name.starts_with("access-control-")
        || (!is_media
            && matches!(
                name,
                "content-disposition" | "content-encoding" | "content-language"
            ))
}

/// The answer as production frames it, and whether it was framed completely (the server then does
/// not stamp the official emulator's CORS and `nosniff` headers over it). A shape the plan does
/// not cover is returned untouched and not framed.
#[must_use]
pub fn frame(shape: &Shape, mut response: StorageResponse) -> (StorageResponse, bool) {
    let content_type = response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.to_ascii_lowercase());
    let is_json = content_type
        .as_deref()
        .is_some_and(|value| value.starts_with("application/json"));
    let is_text = content_type
        .as_deref()
        .is_some_and(|value| value.starts_with("text/plain"));
    let mut object_etag = None;
    if is_json {
        if let Ok(value) = serde_json::from_slice::<Value>(&response.body) {
            // The JSON API repeats an object resource's `etag` as a header (recorded: every 200
            // that answers an object, from a read, an update, an upload or a copy).
            if shape.wire == Wire::Gcs
                && response.status == 200
                && value.get("kind").and_then(Value::as_str) == Some("storage#object")
            {
                object_etag = value.get("etag").and_then(Value::as_str).map(str::to_owned);
            }
            if let Some(body) = layout_value(shape.wire, &response.body, &value) {
                response.body = bytes::Bytes::from(body);
            }
        }
    }
    let plan = plan(shape, response.status, is_json, is_text);
    // A shape the plan adds nothing to (the resumable protocol's text answers, the 308) is still
    // framed: production sends it without CORS, `Vary` or `nosniff`, so the server stamps none.
    if plan.cache.is_none() && !plan.firebase_cors && !plan.vary {
        return (response, true);
    }
    let media_answer = shape.media && matches!(response.status, 200 | 206);
    response
        .headers
        .retain(|(name, _)| !is_replaced(&name.to_ascii_lowercase(), media_answer));
    let mut add =
        |name: &str, value: &str| response.headers.push((name.to_owned(), value.to_owned()));
    match plan.cache {
        Some(Caching::NoCache) => {
            add("cache-control", NO_CACHE);
            add("expires", EPOCH_EXPIRES);
            add("pragma", "no-cache");
        }
        Some(Caching::Read) => {
            add("cache-control", READ_CACHE);
            add("expires", &http_date(shape.now_unix_seconds));
        }
        Some(Caching::Private) => {
            add("cache-control", PRIVATE);
            add("expires", &http_date(shape.now_unix_seconds));
        }
        None => {}
    }
    if plan.vary {
        // Two header lines, as the Google front end writes them (recorded raw headers of the
        // stage 3 v9 recording: `Vary: Origin` and `Vary: X-Origin`).
        add("vary", "Origin");
        add("vary", "X-Origin");
    }
    if let Some(etag) = &object_etag {
        add("etag", etag);
    }
    if plan.firebase_cors {
        add("access-control-allow-origin", "*");
        add("access-control-expose-headers", FIREBASE_EXPOSED);
    }
    if plan.nosniff {
        add("x-content-type-options", "nosniff");
    }
    // An `Origin` makes the JSON API reflect it, as the Google front end does for a browser; the
    // recordings sent none, so this is the one header here that is not recorded.
    if shape.wire == Wire::Gcs {
        if let Some(origin) = &shape.origin {
            add("access-control-allow-origin", origin);
        }
    }
    (response, true)
}

/// `Thu, 01 Oct 2026 03:26:31 GMT` for a count of seconds since the Unix epoch.
#[must_use]
pub fn http_date(unix_seconds: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = unix_seconds.div_euclid(86_400);
    let seconds = unix_seconds.rem_euclid(86_400);
    // Civil date from a day count (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let weekday = usize::try_from(days.rem_euclid(7)).unwrap_or(0);
    format!(
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        DAYS[weekday],
        MONTHS[usize::try_from(month - 1).unwrap_or(0)],
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    )
}

// ------------------------------------------------------------------------------------------
// body layout and member order
// ------------------------------------------------------------------------------------------

/// The JSON API's member order, from the recorded resources: object (`kind` to `owner`), list
/// (`kind`, `nextPageToken`, `prefixes`, `items`), rewrite response and error body. The contexts
/// share one sequence because their key sets are disjoint.
const GCS_ORDER: &[&str] = &[
    "kind",
    "id",
    "selfLink",
    "mediaLink",
    "name",
    "bucket",
    "generation",
    "metageneration",
    "contentType",
    "storageClass",
    "size",
    "md5Hash",
    "contentEncoding",
    "contentDisposition",
    "contentLanguage",
    "cacheControl",
    "crc32c",
    "etag",
    "timeCreated",
    "updated",
    "timeStorageClassUpdated",
    "timeFinalized",
    "metadata",
    "owner",
    "nextPageToken",
    "prefixes",
    "items",
    "totalBytesRewritten",
    "objectSize",
    "done",
    "rewriteToken",
    "resource",
    "code",
    "message",
    "errors",
    "domain",
    "reason",
    "locationType",
    "location",
];

/// The Firebase dialect's member order: object (`name` to `metadata`), list (`prefixes`, `items`,
/// `nextPageToken`) and error body.
const FIREBASE_ORDER: &[&str] = &[
    "name",
    "bucket",
    "generation",
    "metageneration",
    "contentType",
    "timeCreated",
    "updated",
    "storageClass",
    "size",
    "md5Hash",
    "contentEncoding",
    "contentDisposition",
    "contentLanguage",
    "cacheControl",
    "crc32c",
    "etag",
    "downloadTokens",
    "metadata",
    "prefixes",
    "items",
    "nextPageToken",
    "code",
    "message",
];

/// The body in production's layout, or `None` when it is not a JSON object or array, or is
/// already laid out (the error builders write production's bytes directly).
///
/// The JSON API ends its bodies with a line feed and the Firebase dialect does not (recorded:
/// the layout overhead of all 1,042 JSON API and 592 v0 JSON bodies). Both indent by two spaces.
/// Keys follow the recorded order of the dialect, then any other key alphabetically; the maps
/// under `metadata` and `owner` stay alphabetical, so a user's key can never take a recorded
/// key's place.
#[must_use]
pub fn layout_json(wire: Wire, body: &[u8]) -> Option<Vec<u8>> {
    let value: Value = serde_json::from_slice(body).ok()?;
    layout_value(wire, body, &value)
}

fn layout_value(wire: Wire, body: &[u8], value: &Value) -> Option<Vec<u8>> {
    if body.starts_with(b"{\n") || body.starts_with(b"[\n") {
        return None;
    }
    if !matches!(value, Value::Object(_) | Value::Array(_)) {
        return None;
    }
    let order = match wire {
        Wire::Gcs => GCS_ORDER,
        Wire::Firebase => FIREBASE_ORDER,
    };
    let mut out = Vec::with_capacity(body.len() * 2);
    write_value(&mut out, value, 0, order, true);
    if wire == Wire::Gcs {
        out.push(b'\n');
    }
    Some(out)
}

fn write_value(out: &mut Vec<u8>, value: &Value, indent: usize, order: &[&str], ranked: bool) {
    match value {
        Value::Object(map) if map.is_empty() => out.extend_from_slice(b"{}"),
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            if ranked {
                entries.sort_by_key(|(key, _)| {
                    order
                        .iter()
                        .position(|known| known == key)
                        .unwrap_or(order.len())
                });
            }
            out.extend_from_slice(b"{\n");
            for (index, (key, member)) in entries.iter().enumerate() {
                push_indent(out, indent + 1);
                out.extend_from_slice(
                    serde_json::to_string(key.as_str())
                        .unwrap_or_default()
                        .as_bytes(),
                );
                out.extend_from_slice(b": ");
                let member_ranked = ranked && !matches!(key.as_str(), "metadata" | "owner");
                write_value(out, member, indent + 1, order, member_ranked);
                out.extend_from_slice(if index + 1 == entries.len() {
                    b"\n"
                } else {
                    b",\n"
                });
            }
            push_indent(out, indent);
            out.push(b'}');
        }
        Value::Array(items) if items.is_empty() => out.extend_from_slice(b"[]"),
        Value::Array(items) => {
            out.extend_from_slice(b"[\n");
            for (index, item) in items.iter().enumerate() {
                push_indent(out, indent + 1);
                write_value(out, item, indent + 1, order, ranked);
                out.extend_from_slice(if index + 1 == items.len() {
                    b"\n"
                } else {
                    b",\n"
                });
            }
            push_indent(out, indent);
            out.push(b']');
        }
        scalar => {
            out.extend_from_slice(serde_json::to_string(scalar).unwrap_or_default().as_bytes());
        }
    }
}

fn push_indent(out: &mut Vec<u8>, levels: usize) {
    for _ in 0..levels {
        out.extend_from_slice(b"  ");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One recorded body: the stored compact value with its keys reversed (the order a handler's
    /// map may give), the recorded layout overhead in bytes, and the layout production sent
    /// (the stored value pretty-printed in its recorded order; the fixture row is named).
    struct Recorded {
        row: &'static str,
        wire: Wire,
        shuffled: &'static str,
        overhead: usize,
        expected: &'static str,
    }

    const RECORDED: &[Recorded] = &[
        Recorded {
            row: "auth--admin.json #1 (gcs-list-empty)",
            wire: Wire::Gcs,
            shuffled: r#"{"kind":"storage#objects"}"#,
            overhead: 6,
            expected: r#"{
  "kind": "storage#objects"
}
"#,
        },
        Recorded {
            row: "auth--admin.json #2 (v0-error)",
            wire: Wire::Firebase,
            shuffled: r#"{"error":{"message":"Not Found.","code":404}}"#,
            overhead: 20,
            expected: r#"{
  "error": {
    "code": 404,
    "message": "Not Found."
  }
}"#,
        },
        Recorded {
            row: "auth--admin.json #7 (gcs-object-disposition)",
            wire: Wire::Gcs,
            shuffled: r#"{"metadata":{"firebaseStorageDownloadTokens":"<TOKEN:1>"},"timeFinalized":"<TIME:3>","timeStorageClassUpdated":"<TIME:3>","updated":"<TIME:3>","timeCreated":"<TIME:3>","etag":"<ETAG:1>","crc32c":"H2YOnQ==","contentDisposition":"inline; filename*=utf-8''admin-firebase.bin","md5Hash":"uqXbknofvmFOfH+qMaon5A==","size":"3","storageClass":"STANDARD","contentType":"application/octet-stream","metageneration":"1","generation":"<GEN:1>","bucket":"<BUCKET>","name":"storage-object/<RUN>/auth/admin-firebase.bin","mediaLink":"https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fauth%2Fadmin-firebase.bin?generation=<GEN:1>&alt=media","selfLink":"https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fauth%2Fadmin-firebase.bin","id":"<BUCKET>/storage-object/<RUN>/auth/admin-firebase.bin/<GEN:1>","kind":"storage#object"}"#,
            overhead: 91,
            expected: r#"{
  "kind": "storage#object",
  "id": "<BUCKET>/storage-object/<RUN>/auth/admin-firebase.bin/<GEN:1>",
  "selfLink": "https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fauth%2Fadmin-firebase.bin",
  "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fauth%2Fadmin-firebase.bin?generation=<GEN:1>&alt=media",
  "name": "storage-object/<RUN>/auth/admin-firebase.bin",
  "bucket": "<BUCKET>",
  "generation": "<GEN:1>",
  "metageneration": "1",
  "contentType": "application/octet-stream",
  "storageClass": "STANDARD",
  "size": "3",
  "md5Hash": "uqXbknofvmFOfH+qMaon5A==",
  "contentDisposition": "inline; filename*=utf-8''admin-firebase.bin",
  "crc32c": "H2YOnQ==",
  "etag": "<ETAG:1>",
  "timeCreated": "<TIME:3>",
  "updated": "<TIME:3>",
  "timeStorageClassUpdated": "<TIME:3>",
  "timeFinalized": "<TIME:3>",
  "metadata": {
    "firebaseStorageDownloadTokens": "<TOKEN:1>"
  }
}
"#,
        },
        Recorded {
            row: "cross-dialect--state.json #7 (v0-object-metadata)",
            wire: Wire::Firebase,
            shuffled: r#"{"metadata":{"marker":"cross-dialect-updated"},"downloadTokens":"<TOKEN:1>","etag":"<ETAG:3>","crc32c":"vjoVNQ==","contentEncoding":"identity","md5Hash":"6JnTKwgIrXzMisIUzQRzpw==","size":"5","storageClass":"STANDARD","updated":"<TIME:3>","timeCreated":"<TIME:3>","contentType":"application/octet-stream","metageneration":"3","generation":"<GEN:1>","bucket":"<BUCKET>","name":"storage-object/<RUN>/cross/a b%+snow.bin"}"#,
            overhead: 70,
            expected: r#"{
  "name": "storage-object/<RUN>/cross/a b%+snow.bin",
  "bucket": "<BUCKET>",
  "generation": "<GEN:1>",
  "metageneration": "3",
  "contentType": "application/octet-stream",
  "timeCreated": "<TIME:3>",
  "updated": "<TIME:3>",
  "storageClass": "STANDARD",
  "size": "5",
  "md5Hash": "6JnTKwgIrXzMisIUzQRzpw==",
  "contentEncoding": "identity",
  "crc32c": "vjoVNQ==",
  "etag": "<ETAG:3>",
  "downloadTokens": "<TOKEN:1>",
  "metadata": {
    "marker": "cross-dialect-updated"
  }
}"#,
        },
        Recorded {
            row: "firebase--list.json #39 (v0-list-token)",
            wire: Wire::Firebase,
            shuffled: r#"{"nextPageToken":"<PAGE_TOKEN>","items":[{"bucket":"<BUCKET>","name":"storage-object/<RUN>/list/firebase/a.txt"},{"bucket":"<BUCKET>","name":"storage-object/<RUN>/list/firebase/b.txt"}],"prefixes":[]}"#,
            overhead: 68,
            expected: r#"{
  "prefixes": [],
  "items": [
    {
      "name": "storage-object/<RUN>/list/firebase/a.txt",
      "bucket": "<BUCKET>"
    },
    {
      "name": "storage-object/<RUN>/list/firebase/b.txt",
      "bucket": "<BUCKET>"
    }
  ],
  "nextPageToken": "<PAGE_TOKEN>"
}"#,
        },
        Recorded {
            row: "gcs--copy-rewrite.json #31 (gcs-copy-owner)",
            wire: Wire::Gcs,
            shuffled: r#"{"owner":{"entity":"<OWNER>"},"metadata":{"marker":"copy-source","firebaseStorageDownloadTokens":"<TOKEN:1>"},"timeFinalized":"<TIME:3>","timeStorageClassUpdated":"<TIME:3>","updated":"<TIME:3>","timeCreated":"<TIME:3>","etag":"<ETAG:4>","crc32c":"1Kspzg==","md5Hash":"/upD6bdvwxw0vOxAPcxL+A==","size":"5","storageClass":"STANDARD","contentType":"application/octet-stream","metageneration":"1","generation":"<GEN:2>","bucket":"<BUCKET>","name":"storage-object/<RUN>/copy/copied.bin","mediaLink":"https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fcopy%2Fcopied.bin?generation=<GEN:2>&alt=media","selfLink":"https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fcopy%2Fcopied.bin","id":"<BUCKET>/storage-object/<RUN>/copy/copied.bin/<GEN:2>","kind":"storage#object"}"#,
            overhead: 106,
            expected: r#"{
  "kind": "storage#object",
  "id": "<BUCKET>/storage-object/<RUN>/copy/copied.bin/<GEN:2>",
  "selfLink": "https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fcopy%2Fcopied.bin",
  "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fcopy%2Fcopied.bin?generation=<GEN:2>&alt=media",
  "name": "storage-object/<RUN>/copy/copied.bin",
  "bucket": "<BUCKET>",
  "generation": "<GEN:2>",
  "metageneration": "1",
  "contentType": "application/octet-stream",
  "storageClass": "STANDARD",
  "size": "5",
  "md5Hash": "/upD6bdvwxw0vOxAPcxL+A==",
  "crc32c": "1Kspzg==",
  "etag": "<ETAG:4>",
  "timeCreated": "<TIME:3>",
  "updated": "<TIME:3>",
  "timeStorageClassUpdated": "<TIME:3>",
  "timeFinalized": "<TIME:3>",
  "metadata": {
    "firebaseStorageDownloadTokens": "<TOKEN:1>",
    "marker": "copy-source"
  },
  "owner": {
    "entity": "<OWNER>"
  }
}
"#,
        },
        Recorded {
            row: "gcs--copy-rewrite.json #36 (gcs-rewrite)",
            wire: Wire::Gcs,
            shuffled: r#"{"resource":{"owner":{"entity":"<OWNER>"},"metadata":{"marker":"rewrite-override"},"timeFinalized":"<TIME:3>","timeStorageClassUpdated":"<TIME:3>","updated":"<TIME:3>","timeCreated":"<TIME:3>","etag":"<ETAG:5>","crc32c":"1Kspzg==","md5Hash":"/upD6bdvwxw0vOxAPcxL+A==","size":"5","storageClass":"STANDARD","contentType":"text/plain","metageneration":"1","generation":"<GEN:3>","bucket":"<BUCKET>","name":"storage-object/<RUN>/copy/rewritten.bin","mediaLink":"https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fcopy%2Frewritten.bin?generation=<GEN:3>&alt=media","selfLink":"https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fcopy%2Frewritten.bin","id":"<BUCKET>/storage-object/<RUN>/copy/rewritten.bin/<GEN:3>","kind":"storage#object"},"done":true,"objectSize":"5","totalBytesRewritten":"5","kind":"storage#rewriteResponse"}"#,
            overhead: 171,
            expected: r#"{
  "kind": "storage#rewriteResponse",
  "totalBytesRewritten": "5",
  "objectSize": "5",
  "done": true,
  "resource": {
    "kind": "storage#object",
    "id": "<BUCKET>/storage-object/<RUN>/copy/rewritten.bin/<GEN:3>",
    "selfLink": "https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fcopy%2Frewritten.bin",
    "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fcopy%2Frewritten.bin?generation=<GEN:3>&alt=media",
    "name": "storage-object/<RUN>/copy/rewritten.bin",
    "bucket": "<BUCKET>",
    "generation": "<GEN:3>",
    "metageneration": "1",
    "contentType": "text/plain",
    "storageClass": "STANDARD",
    "size": "5",
    "md5Hash": "/upD6bdvwxw0vOxAPcxL+A==",
    "crc32c": "1Kspzg==",
    "etag": "<ETAG:5>",
    "timeCreated": "<TIME:3>",
    "updated": "<TIME:3>",
    "timeStorageClassUpdated": "<TIME:3>",
    "timeFinalized": "<TIME:3>",
    "metadata": {
      "marker": "rewrite-override"
    },
    "owner": {
      "entity": "<OWNER>"
    }
  }
}
"#,
        },
        Recorded {
            row: "gcs--list.json #41 (gcs-list-token)",
            wire: Wire::Gcs,
            shuffled: r#"{"items":[{"timeFinalized":"<TIME:3>","timeStorageClassUpdated":"<TIME:3>","updated":"<TIME:3>","timeCreated":"<TIME:3>","etag":"<ETAG:1>","crc32c":"<DIGEST>","md5Hash":"<DIGEST>","size":"50","storageClass":"STANDARD","contentType":"application/octet-stream","metageneration":"1","generation":"<GEN:1>","bucket":"<BUCKET>","name":"storage-object/<RUN>/list/gcs/a.txt","mediaLink":"https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fa.txt?generation=<GEN:1>&alt=media","selfLink":"https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fa.txt","id":"<BUCKET>/storage-object/<RUN>/list/gcs/a.txt/<GEN:1>","kind":"storage#object"},{"timeFinalized":"<TIME:3>","timeStorageClassUpdated":"<TIME:3>","updated":"<TIME:3>","timeCreated":"<TIME:3>","etag":"<ETAG:2>","crc32c":"<DIGEST>","md5Hash":"<DIGEST>","size":"50","storageClass":"STANDARD","contentType":"application/octet-stream","metageneration":"1","generation":"<GEN:2>","bucket":"<BUCKET>","name":"storage-object/<RUN>/list/gcs/b.txt","mediaLink":"https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fb.txt?generation=<GEN:2>&alt=media","selfLink":"https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fb.txt","id":"<BUCKET>/storage-object/<RUN>/list/gcs/b.txt/<GEN:2>","kind":"storage#object"}],"prefixes":["storage-object/<RUN>/list/gcs/dir/"],"nextPageToken":"<PAGE_TOKEN>","kind":"storage#objects"}"#,
            overhead: 337,
            expected: r#"{
  "kind": "storage#objects",
  "nextPageToken": "<PAGE_TOKEN>",
  "prefixes": [
    "storage-object/<RUN>/list/gcs/dir/"
  ],
  "items": [
    {
      "kind": "storage#object",
      "id": "<BUCKET>/storage-object/<RUN>/list/gcs/a.txt/<GEN:1>",
      "selfLink": "https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fa.txt",
      "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fa.txt?generation=<GEN:1>&alt=media",
      "name": "storage-object/<RUN>/list/gcs/a.txt",
      "bucket": "<BUCKET>",
      "generation": "<GEN:1>",
      "metageneration": "1",
      "contentType": "application/octet-stream",
      "storageClass": "STANDARD",
      "size": "50",
      "md5Hash": "<DIGEST>",
      "crc32c": "<DIGEST>",
      "etag": "<ETAG:1>",
      "timeCreated": "<TIME:3>",
      "updated": "<TIME:3>",
      "timeStorageClassUpdated": "<TIME:3>",
      "timeFinalized": "<TIME:3>"
    },
    {
      "kind": "storage#object",
      "id": "<BUCKET>/storage-object/<RUN>/list/gcs/b.txt/<GEN:2>",
      "selfLink": "https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fb.txt",
      "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fb.txt?generation=<GEN:2>&alt=media",
      "name": "storage-object/<RUN>/list/gcs/b.txt",
      "bucket": "<BUCKET>",
      "generation": "<GEN:2>",
      "metageneration": "1",
      "contentType": "application/octet-stream",
      "storageClass": "STANDARD",
      "size": "50",
      "md5Hash": "<DIGEST>",
      "crc32c": "<DIGEST>",
      "etag": "<ETAG:2>",
      "timeCreated": "<TIME:3>",
      "updated": "<TIME:3>",
      "timeStorageClassUpdated": "<TIME:3>",
      "timeFinalized": "<TIME:3>"
    }
  ]
}
"#,
        },
        Recorded {
            row: "gcs--metadata.json #7 (gcs-object-cache)",
            wire: Wire::Gcs,
            shuffled: r#"{"metadata":{"remove":"present","marker":"first"},"timeFinalized":"<TIME:3>","timeStorageClassUpdated":"<TIME:3>","updated":"<TIME:3>","timeCreated":"<TIME:3>","etag":"<ETAG:2>","crc32c":"1Kspzg==","cacheControl":"private, max-age=0","md5Hash":"/upD6bdvwxw0vOxAPcxL+A==","size":"5","storageClass":"STANDARD","contentType":"application/octet-stream","metageneration":"2","generation":"<GEN:1>","bucket":"<BUCKET>","name":"storage-object/<RUN>/metadata/gcs.bin","mediaLink":"https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fmetadata%2Fgcs.bin?generation=<GEN:1>&alt=media","selfLink":"https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fmetadata%2Fgcs.bin","id":"<BUCKET>/storage-object/<RUN>/metadata/gcs.bin/<GEN:1>","kind":"storage#object"}"#,
            overhead: 97,
            expected: r#"{
  "kind": "storage#object",
  "id": "<BUCKET>/storage-object/<RUN>/metadata/gcs.bin/<GEN:1>",
  "selfLink": "https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fmetadata%2Fgcs.bin",
  "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Fmetadata%2Fgcs.bin?generation=<GEN:1>&alt=media",
  "name": "storage-object/<RUN>/metadata/gcs.bin",
  "bucket": "<BUCKET>",
  "generation": "<GEN:1>",
  "metageneration": "2",
  "contentType": "application/octet-stream",
  "storageClass": "STANDARD",
  "size": "5",
  "md5Hash": "/upD6bdvwxw0vOxAPcxL+A==",
  "cacheControl": "private, max-age=0",
  "crc32c": "1Kspzg==",
  "etag": "<ETAG:2>",
  "timeCreated": "<TIME:3>",
  "updated": "<TIME:3>",
  "timeStorageClassUpdated": "<TIME:3>",
  "timeFinalized": "<TIME:3>",
  "metadata": {
    "marker": "first",
    "remove": "present"
  }
}
"#,
        },
        Recorded {
            row: "gcs--list.json #35 (gcs-list-prefixes)",
            wire: Wire::Gcs,
            shuffled: r#"{"items":[{"timeFinalized":"<TIME:3>","timeStorageClassUpdated":"<TIME:3>","updated":"<TIME:3>","timeCreated":"<TIME:3>","etag":"<ETAG:1>","crc32c":"<DIGEST>","md5Hash":"<DIGEST>","size":"50","storageClass":"STANDARD","contentType":"application/octet-stream","metageneration":"1","generation":"<GEN:1>","bucket":"<BUCKET>","name":"storage-object/<RUN>/list/gcs/a.txt","mediaLink":"https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fa.txt?generation=<GEN:1>&alt=media","selfLink":"https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fa.txt","id":"<BUCKET>/storage-object/<RUN>/list/gcs/a.txt/<GEN:1>","kind":"storage#object"},{"timeFinalized":"<TIME:3>","timeStorageClassUpdated":"<TIME:3>","updated":"<TIME:3>","timeCreated":"<TIME:3>","etag":"<ETAG:2>","crc32c":"<DIGEST>","md5Hash":"<DIGEST>","size":"50","storageClass":"STANDARD","contentType":"application/octet-stream","metageneration":"1","generation":"<GEN:2>","bucket":"<BUCKET>","name":"storage-object/<RUN>/list/gcs/b.txt","mediaLink":"https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fb.txt?generation=<GEN:2>&alt=media","selfLink":"https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fb.txt","id":"<BUCKET>/storage-object/<RUN>/list/gcs/b.txt/<GEN:2>","kind":"storage#object"},{"timeFinalized":"<TIME:3>","timeStorageClassUpdated":"<TIME:3>","updated":"<TIME:3>","timeCreated":"<TIME:3>","etag":"<ETAG:6>","crc32c":"<DIGEST>","md5Hash":"<DIGEST>","size":"51","storageClass":"STANDARD","contentType":"application/octet-stream","metageneration":"1","generation":"<GEN:6>","bucket":"<BUCKET>","name":"storage-object/<RUN>/list/gcs/zz.txt","mediaLink":"https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fzz.txt?generation=<GEN:6>&alt=media","selfLink":"https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fzz.txt","id":"<BUCKET>/storage-object/<RUN>/list/gcs/zz.txt/<GEN:6>","kind":"storage#object"}],"prefixes":["storage-object/<RUN>/list/gcs/dir/","storage-object/<RUN>/list/gcs/dir2/"],"kind":"storage#objects"}"#,
            overhead: 492,
            expected: r#"{
  "kind": "storage#objects",
  "prefixes": [
    "storage-object/<RUN>/list/gcs/dir/",
    "storage-object/<RUN>/list/gcs/dir2/"
  ],
  "items": [
    {
      "kind": "storage#object",
      "id": "<BUCKET>/storage-object/<RUN>/list/gcs/a.txt/<GEN:1>",
      "selfLink": "https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fa.txt",
      "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fa.txt?generation=<GEN:1>&alt=media",
      "name": "storage-object/<RUN>/list/gcs/a.txt",
      "bucket": "<BUCKET>",
      "generation": "<GEN:1>",
      "metageneration": "1",
      "contentType": "application/octet-stream",
      "storageClass": "STANDARD",
      "size": "50",
      "md5Hash": "<DIGEST>",
      "crc32c": "<DIGEST>",
      "etag": "<ETAG:1>",
      "timeCreated": "<TIME:3>",
      "updated": "<TIME:3>",
      "timeStorageClassUpdated": "<TIME:3>",
      "timeFinalized": "<TIME:3>"
    },
    {
      "kind": "storage#object",
      "id": "<BUCKET>/storage-object/<RUN>/list/gcs/b.txt/<GEN:2>",
      "selfLink": "https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fb.txt",
      "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fb.txt?generation=<GEN:2>&alt=media",
      "name": "storage-object/<RUN>/list/gcs/b.txt",
      "bucket": "<BUCKET>",
      "generation": "<GEN:2>",
      "metageneration": "1",
      "contentType": "application/octet-stream",
      "storageClass": "STANDARD",
      "size": "50",
      "md5Hash": "<DIGEST>",
      "crc32c": "<DIGEST>",
      "etag": "<ETAG:2>",
      "timeCreated": "<TIME:3>",
      "updated": "<TIME:3>",
      "timeStorageClassUpdated": "<TIME:3>",
      "timeFinalized": "<TIME:3>"
    },
    {
      "kind": "storage#object",
      "id": "<BUCKET>/storage-object/<RUN>/list/gcs/zz.txt/<GEN:6>",
      "selfLink": "https://www.googleapis.com/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fzz.txt",
      "mediaLink": "https://storage.googleapis.com/download/storage/v1/b/<BUCKET>/o/storage-object%2F<RUN>%2Flist%2Fgcs%2Fzz.txt?generation=<GEN:6>&alt=media",
      "name": "storage-object/<RUN>/list/gcs/zz.txt",
      "bucket": "<BUCKET>",
      "generation": "<GEN:6>",
      "metageneration": "1",
      "contentType": "application/octet-stream",
      "storageClass": "STANDARD",
      "size": "51",
      "md5Hash": "<DIGEST>",
      "crc32c": "<DIGEST>",
      "etag": "<ETAG:6>",
      "timeCreated": "<TIME:3>",
      "updated": "<TIME:3>",
      "timeStorageClassUpdated": "<TIME:3>",
      "timeFinalized": "<TIME:3>"
    }
  ]
}
"#,
        },
    ];

    #[test]
    fn bodies_take_the_recorded_layout_order_and_length() {
        for row in RECORDED {
            let laid_out = layout_json(row.wire, row.shuffled.as_bytes())
                .unwrap_or_else(|| panic!("{} was not laid out", row.row));
            assert_eq!(
                String::from_utf8(laid_out.clone()).unwrap(),
                row.expected,
                "{}",
                row.row
            );
            // The recorded overhead counts the final line feed the JSON API sends, over the compact
            // form of the same value.
            let compact = serde_json::to_vec(
                &serde_json::from_str::<serde_json::Value>(row.shuffled).unwrap(),
            )
            .unwrap();
            assert_eq!(laid_out.len() - compact.len(), row.overhead, "{}", row.row);
        }
    }

    #[test]
    fn a_body_already_laid_out_is_left_alone() {
        assert_eq!(layout_json(Wire::Gcs, b"{\n  \"kind\": \"x\"\n}\n"), None);
        assert_eq!(layout_json(Wire::Firebase, b"not json"), None);
        assert_eq!(layout_json(Wire::Gcs, b"\"a string\""), None);
    }

    #[test]
    fn user_metadata_keys_never_take_a_recorded_key_s_place() {
        let body = br#"{"metadata":{"name":"x","bucket":"y","a":"z"},"name":"n","bucket":"b"}"#;
        let laid_out = String::from_utf8(layout_json(Wire::Firebase, body).unwrap()).unwrap();
        assert_eq!(
            laid_out,
            "{\n  \"name\": \"n\",\n  \"bucket\": \"b\",\n  \"metadata\": {\n    \"a\": \"z\",\n    \"bucket\": \"y\",\n    \"name\": \"x\"\n  }\n}"
        );
    }

    #[test]
    fn http_dates_are_rfc_9110_imf_fixdate() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_790_825_534), "Thu, 01 Oct 2026 03:32:14 GMT");
        assert_eq!(http_date(1_582_934_400), "Sat, 29 Feb 2020 00:00:00 GMT");
        assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(http_date(-86_400), "Wed, 31 Dec 1969 00:00:00 GMT");
    }

    fn frame(shape: &Shape, response: StorageResponse) -> StorageResponse {
        let (framed, was_framed) = super::frame(shape, response);
        assert!(was_framed || framed.headers.iter().any(|(n, _)| n == "cache-control"));
        framed
    }

    fn shape(wire: Wire, method: &str) -> Shape {
        Shape {
            wire,
            method: method.to_owned(),
            media: false,
            list: false,
            object_read: false,
            end_user_read: false,
            origin: None,
            now_unix_seconds: 1_790_825_534,
        }
    }

    fn response(
        status: u16,
        content_type: &str,
        body: &str,
        extra: &[(&str, &str)],
    ) -> StorageResponse {
        let mut headers = vec![("content-type".to_owned(), content_type.to_owned())];
        // What a handler and the official emulator's conventions put on the answer.
        headers.push(("cache-control".to_owned(), "public".to_owned()));
        headers.push((
            "access-control-allow-origin".to_owned(),
            "http://x".to_owned(),
        ));
        for (name, value) in extra {
            headers.push(((*name).to_owned(), (*value).to_owned()));
        }
        StorageResponse {
            status,
            headers,
            body: bytes::Bytes::from(body.to_owned()),
        }
    }

    fn names(response: &StorageResponse) -> Vec<String> {
        let mut names: Vec<String> = response
            .headers
            .iter()
            .map(|(name, _)| name.clone())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    fn header<'a>(response: &'a StorageResponse, name: &str) -> Option<&'a str> {
        response
            .headers
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }

    const OBJECT: &str = r#"{"kind":"storage#object","etag":"abc","name":"n","bucket":"b"}"#;
    const JSON: &str = "application/json; charset=UTF-8";

    /// Recorded header names, by request shape and status (lean-v5, `auth--admin` and the
    /// recipes named beside each).
    #[test]
    fn json_api_answers_carry_the_recorded_header_sets() {
        // GET /o: `private, max-age=0, must-revalidate, no-transform`, expires now, no pragma.
        let mut list = shape(Wire::Gcs, "GET");
        list.list = true;
        let answered = frame(
            &list,
            response(200, JSON, r#"{"kind":"storage#objects"}"#, &[]),
        );
        assert_eq!(
            names(&answered),
            ["cache-control", "content-type", "expires", "vary"]
        );
        assert_eq!(header(&answered, "cache-control"), Some(READ_CACHE));
        assert_eq!(
            header(&answered, "expires"),
            Some("Thu, 01 Oct 2026 03:32:14 GMT")
        );
        let varies: Vec<&str> = answered
            .headers
            .iter()
            .filter(|(name, _)| name == "vary")
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(varies, ["Origin", "X-Origin"]);
        // GET /o/<name> 200: the same, with the object's `etag` as a header.
        let mut read = shape(Wire::Gcs, "GET");
        read.object_read = true;
        let answered = frame(&read, response(200, JSON, OBJECT, &[]));
        assert_eq!(
            names(&answered),
            ["cache-control", "content-type", "etag", "expires", "vary"]
        );
        assert_eq!(header(&answered, "etag"), Some("abc"));
        // GET /o/<name> 404: the no-cache set with a 1990 expiry and a pragma.
        let answered = frame(&read, response(404, JSON, r#"{"error":{"code":404}}"#, &[]));
        assert_eq!(
            names(&answered),
            ["cache-control", "content-type", "expires", "pragma", "vary"]
        );
        assert_eq!(header(&answered, "cache-control"), Some(NO_CACHE));
        assert_eq!(header(&answered, "expires"), Some(EPOCH_EXPIRES));
        // PATCH 200: the no-cache set and the `etag`; DELETE 204: no `etag`.
        let patch = shape(Wire::Gcs, "PATCH");
        let answered = frame(&patch, response(200, JSON, OBJECT, &[]));
        assert_eq!(
            names(&answered),
            [
                "cache-control",
                "content-type",
                "etag",
                "expires",
                "pragma",
                "vary"
            ]
        );
        let delete = shape(Wire::Gcs, "DELETE");
        let answered = frame(&delete, response(204, "application/json", "", &[]));
        assert_eq!(
            names(&answered),
            ["cache-control", "content-type", "expires", "pragma", "vary"]
        );
        // The 308 of a resumable upload keeps only what its handler gave it.
        let upload = shape(Wire::Gcs, "PUT");
        let answered = frame(
            &upload,
            response(
                308,
                "text/plain; charset=utf-8",
                "",
                &[("range", "bytes=0-1")],
            ),
        );
        assert_eq!(header(&answered, "cache-control"), Some("public"));
    }

    #[test]
    fn json_api_media_answers_carry_the_recorded_header_sets() {
        let mut media = shape(Wire::Gcs, "GET");
        media.object_read = true;
        media.media = true;
        let dynamic = [
            ("content-disposition", "attachment"),
            ("etag", "e"),
            ("last-modified", "Wed, 30 Sep 2026 17:14:46 GMT"),
            ("x-goog-generation", "1"),
            ("x-goog-hash", "crc32c=a"),
            ("x-goog-metageneration", "1"),
            ("x-goog-storage-class", "STANDARD"),
            ("x-goog-stored-content-encoding", "identity"),
            ("x-goog-stored-content-length", "3"),
        ];
        let answered = frame(
            &media,
            response(200, "application/octet-stream", "abc", &dynamic),
        );
        assert_eq!(
            names(&answered),
            [
                "cache-control",
                "content-disposition",
                "content-type",
                "etag",
                "expires",
                "last-modified",
                "pragma",
                "vary",
                "x-goog-generation",
                "x-goog-hash",
                "x-goog-metageneration",
                "x-goog-storage-class",
                "x-goog-stored-content-encoding",
                "x-goog-stored-content-length"
            ]
        );
        assert_eq!(header(&answered, "cache-control"), Some(NO_CACHE));
        // A media 404, 412 or 416 is `private, max-age=0` with an expiry of now and no pragma.
        for status in [404, 412, 416] {
            let answered = frame(
                &media,
                response(status, "text/html; charset=UTF-8", "x", &[]),
            );
            assert_eq!(
                names(&answered),
                ["cache-control", "content-type", "expires", "vary"],
                "{status}"
            );
            assert_eq!(
                header(&answered, "cache-control"),
                Some(PRIVATE),
                "{status}"
            );
        }
        // An origin is reflected on the JSON API.
        let mut with_origin = media.clone();
        with_origin.origin = Some("http://localhost:5173".to_owned());
        let answered = frame(
            &with_origin,
            response(404, "text/html; charset=UTF-8", "x", &[]),
        );
        assert_eq!(
            header(&answered, "access-control-allow-origin"),
            Some("http://localhost:5173")
        );
    }

    #[test]
    fn firebase_answers_carry_the_recorded_header_sets() {
        // JSON on GET and DELETE: CORS, nosniff, `private, max-age=0` and an expiry of now.
        let mut read = shape(Wire::Firebase, "GET");
        read.object_read = true;
        let answered = frame(
            &read,
            response(200, JSON, r#"{"name":"n","bucket":"b"}"#, &[]),
        );
        assert_eq!(
            names(&answered),
            [
                "access-control-allow-origin",
                "access-control-expose-headers",
                "cache-control",
                "content-type",
                "expires",
                "x-content-type-options"
            ]
        );
        assert_eq!(header(&answered, "access-control-allow-origin"), Some("*"));
        assert_eq!(
            header(&answered, "access-control-expose-headers"),
            Some("Content-Range, X-Firebase-Storage-XSRF")
        );
        assert_eq!(header(&answered, "cache-control"), Some(PRIVATE));
        // JSON on POST and PATCH: no cache headers.
        let post = shape(Wire::Firebase, "POST");
        let answered = frame(
            &post,
            response(200, JSON, r#"{"name":"n","bucket":"b"}"#, &[]),
        );
        assert_eq!(
            names(&answered),
            [
                "access-control-allow-origin",
                "access-control-expose-headers",
                "content-type",
                "x-content-type-options"
            ]
        );
        // DELETE 204: no body, no content type, no nosniff.
        let delete = shape(Wire::Firebase, "DELETE");
        let mut no_content = response(204, JSON, "", &[]);
        no_content
            .headers
            .retain(|(name, _)| name != "content-type");
        let answered = frame(&delete, no_content);
        assert_eq!(
            names(&answered),
            [
                "access-control-allow-origin",
                "access-control-expose-headers",
                "cache-control",
                "expires"
            ]
        );
        // The resumable protocol's text answers are not touched.
        let answered = frame(
            &post,
            response(
                200,
                "text/plain; charset=utf-8",
                "",
                &[("x-goog-upload-status", "active")],
            ),
        );
        assert_eq!(header(&answered, "cache-control"), Some("public"));
    }

    #[test]
    fn firebase_media_is_no_cache_for_the_owner_and_private_for_an_end_user() {
        let mut media = shape(Wire::Firebase, "GET");
        media.object_read = true;
        media.media = true;
        let dynamic = [
            ("accept-ranges", "bytes"),
            ("etag", "\"e\""),
            ("last-modified", "Wed, 30 Sep 2026 17:14:46 GMT"),
            ("x-goog-generation", "1"),
        ];
        let owner = frame(
            &media,
            response(200, "application/octet-stream", "abc", &dynamic),
        );
        assert_eq!(
            names(&owner),
            [
                "accept-ranges",
                "cache-control",
                "content-type",
                "etag",
                "expires",
                "last-modified",
                "pragma",
                "x-goog-generation"
            ]
        );
        assert_eq!(header(&owner, "cache-control"), Some(NO_CACHE));
        assert_eq!(header(&owner, "expires"), Some(EPOCH_EXPIRES));
        let mut end_user = media.clone();
        end_user.end_user_read = true;
        let private = frame(
            &end_user,
            response(200, "application/octet-stream", "abc", &dynamic),
        );
        assert_eq!(header(&private, "cache-control"), Some(PRIVATE));
        assert_eq!(header(&private, "pragma"), None);
        assert_eq!(
            header(&private, "expires"),
            Some("Thu, 01 Oct 2026 03:32:14 GMT")
        );
        // The XML 416 is private with an expiry of now.
        let answered = frame(
            &media,
            response(416, "application/xml; charset=UTF-8", "x", &dynamic),
        );
        assert_eq!(header(&answered, "cache-control"), Some(PRIVATE));
        assert_eq!(header(&answered, "pragma"), None);
        assert_eq!(header(&answered, "content-disposition"), None);
    }
}
