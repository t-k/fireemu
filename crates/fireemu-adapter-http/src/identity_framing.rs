//! The strict profile's framing of the Identity Toolkit answers the STORAGE-OBJECT recordings
//! cover (lean-v5, 2026-09-30 and 2026-10-01): a 200 from `accounts:signUp`, `accounts:lookup`
//! (both spellings) and `projects/{p}/accounts:delete`.
//!
//! Production sends these with `no-cache` headers, `X-Frame-Options`, `X-XSS-Protection`, a
//! three-valued `Vary` and, when the request accepts it, a gzip body; no CORS headers unless the
//! request carried an `Origin`. The body is two-space JSON with a final line feed (the recorded
//! layout overhead of 6 and 176 bytes), and the members come in the recorded order, not the
//! alphabetical order a map gives them. Other routes, other statuses and the emulator profile keep
//! the official emulator's framing.

use bytes::Bytes;
use http_body_util::Full;
use hyper::Response;
use serde_json::Value;

/// Whether `path` (with its query, host prefix and all) is one of the recorded POST routes.
#[must_use]
pub fn is_recorded_route(method: &str, path_and_query: &str) -> bool {
    if method != "POST" {
        return false;
    }
    let path = path_and_query.split('?').next().unwrap_or_default();
    let Some((_, tail)) = path.rsplit_once("/v1/") else {
        return false;
    };
    match tail.split('/').collect::<Vec<_>>().as_slice() {
        ["accounts:signUp" | "accounts:lookup"] => true,
        ["projects", project, "accounts:lookup" | "accounts:delete"] => !project.is_empty(),
        _ => false,
    }
}

/// The recorded member orders: the response itself, a user and a provider entry. Members the
/// recordings did not show follow these, alphabetically.
const RESPONSE_ORDER: &[&str] = &[
    "kind",
    "idToken",
    "email",
    "refreshToken",
    "expiresIn",
    "localId",
    "users",
];
const USER_ORDER: &[&str] = &[
    "localId",
    "email",
    "passwordHash",
    "emailVerified",
    "passwordUpdatedAt",
    "providerUserInfo",
    "validSince",
    "lastLoginAt",
    "createdAt",
    "lastRefreshAt",
];
const PROVIDER_ORDER: &[&str] = &["providerId", "federatedId", "email", "rawId"];

/// The body in production's layout.
#[must_use]
pub fn layout(body: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write(&mut out, body, 0, Some(RESPONSE_ORDER), &[]);
    out.push(b'\n');
    out
}

fn write(out: &mut Vec<u8>, value: &Value, indent: usize, order: Option<&[&str]>, path: &[&str]) {
    match value {
        Value::Object(map) if map.is_empty() => out.extend_from_slice(b"{}"),
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            if let Some(order) = order {
                entries.sort_by_key(|(key, _)| {
                    order
                        .iter()
                        .position(|known| known == key)
                        .unwrap_or(order.len())
                });
            }
            out.extend_from_slice(b"{\n");
            for (index, (key, member)) in entries.iter().enumerate() {
                out.extend_from_slice("  ".repeat(indent + 1).as_bytes());
                out.extend_from_slice(
                    serde_json::to_string(key.as_str())
                        .unwrap_or_default()
                        .as_bytes(),
                );
                out.extend_from_slice(b": ");
                let mut deeper = path.to_vec();
                deeper.push(key.as_str());
                write(out, member, indent + 1, member_order(&deeper), &deeper);
                out.extend_from_slice(if index + 1 == entries.len() {
                    b"\n"
                } else {
                    b",\n"
                });
            }
            out.extend_from_slice("  ".repeat(indent).as_bytes());
            out.push(b'}');
        }
        Value::Array(items) if items.is_empty() => out.extend_from_slice(b"[]"),
        Value::Array(items) => {
            out.extend_from_slice(b"[\n");
            for (index, item) in items.iter().enumerate() {
                out.extend_from_slice("  ".repeat(indent + 1).as_bytes());
                write(out, item, indent + 1, order, path);
                out.extend_from_slice(if index + 1 == items.len() {
                    b"\n"
                } else {
                    b",\n"
                });
            }
            out.extend_from_slice("  ".repeat(indent).as_bytes());
            out.push(b']');
        }
        scalar => {
            out.extend_from_slice(serde_json::to_string(scalar).unwrap_or_default().as_bytes());
        }
    }
}

/// The recorded order for the object found at `path` (the keys leading to it).
fn member_order(path: &[&str]) -> Option<&'static [&'static str]> {
    match path {
        ["users"] => Some(USER_ORDER),
        ["users", "providerUserInfo"] => Some(PROVIDER_ORDER),
        _ => None,
    }
}

/// Whether the request's `Accept-Encoding` admits gzip (`gzip` or `*` with a non-zero quality).
#[must_use]
pub fn accepts_gzip(accept_encoding: Option<&str>) -> bool {
    accept_encoding.is_some_and(|value| {
        value.split(',').any(|item| {
            let mut parts = item.split(';');
            let coding = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            let refused = parts.any(|parameter| {
                parameter
                    .trim()
                    .strip_prefix("q=")
                    .is_some_and(|quality| quality.trim().parse::<f64>().is_ok_and(|q| q <= 0.0))
            });
            (coding == "gzip" || coding == "*") && !refused
        })
    })
}

/// `data` as a gzip stream of stored (uncompressed) deflate blocks: any gzip decoder reads it, and
/// it needs no compressor. The bytes of production's compressed stream are not reproduced.
#[must_use]
pub fn gzip_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff];
    let mut blocks = data.chunks(65_535).peekable();
    if blocks.peek().is_none() {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
    }
    while let Some(block) = blocks.next() {
        let length = u16::try_from(block.len()).unwrap_or(u16::MAX);
        out.push(u8::from(blocks.peek().is_none()));
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&(!length).to_le_bytes());
        out.extend_from_slice(block);
    }
    out.extend_from_slice(&crc32(data).to_le_bytes());
    out.extend_from_slice(
        &u32::try_from(data.len() & 0xffff_ffff)
            .unwrap_or(0)
            .to_le_bytes(),
    );
    out
}

/// CRC-32 (IEEE 802.3), bitwise.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// The answer as production frames it: the recorded headers, the body laid out and, when the
/// request accepts it, gzipped. An `Origin` is reflected (not recorded: the recordings sent none).
#[must_use]
pub fn respond(
    body: &Value,
    origin: Option<&str>,
    accept_encoding: Option<&str>,
) -> Response<Full<Bytes>> {
    let text = layout(body);
    let gzip = accepts_gzip(accept_encoding);
    let mut builder = Response::builder()
        .status(200)
        .header(
            "cache-control",
            "no-cache, no-store, max-age=0, must-revalidate",
        )
        .header("pragma", "no-cache")
        .header("expires", "Mon, 01 Jan 1990 00:00:00 GMT")
        .header("content-type", "application/json; charset=UTF-8")
        .header("vary", "Origin")
        .header("vary", "X-Origin")
        .header("vary", "Referer")
        .header("x-content-type-options", "nosniff")
        .header("x-frame-options", "SAMEORIGIN")
        .header("x-xss-protection", "0");
    if gzip {
        builder = builder.header("content-encoding", "gzip");
    }
    if let Some(origin) = origin {
        builder = builder
            .header("access-control-allow-origin", origin)
            .header("access-control-allow-credentials", "true");
    }
    let payload = if gzip { gzip_stored(&text) } else { text };
    builder
        .body(Full::new(Bytes::from(payload)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_the_recorded_routes_are_framed() {
        for path in [
            "/identitytoolkit.googleapis.com/v1/accounts:signUp?key=k",
            "/v1/accounts:lookup",
            "/identitytoolkit.googleapis.com/v1/projects/p/accounts:lookup",
            "/v1/projects/demo-x/accounts:delete",
        ] {
            assert!(is_recorded_route("POST", path), "{path}");
            assert!(!is_recorded_route("GET", path), "{path}");
        }
        for path in [
            "/v1/accounts:signInWithPassword",
            "/v1/accounts:delete",
            "/v1/projects//accounts:lookup",
            "/v1/projects/p/accounts:update",
            "/v1/projects/p/tenants/t/accounts:lookup",
            "/v2/accounts:lookup",
            "/accounts:lookup",
        ] {
            assert!(!is_recorded_route("POST", path), "{path}");
        }
    }

    /// Recorded, lean-v5: the bodies of three rows with the layout overhead the recorder
    /// measured (6, 176 and 6 bytes), in the recorded member order, from an alphabetical input.
    #[test]
    fn recorded_bodies_take_the_recorded_order_and_layout() {
        let lookup = json!({
            "kind": "identitytoolkit#GetAccountInfoResponse",
            "users": [{
                "createdAt": "<EPOCH:string:13>",
                "email": "storage-object@example.com",
                "emailVerified": false,
                "lastLoginAt": "<EPOCH:string:13>",
                "lastRefreshAt": "<TIME:3>",
                "localId": "<UID>",
                "passwordHash": "UkVEQUNURUQ=",
                "passwordUpdatedAt": "<EPOCH:number:13>",
                "providerUserInfo": [{
                    "email": "storage-object@example.com",
                    "federatedId": "storage-object@example.com",
                    "providerId": "password",
                    "rawId": "storage-object@example.com"
                }],
                "validSince": "<EPOCH:string:10>"
            }]
        });
        let text = String::from_utf8(layout(&lookup)).unwrap();
        let compact = serde_json::to_string(&lookup).unwrap();
        assert_eq!(text.len() - compact.len(), 176);
        let positions: Vec<usize> = [
            "\"localId\"",
            "\"email\"",
            "\"passwordHash\"",
            "\"emailVerified\"",
            "\"passwordUpdatedAt\"",
            "\"providerUserInfo\"",
            "\"providerId\"",
            "\"federatedId\"",
            "\"rawId\"",
            "\"validSince\"",
            "\"lastLoginAt\"",
            "\"createdAt\"",
            "\"lastRefreshAt\"",
        ]
        .iter()
        .map(|key| text.find(key).unwrap())
        .collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "{text}");
        for (body, overhead) in [
            (json!({"kind": "identitytoolkit#GetAccountInfoResponse"}), 6),
            (json!({"kind": "identitytoolkit#DeleteAccountResponse"}), 6),
        ] {
            let laid_out = String::from_utf8(layout(&body)).unwrap();
            assert_eq!(
                laid_out.len() - serde_json::to_string(&body).unwrap().len(),
                overhead
            );
            assert!(laid_out.ends_with("\n}\n"));
        }
        let sign_up = json!({
            "email": "storage-object@example.com", "expiresIn": "3600", "idToken": "<JWT>",
            "kind": "identitytoolkit#SignupNewUserResponse", "localId": "<UID>", "refreshToken": "<UID>"
        });
        let text = String::from_utf8(layout(&sign_up)).unwrap();
        assert_eq!(
            text,
            "{\n  \"kind\": \"identitytoolkit#SignupNewUserResponse\",\n  \"idToken\": \"<JWT>\",\n  \"email\": \"storage-object@example.com\",\n  \"refreshToken\": \"<UID>\",\n  \"expiresIn\": \"3600\",\n  \"localId\": \"<UID>\"\n}\n"
        );
    }

    #[test]
    fn unrecorded_members_follow_the_recorded_ones_alphabetically() {
        let body = json!({"users": [{"displayName": "d", "localId": "u", "customAttributes": "{}", "email": "e"}], "kind": "k", "zz": 1, "aa": 2});
        let text = String::from_utf8(layout(&body)).unwrap();
        let order: Vec<&str> = text
            .lines()
            .filter_map(|line| {
                line.trim()
                    .split_once("\": ")
                    .map(|(key, _)| key.trim_start_matches('"'))
            })
            .collect();
        assert_eq!(
            order,
            [
                "kind",
                "users",
                "localId",
                "email",
                "customAttributes",
                "displayName",
                "aa",
                "zz"
            ]
        );
    }

    fn hex(bytes: &[u8]) -> String {
        fireemu_core_storage::hash::hex(bytes)
    }

    #[test]
    fn gzip_is_read_by_any_decoder_and_chosen_by_accept_encoding() {
        // Python's gzip.decompress reads these bytes back to "" and "hello".
        assert_eq!(
            hex(&gzip_stored(b"")),
            "1f8b08000000000000ff010000ffff0000000000000000"
        );
        assert_eq!(
            hex(&gzip_stored(b"hello")),
            "1f8b08000000000000ff010500faff68656c6c6f86a6103605000000"
        );
        // More than one block: the first is not final and the sizes add up.
        let big = vec![7u8; 70_000];
        let stream = gzip_stored(&big);
        assert_eq!(stream[10], 0x00);
        assert_eq!(&stream[11..13], &65_535u16.to_le_bytes());
        assert_eq!(stream.len(), 10 + 5 + 65_535 + 5 + (70_000 - 65_535) + 8);
        assert_eq!(stream[10 + 5 + 65_535], 0x01);
        for (header, expected) in [
            (None, false),
            (Some("identity"), false),
            (Some("gzip"), true),
            (Some("deflate, GZIP;q=0.5"), true),
            (Some("gzip;q=0"), false),
            (Some("*"), true),
            (Some("br, deflate"), false),
        ] {
            assert_eq!(accepts_gzip(header), expected, "{header:?}");
        }
    }

    #[test]
    fn the_answer_carries_the_recorded_headers() {
        let response = respond(&json!({"kind": "k"}), None, Some("gzip"));
        let names: Vec<String> = response
            .headers()
            .keys()
            .map(|name| name.as_str().to_owned())
            .collect();
        for expected in [
            "cache-control",
            "content-encoding",
            "content-type",
            "expires",
            "pragma",
            "vary",
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
        ] {
            assert!(names.iter().any(|name| name == expected), "{expected}");
        }
        assert!(!names.iter().any(|name| name.starts_with("access-control-")));
        assert_eq!(response.headers().get_all("vary").iter().count(), 3);
        let plain = respond(&json!({"kind": "k"}), Some("http://localhost:5173"), None);
        assert!(plain.headers().get("content-encoding").is_none());
        assert_eq!(
            plain.headers().get("access-control-allow-origin").unwrap(),
            "http://localhost:5173"
        );
    }

    mod properties {
        use super::super::*;
        use proptest::prelude::*;

        /// An independent CRC-32 (the table-driven form).
        fn table_crc32(data: &[u8]) -> u32 {
            let table: Vec<u32> = (0..256u32)
                .map(|index| {
                    (0..8).fold(index, |value, _| {
                        if value & 1 == 1 {
                            0xedb8_8320 ^ (value >> 1)
                        } else {
                            value >> 1
                        }
                    })
                })
                .collect();
            !data.iter().fold(0xffff_ffff_u32, |crc, &byte| {
                table[usize::try_from((crc ^ u32::from(byte)) & 0xff).unwrap()] ^ (crc >> 8)
            })
        }

        /// Reads a stream of stored blocks back (the only kind written).
        fn gunzip_stored(stream: &[u8]) -> Vec<u8> {
            assert_eq!(
                &stream[..10],
                &[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xff]
            );
            let mut at = 10;
            let mut out = Vec::new();
            loop {
                let last = stream[at] == 1;
                let length = usize::from(u16::from_le_bytes([stream[at + 1], stream[at + 2]]));
                let complement = u16::from_le_bytes([stream[at + 3], stream[at + 4]]);
                assert_eq!(complement, !u16::try_from(length).unwrap());
                out.extend_from_slice(&stream[at + 5..at + 5 + length]);
                at += 5 + length;
                if last {
                    break;
                }
            }
            let crc = u32::from_le_bytes(stream[at..at + 4].try_into().unwrap());
            let size = u32::from_le_bytes(stream[at + 4..at + 8].try_into().unwrap());
            assert_eq!(stream.len(), at + 8);
            assert_eq!(crc, table_crc32(&out));
            assert_eq!(usize::try_from(size).unwrap(), out.len());
            out
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(48))]

            /// Whatever the data, the stream is well formed: blocks of at most 65,535 bytes, a
            /// final one marked, the checksum and size right, and the bytes come back.
            #[test]
            fn gzip_round_trips_through_an_independent_reader(
                data in proptest::collection::vec(any::<u8>(), 0..140_000),
            ) {
                prop_assert_eq!(gunzip_stored(&gzip_stored(&data)), data);
            }
        }

        proptest! {
            /// Laying a body out never changes its value.
            #[test]
            fn layout_preserves_the_value(
                members in proptest::collection::btree_map(
                    proptest::sample::select(&["kind", "users", "localId", "email", "zz", "aa", "idToken"][..]),
                    prop_oneof![
                        any::<bool>().prop_map(Value::Bool),
                        "[a-z ]{0,8}".prop_map(Value::String),
                        proptest::collection::vec("[a-z]{0,3}".prop_map(Value::String), 0..3).prop_map(Value::Array),
                    ],
                    0..=7,
                ),
            ) {
                let value = Value::Object(members.into_iter().map(|(k, v)| (k.to_owned(), v)).collect());
                let text = layout(&value);
                prop_assert_eq!(serde_json::from_slice::<Value>(&text).unwrap(), value);
                let closes_with_a_line_feed = text.last() == Some(&b'\n');
                prop_assert!(closes_with_a_line_feed);
            }
        }
    }
}
