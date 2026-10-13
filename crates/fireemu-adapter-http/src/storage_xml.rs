//! The two checks the strict profile makes on the XML API requests that carry their own
//! authorization in the request: the expiry of a signed URL and the signed policy of a form
//! (POST object) upload.
//!
//! Neither check verifies a signature. A signature needs the signing service account's key,
//! which a local run does not have, so a well-formed signature is accepted whatever it is (a
//! documented development default). What production would refuse for reasons that need no key is
//! refused here: an expired URL or policy, a URL signed for a lifetime Cloud Storage does not allow,
//! a form with no policy, and a form that breaks a condition of its own policy.
//!
//! The XML API's answers were not recorded (STORAGE-OBJECT scope decision 3). The refusals follow
//! Cloud Storage's documented XML error codes and are UNRECORDED.

use std::collections::BTreeMap;

use fireemu_core_types::time::LogicalInstant;
use serde_json::Value;

/// The longest lifetime a V4 signed URL may name: seven days.
pub const MAX_SIGNED_URL_SECONDS: u64 = 604_800;

/// What a request's query says about being a signed URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedUrl {
    /// Not a signed URL (no signature in the query).
    Absent,
    /// A signed URL that has not expired.
    Valid,
    /// A signed URL whose lifetime has passed.
    Expired,
    /// A signed URL whose date or lifetime is missing or unreadable, or longer than allowed.
    Invalid(&'static str),
}

/// Judges the signed-URL parameters of a request at `now_unix` seconds. V4 (`X-Goog-Signature`
/// with `X-Goog-Date` and `X-Goog-Expires`) and V2 (`Signature` with `Expires`, a Unix time) are
/// read; parameter names are case-insensitive.
#[must_use]
pub fn check_signed_url(params: &BTreeMap<String, String>, now_unix: i64) -> SignedUrl {
    let lower: BTreeMap<String, &str> = params
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.as_str()))
        .collect();
    if lower.contains_key("x-goog-signature") {
        let Some(date) = lower.get("x-goog-date").and_then(|d| parse_v4_date(d)) else {
            return SignedUrl::Invalid("X-Goog-Date is missing or is not YYYYMMDDTHHMMSSZ.");
        };
        let Some(seconds) = lower
            .get("x-goog-expires")
            .and_then(|e| e.parse::<u64>().ok())
        else {
            return SignedUrl::Invalid("X-Goog-Expires is missing or is not a whole number.");
        };
        if seconds == 0 || seconds > MAX_SIGNED_URL_SECONDS {
            return SignedUrl::Invalid("X-Goog-Expires must be between 1 and 604800 seconds.");
        }
        let expires = date.saturating_add(i64::try_from(seconds).unwrap_or(i64::MAX));
        return if now_unix > expires {
            SignedUrl::Expired
        } else {
            SignedUrl::Valid
        };
    }
    if lower.contains_key("signature") {
        let Some(expires) = lower.get("expires").and_then(|e| e.parse::<i64>().ok()) else {
            return SignedUrl::Invalid("Expires is missing or is not a Unix time.");
        };
        return if now_unix > expires {
            SignedUrl::Expired
        } else {
            SignedUrl::Valid
        };
    }
    SignedUrl::Absent
}

/// `YYYYMMDDTHHMMSSZ` as Unix seconds.
fn parse_v4_date(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let slice = text.get(range)?;
        slice
            .bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| slice.parse().ok())
            .flatten()
    };
    let rfc3339 = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        digits(0..4)?,
        digits(4..6)?,
        digits(6..8)?,
        digits(9..11)?,
        digits(11..13)?,
        digits(13..15)?
    );
    let instant = LogicalInstant::parse_rfc3339(&rfc3339).ok()?;
    i64::try_from(instant.as_nanos().div_euclid(1_000_000_000)).ok()
}

/// Why a form upload's policy was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyFault {
    /// No `policy` field, or no signature with it: Cloud Storage treats the upload as anonymous.
    Unsigned,
    /// The policy is not base64 JSON of the documented shape.
    Malformed(String),
    /// The policy's `expiration` has passed.
    Expired,
    /// A `["eq" | "starts-with" | exact-match]` condition is not met; carries the condition.
    Condition(String),
    /// The file is longer than `content-length-range` allows.
    TooLarge,
    /// The file is shorter than `content-length-range` allows.
    TooSmall,
}

/// Judges a form upload against the policy it carries. `form` holds every non-file field as
/// `(name, value)`, the object name included as `key`; `bucket` is the bucket the form is posted
/// to and `file_len` the file part's length.
pub fn check_post_policy(
    form: &[(String, String)],
    bucket: &str,
    file_len: u64,
    now_unix: i64,
) -> Result<(), PolicyFault> {
    let field = |name: &str| {
        form.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let (Some(policy), true) = (
        field("policy"),
        field("x-goog-signature").is_some() || field("signature").is_some(),
    ) else {
        return Err(PolicyFault::Unsigned);
    };
    let decoded = decode_base64(policy)
        .ok_or_else(|| PolicyFault::Malformed("the policy is not base64".to_owned()))?;
    let document: Value = serde_json::from_slice(&decoded)
        .map_err(|_| PolicyFault::Malformed("the policy is not JSON".to_owned()))?;
    let Some(document) = document.as_object() else {
        return Err(PolicyFault::Malformed(
            "the policy is not an object".to_owned(),
        ));
    };
    let expiration = document
        .get("expiration")
        .and_then(Value::as_str)
        .and_then(|e| LogicalInstant::parse_rfc3339(e).ok())
        .ok_or_else(|| PolicyFault::Malformed("the policy has no valid expiration".to_owned()))?;
    let conditions = document
        .get("conditions")
        .and_then(Value::as_array)
        .ok_or_else(|| PolicyFault::Malformed("the policy has no conditions".to_owned()))?;
    if i128::from(now_unix) > expiration.as_nanos().div_euclid(1_000_000_000) {
        return Err(PolicyFault::Expired);
    }
    // The value a condition compares: the bucket is the one posted to, every other field is a
    // form field. A field the form does not carry reads as empty.
    let value_of = |name: &str| -> String {
        let name = name.strip_prefix('$').unwrap_or(name);
        if name.eq_ignore_ascii_case("bucket") {
            bucket.to_owned()
        } else {
            field(name).unwrap_or_default().to_owned()
        }
    };
    for condition in conditions {
        match condition {
            Value::Object(map) => {
                for (name, expected) in map {
                    let expected = expected.as_str().ok_or_else(|| {
                        PolicyFault::Malformed(format!("condition {name} is not a string"))
                    })?;
                    if value_of(name) != expected {
                        return Err(PolicyFault::Condition(condition.to_string()));
                    }
                }
            }
            Value::Array(parts) => match parts.as_slice() {
                [Value::String(op), Value::String(name), Value::String(expected)]
                    if op.eq_ignore_ascii_case("eq") =>
                {
                    if value_of(name) != *expected {
                        return Err(PolicyFault::Condition(condition.to_string()));
                    }
                }
                [Value::String(op), Value::String(name), Value::String(prefix)]
                    if op.eq_ignore_ascii_case("starts-with") =>
                {
                    if !value_of(name).starts_with(prefix.as_str()) {
                        return Err(PolicyFault::Condition(condition.to_string()));
                    }
                }
                [Value::String(op), min, max]
                    if op.eq_ignore_ascii_case("content-length-range") =>
                {
                    let (Some(min), Some(max)) = (min.as_u64(), max.as_u64()) else {
                        return Err(PolicyFault::Malformed(
                            "content-length-range takes two whole numbers".to_owned(),
                        ));
                    };
                    if file_len > max {
                        return Err(PolicyFault::TooLarge);
                    }
                    if file_len < min {
                        return Err(PolicyFault::TooSmall);
                    }
                }
                _ => {
                    return Err(PolicyFault::Malformed(format!(
                        "unknown condition {condition}"
                    )));
                }
            },
            _ => {
                return Err(PolicyFault::Malformed(format!(
                    "unknown condition {condition}"
                )));
            }
        }
    }
    Ok(())
}

/// Standard or URL-safe base64, padded or not.
fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in text.trim().bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xFF).ok()?);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::needless_pass_by_value)]
    use super::*;
    use proptest::prelude::*;

    fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    // 2026-08-29T12:01:00Z
    const NOW: i64 = 1_788_004_860;

    #[test]
    fn a_request_with_no_signature_is_not_a_signed_url() {
        assert_eq!(check_signed_url(&params(&[]), NOW), SignedUrl::Absent);
        assert_eq!(
            check_signed_url(&params(&[("X-Goog-Expires", "10"), ("alt", "media")]), NOW),
            SignedUrl::Absent,
            "an expiry without a signature is nothing"
        );
    }

    #[test]
    fn a_v4_url_is_valid_through_its_last_second_and_expired_after() {
        let url = |date: &str, expires: &str| {
            params(&[
                ("X-Goog-Algorithm", "GOOG4-RSA-SHA256"),
                ("X-Goog-Date", date),
                ("X-Goog-Expires", expires),
                ("X-Goog-Signature", "abcdef"),
            ])
        };
        // Signed at 12:00:00Z for 60 seconds: expires at 12:01:00Z.
        assert_eq!(
            check_signed_url(&url("20260829T120000Z", "60"), NOW),
            SignedUrl::Valid
        );
        assert_eq!(
            check_signed_url(&url("20260829T120000Z", "59"), NOW),
            SignedUrl::Expired
        );
        assert_eq!(
            check_signed_url(&url("20260829T120000Z", "3600"), NOW),
            SignedUrl::Valid
        );
        assert_eq!(
            check_signed_url(&url("20260829T100000Z", "60"), NOW),
            SignedUrl::Expired
        );
    }

    #[test]
    fn a_v4_url_with_an_unreadable_date_or_lifetime_is_invalid() {
        let base = |date: &str, expires: &str| {
            params(&[
                ("X-Goog-Date", date),
                ("X-Goog-Expires", expires),
                ("X-Goog-Signature", "abcdef"),
            ])
        };
        for (date, expires) in [
            ("20260829T120000", "60"),
            ("2026-08-29T12:00:00Z", "60"),
            ("2026082XT120000Z", "60"),
            ("20260829T120000Z", "soon"),
            ("20260829T120000Z", "0"),
            ("20260829T120000Z", "604801"),
            ("20260829T120000Z", "-5"),
        ] {
            assert!(
                matches!(
                    check_signed_url(&base(date, expires), NOW),
                    SignedUrl::Invalid(_)
                ),
                "{date} {expires}"
            );
        }
        assert!(matches!(
            check_signed_url(&params(&[("X-Goog-Signature", "abcdef")]), NOW),
            SignedUrl::Invalid(_)
        ));
        // The longest allowed lifetime is accepted.
        assert_eq!(
            check_signed_url(&base("20260829T120000Z", "604800"), NOW),
            SignedUrl::Valid
        );
    }

    #[test]
    fn a_v2_url_expires_at_its_unix_time() {
        let url = |expires: i64| {
            params(&[
                ("GoogleAccessId", "sa@demo-app.iam.gserviceaccount.com"),
                ("Expires", &expires.to_string()),
                ("Signature", "abc%2Fdef"),
            ])
        };
        assert_eq!(check_signed_url(&url(NOW), NOW), SignedUrl::Valid);
        assert_eq!(check_signed_url(&url(NOW - 1), NOW), SignedUrl::Expired);
        assert!(matches!(
            check_signed_url(&params(&[("Signature", "abc")]), NOW),
            SignedUrl::Invalid(_)
        ));
        assert!(matches!(
            check_signed_url(
                &params(&[("Signature", "abc"), ("Expires", "tomorrow")]),
                NOW
            ),
            SignedUrl::Invalid(_)
        ));
    }

    proptest! {
        /// A V4 URL is expired exactly when the clock has passed `date + lifetime`.
        #[test]
        fn a_v4_url_is_expired_exactly_when_the_clock_passes_its_lifetime(
            offset in -100_000i64..100_000,
            lifetime in 1u64..=604_800,
        ) {
            let signed_at = NOW + offset;
            let (year, month, day) = fireemu_core_types::time::civil_from_days(signed_at.div_euclid(86_400));
            let secs = signed_at.rem_euclid(86_400);
            let date = format!(
                "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
                secs / 3600,
                secs % 3600 / 60,
                secs % 60
            );
            let verdict = check_signed_url(
                &params(&[
                    ("X-Goog-Date", &date),
                    ("X-Goog-Expires", &lifetime.to_string()),
                    ("X-Goog-Signature", "sig"),
                ]),
                NOW,
            );
            let expires = signed_at + i64::try_from(lifetime).unwrap();
            prop_assert_eq!(verdict == SignedUrl::Expired, NOW > expires);
            prop_assert_eq!(verdict == SignedUrl::Valid, NOW <= expires);
        }
    }

    fn b64(text: &str) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in text.as_bytes().chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..=chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            }
            for _ in chunk.len()..3 {
                out.push('=');
            }
        }
        out
    }

    fn form(policy: &Value, extra: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut fields = vec![
            ("key".to_owned(), "up/a.txt".to_owned()),
            ("policy".to_owned(), b64(&policy.to_string())),
            ("x-goog-signature".to_owned(), "abcdef".to_owned()),
        ];
        fields.extend(
            extra
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
        );
        fields
    }

    fn policy(conditions: Value) -> Value {
        serde_json::json!({"expiration": "2026-08-29T13:00:00Z", "conditions": conditions})
    }

    #[test]
    fn a_form_without_a_policy_or_a_signature_is_unsigned() {
        let bare = vec![("key".to_owned(), "a.txt".to_owned())];
        assert_eq!(
            check_post_policy(&bare, "bucket-one", 3, NOW),
            Err(PolicyFault::Unsigned)
        );
        let mut no_signature = form(&policy(serde_json::json!([])), &[]);
        no_signature.retain(|(k, _)| k != "x-goog-signature");
        assert_eq!(
            check_post_policy(&no_signature, "bucket-one", 3, NOW),
            Err(PolicyFault::Unsigned)
        );
        let mut v2 = form(&policy(serde_json::json!([])), &[("signature", "abc")]);
        v2.retain(|(k, _)| k != "x-goog-signature");
        assert_eq!(check_post_policy(&v2, "bucket-one", 3, NOW), Ok(()));
    }

    #[test]
    fn a_policy_with_every_condition_met_is_accepted() {
        let conditions = serde_json::json!([
            {"bucket": "bucket-one"},
            ["eq", "$key", "up/a.txt"],
            ["starts-with", "$key", "up/"],
            ["starts-with", "$Content-Type", ""],
            {"x-goog-meta-owner": "alice"},
            ["content-length-range", 0, 10],
        ]);
        let fields = form(&policy(conditions), &[("x-goog-meta-owner", "alice")]);
        assert_eq!(check_post_policy(&fields, "bucket-one", 10, NOW), Ok(()));
    }

    #[test]
    fn each_broken_condition_is_named() {
        let broken = |conditions: Value, extra: &[(&str, &str)], len: u64| {
            check_post_policy(&form(&policy(conditions), extra), "bucket-one", len, NOW)
        };
        assert!(matches!(
            broken(serde_json::json!([{"bucket": "other-bucket"}]), &[], 1),
            Err(PolicyFault::Condition(_))
        ));
        assert!(matches!(
            broken(serde_json::json!([["eq", "$key", "up/b.txt"]]), &[], 1),
            Err(PolicyFault::Condition(_))
        ));
        assert!(matches!(
            broken(
                serde_json::json!([["starts-with", "$key", "down/"]]),
                &[],
                1
            ),
            Err(PolicyFault::Condition(_))
        ));
        assert!(
            matches!(
                broken(serde_json::json!([{"x-goog-meta-owner": "alice"}]), &[], 1),
                Err(PolicyFault::Condition(_))
            ),
            "a field the form lacks reads as empty"
        );
        assert_eq!(
            broken(serde_json::json!([["content-length-range", 2, 4]]), &[], 5),
            Err(PolicyFault::TooLarge)
        );
        assert_eq!(
            broken(serde_json::json!([["content-length-range", 2, 4]]), &[], 1),
            Err(PolicyFault::TooSmall)
        );
        assert_eq!(
            broken(serde_json::json!([["content-length-range", 2, 4]]), &[], 4),
            Ok(())
        );
    }

    #[test]
    fn an_expired_or_unreadable_policy_is_refused() {
        let expired = serde_json::json!({"expiration": "2026-08-29T12:00:59Z", "conditions": []});
        assert_eq!(
            check_post_policy(&form(&expired, &[]), "bucket-one", 1, NOW),
            Err(PolicyFault::Expired)
        );
        let on_the_second =
            serde_json::json!({"expiration": "2026-08-29T12:01:00Z", "conditions": []});
        assert_eq!(
            check_post_policy(&form(&on_the_second, &[]), "bucket-one", 1, NOW),
            Ok(())
        );
        for bad in [
            serde_json::json!({"conditions": []}),
            serde_json::json!({"expiration": "soon", "conditions": []}),
            serde_json::json!({"expiration": "2026-08-29T13:00:00Z"}),
            serde_json::json!({"expiration": "2026-08-29T13:00:00Z", "conditions": [["between", "$key", "a"]]}),
            serde_json::json!({"expiration": "2026-08-29T13:00:00Z", "conditions": [7]}),
            serde_json::json!({"expiration": "2026-08-29T13:00:00Z", "conditions": [["content-length-range", "a", 5]]}),
            serde_json::json!([]),
        ] {
            assert!(
                matches!(
                    check_post_policy(&form(&bad, &[]), "bucket-one", 1, NOW),
                    Err(PolicyFault::Malformed(_))
                ),
                "{bad}"
            );
        }
        let mut not_base64 = form(&policy(serde_json::json!([])), &[]);
        not_base64[1].1 = "***".to_owned();
        assert!(matches!(
            check_post_policy(&not_base64, "bucket-one", 1, NOW),
            Err(PolicyFault::Malformed(_))
        ));
    }

    #[test]
    fn a_v4_date_needs_its_t_and_z_markers() {
        for date in [
            "20260829X120000Z",
            "20260829T120000X",
            "20260829t120000Z",
            "20260829T120000z",
        ] {
            assert!(
                matches!(
                    check_signed_url(
                        &params(&[
                            ("X-Goog-Date", date),
                            ("X-Goog-Expires", "60"),
                            ("X-Goog-Signature", "abc"),
                        ]),
                        NOW
                    ),
                    SignedUrl::Invalid(_)
                ),
                "{date}"
            );
        }
    }

    #[test]
    fn an_unknown_three_part_condition_is_malformed_whatever_its_parts() {
        for condition in [
            serde_json::json!(["frobnicate", 1, 2]),
            serde_json::json!(["between", 0, 10]),
        ] {
            assert!(matches!(
                check_post_policy(
                    &form(&policy(serde_json::json!([condition])), &[]),
                    "bucket-one",
                    1,
                    NOW
                ),
                Err(PolicyFault::Malformed(_))
            ));
        }
    }

    #[test]
    fn a_policy_is_read_in_either_base64_alphabet_padded_or_not() {
        // "???" encodes to "Pz8/" and ">>>" to "Pj4+": both alphabets' special characters.
        let document = serde_json::json!({
            "expiration": "2026-08-29T13:00:00Z",
            "conditions": [{"x-goog-meta-note": "???>>>???>>>"}]
        })
        .to_string();
        let standard = b64(&document);
        assert!(
            standard.contains('+') || standard.contains('/'),
            "{standard}"
        );
        let url_safe = standard.replace('+', "-").replace('/', "_");
        let unpadded = standard.trim_end_matches('=').to_owned();
        for encoded in [standard.clone(), url_safe, unpadded] {
            let fields = vec![
                ("key".to_owned(), "a".to_owned()),
                ("policy".to_owned(), encoded.clone()),
                ("x-goog-signature".to_owned(), "abc".to_owned()),
                ("x-goog-meta-note".to_owned(), "???>>>???>>>".to_owned()),
            ];
            assert_eq!(
                check_post_policy(&fields, "bucket-one", 1, NOW),
                Ok(()),
                "{encoded}"
            );
        }
    }

    proptest! {
        /// `content-length-range` admits exactly the lengths from its minimum to its maximum.
        #[test]
        fn content_length_range_admits_exactly_its_bounds(
            min in 0u64..50,
            span in 0u64..50,
            len in 0u64..120,
        ) {
            let max = min + span;
            let verdict = check_post_policy(
                &form(&policy(serde_json::json!([["content-length-range", min, max]])), &[]),
                "bucket-one",
                len,
                NOW,
            );
            if len > max {
                prop_assert_eq!(verdict, Err(PolicyFault::TooLarge));
            } else if len < min {
                prop_assert_eq!(verdict, Err(PolicyFault::TooSmall));
            } else {
                prop_assert_eq!(verdict, Ok(()));
            }
        }

        /// `starts-with` admits exactly the values with the prefix.
        #[test]
        fn starts_with_admits_exactly_the_prefixed_values(
            prefix in "[a-z/]{0,6}",
            key in "[a-z/]{1,10}",
        ) {
            let mut fields = form(&policy(serde_json::json!([["starts-with", "$key", prefix]])), &[]);
            fields[0].1 = key.clone();
            prop_assert_eq!(
                check_post_policy(&fields, "bucket-one", 1, NOW).is_ok(),
                key.starts_with(&prefix)
            );
        }
    }
}
