//! Production-shaped error statuses that carry `google.rpc` error details, and their REST JSON
//! rendering.
//!
//! Production Firestore attaches `google.rpc.ErrorInfo` and `google.rpc.Help` details to some
//! refusals. Over gRPC they travel in the `grpc-status-details-bin` trailer as an encoded
//! `google.rpc.Status`; over REST they appear as the `details` array of the error envelope.

use core::fmt::Write as _;
use fireemu_proto_firestore::google::rpc::Status as RpcStatus;

use prost::Message;
use serde_json::{json, Value};
use tonic::{Code, Status};

const ERROR_INFO: &str = "type.googleapis.com/google.rpc.ErrorInfo";
const HELP: &str = "type.googleapis.com/google.rpc.Help";
const BAD_REQUEST: &str = "type.googleapis.com/google.rpc.BadRequest";

/// `google.rpc.ErrorInfo`.
#[derive(Clone, PartialEq, Message)]
struct ErrorInfo {
    #[prost(string, tag = "1")]
    reason: String,
    #[prost(string, tag = "2")]
    domain: String,
    #[prost(btree_map = "string, string", tag = "3")]
    metadata: std::collections::BTreeMap<String, String>,
}

/// `google.rpc.Help.Link`.
#[derive(Clone, PartialEq, Message)]
struct Link {
    #[prost(string, tag = "1")]
    description: String,
    #[prost(string, tag = "2")]
    url: String,
}

/// `google.rpc.BadRequest.FieldViolation`.
#[derive(Clone, PartialEq, Message)]
struct FieldViolation {
    #[prost(string, tag = "1")]
    field: String,
    #[prost(string, tag = "2")]
    description: String,
}

/// `google.rpc.BadRequest`.
#[derive(Clone, PartialEq, Message)]
struct BadRequest {
    #[prost(message, repeated, tag = "1")]
    field_violations: Vec<FieldViolation>,
}

/// `google.rpc.Help`.
#[derive(Clone, PartialEq, Message)]
struct Help {
    #[prost(message, repeated, tag = "1")]
    links: Vec<Link>,
}

fn any(type_url: &str, message: &impl Message) -> prost_types::Any {
    prost_types::Any {
        type_url: type_url.to_owned(),
        value: message.encode_to_vec(),
    }
}

fn with_details(code: Code, message: &str, details: Vec<prost_types::Any>) -> Status {
    let status = RpcStatus {
        code: code as i32,
        message: message.to_owned(),
        details,
    };
    Status::with_details(code, message, status.encode_to_vec().into())
}

/// The message production returns for any pipeline operation on a Standard-edition database.
pub const PIPELINE_REQUIRES_ENTERPRISE: &str = "Pipeline Operations are only available for \
Firestore databases in Enterprise edition.\n\nPlease switch to an Enterprise edition database \
to take advantage of such functionality.";

/// Production's refusal of `ExecutePipeline` on a Standard-edition database (observed
/// 2026-09-24 over REST and gRPC): `FAILED_PRECONDITION` with an `ErrorInfo` and a `Help` link.
#[must_use]
pub fn pipeline_requires_enterprise() -> Status {
    with_details(
        Code::FailedPrecondition,
        PIPELINE_REQUIRES_ENTERPRISE,
        vec![
            any(
                ERROR_INFO,
                &ErrorInfo {
                    reason: "PIPELINE_REQUIRES_ENTERPRISE_EDITION".to_owned(),
                    domain: "firestore.googleapis.com".to_owned(),
                    metadata: std::collections::BTreeMap::new(),
                },
            ),
            any(
                HELP,
                &Help {
                    links: vec![Link {
                        description: "Learn more about Firestore database editions".to_owned(),
                        url: "https://cloud.google.com/firestore/docs/editions".to_owned(),
                    }],
                },
            ),
        ],
    )
}

fn error_info(reason: &str, metadata: &[(&str, String)]) -> prost_types::Any {
    any(
        ERROR_INFO,
        &ErrorInfo {
            reason: reason.to_owned(),
            domain: "firestore.googleapis.com".to_owned(),
            metadata: metadata
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        },
    )
}

/// Production's text for a cosine search that meets a zero vector.
pub const COSINE_ZERO_VECTOR: &str =
    "Cannot compute cosine distance against a vector with a magnitude of zero.";

/// A `FAILED_PRECONDITION` in production's shape: the texts production attaches an
/// `ErrorInfo` to carry it, every other one is plain.
#[must_use]
pub fn failed_precondition(message: &str) -> Status {
    if message == COSINE_ZERO_VECTOR {
        return with_details(
            Code::FailedPrecondition,
            message,
            vec![error_info("COSINE_DISTANCE_ON_ZERO_VECTOR", &[])],
        );
    }
    Status::failed_precondition(message)
}

/// Production's refusal of an aggregation query with more than five aggregations.
#[must_use]
pub fn too_many_aggregations(actual: usize) -> Status {
    with_details(
        Code::InvalidArgument,
        &format!(
            "The maximum number of aggregations allowed in an aggregation query is 5. Received: {actual}"
        ),
        vec![error_info(
            "TOO_MANY_AGGREGATIONS",
            &[
                ("actual_aggregations", actual.to_string()),
                ("max_aggregations", "5".to_owned()),
            ],
        )],
    )
}

/// The request transcoder's refusal: `INVALID_ARGUMENT` whose message joins the violation
/// descriptions with newlines, with one `BadRequest` field violation each (`field` is empty for
/// an unknown name at the root).
#[must_use]
pub fn bad_request(violations: &[(String, String)]) -> Status {
    let message = violations
        .iter()
        .map(|(_, description)| description.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    with_details(
        Code::InvalidArgument,
        &message,
        vec![any(
            BAD_REQUEST,
            &BadRequest {
                field_violations: violations
                    .iter()
                    .map(|(field, description)| FieldViolation {
                        field: field.clone(),
                        description: description.clone(),
                    })
                    .collect(),
            },
        )],
    )
}

/// The REST `details` array for a status's encoded `google.rpc.Status` details, or `None` when
/// it carries none this module renders. Unknown detail types are left out, as they are not
/// produced by fireemu.
#[must_use]
pub fn details_to_json(details: &[u8]) -> Option<Vec<Value>> {
    if details.is_empty() {
        return None;
    }
    let status = RpcStatus::decode(details).ok()?;
    let rendered: Vec<Value> = status
        .details
        .iter()
        .filter_map(|detail| match detail.type_url.as_str() {
            ERROR_INFO => {
                let info = ErrorInfo::decode(detail.value.as_slice()).ok()?;
                let mut out = json!({
                    "@type": ERROR_INFO,
                    "reason": info.reason,
                    "domain": info.domain,
                });
                if !info.metadata.is_empty() {
                    out["metadata"] = json!(info.metadata);
                }
                Some(out)
            }
            BAD_REQUEST => {
                let request = BadRequest::decode(detail.value.as_slice()).ok()?;
                let violations: Vec<Value> = request
                    .field_violations
                    .iter()
                    .map(|v| {
                        let mut out = json!({"description": v.description});
                        if !v.field.is_empty() {
                            out["field"] = json!(v.field);
                        }
                        out
                    })
                    .collect();
                Some(json!({"@type": BAD_REQUEST, "fieldViolations": violations}))
            }
            HELP => {
                let help = Help::decode(detail.value.as_slice()).ok()?;
                let links: Vec<Value> = help
                    .links
                    .iter()
                    .map(|l| json!({"description": l.description, "url": l.url}))
                    .collect();
                Some(json!({"@type": HELP, "links": links}))
            }
            _ => None,
        })
        .collect();
    (!rendered.is_empty()).then_some(rendered)
}

/// Re-encodes a `grpc-message` header the way the gRPC wire spec (and production) does: only
/// `%` and bytes outside printable ASCII are percent-encoded. tonic also encodes `?`, `#`, space
/// and other printable characters, which clients that decode with `decodeURI` (grpc-js, and so
/// the Node SDKs) leave as `%3F` or `%23` in the message they report.
pub fn respec_grpc_message(headers: &mut hyper::HeaderMap) {
    let Some(value) = headers.get(Status::GRPC_MESSAGE) else {
        return;
    };
    let Ok(text) = value.to_str() else {
        return;
    };
    let decoded = fireemu_core_types::codec::percent_decode_bytes(
        text,
        fireemu_core_types::codec::PlusMode::Literal,
    );
    let mut encoded = String::with_capacity(decoded.len());
    for byte in decoded {
        if byte == b'%' || !(0x20..=0x7e).contains(&byte) {
            let _ = write!(encoded, "%{byte:02X}");
        } else {
            encoded.push(char::from(byte));
        }
    }
    if let Ok(value) = hyper::header::HeaderValue::from_str(&encoded) {
        headers.insert(Status::GRPC_MESSAGE, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pipeline_refusal_renders_production_details() {
        let status = pipeline_requires_enterprise();
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert_eq!(status.message(), PIPELINE_REQUIRES_ENTERPRISE);
        assert_eq!(
            details_to_json(status.details()),
            Some(vec![
                json!({
                    "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                    "reason": "PIPELINE_REQUIRES_ENTERPRISE_EDITION",
                    "domain": "firestore.googleapis.com",
                }),
                json!({
                    "@type": "type.googleapis.com/google.rpc.Help",
                    "links": [{
                        "description": "Learn more about Firestore database editions",
                        "url": "https://cloud.google.com/firestore/docs/editions",
                    }],
                }),
            ])
        );
    }

    #[test]
    fn grpc_messages_are_percent_encoded_as_the_spec_says() {
        let status = Status::failed_precondition(
            "Create it here: https://x/indexes?create_composite=Ab_- #1 100% \u{e9}\n",
        );
        let mut headers = hyper::HeaderMap::new();
        status.add_header(&mut headers).unwrap();
        respec_grpc_message(&mut headers);
        assert_eq!(
            headers.get(Status::GRPC_MESSAGE).unwrap(),
            "Create it here: https://x/indexes?create_composite=Ab_- #1 100%25 %C3%A9%0A"
        );
        let back = Status::from_header_map(&headers).unwrap();
        assert_eq!(back.message(), status.message());
    }

    #[test]
    fn statuses_without_known_details_render_none() {
        assert_eq!(details_to_json(b""), None);
        assert_eq!(details_to_json(b"not a status"), None);
        let other = RpcStatus {
            code: 3,
            message: "x".to_owned(),
            details: vec![prost_types::Any {
                type_url: "type.googleapis.com/other".to_owned(),
                value: vec![1],
            }],
        };
        assert_eq!(details_to_json(&other.encode_to_vec()), None);
    }
}
