//! Named JSON error shapes used by Firebase and Google API adapters.
//!
//! These constructors intentionally preserve protocol differences. They do not choose HTTP
//! status codes, headers or product policy, and adding a field to one shape never changes another.

use serde_json::{json, Value};

/// Minimal Firebase emulator error with only `code` and `message`.
#[must_use]
pub fn firebase_minimal(code: u16, message: &str) -> Value {
    json!({"error": {"code": code, "message": message}})
}

/// Google RPC JSON error with its canonical status name.
#[must_use]
pub fn google_rpc(code: u16, message: &str, status: &str) -> Value {
    json!({"error": {"code": code, "message": message, "status": status}})
}

/// Google RPC JSON error with a public machine-readable reason on the error itself.
#[must_use]
pub fn google_rpc_with_reason(code: u16, message: &str, status: &str, reason: &str) -> Value {
    json!({"error": {"code": code, "message": message, "status": status, "reason": reason}})
}

/// GCS JSON API error with its `errors` detail array.
#[must_use]
pub fn gcs(code: u16, message: &str, reason: &str) -> Value {
    json!({"error": {"code": code, "message": message, "errors": [{"domain": "global", "reason": reason, "message": message}]}})
}

/// Identity Toolkit `BadRequestError`, including its fixed global/invalid detail.
#[must_use]
pub fn identity_invalid(code: u16, message: &str) -> Value {
    json!({"error": {"code": code, "message": message, "errors": [{"message": message, "domain": "global", "reason": "invalid"}]}})
}

/// Identity Toolkit's unknown-route response, which has no detail domain.
#[must_use]
pub fn identity_not_found() -> Value {
    json!({"error": {"code": 404, "message": "Not Found", "errors": [{"message": "Not Found", "reason": "notFound"}], "status": "NOT_FOUND"}})
}

/// Identity Toolkit extension response for an explicitly unsupported operation.
#[must_use]
pub fn identity_unimplemented(message: &str) -> Value {
    json!({"error": {"code": 501, "message": message, "errors": [{"message": message, "reason": "unimplemented"}], "status": "NOT_IMPLEMENTED"}})
}

/// Auth App Check denial, retaining both the public App Check reason and Google's forbidden
/// detail required by the existing Auth wire contract.
#[must_use]
pub fn identity_app_check_denied(message: &str, reason: &str) -> Value {
    json!({"error": {
        "code": 403,
        "message": message,
        "status": "PERMISSION_DENIED",
        "reason": reason,
        "errors": [{"message": message, "domain": "global", "reason": "forbidden"}]
    }})
}

/// Flat Hub/Functions error whose value is a string rather than a Google error object.
#[must_use]
pub fn flat(message: &str) -> Value {
    json!({"error": message})
}

/// Control API await-idle timeout. Its `status` is a runtime diagnostic object, not a Google
/// canonical status string, so it remains a distinct shape.
#[must_use]
pub fn control_deadline(message: &str, status: &Value) -> Value {
    json!({"error": {"code": 504, "message": message, "status": status}})
}

#[cfg(test)]
mod tests {
    use super::{
        control_deadline, firebase_minimal, flat, gcs, google_rpc, google_rpc_with_reason,
        identity_app_check_denied, identity_invalid, identity_not_found, identity_unimplemented,
    };

    fn text(value: &serde_json::Value) -> String {
        serde_json::to_string(value).expect("error shape serializes")
    }

    #[test]
    fn every_named_error_shape_has_a_stable_wire_body() {
        assert_eq!(
            text(&firebase_minimal(413, "PAYLOAD_TOO_LARGE")),
            r#"{"error":{"code":413,"message":"PAYLOAD_TOO_LARGE"}}"#
        );
        assert_eq!(
            text(&google_rpc(
                413,
                "request body too large",
                "INVALID_ARGUMENT"
            )),
            r#"{"error":{"code":413,"message":"request body too large","status":"INVALID_ARGUMENT"}}"#
        );
        assert_eq!(
            text(&google_rpc_with_reason(
                403,
                "denied",
                "PERMISSION_DENIED",
                "required"
            )),
            r#"{"error":{"code":403,"message":"denied","reason":"required","status":"PERMISSION_DENIED"}}"#
        );
        assert_eq!(
            text(&gcs(404, "missing", "notFound")),
            r#"{"error":{"code":404,"errors":[{"domain":"global","message":"missing","reason":"notFound"}],"message":"missing"}}"#
        );
        assert_eq!(
            text(&identity_invalid(400, "INVALID")),
            r#"{"error":{"code":400,"errors":[{"domain":"global","message":"INVALID","reason":"invalid"}],"message":"INVALID"}}"#
        );
        assert_eq!(
            text(&identity_not_found()),
            r#"{"error":{"code":404,"errors":[{"message":"Not Found","reason":"notFound"}],"message":"Not Found","status":"NOT_FOUND"}}"#
        );
        assert_eq!(
            text(&identity_unimplemented("later")),
            r#"{"error":{"code":501,"errors":[{"message":"later","reason":"unimplemented"}],"message":"later","status":"NOT_IMPLEMENTED"}}"#
        );
        assert_eq!(
            text(&identity_app_check_denied("denied", "required")),
            r#"{"error":{"code":403,"errors":[{"domain":"global","message":"denied","reason":"forbidden"}],"message":"denied","reason":"required","status":"PERMISSION_DENIED"}}"#
        );
        assert_eq!(text(&flat("missing")), r#"{"error":"missing"}"#);
        assert_eq!(
            text(&control_deadline(
                "waiting",
                &serde_json::json!({"pending": 1})
            )),
            r#"{"error":{"code":504,"message":"waiting","status":{"pending":1}}}"#
        );
    }
}
