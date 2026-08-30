//! Canonical `X-Firebase-AppCheck` classification (specification section 7.3).
//!
//! Every automatically classified ingress uses this one contract, whatever the transport:
//! HTTP/1, HTTP/2, gRPC metadata, `WebChannel`, Storage and callable Functions all hand over the
//! list of field values they received and take the answer. An adapter must never select the
//! first or the last of several values.

use crate::limits::MAX_TOKEN_BYTES;

/// The canonical header name, lowercase. Field names are matched case-insensitively.
pub const APP_CHECK_HEADER: &str = "x-firebase-appcheck";

/// The outcome of classifying the presented field values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderClassification {
    /// No field instance at all.
    Missing,
    /// Exactly one eligible value.
    Present(String),
    /// Several instances, a comma-folded value, an empty value, invalid text, or a value above
    /// [`MAX_TOKEN_BYTES`].
    Malformed,
}

/// Whether a field name is the App Check header, compared case-insensitively.
#[must_use]
pub fn is_app_check_header(name: &str) -> bool {
    name.eq_ignore_ascii_case(APP_CHECK_HEADER)
}

/// Classifies the App Check field values a transport received.
///
/// Zero values are [`HeaderClassification::Missing`]. Exactly one value of visible ASCII, at
/// most [`MAX_TOKEN_BYTES`] bytes and without a comma is
/// [`HeaderClassification::Present`]. Everything else — several instances, a folded
/// `a,b` value, an empty or whitespace value, control characters, non-ASCII text, or an
/// oversized value — is [`HeaderClassification::Malformed`], never a silently chosen value.
#[must_use]
pub fn classify_app_check_header<S: AsRef<str>>(values: &[S]) -> HeaderClassification {
    match values {
        [] => HeaderClassification::Missing,
        [only] => {
            let value = only.as_ref();
            if value.is_empty() || value.len() > MAX_TOKEN_BYTES || !is_eligible_value(value) {
                HeaderClassification::Malformed
            } else {
                HeaderClassification::Present(value.to_owned())
            }
        }
        _ => HeaderClassification::Malformed,
    }
}

/// Collects the App Check values out of a transport's `(name, value)` field list.
///
/// The iterator order is the wire order; duplicates are kept so that
/// [`classify_app_check_header`] can refuse them.
pub fn collect_values<'a, I>(fields: I) -> Vec<&'a str>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    fields
        .into_iter()
        .filter(|(name, _)| is_app_check_header(name))
        .map(|(_, value)| value)
        .collect()
}

/// Visible ASCII only, and never a comma: a folded `a,b` value is ambiguous, and a JWT never
/// contains a comma, whitespace or a control character.
fn is_eligible_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| (0x21..=0x7E).contains(&b) && b != b',')
}
