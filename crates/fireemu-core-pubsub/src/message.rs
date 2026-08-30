//! The published-message model and its input validation.
//!
//! A [`PubsubMessage`] is validated at the boundary: data and attributes are bounded in size
//! and count, and NUL is rejected in attribute keys, attribute values and ordering keys. The
//! official emulator does not reject NUL there; doing so is an intentional local hardening
//! (recorded as a documented divergence) so that an attribute can never carry a NUL into a
//! trace, a JSON document, a log line or a function payload.

use std::collections::BTreeMap;

use fireemu_core_types::time::LogicalInstant;

use crate::error::{PubSubError, Result};

/// Maximum size of the message data payload, in bytes (10 MB, the documented Pub/Sub limit).
pub const MAX_DATA_BYTES: usize = 10_000_000;
/// Maximum combined size of data plus attribute keys and values, in bytes.
pub const MAX_TOTAL_BYTES: usize = 10_000_000;
/// Maximum number of attributes on one message.
pub const MAX_ATTRIBUTES: usize = 100;
/// Maximum size of an attribute key, in bytes.
pub const MAX_ATTR_KEY_BYTES: usize = 256;
/// Maximum size of an attribute value, in bytes.
pub const MAX_ATTR_VALUE_BYTES: usize = 1024;
/// Maximum size of an ordering key, in bytes.
pub const MAX_ORDERING_KEY_BYTES: usize = 1024;

/// A message as accepted for publication: raw data, string attributes and an ordering key.
///
/// Attributes are kept in a [`BTreeMap`] so that iteration order is deterministic regardless
/// of the order in which a client sent them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PubsubMessage {
    /// The opaque payload.
    pub data: Vec<u8>,
    /// String attributes.
    pub attributes: BTreeMap<String, String>,
    /// The ordering key; empty means unordered.
    pub ordering_key: String,
}

impl PubsubMessage {
    /// Validates the message against the documented Pub/Sub bounds and the local NUL hardening.
    ///
    /// A message with neither data nor attributes is rejected exactly as the service rejects it.
    pub fn validate(&self) -> Result<()> {
        if self.data.is_empty() && self.attributes.is_empty() {
            return Err(PubSubError::invalid_argument(
                "message must carry non-empty data or at least one attribute",
            ));
        }
        if self.data.len() > MAX_DATA_BYTES {
            return Err(PubSubError::invalid_argument(format!(
                "message data exceeds {MAX_DATA_BYTES} bytes"
            )));
        }
        if self.attributes.len() > MAX_ATTRIBUTES {
            return Err(PubSubError::invalid_argument(format!(
                "message has more than {MAX_ATTRIBUTES} attributes"
            )));
        }
        let mut total = self.data.len();
        for (key, value) in &self.attributes {
            validate_attribute(key, value)?;
            total = total
                .saturating_add(key.len())
                .saturating_add(value.len());
        }
        if total > MAX_TOTAL_BYTES {
            return Err(PubSubError::invalid_argument(format!(
                "message total size exceeds {MAX_TOTAL_BYTES} bytes"
            )));
        }
        validate_ordering_key(&self.ordering_key)?;
        Ok(())
    }
}

/// Validates one attribute key/value pair.
fn validate_attribute(key: &str, value: &str) -> Result<()> {
    if key.is_empty() {
        return Err(PubSubError::invalid_argument("attribute key is empty"));
    }
    if key.len() > MAX_ATTR_KEY_BYTES {
        return Err(PubSubError::invalid_argument(format!(
            "attribute key exceeds {MAX_ATTR_KEY_BYTES} bytes"
        )));
    }
    if value.len() > MAX_ATTR_VALUE_BYTES {
        return Err(PubSubError::invalid_argument(format!(
            "attribute value for {key:?} exceeds {MAX_ATTR_VALUE_BYTES} bytes"
        )));
    }
    if key.starts_with("goog") {
        return Err(PubSubError::invalid_argument(format!(
            "attribute key {key:?} must not start with the reserved prefix 'goog'"
        )));
    }
    if key.contains('\u{0}') {
        return Err(PubSubError::invalid_argument(format!(
            "attribute key {key:?} contains a NUL byte"
        )));
    }
    if value.contains('\u{0}') {
        return Err(PubSubError::invalid_argument(format!(
            "attribute value for {key:?} contains a NUL byte"
        )));
    }
    Ok(())
}

/// Validates an ordering key.
fn validate_ordering_key(key: &str) -> Result<()> {
    if key.len() > MAX_ORDERING_KEY_BYTES {
        return Err(PubSubError::invalid_argument(format!(
            "ordering key exceeds {MAX_ORDERING_KEY_BYTES} bytes"
        )));
    }
    if key.contains('\u{0}') {
        return Err(PubSubError::invalid_argument(
            "ordering key contains a NUL byte",
        ));
    }
    Ok(())
}

/// A message stored in a subscription's backlog: the accepted message plus the identity and
/// time the broker assigned at publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    /// The broker-assigned message ID (stable for the life of the message).
    pub message_id: String,
    /// When the message was published, on the virtual clock.
    pub publish_time: LogicalInstant,
    /// The message body.
    pub message: PubsubMessage,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(data: &[u8]) -> PubsubMessage {
        PubsubMessage {
            data: data.to_vec(),
            ..PubsubMessage::default()
        }
    }

    #[test]
    fn empty_message_is_rejected() {
        assert!(PubsubMessage::default().validate().is_err());
    }

    #[test]
    fn plain_data_is_accepted() {
        assert!(msg(b"hello").validate().is_ok());
    }

    #[test]
    fn nul_in_attribute_value_is_rejected() {
        let mut m = msg(b"x");
        m.attributes.insert("k".to_owned(), "a\u{0}b".to_owned());
        assert!(m.validate().is_err());
    }

    #[test]
    fn goog_attribute_key_is_rejected() {
        let mut m = msg(b"x");
        m.attributes.insert("googfoo".to_owned(), "v".to_owned());
        assert!(m.validate().is_err());
    }

    #[test]
    fn oversize_data_is_rejected() {
        let m = PubsubMessage {
            data: vec![0u8; MAX_DATA_BYTES + 1],
            ..PubsubMessage::default()
        };
        assert!(m.validate().is_err());
    }

    #[test]
    fn oversize_ordering_key_is_rejected() {
        let mut m = msg(b"x");
        m.ordering_key = "a".repeat(MAX_ORDERING_KEY_BYTES + 1);
        assert!(m.validate().is_err());
    }
}
