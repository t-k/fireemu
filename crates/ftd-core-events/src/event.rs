//! Logical event model (spec 10.1).

use core::fmt;

use ftd_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
use ftd_core_types::time::LogicalInstant;

/// Where an event originates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventSource {
    /// Firestore document change.
    Firestore,
    /// Cloud Storage object change.
    Storage,
    /// Scheduler due run.
    Scheduler,
    /// Manually injected by the control API or testkit.
    Manual,
    /// A Pub/Sub message published through the control API.
    PubSub,
    /// An Auth user lifecycle event.
    Auth,
}

/// CloudEvents-style event type, e.g. `google.cloud.firestore.document.v1.created`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventType(String);

/// Invalid event type string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTypeError {
    /// Empty string.
    Empty,
    /// Exceeds the byte limit.
    TooLong,
    /// Contains a character outside `[A-Za-z0-9._-]`.
    InvalidCharacter {
        /// Byte offset.
        offset: usize,
    },
}

impl fmt::Display for EventTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("event type is empty"),
            Self::TooLong => write!(f, "event type exceeds {} bytes", EventType::MAX_BYTES),
            Self::InvalidCharacter { offset } => {
                write!(f, "event type has an invalid character at byte {offset}")
            }
        }
    }
}

impl std::error::Error for EventTypeError {}

impl EventType {
    /// Maximum length in bytes.
    pub const MAX_BYTES: usize = 256;

    /// Validates an event type.
    pub fn try_new(value: impl Into<String>) -> Result<Self, EventTypeError> {
        let value = value.into();
        if value.is_empty() {
            return Err(EventTypeError::Empty);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(EventTypeError::TooLong);
        }
        if let Some(offset) = value
            .bytes()
            .position(|b| !(b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-'))
        {
            return Err(EventTypeError::InvalidCharacter { offset });
        }
        Ok(Self(value))
    }

    /// Borrows the type string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A logical event. Payload encoding is the concern of the protocol shell; the core keeps
/// opaque bytes so that serialization formats never leak into the domain model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalEvent {
    /// Event ID.
    pub event_id: EventId,
    /// Owning session.
    pub session_id: SessionId,
    /// Epoch the event was created in.
    pub epoch: Epoch,
    /// Source.
    pub source: EventSource,
    /// Event type.
    pub event_type: EventType,
    /// Subject (resource path).
    pub subject: String,
    /// Logical time of the change that produced the event.
    pub logical_time: LogicalInstant,
    /// Event that caused this one, if any.
    pub causation_id: Option<EventId>,
    /// Correlation ID shared by the causal tree.
    pub correlation_id: CorrelationId,
    /// Opaque payload.
    pub payload: Vec<u8>,
}
