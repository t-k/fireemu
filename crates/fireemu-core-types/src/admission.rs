//! Typed admission failures shared across source products and their wire adapters.

use std::fmt;

/// Why a coupled logical-event batch could not be reserved before source publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventAdmissionError {
    /// The bounded logical-event queue cannot retain the complete batch.
    Capacity(String),
    /// The event runtime cannot currently accept owned work, such as during shutdown.
    Unavailable(String),
    /// The configured trigger produced an event that cannot be represented.
    InvalidEvent(String),
    /// An event of the write is larger than the source product lets a function receive; the write is refused
    /// and nothing is applied (Realtime Database: HTTP 400, recorded 2026-11-08).
    PayloadTooLarge(String),
}

impl EventAdmissionError {
    /// Human-readable detail without erasing the machine-readable category.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Capacity(message)
            | Self::Unavailable(message)
            | Self::InvalidEvent(message)
            | Self::PayloadTooLarge(message) => message,
        }
    }
}

impl fmt::Display for EventAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for EventAdmissionError {}

#[cfg(test)]
mod tests {
    use super::EventAdmissionError;

    #[test]
    fn every_category_keeps_its_own_message_for_display() {
        for error in [
            EventAdmissionError::Capacity("full".to_owned()),
            EventAdmissionError::Unavailable("closing".to_owned()),
            EventAdmissionError::InvalidEvent("invalid".to_owned()),
            EventAdmissionError::PayloadTooLarge("large".to_owned()),
        ] {
            let message = error.message().to_owned();
            assert!(!message.is_empty());
            assert_eq!(error.to_string(), message);
        }
        assert_eq!(
            EventAdmissionError::PayloadTooLarge("large".to_owned()).message(),
            "large"
        );
    }
}
