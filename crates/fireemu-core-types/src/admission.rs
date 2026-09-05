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
}

impl EventAdmissionError {
    /// Human-readable detail without erasing the machine-readable category.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Capacity(message) | Self::Unavailable(message) | Self::InvalidEvent(message) => {
                message
            }
        }
    }
}

impl fmt::Display for EventAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for EventAdmissionError {}
