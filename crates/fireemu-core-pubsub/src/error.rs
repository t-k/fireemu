//! Error model for the Pub/Sub state machine.
//!
//! Every fallible operation returns [`PubSubError`]. The variant carries a canonical
//! [`Code`] that the protocol adapter maps to a gRPC status (and to the REST/HTTP status the
//! official emulator uses) plus a human-readable message. The core never speaks gRPC or HTTP;
//! it only classifies.

use core::fmt;

/// Canonical status classes, a subset of the gRPC status codes the official Pub/Sub emulator
/// returns. The adapter maps these to `tonic::Code` and to HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// The request was malformed (bad name, bad field value, unparriseable filter).
    InvalidArgument,
    /// A named topic or subscription does not exist.
    NotFound,
    /// A topic or subscription with that name already exists.
    AlreadyExists,
    /// The operation is not allowed in the current state (e.g. an ack id that never existed).
    FailedPrecondition,
    /// A bound (topic count, retained messages, attribute count) was reached.
    ResourceExhausted,
    /// The operation is documented as unsupported by the official emulator.
    Unimplemented,
}

impl Code {
    /// The canonical uppercase name, used in wire error bodies.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::Unimplemented => "UNIMPLEMENTED",
        }
    }
}

/// A classified Pub/Sub error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PubSubError {
    code: Code,
    message: String,
}

impl PubSubError {
    /// Builds an error with an explicit code and message.
    #[must_use]
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// `INVALID_ARGUMENT`.
    #[must_use]
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(Code::InvalidArgument, message)
    }

    /// `NOT_FOUND`.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Code::NotFound, message)
    }

    /// `ALREADY_EXISTS`.
    #[must_use]
    pub fn already_exists(message: impl Into<String>) -> Self {
        Self::new(Code::AlreadyExists, message)
    }

    /// `FAILED_PRECONDITION`.
    #[must_use]
    pub fn failed_precondition(message: impl Into<String>) -> Self {
        Self::new(Code::FailedPrecondition, message)
    }

    /// `RESOURCE_EXHAUSTED`.
    #[must_use]
    pub fn resource_exhausted(message: impl Into<String>) -> Self {
        Self::new(Code::ResourceExhausted, message)
    }

    /// `UNIMPLEMENTED`.
    #[must_use]
    pub fn unimplemented(message: impl Into<String>) -> Self {
        Self::new(Code::Unimplemented, message)
    }

    /// The canonical code.
    #[must_use]
    pub const fn code(&self) -> Code {
        self.code
    }

    /// The human-readable message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PubSubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for PubSubError {}

/// Convenience result alias.
pub type Result<T> = core::result::Result<T, PubSubError>;
