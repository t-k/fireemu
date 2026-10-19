//! Errors of the Realtime Database core.
//!
//! The kinds are stable; the messages are provisional English texts. Production's exact
//! wording and status codes are decided by the transport adapters once they are observed.

use std::fmt;

/// What was wrong with a request to the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// A key is empty or contains a forbidden character.
    InvalidKey,
    /// A path string cannot name a location (for example `.priority` in the middle).
    InvalidPath,
    /// A key is longer than the key byte limit.
    KeyTooLong,
    /// The written data reaches deeper than the depth limit.
    PathTooDeep,
    /// A string value is longer than the string byte limit.
    StringTooLong,
    /// The data is not a valid Realtime Database value.
    InvalidData,
    /// A priority is neither null, a number nor a string.
    InvalidPriority,
    /// A server value placeholder (`.sv`) is unknown or malformed.
    InvalidServerValue,
    /// Two paths of one multipath update overlap.
    OverlappingUpdate,
    /// The location is read-only (`.info`).
    ReadOnlyPath,
    /// Query parameters that cannot be combined with the chosen order.
    InvalidQuery,
}

/// An error of the Realtime Database core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseError {
    /// The stable kind.
    pub kind: ErrorKind,
    /// A provisional human-readable message.
    pub message: String,
}

impl DatabaseError {
    /// An error of `kind` with `message`.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DatabaseError {}

/// The result type of the core.
pub type Result<T> = std::result::Result<T, DatabaseError>;
