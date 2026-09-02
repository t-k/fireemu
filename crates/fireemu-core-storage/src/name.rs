//! Bucket and object names (spec 9.1): validated, opaque, never normalized.

use core::fmt;

/// Maximum object name length in UTF-8 bytes (Cloud Storage).
pub const MAX_OBJECT_NAME_BYTES: usize = 1024;
/// Maximum bucket name length.
pub const MAX_BUCKET_NAME_LEN: usize = 222;

/// Why a name was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    /// Empty name.
    Empty,
    /// Too long.
    TooLong,
    /// Contains a carriage return, line feed or NUL.
    ControlCharacter,
    /// `.` or `..` (Cloud Storage refuses them).
    Dot,
    /// Reserved prefix `.well-known/acme-challenge/`.
    ReservedPrefix,
    /// Bucket names use lowercase letters, digits, `-`, `_` and `.` only.
    InvalidBucketCharacter,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "name is empty",
            Self::TooLong => "name is too long",
            Self::ControlCharacter => "name contains a control character",
            Self::Dot => "name is '.' or '..'",
            Self::ReservedPrefix => "name uses the reserved .well-known/acme-challenge/ prefix",
            Self::InvalidBucketCharacter => "bucket name contains an invalid character",
        })
    }
}

impl std::error::Error for NameError {}

/// A validated object name. `/` is an ordinary character; NFC and NFD are different names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectName(String);

impl ObjectName {
    /// Builds a lexical range boundary. Boundaries are never stored and may be empty or
    /// otherwise invalid as object names.
    pub(crate) fn range_start(name: &str) -> Self {
        Self(name.to_owned())
    }

    /// Validates a decoded object name (the protocol layer decodes exactly once).
    pub fn try_new(name: impl Into<String>) -> Result<Self, NameError> {
        let name = name.into();
        if name.is_empty() {
            return Err(NameError::Empty);
        }
        if name.len() > MAX_OBJECT_NAME_BYTES {
            return Err(NameError::TooLong);
        }
        if name.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
            return Err(NameError::ControlCharacter);
        }
        if name == "." || name == ".." {
            return Err(NameError::Dot);
        }
        if name.starts_with(".well-known/acme-challenge/") {
            return Err(NameError::ReservedPrefix);
        }
        Ok(Self(name))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObjectName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated bucket name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BucketName(String);

impl BucketName {
    /// Validates a bucket name.
    pub fn try_new(name: impl Into<String>) -> Result<Self, NameError> {
        let name = name.into();
        if name.is_empty() {
            return Err(NameError::Empty);
        }
        if name.len() > MAX_BUCKET_NAME_LEN {
            return Err(NameError::TooLong);
        }
        if !name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        }) {
            return Err(NameError::InvalidBucketCharacter);
        }
        Ok(Self(name))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BucketName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
