//! Identifier newtypes.
//!
//! Every identifier keeps its inner field private. External crates must go through the
//! validating constructors (`try_new`, `new`) so that only syntactically valid identifiers
//! exist at runtime. Serialization adapters use `as_str` / `value` / `into_inner` explicitly.

use core::fmt;

/// Maximum UTF-8 byte length of a collection ID, document ID and field name.
///
/// Mirrors `FS-LIMIT-COLLECTION-ID`, `FS-LIMIT-DOCUMENT-ID` and `FS-LIMIT-FIELD-NAME` in the
/// Firestore Standard limit catalog. The catalog test suite asserts that the catalog value
/// and this constant never drift apart.
pub const MAX_ID_UTF8_BYTES: usize = 1_500;

/// Syntax violations for identifiers. Byte counts are UTF-8 bytes, never character counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdSyntaxError {
    /// The identifier is empty.
    Empty,
    /// The identifier exceeds the UTF-8 byte limit.
    TooManyBytes {
        /// Observed UTF-8 byte length.
        bytes: usize,
        /// Inclusive maximum.
        maximum: usize,
    },
    /// A character outside the allowed alphabet was found.
    InvalidCharacter {
        /// Byte offset of the offending character.
        offset: usize,
    },
    /// The identifier starts or ends with a hyphen.
    LeadingOrTrailingHyphen,
    /// The identifier contains a forward slash.
    ContainsSlash,
    /// The identifier is exactly `.` or `..`.
    DotSegment,
    /// The identifier matches the reserved pattern `__.*__`.
    ReservedDunder,
}

impl fmt::Display for IdSyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("identifier is empty"),
            Self::TooManyBytes { bytes, maximum } => {
                write!(f, "identifier is {bytes} UTF-8 bytes, maximum is {maximum}")
            }
            Self::InvalidCharacter { offset } => {
                write!(f, "invalid character at byte offset {offset}")
            }
            Self::LeadingOrTrailingHyphen => f.write_str("identifier starts or ends with '-'"),
            Self::ContainsSlash => f.write_str("identifier contains '/'"),
            Self::DotSegment => f.write_str("identifier must not be '.' or '..'"),
            Self::ReservedDunder => f.write_str("identifier matches reserved pattern __.*__"),
        }
    }
}

impl std::error::Error for IdSyntaxError {}

/// Validates the lowercase `[a-z0-9-]` alphabet used by project and database IDs.
fn validate_lowercase_hyphenated(s: &str, max_bytes: usize) -> Result<(), IdSyntaxError> {
    if s.is_empty() {
        return Err(IdSyntaxError::Empty);
    }
    if s.len() > max_bytes {
        return Err(IdSyntaxError::TooManyBytes {
            bytes: s.len(),
            maximum: max_bytes,
        });
    }
    if let Some(offset) = s
        .bytes()
        .position(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
    {
        return Err(IdSyntaxError::InvalidCharacter { offset });
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(IdSyntaxError::LeadingOrTrailingHyphen);
    }
    Ok(())
}

/// Validates a Firestore path segment (collection ID, document ID, field name).
fn validate_path_segment(s: &str) -> Result<(), IdSyntaxError> {
    if s.is_empty() {
        return Err(IdSyntaxError::Empty);
    }
    if s.len() > MAX_ID_UTF8_BYTES {
        return Err(IdSyntaxError::TooManyBytes {
            bytes: s.len(),
            maximum: MAX_ID_UTF8_BYTES,
        });
    }
    if s.contains('/') {
        return Err(IdSyntaxError::ContainsSlash);
    }
    if s == "." || s == ".." {
        return Err(IdSyntaxError::DotSegment);
    }
    if is_reserved_dunder(s) {
        return Err(IdSyntaxError::ReservedDunder);
    }
    Ok(())
}

/// `__.*__`: at least four bytes, starting and ending with two underscores.
fn is_reserved_dunder(s: &str) -> bool {
    s.len() >= 4 && s.starts_with("__") && s.ends_with("__")
}

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident, $validate:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Validates and wraps the identifier.
            pub fn try_new(value: impl Into<String>) -> Result<Self, IdSyntaxError> {
                let value = value.into();
                $validate(&value)?;
                Ok(Self(value))
            }

            /// Borrows the identifier text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the identifier and returns the validated text.
            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_id!(
    /// Firebase project ID. Also the session routing key (spec 14.1).
    ProjectId,
    |s: &str| validate_lowercase_hyphenated(s, 63)
);

impl ProjectId {
    /// Whether the project ID carries the `demo-` prefix that keeps the official SDKs from
    /// reaching real Firebase backends.
    #[must_use]
    pub fn has_demo_prefix(&self) -> bool {
        self.0.starts_with("demo-")
    }
}

string_id!(
    /// Firestore database ID. `(default)` or a lowercase hyphenated name.
    DatabaseId,
    |s: &str| if s == DatabaseId::DEFAULT {
        Ok(())
    } else {
        validate_lowercase_hyphenated(s, 63)
    }
);

impl DatabaseId {
    /// The literal name of the default database.
    pub const DEFAULT: &'static str = "(default)";

    /// The default database `(default)`.
    #[must_use]
    pub fn default_database() -> Self {
        Self(Self::DEFAULT.to_owned())
    }
}

string_id!(
    /// Firestore collection ID (`FS-LIMIT-COLLECTION-ID`).
    CollectionId,
    validate_path_segment
);

string_id!(
    /// Firestore document ID (`FS-LIMIT-DOCUMENT-ID`).
    DocumentId,
    validate_path_segment
);

string_id!(
    /// Immutable limit catalog identifier such as `firestore-standard-2026-08-25`.
    LimitCatalogId,
    |s: &str| validate_lowercase_hyphenated(s, 128)
);

macro_rules! numeric_id {
    ($(#[$meta:meta])* $name:ident, $inner:ty) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name($inner);

        impl $name {
            /// Wraps a raw value. Raw values come from deterministic ID sources only.
            #[must_use]
            pub const fn new(value: $inner) -> Self {
                Self(value)
            }

            /// Returns the raw value.
            #[must_use]
            pub const fn value(self) -> $inner {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

numeric_id!(
    /// Session identifier, derived from the session seed.
    SessionId,
    u128
);
numeric_id!(
    /// Dense, monotonic command sequence number within a session.
    CommandId,
    u64
);
numeric_id!(
    /// Logical event identifier.
    EventId,
    u128
);
numeric_id!(
    /// Function invocation identifier.
    InvocationId,
    u128
);
numeric_id!(
    /// Transaction identifier.
    TransactionId,
    u128
);
numeric_id!(
    /// Correlation identifier shared by a causal tree of events and invocations.
    CorrelationId,
    u128
);

/// Session epoch. Every asynchronous work item carries the epoch it was created in and is
/// discarded as stale when the session has moved on (spec 7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(u64);

impl Epoch {
    /// Wraps a raw epoch number.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The epoch a freshly created session starts in.
    #[must_use]
    pub const fn initial() -> Self {
        Self(0)
    }

    /// Returns the raw epoch number.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// The next epoch, or `None` on overflow. Epochs are never reused.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }
}

impl fmt::Display for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_dunder_needs_four_bytes() {
        assert!(!is_reserved_dunder("__"));
        assert!(!is_reserved_dunder("___"));
        assert!(is_reserved_dunder("____"));
        assert!(is_reserved_dunder("__name__"));
    }
}
