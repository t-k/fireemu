//! The canonical function manifest (spec 12.3) and trigger matching.

use std::collections::BTreeMap;
use std::fmt;

use crate::cron::Schedule;
use crate::pattern::PathPattern;

/// Default region of a function.
pub const DEFAULT_REGION: &str = "us-central1";
/// Default invocation timeout.
pub const DEFAULT_TIMEOUT_SECONDS: u32 = 60;
/// Default per-function concurrency.
pub const DEFAULT_CONCURRENCY: u32 = 1;

/// Firestore document event kinds (`google.cloud.firestore.document.v1.*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DocumentEvent {
    /// A document was created.
    Created,
    /// An existing document changed.
    Updated,
    /// A document was deleted.
    Deleted,
    /// Any of the above.
    Written,
}

impl DocumentEvent {
    /// `CloudEvents` type.
    #[must_use]
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::Created => "google.cloud.firestore.document.v1.created",
            Self::Updated => "google.cloud.firestore.document.v1.updated",
            Self::Deleted => "google.cloud.firestore.document.v1.deleted",
            Self::Written => "google.cloud.firestore.document.v1.written",
        }
    }

    /// Parses a `CloudEvents` type (the `.withAuthContext` variants map to the same kind).
    #[must_use]
    pub fn from_event_type(s: &str) -> Option<Self> {
        let base = s.strip_suffix(".withAuthContext").unwrap_or(s);
        match base {
            "google.cloud.firestore.document.v1.created" => Some(Self::Created),
            "google.cloud.firestore.document.v1.updated" => Some(Self::Updated),
            "google.cloud.firestore.document.v1.deleted" => Some(Self::Deleted),
            "google.cloud.firestore.document.v1.written" => Some(Self::Written),
            _ => None,
        }
    }

    /// Whether a trigger of this kind fires for a change of `actual` kind (`Written` fires
    /// for everything).
    #[must_use]
    pub const fn accepts(self, actual: Self) -> bool {
        matches!(self, Self::Written) || (self as u8) == (actual as u8)
    }
}

/// Storage object event kinds (`google.cloud.storage.object.v1.*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectEvent {
    /// A new generation was committed.
    Finalized,
    /// A generation was deleted.
    Deleted,
    /// Metadata changed.
    MetadataUpdated,
    /// A generation was archived (versioned buckets only).
    Archived,
}

impl ObjectEvent {
    /// `CloudEvents` type.
    #[must_use]
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::Finalized => "google.cloud.storage.object.v1.finalized",
            Self::Deleted => "google.cloud.storage.object.v1.deleted",
            Self::MetadataUpdated => "google.cloud.storage.object.v1.metadataUpdated",
            Self::Archived => "google.cloud.storage.object.v1.archived",
        }
    }

    /// Parses a `CloudEvents` type.
    #[must_use]
    pub fn from_event_type(s: &str) -> Option<Self> {
        match s {
            "google.cloud.storage.object.v1.finalized" => Some(Self::Finalized),
            "google.cloud.storage.object.v1.deleted" => Some(Self::Deleted),
            "google.cloud.storage.object.v1.metadataUpdated" => Some(Self::MetadataUpdated),
            "google.cloud.storage.object.v1.archived" => Some(Self::Archived),
            _ => None,
        }
    }
}

/// What invokes a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trigger {
    /// HTTP request (`onRequest`) or callable (`onCall`).
    Http {
        /// Callable protocol.
        callable: bool,
    },
    /// Firestore document change.
    Firestore {
        /// Event kind.
        event: DocumentEvent,
        /// Database (`(default)`).
        database: String,
        /// Document path pattern.
        document: PathPattern,
    },
    /// Cloud Storage object change.
    Storage {
        /// Event kind.
        event: ObjectEvent,
        /// Bucket (`None` = the project's default bucket).
        bucket: Option<String>,
    },
    /// Scheduled run.
    Schedule {
        /// Schedule.
        schedule: Schedule,
        /// IANA time zone (`None` = UTC).
        time_zone: Option<String>,
    },
}

/// One function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSpec {
    /// Name (unique within the manifest).
    pub name: String,
    /// Region.
    pub region: String,
    /// Entry point exported by the codebase (defaults to the name).
    pub entry_point: String,
    /// Trigger.
    pub trigger: Trigger,
    /// Invocation timeout.
    pub timeout_seconds: u32,
    /// Retry failed event invocations (up to the runtime's retry policy).
    pub retry: bool,
    /// Maximum concurrent invocations.
    pub concurrency: u32,
}

/// The function manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionManifest {
    /// Functions.
    pub functions: Vec<FunctionSpec>,
}

/// Manifest validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// Two functions share a name.
    DuplicateName(String),
    /// Invalid name.
    InvalidName(String),
    /// Zero timeout or concurrency.
    InvalidLimit {
        /// Function.
        function: String,
        /// Field.
        field: &'static str,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateName(n) => write!(f, "function {n:?} is declared twice"),
            Self::InvalidName(n) => write!(f, "invalid function name {n:?}"),
            Self::InvalidLimit { function, field } => {
                write!(f, "function {function:?}: {field} must be at least 1")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

/// A Firestore trigger matched by a document change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirestoreMatch<'a> {
    /// The function.
    pub function: &'a FunctionSpec,
    /// Captured path parameters.
    pub params: BTreeMap<String, String>,
}

impl FunctionManifest {
    /// Validates names, uniqueness and limits.
    pub fn validate(&self) -> Result<(), ManifestError> {
        let mut seen: Vec<&str> = Vec::new();
        for f in &self.functions {
            if f.name.is_empty()
                || !f
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err(ManifestError::InvalidName(f.name.clone()));
            }
            if seen.contains(&f.name.as_str()) {
                return Err(ManifestError::DuplicateName(f.name.clone()));
            }
            seen.push(&f.name);
            if f.timeout_seconds == 0 {
                return Err(ManifestError::InvalidLimit {
                    function: f.name.clone(),
                    field: "timeoutSeconds",
                });
            }
            if f.concurrency == 0 {
                return Err(ManifestError::InvalidLimit {
                    function: f.name.clone(),
                    field: "concurrency",
                });
            }
        }
        Ok(())
    }

    /// The function called `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&FunctionSpec> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Functions whose Firestore trigger fires for a change of `actual` kind to `path`
    /// (relative to `documents/`) in `database`, with their captured parameters.
    #[must_use]
    pub fn firestore_matches(
        &self,
        database: &str,
        path: &str,
        actual: DocumentEvent,
    ) -> Vec<FirestoreMatch<'_>> {
        self.functions
            .iter()
            .filter_map(|f| match &f.trigger {
                Trigger::Firestore {
                    event,
                    database: db,
                    document,
                } if db == database && event.accepts(actual) => {
                    document.matches(path).map(|params| FirestoreMatch {
                        function: f,
                        params,
                    })
                }
                _ => None,
            })
            .collect()
    }

    /// Functions whose Storage trigger fires for `event` on `bucket` (`default_bucket` is
    /// what a trigger without a bucket listens to).
    #[must_use]
    pub fn storage_matches(
        &self,
        bucket: &str,
        default_bucket: &str,
        event: ObjectEvent,
    ) -> Vec<&FunctionSpec> {
        self.functions
            .iter()
            .filter(|f| match &f.trigger {
                Trigger::Storage {
                    event: e,
                    bucket: b,
                } => *e == event && b.as_deref().unwrap_or(default_bucket) == bucket,
                _ => false,
            })
            .collect()
    }

    /// Scheduled functions.
    pub fn scheduled(&self) -> impl Iterator<Item = (&FunctionSpec, &Schedule, Option<&str>)> {
        self.functions.iter().filter_map(|f| match &f.trigger {
            Trigger::Schedule {
                schedule,
                time_zone,
            } => Some((f, schedule, time_zone.as_deref())),
            _ => None,
        })
    }
}
