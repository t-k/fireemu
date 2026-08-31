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

/// Auth user lifecycle event kinds (v1 `auth.user().onCreate` / `onDelete`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthEvent {
    /// A user was created.
    Created,
    /// A user was deleted.
    Deleted,
}

/// Synchronous Identity Platform blocking events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockingAuthEvent {
    /// Before a new user is committed.
    BeforeCreate,
    /// Before a successful sign-in is committed.
    BeforeSignIn,
}

impl BlockingAuthEvent {
    /// Short event spelling used by firebase-functions.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeCreate => "beforeCreate",
            Self::BeforeSignIn => "beforeSignIn",
        }
    }

    /// Parses either the short or legacy provider event type.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        if value.ends_with("beforeCreate") {
            Some(Self::BeforeCreate)
        } else if value.ends_with("beforeSignIn") {
            Some(Self::BeforeSignIn)
        } else {
            None
        }
    }
}

impl AuthEvent {
    /// Canonical event type.
    #[must_use]
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::Created => "google.firebase.auth.user.v1.created",
            Self::Deleted => "google.firebase.auth.user.v1.deleted",
        }
    }

    /// The legacy (v1) event type the SDK declares.
    #[must_use]
    pub const fn legacy_event_type(self) -> &'static str {
        match self {
            Self::Created => "providers/firebase.auth/eventTypes/user.create",
            Self::Deleted => "providers/firebase.auth/eventTypes/user.delete",
        }
    }

    /// Parses either form.
    #[must_use]
    pub fn from_event_type(s: &str) -> Option<Self> {
        match s {
            "google.firebase.auth.user.v1.created"
            | "providers/firebase.auth/eventTypes/user.create" => Some(Self::Created),
            "google.firebase.auth.user.v1.deleted"
            | "providers/firebase.auth/eventTypes/user.delete" => Some(Self::Deleted),
            _ => None,
        }
    }
}

/// What a callable declared for `consumeAppCheckToken`, three-valued and fail-closed
/// (specification section 13.4).
///
/// The option lives inside the callable wrapper's closure, so it cannot be read off the
/// deployed endpoint: the runner has to observe it as the callable is declared. When it cannot
/// — an unsupported `firebase-functions` version, a callable built without passing through the
/// instrumented export — the answer is [`Self::Undetermined`], never a guessed `Disabled`. A
/// hidden `consumeAppCheckToken: true` would otherwise run with `alreadyConsumed: false`, which
/// is exactly the silent wrong answer replay protection exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConsumeAppCheckToken {
    /// The callable declared `false`, or declared nothing at all.
    Disabled,
    /// The callable declared `true`. Unsupported while `APPCHECK-REPLAY-1` is unimplemented.
    Enabled,
    /// The value could not be observed.
    #[default]
    Undetermined,
}

impl ConsumeAppCheckToken {
    /// The manifest spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
            Self::Undetermined => "undetermined",
        }
    }

    /// Parses the manifest spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "disabled" => Some(Self::Disabled),
            "enabled" => Some(Self::Enabled),
            "undetermined" => Some(Self::Undetermined),
            _ => None,
        }
    }
}

impl Trigger {
    /// An HTTP trigger with no callable App Check options observed.
    ///
    /// `onRequest` functions never get an automatic App Check decision, so the options are
    /// meaningless for them; a callable built this way is undetermined and fails closed.
    #[must_use]
    pub const fn http(callable: bool) -> Self {
        Self::Http {
            callable,
            enforce_app_check: false,
            consume_app_check_token: ConsumeAppCheckToken::Undetermined,
        }
    }
}

/// A task queue's retry policy.
///
/// The defaults are `RETRY_CONFIG_DEFAULTS` (`tasksEmulator.js:11`), and they are applied the
/// way the emulator applies them -- with `??`, so both an absent value and the explicit
/// `null` the discovered manifest carries fall through to the default.
///
/// Durations are milliseconds rather than the official seconds because the default
/// `minBackoffSeconds` is `0.1`: a whole-second type would lose it, and a floating-point one
/// would cost the manifest its `Eq`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskRetryConfig {
    /// Attempts before a task is given up on.
    pub max_attempts: u32,
    /// A wall-clock budget that lets retries continue past `max_attempts`; `None` (the
    /// default) leaves `max_attempts` in sole charge.
    pub max_retry_millis: Option<u64>,
    /// Backoff ceiling.
    pub max_backoff_millis: u64,
    /// How many times the backoff may double before it grows linearly.
    pub max_doublings: u32,
    /// Backoff unit.
    pub min_backoff_millis: u64,
}

impl Default for TaskRetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            max_retry_millis: None,
            max_backoff_millis: 60 * 60 * 1000,
            max_doublings: 16,
            min_backoff_millis: 100,
        }
    }
}

/// Cloud Scheduler retry settings attached to an `onSchedule` function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduleRetryConfig {
    /// Additional attempts after the first invocation.
    pub retry_count: u32,
    /// Total retry window in seconds; zero means no time-based limit.
    pub max_retry_seconds: u64,
    /// Backoff ceiling in seconds.
    pub max_backoff_seconds: u64,
    /// Number of exponential doublings before the delay grows linearly.
    pub max_doublings: u32,
    /// Initial backoff in seconds.
    pub min_backoff_seconds: u64,
}

impl Default for ScheduleRetryConfig {
    fn default() -> Self {
        Self {
            retry_count: 0,
            max_retry_seconds: 0,
            max_backoff_seconds: 3_600,
            max_doublings: 5,
            min_backoff_seconds: 5,
        }
    }
}

impl TaskRetryConfig {
    /// The backoff before attempt `attempt` (1-based), by the official formula
    /// (`taskQueue.js:263`).
    #[must_use]
    pub fn backoff_millis(&self, attempt: u32) -> u64 {
        let doublings = f64::from(self.max_doublings);
        let multiplier = 2f64.powf(f64::from(attempt.saturating_sub(1)).min(doublings))
            + f64::from(attempt.saturating_sub(self.max_doublings + 1)).max(0.0)
                * 2f64.powf(doublings);
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation
        )]
        let scaled = (multiplier * self.min_backoff_millis as f64).min(u64::MAX as f64) as u64;
        self.max_backoff_millis.min(scaled)
    }

    /// Whether a task on its `attempt`-th delivery, `elapsed_millis` after it was first
    /// dispatched, has run out of retries (`shouldStopRetrying`, `taskQueue.js:252`).
    ///
    /// A positive `maxRetrySeconds` deliberately lets a task keep retrying past
    /// `maxAttempts` until the wall clock runs out; the default does not.
    #[must_use]
    pub fn exhausted(&self, attempt: u32, elapsed_millis: u64) -> bool {
        if attempt <= self.max_attempts {
            return false;
        }
        match self.max_retry_millis {
            None | Some(0) => true,
            Some(budget) => elapsed_millis > budget,
        }
    }
}

/// A task queue's rate limits (`RATE_LIMITS_DEFAULT`, `tasksEmulator.js:18`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskRateLimits {
    /// How many tasks of this queue may be in flight at once.
    pub max_concurrent_dispatches: u32,
    /// The token-bucket refill rate.
    pub max_dispatches_per_second: u32,
}

impl Default for TaskRateLimits {
    fn default() -> Self {
        Self {
            max_concurrent_dispatches: 1000,
            max_dispatches_per_second: 500,
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
        /// The callable's effective `enforceAppCheck`, global options included. Meaningless
        /// for an `onRequest` function, which never gets an automatic App Check decision
        /// (specification section 7.3).
        enforce_app_check: bool,
        /// The callable's `consumeAppCheckToken`, as the runner could observe it.
        consume_app_check_token: ConsumeAppCheckToken,
    },
    /// Firestore document change.
    Firestore {
        /// Event kind.
        event: DocumentEvent,
        /// Database (`(default)`).
        database: String,
        /// Document path pattern.
        document: PathPattern,
        /// `*.withAuthContext`: events carry the principal that made the change.
        with_auth_context: bool,
    },
    /// A Pub/Sub message on a topic (short name).
    PubSub {
        /// Topic.
        topic: String,
    },
    /// An Auth user lifecycle event.
    Auth {
        /// Event kind.
        event: AuthEvent,
    },
    /// Identity Platform request-blocking function.
    BlockingAuth {
        /// Before-create or before-sign-in.
        event: BlockingAuthEvent,
    },
    /// Cloud Storage object change.
    Storage {
        /// Event kind.
        event: ObjectEvent,
        /// Bucket (`None` = the project's default bucket).
        bucket: Option<String>,
    },
    /// A Cloud Tasks queue function (`onTaskDispatched`).
    ///
    /// It is an HTTP function that only the queue calls: the official emulator sets both
    /// `httpsTrigger` and `taskQueueTrigger` on the definition, gives it the ordinary
    /// `/{project}/{region}/{name}` URL, and registers that URL as the queue's `defaultUri`.
    TaskQueue {
        /// The retry policy, with the official defaults filled in.
        retry: TaskRetryConfig,
        /// The rate limits, with the official defaults filled in.
        rate_limits: TaskRateLimits,
    },
    /// A custom event published on an Eventarc channel (`onCustomEventPublished`).
    Eventarc {
        /// The `type` attribute the trigger listens for.
        event_type: String,
        /// The channel, as `firebase-functions` writes it:
        /// `locations/<location>/channels/<channel>`. The emulator keys its trigger table on
        /// `<eventType>-<channel>` and, when a channel is not named, on the literal `google`.
        channel: String,
        /// `eventFilters` beyond the type, matched against the published event's attributes.
        filters: BTreeMap<String, String>,
    },
    /// Scheduled run.
    Schedule {
        /// Schedule.
        schedule: Schedule,
        /// IANA time zone (`None` = UTC).
        time_zone: Option<String>,
        /// Per-function Cloud Scheduler retry policy.
        retry: ScheduleRetryConfig,
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

/// Why an exported function is not served, in the daemon's product-scope vocabulary.
///
/// The official emulator never fails on one: it logs `Unsupported trigger` (DEBUG) or
/// `Unsupported function type on <name>` (WARN) and records the definition with
/// `ignored: true` (`functionsEmulator.js:488`, `:497`, `:501`). fireemu keeps the inventory
/// for the same reason -- an export must never disappear -- but distinguishes a product it
/// does not serve, where continuing would let a project believe a trigger runs, from a shape
/// nobody recognises, where the official emulator's carry-on is the compatible answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoredScope {
    /// The product has an open compatibility issue and no implementation.
    Deferred,
    /// The product is on the active list and not implemented yet.
    Planned,
    /// A closed product decision: it will not be served.
    NotPlanned,
    /// Neither the official emulator nor this runner recognises the shape.
    Unsupported,
}

impl IgnoredScope {
    /// The manifest spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Deferred => "deferred",
            Self::Planned => "planned",
            Self::NotPlanned => "notPlanned",
            Self::Unsupported => "unsupported",
        }
    }

    /// Parses the manifest spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "deferred" => Some(Self::Deferred),
            "planned" => Some(Self::Planned),
            "notPlanned" => Some(Self::NotPlanned),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }

    /// Whether an export of this scope is fatal to discovery.
    ///
    /// A product decision is: the daemon serves no such product, so the function would never
    /// run and saying nothing would be a silently wrong answer. An unrecognised shape is not:
    /// that is what the official emulator carries on from.
    #[must_use]
    pub const fn is_product_decision(self) -> bool {
        matches!(self, Self::Deferred | Self::Planned | Self::NotPlanned)
    }
}

/// One exported function the runner discovered and cannot serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoredFunction {
    /// Name, as exported.
    pub name: String,
    /// Region.
    pub region: String,
    /// The trigger family, in the daemon's spelling (`database`, `eventarc`, `unknown`, ...).
    pub trigger_type: String,
    /// Why it is not served.
    pub scope: IgnoredScope,
    /// The sentence the daemon prints or refuses with.
    pub reason: String,
}

/// The function manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionManifest {
    /// Functions.
    pub functions: Vec<FunctionSpec>,
    /// Exports the runner discovered and cannot serve. Never empty by omission: an export
    /// that is not in `functions` is in here with the reason.
    pub ignored: Vec<IgnoredFunction>,
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

/// The `locations/<l>/channels/<c>` tail of a channel name, whichever of the two spellings
/// it arrived in.
#[must_use]
pub fn channel_suffix(channel: &str) -> &str {
    match channel.find("locations/") {
        Some(i) => &channel[i..],
        None => channel,
    }
}

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
                    ..
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

    /// Functions whose Eventarc trigger fires for an event of `event_type` on `channel`
    /// carrying `attributes`.
    ///
    /// The channel is compared after normalising the two spellings the official emulator
    /// keys its table with: a full `projects/<p>/locations/<l>/channels/<c>` resource name
    /// (what the Admin SDK publishes to) and the `locations/<l>/channels/<c>` form
    /// `firebase-functions` puts in the endpoint. Filters are matched as
    /// `EventarcEmulator.matchesAll` matches them: every declared filter must equal the
    /// event's attribute of that name.
    #[must_use]
    pub fn eventarc_matches(
        &self,
        channel: &str,
        event_type: &str,
        attributes: &BTreeMap<String, String>,
    ) -> Vec<&FunctionSpec> {
        let wanted = channel_suffix(channel);
        self.functions
            .iter()
            .filter(|f| match &f.trigger {
                Trigger::Eventarc {
                    event_type: t,
                    channel: c,
                    filters,
                } => {
                    t == event_type
                        && channel_suffix(c) == wanted
                        && filters
                            .iter()
                            .all(|(k, v)| attributes.get(k).is_some_and(|actual| actual == v))
                }
                _ => false,
            })
            .collect()
    }

    /// Functions subscribed to `topic`.
    #[must_use]
    pub fn pubsub_matches(&self, topic: &str) -> Vec<&FunctionSpec> {
        self.functions
            .iter()
            .filter(|f| matches!(&f.trigger, Trigger::PubSub { topic: t } if t == topic))
            .collect()
    }

    /// Functions listening to `event` on users.
    #[must_use]
    pub fn auth_matches(&self, event: AuthEvent) -> Vec<&FunctionSpec> {
        self.functions
            .iter()
            .filter(|f| matches!(&f.trigger, Trigger::Auth { event: e } if *e == event))
            .collect()
    }

    /// Scheduled functions.
    pub fn scheduled(&self) -> impl Iterator<Item = (&FunctionSpec, &Schedule, Option<&str>)> {
        self.functions.iter().filter_map(|f| match &f.trigger {
            Trigger::Schedule {
                schedule,
                time_zone,
                ..
            } => Some((f, schedule, time_zone.as_deref())),
            _ => None,
        })
    }
}
