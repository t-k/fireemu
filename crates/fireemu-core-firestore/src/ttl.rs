//! Time-to-live field configuration and expiry selection (`FS-CONFIG-RT-004`).
//!
//! Firestore expresses a time-to-live policy as a field configuration on a collection group:
//! `projects/{p}/databases/{d}/collectionGroups/{cg}/fields/{field}` carries a `ttlConfig`
//! whose state is output-only. A document of that collection group is eligible for deletion
//! once the configured field holds a timestamp whose expiration time is earlier than the
//! current time. The expiration time is the sum of the stored timestamp and the
//! configuration's `expirationOffset`, which defaults to zero. A value that is not a
//! timestamp is ignored: production never deletes such a document and never reports an error
//! for it.
//!
//! Production deletes an eligible document asynchronously, typically within 24 hours of
//! expiry and within 72 hours at worst, so an expired document stays readable until the
//! sweep reaches it. [`SweepSchedule`] reproduces that delay on the virtual clock instead of
//! deleting at the instant of expiry, which would be a behaviour no production client may
//! rely on.

use std::collections::BTreeMap;

use core::fmt;

use fireemu_core_types::ids::CollectionId;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

use crate::field_path::FieldPath;
use crate::value::{Timestamp, Value};

/// Maximum number of collection groups that may carry a time-to-live policy in one database.
///
/// Every configured policy costs one collection-group scan per sweep, so the catalog is
/// bounded to keep the sweep cost a function of the data rather than of how many
/// configurations a caller was able to create.
pub const MAX_TTL_FIELDS_PER_DATABASE: usize = 64;

/// Default interval between expiry sweeps, matching the documented "typically within 24
/// hours" deletion delay.
pub const DEFAULT_SWEEP_INTERVAL: LogicalDuration = LogicalDuration::from_seconds(24 * 60 * 60);

/// The longest sweep interval that still deletes inside the documented 72-hour bound.
pub const MAX_SWEEP_INTERVAL: LogicalDuration = LogicalDuration::from_seconds(72 * 60 * 60);

/// Largest `expirationOffset` a time-to-live configuration may carry, in seconds.
///
/// `google.firestore.admin.v1.Field.TtlConfig.expiration_offset` documents
/// `expiration_offset.seconds` as between 0 and 2,147,483,647 inclusive.
pub const MAX_EXPIRATION_OFFSET_SECONDS: i64 = 2_147_483_647;

/// Why an `expirationOffset` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetError {
    /// The value is not a `google.protobuf.Duration` in its JSON spelling.
    NotADuration,
    /// The duration names a fraction of a second, which the field rejects.
    SubSecondPrecision,
    /// The duration is negative or larger than [`MAX_EXPIRATION_OFFSET_SECONDS`].
    OutOfRange,
}

impl fmt::Display for OffsetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotADuration => f.write_str(
                "ttlConfig.expirationOffset must be a duration in seconds, such as \"604800s\"",
            ),
            Self::SubSecondPrecision => f.write_str(
                "ttlConfig.expirationOffset values more precise than seconds are rejected",
            ),
            Self::OutOfRange => write!(
                f,
                "ttlConfig.expirationOffset seconds must be between 0 and \
                 {MAX_EXPIRATION_OFFSET_SECONDS} inclusive"
            ),
        }
    }
}

impl std::error::Error for OffsetError {}

/// Reads an `expirationOffset` in its `google.protobuf.Duration` JSON spelling.
///
/// The field's own contract is narrower than a duration: the seconds must lie between 0 and
/// [`MAX_EXPIRATION_OFFSET_SECONDS`] inclusive and anything more precise than a second is
/// refused, so `"1.5s"` is an error rather than a rounded value.
pub fn parse_expiration_offset(text: &str) -> Result<LogicalDuration, OffsetError> {
    let body = text.strip_suffix('s').ok_or(OffsetError::NotADuration)?;
    let (seconds, fraction) = match body.split_once('.') {
        Some((seconds, fraction)) => (seconds, Some(fraction)),
        None => (body, None),
    };
    let (negative, digits) = match seconds.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, seconds),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(OffsetError::NotADuration);
    }
    if let Some(fraction) = fraction {
        if fraction.is_empty()
            || fraction.len() > 9
            || !fraction.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(OffsetError::NotADuration);
        }
        if fraction.bytes().any(|b| b != b'0') {
            return Err(OffsetError::SubSecondPrecision);
        }
    }
    let value: i64 = digits.parse().map_err(|_| OffsetError::OutOfRange)?;
    if (negative && value != 0) || value > MAX_EXPIRATION_OFFSET_SECONDS {
        return Err(OffsetError::OutOfRange);
    }
    Ok(LogicalDuration::from_seconds(value))
}

/// Writes an `expirationOffset` back in the spelling a readback reports.
///
/// The field carries whole seconds, so the JSON form never needs a fractional part.
#[must_use]
pub fn format_expiration_offset(offset: LogicalDuration) -> String {
    format!("{}s", offset.as_seconds())
}

/// Output-only state of a time-to-live configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TtlState {
    /// The policy is being applied and does not yet delete anything.
    Creating,
    /// The policy is in force.
    Active,
    /// The policy needs to be re-applied before it deletes anything.
    NeedsRepair,
}

impl TtlState {
    /// The `google.firestore.admin.v1.Field.TtlConfig.State` enum name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "CREATING",
            Self::Active => "ACTIVE",
            Self::NeedsRepair => "NEEDS_REPAIR",
        }
    }
}

impl fmt::Display for TtlState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a time-to-live configuration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtlError {
    /// The collection group already has a time-to-live policy on a different field.
    ConflictingField {
        /// Collection group holding the existing policy.
        collection_group: String,
        /// Canonical field path of the existing policy.
        existing: String,
    },
    /// `__name__` is the document name, never a timestamp.
    DocumentNameField,
    /// The database already holds the maximum number of time-to-live policies.
    TooManyFields {
        /// Inclusive maximum.
        maximum: usize,
    },
}

impl fmt::Display for TtlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConflictingField {
                collection_group,
                existing,
            } => write!(
                f,
                "collection group {collection_group} already has a TTL policy on field {existing}; \
                 a collection group may have at most one TTL field"
            ),
            Self::DocumentNameField => {
                f.write_str("__name__ is the document name and can never hold a timestamp")
            }
            Self::TooManyFields { maximum } => write!(
                f,
                "this database already has {maximum} TTL policies, which is the local maximum"
            ),
        }
    }
}

impl std::error::Error for TtlError {}

/// One collection group's time-to-live policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TtlPolicy {
    /// The field whose timestamp decides expiry.
    pub field: FieldPath,
    /// Output-only state of the policy.
    pub state: TtlState,
    /// The offset added to the stored timestamp to get the expiration time.
    ///
    /// `None` is an unset `expirationOffset`, which a readback omits and which behaves as
    /// zero; `Some(zero)` is an offset the caller spelled out, which a readback reports.
    pub expiration_offset: Option<LogicalDuration>,
}

impl TtlPolicy {
    /// Whether a document's fields make it eligible for deletion at `now` under this policy.
    ///
    /// The expiration time is the stored timestamp plus the configured offset, so a policy
    /// with a one-week offset keeps a document for one week after the timestamp it carries.
    #[must_use]
    pub fn is_expired(&self, fields: &BTreeMap<String, Value>, now: Timestamp) -> bool {
        is_expired_with_offset(fields, &self.field, now, self.expiration_offset)
    }
}

/// One database's time-to-live field configuration.
///
/// A collection group holds at most one policy, which is what the Admin API enforces: a
/// second `fields.patch` naming a different field of the same collection group is refused
/// rather than silently replacing the first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TtlCatalog {
    entries: BTreeMap<CollectionId, TtlPolicy>,
}

impl TtlCatalog {
    /// An empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables a time-to-live policy with no `expirationOffset`, returning the state a
    /// readback reports.
    ///
    /// Re-enabling the field that already carries the policy is accepted and leaves the
    /// state unchanged, so a campaign may replay its own patch.
    pub fn enable(
        &mut self,
        collection_group: CollectionId,
        field: FieldPath,
    ) -> Result<TtlState, TtlError> {
        self.enable_with_offset(collection_group, field, None)
    }

    /// Enables a time-to-live policy carrying an `expirationOffset`.
    ///
    /// Re-enabling the field that already carries the policy installs the offset the patch
    /// names, which is what a second `fields.patch` on the same field asks for: the
    /// configuration is replaced, not merged with the one it replaces.
    pub fn enable_with_offset(
        &mut self,
        collection_group: CollectionId,
        field: FieldPath,
        expiration_offset: Option<LogicalDuration>,
    ) -> Result<TtlState, TtlError> {
        if field.is_document_name() {
            return Err(TtlError::DocumentNameField);
        }
        if let Some(existing) = self.entries.get_mut(&collection_group) {
            if existing.field == field {
                existing.expiration_offset = expiration_offset;
                return Ok(existing.state);
            }
            return Err(TtlError::ConflictingField {
                collection_group: collection_group.as_str().to_owned(),
                existing: existing.field.canonical(),
            });
        }
        if self.entries.len() >= MAX_TTL_FIELDS_PER_DATABASE {
            return Err(TtlError::TooManyFields {
                maximum: MAX_TTL_FIELDS_PER_DATABASE,
            });
        }
        // The local runtime applies a configuration change synchronously, so the readback
        // that follows the patch already reports the policy in force.
        self.entries.insert(
            collection_group,
            TtlPolicy {
                field,
                state: TtlState::Active,
                expiration_offset,
            },
        );
        Ok(TtlState::Active)
    }

    /// Removes the policy on `field`, returning whether one was removed.
    ///
    /// Clearing a field that carries no policy is not an error: the resulting configuration
    /// is the one the caller asked for.
    pub fn disable(&mut self, collection_group: &CollectionId, field: &FieldPath) -> bool {
        let matches = self
            .entries
            .get(collection_group)
            .is_some_and(|policy| &policy.field == field);
        if matches {
            self.entries.remove(collection_group);
        }
        matches
    }

    /// The state reported for one field, absent when the field carries no policy.
    #[must_use]
    pub fn state(&self, collection_group: &CollectionId, field: &FieldPath) -> Option<TtlState> {
        self.entries
            .get(collection_group)
            .filter(|policy| &policy.field == field)
            .map(|policy| policy.state)
    }

    /// One collection group's policy.
    #[must_use]
    pub fn policy(&self, collection_group: &CollectionId) -> Option<&TtlPolicy> {
        self.entries.get(collection_group)
    }

    /// Every configured policy, ordered by collection group.
    pub fn iter(&self) -> impl Iterator<Item = (&CollectionId, &TtlPolicy)> {
        self.entries.iter()
    }

    /// Number of configured policies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no policy is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<'a> IntoIterator for &'a TtlCatalog {
    type Item = (&'a CollectionId, &'a TtlPolicy);
    type IntoIter = std::collections::btree_map::Iter<'a, CollectionId, TtlPolicy>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

/// Whether a document's fields make it eligible for time-to-live deletion at `now`.
///
/// Only a timestamp earlier than `now` is eligible. A missing field, a value of any other
/// type, and a timestamp at or after `now` all keep the document, which is what production
/// does: a non-timestamp value is ignored rather than refused.
#[must_use]
pub fn is_expired(fields: &BTreeMap<String, Value>, field: &FieldPath, now: Timestamp) -> bool {
    is_expired_with_offset(fields, field, now, None)
}

/// Whether a document's fields make it eligible for deletion at `now` under an offset.
///
/// The expiration time is the stored timestamp plus `offset`, so the document is eligible
/// once that sum lies before `now`. The sum is computed in nanoseconds wide enough that an
/// offset added to the largest representable timestamp cannot wrap: an expiration time past
/// the end of the timestamp range is simply never reached.
#[must_use]
pub fn is_expired_with_offset(
    fields: &BTreeMap<String, Value>,
    field: &FieldPath,
    now: Timestamp,
    offset: Option<LogicalDuration>,
) -> bool {
    let Some(Value::Timestamp(at)) = crate::store::get_field(fields, field) else {
        return false;
    };
    let expires_at = total_nanos(*at).saturating_add(offset.map_or(0, LogicalDuration::as_nanos));
    expires_at < total_nanos(now)
}

/// A timestamp as a count of nanoseconds since the epoch.
fn total_nanos(at: Timestamp) -> i128 {
    i128::from(at.seconds()) * 1_000_000_000 + i128::from(at.nanos())
}

/// Converts a logical instant to the timestamp a stored value is compared against.
///
/// An instant outside the representable timestamp range saturates, so a clock set beyond
/// year 9999 expires everything rather than silently sweeping nothing.
#[must_use]
pub fn timestamp_at(now: LogicalInstant) -> Timestamp {
    /// The earliest representable timestamp; nothing stored can sort before it.
    fn floor() -> Timestamp {
        Timestamp::new(Timestamp::MIN_SECONDS, 0).expect("the minimum second is representable")
    }
    /// The latest representable timestamp; every stored timestamp sorts before it.
    fn ceiling() -> Timestamp {
        Timestamp::new(Timestamp::MAX_SECONDS, 999_999_999)
            .expect("the maximum second is representable")
    }
    let nanos = now.as_nanos();
    let seconds = nanos.div_euclid(1_000_000_000);
    let sub = u32::try_from(nanos.rem_euclid(1_000_000_000)).unwrap_or(0);
    let Ok(seconds) = i64::try_from(seconds) else {
        return if nanos.is_negative() {
            floor()
        } else {
            ceiling()
        };
    };
    Timestamp::new(seconds, sub).unwrap_or_else(|_| {
        if seconds < Timestamp::MIN_SECONDS {
            floor()
        } else {
            ceiling()
        }
    })
}

/// When the next expiry sweep is due.
///
/// A sweep runs at most once per interval, so a document that expires just after one sweep
/// stays readable until the next one. That reproduces the documented deletion delay instead
/// of deleting at the instant of expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepSchedule {
    interval: LogicalDuration,
    last: Option<LogicalInstant>,
}

impl SweepSchedule {
    /// A schedule with the given interval that has never swept.
    #[must_use]
    pub const fn new(interval: LogicalDuration) -> Self {
        Self {
            interval,
            last: None,
        }
    }

    /// The configured interval.
    #[must_use]
    pub const fn interval(&self) -> LogicalDuration {
        self.interval
    }

    /// When the last sweep ran.
    #[must_use]
    pub const fn last_swept_at(&self) -> Option<LogicalInstant> {
        self.last
    }

    /// Whether a sweep is due at `now`.
    ///
    /// The first call establishes the baseline rather than sweeping immediately: a run that
    /// starts with an already-expired document must still observe it for one interval, which
    /// is what a client that wrote the document against production would see.
    #[must_use]
    pub fn due(&self, now: LogicalInstant) -> bool {
        match self.last {
            None => false,
            Some(last) => match last.checked_add(self.interval) {
                Some(next) => now >= next,
                None => false,
            },
        }
    }

    /// Records that a sweep ran at `now`, or establishes the baseline on the first call.
    pub fn mark(&mut self, now: LogicalInstant) {
        self.last = Some(now);
    }

    /// Establishes the baseline if none is set, without recording a sweep.
    pub fn start(&mut self, now: LogicalInstant) {
        if self.last.is_none() {
            self.last = Some(now);
        }
    }
}

impl Default for SweepSchedule {
    fn default() -> Self {
        Self::new(DEFAULT_SWEEP_INTERVAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(name: &str) -> CollectionId {
        CollectionId::try_new(name).expect("collection id")
    }

    fn path(name: &str) -> FieldPath {
        FieldPath::parse(name).expect("field path")
    }

    fn at(seconds: i64) -> Timestamp {
        Timestamp::new(seconds, 0).expect("timestamp")
    }

    #[test]
    fn enabling_a_policy_reports_it_active_on_readback() {
        let mut catalog = TtlCatalog::new();
        let state = catalog
            .enable(group("orders"), path("expiresAt"))
            .expect("enable");
        assert_eq!(state, TtlState::Active);
        assert_eq!(
            catalog.state(&group("orders"), &path("expiresAt")),
            Some(TtlState::Active)
        );
    }

    #[test]
    fn a_field_without_a_policy_reports_no_state() {
        let mut catalog = TtlCatalog::new();
        catalog
            .enable(group("orders"), path("expiresAt"))
            .expect("enable");
        assert_eq!(catalog.state(&group("orders"), &path("other")), None);
        assert_eq!(catalog.state(&group("carts"), &path("expiresAt")), None);
    }

    #[test]
    fn a_second_ttl_field_in_one_collection_group_is_refused() {
        let mut catalog = TtlCatalog::new();
        catalog
            .enable(group("orders"), path("expiresAt"))
            .expect("enable");
        let error = catalog
            .enable(group("orders"), path("purgeAt"))
            .expect_err("second field");
        assert_eq!(
            error,
            TtlError::ConflictingField {
                collection_group: "orders".to_owned(),
                existing: "expiresAt".to_owned(),
            }
        );
        assert_eq!(catalog.state(&group("orders"), &path("purgeAt")), None);
    }

    #[test]
    fn re_enabling_the_same_field_is_accepted() {
        let mut catalog = TtlCatalog::new();
        catalog
            .enable(group("orders"), path("expiresAt"))
            .expect("enable");
        assert_eq!(
            catalog.enable(group("orders"), path("expiresAt")),
            Ok(TtlState::Active)
        );
        assert_eq!(catalog.len(), 1);
    }

    #[test]
    fn the_document_name_can_never_carry_a_policy() {
        let mut catalog = TtlCatalog::new();
        assert_eq!(
            catalog.enable(group("orders"), FieldPath::document_name()),
            Err(TtlError::DocumentNameField)
        );
        assert!(catalog.is_empty());
    }

    #[test]
    fn the_catalog_refuses_more_policies_than_the_local_maximum() {
        let mut catalog = TtlCatalog::new();
        for i in 0..MAX_TTL_FIELDS_PER_DATABASE {
            catalog
                .enable(group(&format!("g{i}")), path("expiresAt"))
                .expect("enable");
        }
        assert_eq!(
            catalog.enable(group("one-too-many"), path("expiresAt")),
            Err(TtlError::TooManyFields {
                maximum: MAX_TTL_FIELDS_PER_DATABASE
            })
        );
    }

    #[test]
    fn disabling_removes_only_the_named_field() {
        let mut catalog = TtlCatalog::new();
        catalog
            .enable(group("orders"), path("expiresAt"))
            .expect("enable");
        assert!(!catalog.disable(&group("orders"), &path("other")));
        assert_eq!(
            catalog.state(&group("orders"), &path("expiresAt")),
            Some(TtlState::Active)
        );
        assert!(catalog.disable(&group("orders"), &path("expiresAt")));
        assert!(catalog.is_empty());
    }

    #[test]
    fn a_timestamp_before_now_is_expired() {
        let mut fields = BTreeMap::new();
        fields.insert("expiresAt".to_owned(), Value::Timestamp(at(10)));
        assert!(is_expired(&fields, &path("expiresAt"), at(11)));
        assert!(!is_expired(&fields, &path("expiresAt"), at(10)));
        assert!(!is_expired(&fields, &path("expiresAt"), at(9)));
    }

    #[test]
    fn a_non_timestamp_value_is_ignored_rather_than_expired() {
        let mut fields = BTreeMap::new();
        fields.insert("expiresAt".to_owned(), Value::Integer(10));
        assert!(!is_expired(&fields, &path("expiresAt"), at(1_000)));
        fields.insert("expiresAt".to_owned(), Value::String("2020".to_owned()));
        assert!(!is_expired(&fields, &path("expiresAt"), at(1_000)));
        fields.insert("expiresAt".to_owned(), Value::Null);
        assert!(!is_expired(&fields, &path("expiresAt"), at(1_000)));
    }

    #[test]
    fn a_missing_field_is_never_expired() {
        let fields = BTreeMap::new();
        assert!(!is_expired(&fields, &path("expiresAt"), at(1_000)));
    }

    #[test]
    fn a_nested_timestamp_field_is_expired_through_its_path() {
        let mut inner = BTreeMap::new();
        inner.insert("at".to_owned(), Value::Timestamp(at(10)));
        let mut fields = BTreeMap::new();
        fields.insert("ttl".to_owned(), Value::Map(inner));
        assert!(is_expired(&fields, &path("ttl.at"), at(11)));
        assert!(!is_expired(&fields, &path("ttl.at"), at(10)));
    }

    #[test]
    fn a_sweep_is_not_due_before_one_interval_has_passed() {
        let mut schedule = SweepSchedule::new(LogicalDuration::from_seconds(100));
        schedule.start(LogicalInstant::from_unix_seconds(0));
        assert!(!schedule.due(LogicalInstant::from_unix_seconds(99)));
        assert!(schedule.due(LogicalInstant::from_unix_seconds(100)));
        assert!(schedule.due(LogicalInstant::from_unix_seconds(1_000)));
    }

    #[test]
    fn a_sweep_is_never_due_before_the_baseline_is_established() {
        let schedule = SweepSchedule::new(LogicalDuration::from_seconds(100));
        assert!(!schedule.due(LogicalInstant::from_unix_seconds(1_000_000)));
    }

    #[test]
    fn marking_a_sweep_defers_the_next_one_by_one_interval() {
        let mut schedule = SweepSchedule::new(LogicalDuration::from_seconds(100));
        schedule.start(LogicalInstant::from_unix_seconds(0));
        schedule.mark(LogicalInstant::from_unix_seconds(150));
        assert_eq!(
            schedule.last_swept_at(),
            Some(LogicalInstant::from_unix_seconds(150))
        );
        assert!(!schedule.due(LogicalInstant::from_unix_seconds(249)));
        assert!(schedule.due(LogicalInstant::from_unix_seconds(250)));
    }

    #[test]
    fn starting_twice_keeps_the_first_baseline() {
        let mut schedule = SweepSchedule::new(LogicalDuration::from_seconds(100));
        schedule.start(LogicalInstant::from_unix_seconds(10));
        schedule.start(LogicalInstant::from_unix_seconds(90));
        assert_eq!(
            schedule.last_swept_at(),
            Some(LogicalInstant::from_unix_seconds(10))
        );
    }

    fn ttl_policy(field_path: &str, offset: Option<LogicalDuration>) -> TtlPolicy {
        TtlPolicy {
            field: path(field_path),
            state: TtlState::Active,
            expiration_offset: offset,
        }
    }

    #[test]
    fn an_offset_moves_the_expiration_time_past_the_stored_timestamp() {
        let mut fields = BTreeMap::new();
        fields.insert("expiresAt".to_owned(), Value::Timestamp(at(1_000)));
        let week = LogicalDuration::from_seconds(604_800);
        let policy = ttl_policy("expiresAt", Some(week));
        // The expiration time is the sum, so nothing expires until one offset has passed.
        assert!(!policy.is_expired(&fields, at(1_000 + 604_800)));
        assert!(policy.is_expired(&fields, at(1_000 + 604_801)));
        // The same document under no offset is already expired.
        assert!(ttl_policy("expiresAt", None).is_expired(&fields, at(1_001)));
    }

    #[test]
    fn an_offset_spelled_as_zero_behaves_as_no_offset() {
        let mut fields = BTreeMap::new();
        fields.insert("expiresAt".to_owned(), Value::Timestamp(at(1_000)));
        let zero = ttl_policy("expiresAt", Some(LogicalDuration::from_seconds(0)));
        assert!(!zero.is_expired(&fields, at(1_000)));
        assert!(zero.is_expired(&fields, at(1_001)));
    }

    #[test]
    fn an_offset_never_expires_a_value_that_is_not_a_timestamp() {
        let mut fields = BTreeMap::new();
        fields.insert("expiresAt".to_owned(), Value::Integer(1));
        let policy = ttl_policy("expiresAt", Some(LogicalDuration::from_seconds(1)));
        assert!(!policy.is_expired(&fields, at(1_000_000)));
    }

    #[test]
    fn an_offset_on_the_largest_timestamp_is_never_reached() {
        let mut fields = BTreeMap::new();
        fields.insert(
            "expiresAt".to_owned(),
            Value::Timestamp(Timestamp::new(Timestamp::MAX_SECONDS, 999_999_999).expect("max")),
        );
        let policy = ttl_policy(
            "expiresAt",
            Some(LogicalDuration::from_seconds(MAX_EXPIRATION_OFFSET_SECONDS)),
        );
        assert!(!policy.is_expired(&fields, at(Timestamp::MAX_SECONDS)));
    }

    #[test]
    fn enabling_with_an_offset_reports_it_on_readback() {
        let mut catalog = TtlCatalog::new();
        let week = LogicalDuration::from_seconds(604_800);
        catalog
            .enable_with_offset(group("orders"), path("expiresAt"), Some(week))
            .expect("enable");
        assert_eq!(
            catalog
                .policy(&group("orders"))
                .expect("policy")
                .expiration_offset,
            Some(week)
        );
    }

    #[test]
    fn re_enabling_the_same_field_replaces_the_offset() {
        let mut catalog = TtlCatalog::new();
        catalog
            .enable_with_offset(
                group("orders"),
                path("expiresAt"),
                Some(LogicalDuration::from_seconds(60)),
            )
            .expect("enable");
        catalog
            .enable_with_offset(group("orders"), path("expiresAt"), None)
            .expect("re-enable");
        assert_eq!(
            catalog
                .policy(&group("orders"))
                .expect("policy")
                .expiration_offset,
            None
        );
        assert_eq!(catalog.len(), 1);
    }

    #[test]
    fn a_conflicting_field_leaves_the_offset_of_the_policy_in_force() {
        let mut catalog = TtlCatalog::new();
        let minute = LogicalDuration::from_seconds(60);
        catalog
            .enable_with_offset(group("orders"), path("expiresAt"), Some(minute))
            .expect("enable");
        catalog
            .enable_with_offset(group("orders"), path("purgeAt"), None)
            .expect_err("conflicting field");
        assert_eq!(
            catalog
                .policy(&group("orders"))
                .expect("policy")
                .expiration_offset,
            Some(minute)
        );
    }

    #[test]
    fn a_whole_second_duration_is_the_offset_it_names() {
        assert_eq!(
            parse_expiration_offset("604800s"),
            Ok(LogicalDuration::from_seconds(604_800))
        );
        assert_eq!(
            parse_expiration_offset("0s"),
            Ok(LogicalDuration::from_seconds(0))
        );
        assert_eq!(
            parse_expiration_offset("-0s"),
            Ok(LogicalDuration::from_seconds(0))
        );
        assert_eq!(
            parse_expiration_offset("60.000000000s"),
            Ok(LogicalDuration::from_seconds(60))
        );
    }

    #[test]
    fn a_duration_more_precise_than_seconds_is_refused() {
        assert_eq!(
            parse_expiration_offset("1.5s"),
            Err(OffsetError::SubSecondPrecision)
        );
        assert_eq!(
            parse_expiration_offset("0.000000001s"),
            Err(OffsetError::SubSecondPrecision)
        );
    }

    #[test]
    fn a_duration_outside_the_documented_range_is_refused() {
        assert_eq!(parse_expiration_offset("-1s"), Err(OffsetError::OutOfRange));
        assert_eq!(
            parse_expiration_offset(&format!("{}s", MAX_EXPIRATION_OFFSET_SECONDS + 1)),
            Err(OffsetError::OutOfRange)
        );
        assert_eq!(
            parse_expiration_offset(&format!("{MAX_EXPIRATION_OFFSET_SECONDS}s")),
            Ok(LogicalDuration::from_seconds(MAX_EXPIRATION_OFFSET_SECONDS))
        );
        assert_eq!(
            parse_expiration_offset("99999999999999999999s"),
            Err(OffsetError::OutOfRange)
        );
    }

    #[test]
    fn a_value_that_is_not_a_duration_is_refused() {
        for text in [
            "604800",
            "s",
            "",
            "abc",
            "1e3s",
            " 1s",
            "1.s",
            "1.0000000000s",
        ] {
            assert_eq!(
                parse_expiration_offset(text),
                Err(OffsetError::NotADuration),
                "{text:?}"
            );
        }
    }

    #[test]
    fn an_offset_reads_back_in_the_spelling_it_was_given() {
        assert_eq!(
            format_expiration_offset(LogicalDuration::from_seconds(604_800)),
            "604800s"
        );
        assert_eq!(
            format_expiration_offset(LogicalDuration::from_seconds(0)),
            "0s"
        );
    }

    #[test]
    fn a_logical_instant_converts_to_the_timestamp_it_names() {
        assert_eq!(timestamp_at(LogicalInstant::from_unix_seconds(5)), at(5));
        assert_eq!(
            timestamp_at(LogicalInstant::from_nanos(-1)),
            Timestamp::new(-1, 999_999_999).expect("timestamp")
        );
    }

    #[test]
    fn the_default_sweep_interval_is_the_documented_twenty_four_hours() {
        assert_eq!(
            SweepSchedule::default().interval(),
            LogicalDuration::from_seconds(86_400)
        );
    }
}
