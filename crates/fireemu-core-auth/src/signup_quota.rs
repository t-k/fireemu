//! Deterministic local sign-up quota simulation.
//!
//! This module models a bounded, fixed-window counter for local testing. It does not claim to
//! reproduce Firebase's private abuse detection or production quota accounting. The caller must
//! obtain a trusted transport peer address and pass the normalized address here; request bodies
//! and `X-Forwarded-For` values are not accepted as an address source by this module.

use std::collections::{BTreeMap, BTreeSet};

use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

const NANOS_PER_HOUR: i128 = 3_600_000_000_000;
const MAX_I64: u64 = i64::MAX as u64;

/// The local quota simulation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuotaMode {
    /// Do not count or enforce sign-ups.
    #[default]
    Off,
    /// Count sign-ups and report overages, but do not reject them.
    Observe,
    /// Count sign-ups and reject reservations after the limit.
    Enforce,
}

/// The only supported local simulation algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuotaAlgorithm {
    /// UTC-aligned half-open hourly windows.
    #[default]
    FixedWindowV1,
}

/// A temporary quota interval, analogous to the official API's quota override shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemporaryQuota {
    /// Maximum successful reservations in the interval.
    pub quota: u64,
    /// Inclusive interval start.
    pub start_time: LogicalInstant,
    /// Positive interval duration.
    pub duration: LogicalDuration,
}

impl TemporaryQuota {
    /// Creates a validated temporary quota.
    pub fn new(
        quota: u64,
        start_time: LogicalInstant,
        duration: LogicalDuration,
    ) -> Result<Self, QuotaConfigError> {
        if quota > MAX_I64 {
            return Err(QuotaConfigError::QuotaOutOfRange);
        }
        if !duration.is_positive() {
            return Err(QuotaConfigError::DurationNotPositive);
        }
        start_time
            .checked_add(duration)
            .ok_or(QuotaConfigError::IntervalOverflow)?;
        Ok(Self {
            quota,
            start_time,
            duration,
        })
    }

    fn active_at(self, now: LogicalInstant) -> bool {
        now >= self.start_time
            && self
                .start_time
                .checked_add(self.duration)
                .is_some_and(|end| now < end)
    }
}

/// Configuration for [`SignupQuota`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignupQuotaConfig {
    /// Local simulation mode.
    pub mode: QuotaMode,
    /// Fixed-window algorithm. Only `FixedWindowV1` is currently supported.
    pub algorithm: QuotaAlgorithm,
    /// Default per-window quota when no temporary override is active.
    pub default_quota_per_hour: u64,
    /// Maximum number of project/IP/window buckets retained.
    pub max_tracked_buckets: usize,
    /// Optional temporary quota interval.
    pub temporary: Option<TemporaryQuota>,
}

impl Default for SignupQuotaConfig {
    fn default() -> Self {
        Self {
            mode: QuotaMode::Off,
            algorithm: QuotaAlgorithm::FixedWindowV1,
            default_quota_per_hour: 100,
            max_tracked_buckets: 4_096,
            temporary: None,
        }
    }
}

impl SignupQuotaConfig {
    /// Validates a local simulation configuration.
    pub fn validate(&self) -> Result<(), QuotaConfigError> {
        if self.algorithm != QuotaAlgorithm::FixedWindowV1 {
            return Err(QuotaConfigError::UnsupportedAlgorithm);
        }
        if self.default_quota_per_hour > 1_000_000 {
            return Err(QuotaConfigError::DefaultQuotaOutOfRange);
        }
        if !(1..=65_536).contains(&self.max_tracked_buckets) {
            return Err(QuotaConfigError::BucketLimitOutOfRange);
        }
        if let Some(temporary) = self.temporary {
            TemporaryQuota::new(temporary.quota, temporary.start_time, temporary.duration)?;
        }
        Ok(())
    }
}

/// Invalid local quota configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaConfigError {
    /// Only the fixed-window simulation is supported.
    UnsupportedAlgorithm,
    /// The default quota is outside the local contract.
    DefaultQuotaOutOfRange,
    /// The bucket limit is outside the local contract.
    BucketLimitOutOfRange,
    /// The temporary quota does not fit the official int64 representation.
    QuotaOutOfRange,
    /// A temporary interval must be positive.
    DurationNotPositive,
    /// The temporary interval overflows the logical clock.
    IntervalOverflow,
}

/// Runtime quota errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaError {
    /// The configuration was invalid.
    InvalidConfiguration(QuotaConfigError),
    /// The peer address was absent or contained a control character.
    InvalidPeerAddress,
    /// Enforce mode reached its quota.
    Exceeded,
    /// No bounded bucket is available for a new project/IP/window key.
    BucketCapacity,
    /// The reservation does not belong to this quota instance or was already finalized.
    InvalidReservation,
    /// The reservation was created under a different effective policy, window, or generation.
    /// The reservation is released when this is returned.
    StaleReservation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BucketKey {
    project_id: String,
    peer_ip: String,
    window_start: LogicalInstant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bucket {
    committed: u64,
    reserved: u64,
    observed_over_limit: u64,
}

/// A reservation held between an accepted sign-up preflight and its commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignupReservation {
    key: Option<BucketKey>,
    token: u64,
    generation: u64,
    window_start: LogicalInstant,
    limit: u64,
    mode: QuotaMode,
    /// In observe mode this records that the request exceeded the configured limit.
    pub would_exceed: bool,
}

/// A bounded local sign-up counter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignupQuota {
    config: SignupQuotaConfig,
    buckets: BTreeMap<BucketKey, Bucket>,
    active_reservations: BTreeMap<u64, BucketKey>,
    next_token: u64,
    generation: u64,
}

impl Default for SignupQuota {
    fn default() -> Self {
        Self::new(SignupQuotaConfig::default()).expect("the default quota config is valid")
    }
}

impl SignupQuota {
    /// Creates a quota counter from a validated local configuration.
    pub fn new(config: SignupQuotaConfig) -> Result<Self, QuotaConfigError> {
        config.validate()?;
        Ok(Self {
            config,
            buckets: BTreeMap::new(),
            active_reservations: BTreeMap::new(),
            next_token: 1,
            generation: 0,
        })
    }

    /// The current configuration.
    #[must_use]
    pub const fn config(&self) -> &SignupQuotaConfig {
        &self.config
    }

    /// Replaces the configuration without changing already counted usage.
    pub fn set_config(&mut self, config: SignupQuotaConfig) -> Result<(), QuotaConfigError> {
        config.validate()?;
        self.config = config;
        self.generation = self.generation.wrapping_add(1).max(1);
        Ok(())
    }

    /// Returns the number of retained buckets, for bounded-state assertions.
    #[must_use]
    pub fn tracked_bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Returns committed and in-flight counts for a project/IP at `now`.
    #[must_use]
    pub fn usage(&self, project_id: &str, peer_ip: &str, now: LogicalInstant) -> (u64, u64) {
        let key = BucketKey {
            project_id: project_id.to_owned(),
            peer_ip: peer_ip.to_owned(),
            window_start: window_start(now),
        };
        self.buckets
            .get(&key)
            .map_or((0, 0), |bucket| (bucket.committed, bucket.reserved))
    }

    /// Reserves one successful end-user account creation.
    pub fn reserve(
        &mut self,
        project_id: &str,
        peer_ip: &str,
        now: LogicalInstant,
    ) -> Result<SignupReservation, QuotaError> {
        if peer_ip.is_empty() || peer_ip.chars().any(char::is_control) {
            return Err(QuotaError::InvalidPeerAddress);
        }
        if self.config.mode == QuotaMode::Off {
            return Ok(SignupReservation {
                key: None,
                token: 0,
                generation: self.generation,
                window_start: window_start(now),
                limit: self.limit_at(now),
                mode: self.config.mode,
                would_exceed: false,
            });
        }
        let key = BucketKey {
            project_id: project_id.to_owned(),
            peer_ip: peer_ip.to_owned(),
            window_start: window_start(now),
        };
        let limit = self.limit_at(now);
        self.prune_expired_buckets(now);
        let bucket_was_tracked = if self.buckets.contains_key(&key) {
            true
        } else {
            if self.buckets.len() >= self.config.max_tracked_buckets {
                return Err(QuotaError::BucketCapacity);
            }
            self.buckets.insert(
                key.clone(),
                Bucket {
                    committed: 0,
                    reserved: 0,
                    observed_over_limit: 0,
                },
            );
            false
        };
        let would_exceed = self
            .buckets
            .get(&key)
            .is_some_and(|bucket| bucket.committed.saturating_add(bucket.reserved) >= limit);
        if would_exceed && self.config.mode == QuotaMode::Enforce {
            if !bucket_was_tracked {
                self.buckets.remove(&key);
            }
            return Err(QuotaError::Exceeded);
        }
        let bucket = self
            .buckets
            .get_mut(&key)
            .expect("the quota bucket exists after capacity checks");
        bucket.reserved = bucket.reserved.saturating_add(1);
        if would_exceed {
            bucket.observed_over_limit = bucket.observed_over_limit.saturating_add(1);
        }
        let token = loop {
            let token = self.next_token;
            self.next_token = self.next_token.wrapping_add(1).max(1);
            if !self.active_reservations.contains_key(&token) {
                break token;
            }
        };
        self.active_reservations.insert(token, key.clone());
        Ok(SignupReservation {
            key: Some(key),
            token,
            generation: self.generation,
            window_start: window_start(now),
            limit,
            mode: self.config.mode,
            would_exceed,
        })
    }

    /// Commits a previously accepted reservation after the account exists.
    pub fn commit(
        &mut self,
        reservation: SignupReservation,
        now: LogicalInstant,
    ) -> Result<(), QuotaError> {
        let Some(key) = reservation.key else {
            if reservation.token != 0
                || reservation.generation != self.generation
                || reservation.mode != self.config.mode
                || self.config.mode != QuotaMode::Off
            {
                return Err(QuotaError::StaleReservation);
            }
            return Ok(());
        };
        if self.active_reservations.get(&reservation.token) != Some(&key) {
            return Err(QuotaError::InvalidReservation);
        }
        if reservation.generation != self.generation
            || reservation.window_start != window_start(now)
            || reservation.limit != self.limit_at(now)
            || reservation.mode != self.config.mode
        {
            self.release_tracked(&key, reservation.token, reservation.would_exceed)?;
            return Err(QuotaError::StaleReservation);
        }
        let Some(bucket) = self.buckets.get_mut(&key) else {
            return Err(QuotaError::InvalidReservation);
        };
        if bucket.reserved == 0
            || self
                .active_reservations
                .remove(&reservation.token)
                .is_none()
        {
            return Err(QuotaError::InvalidReservation);
        }
        bucket.reserved -= 1;
        bucket.committed = bucket.committed.saturating_add(1);
        Ok(())
    }

    /// Releases a reservation when account creation fails before commit.
    pub fn release(&mut self, reservation: SignupReservation) -> Result<(), QuotaError> {
        let Some(key) = reservation.key else {
            return Ok(());
        };
        self.release_tracked(&key, reservation.token, reservation.would_exceed)
    }

    fn release_tracked(
        &mut self,
        key: &BucketKey,
        token: u64,
        would_exceed: bool,
    ) -> Result<(), QuotaError> {
        if self.active_reservations.get(&token) != Some(key) {
            return Err(QuotaError::InvalidReservation);
        }
        let Some(bucket) = self.buckets.get_mut(key) else {
            return Err(QuotaError::InvalidReservation);
        };
        if bucket.reserved == 0 {
            return Err(QuotaError::InvalidReservation);
        }
        self.active_reservations.remove(&token);
        bucket.reserved -= 1;
        if would_exceed {
            bucket.observed_over_limit = bucket.observed_over_limit.saturating_sub(1);
        }
        if bucket.committed == 0 && bucket.reserved == 0 && bucket.observed_over_limit == 0 {
            self.buckets.remove(key);
        }
        Ok(())
    }

    fn limit_at(&self, now: LogicalInstant) -> u64 {
        self.config
            .temporary
            .filter(|temporary| temporary.active_at(now))
            .map_or(self.config.default_quota_per_hour, |temporary| {
                temporary.quota
            })
    }

    fn prune_expired_buckets(&mut self, now: LogicalInstant) {
        let active_keys: BTreeSet<BucketKey> = self.active_reservations.values().cloned().collect();
        self.buckets.retain(|key, bucket| {
            let expired = key
                .window_start
                .checked_add(LogicalDuration::from_nanos(NANOS_PER_HOUR))
                .is_some_and(|end| end <= now);
            !expired || bucket.reserved != 0 || active_keys.contains(key)
        });
    }
}

fn window_start(now: LogicalInstant) -> LogicalInstant {
    LogicalInstant::from_nanos(now.as_nanos().div_euclid(NANOS_PER_HOUR) * NANOS_PER_HOUR)
}

#[cfg(test)]
mod tests {
    use super::{QuotaError, QuotaMode, SignupQuota, SignupQuotaConfig, TemporaryQuota};
    use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

    const T0: LogicalInstant = LogicalInstant::from_unix_seconds(3_600);

    fn quota(mode: QuotaMode, limit: u64) -> SignupQuota {
        SignupQuota::new(SignupQuotaConfig {
            mode,
            default_quota_per_hour: limit,
            ..SignupQuotaConfig::default()
        })
        .unwrap()
    }

    #[test]
    fn off_does_not_track_or_reject() {
        let mut quota = quota(QuotaMode::Off, 0);
        for _ in 0..3 {
            let reservation = quota.reserve("project", "192.0.2.1", T0).unwrap();
            quota.commit(reservation, T0).unwrap();
        }
        assert_eq!(quota.tracked_bucket_count(), 0);
    }

    #[test]
    fn enforce_reserves_atomically_and_releases_failed_creation() {
        let mut quota = quota(QuotaMode::Enforce, 1);
        let first = quota.reserve("project", "192.0.2.1", T0).unwrap();
        assert!(matches!(
            quota.reserve("project", "192.0.2.1", T0),
            Err(QuotaError::Exceeded)
        ));
        quota.release(first).unwrap();
        assert_eq!(quota.usage("project", "192.0.2.1", T0), (0, 0));
        let retry = quota.reserve("project", "192.0.2.1", T0).unwrap();
        quota.commit(retry, T0).unwrap();
        assert_eq!(quota.usage("project", "192.0.2.1", T0), (1, 0));
    }

    #[test]
    fn enforce_rejecting_a_new_over_limit_key_does_not_retain_a_bucket() {
        let mut quota = SignupQuota::new(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 0,
            max_tracked_buckets: 1,
            ..SignupQuotaConfig::default()
        })
        .unwrap();

        assert_eq!(
            quota.reserve("project", "192.0.2.1", T0),
            Err(QuotaError::Exceeded)
        );
        assert_eq!(quota.tracked_bucket_count(), 0);

        let other_key = quota.reserve("project", "192.0.2.2", T0);
        assert_eq!(other_key, Err(QuotaError::Exceeded));
        assert_eq!(quota.tracked_bucket_count(), 0);
    }

    #[test]
    fn expired_buckets_are_pruned_before_capacity_refusal() {
        let mut quota = SignupQuota::new(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 10,
            max_tracked_buckets: 2,
            ..SignupQuotaConfig::default()
        })
        .unwrap();

        for peer_ip in ["192.0.2.1", "192.0.2.2"] {
            let reservation = quota.reserve("project", peer_ip, T0).unwrap();
            quota.commit(reservation, T0).unwrap();
        }
        assert_eq!(quota.tracked_bucket_count(), 2);

        let next_window = T0
            .checked_add(LogicalDuration::from_seconds(3_600))
            .unwrap();
        let reservation = quota
            .reserve("project", "192.0.2.3", next_window)
            .expect("expired buckets should make room for the new window");
        assert_eq!(quota.tracked_bucket_count(), 1);
        quota.commit(reservation, next_window).unwrap();
        assert_eq!(quota.usage("project", "192.0.2.3", next_window), (1, 0));
    }

    #[test]
    fn active_reservations_are_never_pruned_for_capacity() {
        let mut quota = SignupQuota::new(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 10,
            max_tracked_buckets: 1,
            ..SignupQuotaConfig::default()
        })
        .unwrap();
        let held = quota.reserve("project", "192.0.2.1", T0).unwrap();
        let next_window = T0
            .checked_add(LogicalDuration::from_seconds(3_600))
            .unwrap();

        assert_eq!(
            quota.reserve("project", "192.0.2.2", next_window),
            Err(QuotaError::BucketCapacity)
        );
        assert_eq!(quota.tracked_bucket_count(), 1);
        quota.release(held).unwrap();

        let retry = quota
            .reserve("project", "192.0.2.2", next_window)
            .expect("released expired reservations should no longer consume capacity");
        quota.commit(retry, next_window).unwrap();
    }

    #[test]
    fn committed_usage_in_an_active_window_is_never_pruned_for_capacity() {
        let mut quota = SignupQuota::new(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 10,
            max_tracked_buckets: 1,
            ..SignupQuotaConfig::default()
        })
        .unwrap();
        let first = quota.reserve("project", "192.0.2.1", T0).unwrap();
        quota.commit(first, T0).unwrap();
        let before_window_end = T0
            .checked_add(LogicalDuration::from_seconds(3_599))
            .unwrap();

        assert_eq!(
            quota.reserve("project", "192.0.2.2", before_window_end),
            Err(QuotaError::BucketCapacity)
        );
        assert_eq!(
            quota.usage("project", "192.0.2.1", before_window_end),
            (1, 0)
        );
        assert_eq!(quota.tracked_bucket_count(), 1);
    }

    #[test]
    fn observe_records_overage_without_rejecting() {
        let mut quota = quota(QuotaMode::Observe, 1);
        let first = quota.reserve("project", "192.0.2.1", T0).unwrap();
        quota.commit(first, T0).unwrap();
        let second = quota.reserve("project", "192.0.2.1", T0).unwrap();
        assert!(second.would_exceed);
        quota.commit(second, T0).unwrap();
        assert_eq!(quota.usage("project", "192.0.2.1", T0), (2, 0));
        assert_eq!(
            quota.buckets.values().next().unwrap().observed_over_limit,
            1
        );
    }

    #[test]
    fn observe_releasing_a_failed_over_limit_creation_reclaims_the_bucket() {
        let mut quota = SignupQuota::new(SignupQuotaConfig {
            mode: QuotaMode::Observe,
            default_quota_per_hour: 0,
            max_tracked_buckets: 1,
            ..SignupQuotaConfig::default()
        })
        .unwrap();

        let failed = quota.reserve("project", "192.0.2.1", T0).unwrap();
        assert!(failed.would_exceed);
        quota.release(failed).unwrap();
        assert_eq!(quota.tracked_bucket_count(), 0);
        assert_eq!(quota.usage("project", "192.0.2.1", T0), (0, 0));

        let retry = quota.reserve("project", "192.0.2.2", T0).unwrap();
        assert!(retry.would_exceed);
        quota.commit(retry, T0).unwrap();
        assert_eq!(quota.tracked_bucket_count(), 1);
    }

    #[test]
    fn keys_are_project_and_peer_isolated_and_windows_are_half_open() {
        let mut quota = quota(QuotaMode::Enforce, 1);
        let first = quota.reserve("project", "192.0.2.1", T0).unwrap();
        quota.commit(first, T0).unwrap();
        assert!(quota.reserve("project", "192.0.2.2", T0).is_ok());
        assert!(quota.reserve("other", "192.0.2.1", T0).is_ok());
        let next_window = T0
            .checked_add(LogicalDuration::from_seconds(3_600))
            .unwrap();
        assert!(quota.reserve("project", "192.0.2.1", next_window).is_ok());
    }

    #[test]
    fn temporary_quota_applies_only_inside_the_interval() {
        let temporary = TemporaryQuota::new(2, T0, LogicalDuration::from_seconds(60)).unwrap();
        let mut quota = SignupQuota::new(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 1,
            temporary: Some(temporary),
            ..SignupQuotaConfig::default()
        })
        .unwrap();
        let first = quota.reserve("project", "192.0.2.1", T0).unwrap();
        quota.commit(first, T0).unwrap();
        assert!(quota.reserve("project", "192.0.2.1", T0).is_ok());
        let before = T0.checked_add(LogicalDuration::from_seconds(-1)).unwrap();
        assert!(quota.reserve("project", "192.0.2.2", before).is_ok());
    }

    #[test]
    fn commit_rejects_a_reservation_after_configuration_changes() {
        let mut quota = quota(QuotaMode::Enforce, 2);
        let reservation = quota.reserve("project", "192.0.2.1", T0).unwrap();
        let mut changed = quota.config().clone();
        changed.default_quota_per_hour = 3;
        quota.set_config(changed).unwrap();

        assert_eq!(
            quota.commit(reservation, T0),
            Err(QuotaError::StaleReservation)
        );
        assert_eq!(quota.usage("project", "192.0.2.1", T0), (0, 0));
        assert!(quota.reserve("project", "192.0.2.1", T0).is_ok());
    }

    #[test]
    fn commit_rejects_a_reservation_after_the_hourly_window_changes() {
        let mut quota = quota(QuotaMode::Enforce, 1);
        let reservation = quota.reserve("project", "192.0.2.1", T0).unwrap();
        let next_window = T0
            .checked_add(LogicalDuration::from_seconds(3_600))
            .unwrap();

        assert_eq!(
            quota.commit(reservation, next_window),
            Err(QuotaError::StaleReservation)
        );
        assert_eq!(quota.tracked_bucket_count(), 0);
        let retry = quota.reserve("project", "192.0.2.1", next_window).unwrap();
        quota.commit(retry, next_window).unwrap();
        assert_eq!(quota.usage("project", "192.0.2.1", next_window), (1, 0));
    }

    #[test]
    fn commit_rejects_when_a_temporary_limit_changes_inside_the_window() {
        let temporary = TemporaryQuota::new(
            2,
            T0.checked_add(LogicalDuration::from_seconds(60)).unwrap(),
            LogicalDuration::from_seconds(60),
        )
        .unwrap();
        let mut quota = SignupQuota::new(SignupQuotaConfig {
            mode: QuotaMode::Enforce,
            default_quota_per_hour: 1,
            temporary: Some(temporary),
            ..SignupQuotaConfig::default()
        })
        .unwrap();
        let reservation = quota.reserve("project", "192.0.2.1", T0).unwrap();
        let during_temporary = T0.checked_add(LogicalDuration::from_seconds(60)).unwrap();

        assert_eq!(
            quota.commit(reservation, during_temporary),
            Err(QuotaError::StaleReservation)
        );
        assert_eq!(quota.usage("project", "192.0.2.1", T0), (0, 0));
        assert_eq!(
            quota.usage("project", "192.0.2.1", during_temporary),
            (0, 0)
        );
    }

    #[test]
    fn each_reservation_can_be_finalized_only_once() {
        let mut quota = quota(QuotaMode::Enforce, 2);
        let reservation = quota.reserve("project", "192.0.2.1", T0).unwrap();
        quota.commit(reservation.clone(), T0).unwrap();
        assert_eq!(
            quota.commit(reservation, T0),
            Err(QuotaError::InvalidReservation)
        );
        assert_eq!(quota.usage("project", "192.0.2.1", T0), (1, 0));
    }
}
