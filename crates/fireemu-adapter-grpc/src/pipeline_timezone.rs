//! Named time zones for pipeline calendar functions.

use chrono::{DateTime, TimeZone, Utc};
use chrono_tz::Tz;
use fireemu_core_firestore::pipeline_exec::{
    local_calendar_value, ZoneError, ZoneOperation, ZoneResult,
};
use fireemu_core_firestore::value::Timestamp;

pub(crate) fn resolve(
    timestamp: Timestamp,
    zone: &str,
    unit: &str,
    operation: ZoneOperation,
) -> Result<ZoneResult, ZoneError> {
    let zone: Tz = match zone.parse() {
        Ok(zone) => zone,
        Err(_) if is_custom_gmt_offset(zone) => return Err(ZoneError::Unsupported),
        Err(_) => return Err(ZoneError::InvalidZone),
    };
    let utc = DateTime::<Utc>::from_timestamp(timestamp.seconds(), timestamp.nanos())
        .ok_or(ZoneError::OutOfRange)?;
    let local = utc.with_timezone(&zone).naive_local();
    let wall = local.and_utc();
    let local_timestamp = Timestamp::new(wall.timestamp(), wall.timestamp_subsec_nanos())
        .map_err(|_| ZoneError::OutOfRange)?;
    match local_calendar_value(local_timestamp, unit, operation)? {
        ZoneResult::Integer(value) => Ok(ZoneResult::Integer(value)),
        ZoneResult::Timestamp(boundary) => {
            let wall = DateTime::<Utc>::from_timestamp(boundary.seconds(), boundary.nanos())
                .ok_or(ZoneError::OutOfRange)?
                .naive_utc();
            let resolved = zone
                .from_local_datetime(&wall)
                .single()
                .ok_or(ZoneError::Ambiguous)?
                .with_timezone(&Utc);
            let result = Timestamp::new(resolved.timestamp(), resolved.timestamp_subsec_nanos())
                .map_err(|_| ZoneError::OutOfRange)?;
            Ok(ZoneResult::Timestamp(result))
        }
    }
}

// Recognize documented numeric GMT offset syntax without choosing its offset semantics.
fn is_custom_gmt_offset(zone: &str) -> bool {
    let Some(rest) = zone
        .strip_prefix("GMT")
        .and_then(|s| s.strip_prefix('+').or_else(|| s.strip_prefix('-')))
    else {
        return false;
    };
    let mut parts = rest.split(':');
    let valid = |part: &str, max: u8| {
        part.len() == 2
            && part.bytes().all(|b| b.is_ascii_digit())
            && part.parse::<u8>().is_ok_and(|n| n <= max)
    };
    let Some(hours) = parts.next() else {
        return false;
    };
    if !valid(hours, 23) {
        return false;
    }
    for part in parts.by_ref().take(2) {
        if !valid(part, 59) {
            return false;
        }
    }
    parts.next().is_none()
}

pub(crate) fn runtime(
    local: &crate::local::LocalBackend,
) -> fireemu_core_firestore::pipeline_exec::RuntimeContext {
    let nanos = local.admin_now().as_nanos();
    let timestamp = i64::try_from(nanos.div_euclid(1_000_000_000))
        .ok()
        .and_then(|seconds| {
            u32::try_from(nanos.rem_euclid(1_000_000_000) / 1_000 * 1_000)
                .ok()
                .and_then(|nanos| Timestamp::new(seconds, nanos).ok())
        });
    fireemu_core_firestore::pipeline_exec::RuntimeContext {
        request_timestamp: timestamp,
        zone_resolver: Some(resolve),
        regex_resolver: Some(crate::pipeline_regex::resolve),
        sample_seed: None,
    }
}

pub(crate) fn runtime_for_stages(
    local: &crate::local::LocalBackend,
    stages: &[fireemu_core_firestore::pipeline_exec::Stage],
) -> fireemu_core_firestore::pipeline_exec::RuntimeContext {
    let mut runtime = runtime(local);
    if stages.iter().any(|stage| {
        matches!(
            stage,
            fireemu_core_firestore::pipeline_exec::Stage::Sample(_)
        )
    }) {
        runtime.sample_seed = Some(local.next_sample_seed());
    }
    runtime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokyo_recorded_calendar_and_invalid_zone() {
        let t = Timestamp::new(1_582_979_696, 789_012_000).unwrap();
        assert_eq!(
            resolve(t, "Asia/Tokyo", "day", ZoneOperation::Trunc),
            Ok(ZoneResult::Timestamp(
                Timestamp::new(1_582_902_000, 0).unwrap()
            ))
        );
        assert_eq!(
            resolve(t, "Asia/Tokyo", "hour", ZoneOperation::Extract),
            Ok(ZoneResult::Integer(21))
        );
        assert_eq!(
            resolve(t, "Not/AZone", "hour", ZoneOperation::Extract),
            Err(ZoneError::InvalidZone)
        );
    }

    #[test]
    fn dst_boundary_is_not_silently_chosen() {
        let t = Timestamp::new(1_699_165_800, 0).unwrap();
        assert_eq!(
            resolve(t, "America/New_York", "hour", ZoneOperation::Trunc),
            Err(ZoneError::Ambiguous)
        );
    }
    #[test]
    fn request_samples_configured_clock_once() {
        use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
        use fireemu_core_types::time::LogicalInstant;
        use std::sync::{Arc, Mutex};
        let clock = Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(100),
        )));
        let local = crate::local::LocalBackend::new(
            crate::gateway::Gateway {
                enforce_limits: false,
                ctx: PlanningContext {
                    edition: FirestoreEdition::Enterprise,
                    api_mode: FirestoreApiMode::Native,
                    policy: IndexValidationPolicy::Emulator,
                },
                indexes: IndexSet::default(),
            },
            clock.clone(),
            7,
        );
        let first = runtime(&local);
        clock
            .lock()
            .unwrap()
            .advance_to(LogicalInstant::from_unix_seconds(200))
            .unwrap();
        let second = runtime(&local);
        assert_eq!(
            first.request_timestamp,
            Some(Timestamp::new(100, 0).unwrap())
        );
        assert_eq!(
            second.request_timestamp,
            Some(Timestamp::new(200, 0).unwrap())
        );
    }

    #[test]
    fn request_clock_floors_submicroseconds_for_both_epoch_sides() {
        use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
        use fireemu_core_session::clock::VirtualClock;
        use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
        use fireemu_core_types::time::LogicalInstant;
        use std::sync::{Arc, Mutex};
        let clock = Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(
            -1,
        ))));
        let local = crate::local::LocalBackend::new(
            crate::gateway::Gateway {
                enforce_limits: false,
                ctx: PlanningContext {
                    edition: FirestoreEdition::Enterprise,
                    api_mode: FirestoreApiMode::Native,
                    policy: IndexValidationPolicy::Emulator,
                },
                indexes: IndexSet::default(),
            },
            clock.clone(),
            7,
        );
        assert_eq!(
            runtime(&local).request_timestamp,
            Some(Timestamp::new(-1, 999_999_000).unwrap())
        );
        clock
            .lock()
            .unwrap()
            .advance_to(LogicalInstant::from_nanos(1_000_001_234))
            .unwrap();
        assert_eq!(
            runtime(&local).request_timestamp,
            Some(Timestamp::new(1, 1_000).unwrap())
        );
        clock
            .lock()
            .unwrap()
            .set_allow_backwards(LogicalInstant::from_nanos(i128::MIN));
        assert_eq!(runtime(&local).request_timestamp, None);
        clock
            .lock()
            .unwrap()
            .set_allow_backwards(LogicalInstant::from_nanos(i128::MAX));
        assert_eq!(runtime(&local).request_timestamp, None);
    }

    #[test]
    fn documented_gmt_offsets_are_unobserved_but_bad_names_are_invalid() {
        let t = Timestamp::new(1_582_979_696, 0).unwrap();
        assert_eq!(
            resolve(t, "GMT+06:32:43", "hour", ZoneOperation::Extract),
            Err(ZoneError::Unsupported)
        );
        assert_eq!(
            resolve(t, "not-a-zone", "hour", ZoneOperation::Extract),
            Err(ZoneError::InvalidZone)
        );
        assert_eq!(
            resolve(t, "GMT+bad", "hour", ZoneOperation::Extract),
            Err(ZoneError::InvalidZone)
        );
    }

    #[test]
    fn dst_gap_and_other_zone() {
        let gap_day = Timestamp::new(1_541_332_800, 0).unwrap();
        assert_eq!(
            resolve(gap_day, "America/Sao_Paulo", "day", ZoneOperation::Trunc),
            Err(ZoneError::Ambiguous)
        );
        let winter = Timestamp::new(1_704_067_200, 0).unwrap();
        assert_eq!(
            resolve(winter, "Europe/Berlin", "hour", ZoneOperation::Extract),
            Ok(ZoneResult::Integer(1))
        );
    }
}
