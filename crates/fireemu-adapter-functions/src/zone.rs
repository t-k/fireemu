//! IANA time zones for schedules (spec 11.4): `chrono-tz` is the single audited dependency
//! that knows daylight-saving rules; the core only sees [`ZoneRules`].

use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Offset, TimeZone};
use fireemu_core_functions::cron::{fixed_offset_seconds, FixedOffset, ZoneRules};

/// A zone from the IANA database.
#[derive(Debug, Clone, Copy)]
pub struct IanaZone(pub chrono_tz::Tz);

impl ZoneRules for IanaZone {
    fn local_of(&self, utc_secs: i64) -> i64 {
        let Some(utc) = DateTime::from_timestamp(utc_secs, 0) else {
            return utc_secs;
        };
        let offset = self.0.offset_from_utc_datetime(&utc.naive_utc());
        utc_secs + i64::from(offset.fix().local_minus_utc())
    }

    fn utc_of(&self, local_secs: i64) -> Option<i64> {
        let naive = DateTime::from_timestamp(local_secs, 0)?.naive_utc();
        match self.0.from_local_datetime(&naive) {
            chrono::LocalResult::Single(dt) | chrono::LocalResult::Ambiguous(dt, _) => {
                Some(dt.timestamp())
            }
            chrono::LocalResult::None => None,
        }
    }
}

/// Shared zone rules.
pub type SharedZone = Arc<dyn ZoneRules + Send + Sync>;

/// Resolves a zone name: an IANA name (daylight-saving rules included), one of the core's
/// fixed-offset aliases, or UTC when absent.
pub fn resolve(name: Option<&str>) -> Result<SharedZone, String> {
    let Some(name) = name else {
        return Ok(Arc::new(FixedOffset(0)));
    };
    if let Ok(tz) = chrono_tz::Tz::from_str(name) {
        return Ok(Arc::new(IanaZone(tz)));
    }
    fixed_offset_seconds(Some(name))
        .map(|o| Arc::new(FixedOffset(o)) as SharedZone)
        .map_err(|e| e.to_string())
}

/// The version of the bundled zone database (recorded in traces / status).
#[must_use]
pub fn database_version() -> &'static str {
    chrono_tz::IANA_TZDB_VERSION
}
