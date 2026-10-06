//! Explicit application-clock policies. Native transport and watchdog time remains real.

use fireemu_core_session::clock::ClockSnapshot;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

/// Independent choices for application dates, JavaScript timers and Cloud Tasks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplicationClockPolicy {
    /// Bind Date to the daemon clock.
    pub date_virtual: bool,
    /// Drive application timers by positive virtual elapsed time.
    pub timers_virtual: bool,
    /// Drive task eligibility and backoff by virtual time.
    pub tasks_virtual: bool,
}

impl ApplicationClockPolicy {
    /// Whether any policy requires a pinned initial clock.
    #[must_use]
    pub const fn any_virtual(self) -> bool {
        self.date_virtual || self.timers_virtual || self.tasks_virtual
    }

    /// Validate the instant before admitting a transition into a JavaScript Date world.
    pub fn validate(self, instant: LogicalInstant) -> Result<(), String> {
        let millis = instant.as_nanos().div_euclid(1_000_000);
        if self.date_virtual && !(-8_640_000_000_000_000..=8_640_000_000_000_000).contains(&millis)
        {
            return Err("clock instant is outside the JavaScript Date range".into());
        }
        Ok(())
    }

    /// Initial runner state, installed before user imports.
    #[must_use]
    pub fn runner_options(self, snapshot: ClockSnapshot) -> Value {
        json!({"date": if self.date_virtual { "virtual" } else { "real" },
            "timers": if self.timers_virtual { "virtual" } else { "real" },
            "instantNanos": snapshot.instant.as_nanos().to_string(),
            "elapsedNanos": snapshot.elapsed_nanos.to_string(),
            "revision": snapshot.revision.to_string()})
    }
}
