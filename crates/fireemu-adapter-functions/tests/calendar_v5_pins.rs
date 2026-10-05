//! Production calendar observations pinned as local tests (SCHEDULED-FUNCTIONS calendar v5).
//!
//! Source: one recorded run of the production Cloud Scheduler job API in `us-central1`
//! (run `5a73ba99b7014cfd`, 2026-10-01, cases `c01` to `c08`; every job was cleaned up and
//! its absence read back). For each case the journal holds the `jobs.create` request, the
//! moment it was dispatched, the moment its response arrived, and the response body.
//!
//! What is pinned is the `scheduleTime` of the created job (the next run) for the six accepted
//! schedules, and the refusal for the two refused ones. The server computed `scheduleTime` at
//! an unknown instant between dispatch and response, so a case matches when SOME instant in
//! that window makes the local next-run computation yield the recorded value. This is the
//! recorded obligation, not a loosening: a value that no instant in the window can produce
//! does not match (see the near-miss tests). c01 is the one case that relies on the window's
//! far edge (see its test).
//!
//! The daylight-saving cases (c05, c06) record the next run only: a gap is skipped and a fold
//! runs at its first occurrence, which matches the rule fireemu inherits from cron fields. The
//! repeated-delivery behaviour of a fold is not observed.
//!
//! Wire shapes (the 400 body and its message) are not claimed here: these tests cover the
//! schedule grammar, the zone lookup and the next-run computation only.

use fireemu_adapter_functions::zone::resolve;
use fireemu_core_functions::cron::{Schedule, ScheduleError, ZoneRules};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

fn t(text: &str) -> LogicalInstant {
    LogicalInstant::parse_rfc3339(text).unwrap_or_else(|e| panic!("bad instant {text}: {e:?}"))
}

/// One accepted production case: the create request's window and the recorded next run.
struct Accepted {
    id: &'static str,
    schedule: &'static str,
    zone: &'static str,
    dispatched: &'static str,
    responded: &'static str,
    schedule_time: &'static str,
}

const ACCEPTED: [Accepted; 6] = [
    Accepted {
        id: "c01-create",
        schedule: "* * * * *",
        zone: "UTC",
        dispatched: "2026-10-01T05:19:58.550Z",
        responded: "2026-10-01T05:20:00.636Z",
        schedule_time: "2026-10-01T05:21:00Z",
    },
    Accepted {
        id: "c02-create",
        schedule: "0 9 * JAN MON",
        zone: "UTC",
        dispatched: "2026-10-01T05:20:04.683Z",
        responded: "2026-10-01T05:20:08.905Z",
        schedule_time: "2027-01-04T09:00:00Z",
    },
    Accepted {
        id: "c03-create",
        schedule: "every 5 minutes",
        zone: "UTC",
        dispatched: "2026-10-01T05:20:12.779Z",
        responded: "2026-10-01T05:20:14.530Z",
        schedule_time: "2026-10-01T05:25:00Z",
    },
    Accepted {
        id: "c04-create",
        schedule: "1st friday of quarter 9:00",
        zone: "UTC",
        dispatched: "2026-10-01T05:20:18.402Z",
        responded: "2026-10-01T05:20:20.360Z",
        schedule_time: "2026-10-02T09:00:00Z",
    },
    Accepted {
        id: "c05-create",
        schedule: "30 2 14 3 *",
        zone: "America/New_York",
        dispatched: "2026-10-01T05:20:24.776Z",
        responded: "2026-10-01T05:20:26.743Z",
        schedule_time: "2028-03-14T06:30:00Z",
    },
    Accepted {
        id: "c06-create",
        schedule: "30 1 1 11 *",
        zone: "America/New_York",
        dispatched: "2026-10-01T05:20:29.651Z",
        responded: "2026-10-01T05:20:31.277Z",
        schedule_time: "2026-11-01T05:30:00Z",
    },
];

/// Whether some instant in `[dispatched, responded]` makes `schedule` yield `recorded` as its
/// next run. The next run is monotone in the instant it is computed at, and the latest
/// instant that can still yield `recorded` is one second before it, so one probe decides.
fn attainable(
    schedule: &Schedule,
    zone: &dyn ZoneRules,
    dispatched: LogicalInstant,
    responded: LogicalInstant,
    recorded: LogicalInstant,
) -> bool {
    let probe = responded.min(
        recorded
            .checked_add(LogicalDuration::from_seconds(-1))
            .expect("instant arithmetic"),
    );
    probe >= dispatched && schedule.next_after_in(probe, zone) == Some(recorded)
}

fn matches(case: &Accepted, recorded: &str) -> bool {
    let schedule = Schedule::parse(case.schedule)
        .unwrap_or_else(|e| panic!("{}: {:?} must parse: {e}", case.id, case.schedule));
    let zone = resolve(Some(case.zone)).unwrap_or_else(|e| panic!("{}: {e}", case.id));
    attainable(
        &schedule,
        &*zone,
        t(case.dispatched),
        t(case.responded),
        t(recorded),
    )
}

#[test]
fn every_accepted_production_case_matches_within_its_window() {
    for case in &ACCEPTED {
        assert!(
            matches(case, case.schedule_time),
            "{}: {:?} in {} should yield {} for some instant in [{}, {}]",
            case.id,
            case.schedule,
            case.zone,
            case.schedule_time,
            case.dispatched,
            case.responded
        );
    }
}

/// c01: the create request was dispatched at 05:19:58.550Z, answered at 05:20:00.636Z, and the
/// response's own `userUpdateTime` is 05:19:59.866Z, 0.13 s before the 05:20:00 tick. Production
/// still answered 05:21:00. A server that evaluated at its `userUpdateTime` would have returned
/// 05:20:00 under the plain "first run strictly after now" rule, so either it evaluated later
/// than `userUpdateTime`, or it skips a run that is too close to now. This pin does not choose:
/// it holds through the dispatch-to-response window only (dispatch gives 05:20:00, response
/// gives the recorded 05:21:00). The fireemu rule has no "too close" margin; one more
/// observation of a create made just before a boundary is a candidate for the next recording.
#[test]
fn c01_matches_only_because_the_create_window_straddles_the_minute_boundary() {
    let case = &ACCEPTED[0];
    let schedule = Schedule::parse(case.schedule).unwrap();
    let zone = resolve(Some(case.zone)).unwrap();
    assert_eq!(
        schedule.next_after_in(t(case.dispatched), &*zone),
        Some(t("2026-10-01T05:20:00Z"))
    );
    assert_eq!(
        schedule.next_after_in(t(case.responded), &*zone),
        Some(t(case.schedule_time))
    );
}

/// The helper must not accept a value no instant in the window can produce.
#[test]
fn a_recorded_value_outside_the_reachable_set_does_not_match() {
    let near_misses: [(&str, &str); 6] = [
        ("c01-create", "2026-10-01T05:22:00Z"),
        ("c02-create", "2027-01-11T09:00:00Z"),
        ("c03-create", "2026-10-01T05:30:00Z"),
        ("c04-create", "2026-11-06T09:00:00Z"),
        ("c05-create", "2027-03-14T07:30:00Z"),
        ("c06-create", "2026-11-01T06:30:00Z"),
    ];
    for (id, wrong) in near_misses {
        let case = ACCEPTED.iter().find(|c| c.id == id).unwrap();
        assert!(!matches(case, wrong), "{id}: {wrong} must not match");
    }
}

/// c05: 2027-03-14 02:30 does not exist in `America/New_York` (clocks jump 02:00 to 03:00), so
/// the next run is the following year's, at EDT.
#[test]
fn c05_spring_gap_skips_to_the_next_year() {
    let case = &ACCEPTED[4];
    let schedule = Schedule::parse(case.schedule).unwrap();
    let zone = resolve(Some(case.zone)).unwrap();
    assert_eq!(
        schedule.next_after_in(t(case.dispatched), &*zone),
        Some(t("2028-03-14T06:30:00Z"))
    );
}

/// c06: 2026-11-01 01:30 happens twice in `America/New_York`; production chose the first
/// occurrence (EDT, 05:30Z), not the second (EST, 06:30Z).
#[test]
fn c06_fall_back_hour_runs_at_the_first_occurrence() {
    let case = &ACCEPTED[5];
    let schedule = Schedule::parse(case.schedule).unwrap();
    let zone = resolve(Some(case.zone)).unwrap();
    assert_eq!(
        schedule.next_after_in(t(case.dispatched), &*zone),
        Some(t("2026-11-01T05:30:00Z"))
    );
}

/// c07: production refused `Invalid/Unknown` as a time zone (400 `INVALID_ARGUMENT`).
#[test]
fn c07_unknown_time_zone_is_refused() {
    assert!(resolve(Some("Invalid/Unknown")).is_err());
}

/// c08: production refused a six-field schedule (400 `INVALID_ARGUMENT`).
#[test]
fn c08_six_field_schedule_is_refused() {
    assert!(matches!(
        Schedule::parse("0 0 0 1 4 *"),
        Err(ScheduleError::Malformed(_))
    ));
}
