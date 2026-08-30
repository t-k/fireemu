//! Patterns, manifests and schedules.

use fireemu_core_functions::cron::{
    fixed_offset_seconds, Civil, FixedOffset, RunCount, Schedule, ScheduleError, ZoneRules,
};
use fireemu_core_functions::manifest::{
    DocumentEvent, FunctionManifest, FunctionSpec, ObjectEvent, Trigger, DEFAULT_CONCURRENCY,
    DEFAULT_REGION, DEFAULT_TIMEOUT_SECONDS,
};
use fireemu_core_functions::pattern::{PathPattern, PatternError};
use fireemu_core_types::time::LogicalInstant;

fn t(rfc3339: &str) -> LogicalInstant {
    LogicalInstant::parse_rfc3339(rfc3339).unwrap()
}

#[test]
fn document_patterns_capture_parameters_and_reject_malformed_input() {
    let p = PathPattern::parse("users/{uid}/posts/{postId}").unwrap();
    let params = p.matches("users/alice/posts/p1").unwrap();
    assert_eq!(params["uid"], "alice");
    assert_eq!(params["postId"], "p1");
    assert!(p.matches("users/alice").is_none());
    assert!(p.matches("users/alice/posts/p1/comments/c1").is_none());
    assert!(p.is_document_pattern());
    let any = PathPattern::parse("{path=**}").unwrap();
    assert_eq!(any.matches("a/b/c/d").unwrap()["path"], "a/b/c/d");
    let star = PathPattern::parse("rooms/*/messages/**").unwrap();
    assert!(star.matches("rooms/r1/messages/m1").unwrap().is_empty());
    assert!(star.matches("rooms/r1/messages/m1/x/y").is_some());
    assert!(star.matches("rooms/r1/other/m1").is_none());
    assert_eq!(
        PathPattern::parse("a/{x=**}/b").unwrap_err(),
        PatternError::MultiNotLast
    );
    assert_eq!(
        PathPattern::parse("a/{x}/b/{x}").unwrap_err(),
        PatternError::DuplicateCapture("x".into())
    );
    assert!(matches!(
        PathPattern::parse("a/{bad").unwrap_err(),
        PatternError::MalformedCapture(_)
    ));
    assert_eq!(PathPattern::parse("a//b").unwrap_err(), PatternError::Empty);
}

fn function(name: &str, trigger: Trigger) -> FunctionSpec {
    FunctionSpec {
        name: name.to_owned(),
        region: DEFAULT_REGION.to_owned(),
        entry_point: name.to_owned(),
        trigger,
        timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        retry: false,
        concurrency: DEFAULT_CONCURRENCY,
    }
}

#[test]
fn manifests_match_firestore_and_storage_triggers() {
    let m = FunctionManifest {
        functions: vec![
            function(
                "onTodo",
                Trigger::Firestore {
                    event: DocumentEvent::Created,
                    database: "(default)".into(),
                    document: PathPattern::parse("todos/{id}").unwrap(),
                    with_auth_context: false,
                },
            ),
            function(
                "onAny",
                Trigger::Firestore {
                    event: DocumentEvent::Written,
                    database: "(default)".into(),
                    document: PathPattern::parse("{path=**}").unwrap(),
                    with_auth_context: false,
                },
            ),
            function(
                "onUpload",
                Trigger::Storage {
                    event: ObjectEvent::Finalized,
                    bucket: None,
                },
            ),
            function(
                "onOther",
                Trigger::Storage {
                    event: ObjectEvent::Finalized,
                    bucket: Some("other".into()),
                },
            ),
        ],
    };
    m.validate().unwrap();
    let created = m.firestore_matches("(default)", "todos/t1", DocumentEvent::Created);
    assert_eq!(
        created
            .iter()
            .map(|x| x.function.name.as_str())
            .collect::<Vec<_>>(),
        ["onTodo", "onAny"]
    );
    assert_eq!(created[0].params["id"], "t1");
    let deleted = m.firestore_matches("(default)", "todos/t1", DocumentEvent::Deleted);
    assert_eq!(deleted.len(), 1, "created triggers do not fire on delete");
    assert!(m
        .firestore_matches("other-db", "todos/t1", DocumentEvent::Created)
        .is_empty());
    let finalized = m.storage_matches(
        "demo-app.appspot.com",
        "demo-app.appspot.com",
        ObjectEvent::Finalized,
    );
    assert_eq!(finalized.len(), 1);
    assert_eq!(finalized[0].name, "onUpload");
    assert_eq!(
        m.storage_matches("other", "demo-app.appspot.com", ObjectEvent::Finalized)[0].name,
        "onOther"
    );
    assert!(m
        .storage_matches(
            "demo-app.appspot.com",
            "demo-app.appspot.com",
            ObjectEvent::Deleted
        )
        .is_empty());
    assert_eq!(
        DocumentEvent::from_event_type(
            "google.cloud.firestore.document.v1.updated.withAuthContext"
        ),
        Some(DocumentEvent::Updated)
    );
    assert_eq!(
        ObjectEvent::from_event_type("google.cloud.storage.object.v1.metadataUpdated"),
        Some(ObjectEvent::MetadataUpdated)
    );
    let dup = FunctionManifest {
        functions: vec![
            function("a", Trigger::http(false)),
            function("a", Trigger::http(true)),
        ],
    };
    assert!(dup.validate().is_err());
}

#[test]
fn cron_schedules_compute_the_next_run_in_a_fixed_offset_zone() {
    let s = Schedule::parse("*/15 9-17 * * mon-fri").unwrap();
    // Saturday 2026-08-29 12:00 UTC: the next run is Monday 09:00.
    assert_eq!(
        s.next_after(t("2026-08-29T12:00:00Z"), 0).unwrap(),
        t("2026-08-31T09:00:00Z")
    );
    assert_eq!(
        s.next_after(t("2026-08-31T09:00:00Z"), 0).unwrap(),
        t("2026-08-31T09:15:00Z")
    );
    // Tokyo: 09:00 local is 00:00 UTC.
    let tokyo = fixed_offset_seconds(Some("Asia/Tokyo")).unwrap();
    let daily = Schedule::parse("0 9 * * *").unwrap();
    assert_eq!(
        daily.next_after(t("2026-08-30T12:00:00Z"), tokyo).unwrap(),
        t("2026-08-31T00:00:00Z")
    );
    // Catch-up enumerates every run in the window, capped.
    let every5 = Schedule::parse("every 5 minutes").unwrap();
    let runs = every5.runs_between(t("2026-08-30T12:00:00Z"), t("2026-08-30T12:20:00Z"), 0, 100);
    assert_eq!(
        runs,
        vec![
            t("2026-08-30T12:05:00Z"),
            t("2026-08-30T12:10:00Z"),
            t("2026-08-30T12:15:00Z"),
            t("2026-08-30T12:20:00Z"),
        ]
    );
    assert_eq!(
        every5
            .runs_between(t("2026-08-30T12:00:00Z"), t("2026-08-30T13:00:00Z"), 0, 3)
            .len(),
        3
    );
    // Day-of-month and day-of-week both restricted: either matches (Vixie cron).
    let either = Schedule::parse("0 0 1 * sun").unwrap();
    assert_eq!(
        either.next_after(t("2026-08-29T12:00:00Z"), 0).unwrap(),
        t("2026-08-30T00:00:00Z"),
        "Sunday 2026-08-30 before the 1st"
    );
    assert_eq!(
        Schedule::parse("every day 09:30").unwrap().as_str(),
        "every day 09:30"
    );
    assert_eq!(
        Schedule::parse("every monday 09:30")
            .unwrap()
            .next_after(t("2026-08-29T12:00:00Z"), 0)
            .unwrap(),
        t("2026-08-31T09:30:00Z")
    );
    assert!(Schedule::parse("@hourly").is_ok());
    // App Engine intervals are anchored at the epoch, not synchronized to the wall clock.
    let every7 = Schedule::parse("every 7 minutes").unwrap();
    assert_eq!(
        every7.next_after(t("2026-08-30T12:00:00Z"), 0).unwrap(),
        t("2026-08-30T12:07:00Z"),
        "1788091200 is a multiple of 420: the next run is one interval later"
    );
    assert_eq!(
        every7.next_after(t("2026-08-30T12:01:00Z"), 0).unwrap(),
        t("2026-08-30T12:07:00Z")
    );
    assert!(matches!(
        Schedule::parse("every 0 minutes").unwrap_err(),
        ScheduleError::Malformed(_)
    ));
    assert!(matches!(
        Schedule::parse("60 * * * *").unwrap_err(),
        ScheduleError::OutOfRange {
            field: "minute",
            ..
        }
    ));
    assert!(Schedule::parse("* * *").is_err());
    assert!(fixed_offset_seconds(Some("America/New_York")).is_err());
    // A February 30 schedule never runs.
    assert!(Schedule::parse("0 0 30 2 *")
        .unwrap()
        .next_after(t("2026-01-01T00:00:00Z"), 0)
        .is_none());
    let c = Civil::from_unix(0);
    assert_eq!((c.year, c.month, c.day, c.weekday), (1970, 1, 1, 4));
}

/// A zone with daylight saving, so the schedule tests do not need the IANA database: US
/// Eastern in 2026 (EDT between 2026-03-08T07:00Z and 2026-11-01T06:00Z, EST otherwise).
struct UsEastern2026;

impl UsEastern2026 {
    const EDT: i64 = -4 * 3_600;
    const EST: i64 = -5 * 3_600;
    const SPRING: i64 = 1_773_385_200; // 2026-03-08T07:00:00Z
    const FALL: i64 = 1_793_944_800; // 2026-11-01T06:00:00Z

    const fn offset_at(utc: i64) -> i64 {
        if utc >= Self::SPRING && utc < Self::FALL {
            Self::EDT
        } else {
            Self::EST
        }
    }
}

impl ZoneRules for UsEastern2026 {
    fn local_of(&self, utc_secs: i64) -> i64 {
        utc_secs + Self::offset_at(utc_secs)
    }

    fn utc_of(&self, local_secs: i64) -> Option<i64> {
        // EDT first: an ambiguous civil time runs at its first (daylight) occurrence.
        for offset in [Self::EDT, Self::EST] {
            let utc = local_secs - offset;
            if Self::offset_at(utc) == offset {
                return Some(utc);
            }
        }
        None
    }
}

/// The enumerating reference the bounded window is compared against.
fn reference(
    s: &Schedule,
    from: LogicalInstant,
    to: LogicalInstant,
    zone: &dyn ZoneRules,
) -> Vec<LogicalInstant> {
    s.runs_between_in(from, to, zone, 100_000)
}

#[test]
fn the_bounded_run_window_matches_enumeration_over_zones_and_schedules() {
    // FN-CATCHUP-03 / 04: the latest instant and the count of a window agree with the
    // enumerating implementation, daylight-saving gaps and folds included.
    let utc = FixedOffset(0);
    let tokyo = FixedOffset(fixed_offset_seconds(Some("Asia/Tokyo")).unwrap());
    let zones: [(&str, &dyn ZoneRules); 3] = [
        ("UTC", &utc),
        ("Asia/Tokyo", &tokyo),
        ("US/Eastern", &UsEastern2026),
    ];
    let schedules = [
        "* * * * *",
        "*/15 9-17 * * mon-fri",
        "0 9 * * *",
        "30 2 * * *",
        "30 1 * * *",
        "0 0 1 * *",
        "0 0 1 1 *",
        "0 0 1 * sun",
        "every 5 minutes",
        "every 7 minutes",
        "every 3 hours",
        "every monday 09:30",
    ];
    let ranges = [
        // A DST spring gap, a fall fold, a plain week, an empty window and a minute.
        ("2026-03-07T00:00:00Z", "2026-03-09T12:00:00Z"),
        ("2026-11-01T00:00:00Z", "2026-11-02T12:00:00Z"),
        ("2026-11-01T05:00:00Z", "2026-11-01T06:20:00Z"),
        ("2026-08-24T00:00:00Z", "2026-08-31T00:00:00Z"),
        ("2026-08-24T00:00:00Z", "2026-08-24T00:00:00Z"),
        ("2026-08-24T00:00:00Z", "2026-08-24T00:01:00Z"),
        // A month: enough runs of an every-minute schedule to matter, few enough to enumerate.
        ("2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"),
    ];
    for (zone_name, zone) in zones {
        for source in schedules {
            let s = Schedule::parse(source).unwrap();
            for (from, to) in ranges {
                let (from, to) = (t(from), t(to));
                let expected = reference(&s, from, to, zone);
                let window = s.window_in(from, to, zone, 100_000);
                let label = format!("{zone_name} {source} {from:?}..{to:?}");
                assert_eq!(
                    window.latest,
                    expected.last().copied(),
                    "latest instant: {label}"
                );
                assert_eq!(
                    window.count,
                    RunCount::Exact(expected.len() as u64),
                    "count: {label}"
                );
            }
        }
    }
}

#[test]
fn a_large_window_costs_the_same_whatever_it_holds() {
    // FN-CATCHUP-01 / 02: the search does not step once per missed occurrence. Ten years of
    // an every-minute schedule hold 5.2 million runs; the window is answered in a number of
    // steps bounded by the count cap, and the latest instant alone in a handful.
    let utc = FixedOffset(0);
    let every_minute = Schedule::parse("* * * * *").unwrap();
    let from = t("2026-01-01T00:00:00Z");
    let to = t("2036-01-01T00:00:00Z");

    let capped = every_minute.window_in(from, to, &utc, 1_000);
    assert_eq!(capped.latest, Some(t("2036-01-01T00:00:00Z")));
    assert_eq!(capped.count, RunCount::AtLeast(1_000));
    // Measured: 1030 steps for 5.2 million occurrences.
    assert!(capped.steps <= 1_500, "{} steps", capped.steps);

    // A count cap of one keeps the whole window to a handful of steps: this is the shape
    // `catchUp = none` uses, where only "was anything due" matters.
    let tiny = every_minute.window_in(from, to, &utc, 1);
    assert_eq!(tiny.count, RunCount::AtLeast(1));
    // Measured: 31 steps (the zone probes plus a handful of civil-time steps).
    assert!(tiny.steps <= 64, "{} steps", tiny.steps);

    // An interval schedule is exact in constant time whatever the cap.
    let every5 = Schedule::parse("every 5 minutes").unwrap();
    let interval = every5.window_in(from, to, &utc, 1_000);
    // 3652 days (2028 and 2032 are the leap years in the window) of 288 runs each.
    assert_eq!(interval.count, RunCount::Exact(3_652 * 288));
    assert_eq!(interval.latest, Some(to));
    assert!(interval.steps <= 4, "{} steps", interval.steps);

    // A daily schedule: 3652 runs in the window, counted up to the cap, and the searches skip
    // to the next allowed hour and minute rather than stepping through the ones in between.
    let daily = Schedule::parse("0 3 * * *").unwrap();
    let daily_window = daily.window_in(from, to, &utc, 1_000);
    assert_eq!(daily_window.latest, Some(t("2035-12-31T03:00:00Z")));
    assert_eq!(daily_window.count, RunCount::AtLeast(1_000));
    // Measured: 4033 steps, i.e. four per counted run, not the ~83 a minute-by-minute
    // walk of each day would take.
    assert!(daily_window.steps <= 5_000, "{} steps", daily_window.steps);

    // A sparse schedule over the same window: the reverse search skips whole months.
    let yearly = Schedule::parse("0 0 1 1 *").unwrap();
    let sparse = yearly.window_in(from, to, &utc, 1_000);
    assert_eq!(sparse.latest, Some(t("2036-01-01T00:00:00Z")));
    assert_eq!(sparse.count, RunCount::Exact(10));
    // Measured: 513 steps, mostly month skips over the ten-year window.
    assert!(sparse.steps <= 1_000, "{} steps", sparse.steps);

    // An empty window and a window with a single run.
    let empty = every_minute.window_in(to, from, &utc, 1_000);
    assert_eq!(
        (empty.latest, empty.count),
        (None, RunCount::Exact(0)),
        "a window that ends before it starts holds nothing"
    );
    let one = every5.window_in(
        t("2026-01-01T00:00:00Z"),
        t("2026-01-01T00:05:00Z"),
        &utc,
        1_000,
    );
    assert_eq!(one.count, RunCount::Exact(1));
    assert_eq!(one.count.to_string(), "1 run");
    assert_eq!(RunCount::Exact(3).to_string(), "3 runs");
    assert_eq!(RunCount::AtLeast(1_000).to_string(), "at least 1000 runs");
    assert_eq!(RunCount::AtLeast(4).saturating_sub(1), RunCount::AtLeast(3));
    assert_eq!(RunCount::Exact(0).saturating_sub(1), RunCount::Exact(0));
    assert!(RunCount::Exact(0).is_zero() && !RunCount::AtLeast(0).is_zero());
    assert_eq!(RunCount::AtLeast(7).value(), 7);
}
