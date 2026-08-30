//! Patterns, manifests and schedules.

use ftd_core_functions::cron::{fixed_offset_seconds, Civil, Schedule, ScheduleError};
use ftd_core_functions::manifest::{
    DocumentEvent, FunctionManifest, FunctionSpec, ObjectEvent, Trigger, DEFAULT_CONCURRENCY,
    DEFAULT_REGION, DEFAULT_TIMEOUT_SECONDS,
};
use ftd_core_functions::pattern::{PathPattern, PatternError};
use ftd_core_types::time::LogicalInstant;

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
            function("a", Trigger::Http { callable: false }),
            function("a", Trigger::Http { callable: true }),
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
