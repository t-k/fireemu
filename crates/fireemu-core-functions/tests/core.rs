//! Patterns, manifests and schedules.

use fireemu_core_functions::cron::{
    fixed_offset_seconds, Civil, FixedOffset, RunCount, Schedule, ScheduleError, ZoneRules,
};
use fireemu_core_functions::manifest::{
    BlockingAuthEvent, BlockingAuthSelection, BlockingAuthSelectionError, BlockingAuthTokenPolicy,
    DocumentEvent, FunctionGeneration, FunctionManifest, FunctionSpec, ManifestError, ObjectEvent,
    PlatformOptions, Trigger, DEFAULT_REGION, DEFAULT_TIMEOUT_SECONDS,
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
        generation: FunctionGeneration::First,
        concurrency: None,
        platform_options: PlatformOptions::default(),
    }
}

fn validate_function(spec: &FunctionSpec) -> Result<(), ManifestError> {
    FunctionManifest {
        functions: vec![spec.clone()],
        ignored: Vec::new(),
    }
    .validate()
}

#[test]
fn manifests_match_firestore_and_storage_triggers() {
    let m = FunctionManifest {
        functions: vec![
            function(
                "onTodo",
                Trigger::Firestore {
                    event: DocumentEvent::Created,
                    database: fireemu_core_types::ids::DatabaseId::DEFAULT.into(),
                    document: PathPattern::parse("todos/{id}").unwrap(),
                    with_auth_context: false,
                },
            ),
            function(
                "onAny",
                Trigger::Firestore {
                    event: DocumentEvent::Written,
                    database: fireemu_core_types::ids::DatabaseId::DEFAULT.into(),
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
        ignored: Vec::new(),
    };
    m.validate().unwrap();
    let created = m.firestore_matches(
        fireemu_core_types::ids::DatabaseId::DEFAULT,
        "todos/t1",
        DocumentEvent::Created,
    );
    assert_eq!(
        created
            .iter()
            .map(|x| x.function.name.as_str())
            .collect::<Vec<_>>(),
        ["onTodo", "onAny"]
    );
    assert_eq!(created[0].params["id"], "t1");
    let deleted = m.firestore_matches(
        fireemu_core_types::ids::DatabaseId::DEFAULT,
        "todos/t1",
        DocumentEvent::Deleted,
    );
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
        ignored: Vec::new(),
    };
    assert!(dup.validate().is_err());
}

#[test]
fn blocking_auth_selection_is_resolved_against_discovered_event_and_region() {
    let manifest = FunctionManifest {
        functions: vec![
            function(
                "createGuard",
                Trigger::BlockingAuth {
                    event: BlockingAuthEvent::BeforeCreate,
                    token_policy: BlockingAuthTokenPolicy::default(),
                },
            ),
            {
                let mut spec = function(
                    "signInGuard",
                    Trigger::BlockingAuth {
                        event: BlockingAuthEvent::BeforeSignIn,
                        token_policy: BlockingAuthTokenPolicy::ALL,
                    },
                );
                spec.region = "europe-west1".to_owned();
                spec
            },
        ],
        ignored: Vec::new(),
    };

    let target = manifest
        .blocking_auth_target(
            BlockingAuthEvent::BeforeSignIn,
            &BlockingAuthSelection::Explicit {
                function: "signInGuard".to_owned(),
                region: Some("europe-west1".to_owned()),
            },
        )
        .unwrap()
        .unwrap();
    assert_eq!(target.name, "signInGuard");

    let inherited = manifest
        .blocking_auth_target(
            BlockingAuthEvent::BeforeCreate,
            &BlockingAuthSelection::Discovery,
        )
        .unwrap()
        .unwrap();
    assert_eq!(inherited.name, "createGuard");
    assert!(manifest
        .blocking_auth_target(
            BlockingAuthEvent::BeforeCreate,
            &BlockingAuthSelection::Disabled,
        )
        .unwrap()
        .is_none());

    let wrong_region = manifest
        .blocking_auth_target(
            BlockingAuthEvent::BeforeSignIn,
            &BlockingAuthSelection::Explicit {
                function: "signInGuard".to_owned(),
                region: Some("asia-northeast1".to_owned()),
            },
        )
        .unwrap_err();
    assert!(matches!(
        wrong_region,
        BlockingAuthSelectionError::RegionMismatch { .. }
    ));
}

#[test]
fn blocking_auth_selection_fails_closed_for_missing_or_wrong_event_targets() {
    let manifest = FunctionManifest {
        functions: vec![function("http", Trigger::http(false))],
        ignored: Vec::new(),
    };
    let missing = manifest
        .blocking_auth_target(
            BlockingAuthEvent::BeforeCreate,
            &BlockingAuthSelection::Explicit {
                function: "missing".to_owned(),
                region: None,
            },
        )
        .unwrap_err();
    assert!(matches!(
        missing,
        BlockingAuthSelectionError::FunctionNotFound { .. }
    ));

    let wrong_event = manifest
        .blocking_auth_target(
            BlockingAuthEvent::BeforeCreate,
            &BlockingAuthSelection::Explicit {
                function: "http".to_owned(),
                region: None,
            },
        )
        .unwrap_err();
    assert!(matches!(
        wrong_event,
        BlockingAuthSelectionError::WrongEvent { .. }
    ));
}

#[test]
fn blocking_auth_token_policy_intersects_global_switch_and_request_presence() {
    let requested = BlockingAuthTokenPolicy::ALL;
    let present = fireemu_core_functions::manifest::BlockingAuthCredentialPresence {
        access_token: true,
        id_token: false,
        refresh_token: true,
    };
    assert_eq!(
        requested.effective(true, present),
        BlockingAuthTokenPolicy {
            access_token: true,
            id_token: false,
            refresh_token: true,
        }
    );
    assert_eq!(
        requested.effective(false, present),
        BlockingAuthTokenPolicy::default()
    );
}

#[test]
fn second_generation_concurrency_resolves_per_instance_defaults_and_virtual_capacity() {
    let mut spec = function(
        "http",
        Trigger::Http {
            callable: false,
            enforce_app_check: false,
            consume_app_check_token:
                fireemu_core_functions::manifest::ConsumeAppCheckToken::Undetermined,
        },
    );
    spec.generation = FunctionGeneration::Second;
    spec.concurrency = None;
    for memory_mb in [256, 512, 1_024, 2_048] {
        spec.platform_options.available_memory_mb = Some(memory_mb);
        assert_eq!(
            spec.effective_concurrency(),
            80,
            "second-generation functions default to one CPU at {memory_mb} MiB"
        );
        assert_eq!(spec.http_capacity(8), 8);
    }

    spec.generation = FunctionGeneration::First;
    assert_eq!(spec.effective_concurrency(), 1);
    spec.generation = FunctionGeneration::Second;

    spec.platform_options.cpu = Some("gcf_gen1".to_owned());
    for (memory_mb, expected) in [(1_024, 1), (2_048, 80), (4_096, 80)] {
        spec.platform_options.available_memory_mb = Some(memory_mb);
        assert_eq!(spec.effective_concurrency(), expected);
    }
    spec.platform_options.available_memory_mb = Some(4_096);
    spec.platform_options.cpu = Some("0.5".to_owned());
    assert_eq!(spec.effective_concurrency(), 1);
    spec.platform_options.cpu = Some("1".to_owned());
    assert_eq!(spec.effective_concurrency(), 80);

    spec.concurrency = Some(1);
    spec.platform_options.max_instances = Some(2);
    assert_eq!(spec.http_capacity(8), 2);
}

#[test]
fn manifest_validation_rejects_gen1_only_capacity_options() {
    let mut spec = function("http", Trigger::http(false));
    spec.concurrency = Some(1);
    let error = validate_function(&spec).unwrap_err();
    assert!(error.to_string().contains("concurrency"));

    spec.concurrency = None;
    spec.platform_options.cpu = Some("gcf_gen1".to_owned());
    assert!(validate_function(&spec).is_err());

    spec.platform_options.cpu = None;
    spec.platform_options.network_interfaces = vec!["{\"network\":\"default\"}".to_owned()];
    assert!(validate_function(&spec).is_err());
}

#[test]
fn manifest_validation_rejects_invalid_gen2_cpu_and_concurrency_combinations() {
    let mut spec = function("http", Trigger::http(false));
    spec.generation = FunctionGeneration::Second;
    spec.concurrency = Some(1_001);
    assert!(validate_function(&spec).is_err());

    spec.concurrency = Some(2);
    spec.platform_options.cpu = Some("0.5".to_owned());
    assert!(validate_function(&spec).is_err());

    spec.concurrency = Some(2);
    spec.platform_options.cpu = Some("gcf_gen1".to_owned());
    spec.platform_options.available_memory_mb = Some(1_024);
    assert!(validate_function(&spec).is_err());

    for (cpu, memory_mb, concurrency) in [
        (None, None, Some(1_000)),
        (Some("0.5"), None, None),
        (Some("0.5"), None, Some(1)),
        (Some("1"), None, Some(2)),
        (Some("gcf_gen1"), Some(1_024), Some(1)),
        (Some("gcf_gen1"), Some(2_048), Some(2)),
    ] {
        spec.platform_options.cpu = cpu.map(str::to_owned);
        spec.platform_options.available_memory_mb = memory_mb;
        spec.concurrency = concurrency;
        validate_function(&spec).unwrap();
    }

    for cpu in ["invalid", "0", "NaN"] {
        spec.platform_options.cpu = Some(cpu.to_owned());
        spec.concurrency = None;
        assert!(validate_function(&spec).is_err());
    }
}

#[test]
fn manifest_validation_rejects_invalid_memory_and_instance_limits() {
    let mut spec = function("http", Trigger::http(false));
    spec.generation = FunctionGeneration::Second;
    spec.platform_options.cpu = None;
    spec.platform_options.available_memory_mb = Some(0);
    assert!(validate_function(&spec).is_err());

    spec.platform_options.available_memory_mb = None;
    spec.platform_options.min_instances = Some(0);
    spec.platform_options.max_instances = Some(0);
    assert!(validate_function(&spec).is_err());

    spec.platform_options.min_instances = Some(4);
    spec.platform_options.max_instances = Some(3);
    assert!(validate_function(&spec).is_err());

    spec.platform_options.min_instances = Some(1);
    spec.platform_options.max_instances = Some(1);
    validate_function(&spec).unwrap();
}

#[test]
fn manifest_validation_rejects_task_concurrency_above_the_emulator_limit() {
    let mut spec = function(
        "queue",
        Trigger::TaskQueue {
            retry: fireemu_core_functions::manifest::TaskRetryConfig::default(),
            rate_limits: fireemu_core_functions::manifest::TaskRateLimits {
                max_concurrent_dispatches: 5_001,
                max_dispatches_per_second: 500.0,
            },
        },
    );
    let error = validate_function(&spec).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("rateLimits.maxConcurrentDispatches must be at most 5000"),
        "{error}"
    );

    if let Trigger::TaskQueue { rate_limits, .. } = &mut spec.trigger {
        rate_limits.max_concurrent_dispatches = 5_000;
    }
    validate_function(&spec).unwrap();
}

#[test]
fn manifest_validation_rejects_task_dispatch_rates_outside_production_limits() {
    let mut spec = function(
        "queue",
        Trigger::TaskQueue {
            retry: fireemu_core_functions::manifest::TaskRetryConfig::default(),
            rate_limits: fireemu_core_functions::manifest::TaskRateLimits {
                max_concurrent_dispatches: 1,
                max_dispatches_per_second: 0.0,
            },
        },
    );
    for invalid in [0.0, -0.5, 500.1, f64::INFINITY, f64::NAN] {
        let Trigger::TaskQueue { rate_limits, .. } = &mut spec.trigger else {
            unreachable!();
        };
        rate_limits.max_dispatches_per_second = invalid;
        let error = validate_function(&spec).unwrap_err();
        assert!(
            error.to_string().contains(
                "rateLimits.maxDispatchesPerSecond must be greater than 0 and at most 500"
            ),
            "{invalid:?}: {error}"
        );
    }

    if let Trigger::TaskQueue { rate_limits, .. } = &mut spec.trigger {
        rate_limits.max_dispatches_per_second = 0.5;
    }
    validate_function(&spec).unwrap();
    if let Trigger::TaskQueue { rate_limits, .. } = &mut spec.trigger {
        rate_limits.max_dispatches_per_second = 500.0;
    }
    validate_function(&spec).unwrap();
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

#[test]
fn fixed_offset_error_describes_the_limited_table() {
    let error = fixed_offset_seconds(Some("America/New_York")).unwrap_err();
    assert_eq!(
        error.to_string(),
        "time zone \"America/New_York\" is not in the fixed-offset zone table"
    );
}

/// A zone with daylight saving, so the schedule tests do not need the IANA database: US
/// Eastern in 2026 (EDT between 2026-03-08T07:00Z and 2026-11-01T06:00Z, EST otherwise).
struct UsEastern2026;

impl UsEastern2026 {
    const EDT: i64 = -4 * 3_600;
    const EST: i64 = -5 * 3_600;
    const SPRING: i64 = 1772953200; // 2026-03-08T07:00:00Z
    const FALL: i64 = 1793512800; // 2026-11-01T06:00:00Z

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

// ---------------------------------------------------------------------------------------------
// The boundary of a run window: an occurrence belongs to `(from, to]`.
// ---------------------------------------------------------------------------------------------

#[test]
fn an_occurrence_is_in_the_window_that_ends_at_it_and_not_in_one_that_ends_a_nanosecond_before() {
    let utc = FixedOffset(0);
    let from = t("2026-08-29T12:00:00Z");
    let at = t("2026-08-29T12:05:00Z");
    let before = |i: LogicalInstant| LogicalInstant::from_nanos(i.as_nanos() - 1);
    let after = |i: LogicalInstant| LogicalInstant::from_nanos(i.as_nanos() + 1);
    for text in ["every 5 minutes", "*/5 * * * *", "5 12 * * *"] {
        let schedule = Schedule::parse(text).unwrap();
        // Ends one nanosecond before the occurrence: nothing is due yet.
        assert!(
            schedule
                .runs_between_in(from, before(at), &utc, 10)
                .is_empty(),
            "{text}"
        );
        let early = schedule.window_in(from, before(at), &utc, 10);
        assert_eq!(early.count, RunCount::Exact(0), "{text}");
        assert_eq!(early.latest, None, "{text}");
        // Ends exactly at the occurrence: it is due, once.
        assert_eq!(
            schedule.runs_between_in(from, at, &utc, 10),
            vec![at],
            "{text}"
        );
        let on_time = schedule.window_in(from, at, &utc, 10);
        assert_eq!(on_time.count, RunCount::Exact(1), "{text}");
        assert_eq!(on_time.latest, Some(at), "{text}");
        // Starts at the occurrence: it is not due a second time.
        assert!(
            schedule.runs_between_in(at, after(at), &utc, 10).is_empty(),
            "{text}"
        );
        assert_eq!(
            schedule.window_in(at, after(at), &utc, 10).count,
            RunCount::Exact(0),
            "{text}"
        );
    }
}

#[test]
fn a_restricted_month_or_day_is_found_across_months_years_and_leap_days() {
    let utc = FixedOffset(0);
    let next = |text: &str, after: &str| {
        Schedule::parse(text)
            .unwrap()
            .next_after_in(t(after), &utc)
            .unwrap_or_else(|| panic!("{text} after {after} has no run"))
    };
    // A month later in the same year, the same run exactly at the instant, and the next year.
    assert_eq!(
        next("0 9 1 6 *", "2026-01-15T00:00:00Z"),
        t("2026-06-01T09:00:00Z")
    );
    assert_eq!(
        next("0 9 1 6 *", "2026-06-01T08:59:59Z"),
        t("2026-06-01T09:00:00Z")
    );
    assert_eq!(
        next("0 9 1 6 *", "2026-06-01T09:00:00Z"),
        t("2027-06-01T09:00:00Z")
    );
    // The search wraps over the year end (December to a month early in the next year).
    assert_eq!(
        next("0 9 1 6 *", "2026-12-31T10:00:00Z"),
        t("2027-06-01T09:00:00Z")
    );
    assert_eq!(
        next("0 0 1 1,7 *", "2026-07-01T00:00:00Z"),
        t("2027-01-01T00:00:00Z")
    );
    assert_eq!(
        next("0 0 1 1,7 *", "2026-12-15T00:00:00Z"),
        t("2027-01-01T00:00:00Z")
    );
    // A day some months lack, and a leap day years ahead.
    assert_eq!(
        next("0 9 31 * *", "2026-04-15T00:00:00Z"),
        t("2026-05-31T09:00:00Z")
    );
    assert_eq!(
        next("0 0 29 2 *", "2026-03-01T00:00:00Z"),
        t("2028-02-29T00:00:00Z")
    );
}

#[test]
fn a_window_over_a_restricted_schedule_lists_counts_and_ends_on_the_right_runs() {
    let utc = FixedOffset(0);
    let june_first = Schedule::parse("0 9 1 6,12 *").unwrap();
    assert_eq!(
        june_first.runs_between_in(
            t("2026-01-01T00:00:00Z"),
            t("2027-12-31T00:00:00Z"),
            &utc,
            100
        ),
        vec![
            t("2026-06-01T09:00:00Z"),
            t("2026-12-01T09:00:00Z"),
            t("2027-06-01T09:00:00Z"),
            t("2027-12-01T09:00:00Z"),
        ]
    );
    // Seven Junes in the window: counted exactly, the newest is the latest, and the work done
    // is more than nothing (the counter is what the bounded-work assertions read).
    let june = Schedule::parse("0 9 1 6 *").unwrap();
    let all = june.window_in(
        t("2020-01-01T00:00:00Z"),
        t("2026-12-31T00:00:00Z"),
        &utc,
        100,
    );
    assert_eq!(all.count, RunCount::Exact(7));
    assert_eq!(all.latest, Some(t("2026-06-01T09:00:00Z")));
    assert!(all.steps >= 7, "{} steps for seven runs", all.steps);
    // A cap below the number of runs stops the count there and says so.
    let capped = june.window_in(
        t("2020-01-01T00:00:00Z"),
        t("2026-12-31T00:00:00Z"),
        &utc,
        5,
    );
    assert!(!capped.count.is_exact());
    assert_eq!(capped.count.value(), 5);
    assert_eq!(capped.latest, Some(t("2026-06-01T09:00:00Z")));
    // Three nights in a window that ends before the fourth.
    let nightly = Schedule::parse("0 3 * * *").unwrap();
    let nights = nightly.window_in(
        t("2026-08-29T12:01:00Z"),
        t("2026-09-01T04:00:00Z"),
        &utc,
        100,
    );
    assert_eq!(nights.count, RunCount::Exact(3));
    assert_eq!(nights.latest, Some(t("2026-09-01T03:00:00Z")));
    assert!(nights.steps >= 3, "{} steps", nights.steps);
    // A cap equal to the number of runs is not "at least": nothing more lies in the window.
    let exact = nightly.window_in(
        t("2026-08-29T12:01:00Z"),
        t("2026-09-01T04:00:00Z"),
        &utc,
        3,
    );
    assert_eq!(exact.count, RunCount::Exact(3));
    let below = nightly.window_in(
        t("2026-08-29T12:01:00Z"),
        t("2026-09-01T04:00:00Z"),
        &utc,
        2,
    );
    assert_eq!(below.count, RunCount::AtLeast(2));
}

#[test]
fn the_dst_gap_is_skipped_and_the_fold_runs_at_its_first_occurrence_in_every_window_search() {
    let ny = UsEastern2026;
    // 2026-03-08 02:30 does not exist: the next run of `30 2 * * *` is the day after.
    let spring = Schedule::parse("30 2 * * *").unwrap();
    assert_eq!(
        spring.next_after_in(t("2026-03-07T12:00:00Z"), &ny),
        Some(t("2026-03-09T06:30:00Z"))
    );
    let gap = spring.window_in(
        t("2026-03-07T12:00:00Z"),
        t("2026-03-09T12:00:00Z"),
        &ny,
        100,
    );
    assert_eq!(gap.count, RunCount::Exact(1));
    assert_eq!(gap.latest, Some(t("2026-03-09T06:30:00Z")));

    // 2026-11-01 01:30 happens twice: the schedule runs at the first (EDT, 05:30Z) only.
    let fold = Schedule::parse("30 1 * * *").unwrap();
    assert_eq!(
        fold.next_after_in(t("2026-10-31T12:00:00Z"), &ny),
        Some(t("2026-11-01T05:30:00Z"))
    );
    assert_eq!(
        fold.next_after_in(t("2026-11-01T05:30:00Z"), &ny),
        Some(t("2026-11-02T06:30:00Z")),
        "the second 01:30 (EST) is not a run"
    );
    // A window ending in the repeated hour, after the first occurrence: it holds that run, and
    // the one ending after the second occurrence holds it too, once.
    for to in ["2026-11-01T06:10:00Z", "2026-11-01T06:40:00Z"] {
        let w = fold.window_in(t("2026-10-31T12:00:00Z"), t(to), &ny, 100);
        assert_eq!(w.count, RunCount::Exact(1), "{to}");
        assert_eq!(w.latest, Some(t("2026-11-01T05:30:00Z")), "{to}");
    }
    // A window that ends before the first occurrence: the candidate 01:30 maps to an instant
    // after the window's end, so the latest run is the previous night's.
    let before = fold.window_in(
        t("2026-10-30T12:00:00Z"),
        t("2026-11-01T05:10:00Z"),
        &ny,
        100,
    );
    assert_eq!(before.count, RunCount::Exact(1));
    assert_eq!(before.latest, Some(t("2026-10-31T05:30:00Z")));
}

#[test]
fn the_work_counter_is_deterministic() {
    let utc = FixedOffset(0);
    let every5 = Schedule::parse("every 5 minutes").unwrap();
    let w = every5.window_in(
        t("2026-08-29T12:00:00Z"),
        t("2026-08-29T12:20:00Z"),
        &utc,
        100,
    );
    assert_eq!(w.steps, 2, "an interval window is two divisions");
    let nightly = Schedule::parse("0 3 * * *").unwrap();
    let n = nightly.window_in(
        t("2026-08-29T12:01:00Z"),
        t("2026-09-01T04:00:00Z"),
        &utc,
        100,
    );
    assert_eq!(
        n.steps, 45,
        "27 reverse-probe hours, the backward walk, the forward count"
    );
    let june = Schedule::parse("0 9 1 6 *").unwrap();
    let j = june.window_in(
        t("2020-01-01T00:00:00Z"),
        t("2026-12-31T00:00:00Z"),
        &utc,
        100,
    );
    assert_eq!(j.steps, 380, "a month-restricted schedule walks months");
    let ny = UsEastern2026;
    let fold = Schedule::parse("30 1 * * *").unwrap();
    let f = fold.window_in(
        t("2026-10-31T12:00:00Z"),
        t("2026-11-01T06:10:00Z"),
        &ny,
        100,
    );
    assert_eq!(f.steps, 39, "a fold window walks one repeated hour");
}
