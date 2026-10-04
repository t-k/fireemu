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
        "1st friday of quarter 9:00",
        "2nd,3rd monday 06:30",
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
// App Engine ordinal-weekday ("groc") schedules: `1st friday of quarter 9:00`.
// ---------------------------------------------------------------------------------------------

fn utc_next(text: &str, after: &str) -> Option<LogicalInstant> {
    Schedule::parse(text)
        .unwrap_or_else(|e| panic!("{text:?} must parse: {e}"))
        .next_after_in(t(after), &FixedOffset(0))
}

#[test]
fn groc_ordinal_weekday_forms_parse() {
    for text in [
        "1st friday of quarter 9:00",
        "1st friday of quarter 09:00",
        "first monday of month 12:00",
        "1st,3rd sat of month 09:00",
        "2nd,third wed,thu of feb,aug 13:50",
        "1st,2nd monday 9:00",
        "5th sunday of month 00:00",
        "FIRST Friday OF Quarter 9:00",
    ] {
        let schedule = Schedule::parse(text).unwrap_or_else(|e| panic!("{text:?}: {e}"));
        assert_eq!(schedule.as_str(), text);
    }
}

#[test]
fn groc_ordinal_weekday_refuses_what_it_does_not_recognise() {
    for text in [
        "1st friday of quarter",
        "1st friday of quarter 24:00",
        "1st friday of quarter 9:60",
        "1st friday of quarter 9:0",
        "1st friday of quarter 9",
        "6th friday of month 9:00",
        "0th friday of month 9:00",
        "1st funday of month 9:00",
        "1st friday of fortnight 9:00",
        "1st friday off month 9:00",
        "1st friday of month 9:00 extra",
        "1st,,3rd friday of month 9:00",
        "1st friday,, of month 9:00",
        "1st friday of jan,,feb 9:00",
        "1st of month 9:00",
        "friday of month 9:00",
        "1st friday of 9:00",
    ] {
        assert!(
            matches!(
                Schedule::parse(text),
                Err(ScheduleError::Malformed(_) | ScheduleError::OutOfRange { .. })
            ),
            "{text:?} must be refused"
        );
    }
}

/// The production observation (calendar v5, c04): created on 2026-10-01 (a Thursday) the
/// next run was the first Friday of October.
#[test]
fn groc_first_friday_of_quarter_runs_on_the_first_friday() {
    assert_eq!(
        utc_next("1st friday of quarter 9:00", "2026-10-01T05:20:18Z"),
        Some(t("2026-10-02T09:00:00Z"))
    );
}

/// UNVERIFIED against production: that `quarter` means January, April, July and October. The
/// recorded c04 cannot tell it from `month` (it was created before October's first Friday).
/// 2027-01-01 is a Friday, so the next run after October's is the very first day of January.
#[test]
fn groc_quarter_is_assumed_to_be_the_first_month_of_each_quarter() {
    assert_eq!(
        utc_next("1st friday of quarter 9:00", "2026-10-02T09:00:00Z"),
        Some(t("2027-01-01T09:00:00Z"))
    );
    assert_eq!(
        utc_next("1st friday of month 9:00", "2026-10-02T09:00:00Z"),
        Some(t("2026-11-06T09:00:00Z"))
    );
}

#[test]
fn groc_ordinal_lists_pick_every_listed_occurrence() {
    let sat = Schedule::parse("1st,3rd sat of month 09:00").unwrap();
    let zone = FixedOffset(0);
    let runs = sat.runs_between_in(
        t("2026-10-01T00:00:00Z"),
        t("2026-11-30T00:00:00Z"),
        &zone,
        100,
    );
    assert_eq!(
        runs,
        [
            t("2026-10-03T09:00:00Z"),
            t("2026-10-17T09:00:00Z"),
            t("2026-11-07T09:00:00Z"),
            t("2026-11-21T09:00:00Z"),
        ]
    );
}

#[test]
fn groc_weekday_and_month_lists_combine() {
    let schedule = Schedule::parse("2nd,third wed,thu of feb,aug 13:50").unwrap();
    let runs = schedule.runs_between_in(
        t("2026-01-01T00:00:00Z"),
        t("2026-12-31T00:00:00Z"),
        &FixedOffset(0),
        100,
    );
    assert_eq!(
        runs,
        [
            t("2026-02-11T13:50:00Z"),
            t("2026-02-12T13:50:00Z"),
            t("2026-02-18T13:50:00Z"),
            t("2026-02-19T13:50:00Z"),
            t("2026-08-12T13:50:00Z"),
            t("2026-08-13T13:50:00Z"),
            t("2026-08-19T13:50:00Z"),
            t("2026-08-20T13:50:00Z"),
        ]
    );
}

#[test]
fn groc_fifth_occurrence_exists_only_in_months_with_five_of_that_weekday() {
    let schedule = Schedule::parse("5th monday of month 09:00").unwrap();
    let runs = schedule.runs_between_in(
        t("2026-01-01T00:00:00Z"),
        t("2026-12-31T00:00:00Z"),
        &FixedOffset(0),
        100,
    );
    assert_eq!(
        runs,
        [
            t("2026-03-30T09:00:00Z"),
            t("2026-06-29T09:00:00Z"),
            t("2026-08-31T09:00:00Z"),
            t("2026-11-30T09:00:00Z"),
        ]
    );
}

#[test]
fn groc_without_a_month_spec_runs_in_every_month() {
    let schedule = Schedule::parse("1st,2nd monday 9:00").unwrap();
    let runs = schedule.runs_between_in(
        t("2026-10-01T00:00:00Z"),
        t("2026-11-30T00:00:00Z"),
        &FixedOffset(0),
        100,
    );
    assert_eq!(
        runs,
        [
            t("2026-10-05T09:00:00Z"),
            t("2026-10-12T09:00:00Z"),
            t("2026-11-02T09:00:00Z"),
            t("2026-11-09T09:00:00Z"),
        ]
    );
}

mod groc_model {
    use super::*;
    use fireemu_core_functions::cron::civil_from_days;
    use proptest::prelude::*;
    use std::fmt::Write as _;

    const ORDINALS: [[&str; 2]; 5] = [
        ["1st", "first"],
        ["2nd", "second"],
        ["3rd", "third"],
        ["4th", "fourth"],
        ["5th", "fifth"],
    ];
    const WEEKDAYS: [[&str; 2]; 7] = [
        ["sun", "sunday"],
        ["mon", "monday"],
        ["tue", "tuesday"],
        ["wed", "wednesday"],
        ["thu", "thursday"],
        ["fri", "friday"],
        ["sat", "saturday"],
    ];
    const MONTHS: [[&str; 2]; 12] = [
        ["jan", "january"],
        ["feb", "february"],
        ["mar", "march"],
        ["apr", "april"],
        ["may", "may"],
        ["jun", "june"],
        ["jul", "july"],
        ["aug", "august"],
        ["sep", "september"],
        ["oct", "october"],
        ["nov", "november"],
        ["dec", "december"],
    ];
    const HORIZON_DAYS: i64 = 8 * 366;

    /// How the month part of the text is written, with the month mask it must mean.
    #[derive(Debug, Clone)]
    enum MonthSpec {
        Absent,
        Month,
        Quarter,
        List(u16),
    }

    impl MonthSpec {
        fn mask(&self) -> u16 {
            match self {
                Self::Absent | Self::Month => 0b1_1111_1111_1110,
                Self::Quarter => (1 << 1) | (1 << 4) | (1 << 7) | (1 << 10),
                Self::List(mask) => *mask,
            }
        }
    }

    fn names(table: &[[&str; 2]], mask: u16, base: u32, long: bool) -> String {
        (base..base + u32::try_from(table.len()).unwrap())
            .filter(|n| mask >> n & 1 == 1)
            .map(|n| table[(n - base) as usize][usize::from(long)])
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The independent day-by-day reference: the first matching minute strictly after `after`.
    fn reference_next(
        after: i64,
        offset: i64,
        ordinals: u16,
        weekdays: u16,
        months: u16,
        hour: u32,
        minute: u32,
    ) -> Option<i64> {
        let start_day = (after + offset).div_euclid(86_400);
        (start_day..start_day + HORIZON_DAYS).find_map(|day| {
            let (_, month, dom) = civil_from_days(day);
            let weekday = (day + 4).rem_euclid(7);
            let nth = (dom - 1) / 7 + 1;
            let matches = months >> month & 1 == 1
                && weekdays >> weekday & 1 == 1
                && ordinals >> nth & 1 == 1;
            let utc = day * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60 - offset;
            (matches && utc > after).then_some(utc)
        })
    }

    fn month_spec() -> impl Strategy<Value = MonthSpec> {
        prop_oneof![
            Just(MonthSpec::Absent),
            Just(MonthSpec::Month),
            Just(MonthSpec::Quarter),
            (1u16..4096).prop_map(|bits| MonthSpec::List(bits << 1)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(400))]

        #[test]
        fn the_next_run_matches_a_day_by_day_reference(
            ordinal_bits in 1u16..32,
            weekday_bits in 1u16..128,
            spec in month_spec(),
            long_names in any::<bool>(),
            hour in 0u32..24,
            minute in 0u32..60,
            after in 1_577_836_800i64..2_082_758_400,
            offset in prop::sample::select(vec![-18_000i64, 0, 19_800, 32_400]),
        ) {
            let ordinals = ordinal_bits << 1;
            let mut text = names(&ORDINALS, ordinals, 1, long_names);
            text.push(' ');
            text.push_str(&names(&WEEKDAYS, weekday_bits, 0, long_names));
            match &spec {
                MonthSpec::Absent => {}
                MonthSpec::Month => text.push_str(" of month"),
                MonthSpec::Quarter => text.push_str(" of quarter"),
                MonthSpec::List(mask) => {
                    text.push_str(" of ");
                    text.push_str(&names(&MONTHS, *mask, 1, long_names));
                }
            }
            write!(text, " {hour}:{minute:02}").unwrap();

            let schedule = Schedule::parse(&text).unwrap_or_else(|e| panic!("{text:?}: {e}"));
            let got = schedule
                .next_after(LogicalInstant::from_unix_seconds(after), offset)
                .map(|i| i64::try_from(i.as_nanos() / 1_000_000_000).unwrap());
            let want = reference_next(
                after, offset, ordinals, weekday_bits, spec.mask(), hour, minute,
            );
            let near_horizon = after + (HORIZON_DAYS - 3) * 86_400;
            if want.is_some_and(|w| w < near_horizon) {
                prop_assert_eq!(got, want, "{}", text);
            } else {
                prop_assert!(got.is_none() || got.is_some_and(|g| g >= near_horizon), "{}", text);
            }
        }
    }
}
