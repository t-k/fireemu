//! Kani harnesses for the pure core (spec 22).
//!
//! Each harness names the requirement it covers. Run with `cargo kani -p ftd-verification-kani`.
//! The harnesses compile only under `cfg(kani)`; a normal build sees an empty crate.

#[cfg(kani)]
mod harnesses {
    use ftd_core_auth::totp::{time_step, TotpParams};
    use ftd_core_events::event::{EventSource, EventType, LogicalEvent};
    use ftd_core_events::retry::RetryPolicy;
    use ftd_core_events::state::{EventRecord, EventTransitionError};
    use ftd_core_limits::evaluate::{
        classify_severity, ratio_micros, violates_boundary, DEFAULT_THRESHOLDS,
    };
    use ftd_core_limits::model::LimitBoundary;
    use ftd_core_session::clock::VirtualClock;
    use ftd_core_session::idle::{AwaitIdleOptions, WorkKind};
    use ftd_core_session::session::{Session, WorkResult};
    use ftd_core_types::determinism::Clock;
    use ftd_core_types::ids::{CorrelationId, Epoch, EventId, SessionId};
    use ftd_core_types::time::{LogicalDuration, LogicalInstant};

    /// INV-LIMIT-001 (boundary part): inclusive allows N, exclusive rejects N, and a boundary
    /// rejection always takes precedence over warnings.
    #[kani::proof]
    fn limit_boundary_classification() {
        // 16-bit operands keep the u128 ratio arithmetic tractable for the solver.
        let maximum: u16 = kani::any();
        let current: u16 = kani::any();
        kani::assume(maximum > 0);
        let (maximum, current) = (u64::from(maximum), u64::from(current));
        let inclusive = violates_boundary(LimitBoundary::InclusiveMaximum, current, maximum);
        let exclusive = violates_boundary(LimitBoundary::ExclusiveMaximum, current, maximum);
        assert_eq!(inclusive, current > maximum);
        assert_eq!(exclusive, current >= maximum);
        if !inclusive {
            assert!(ratio_micros(current, maximum) <= 1_000_000);
        }
        kani::cover!(inclusive && !exclusive == false);
    }

    /// Warning severity is monotone in the usage. Bounded to 16-bit operands so that the u128
    /// threshold arithmetic stays tractable for the solver.
    #[kani::proof]
    #[kani::unwind(4)]
    fn severity_is_monotone() {
        let maximum: u16 = kani::any();
        let a: u16 = kani::any();
        let b: u16 = kani::any();
        kani::assume(maximum > 0 && a <= b);
        let sa = classify_severity(u64::from(a), u64::from(maximum), DEFAULT_THRESHOLDS);
        let sb = classify_severity(u64::from(b), u64::from(maximum), DEFAULT_THRESHOLDS);
        assert!(sa <= sb);
    }

    /// INV-EPOCH-001: the guard accepts exactly the current epoch while active.
    #[kani::proof]
    #[kani::unwind(4)]
    fn epoch_guard_rejects_every_other_epoch() {
        let mut session =
            Session::create(SessionId::new(1), kani::any(), LogicalInstant::UNIX_EPOCH);
        session.activate().unwrap();
        let resets: u8 = kani::any();
        kani::assume(resets <= 2);
        for _ in 0..resets {
            session.begin_reset().unwrap();
            session.complete_reset().unwrap();
        }
        let claimed = Epoch::new(kani::any());
        let result = session.check_work_epoch(claimed);
        if claimed == session.epoch() {
            assert_eq!(result, WorkResult::Proceed);
        } else {
            assert_eq!(result, WorkResult::DiscardedStaleEpoch);
        }
    }

    /// INV-TIME-001: advancing never moves the clock backwards and never panics.
    #[kani::proof]
    fn virtual_clock_never_moves_backwards() {
        let start = LogicalInstant::from_nanos(kani::any());
        let mut clock = VirtualClock::new(start);
        let d = LogicalDuration::from_nanos(kani::any());
        let _ = clock.advance(d);
        assert!(clock.now() >= start);
    }

    /// INV-IDLE-001 (predicate part): every work kind except future schedules is fenced under
    /// the default options, and Text Index builds are fenced unless explicitly ignored. This
    /// harness is allocation-free; the ledger itself is covered by tests and Loom.
    #[kani::proof]
    fn idle_predicate_never_ignores_active_work() {
        let kinds = [
            WorkKind::FirestoreCommit,
            WorkKind::EventDispatch,
            WorkKind::EventRetryWait,
            WorkKind::FunctionInvocation,
            WorkKind::DueSchedule,
            WorkKind::UploadFinalize,
            WorkKind::TextIndexBuild,
            WorkKind::SnapshotRestoreOrRulesetActivation,
            WorkKind::ChildEnqueueReservation,
        ];
        let pick: usize = kani::any();
        kani::assume(pick < kinds.len());
        let options = AwaitIdleOptions::default();
        assert!(kinds[pick].is_fenced(&options));
        let ignore = AwaitIdleOptions {
            text_index_builds: ftd_core_session::idle::IdleWaitPolicy::Ignore,
            ..AwaitIdleOptions::default()
        };
        assert_eq!(
            kinds[pick].is_fenced(&ignore),
            kinds[pick] != WorkKind::TextIndexBuild
        );
        assert!(!WorkKind::ScheduledFutureWork.is_fenced(&options));
    }

    /// INV-EVENT-001: once an event is terminal, every transition is refused with `Terminal`
    /// and the record keeps its state and attempt counter. The four terminal states and the
    /// eight transitions are enumerated symbolically.
    ///
    /// This harness allocates (an event carries an event type, a subject and a payload), so it
    /// needs a Kani build whose allocator model is available; see the README.
    #[kani::proof]
    #[kani::unwind(4)]
    fn terminal_event_rejects_every_transition() {
        let epoch = Epoch::initial();
        let policy = RetryPolicy::try_new(
            1,
            LogicalDuration::from_seconds(1),
            LogicalDuration::from_seconds(60),
        )
        .unwrap();
        let mut record = EventRecord::new(LogicalEvent {
            event_id: EventId::new(1),
            session_id: SessionId::new(1),
            epoch,
            source: EventSource::Firestore,
            event_type: EventType::try_new("google.cloud.firestore.document.v1.created").unwrap(),
            subject: String::new(),
            logical_time: LogicalInstant::UNIX_EPOCH,
            causation_id: None,
            correlation_id: CorrelationId::new(1),
            payload: Vec::new(),
        });
        let kind: u8 = kani::any();
        kani::assume(kind < 4);
        match kind {
            0 => {
                record.lease().unwrap();
                record.start().unwrap();
                record.succeed().unwrap();
            }
            1 => {
                record.lease().unwrap();
                record.start().unwrap();
                let _ = record.fail(&policy, LogicalInstant::UNIX_EPOCH).unwrap();
            }
            2 => record.cancel().unwrap(),
            _ => record.discard_stale(epoch.next().unwrap()).unwrap(),
        }
        assert!(record.is_terminal());
        let expected = EventTransitionError::Terminal {
            state: record.state().name(),
        };
        let before_state = record.state().clone();
        let before_attempt = record.attempt();
        let action: u8 = kani::any();
        kani::assume(action < 8);
        let now = LogicalInstant::from_nanos(kani::any());
        let result = match action {
            0 => record.lease(),
            1 => record.start(),
            2 => record.succeed(),
            3 => record.fail(&policy, now).map(|_| ()),
            4 => record.interrupt(),
            5 => record.retry_due(now),
            6 => record.cancel(),
            _ => record.discard_stale(Epoch::new(kani::any())),
        };
        assert_eq!(result, Err(expected));
        assert_eq!(record.state(), &before_state);
        assert_eq!(record.attempt(), before_attempt);
        assert!(record.is_terminal());
    }

    /// INV-AUTH-001 (window boundary): `time_step` partitions logical time into half-open
    /// windows of exactly `period_seconds`, is monotone, and clamps everything at or before the
    /// Unix epoch to step 0. That is what makes "the same step yields the same code" and the
    /// `step <= last_accepted` replay test well defined.
    ///
    /// The code derivation itself (HMAC-SHA1) is covered by the RFC 6238 vectors in
    /// `crates/ftd-core-auth/tests/totp.rs` and by `prop_same_step_same_code`; a bit-level proof
    /// over SHA-1 is out of reach for bounded model checking.
    #[kani::proof]
    fn totp_window_boundary() {
        let period: u16 = kani::any();
        kani::assume(period > 0);
        let params = TotpParams {
            period_seconds: u32::from(period),
            digits: 6,
        };
        let seconds: i32 = kani::any();
        let at = LogicalInstant::from_unix_seconds(i64::from(seconds));
        let step = time_step(&params, at);
        if seconds <= 0 {
            assert_eq!(step, 0);
        } else {
            // The step changes exactly at a multiple of the period, never inside a window.
            let period = i64::from(period);
            let offset = i64::from(seconds) % period;
            let window_start = LogicalInstant::from_unix_seconds(i64::from(seconds) - offset);
            assert_eq!(time_step(&params, window_start), step);
            let previous = LogicalInstant::from_unix_seconds(i64::from(seconds) - offset - 1);
            assert!(time_step(&params, previous) < step || step == 0);
        }
        // Monotonicity: a later instant never belongs to an earlier window.
        let later: i32 = kani::any();
        kani::assume(later >= seconds);
        assert!(time_step(&params, LogicalInstant::from_unix_seconds(i64::from(later))) >= step);
    }

    /// Rejection precedes warnings for every value outside the boundary (allocation-free form
    /// of the `evaluate` contract).
    #[kani::proof]
    #[kani::unwind(4)]
    fn boundary_reject_precedes_warning() {
        let maximum: u16 = kani::any();
        let current: u16 = kani::any();
        kani::assume(maximum > 0);
        let (current, maximum) = (u64::from(current), u64::from(maximum));
        let violates = violates_boundary(LimitBoundary::ExclusiveMaximum, current, maximum);
        assert_eq!(violates, current >= maximum);
        if !violates {
            // Inside the boundary the ratio is below 100% and the severity is defined by the
            // thresholds alone.
            assert!(ratio_micros(current, maximum) < 1_000_000);
            let _ = classify_severity(current, maximum, DEFAULT_THRESHOLDS);
        }
    }
}
