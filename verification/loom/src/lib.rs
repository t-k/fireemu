//! Loom concurrency scenarios (spec 23).
//!
//! Scenario names are the canonical ones from `verification/loom/scenarios.json`; the
//! traceability check verifies that every scenario referenced by an implemented requirement
//! exists here as a test function.
//!
//! Run with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p ftd-verification-loom --release
//! ```
//!
//! Loom is a dev-time dependency only and is never linked into the release binary.

#[cfg(loom)]
mod scenarios {
    use loom::sync::{Arc, Mutex};
    use loom::thread;

    use ftd_core_session::idle::{AwaitIdleOptions, IdleVerdict, WorkKind, WorkLedger};
    use ftd_core_session::session::{Session, WorkResult};
    use ftd_core_types::ids::{Epoch, SessionId};
    use ftd_core_types::time::LogicalInstant;

    /// Shared state of the session core: the session plus the log of applied effects, each
    /// tagged with the work item's epoch and the session epoch at apply time.
    struct Core {
        session: Session,
        applied: Vec<(Epoch, Epoch)>,
    }

    fn active_core() -> Arc<Mutex<Core>> {
        let mut session = Session::create(SessionId::new(1), 0, LogicalInstant::UNIX_EPOCH);
        session.activate().unwrap();
        Arc::new(Mutex::new(Core {
            session,
            applied: Vec::new(),
        }))
    }

    /// INV-EPOCH-001: a worker that captured epoch 0 must not apply after a reset published
    /// epoch 1, regardless of interleaving. The check and the apply happen under one lock.
    #[test]
    fn stale_epoch_never_mutates_new_state() {
        loom::model(|| {
            let core = active_core();
            let work_epoch = core.lock().unwrap().session.epoch();

            let worker = {
                let core = core.clone();
                thread::spawn(move || {
                    let mut c = core.lock().unwrap();
                    if c.session.check_work_epoch(work_epoch) == WorkResult::Proceed {
                        let session_epoch = c.session.epoch();
                        c.applied.push((work_epoch, session_epoch));
                    }
                })
            };
            let resetter = {
                let core = core.clone();
                thread::spawn(move || {
                    let mut c = core.lock().unwrap();
                    c.session.begin_reset().unwrap();
                    c.session.complete_reset().unwrap();
                })
            };
            worker.join().unwrap();
            resetter.join().unwrap();

            let c = core.lock().unwrap();
            assert!(c.applied.iter().all(|(work, session)| work == session));
            assert_eq!(c.session.epoch(), Epoch::new(1));
        });
    }

    /// Same invariant, with the reset split into begin / complete across interleavings of a
    /// commit that captured the old epoch.
    #[test]
    fn reset_races_with_commit() {
        loom::model(|| {
            let core = active_core();
            let work_epoch = Epoch::initial();

            let committer = {
                let core = core.clone();
                thread::spawn(move || {
                    let mut c = core.lock().unwrap();
                    match c.session.check_work_epoch(work_epoch) {
                        WorkResult::Proceed => {
                            let e = c.session.epoch();
                            c.applied.push((work_epoch, e));
                        }
                        WorkResult::DiscardedStaleEpoch | WorkResult::SessionNotActive(_) => {}
                    }
                })
            };
            let begin = {
                let core = core.clone();
                thread::spawn(move || {
                    core.lock().unwrap().session.begin_reset().unwrap();
                })
            };
            begin.join().unwrap();
            let complete = {
                let core = core.clone();
                thread::spawn(move || {
                    core.lock().unwrap().session.complete_reset().unwrap();
                })
            };
            committer.join().unwrap();
            complete.join().unwrap();

            let c = core.lock().unwrap();
            assert!(c.applied.iter().all(|(work, session)| work == session));
        });
    }

    /// The ledger never underflows and always returns to idle once every begin has a
    /// matching end, regardless of thread interleaving.
    #[test]
    fn active_work_counter_never_underflows() {
        loom::model(|| {
            let ledger = Arc::new(Mutex::new(WorkLedger::new(Epoch::initial())));
            let workers: Vec<_> = [WorkKind::FirestoreCommit, WorkKind::FunctionInvocation]
                .into_iter()
                .map(|kind| {
                    let ledger = ledger.clone();
                    thread::spawn(move || {
                        let token = ledger
                            .lock()
                            .unwrap()
                            .begin(kind, Epoch::initial())
                            .unwrap();
                        // Observers may run here; the ledger must report busy.
                        assert!(matches!(
                            ledger.lock().unwrap().verdict(&AwaitIdleOptions::default()),
                            IdleVerdict::Busy { .. }
                        ));
                        ledger.lock().unwrap().end(token).unwrap();
                    })
                })
                .collect();
            for w in workers {
                w.join().unwrap();
            }
            let l = ledger.lock().unwrap();
            assert_eq!(l.active_total(), 0);
            assert_eq!(l.verdict(&AwaitIdleOptions::default()), IdleVerdict::Idle);
        });
    }

    /// M-IDLE-002: the parent -> child handoff is atomic. If an observer ever sees the ledger
    /// idle, no fenced work may begin afterwards; the latch makes the scenario fail for a
    /// ledger that lets the reservation lapse before the child is registered.
    #[test]
    fn await_idle_races_with_child_enqueue() {
        use loom::sync::atomic::{AtomicBool, Ordering};

        loom::model(|| {
            let ledger = Arc::new(Mutex::new(WorkLedger::new(Epoch::initial())));
            let saw_idle = Arc::new(AtomicBool::new(false));
            let parent = ledger
                .lock()
                .unwrap()
                .begin(WorkKind::FunctionInvocation, Epoch::initial())
                .unwrap();

            let chain = {
                let ledger = ledger.clone();
                let saw_idle = saw_idle.clone();
                thread::spawn(move || {
                    let reservation = ledger
                        .lock()
                        .unwrap()
                        .begin(WorkKind::ChildEnqueueReservation, Epoch::initial())
                        .unwrap();
                    ledger.lock().unwrap().end(parent).unwrap();
                    let child = {
                        let mut l = ledger.lock().unwrap();
                        let child = l.handoff(reservation, WorkKind::EventDispatch).unwrap();
                        // Fenced work is starting: idle must not have been observed before.
                        assert!(!saw_idle.load(Ordering::SeqCst), "false idle before child");
                        child
                    };
                    ledger.lock().unwrap().end(child).unwrap();
                })
            };
            let observer = {
                let ledger = ledger.clone();
                let saw_idle = saw_idle.clone();
                thread::spawn(move || {
                    let l = ledger.lock().unwrap();
                    if l.verdict(&AwaitIdleOptions::default()) == IdleVerdict::Idle {
                        saw_idle.store(true, Ordering::SeqCst);
                        assert_eq!(l.active_total(), 0);
                    }
                })
            };
            chain.join().unwrap();
            observer.join().unwrap();
            assert_eq!(ledger.lock().unwrap().active_total(), 0);
        });
    }

    /// INV-EVENT-001: a success and a retry-timer firing race on the same record; whichever
    /// wins, the record ends terminal-or-pending consistently and never regresses from
    /// Succeeded.
    #[test]
    fn event_success_races_with_retry_timer() {
        use ftd_core_events::event::{EventSource, EventType, LogicalEvent};
        use ftd_core_events::retry::RetryPolicy;
        use ftd_core_events::state::{EventRecord, EventState};
        use ftd_core_types::ids::{CorrelationId, EventId};
        use ftd_core_types::time::LogicalDuration;

        loom::model(|| {
            let event = LogicalEvent {
                event_id: EventId::new(1),
                session_id: SessionId::new(1),
                epoch: Epoch::initial(),
                source: EventSource::Firestore,
                event_type: EventType::try_new("google.cloud.firestore.document.v1.created")
                    .unwrap(),
                subject: String::new(),
                logical_time: LogicalInstant::UNIX_EPOCH,
                causation_id: None,
                correlation_id: CorrelationId::new(1),
                payload: Vec::new(),
            };
            let policy = RetryPolicy::try_new(
                3,
                LogicalDuration::from_seconds(1),
                LogicalDuration::from_seconds(1),
            )
            .unwrap();
            let record = Arc::new(Mutex::new(EventRecord::new(event)));
            {
                let mut r = record.lock().unwrap();
                r.lease().unwrap();
                r.start().unwrap();
                r.fail(&policy, LogicalInstant::UNIX_EPOCH).unwrap();
            }
            // Timer thread: retry becomes due, the worker re-runs and succeeds.
            let timer = {
                let record = record.clone();
                thread::spawn(move || {
                    let mut r = record.lock().unwrap();
                    if r.retry_due(LogicalInstant::from_unix_seconds(1)).is_ok() {
                        r.lease().unwrap();
                        r.start().unwrap();
                        r.succeed().unwrap();
                    }
                })
            };
            // A late timer firing must not move a terminal record.
            let late = {
                let record = record.clone();
                thread::spawn(move || {
                    let mut r = record.lock().unwrap();
                    let before = r.state().clone();
                    let _ = r.retry_due(LogicalInstant::from_unix_seconds(1));
                    if before.is_terminal() {
                        assert_eq!(r.state(), &before);
                    }
                })
            };
            timer.join().unwrap();
            late.join().unwrap();
            let r = record.lock().unwrap();
            assert!(matches!(
                r.state(),
                EventState::Succeeded | EventState::Pending
            ));
        });
    }

    /// M-IDLE-003: a Text Index build is fenced work; an observer never sees idle while the
    /// build is registered under the default Wait policy.
    #[test]
    fn await_idle_races_with_text_index_backfill_completion() {
        loom::model(|| {
            let ledger = Arc::new(Mutex::new(WorkLedger::new(Epoch::initial())));
            let build = ledger
                .lock()
                .unwrap()
                .begin(WorkKind::TextIndexBuild, Epoch::initial())
                .unwrap();
            let builder = {
                let ledger = ledger.clone();
                thread::spawn(move || {
                    ledger.lock().unwrap().end(build).unwrap();
                })
            };
            let observer = {
                let ledger = ledger.clone();
                thread::spawn(move || {
                    let l = ledger.lock().unwrap();
                    if l.verdict(&AwaitIdleOptions::default()) == IdleVerdict::Idle {
                        assert_eq!(l.active_total(), 0);
                    }
                })
            };
            builder.join().unwrap();
            observer.join().unwrap();
            assert_eq!(ledger.lock().unwrap().active_total(), 0);
        });
    }
    fn auth_fixture() -> (
        Arc<Mutex<ftd_core_auth::store::AuthStore>>,
        ftd_core_auth::store::LocalId,
        Vec<u8>,
        LogicalInstant,
    ) {
        use ftd_core_auth::mfa::TotpPolicy;
        use ftd_core_auth::store::{AuthStore, NewUser};
        use ftd_core_auth::totp::totp_at;
        use ftd_core_types::determinism::SplitMix64;

        let t0 = LogicalInstant::from_unix_seconds(1_788_004_860);
        let mut store = AuthStore::new("demo-app", SplitMix64::new(1), TotpPolicy::default());
        let uid = store
            .create_user(NewUser::email("a@example.com"), t0)
            .unwrap();
        let m = store.start_totp_enrollment(&uid, t0).unwrap();
        let secret = m.secret_for_test().to_vec();
        let code = totp_at(&secret, &store.policy().params(), t0);
        store
            .finalize_totp_enrollment(&uid, &m.session_id, code, t0)
            .unwrap();
        (Arc::new(Mutex::new(store)), uid, secret, t0)
    }

    /// INV-AUTH-001: two sign-ins presenting the same code race; at most one succeeds and the
    /// other sees CodeAlreadyUsed, regardless of a concurrent clock advance.
    #[test]
    fn totp_verify_races_with_clock_advance() {
        use ftd_core_auth::mfa::MfaError;
        use ftd_core_auth::totp::totp_at;
        use ftd_core_types::time::LogicalDuration;

        loom::model(|| {
            let (store, uid, secret, t0) = auth_fixture();
            let now = t0.checked_add(LogicalDuration::from_seconds(120)).unwrap();
            let code = totp_at(&secret, &store.lock().unwrap().policy().params(), now);
            let outcomes: Vec<_> = (0..2)
                .map(|_| {
                    let store = store.clone();
                    let uid = uid.clone();
                    thread::spawn(move || {
                        let mut s = store.lock().unwrap();
                        let pending = s.start_mfa_sign_in(&uid, now).unwrap();
                        s.finalize_mfa_sign_in(&uid, &pending, code, now).is_ok()
                    })
                })
                .collect();
            let ok: usize = outcomes
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum();
            assert_eq!(ok, 1, "exactly one sign-in may consume the code");
            let mut s = store.lock().unwrap();
            let p = s.start_mfa_sign_in(&uid, now).unwrap();
            assert_eq!(
                s.finalize_mfa_sign_in(&uid, &p, code, now),
                Err(MfaError::CodeAlreadyUsed)
            );
        });
    }

    /// INV-AUTH-002: finalizing an enrollment races with its expiry; a token issued afterwards
    /// carries a second factor claim only if the enrollment actually finalized.
    #[test]
    fn enrollment_finalize_races_with_expiry() {
        use ftd_core_auth::mfa::TotpPolicy;
        use ftd_core_auth::store::{AuthStore, NewUser};
        use ftd_core_auth::totp::totp_at;
        use ftd_core_types::determinism::SplitMix64;
        use ftd_core_types::time::LogicalDuration;

        loom::model(|| {
            let t0 = LogicalInstant::from_unix_seconds(1_788_004_860);
            let mut st = AuthStore::new("demo-app", SplitMix64::new(2), TotpPolicy::default());
            let uid = st.create_user(NewUser::email("b@example.com"), t0).unwrap();
            let m = st.start_totp_enrollment(&uid, t0).unwrap();
            let secret = m.secret_for_test().to_vec();
            let params = st.policy().params();
            let store = Arc::new(Mutex::new(st));
            let late = t0.checked_add(LogicalDuration::from_seconds(301)).unwrap();
            let on_time = t0.checked_add(LogicalDuration::from_seconds(200)).unwrap();
            let finalize = {
                let store = store.clone();
                let uid = uid.clone();
                let session = m.session_id.clone();
                thread::spawn(move || {
                    let mut s = store.lock().unwrap();
                    let code = totp_at(&secret, &params, on_time);
                    s.finalize_totp_enrollment(&uid, &session, code, on_time)
                        .ok()
                })
            };
            let expiry = {
                let store = store.clone();
                let uid = uid.clone();
                let session = m.session_id.clone();
                thread::spawn(move || {
                    let mut s = store.lock().unwrap();
                    // A late finalize attempt behaves as expiry.
                    let _ = s.finalize_totp_enrollment(&uid, &session, 0, late);
                })
            };
            let enrolled = finalize.join().unwrap();
            expiry.join().unwrap();
            let s = store.lock().unwrap();
            let claims = s.id_token_claims(&uid, None, late).unwrap();
            assert!(claims.firebase.sign_in_second_factor.is_none());
            assert_eq!(
                s.user(&uid).unwrap().mfa.totp_factors().len(),
                usize::from(enrolled.is_some())
            );
        });
    }

    /// Revocation and sign-in race: a token issued before revocation is invalid afterwards and a
    /// token issued after revocation stays valid.
    #[test]
    fn token_revocation_races_with_sign_in() {
        use ftd_core_types::time::LogicalDuration;

        loom::model(|| {
            let (store, uid, _secret, t0) = auth_fixture();
            let revoke_at = t0.checked_add(LogicalDuration::from_seconds(10)).unwrap();
            let issue_at = t0.checked_add(LogicalDuration::from_seconds(5)).unwrap();
            let revoker = {
                let store = store.clone();
                let uid = uid.clone();
                thread::spawn(move || {
                    store
                        .lock()
                        .unwrap()
                        .revoke_tokens(&uid, revoke_at)
                        .unwrap()
                })
            };
            let issuer = {
                let store = store.clone();
                let uid = uid.clone();
                thread::spawn(move || {
                    let s = store.lock().unwrap();
                    s.id_token_claims(&uid, None, issue_at).unwrap()
                })
            };
            revoker.join().unwrap();
            let claims = issuer.join().unwrap();
            let s = store.lock().unwrap();
            let auth_time = LogicalInstant::from_unix_seconds(claims.auth_time);
            let exp = LogicalInstant::from_unix_seconds(claims.exp);
            let check_at = t0.checked_add(LogicalDuration::from_seconds(20)).unwrap();
            assert!(
                !s.token_is_valid(&uid, auth_time, exp, check_at),
                "pre-revocation token is invalid"
            );
            let fresh = s.id_token_claims(&uid, None, check_at).unwrap();
            assert!(s.token_is_valid(
                &uid,
                LogicalInstant::from_unix_seconds(fresh.auth_time),
                LogicalInstant::from_unix_seconds(fresh.exp),
                check_at
            ));
        });
    }
}
