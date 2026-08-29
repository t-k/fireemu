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

    /// M-IDLE-002: with the reservation held across the parent's completion, an observer can
    /// never see idle between the parent's end and the child's begin.
    #[test]
    fn await_idle_races_with_child_enqueue() {
        loom::model(|| {
            let ledger = Arc::new(Mutex::new(WorkLedger::new(Epoch::initial())));
            let parent = ledger
                .lock()
                .unwrap()
                .begin(WorkKind::FunctionInvocation, Epoch::initial())
                .unwrap();

            let chain = {
                let ledger = ledger.clone();
                thread::spawn(move || {
                    let reservation = ledger
                        .lock()
                        .unwrap()
                        .begin(WorkKind::ChildEnqueueReservation, Epoch::initial())
                        .unwrap();
                    ledger.lock().unwrap().end(parent).unwrap();
                    let child = ledger
                        .lock()
                        .unwrap()
                        .begin(WorkKind::EventDispatch, Epoch::initial())
                        .unwrap();
                    ledger.lock().unwrap().end(reservation).unwrap();
                    ledger.lock().unwrap().end(child).unwrap();
                })
            };
            let observer = {
                let ledger = ledger.clone();
                thread::spawn(move || {
                    let l = ledger.lock().unwrap();
                    let verdict = l.verdict(&AwaitIdleOptions::default());
                    // Idle is only acceptable once nothing at all is registered.
                    if verdict == IdleVerdict::Idle {
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
            let policy = RetryPolicy {
                max_attempts: 3,
                base_backoff: LogicalDuration::from_seconds(1),
                max_backoff: LogicalDuration::from_seconds(1),
            };
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
}
