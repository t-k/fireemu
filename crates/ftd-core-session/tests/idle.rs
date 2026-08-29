//! Idle fence: `await-idle` must never report idle while causal work is active
//! (INV-IDLE-001), and the ledger never underflows.

use ftd_core_session::idle::{
    AwaitIdleOptions, IdleLedgerError, IdleVerdict, IdleWaitPolicy, WorkKind, WorkLedger,
};
use ftd_core_types::ids::Epoch;
use ftd_core_types::time::LogicalDuration;

fn opts() -> AwaitIdleOptions {
    AwaitIdleOptions {
        include_scheduled_future_work: false,
        text_index_builds: IdleWaitPolicy::Wait,
        timeout: LogicalDuration::from_seconds(30),
    }
}

#[test]
fn empty_ledger_is_idle() {
    let ledger = WorkLedger::new(Epoch::initial());
    assert_eq!(ledger.verdict(&opts()), IdleVerdict::Idle);
}

#[test]
fn any_active_work_blocks_idle_until_ended() {
    let mut ledger = WorkLedger::new(Epoch::initial());
    let commit = ledger
        .begin(WorkKind::FirestoreCommit, Epoch::initial())
        .unwrap();
    let invocation = ledger
        .begin(WorkKind::FunctionInvocation, Epoch::initial())
        .unwrap();
    match ledger.verdict(&opts()) {
        IdleVerdict::Busy { blocking } => {
            assert_eq!(
                blocking,
                vec![
                    (WorkKind::FirestoreCommit, 1),
                    (WorkKind::FunctionInvocation, 1)
                ]
            );
        }
        IdleVerdict::Idle => panic!("must not be idle"),
    }
    ledger.end(commit).unwrap();
    assert!(matches!(ledger.verdict(&opts()), IdleVerdict::Busy { .. }));
    ledger.end(invocation).unwrap();
    assert_eq!(ledger.verdict(&opts()), IdleVerdict::Idle);
}

#[test]
fn child_enqueue_reservation_counts_as_work() {
    // M-IDLE-002: the fence must not complete between parent completion and child enqueue.
    let mut ledger = WorkLedger::new(Epoch::initial());
    let parent = ledger
        .begin(WorkKind::FunctionInvocation, Epoch::initial())
        .unwrap();
    let reservation = ledger
        .begin(WorkKind::ChildEnqueueReservation, Epoch::initial())
        .unwrap();
    ledger.end(parent).unwrap();
    assert!(matches!(ledger.verdict(&opts()), IdleVerdict::Busy { .. }));
    let child = ledger
        .begin(WorkKind::EventDispatch, Epoch::initial())
        .unwrap();
    ledger.end(reservation).unwrap();
    assert!(matches!(ledger.verdict(&opts()), IdleVerdict::Busy { .. }));
    ledger.end(child).unwrap();
    assert_eq!(ledger.verdict(&opts()), IdleVerdict::Idle);
}

#[test]
fn text_index_builds_block_by_default_and_can_be_ignored_explicitly() {
    // M-IDLE-003: text index backfill is causal work.
    let mut ledger = WorkLedger::new(Epoch::initial());
    let _build = ledger
        .begin(WorkKind::TextIndexBuild, Epoch::initial())
        .unwrap();
    assert!(matches!(ledger.verdict(&opts()), IdleVerdict::Busy { .. }));
    let ignore = AwaitIdleOptions {
        text_index_builds: IdleWaitPolicy::Ignore,
        ..opts()
    };
    assert_eq!(ledger.verdict(&ignore), IdleVerdict::Idle);
}

#[test]
fn scheduled_future_work_is_only_counted_when_requested() {
    let mut ledger = WorkLedger::new(Epoch::initial());
    let _future = ledger
        .begin(WorkKind::ScheduledFutureWork, Epoch::initial())
        .unwrap();
    assert_eq!(ledger.verdict(&opts()), IdleVerdict::Idle);
    let include = AwaitIdleOptions {
        include_scheduled_future_work: true,
        ..opts()
    };
    assert!(matches!(ledger.verdict(&include), IdleVerdict::Busy { .. }));
}

#[test]
fn ending_twice_or_ending_unknown_token_is_an_error_not_underflow() {
    let mut ledger = WorkLedger::new(Epoch::initial());
    let t = ledger
        .begin(WorkKind::EventDispatch, Epoch::initial())
        .unwrap();
    ledger.end(t).unwrap();
    assert_eq!(ledger.end(t), Err(IdleLedgerError::UnknownToken(t)));
    assert_eq!(ledger.active_total(), 0);
}

#[test]
fn stale_epoch_work_cannot_be_registered_and_reset_drops_old_work() {
    let mut ledger = WorkLedger::new(Epoch::initial());
    let _old = ledger
        .begin(WorkKind::EventDispatch, Epoch::initial())
        .unwrap();
    let new_epoch = Epoch::new(1);
    ledger.reset(new_epoch);
    assert_eq!(ledger.verdict(&opts()), IdleVerdict::Idle);
    assert_eq!(
        ledger.begin(WorkKind::EventDispatch, Epoch::initial()),
        Err(IdleLedgerError::StaleEpoch {
            current: new_epoch,
            requested: Epoch::initial()
        })
    );
}
