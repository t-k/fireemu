//! Admission barrier: epochs advance with every reset and late admissions are refused.

use ftd_core_session::barrier::{AdmissionBarrier, ResetSince};

#[test]
fn every_reset_advances_the_epoch_and_admission_reports_it() {
    let barrier = AdmissionBarrier::new();
    assert_eq!(barrier.epoch(), 0);
    assert_eq!(barrier.admit().epoch(), 0);
    drop(barrier.exclusive());
    drop(barrier.exclusive());
    assert_eq!(barrier.epoch(), 2);
    assert_eq!(barrier.admit().epoch(), 2);
}

#[test]
fn a_request_that_started_before_a_reset_is_refused_after_it() {
    let barrier = AdmissionBarrier::new();
    let seen = barrier.epoch();
    assert!(barrier.admit_since(seen).is_ok());
    drop(barrier.exclusive());
    assert_eq!(barrier.admit_since(seen).err(), Some(ResetSince));
    assert!(barrier.admit_since(barrier.epoch()).is_ok());
    assert_eq!(
        ResetSince.to_string(),
        "the session was reset while the request was in flight"
    );
}
