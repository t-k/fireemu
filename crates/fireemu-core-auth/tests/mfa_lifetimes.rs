//! Separate lifetimes of the transient credentials one account can hold at once (TP-AUTH-D-02).
//!
//! Five objects live on the virtual clock, each in its own registry with its own TTL:
//!
//! | object                          | TTL (s)          | last valid age | registry              |
//! |---------------------------------|------------------|----------------|-----------------------|
//! | email action code (OOB)         | 3600             | age <= 3600    | `oob_codes`           |
//! | phone verification code (SMS)   | 600              | age <= 600     | `verification_codes`  |
//! | pending second-factor sign-in   | 3600 (declared)  | age <= 3600    | `pending_sign_ins`    |
//! | TOTP enrollment session         | 300 (+300 grace) | age <= 300     | `pending_enrollments` |
//! | `IdP` continuation (`pendingToken`) | 300           | age < 300      | `PendingIdpCache`     |
//!
//! The matrix crosses each lifetime alone, with every other object created late enough to be
//! inside its own lifetime at the check instant, and asserts that only the crossed object is
//! refused. This is the "separate state machines" proof asked for by the mission's section
//! 11: no common TTL is inferred from any pair of these numbers.
//!
//! The pending sign-in lifetime of 3600 s is a declared local policy, not a production value:
//! production refused a pending credential at 600 s once (GAP-AUTH-007) after surviving 300 s
//! once (GAP-AUTH-006). The tests assert the declared local constant and claim no production
//! TTL. The virtual clock is not production time.

use std::sync::{Arc, Barrier, Mutex};

use fireemu_core_auth::federation::PENDING_IDP_TTL_SECONDS;
use fireemu_core_auth::mfa::{MfaError, TotpPolicy};
use fireemu_core_auth::store::{
    AuthError, AuthStore, LocalId, NewUser, OobRequestType, PendingSignInId, VerificationPurpose,
    OOB_CODE_TTL_SECONDS, PENDING_SIGN_IN_TTL_SECONDS, SMS_CODE_TTL_SECONDS,
};
use fireemu_core_auth::totp::totp_at;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};

const EMAIL: &str = "lifetimes@example.com";
const PHONE: &str = "+15559876543";
const IDP_AUTHORITY: &str = "fixture-idp-v1";
const IDP_ASSERTION: &str = "ASSERTION";

fn t0() -> LogicalInstant {
    LogicalInstant::from_unix_seconds(1_788_004_860)
}

fn at(offset_seconds: i64) -> LogicalInstant {
    t0().checked_add(LogicalDuration::from_seconds(offset_seconds))
        .unwrap()
}

fn store() -> AuthStore {
    AuthStore::new("demo-app", SplitMix64::new(7), TotpPolicy::default())
}

fn enrollment_ttl_seconds() -> i64 {
    i64::try_from(TotpPolicy::default().enrollment_session_ttl.as_seconds()).unwrap()
}

/// An email/password account with a verified email and one enrolled phone factor, so that
/// every object of the matrix can be created on it. Returns the uid and the phone factor id.
fn account(s: &mut AuthStore) -> (LocalId, String) {
    let uid = s.create_user(NewUser::email(EMAIL), t0()).unwrap();
    s.user_mut(&uid).unwrap().email_verified = true;
    let phone = s.enroll_phone_factor(&uid, PHONE, None, t0()).unwrap();
    (uid, phone.mfa_enrollment_id)
}

/// The objects of the matrix, in the order the table above lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Object {
    Oob,
    Sms,
    Pending,
    TotpEnrollment,
    PendingToken,
}

impl Object {
    const ALL: [Self; 5] = [
        Self::Oob,
        Self::Sms,
        Self::Pending,
        Self::TotpEnrollment,
        Self::PendingToken,
    ];

    /// Largest age (seconds) at which the object is still usable.
    fn last_valid_age(self) -> i64 {
        match self {
            Self::Oob => OOB_CODE_TTL_SECONDS,
            Self::Sms => SMS_CODE_TTL_SECONDS,
            Self::Pending => PENDING_SIGN_IN_TTL_SECONDS,
            Self::TotpEnrollment => enrollment_ttl_seconds(),
            // The continuation cache is half-open: the handle is gone at exactly its TTL.
            Self::PendingToken => PENDING_IDP_TTL_SECONDS - 1,
        }
    }
}

/// Everything the matrix creates on one account. The SMS code is bound to its own pending
/// credential (`sms_pending`), separate from the bare pending credential the `Pending` row
/// expires, so the other pending credential and its code stay observable after the crossed
/// one is gone.
#[derive(Default)]
struct Objects {
    oob: String,
    sms_pending: Option<PendingSignInId>,
    sms_session: String,
    sms_code: String,
    pending: Option<PendingSignInId>,
    enrollment_session: String,
    enrollment_secret: Vec<u8>,
    idp_token: String,
}

/// Creation offset (seconds after `t0`) of `other` in the row that crosses `crossed` at
/// `check_at`: an object that outlives the check instant is created at `t0`, every other one
/// at half its lifetime before the check, so at the check only the crossed object is expired.
fn creation_offset(crossed: Object, other: Object, check_at: i64) -> i64 {
    if other == crossed || other.last_valid_age() > check_at {
        0
    } else {
        check_at - other.last_valid_age() / 2
    }
}

fn create(
    s: &mut AuthStore,
    uid: &LocalId,
    phone_factor: &str,
    object: Object,
    now: LogicalInstant,
    into: &mut Objects,
) {
    // The adapter sweeps before every request and the store before every creation; the
    // explicit sweep keeps the store-level matrix on the same observation path.
    s.sweep_transient_credentials(now);
    match object {
        Object::Oob => {
            into.oob = s
                .create_oob_code(
                    OobRequestType::VerifyEmail,
                    EMAIL,
                    Some(uid.clone()),
                    None,
                    now,
                )
                .unwrap();
        }
        Object::Sms => {
            let pending = s.start_mfa_sign_in(uid, now).unwrap();
            let code = s
                .send_verification_code(
                    PHONE,
                    VerificationPurpose::MfaSignIn {
                        uid: uid.clone(),
                        pending: pending.clone(),
                        enrollment_id: phone_factor.to_owned(),
                    },
                    now,
                )
                .unwrap();
            into.sms_pending = Some(pending);
            into.sms_session = code.session_info;
            into.sms_code = code.code;
        }
        Object::Pending => into.pending = Some(s.start_mfa_sign_in(uid, now).unwrap()),
        Object::TotpEnrollment => {
            let material = s.start_totp_enrollment(uid, now).unwrap();
            into.enrollment_secret = material.secret_for_test().to_vec();
            into.enrollment_session = material.session_id;
        }
        Object::PendingToken => {
            into.idp_token = s
                .remember_idp_sign_in(IDP_ASSERTION.to_owned(), IDP_AUTHORITY.to_owned(), now)
                .unwrap();
        }
    }
}

/// Creates the five objects in creation-time order; returns them with the check offset.
fn build(s: &mut AuthStore, uid: &LocalId, phone_factor: &str, crossed: Object) -> (Objects, i64) {
    let check_at = crossed.last_valid_age() + 1;
    let mut schedule: Vec<(i64, Object)> = Object::ALL
        .iter()
        .map(|&o| (creation_offset(crossed, o, check_at), o))
        .collect();
    schedule.sort_by_key(|(offset, _)| *offset);
    let mut objects = Objects::default();
    for (offset, object) in schedule {
        create(s, uid, phone_factor, object, at(offset), &mut objects);
    }
    (objects, check_at)
}

#[test]
#[allow(clippy::too_many_lines)]
fn crossing_each_lifetime_alone_leaves_the_other_objects_usable() {
    for crossed in Object::ALL {
        let mut s = store();
        let (uid, phone_factor) = account(&mut s);
        let (objects, check_at) = build(&mut s, &uid, &phone_factor, crossed);
        let now = at(check_at);
        let users_before = s.user_count();
        let account_before = s.user(&uid).unwrap().clone();
        let sms_pending = objects.sms_pending.clone().unwrap();
        let pending = objects.pending.clone().unwrap();
        s.sweep_transient_credentials(now);

        // The crossed object is refused with its own typed error.
        match crossed {
            Object::Oob => {
                assert_eq!(
                    s.consume_oob_code(&objects.oob, Some(OobRequestType::VerifyEmail), now),
                    Err(AuthError::InvalidOobCode)
                );
                assert!(s.oob_code(&objects.oob).is_none());
            }
            Object::Sms => {
                assert_eq!(
                    s.check_phone_code(&objects.sms_session, &objects.sms_code, now),
                    Err(AuthError::InvalidSessionInfo)
                );
                // Its pending credential is a separate object and survives the code.
                assert_eq!(s.pending_sign_in_user(&sms_pending), Some(uid.clone()));
            }
            Object::Pending => {
                assert_eq!(s.pending_sign_in_user(&pending), None);
                assert_eq!(
                    s.finalize_phone_mfa_sign_in(&uid, &pending, &phone_factor, now),
                    Err(MfaError::PendingSignInUnknown)
                );
            }
            Object::TotpEnrollment => {
                // Inside the grace window the sweep keeps the expired session so that the
                // late finalize is answered SESSION_EXPIRED; that answer reaps it.
                assert_eq!(s.user(&uid).unwrap().mfa.pending_count(), 3);
                let code = totp_at(&objects.enrollment_secret, &s.policy().params(), now);
                assert_eq!(
                    s.finalize_totp_enrollment(&uid, &objects.enrollment_session, code, now),
                    Err(MfaError::EnrollmentSessionExpired)
                );
                assert_eq!(s.user(&uid).unwrap().mfa.pending_count(), 2);
                assert!(s.user(&uid).unwrap().mfa.totp_factors().is_empty());
            }
            Object::PendingToken => {
                assert_eq!(
                    s.pending_idp_sign_in(&objects.idp_token, IDP_AUTHORITY, now),
                    None
                );
            }
        }
        // A refusal mutates neither the account nor the population.
        assert_eq!(s.user_count(), users_before, "{crossed:?}");
        let refused = s.user(&uid).unwrap();
        assert_eq!(refused.last_sign_in_at, account_before.last_sign_in_at);
        assert_eq!(
            refused.mfa.phone_factors(),
            account_before.mfa.phone_factors()
        );
        assert_eq!(
            refused.mfa.totp_factors(),
            account_before.mfa.totp_factors()
        );

        // Every other object is still consumable at the same instant.
        if crossed != Object::Oob {
            let consumed = s
                .consume_oob_code(&objects.oob, Some(OobRequestType::VerifyEmail), now)
                .unwrap_or_else(|e| panic!("{crossed:?}: the oob code should be live: {e:?}"));
            assert_eq!(consumed.uid.as_ref(), Some(&uid));
        }
        if crossed != Object::Sms {
            let verified = s
                .check_phone_code(&objects.sms_session, &objects.sms_code, now)
                .unwrap_or_else(|e| panic!("{crossed:?}: the sms code should be live: {e:?}"));
            assert!(matches!(
                verified.purpose,
                VerificationPurpose::MfaSignIn { .. }
            ));
            let assertion = s
                .finalize_phone_mfa_sign_in(&uid, &sms_pending, &phone_factor, now)
                .unwrap();
            s.consume_phone_code(&objects.sms_session);
            assert_eq!(assertion.sign_in_second_factor, "phone");
        }
        if crossed != Object::Pending {
            assert_eq!(s.pending_sign_in_user(&pending), Some(uid.clone()));
            let assertion = s
                .finalize_phone_mfa_sign_in(&uid, &pending, &phone_factor, now)
                .unwrap_or_else(|e| panic!("{crossed:?}: the pending should be live: {e:?}"));
            assert_eq!(assertion.second_factor_identifier, phone_factor);
        }
        if crossed != Object::TotpEnrollment {
            let code = totp_at(&objects.enrollment_secret, &s.policy().params(), now);
            let factor = s
                .finalize_totp_enrollment(&uid, &objects.enrollment_session, code, now)
                .unwrap_or_else(|e| panic!("{crossed:?}: the enrollment should be live: {e:?}"));
            assert!(s
                .user(&uid)
                .unwrap()
                .mfa
                .has_factor(&factor.mfa_enrollment_id));
        }
        if crossed != Object::PendingToken {
            assert_eq!(
                s.pending_idp_sign_in(&objects.idp_token, IDP_AUTHORITY, now),
                Some(IDP_ASSERTION),
                "{crossed:?}: the continuation should be live"
            );
        }

        // Post-state: the crossed object and everything consumed above are gone, and only
        // the two registries with a documented retention (enrollment grace, reusable
        // continuation) still hold an entry.
        assert!(s.oob_codes().is_empty(), "{crossed:?}");
        assert!(s.verification_codes().is_empty(), "{crossed:?}");
        assert_eq!(
            s.pending_sign_in_count(),
            usize::from(crossed == Object::Sms),
            "{crossed:?}: the pending credential of an expired code survives it"
        );
        assert_eq!(
            s.user(&uid).unwrap().mfa.pending_count(),
            usize::from(crossed == Object::Sms),
            "{crossed:?}: the account holds nothing pending but the surviving credential"
        );
        assert_eq!(
            s.pending_idp_count(),
            usize::from(crossed != Object::PendingToken),
            "{crossed:?}: a live continuation is reusable, an expired one is swept"
        );
        assert_eq!(s.user_count(), users_before);

        // Fresh control: a new object of the crossed kind, issued after the expiry, works.
        fresh_control(&mut s, &uid, &phone_factor, crossed, &sms_pending, now);
    }
}

fn fresh_control(
    s: &mut AuthStore,
    uid: &LocalId,
    phone_factor: &str,
    crossed: Object,
    surviving_pending: &PendingSignInId,
    now: LogicalInstant,
) {
    match crossed {
        Object::Oob => {
            let code = s
                .create_oob_code(
                    OobRequestType::VerifyEmail,
                    EMAIL,
                    Some(uid.clone()),
                    None,
                    now,
                )
                .unwrap();
            assert!(s
                .consume_oob_code(&code, Some(OobRequestType::VerifyEmail), now)
                .is_ok());
        }
        Object::Sms | Object::Pending => {
            // An expired code is replaced on the pending credential that outlived it; an
            // expired pending credential is replaced by a fresh sign-in.
            let pending = if crossed == Object::Sms {
                surviving_pending.clone()
            } else {
                s.start_mfa_sign_in(uid, now).unwrap()
            };
            let code = s
                .send_verification_code(
                    PHONE,
                    VerificationPurpose::MfaSignIn {
                        uid: uid.clone(),
                        pending: pending.clone(),
                        enrollment_id: phone_factor.to_owned(),
                    },
                    now,
                )
                .unwrap();
            assert!(s
                .check_phone_code(&code.session_info, &code.code, now)
                .is_ok());
            assert!(s
                .finalize_phone_mfa_sign_in(uid, &pending, phone_factor, now)
                .is_ok());
            s.consume_phone_code(&code.session_info);
            assert_eq!(s.pending_sign_in_count(), 0);
            assert!(s.verification_codes().is_empty());
        }
        Object::TotpEnrollment => {
            let material = s.start_totp_enrollment(uid, now).unwrap();
            let code = totp_at(material.secret_for_test(), &s.policy().params(), now);
            assert!(s
                .finalize_totp_enrollment(uid, &material.session_id, code, now)
                .is_ok());
            assert_eq!(s.user(uid).unwrap().mfa.totp_factors().len(), 1);
        }
        Object::PendingToken => {
            let token = s
                .remember_idp_sign_in("ASSERTION-2".to_owned(), IDP_AUTHORITY.to_owned(), now)
                .unwrap();
            assert_eq!(
                s.pending_idp_sign_in(&token, IDP_AUTHORITY, now),
                Some("ASSERTION-2")
            );
        }
    }
}

/// Whether `object` is usable at `now`, checked without consuming it where the API allows
/// and by the consuming call otherwise (a consumed object is not needed afterwards).
fn usable(
    s: &mut AuthStore,
    uid: &LocalId,
    phone_factor: &str,
    objects: &Objects,
    object: Object,
    now: LogicalInstant,
) -> bool {
    s.sweep_transient_credentials(now);
    match object {
        Object::Oob => {
            s.oob_code(&objects.oob).is_some()
                && s.consume_oob_code(&objects.oob, Some(OobRequestType::VerifyEmail), now)
                    .is_ok()
        }
        Object::Sms => s
            .check_phone_code(&objects.sms_session, &objects.sms_code, now)
            .is_ok(),
        Object::Pending => s
            .finalize_phone_mfa_sign_in(uid, objects.pending.as_ref().unwrap(), phone_factor, now)
            .is_ok(),
        Object::TotpEnrollment => s
            .finalize_totp_enrollment(
                uid,
                &objects.enrollment_session,
                totp_at(&objects.enrollment_secret, &s.policy().params(), now),
                now,
            )
            .is_ok(),
        Object::PendingToken => s
            .pending_idp_sign_in(&objects.idp_token, IDP_AUTHORITY, now)
            .is_some(),
    }
}

#[test]
fn each_object_is_usable_at_its_last_valid_age_and_refused_one_second_later() {
    for object in Object::ALL {
        for (age, expected) in [
            (object.last_valid_age(), true),
            (object.last_valid_age() + 1, false),
        ] {
            let mut s = store();
            let (uid, phone_factor) = account(&mut s);
            let mut objects = Objects::default();
            create(&mut s, &uid, &phone_factor, object, t0(), &mut objects);
            assert_eq!(
                usable(&mut s, &uid, &phone_factor, &objects, object, at(age)),
                expected,
                "{object:?} at age {age}"
            );
        }
    }
}

#[test]
fn an_expired_enrollment_is_reaped_after_one_grace_window_and_a_fresh_one_still_enrolls() {
    let mut s = store();
    let (uid, _) = account(&mut s);
    let ttl = enrollment_ttl_seconds();
    let material = s.start_totp_enrollment(&uid, t0()).unwrap();
    let secret = material.secret_for_test().to_vec();
    let params = s.policy().params();

    // Inside the grace window the session is reported expired and is still held.
    let in_grace = at(2 * ttl);
    s.sweep_transient_credentials(in_grace);
    assert_eq!(s.user(&uid).unwrap().mfa.pending_count(), 1);
    assert_eq!(
        s.finalize_totp_enrollment(
            &uid,
            &material.session_id,
            totp_at(&secret, &params, in_grace),
            in_grace
        ),
        Err(MfaError::EnrollmentSessionExpired)
    );
    // The refusal reaps it; a later attempt no longer knows the session.
    assert_eq!(s.user(&uid).unwrap().mfa.pending_count(), 0);
    assert_eq!(
        s.finalize_totp_enrollment(
            &uid,
            &material.session_id,
            totp_at(&secret, &params, in_grace),
            in_grace
        ),
        Err(MfaError::EnrollmentSessionUnknown)
    );

    // Past the grace window the sweep alone reaps an untouched session.
    let second = s.start_totp_enrollment(&uid, in_grace).unwrap();
    let past_grace = in_grace
        .checked_add(LogicalDuration::from_seconds(2 * ttl + 1))
        .unwrap();
    s.sweep_transient_credentials(past_grace);
    assert_eq!(s.user(&uid).unwrap().mfa.pending_count(), 0);
    assert_eq!(
        s.finalize_totp_enrollment(
            &uid,
            &second.session_id,
            totp_at(second.secret_for_test(), &params, past_grace),
            past_grace
        ),
        Err(MfaError::EnrollmentSessionUnknown)
    );
    // A fresh session enrolls: no factor was created by any refusal above.
    assert!(s.user(&uid).unwrap().mfa.totp_factors().is_empty());
    let third = s.start_totp_enrollment(&uid, past_grace).unwrap();
    assert!(s
        .finalize_totp_enrollment(
            &uid,
            &third.session_id,
            totp_at(third.secret_for_test(), &params, past_grace),
            past_grace
        )
        .is_ok());
    assert_eq!(s.user(&uid).unwrap().mfa.totp_factors().len(), 1);
}

/// Enrolls a TOTP factor at `t0` and returns its id with the shared secret.
fn totp_account(s: &mut AuthStore) -> (LocalId, String, Vec<u8>) {
    let (uid, _) = account(s);
    let material = s.start_totp_enrollment(&uid, t0()).unwrap();
    let secret = material.secret_for_test().to_vec();
    let factor = s
        .finalize_totp_enrollment(
            &uid,
            &material.session_id,
            totp_at(&secret, &s.policy().params(), t0()),
            t0(),
        )
        .unwrap();
    (uid, factor.mfa_enrollment_id, secret)
}

#[test]
fn a_wrong_totp_code_leaves_the_session_intact_and_the_correct_code_then_succeeds() {
    let mut s = store();
    let (uid, factor, secret) = totp_account(&mut s);
    let params = s.policy().params();
    // One step past enrollment so the enrollment step is not the sign-in step.
    let now = at(30);
    let pending = s.start_mfa_sign_in(&uid, now).unwrap();
    let right = totp_at(&secret, &params, now);
    let wrong = (right + 1) % 1_000_000;
    let step_before = s.user(&uid).unwrap().mfa.totp_factors()[0].last_accepted_step;

    // Wrong: refused as INVALID_CODE, and nothing is consumed (pending, step, sign-in time).
    assert_eq!(
        s.finalize_mfa_sign_in_for_factor(&uid, &pending, &factor, wrong, now),
        Err(MfaError::InvalidCode)
    );
    assert_eq!(s.pending_sign_in_user(&pending), Some(uid.clone()));
    assert_eq!(s.pending_sign_in_count(), 1);
    assert_eq!(
        s.user(&uid).unwrap().mfa.totp_factors()[0].last_accepted_step,
        step_before
    );
    assert_eq!(s.user(&uid).unwrap().last_sign_in_at, None);

    // Correct, same session: accepted (the current runtime keeps the session usable after a
    // wrong attempt; there is no attempt counter).
    let assertion = s
        .finalize_mfa_sign_in_for_factor(&uid, &pending, &factor, right, now)
        .unwrap();
    assert_eq!(assertion.sign_in_second_factor, "totp");
    assert_eq!(s.pending_sign_in_count(), 0);
    assert_eq!(s.user(&uid).unwrap().last_sign_in_at, Some(now));
    assert!(s.user(&uid).unwrap().mfa.totp_factors()[0]
        .last_accepted_step
        .is_some());
}

#[test]
fn replaying_a_consumed_step_after_success_is_refused_for_both_factor_kinds() {
    let mut s = store();
    let (uid, factor, secret) = totp_account(&mut s);
    let phone_factor = s.user(&uid).unwrap().mfa.phone_factors()[0]
        .mfa_enrollment_id
        .clone();
    let params = s.policy().params();
    let now = at(30);

    // TOTP: the consumed pending credential is unknown, and a new pending credential with
    // the same code is refused as a replay (INV-AUTH-001).
    let pending = s.start_mfa_sign_in(&uid, now).unwrap();
    let code = totp_at(&secret, &params, now);
    s.finalize_mfa_sign_in_for_factor(&uid, &pending, &factor, code, now)
        .unwrap();
    assert_eq!(
        s.finalize_mfa_sign_in_for_factor(&uid, &pending, &factor, code, now),
        Err(MfaError::PendingSignInUnknown)
    );
    let next = s.start_mfa_sign_in(&uid, now).unwrap();
    assert_eq!(
        s.finalize_mfa_sign_in_for_factor(&uid, &next, &factor, code, now),
        Err(MfaError::CodeAlreadyUsed)
    );
    assert_eq!(s.pending_sign_in_user(&next), Some(uid.clone()));

    // Phone: the consumed code is unknown, and the consumed pending credential is unknown.
    let sms_code = s
        .send_verification_code(
            PHONE,
            VerificationPurpose::MfaSignIn {
                uid: uid.clone(),
                pending: next.clone(),
                enrollment_id: phone_factor.clone(),
            },
            now,
        )
        .unwrap();
    s.verify_phone_code(&sms_code.session_info, &sms_code.code, now)
        .unwrap();
    s.finalize_phone_mfa_sign_in(&uid, &next, &phone_factor, now)
        .unwrap();
    assert_eq!(
        s.check_phone_code(&sms_code.session_info, &sms_code.code, now),
        Err(AuthError::InvalidSessionInfo)
    );
    assert_eq!(
        s.finalize_phone_mfa_sign_in(&uid, &next, &phone_factor, now),
        Err(MfaError::PendingSignInUnknown)
    );
    assert_eq!(s.pending_sign_in_count(), 0);
    assert!(s.verification_codes().is_empty());
    assert_eq!(s.user(&uid).unwrap().mfa.factor_count(), 2);
}

#[test]
fn two_threads_finalizing_one_pending_credential_succeed_exactly_once() {
    let mut s = store();
    let (uid, factor, secret) = totp_account(&mut s);
    let params = s.policy().params();
    let now = at(30);
    let pending = s.start_mfa_sign_in(&uid, now).unwrap();
    let code = totp_at(&secret, &params, now);
    let factors_before = s.user(&uid).unwrap().mfa.factor_count();
    let shared = Arc::new(Mutex::new(s));
    let start = Arc::new(Barrier::new(2));

    let results: Vec<Result<String, MfaError>> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let shared = Arc::clone(&shared);
                let start = Arc::clone(&start);
                let (uid, pending, factor) = (uid.clone(), pending.clone(), factor.clone());
                scope.spawn(move || {
                    start.wait();
                    shared
                        .lock()
                        .unwrap()
                        .finalize_mfa_sign_in_for_factor(&uid, &pending, &factor, code, now)
                        .map(|a| a.second_factor_identifier)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let successes = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(successes, 1, "{results:?}");
    assert!(
        results.contains(&Err(MfaError::PendingSignInUnknown)),
        "the loser sees the consumed credential as unknown: {results:?}"
    );
    let s = shared.lock().unwrap();
    assert_eq!(s.pending_sign_in_count(), 0);
    assert_eq!(s.user(&uid).unwrap().mfa.pending_count(), 0);
    assert_eq!(s.user(&uid).unwrap().mfa.factor_count(), factors_before);
    assert_eq!(s.user(&uid).unwrap().last_sign_in_at, Some(now));
}
