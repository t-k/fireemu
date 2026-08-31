------------------------------ MODULE AuthTotp ------------------------------
(***************************************************************************)
(* TOTP second factor lifecycle (spec 12A.5).                              *)
(*                                                                         *)
(*   NotEnrolled -> EnrollmentStarted -> Enrolled                          *)
(*                       `-> Expired                                       *)
(*   Enrolled: Verify(step) accepted iff |step - clock| <= Window and      *)
(*             step > lastAccepted.                                        *)
(*                                                                         *)
(* Properties                                                              *)
(*   INV-AUTH-001  NoTotpCodeReuse                                         *)
(*   INV-AUTH-002  NoSecondFactorWithoutEnrollment                         *)
(*   LIVE-AUTH-001 EnrollmentEventuallyFinalizesOrExpires                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS MaxStep,      \* clock bound in time steps
          Window,       \* accepted steps before / after the clock
          SessionTtl    \* enrollment session lifetime in steps

VARIABLES clock,        \* current time step
          state,        \* "NotEnrolled" | "EnrollmentStarted" | "Enrolled" | "Expired"
          sessionEnd,   \* enrollment session expiry step
          lastAccepted, \* highest accepted step (-1 encoded as NoStep)
          accepted,     \* function step -> number of acceptances
          tokenSecond,  \* TRUE when a token with a second-factor claim was issued
          acceptedAt,   \* clock value of the latest accepted code
          enrollmentAcceptedAt \* clock value of the accepted enrollment

vars == <<clock, state, sessionEnd, lastAccepted, accepted, tokenSecond,
          acceptedAt, enrollmentAcceptedAt>>

NoStep == MaxStep + 1
NoTime == MaxStep + SessionTtl + 1
Steps == 0..MaxStep

TypeOK ==
    /\ clock \in Steps
    /\ state \in {"NotEnrolled", "EnrollmentStarted", "Enrolled", "Expired"}
    /\ sessionEnd \in 0..(MaxStep + SessionTtl)
    /\ lastAccepted \in Steps \cup {NoStep}
    /\ accepted \in [Steps -> 0..2]
    /\ tokenSecond \in BOOLEAN
    /\ acceptedAt \in Steps \cup {NoTime}
    /\ enrollmentAcceptedAt \in Steps \cup {NoTime}

Init ==
    /\ clock = 0
    /\ state = "NotEnrolled"
    /\ sessionEnd = 0
    /\ lastAccepted = NoStep
    /\ accepted = [s \in Steps |-> 0]
    /\ tokenSecond = FALSE
    /\ acceptedAt = NoTime
    /\ enrollmentAcceptedAt = NoTime

Tick ==
    /\ clock < MaxStep
    /\ clock' = clock + 1
    /\ UNCHANGED <<state, sessionEnd, lastAccepted, accepted, tokenSecond,
                    acceptedAt, enrollmentAcceptedAt>>

StartEnrollment ==
    /\ state \in {"NotEnrolled", "Expired"}
    /\ state' = "EnrollmentStarted"
    /\ sessionEnd' = clock + SessionTtl
    /\ UNCHANGED <<clock, lastAccepted, accepted, tokenSecond,
                    acceptedAt, enrollmentAcceptedAt>>

InWindowAt(step, at) == step + Window >= at /\ step <= at + Window
InWindow(step) == InWindowAt(step, clock)

FinalizeEnrollment(step) ==
    /\ state = "EnrollmentStarted"
    /\ clock <= sessionEnd
    /\ InWindow(step)
    /\ state' = "Enrolled"
    /\ lastAccepted' = step
    /\ accepted' = [accepted EXCEPT ![step] = @ + 1]
    /\ acceptedAt' = clock
    /\ enrollmentAcceptedAt' = clock
    /\ UNCHANGED <<clock, sessionEnd, tokenSecond>>

ExpireEnrollment ==
    /\ state = "EnrollmentStarted"
    /\ clock > sessionEnd
    /\ state' = "Expired"
    /\ UNCHANGED <<clock, sessionEnd, lastAccepted, accepted, tokenSecond,
                    acceptedAt, enrollmentAcceptedAt>>

\* Sign-in verification: replay protection is the guard step > lastAccepted.
Verify(step) ==
    /\ state = "Enrolled"
    /\ InWindow(step)
    /\ (lastAccepted = NoStep \/ step > lastAccepted)
    /\ lastAccepted' = step
    /\ accepted' = [accepted EXCEPT ![step] = @ + 1]
    /\ tokenSecond' = TRUE
    /\ acceptedAt' = clock
    /\ UNCHANGED <<clock, state, sessionEnd, enrollmentAcceptedAt>>

Next ==
    \/ Tick
    \/ StartEnrollment
    \/ ExpireEnrollment
    \/ \E s \in Steps: FinalizeEnrollment(s) \/ Verify(s)

Fairness ==
    /\ WF_vars(Tick)
    /\ WF_vars(ExpireEnrollment)
    /\ \A s \in Steps: WF_vars(FinalizeEnrollment(s))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
\* INV-AUTH-001: no step is accepted twice.
NoTotpCodeReuse == \A s \in Steps: accepted[s] <= 1

\* INV-AUTH-002: a second-factor token implies an enrolled factor.
NoSecondFactorWithoutEnrollment == tokenSecond => state = "Enrolled"

\* Every accepted code was inside the configured window at its acceptance time.
AcceptedOnlyWithinWindow ==
    acceptedAt = NoTime \/ InWindowAt(lastAccepted, acceptedAt)

\* The implementation accepts the exact expiry instant and rejects every later instant.
EnrollmentAcceptedBeforeExpiry ==
    enrollmentAcceptedAt = NoTime \/ enrollmentAcceptedAt <= sessionEnd

\* LIVE-AUTH-001
EnrollmentEventuallyFinalizesOrExpires ==
    (state = "EnrollmentStarted") ~> (state \in {"Enrolled", "Expired"})
=============================================================================
