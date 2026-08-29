---------------------------- MODULE EventDelivery ----------------------------
(***************************************************************************)
(* Event state machine (spec 10.2, 21.2, 21.3).                            *)
(*                                                                         *)
(*   Pending -> Leased -> Running -> Succeeded                             *)
(*      |         |          |-> RetryWaiting -> Pending                   *)
(*      |         |          |-> DeadLettered                              *)
(*      |         |          `-> Cancelled                                 *)
(*      `---------+------------> DiscardedStaleEpoch                       *)
(*                                                                         *)
(* Properties                                                              *)
(*   INV-EVENT-001    NoTerminalRegression                                 *)
(*   AttemptsBounded  attempts never exceed MaxAttempts                    *)
(*   LIVE-DISPATCH-001 EventEventuallyTerminates                           *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Events,       \* set of event identities
          MaxAttempts,  \* retry policy: total attempts
          MaxEpoch

VARIABLES state,        \* state[e]
          attempts,     \* attempts[e]
          eventEpoch,   \* epoch the event was created in
          epoch         \* current session epoch

vars == <<state, attempts, eventEpoch, epoch>>

Terminal == {"Succeeded", "DeadLettered", "Cancelled", "DiscardedStaleEpoch"}
NonTerminal == {"Pending", "Leased", "Running", "RetryWaiting"}
States == Terminal \cup NonTerminal

TypeOK ==
    /\ state \in [Events -> States]
    /\ attempts \in [Events -> 0..MaxAttempts]
    /\ eventEpoch \in [Events -> 0..MaxEpoch]
    /\ epoch \in 0..MaxEpoch

Init ==
    /\ state = [e \in Events |-> "Pending"]
    /\ attempts = [e \in Events |-> 0]
    /\ eventEpoch = [e \in Events |-> 0]
    /\ epoch = 0

Lease(e) ==
    /\ state[e] = "Pending"
    /\ state' = [state EXCEPT ![e] = "Leased"]
    /\ UNCHANGED <<attempts, eventEpoch, epoch>>

Start(e) ==
    /\ state[e] = "Leased"
    /\ attempts[e] < MaxAttempts
    /\ state' = [state EXCEPT ![e] = "Running"]
    /\ attempts' = [attempts EXCEPT ![e] = attempts[e] + 1]
    /\ UNCHANGED <<eventEpoch, epoch>>

Succeed(e) ==
    /\ state[e] = "Running"
    /\ state' = [state EXCEPT ![e] = "Succeeded"]
    /\ UNCHANGED <<attempts, eventEpoch, epoch>>

\* Failure: retry while attempts remain, otherwise dead-letter.
Fail(e) ==
    /\ state[e] = "Running"
    /\ state' = [state EXCEPT ![e] =
                    IF attempts[e] < MaxAttempts THEN "RetryWaiting" ELSE "DeadLettered"]
    /\ UNCHANGED <<attempts, eventEpoch, epoch>>

RetryDue(e) ==
    /\ state[e] = "RetryWaiting"
    /\ state' = [state EXCEPT ![e] = "Pending"]
    /\ UNCHANGED <<attempts, eventEpoch, epoch>>

Cancel(e) ==
    /\ state[e] \in NonTerminal
    /\ state' = [state EXCEPT ![e] = "Cancelled"]
    /\ UNCHANGED <<attempts, eventEpoch, epoch>>

Reset ==
    /\ epoch < MaxEpoch
    /\ epoch' = epoch + 1
    /\ UNCHANGED <<state, attempts, eventEpoch>>

DiscardStale(e) ==
    /\ state[e] \in NonTerminal
    /\ eventEpoch[e] < epoch
    /\ state' = [state EXCEPT ![e] = "DiscardedStaleEpoch"]
    /\ UNCHANGED <<attempts, eventEpoch, epoch>>

Progress(e) == Lease(e) \/ Start(e) \/ Succeed(e) \/ Fail(e) \/ RetryDue(e) \/ DiscardStale(e)

Next ==
    \/ Reset
    \/ \E e \in Events: Progress(e) \/ Cancel(e)

\* Fair workers: every enabled progress step for every event is eventually taken.
Fairness == \A e \in Events: WF_vars(Progress(e))

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
\* INV-EVENT-001: a terminal event never changes state again.
NoTerminalRegression ==
    [][\A e \in Events: state[e] \in Terminal => state'[e] = state[e]]_vars

\* Retry bound (M-RETRY-002 off-by-one would violate this).
AttemptsBounded == \A e \in Events: attempts[e] <= MaxAttempts

\* Retry exhaustion is only reached through DeadLettered, never by a silent stop.
DeadLetterOnlyAfterExhaustion ==
    \A e \in Events: state[e] = "DeadLettered" => attempts[e] = MaxAttempts

\* LIVE-DISPATCH-001
EventEventuallyTerminates == \A e \in Events: <>(state[e] \in Terminal)
=============================================================================
