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
          epoch,        \* current session epoch
          previousState,
          previousAttempts,
          previousEventEpoch,
          previousEpoch,
          lastAction,
          lastTarget

vars == <<state, attempts, eventEpoch, epoch, previousState, previousAttempts,
          previousEventEpoch, previousEpoch, lastAction, lastTarget>>

Terminal == {"Succeeded", "DeadLettered", "Cancelled", "DiscardedStaleEpoch"}
NonTerminal == {"Pending", "Leased", "Running", "RetryWaiting"}
States == Terminal \cup NonTerminal
Actions == {"Init", "Lease", "Start", "Succeed", "Fail", "RetryDue",
             "Cancel", "Reset", "DiscardStale"}

TypeOK ==
    /\ state \in [Events -> States]
    /\ attempts \in [Events -> 0..MaxAttempts]
    /\ eventEpoch \in [Events -> 0..MaxEpoch]
    /\ epoch \in 0..MaxEpoch
    /\ previousState \in [Events -> States]
    /\ previousAttempts \in [Events -> 0..MaxAttempts]
    /\ previousEventEpoch \in [Events -> 0..MaxEpoch]
    /\ previousEpoch \in 0..MaxEpoch
    /\ lastAction \in Actions
    /\ lastTarget \subseteq Events
    /\ Cardinality(lastTarget) <= 1

Init ==
    /\ state = [e \in Events |-> "Pending"]
    /\ attempts = [e \in Events |-> 0]
    /\ eventEpoch = [e \in Events |-> 0]
    /\ epoch = 0
    /\ previousState = state
    /\ previousAttempts = attempts
    /\ previousEventEpoch = eventEpoch
    /\ previousEpoch = epoch
    /\ lastAction = "Init"
    /\ lastTarget = {}

RecordEvent(action, e) ==
    /\ previousState' = state
    /\ previousAttempts' = attempts
    /\ previousEventEpoch' = eventEpoch
    /\ previousEpoch' = epoch
    /\ lastAction' = action
    /\ lastTarget' = {e}

RecordReset ==
    /\ previousState' = state
    /\ previousAttempts' = attempts
    /\ previousEventEpoch' = eventEpoch
    /\ previousEpoch' = epoch
    /\ lastAction' = "Reset"
    /\ lastTarget' = {}

Lease(e) ==
    /\ state[e] = "Pending"
    /\ state' = [state EXCEPT ![e] = "Leased"]
    /\ RecordEvent("Lease", e)
    /\ UNCHANGED <<attempts, eventEpoch, epoch>>

Start(e) ==
    /\ state[e] = "Leased"
    /\ attempts[e] < MaxAttempts
    /\ state' = [state EXCEPT ![e] = "Running"]
    /\ attempts' = [attempts EXCEPT ![e] = attempts[e] + 1]
    /\ RecordEvent("Start", e)
    /\ UNCHANGED <<eventEpoch, epoch>>

Succeed(e) ==
    /\ state[e] = "Running"
    /\ state' = [state EXCEPT ![e] = "Succeeded"]
    /\ RecordEvent("Succeed", e)
    /\ UNCHANGED <<attempts, eventEpoch, epoch>>

\* Failure: retry while attempts remain, otherwise dead-letter.
Fail(e) ==
    /\ state[e] = "Running"
    /\ state' = [state EXCEPT ![e] =
                    IF attempts[e] < MaxAttempts THEN "RetryWaiting" ELSE "DeadLettered"]
    /\ RecordEvent("Fail", e)
    /\ UNCHANGED <<attempts, eventEpoch, epoch>>

RetryDue(e) ==
    /\ state[e] = "RetryWaiting"
    /\ state' = [state EXCEPT ![e] = "Pending"]
    /\ RecordEvent("RetryDue", e)
    /\ UNCHANGED <<attempts, eventEpoch, epoch>>

Cancel(e) ==
    /\ state[e] \in NonTerminal
    /\ state' = [state EXCEPT ![e] = "Cancelled"]
    /\ RecordEvent("Cancel", e)
    /\ UNCHANGED <<attempts, eventEpoch, epoch>>

Reset ==
    /\ epoch < MaxEpoch
    /\ epoch' = epoch + 1
    /\ RecordReset
    /\ UNCHANGED <<state, attempts, eventEpoch>>

DiscardStale(e) ==
    /\ state[e] \in NonTerminal
    /\ eventEpoch[e] < epoch
    /\ state' = [state EXCEPT ![e] = "DiscardedStaleEpoch"]
    /\ RecordEvent("DiscardStale", e)
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

OnlyTargetStateChanged(e) ==
    \A other \in Events \ {e}: state[other] = previousState[other]

LegalEventTransition(e) ==
    /\ OnlyTargetStateChanged(e)
    /\ CASE lastAction = "Lease" ->
                previousState[e] = "Pending" /\ state[e] = "Leased"
            [] lastAction = "Start" ->
                previousState[e] = "Leased" /\ state[e] = "Running"
            [] lastAction = "Succeed" ->
                previousState[e] = "Running" /\ state[e] = "Succeeded"
            [] lastAction = "Fail" ->
                /\ previousState[e] = "Running"
                /\ state[e] = IF previousAttempts[e] < MaxAttempts
                               THEN "RetryWaiting" ELSE "DeadLettered"
            [] lastAction = "RetryDue" ->
                previousState[e] = "RetryWaiting" /\ state[e] = "Pending"
            [] lastAction = "Cancel" ->
                previousState[e] \in NonTerminal /\ state[e] = "Cancelled"
            [] lastAction = "DiscardStale" ->
                previousState[e] \in NonTerminal /\ state[e] = "DiscardedStaleEpoch"
            [] OTHER -> FALSE

LegalStateTransitions ==
    \/ lastAction = "Init" /\ lastTarget = {}
    \/ lastAction = "Reset" /\ lastTarget = {} /\ state = previousState
    \/ \E e \in Events: lastTarget = {e} /\ LegalEventTransition(e)

AttemptsChangeOnlyOnStart ==
    IF lastAction = "Start"
    THEN \E e \in Events:
            /\ lastTarget = {e}
            /\ attempts[e] = previousAttempts[e] + 1
            /\ \A other \in Events \ {e}: attempts[other] = previousAttempts[other]
    ELSE attempts = previousAttempts

StaleDiscardRequiresOlderEpoch ==
    lastAction = "DiscardStale" =>
        \E e \in Events:
            /\ lastTarget = {e}
            /\ previousEventEpoch[e] < previousEpoch

\* LIVE-DISPATCH-001
EventEventuallyTerminates == \A e \in Events: <>(state[e] \in Terminal)
=============================================================================
