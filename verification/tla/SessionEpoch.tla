---------------------------- MODULE SessionEpoch ----------------------------
(***************************************************************************)
(* Session lifecycle and epoch isolation (spec 7.3, 7.4, 21.2, 21.3).      *)
(*                                                                         *)
(*   Creating -> Active -> Resetting -> Active -> Closing -> Closed        *)
(*                                                                         *)
(* A reset is an atomic epoch switch.  Every work item captures the epoch  *)
(* it was created in and may only apply its effect while that epoch is the *)
(* current one and the session is Active.                                  *)
(*                                                                         *)
(* Properties                                                              *)
(*   INV-EPOCH-001  EpochIsolation                                         *)
(*   INV-EPOCH-002  WorkCapturedOnlyWhileActive                            *)
(*   INV-TIME-001   EpochNeverDecreases (epoch is the model's clock)       *)
(*   LIVE-RESET-001 ResetEventuallyActivatesNewEpoch                       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Workers,   \* set of worker identities
          MaxEpoch   \* bound on the number of resets explored

VARIABLES state,             \* lifecycle state
          epoch,             \* current epoch
          workEpoch,         \* workEpoch[w]: captured epoch (NoWork if none)
          applied,           \* records [worker, work, session] for applied effects
          previousState,
          lastCapturedEpoch,
          lastAction

vars == <<state, epoch, workEpoch, applied, previousState, lastCapturedEpoch,
          lastAction>>

NoWork == MaxEpoch + 1

States == {"Creating", "Active", "Resetting", "Closing", "Closed"}

Actions == {"Init", "Activate", "BeginReset", "CompleteReset", "BeginClose",
             "CompleteClose", "CaptureWork", "ApplyWork", "DiscardWork"}

TypeOK ==
    /\ state \in States
    /\ epoch \in 0..MaxEpoch
    /\ workEpoch \in [Workers -> 0..NoWork]
    /\ applied \subseteq [worker: Workers, work: 0..MaxEpoch, session: 0..MaxEpoch]
    /\ previousState \in States
    /\ lastCapturedEpoch \in 0..NoWork
    /\ lastAction \in Actions

Init ==
    /\ state = "Creating"
    /\ epoch = 0
    /\ workEpoch = [w \in Workers |-> NoWork]
    /\ applied = {}
    /\ previousState = state
    /\ lastCapturedEpoch = NoWork
    /\ lastAction = "Init"

Record(action, capturedEpoch) ==
    /\ previousState' = state
    /\ lastCapturedEpoch' = capturedEpoch
    /\ lastAction' = action

Activate ==
    /\ state = "Creating"
    /\ state' = "Active"
    /\ Record("Activate", NoWork)
    /\ UNCHANGED <<epoch, workEpoch, applied>>

\* Reset: bump the epoch first, then publish the new epoch as Active.
BeginReset ==
    /\ state = "Active"
    /\ epoch < MaxEpoch
    /\ state' = "Resetting"
    /\ epoch' = epoch + 1
    /\ Record("BeginReset", NoWork)
    /\ UNCHANGED <<workEpoch, applied>>

CompleteReset ==
    /\ state = "Resetting"
    /\ state' = "Active"
    /\ Record("CompleteReset", NoWork)
    /\ UNCHANGED <<epoch, workEpoch, applied>>

\* A session is always closable, including from an unfinished reset.
BeginClose ==
    /\ state \in {"Creating", "Active", "Resetting"}
    /\ state' = "Closing"
    /\ Record("BeginClose", NoWork)
    /\ UNCHANGED <<epoch, workEpoch, applied>>

CompleteClose ==
    /\ state = "Closing"
    /\ state' = "Closed"
    /\ Record("CompleteClose", NoWork)
    /\ UNCHANGED <<epoch, workEpoch, applied>>

\* A worker creates a work item while the session is active; the item captures the epoch.
CaptureWork(w) ==
    /\ state = "Active"
    /\ workEpoch[w] = NoWork
    /\ workEpoch' = [workEpoch EXCEPT ![w] = epoch]
    /\ Record("CaptureWork", epoch)
    /\ UNCHANGED <<state, epoch, applied>>

\* The epoch guard: apply only when the captured epoch is current and the session is Active.
ApplyWork(w) ==
    /\ workEpoch[w] # NoWork
    /\ state = "Active"
    /\ workEpoch[w] = epoch
    /\ applied' = applied \cup {[worker |-> w, work |-> workEpoch[w], session |-> epoch]}
    /\ workEpoch' = [workEpoch EXCEPT ![w] = NoWork]
    /\ Record("ApplyWork", NoWork)
    /\ UNCHANGED <<state, epoch>>

\* A stale work item is discarded without any effect.
DiscardWork(w) ==
    /\ workEpoch[w] # NoWork
    /\ workEpoch[w] # epoch
    /\ workEpoch' = [workEpoch EXCEPT ![w] = NoWork]
    /\ Record("DiscardWork", NoWork)
    /\ UNCHANGED <<state, epoch, applied>>

Next ==
    \/ Activate
    \/ BeginReset
    \/ CompleteReset
    \/ BeginClose
    \/ CompleteClose
    \/ \E w \in Workers: CaptureWork(w) \/ ApplyWork(w) \/ DiscardWork(w)

Fairness == WF_vars(CompleteReset)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
\* INV-EPOCH-001: every applied effect was produced in the epoch that was current.
EpochIsolation == \A a \in applied: a.work = a.session

WorkCapturedOnlyWhileActive ==
    lastAction = "CaptureWork" =>
        /\ previousState = "Active"
        /\ lastCapturedEpoch = epoch

\* INV-TIME-001 (model clock): the epoch never decreases.
EpochNeverDecreases == [][epoch' >= epoch]_vars

\* LIVE-RESET-001: a started reset eventually publishes the new epoch as Active, unless the
\* session is being closed (closing from Resetting is the explicit escape hatch).
ResetEventuallyActivatesNewEpoch ==
    (state = "Resetting") ~> (state \in {"Active", "Closing", "Closed"})

\* Non-vacuity: each of these must be reachable (TLC reports coverage).
StaleWorkExists == \E w \in Workers: workEpoch[w] # NoWork /\ workEpoch[w] # epoch
=============================================================================
