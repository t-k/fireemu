------------------------ MODULE AtomicCommitOutbox ------------------------
(***************************************************************************)
(* One bounded Firestore transaction publishes its complete write set and  *)
(* corresponding logical outbox records at one observable boundary.        *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Docs, MaxVersion

VARIABLES phase,
          version,
          staged,
          stagedVersion,
          stagedEvents,
          visible,
          outbox,
          conflict,
          previousVersion,
          previousVisible,
          previousOutbox,
          previousConflict,
          lastStaged,
          lastStagedEvents,
          lastAction

vars == <<phase, version, staged, stagedVersion, stagedEvents, visible,
          outbox, conflict, previousVersion, previousVisible, previousOutbox,
          previousConflict, lastStaged, lastStagedEvents, lastAction>>

Phases == {"Idle", "Staging", "Committed", "Aborted"}
Actions == {"Init", "Begin", "StageWrite", "StageOutbox", "DetectConflict",
             "Commit", "Abort"}

TypeOK ==
    /\ phase \in Phases
    /\ version \in [Docs -> 0..MaxVersion]
    /\ staged \subseteq Docs
    /\ stagedVersion \in [Docs -> 0..MaxVersion]
    /\ stagedEvents \subseteq Docs
    /\ visible \subseteq Docs
    /\ outbox \subseteq Docs
    /\ conflict \in BOOLEAN
    /\ previousVersion \in [Docs -> 0..MaxVersion]
    /\ previousVisible \subseteq Docs
    /\ previousOutbox \subseteq Docs
    /\ previousConflict \in BOOLEAN
    /\ lastStaged \subseteq Docs
    /\ lastStagedEvents \subseteq Docs
    /\ lastAction \in Actions

Init ==
    /\ phase = "Idle"
    /\ version = [d \in Docs |-> 0]
    /\ staged = {}
    /\ stagedVersion = version
    /\ stagedEvents = {}
    /\ visible = {}
    /\ outbox = {}
    /\ conflict = FALSE
    /\ previousVersion = version
    /\ previousVisible = visible
    /\ previousOutbox = outbox
    /\ previousConflict = conflict
    /\ lastStaged = staged
    /\ lastStagedEvents = stagedEvents
    /\ lastAction = "Init"

Record(action) ==
    /\ previousVersion' = version
    /\ previousVisible' = visible
    /\ previousOutbox' = outbox
    /\ previousConflict' = conflict
    /\ lastStaged' = staged
    /\ lastStagedEvents' = stagedEvents
    /\ lastAction' = action

Begin ==
    /\ phase = "Idle"
    /\ phase' = "Staging"
    /\ staged' = {}
    /\ stagedVersion' = version
    /\ stagedEvents' = {}
    /\ conflict' = FALSE
    /\ Record("Begin")
    /\ UNCHANGED <<version, visible, outbox>>

StageWrite(d) ==
    /\ phase = "Staging"
    /\ d \notin staged
    /\ version[d] < MaxVersion
    /\ staged' = staged \cup {d}
    /\ stagedVersion' = [stagedVersion EXCEPT ![d] = version[d] + 1]
    /\ Record("StageWrite")
    /\ UNCHANGED <<phase, version, stagedEvents, visible, outbox, conflict>>

StageOutbox(d) ==
    /\ phase = "Staging"
    /\ d \in staged
    /\ stagedEvents' = stagedEvents \cup {d}
    /\ Record("StageOutbox")
    /\ UNCHANGED <<phase, version, staged, stagedVersion, visible, outbox, conflict>>

DetectConflict ==
    /\ phase = "Staging"
    /\ conflict' = TRUE
    /\ Record("DetectConflict")
    /\ UNCHANGED <<phase, version, staged, stagedVersion, stagedEvents, visible, outbox>>

Commit ==
    /\ phase = "Staging"
    /\ ~conflict
    /\ staged # {}
    /\ stagedEvents = staged
    /\ phase' = "Committed"
    /\ version' = [d \in Docs |-> IF d \in staged THEN stagedVersion[d] ELSE version[d]]
    /\ visible' = visible \cup staged
    /\ outbox' = outbox \cup stagedEvents
    /\ Record("Commit")
    /\ UNCHANGED <<staged, stagedVersion, stagedEvents, conflict>>

Abort ==
    /\ phase = "Staging"
    /\ conflict
    /\ phase' = "Aborted"
    /\ Record("Abort")
    /\ UNCHANGED <<version, staged, stagedVersion, stagedEvents, visible, outbox, conflict>>

Next ==
    \/ Begin
    \/ DetectConflict
    \/ Commit
    \/ Abort
    \/ \E d \in Docs: StageWrite(d) \/ StageOutbox(d)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
AtomicCommit ==
    /\ (lastAction # "Commit" =>
            /\ version = previousVersion
            /\ visible = previousVisible
            /\ outbox = previousOutbox)
    /\ (lastAction = "Commit" =>
            /\ visible \ previousVisible = lastStaged
            /\ outbox \ previousOutbox = lastStagedEvents)

OutboxCompleteness ==
    lastAction = "Commit" => lastStaged \subseteq outbox

NoPartialTransaction ==
    lastAction = "Commit" =>
        /\ lastStaged \subseteq visible
        /\ \A d \in Docs:
               IF d \in lastStaged
               THEN version[d] = previousVersion[d] + 1
               ELSE version[d] = previousVersion[d]

ConflictNeverCommits ==
    lastAction = "Commit" => ~previousConflict
=============================================================================
