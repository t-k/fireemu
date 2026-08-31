------------------------- MODULE RulesetActivation -------------------------
(***************************************************************************)
(* A candidate becomes active only after every load check. Requests pin the *)
(* active version observed at admission until they finish.                  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Requests, Versions, ExistingVersion, CandidateVersion

VARIABLES candidatePhase,
          activeVersion,
          requestState,
          requestVersion,
          previousCandidatePhase,
          previousActiveVersion,
          previousRequestState,
          previousRequestVersion,
          lastAction,
          lastRequest

vars == <<candidatePhase, activeVersion, requestState, requestVersion,
          previousCandidatePhase, previousActiveVersion, previousRequestState,
          previousRequestVersion, lastAction, lastRequest>>

CandidatePhases == {"Absent", "Created", "Parsed", "Compiled", "Checked",
                     "Active", "Rejected"}
RequestStates == {"Idle", "Running", "Finished"}
Actions == {"Init", "Create", "Parse", "Compile", "Check", "Reject",
             "Activate", "StartRequest", "ProgressRequest", "FinishRequest"}

TypeOK ==
    /\ candidatePhase \in CandidatePhases
    /\ activeVersion \in Versions
    /\ requestState \in [Requests -> RequestStates]
    /\ requestVersion \in [Requests -> Versions]
    /\ previousCandidatePhase \in CandidatePhases
    /\ previousActiveVersion \in Versions
    /\ previousRequestState \in [Requests -> RequestStates]
    /\ previousRequestVersion \in [Requests -> Versions]
    /\ lastAction \in Actions
    /\ lastRequest \subseteq Requests
    /\ Cardinality(lastRequest) <= 1

Init ==
    /\ ExistingVersion \in Versions
    /\ CandidateVersion \in Versions
    /\ ExistingVersion # CandidateVersion
    /\ candidatePhase = "Absent"
    /\ activeVersion = ExistingVersion
    /\ requestState = [r \in Requests |-> "Idle"]
    /\ requestVersion = [r \in Requests |-> ExistingVersion]
    /\ previousCandidatePhase = candidatePhase
    /\ previousActiveVersion = activeVersion
    /\ previousRequestState = requestState
    /\ previousRequestVersion = requestVersion
    /\ lastAction = "Init"
    /\ lastRequest = {}

Record(action, request) ==
    /\ previousCandidatePhase' = candidatePhase
    /\ previousActiveVersion' = activeVersion
    /\ previousRequestState' = requestState
    /\ previousRequestVersion' = requestVersion
    /\ lastAction' = action
    /\ lastRequest' = request

Create ==
    /\ candidatePhase = "Absent"
    /\ candidatePhase' = "Created"
    /\ Record("Create", {})
    /\ UNCHANGED <<activeVersion, requestState, requestVersion>>

Parse ==
    /\ candidatePhase = "Created"
    /\ candidatePhase' = "Parsed"
    /\ Record("Parse", {})
    /\ UNCHANGED <<activeVersion, requestState, requestVersion>>

Compile ==
    /\ candidatePhase = "Parsed"
    /\ candidatePhase' = "Compiled"
    /\ Record("Compile", {})
    /\ UNCHANGED <<activeVersion, requestState, requestVersion>>

Check ==
    /\ candidatePhase = "Compiled"
    /\ candidatePhase' = "Checked"
    /\ Record("Check", {})
    /\ UNCHANGED <<activeVersion, requestState, requestVersion>>

Reject ==
    /\ candidatePhase \in {"Created", "Parsed", "Compiled", "Checked"}
    /\ candidatePhase' = "Rejected"
    /\ Record("Reject", {})
    /\ UNCHANGED <<activeVersion, requestState, requestVersion>>

Activate ==
    /\ candidatePhase = "Checked"
    /\ candidatePhase' = "Active"
    /\ activeVersion' = CandidateVersion
    /\ Record("Activate", {})
    /\ UNCHANGED <<requestState, requestVersion>>

StartRequest(r) ==
    /\ requestState[r] = "Idle"
    /\ requestState' = [requestState EXCEPT ![r] = "Running"]
    /\ requestVersion' = [requestVersion EXCEPT ![r] = activeVersion]
    /\ Record("StartRequest", {r})
    /\ UNCHANGED <<candidatePhase, activeVersion>>

ProgressRequest(r) ==
    /\ requestState[r] = "Running"
    /\ Record("ProgressRequest", {r})
    /\ UNCHANGED <<candidatePhase, activeVersion, requestState, requestVersion>>

FinishRequest(r) ==
    /\ requestState[r] = "Running"
    /\ requestState' = [requestState EXCEPT ![r] = "Finished"]
    /\ Record("FinishRequest", {r})
    /\ UNCHANGED <<candidatePhase, activeVersion, requestVersion>>

Next ==
    \/ Create
    \/ Parse
    \/ Compile
    \/ Check
    \/ Reject
    \/ Activate
    \/ \E r \in Requests: StartRequest(r) \/ ProgressRequest(r) \/ FinishRequest(r)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
ActivationRequiresAllChecks ==
    lastAction = "Activate" => previousCandidatePhase = "Checked"

FailedCandidateNeverActivates ==
    previousCandidatePhase = "Rejected" => activeVersion = previousActiveVersion

RequestVersionIsImmutable ==
    \A r \in Requests:
        previousRequestState[r] = "Running" /\
        requestState[r] \in {"Running", "Finished"} =>
            requestVersion[r] = previousRequestVersion[r]

ActiveVersionChangesAtomically ==
    activeVersion # previousActiveVersion =>
        /\ lastAction = "Activate"
        /\ candidatePhase = "Active"

AtomicRulesetActivation ==
    /\ ActivationRequiresAllChecks
    /\ FailedCandidateNeverActivates
    /\ RequestVersionIsImmutable
    /\ ActiveVersionChangesAtomically
=============================================================================
