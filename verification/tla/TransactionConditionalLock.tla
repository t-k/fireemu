-------------------- MODULE TransactionConditionalLock --------------------
(***************************************************************************)
(* Two concurrent read-write transactions observe an unlocked document.    *)
(* Exactly one stale snapshot may commit; the other attempt is aborted and *)
(* retries against the committed lock before the protected action releases *)
(* it. This is the bounded protocol exercised by the Admin SDK corpus row.  *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANT Clients

VARIABLES phase, locked, observations, acted

vars == <<phase, locked, observations, acted>>

Phases == {"Ready", "Read", "Committed", "Aborted", "Retried", "Rejected", "Done"}

TypeOK ==
    /\ phase \in [Clients -> Phases]
    /\ locked \in BOOLEAN
    /\ observations \in [Clients -> Seq(BOOLEAN)]
    /\ acted \subseteq Clients

Init ==
    /\ phase = [c \in Clients |-> "Ready"]
    /\ locked = FALSE
    /\ observations = [c \in Clients |-> <<>>]
    /\ acted = {}

ReadUnlocked(c) ==
    /\ phase[c] = "Ready"
    /\ ~locked
    /\ phase' = [phase EXCEPT ![c] = "Read"]
    /\ observations' = [observations EXCEPT ![c] = Append(@, locked)]
    /\ UNCHANGED <<locked, acted>>

Commit(c) ==
    /\ phase[c] = "Read"
    /\ \A other \in Clients: observations[other] = <<FALSE>>
    /\ ~locked
    /\ phase' = [phase EXCEPT ![c] = "Committed"]
    /\ locked' = TRUE
    /\ UNCHANGED <<observations, acted>>

AbortStale(c) ==
    /\ phase[c] = "Read"
    /\ locked
    /\ phase' = [phase EXCEPT ![c] = "Aborted"]
    /\ UNCHANGED <<locked, observations, acted>>

Retry(c) ==
    /\ phase[c] = "Aborted"
    /\ phase' = [phase EXCEPT ![c] = "Retried"]
    /\ observations' = [observations EXCEPT ![c] = Append(@, locked)]
    /\ UNCHANGED <<locked, acted>>

RejectLocked(c) ==
    /\ phase[c] = "Retried"
    /\ Len(observations[c]) = 2
    /\ observations[c][2]
    /\ phase' = [phase EXCEPT ![c] = "Rejected"]
    /\ UNCHANGED <<locked, observations, acted>>

RunProtectedAction(c) ==
    /\ phase[c] = "Committed"
    /\ c \notin acted
    /\ acted' = acted \cup {c}
    /\ UNCHANGED <<phase, locked, observations>>

Release(c) ==
    /\ phase[c] = "Committed"
    /\ c \in acted
    /\ \A other \in Clients \ {c}: phase[other] = "Rejected"
    /\ phase' = [phase EXCEPT ![c] = "Done"]
    /\ locked' = FALSE
    /\ UNCHANGED <<observations, acted>>

Next ==
    \E c \in Clients:
        \/ ReadUnlocked(c)
        \/ Commit(c)
        \/ AbortStale(c)
        \/ Retry(c)
        \/ RejectLocked(c)
        \/ RunProtectedAction(c)
        \/ Release(c)

Spec == Init /\ [][Next]_vars

OneWinner == Cardinality({c \in Clients: phase[c] \in {"Committed", "Done"}}) <= 1

AtMostOneProtectedAction == Cardinality(acted) <= 1

RetryReadsCommittedLock ==
    \A c \in Clients:
        phase[c] \in {"Retried", "Rejected"} =>
            /\ Len(observations[c]) = 2
            /\ observations[c][2] = TRUE
=============================================================================
