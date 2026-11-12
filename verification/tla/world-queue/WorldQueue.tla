------------------------------ MODULE WorldQueue ------------------------------
(* Admission rules of the test-world operation queue (npm/fireemu/testing-queue.mjs).
   Kinds: "M" ordered (clock helpers and ordinary control calls), "W" waiting
   (awaitIdle), "E" exclusive (reset, dispose). Operations are admitted in call
   order; each starts when its predecessor set has completed.
   Mode "serial" is the old single FIFO queue; "lanes" is the new rule set.
   A waiting operation with needs=TRUE completes only after some ordered
   operation issued LATER than it has completed (awaitIdle waits for a clock move).
   Admitting an exclusive operation cancels every waiting operation admitted before it that is
   not done (state "cancelled": it never starts, or stops at once). Cancelled counts as done for
   the exclusive operation's predecessor check. *)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS N, Mode

VARIABLES kind, needs, state, issued
\* kind[i] in {"M","W","E"}; needs[i] BOOLEAN (only meaningful for "W");
\* state[i] in {"queued","running","done","cancelled"}; issued = number of admitted operations.
vars == <<kind, needs, state, issued>>

Idx == 1..N
Kinds == {"M","W","E"}

Admitted == 1..issued
Before(i) == 1..(i-1)

\* Predecessor sets
Preds(i) ==
  IF Mode = "serial" THEN Before(i)
  ELSE CASE kind[i] = "E" -> Before(i)
         [] kind[i] = "M" -> {j \in Before(i) : kind[j] \in {"M","E"}}
         [] kind[i] = "W" -> {j \in Before(i) : kind[j] \in {"M","E"}}

\* Starting a type-M or W operation must also wait for the latest exclusive before it (already in Preds via kind E).

\* A needy wait must eventually be enabled or cancelled: some ordered or exclusive operation is issued
\* after it (a wait nothing follows can only end by the daemon's own timeout, which this model does
\* not represent). Mode "lanes-nocancel" keeps the earlier rule set (no cancellation), where each needy
\* wait also needs an ordered operation after it with no exclusive operation between them.
WellFormed(k, n) ==
  \A i \in Idx : (k[i] = "W" /\ n[i]) =>
     IF Mode = "lanes"
       THEN \E j \in Idx : j > i /\ k[j] \in {"M","E"}
       ELSE \E j \in Idx : j > i /\ k[j] = "M" /\ \A m \in (i+1)..j : k[m] # "E"

Init ==
  /\ kind \in [Idx -> Kinds]
  /\ needs \in [Idx -> BOOLEAN]
  /\ WellFormed(kind, needs)
  /\ state = [i \in Idx |-> "queued"]
  /\ issued = 0

Ended(j) == state[j] \in {"done","cancelled"}

\* Admitting operation number issued+1; an exclusive one cancels the unfinished waits before it.
Issue ==
  /\ issued < N
  /\ issued' = issued + 1
  /\ IF Mode = "lanes" /\ kind[issued + 1] = "E"
       THEN state' = [j \in Idx |->
                        IF j <= issued /\ kind[j] = "W" /\ ~Ended(j) THEN "cancelled" ELSE state[j]]
       ELSE UNCHANGED state
  /\ UNCHANGED <<kind, needs>>

Start(i) ==
  /\ i \in Admitted
  /\ state[i] = "queued"
  /\ \A j \in Preds(i) : Ended(j)
  /\ state' = [state EXCEPT ![i] = "running"]
  /\ UNCHANGED <<kind, needs, issued>>

Satisfied(i) ==
  \/ kind[i] # "W"
  \/ ~needs[i]
  \/ \E j \in Idx : j > i /\ j <= issued /\ kind[j] = "M" /\ state[j] = "done"
        /\ \A m \in (i+1)..j : kind[m] # "E"

Finish(i) ==
  /\ state[i] = "running"
  /\ Satisfied(i)
  /\ state' = [state EXCEPT ![i] = "done"]
  /\ UNCHANGED <<kind, needs, issued>>

AllDone == issued = N /\ \A i \in Idx : Ended(i)

Finished == AllDone /\ UNCHANGED vars

Next == Issue \/ (\E i \in Idx : Start(i) \/ Finish(i)) \/ Finished

Spec == Init /\ [][Next]_vars /\ WF_vars(Issue) /\ \A i \in Idx : WF_vars(Start(i)) /\ WF_vars(Finish(i))

\* --- Safety ---
Running == {i \in Admitted : state[i] = "running"}
Started(i) == state[i] \in {"running","done"}

\* An exclusive operation runs alone and only after every earlier operation is done.
ExclusiveAlone ==
  \A i \in Running : kind[i] = "E" =>
     /\ Running = {i}
     /\ \A j \in Before(i) : Ended(j)

\* Nothing admitted after an exclusive operation starts before it is done.
NothingOvertakesExclusive ==
  \A i, j \in Admitted : (i < j /\ kind[i] = "E" /\ Started(j)) => state[i] = "done"

\* Ordered operations start in admission order and a waiting operation starts only after every
\* earlier ordered operation is done.
OrderedFifo ==
  \A i, j \in Admitted :
     (i < j /\ kind[i] = "M" /\ kind[j] = "M" /\ Started(j)) => state[i] = "done"
WaitAfterOrdered ==
  \A i, j \in Admitted :
     (i < j /\ kind[i] = "M" /\ kind[j] = "W" /\ Started(j)) => state[i] = "done"

\* A cancelled wait is always one with a later exclusive operation, and it never runs on.
CancelledOnlyBeforeExclusive ==
  \A i \in Admitted : state[i] = "cancelled" =>
     /\ kind[i] = "W"
     /\ \E j \in Admitted : j > i /\ kind[j] = "E"

\* --- Liveness ---
Completes == <>AllDone
=============================================================================
