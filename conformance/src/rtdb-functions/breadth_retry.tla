--------------------------- MODULE breadth_retry ---------------------------
EXTENDS Naturals, TLC

VARIABLES age, failures, state, lastFailureAge
vars == <<age, failures, state, lastFailureAge>>

Init == /\ age = 0
        /\ failures = 0
        /\ state = "ready"
        /\ lastFailureAge = 0

Attempt == /\ state = "ready"
           /\ IF age < 45
                 THEN /\ failures' = failures + 1
                      /\ lastFailureAge' = age
                      /\ state' = "backoff"
                 ELSE /\ UNCHANGED <<failures, lastFailureAge>>
                      /\ state' = "success"
           /\ UNCHANGED age

Backoff == /\ state = "backoff"
           /\ age' = age + 10
           /\ state' = "ready"
           /\ UNCHANGED <<failures, lastFailureAge>>

Delete == /\ state \in {"ready", "backoff"}
          /\ state' = "deleted"
          /\ UNCHANGED <<age, failures, lastFailureAge>>

Next == Attempt \/ Backoff \/ Delete
Spec == Init /\ [][Next]_vars /\ WF_vars(Next)
FailureBound == failures <= 5
FailureAge == failures = 0 \/ lastFailureAge < 45
Terminates == <> (state = "success" \/ state = "deleted")
=============================================================================
