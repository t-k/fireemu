------------------------- MODULE RegexAuthorization -------------------------
EXTENDS TLC

Outcomes == {"Matched", "NotMatched", "Exhausted"}

VARIABLE outcome

vars == <<outcome>>

Init == outcome \in Outcomes

Next == outcome' \in Outcomes

Decision(result) ==
    IF result = "Exhausted"
    THEN "Deny"
    ELSE IF result = "NotMatched"
         THEN "Allow"
         ELSE "Deny"

Spec == Init /\ [][Next]_vars

ExhaustionNeverAllows ==
    outcome = "Exhausted" => Decision(outcome) = "Deny"

=============================================================================
