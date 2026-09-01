------------------------- MODULE RegexAuthorization -------------------------
EXTENDS TLC

Outcomes == {"Matched", "NotMatched", "Exhausted"}

VARIABLES parentOutcome, nestedOutcome, parentNegated, nestedNegated

vars == <<parentOutcome, nestedOutcome, parentNegated, nestedNegated>>

TypeOK ==
    /\ parentOutcome \in Outcomes
    /\ nestedOutcome \in Outcomes
    /\ parentNegated \in BOOLEAN
    /\ nestedNegated \in BOOLEAN

Init == TypeOK

Next ==
    /\ parentOutcome' \in Outcomes
    /\ nestedOutcome' \in Outcomes
    /\ parentNegated' \in BOOLEAN
    /\ nestedNegated' \in BOOLEAN

Condition(outcome, negated) ==
    IF outcome = "Exhausted"
    THEN "Exhausted"
    ELSE IF negated
         THEN IF outcome = "Matched" THEN "NotMatched" ELSE "Matched"
         ELSE outcome

Merge(parent, nested) ==
    IF parent = "Exhausted" \/ nested = "Exhausted"
    THEN "Exhausted"
    ELSE IF parent = "Matched" \/ nested = "Matched"
         THEN "Matched"
         ELSE "NotMatched"

AuthorizationOutcome ==
    Merge(
        Condition(parentOutcome, parentNegated),
        Condition(nestedOutcome, nestedNegated)
    )

Decision(outcome) == IF outcome = "Matched" THEN "Allow" ELSE "Deny"

Spec == Init /\ [][Next]_vars

ExhaustionNeverAllows ==
    (parentOutcome = "Exhausted" \/ nestedOutcome = "Exhausted")
        => Decision(AuthorizationOutcome) = "Deny"

=============================================================================
