------------------------- MODULE RegexLinearRepeat -------------------------
EXTENDS Naturals, TLC

CONSTANTS SubjectLength, StepMaximum, DepthMaximum

Classifications == {"Atomic", "NonAtomic"}
Outcomes == {"Running", "Matched", "NotMatched", "Exhausted"}
Actions == {"Init", "AtomicConsume", "AtomicReject", "AtomicFinish", "Fallback", "Exhaust"}

VARIABLES position, steps, depth, classification, currentAccepted,
          acceptedPrefix, outcome, lastAction

vars == <<position, steps, depth, classification, currentAccepted,
          acceptedPrefix, outcome, lastAction>>

TypeOK ==
    /\ position \in 0..SubjectLength
    /\ steps \in Nat
    /\ depth \in Nat
    /\ classification \in Classifications
    /\ currentAccepted \in BOOLEAN
    /\ acceptedPrefix \in BOOLEAN
    /\ outcome \in Outcomes
    /\ lastAction \in Actions

Init ==
    /\ position = 0
    /\ steps = 0
    /\ classification \in Classifications
    /\ depth = IF classification = "Atomic" THEN 1 ELSE 0
    /\ currentAccepted \in BOOLEAN
    /\ acceptedPrefix = TRUE
    /\ outcome = "Running"
    /\ lastAction = "Init"

AtomicConsume ==
    /\ classification = "Atomic"
    /\ outcome = "Running"
    /\ position < SubjectLength
    /\ steps < StepMaximum
    /\ currentAccepted
    /\ position' = position + 1
    /\ steps' = steps + 1
    /\ depth' = depth
    /\ currentAccepted' \in BOOLEAN
    /\ acceptedPrefix' = (acceptedPrefix /\ currentAccepted)
    /\ outcome' = outcome
    /\ lastAction' = "AtomicConsume"
    /\ UNCHANGED classification

AtomicReject ==
    /\ classification = "Atomic"
    /\ outcome = "Running"
    /\ position < SubjectLength
    /\ steps < StepMaximum
    /\ ~currentAccepted
    /\ steps' = steps + 1
    /\ acceptedPrefix' = FALSE
    /\ outcome' = "NotMatched"
    /\ lastAction' = "AtomicReject"
    /\ UNCHANGED <<position, depth, classification, currentAccepted>>

AtomicFinish ==
    /\ classification = "Atomic"
    /\ outcome = "Running"
    /\ position = SubjectLength
    /\ outcome' = "Matched"
    /\ lastAction' = "AtomicFinish"
    /\ UNCHANGED <<position, steps, depth, classification, currentAccepted, acceptedPrefix>>

Fallback ==
    /\ classification = "NonAtomic"
    /\ outcome = "Running"
    /\ steps < StepMaximum
    /\ depth < DepthMaximum
    /\ steps' = steps + 1
    /\ depth' = depth + 1
    /\ lastAction' = "Fallback"
    /\ UNCHANGED <<position, classification, currentAccepted, acceptedPrefix, outcome>>

Exhaust ==
    /\ outcome = "Running"
    /\ steps = StepMaximum \/ depth = DepthMaximum
    /\ outcome' = "Exhausted"
    /\ lastAction' = "Exhaust"
    /\ UNCHANGED <<position, steps, depth, classification, currentAccepted, acceptedPrefix>>

Terminal ==
    /\ outcome # "Running"
    /\ UNCHANGED vars

Next == AtomicConsume \/ AtomicReject \/ AtomicFinish \/ Fallback \/ Exhaust \/ Terminal

Spec == Init /\ [][Next]_vars

Decision(value) == IF value = "Matched" THEN "Allow" ELSE "Deny"

AtomicProgressDoesNotIncreaseDepth ==
    classification = "Atomic" => depth = 1

MatchedImpliesEveryCharacterAccepted ==
    outcome = "Matched" => position = SubjectLength /\ acceptedPrefix

ForbiddenCharacterNeverMatches ==
    ~acceptedPrefix => outcome # "Matched"

WorkIsCharged ==
    position > 0 => steps >= position

BudgetExhaustionNeverMatches ==
    lastAction = "Exhaust" => outcome = "Exhausted" /\ Decision(outcome) = "Deny"

NonAtomicFallsBack ==
    lastAction = "Fallback" => classification = "NonAtomic" /\ depth > 0

AtomicConsumeAdvancesOneChargedCharacter ==
    lastAction = "AtomicConsume" =>
        /\ classification = "Atomic"
        /\ outcome = "Running"
        /\ position \in 1..SubjectLength
        /\ acceptedPrefix
        /\ steps = position
        /\ steps <= StepMaximum
        /\ depth = 1

AtomicRejectIsOneChargedBoundedProbe ==
    lastAction = "AtomicReject" =>
        /\ classification = "Atomic"
        /\ outcome = "NotMatched"
        /\ position < SubjectLength
        /\ ~currentAccepted
        /\ ~acceptedPrefix
        /\ steps = position + 1
        /\ steps <= StepMaximum
        /\ depth = 1

FallbackAdvancesOneChargedFrame ==
    lastAction = "Fallback" =>
        /\ classification = "NonAtomic"
        /\ outcome = "Running"
        /\ position = 0
        /\ acceptedPrefix
        /\ depth <= DepthMaximum
        /\ steps = depth
        /\ steps <= StepMaximum
        /\ depth \in 1..DepthMaximum

ExhaustionRequiresABudgetBoundary ==
    lastAction = "Exhaust" =>
        /\ outcome = "Exhausted"
        /\ Decision(outcome) = "Deny"
        /\ (steps = StepMaximum \/ depth = DepthMaximum)

=============================================================================
