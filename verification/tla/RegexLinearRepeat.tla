------------------------- MODULE RegexLinearRepeat -------------------------
EXTENDS Naturals, TLC

CONSTANTS SubjectLength, StepMaximum, DepthMaximum, BranchCount

Classifications == {"Atomic", "NonAtomic"}
Outcomes == {"Running", "Matched", "NotMatched", "Exhausted"}
Actions == {"Init", "AtomicProbeMiss", "AtomicConsume", "AtomicReject", "AtomicFinish", "Fallback", "Exhaust"}

VARIABLES position, steps, depth, classification, currentAccepted,
          matchingProbe, probe, probesForCharacter, attemptedProbes,
          chargedProbes, acceptedPrefix, outcome, exhaustSourceOutcome, lastAction

vars == <<position, steps, depth, classification, currentAccepted,
          matchingProbe, probe, probesForCharacter, attemptedProbes,
          chargedProbes, acceptedPrefix, outcome, exhaustSourceOutcome, lastAction>>

TypeOK ==
    /\ position \in 0..SubjectLength
    /\ steps \in Nat
    /\ depth \in Nat
    /\ classification \in Classifications
    /\ currentAccepted \in BOOLEAN
    /\ matchingProbe \in 1..(BranchCount + 1)
    /\ probe \in 1..BranchCount
    /\ probesForCharacter \in 0..BranchCount
    /\ attemptedProbes \in Nat
    /\ chargedProbes \in Nat
    /\ acceptedPrefix \in BOOLEAN
    /\ outcome \in Outcomes
    /\ exhaustSourceOutcome \in Outcomes
    /\ lastAction \in Actions

Init ==
    /\ position = 0
    /\ steps = 0
    /\ classification \in Classifications
    /\ depth = IF classification = "Atomic" THEN 1 ELSE 0
    /\ currentAccepted \in BOOLEAN
    /\ matchingProbe \in IF currentAccepted THEN 1..BranchCount ELSE {BranchCount + 1}
    /\ probe = 1
    /\ probesForCharacter = 0
    /\ attemptedProbes = 0
    /\ chargedProbes = 0
    /\ acceptedPrefix = TRUE
    /\ outcome = "Running"
    /\ exhaustSourceOutcome = "Running"
    /\ lastAction = "Init"

AtomicProbeMiss ==
    /\ classification = "Atomic"
    /\ outcome = "Running"
    /\ position < SubjectLength
    /\ steps < StepMaximum
    /\ probe < matchingProbe
    /\ probe < BranchCount
    /\ steps' = steps + 1
    /\ attemptedProbes' = attemptedProbes + 1
    /\ chargedProbes' = chargedProbes + 1
    /\ probesForCharacter' = probesForCharacter + 1
    /\ probe' = probe + 1
    /\ lastAction' = "AtomicProbeMiss"
    /\ UNCHANGED <<position, depth, classification, currentAccepted,
                    matchingProbe, acceptedPrefix, outcome, exhaustSourceOutcome>>

AtomicConsume ==
    /\ classification = "Atomic"
    /\ outcome = "Running"
    /\ position < SubjectLength
    /\ steps < StepMaximum
    /\ currentAccepted
    /\ probe = matchingProbe
    /\ position' = position + 1
    /\ steps' = steps + 1
    /\ depth' = depth
    /\ currentAccepted' \in BOOLEAN
    /\ matchingProbe' \in IF currentAccepted' THEN 1..BranchCount ELSE {BranchCount + 1}
    /\ probe' = 1
    /\ probesForCharacter' = 0
    /\ attemptedProbes' = attemptedProbes + 1
    /\ chargedProbes' = chargedProbes + 1
    /\ acceptedPrefix' = acceptedPrefix
    /\ outcome' = outcome
    /\ lastAction' = "AtomicConsume"
    /\ UNCHANGED <<classification, exhaustSourceOutcome>>

AtomicReject ==
    /\ classification = "Atomic"
    /\ outcome = "Running"
    /\ position < SubjectLength
    /\ steps < StepMaximum
    /\ ~currentAccepted
    /\ matchingProbe = BranchCount + 1
    /\ probe = BranchCount
    /\ steps' = steps + 1
    /\ attemptedProbes' = attemptedProbes + 1
    /\ chargedProbes' = chargedProbes + 1
    /\ probesForCharacter' = probesForCharacter + 1
    /\ acceptedPrefix' = FALSE
    /\ outcome' = "NotMatched"
    /\ lastAction' = "AtomicReject"
    /\ UNCHANGED <<position, depth, classification, currentAccepted,
                    matchingProbe, probe, exhaustSourceOutcome>>

AtomicFinish ==
    /\ classification = "Atomic"
    /\ outcome = "Running"
    /\ position = SubjectLength
    /\ outcome' = "Matched"
    /\ lastAction' = "AtomicFinish"
    /\ UNCHANGED <<position, steps, depth, classification, currentAccepted,
                    matchingProbe, probe, probesForCharacter, attemptedProbes,
                    chargedProbes, acceptedPrefix, exhaustSourceOutcome>>

Fallback ==
    /\ classification = "NonAtomic"
    /\ outcome = "Running"
    /\ steps < StepMaximum
    /\ depth < DepthMaximum
    /\ steps' = steps + 1
    /\ depth' = depth + 1
    /\ lastAction' = "Fallback"
    /\ UNCHANGED <<position, classification, currentAccepted, matchingProbe,
                    probe, probesForCharacter, attemptedProbes, chargedProbes,
                    acceptedPrefix, outcome, exhaustSourceOutcome>>

Exhaust ==
    /\ outcome = "Running"
    /\ steps = StepMaximum \/ depth = DepthMaximum
    /\ exhaustSourceOutcome' = outcome
    /\ outcome' = "Exhausted"
    /\ lastAction' = "Exhaust"
    /\ UNCHANGED <<position, steps, depth, classification, currentAccepted,
                    matchingProbe, probe, probesForCharacter, attemptedProbes,
                    chargedProbes, acceptedPrefix>>

Terminal ==
    /\ outcome # "Running"
    /\ UNCHANGED vars

Next == AtomicProbeMiss \/ AtomicConsume \/ AtomicReject \/ AtomicFinish \/ Fallback \/ Exhaust \/ Terminal

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

EveryAtomicBranchProbeIsCharged ==
    attemptedProbes = chargedProbes

ExhaustionStartsOnlyFromRunning ==
    lastAction = "Exhaust" => exhaustSourceOutcome = "Running"

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
        /\ probe = 1
        /\ probesForCharacter = 0
        /\ steps = chargedProbes
        /\ chargedProbes = attemptedProbes
        /\ steps <= StepMaximum
        /\ depth = 1

AtomicProbeMissAdvancesOneChargedProbe ==
    lastAction = "AtomicProbeMiss" =>
        /\ classification = "Atomic"
        /\ outcome = "Running"
        /\ position < SubjectLength
        /\ probe \in 2..BranchCount
        /\ probesForCharacter = probe - 1
        /\ steps = chargedProbes
        /\ chargedProbes = attemptedProbes
        /\ depth = 1

AtomicRejectIsOneChargedBoundedProbe ==
    lastAction = "AtomicReject" =>
        /\ classification = "Atomic"
        /\ outcome = "NotMatched"
        /\ position < SubjectLength
        /\ ~currentAccepted
        /\ ~acceptedPrefix
        /\ probesForCharacter = BranchCount
        /\ steps = chargedProbes
        /\ chargedProbes = attemptedProbes
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
