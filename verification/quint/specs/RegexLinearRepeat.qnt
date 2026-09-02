// Bounded linear repeated alternatives and fail-closed regex budgets.

module RegexLinearRepeatProof {
  pure val SUBJECT_LENGTH = 3
  pure val STEP_MAXIMUM = 4
  pure val DEPTH_MAXIMUM = 2
  pure val BRANCH_COUNT = 3

  type Classification = Atomic | NonAtomic
  type Outcome = Running | Matched | NotMatched | Exhausted

  var position: int
  var steps: int
  var depth: int
  var classification: Classification
  var currentAccepted: bool
  var matchingProbe: int
  var probe: int
  var probesForCharacter: int
  var attemptedProbes: int
  var chargedProbes: int
  var acceptedPrefix: bool
  var outcome: Outcome
  var exhaustSourceOutcome: Outcome
  var lastAction: str

  action init = {
    nondet initialClassification = Set(Atomic, NonAtomic).oneOf()
    nondet initialAccepted = Set(false, true).oneOf()
    nondet initialProbe = 1.to(BRANCH_COUNT + 1).oneOf()
    all {
      initialProbe.in(if (initialAccepted) 1.to(BRANCH_COUNT) else Set(BRANCH_COUNT + 1)),
      position' = 0,
      steps' = 0,
      depth' = if (initialClassification == Atomic) 1 else 0,
      classification' = initialClassification,
      currentAccepted' = initialAccepted,
      matchingProbe' = initialProbe,
      probe' = 1,
      probesForCharacter' = 0,
      attemptedProbes' = 0,
      chargedProbes' = 0,
      acceptedPrefix' = true,
      outcome' = Running,
      exhaustSourceOutcome' = Running,
      lastAction' = "Init",
    }
  }

  action atomicProbeMiss = all {
    classification == Atomic, outcome == Running, position < SUBJECT_LENGTH,
    steps < STEP_MAXIMUM, probe < matchingProbe, probe < BRANCH_COUNT,
    position' = position,
    steps' = steps + 1,
    depth' = depth,
    classification' = classification,
    currentAccepted' = currentAccepted,
    matchingProbe' = matchingProbe,
    probe' = probe + 1,
    probesForCharacter' = probesForCharacter + 1,
    attemptedProbes' = attemptedProbes + 1,
    chargedProbes' = chargedProbes + 1,
    acceptedPrefix' = acceptedPrefix,
    outcome' = outcome,
    exhaustSourceOutcome' = exhaustSourceOutcome,
    lastAction' = "AtomicProbeMiss",
  }

  action atomicConsume = {
    nondet nextAccepted = Set(false, true).oneOf()
    nondet nextProbe = 1.to(BRANCH_COUNT + 1).oneOf()
    all {
      nextProbe.in(if (nextAccepted) 1.to(BRANCH_COUNT) else Set(BRANCH_COUNT + 1)),
      classification == Atomic, outcome == Running, position < SUBJECT_LENGTH,
      steps < STEP_MAXIMUM, currentAccepted, probe == matchingProbe,
      position' = position + 1,
      steps' = steps + 1,
      depth' = depth,
      classification' = classification,
      currentAccepted' = nextAccepted,
      matchingProbe' = nextProbe,
      probe' = 1,
      probesForCharacter' = 0,
      attemptedProbes' = attemptedProbes + 1,
      chargedProbes' = chargedProbes + 1,
      acceptedPrefix' = acceptedPrefix,
      outcome' = outcome,
      exhaustSourceOutcome' = exhaustSourceOutcome,
      lastAction' = "AtomicConsume",
    }
  }

  action atomicReject = all {
    classification == Atomic, outcome == Running, position < SUBJECT_LENGTH,
    steps < STEP_MAXIMUM, not(currentAccepted), matchingProbe == BRANCH_COUNT + 1,
    probe == BRANCH_COUNT,
    position' = position,
    steps' = steps + 1,
    depth' = depth,
    classification' = classification,
    currentAccepted' = currentAccepted,
    matchingProbe' = matchingProbe,
    probe' = probe,
    probesForCharacter' = probesForCharacter + 1,
    attemptedProbes' = attemptedProbes + 1,
    chargedProbes' = chargedProbes + 1,
    acceptedPrefix' = false,
    outcome' = NotMatched,
    exhaustSourceOutcome' = exhaustSourceOutcome,
    lastAction' = "AtomicReject",
  }

  action atomicFinish = all {
    classification == Atomic, outcome == Running, position == SUBJECT_LENGTH,
    position' = position, steps' = steps, depth' = depth,
    classification' = classification, currentAccepted' = currentAccepted,
    matchingProbe' = matchingProbe, probe' = probe,
    probesForCharacter' = probesForCharacter, attemptedProbes' = attemptedProbes,
    chargedProbes' = chargedProbes, acceptedPrefix' = acceptedPrefix,
    outcome' = Matched, exhaustSourceOutcome' = exhaustSourceOutcome,
    lastAction' = "AtomicFinish",
  }

  action fallback = all {
    classification == NonAtomic, outcome == Running,
    steps < STEP_MAXIMUM, depth < DEPTH_MAXIMUM,
    position' = position, steps' = steps + 1, depth' = depth + 1,
    classification' = classification, currentAccepted' = currentAccepted,
    matchingProbe' = matchingProbe, probe' = probe,
    probesForCharacter' = probesForCharacter, attemptedProbes' = attemptedProbes,
    chargedProbes' = chargedProbes, acceptedPrefix' = acceptedPrefix,
    outcome' = outcome, exhaustSourceOutcome' = exhaustSourceOutcome,
    lastAction' = "Fallback",
  }

  action exhaust = all {
    outcome == Running, (steps == STEP_MAXIMUM or depth == DEPTH_MAXIMUM),
    position' = position, steps' = steps, depth' = depth,
    classification' = classification, currentAccepted' = currentAccepted,
    matchingProbe' = matchingProbe, probe' = probe,
    probesForCharacter' = probesForCharacter, attemptedProbes' = attemptedProbes,
    chargedProbes' = chargedProbes, acceptedPrefix' = acceptedPrefix,
    outcome' = Exhausted, exhaustSourceOutcome' = outcome,
    lastAction' = "Exhaust",
  }

  action AtomicProbeMiss = atomicProbeMiss
  action AtomicConsume = atomicConsume
  action AtomicReject = atomicReject
  action AtomicFinish = atomicFinish
  action Fallback = fallback
  action Exhaust = exhaust
  action step = any { AtomicProbeMiss, AtomicConsume, AtomicReject, AtomicFinish, Fallback, Exhaust }

  val TypeOK = and {
    position >= 0 and position <= SUBJECT_LENGTH,
    steps >= 0, depth >= 0,
    probe >= 1 and probe <= BRANCH_COUNT,
    probesForCharacter >= 0 and probesForCharacter <= BRANCH_COUNT,
    attemptedProbes >= 0, chargedProbes >= 0,
    lastAction.in(Set("Init", "AtomicProbeMiss", "AtomicConsume", "AtomicReject", "AtomicFinish", "Fallback", "Exhaust")),
  }
  val AtomicProgressDoesNotIncreaseDepth = (classification == Atomic).implies(depth == 1)
  val MatchedImpliesEveryCharacterAccepted = (outcome == Matched).implies(position == SUBJECT_LENGTH and acceptedPrefix)
  val ForbiddenCharacterNeverMatches = not(acceptedPrefix).implies(outcome != Matched)
  val WorkIsCharged = (position > 0).implies(steps >= position)
  val EveryAtomicBranchProbeIsCharged = attemptedProbes == chargedProbes
  val ExhaustionStartsOnlyFromRunning = (lastAction == "Exhaust").implies(exhaustSourceOutcome == Running)
  val BudgetExhaustionNeverMatches = (lastAction == "Exhaust").implies(outcome == Exhausted)
  val NonAtomicFallsBack = (lastAction == "Fallback").implies(classification == NonAtomic and depth > 0)
  val AtomicConsumeAdvancesOneChargedCharacter = (lastAction == "AtomicConsume").implies(and {
    classification == Atomic, outcome == Running, position >= 1 and position <= SUBJECT_LENGTH,
    acceptedPrefix, probe == 1, probesForCharacter == 0,
    steps == chargedProbes, chargedProbes == attemptedProbes,
    steps <= STEP_MAXIMUM, depth == 1,
  })
  val AtomicProbeMissAdvancesOneChargedProbe = (lastAction == "AtomicProbeMiss").implies(and {
    classification == Atomic, outcome == Running, position < SUBJECT_LENGTH,
    probe >= 2 and probe <= BRANCH_COUNT, probesForCharacter == probe - 1,
    steps == chargedProbes, chargedProbes == attemptedProbes, depth == 1,
  })
  val AtomicRejectIsOneChargedBoundedProbe = (lastAction == "AtomicReject").implies(and {
    classification == Atomic, outcome == NotMatched, position < SUBJECT_LENGTH,
    not(currentAccepted), not(acceptedPrefix), probesForCharacter == BRANCH_COUNT,
    steps == chargedProbes, chargedProbes == attemptedProbes,
    steps <= STEP_MAXIMUM, depth == 1,
  })
  val FallbackAdvancesOneChargedFrame = (lastAction == "Fallback").implies(and {
    classification == NonAtomic, outcome == Running, position == 0, acceptedPrefix,
    depth <= DEPTH_MAXIMUM, steps == depth, steps <= STEP_MAXIMUM, depth >= 1,
  })
  val ExhaustionRequiresABudgetBoundary = (lastAction == "Exhaust").implies(and {
    outcome == Exhausted, steps == STEP_MAXIMUM or depth == DEPTH_MAXIMUM,
  })
}

module RegexLinearRepeatConnect {
  type Observable = { lastCase: str, outcome: str, workClass: str, depthClass: str, probeAccounting: str }
  type ActionTaken = { tag: str, value: { case: str } }
  pure val CASES = Set("atomicFirst", "atomicThird", "forbidden", "nonAtomic", "exhausted")
  var observable: Observable
  var actionTaken: ActionTaken
  pure def expected(case: str): Observable = {
    lastCase: case,
    outcome: if (case.in(Set("atomicFirst", "atomicThird", "nonAtomic"))) "Matched"
      else if (case == "forbidden") "NotMatched" else "Exhausted",
    workClass: if (case == "atomicFirst") "FirstBranch"
      else if (case == "atomicThird") "ThirdBranch"
      else if (case == "forbidden") "Rejected"
      else if (case == "nonAtomic") "Fallback" else "Exhausted",
    depthClass: if (case == "nonAtomic") "Nested" else "Constant",
    probeAccounting: "Charged",
  }
  action init = all {
    observable' = { lastCase: "none", outcome: "Running", workClass: "None", depthClass: "None", probeAccounting: "None" },
    actionTaken' = { tag: "init", value: { case: "none" } },
  }
  action evaluateCase(case) = all {
    observable.lastCase == "none", case.in(CASES),
    observable' = expected(case),
    actionTaken' = { tag: "Evaluate", value: { case: case } },
  }
  action Evaluate = { nondet case = CASES.oneOf() evaluateCase(case) }
  action step = Evaluate
}

module RegexLinearRepeatScenarios {
  import RegexLinearRepeatConnect.*
  run atomicFirst = init.then(evaluateCase("atomicFirst"))
  run atomicThird = init.then(evaluateCase("atomicThird"))
  run forbidden = init.then(evaluateCase("forbidden"))
  run nonAtomic = init.then(evaluateCase("nonAtomic"))
  run exhausted = init.then(evaluateCase("exhausted"))
}
