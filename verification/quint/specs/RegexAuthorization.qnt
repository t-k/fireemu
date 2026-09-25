// Regex authorization: exhaustion never grants, and a holding allow decides (production and
// the official emulator, FS-RULES 2026-09-24), with production evaluator cases. A request may
// exhaust the regex step budget at most CAP times: past that it stops, whatever holds later.

module RegexAuthorizationLogic {
  type Outcome = Matched | NotMatched | Exhausted

  pure val OUTCOMES = Set(Matched, NotMatched, Exhausted)

  pure def condition(outcome: Outcome, negated: bool): Outcome =
    if (outcome == Exhausted) Exhausted
    else if (negated) {
      if (outcome == Matched) NotMatched else Matched
    } else outcome

  pure def merge(parent: Outcome, nested: Outcome): Outcome =
    if (parent == Matched or nested == Matched) Matched
    else if (parent == Exhausted or nested == Exhausted) Exhausted
    else NotMatched

  pure def authorizationOutcome(
    parent: Outcome,
    nested: Outcome,
    parentNegated: bool,
    nestedNegated: bool
  ): Outcome = merge(condition(parent, parentNegated), condition(nested, nestedNegated))

  pure def decision(outcome: Outcome): str = if (outcome == Matched) "Allow" else "Deny"

  // Exhausted matches a request may have before it stops (REGEX_EXHAUSTIONS_PER_REQUEST_MAX).
  pure val CAP = 4

  pure def exhausted(outcome: Outcome): int = if (outcome == Exhausted) 1 else 0

  // The parent's allow is evaluated first and decides when it holds; otherwise the nested one
  // is evaluated, and the request stops once more than CAP matches exhausted.
  pure def requestDecision(
    prior: int,
    parent: Outcome,
    nested: Outcome,
    parentNegated: bool,
    nestedNegated: bool
  ): str =
    if (condition(parent, parentNegated) == Matched) "Allow"
    else if (prior + exhausted(parent) + exhausted(nested) > CAP) "Deny"
    else decision(authorizationOutcome(parent, nested, parentNegated, nestedNegated))
}

module RegexAuthorizationProof {
  import RegexAuthorizationLogic.*

  var parentOutcome: Outcome
  var nestedOutcome: Outcome
  var parentNegated: bool
  var nestedNegated: bool
  // Matches that exhausted earlier in the same request (the request had not stopped yet).
  var priorExhaustions: int

  pure val PRIORS = 0.to(CAP)

  action choose = {
    nondet nextParent = OUTCOMES.oneOf()
    nondet nextNested = OUTCOMES.oneOf()
    nondet nextParentNegated = Set(false, true).oneOf()
    nondet nextNestedNegated = Set(false, true).oneOf()
    nondet nextPrior = PRIORS.oneOf()
    all {
      parentOutcome' = nextParent,
      nestedOutcome' = nextNested,
      parentNegated' = nextParentNegated,
      nestedNegated' = nextNestedNegated,
      priorExhaustions' = nextPrior,
    }
  }

  action init = {
    nondet initialParent = OUTCOMES.oneOf()
    nondet initialNested = OUTCOMES.oneOf()
    nondet initialParentNegated = Set(false, true).oneOf()
    nondet initialNestedNegated = Set(false, true).oneOf()
    nondet initialPrior = PRIORS.oneOf()
    all {
      parentOutcome' = initialParent,
      nestedOutcome' = initialNested,
      parentNegated' = initialParentNegated,
      nestedNegated' = initialNestedNegated,
      priorExhaustions' = initialPrior,
    }
  }
  action step = choose

  val TypeOK = and {
    parentOutcome.in(OUTCOMES),
    nestedOutcome.in(OUTCOMES),
    priorExhaustions.in(PRIORS),
  }

  // Whether a condition holds, read from the outcome itself (not through `condition`, which
  // the properties check): a match, or a non-match under `!`. Exhaustion never holds.
  pure def holdsFor(outcome: Outcome, negated: bool): bool =
    (outcome == Matched and not(negated)) or (outcome == NotMatched and negated)

  val holds = holdsFor(parentOutcome, parentNegated) or holdsFor(nestedOutcome, nestedNegated)

  val decided =
    requestDecision(priorExhaustions, parentOutcome, nestedOutcome, parentNegated, nestedNegated)

  // Counted from the outcomes, not through requestDecision: the parent holding ends the
  // evaluation first; otherwise both conditions ran, and each exhaustion counts.
  val parentHolds = holdsFor(parentOutcome, parentNegated)
  val exhaustionsSeen =
    priorExhaustions
      + (if (parentOutcome == Exhausted) 1 else 0)
      + (if (not(parentHolds) and nestedOutcome == Exhausted) 1 else 0)
  val stopped = exhaustionsSeen > 4

  // An exhausted condition never grants: only a condition that holds allows.
  val ExhaustionNeverAllows = (decided == "Allow").implies(holds)

  // Allow statements are alternatives: one that holds allows whatever the other raises, until
  // the request has exhausted too many matches.
  val AlternativesDecide = (holds and not(stopped)).implies(decided == "Allow")

  // Past the cap the request stops: nothing evaluated after it allows.
  val CapStops = stopped.implies(decided == "Deny")
}

module RegexAuthorizationConnect {
  type Observable = { lastCase: str, decision: str, denialClass: str }
  type ActionTaken = { tag: str, value: { case: str } }

  pure val CASES = Set(
    "matched",
    "notMatched",
    "stepExhausted",
    "depthExhausted",
    "exhaustedBesideAllow",
    "exhaustedPastCap",
    "parentNegated",
    "nestedNegated"
  )

  var observable: Observable
  var actionTaken: ActionTaken

  pure def expectedDecision(case: str): str =
    if (case.in(Set("matched", "nestedNegated", "exhaustedBesideAllow"))) "Allow" else "Deny"

  pure def expectedDenialClass(case: str): str =
    if (case.in(Set("matched", "nestedNegated", "exhaustedBesideAllow"))) "None"
    else if (case == "stepExhausted") "FIREEMU-REGEX-STEPS-PER-MATCH"
    else if (case == "depthExhausted") "FIREEMU-REGEX-DEPTH-PER-MATCH"
    else if (case == "exhaustedPastCap") "FIREEMU-REGEX-EXHAUSTIONS-PER-REQUEST"
    else "RuleMismatch"

  action init = all {
    observable' = { lastCase: "none", decision: "Deny", denialClass: "NotEvaluated" },
    actionTaken' = { tag: "init", value: { case: "none" } },
  }

  action evaluateCase(case) = all {
    observable.lastCase == "none",
    case.in(CASES),
    observable' = {
      lastCase: case,
      decision: expectedDecision(case),
      denialClass: expectedDenialClass(case),
    },
    actionTaken' = { tag: "Evaluate", value: { case: case } },
  }

  action Evaluate = {
    nondet case = CASES.oneOf()
    evaluateCase(case)
  }

  action step = Evaluate
}

module RegexAuthorizationScenarios {
  import RegexAuthorizationConnect.*

  run matched = init.then(evaluateCase("matched"))
    .expect(observable.decision == "Allow" and observable.denialClass == "None")

  run notMatched = init.then(evaluateCase("notMatched"))
    .expect(observable.decision == "Deny" and observable.denialClass == "RuleMismatch")

  run stepExhausted = init.then(evaluateCase("stepExhausted"))
    .expect(observable.decision == "Deny" and observable.denialClass == "FIREEMU-REGEX-STEPS-PER-MATCH")

  run depthExhausted = init.then(evaluateCase("depthExhausted"))
    .expect(observable.decision == "Deny" and observable.denialClass == "FIREEMU-REGEX-DEPTH-PER-MATCH")

  run exhaustedBesideAllow = init.then(evaluateCase("exhaustedBesideAllow"))
    .expect(observable.decision == "Allow" and observable.denialClass == "None")

  run exhaustedPastCap = init.then(evaluateCase("exhaustedPastCap"))
    .expect(observable.decision == "Deny" and observable.denialClass == "FIREEMU-REGEX-EXHAUSTIONS-PER-REQUEST")

  run parentNegated = init.then(evaluateCase("parentNegated"))
    .expect(observable.decision == "Deny" and observable.denialClass == "RuleMismatch")

  run nestedNegated = init.then(evaluateCase("nestedNegated"))
    .expect(observable.decision == "Allow" and observable.denialClass == "None")
}
