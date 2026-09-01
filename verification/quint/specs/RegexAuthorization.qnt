// Regex authorization exhaustion precedence and production evaluator cases.

module RegexAuthorizationLogic {
  type Outcome = Matched | NotMatched | Exhausted

  pure val OUTCOMES = Set(Matched, NotMatched, Exhausted)

  pure def condition(outcome: Outcome, negated: bool): Outcome =
    if (outcome == Exhausted) Exhausted
    else if (negated) {
      if (outcome == Matched) NotMatched else Matched
    } else outcome

  pure def merge(parent: Outcome, nested: Outcome): Outcome =
    if (parent == Exhausted or nested == Exhausted) Exhausted
    else if (parent == Matched or nested == Matched) Matched
    else NotMatched

  pure def authorizationOutcome(
    parent: Outcome,
    nested: Outcome,
    parentNegated: bool,
    nestedNegated: bool
  ): Outcome = merge(condition(parent, parentNegated), condition(nested, nestedNegated))

  pure def decision(outcome: Outcome): str = if (outcome == Matched) "Allow" else "Deny"
}

module RegexAuthorizationProof {
  import RegexAuthorizationLogic.*

  var parentOutcome: Outcome
  var nestedOutcome: Outcome
  var parentNegated: bool
  var nestedNegated: bool

  action choose = {
    nondet nextParent = OUTCOMES.oneOf()
    nondet nextNested = OUTCOMES.oneOf()
    nondet nextParentNegated = Set(false, true).oneOf()
    nondet nextNestedNegated = Set(false, true).oneOf()
    all {
      parentOutcome' = nextParent,
      nestedOutcome' = nextNested,
      parentNegated' = nextParentNegated,
      nestedNegated' = nextNestedNegated,
    }
  }

  action init = {
    nondet initialParent = OUTCOMES.oneOf()
    nondet initialNested = OUTCOMES.oneOf()
    nondet initialParentNegated = Set(false, true).oneOf()
    nondet initialNestedNegated = Set(false, true).oneOf()
    all {
      parentOutcome' = initialParent,
      nestedOutcome' = initialNested,
      parentNegated' = initialParentNegated,
      nestedNegated' = initialNestedNegated,
    }
  }
  action step = choose

  val TypeOK = and {
    parentOutcome.in(OUTCOMES),
    nestedOutcome.in(OUTCOMES),
  }

  val ExhaustionNeverAllows =
    (parentOutcome == Exhausted or nestedOutcome == Exhausted).implies(
      decision(authorizationOutcome(
        parentOutcome,
        nestedOutcome,
        parentNegated,
        nestedNegated
      )) == "Deny"
    )
}

module RegexAuthorizationConnect {
  type Observable = { lastCase: str, decision: str, denialClass: str }
  type ActionTaken = { tag: str, value: { case: str } }

  pure val CASES = Set(
    "matched",
    "notMatched",
    "stepExhausted",
    "depthExhausted",
    "parentNegated",
    "nestedNegated"
  )

  var observable: Observable
  var actionTaken: ActionTaken

  pure def expectedDecision(case: str): str =
    if (case.in(Set("matched", "nestedNegated"))) "Allow" else "Deny"

  pure def expectedDenialClass(case: str): str =
    if (case.in(Set("matched", "nestedNegated"))) "None"
    else if (case == "stepExhausted") "FIREEMU-REGEX-STEPS-PER-MATCH"
    else if (case == "depthExhausted") "FIREEMU-REGEX-DEPTH-PER-MATCH"
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

  run parentNegated = init.then(evaluateCase("parentNegated"))
    .expect(observable.decision == "Deny" and observable.denialClass == "RuleMismatch")

  run nestedNegated = init.then(evaluateCase("nestedNegated"))
    .expect(observable.decision == "Allow" and observable.denialClass == "None")
}
