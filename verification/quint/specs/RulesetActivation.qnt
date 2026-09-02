// Atomic ruleset publication and immutable evaluation snapshots.

module RulesetActivation {
  const EVALUATIONS: Set[str]

  type Observable = {
    activeVersion: str,
    generation: int,
    evaluationVersion: str -> str,
    evaluationGeneration: str -> int,
  }
  type ActionTaken = { tag: str, value: { evaluation: str } }

  var observable: Observable
  var previousObservable: Observable
  var candidatePhase: str
  var previousCandidatePhase: str
  var evaluationState: str -> str
  var previousEvaluationState: str -> str
  var lastAction: str
  var lastEvaluation: str
  var actionTaken: ActionTaken

  pure val CANDIDATE_PHASES = Set(
    "Absent", "Created", "Parsed", "Compiled", "Checked", "Active", "Rejected"
  )
  pure val REQUEST_STATES = Set("Idle", "Running", "Finished")
  pure val ACTIONS = Set(
    "Init", "Create", "Parse", "Compile", "Check", "Reject", "Activate", "Republish",
    "StartEvaluation", "ProgressEvaluation", "FinishEvaluation"
  )

  action record(actionName, evaluation, nextObservable) = all {
    previousObservable' = observable,
    previousCandidatePhase' = candidatePhase,
    previousEvaluationState' = evaluationState,
    observable' = nextObservable,
    lastAction' = actionName,
    lastEvaluation' = evaluation,
    actionTaken' = { tag: actionName, value: { evaluation: evaluation } },
  }

  action init = {
    val initial = {
      activeVersion: "v1",
      generation: 0,
      evaluationVersion: EVALUATIONS.mapBy(_ => "v1"),
      evaluationGeneration: EVALUATIONS.mapBy(_ => 0),
    }
    all {
      observable' = initial,
      previousObservable' = initial,
      candidatePhase' = "Absent",
      previousCandidatePhase' = "Absent",
      evaluationState' = EVALUATIONS.mapBy(_ => "Idle"),
      previousEvaluationState' = EVALUATIONS.mapBy(_ => "Idle"),
      lastAction' = "Init",
      lastEvaluation' = "",
      actionTaken' = { tag: "init", value: { evaluation: "" } },
    }
  }

  action create = all {
    candidatePhase == "Absent",
    record("Create", "", observable),
    candidatePhase' = "Created",
    evaluationState' = evaluationState,
  }

  action parse = all {
    candidatePhase == "Created",
    record("Parse", "", observable),
    candidatePhase' = "Parsed",
    evaluationState' = evaluationState,
  }

  action compile = all {
    candidatePhase == "Parsed",
    record("Compile", "", observable),
    candidatePhase' = "Compiled",
    evaluationState' = evaluationState,
  }

  action check = all {
    candidatePhase == "Compiled",
    record("Check", "", observable),
    candidatePhase' = "Checked",
    evaluationState' = evaluationState,
  }

  action rejectCandidate = all {
    candidatePhase.in(Set("Created", "Parsed", "Compiled", "Checked")),
    record("Reject", "", observable),
    candidatePhase' = "Rejected",
    evaluationState' = evaluationState,
  }

  action publishCandidate = all {
    candidatePhase == "Checked",
    record("Activate", "", {
      activeVersion: "v2",
      generation: observable.generation + 1,
      evaluationVersion: observable.evaluationVersion,
      evaluationGeneration: observable.evaluationGeneration,
    }),
    candidatePhase' = "Active",
    evaluationState' = evaluationState,
  }

  action republish = all {
    candidatePhase == "Active",
    observable.generation < 2,
    record("Republish", "", {
      activeVersion: observable.activeVersion,
      generation: observable.generation + 1,
      evaluationVersion: observable.evaluationVersion,
      evaluationGeneration: observable.evaluationGeneration,
    }),
    candidatePhase' = candidatePhase,
    evaluationState' = evaluationState,
  }

  action startEvaluation(evaluation) = all {
    evaluationState.get(evaluation) == "Idle",
    record("StartEvaluation", evaluation, {
      activeVersion: observable.activeVersion,
      generation: observable.generation,
      evaluationVersion: observable.evaluationVersion.set(evaluation, observable.activeVersion),
      evaluationGeneration: observable.evaluationGeneration.set(evaluation, observable.generation),
    }),
    candidatePhase' = candidatePhase,
    evaluationState' = evaluationState.set(evaluation, "Running"),
  }

  action progressEvaluation(evaluation) = all {
    evaluationState.get(evaluation) == "Running",
    record("ProgressEvaluation", evaluation, observable),
    candidatePhase' = candidatePhase,
    evaluationState' = evaluationState,
  }

  action finishEvaluation(evaluation) = all {
    evaluationState.get(evaluation) == "Running",
    record("FinishEvaluation", evaluation, observable),
    candidatePhase' = candidatePhase,
    evaluationState' = evaluationState.set(evaluation, "Finished"),
  }

  action Create = create
  action Parse = parse
  action Compile = compile
  action Check = check
  action Reject = rejectCandidate
  action Activate = publishCandidate
  action Republish = republish
  action StartEvaluation = { nondet evaluation = EVALUATIONS.oneOf() startEvaluation(evaluation) }
  action ProgressEvaluation = { nondet evaluation = EVALUATIONS.oneOf() progressEvaluation(evaluation) }
  action FinishEvaluation = { nondet evaluation = EVALUATIONS.oneOf() finishEvaluation(evaluation) }

  action step = any {
    Create,
    Parse,
    Compile,
    Check,
    Reject,
    Activate,
    Republish,
    StartEvaluation,
    ProgressEvaluation,
    FinishEvaluation,
  }

  val TypeOK = and {
    EVALUATIONS.size() > 0,
    observable.activeVersion.in(Set("v1", "v2")),
    observable.generation >= 0 and observable.generation <= 2,
    observable.evaluationVersion.keys() == EVALUATIONS,
    observable.evaluationGeneration.keys() == EVALUATIONS,
    EVALUATIONS.forall(evaluation => observable.evaluationVersion.get(evaluation).in(Set("v1", "v2"))),
    EVALUATIONS.forall(evaluation => observable.evaluationGeneration.get(evaluation) >= 0
      and observable.evaluationGeneration.get(evaluation) <= 2),
    previousObservable.activeVersion.in(Set("v1", "v2")),
    previousObservable.generation >= 0 and previousObservable.generation <= 2,
    candidatePhase.in(CANDIDATE_PHASES),
    previousCandidatePhase.in(CANDIDATE_PHASES),
    evaluationState.keys() == EVALUATIONS,
    previousEvaluationState.keys() == EVALUATIONS,
    EVALUATIONS.forall(evaluation => evaluationState.get(evaluation).in(REQUEST_STATES)),
    EVALUATIONS.forall(evaluation => previousEvaluationState.get(evaluation).in(REQUEST_STATES)),
    lastAction.in(ACTIONS),
    lastEvaluation == "" or EVALUATIONS.contains(lastEvaluation),
  }

  val ActivationRequiresAllChecks =
    (lastAction == "Activate").implies(previousCandidatePhase == "Checked")

  val FailedCandidateNeverActivates =
    (previousCandidatePhase == "Rejected").implies(and {
      observable.activeVersion == previousObservable.activeVersion,
      observable.generation == previousObservable.generation,
    })

  val EvaluationSnapshotIsImmutable = EVALUATIONS.forall(evaluation =>
    (previousEvaluationState.get(evaluation) == "Running"
      and evaluationState.get(evaluation).in(Set("Running", "Finished"))).implies(
        observable.evaluationVersion.get(evaluation) == previousObservable.evaluationVersion.get(evaluation)
          and observable.evaluationGeneration.get(evaluation)
            == previousObservable.evaluationGeneration.get(evaluation)
      )
  )

  val ActiveVersionChangesAtomically =
    (observable.activeVersion != previousObservable.activeVersion
      or observable.generation != previousObservable.generation).implies(and {
        lastAction.in(Set("Activate", "Republish")),
        candidatePhase == "Active",
        observable.activeVersion == "v2",
        observable.generation == previousObservable.generation + 1,
      })

  val AtomicRulesetActivation = and {
    ActivationRequiresAllChecks,
    FailedCandidateNeverActivates,
    EvaluationSnapshotIsImmutable,
    ActiveVersionChangesAtomically,
  }
}

module RulesetActivationProof {
  import RulesetActivation(EVALUATIONS = Set("r1", "r2")).*
}

module RulesetActivationScenarios {
  import RulesetActivation(EVALUATIONS = Set("r1", "r2")).*

  run activate = init.then(Create).then(Parse).then(Compile).then(Check).then(Activate)
    .expect(observable.activeVersion == "v2" and observable.generation == 1)

  run reject = init.then(Create).then(Parse).then(Reject)
    .expect(observable.activeVersion == "v1" and observable.generation == 0)

  run pinEvaluation = init.then(startEvaluation("r1")).then(Create).then(Parse).then(Compile)
    .then(Check).then(Activate).then(progressEvaluation("r1")).then(finishEvaluation("r1"))
    .expect(observable.activeVersion == "v2"
      and observable.evaluationVersion.get("r1") == "v1")

  run pinGeneration = init.then(Create).then(Parse).then(Compile).then(Check).then(Activate)
    .then(startEvaluation("r1")).then(Republish).then(progressEvaluation("r1"))
    .then(finishEvaluation("r1"))
    .expect(observable.activeVersion == "v2" and observable.generation == 2
      and observable.evaluationVersion.get("r1") == "v2"
      and observable.evaluationGeneration.get("r1") == 1)
}

module RulesetActivationConnect {
  import RulesetActivation(EVALUATIONS = Set("r1", "r2")).*
}
