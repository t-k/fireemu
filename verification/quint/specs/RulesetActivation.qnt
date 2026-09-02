// Atomic ruleset publication and immutable request snapshots.

module RulesetActivation {
  const REQUESTS: Set[str]

  type Observable = {
    activeVersion: str,
    generation: int,
    requestVersion: str -> str,
    requestGeneration: str -> int,
  }
  type ActionTaken = { tag: str, value: { request: str } }

  var observable: Observable
  var previousObservable: Observable
  var candidatePhase: str
  var previousCandidatePhase: str
  var requestState: str -> str
  var previousRequestState: str -> str
  var lastAction: str
  var lastRequest: str
  var actionTaken: ActionTaken

  pure val CANDIDATE_PHASES = Set(
    "Absent", "Created", "Parsed", "Compiled", "Checked", "Active", "Rejected"
  )
  pure val REQUEST_STATES = Set("Idle", "Running", "Finished")
  pure val ACTIONS = Set(
    "Init", "Create", "Parse", "Compile", "Check", "Reject", "Activate", "Republish",
    "StartRequest", "ProgressRequest", "FinishRequest"
  )

  action record(actionName, request, nextObservable) = all {
    previousObservable' = observable,
    previousCandidatePhase' = candidatePhase,
    previousRequestState' = requestState,
    observable' = nextObservable,
    lastAction' = actionName,
    lastRequest' = request,
    actionTaken' = { tag: actionName, value: { request: request } },
  }

  action init = {
    val initial = {
      activeVersion: "v1",
      generation: 0,
      requestVersion: REQUESTS.mapBy(_ => "v1"),
      requestGeneration: REQUESTS.mapBy(_ => 0),
    }
    all {
      observable' = initial,
      previousObservable' = initial,
      candidatePhase' = "Absent",
      previousCandidatePhase' = "Absent",
      requestState' = REQUESTS.mapBy(_ => "Idle"),
      previousRequestState' = REQUESTS.mapBy(_ => "Idle"),
      lastAction' = "Init",
      lastRequest' = "",
      actionTaken' = { tag: "init", value: { request: "" } },
    }
  }

  action create = all {
    candidatePhase == "Absent",
    record("Create", "", observable),
    candidatePhase' = "Created",
    requestState' = requestState,
  }

  action parse = all {
    candidatePhase == "Created",
    record("Parse", "", observable),
    candidatePhase' = "Parsed",
    requestState' = requestState,
  }

  action compile = all {
    candidatePhase == "Parsed",
    record("Compile", "", observable),
    candidatePhase' = "Compiled",
    requestState' = requestState,
  }

  action check = all {
    candidatePhase == "Compiled",
    record("Check", "", observable),
    candidatePhase' = "Checked",
    requestState' = requestState,
  }

  action rejectCandidate = all {
    candidatePhase.in(Set("Created", "Parsed", "Compiled", "Checked")),
    record("Reject", "", observable),
    candidatePhase' = "Rejected",
    requestState' = requestState,
  }

  action publishCandidate = all {
    candidatePhase == "Checked",
    record("Activate", "", {
      activeVersion: "v2",
      generation: observable.generation + 1,
      requestVersion: observable.requestVersion,
      requestGeneration: observable.requestGeneration,
    }),
    candidatePhase' = "Active",
    requestState' = requestState,
  }

  action republish = all {
    candidatePhase == "Active",
    observable.generation < 2,
    record("Republish", "", {
      activeVersion: observable.activeVersion,
      generation: observable.generation + 1,
      requestVersion: observable.requestVersion,
      requestGeneration: observable.requestGeneration,
    }),
    candidatePhase' = candidatePhase,
    requestState' = requestState,
  }

  action startRequest(request) = all {
    requestState.get(request) == "Idle",
    record("StartRequest", request, {
      activeVersion: observable.activeVersion,
      generation: observable.generation,
      requestVersion: observable.requestVersion.set(request, observable.activeVersion),
      requestGeneration: observable.requestGeneration.set(request, observable.generation),
    }),
    candidatePhase' = candidatePhase,
    requestState' = requestState.set(request, "Running"),
  }

  action progressRequest(request) = all {
    requestState.get(request) == "Running",
    record("ProgressRequest", request, observable),
    candidatePhase' = candidatePhase,
    requestState' = requestState,
  }

  action finishRequest(request) = all {
    requestState.get(request) == "Running",
    record("FinishRequest", request, observable),
    candidatePhase' = candidatePhase,
    requestState' = requestState.set(request, "Finished"),
  }

  action Create = create
  action Parse = parse
  action Compile = compile
  action Check = check
  action Reject = rejectCandidate
  action Activate = publishCandidate
  action Republish = republish
  action StartRequest = { nondet request = REQUESTS.oneOf() startRequest(request) }
  action ProgressRequest = { nondet request = REQUESTS.oneOf() progressRequest(request) }
  action FinishRequest = { nondet request = REQUESTS.oneOf() finishRequest(request) }

  action step = any {
    Create,
    Parse,
    Compile,
    Check,
    Reject,
    Activate,
    Republish,
    StartRequest,
    ProgressRequest,
    FinishRequest,
  }

  val TypeOK = and {
    REQUESTS.size() > 0,
    observable.activeVersion.in(Set("v1", "v2")),
    observable.generation >= 0 and observable.generation <= 2,
    observable.requestVersion.keys() == REQUESTS,
    observable.requestGeneration.keys() == REQUESTS,
    REQUESTS.forall(request => observable.requestVersion.get(request).in(Set("v1", "v2"))),
    REQUESTS.forall(request => observable.requestGeneration.get(request) >= 0
      and observable.requestGeneration.get(request) <= 2),
    previousObservable.activeVersion.in(Set("v1", "v2")),
    previousObservable.generation >= 0 and previousObservable.generation <= 2,
    candidatePhase.in(CANDIDATE_PHASES),
    previousCandidatePhase.in(CANDIDATE_PHASES),
    requestState.keys() == REQUESTS,
    previousRequestState.keys() == REQUESTS,
    REQUESTS.forall(request => requestState.get(request).in(REQUEST_STATES)),
    REQUESTS.forall(request => previousRequestState.get(request).in(REQUEST_STATES)),
    lastAction.in(ACTIONS),
    lastRequest == "" or REQUESTS.contains(lastRequest),
  }

  val ActivationRequiresAllChecks =
    (lastAction == "Activate").implies(previousCandidatePhase == "Checked")

  val FailedCandidateNeverActivates =
    (previousCandidatePhase == "Rejected").implies(and {
      observable.activeVersion == previousObservable.activeVersion,
      observable.generation == previousObservable.generation,
    })

  val RequestVersionIsImmutable = REQUESTS.forall(request =>
    (previousRequestState.get(request) == "Running"
      and requestState.get(request).in(Set("Running", "Finished"))).implies(
        observable.requestVersion.get(request) == previousObservable.requestVersion.get(request)
          and observable.requestGeneration.get(request)
            == previousObservable.requestGeneration.get(request)
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
    RequestVersionIsImmutable,
    ActiveVersionChangesAtomically,
  }
}

module RulesetActivationProof {
  import RulesetActivation(REQUESTS = Set("r1", "r2")).*
}

module RulesetActivationScenarios {
  import RulesetActivation(REQUESTS = Set("r1", "r2")).*

  run activate = init.then(Create).then(Parse).then(Compile).then(Check).then(Activate)
    .expect(observable.activeVersion == "v2" and observable.generation == 1)

  run reject = init.then(Create).then(Parse).then(Reject)
    .expect(observable.activeVersion == "v1" and observable.generation == 0)

  run pinRequest = init.then(startRequest("r1")).then(Create).then(Parse).then(Compile)
    .then(Check).then(Activate).then(progressRequest("r1")).then(finishRequest("r1"))
    .expect(observable.activeVersion == "v2"
      and observable.requestVersion.get("r1") == "v1")

  run pinGeneration = init.then(Create).then(Parse).then(Compile).then(Check).then(Activate)
    .then(startRequest("r1")).then(Republish).then(progressRequest("r1"))
    .then(finishRequest("r1"))
    .expect(observable.activeVersion == "v2" and observable.generation == 2
      and observable.requestVersion.get("r1") == "v2"
      and observable.requestGeneration.get("r1") == 1)
}

module RulesetActivationConnect {
  import RulesetActivation(REQUESTS = Set("r1", "r2")).*
}
