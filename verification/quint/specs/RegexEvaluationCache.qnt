// Request-local regular expression compilation and bounded dynamic-pattern reuse.

module RegexEvaluationCacheProof {
  pure val CACHE_CAPACITY = 16
  pure val MAX_OPERATIONS = 18
  pure val MAX_EVALUATIONS = 2

  type Mode = Idle | Active | Done

  var mode: Mode
  var evaluation: int
  var cacheEntries: int
  var trackedPatternCached: bool
  var runtimeCompiles: int
  var cacheHits: int
  var peakCacheEntries: int
  var operations: int
  var previousEvaluation: int
  var previousCacheEntries: int
  var previousTrackedPatternCached: bool
  var previousRuntimeCompiles: int
  var previousCacheHits: int
  var lastAction: str

  action init = all {
    mode' = Idle,
    evaluation' = 0,
    cacheEntries' = 0,
    trackedPatternCached' = false,
    runtimeCompiles' = 0,
    cacheHits' = 0,
    peakCacheEntries' = 0,
    operations' = 0,
    previousEvaluation' = 0,
    previousCacheEntries' = 0,
    previousTrackedPatternCached' = false,
    previousRuntimeCompiles' = 0,
    previousCacheHits' = 0,
    lastAction' = "Init",
  }

  action beginEvaluation = all {
    mode.in(Set(Idle, Done)), evaluation < MAX_EVALUATIONS,
    mode' = Active,
    evaluation' = evaluation + 1,
    cacheEntries' = 0,
    trackedPatternCached' = false,
    runtimeCompiles' = 0,
    cacheHits' = 0,
    peakCacheEntries' = 0,
    operations' = 0,
    previousEvaluation' = evaluation,
    previousCacheEntries' = cacheEntries,
    previousTrackedPatternCached' = trackedPatternCached,
    previousRuntimeCompiles' = runtimeCompiles,
    previousCacheHits' = cacheHits,
    lastAction' = "BeginEvaluation",
  }

  action useLiteral = all {
    mode == Active, operations < MAX_OPERATIONS,
    mode' = mode,
    evaluation' = evaluation,
    cacheEntries' = cacheEntries,
    trackedPatternCached' = trackedPatternCached,
    runtimeCompiles' = runtimeCompiles,
    cacheHits' = cacheHits,
    peakCacheEntries' = peakCacheEntries,
    operations' = operations + 1,
    previousEvaluation' = evaluation,
    previousCacheEntries' = cacheEntries,
    previousTrackedPatternCached' = trackedPatternCached,
    previousRuntimeCompiles' = runtimeCompiles,
    previousCacheHits' = cacheHits,
    lastAction' = "UseLiteral",
  }

  action useDynamicMiss = {
    nondet isTracked = Set(false, true).oneOf()
    val admitted = cacheEntries < CACHE_CAPACITY
    val nextEntries = if (admitted) cacheEntries + 1 else cacheEntries
    all {
      mode == Active, operations < MAX_OPERATIONS,
      not(isTracked and trackedPatternCached),
      mode' = mode,
      evaluation' = evaluation,
      cacheEntries' = nextEntries,
      trackedPatternCached' = if (isTracked and admitted) true else trackedPatternCached,
      runtimeCompiles' = runtimeCompiles + 1,
      cacheHits' = cacheHits,
      peakCacheEntries' = if (nextEntries > peakCacheEntries) nextEntries else peakCacheEntries,
      operations' = operations + 1,
      previousEvaluation' = evaluation,
      previousCacheEntries' = cacheEntries,
      previousTrackedPatternCached' = trackedPatternCached,
      previousRuntimeCompiles' = runtimeCompiles,
      previousCacheHits' = cacheHits,
      lastAction' = "UseDynamicMiss",
    }
  }

  action useDynamicHit = all {
    mode == Active, operations < MAX_OPERATIONS, trackedPatternCached,
    mode' = mode,
    evaluation' = evaluation,
    cacheEntries' = cacheEntries,
    trackedPatternCached' = trackedPatternCached,
    runtimeCompiles' = runtimeCompiles,
    cacheHits' = cacheHits + 1,
    peakCacheEntries' = peakCacheEntries,
    operations' = operations + 1,
    previousEvaluation' = evaluation,
    previousCacheEntries' = cacheEntries,
    previousTrackedPatternCached' = trackedPatternCached,
    previousRuntimeCompiles' = runtimeCompiles,
    previousCacheHits' = cacheHits,
    lastAction' = "UseDynamicHit",
  }

  action endEvaluation = all {
    mode == Active,
    mode' = Done,
    evaluation' = evaluation,
    cacheEntries' = cacheEntries,
    trackedPatternCached' = trackedPatternCached,
    runtimeCompiles' = runtimeCompiles,
    cacheHits' = cacheHits,
    peakCacheEntries' = peakCacheEntries,
    operations' = operations,
    previousEvaluation' = evaluation,
    previousCacheEntries' = cacheEntries,
    previousTrackedPatternCached' = trackedPatternCached,
    previousRuntimeCompiles' = runtimeCompiles,
    previousCacheHits' = cacheHits,
    lastAction' = "EndEvaluation",
  }

  action BeginEvaluation = beginEvaluation
  action UseLiteral = useLiteral
  action UseDynamicMiss = useDynamicMiss
  action UseDynamicHit = useDynamicHit
  action EndEvaluation = endEvaluation
  action step = any { BeginEvaluation, UseLiteral, UseDynamicMiss, UseDynamicHit, EndEvaluation }

  val TypeOK = and {
    evaluation >= 0 and evaluation <= MAX_EVALUATIONS,
    cacheEntries >= 0 and cacheEntries <= CACHE_CAPACITY,
    runtimeCompiles >= 0 and runtimeCompiles <= MAX_OPERATIONS,
    cacheHits >= 0 and cacheHits <= MAX_OPERATIONS,
    peakCacheEntries >= 0 and peakCacheEntries <= CACHE_CAPACITY,
    operations >= 0 and operations <= MAX_OPERATIONS,
    lastAction.in(Set("Init", "BeginEvaluation", "UseLiteral", "UseDynamicMiss", "UseDynamicHit", "EndEvaluation")),
  }

  val LiteralPatternsDoNotCompileAtRuntime = (lastAction == "UseLiteral").implies(and {
    runtimeCompiles == previousRuntimeCompiles,
    cacheEntries == previousCacheEntries,
    cacheHits == previousCacheHits,
  })

  val RepeatedDynamicPatternCompilesOnce = (lastAction == "UseDynamicHit").implies(and {
    previousTrackedPatternCached,
    trackedPatternCached,
    runtimeCompiles == previousRuntimeCompiles,
    cacheHits == previousCacheHits + 1,
  })

  val DynamicMissCompilesExactlyOnce = (lastAction == "UseDynamicMiss").implies(and {
    runtimeCompiles == previousRuntimeCompiles + 1,
    cacheHits == previousCacheHits,
  })

  val DynamicCacheEntriesAreBounded = cacheEntries <= CACHE_CAPACITY

  val SeparateEvaluationsDoNotShareCache = (lastAction == "BeginEvaluation").implies(and {
    evaluation == previousEvaluation + 1,
    cacheEntries == 0,
    not(trackedPatternCached),
    runtimeCompiles == 0,
    cacheHits == 0,
    peakCacheEntries == 0,
  })

  val PeakCacheEntriesTracksRetainedEntries = and {
    peakCacheEntries >= cacheEntries,
    peakCacheEntries <= CACHE_CAPACITY,
  }
}

module RegexEvaluationCacheConnect {
  type Observable = {
    lastCase: str,
    decision: str,
    runtimeCompiles: int,
    cacheHits: int,
    peakCacheEntries: int,
    evaluationIsolation: bool,
  }
  type ActionTaken = { tag: str, value: { case: str } }

  pure val CASES = Set("literal", "dynamicRepeated", "capacity", "separateEvaluations")
  var observable: Observable
  var actionTaken: ActionTaken

  pure def expected(case: str): Observable = {
    lastCase: case,
    decision: "Allow",
    runtimeCompiles: if (case == "literal") 0 else if (case == "capacity") 17 else 1,
    cacheHits: if (case.in(Set("dynamicRepeated", "separateEvaluations"))) 2
      else if (case == "capacity") 1 else 0,
    peakCacheEntries: if (case == "literal") 0 else if (case == "capacity") 16 else 1,
    evaluationIsolation: true,
  }

  action init = all {
    observable' = {
      lastCase: "none",
      decision: "Deny",
      runtimeCompiles: 0,
      cacheHits: 0,
      peakCacheEntries: 0,
      evaluationIsolation: true,
    },
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

module RegexEvaluationCacheScenarios {
  import RegexEvaluationCacheConnect.*
  run literal = init.then(evaluateCase("literal"))
  run dynamicRepeated = init.then(evaluateCase("dynamicRepeated"))
  run capacity = init.then(evaluateCase("capacity"))
  run separateEvaluations = init.then(evaluateCase("separateEvaluations"))
}
