// Firestore Listen refresh boundaries and changed-path delta selection.

module FirestoreListenRefresh {
  const MAX_VERSION: int
  const MAX_GENERATION: int
  const PATHS: Set[str]
  const MANY_TARGETS: int

  type Observable = {
    generation: int,
    lastVersion: int,
    throughVersion: int,
    refreshMode: str,
    changedPaths: Set[str],
    safeQuery: bool,
    targetCount: int,
    examinedCount: int,
    projectionEquivalent: bool,
    incrementalUsed: bool,
    targetCurrent: bool,
    resetPending: bool,
    replayCount: int,
    lastReason: str,
  }
  type ActionTaken = { tag: str, value: { path: str } }

  var observable: Observable
  var previousObservable: Observable
  var lastAction: str
  var lastPath: str
  var actionTaken: ActionTaken

  pure val MODES = Set("Idle", "Delta", "Full")
  pure val REASONS = Set("init", "contiguous", "gap", "reset", "unsafe", "targets", "delta", "full")
  pure val ACTIONS = Set(
    "Init",
    "QueueContiguous",
    "QueueGap",
    "QueueReset",
    "MarkUnsafe",
    "SetFiftyTargets",
    "Refresh"
  )

  action record(actionName, path, nextObservable) = all {
    previousObservable' = observable,
    observable' = nextObservable,
    lastAction' = actionName,
    lastPath' = path,
    actionTaken' = { tag: actionName, value: { path: path } },
  }

  action init = {
    val initial = {
      generation: 1,
      lastVersion: 1,
      throughVersion: 1,
      refreshMode: "Idle",
      changedPaths: Set(),
      safeQuery: true,
      targetCount: 1,
      examinedCount: 0,
      projectionEquivalent: true,
      incrementalUsed: false,
      targetCurrent: true,
      resetPending: false,
      replayCount: 0,
      lastReason: "init",
    }
    all {
      observable' = initial,
      previousObservable' = initial,
      lastAction' = "Init",
      lastPath' = "",
      actionTaken' = { tag: "init", value: { path: "" } },
    }
  }

  action queueContiguous(path) = all {
    path.in(PATHS),
    observable.throughVersion < MAX_VERSION,
    record("QueueContiguous", path, {
      generation: observable.generation,
      lastVersion: observable.lastVersion,
      throughVersion: observable.throughVersion + 1,
      refreshMode: if (observable.refreshMode == "Full" or not(observable.safeQuery)) "Full" else "Delta",
      changedPaths: observable.changedPaths.union(Set(path)),
      safeQuery: observable.safeQuery,
      targetCount: observable.targetCount,
      examinedCount: observable.examinedCount,
      projectionEquivalent: observable.projectionEquivalent,
      incrementalUsed: false,
      targetCurrent: observable.targetCurrent,
      resetPending: observable.resetPending,
      replayCount: observable.replayCount,
      lastReason: "contiguous",
    }),
  }

  action queueGap = all {
    observable.throughVersion + 2 <= MAX_VERSION,
    record("QueueGap", "", {
      generation: observable.generation,
      lastVersion: observable.lastVersion,
      throughVersion: observable.throughVersion + 2,
      refreshMode: "Full",
      changedPaths: observable.changedPaths.union(Set("items/a")),
      safeQuery: observable.safeQuery,
      targetCount: observable.targetCount,
      examinedCount: observable.examinedCount,
      projectionEquivalent: observable.projectionEquivalent,
      incrementalUsed: false,
      targetCurrent: observable.targetCurrent,
      resetPending: observable.resetPending,
      replayCount: observable.replayCount,
      lastReason: "gap",
    }),
  }

  action queueReset = all {
    observable.generation < MAX_GENERATION,
    record("QueueReset", "", {
      generation: observable.generation + 1,
      lastVersion: observable.lastVersion,
      throughVersion: observable.throughVersion,
      refreshMode: "Full",
      changedPaths: Set(),
      safeQuery: observable.safeQuery,
      targetCount: observable.targetCount,
      examinedCount: observable.examinedCount,
      projectionEquivalent: observable.projectionEquivalent,
      incrementalUsed: false,
      targetCurrent: false,
      resetPending: true,
      replayCount: 0,
      lastReason: "reset",
    }),
  }

  action markUnsafe = all {
    observable.safeQuery,
    record("MarkUnsafe", "", {
      generation: observable.generation,
      lastVersion: observable.lastVersion,
      throughVersion: observable.throughVersion,
      refreshMode: "Full",
      changedPaths: observable.changedPaths,
      safeQuery: false,
      targetCount: observable.targetCount,
      examinedCount: observable.examinedCount,
      projectionEquivalent: observable.projectionEquivalent,
      incrementalUsed: false,
      targetCurrent: observable.targetCurrent,
      resetPending: observable.resetPending,
      replayCount: observable.replayCount,
      lastReason: "unsafe",
    }),
  }

  action setFiftyTargets = all {
    observable.targetCount == 1,
    record("SetFiftyTargets", "", {
      generation: observable.generation,
      lastVersion: observable.lastVersion,
      throughVersion: observable.throughVersion,
      refreshMode: observable.refreshMode,
      changedPaths: observable.changedPaths,
      safeQuery: observable.safeQuery,
      targetCount: MANY_TARGETS,
      examinedCount: observable.examinedCount,
      projectionEquivalent: observable.projectionEquivalent,
      incrementalUsed: false,
      targetCurrent: observable.targetCurrent,
      resetPending: observable.resetPending,
      replayCount: observable.replayCount,
      lastReason: "targets",
    }),
  }

  action refresh = {
    val useIncremental = observable.refreshMode == "Delta" and observable.safeQuery
    all {
      observable.refreshMode != "Idle",
      record("Refresh", "", {
        generation: observable.generation,
        lastVersion: observable.throughVersion,
        throughVersion: observable.throughVersion,
        refreshMode: "Idle",
        changedPaths: Set(),
        safeQuery: observable.safeQuery,
        targetCount: observable.targetCount,
        examinedCount: if (useIncremental) observable.changedPaths.size() * observable.targetCount else 0,
        projectionEquivalent: true,
        incrementalUsed: useIncremental,
        targetCurrent: true,
        resetPending: false,
        replayCount: if (observable.resetPending) observable.targetCount else 0,
        lastReason: if (useIncremental) "delta" else "full",
      }),
    }
  }

  action QueueContiguous = { nondet path = PATHS.oneOf() queueContiguous(path) }
  action QueueGap = queueGap
  action QueueReset = queueReset
  action MarkUnsafe = markUnsafe
  action SetFiftyTargets = setFiftyTargets
  action Refresh = refresh

  action step = any {
    QueueContiguous,
    QueueGap,
    QueueReset,
    MarkUnsafe,
    SetFiftyTargets,
    Refresh,
  }

  val TypeOK = and {
    MAX_VERSION >= 5,
    MAX_GENERATION >= 3,
    MANY_TARGETS == 50,
    PATHS == Set("items/a", "items/b", "other/a"),
    observable.lastVersion >= 1 and observable.lastVersion <= MAX_VERSION,
    observable.generation >= 1 and observable.generation <= MAX_GENERATION,
    observable.throughVersion >= observable.lastVersion and observable.throughVersion <= MAX_VERSION,
    observable.refreshMode.in(MODES),
    observable.changedPaths.subseteq(PATHS),
    observable.targetCount.in(Set(1, MANY_TARGETS)),
    observable.examinedCount >= 0,
    observable.replayCount >= 0 and observable.replayCount <= observable.targetCount,
    observable.lastReason.in(REASONS),
    lastAction.in(ACTIONS),
  }

  val ExactContiguousVersionBoundary = (lastAction == "QueueContiguous").implies(and {
    observable.throughVersion == previousObservable.throughVersion + 1,
    observable.lastVersion == previousObservable.lastVersion,
    observable.refreshMode == if (
      previousObservable.refreshMode == "Full" or not(previousObservable.safeQuery)
    ) "Full" else "Delta",
  })

  val ChangedPathsAreUnioned = (lastAction == "QueueContiguous").implies(
    observable.changedPaths == previousObservable.changedPaths.union(Set(lastPath))
  )

  val VersionGapFallsBack = (lastAction == "QueueGap").implies(and {
    observable.throughVersion > previousObservable.throughVersion + 1,
    observable.refreshMode == "Full",
  })

  val ResetFallsBack = (lastAction == "QueueReset").implies(
    observable.refreshMode == "Full" and observable.changedPaths.size() == 0
  )

  val GenerationChangeInvalidatesTarget = (lastAction == "QueueReset").implies(and {
    observable.generation == previousObservable.generation + 1,
    not(observable.targetCurrent),
    observable.resetPending,
  })

  val UnsafeQueryFallsBack = (lastAction == "MarkUnsafe").implies(
    not(observable.safeQuery) and observable.refreshMode == "Full"
  )

  val FullFallbackIsSticky = and {
    (lastAction == "QueueContiguous" and previousObservable.refreshMode == "Full")
      .implies(observable.refreshMode == "Full"),
    (not(observable.safeQuery)).implies(observable.refreshMode != "Delta"),
  }

  val RefreshCommitsExactBoundary = (lastAction == "Refresh").implies(and {
    observable.lastVersion == previousObservable.throughVersion,
    observable.throughVersion == previousObservable.throughVersion,
    observable.refreshMode == "Idle",
    observable.changedPaths.size() == 0,
  })

  val IncrementalOnlyForSafeExactDelta = (lastAction == "Refresh").implies(
    observable.incrementalUsed == (
      previousObservable.refreshMode == "Delta" and previousObservable.safeQuery
    )
  )

  val IncrementalProjectionEquivalent = observable.projectionEquivalent

  val FiftyTargetsOneChangeIsLinear = (
    lastAction == "Refresh"
      and previousObservable.refreshMode == "Delta"
      and previousObservable.safeQuery
      and previousObservable.targetCount == MANY_TARGETS
      and previousObservable.changedPaths.size() == 1
  ).implies(observable.examinedCount == MANY_TARGETS)

  val FullRefreshExaminesNoDeltaRows = (
    lastAction == "Refresh" and not(observable.incrementalUsed)
  ).implies(observable.examinedCount == 0)

  val GenerationResetReplaysEveryTarget = (
    lastAction == "Refresh" and previousObservable.resetPending
  ).implies(and {
    observable.targetCurrent,
    not(observable.resetPending),
    not(observable.incrementalUsed),
    observable.replayCount == previousObservable.targetCount,
  })
}

module FirestoreListenRefreshProof {
  import FirestoreListenRefresh(
    MAX_VERSION = 5,
    MAX_GENERATION = 3,
    PATHS = Set("items/a", "items/b", "other/a"),
    MANY_TARGETS = 50
  ).*
}

module FirestoreListenRefreshScenarios {
  import FirestoreListenRefresh(
    MAX_VERSION = 5,
    MAX_GENERATION = 3,
    PATHS = Set("items/a", "items/b", "other/a"),
    MANY_TARGETS = 50
  ).*

  run contiguous = init.then(queueContiguous("items/a")).then(Refresh)
    .expect(observable.lastVersion == 2 and observable.incrementalUsed and observable.projectionEquivalent)

  run pathUnion = init.then(queueContiguous("items/a")).then(queueContiguous("items/b"))
    .then(queueContiguous("items/a")).then(Refresh)
    .expect(observable.lastVersion == 4 and observable.examinedCount == 2)

  run gap = init.then(QueueGap).then(Refresh)
    .expect(observable.lastVersion == 3 and not(observable.incrementalUsed))

  run reset = init.then(QueueReset).then(Refresh)
    .expect(observable.generation == 2 and observable.targetCurrent and observable.replayCount == 1)

  run generationReset = init.then(SetFiftyTargets).then(QueueReset).then(Refresh)
    .expect(observable.generation == 2 and observable.targetCurrent and observable.replayCount == 50)

  run unsafe = init.then(MarkUnsafe).then(queueContiguous("items/a")).then(Refresh)
    .then(queueContiguous("items/b")).then(Refresh)
    .expect(observable.lastVersion == 3 and not(observable.incrementalUsed))

  run fiftyTargets = init.then(SetFiftyTargets).then(queueContiguous("items/a")).then(Refresh)
    .expect(observable.examinedCount == 50 and observable.projectionEquivalent)
}

module FirestoreListenRefreshConnect {
  import FirestoreListenRefresh(
    MAX_VERSION = 5,
    MAX_GENERATION = 3,
    PATHS = Set("items/a", "items/b", "other/a"),
    MANY_TARGETS = 50
  ).*
}
