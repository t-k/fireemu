// Causal work, child reservations, and the await-idle fence lifecycle.

module AwaitIdle {
  const ITEMS: Set[str]
  const MAX_DEPTH: int
  const IGNORE_TEXT_INDEX_VALUES: Set[bool]
  // Causal records the runtime keeps for await-idle diagnostics (spec 10.5); older records
  // are evicted and counted, never completed.
  const WINDOW_CAP: int

  type Observable = {
    fence: str,
    inFlight: str -> str,
    reservations: Set[str],
    returned: bool,
  }
  type ActionTaken = { tag: str, value: { item: str, child: str, kind: str } }

  var observable: Observable
  var previousObservable: Observable
  var depth: str -> int
  var used: Set[str]
  var previousUsed: Set[str]
  var fenced: Set[str]
  var ignoreTextIndex: bool
  var lastAction: str
  var lastItem: str
  var actionTaken: ActionTaken
  // The bounded causality window: registered work whose phases are still retained, how many
  // records were evicted, and which retained records reached a terminal phase.
  var window: Set[str]
  var evicted: int
  var terminalMarks: Set[str]

  pure val KINDS = Set("commit", "event", "invocation", "textIndexBuild")
  pure val FENCES = Set("none", "waiting", "returned")
  pure val ACTIONS = Set("Init", "BeginExternal", "CompleteLeaf", "CompleteWithReservation", "EnqueueChild", "RequestFence", "ReturnIdle")

  pure def activeItems(state) = ITEMS.filter(work => state.inFlight.get(work) != "")

  def blocking(state) = state.reservations.intersect(fenced).union(
    activeItems(state).filter(work => fenced.contains(work)
      and (state.inFlight.get(work) != "textIndexBuild" or not(ignoreTextIndex)))
  )

  action record(name, work, child, kind, nextObservable) = all {
    previousObservable' = observable,
    observable' = nextObservable,
    lastAction' = name,
    previousUsed' = used,
    ignoreTextIndex' = ignoreTextIndex,
    lastItem' = if (child == "") work else child,
    actionTaken' = { tag: name, value: { item: work, child: child, kind: kind } },
  }

  action init = {
    nondet selectedTextIndexPolicy = IGNORE_TEXT_INDEX_VALUES.oneOf()
    val initial = {
      fence: "none",
      inFlight: ITEMS.mapBy(_ => ""),
      reservations: Set(),
      returned: false,
    }
    all {
      observable' = initial,
      previousObservable' = initial,
      depth' = ITEMS.mapBy(_ => 0),
      used' = Set(),
      previousUsed' = Set(),
      fenced' = Set(),
      ignoreTextIndex' = selectedTextIndexPolicy,
      lastAction' = "Init",
      lastItem' = "",
      actionTaken' = { tag: "init", value: { item: "", child: "", kind: "" } },
      window' = Set(),
      evicted' = 0,
      terminalMarks' = Set(),
    }
  }

  // Registers `work` in the window. At capacity, one older record is evicted and counted;
  // its terminal mark goes with it, so an evicted record can never read as completed.
  action register(work) = {
    val candidates = window.exclude(Set(work))
    if (candidates.size() >= WINDOW_CAP) {
      nondet victim = candidates.oneOf()
      all {
        window' = window.exclude(Set(victim)).union(Set(work)),
        evicted' = evicted + 1,
        terminalMarks' = terminalMarks.exclude(Set(victim, work)),
      }
    } else {
      all {
        window' = window.union(Set(work)),
        evicted' = evicted,
        terminalMarks' = terminalMarks.exclude(Set(work)),
      }
    }
  }

  action keepWindow = all {
    window' = window,
    evicted' = evicted,
    terminalMarks' = terminalMarks,
  }

  // A retained record reaches its terminal phase; an evicted one is not marked.
  action markTerminal(work) = all {
    window' = window,
    evicted' = evicted,
    terminalMarks' = if (window.contains(work)) terminalMarks.union(Set(work)) else terminalMarks,
  }

  action beginExternal(work, kind) = all {
    observable.fence == "none",
    ITEMS.contains(work),
    KINDS.contains(kind),
    not(used.contains(work)),
    ITEMS.exclude(used).size() > observable.reservations.size(),
    record("BeginExternal", work, "", kind, {
      ...observable,
      inFlight: observable.inFlight.set(work, kind),
    }),
    depth' = depth.set(work, 0),
    used' = used.union(Set(work)),
    fenced' = fenced,
    register(work),
  }

  action completeLeaf(work) = all {
    observable.inFlight.get(work) != "",
    record("CompleteLeaf", work, "", "", {
      ...observable,
      inFlight: observable.inFlight.set(work, ""),
    }),
    depth' = depth,
    used' = used,
    fenced' = fenced,
    markTerminal(work),
  }

  action completeWithReservation(work) = all {
    observable.inFlight.get(work) != "",
    depth.get(work) < MAX_DEPTH,
    ITEMS.exclude(used).size() > observable.reservations.size(),
    record("CompleteWithReservation", work, "", "", {
      ...observable,
      inFlight: observable.inFlight.set(work, ""),
      reservations: observable.reservations.union(Set(work)),
    }),
    depth' = depth,
    used' = used,
    fenced' = fenced,
    // The parent's own invocation is over; its reservation is a new child's registration.
    markTerminal(work),
  }

  action enqueueChild(parent, child, kind) = all {
    observable.reservations.contains(parent),
    ITEMS.contains(child),
    KINDS.contains(kind),
    not(used.contains(child)),
    record("EnqueueChild", parent, child, kind, {
      ...observable,
      inFlight: observable.inFlight.set(child, kind),
      reservations: observable.reservations.exclude(Set(parent)),
    }),
    depth' = depth.set(child, depth.get(parent) + 1),
    used' = used.union(Set(child)),
    fenced' = if (fenced.contains(parent)) fenced.union(Set(child)) else fenced,
    register(child),
  }

  action requestFence = {
    val covered = activeItems(observable).union(observable.reservations)
    all {
      observable.fence == "none",
      record("RequestFence", "", "", "", { ...observable, fence: "waiting" }),
      depth' = depth,
      used' = used,
      fenced' = covered,
      keepWindow,
    }
  }

  action returnIdle = all {
    observable.fence == "waiting",
    blocking(observable) == Set(),
    record("ReturnIdle", "", "", "", { ...observable, fence: "returned", returned: true }),
    depth' = depth,
    used' = used,
    fenced' = fenced,
    keepWindow,
  }

  action completeAny(work) = any { completeLeaf(work), completeWithReservation(work) }
  action enqueueAnyChild(parent, child) = {
    nondet kind = KINDS.oneOf()
    enqueueChild(parent, child, kind)
  }

  action BeginExternal = { nondet work = ITEMS.oneOf() nondet kind = KINDS.oneOf() beginExternal(work, kind) }
  action CompleteLeaf = { nondet work = ITEMS.oneOf() completeLeaf(work) }
  action CompleteWithReservation = { nondet work = ITEMS.oneOf() completeWithReservation(work) }
  action EnqueueChild = { nondet parent = ITEMS.oneOf() nondet child = ITEMS.oneOf() nondet kind = KINDS.oneOf() enqueueChild(parent, child, kind) }
  action RequestFence = requestFence
  action ReturnIdle = returnIdle

  action step = any { BeginExternal, CompleteLeaf, CompleteWithReservation, EnqueueChild, RequestFence, ReturnIdle }

  val TypeOK = and {
    ITEMS.size() > 0,
    MAX_DEPTH >= 0,
    IGNORE_TEXT_INDEX_VALUES != Set(),
    IGNORE_TEXT_INDEX_VALUES.contains(ignoreTextIndex),
    observable.fence.in(FENCES),
    observable.inFlight.keys() == ITEMS,
    ITEMS.forall(work => observable.inFlight.get(work) == "" or observable.inFlight.get(work).in(KINDS)),
    observable.reservations.subseteq(ITEMS),
    observable.returned == (observable.fence == "returned"),
    used.subseteq(ITEMS),
    previousUsed.subseteq(ITEMS),
    fenced.subseteq(used),
    lastAction.in(ACTIONS),
    WINDOW_CAP >= 1,
    window.subseteq(used),
    terminalMarks.subseteq(window),
    evicted >= 0,
  }

  // The causality window is bounded, and every registration is either retained or counted
  // as evicted: the diagnostic never loses a record silently.
  val WindowBounded = window.size() <= WINDOW_CAP
  val WindowAccounting = window.size() + evicted == used.size()
  // A terminal mark belongs to a retained record whose work is over: eviction is a gap, not
  // a completion, and no record reads as completed while its work is still in flight.
  val EvictionIsNotCompletion = and {
    terminalMarks.subseteq(window),
    terminalMarks.intersect(activeItems(observable)) == Set(),
  }

  val NoFalseIdle = (lastAction == "ReturnIdle").implies(blocking(observable) == Set())
  val CoveredReservationsBlock = observable.reservations.intersect(fenced).subseteq(blocking(observable))
  val NoIdentityReuse = if (lastAction.in(Set("BeginExternal", "EnqueueChild"))) {
    not(previousUsed.contains(lastItem)) and used == previousUsed.union(Set(lastItem))
  } else {
    used == previousUsed
  }
  val FenceClosedToNewExternalWork = (lastAction == "BeginExternal").implies(previousObservable.fence == "none")
  val FenceLifecycleMonotonic = and {
    (previousObservable.fence == "waiting").implies(observable.fence.in(Set("waiting", "returned"))),
    (previousObservable.fence == "returned").implies(observable.fence == "returned"),
  }

  temporal FencedWorkStaysTerminal = always(and {
    not(ignoreTextIndex),
    observable.returned,
  }.implies(blocking(observable) == Set()))
  temporal Fairness = and {
    ITEMS.forall(work => completeAny(work).weakFair((observable, previousObservable, depth, used, previousUsed, fenced, ignoreTextIndex, lastAction, lastItem, window, evicted, terminalMarks))),
    ITEMS.forall(parent => ITEMS.forall(child => enqueueAnyChild(parent, child).weakFair((observable, previousObservable, depth, used, previousUsed, fenced, ignoreTextIndex, lastAction, lastItem, window, evicted, terminalMarks)))),
    ReturnIdle.weakFair((observable, previousObservable, depth, used, previousUsed, fenced, ignoreTextIndex, lastAction, lastItem, window, evicted, terminalMarks)),
  }
  temporal AwaitIdleEventuallyReturns = Fairness.implies(always((observable.fence == "waiting").implies(eventually(observable.returned))))
}

module AwaitIdleProof {
  import AwaitIdle(ITEMS = Set("i1", "i2", "i3"), MAX_DEPTH = 1, IGNORE_TEXT_INDEX_VALUES = Set(false, true), WINDOW_CAP = 2).*
}

module AwaitIdleScenarios {
  import AwaitIdle(ITEMS = Set("i1", "i2", "i3"), MAX_DEPTH = 1, IGNORE_TEXT_INDEX_VALUES = Set(false), WINDOW_CAP = 2).*

  run leaf = init.then(beginExternal("i1", "commit")).then(RequestFence).then(completeLeaf("i1")).then(ReturnIdle).expect(observable.returned)
  run reservation = init.then(beginExternal("i1", "invocation")).then(RequestFence).then(completeWithReservation("i1")).then(enqueueChild("i1", "i2", "event")).then(completeLeaf("i2")).then(ReturnIdle).expect(observable.returned)
  run fence = init.then(RequestFence).then(ReturnIdle).expect(observable.fence == "returned")
  run evictedRecordIsAGap = init.then(beginExternal("i1", "commit")).then(completeLeaf("i1")).then(beginExternal("i2", "event")).then(beginExternal("i3", "event")).expect(window.size() == 2 and evicted == 1 and WindowAccounting and EvictionIsNotCompletion)
}

module AwaitIdleIgnoreTextIndexScenarios {
  import AwaitIdle(ITEMS = Set("i1", "i2", "i3"), MAX_DEPTH = 1, IGNORE_TEXT_INDEX_VALUES = Set(true), WINDOW_CAP = 2).*

  run ignoredTextIndexReturns = init.then(beginExternal("i1", "textIndexBuild")).then(RequestFence).then(ReturnIdle).expect(observable.returned and observable.inFlight.get("i1") == "textIndexBuild")
}

module AwaitIdleConnect {
  import AwaitIdle(ITEMS = Set("i1", "i2", "i3"), MAX_DEPTH = 1, IGNORE_TEXT_INDEX_VALUES = Set(false), WINDOW_CAP = 2).*
}
