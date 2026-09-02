// Causal work, child reservations, and the await-idle fence lifecycle.

module AwaitIdle {
  const ITEMS: Set[str]
  const MAX_DEPTH: int
  const IGNORE_TEXT_INDEX: bool

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
  var lastAction: str
  var lastItem: str
  var actionTaken: ActionTaken

  pure val KINDS = Set("commit", "event", "invocation", "textIndexBuild")
  pure val FENCES = Set("none", "waiting", "returned")
  pure val ACTIONS = Set("Init", "BeginExternal", "CompleteLeaf", "CompleteWithReservation", "EnqueueChild", "RequestFence", "ReturnIdle")

  pure def activeItems(state) = ITEMS.filter(work => state.inFlight.get(work) != "")

  def blocking(state) = state.reservations.intersect(fenced).union(
    activeItems(state).filter(work => fenced.contains(work)
      and (state.inFlight.get(work) != "textIndexBuild" or not(IGNORE_TEXT_INDEX)))
  )

  action record(name, work, child, kind, nextObservable) = all {
    previousObservable' = observable,
    observable' = nextObservable,
    lastAction' = name,
    previousUsed' = used,
    lastItem' = if (child == "") work else child,
    actionTaken' = { tag: name, value: { item: work, child: child, kind: kind } },
  }

  action init = {
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
      lastAction' = "Init",
      lastItem' = "",
      actionTaken' = { tag: "init", value: { item: "", child: "", kind: "" } },
    }
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
  }

  action requestFence = {
    val covered = activeItems(observable).union(observable.reservations)
    all {
      observable.fence == "none",
      record("RequestFence", "", "", "", { ...observable, fence: "waiting" }),
      depth' = depth,
      used' = used,
      fenced' = covered,
    }
  }

  action returnIdle = all {
    observable.fence == "waiting",
    blocking(observable) == Set(),
    record("ReturnIdle", "", "", "", { ...observable, fence: "returned", returned: true }),
    depth' = depth,
    used' = used,
    fenced' = fenced,
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
    observable.fence.in(FENCES),
    observable.inFlight.keys() == ITEMS,
    ITEMS.forall(work => observable.inFlight.get(work) == "" or observable.inFlight.get(work).in(KINDS)),
    observable.reservations.subseteq(ITEMS),
    observable.returned == (observable.fence == "returned"),
    used.subseteq(ITEMS),
    previousUsed.subseteq(ITEMS),
    fenced.subseteq(used),
    lastAction.in(ACTIONS),
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

  temporal FencedWorkStaysTerminal = always(observable.returned.implies(blocking(observable) == Set()))
  temporal Fairness = and {
    ITEMS.forall(work => completeAny(work).weakFair((observable, previousObservable, depth, used, previousUsed, fenced, lastAction, lastItem))),
    ITEMS.forall(parent => ITEMS.forall(child => enqueueAnyChild(parent, child).weakFair((observable, previousObservable, depth, used, previousUsed, fenced, lastAction, lastItem)))),
    ReturnIdle.weakFair((observable, previousObservable, depth, used, previousUsed, fenced, lastAction, lastItem)),
  }
  temporal AwaitIdleEventuallyReturns = Fairness.implies(always((observable.fence == "waiting").implies(eventually(observable.returned))))
}

module AwaitIdleProof {
  import AwaitIdle(ITEMS = Set("i1", "i2", "i3"), MAX_DEPTH = 1, IGNORE_TEXT_INDEX = false).*
}

module AwaitIdleScenarios {
  import AwaitIdle(ITEMS = Set("i1", "i2", "i3"), MAX_DEPTH = 1, IGNORE_TEXT_INDEX = false).*

  run leaf = init.then(beginExternal("i1", "commit")).then(RequestFence).then(completeLeaf("i1")).then(ReturnIdle).expect(observable.returned)
  run reservation = init.then(beginExternal("i1", "invocation")).then(RequestFence).then(completeWithReservation("i1")).then(enqueueChild("i1", "i2", "event")).then(completeLeaf("i2")).then(ReturnIdle).expect(observable.returned)
  run fence = init.then(RequestFence).then(ReturnIdle).expect(observable.fence == "returned")
  run ignoreTextIndex = init.then(beginExternal("i1", "textIndexBuild")).then(RequestFence).then(completeLeaf("i1")).then(ReturnIdle).expect(observable.returned)
}

module AwaitIdleConnect {
  import AwaitIdle(ITEMS = Set("i1", "i2", "i3"), MAX_DEPTH = 1, IGNORE_TEXT_INDEX = false).*
}
