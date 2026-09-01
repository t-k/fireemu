// Event delivery state machine used by the additive Quint pilot.
// The Rust-only Interrupt transition is intentionally outside this pilot.

module EventDelivery {
  const EVENTS: Set[str]
  const MAX_ATTEMPTS: int
  const MAX_EPOCH: int

  type Lifecycle =
    | Pending
    | Leased
    | Running
    | Succeeded
    | RetryWaiting
    | DeadLettered
    | Cancelled
    | DiscardedStaleEpoch

  type Observable = {
    state: str -> Lifecycle,
    attempts: str -> int,
    maxAttempts: int,
    capturedEpoch: str -> int,
    currentEpoch: int,
    terminal: str -> bool,
    cancelled: str -> bool,
    stale: str -> bool,
  }

  // Quint Connect 0.1.2 does not request Quint's built-in MBT metadata for
  // named `quint test` runs, so the pilot records the equivalent boundary explicitly.
  type ActionTaken = { tag: str, value: { event: str } }

  var observable: Observable
  var previousObservable: Observable
  var lastAction: str
  var lastTarget: Set[str]
  var actionTaken: ActionTaken

  pure val TERMINAL = Set(Succeeded, DeadLettered, Cancelled, DiscardedStaleEpoch)
  pure val NON_TERMINAL = Set(Pending, Leased, Running, RetryWaiting)
  pure val STATES = TERMINAL.union(NON_TERMINAL)
  pure val ACTIONS = Set(
    "Init",
    "Lease",
    "Start",
    "Succeed",
    "Fail",
    "RetryDue",
    "Cancel",
    "Reset",
    "DiscardStale"
  )

  pure def isTerminal(state: Lifecycle): bool = state.in(TERMINAL)

  pure def makeObservable(
    state: str -> Lifecycle,
    attempts: str -> int,
    capturedEpoch: str -> int,
    currentEpoch: int
  ): Observable = {
    state: state,
    attempts: attempts,
    maxAttempts: MAX_ATTEMPTS,
    capturedEpoch: capturedEpoch,
    currentEpoch: currentEpoch,
    terminal: EVENTS.mapBy(event => isTerminal(state.get(event))),
    cancelled: EVENTS.mapBy(event => state.get(event) == Cancelled),
    stale: EVENTS.mapBy(event => state.get(event) == DiscardedStaleEpoch),
  }

  action record(actionName, event, target, state, attempts, capturedEpoch, currentEpoch) = all {
    previousObservable' = observable,
    lastAction' = actionName,
    lastTarget' = target,
    actionTaken' = {
      tag: actionName,
      value: { event: event },
    },
    observable' = makeObservable(state, attempts, capturedEpoch, currentEpoch),
  }

  action init = {
    val state = EVENTS.mapBy(_ => Pending)
    val attempts = EVENTS.mapBy(_ => 0)
    val capturedEpoch = EVENTS.mapBy(_ => 0)
    val initial = makeObservable(state, attempts, capturedEpoch, 0)
    all {
      observable' = initial,
      previousObservable' = initial,
      lastAction' = "Init",
      lastTarget' = Set(),
      actionTaken' = { tag: "init", value: { event: "" } },
    }
  }

  action leaseEvent(event) = all {
    observable.state.get(event) == Pending,
    record(
      "Lease",
      event,
      Set(event),
      observable.state.set(event, Leased),
      observable.attempts,
      observable.capturedEpoch,
      observable.currentEpoch
    ),
  }

  action startEvent(event) = all {
    observable.state.get(event) == Leased,
    observable.attempts.get(event) < MAX_ATTEMPTS,
    record(
      "Start",
      event,
      Set(event),
      observable.state.set(event, Running),
      observable.attempts.set(event, observable.attempts.get(event) + 1),
      observable.capturedEpoch,
      observable.currentEpoch
    ),
  }

  action succeedEvent(event) = all {
    observable.state.get(event) == Running,
    record(
      "Succeed",
      event,
      Set(event),
      observable.state.set(event, Succeeded),
      observable.attempts,
      observable.capturedEpoch,
      observable.currentEpoch
    ),
  }

  action failEvent(event) = all {
    observable.state.get(event) == Running,
    record(
      "Fail",
      event,
      Set(event),
      observable.state.set(
        event,
        if (observable.attempts.get(event) < MAX_ATTEMPTS) RetryWaiting else DeadLettered
      ),
      observable.attempts,
      observable.capturedEpoch,
      observable.currentEpoch
    ),
  }

  action retryEvent(event) = all {
    observable.state.get(event) == RetryWaiting,
    record(
      "RetryDue",
      event,
      Set(event),
      observable.state.set(event, Pending),
      observable.attempts,
      observable.capturedEpoch,
      observable.currentEpoch
    ),
  }

  action cancelEvent(event) = all {
    observable.state.get(event).in(NON_TERMINAL),
    record(
      "Cancel",
      event,
      Set(event),
      observable.state.set(event, Cancelled),
      observable.attempts,
      observable.capturedEpoch,
      observable.currentEpoch
    ),
  }

  action resetSession = all {
    observable.currentEpoch < MAX_EPOCH,
    record(
      "Reset",
      "",
      Set(),
      observable.state,
      observable.attempts,
      observable.capturedEpoch,
      observable.currentEpoch + 1
    ),
  }

  action discardEvent(event) = all {
    observable.state.get(event).in(NON_TERMINAL),
    observable.capturedEpoch.get(event) < observable.currentEpoch,
    record(
      "DiscardStale",
      event,
      Set(event),
      observable.state.set(event, DiscardedStaleEpoch),
      observable.attempts,
      observable.capturedEpoch,
      observable.currentEpoch
    ),
  }

  action Lease = {
    nondet event = EVENTS.oneOf()
    leaseEvent(event)
  }

  action Start = {
    nondet event = EVENTS.oneOf()
    startEvent(event)
  }

  action Succeed = {
    nondet event = EVENTS.oneOf()
    succeedEvent(event)
  }

  action Fail = {
    nondet event = EVENTS.oneOf()
    failEvent(event)
  }

  action RetryDue = {
    nondet event = EVENTS.oneOf()
    retryEvent(event)
  }

  action Cancel = {
    nondet event = EVENTS.oneOf()
    cancelEvent(event)
  }

  action Reset = resetSession

  action DiscardStale = {
    nondet event = EVENTS.oneOf()
    discardEvent(event)
  }

  action progress(event) = any {
    leaseEvent(event),
    startEvent(event),
    succeedEvent(event),
    failEvent(event),
    retryEvent(event),
    discardEvent(event),
  }

  action step = any {
    Lease,
    Start,
    Succeed,
    Fail,
    RetryDue,
    Cancel,
    Reset,
    DiscardStale,
  }

  val TypeOK = and {
    EVENTS.size() > 0,
    MAX_ATTEMPTS > 0,
    MAX_EPOCH >= 0,
    observable.state.keys() == EVENTS,
    EVENTS.forall(event => observable.state.get(event).in(STATES)),
    observable.attempts.keys() == EVENTS,
    EVENTS.forall(event => observable.attempts.get(event) >= 0 and observable.attempts.get(event) <= MAX_ATTEMPTS),
    observable.maxAttempts == MAX_ATTEMPTS,
    observable.capturedEpoch.keys() == EVENTS,
    EVENTS.forall(event => observable.capturedEpoch.get(event) >= 0 and observable.capturedEpoch.get(event) <= MAX_EPOCH),
    observable.currentEpoch >= 0 and observable.currentEpoch <= MAX_EPOCH,
    previousObservable.state.keys() == EVENTS,
    EVENTS.forall(event => previousObservable.state.get(event).in(STATES)),
    previousObservable.attempts.keys() == EVENTS,
    EVENTS.forall(event => previousObservable.attempts.get(event) >= 0 and previousObservable.attempts.get(event) <= MAX_ATTEMPTS),
    previousObservable.maxAttempts == MAX_ATTEMPTS,
    previousObservable.capturedEpoch.keys() == EVENTS,
    EVENTS.forall(event => previousObservable.capturedEpoch.get(event) >= 0 and previousObservable.capturedEpoch.get(event) <= MAX_EPOCH),
    previousObservable.currentEpoch >= 0 and previousObservable.currentEpoch <= MAX_EPOCH,
    lastAction.in(ACTIONS),
    lastTarget.subseteq(EVENTS),
    lastTarget.size() <= 1,
  }

  val AttemptsBounded = EVENTS.forall(event => observable.attempts.get(event) <= MAX_ATTEMPTS)

  val DeadLetterOnlyAfterExhaustion = EVENTS.forall(event =>
    (observable.state.get(event) == DeadLettered).implies(observable.attempts.get(event) == MAX_ATTEMPTS)
  )

  def onlyTargetStateChanged(event: str): bool = EVENTS
    .exclude(Set(event))
    .forall(other => observable.state.get(other) == previousObservable.state.get(other))

  def legalEventTransition(event: str): bool = and {
    onlyTargetStateChanged(event),
    or {
      and {
        lastAction == "Lease",
        previousObservable.state.get(event) == Pending,
        observable.state.get(event) == Leased,
      },
      and {
        lastAction == "Start",
        previousObservable.state.get(event) == Leased,
        observable.state.get(event) == Running,
      },
      and {
        lastAction == "Succeed",
        previousObservable.state.get(event) == Running,
        observable.state.get(event) == Succeeded,
      },
      and {
        lastAction == "Fail",
          previousObservable.state.get(event) == Running,
          observable.state.get(event) == if (previousObservable.attempts.get(event) < MAX_ATTEMPTS) RetryWaiting else DeadLettered,
      },
      and {
        lastAction == "RetryDue",
        previousObservable.state.get(event) == RetryWaiting,
        observable.state.get(event) == Pending,
      },
      and {
        lastAction == "Cancel",
        previousObservable.state.get(event).in(NON_TERMINAL),
        observable.state.get(event) == Cancelled,
      },
      and {
        lastAction == "DiscardStale",
        previousObservable.state.get(event).in(NON_TERMINAL),
        observable.state.get(event) == DiscardedStaleEpoch,
      },
    },
  }

  val LegalStateTransitions = or {
    lastAction == "Init" and lastTarget == Set(),
    and {
      lastAction == "Reset",
      lastTarget == Set(),
      observable.state == previousObservable.state,
    },
    EVENTS.exists(event => lastTarget == Set(event) and legalEventTransition(event)),
  }

  val AttemptsChangeOnlyOnStart = if (lastAction == "Start") {
    EVENTS.exists(event => and {
      lastTarget == Set(event),
      observable.attempts.get(event) == previousObservable.attempts.get(event) + 1,
      EVENTS.exclude(Set(event)).forall(other =>
        observable.attempts.get(other) == previousObservable.attempts.get(other)
      ),
    })
  } else {
    observable.attempts == previousObservable.attempts
  }

  val StaleDiscardRequiresOlderEpoch = (lastAction == "DiscardStale").implies(
    EVENTS.exists(event => and {
      lastTarget == Set(event),
      previousObservable.capturedEpoch.get(event) < previousObservable.currentEpoch,
    })
  )

  temporal NoTerminalRegression = always(EVENTS.forall(event =>
    isTerminal(previousObservable.state.get(event)).implies(
      observable.state.get(event) == previousObservable.state.get(event)
    )
  ))

  temporal Fairness = EVENTS.forall(event =>
    progress(event).weakFair((observable, previousObservable, lastAction, lastTarget))
  )

  temporal EventEventuallyTerminates = Fairness.implies(
    EVENTS.forall(event => eventually(observable.terminal.get(event)))
  )
}

module EventDeliveryProof {
  import EventDelivery(
    EVENTS = Set("e1", "e2"),
    MAX_ATTEMPTS = 3,
    MAX_EPOCH = 1
  ).*
}

module EventDeliveryScenarios {
  import EventDelivery(
    EVENTS = Set("e1"),
    MAX_ATTEMPTS = 2,
    MAX_EPOCH = 1
  ).*

  run success = init
    .then(Lease)
    .then(Start)
    .then(Succeed)
    .expect(observable.state.get("e1") == Succeeded)

  run retryExhaustion = init
    .then(Lease)
    .then(Start)
    .then(Fail)
    .then(RetryDue)
    .then(Lease)
    .then(Start)
    .then(Fail)
    .expect(observable.state.get("e1") == DeadLettered)

  run staleDiscard = init
    .then(Reset)
    .then(DiscardStale)
    .expect(observable.state.get("e1") == DiscardedStaleEpoch)

  run cancel = init
    .then(Cancel)
    .expect(observable.state.get("e1") == Cancelled)
}

module EventDeliveryConnect {
  import EventDelivery(
    EVENTS = Set("e1", "e2"),
    MAX_ATTEMPTS = 3,
    MAX_EPOCH = 1
  ).*
}
