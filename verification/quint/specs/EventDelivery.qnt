// Event delivery state, interruption, and bounded retry timing.

module EventDelivery {
  const EVENTS: Set[str]
  const MAX_ATTEMPTS: int
  const MAX_EPOCH: int
  const INITIAL_TIME: int
  const MAX_TIME: int
  const BASE_BACKOFF: int
  const MAX_BACKOFF: int

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
    now: int,
    retryAt: str -> int,
    baseBackoff: int,
    maxBackoff: int,
  }

  // Quint Connect 0.1.2 does not request built-in MBT metadata for named
  // `quint test` runs, so scenarios record the equivalent boundary explicitly.
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
    "Interrupt",
    "Cancel",
    "Tick",
    "Reset",
    "DiscardStale"
  )

  pure def isTerminal(state: Lifecycle): bool = state.in(TERMINAL)

  pure def retryDelay(attempt: int): int = {
    val exponential = BASE_BACKOFF * 2.ipow(attempt - 1)
    if (exponential < MAX_BACKOFF) exponential else MAX_BACKOFF
  }

  pure def makeObservable(
    state: str -> Lifecycle,
    attempts: str -> int,
    capturedEpoch: str -> int,
    currentEpoch: int,
    now: int,
    retryAt: str -> int
  ): Observable = {
    state: state,
    attempts: attempts,
    maxAttempts: MAX_ATTEMPTS,
    capturedEpoch: capturedEpoch,
    currentEpoch: currentEpoch,
    terminal: EVENTS.mapBy(event => isTerminal(state.get(event))),
    cancelled: EVENTS.mapBy(event => state.get(event) == Cancelled),
    stale: EVENTS.mapBy(event => state.get(event) == DiscardedStaleEpoch),
    now: now,
    retryAt: retryAt,
    baseBackoff: BASE_BACKOFF,
    maxBackoff: MAX_BACKOFF,
  }

  action record(
    actionName,
    event,
    target,
    state,
    attempts,
    capturedEpoch,
    currentEpoch,
    now,
    retryAt
  ) = all {
    previousObservable' = observable,
    lastAction' = actionName,
    lastTarget' = target,
    actionTaken' = { tag: actionName, value: { event: event } },
    observable' = makeObservable(state, attempts, capturedEpoch, currentEpoch, now, retryAt),
  }

  action init = {
    val state = EVENTS.mapBy(_ => Pending)
    val attempts = EVENTS.mapBy(_ => 0)
    val capturedEpoch = EVENTS.mapBy(_ => 0)
    val retryAt = EVENTS.mapBy(_ => -1)
    val initial = makeObservable(state, attempts, capturedEpoch, 0, INITIAL_TIME, retryAt)
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
      observable.currentEpoch,
      observable.now,
      observable.retryAt
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
      observable.currentEpoch,
      observable.now,
      observable.retryAt
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
      observable.currentEpoch,
      observable.now,
      observable.retryAt.set(event, -1)
    ),
  }

  action failEvent(event) = {
    val canRetry = observable.attempts.get(event) < MAX_ATTEMPTS
    all {
      observable.state.get(event) == Running,
      record(
        "Fail",
        event,
        Set(event),
        observable.state.set(event, if (canRetry) RetryWaiting else DeadLettered),
        observable.attempts,
        observable.capturedEpoch,
        observable.currentEpoch,
        observable.now,
        observable.retryAt.set(
          event,
          if (canRetry) observable.now + retryDelay(observable.attempts.get(event)) else -1
        )
      ),
    }
  }

  action retryEvent(event) = all {
    observable.state.get(event) == RetryWaiting,
    observable.retryAt.get(event) >= 0,
    observable.now >= observable.retryAt.get(event),
    record(
      "RetryDue",
      event,
      Set(event),
      observable.state.set(event, Pending),
      observable.attempts,
      observable.capturedEpoch,
      observable.currentEpoch,
      observable.now,
      observable.retryAt.set(event, -1)
    ),
  }

  action interruptEvent(event) = all {
    observable.state.get(event) == Running,
    observable.attempts.get(event) > 0,
    record(
      "Interrupt",
      event,
      Set(event),
      observable.state.set(event, Pending),
      observable.attempts.set(event, observable.attempts.get(event) - 1),
      observable.capturedEpoch,
      observable.currentEpoch,
      observable.now,
      observable.retryAt.set(event, -1)
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
      observable.currentEpoch,
      observable.now,
      observable.retryAt.set(event, -1)
    ),
  }

  action tickTime = all {
    observable.now < MAX_TIME,
    EVENTS.exists(event => and {
      observable.state.get(event) == RetryWaiting,
      observable.now < observable.retryAt.get(event),
    }),
    record(
      "Tick",
      "",
      Set(),
      observable.state,
      observable.attempts,
      observable.capturedEpoch,
      observable.currentEpoch,
      observable.now + 1,
      observable.retryAt
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
      observable.currentEpoch + 1,
      observable.now,
      observable.retryAt
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
      observable.currentEpoch,
      observable.now,
      observable.retryAt.set(event, -1)
    ),
  }

  action Lease = { nondet event = EVENTS.oneOf() leaseEvent(event) }
  action Start = { nondet event = EVENTS.oneOf() startEvent(event) }
  action Succeed = { nondet event = EVENTS.oneOf() succeedEvent(event) }
  action Fail = { nondet event = EVENTS.oneOf() failEvent(event) }
  action RetryDue = { nondet event = EVENTS.oneOf() retryEvent(event) }
  action Interrupt = { nondet event = EVENTS.oneOf() interruptEvent(event) }
  action Cancel = { nondet event = EVENTS.oneOf() cancelEvent(event) }
  action Tick = tickTime
  action Reset = resetSession
  action DiscardStale = { nondet event = EVENTS.oneOf() discardEvent(event) }

  action nonRunningProgress(event) = any {
    leaseEvent(event),
    startEvent(event),
    retryEvent(event),
    discardEvent(event),
  }

  action finishAttempt(event) = any {
    succeedEvent(event),
    failEvent(event),
  }

  action advanceRetryClock(event) = all {
    observable.state.get(event) == RetryWaiting,
    observable.now < observable.retryAt.get(event),
    tickTime,
  }

  action step = any {
    Lease,
    Start,
    Succeed,
    Fail,
    RetryDue,
    Interrupt,
    Cancel,
    Tick,
    Reset,
    DiscardStale,
  }

  val TypeOK = and {
    EVENTS.size() > 0,
    MAX_ATTEMPTS > 0,
    MAX_EPOCH >= 0,
    INITIAL_TIME <= MAX_TIME,
    BASE_BACKOFF > 0,
    BASE_BACKOFF <= MAX_BACKOFF,
    MAX_TIME - INITIAL_TIME >= EVENTS.size() * (MAX_ATTEMPTS - 1) * MAX_BACKOFF,
    observable.state.keys() == EVENTS,
    EVENTS.forall(event => observable.state.get(event).in(STATES)),
    observable.attempts.keys() == EVENTS,
    EVENTS.forall(event => observable.attempts.get(event) >= 0 and observable.attempts.get(event) <= MAX_ATTEMPTS),
    observable.maxAttempts == MAX_ATTEMPTS,
    observable.capturedEpoch.keys() == EVENTS,
    EVENTS.forall(event => observable.capturedEpoch.get(event) >= 0 and observable.capturedEpoch.get(event) <= MAX_EPOCH),
    observable.currentEpoch >= 0 and observable.currentEpoch <= MAX_EPOCH,
    observable.now >= INITIAL_TIME and observable.now <= MAX_TIME,
    observable.retryAt.keys() == EVENTS,
    EVENTS.forall(event => observable.retryAt.get(event) == -1 or and {
      observable.retryAt.get(event) >= INITIAL_TIME,
      observable.retryAt.get(event) <= MAX_TIME + MAX_BACKOFF,
    }),
    observable.baseBackoff == BASE_BACKOFF,
    observable.maxBackoff == MAX_BACKOFF,
    previousObservable.state.keys() == EVENTS,
    previousObservable.attempts.keys() == EVENTS,
    previousObservable.capturedEpoch.keys() == EVENTS,
    previousObservable.retryAt.keys() == EVENTS,
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
      and { lastAction == "Lease", previousObservable.state.get(event) == Pending, observable.state.get(event) == Leased },
      and { lastAction == "Start", previousObservable.state.get(event) == Leased, observable.state.get(event) == Running },
      and { lastAction == "Succeed", previousObservable.state.get(event) == Running, observable.state.get(event) == Succeeded },
      and {
        lastAction == "Fail",
        previousObservable.state.get(event) == Running,
        observable.state.get(event) == if (previousObservable.attempts.get(event) < MAX_ATTEMPTS) RetryWaiting else DeadLettered,
      },
      and { lastAction == "RetryDue", previousObservable.state.get(event) == RetryWaiting, observable.state.get(event) == Pending },
      and { lastAction == "Interrupt", previousObservable.state.get(event) == Running, observable.state.get(event) == Pending },
      and { lastAction == "Cancel", previousObservable.state.get(event).in(NON_TERMINAL), observable.state.get(event) == Cancelled },
      and { lastAction == "DiscardStale", previousObservable.state.get(event).in(NON_TERMINAL), observable.state.get(event) == DiscardedStaleEpoch },
    },
  }

  val LegalStateTransitions = or {
    lastAction == "Init" and lastTarget == Set(),
    lastAction.in(Set("Reset", "Tick")) and lastTarget == Set() and observable.state == previousObservable.state,
    EVENTS.exists(event => lastTarget == Set(event) and legalEventTransition(event)),
  }

  val AttemptsChangeOnlyOnStart = if (lastAction == "Start") {
    EVENTS.exists(event => and {
      lastTarget == Set(event),
      observable.attempts.get(event) == previousObservable.attempts.get(event) + 1,
      EVENTS.exclude(Set(event)).forall(other => observable.attempts.get(other) == previousObservable.attempts.get(other)),
    })
  } else if (lastAction == "Interrupt") {
    EVENTS.exists(event => and {
      lastTarget == Set(event),
      observable.attempts.get(event) + 1 == previousObservable.attempts.get(event),
      EVENTS.exclude(Set(event)).forall(other => observable.attempts.get(other) == previousObservable.attempts.get(other)),
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

  val RetryDeadlineMatchesPolicy = and {
    retryDelay(1) == BASE_BACKOFF,
    retryDelay(2) == if (BASE_BACKOFF * 2 < MAX_BACKOFF) BASE_BACKOFF * 2 else MAX_BACKOFF,
    retryDelay(3) == if (BASE_BACKOFF * 4 < MAX_BACKOFF) BASE_BACKOFF * 4 else MAX_BACKOFF,
    retryDelay(MAX_ATTEMPTS + 1) <= MAX_BACKOFF,
    (lastAction == "Fail").implies(
    EVENTS.exists(event => and {
      lastTarget == Set(event),
      if (previousObservable.attempts.get(event) < MAX_ATTEMPTS) {
        observable.retryAt.get(event) == previousObservable.now + retryDelay(previousObservable.attempts.get(event))
      } else {
        observable.retryAt.get(event) == -1
      },
    })
    ),
  }

  val RetryRequiresDeadline = and {
    EVENTS.forall(event =>
      (observable.state.get(event) == RetryWaiting) == (observable.retryAt.get(event) >= 0)
    ),
    (lastAction == "RetryDue").implies(EVENTS.exists(event => and {
      lastTarget == Set(event),
      previousObservable.retryAt.get(event) >= 0,
      previousObservable.now >= previousObservable.retryAt.get(event),
    })),
  }

  temporal NoTerminalRegression = always(EVENTS.forall(event =>
    isTerminal(previousObservable.state.get(event)).implies(
      observable.state.get(event) == previousObservable.state.get(event)
    )
  ))

  temporal TimeNeverDecreases = always(observable.now >= previousObservable.now)

  temporal Fairness = EVENTS.forall(event => and {
    nonRunningProgress(event).weakFair((observable, previousObservable, lastAction, lastTarget)),
    finishAttempt(event).strongFair((observable, previousObservable, lastAction, lastTarget)),
    advanceRetryClock(event).weakFair((observable, previousObservable, lastAction, lastTarget)),
  })

  temporal EventEventuallyTerminates = Fairness.implies(
    EVENTS.forall(event => eventually(observable.terminal.get(event)))
  )
}

module EventDeliveryProof {
  import EventDelivery(
    EVENTS = Set("e1", "e2"),
    MAX_ATTEMPTS = 3,
    MAX_EPOCH = 1,
    INITIAL_TIME = 100,
    MAX_TIME = 120,
    BASE_BACKOFF = 1,
    MAX_BACKOFF = 4
  ).*
}

module EventDeliveryScenarios {
  import EventDelivery(
    EVENTS = Set("e1"),
    MAX_ATTEMPTS = 2,
    MAX_EPOCH = 1,
    INITIAL_TIME = 100,
    MAX_TIME = 112,
    BASE_BACKOFF = 1,
    MAX_BACKOFF = 4
  ).*

  run success = init.then(Lease).then(Start).then(Succeed)
    .expect(observable.state.get("e1") == Succeeded)

  run retryTiming = init.then(Lease).then(Start).then(Fail).then(Tick).then(RetryDue)
    .expect(observable.state.get("e1") == Pending and observable.now == 101)

  run interrupt = init.then(Lease).then(Start).then(Interrupt)
    .expect(observable.state.get("e1") == Pending and observable.attempts.get("e1") == 0)

  run staleDiscard = init.then(Reset).then(DiscardStale)
    .expect(observable.state.get("e1") == DiscardedStaleEpoch)

  run cancel = init.then(Cancel)
    .expect(observable.state.get("e1") == Cancelled)
}

module EventDeliveryConnect {
  import EventDelivery(
    EVENTS = Set("e1", "e2"),
    MAX_ATTEMPTS = 3,
    MAX_EPOCH = 1,
    INITIAL_TIME = 100,
    MAX_TIME = 120,
    BASE_BACKOFF = 1,
    MAX_BACKOFF = 4
  ).*
}
