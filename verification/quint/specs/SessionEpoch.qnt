// Session lifecycle, epoch isolation, and stale-work rejection.

module SessionEpoch {
  const WORKERS: Set[str]
  const MAX_EPOCH: int

  type Observable = { state: str, epoch: int, workEpochResult: str }
  type Applied = { worker: str, work: int, session: int }
  type ActionTaken = { tag: str, value: { worker: str } }

  var observable: Observable
  var previousObservable: Observable
  var workEpoch: str -> int
  var applied: Set[Applied]
  var previousState: str
  var lastCapturedEpoch: int
  var lastAction: str
  var actionTaken: ActionTaken

  pure val NO_WORK = MAX_EPOCH + 1
  pure val STATES = Set("Creating", "Active", "Resetting", "Closing", "Closed")
  pure val WORK_RESULTS = Set("NotChecked", "Proceed", "DiscardedStaleEpoch")
  pure val ACTIONS = Set(
    "Init",
    "Activate",
    "BeginReset",
    "CompleteReset",
    "BeginClose",
    "CompleteClose",
    "CaptureWork",
    "ApplyWork",
    "DiscardWork"
  )

  action record(actionName, worker, capturedEpoch, nextObservable) = all {
    previousObservable' = observable,
    previousState' = observable.state,
    lastCapturedEpoch' = capturedEpoch,
    lastAction' = actionName,
    actionTaken' = { tag: actionName, value: { worker: worker } },
    observable' = nextObservable,
  }

  action init = {
    val initial = { state: "Creating", epoch: 0, workEpochResult: "NotChecked" }
    all {
      observable' = initial,
      previousObservable' = initial,
      workEpoch' = WORKERS.mapBy(_ => NO_WORK),
      applied' = Set(),
      previousState' = "Creating",
      lastCapturedEpoch' = NO_WORK,
      lastAction' = "Init",
      actionTaken' = { tag: "init", value: { worker: "" } },
    }
  }

  action activate = all {
    observable.state == "Creating",
    record("Activate", "", NO_WORK, {
      state: "Active",
      epoch: observable.epoch,
      workEpochResult: observable.workEpochResult,
    }),
    workEpoch' = workEpoch,
    applied' = applied,
  }

  action beginReset = {
    val nextEpoch = observable.epoch + 1
    all {
      observable.state == "Active",
      observable.epoch < MAX_EPOCH,
      record("BeginReset", "", NO_WORK, {
        state: "Resetting",
        epoch: nextEpoch,
        workEpochResult: observable.workEpochResult,
      }),
      workEpoch' = workEpoch,
      applied' = applied,
    }
  }

  action completeReset = all {
    observable.state == "Resetting",
    record("CompleteReset", "", NO_WORK, {
      state: "Active",
      epoch: observable.epoch,
      workEpochResult: observable.workEpochResult,
    }),
    workEpoch' = workEpoch,
    applied' = applied,
  }

  action beginClose = all {
    observable.state.in(Set("Creating", "Active", "Resetting")),
    record("BeginClose", "", NO_WORK, {
      state: "Closing",
      epoch: observable.epoch,
      workEpochResult: observable.workEpochResult,
    }),
    workEpoch' = workEpoch,
    applied' = applied,
  }

  action completeClose = all {
    observable.state == "Closing",
    record("CompleteClose", "", NO_WORK, {
      state: "Closed",
      epoch: observable.epoch,
      workEpochResult: observable.workEpochResult,
    }),
    workEpoch' = workEpoch,
    applied' = applied,
  }

  action captureWork(worker) = all {
    observable.state == "Active",
    workEpoch.get(worker) == NO_WORK,
    record("CaptureWork", worker, observable.epoch, observable),
    workEpoch' = workEpoch.set(worker, observable.epoch),
    applied' = applied,
  }

  action applyWork(worker) = all {
    workEpoch.get(worker) != NO_WORK,
    observable.state == "Active",
    workEpoch.get(worker) == observable.epoch,
    record("ApplyWork", worker, NO_WORK, {
      state: observable.state,
      epoch: observable.epoch,
      workEpochResult: "Proceed",
    }),
    workEpoch' = workEpoch.set(worker, NO_WORK),
    applied' = applied.union(Set({
      worker: worker,
      work: workEpoch.get(worker),
      session: observable.epoch,
    })),
  }

  action discardWork(worker) = all {
    workEpoch.get(worker) != NO_WORK,
    workEpoch.get(worker) != observable.epoch,
    record("DiscardWork", worker, NO_WORK, {
      state: observable.state,
      epoch: observable.epoch,
      workEpochResult: "DiscardedStaleEpoch",
    }),
    workEpoch' = workEpoch.set(worker, NO_WORK),
    applied' = applied,
  }

  action Activate = activate
  action BeginReset = beginReset
  action CompleteReset = completeReset
  action BeginClose = beginClose
  action CompleteClose = completeClose
  action CaptureWork = { nondet worker = WORKERS.oneOf() captureWork(worker) }
  action ApplyWork = { nondet worker = WORKERS.oneOf() applyWork(worker) }
  action DiscardWork = { nondet worker = WORKERS.oneOf() discardWork(worker) }

  action step = any {
    Activate,
    BeginReset,
    CompleteReset,
    BeginClose,
    CompleteClose,
    CaptureWork,
    ApplyWork,
    DiscardWork,
  }

  val TypeOK = and {
    WORKERS.size() > 0,
    MAX_EPOCH > 0,
    observable.state.in(STATES),
    observable.epoch >= 0 and observable.epoch <= MAX_EPOCH,
    observable.workEpochResult.in(WORK_RESULTS),
    previousObservable.state.in(STATES),
    previousObservable.epoch >= 0 and previousObservable.epoch <= MAX_EPOCH,
    workEpoch.keys() == WORKERS,
    WORKERS.forall(worker => workEpoch.get(worker) >= 0 and workEpoch.get(worker) <= NO_WORK),
    applied.forall(effect => and {
      effect.worker.in(WORKERS),
      effect.work >= 0 and effect.work <= MAX_EPOCH,
      effect.session >= 0 and effect.session <= MAX_EPOCH,
    }),
    previousState.in(STATES),
    lastCapturedEpoch >= 0 and lastCapturedEpoch <= NO_WORK,
    lastAction.in(ACTIONS),
  }

  val EpochIsolation = applied.forall(effect => effect.work == effect.session)

  val WorkCapturedOnlyWhileActive = (lastAction == "CaptureWork").implies(and {
    previousState == "Active",
    lastCapturedEpoch == observable.epoch,
  })

  temporal EpochNeverDecreases = always(observable.epoch >= previousObservable.epoch)

  temporal Fairness = CompleteReset.weakFair((
    observable,
    previousObservable,
    workEpoch,
    applied,
    previousState,
    lastCapturedEpoch,
    lastAction
  ))

  temporal ResetEventuallyActivatesNewEpoch = Fairness.implies(always(
    (observable.state == "Resetting").implies(eventually(
      observable.state.in(Set("Active", "Closing", "Closed"))
    ))
  ))
}

module SessionEpochProof {
  import SessionEpoch(WORKERS = Set("w1", "w2"), MAX_EPOCH = 2).*
}

module SessionEpochScenarios {
  import SessionEpoch(WORKERS = Set("w1", "w2"), MAX_EPOCH = 2).*

  run activateScenario = init.then(Activate)
    .expect(observable.state == "Active")

  run applyCurrent = init.then(Activate).then(captureWork("w1")).then(applyWork("w1"))
    .expect(observable.workEpochResult == "Proceed")

  run resetScenario = init.then(Activate).then(BeginReset).then(CompleteReset)
    .expect(observable.state == "Active" and observable.epoch == 1)

  run closeScenario = init.then(BeginClose).then(CompleteClose)
    .expect(observable.state == "Closed")

  run discardStale = init.then(Activate).then(captureWork("w1"))
    .then(BeginReset).then(CompleteReset).then(discardWork("w1"))
    .expect(observable.workEpochResult == "DiscardedStaleEpoch")
}

module SessionEpochConnect {
  import SessionEpoch(WORKERS = Set("w1", "w2"), MAX_EPOCH = 2).*
}
