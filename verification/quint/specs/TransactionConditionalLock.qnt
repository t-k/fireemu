// Two read-write transactions contend for one application-level conditional lock under
// production's pessimistic locking: a commit that runs into the other client's read lock is
// held back and completes when that client's own commit is aborted as the deadlock victim.

module TransactionConditionalLock {
  const CLIENTS: Set[str]

  type Observable = {
    phase: str -> str,
    locked: bool,
    observations: str -> List[bool],
    acted: Set[str],
  }
  type ActionTaken = { tag: str, value: { client: str } }

  var observable: Observable
  var lastAction: str
  var actionTaken: ActionTaken

  pure val PHASES = Set("Ready", "Read", "Held", "Committed", "Aborted", "Retried", "Rejected", "Done")
  pure val ACTIONS = Set(
    "Init", "ReadUnlocked", "Commit", "AbortStale", "Retry", "RejectLocked",
    "RunProtectedAction", "Release"
  )

  action record(actionName, client, nextObservable) = all {
    observable' = nextObservable,
    lastAction' = actionName,
    actionTaken' = { tag: actionName, value: { client: client } },
  }

  action init = {
    val initial = {
      phase: CLIENTS.mapBy(_ => "Ready"),
      locked: false,
      observations: CLIENTS.mapBy(_ => List()),
      acted: Set(),
    }
    all {
      observable' = initial,
      lastAction' = "Init",
      actionTaken' = { tag: "init", value: { client: "" } },
    }
  }

  action readUnlocked(client) = all {
    observable.phase.get(client) == "Ready",
    not(observable.locked),
    record("ReadUnlocked", client, {
      phase: observable.phase.set(client, "Read"),
      locked: observable.locked,
      observations: observable.observations.set(
        client, observable.observations.get(client).append(observable.locked)),
      acted: observable.acted,
    }),
  }

  action commit(client) = all {
    observable.phase.get(client) == "Read",
    CLIENTS.forall(other => observable.observations.get(other) == List(false)),
    not(observable.locked),
    // A commit that runs into a held-back commit is the deadlock victim (abortStale), never
    // a second winner.
    CLIENTS.exclude(Set(client)).forall(other => observable.phase.get(other) != "Held"),
    // Another client still holding its read lock holds this commit back; it completes when
    // that client's commit is aborted (abortStale).
    val heldBack = CLIENTS.exclude(Set(client)).exists(other => observable.phase.get(other) == "Read")
    record("Commit", client, {
      phase: observable.phase.set(client, if (heldBack) "Held" else "Committed"),
      locked: not(heldBack),
      observations: observable.observations,
      acted: observable.acted,
    }),
  }

  action abortStale(client) = all {
    observable.phase.get(client) == "Read",
    or {
      observable.locked,
      CLIENTS.exclude(Set(client)).exists(other => observable.phase.get(other) == "Held"),
    },
    // The stale commit is aborted: as the deadlock victim when the other commit is held
    // back (which then completes), or as a stale read set once the lock is committed.
    record("AbortStale", client, {
      phase: CLIENTS.exclude(Set(client)).fold(
        observable.phase.set(client, "Aborted"),
        (phases, other) => if (phases.get(other) == "Held") phases.set(other, "Committed") else phases
      ),
      locked: true,
      observations: observable.observations,
      acted: observable.acted,
    }),
  }

  action retry(client) = all {
    observable.phase.get(client) == "Aborted",
    record("Retry", client, {
      phase: observable.phase.set(client, "Retried"),
      locked: observable.locked,
      observations: observable.observations.set(
        client, observable.observations.get(client).append(observable.locked)),
      acted: observable.acted,
    }),
  }

  action rejectLocked(client) = all {
    observable.phase.get(client) == "Retried",
    observable.observations.get(client).length() == 2,
    observable.observations.get(client).nth(1),
    record("RejectLocked", client, {
      phase: observable.phase.set(client, "Rejected"),
      locked: observable.locked,
      observations: observable.observations,
      acted: observable.acted,
    }),
  }

  action runProtectedAction(client) = all {
    observable.phase.get(client) == "Committed",
    not(observable.acted.contains(client)),
    record("RunProtectedAction", client, {
      phase: observable.phase,
      locked: observable.locked,
      observations: observable.observations,
      acted: observable.acted.union(Set(client)),
    }),
  }

  action release(client) = all {
    observable.phase.get(client) == "Committed",
    observable.acted.contains(client),
    CLIENTS.exclude(Set(client)).forall(other => observable.phase.get(other) == "Rejected"),
    record("Release", client, {
      phase: observable.phase.set(client, "Done"),
      locked: false,
      observations: observable.observations,
      acted: observable.acted,
    }),
  }

  action ReadUnlocked = { nondet client = CLIENTS.oneOf() readUnlocked(client) }
  action Commit = { nondet client = CLIENTS.oneOf() commit(client) }
  action AbortStale = { nondet client = CLIENTS.oneOf() abortStale(client) }
  action Retry = { nondet client = CLIENTS.oneOf() retry(client) }
  action RejectLocked = { nondet client = CLIENTS.oneOf() rejectLocked(client) }
  action RunProtectedAction = { nondet client = CLIENTS.oneOf() runProtectedAction(client) }
  action Release = { nondet client = CLIENTS.oneOf() release(client) }

  action step = any {
    ReadUnlocked,
    Commit,
    AbortStale,
    Retry,
    RejectLocked,
    RunProtectedAction,
    Release,
  }

  val TypeOK = and {
    CLIENTS.size() == 2,
    observable.phase.keys() == CLIENTS,
    observable.observations.keys() == CLIENTS,
    CLIENTS.forall(client => observable.phase.get(client).in(PHASES)),
    CLIENTS.forall(client => observable.observations.get(client).length() <= 2),
    observable.acted.subseteq(CLIENTS),
    lastAction.in(ACTIONS),
  }

  // A held-back commit is the winner in waiting: nobody else may commit past it.
  val OneWinner = CLIENTS.filter(client =>
    observable.phase.get(client).in(Set("Held", "Committed", "Done"))).size() <= 1

  val AtMostOneProtectedAction = observable.acted.size() <= 1

  val RetryReadsCommittedLock = CLIENTS.forall(client =>
    observable.phase.get(client).in(Set("Retried", "Rejected")).implies(and {
      observable.observations.get(client).length() == 2,
      observable.observations.get(client).nth(1),
    })
  )
}

module TransactionConditionalLockProof {
  import TransactionConditionalLock(CLIENTS = Set("c1", "c2")).*
}

module TransactionConditionalLockScenarios {
  import TransactionConditionalLock(CLIENTS = Set("c1", "c2")).*

  run firstClientWins = init.then(readUnlocked("c1")).then(readUnlocked("c2"))
    .then(commit("c1")).then(abortStale("c2")).then(retry("c2"))
    .then(rejectLocked("c2")).then(runProtectedAction("c1")).then(release("c1"))
    .expect(not(observable.locked) and observable.acted == Set("c1"))

  run secondClientWins = init.then(readUnlocked("c1")).then(readUnlocked("c2"))
    .then(commit("c2")).then(abortStale("c1")).then(retry("c1"))
    .then(rejectLocked("c1")).then(runProtectedAction("c2"))
    .expect(observable.locked and observable.acted == Set("c2"))

  run retrySeesCommittedLock = init.then(readUnlocked("c1")).then(readUnlocked("c2"))
    .then(commit("c1")).then(abortStale("c2")).then(retry("c2"))
    .expect(observable.observations.get("c2") == List(false, true))
}

module TransactionConditionalLockConnect {
  import TransactionConditionalLock(CLIENTS = Set("c1", "c2")).*
}
