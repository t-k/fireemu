// Two read-write transactions contend for one application-level conditional lock under
// production's pessimistic locking: a commit that runs into the other client's read lock is
// held back; on deadlock the younger (begin instant, begin order) loses. This bounded
// model pins both begin instants, so age is the transaction-id tie-break in begin order.

module TransactionConditionalLock {
  const CLIENTS: Set[str]

  type Observable = {
    phase: str -> str,
    age: str -> int,
    startedAt: str -> int,
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
      age: CLIENTS.mapBy(_ => 0),
      startedAt: CLIENTS.mapBy(_ => -1),
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
      // Both lazy begins occur at instant zero; ids still increase in begin order.
      age: observable.age.set(client, CLIENTS.filter(c => observable.age.get(c) > 0).size() + 1),
      startedAt: observable.startedAt.set(client, 0),
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
      age: observable.age,
      startedAt: observable.startedAt,
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
    // Resolve the cycle only when the second Commit arrives; never wound or refuse at first wait.
    val holder = CLIENTS.exclude(Set(client)).filter(other => observable.phase.get(other) == "Held")
    val ownWins = holder.exists(other => or {
      observable.startedAt.get(client) < observable.startedAt.get(other),
      observable.startedAt.get(client) == observable.startedAt.get(other) and observable.age.get(client) < observable.age.get(other),
    })
    record("AbortStale", client, {
      phase: holder.fold(
        observable.phase.set(client, if (ownWins) "Committed" else "Aborted"),
        (phases, other) => phases.set(other, if (ownWins) "Aborted" else "Committed")
      ),
      age: observable.age,
      startedAt: observable.startedAt,
      locked: true,
      observations: observable.observations,
      acted: observable.acted,
    }),
  }

  action retry(client) = all {
    observable.phase.get(client) == "Aborted",
    record("Retry", client, {
      phase: observable.phase.set(client, "Retried"),
      age: observable.age,
      startedAt: observable.startedAt,
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
      age: observable.age,
      startedAt: observable.startedAt,
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
      age: observable.age,
      startedAt: observable.startedAt,
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
      age: observable.age,
      startedAt: observable.startedAt,
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
    observable.age.keys() == CLIENTS,
    observable.startedAt.keys() == CLIENTS,
    CLIENTS.forall(client => observable.startedAt.get(client) == (if (observable.age.get(client) == 0) -1 else 0)),
    CLIENTS.forall(client => observable.age.get(client).in(0.to(CLIENTS.size()))),
    observable.observations.keys() == CLIENTS,
    CLIENTS.forall(client => observable.phase.get(client).in(PHASES)),
    CLIENTS.forall(client => observable.observations.get(client).length() <= 2),
    observable.acted.subseteq(CLIENTS),
    lastAction.in(ACTIONS),
  }

  // A held-back commit is pending; deadlock resolution leaves only one committed winner.
  val OneWinner = CLIENTS.filter(client =>
    observable.phase.get(client).in(Set("Held", "Committed", "Done"))).size() <= 1

  val OlderWins = CLIENTS.forall(client =>
    observable.phase.get(client).in(Set("Committed", "Done")).implies(
      CLIENTS.exclude(Set(client)).forall(other => or {
        observable.startedAt.get(client) < observable.startedAt.get(other),
        observable.startedAt.get(client) == observable.startedAt.get(other) and observable.age.get(client) < observable.age.get(other),
      })
    )
  )

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

  run secondClientWins = init.then(readUnlocked("c2")).then(readUnlocked("c1"))
    .then(commit("c2")).then(abortStale("c1")).then(retry("c1"))
    .then(rejectLocked("c1")).then(runProtectedAction("c2"))
    .expect(observable.locked and observable.acted == Set("c2"))

  run youngerWaitsThenLoses = init.then(readUnlocked("c1")).then(readUnlocked("c2"))
    .then(commit("c2")).expect(observable.phase.get("c2") == "Held" and observable.phase.get("c1") == "Read")
    .then(abortStale("c1")).then(retry("c2")).then(rejectLocked("c2"))
    .then(runProtectedAction("c1")).then(release("c1"))
    .expect(not(observable.locked) and observable.acted == Set("c1"))

  run retrySeesCommittedLock = init.then(readUnlocked("c1")).then(readUnlocked("c2"))
    .then(commit("c1")).then(abortStale("c2")).then(retry("c2"))
    .expect(observable.observations.get("c2") == List(false, true))
}

module TransactionConditionalLockConnect {
  import TransactionConditionalLock(CLIENTS = Set("c1", "c2")).*
}
