// Atomic Firestore publication and its complete logical change batch.

module AtomicCommitOutbox {
  const DOCS: Set[str]
  const MAX_VERSION: int

  type Observable = {
    documents: str -> int,
    outbox: Set[str],
    transactionState: str,
  }
  type ActionTaken = { tag: str, value: { doc: str } }

  var observable: Observable
  var previousObservable: Observable
  var staged: Set[str]
  var stagedVersion: str -> int
  var stagedEvents: Set[str]
  var hasConflict: bool
  var previousConflict: bool
  var lastStaged: Set[str]
  var lastStagedEvents: Set[str]
  var lastAction: str
  var actionTaken: ActionTaken

  pure val PHASES = Set("Idle", "Staging", "Committed", "Aborted")
  pure val ACTIONS = Set(
    "Init", "Begin", "StageWrite", "StageOutbox", "DetectConflict", "Commit", "Abort"
  )

  action record(actionName, doc) = all {
    previousObservable' = observable,
    previousConflict' = hasConflict,
    lastStaged' = staged,
    lastStagedEvents' = stagedEvents,
    lastAction' = actionName,
    actionTaken' = { tag: actionName, value: { doc: doc } },
  }

  action init = {
    val initial = {
      documents: DOCS.mapBy(_ => 0),
      outbox: Set(),
      transactionState: "Idle",
    }
    all {
      observable' = initial,
      previousObservable' = initial,
      staged' = Set(),
      stagedVersion' = DOCS.mapBy(_ => 0),
      stagedEvents' = Set(),
      hasConflict' = false,
      previousConflict' = false,
      lastStaged' = Set(),
      lastStagedEvents' = Set(),
      lastAction' = "Init",
      actionTaken' = { tag: "init", value: { doc: "" } },
    }
  }

  action begin = all {
    observable.transactionState == "Idle",
    record("Begin", ""),
    observable' = {
      documents: observable.documents,
      outbox: observable.outbox,
      transactionState: "Staging",
    },
    staged' = Set(),
    stagedVersion' = observable.documents,
    stagedEvents' = Set(),
    hasConflict' = false,
  }

  action stageWrite(doc) = all {
    observable.transactionState == "Staging",
    not(staged.contains(doc)),
    observable.documents.get(doc) < MAX_VERSION,
    record("StageWrite", doc),
    observable' = observable,
    staged' = staged.union(Set(doc)),
    stagedVersion' = stagedVersion.set(doc, observable.documents.get(doc) + 1),
    stagedEvents' = stagedEvents,
    hasConflict' = hasConflict,
  }

  action stageOutbox(doc) = all {
    observable.transactionState == "Staging",
    staged.contains(doc),
    record("StageOutbox", doc),
    observable' = observable,
    staged' = staged,
    stagedVersion' = stagedVersion,
    stagedEvents' = stagedEvents.union(Set(doc)),
    hasConflict' = hasConflict,
  }

  action detectConflict = all {
    observable.transactionState == "Staging",
    record("DetectConflict", ""),
    observable' = observable,
    staged' = staged,
    stagedVersion' = stagedVersion,
    stagedEvents' = stagedEvents,
    hasConflict' = true,
  }

  action publishCommit = {
    val publishDocs = DOCS.mapBy(doc =>
      if (staged.contains(doc)) stagedVersion.get(doc) else observable.documents.get(doc))
    all {
      observable.transactionState == "Staging",
      not(hasConflict),
      staged.size() > 0,
      stagedEvents == staged,
      record("Commit", ""),
      observable' = {
        documents: publishDocs,
        outbox: observable.outbox.union(stagedEvents),
        transactionState: "Committed",
      },
      staged' = staged,
      stagedVersion' = stagedVersion,
      stagedEvents' = stagedEvents,
      hasConflict' = hasConflict,
    }
  }

  action rejectCommit = all {
    observable.transactionState == "Staging",
    hasConflict,
    record("Abort", ""),
    observable' = {
      documents: observable.documents,
      outbox: observable.outbox,
      transactionState: "Aborted",
    },
    staged' = staged,
    stagedVersion' = stagedVersion,
    stagedEvents' = stagedEvents,
    hasConflict' = hasConflict,
  }

  action Begin = begin
  action StageWrite = { nondet doc = DOCS.oneOf() stageWrite(doc) }
  action StageOutbox = { nondet doc = DOCS.oneOf() stageOutbox(doc) }
  action DetectConflict = detectConflict
  action Commit = publishCommit
  action Abort = rejectCommit

  action step = any { Begin, StageWrite, StageOutbox, DetectConflict, Commit, Abort }

  val TypeOK = and {
    DOCS.size() > 0,
    MAX_VERSION > 0,
    observable.documents.keys() == DOCS,
    DOCS.forall(doc => observable.documents.get(doc) >= 0
      and observable.documents.get(doc) <= MAX_VERSION),
    observable.outbox.subseteq(DOCS),
    observable.transactionState.in(PHASES),
    previousObservable.documents.keys() == DOCS,
    staged.subseteq(DOCS),
    stagedVersion.keys() == DOCS,
    stagedEvents.subseteq(DOCS),
    lastStaged.subseteq(DOCS),
    lastStagedEvents.subseteq(DOCS),
    lastAction.in(ACTIONS),
  }

  val AtomicCommit = if (lastAction != "Commit") {
    observable.documents == previousObservable.documents
      and observable.outbox == previousObservable.outbox
  } else {
    and {
      DOCS.forall(doc =>
        (observable.documents.get(doc) != previousObservable.documents.get(doc))
          == lastStaged.contains(doc)),
      DOCS.forall(doc =>
        (observable.outbox.contains(doc) and not(previousObservable.outbox.contains(doc)))
          == lastStagedEvents.contains(doc)),
    }
  }

  val OutboxCompleteness = (lastAction == "Commit").implies(
    lastStaged.subseteq(observable.outbox)
  )

  val NoPartialTransaction = (lastAction == "Commit").implies(DOCS.forall(doc =>
    if (lastStaged.contains(doc)) {
      observable.documents.get(doc) == previousObservable.documents.get(doc) + 1
    } else {
      observable.documents.get(doc) == previousObservable.documents.get(doc)
    }
  ))

  val ConflictNeverCommits = (lastAction == "Commit").implies(not(previousConflict))
}

module AtomicCommitOutboxProof {
  import AtomicCommitOutbox(DOCS = Set("d1", "d2"), MAX_VERSION = 2).*
}

module AtomicCommitOutboxScenarios {
  import AtomicCommitOutbox(DOCS = Set("d1", "d2"), MAX_VERSION = 2).*

  run commit = init.then(Begin).then(stageWrite("d1")).then(stageOutbox("d1"))
    .then(stageWrite("d2")).then(stageOutbox("d2")).then(Commit)
    .expect(observable.outbox == Set("d1", "d2"))

  run conflict = init.then(Begin).then(stageWrite("d1")).then(stageOutbox("d1"))
    .then(DetectConflict).then(Abort)
    .expect(observable.transactionState == "Aborted")

  run abort = init.then(Begin).then(DetectConflict).then(Abort)
    .expect(observable.documents == DOCS.mapBy(_ => 0))
}

module AtomicCommitOutboxConnect {
  import AtomicCommitOutbox(DOCS = Set("d1", "d2"), MAX_VERSION = 2).*
}
