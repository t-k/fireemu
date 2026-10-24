// Bounded actual commit-limit rejection; unique indexes and general quota accounting are excluded.

module LimitRejection {
  const DOCS: Set[str]
  const FANOUT: int
  type Observable = {
    documents: str -> int,
    outbox: Set[str],
    transactionState: str,
    reservedEvents: int,
    publishedEvents: int,
    eventGeneration: int,
  }
  type ActionTaken = { tag: str, value: { doc: str, kind: str } }
  var observable: Observable
  var previousObservable: Observable
  var staged: Set[str]
  var lastAction: str
  var lastKind: str
  var actionTaken: ActionTaken

  pure val EMPTY = {
    documents: DOCS.mapBy(_ => 0), outbox: Set(), transactionState: "Idle",
    reservedEvents: 0, publishedEvents: 0, eventGeneration: 0,
  }
  action record(tag, doc, kind) = all {
    previousObservable' = observable,
    lastAction' = tag,
    lastKind' = kind,
    actionTaken' = { tag: tag, value: { doc: doc, kind: kind } },
  }
  action init = all {
    observable' = EMPTY, previousObservable' = EMPTY, staged' = Set(),
    lastAction' = "Init", lastKind' = "",
    actionTaken' = { tag: "init", value: { doc: "", kind: "" } },
  }
  action seed = all {
    observable == EMPTY,
    record("Seed", "", ""),
    observable' = { ...observable,
      documents: observable.documents.set("d1", 1), outbox: Set("d1"),
      publishedEvents: FANOUT,
    },
    staged' = staged,
  }
  action begin = all {
    observable.transactionState == "Idle",
    record("Begin", "", ""),
    observable' = { ...observable, transactionState: "Staging" },
    staged' = Set(),
  }
  action stage(doc) = all {
    observable.transactionState == "Staging",
    not(staged.contains(doc)),
    record("Stage", doc, ""),
    observable' = observable,
    staged' = staged.union(Set(doc)),
  }
  action attempt(kind) = all {
    observable.transactionState == "Staging",
    staged.size() > 0,
    record("Attempt", "", kind),
    observable' = if (kind == "valid") {
      val version = if (DOCS.exists(doc => observable.documents.get(doc) > 0)) 2 else 1
      { ...observable,
        documents: DOCS.mapBy(doc => if (staged.contains(doc)) version else observable.documents.get(doc)),
        outbox: staged,
        transactionState: "Committed",
        publishedEvents: observable.publishedEvents + staged.size() * FANOUT
          - staged.filter(doc => observable.documents.get(doc) > 0).size(),
      }
    } else {
      { ...observable, transactionState: "Aborted" }
    },
    staged' = staged,
  }
  action reset = all {
    record("Reset", "", ""),
    observable' = EMPTY,
    staged' = Set(),
  }
  action Seed = seed
  action Begin = begin
  action Stage = { nondet doc = DOCS.oneOf() stage(doc) }
  action Attempt = { nondet kind = Set("valid", "size", "transforms").oneOf() attempt(kind) }
  action Reset = reset
  action step = any { Seed, Begin, Stage, Attempt, Reset }

  val TypeOK = and {
    observable.documents.keys() == DOCS,
    DOCS.forall(doc => observable.documents.get(doc).in(0.to(2))),
    observable.outbox.subseteq(DOCS),
    observable.transactionState.in(Set("Idle", "Staging", "Committed", "Aborted")),
    observable.reservedEvents == 0,
    observable.publishedEvents.in(0.to(6)),
    observable.eventGeneration == 0,
    staged.subseteq(DOCS),
  }
  val LimitRejectionAtomicity = (lastAction == "Attempt" and lastKind != "valid").implies(and {
    observable.documents == previousObservable.documents,
    observable.outbox == previousObservable.outbox,
    observable.reservedEvents == previousObservable.reservedEvents,
    observable.publishedEvents == previousObservable.publishedEvents,
    observable.eventGeneration == previousObservable.eventGeneration,
    observable.transactionState == "Aborted",
  })
  val NoPublicationDuringStaging = lastAction.in(Set("Begin", "Stage")).implies(and {
    observable.documents == previousObservable.documents,
    observable.outbox == previousObservable.outbox,
    observable.publishedEvents == previousObservable.publishedEvents,
  })
  val ValidCommitPublishesAllWrites = (lastAction == "Attempt" and lastKind == "valid").implies(and {
    staged.subseteq(observable.outbox),
    staged.forall(doc => observable.documents.get(doc) > previousObservable.documents.get(doc)),
    observable.publishedEvents == previousObservable.publishedEvents + staged.size() * FANOUT
      - staged.filter(doc => previousObservable.documents.get(doc) > 0).size(),
  })
}
module LimitRejectionProof {
  import LimitRejection(DOCS = Set("d1", "d2"), FANOUT = 2).*
}
module LimitRejectionScenarios {
  import LimitRejection(DOCS = Set("d1", "d2"), FANOUT = 2).*
  run sizeEmpty = init.then(Begin).then(stage("d1")).then(stage("d2")).then(attempt("size"))
    .expect(observable.documents == DOCS.mapBy(_ => 0))
  run sizeSeeded = init.then(Seed).then(Begin).then(stage("d1")).then(stage("d2")).then(attempt("size"))
    .expect(observable.documents.get("d1") == 1)
  run transformsSeeded = init.then(Seed).then(Begin).then(stage("d2")).then(stage("d1")).then(attempt("transforms"))
    .expect(observable.publishedEvents == 2)
  run valid = init.then(Seed).then(Begin).then(stage("d1")).then(stage("d2")).then(attempt("valid"))
    .then(Reset).expect(observable == EMPTY)
}
module LimitRejectionConnect {
  import LimitRejection(DOCS = Set("d1", "d2"), FANOUT = 2).*
}
