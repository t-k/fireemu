// Storage identity allocation, metadata updates, imports, and snapshot restore.

module StorageGeneration {
  const MAX_GENERATION: int
  const MAX_METAGENERATION: int
  const IMPORTED_GENERATION: int

  type Observable = {
    exists: bool,
    generation: int,
    metageneration: int,
    highWater: int,
    issued: Set[int],
  }
  type ActionTaken = { tag: str, value: { unused: str } }

  var observable: Observable
  var previousObservable: Observable
  var snapshotCaptured: bool
  var snapshotExists: bool
  var snapshotGeneration: int
  var snapshotMetageneration: int
  var snapshotHighWater: int
  var lastAction: str
  var actionTaken: ActionTaken

  pure val ACTIONS = Set(
    "Init",
    "PutData",
    "PatchMetadata",
    "Delete",
    "CaptureSnapshot",
    "RestoreSnapshot",
    "ImportData"
  )

  action record(actionName, nextObservable) = all {
    previousObservable' = observable,
    observable' = nextObservable,
    lastAction' = actionName,
    actionTaken' = { tag: actionName, value: { unused: "" } },
  }

  action init = {
    val initial = {
      exists: false,
      generation: 0,
      metageneration: 0,
      highWater: 0,
      issued: Set(),
    }
    all {
      observable' = initial,
      previousObservable' = initial,
      snapshotCaptured' = false,
      snapshotExists' = false,
      snapshotGeneration' = 0,
      snapshotMetageneration' = 0,
      snapshotHighWater' = 0,
      lastAction' = "Init",
      actionTaken' = { tag: "init", value: { unused: "" } },
    }
  }

  action putData = {
    val allocatedGeneration = observable.highWater + 1
    all {
      observable.highWater < MAX_GENERATION,
      record("PutData", {
        exists: true,
        generation: allocatedGeneration,
        metageneration: 1,
        highWater: observable.highWater + 1,
        issued: observable.issued.union(Set(observable.highWater + 1)),
      }),
      snapshotCaptured' = snapshotCaptured,
      snapshotExists' = snapshotExists,
      snapshotGeneration' = snapshotGeneration,
      snapshotMetageneration' = snapshotMetageneration,
      snapshotHighWater' = snapshotHighWater,
    }
  }

  action patchMetadata = {
    val patchedGeneration = observable.generation
    val patchedMetageneration = observable.metageneration + 1
    all {
      observable.exists,
      observable.metageneration < MAX_METAGENERATION,
      record("PatchMetadata", {
        exists: true,
        generation: patchedGeneration,
        metageneration: patchedMetageneration,
        highWater: observable.highWater,
        issued: observable.issued,
      }),
      snapshotCaptured' = snapshotCaptured,
      snapshotExists' = snapshotExists,
      snapshotGeneration' = snapshotGeneration,
      snapshotMetageneration' = snapshotMetageneration,
      snapshotHighWater' = snapshotHighWater,
    }
  }

  action deleteData = {
    val deletedHighWater = observable.highWater
    all {
      observable.exists,
      record("Delete", {
        exists: false,
        generation: 0,
        metageneration: 0,
        highWater: deletedHighWater,
        issued: observable.issued,
      }),
      snapshotCaptured' = snapshotCaptured,
      snapshotExists' = snapshotExists,
      snapshotGeneration' = snapshotGeneration,
      snapshotMetageneration' = snapshotMetageneration,
      snapshotHighWater' = snapshotHighWater,
    }
  }

  action captureSnapshot = all {
    not(snapshotCaptured),
    record("CaptureSnapshot", observable),
    snapshotCaptured' = true,
    snapshotExists' = observable.exists,
    snapshotGeneration' = observable.generation,
    snapshotMetageneration' = observable.metageneration,
    snapshotHighWater' = observable.highWater,
  }

  action restoreSnapshot = {
    val restoredHighWater = if (observable.highWater >= snapshotHighWater) observable.highWater else snapshotHighWater
    all {
      snapshotCaptured,
      record("RestoreSnapshot", {
        exists: snapshotExists,
        generation: snapshotGeneration,
        metageneration: snapshotMetageneration,
        highWater: restoredHighWater,
        issued: observable.issued,
      }),
      snapshotCaptured' = snapshotCaptured,
      snapshotExists' = snapshotExists,
      snapshotGeneration' = snapshotGeneration,
      snapshotMetageneration' = snapshotMetageneration,
      snapshotHighWater' = snapshotHighWater,
    }
  }

  action importData = {
    val importedHighWater = if (observable.highWater >= IMPORTED_GENERATION) observable.highWater else IMPORTED_GENERATION
    all {
      observable.highWater < IMPORTED_GENERATION,
      record("ImportData", {
        exists: true,
        generation: IMPORTED_GENERATION,
        metageneration: 2,
        highWater: importedHighWater,
        issued: observable.issued.union(Set(IMPORTED_GENERATION)),
      }),
      snapshotCaptured' = snapshotCaptured,
      snapshotExists' = snapshotExists,
      snapshotGeneration' = snapshotGeneration,
      snapshotMetageneration' = snapshotMetageneration,
      snapshotHighWater' = snapshotHighWater,
    }
  }

  action PutData = putData
  action PatchMetadata = patchMetadata
  action Delete = deleteData
  action CaptureSnapshot = captureSnapshot
  action RestoreSnapshot = restoreSnapshot
  action ImportData = importData

  action step = any {
    PutData,
    PatchMetadata,
    Delete,
    CaptureSnapshot,
    RestoreSnapshot,
    ImportData,
  }

  val TypeOK = and {
    MAX_GENERATION >= 3,
    MAX_METAGENERATION >= 2,
    IMPORTED_GENERATION == 2,
    observable.generation >= 0 and observable.generation <= MAX_GENERATION,
    observable.metageneration >= 0 and observable.metageneration <= MAX_METAGENERATION,
    observable.highWater >= 0 and observable.highWater <= MAX_GENERATION,
    observable.issued.subseteq(1.to(MAX_GENERATION + 1)),
    (not(observable.exists)).implies(
      observable.generation == 0 and observable.metageneration == 0
    ),
    observable.exists.implies(and {
      observable.generation > 0,
      observable.generation.in(observable.issued),
    }),
    snapshotGeneration >= 0 and snapshotGeneration <= MAX_GENERATION,
    snapshotMetageneration >= 0 and snapshotMetageneration <= MAX_METAGENERATION,
    snapshotHighWater >= 0 and snapshotHighWater <= MAX_GENERATION,
    lastAction.in(ACTIONS),
  }

  val GenerationMonotonicity = observable.highWater >= previousObservable.highWater

  val GenerationNeverReused = (lastAction == "PutData").implies(
    not(observable.generation.in(previousObservable.issued))
  )

  val MetadataOnlyPreservesGeneration = (lastAction == "PatchMetadata").implies(and {
    observable.generation == previousObservable.generation,
    observable.metageneration == previousObservable.metageneration + 1,
  })

  val RestorePreservesGenerationHighWater = (lastAction == "RestoreSnapshot").implies(and {
    observable.highWater >= previousObservable.highWater,
    observable.issued == previousObservable.issued,
  })
}

module StorageGenerationProof {
  import StorageGeneration(
    MAX_GENERATION = 3,
    MAX_METAGENERATION = 3,
    IMPORTED_GENERATION = 2
  ).*
}

module StorageGenerationScenarios {
  import StorageGeneration(
    MAX_GENERATION = 3,
    MAX_METAGENERATION = 3,
    IMPORTED_GENERATION = 2
  ).*

  run write = init.then(PutData)
    .expect(observable.generation == 1 and observable.issued == Set(1))

  run metadata = init.then(PutData).then(PatchMetadata)
    .expect(observable.generation == 1 and observable.metageneration == 2)

  run deleteThenPut = init.then(PutData).then(Delete).then(PutData)
    .expect(observable.generation == 2 and observable.issued == Set(1, 2))

  run snapshotRestore = init.then(PutData).then(CaptureSnapshot).then(PutData)
    .then(RestoreSnapshot).then(PutData)
    .expect(observable.generation == 3 and observable.issued == Set(1, 2, 3))

  run importRestore = init.then(CaptureSnapshot).then(ImportData)
    .then(RestoreSnapshot).then(PutData)
    .expect(observable.generation == 3 and observable.issued == Set(2, 3))
}

module StorageGenerationConnect {
  import StorageGeneration(
    MAX_GENERATION = 3,
    MAX_METAGENERATION = 3,
    IMPORTED_GENERATION = 2
  ).*
}
