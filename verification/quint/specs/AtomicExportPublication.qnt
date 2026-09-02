// Owner-only staging and atomic export-directory publication.

module AtomicExportPublication {
  const DOMAIN: Set[str]
  type Observable = {
    stageState: str,
    stageIdentity: str,
    targetIdentity: str,
    publicArtifact: str,
    stagePrivate: bool,
    publicPrivate: bool,
    lastResult: str,
  }
  type ActionTaken = { tag: str, value: { doc: str } }

  var observable: Observable
  var previousObservable: Observable
  var lastAction: str
  var actionTaken: ActionTaken

  pure val STAGES = Set("Absent", "Created", "Partial", "Complete")
  pure val STAGE_IDENTITIES = Set("Absent", "Owned", "Changed")
  pure val IDENTITIES = Set("Original", "Changed")
  pure val ARTIFACTS = Set("Old", "New", "Partial")
  pure val RESULTS = Set("None", "Published", "Refused")
  pure val ACTIONS = Set("Init", "Create", "Write", "Complete", "Swap", "SwapStage", "Refuse", "Publish")

  action record(actionName, nextObservable) = all {
    previousObservable' = observable,
    observable' = nextObservable,
    lastAction' = actionName,
    actionTaken' = { tag: actionName, value: { doc: "" } },
  }

  action init = {
    val initial = {
      stageState: "Absent",
      stageIdentity: "Absent",
      targetIdentity: "Original",
      publicArtifact: "Old",
      stagePrivate: true,
      publicPrivate: true,
      lastResult: "None",
    }
    all {
      observable' = initial,
      previousObservable' = initial,
      lastAction' = "Init",
      actionTaken' = { tag: "init", value: { doc: "" } },
    }
  }

  action createStage = all {
    observable.stageState == "Absent",
    record("Create", {
      stageState: "Created",
      stageIdentity: "Owned",
      targetIdentity: observable.targetIdentity,
      publicArtifact: observable.publicArtifact,
      stagePrivate: true,
      publicPrivate: observable.publicPrivate,
      lastResult: "None",
    }),
  }

  action writeStage = all {
    observable.stageState == "Created",
    record("Write", {
      stageState: "Partial",
      stageIdentity: observable.stageIdentity,
      targetIdentity: observable.targetIdentity,
      publicArtifact: observable.publicArtifact,
      stagePrivate: observable.stagePrivate,
      publicPrivate: observable.publicPrivate,
      lastResult: observable.lastResult,
    }),
  }

  action completeStage = all {
    observable.stageState == "Partial",
    record("Complete", {
      stageState: "Complete",
      stageIdentity: observable.stageIdentity,
      targetIdentity: observable.targetIdentity,
      publicArtifact: observable.publicArtifact,
      stagePrivate: observable.stagePrivate,
      publicPrivate: observable.publicPrivate,
      lastResult: observable.lastResult,
    }),
  }

  action swapTarget = all {
    observable.stageState != "Absent",
    observable.targetIdentity == "Original",
    record("Swap", {
      stageState: observable.stageState,
      stageIdentity: observable.stageIdentity,
      targetIdentity: "Changed",
      publicArtifact: observable.publicArtifact,
      stagePrivate: observable.stagePrivate,
      publicPrivate: observable.publicPrivate,
      lastResult: observable.lastResult,
    }),
  }

  action swapStage = all {
    observable.stageState != "Absent",
    observable.stageIdentity == "Owned",
    record("SwapStage", {
      stageState: observable.stageState,
      stageIdentity: "Changed",
      targetIdentity: observable.targetIdentity,
      publicArtifact: observable.publicArtifact,
      stagePrivate: observable.stagePrivate,
      publicPrivate: observable.publicPrivate,
      lastResult: observable.lastResult,
    }),
  }

  action refuseStage = all {
    observable.stageState != "Absent",
    record("Refuse", {
      stageState: "Absent",
      stageIdentity: if (observable.stageIdentity == "Changed") "Changed" else "Absent",
      targetIdentity: observable.targetIdentity,
      publicArtifact: observable.publicArtifact,
      stagePrivate: true,
      publicPrivate: observable.publicPrivate,
      lastResult: "Refused",
    }),
  }

  action publishStage = all {
    observable.stageState == "Complete",
    observable.stageIdentity == "Owned",
    observable.targetIdentity == "Original",
    observable.stagePrivate,
    record("Publish", {
      stageState: "Absent",
      stageIdentity: "Absent",
      targetIdentity: "Original",
      publicArtifact: "New",
      stagePrivate: true,
      publicPrivate: true,
      lastResult: "Published",
    }),
  }

  action Create = createStage
  action Write = writeStage
  action Complete = completeStage
  action Swap = swapTarget
  action SwapStage = swapStage
  action Refuse = refuseStage
  action Publish = publishStage

  action step = any { Create, Write, Complete, Swap, SwapStage, Refuse, Publish }

  val TypeOK = and {
    DOMAIN == Set("bounded"),
    observable.stageState.in(STAGES),
    observable.stageIdentity.in(STAGE_IDENTITIES),
    observable.targetIdentity.in(IDENTITIES),
    observable.publicArtifact.in(ARTIFACTS),
    observable.lastResult.in(RESULTS),
    previousObservable.stageState.in(STAGES),
    previousObservable.stageIdentity.in(STAGE_IDENTITIES),
    previousObservable.targetIdentity.in(IDENTITIES),
    previousObservable.publicArtifact.in(ARTIFACTS),
    previousObservable.lastResult.in(RESULTS),
    lastAction.in(ACTIONS),
  }

  val NoPartialPublication = observable.publicArtifact != "Partial"

  val PublicationRequiresCompletePrivateStage = (lastAction == "Publish").implies(and {
    previousObservable.stageState == "Complete",
    previousObservable.targetIdentity == "Original",
    previousObservable.stagePrivate,
  })

  val PublicationRequiresOwnedStage = (lastAction == "Publish").implies(
    previousObservable.stageIdentity == "Owned"
  )

  val RefusalPreservesPublicArtifact = (lastAction == "Refuse").implies(and {
    observable.publicArtifact == previousObservable.publicArtifact,
    observable.publicPrivate == previousObservable.publicPrivate,
    observable.targetIdentity == previousObservable.targetIdentity,
  })

  val RefusalPreservesChangedStage = and {
    (lastAction == "Refuse" and previousObservable.stageIdentity == "Changed").implies(
      observable.stageIdentity == "Changed"
    ),
    (lastAction == "Refuse" and previousObservable.stageIdentity == "Owned").implies(
      observable.stageIdentity == "Absent"
    ),
  }

  val PublishedArtifactIsPrivate =
    (observable.publicArtifact == "New").implies(observable.publicPrivate)

  val AtomicExportPublication = and {
    NoPartialPublication,
    PublicationRequiresCompletePrivateStage,
    PublicationRequiresOwnedStage,
    RefusalPreservesPublicArtifact,
    RefusalPreservesChangedStage,
    PublishedArtifactIsPrivate,
  }
}

module AtomicExportPublicationProof {
  import AtomicExportPublication(DOMAIN = Set("bounded")).*
}

module AtomicExportPublicationScenarios {
  import AtomicExportPublication(DOMAIN = Set("bounded")).*

  run publish = init.then(Create).then(Write).then(Complete).then(Publish)
    .expect(observable.publicArtifact == "New")

  run refuse = init.then(Create).then(Write).then(Refuse)
    .expect(observable.publicArtifact == "Old" and observable.stageState == "Absent")

  run replace = init.then(Create).then(Write).then(Complete).then(Swap).then(Refuse)
    .expect(observable.targetIdentity == "Changed" and observable.publicArtifact == "Old")

  run stageReplace = init.then(Create).then(Write).then(Complete).then(SwapStage).then(Refuse)
    .expect(observable.stageIdentity == "Changed" and observable.publicArtifact == "Old")
}

module AtomicExportPublicationConnect {
  import AtomicExportPublication(DOMAIN = Set("bounded")).*
}
