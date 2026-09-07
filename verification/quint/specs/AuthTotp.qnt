// TOTP enrollment, expiry, verification window, and replay protection.

module AuthTotp {
  const MAX_STEP: int
  const WINDOW: int
  const SESSION_TTL: int

  type Observable = {
    factorCount: int,
    pendingCount: int,
    lastAcceptedStep: int,
    lastResult: str,
    secondFactorClaim: str,
  }
  type ActionTaken = { tag: str, value: { codeStep: int } }

  var observable: Observable
  var previousObservable: Observable
  var clock: int
  var lifecycle: str
  var sessionEnd: int
  var accepted: int -> int
  var acceptedAt: int
  var enrollmentAcceptedAt: int
  var lastAction: str
  var lastCodeStep: int
  var actionTaken: ActionTaken

  pure val NO_STEP = MAX_STEP + 1
  pure val NO_TIME = MAX_STEP + SESSION_TTL + 1
  pure val STEPS = 0.to(MAX_STEP)
  pure val LIFECYCLES = Set("NotEnrolled", "EnrollmentStarted", "Enrolled", "Expired")
  pure val RESULTS = Set(
    "Initial",
    "EnrollmentStarted",
    "EnrollmentAccepted",
    "EnrollmentInvalid",
    "EnrollmentExpired",
    "VerificationAccepted",
    "VerificationInvalid",
    "VerificationReplayed",
    "NoEnrolledFactor"
  )
  pure val ACTIONS = Set(
    "Init",
    "Tick",
    "StartEnrollment",
    "FinalizeEnrollment",
    "ExpireEnrollment",
    "Verify"
  )

  pure def inWindowAt(codeStep, at) =
    codeStep + WINDOW >= at and codeStep <= at + WINDOW

  action record(actionName, codeStep, nextObservable) = all {
    previousObservable' = observable,
    observable' = nextObservable,
    lastAction' = actionName,
    lastCodeStep' = codeStep,
    actionTaken' = { tag: actionName, value: { codeStep: codeStep } },
  }

  action init = {
    val initial = {
      factorCount: 0,
      pendingCount: 0,
      lastAcceptedStep: NO_STEP,
      lastResult: "Initial",
      secondFactorClaim: "None",
    }
    all {
      observable' = initial,
      previousObservable' = initial,
      clock' = 0,
      lifecycle' = "NotEnrolled",
      sessionEnd' = 0,
      accepted' = STEPS.mapBy(_ => 0),
      acceptedAt' = NO_TIME,
      enrollmentAcceptedAt' = NO_TIME,
      lastAction' = "Init",
      lastCodeStep' = NO_STEP,
      actionTaken' = { tag: "init", value: { codeStep: NO_STEP } },
    }
  }

  action tick = all {
    clock < MAX_STEP,
    record("Tick", NO_STEP, observable),
    clock' = clock + 1,
    lifecycle' = lifecycle,
    sessionEnd' = sessionEnd,
    accepted' = accepted,
    acceptedAt' = acceptedAt,
    enrollmentAcceptedAt' = enrollmentAcceptedAt,
  }

  action startEnrollment = all {
    lifecycle.in(Set("NotEnrolled", "Expired")),
    observable.factorCount == 0,
    record("StartEnrollment", NO_STEP, {
      factorCount: 0,
      pendingCount: 1,
      lastAcceptedStep: observable.lastAcceptedStep,
      lastResult: "EnrollmentStarted",
      secondFactorClaim: "None",
    }),
    clock' = clock,
    lifecycle' = "EnrollmentStarted",
    sessionEnd' = clock + SESSION_TTL,
    accepted' = accepted,
    acceptedAt' = acceptedAt,
    enrollmentAcceptedAt' = enrollmentAcceptedAt,
  }

  action finalizeEnrollment(codeStep) = {
    val acceptedCode = inWindowAt(codeStep, clock)
    all {
      lifecycle == "EnrollmentStarted",
      clock <= sessionEnd,
      codeStep.in(STEPS),
      record("FinalizeEnrollment", codeStep, {
        factorCount: if (acceptedCode) 1 else 0,
        pendingCount: if (acceptedCode) 0 else 1,
        lastAcceptedStep: if (acceptedCode) codeStep else observable.lastAcceptedStep,
        lastResult: if (acceptedCode) "EnrollmentAccepted" else "EnrollmentInvalid",
        secondFactorClaim: "None",
      }),
      clock' = clock,
      lifecycle' = if (acceptedCode) "Enrolled" else lifecycle,
      sessionEnd' = sessionEnd,
      accepted' = if (acceptedCode) accepted.set(codeStep, accepted.get(codeStep) + 1) else accepted,
      acceptedAt' = if (acceptedCode) clock else acceptedAt,
      enrollmentAcceptedAt' = if (acceptedCode) clock else enrollmentAcceptedAt,
    }
  }

  action expireEnrollment = all {
    lifecycle == "EnrollmentStarted",
    clock > sessionEnd,
    record("ExpireEnrollment", NO_STEP, {
      factorCount: 0,
      pendingCount: 0,
      lastAcceptedStep: observable.lastAcceptedStep,
      lastResult: "EnrollmentExpired",
      secondFactorClaim: "None",
    }),
    clock' = clock,
    lifecycle' = "Expired",
    sessionEnd' = sessionEnd,
    accepted' = accepted,
    acceptedAt' = acceptedAt,
    enrollmentAcceptedAt' = enrollmentAcceptedAt,
  }

  action verify(codeStep) = {
    val hasFactor = observable.factorCount == 1
    val inWindow = inWindowAt(codeStep, clock)
    val fresh = observable.lastAcceptedStep == NO_STEP or codeStep > observable.lastAcceptedStep
    val acceptedCode = hasFactor and inWindow and fresh
    val replayed = hasFactor and inWindow and not(fresh)
    val result = if (not(hasFactor)) {
      "NoEnrolledFactor"
    } else if (acceptedCode) {
      "VerificationAccepted"
    } else if (replayed) {
      "VerificationReplayed"
    } else {
      "VerificationInvalid"
    }
    all {
      codeStep.in(STEPS),
      record("Verify", codeStep, {
        factorCount: observable.factorCount,
        pendingCount: if (not(hasFactor)) {
          observable.pendingCount
        } else if (acceptedCode) {
          0
        } else {
          1
        },
        lastAcceptedStep: if (acceptedCode) codeStep else observable.lastAcceptedStep,
        lastResult: result,
        secondFactorClaim: if (acceptedCode) "ValidTotp" else "None",
      }),
      clock' = clock,
      lifecycle' = lifecycle,
      sessionEnd' = sessionEnd,
      accepted' = if (acceptedCode) accepted.set(codeStep, accepted.get(codeStep) + 1) else accepted,
      acceptedAt' = if (acceptedCode) clock else acceptedAt,
      enrollmentAcceptedAt' = enrollmentAcceptedAt,
    }
  }

  action Tick = tick
  action StartEnrollment = startEnrollment
  action FinalizeEnrollment = { nondet codeStep = STEPS.oneOf() finalizeEnrollment(codeStep) }
  action ExpireEnrollment = expireEnrollment
  action Verify = { nondet codeStep = STEPS.oneOf() verify(codeStep) }

  action step = any {
    Tick,
    StartEnrollment,
    FinalizeEnrollment,
    ExpireEnrollment,
    Verify,
  }

  val TypeOK = and {
    MAX_STEP > 0,
    WINDOW >= 0,
    SESSION_TTL > 0,
    clock >= 0 and clock <= MAX_STEP,
    lifecycle.in(LIFECYCLES),
    sessionEnd >= 0 and sessionEnd <= MAX_STEP + SESSION_TTL,
    observable.factorCount >= 0 and observable.factorCount <= 1,
    observable.pendingCount >= 0 and observable.pendingCount <= 1,
    observable.lastAcceptedStep.in(STEPS.union(Set(NO_STEP))),
    observable.lastResult.in(RESULTS),
    observable.secondFactorClaim.in(Set("None", "ValidTotp", "Invalid")),
    previousObservable.lastResult.in(RESULTS),
    accepted.keys() == STEPS,
    STEPS.forall(codeStep => accepted.get(codeStep) >= 0 and accepted.get(codeStep) <= 2),
    acceptedAt.in(STEPS.union(Set(NO_TIME))),
    enrollmentAcceptedAt >= 0 and enrollmentAcceptedAt <= NO_TIME,
    lastAction.in(ACTIONS),
    lastCodeStep.in(STEPS.union(Set(NO_STEP))),
  }

  val NoTotpCodeReuse = STEPS.forall(codeStep => accepted.get(codeStep) <= 1)

  val NoSecondFactorWithoutEnrollment =
    (observable.secondFactorClaim != "None").implies(and {
      observable.secondFactorClaim == "ValidTotp",
      observable.factorCount == 1,
      lifecycle == "Enrolled",
    })

  val AcceptedOnlyWithinWindow =
    (acceptedAt == NO_TIME).or(inWindowAt(observable.lastAcceptedStep, acceptedAt))

  val EnrollmentAcceptedBeforeExpiry =
    (enrollmentAcceptedAt == NO_TIME).or(enrollmentAcceptedAt <= sessionEnd)

  temporal EnrollmentProgressFairness = and {
    Tick.weakFair((observable, previousObservable, clock, lifecycle, sessionEnd, accepted,
      acceptedAt, enrollmentAcceptedAt, lastAction, lastCodeStep)),
    ExpireEnrollment.weakFair((observable, previousObservable, clock, lifecycle, sessionEnd, accepted,
      acceptedAt, enrollmentAcceptedAt, lastAction, lastCodeStep)),
    finalizeEnrollment(clock).weakFair((observable, previousObservable, clock, lifecycle, sessionEnd,
      accepted, acceptedAt, enrollmentAcceptedAt, lastAction, lastCodeStep)),
  }

  temporal EnrollmentEventuallyFinalizesOrExpires = EnrollmentProgressFairness.implies(always(
    (lifecycle == "EnrollmentStarted").implies(eventually(
      lifecycle.in(Set("Enrolled", "Expired"))
    ))
  ))
}

module AuthTotpProof {
  import AuthTotp(MAX_STEP = 4, WINDOW = 1, SESSION_TTL = 2).*
}

module AuthTotpScenarios {
  import AuthTotp(MAX_STEP = 4, WINDOW = 1, SESSION_TTL = 2).*

  run enrollAtTtl = init.then(StartEnrollment).then(Tick).then(Tick)
    .then(finalizeEnrollment(2))
    .expect(observable.lastResult == "EnrollmentAccepted")

  run expireAfterTtl = init.then(StartEnrollment).then(Tick).then(Tick).then(Tick)
    .then(ExpireEnrollment)
    .expect(observable.lastResult == "EnrollmentExpired")

  run verifyAdjacent = init.then(StartEnrollment).then(finalizeEnrollment(0))
    .then(Tick).then(Tick).then(verify(1))
    .expect(observable.lastResult == "VerificationAccepted")

  run rejectOutsideWindow = init.then(StartEnrollment).then(finalizeEnrollment(0))
    .then(Tick).then(Tick).then(verify(4))
    .expect(observable.lastResult == "VerificationInvalid")

  run rejectReplay = init.then(StartEnrollment).then(finalizeEnrollment(0))
    .then(Tick).then(verify(1)).then(verify(1))
    .expect(observable.lastResult == "VerificationReplayed")

  run rejectWithoutFactor = init.then(verify(0))
    .expect(observable.lastResult == "NoEnrolledFactor")
}

module AuthTotpConnect {
  import AuthTotp(MAX_STEP = 4, WINDOW = 1, SESSION_TTL = 2).*
}
