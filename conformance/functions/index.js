// Callable Cloud Functions for the conformance corpus.
//
// Deliberately narrow: HTTP handlers and one Admin SDK transaction probe, with no triggers,
// so that both the official Functions emulator and the fireemu runner load the same codebase
// quickly and the rows compare request handling rather than trigger scheduling.
const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");
const { getApps, initializeApp } = require("firebase-admin/app");
const { FieldValue, getFirestore } = require("firebase-admin/firestore");

const adminApp = getApps()[0] ?? initializeApp();
const adminDb = getFirestore(adminApp);

// The happy path plus every callable error the corpus asks for.
exports.confAdd = onCall((request) => {
  const { a, b } = request.data || {};
  if (typeof a !== "number" || typeof b !== "number") {
    throw new HttpsError("invalid-argument", "a and b must be numbers", { got: typeof a });
  }
  return { sum: a + b };
});

// Every HttpsError code the corpus records, selected by the request payload.
exports.confThrow = onCall((request) => {
  const code = String(request.data?.code ?? "internal");
  throw new HttpsError(code, `deliberate ${code}`, { detail: "conformance" });
});

// An uncaught non-HttpsError: the callable protocol has to collapse it to INTERNAL without
// leaking the message.
exports.confCrash = onCall(() => {
  throw new Error("this message must not reach the client");
});

// The Auth context a callable sees, shaped so that a missing context is distinguishable from
// an anonymous one.
exports.confWhoAmI = onCall((request) => ({
  hasAuth: request.auth != null,
  uid: request.auth?.uid ?? null,
  email: request.auth?.token?.email ?? null,
  hasApp: request.app != null,
  appId: request.app?.appId ?? null,
}));

// A callable that enforces App Check itself.
exports.confGuarded = onCall({ enforceAppCheck: true }, (request) => ({
  hasApp: request.app != null,
  appId: request.app?.appId ?? null,
}));

// An ordinary HTTP function: application code owns App Check verification here, so the raw
// header list is echoed back.
exports.confEcho = onRequest((req, res) => {
  res.status(200).json({
    method: req.method,
    path: req.path,
    query: req.query,
    appCheckHeaderCount: [].concat(req.headers["x-firebase-appcheck"] ?? []).length,
  });
});

// A function in another region: the URL carries the region, so this one is only reachable at
// /{project}/europe-west1/confRegional and never at us-central1.
exports.confRegional = onRequest({ region: "europe-west1" }, (req, res) => {
  res.status(200).json({ region: "europe-west1", path: req.path });
});

// A function that overruns its own `timeoutSeconds`. What the caller sees when the emulator
// gives up is the record this scenario exists for.
exports.confSlow = onRequest({ timeoutSeconds: 1 }, async (_req, res) => {
  await new Promise((resolve) => setTimeout(resolve, 4000));
  res.status(200).send("this answer arrives after the deadline");
});

exports.confConditionalLock = onRequest({ concurrency: 2 }, async (req, res) => {
  const participant = Number(req.body?.participant);
  if (participant !== 0 && participant !== 1) {
    res.status(400).json({ error: "participant must be 0 or 1" });
    return;
  }
  const contextRef = adminDb.doc("conf_fn_lock/context");
  const lockRef = adminDb.doc("conf_fn_lock/lock");
  const actionsRef = adminDb.doc("conf_fn_lock/actions");
  let attempts = 0;
  const observations = [];
  const reachLatch = async (phase, barrierPort, barrierToken) => {
    const barrier = await fetch(
      `http://127.0.0.1:${barrierPort}/${phase}/${barrierToken}/${participant}`,
      { method: "POST", signal: AbortSignal.timeout(20_000) },
    );
    if (barrier.status !== 204) throw new Error(`conditional lock ${phase} failed`);
  };
  const acquired = await adminDb.runTransaction(async (tx) => {
    attempts += 1;
    const context = await tx.get(contextRef);
    const lock = await tx.get(lockRef);
    if (!context.exists || context.data().enabled !== true || !lock.exists) {
      throw new Error("conditional lock fixtures are missing");
    }
    const barrierPort = context.data().barrierPort;
    const barrierToken = context.data().barrierToken;
    if (
      !Number.isSafeInteger(barrierPort) ||
      barrierPort < 1 ||
      barrierPort > 65535 ||
      typeof barrierToken !== "string" ||
      !/^[0-9a-f]{32}$/.test(barrierToken)
    ) {
      throw new Error("conditional lock barrier configuration is invalid");
    }
    const locked = lock.data().locked === true;
    observations.push(locked);
    if (attempts === 1) {
      await reachLatch("arrive", barrierPort, barrierToken);
    } else if (locked) {
      await reachLatch("retry-observed", barrierPort, barrierToken);
    }
    if (locked) return false;
    tx.update(lockRef, { locked: true, owner: participant });
    return true;
  });
  if (acquired) {
    await actionsRef.update({ count: FieldValue.increment(1) });
    const context = (await contextRef.get()).data();
    await reachLatch("await-retry", context.barrierPort, context.barrierToken);
    await lockRef.update({ locked: false });
  }
  res.status(acquired ? 200 : 409).json({ acquired, attempts, observations });
});
