// Callable Cloud Functions for the conformance corpus.
//
// Deliberately narrow: only callables and one onRequest function, no Admin SDK and no
// triggers, so that both the official Functions emulator and the fireemu runner load
// the same codebase quickly and the rows compare callable envelopes rather than trigger
// scheduling.
const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");

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
    appCheckHeaderCount: [].concat(req.headers["x-firebase-appcheck"] ?? []).length,
  });
});
