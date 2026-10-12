// Withholding an App Check token from a callable that could consume it (specification 13.4).
//
// Without the trusted protocol the runner has no `skipTokenVerification`, so the installed
// onCall wrapper hands a presented `X-Firebase-AppCheck` to the Admin SDK's `verifyToken`, and
// with `consumeAppCheckToken: true` that call consumes the token against the production App
// Check API. The daemon's proxy already removes the field for such callables, but a request can
// reach this runner on other paths too: a task dispatched to a queue a configured manifest named
// after the callable, for one. So the runner applies the same rule at the one point every path
// shares, using its own discovery of what the export is, whatever trigger type the daemon
// assigned to the name.

const APP_CHECK_HEADER = "x-firebase-appcheck";
const TRUSTED_DEBUG_FEATURE = "skipTokenVerification";

/// Whether the trusted protocol is active: the daemon turns `skipTokenVerification` on (with
/// `FIREBASE_DEBUG_MODE`) only when it verifies App Check itself.
export function tokenVerificationSkipped(env) {
  if (env.FIREBASE_DEBUG_MODE !== "true") return false;
  let features;
  try {
    features = JSON.parse(env.FIREBASE_DEBUG_FEATURES ?? "{}");
  } catch {
    return false;
  }
  return features?.[TRUSTED_DEBUG_FEATURE] === true;
}

/// Whether a request to the export behind `spec` (this runner's own discovery) must not carry
/// an App Check token: a callable whose `consumeAppCheckToken` is not known to be off, while
/// App Check is off.
export function withholdsAppCheckToken(spec, env) {
  const trigger = spec?.trigger;
  const mayConsume =
    trigger?.type === "http" &&
    trigger.callable === true &&
    trigger.consumeAppCheckToken !== "disabled";
  return mayConsume && !tokenVerificationSkipped(env);
}

/// Removes every `X-Firebase-AppCheck` field from a Node request, from both `headers` and
/// `rawHeaders`.
export function removeAppCheckToken(req) {
  delete req.headers[APP_CHECK_HEADER];
  if (Array.isArray(req.rawHeaders)) {
    const kept = [];
    for (let i = 0; i + 1 < req.rawHeaders.length; i += 2) {
      if (String(req.rawHeaders[i]).toLowerCase() !== APP_CHECK_HEADER) {
        kept.push(req.rawHeaders[i], req.rawHeaders[i + 1]);
      }
    }
    req.rawHeaders = kept;
  }
}
