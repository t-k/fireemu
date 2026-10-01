// The reasons a request path stops, carried on the error as a `stopCode` so the controller maps a failure by its code and never by its message text.
export const STOP_CODES = Object.freeze({
  admissionRefused: "admission-refused",
  preflightFailed: "preflight-failed",
  outcomeUncertain: "outcome-uncertain",
  captureFailed: "capture-failed",
});

const KNOWN = new Set(Object.values(STOP_CODES));

/** An error that names its stop reason. */
export function tagged(code, message) {
  if (!KNOWN.has(code)) throw new Error("unknown stop code");
  return Object.assign(new Error(message), { stopCode: code });
}

/** The stop reason an error carries, or null for any other failure. */
export function stopCodeOf(error) {
  return typeof error?.stopCode === "string" && KNOWN.has(error.stopCode) ? error.stopCode : null;
}
