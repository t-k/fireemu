const functionErrorCodes = new Map([
  ["cancelled", { canonicalName: "CANCELLED", status: 499 }],
  ["unknown", { canonicalName: "UNKNOWN", status: 500 }],
  ["invalid-argument", { canonicalName: "INVALID_ARGUMENT", status: 400 }],
  ["deadline-exceeded", { canonicalName: "DEADLINE_EXCEEDED", status: 504 }],
  ["not-found", { canonicalName: "NOT_FOUND", status: 404 }],
  ["already-exists", { canonicalName: "ALREADY_EXISTS", status: 409 }],
  ["permission-denied", { canonicalName: "PERMISSION_DENIED", status: 403 }],
  ["unauthenticated", { canonicalName: "UNAUTHENTICATED", status: 401 }],
  ["resource-exhausted", { canonicalName: "RESOURCE_EXHAUSTED", status: 429 }],
  ["failed-precondition", { canonicalName: "FAILED_PRECONDITION", status: 400 }],
  ["aborted", { canonicalName: "ABORTED", status: 409 }],
  ["out-of-range", { canonicalName: "OUT_OF_RANGE", status: 400 }],
  ["unimplemented", { canonicalName: "UNIMPLEMENTED", status: 501 }],
  ["internal", { canonicalName: "INTERNAL", status: 500 }],
  ["unavailable", { canonicalName: "UNAVAILABLE", status: 503 }],
  ["data-loss", { canonicalName: "DATA_LOSS", status: 500 }],
]);

const unavailable = Object.freeze({
  canonicalName: "UNAVAILABLE",
  message: "An unexpected error occurred.",
  status: 503,
});

const safeMessage = (value) =>
  typeof value === "string" &&
  Buffer.byteLength(value, "utf8") <= 4096 &&
  !/\p{Cc}|[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(value);

export function blockingFailure(error, HttpsErrors) {
  try {
    if (
      !Array.isArray(HttpsErrors) ||
      !HttpsErrors.some((HttpsError) =>
        typeof HttpsError === "function" && error instanceof HttpsError
      )
    ) {
      return unavailable;
    }
    // Read each potentially user-defined accessor once. In particular, validating
    // one message and returning a second getter result can leak an unsafe message.
    const rawCode = error.code;
    const metadata = error.httpErrorCode;
    const message = error.message;
    const code = typeof rawCode === "string" ? functionErrorCodes.get(rawCode) : undefined;
    if (
      !code ||
      metadata?.canonicalName !== code.canonicalName ||
      metadata?.status !== code.status ||
      !safeMessage(message)
    ) {
      return unavailable;
    }
    return { ...code, message };
  } catch {
    // Error objects, proxies and even instanceof hooks can throw. Their details
    // must not replace the fixed public fallback or break the HTTP error path.
    return unavailable;
  }
}
