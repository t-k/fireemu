import assert from "node:assert/strict";
import test from "node:test";

import { blockingFailure } from "./blocking-error.mjs";

class HttpsError extends Error {
  constructor(code, canonicalName, status, message = "rejected") {
    super(message);
    this.code = code;
    this.httpErrorCode = { canonicalName, status };
  }
}

class EsmHttpsError extends HttpsError {}

const httpsError = (code, canonicalName, status, message = "rejected") =>
  new HttpsError(code, canonicalName, status, message);

test("supported HttpsError codes retain their canonical function response", () => {
  for (const [code, canonicalName, status] of [
    ["cancelled", "CANCELLED", 499],
    ["unknown", "UNKNOWN", 500],
    ["invalid-argument", "INVALID_ARGUMENT", 400],
    ["deadline-exceeded", "DEADLINE_EXCEEDED", 504],
    ["not-found", "NOT_FOUND", 404],
    ["already-exists", "ALREADY_EXISTS", 409],
    ["permission-denied", "PERMISSION_DENIED", 403],
    ["unauthenticated", "UNAUTHENTICATED", 401],
    ["resource-exhausted", "RESOURCE_EXHAUSTED", 429],
    ["failed-precondition", "FAILED_PRECONDITION", 400],
    ["aborted", "ABORTED", 409],
    ["out-of-range", "OUT_OF_RANGE", 400],
    ["unimplemented", "UNIMPLEMENTED", 501],
    ["internal", "INTERNAL", 500],
    ["unavailable", "UNAVAILABLE", 503],
    ["data-loss", "DATA_LOSS", 500],
  ]) {
    assert.deepEqual(blockingFailure(httpsError(code, canonicalName, status), [HttpsError]), {
      canonicalName,
      message: "rejected",
      status,
    });
  }
  assert.deepEqual(
    blockingFailure(
      new EsmHttpsError("permission-denied", "PERMISSION_DENIED", 403, "ESM rejected"),
      [HttpsError, EsmHttpsError],
    ),
    { canonicalName: "PERMISSION_DENIED", message: "ESM rejected", status: 403 },
  );
});

test("messages are bounded without changing safe Unicode or JSON characters", () => {
  assert.equal(
    blockingFailure(
      httpsError("invalid-argument", "INVALID_ARGUMENT", 400, "a".repeat(4096)),
      [HttpsError],
    )
      .message.length,
    4096,
  );
  for (const message of ["a".repeat(4097), "nul\0", "line\nfeed", "return\r", "next\u0085line"]) {
    assert.deepEqual(
      blockingFailure(httpsError("invalid-argument", "INVALID_ARGUMENT", 400, message), [HttpsError]),
      {
        canonicalName: "UNAVAILABLE",
        message: "An unexpected error occurred.",
        status: 503,
      },
    );
  }
  assert.equal(
    blockingFailure(
      httpsError("invalid-argument", "INVALID_ARGUMENT", 400, 'quoted "slash\\ 日本語'),
      [HttpsError],
    ).message,
    'quoted "slash\\ 日本語',
  );
});

test("plain and inconsistent errors fail closed as unavailable", () => {
  const expected = {
    canonicalName: "UNAVAILABLE",
    message: "An unexpected error occurred.",
    status: 503,
  };
  assert.deepEqual(blockingFailure(new Error("private marker"), [HttpsError]), expected);
  assert.deepEqual(
    blockingFailure(
      httpsError("permission-denied", "PERMISSION_DENIED", 418, "private marker"),
      [HttpsError],
    ),
    expected,
  );
  assert.deepEqual(
    blockingFailure(httpsError("made-up", "MADE_UP", 599, "private marker"), [HttpsError]),
    expected,
  );
  assert.deepEqual(
    blockingFailure(
      {
        code: "permission-denied",
        httpErrorCode: { canonicalName: "PERMISSION_DENIED", status: 403 },
        message: "private spoofed marker",
      },
      [HttpsError],
    ),
    expected,
  );
});

test("bidirectional control characters fail closed", () => {
  for (const marker of ["\u061c", "\u200e", "\u200f", "\u202a", "\u202e", "\u2066", "\u2069"]) {
    assert.deepEqual(
      blockingFailure(
        httpsError("permission-denied", "PERMISSION_DENIED", 403, `prefix${marker}suffix`),
        [HttpsError],
      ),
      {
        canonicalName: "UNAVAILABLE",
        message: "An unexpected error occurred.",
        status: 503,
      },
    );
  }
});
