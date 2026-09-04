import assert from "node:assert/strict";
import test from "node:test";

import { blockingResult } from "./blocking-response.mjs";

class HttpsError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

test("session claims use the Functions SDK 1000-character boundary", () => {
  const exact = { value: "a".repeat(988) };
  assert.equal(JSON.stringify(exact).length, 1000);
  assert.deepEqual(blockingResult({ sessionClaims: exact }, "beforeSignIn", HttpsError), {
    userRecord: { sessionClaims: exact, updateMask: "sessionClaims" },
  });

  const nonBmpOverLimit = { value: "😀".repeat(495) };
  assert.ok([...JSON.stringify(nonBmpOverLimit)].length <= 1000);
  assert.ok(JSON.stringify(nonBmpOverLimit).length > 1000);
  assert.throws(
    () => blockingResult({ sessionClaims: nonBmpOverLimit }, "beforeSignIn", HttpsError),
    (error) => error.code === "invalid-argument" && /sessionClaims payload/.test(error.message),
  );
});

test("custom and session claims enforce reserved and combined limits", () => {
  assert.throws(
    () => blockingResult({ sessionClaims: { firebase: "reserved" } }, "beforeSignIn", HttpsError),
    (error) => error.code === "invalid-argument" && /reserved/.test(error.message),
  );
  assert.throws(
    () =>
      blockingResult(
        {
          customClaims: { custom: "a".repeat(600) },
          sessionClaims: { session: "b".repeat(600) },
        },
        "beforeSignIn",
        HttpsError,
      ),
    (error) => error.code === "invalid-argument" && /combined/.test(error.message),
  );
});
