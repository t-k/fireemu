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

test("SDK wire responses cannot bypass claim validation", () => {
  assert.throws(
    () =>
      blockingResult(
        { userRecord: { updateMask: "sessionClaims", sessionClaims: { firebase: "reserved" } } },
        "beforeSignIn",
        HttpsError,
      ),
    (error) => error.code === "invalid-argument" && /reserved/.test(error.message),
  );
  assert.throws(
    () =>
      blockingResult(
        {
          userRecord: {
            updateMask: "sessionClaims",
            sessionClaims: { value: "😀".repeat(495) },
          },
        },
        "beforeSignIn",
        HttpsError,
      ),
    (error) => error.code === "invalid-argument" && /sessionClaims payload/.test(error.message),
  );
  assert.throws(
    () =>
      blockingResult(
        {
          userRecord: {
            updateMask: "customClaims,sessionClaims",
            customClaims: { custom: "a".repeat(600) },
            sessionClaims: { session: "b".repeat(600) },
          },
        },
        "beforeSignIn",
        HttpsError,
      ),
    (error) => error.code === "invalid-argument" && /combined/.test(error.message),
  );
  for (const userRecord of [null, "invalid", []]) {
    assert.throws(
      () => blockingResult({ userRecord }, "beforeSignIn", HttpsError),
      (error) => error.code === "invalid-argument" && /userRecord/.test(error.message),
    );
  }
});

test("the custom claims travel with their JSON.stringify text, which the runner owns", () => {
  // Production reads the claims back as the function's JSON.stringify gave them, key order
  // included (AUTH-TENANT-BLOCKING recording 2026-09-28, rollback#lookup-refused-at-sign-in).
  const claims = { b: 1, a: { d: [2, "x"], c: null } };
  const text = JSON.stringify(claims);
  assert.equal(text, '{"b":1,"a":{"d":[2,"x"],"c":null}}');
  const plain = blockingResult({ customClaims: claims }, "beforeCreate", HttpsError);
  assert.equal(plain.fireemuCustomClaimsText, text);
  assert.ok(Object.isFrozen(plain));
  // A wire envelope's own member of that name is replaced, or removed without claims.
  const wire = blockingResult(
    {
      userRecord: { updateMask: "customClaims", customClaims: claims },
      fireemuCustomClaimsText: '{"a":1}',
    },
    "beforeCreate",
    HttpsError,
  );
  assert.equal(wire.fireemuCustomClaimsText, text);
  for (const value of [
    { userRecord: { updateMask: "displayName", displayName: "n" }, fireemuCustomClaimsText: "{}" },
    { userRecord: { updateMask: "customClaims", customClaims: null }, fireemuCustomClaimsText: "{}" },
  ]) {
    assert.equal(
      Object.hasOwn(blockingResult(value, "beforeCreate", HttpsError), "fireemuCustomClaimsText"),
      false,
    );
  }
  assert.deepEqual(blockingResult({ displayName: "n" }, "beforeCreate", HttpsError), {
    userRecord: { displayName: "n", updateMask: "displayName" },
  });
});
