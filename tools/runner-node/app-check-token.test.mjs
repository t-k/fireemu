import assert from "node:assert/strict";
import test from "node:test";
import {
  removeAppCheckToken,
  tokenVerificationSkipped,
  withholdsAppCheckToken,
} from "./app-check-token.mjs";

const callable = (consumeAppCheckToken) => ({
  name: "fn",
  trigger: { type: "http", callable: true, enforceAppCheck: false, consumeAppCheckToken },
});
const off = {};
const trusted = {
  FIREBASE_DEBUG_MODE: "true",
  FIREBASE_DEBUG_FEATURES: JSON.stringify({ skipTokenVerification: true }),
};

test("only the trusted debug switch counts as App Check being on", () => {
  assert.equal(tokenVerificationSkipped(trusted), true);
  assert.equal(tokenVerificationSkipped(off), false);
  for (const env of [
    { FIREBASE_DEBUG_MODE: "true", FIREBASE_DEBUG_FEATURES: '{"enableCors":true}' },
    { FIREBASE_DEBUG_MODE: "false", FIREBASE_DEBUG_FEATURES: '{"skipTokenVerification":true}' },
    { FIREBASE_DEBUG_FEATURES: '{"skipTokenVerification":true}' },
    { FIREBASE_DEBUG_MODE: "true", FIREBASE_DEBUG_FEATURES: '{"skipTokenVerification":"true"}' },
    { FIREBASE_DEBUG_MODE: "true", FIREBASE_DEBUG_FEATURES: "not json" },
    { FIREBASE_DEBUG_MODE: "true", FIREBASE_DEBUG_FEATURES: "null" },
  ]) {
    assert.equal(tokenVerificationSkipped(env), false, JSON.stringify(env));
  }
});

test("without App Check a callable that consumes or was not observed has its token withheld", () => {
  for (const consume of ["enabled", "undetermined", undefined]) {
    assert.equal(withholdsAppCheckToken(callable(consume), off), true, String(consume));
    assert.equal(withholdsAppCheckToken(callable(consume), trusted), false, String(consume));
  }
  assert.equal(withholdsAppCheckToken(callable("disabled"), off), false);
  for (const spec of [
    { name: "plain", trigger: { type: "http", callable: false, consumeAppCheckToken: "enabled" } },
    { name: "queue", trigger: { type: "tasks" } },
    { name: "block", trigger: { type: "blockingAuth" } },
    undefined,
  ]) {
    assert.equal(withholdsAppCheckToken(spec, off), false, JSON.stringify(spec));
  }
});

test("removing the token drops every spelling from headers and rawHeaders and keeps the rest", () => {
  const req = {
    headers: { "x-firebase-appcheck": "a, b", "content-type": "application/json", "x-custom": "kept" },
    rawHeaders: [
      "X-Firebase-AppCheck", "a",
      "Content-Type", "application/json",
      "x-firebase-appcheck", "b",
      "X-Custom", "kept",
      "x-firebase-appcheck-token", "near-miss",
    ],
  };
  removeAppCheckToken(req);
  assert.deepEqual(req.headers, { "content-type": "application/json", "x-custom": "kept" });
  assert.deepEqual(req.rawHeaders, [
    "Content-Type", "application/json",
    "X-Custom", "kept",
    "x-firebase-appcheck-token", "near-miss",
  ]);
});
