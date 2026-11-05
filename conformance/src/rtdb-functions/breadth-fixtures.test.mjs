import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { FIXTURE_HANDLERS, ITEM_PATH, FRAME_MARKER } from "./breadth-frames.mjs";
const require = createRequire(import.meta.url);
const snap = (v) => ({ exists: () => v !== null, val: () => v, key: "a" });
function fixture() {
  const ref = { onWrite: (handler) => ({ handler }) };
  let v1options;
  const registry = {
    "firebase-admin/app": { initializeApp() {}, getApps: () => [] },
    "firebase-functions/v1": {
      region: () => ({
        runWith: (options) => (
          (v1options = options),
          { database: { instance: () => ({ ref: () => ref }) } }
        ),
      }),
    },
    "firebase-functions/v2/database": {
      onValueWritten: (options, handler) => ({ options, handler }),
    },
    "./frames": require("./fixtures-breadth/frames.js"),
  };
  const exports = {};
  new Function(
    "require",
    "exports",
    readFileSync(new URL("./fixtures-breadth/index.js", import.meta.url), "utf8"),
  )((name) => registry[name], exports);
  return { exports, v1options };
}
test("T1 handlers declare nested trigger and retry settings", () => {
  const { exports, v1options } = fixture();
  assert.deepEqual(Object.keys(exports).sort(), FIXTURE_HANDLERS.map((h) => h.name).sort());
  assert.equal(v1options.failurePolicy, true);
  assert.equal(exports.g9WrittenV2Retry.options.retry, true);
  assert.equal(exports.g9WrittenV2.options.retry, undefined);
  assert.equal(exports.g9WrittenV2.options.ref, ITEM_PATH);
});
test("failure boundary, invalid time, group and delete are recorded before throwing", () => {
  const { exports } = fixture();
  const original = console.log;
  const lines = [];
  console.log = (line) => lines.push(line);
  const now = Date.now();
  try {
    for (const [age, group, before, after, throws] of [
      [44999, "gr", null, { failForMs: 45000 }, true],
      [45000, "gr", null, { failForMs: 45000 }, false],
      ["bad", "gr", null, { failForMs: 45000 }, false],
      [0, "ga", null, { failForMs: 45000 }, false],
      [0, "gr", { failForMs: 45000 }, null, true],
    ]) {
      const event = {
        params: { group, id: "a" },
        time: age === "bad" ? "bad" : new Date(now - age).toISOString(),
        data: { before: snap(before), after: snap(after) },
      };
      const dateNow = Date.now;
      Date.now = () => now;
      try {
        if (throws) assert.throws(() => exports.g9WrittenV2.handler(event));
        else exports.g9WrittenV2.handler(event);
      } finally {
        Date.now = dateNow;
      }
      assert.equal(JSON.parse(lines.at(-1).slice(FRAME_MARKER.length)).attempt.threw, throws);
    }
  } finally {
    console.log = original;
  }
  assert.equal(lines.length, 5);
});
test("v1 auth projects claim names without claim values", () => {
  const frames = require("./fixtures-breadth/frames.js");
  const auth = frames.v1Context({
    auth: {
      uid: "user",
      token: {
        z: "sensitive",
        email: "person@example.test",
        firebase: { sign_in_provider: "password" },
        email_verified: true,
      },
    },
  }).auth;
  assert.deepEqual(auth, {
    uid: "user",
    tokenKeys: ["email", "email_verified", "firebase", "z"],
    signInProvider: "password",
    emailVerified: true,
  });
});

test("failure duration uses the smaller of the configured window and cap", () => {
  const { exports } = fixture();
  const originalLog = console.log;
  const originalNow = Date.now;
  console.log = () => {};
  Date.now = () => 100000;
  try {
    for (const [age, window, shouldThrow] of [
      [999, 1000, true],
      [1000, 1000, false],
      [45000, 90000, false],
      [45000, 45000, false],
    ]) {
      const event = {
        params: { group: "gr", id: "a" },
        time: new Date(100000 - age).toISOString(),
        data: { before: snap(null), after: snap({ failForMs: window }) },
      };
      if (shouldThrow) assert.throws(() => exports.g9WrittenV2.handler(event));
      else assert.doesNotThrow(() => exports.g9WrittenV2.handler(event));
    }
  } finally {
    console.log = originalLog;
    Date.now = originalNow;
  }
});
