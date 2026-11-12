import assert from "node:assert/strict";
import test from "node:test";
import { expectedShapes, profileFromEnv } from "./functions-expect.mjs";

test("strict expects the recorded production shapes", () => {
  assert.deepEqual(expectedShapes("strict", "demo-app"), {
    customEventDatacontenttype: null,
    taskQueueName: "countJob",
    authType: "unknown",
    authId: "owner",
  });
});

test("emulator expects the official emulator's shapes, with the project in the queue key", () => {
  assert.deepEqual(expectedShapes("emulator", "demo-app"), {
    customEventDatacontenttype: "application/json",
    taskQueueName: "queue:demo-app-us-central1-countJob",
    authType: "unknown",
    authId: "fake-auth-id@gmail.com",
  });
  assert.equal(expectedShapes("emulator", "other").taskQueueName, "queue:other-us-central1-countJob");
});

test("the profile defaults to strict and an unknown name fails closed", () => {
  assert.equal(profileFromEnv({}), "strict");
  assert.equal(profileFromEnv({ FIREEMU_SMOKE_PROFILE: "emulator" }), "emulator");
  assert.throws(() => profileFromEnv({ FIREEMU_SMOKE_PROFILE: "Strict" }), /must be one of/);
  assert.throws(() => profileFromEnv({ FIREEMU_SMOKE_PROFILE: "" }), /must be one of/);
  assert.throws(() => expectedShapes("lenient", "demo-app"), /unknown functions smoke profile/);
});
