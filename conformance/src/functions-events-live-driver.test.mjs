import assert from "node:assert/strict";
import { test } from "node:test";
import { createLiveDriver } from "./functions-events/live-driver.mjs";

const required = [
  "FIRESTORE_EMULATOR_HOST",
  "FIREBASE_STORAGE_EMULATOR_HOST",
  "FIREBASE_AUTH_EMULATOR_HOST",
  "PUBSUB_EMULATOR_HOST",
];

test("every live driver refuses missing or remote SDK hosts before initialization", async () => {
  const previous = Object.fromEntries(
    [...required, "STORAGE_EMULATOR_HOST"].map((name) => [name, process.env[name]]),
  );
  try {
    for (const name of required) process.env[name] = "127.0.0.1:1";
    process.env.STORAGE_EMULATOR_HOST = "http://127.0.0.1:1";
    for (const name of required) {
      for (const bad of [undefined, "firestore.googleapis.com:443", "localhost.evil.com:443"]) {
        if (bad === undefined) delete process.env[name];
        else process.env[name] = bad;
        await assert.rejects(
          createLiveDriver({ projectId: "demo-conformance" }),
          /loopback emulator/,
        );
        process.env[name] = "127.0.0.1:1";
      }
    }
    process.env.STORAGE_EMULATOR_HOST = "https://storage.googleapis.com";
    await assert.rejects(createLiveDriver({ projectId: "demo-conformance" }), /loopback emulator/);
  } finally {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});
