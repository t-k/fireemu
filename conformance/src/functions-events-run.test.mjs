import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { buildFireemuArgs, sessionEnvironment } from "./functions-events/run.mjs";

test("both local profiles use the same fixture and OS-assigned product ports", () => {
  const emulator = buildFireemuArgs("emulator");
  const strict = buildFireemuArgs("strict");
  for (const args of [emulator, strict]) {
    assert.equal(args.includes("--only"), true);
    assert.equal(args[args.indexOf("--only") + 1], "auth,firestore,storage,functions,pubsub");
    for (const flag of [
      "--firestore-port",
      "--http-port",
      "--storage-port",
      "--functions-port",
      "--pubsub-port",
      "--eventarc-port",
      "--tasks-port",
      "--hub-port",
      "--logging-port",
      "--ui-port",
    ]) {
      assert.equal(args[args.indexOf(flag) + 1], "0", flag);
    }
    assert.equal(args[args.indexOf("--functions") + 1], "conformance/functions-events/fixtures");
  }
  assert.equal(
    emulator[emulator.indexOf("--config") + 1],
    "conformance/functions-events/emulator.json",
  );
  assert.equal(strict[strict.indexOf("--config") + 1], "conformance/functions-events/strict.json");
});

test("the strict profile loads the Firestore rules the production recording ran under", () => {
  // The ruleset of the FE v5 recording (ruleset 732dd8ab, request body docs.local/runs/fe-formal-v2-prereq/ruleset-request.json).
  const production =
    "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /fe_events_primary/{id} {\n      allow create: if request.auth != null;\n    }\n  }\n}\n";
  const read = (name) =>
    readFileSync(new URL(`../functions-events/${name}`, import.meta.url), "utf8");
  const strict = JSON.parse(read("strict.json"));
  assert.equal(strict.rules.source, "conformance/functions-events/firestore.rules");
  assert.equal(read("firestore.rules"), production);
});

test("a session runs without credentials, with the capture socket, the binary's identity and the runner of this checkout pinned", () => {
  const identity = {
    binarySha256: "a".repeat(64),
    sourceCommit: "b".repeat(40),
    dirty: false,
    runnerPath: "/checkout/tools/runner-node/index.mjs",
    runnerSha256: "c".repeat(64),
    runnerTree: "d".repeat(40),
  };
  const base = {
    PATH: "/bin",
    GOOGLE_APPLICATION_CREDENTIALS: "/secret.json",
    FE_EVENTS_ALLOW_PRODUCTION_ADMIN: "1",
    FIREEMU_RUNNER_NODE: "/elsewhere/index.mjs",
    FE_EVENTS_BINARY_SHA256: "f".repeat(64),
  };
  const env = sessionEnvironment({
    base,
    shortDir: "/tmp/fe-x/run",
    onlyRecipeIds: undefined,
    windowMs: 5000,
    socketPath: "/tmp/fe-x/run/events.sock",
    identity,
  });
  assert.equal(env.PATH, "/bin");
  assert.equal(env.GOOGLE_APPLICATION_CREDENTIALS, "");
  assert.equal("FE_EVENTS_ALLOW_PRODUCTION_ADMIN" in env, false);
  assert.equal(
    env.FIREEMU_RUNNER_NODE,
    identity.runnerPath,
    "the runner of this checkout wins over the caller's",
  );
  assert.equal(
    env.FE_EVENTS_BINARY_SHA256,
    identity.binarySha256,
    "the identity is the hashed one, not the caller's",
  );
  assert.equal(env.FE_EVENTS_SOURCE_COMMIT, identity.sourceCommit);
  assert.equal(env.FE_EVENTS_TREE_DIRTY, "0");
  assert.equal(env.FE_EVENTS_RUNNER_SHA256, identity.runnerSha256);
  assert.equal(env.FE_EVENTS_RUNNER_TREE, identity.runnerTree);
  assert.equal(env.FE_EVENTS_PRIVATE_DIR, "/tmp/fe-x/run");
  assert.equal(env.FE_EVENTS_ONLY, "");
  assert.equal(env.FE_EVENTS_WINDOW_MS, "5000");
  assert.equal(env.FE_EVENTS_MODE, "local");
  assert.equal(env.FE_EVENTS_CAPTURE_MODE, "socket");
  assert.equal(env.FE_EVENTS_CAPTURE_SOCKET, "/tmp/fe-x/run/events.sock");
  assert.equal(
    sessionEnvironment({
      base: {},
      shortDir: "d",
      onlyRecipeIds: "a,b",
      windowMs: 1,
      socketPath: "s",
      identity,
    }).FE_EVENTS_ONLY,
    "a,b",
  );
});
