import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { buildFireemuArgs } from "./functions-events/run.mjs";

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
