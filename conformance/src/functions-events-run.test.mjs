import assert from "node:assert/strict";
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
