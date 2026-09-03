import assert from "node:assert/strict";
import test from "node:test";

import { deferred, requireNode20 } from "./listener-runtime-compat.mjs";

test("the listener smoke supports the Firebase CLI Node 20 runtime", async () => {
  assert.doesNotThrow(() => requireNode20("20.19.5"));
  assert.throws(() => requireNode20("19.9.0"), /requires Node.js 20 or newer/);

  const completed = deferred();
  completed.resolve("ready");
  assert.equal(await completed.promise, "ready");
});
