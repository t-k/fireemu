import assert from "node:assert/strict";
import { test } from "node:test";

import { programDigest } from "./digest.mjs";

test("a program's rows depend on the captures it uploads from elsewhere, not its own", () => {
  const program = {
    id: "p",
    steps: [
      { id: "capture-all", capture: { prefix: "all", as: "all" } },
      { id: "upload-own", upload: { from: "p:all" } },
      { id: "upload-other", upload: { from: "fireemu:all" } },
    ],
  };
  const base = { "p:all": { files: { a: "1" } }, "fireemu:all": { files: { a: "1" } } };
  const digest = programDigest(program, base);
  // The recording that writes p:all is the recording its rows come from.
  assert.equal(programDigest(program, { ...base, "p:all": { files: { a: "2" } } }), digest);
  // A capture another program or fireemu wrote is an input: changing it makes the rows stale.
  assert.notEqual(programDigest(program, { ...base, "fireemu:all": { files: { a: "2" } } }), digest);
});
