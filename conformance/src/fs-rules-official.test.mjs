// The official emulator answers as production does on the FS-RULES cases where fireemu's
// emulator profile changed with production (scope decision R9: that profile adds no refusal the
// official emulator does not make). conformance/fs-rules-official.json is recorded by
// src/fs-rules-official.mjs against the pinned official emulator.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { RUNTIME_CASES } from "./fs-rules-official.mjs";
import { COMPILE_CASES } from "./fs-rules/programs/limits.mjs";

const read = (name) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../${name}`, import.meta.url)), "utf8"));

// Where the official emulator and production answer differently. fireemu follows production in
// both profiles only where this lists the official emulator as the stricter one; otherwise the
// emulator profile would refuse what the official emulator allows.
const OFFICIAL_DIFFERS = {
  "source-256k-plus":
    "The official emulator compiles a source over 256 KiB, production refuses it; fireemu refuses it (RULES-SOURCE-SIZE) in both profiles, as it did before FS-RULES.",
};

const allowed = (recorded) => {
  if (recorded.grpc !== undefined) return recorded.grpc === 0 || recorded.grpc === 5;
  const body = Array.isArray(recorded.body) ? recorded.body : [recorded.body];
  // A read of a missing document that the rules allowed is 404 in production.
  return (
    (recorded.status < 400 || recorded.status === 404) &&
    !body.some((e) => e?.error?.status === "PERMISSION_DENIED")
  );
};

test("the official emulator compiles what production compiles", () => {
  const official = read("fs-rules-official.json");
  const production = read("fs-rules-production.json").programs["fs-rules/compile/acceptance"].steps;
  assert.deepEqual(
    Object.keys(official.compile).toSorted(),
    COMPILE_CASES.map(([n]) => n).toSorted(),
  );
  for (const [name, { accepted }] of Object.entries(official.compile)) {
    if (Object.hasOwn(OFFICIAL_DIFFERS, name)) {
      assert.notEqual(accepted, production[name].compiled, `${name} is listed as differing`);
      continue;
    }
    assert.equal(accepted, production[name].compiled, name);
  }
});

test("the official emulator decides the changed runtime cases as production does", () => {
  const official = read("fs-rules-official.json");
  const production = read("fs-rules-production.json").programs;
  assert.deepEqual(
    Object.keys(official.runtime).toSorted(),
    RUNTIME_CASES.map(({ name }) => name).toSorted(),
  );
  for (const { name, production: row } of RUNTIME_CASES) {
    const answer = official.runtime[name];
    assert.notEqual(answer.compiled, false, `${name} compiles in the official emulator`);
    if (!row) continue;
    const [program, step] = row;
    const recorded = production[program].steps[step];
    assert.ok(recorded, `${program}#${step} is recorded`);
    assert.equal(answer.allowed, allowed(recorded), `${name} against ${program}#${step}`);
  }
  // The exploratory probes' nine request.query keys, which no recorded row names.
  assert.equal(official.runtime["query-has-nine-keys"].allowed, true);
});
