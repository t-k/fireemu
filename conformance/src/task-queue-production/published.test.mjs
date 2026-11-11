// The committed recordings (masked projections), their comparisons and the committed local replay: nothing is sent or started
// here. The comparisons are rebuilt from the committed projections and must equal the committed files byte for byte.
import "./record/isolation.mjs";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { compareRuns, compareStrict } from "./compare-cli.mjs";
import { PROGRAM, corpusManifest } from "./corpus.mjs";
import { refuseUnmaskedNumbers } from "./project.mjs";

const read = (name) => readFileSync(new URL(`../../${name}`, import.meta.url), "utf8");
const json = (name) => JSON.parse(read(name));
const FILES = {
  pass1: "task-queue-production-pass-1.json",
  pass2: "task-queue-production-pass-2.json",
  local: "task-queue-production-local-strict.json",
  runs: "task-queue-production-run-comparison.json",
  strict1: "task-queue-production-strict-vs-pass-1.json",
  strict2: "task-queue-production-strict-vs-pass-2.json",
};

test("every published file is bound to the corpus and holds no unmasked number", () => {
  const { corpusSha256 } = corpusManifest();
  for (const name of [FILES.pass1, FILES.pass2, FILES.local]) {
    assert.equal(json(name).corpusSha256, corpusSha256, name);
    assert.doesNotThrow(() => refuseUnmaskedNumbers(read(name)), name);
  }
  for (const name of Object.values(FILES))
    assert.doesNotThrow(() => refuseUnmaskedNumbers(read(name)), name);
});

test("both recordings answered the whole program, completely observed, with no finding", () => {
  const keys = PROGRAM.map((step) => step.key);
  for (const name of [FILES.pass1, FILES.pass2]) {
    const recording = json(name);
    assert.equal(recording.observationComplete, true, name);
    assert.equal(recording.findings, 0, name);
    assert.equal(recording.recorderRequests, 230, name);
    assert.deepEqual(Object.keys(recording.cases).toSorted(), [...keys].toSorted(), name);
  }
  assert.deepEqual(Object.keys(json(FILES.local).cases).toSorted(), [...keys].toSorted());
});

test("the two production runs agree with each other: no mismatch, no unknown, equal concurrency properties", () => {
  const committed = json(FILES.runs);
  assert.deepEqual(compareRuns(json(FILES.pass1), json(FILES.pass2)), committed);
  assert.equal(committed.summary.structure.MISMATCH ?? 0, 0);
  assert.equal(committed.summary.structure.UNKNOWN ?? 0, 0);
  assert.equal(committed.summary.timing.OUTSIDE ?? 0, 0);
  assert.ok(committed.properties.every((p) => p.verdict === "MATCH"));
  assert.equal(committed.knownDifferences.length, 0);
});

test("strict fireemu against each recording: no mismatch outside the known differences, every timing within", () => {
  for (const [name, pass] of [
    [FILES.strict1, FILES.pass1],
    [FILES.strict2, FILES.pass2],
  ]) {
    const committed = json(name);
    assert.deepEqual(compareStrict(json(FILES.local), json(pass)), committed, name);
    assert.equal(committed.summary.structure.MISMATCH ?? 0, 0, name);
    assert.equal(committed.summary.structure.UNKNOWN ?? 0, 0, name);
    assert.equal(committed.summary.timing.OUTSIDE ?? 0, 0, name);
    assert.ok(
      committed.properties.every((p) => p.verdict === "MATCH"),
      name,
    );
    // Each known difference is used, so none is left over after a change of behaviour. A timing allowance is used only when
    // a run's timing falls outside the tolerance, so it may be unused in one of the files.
    for (const kd of committed.knownDifferences)
      assert.ok(kd.rows > 0 || kd.part === "timing", `${name} ${kd.id} is unused`);
  }
});

test("every known difference cites a ruling", () => {
  for (const name of [FILES.strict1, FILES.strict2])
    for (const kd of json(name).knownDifferences)
      assert.ok(Number.isInteger(kd.ruling) && kd.ruling > 0, kd.id);
});
