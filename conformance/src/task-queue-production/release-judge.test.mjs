import "./record/isolation.mjs";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { COMPARISON_KIND } from "./compare-cli.mjs";
import { EXPORT_KIND, TOLERANCE_FACTOR, judgeTaskQueue } from "./release-judge.mjs";
import { documentsFor, optionValue, usageOk } from "./release-replay.mjs";

const read = (name) => JSON.parse(readFileSync(new URL(`../../${name}`, import.meta.url), "utf8"));
const FILES = {
  runs: "task-queue-production-run-comparison.json",
  strict1: "task-queue-production-strict-vs-pass-1.json",
  strict2: "task-queue-production-strict-vs-pass-2.json",
};
const pass1 = read("task-queue-production-pass-1.json");
const pass2 = read("task-queue-production-pass-2.json");
const local = read("task-queue-production-local-strict.json");
const SHA = "a".repeat(64);
const path = (name) => `conformance/${name}`;
const exportOf = (documents = documentsFor(local, pass1, pass2)) => ({
  kind: EXPORT_KIND,
  binarySha256: SHA,
  documents,
});
const judge = (name, observed) =>
  judgeTaskQueue(path(name), read(name), observed, { binarySha256: SHA });
const clone = (value) => JSON.parse(JSON.stringify(value));
const strict1 = (mutate) => {
  const documents = documentsFor(local, pass1, pass2);
  mutate(documents[path(FILES.strict1)]);
  return judge(FILES.strict1, exportOf(documents)).join();
};

test("the committed local replay passes the judge for all three comparison files", () => {
  for (const name of Object.values(FILES)) assert.deepEqual(judge(name, exportOf()), [], name);
});

test("every committed comparison carries the kind the release run is found by", () => {
  assert.equal(COMPARISON_KIND, "task-queue-comparison-v1");
  for (const name of Object.values(FILES)) assert.equal(read(name).kind, COMPARISON_KIND, name);
});

test("the replay is computed at twice the committed tolerance and the judge requires it", () => {
  const documents = documentsFor(local, pass1, pass2);
  const expected = read(FILES.strict1);
  assert.equal(
    documents[path(FILES.strict1)].tolerance.firstMs,
    expected.tolerance.firstMs * TOLERANCE_FACTOR,
  );
  const committedTolerance = clone(documents);
  committedTolerance[path(FILES.strict1)].tolerance = expected.tolerance;
  assert.match(
    judge(FILES.strict1, exportOf(committedTolerance)).join(),
    /times the committed tolerance/,
  );
});

test("a missing export, another kind, another binary or a missing document are refused", () => {
  assert.match(judge(FILES.strict1, undefined).join(), /produced no export/);
  assert.match(judge(FILES.strict1, { ...exportOf(), kind: "x" }).join(), /export kind/);
  assert.match(
    judge(FILES.strict1, { ...exportOf(), binarySha256: "b".repeat(64) }).join(),
    /another binary/,
  );
  assert.match(judge(FILES.strict1, exportOf({})).join(), /not in the export/);
});

test("a mismatch, an unknown row, a timing outside the tolerance or a differing property is refused", () => {
  assert.match(
    strict1((d) => (d.summary.structure.MISMATCH = 1)),
    /mismatch or an unknown/,
  );
  assert.match(
    strict1((d) => (d.summary.structure.UNKNOWN = 1)),
    /mismatch or an unknown/,
  );
  assert.match(
    strict1((d) => (d.summary.timing.OUTSIDE = 1)),
    /timing outside/,
  );
  assert.match(
    strict1((d) => (d.properties[0].verdict = "MISMATCH")),
    /property/,
  );
  assert.match(
    strict1((d) => (d.properties = [])),
    /property/,
  );
  assert.match(
    strict1((d) => (d.kind = "other")),
    /document kind/,
  );
  assert.match(
    strict1((d) => (d.left.corpusSha256 = "0".repeat(64))),
    /other recordings or another corpus/,
  );
  assert.match(
    strict1((d) => (d.right.corpusSha256 = "0".repeat(64))),
    /other recordings or another corpus/,
  );
});

test("the rows must be the committed rows, case by case, in structure and parts", () => {
  assert.match(
    strict1((d) => d.rows.pop()),
    /cases differ/,
  );
  assert.match(
    strict1((d) => (d.rows[3].case = "renamed")),
    /cases differ/,
  );
  assert.match(
    strict1(
      (d) => (d.rows[3].structure = d.rows[3].structure === "MATCH" ? "KNOWN_DIFFERENCE" : "MATCH"),
    ),
    /structure/,
  );
  const known = (d) => d.rows.findIndex((row) => row.structure === "KNOWN_DIFFERENCE");
  assert.match(
    strict1((d) => (d.rows[known(d)].parts.admission.knownDifferences = ["KD-OTHER"])),
    /parts differ/,
  );
  // A timing that moved but stayed inside the tolerance is not a difference.
  assert.equal(
    strict1((d) => (d.rows[3].timing = { verdict: "WITHIN" })),
    "",
  );
});

test("the comparison of the two recordings must equal the committed one exactly", () => {
  assert.deepEqual(judge(FILES.runs, exportOf()), []);
  const documents = documentsFor(local, pass1, pass2);
  documents[path(FILES.runs)].rows[0].structure = "MISMATCH";
  assert.match(judge(FILES.runs, exportOf(documents)).join(), /two recordings differs/);
});

test("the command line is local, a binary and an export file", () => {
  assert.equal(usageOk(["local", "--fireemu", "f", "--export", "e"]), true);
  for (const bad of [
    [],
    ["local"],
    ["local", "--fireemu", "f"],
    ["local", "--fireemu", "--export", "e"],
    ["remote", "--fireemu", "f", "--export", "e"],
  ])
    assert.equal(usageOk(bad), false, bad.join(" "));
  assert.equal(optionValue(["--a", "x"], "--a"), "x");
  assert.equal(optionValue(["--a"], "--a"), undefined);
  assert.equal(optionValue(["--a", "--b"], "--a"), undefined);
});
