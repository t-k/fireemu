import assert from "node:assert/strict";
import test from "node:test";

import { judgeHosting } from "./release-judge.mjs";

const PATH = "conformance/hosting-production-strict-vs-pass-1.json";
const SHA = "a".repeat(64);
const document = (summary = { MATCH: 201, MISMATCH: 0, UNKNOWN: 0 }) => ({
  kind: "hosting-comparison-v1",
  comparison: "production-vs-local",
  summary,
  rows: [{ id: "v01.root", status: "MATCH", differences: [] }],
});
const exported = (overrides = {}) => ({
  kind: "hosting-comparison-v1-export",
  binarySha256: SHA,
  documents: { [PATH]: document() },
  ...overrides,
});
const judge = (observed, expected = document(), binarySha256 = SHA) =>
  judgeHosting(PATH, expected, observed, { binarySha256 });

test("a binary that reproduces the committed document passes", () => {
  assert.deepEqual(judge(exported()), []);
});

test("no export, a wrong kind, another binary or a missing document are each a difference", () => {
  assert.deepEqual(judge(undefined), [`${PATH}: R37 produced no export`]);
  assert.deepEqual(judge(exported({ kind: "other" })), ["the export kind differs"]);
  assert.deepEqual(judge(exported({ binarySha256: "b".repeat(64) })), [
    "the export names another binary than the one under test",
  ]);
  assert.deepEqual(judge(exported({ documents: {} })), [`${PATH}: not in the export`]);
  assert.deepEqual(judge(exported({ documents: undefined })), [`${PATH}: not in the export`]);
  // the differences add up: a wrong kind and a missing document
  assert.deepEqual(judge(exported({ kind: "other", documents: {} })), [
    "the export kind differs",
    `${PATH}: not in the export`,
  ]);
  // another document's path is not this one
  assert.deepEqual(judge(exported({ documents: { "conformance/other.json": document() } })), [
    `${PATH}: not in the export`,
  ]);
});

test("a mismatch or an unknown row in the export is a difference even when the committed file says the same", () => {
  for (const summary of [
    { MATCH: 200, MISMATCH: 1, UNKNOWN: 0 },
    { MATCH: 200, MISMATCH: 0, UNKNOWN: 1 },
  ]) {
    const bad = document(summary);
    const found = judge(exported({ documents: { [PATH]: bad } }), bad);
    assert.deepEqual(found, [`${PATH}: the replay has a mismatch or an unknown row`]);
  }
  // a summary with no counts at all is not a pass
  const bare = { ...document(), summary: {} };
  assert.deepEqual(judge(exported({ documents: { [PATH]: bare } }), bare), [
    `${PATH}: the replay has a mismatch or an unknown row`,
  ]);
});

test("the exported document must equal the committed one in every field", () => {
  const changedRow = document();
  changedRow.rows[0].status = "MATCH_LAYOUT";
  assert.deepEqual(judge(exported({ documents: { [PATH]: changedRow } })), [
    `${PATH}: differs from the committed comparison`,
  ]);
  const extra = { ...document(), extra: 1 };
  assert.deepEqual(judge(exported({ documents: { [PATH]: extra } })), [
    `${PATH}: differs from the committed comparison`,
  ]);
  const summaryOnly = document({ MATCH: 200, MATCH_LAYOUT: 1, MISMATCH: 0, UNKNOWN: 0 });
  assert.deepEqual(judge(exported({ documents: { [PATH]: summaryOnly } })), [
    `${PATH}: differs from the committed comparison`,
  ]);
});
