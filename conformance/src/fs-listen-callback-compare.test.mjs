import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { tempDir } from "./test-tmpdir.mjs";
import { compareRecordings } from "./fs-listen/compare.mjs";
import { rowsFromReceipt } from "./fs-listen/sdk-record.mjs";

const snapshot = (extra = {}) => ({
  listener: "primary",
  snapshotKind: "delta",
  docs: ["b"],
  changes: [{ type: "removed", doc: "a", oldIndex: 0, newIndex: -1 }],
  exists: null,
  error: null,
  fromCache: false,
  hasPendingWrites: false,
  ...extra,
});
const row = (rawEvents, baselineAt = 0) => ({
  observed: [{ docs: ["b"], changes: [{ type: "removed", doc: "a" }] }],
  failures: [],
  invariantViolations: [],
  end: null,
  timedOut: false,
  ...(rawEvents === undefined ? {} : { rawEvents, baselineAt }),
});
const recording = (value) => ({
  version: 1,
  cleanup: { complete: true },
  errors: {},
  rows: { "sdk/111": value },
});
const compare = (production, local, second = production) =>
  compareRecordings({
    productions: [recording(production), recording(second)],
    local: recording(local),
  });

test("SDK111 retains aggregate MATCH but missing callback observations cannot pass", () => {
  const report = compare(row(undefined), row(undefined));
  assert.equal(report.rows["sdk/111"].status, "MATCH");
  assert.equal(report.rows["sdk/111"].callbackStatus, "UNOBSERVED");
  assert.equal(report.aggregateOk, true);
  assert.equal(report.callbackOk, false);
  assert.equal(report.ok, false);
});
test("SDK111 valid empty callback windows are observed and distinct from missing windows", () => {
  assert.equal(compare(row([]), row([])).rows["sdk/111"].callbackStatus, "MATCH");
  assert.equal(compare(row([]), row([])).ok, true);
  assert.equal(compare(row([]), row(undefined)).rows["sdk/111"].callbackStatus, "UNOBSERVED");
});
test("SDK111 callback comparison slices the collector baseline without collapsing callbacks", () => {
  const production = row([snapshot({ docs: ["warmup"] }), snapshot()], 1);
  const local = row(
    [snapshot({ docs: ["other warmup"] }), snapshot({ generatedAt: "another clock" })],
    1,
  );
  assert.equal(compare(production, local).rows["sdk/111"].callbackStatus, "MATCH");
  assert.equal(compare(production, local).ok, true);
});
for (const [name, local] of [
  [
    "split snapshot grouping",
    [snapshot({ fromCache: true, changes: [] }), snapshot({ changes: [] }), snapshot()],
  ],
  ["metadata-only callback omission", [snapshot()]],
  [
    "change oldIndex",
    [
      snapshot({ fromCache: true, changes: [] }),
      snapshot({ changes: [{ type: "removed", doc: "a", oldIndex: 7, newIndex: -1 }] }),
    ],
  ],
  [
    "change newIndex",
    [
      snapshot({ fromCache: true, changes: [] }),
      snapshot({ changes: [{ type: "removed", doc: "a", oldIndex: 0, newIndex: 7 }] }),
    ],
  ],
  ["document order", [snapshot({ fromCache: true, changes: [] }), snapshot({ docs: ["c", "b"] })]],
  [
    "pending-write metadata",
    [snapshot({ fromCache: true, changes: [] }), snapshot({ hasPendingWrites: true })],
  ],
  [
    "listener identity",
    [snapshot({ fromCache: true, changes: [] }), snapshot({ listener: "other" })],
  ],
])
  test(`SDK111 equal aggregates do not hide ${name}`, () => {
    const production = row([snapshot({ fromCache: true, changes: [] }), snapshot()]);
    const report = compare(production, row(local));
    assert.equal(report.rows["sdk/111"].status, "MATCH");
    assert.equal(report.rows["sdk/111"].callbackStatus, "MISMATCH");
    assert.equal(report.ok, false);
  });
test("SDK111 preserves errors interleaved with later snapshots", () => {
  const error = snapshot({
    snapshotKind: "error",
    docs: [],
    changes: [],
    error: "permission-denied",
  });
  assert.equal(
    compare(row([error, snapshot()]), row([snapshot(), error])).rows["sdk/111"].callbackStatus,
    "MISMATCH",
  );
});
test("SDK111 rejects malformed baseline and incomplete callback evidence", () => {
  for (const baselineAt of [-1, 1.5, 2, undefined]) {
    const local = row([snapshot()]);
    local.baselineAt = baselineAt;
    assert.equal(compare(row([snapshot()]), local).rows["sdk/111"].callbackStatus, "UNOBSERVED");
  }
  const timedOut = { ...row([snapshot()]), timedOut: true };
  assert.equal(
    compare(row([snapshot()]), timedOut).rows["sdk/111"].callbackStatus,
    "INDETERMINATE",
  );
});
test("SDK111 callback nondeterminism remains independent of matching aggregates", () => {
  const report = compare(
    row([snapshot()]),
    row([snapshot()]),
    row([snapshot({ fromCache: true })]),
  );
  assert.equal(report.rows["sdk/111"].status, "MATCH");
  assert.equal(report.rows["sdk/111"].callbackStatus, "NONDETERMINISTIC");
  assert.equal(report.ok, false);
});
test("SDK111 recorder-to-comparator path retains full callback evidence", () => {
  const receipt = {
    cases: [
      {
        caseId: "FS-LISTEN-SDK-111",
        comparedFields: ["docs", "changes"],
        observed: [{ docs: ["b"], changes: [] }],
        rawEvents: [snapshot({ docs: ["warmup"] }), snapshot()],
        rawEventCount: 2,
        baselineAt: 1,
        failures: [],
        invariantViolations: [],
      },
    ],
  };
  const recorded = rowsFromReceipt(receipt)["sdk/111"];
  const report = compare(recorded, structuredClone(recorded));
  assert.equal(report.rows["sdk/111"].callbackStatus, "MATCH");
  const mutant = structuredClone(recorded);
  mutant.rawEvents[1].changes[0].oldIndex = 999;
  assert.equal(compare(recorded, mutant).rows["sdk/111"].callbackStatus, "MISMATCH");
});

test("SDK111 malformed raw evidence is unobserved, not an empty callback match", () => {
  for (const extra of [
    { rawEvents: null },
    { rawEvents: [null] },
    { rawEvents: [{}] },
    { rawEventCount: 99 },
    { rawEvents: [snapshot({ changes: null })] },
  ]) {
    const bad = { ...row([snapshot()]), ...extra };
    assert.equal(compare(bad, bad).rows["sdk/111"].callbackStatus, "UNOBSERVED");
    assert.equal(compare(bad, bad).ok, false);
  }
});
for (const mode of ["long-polling", "streaming"])
  test(`SDK111 ${mode} browser CLI reports missing callbacks separately from its matching aggregate`, () => {
    const caseId = `browser-${mode}/sdk/111`;
    const dir = tempDir("fs-listen-callback-cli-");
    const production = join(dir, "production.json"),
      local = join(dir, "local.json"),
      out = join(dir, "report.json"),
      md = join(dir, "report.md");
    writeFileSync(
      production,
      JSON.stringify({
        ...recording(row(undefined)),
        kind: "browser",
        rows: { [caseId]: row(undefined) },
      }),
    );
    writeFileSync(
      local,
      JSON.stringify({
        ...recording(row(undefined)),
        kind: "browser",
        rows: { [caseId]: row(undefined) },
      }),
    );
    const result = spawnSync(
      process.execPath,
      [
        fileURLToPath(new URL("./fs-listen/compare.mjs", import.meta.url)),
        "--production",
        production,
        "--local",
        local,
        "--out",
        out,
        "--md",
        md,
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 1);
    const report = JSON.parse(readFileSync(out));
    assert.equal(report.rows[caseId].status, "MATCH");
    assert.equal(report.rows[caseId].callbackStatus, "UNOBSERVED");
    assert.equal(report.aggregateOk, true);
    assert.equal(report.callbackOk, false);
    assert.equal(report.ok, false);
    assert.match(readFileSync(md, "utf8"), /callbacks: UNOBSERVED/);
  });
test("SDK111 preserves arbitrary callback change indexes", () => {
  for (let index = 0; index < 32; index += 1) {
    const production = row([
      snapshot({ changes: [{ type: "modified", doc: "a", oldIndex: index, newIndex: index + 1 }] }),
    ]);
    assert.equal(
      compare(production, structuredClone(production)).rows["sdk/111"].callbackStatus,
      "MATCH",
    );
    const local = structuredClone(production);
    local.rawEvents[0].changes[0].newIndex += 1;
    assert.equal(compare(production, local).rows["sdk/111"].callbackStatus, "MISMATCH");
  }
});

test("SDK111 callback and aggregate verdicts remain independent", () => {
  const production = row([snapshot()]);
  const local = structuredClone(production);
  local.observed[0].docs = ["other"];
  const report = compare(production, local);
  assert.equal(report.rows["sdk/111"].status, "MISMATCH");
  assert.equal(report.rows["sdk/111"].callbackStatus, "MATCH");
  assert.equal(report.aggregateOk, false);
  assert.equal(report.callbackOk, true);
  assert.equal(report.ok, false);
});

test("SDK111 preserves exact duplicate callback count, document order, and change order", () => {
  assert.equal(
    compare(row([snapshot(), snapshot()]), row([snapshot()])).rows["sdk/111"].callbackStatus,
    "MISMATCH",
  );
  const production = row([
    snapshot({
      docs: ["b", "c"],
      changes: [
        { type: "removed", doc: "a", oldIndex: 0, newIndex: -1 },
        { type: "added", doc: "c", oldIndex: -1, newIndex: 1 },
      ],
    }),
  ]);
  for (const field of ["docs", "changes"]) {
    const local = structuredClone(production);
    local.rawEvents[0][field].reverse();
    assert.equal(compare(production, local).rows["sdk/111"].callbackStatus, "MISMATCH", field);
  }
});
test("SDK111 retains snapshot kind, existence, and error code", () => {
  for (const extra of [
    { snapshotKind: "initial" },
    { exists: true },
    { error: "permission-denied" },
  ])
    assert.equal(
      compare(row([snapshot()]), row([snapshot(extra)])).rows["sdk/111"].callbackStatus,
      "MISMATCH",
    );
});
test("SDK111 incomplete metadata or change indexes cannot establish an observed callback match", () => {
  for (const extra of [
    { fromCache: undefined },
    { listener: null },
    { changes: [{ type: "removed", doc: "a" }] },
  ]) {
    const incomplete = row([snapshot(extra)]);
    assert.equal(compare(incomplete, incomplete).rows["sdk/111"].callbackStatus, "UNOBSERVED");
    assert.equal(compare(incomplete, incomplete).ok, false);
  }
});
