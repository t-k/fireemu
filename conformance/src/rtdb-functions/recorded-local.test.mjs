// What fireemu delivered for the CV14 fixture and write sequence (recorded/local-rtdb-triggers-<profile>.json,
// produced by local-run.mjs on the release binary named in each file) against the production recording:
// the strict profile matches on every row; the emulator profile keeps the official emulator's shape, and the
// difference is exactly the declared list below.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { compareRecordings } from "./compare-local.mjs";

const load = (name) =>
  JSON.parse(readFileSync(new URL(`./recorded/${name}.json`, import.meta.url), "utf8"));
const production = load("production-rtdb-triggers").frames.map(
  ({ n: _n, step: _step, ...frame }) => frame,
);
const compared = (profile) =>
  compareRecordings({ production, local: load(`local-rtdb-triggers-${profile}`).frames });

test("both local recordings name the binary and the profile that produced them", () => {
  for (const profile of ["strict", "emulator"]) {
    const recording = load(`local-rtdb-triggers-${profile}`);
    assert.equal(recording.profile, profile);
    assert.match(recording.binary.sha256, /^[0-9a-f]{64}$/u);
    assert.match(recording.binary.sourceCommit, /^[0-9a-f]{40}$/u);
    assert.equal(recording.frames.length, 28);
  }
});

test("the strict profile matches production on all 72 rows (9 writes x 8 handlers, 28 deliveries)", () => {
  const result = compared("strict");
  assert.deepEqual(result.totals, { rows: 72, match: 72, difference: 0 });
  assert.equal(result.rows.filter((row) => row.local === 1).length, 28);
  assert.deepEqual(result.unattributed, { production: [], local: [] });
  assert.deepEqual(
    result.facts.map((fact) => [fact.oneTimePerWrite, fact.distinctIds]),
    [
      [true, true],
      [true, true],
    ],
  );
});

test("the emulator profile differs on exactly the 28 deliveries, in exactly the declared members", () => {
  const result = compared("emulator");
  assert.deepEqual(result.totals, { rows: 72, match: 44, difference: 28 });
  assert.deepEqual(
    result.rows
      .filter((row) => row.verdict === "MATCH")
      .every((row) => row.production === 0 && row.local === 0),
    true,
    "the rows without a delivery match",
  );
  const paths = new Map();
  for (const row of result.rows) {
    const generation = row.row.endsWith("V1") ? 1 : 2;
    for (const difference of row.differences) {
      const key = `gen${generation} ${difference.path}`;
      paths.set(key, (paths.get(key) ?? 0) + 1);
    }
  }
  assert.deepEqual(Object.fromEntries([...paths].toSorted()), {
    // 1st gen (14 deliveries): the id form, the timestamp form
    "gen1 $.context.eventId": 14,
    "gen1 $.context.timestamp": 14,
    // 2nd gen (14 deliveries)
    "gen2 $.authType": 14,
    "gen2 $.datacontenttype": 14,
    "gen2 $.eventKeys.datacontenttype": 14,
    "gen2 $.eventKeys.traceparent": 14,
    "gen2 $.extras.context.keys": 14,
    "gen2 $.extras.traceparent": 14,
    "gen2 $.id": 14,
    "gen2 $.source": 14,
    "gen2 $.time": 14,
  });
  // the values: admin and unauthenticated writes are named by the official emulator, production says unknown
  const authTypes = new Set();
  for (const row of result.rows)
    for (const d of row.differences)
      if (d.path === "$.authType") authTypes.add(`${d.production}>${d.local}`);
  assert.deepEqual([...authTypes].toSorted(), ["unknown>admin", "unknown>unauthenticated"]);
});
