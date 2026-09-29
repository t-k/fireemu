// A ledger row may name several projects: as a comma-separated string ("a,b", how the
// STORAGE-RULES stage 3 rows and a SANDBOX-CONFIG note write it) or as a `projects` array. The
// admission checks read `row.project` as one name, so a run expands such rows first: one row per
// project, everything else kept, so that another lane's open run or recent line on this project is
// seen whichever way it was written.

import assert from "node:assert/strict";
import test from "node:test";
import { admissionProblems } from "./auth-fs-cross/sandbox.mjs";
import { expandProjectRows } from "./storage-object/ledger-rows.mjs";
import { recentLineProblems } from "./storage-object/record.mjs";

const QUERY = "fireemu-oracle-query";
const IDP = "fireemu-oracle-idp";
const lines = (text) =>
  text
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
const text = (...rows) => rows.map((row) => JSON.stringify(row)).join("\n") + "\n";

// The shape of the real STORAGE-RULES stage 3 rows (ledger lines 446-452).
const reservedRow = {
  ts: "2026-09-29T22:38:16.174Z",
  event: "reservedRow",
  taskId: "STORAGE-RULES-SANDBOX",
  project: `${QUERY},${IDP}`,
  packetId: "stage3-v6",
  runId: "stage3-20260930a",
  maxRequests: 12344,
  estimatedUsd: 2,
};
const finished = {
  ts: "2026-09-29T22:39:27.550Z",
  event: "finished",
  taskId: "STORAGE-RULES-SANDBOX",
  project: `${QUERY},${IDP}`,
  packetId: "stage3-v6",
  runId: "stage3-20260930a",
  outcome: "stopped-clean",
  requests: 17,
  sandboxAtBaseline: true,
  estimatedUsd: 0,
};

test("a row of one project is returned as it was, byte for byte", () => {
  const original = `${JSON.stringify({ ts: "2026-09-29T22:38:16.174Z", taskId: "X", project: QUERY, n: 1 })}\n`;
  assert.equal(expandProjectRows(original), original);
});

test("a comma-separated project string becomes one row per project, the rest of the row kept", () => {
  const rows = lines(expandProjectRows(text(reservedRow)));
  assert.deepEqual(
    rows.map((row) => row.project),
    [QUERY, IDP],
  );
  for (const row of rows) assert.deepEqual({ ...row, project: reservedRow.project }, reservedRow);
});

test("spaces around a name are dropped, and an empty name and a repeated name are not rows", () => {
  const rows = lines(
    expandProjectRows(text({ ...reservedRow, project: ` ${QUERY} , ,${IDP},${QUERY}` })),
  );
  assert.deepEqual(
    rows.map((row) => row.project),
    [QUERY, IDP],
  );
});

test("a projects array is expanded too, and joins a project string without repeating a name", () => {
  const { project: _project, ...rest } = reservedRow;
  assert.deepEqual(
    lines(expandProjectRows(text({ ...rest, projects: [QUERY, IDP] }))).map((row) => row.project),
    [QUERY, IDP],
  );
  assert.deepEqual(
    lines(expandProjectRows(text({ ...reservedRow, project: QUERY, projects: [IDP, QUERY] }))).map(
      (row) => row.project,
    ),
    [QUERY, IDP],
  );
  for (const row of lines(expandProjectRows(text({ ...rest, projects: [QUERY, IDP] }))))
    assert.equal("projects" in row, false, "the array is gone once it is expanded");
});

test("a line that is not JSON, a blank line and a row without a project are kept in place", () => {
  const input = `not json\n\n${JSON.stringify({ ts: "t", note: "no project" })}\n${JSON.stringify(reservedRow)}\n`;
  const out = expandProjectRows(input).split("\n");
  assert.equal(out[0], "not json");
  assert.equal(out[1], "");
  assert.equal(out[2], JSON.stringify({ ts: "t", note: "no project" }));
  assert.equal(out.length, 6, "two rows for the multi-project line");
});

test("a project that is not a string, or an array holding one that is not, is left alone", () => {
  for (const row of [
    { ...reservedRow, project: 5 },
    { ...reservedRow, project: null },
    { ...reservedRow, project: undefined, projects: "a,b" },
  ]) {
    const original = text(row);
    assert.equal(expandProjectRows(original), original);
  }
  const mixed = lines(
    expandProjectRows(text({ ...reservedRow, project: QUERY, projects: [IDP, 7, null] })),
  );
  assert.deepEqual(
    mixed.map((row) => row.project),
    [QUERY, IDP],
  );
});

test("STORAGE-RULES's real rows: six minutes after its run the recorder is inside the quiet interval", () => {
  const now = Date.parse("2026-09-29T22:45:27.550Z");
  const raw = text(reservedRow, finished);
  // Read as they are, the two rows name no project of this run: the defect this fixes.
  assert.deepEqual(recentLineProblems(raw, QUERY, now), []);
  assert.deepEqual(admissionProblems(raw, QUERY, now), []);
  const expanded = expandProjectRows(raw);
  assert.equal(recentLineProblems(expanded, QUERY, now).length, 2);
  // Thirty minutes to the millisecond after the last line, the interval is over.
  const later = Date.parse("2026-09-29T23:09:27.550Z");
  assert.deepEqual(recentLineProblems(expandProjectRows(raw), QUERY, later), []);
  assert.equal(
    recentLineProblems(expandProjectRows(raw), QUERY, later - 1).length,
    1,
    "the last line is 29 minutes 59.999 seconds old",
  );
});

test("a started row of several projects with no closing row is an open run on each of them", () => {
  const now = Date.parse("2026-09-30T09:00:00.000Z");
  const startedRow = { ...reservedRow, event: "started" };
  assert.deepEqual(admissionProblems(text(startedRow), QUERY, now), []);
  const problems = admissionProblems(expandProjectRows(text(startedRow)), QUERY, now);
  assert.ok(problems.length > 0, "the open run is seen once the row is expanded");
  // The same row is also an open run of the other project.
  assert.ok(admissionProblems(expandProjectRows(text(startedRow)), IDP, now).length > 0);
  // And a project that is not named is not affected.
  assert.deepEqual(
    admissionProblems(expandProjectRows(text(startedRow)), "another-project", now),
    [],
  );
});

test("a closed multi-project run is not an open run", () => {
  const now = Date.parse("2026-09-30T09:00:00.000Z");
  const startedRow = { ...reservedRow, event: "started" };
  assert.deepEqual(
    admissionProblems(expandProjectRows(text(startedRow, finished)), QUERY, now),
    [],
  );
});

test("a row of one project keeps the spacing it was written with", () => {
  const original =
    '{"ts": "2026-09-29T15:10:02.000Z", "taskId": "X",   "project": "fireemu-oracle-query"}\n';
  assert.equal(expandProjectRows(original), original);
});

test("a JSON line that is not a row (null, an array, a number, a string) is kept as it is", () => {
  const original = 'null\n[{"project":"a,b"}]\n5\n"a,b"\n';
  assert.equal(expandProjectRows(original), original);
});
