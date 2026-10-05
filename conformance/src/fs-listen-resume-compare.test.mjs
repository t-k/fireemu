import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  allowedAnswers,
  answerSignature,
  compareResumeVariants,
  filtersBeforeCurrent,
  renderComparison,
} from "./fs-listen/resume-compare.mjs";

const add = { kind: "targetChange", type: "ADD", targetIds: [1], cause: null, resumeToken: false };
const current = {
  kind: "targetChange",
  type: "CURRENT",
  targetIds: [1],
  cause: null,
  resumeToken: true,
};
const bnd = { kind: "boundary", resumeToken: true };
const doc = (name) => ({
  kind: "documentChange",
  doc: name,
  fields: {},
  targetIds: [1],
  removedTargetIds: [],
});
const countOnly = (count) => ({
  kind: "filter",
  targetId: 1,
  count,
  unchangedNames: { hashCount: 0, bitmapBytes: 0, padding: 0 },
});
const bloom = (count) => ({
  kind: "filter",
  targetId: 1,
  count,
  unchangedNames: { hashCount: 14, bitmapBytes: 12, padding: 5 },
});
const row = (rows, extra = {}) => ({ rows, end: null, timedOut: false, ...extra });
const REPLAY = row([add, bnd, doc("a"), bnd, current, bnd]);
const DIFF = row([add, bnd, doc("a"), countOnly(3), current, bnd]);
const BLOOM = row([add, bnd, doc("a"), bloom(3), current, bnd]);
const ID = "native/resume-grid-g0/k1";
const recording = (run, rows) => ({ run, kind: "native", rows });

test("filtersBeforeCurrent lists the filters before CURRENT, with their size, and ignores the optional one after it", () => {
  assert.deepEqual(filtersBeforeCurrent(DIFF), ["1:3:0:0:0"]);
  assert.deepEqual(filtersBeforeCurrent(BLOOM), ["1:3:14:12:5"]);
  assert.deepEqual(filtersBeforeCurrent(REPLAY), []);
  assert.deepEqual(
    filtersBeforeCurrent(row([add, bnd, doc("a"), countOnly(3), current, bnd, bloom(3)])),
    ["1:3:0:0:0"],
  );
  assert.deepEqual(filtersBeforeCurrent(row([add, bloom(3), countOnly(3), current])), [
    "1:3:0:0:0",
    "1:3:14:12:5",
  ]);
  assert.deepEqual(
    filtersBeforeCurrent(row([add, bnd, countOnly(2)])),
    ["1:2:0:0:0"],
    "no CURRENT: all",
  );
  assert.deepEqual(filtersBeforeCurrent({}), []);
  // CURRENT as the first frame: nothing is before it. A filter that is the very first frame counts.
  assert.deepEqual(filtersBeforeCurrent(row([current, countOnly(3)])), []);
  assert.deepEqual(filtersBeforeCurrent(row([countOnly(3), add, current])), ["1:3:0:0:0"]);
  // A filter without a bloom filter is read as the count-only one.
  assert.deepEqual(
    filtersBeforeCurrent(
      row([add, { kind: "filter", targetId: 1, count: 3, unchangedNames: null }, current]),
    ),
    ["1:3:0:0:0"],
  );
  assert.deepEqual(answerSignature(DIFF), { kind: "diff+filter", filters: ["1:3:0:0:0"] });
});

test("allowedAnswers keeps each run's answer per variant row, and leaves out initial snapshots, unfinished rows and other programs", () => {
  const a = recording("r1", {
    [ID]: DIFF,
    "native/resume-grid-g0/first": DIFF,
    "native/resume-grid-g0/k2": row([add, bnd], { timedOut: true }),
    "native/resume-token/current": DIFF,
    "native/resume-kinds/leave": REPLAY,
  });
  const b = recording("r2", { [ID]: REPLAY, "native/resume-grid-g0/k2": DIFF });
  const out = allowedAnswers([a, b]);
  assert.deepEqual(out.runs, ["r1", "r2"]);
  assert.deepEqual(Object.keys(out.rows).toSorted(), [
    ID,
    "native/resume-grid-g0/k2",
    "native/resume-kinds/leave",
  ]);
  assert.deepEqual(out.rows[ID], {
    r1: { kind: "diff+filter", filters: ["1:3:0:0:0"] },
    r2: { kind: "replay", filters: [] },
  });
  assert.deepEqual(
    Object.keys(out.rows["native/resume-grid-g0/k2"]),
    ["r2"],
    "r1 did not finish it",
  );
});

const allowedOf = (first, second = first) =>
  allowedAnswers([recording("r1", { [ID]: first }), recording("r2", { [ID]: second })]);
const statusOf = (allowed, local, divergences) =>
  compareResumeVariants({ allowed, local: recording("l", { [ID]: local }), divergences }).rows[ID];

test("a local answer that both runs gave is a MATCH, one of two different answers is MATCH_EITHER, any other is DIFFER", () => {
  assert.equal(statusOf(allowedOf(DIFF), DIFF).status, "MATCH");
  assert.equal(statusOf(allowedOf(DIFF, REPLAY), DIFF).status, "MATCH_EITHER");
  assert.equal(statusOf(allowedOf(DIFF, REPLAY), REPLAY).status, "MATCH_EITHER");
  assert.equal(statusOf(allowedOf(DIFF, REPLAY), BLOOM).status, "DIFFER", "another filter");
  assert.equal(statusOf(allowedOf(REPLAY), DIFF).status, "DIFFER");
  assert.equal(statusOf(allowedOf(DIFF), REPLAY).status, "DIFFER");
  // The same kind with another filter is another answer: a bloom is not the count-only filter.
  assert.equal(statusOf(allowedOf(BLOOM), DIFF).status, "DIFFER");
  assert.equal(statusOf(allowedOf(DIFF), BLOOM).status, "DIFFER");
  // The size and the count of the filter count.
  const other = row([
    add,
    bnd,
    doc("a"),
    { ...bloom(3), unchangedNames: { hashCount: 13, bitmapBytes: 8, padding: 3 } },
    current,
    bnd,
  ]);
  assert.equal(statusOf(allowedOf(BLOOM), other).status, "DIFFER");
  assert.equal(
    statusOf(allowedOf(DIFF), row([add, bnd, doc("a"), countOnly(2), current, bnd])).status,
    "DIFFER",
  );
  // A filter after CURRENT is optional: it changes nothing.
  assert.equal(
    statusOf(allowedOf(DIFF), row([add, bnd, doc("a"), countOnly(3), current, bnd, bloom(3)]))
      .status,
    "MATCH",
  );
});

test("two filters are two answers, not one: keys that would run together when joined are told apart", () => {
  const two = row([
    add,
    bnd,
    doc("a"),
    countOnly(1),
    { ...countOnly(1), targetId: 2 },
    current,
    bnd,
  ]);
  const one = row([
    add,
    bnd,
    doc("a"),
    {
      kind: "filter",
      targetId: 1,
      count: 1,
      unchangedNames: { hashCount: 0, bitmapBytes: 0, padding: "02:1:0:0:0" },
    },
    current,
    bnd,
  ]);
  assert.equal(statusOf(allowedOf(two), one).status, "DIFFER");
  assert.equal(statusOf(allowedOf(one), two).status, "DIFFER");
  assert.equal(statusOf(allowedOf(two), two).status, "MATCH");
  assert.equal(
    statusOf(allowedOf(two, DIFF), two).observed[0],
    "r1: diff+filter [1:1:0:0:0 2:1:0:0:0]",
  );
});

test("a row only one run finished is compared with that run alone", () => {
  const one = allowedAnswers([
    recording("r1", { [ID]: DIFF }),
    recording("r2", { [ID]: row([add, bnd], { timedOut: true }) }),
  ]);
  assert.deepEqual(Object.keys(one.rows[ID]), ["r1"]);
  const match = compareResumeVariants({ allowed: one, local: recording("l", { [ID]: DIFF }) });
  assert.equal(match.rows[ID].status, "MATCH");
  assert.equal(
    compareResumeVariants({ allowed: one, local: recording("l", { [ID]: REPLAY }) }).rows[ID]
      .status,
    "DIFFER",
  );
});

test("each status carries what production answered, by run, and what the local row answered", () => {
  const either = statusOf(allowedOf(DIFF, REPLAY), DIFF);
  assert.deepEqual(either.observed, ["r1: diff+filter [1:3:0:0:0]", "r2: replay"]);
  assert.equal(either.local, "diff+filter [1:3:0:0:0]");
});

test("a declared divergence is KNOWN_DIVERGENCE with its reason (as a string or an object); an unfinished or missing local row is INDETERMINATE", () => {
  const register = { [ID]: "production replayed in both runs" };
  const known = statusOf(allowedOf(REPLAY), DIFF, register);
  assert.equal(known.status, "KNOWN_DIVERGENCE");
  assert.equal(known.reason, "production replayed in both runs");
  assert.equal(statusOf(allowedOf(REPLAY), DIFF, { [ID]: { reason: "r" } }).reason, "r");
  // The register does not excuse a row that matches, and names only the rows it declares.
  assert.equal(statusOf(allowedOf(DIFF), DIFF, register).status, "MATCH");
  assert.equal(statusOf(allowedOf(REPLAY), DIFF, { other: "x" }).status, "DIFFER");
  assert.equal(
    statusOf(allowedOf(DIFF), row([add, bnd], { timedOut: true })).status,
    "INDETERMINATE",
  );
  const missing = compareResumeVariants({ allowed: allowedOf(DIFF), local: recording("l", {}) });
  assert.equal(missing.rows[ID].status, "INDETERMINATE");
  assert.equal(missing.rows[ID].local, null);
  assert.equal(missing.ok, false, "a row that was not answered is not ok");
  assert.match(renderComparison(missing), /\| INDETERMINATE \| .* \| - \|/);
});

test("the report is ok only with no DIFFER and no INDETERMINATE, and lists the local rows production was never asked", () => {
  const allowed = allowedOf(DIFF, REPLAY);
  const ok = compareResumeVariants({ allowed, local: recording("l", { [ID]: DIFF }) });
  assert.equal(ok.ok, true);
  assert.deepEqual(ok.summary, { MATCH_EITHER: 1 });
  const bad = compareResumeVariants({ allowed, local: recording("l", { [ID]: BLOOM }) });
  assert.equal(bad.ok, false);
  const extra = compareResumeVariants({
    allowed,
    local: recording("l", {
      [ID]: DIFF,
      "native/resume-grid-g0/k9": DIFF,
      "native/resume-grid-g0/first": DIFF,
    }),
  });
  assert.deepEqual(extra.localRowsNotObserved, ["native/resume-grid-g0/k9"]);
  const declared = compareResumeVariants({
    allowed: allowedOf(REPLAY),
    local: recording("l", { [ID]: DIFF }),
    divergences: { [ID]: "x" },
  });
  assert.equal(declared.ok, true);
  assert.deepEqual(declared.summary, { KNOWN_DIVERGENCE: 1 });
});

test("renderComparison prints one line per row and the verdict", () => {
  const report = compareResumeVariants({
    allowed: allowedOf(DIFF, REPLAY),
    local: recording("l", { [ID]: DIFF }),
  });
  assert.equal(
    renderComparison(report),
    [
      "| row | status | production | local |",
      "|---|---|---|---|",
      "| grid-g0/k1 | MATCH_EITHER | r1: diff+filter [1:3:0:0:0]; r2: replay | diff+filter [1:3:0:0:0] |",
      "",
      '{"MATCH_EITHER":1}',
      "OK",
    ].join("\n"),
  );
});

const FIXTURE = new URL("../fixtures/fs-listen/l1b-production-answers.json", import.meta.url);
const REGISTER = new URL("../fixtures/fs-listen/l1b-divergences-strict.json", import.meta.url);

test("the committed answers of the two L1b production runs: 31 variant rows, the same two runs, and exactly the seven rows on which they differed", () => {
  const fixture = JSON.parse(readFileSync(FIXTURE, "utf8"));
  assert.deepEqual(fixture.runs, ["nmuv70w0y", "nmuv8dk6e"]);
  assert.equal(Object.keys(fixture.rows).length, 31);
  for (const [id, byRun] of Object.entries(fixture.rows))
    assert.deepEqual(Object.keys(byRun), fixture.runs, id);
  const differing = Object.entries(fixture.rows)
    .filter(([, byRun]) => {
      const [x, y] = fixture.runs.map((run) => byRun[run]);
      return x.kind !== y.kind || x.filters.join() !== y.filters.join();
    })
    .map(([id]) => id.replace("native/resume-", ""))
    .toSorted();
  assert.deepEqual(differing, [
    "grid-gc/k1",
    "grid-gc/k1-expected",
    "grid-gc/k1-repeat",
    "grid-tc/k0",
    "grid-tc/k1",
    "kinds/enter",
    "kinds/modify",
  ]);
  // The facts of the reading: expected-count diffs carry the bloom 14/12/5 in both runs, and the
  // one-commit leave and delete are replays in both.
  for (const id of [
    "grid-g0/k2-expected",
    "grid-g0/k2-wrong",
    "grid-tc/k2-expected",
    "grid-gc/k2-wrong",
  ]) {
    for (const run of fixture.runs)
      assert.deepEqual(
        fixture.rows[`native/resume-${id}`][run],
        { kind: "diff+filter", filters: ["1:3:14:12:5"] },
        id,
      );
  }
  for (const id of ["kinds/leave", "kinds/delete"])
    for (const run of fixture.runs)
      assert.equal(fixture.rows[`native/resume-${id}`][run].kind, "replay", id);
});

test("the strict register names rows of the committed answers, each with a reason that cites both runs", () => {
  const fixture = JSON.parse(readFileSync(FIXTURE, "utf8"));
  const register = JSON.parse(readFileSync(REGISTER, "utf8"));
  assert.deepEqual(Object.keys(register).toSorted(), [
    "native/resume-grid-gc/k0",
    "native/resume-grid-tc/k1-expected",
    "native/resume-grid-tc/k1-repeat",
  ]);
  for (const [id, entry] of Object.entries(register)) {
    assert.ok(id in fixture.rows, id);
    assert.ok(entry.reason.length > 80, id);
    for (const run of fixture.runs) assert.ok(entry.reason.includes(run), `${id} cites ${run}`);
  }
});

const CLI = fileURLToPath(new URL("./fs-listen/resume-compare.mjs", import.meta.url));
const run = (...args) =>
  spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    env: { ...process.env, NODE_OPTIONS: "" },
  });

test("the command builds the answers of two runs and compares a local recording with them", () => {
  const dir = mkdtempSync(join(tmpdir(), "resume-compare-"));
  const write = (name, value) => {
    const file = join(dir, name);
    writeFileSync(file, JSON.stringify(value));
    return file;
  };
  const one = write("one.json", recording("r1", { [ID]: DIFF }));
  const two = write("two.json", recording("r2", { [ID]: REPLAY }));
  const out = join(dir, "allowed.json");
  assert.equal(run("build", one, two, out).status, 0);
  assert.deepEqual(JSON.parse(readFileSync(out, "utf8")), allowedOf(DIFF, REPLAY));
  assert.ok(readFileSync(out, "utf8").startsWith('{\n  "runs": ['), "indented by two");
  assert.ok(readFileSync(out, "utf8").endsWith("}\n"));
  const good = run("compare", out, write("good.json", recording("l", { [ID]: DIFF })));
  assert.equal(good.status, 0, good.stderr);
  assert.match(good.stdout, /MATCH_EITHER/);
  const bad = run("compare", out, write("bad.json", recording("l", { [ID]: BLOOM })));
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /NOT OK/);
  const registered = run(
    "compare",
    write("only-replay.json", allowedOf(REPLAY)),
    write("diff.json", recording("l", { [ID]: DIFF })),
    write("register.json", { [ID]: "r" }),
  );
  assert.equal(registered.status, 0, registered.stdout);
  for (const args of [
    [],
    ["build", one],
    ["compare", out],
    ["other", "a", "b"],
    ["compare", out, "x", "y", "z"],
  ]) {
    const refused = run(...args);
    assert.equal(refused.status, 2, args.join(" "));
    assert.match(refused.stderr, /usage/);
  }
  assert.equal(run("compare", join(dir, "missing.json"), out).status, 2);
});

test("importing the module runs nothing", () => {
  const imported = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", `await import(${JSON.stringify(CLI)})`],
    {
      encoding: "utf8",
      env: { ...process.env, NODE_OPTIONS: "" },
    },
  );
  assert.equal(imported.status, 0, imported.stderr);
  assert.equal(imported.stdout + imported.stderr, "");
});
