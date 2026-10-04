import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  applyClosure,
  buildEvidence,
  closureEvidenceCommand,
  recordingsFromLedger,
} from "./storage-object-compare/closure-evidence.mjs";

const RUN1 = "056c7ca3a8c6daa38e0a";
const RUN2 = "202dd40ac90863add783";
const BINARY = "a".repeat(64);
const INDEX = "b".repeat(64);
const COMMIT = "c".repeat(40);
const RECORDER = "d".repeat(40);

const fixture = (recipes = { "storage-object/a": 3, "storage-object/b/c": 2 }, layout = {}) => ({
  index: { runIds: [RUN1, RUN2] },
  indexSha256: INDEX,
  recipes: new Map(
    Object.entries(recipes).map(([id, rows]) => [
      id,
      Array.from({ length: rows }, (_, i) => ({
        n: i + 1,
        layout: Object.hasOwn(layout, `${id}#${i + 1}`) ? layout[`${id}#${i + 1}`] : 0,
      })),
    ]),
  ),
});
const counts = (match, over = {}) => ({
  MATCH: match,
  DIVERGENCE: 0,
  LOCAL_UNIMPLEMENTED: 0,
  TAINTED: 0,
  ONLY_PRODUCTION: 0,
  ONLY_LOCAL: 0,
  NOT_RUN: 0,
  ...over,
});
const report = (over = {}) => ({
  fixtureRunIds: [RUN1, RUN2],
  fixtureIndexSha256: INDEX,
  fireemu: { binarySha256: BINARY, version: "fireemu 0.10.0", commit: COMMIT },
  recorder: { commit: RECORDER, clean: true },
  rehearsalResult: { status: "LOCAL_COMPLETE", completedRecipes: [2, 0], requests: 9, exitCode: 0 },
  total: counts(5),
  layoutUnjudgedProductionRows: 0,
  recipes: [
    {
      recipeId: "storage-object/a",
      ran: true,
      counts: counts(3),
      results: [1, 2, 3].map((n) => ({ outcome: "MATCH", n })),
    },
    {
      recipeId: "storage-object/b/c",
      ran: true,
      counts: counts(2),
      results: [1, 2].map((n) => ({ outcome: "MATCH", n })),
    },
  ],
  ...over,
});
const receipt = (over = {}) => ({
  fireemu: { binarySha256: BINARY, version: "fireemu 0.10.0", commit: COMMIT },
  recorder: { commit: RECORDER, clean: true },
  fixtureIndexSha256: INDEX,
  result: { status: "LOCAL_COMPLETE", completedRecipes: [2, 0], requests: 9, exitCode: 0 },
  ...over,
});
const row = (event, runId, extra = {}) =>
  JSON.stringify({
    ts: event === "started" ? "2026-09-30T23:14:35.996Z" : "2026-09-30T23:28:01.825Z",
    event,
    taskId: "STORAGE-OBJECT-SANDBOX",
    project: "fireemu-oracle-query",
    runId,
    gitSha: RECORDER,
    ...(event === "finished" ? { outcome: "recorded" } : {}),
    ...extra,
  });
const ledgerText = () =>
  [
    row("started", RUN1, { ts: "2026-09-30T23:14:35.996Z" }),
    row("finished", RUN1),
    row("started", RUN2, { ts: "2026-09-30T23:58:33.198Z" }),
    row("finished", RUN2, { ts: "2026-10-01T00:12:45.860Z" }),
    JSON.stringify({ event: "started", runId: "unrelated" }),
  ].join("\n");
const recordings = () => recordingsFromLedger(ledgerText(), [RUN1, RUN2]);
const closure = () => ({
  parent: "STORAGE-OBJECT",
  parentStatus: "IMPLEMENTING",
  closureReview: { decision: "PENDING_REVIEW" },
  conditions: [
    {
      conditionId: "STORAGE-OBJECT/one",
      recipeIds: ["storage-object/a"],
      status: "PENDING_CORPUS",
      note: "kept",
    },
    {
      conditionId: "STORAGE-OBJECT/two",
      recipeIds: ["storage-object/b/c"],
      status: "PENDING_CORPUS",
    },
    {
      conditionId: "STORAGE-OBJECT/final-artifact-regression",
      recipeIds: ["storage-object/final-artifact"],
      status: "PENDING_CORPUS",
    },
    {
      conditionId: "STORAGE-OBJECT/closure-review",
      recipeIds: ["storage-object/closure-review"],
      status: "PENDING_REVIEW",
    },
  ],
});
const refuses = (fn, pattern) => assert.throws(fn, pattern);

test("the recordings come from the sandbox ledger: one started and one recorded finished row for each run, in the query project, at one commit", () => {
  assert.deepEqual(recordings(), [
    {
      recordedAt: "2026-09-30T23:14:35.996Z",
      gitSha: RECORDER,
      runId: RUN1,
      project: "fireemu-oracle-query",
    },
    {
      recordedAt: "2026-09-30T23:58:33.198Z",
      gitSha: RECORDER,
      runId: RUN2,
      project: "fireemu-oracle-query",
    },
  ]);
  const rows = ledgerText().split("\n");
  const without = (index) => rows.filter((_, i) => i !== index).join("\n");
  const swap = (index, text) => rows.map((line, i) => (i === index ? text : line)).join("\n");
  const cases = {
    "no started row": without(0),
    "no finished row": without(1),
    "a duplicate started row": `${ledgerText()}\n${rows[0]}`,
    "a duplicate finished row": `${ledgerText()}\n${rows[1]}`,
    "an outcome that is not recorded": swap(
      1,
      row("finished", RUN1, { outcome: "needs-recovery" }),
    ),
    "another project": swap(0, row("started", RUN1, { project: "fireemu-oracle-sbx" })),
    "another commit": swap(2, row("started", RUN2, { gitSha: "e".repeat(40) })),
    "a malformed commit": swap(0, row("started", RUN1, { gitSha: "abc" })),
    "a malformed time": swap(0, row("started", RUN1, { ts: "yesterday" })),
    "not JSON": `${ledgerText()}\n{broken`,
  };
  for (const [name, text] of Object.entries(cases))
    refuses(() => recordingsFromLedger(text, [RUN1, RUN2]), /ledger|recording|run/i, name);
  refuses(() => recordingsFromLedger(ledgerText(), [RUN1]), /two/i);
  refuses(() => recordingsFromLedger(ledgerText(), [RUN1, RUN1]), /two|distinct/i);
});

test("the comparison evidence lists every compared row, in the fixture's order, bound to the binary, the fixture and the recorder", () => {
  const { comparison } = buildEvidence({
    report: report(),
    receipt: receipt(),
    fixture: fixture(),
  });
  assert.deepEqual(comparison, {
    kind: "storage-object-comparison-v1",
    artifactSha256: BINARY,
    sourceCommit: COMMIT,
    fixtureSha256: INDEX,
    recorderCommit: RECORDER,
    summary: { MATCH: 5 },
    layoutUnjudged: [],
    rows: [
      { row: "storage-object/a#1", status: "MATCH" },
      { row: "storage-object/a#2", status: "MATCH" },
      { row: "storage-object/a#3", status: "MATCH" },
      { row: "storage-object/b/c#1", status: "MATCH" },
      { row: "storage-object/b/c#2", status: "MATCH" },
    ],
  });
  // The rows whose layout the recorder could not keep are named, not hidden.
  const unjudged = buildEvidence({
    report: report({ layoutUnjudgedProductionRows: 2 }),
    receipt: receipt(),
    fixture: fixture(undefined, { "storage-object/a#2": null, "storage-object/b/c#1": null }),
  }).comparison;
  assert.deepEqual(unjudged.layoutUnjudged, ["storage-object/a#2", "storage-object/b/c#1"]);
  // Same input, same bytes.
  assert.deepEqual(
    buildEvidence({ report: report(), receipt: receipt(), fixture: fixture() }),
    buildEvidence({ report: report(), receipt: receipt(), fixture: fixture() }),
  );
});

test("evidence is refused for anything but a complete comparison of every row", () => {
  const build = (overReport, overReceipt, overFixture) =>
    buildEvidence({
      report: overReport ?? report(),
      receipt: overReceipt ?? receipt(),
      fixture: overFixture ?? fixture(),
    });
  const recipe = (index, patch) => (r) => ({
    ...r,
    recipes: r.recipes.map((entry, i) => (i === index ? { ...entry, ...patch } : entry)),
  });
  const cases = {
    "a divergence": report({ total: counts(4, { DIVERGENCE: 1 }) }),
    "a tainted row": report({ total: counts(4, { TAINTED: 1 }) }),
    "a not-run row": report({ total: counts(4, { NOT_RUN: 1 }) }),
    "an unimplemented row": report({ total: counts(4, { LOCAL_UNIMPLEMENTED: 1 }) }),
    "an exchange only production has": report({ total: counts(5, { ONLY_PRODUCTION: 1 }) }),
    "an exchange only the local run has": report({ total: counts(5, { ONLY_LOCAL: 1 }) }),
    "a total that is not the fixture's rows": report({ total: counts(6) }),
    "a recipe that did not run": recipe(0, { ran: false })(report()),
    "a recipe that is missing": { ...report(), recipes: report().recipes.slice(0, 1) },
    "a recipe the fixture does not have": {
      ...report(),
      recipes: [
        ...report().recipes,
        {
          recipeId: "storage-object/zzz",
          ran: true,
          counts: counts(1),
          results: [{ outcome: "MATCH", n: 1 }],
        },
      ],
    },
    "a result that is not a match": recipe(0, {
      results: [
        { outcome: "DIVERGENCE", n: 1 },
        { outcome: "MATCH", n: 2 },
        { outcome: "MATCH", n: 3 },
      ],
    })(report()),
    "a row that has no result": recipe(0, {
      results: [
        { outcome: "MATCH", n: 1 },
        { outcome: "MATCH", n: 2 },
      ],
    })(report()),
    "a result for a row the fixture lacks": recipe(0, {
      results: [1, 2, 3, 4].map((n) => ({ outcome: "MATCH", n })),
    })(report()),
    "a repeated result": recipe(0, { results: [1, 1, 2, 3].map((n) => ({ outcome: "MATCH", n })) })(
      report(),
    ),
    "recipe counts that disagree": recipe(0, { counts: counts(2) })(report()),
    "a report of another fixture": report({ fixtureIndexSha256: "e".repeat(64) }),
    "a report of other runs": report({ fixtureRunIds: [RUN1, "f".repeat(20)] }),
    "an unfinished rehearsal": report({
      rehearsalResult: { status: "LOCAL_INCOMPLETE", exitCode: 0 },
    }),
    "a rehearsal that exited with an error": report({
      rehearsalResult: { status: "LOCAL_COMPLETE", exitCode: 1 },
    }),
    "a recorder that is not clean": report({ recorder: { commit: RECORDER, clean: false } }),
    "a malformed binary digest": report({
      fireemu: { binarySha256: "abc", version: "x", commit: COMMIT },
    }),
    "a malformed fireemu commit": report({
      fireemu: { binarySha256: BINARY, version: "x", commit: "abc" },
    }),
    "a layout count that disagrees with the fixture": report({ layoutUnjudgedProductionRows: 1 }),
  };
  for (const [name, bad] of Object.entries(cases)) refuses(() => build(bad), /./, name);
  const receipts = {
    "another binary": receipt({
      fireemu: { binarySha256: "e".repeat(64), version: "x", commit: COMMIT },
    }),
    "another commit": receipt({
      fireemu: { binarySha256: BINARY, version: "x", commit: "e".repeat(40) },
    }),
    "another fixture": receipt({ fixtureIndexSha256: "e".repeat(64) }),
    "another recorder": receipt({ recorder: { commit: "e".repeat(40), clean: true } }),
    "an unfinished rehearsal": receipt({ result: { status: "LOCAL_INCOMPLETE", exitCode: 0 } }),
    "an error exit": receipt({ result: { status: "LOCAL_COMPLETE", exitCode: 2 } }),
  };
  for (const [name, bad] of Object.entries(receipts))
    refuses(() => build(undefined, bad), /./, name);
  refuses(
    () => build(undefined, undefined, { ...fixture(), indexSha256: "e".repeat(64) }),
    /./,
    "a fixture of another digest",
  );
  refuses(
    () => build(undefined, undefined, { ...fixture(), index: { runIds: [RUN1] } }),
    /./,
    "a fixture of one run",
  );
});

test("the closure takes the evidence for the conditions whose recipes were compared, and nothing else", () => {
  const { comparison } = buildEvidence({
    report: report(),
    receipt: receipt(),
    fixture: fixture(),
  });
  const applied = applyClosure({
    closure: closure(),
    comparison,
    recordings: recordings(),
    comparisonPath: "spec/compatibility/closure/evidence/STORAGE-OBJECT-comparison.json",
  });
  const [one, two, finalArtifact, review] = applied.conditions;
  assert.equal(one.status, "VERIFIED");
  assert.equal(one.note, "kept", "an existing note stays");
  assert.deepEqual(one.evidence, {
    productionRecordings: recordings(),
    finalArtifactSha256: BINARY,
    sourceCommit: COMMIT,
    comparisonPath: "spec/compatibility/closure/evidence/STORAGE-OBJECT-comparison.json",
    rows: { MATCH: 3 },
  });
  assert.deepEqual(two.evidence.rows, { MATCH: 2 });
  assert.equal(finalArtifact.status, "PENDING_CORPUS");
  assert.equal(Object.hasOwn(finalArtifact, "evidence"), false);
  assert.equal(review.status, "PENDING_REVIEW");
  assert.equal(applied.parentStatus, "IMPLEMENTING");
  assert.deepEqual(applied.closureReview, { decision: "PENDING_REVIEW" });
  // The input is not changed, and applying twice is the same as once.
  assert.equal(closure().conditions[0].status, "PENDING_CORPUS");
  const again = applyClosure({
    closure: applied,
    comparison,
    recordings: recordings(),
    comparisonPath: one.evidence.comparisonPath,
  });
  assert.deepEqual(again, applied);
});

test("a held condition keeps its status, and a binary of another run replaces the evidence of every condition together", () => {
  const first = buildEvidence({
    report: report(),
    receipt: receipt(),
    fixture: fixture(),
  }).comparison;
  const held = applyClosure({
    closure: closure(),
    comparison: first,
    recordings: recordings(),
    comparisonPath: "p",
    hold: ["STORAGE-OBJECT/two"],
  });
  assert.equal(held.conditions[0].status, "VERIFIED");
  assert.equal(held.conditions[1].status, "PENDING_CORPUS");
  assert.equal(Object.hasOwn(held.conditions[1], "evidence"), false);
  refuses(
    () =>
      applyClosure({
        closure: closure(),
        comparison: first,
        recordings: recordings(),
        comparisonPath: "p",
        hold: ["STORAGE-OBJECT/nope"],
      }),
    /hold/i,
  );
  const other = buildEvidence({
    report: report({
      fireemu: { binarySha256: "9".repeat(64), version: "fireemu 0.10.0", commit: "8".repeat(40) },
    }),
    receipt: receipt({
      fireemu: { binarySha256: "9".repeat(64), version: "fireemu 0.10.0", commit: "8".repeat(40) },
    }),
    fixture: fixture(),
  }).comparison;
  const moved = applyClosure({
    closure: held,
    comparison: other,
    recordings: recordings(),
    comparisonPath: "p",
  });
  assert.equal(moved.conditions[0].evidence.finalArtifactSha256, "9".repeat(64));
  assert.equal(moved.conditions[1].evidence.finalArtifactSha256, "9".repeat(64));
  assert.equal(
    moved.conditions[1].status,
    "VERIFIED",
    "a held condition is only held for the run that names it",
  );
});

test("a closure whose recipe was not compared, a malformed path or malformed recordings are refused", () => {
  const { comparison } = buildEvidence({
    report: report(),
    receipt: receipt(),
    fixture: fixture(),
  });
  const base = { closure: closure(), comparison, recordings: recordings(), comparisonPath: "p" };
  refuses(
    () =>
      applyClosure({
        ...base,
        comparison: {
          ...comparison,
          rows: comparison.rows.filter((r) => !r.row.startsWith("storage-object/b/c")),
        },
      }),
    /compared/i,
  );
  refuses(
    () =>
      applyClosure({
        ...base,
        comparison: {
          ...comparison,
          rows: comparison.rows.map((r, i) =>
            i === 0 ? Object.assign({}, r, { status: "DIVERGENCE" }) : r,
          ),
        },
      }),
    /MATCH|compared/i,
  );
  refuses(() => applyClosure({ ...base, recordings: [] }), /recording/i);
  refuses(() => applyClosure({ ...base, recordings: recordings().slice(0, 1) }), /recording/i);
  refuses(() => applyClosure({ ...base, comparisonPath: "" }), /path/i);
  refuses(() => applyClosure({ ...base, closure: { ...closure(), conditions: [] } }), /condition/i);
});

test("the command writes the evidence and the closure from the files, and writes nothing when the comparison is incomplete", () => {
  const dir = mkdtempSync(join(tmpdir(), "closure-evidence-"));
  const write = (name, value) => {
    const path = join(dir, name);
    mkdirSync(join(path, ".."), { recursive: true });
    writeFileSync(path, typeof value === "string" ? value : `${JSON.stringify(value)}\n`);
    return path;
  };
  const options = (reportValue = report(), extra = {}) => ({
    report: write("report.json", reportValue),
    receipt: write("receipt.json", receipt()),
    fixture: dir,
    "sandbox-ledger": write("ledger.jsonl", `${ledgerText()}\n`),
    closure: write("closure.json", closure()),
    out: join(dir, "evidence", "comparison.json"),
    "comparison-path": "spec/compatibility/closure/evidence/STORAGE-OBJECT-comparison.json",
    ...extra,
  });
  const loadFixture = () => fixture();
  const logged = [];
  const good = options();
  closureEvidenceCommand(good, { loadFixture, log: (line) => logged.push(line) });
  const evidence = JSON.parse(readFileSync(good.out, "utf8"));
  assert.equal(evidence.summary.MATCH, 5);
  assert.equal(evidence.rows.length, 5);
  const written = JSON.parse(readFileSync(good.closure, "utf8"));
  assert.equal(written.conditions[0].status, "VERIFIED");
  assert.equal(written.conditions[0].evidence.comparisonPath, good["comparison-path"]);
  assert.match(logged.join("\n"), /5 rows/);
  // Running again gives the same bytes.
  const before = [readFileSync(good.out, "utf8"), readFileSync(good.closure, "utf8")];
  closureEvidenceCommand(good, { loadFixture, log: () => {} });
  assert.deepEqual([readFileSync(good.out, "utf8"), readFileSync(good.closure, "utf8")], before);
  // A held condition is named on the command line.
  const heldOptions = options(report(), { hold: "STORAGE-OBJECT/two" });
  closureEvidenceCommand(heldOptions, { loadFixture, log: () => {} });
  assert.equal(
    JSON.parse(readFileSync(heldOptions.closure, "utf8")).conditions[1].status,
    "PENDING_CORPUS",
  );
  // An incomplete comparison writes neither file.
  const bad = options(report({ total: counts(4, { DIVERGENCE: 1 }) }), {
    out: join(dir, "evidence", "bad.json"),
  });
  refuses(() => closureEvidenceCommand(bad, { loadFixture, log: () => {} }), /./);
  assert.throws(() => readFileSync(bad.out, "utf8"), /ENOENT/);
  assert.equal(
    JSON.parse(readFileSync(bad.closure, "utf8")).conditions[0].status,
    "PENDING_CORPUS",
  );
  for (const name of [
    "report",
    "receipt",
    "fixture",
    "sandbox-ledger",
    "closure",
    "out",
    "comparison-path",
  ])
    refuses(
      () =>
        closureEvidenceCommand({ ...options(), [name]: undefined }, { loadFixture, log: () => {} }),
      new RegExp(name),
    );
});
