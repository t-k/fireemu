import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { loadFixture as loadCommittedFixture } from "./storage-object-compare/run.mjs";
import {
  applyClosure,
  buildEvidence,
  closureEvidenceCommand,
  finalArtifactEvidence,
  inlineJson,
  recordingsFromLedger,
  replaceConditionLines,
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
// A closure file in the style of the real one: expanded header, one line for each condition.
const closureText = (value) =>
  [
    "{",
    '  "parent": "STORAGE-OBJECT",',
    '  "conditions": [',
    value.conditions
      .map(
        (condition, i) =>
          `    ${inlineJson(condition)}${i < value.conditions.length - 1 ? "," : ""}`,
      )
      .join("\n"),
    "  ]",
    "}",
    "",
  ].join("\n");

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
    closure: write("closure.json", closureText(closure())),
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

test("the recordings must be two distinct runs, at one commit across both, whatever the rows around them say", () => {
  for (const runIds of [undefined, null, "ab", [], [RUN1], [RUN1, RUN2, "x"], [RUN1, RUN1]])
    refuses(
      () => recordingsFromLedger(ledgerText(), runIds),
      /two distinct recordings/,
      JSON.stringify(runIds),
    );
  const other = "e".repeat(40);
  const rows = ledgerText().split("\n");
  const atOtherCommit = rows
    .map((line, i) => (i === 2 || i === 3 ? line.replace(RECORDER, other) : line))
    .join("\n");
  refuses(() => recordingsFromLedger(atOtherCommit, [RUN1, RUN2]), /two commits/);
});

test("the binding names the binary and commit, two recordings and a fixture of its own, in these words", () => {
  const build = (overReport, overReceipt, overFixture) =>
    buildEvidence({
      report: overReport ?? report(),
      receipt: overReceipt ?? receipt(),
      fixture: overFixture ?? fixture(),
    });
  const badBinary = { binarySha256: "abc", version: "x", commit: COMMIT };
  const badCommit = { binarySha256: BINARY, version: "x", commit: "abc" };
  refuses(
    () => build(report({ fireemu: badBinary }), receipt({ fireemu: badBinary })),
    /names no binary and commit/,
  );
  refuses(
    () => build(report({ fireemu: badCommit }), receipt({ fireemu: badCommit })),
    /names no binary and commit/,
  );
  refuses(
    () =>
      build(report({ fixtureRunIds: [RUN1] }), receipt(), {
        ...fixture(),
        index: { runIds: [RUN1] },
      }),
    /no two recordings/,
  );
  refuses(
    () => build(report({ fixtureRunIds: undefined }), receipt(), { ...fixture(), index: {} }),
    /no two recordings/,
  );
});

test("a condition needs a compared recipe, whatever its size", () => {
  const single = buildEvidence({
    report: report({
      total: counts(1),
      recipes: [
        {
          recipeId: "storage-object/a",
          ran: true,
          counts: counts(1),
          results: [{ outcome: "MATCH", n: 1 }],
        },
      ],
    }),
    receipt: receipt(),
    fixture: fixture({ "storage-object/a": 1 }),
  }).comparison;
  const base = {
    closure: closure(),
    comparison: single,
    recordings: recordings(),
    comparisonPath: "p",
    hold: ["STORAGE-OBJECT/two"],
  };
  const applied = applyClosure(base);
  assert.deepEqual(applied.conditions[0].evidence.rows, { MATCH: 1 });
  const empty = closure();
  empty.conditions[0].recipeIds = [];
  refuses(() => applyClosure({ ...base, closure: empty }), /no recipe was compared/);
});

test("the command line writes the files from a comparison of the committed fixture, and refuses with a message and exit code 1", () => {
  const fixtureDirectory = fileURLToPath(
    new URL("../fixtures/storage-object-production/", import.meta.url),
  );
  const real = loadCommittedFixture(fixtureDirectory);
  const recipes = [...real.recipes.entries()];
  const total = recipes.reduce((sum, [, rows]) => sum + rows.length, 0);
  const realReport = {
    fixtureRunIds: real.index.runIds,
    fixtureIndexSha256: real.indexSha256,
    fireemu: { binarySha256: BINARY, version: "fireemu 0.10.0", commit: COMMIT },
    recorder: { commit: RECORDER, clean: true },
    rehearsalResult: {
      status: "LOCAL_COMPLETE",
      completedRecipes: [26, 0],
      requests: 1,
      exitCode: 0,
    },
    total: counts(total),
    layoutUnjudgedProductionRows: recipes
      .flatMap(([, rows]) => rows)
      .filter((entry) => !Number.isSafeInteger(entry.layout)).length,
    recipes: recipes.map(([recipeId, rows]) => ({
      recipeId,
      ran: true,
      counts: counts(rows.length),
      results: rows.map((entry) => ({ outcome: "MATCH", n: entry.n })),
    })),
  };
  const dir = mkdtempSync(join(tmpdir(), "closure-evidence-cli-"));
  const file = (name, value) => {
    const path = join(dir, name);
    writeFileSync(path, typeof value === "string" ? value : `${JSON.stringify(value)}\n`);
    return path;
  };
  const closureValue = {
    parent: "STORAGE-OBJECT",
    conditions: [
      {
        conditionId: "STORAGE-OBJECT/firebase-simple-upload",
        recipeIds: ["storage-object/firebase/simple-upload"],
        status: "PENDING_CORPUS",
      },
    ],
  };
  const ledger = [RUN1, RUN2].flatMap((runId, i) => [
    JSON.stringify({
      ts: `2026-09-30T23:1${i}:00.000Z`,
      event: "started",
      project: "fireemu-oracle-query",
      runId,
      gitSha: RECORDER,
    }),
    JSON.stringify({
      ts: `2026-09-30T23:2${i}:00.000Z`,
      event: "finished",
      outcome: "recorded",
      project: "fireemu-oracle-query",
      runId,
      gitSha: RECORDER,
    }),
  ]);
  real.index.runIds.forEach((id, i) => {
    ledger[i * 2] = ledger[i * 2].replace([RUN1, RUN2][i], id);
    ledger[i * 2 + 1] = ledger[i * 2 + 1].replace([RUN1, RUN2][i], id);
  });
  const args = (
    out,
    closurePath = file("closure.json", closureValue),
    reportPath = file("report.json", realReport),
  ) => [
    fileURLToPath(new URL("./storage-object-compare/closure-evidence.mjs", import.meta.url)),
    "--report",
    reportPath,
    "--receipt",
    file("receipt.json", {
      fireemu: realReport.fireemu,
      recorder: realReport.recorder,
      fixtureIndexSha256: real.indexSha256,
      result: realReport.rehearsalResult,
    }),
    "--fixture",
    fixtureDirectory,
    "--sandbox-ledger",
    file("ledger.jsonl", `${ledger.join("\n")}\n`),
    "--closure",
    closurePath,
    "--out",
    out,
    "--comparison-path",
    "spec/compatibility/closure/evidence/STORAGE-OBJECT-comparison.json",
  ];
  const out = join(dir, "comparison.json");
  const closurePath = file("closure.json", closureText(closureValue));
  const ok = spawnSync(process.execPath, args(out, closurePath), { encoding: "utf8" });
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(
    ok.stdout,
    new RegExp(`closure evidence: ${total} rows of ${BINARY} written; 1 conditions verified`),
  );
  assert.equal(JSON.parse(readFileSync(out, "utf8")).rows.length, total);
  assert.equal(JSON.parse(readFileSync(closurePath, "utf8")).conditions[0].status, "VERIFIED");
  // A comparison with a divergence gives a message, exit code 1 and no new files.
  const badOut = join(dir, "bad.json");
  const bad = spawnSync(
    process.execPath,
    args(
      badOut,
      undefined,
      file("bad-report.json", { ...realReport, total: counts(total - 1, { DIVERGENCE: 1 }) }),
    ),
    { encoding: "utf8" },
  );
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /not a MATCH of every row/);
  assert.throws(() => readFileSync(badOut, "utf8"), /ENOENT/);
  // A flag without a value, and a word that is not a flag, are refused as bad arguments.
  for (const argv of [["--report"], ["report", "x"]]) {
    const refused = spawnSync(
      process.execPath,
      [
        fileURLToPath(new URL("./storage-object-compare/closure-evidence.mjs", import.meta.url)),
        ...argv,
      ],
      { encoding: "utf8" },
    );
    assert.equal(refused.status, 1);
    assert.match(refused.stderr, /bad argument/);
  }
});

test("a condition is written on one line like the rest of the file, and the other lines stay byte for byte", () => {
  assert.equal(
    inlineJson({ a: "x", b: ["y", "z"], c: { d: 1, e: [] }, f: {}, g: true, h: null }),
    '{ "a": "x", "b": ["y", "z"], "c": { "d": 1, "e": [] }, "f": {}, "g": true, "h": null }',
  );
  assert.equal(inlineJson([]), "[]");
  assert.equal(inlineJson('quote " and \\ and \n'), JSON.stringify('quote " and \\ and \n'));
  // The real closure file is reproduced exactly by its own conditions.
  const path = new URL("../../spec/compatibility/closure/STORAGE-OBJECT.json", import.meta.url);
  const text = readFileSync(path, "utf8");
  assert.equal(replaceConditionLines(text, JSON.parse(text)), text);
  // A changed condition changes its own line only.
  const parsed = JSON.parse(text);
  parsed.conditions[1].note = "changed";
  const lines = text.split("\n");
  const changed = replaceConditionLines(text, parsed).split("\n");
  assert.equal(changed.length, lines.length);
  const differing = changed.map((line, i) => i).filter((i) => changed[i] !== lines[i]);
  assert.equal(differing.length, 1);
  assert.match(changed[differing[0]], /"note": "changed" }[,]?$/);
  assert.ok(
    changed[differing[0]].startsWith(
      '    { "conditionId": "STORAGE-OBJECT/firebase-multipart-upload"',
    ),
  );
  // The last condition has no comma; the others keep theirs.
  parsed.conditions.at(-1).note = "last";
  const last = replaceConditionLines(text, parsed).split("\n");
  assert.match(
    last[lines.findIndex((line) => line.includes('"STORAGE-OBJECT/closure-review"'))],
    /"note": "last" }$/,
  );
  // A closure whose conditions are not each on a line of the file is refused, and so is a condition the file lacks.
  refuses(
    () => replaceConditionLines(text, { conditions: [{ conditionId: "STORAGE-OBJECT/none" }] }),
    /line/i,
  );
  refuses(
    () =>
      replaceConditionLines(
        text.replace('"STORAGE-OBJECT/firebase-delete"', '"STORAGE-OBJECT/firebase-delete" ,\n"x"'),
        JSON.parse(text),
      ),
    /line|style/i,
  );
});

const buildRecord = (over = {}) => ({
  sourceCommit: COMMIT,
  gitStatusOutsideBuildOutput: [],
  cargoVersion: "cargo 1.93.0 (abcdef012 2026-01-01)",
  locked: true,
  binarySha256: BINARY,
  ...over,
});
const gateClosure = () => {
  const value = closure();
  value.conditions[2].recipeIds = ["storage-object/final-artifact"];
  return value;
};
const evidenceFor = () =>
  buildEvidence({ report: report(), receipt: receipt(), fixture: fixture() }).comparison;

test("the final artifact needs a build record of the compared binary: its commit, a clean tree, the cargo version, --locked and the SHA-256", () => {
  const comparison = evidenceFor();
  assert.deepEqual(
    finalArtifactEvidence({ buildRecord: buildRecord(), comparison }),
    buildRecord(),
  );
  const bad = {
    "another binary": buildRecord({ binarySha256: "e".repeat(64) }),
    "another commit": buildRecord({ sourceCommit: "e".repeat(40) }),
    "a dirty tree": buildRecord({ gitStatusOutsideBuildOutput: [" M crates/x.rs"] }),
    "a status that is not a list": buildRecord({ gitStatusOutsideBuildOutput: "" }),
    "a build without --locked": buildRecord({ locked: false }),
    "a locked flag that is not a boolean": buildRecord({ locked: "true" }),
    "no cargo version": buildRecord({ cargoVersion: "" }),
    "a cargo version that is not a string": buildRecord({ cargoVersion: 1 }),
    "a malformed commit": buildRecord({ sourceCommit: "abc" }),
    "a malformed digest": buildRecord({ binarySha256: "abc" }),
    "an extra field": buildRecord({ extra: 1 }),
  };
  for (const [name, record] of Object.entries(bad))
    refuses(
      () => finalArtifactEvidence({ buildRecord: record, comparison }),
      /build record/i,
      name,
    );
  // The refusal names what is wrong, so a malformed commit or digest is not caught by the comparison with the binary.
  for (const sourceCommit of ["abc", 5, null, "E".repeat(40)])
    refuses(
      () => finalArtifactEvidence({ buildRecord: buildRecord({ sourceCommit }), comparison }),
      /no source commit/,
    );
  for (const binarySha256 of ["abc", 5, null, "E".repeat(64)])
    refuses(
      () => finalArtifactEvidence({ buildRecord: buildRecord({ binarySha256 }), comparison }),
      /no binary digest/,
    );
  const missing = buildRecord();
  delete missing.cargoVersion;
  refuses(() => finalArtifactEvidence({ buildRecord: missing, comparison }), /build record/i);
  for (const record of [null, [], "text", 5])
    refuses(() => finalArtifactEvidence({ buildRecord: record, comparison }), /build record/i);
});

test("the final artifact condition gets its evidence only with a build record, and the review condition never does", () => {
  const comparison = evidenceFor();
  const base = {
    closure: gateClosure(),
    comparison,
    recordings: recordings(),
    comparisonPath: "cp",
  };
  const without = applyClosure(base);
  assert.equal(without.conditions[2].status, "PENDING_CORPUS");
  assert.equal(Object.hasOwn(without.conditions[2], "evidence"), false);
  const withRecord = applyClosure({
    ...base,
    finalArtifact: {
      buildRecord: buildRecord(),
      buildRecordPath: "bp",
      buildRecordSha256: "a".repeat(64),
    },
  });
  const gate = withRecord.conditions[2];
  assert.equal(gate.status, "VERIFIED");
  assert.deepEqual(gate.evidence, {
    productionRecordings: recordings(),
    finalArtifactSha256: BINARY,
    sourceCommit: COMMIT,
    comparisonPath: "cp",
    rows: { MATCH: 5 },
    buildRecordPath: "bp",
    buildRecordSha256: "a".repeat(64),
  });
  assert.equal(withRecord.conditions[3].status, "PENDING_REVIEW");
  assert.equal(Object.hasOwn(withRecord.conditions[3], "evidence"), false);
  refuses(
    () =>
      applyClosure({
        ...base,
        finalArtifact: {
          buildRecord: buildRecord({ binarySha256: "e".repeat(64) }),
          buildRecordPath: "bp",
          buildRecordSha256: "a".repeat(64),
        },
      }),
    /build record/i,
  );
  refuses(
    () =>
      applyClosure({
        ...base,
        finalArtifact: {
          buildRecord: buildRecord(),
          buildRecordPath: "",
          buildRecordSha256: "a".repeat(64),
        },
      }),
    /build record path/i,
  );
  refuses(
    () =>
      applyClosure({
        ...base,
        finalArtifact: {
          buildRecord: buildRecord(),
          buildRecordPath: "bp",
          buildRecordSha256: "abc",
        },
      }),
    /digest/i,
  );
  // The gate is held like any other condition.
  const held = applyClosure({
    ...base,
    hold: ["STORAGE-OBJECT/final-artifact-regression"],
    finalArtifact: {
      buildRecord: buildRecord(),
      buildRecordPath: "bp",
      buildRecordSha256: "a".repeat(64),
    },
  });
  assert.equal(held.conditions[2].status, "PENDING_CORPUS");
  // A closure without a final artifact condition cannot take a build record.
  const noGate = closure();
  noGate.conditions = noGate.conditions.filter(
    (c) => !c.conditionId.endsWith("/final-artifact-regression"),
  );
  refuses(
    () =>
      applyClosure({
        ...base,
        closure: noGate,
        finalArtifact: {
          buildRecord: buildRecord(),
          buildRecordPath: "bp",
          buildRecordSha256: "a".repeat(64),
        },
      }),
    /final artifact condition/i,
  );
});

test("the command copies the build record next to the evidence, pins its digest and sets the gate, or writes nothing", () => {
  const dir = mkdtempSync(join(tmpdir(), "closure-evidence-gate-"));
  const write = (name, value) => {
    const path = join(dir, name);
    writeFileSync(path, typeof value === "string" ? value : `${JSON.stringify(value)}\n`);
    return path;
  };
  const options = (record, extra = {}) => ({
    report: write("report.json", report()),
    receipt: write("receipt.json", receipt()),
    fixture: dir,
    "sandbox-ledger": write("ledger.jsonl", `${ledgerText()}\n`),
    closure: write("closure.json", closureText(gateClosure())),
    out: join(dir, "comparison.json"),
    "comparison-path": "cp",
    "build-record": write("build.json", record),
    "build-record-out": join(dir, "nested", "deeper", "build-copy.json"),
    "build-record-path": "bp",
    ...extra,
  });
  const loadFixture = () => fixture();
  const good = options(buildRecord());
  closureEvidenceCommand(good, { loadFixture, log: () => {} });
  const copy = readFileSync(good["build-record-out"], "utf8");
  assert.equal(copy, readFileSync(good["build-record"], "utf8"));
  const written = JSON.parse(readFileSync(good.closure, "utf8"));
  assert.equal(written.conditions[2].status, "VERIFIED");
  assert.equal(written.conditions[2].evidence.buildRecordPath, "bp");
  assert.equal(
    written.conditions[2].evidence.buildRecordSha256,
    createHash("sha256").update(copy).digest("hex"),
  );
  // Without the option the gate stays as it was.
  const plain = options(buildRecord(), {
    "build-record": undefined,
    "build-record-out": undefined,
    "build-record-path": undefined,
  });
  closureEvidenceCommand(plain, { loadFixture, log: () => {} });
  assert.equal(
    JSON.parse(readFileSync(plain.closure, "utf8")).conditions[2].status,
    "PENDING_CORPUS",
  );
  // The three options go together.
  for (const name of ["build-record-out", "build-record-path"])
    refuses(
      () =>
        closureEvidenceCommand(options(buildRecord(), { [name]: undefined }), {
          loadFixture,
          log: () => {},
        }),
      new RegExp(name),
    );
  // A record of another binary writes no file at all.
  const bad = options(buildRecord({ binarySha256: "e".repeat(64) }), {
    out: join(dir, "bad-comparison.json"),
    "build-record-out": join(dir, "bad-build.json"),
  });
  refuses(() => closureEvidenceCommand(bad, { loadFixture, log: () => {} }), /build record/i);
  for (const path of [bad.out, bad["build-record-out"]])
    assert.throws(() => readFileSync(path, "utf8"), /ENOENT/);
  assert.equal(
    JSON.parse(readFileSync(bad.closure, "utf8")).conditions[2].status,
    "PENDING_CORPUS",
  );
});
