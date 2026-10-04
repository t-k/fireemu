// The closure-evidence generator (functions-events/compare/closure-evidence.mjs): a synthetic comparison made from the
// real closure inventory, synthetic runs, builds and receipts, and the v4 run (0 passes) as the real refusal.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  applyClosure,
  buildReport,
  checkBuildRecord,
  checkComparison,
  checkLedger,
  checkWorkspaceReceipt,
  closureEvidenceCommand,
  expectedRows,
  gateRows,
  mapConditions,
  recordingsFromRun,
  reportText,
} from "./functions-events/compare/closure-evidence.mjs";

const repo = (path) => fileURLToPath(new URL(`../../${path}`, import.meta.url));
const CLOSURE_PATH = "spec/compatibility/closure/FUNCTIONS-EVENTS.json";
const CORPUS_PATH = "conformance/functions-events/corpus.json";
const closureText = readFileSync(repo(CLOSURE_PATH), "utf8");
const corpusText = readFileSync(repo(CORPUS_PATH), "utf8");
const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const closure = () => JSON.parse(closureText);
const ART = "d".repeat(64);
const COMMIT = "a".repeat(40);
const isGate = (c) =>
  ["final-artifact-regression", "closure-review"].some((g) => c.conditionId.endsWith(`/${g}`));
const business = () => closure().conditions.filter((c) => !isGate(c));

/** A comparison with every row the closure expects, MATCH unless `over` says otherwise (row id -> { status, reasons }). */
function comparisonOf({
  over = {},
  drop = [],
  extra = [],
  artifact = ART,
  execution = "FUNCTIONS-EVENTS formal record (FE v5) vs local sessions x",
} = {}) {
  const rows = [];
  for (const condition of business())
    for (const id of expectedRows(condition)) {
      if (drop.includes(id)) continue;
      const [, name, version] = id.split("#");
      rows.push({
        row: id,
        caseId: `${condition.conditionId}#${name}#${version}`,
        conditionId: condition.conditionId,
        case: name,
        generation: Number(version.slice(1)),
        status: "MATCH",
        reasons: [],
        ...over[id],
      });
    }
  rows.push(...extra);
  const count = (s) => rows.filter((r) => r.status === s).length;
  return {
    kind: "functions-events-comparison",
    artifactSha256: artifact,
    execution,
    rows,
    summary: {
      rows: rows.length,
      match: count("MATCH"),
      diff: count("DIFF"),
      incomplete: count("INCOMPLETE"),
    },
  };
}
const runOf = (over = {}) => ({
  kind: "functions-events-production-run",
  project: "fireemu-oracle-events",
  corpusDigest: sha256(corpusText),
  passes: [
    {
      pass: 1,
      startedAt: "2026-10-05T10:00:00.000Z",
      endedAt: "2026-10-05T10:37:00.000Z",
      operations: [{}],
    },
    {
      pass: 2,
      startedAt: "2026-10-05T10:38:00.000Z",
      endedAt: "2026-10-05T11:15:00.000Z",
      operations: [{}],
    },
  ],
  frames: [{}],
  stops: [],
  cleanup: { verified: true },
  ...over,
});
const buildOf = (over = {}) => ({
  sourceCommit: COMMIT,
  gitStatusOutsideBuildOutput: [],
  cargoVersion: "cargo 1.94.0 (85eff7c80 2026-01-15)",
  locked: true,
  binarySha256: ART,
  ...over,
});
const receiptOf = (over = {}) => ({
  sourceCommit: COMMIT,
  binarySha256: ART,
  command: "cargo nextest run --workspace --profile pr",
  exitCode: 0,
  tests: { passed: 4321, failed: 0 },
  ...over,
});
const asRefusal = (fn, pattern) => assert.throws(fn, pattern);

/** The assertions of functions-events-closure.test.mjs for a VERIFIED condition, applied to a closure and its evidence file. */
function assertClosureConsistent(next, evidence) {
  const label = (c) => c.conditionId;
  for (const condition of next.conditions) {
    if (!["PENDING_CORPUS", "PENDING_SCOPE", "PENDING_REVIEW"].includes(condition.status))
      assert.ok(
        ["PRODUCTION_RECORDED", "MISMATCH", "VERIFIED"].includes(condition.status),
        label(condition),
      );
    if (["PENDING_CORPUS", "PENDING_SCOPE", "PENDING_REVIEW"].includes(condition.status))
      assert.equal(
        condition.evidence,
        undefined,
        `${label(condition)}: a pending condition has no evidence`,
      );
    if (condition.status !== "VERIFIED") continue;
    const recordings = condition.evidence.productionRecordings;
    assert.equal(recordings.length, 2);
    assert.notEqual(recordings[0].recordedAt, recordings[1].recordedAt);
    for (const r of recordings) {
      assert.equal(r.project, "fireemu-oracle-events");
      assert.match(r.corpusDigest, /^[0-9a-f]{64}$/);
    }
    assert.equal(recordings[0].corpusDigest, recordings[1].corpusDigest);
    assert.match(condition.evidence.finalArtifactSha256, /^[0-9a-f]{64}$/);
    assert.equal(evidence.artifactSha256, condition.evidence.finalArtifactSha256);
    const rows = evidence.rows.filter(({ row }) =>
      condition.recipeIds.some((recipe) =>
        recipe.endsWith("/")
          ? row.startsWith(recipe)
          : row === recipe || row.startsWith(`${recipe}#`),
      ),
    );
    assert.ok(rows.length > 0, label(condition));
    assert.ok(
      rows.every(({ status }) => status === "MATCH"),
      `${label(condition)}: comparison matches`,
    );
    for (const name of condition.cases)
      for (const generation of condition.generations ?? [null]) {
        const caseRows = rows.filter(
          (row) => row.case === name && (row.generation ?? null) === generation,
        );
        assert.ok(caseRows.length > 0, `${label(condition)}: ${name} ${generation}`);
        assert.ok(caseRows.every(({ status }) => status === "MATCH"));
      }
  }
}

// ---- the closure inventory --------------------------------------------------------------------------

test("the closure has 22 conditions: 20 business ones with generations and the two gates", () => {
  const conditions = closure().conditions;
  assert.equal(conditions.length, 22);
  assert.equal(business().length, 20);
  for (const condition of business()) {
    assert.ok(expectedRows(condition).length >= condition.cases.length, condition.conditionId);
    assert.equal(
      expectedRows(condition).length,
      condition.cases.length * condition.generations.length * condition.recipeIds.length,
    );
  }
  assert.deepEqual(expectedRows({ recipeIds: ["r/a"], cases: ["x", "y"], generations: [1, 2] }), [
    "r/a#x#v1",
    "r/a#x#v2",
    "r/a#y#v1",
    "r/a#y#v2",
  ]);
  assert.deepEqual(expectedRows({ recipeIds: ["r/a"], cases: ["x"] }), []);
  const total = business().reduce((sum, c) => sum + expectedRows(c).length, 0);
  assert.equal(comparisonOf().rows.length, total);
});

// ---- the mapping -------------------------------------------------------------------------------------

test("a comparison whose every row MATCHes verifies all 20 conditions", () => {
  const mapping = mapConditions(closure(), checkComparison(comparisonOf()));
  assert.equal(mapping.length, 20);
  assert.ok(
    mapping.every((entry) => entry.status === "VERIFIED" && entry.match === entry.expected),
  );
  assert.deepEqual(buildReport({ comparison: comparisonOf(), mapping }).conditions, {
    total: 20,
    verified: 20,
    mismatch: 0,
    productionRecorded: 0,
    missing: 0,
  });
});

test("a DIFF row makes its condition MISMATCH with the row and its reasons; an INCOMPLETE row only records the production; others stay VERIFIED", () => {
  const diffId = "functions-events/firestore/create#new-document#v2";
  const incompleteId = "functions-events/pubsub/publish#attributes#v1";
  const comparison = checkComparison(
    comparisonOf({
      over: {
        [diffId]: { status: "DIFF", reasons: ["data.after.updateTime: format differs"] },
        [incompleteId]: { status: "INCOMPLETE", reasons: ["no frame in the window"] },
      },
    }),
  );
  const mapping = mapConditions(closure(), comparison);
  const by = Object.fromEntries(mapping.map((e) => [e.conditionId, e]));
  assert.equal(by["FUNCTIONS-EVENTS/firestore-created"].status, "MISMATCH");
  assert.deepEqual(by["FUNCTIONS-EVENTS/firestore-created"].diffRows, [
    { row: diffId, reasons: ["data.after.updateTime: format differs"] },
  ]);
  assert.equal(by["FUNCTIONS-EVENTS/pubsub-published"].status, "PRODUCTION_RECORDED");
  assert.deepEqual(by["FUNCTIONS-EVENTS/pubsub-published"].incompleteRows, [
    { row: incompleteId, reasons: ["no frame in the window"] },
  ]);
  assert.equal(mapping.filter((e) => e.status === "VERIFIED").length, 18);
  const text = reportText(buildReport({ comparison, mapping }));
  assert.match(text, /MISMATCH FUNCTIONS-EVENTS\/firestore-created: 5\/6 MATCH/);
  assert.match(
    text,
    /DIFF functions-events\/firestore\/create#new-document#v2: data\.after\.updateTime: format differs/,
  );
  assert.match(text, /PRODUCTION_RECORDED FUNCTIONS-EVENTS\/pubsub-published/);
  assert.match(text, /18 VERIFIED, 1 MISMATCH, 1 PRODUCTION_RECORDED, 0 MISSING of 20/);
  // DIFF wins over INCOMPLETE in the same condition
  const both = mapConditions(
    closure(),
    checkComparison(
      comparisonOf({
        over: {
          "functions-events/pubsub/publish#attributes#v1": { status: "INCOMPLETE" },
          "functions-events/pubsub/publish#attributes#v2": { status: "DIFF", reasons: ["x"] },
        },
      }),
    ),
  );
  assert.equal(
    both.find((e) => e.conditionId === "FUNCTIONS-EVENTS/pubsub-published").status,
    "MISMATCH",
  );
});

test("a row the comparison lacks is MISSING; a row of another condition, a stray row and a bad comparison are refusals", () => {
  const dropped = "functions-events/storage/archive#archived-generation#v2";
  const mapping = mapConditions(closure(), checkComparison(comparisonOf({ drop: [dropped] })));
  const entry = mapping.find((e) => e.conditionId === "FUNCTIONS-EVENTS/storage-archived");
  assert.deepEqual([entry.status, entry.missingRows], ["MISSING", [dropped]]);
  assert.match(
    reportText(buildReport({ comparison: comparisonOf({ drop: [dropped] }), mapping })),
    /MISSING functions-events\/storage\/archive#archived-generation#v2/,
  );
  asRefusal(
    () =>
      mapConditions(
        closure(),
        checkComparison(
          comparisonOf({
            over: {
              "functions-events/auth/create#admin-create#v1": {
                conditionId: "FUNCTIONS-EVENTS/auth-deleted",
              },
            },
          }),
        ),
      ),
    /belongs to FUNCTIONS-EVENTS\/auth-deleted/,
  );
  const stray = {
    row: "functions-events/other/thing#x#v1",
    conditionId: "FUNCTIONS-EVENTS/other",
    case: "x",
    generation: 1,
    status: "MATCH",
    reasons: [],
  };
  asRefusal(
    () => mapConditions(closure(), checkComparison(comparisonOf({ extra: [stray] }))),
    /rows the closure does not expect: functions-events\/other\/thing#x#v1/,
  );
  for (const [change, pattern] of [
    [(c) => ({ ...c, kind: "other" }), /not a functions-events-comparison/],
    [(c) => ({ ...c, artifactSha256: "x" }), /no artifact digest/],
    [(c) => ({ ...c, execution: "" }), /no execution label/],
    [(c) => ({ ...c, rows: [] }), /no rows/],
    [
      (c) => ({ ...c, rows: [{ ...c.rows[0], status: "PASS" }, ...c.rows.slice(1)] }),
      /status "PASS"/,
    ],
    [
      (c) => ({ ...c, rows: [{ ...c.rows[0], reasons: undefined }, ...c.rows.slice(1)] }),
      /no reasons list/,
    ],
    [
      (c) => ({
        ...c,
        rows: [c.rows[0], c.rows[0], ...c.rows.slice(1)],
        summary: { ...c.summary, rows: c.rows.length + 1, match: c.summary.match + 1 },
      }),
      /appears twice/,
    ],
    [
      (c) => ({ ...c, summary: { ...c.summary, match: c.summary.match - 1 } }),
      /summary is not its rows' count/,
    ],
    [(c) => ({ ...c, summary: undefined }), /summary is not its rows' count/],
    [() => null, /not a functions-events-comparison/],
  ])
    asRefusal(() => checkComparison(change(comparisonOf())), pattern);
  asRefusal(() => mapConditions({ conditions: [] }, comparisonOf()), /no conditions/);
  asRefusal(
    () =>
      mapConditions(
        { conditions: [{ conditionId: "X/y", recipeIds: ["r"], cases: ["c"] }] },
        comparisonOf(),
      ),
    /no case x generation/,
  );
});

// ---- the run, the build, the workspace, the ledger ---------------------------------------------------

test("two recordings come from a complete run: two passes in order, a verified cleanup, frames, the closure's corpus", () => {
  const recordings = recordingsFromRun(runOf(), { corpusSha256: sha256(corpusText) });
  assert.deepEqual(recordings, [
    {
      recordedAt: "2026-10-05T10:00:00.000Z",
      project: "fireemu-oracle-events",
      corpusDigest: sha256(corpusText),
      pass: 1,
    },
    {
      recordedAt: "2026-10-05T10:38:00.000Z",
      project: "fireemu-oracle-events",
      corpusDigest: sha256(corpusText),
      pass: 2,
    },
  ]);
  const p = (i, over) => (r) => ({
    ...r,
    passes: r.passes.map((pass, k) => (k === i ? { ...pass, ...over } : pass)),
  });
  for (const [change, pattern] of [
    [() => null, /not a production run record/],
    [(r) => ({ ...r, kind: "x" }), /not a production run record/],
    [(r) => ({ ...r, project: "other" }), /not fireemu-oracle-events/],
    [(r) => ({ ...r, corpusDigest: "x" }), /no corpus digest/],
    [(r) => ({ ...r, corpusDigest: "e".repeat(64) }), /another corpus/],
    [(r) => ({ ...r, passes: [] }), /0 passes/],
    [(r) => ({ ...r, passes: [r.passes[0]] }), /1 passes/],
    [(r) => ({ ...r, passes: [...r.passes, r.passes[0]] }), /3 passes/],
    [(r) => ({ ...r, passes: undefined }), /no passes/],
    [
      (r) => ({ ...r, stops: ["the 22 handlers did not become active; the passes were skipped"] }),
      /stopped before it was complete/,
    ],
    [(r) => ({ ...r, stops: undefined }), /stopped before it was complete/],
    [(r) => ({ ...r, cleanup: { verified: false } }), /cleanup is not verified/],
    [(r) => ({ ...r, cleanup: null }), /cleanup is not verified/],
    [(r) => ({ ...r, frames: [] }), /captured no frames/],
    [p(0, { pass: 2 }), /pass 1 is not numbered 1/],
    [p(1, { pass: 1 }), /pass 2 is not numbered 2/],
    [p(0, { startedAt: "soon" }), /pass 1 has no readable times/],
    [p(1, { endedAt: undefined }), /pass 2 has no readable times/],
    [p(0, { endedAt: "2026-10-05T09:00:00.000Z" }), /pass 1 ends before it starts/],
    [p(0, { operations: [] }), /pass 1 has no operations/],
    [p(1, { startedAt: "2026-10-05T10:00:00.000Z" }), /start at the same time|starts before/],
    [p(1, { startedAt: "2026-10-05T10:36:00.000Z" }), /second pass starts before the first ends/],
  ])
    asRefusal(
      () => recordingsFromRun(change(runOf()), { corpusSha256: sha256(corpusText) }),
      pattern,
    );
  assert.equal(recordingsFromRun(runOf()).length, 2, "without a corpus digest to check against");
  assert.equal(
    recordingsFromRun(p(1, { startedAt: "2026-10-05T10:37:00.000Z" })(runOf())).length,
    2,
    "a second pass that starts when the first ends",
  );
});

test("the build record names five keys, a clean tree, --locked and the compared binary", () => {
  const comparison = comparisonOf();
  assert.deepEqual(checkBuildRecord(buildOf(), comparison), buildOf());
  for (const [record, pattern] of [
    [null, /wrong fields/],
    [{ ...buildOf(), extra: 1 }, /wrong fields/],
    [(({ locked: _l, ...rest }) => rest)(buildOf()), /wrong fields/],
    [buildOf({ sourceCommit: "abc" }), /no source commit/],
    [buildOf({ binarySha256: "abc" }), /no binary digest/],
    [buildOf({ gitStatusOutsideBuildOutput: [" M x"] }), /not clean/],
    [buildOf({ gitStatusOutsideBuildOutput: null }), /not clean/],
    [buildOf({ cargoVersion: " " }), /no cargo version/],
    [buildOf({ cargoVersion: 1 }), /no cargo version/],
    [buildOf({ locked: false }), /not built with --locked/],
    [buildOf({ locked: "true" }), /not built with --locked/],
    [buildOf({ binarySha256: "e".repeat(64) }), /another binary/],
  ])
    asRefusal(() => checkBuildRecord(record, comparison), pattern);
});

test("the workspace receipt names the same commit and binary, the nextest command, exit 0 and no failed test", () => {
  assert.deepEqual(checkWorkspaceReceipt(receiptOf(), buildOf()), receiptOf());
  for (const [receipt, pattern] of [
    [null, /not an object/],
    [receiptOf({ sourceCommit: "b".repeat(40) }), /another commit or binary/],
    [receiptOf({ binarySha256: "e".repeat(64) }), /another commit or binary/],
    [receiptOf({ command: "cargo test" }), /did not run cargo nextest/],
    [receiptOf({ exitCode: 1 }), /did not exit 0/],
    [receiptOf({ exitCode: undefined }), /did not exit 0/],
    [receiptOf({ tests: { passed: 10, failed: 1 } }), /failed or no tests/],
    [receiptOf({ tests: { passed: 0, failed: 0 } }), /failed or no tests/],
    [receiptOf({ tests: undefined }), /failed or no tests/],
    [receiptOf({ tests: { passed: "10", failed: 0 } }), /failed or no tests/],
  ])
    asRefusal(() => checkWorkspaceReceipt(receipt, buildOf()), pattern);
});

test("the ledger shows one started, one finished as recorded with the lock freed, one close at the baseline, at one commit", () => {
  const dir = "/runs/functions-events-formal-x";
  const row = (over) =>
    JSON.stringify({
      project: "fireemu-oracle-events",
      runDir: dir,
      gitSha: COMMIT,
      packetSha256: "p".repeat(64),
      ...over,
    });
  const good = [
    row({ event: "started" }),
    row({ event: "finished", outcome: "recorded", lockRetained: false }),
    row({ event: "cleanup-verified", sandboxAtBaseline: true }),
  ];
  assert.deepEqual(checkLedger(good.join("\n"), dir), {
    gitSha: COMMIT,
    packetSha256: "p".repeat(64),
  });
  assert.deepEqual(
    checkLedger(`${row({ runDir: "/other", event: "started" })}\n${good.join("\n")}\n`, dir).gitSha,
    COMMIT,
    "other runs and blank lines are ignored",
  );
  const without = (event) => good.filter((line) => !line.includes(`"event":"${event}"`));
  for (const event of ["started", "finished", "cleanup-verified"])
    asRefusal(
      () => checkLedger(without(event).join("\n"), dir),
      new RegExp(`exactly one ${event} row`),
    );
  asRefusal(() => checkLedger([...good, good[0]].join("\n"), dir), /exactly one started/);
  asRefusal(
    () =>
      checkLedger(
        [
          good[0],
          row({ event: "finished", outcome: "needs-recovery", lockRetained: true }),
          good[2],
        ].join("\n"),
        dir,
      ),
    /did not end recorded/,
  );
  asRefusal(
    () =>
      checkLedger(
        [
          good[0],
          row({ event: "finished", outcome: "recorded", lockRetained: true }),
          good[2],
        ].join("\n"),
        dir,
      ),
    /did not end recorded/,
  );
  asRefusal(
    () =>
      checkLedger(
        [
          good[0],
          row({
            event: "finished",
            outcome: "recorded",
            lockRetained: false,
            gitSha: "b".repeat(40),
          }),
          good[2],
        ].join("\n"),
        dir,
      ),
    /one commit/,
  );
  asRefusal(
    () =>
      checkLedger(
        [
          row({ event: "started", gitSha: "x" }),
          row({ event: "finished", outcome: "recorded", lockRetained: false, gitSha: "x" }),
          good[2],
        ].join("\n"),
        dir,
      ),
    /one commit/,
  );
  asRefusal(
    () =>
      checkLedger(
        [good[0], good[1], row({ event: "cleanup-verified", sandboxAtBaseline: false })].join("\n"),
        dir,
      ),
    /not at its baseline/,
  );
  asRefusal(() => checkLedger(`${good[0]}\nnot json`, dir), /not JSON/);
});

// ---- applying the closure ------------------------------------------------------------------------------

function applied({ comparison = comparisonOf(), withWorkspace = true, build = buildOf() } = {}) {
  const checked = checkComparison(comparison);
  const mapping = mapConditions(closure(), checked);
  const everyMatch = checked.rows.every((r) => r.status === "MATCH");
  const evidence = {
    ...checked,
    rows: everyMatch && withWorkspace ? [...checked.rows, ...gateRows()] : checked.rows,
  };
  const next = applyClosure({
    closure: closure(),
    mapping,
    comparison: evidence,
    recordings: recordingsFromRun(runOf()),
    comparisonPath: "spec/compatibility/closure/evidence/FUNCTIONS-EVENTS-comparison.json",
    finalArtifact: checkBuildRecord(build, checked),
    workspace: withWorkspace ? receiptOf() : undefined,
  });
  return { next, evidence, mapping };
}
const status = (next, suffix) => next.conditions.find((c) => c.conditionId.endsWith(suffix)).status;

test("a full match with the build and the workspace receipt verifies the 20 conditions and the final-artifact gate, and nothing else", () => {
  const { next, evidence } = applied();
  assert.equal(next.conditions.filter((c) => c.status === "VERIFIED").length, 21);
  assert.equal(status(next, "/final-artifact-regression"), "VERIFIED");
  assert.equal(status(next, "/closure-review"), "PENDING_REVIEW");
  assert.equal(
    next.conditions.find((c) => c.conditionId.endsWith("/closure-review")).evidence,
    undefined,
  );
  assert.equal(next.parentStatus, "IMPLEMENTING");
  assert.deepEqual(next.closureReview, { decision: "PENDING" });
  assertClosureConsistent(next, evidence);
  const gate = next.conditions.find((c) => c.conditionId.endsWith("/final-artifact-regression"));
  assert.deepEqual(gate.evidence.rows, { MATCH: evidence.rows.length });
  assert.equal(gate.evidence.sourceCommit, COMMIT);
  assert.equal(evidence.rows.filter((r) => r.row.startsWith("functions-events/gate#")).length, 3);
  const one = next.conditions.find((c) => c.conditionId.endsWith("/firestore-created"));
  assert.deepEqual(one.evidence.rows, { MATCH: 6, DIFF: 0, INCOMPLETE: 0 });
  assert.equal(one.evidence.finalArtifactSha256, ART);
  assert.equal(one.evidence.productionRecordings.length, 2);
  assert.equal(one.evidence.diffRows, undefined);
});

test("without the workspace receipt the gate stays pending and the evidence has no gate rows", () => {
  const { next, evidence } = applied({ withWorkspace: false });
  assert.equal(next.conditions.filter((c) => c.status === "VERIFIED").length, 20);
  assert.equal(status(next, "/final-artifact-regression"), "PENDING_CORPUS");
  assert.equal(
    next.conditions.find((c) => c.conditionId.endsWith("/final-artifact-regression")).evidence,
    undefined,
  );
  assert.equal(
    evidence.rows.some((r) => r.row.startsWith("functions-events/gate#")),
    false,
  );
  assertClosureConsistent(next, evidence);
});

test("a DIFF writes MISMATCH with the rows into that condition only, the gate stays pending, and the closure file stays consistent", () => {
  const diffId = "functions-events/storage/finalize#new-object#v1";
  const { next, evidence } = applied({
    comparison: comparisonOf({
      over: { [diffId]: { status: "DIFF", reasons: ["data.etag differs"] } },
    }),
  });
  assert.equal(status(next, "/storage-finalized"), "MISMATCH");
  const condition = next.conditions.find((c) => c.conditionId.endsWith("/storage-finalized"));
  assert.deepEqual(condition.evidence.diffRows, [{ row: diffId, reasons: ["data.etag differs"] }]);
  assert.deepEqual(condition.evidence.rows, { MATCH: 5, DIFF: 1, INCOMPLETE: 0 });
  assert.equal(next.conditions.filter((c) => c.status === "VERIFIED").length, 19);
  assert.equal(status(next, "/final-artifact-regression"), "PENDING_CORPUS");
  assertClosureConsistent(next, evidence);
});

test("applyClosure refuses a mapping with a missing row, a bad path and the wrong number of recordings", () => {
  const checked = checkComparison(
    comparisonOf({ drop: ["functions-events/auth/delete#single-user-delete#v1"] }),
  );
  const mapping = mapConditions(closure(), checked);
  const base = {
    closure: closure(),
    mapping,
    comparison: checked,
    recordings: recordingsFromRun(runOf()),
    comparisonPath: "p",
    finalArtifact: buildOf(),
    workspace: receiptOf(),
  };
  asRefusal(() => applyClosure(base), /does not cover FUNCTIONS-EVENTS\/auth-deleted/);
  const complete = mapConditions(closure(), checkComparison(comparisonOf()));
  asRefusal(
    () => applyClosure({ ...base, mapping: complete, comparisonPath: "" }),
    /comparison path is empty/,
  );
  asRefusal(
    () => applyClosure({ ...base, mapping: complete, comparisonPath: undefined }),
    /comparison path is empty/,
  );
  asRefusal(
    () => applyClosure({ ...base, mapping: complete, recordings: [base.recordings[0]] }),
    /two recordings/,
  );
  asRefusal(
    () => applyClosure({ ...base, mapping: complete, recordings: undefined }),
    /two recordings/,
  );
  asRefusal(() => applyClosure({ ...base, mapping: complete.slice(1) }), /was not mapped/);
});

test("the closure file is rewritten with only the conditions changed: every other byte stays", () => {
  const { next } = applied({ withWorkspace: false });
  const before = JSON.parse(closureText);
  assert.equal(
    JSON.stringify(before, null, 2) + "\n",
    closureText,
    "the file is the 2-space JSON the generator writes",
  );
  for (const key of Object.keys(before))
    if (key !== "conditions") assert.deepEqual(next[key], before[key], key);
  for (const [i, condition] of next.conditions.entries()) {
    const was = before.conditions[i];
    assert.equal(condition.conditionId, was.conditionId);
    for (const key of ["source", "recipeIds", "cases", "generations", "sources"])
      assert.deepEqual(condition[key], was[key], `${was.conditionId}.${key}`);
  }
});

// ---- the command ---------------------------------------------------------------------------------------

function commandFiles({
  comparison = comparisonOf(),
  run = runOf(),
  build = buildOf(),
  receipt = receiptOf(),
  ledger,
} = {}) {
  const files = new Map([
    ["comparison.json", JSON.stringify(comparison)],
    ["run/production-run.json", JSON.stringify(run)],
    ["closure.json", closureText],
    ["corpus.json", corpusText],
    ["build.json", JSON.stringify(build)],
    ["receipt.json", JSON.stringify(receipt)],
  ]);
  if (ledger !== undefined) files.set("ledger.jsonl", ledger);
  const written = new Map();
  const logs = [];
  const io = {
    read: (path) => files.get(path) ?? assert.fail(`no file ${path}`),
    write: (path, text) => written.set(path, text),
    log: (line) => logs.push(line),
  };
  return { io, written, logs };
}
const options = (over = {}) => ({
  comparison: "comparison.json",
  "production-run": "run/production-run.json",
  closure: "closure.json",
  corpus: "corpus.json",
  ...over,
});
const writing = (over = {}) =>
  options({
    write: true,
    out: "evidence.json",
    "comparison-path": "spec/compatibility/closure/evidence/FUNCTIONS-EVENTS-comparison.json",
    "build-record": "build.json",
    "build-record-out": "build-copy.json",
    "build-record-path": "spec/compatibility/closure/evidence/FUNCTIONS-EVENTS-build.json",
    "workspace-regression": "receipt.json",
    ...over,
  });

test("the report command writes nothing but the report, and prints the DIFF rows", () => {
  const diffId = "functions-events/firestore/update#changed-field#v1";
  const { io, written, logs } = commandFiles({
    comparison: comparisonOf({ over: { [diffId]: { status: "DIFF", reasons: ["a"] } } }),
  });
  const { report } = closureEvidenceCommand(options({ "report-out": "report.json" }), io);
  assert.deepEqual([...written.keys()], ["report.json"]);
  assert.equal(JSON.parse(written.get("report.json")).conditions.mismatch, 1);
  assert.equal(
    report.details.find((e) => e.conditionId.endsWith("firestore-updated")).diffRows[0].row,
    diffId,
  );
  assert.ok(logs.some((l) => l.includes(`DIFF ${diffId}: a`)));
  for (const name of ["comparison", "production-run", "closure", "corpus"]) {
    const missing = options();
    delete missing[name];
    asRefusal(
      () => closureEvidenceCommand(missing, commandFiles().io),
      new RegExp(`--${name} is required`),
    );
  }
});

test("--write writes the comparison evidence with the gate rows, the closure and the build record; the closure still holds", () => {
  const { io, written } = commandFiles();
  const { closure: next, evidence } = closureEvidenceCommand(writing(), io);
  assert.deepEqual([...written.keys()].toSorted(), [
    "build-copy.json",
    "closure.json",
    "evidence.json",
  ]);
  assert.equal(written.get("build-copy.json"), JSON.stringify(buildOf()));
  const evidenceFile = JSON.parse(written.get("evidence.json"));
  assert.equal(evidenceFile.buildRecordSha256, sha256(JSON.stringify(buildOf())));
  assert.equal(
    evidenceFile.buildRecordPath,
    "spec/compatibility/closure/evidence/FUNCTIONS-EVENTS-build.json",
  );
  const closureFile = JSON.parse(written.get("closure.json"));
  assert.deepEqual(closureFile, next);
  assert.equal(written.get("closure.json"), `${JSON.stringify(next, null, 2)}\n`);
  assertClosureConsistent(closureFile, evidenceFile);
  assert.equal(closureFile.conditions.filter((c) => c.status === "VERIFIED").length, 21);
  assert.equal(evidence.rows.length, evidenceFile.rows.length);
});

test("--write refuses a preliminary comparison, a missing option, an incomplete run, the wrong build, the wrong receipt and a bad ledger", () => {
  const refused = (files, opts, pattern) =>
    asRefusal(() => closureEvidenceCommand(opts, commandFiles(files).io), pattern);
  refused(
    { comparison: comparisonOf({ execution: "preliminary (closure-base 774a9f24c)" }) },
    writing(),
    /preliminary comparison is never written/,
  );
  refused({ comparison: comparisonOf({ execution: "Preliminary" }) }, writing(), /never written/);
  for (const name of [
    "out",
    "comparison-path",
    "build-record",
    "build-record-out",
    "build-record-path",
  ])
    refused({}, writing({ [name]: undefined }), new RegExp(`--${name} is required with --write`));
  refused({ run: runOf({ passes: [] }) }, writing(), /0 passes/);
  refused({ run: runOf({ corpusDigest: "e".repeat(64) }) }, writing(), /another corpus/);
  refused({ build: buildOf({ binarySha256: "e".repeat(64) }) }, writing(), /another binary/);
  refused({ build: buildOf({ locked: false }) }, writing(), /--locked/);
  refused({ receipt: receiptOf({ exitCode: 1 }) }, writing(), /did not exit 0/);
  refused(
    { receipt: receiptOf({ sourceCommit: "b".repeat(40) }) },
    writing(),
    /another commit or binary/,
  );
  const dir = "/x/run";
  const ledger = (finished) =>
    [
      JSON.stringify({ runDir: dir, event: "started", gitSha: COMMIT }),
      JSON.stringify({ runDir: dir, event: "finished", gitSha: COMMIT, ...finished }),
      JSON.stringify({ runDir: dir, event: "cleanup-verified", sandboxAtBaseline: true }),
    ].join("\n");
  refused(
    { ledger: ledger({ outcome: "needs-recovery", lockRetained: true }) },
    writing({ "sandbox-ledger": "ledger.jsonl", "production-run": "/x/run/production-run.json" }),
    /not found|no file|did not end recorded/,
  );
});

test("--write without a workspace receipt writes the 20 conditions and leaves the gate; a DIFF is written, not refused", () => {
  const noReceipt = commandFiles();
  const opts = writing();
  delete opts["workspace-regression"];
  const { closure: next } = closureEvidenceCommand(opts, noReceipt.io);
  assert.equal(next.conditions.filter((c) => c.status === "VERIFIED").length, 20);
  assert.equal(status(next, "/final-artifact-regression"), "PENDING_CORPUS");
  const diff = commandFiles({
    comparison: comparisonOf({
      over: {
        "functions-events/pubsub/publish#message-id#v2": {
          status: "DIFF",
          reasons: ["messageId format"],
        },
      },
    }),
  });
  const { closure: withDiff, evidence } = closureEvidenceCommand(writing(), diff.io);
  assert.equal(status(withDiff, "/pubsub-published"), "MISMATCH");
  assert.equal(withDiff.conditions.filter((c) => c.status === "VERIFIED").length, 19);
  assert.equal(
    evidence.rows.some((r) => r.row.startsWith("functions-events/gate#")),
    false,
  );
  assertClosureConsistent(withDiff, evidence);
});

test("the ledger is read for the run directory next to the production run", () => {
  const dir = "/x/run";
  const ledger = [
    JSON.stringify({ runDir: dir, event: "started", gitSha: COMMIT }),
    JSON.stringify({
      runDir: dir,
      event: "finished",
      gitSha: COMMIT,
      outcome: "recorded",
      lockRetained: false,
    }),
    JSON.stringify({ runDir: dir, event: "cleanup-verified", sandboxAtBaseline: true }),
  ].join("\n");
  const ok = commandFiles({ ledger });
  ok.io.read = (
    (read) => (path) =>
      path === "/x/run/production-run.json" ? JSON.stringify(runOf()) : read(path)
  )(ok.io.read);
  closureEvidenceCommand(
    writing({ "sandbox-ledger": "ledger.jsonl", "production-run": "/x/run/production-run.json" }),
    ok.io,
  );
  const bad = commandFiles({ ledger: ledger.replace('"recorded"', '"needs-recovery"') });
  bad.io.read = (
    (read) => (path) =>
      path === "/x/run/production-run.json" ? JSON.stringify(runOf()) : read(path)
  )(bad.io.read);
  asRefusal(
    () =>
      closureEvidenceCommand(
        writing({
          "sandbox-ledger": "ledger.jsonl",
          "production-run": "/x/run/production-run.json",
        }),
        bad.io,
      ),
    /did not end recorded/,
  );
});

// ---- the v4 run: 0 passes, 0 frames ---------------------------------------------------------------------

const realRuns =
  process.env.FE_SANDBOX_RUNS ?? join(import.meta.dirname, "../../../../docs.local/runs");
const v4 = join(
  realRuns,
  "functions-events-formal-20261004T161049Z-17272a4f69f41f21",
  "production-run.json",
);

test(
  "the v4 run (needs-recovery, 0 passes, 0 frames) gives no recordings",
  { skip: !existsSync(v4) },
  () => {
    const run = JSON.parse(readFileSync(v4, "utf8"));
    assert.equal(run.passes.length, 0);
    assert.equal(run.frames.length, 0);
    asRefusal(
      () => recordingsFromRun(run, { corpusSha256: sha256(corpusText) }),
      /the run has 0 passes/,
    );
    const { io } = commandFiles({ run });
    asRefusal(() => closureEvidenceCommand(writing(), io), /the run has 0 passes/);
  },
);

// ---- the command line, on real files in a temporary directory --------------------------------------------

test("the command line reports, writes with --write, and says what is wrong with an exit code 1", async () => {
  const { spawnSync } = await import("node:child_process");
  const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(join(tmpdir(), "fe-ce-"));
  const put = (name, text) => {
    mkdirSync(join(dir, name, ".."), { recursive: true });
    writeFileSync(join(dir, name), typeof text === "string" ? text : JSON.stringify(text));
    return join(dir, name);
  };
  const files = {
    comparison: put("comparison.json", comparisonOf()),
    run: put("run/production-run.json", runOf()),
    closure: put("closure.json", closureText),
    corpus: put("corpus.json", corpusText),
    build: put("build.json", buildOf()),
    receipt: put("receipt.json", receiptOf()),
  };
  const script = fileURLToPath(
    new URL("./functions-events/compare/closure-evidence.mjs", import.meta.url),
  );
  const base = [
    "--comparison",
    files.comparison,
    "--production-run",
    files.run,
    "--closure",
    files.closure,
    "--corpus",
    files.corpus,
  ];
  const run = (args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
  const report = run([...base, "--report-out", join(dir, "report.json")]);
  assert.equal(report.status, 0, report.stderr);
  assert.match(report.stdout, /20 VERIFIED, 0 MISMATCH/);
  assert.equal(JSON.parse(readFileSync(join(dir, "report.json"), "utf8")).conditions.verified, 20);
  assert.equal(
    readFileSync(files.closure, "utf8"),
    closureText,
    "the report does not touch the closure",
  );
  const written = run([
    ...base,
    "--write",
    "--out",
    join(dir, "evidence/out.json"),
    "--comparison-path",
    "spec/compatibility/closure/evidence/FUNCTIONS-EVENTS-comparison.json",
    "--build-record",
    files.build,
    "--build-record-out",
    join(dir, "evidence/build.json"),
    "--build-record-path",
    "spec/compatibility/closure/evidence/FUNCTIONS-EVENTS-build.json",
    "--workspace-regression",
    files.receipt,
  ]);
  assert.equal(written.status, 0, written.stderr);
  const closureAfter = JSON.parse(readFileSync(files.closure, "utf8"));
  assert.equal(closureAfter.conditions.filter((c) => c.status === "VERIFIED").length, 21);
  assertClosureConsistent(
    closureAfter,
    JSON.parse(readFileSync(join(dir, "evidence/out.json"), "utf8")),
  );
  assert.equal(readFileSync(join(dir, "evidence/build.json"), "utf8"), JSON.stringify(buildOf()));
  for (const args of [
    ["--nonsense"],
    ["--comparison"],
    [...base.slice(0, 6)],
    ["comparison", "x"],
  ]) {
    const failed = run(args);
    assert.equal(failed.status, 1, args.join(" "));
    assert.ok(failed.stderr.length > 0);
  }
  assert.match(run(["--nonsense"]).stderr, /bad argument: --nonsense/);
  assert.match(run(["--comparison"]).stderr, /bad argument: --comparison/);
});
