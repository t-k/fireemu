// The closure-evidence generator (functions-events/compare/closure-evidence.mjs): a synthetic comparison made from the
// real closure inventory, synthetic runs, builds and receipts, and the v4 run (0 passes) as the real refusal.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  applyClosure,
  buildReport,
  checkBuildRecord,
  checkComparison,
  checkDeclaredMasks,
  checkLocalBinary,
  checkLedger,
  checkWorkspaceReceipt,
  closureEvidenceCommand,
  expectedRows,
  gateRows,
  mapConditions,
  recordingsFromRun,
  reportText,
} from "./functions-events/compare/closure-evidence.mjs";
import { tempDir } from "./test-tmpdir.mjs";

const repo = (path) => fileURLToPath(new URL(`../../${path}`, import.meta.url));
const CLOSURE_PATH = "spec/compatibility/closure/FUNCTIONS-EVENTS.json";
const CORPUS_PATH = "conformance/functions-events/corpus.json";
const closureText = readFileSync(repo(CLOSURE_PATH), "utf8");
const corpusText = readFileSync(repo(CORPUS_PATH), "utf8");
const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const closure = () => JSON.parse(closureText);
const ART = "d".repeat(64);
const COMMIT = "a".repeat(40);
const RUNNER_TREE = "7".repeat(40);
const RUNNER_BYTES = "runner bytes of the build's source commit";
const RECORDED_AT = "2026-10-05T09:59:00.000Z";
const LOCAL = {
  sha256: ART,
  sourceCommit: COMMIT,
  dirty: false,
  runnerPath: "/repo/tools/runner-node/index.mjs",
  runnerSha256: sha256(RUNNER_BYTES),
  runnerTree: RUNNER_TREE,
};
/** git as the generator asks it: the runner tree and the runner file of the build's source commit. */
const gitFake = (args) => {
  if (args[0] === "rev-parse" && args[1] === `${COMMIT}:tools/runner-node`)
    return `${RUNNER_TREE}\n`;
  if (
    args[0] === "cat-file" &&
    args[1] === "blob" &&
    args[2] === `${COMMIT}:tools/runner-node/index.mjs`
  )
    return Buffer.from(RUNNER_BYTES);
  assert.fail(`unexpected git ${args.join(" ")}`);
};
const validLedger = (dir, commit = COMMIT) =>
  [
    JSON.stringify({ runDir: dir, event: "started", gitSha: commit }),
    JSON.stringify({
      runDir: dir,
      event: "finished",
      gitSha: commit,
      outcome: "recorded",
      lockRetained: false,
    }),
    JSON.stringify({ runDir: dir, event: "cleanup-verified", sandboxAtBaseline: true }),
  ].join("\n");
const isGate = (c) =>
  ["final-artifact-regression", "closure-review"].some((g) => c.conditionId.endsWith(`/${g}`));
const business = () => closure().conditions.filter((c) => !isGate(c));

// The masks a real comparison uses, with the scope decision of the closure record that declares each.
const USED_MASKS = [
  { mask: "authId-api_key-uid", reason: "E10", rows: 1 },
  { mask: "authId-unknown-present", reason: "E10", rows: 1 },
  { mask: "firestore-field-maps-unordered", reason: "E12", rows: 20 },
  { mask: "pubsub-subscription-numbers", reason: "E11", rows: 7 },
];

/**
 * A comparison with every row the closure expects, MATCH unless `over` says otherwise (row id -> { status, reasons } for a fault of
 * the recording or of both profiles, or { only: { strict | emulator: status }, reasons } for one profile's difference).
 */
function comparisonOf({
  over = {},
  drop = [],
  extra = [],
  artifact = ART,
  execution = "FUNCTIONS-EVENTS formal record (FE v5) vs local sessions x",
  corpus = sha256(corpusText),
  productionRun = {
    project: "fireemu-oracle-events",
    recordedAt: RECORDED_AT,
    corpusDigest: sha256(corpusText),
  },
  localBinary = LOCAL,
  declaredMasks = USED_MASKS,
} = {}) {
  const rows = [];
  for (const condition of business())
    for (const id of expectedRows(condition)) {
      if (drop.includes(id)) continue;
      const [, name, version] = id.split("#");
      const {
        only,
        production = { status: "MATCH", reasons: [] },
        status = "MATCH",
        reasons = [],
        ...rest
      } = over[id] ?? {};
      const rank0 = { MATCH: 0, INCOMPLETE: 1, DIFF: 2 };
      const profile = (side) => {
        const own = only
          ? only[side] === undefined
            ? { status: "MATCH", reasons: [] }
            : { status: only[side], reasons: reasons.map((r) => `${side}: ${r}`) }
          : { status, reasons };
        // the production side counts against both profiles, with its reasons
        return {
          status: rank0[production.status] > rank0[own.status] ? production.status : own.status,
          reasons: [...production.reasons, ...own.reasons],
        };
      };
      const profiles = { emulator: profile("emulator"), strict: profile("strict") };
      const rank = { MATCH: 0, INCOMPLETE: 1, DIFF: 2 };
      const combined = [profiles.emulator.status, profiles.strict.status].reduce((a, b) =>
        rank[b] > rank[a] ? b : a,
      );
      rows.push({
        row: id,
        caseId: `${condition.conditionId}#${name}#${version}`,
        conditionId: condition.conditionId,
        case: name,
        generation: Number(version.slice(1)),
        status: combined,
        reasons: [...profiles.emulator.reasons, ...profiles.strict.reasons],
        production,
        profiles,
        ...rest,
      });
    }
  rows.push(...extra);
  const count = (s) => rows.filter((r) => r.status === s).length;
  return {
    kind: "functions-events-comparison",
    artifactSha256: artifact,
    execution,
    corpusSha256: corpus,
    productionRun,
    localBinary,
    rows,
    summary: {
      rows: rows.length,
      match: count("MATCH"),
      diff: count("DIFF"),
      incomplete: count("INCOMPLETE"),
      declaredMasks,
    },
  };
}
const runOf = (over = {}) => ({
  kind: "functions-events-production-run",
  project: "fireemu-oracle-events",
  recordedAt: RECORDED_AT,
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
      assert.ok(condition.status === "VERIFIED", label(condition));
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
    production: { status: "MATCH", reasons: [] },
    profiles: {
      emulator: { status: "MATCH", reasons: [] },
      strict: { status: "MATCH", reasons: [] },
    },
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
  assert.equal(
    one.evidence.comparisonPath,
    "spec/compatibility/closure/evidence/FUNCTIONS-EVENTS-comparison.json",
  );
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

test("a DIFF leaves its condition as it was, with no evidence; the others are VERIFIED, the gate stays pending, and the closure file stays consistent", () => {
  const diffId = "functions-events/storage/finalize#new-object#v1";
  const { next, evidence } = applied({
    comparison: comparisonOf({
      over: { [diffId]: { status: "DIFF", reasons: ["data.etag differs"] } },
    }),
  });
  const condition = next.conditions.find((c) => c.conditionId.endsWith("/storage-finalized"));
  const before = closure().conditions.find((c) => c.conditionId.endsWith("/storage-finalized"));
  assert.deepEqual(condition, before);
  assert.notEqual(condition.status, "VERIFIED");
  assert.equal(condition.evidence, undefined);
  assert.equal(evidence.rows.find((r) => r.row === diffId).status, "DIFF");
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
  ledger = validLedger(resolve("run")),
  repoCorpus = corpusText,
  corpus = corpusText,
  git = gitFake,
} = {}) {
  const files = new Map([
    ["comparison.json", JSON.stringify(comparison)],
    ["run/production-run.json", JSON.stringify(run)],
    ["closure.json", closureText],
    ["corpus.json", corpus],
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
    git,
    repoCorpus: () => repoCorpus,
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
    "sandbox-ledger": "ledger.jsonl",
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
  assert.deepEqual(
    withDiff.conditions.find((c) => c.conditionId.endsWith("/pubsub-published")),
    closure().conditions.find((c) => c.conditionId.endsWith("/pubsub-published")),
  );
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
  const { mkdirSync, writeFileSync } = await import("node:fs");
  const dir = tempDir("fe-ce-");
  const put = (name, text) => {
    mkdirSync(join(dir, name, ".."), { recursive: true });
    writeFileSync(join(dir, name), typeof text === "string" ? text : JSON.stringify(text));
    return join(dir, name);
  };
  // the real repository: the build's source commit is HEAD, and the runner the sessions used is what HEAD holds
  const gitOut = (...args) =>
    spawnSync("git", ["-C", fileURLToPath(new URL("../../", import.meta.url)), ...args]).stdout;
  const head = String(gitOut("rev-parse", "HEAD")).trim();
  const localBinary = {
    ...LOCAL,
    sourceCommit: head,
    runnerTree: String(gitOut("rev-parse", "HEAD:tools/runner-node")).trim(),
    runnerSha256: sha256(gitOut("cat-file", "blob", "HEAD:tools/runner-node/index.mjs")),
  };
  const files = {
    comparison: put("comparison.json", comparisonOf({ localBinary })),
    run: put("run/production-run.json", runOf()),
    closure: put("closure.json", closureText),
    corpus: put("corpus.json", corpusText),
    build: put("build.json", buildOf({ sourceCommit: head })),
    receipt: put("receipt.json", receiptOf({ sourceCommit: head })),
    ledger: put("ledger.jsonl", validLedger(join(dir, "run"), head)),
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
    "--sandbox-ledger",
    files.ledger,
  ]);
  assert.equal(written.status, 0, written.stderr);
  const closureAfter = JSON.parse(readFileSync(files.closure, "utf8"));
  assert.equal(closureAfter.conditions.filter((c) => c.status === "VERIFIED").length, 21);
  assertClosureConsistent(
    closureAfter,
    JSON.parse(readFileSync(join(dir, "evidence/out.json"), "utf8")),
  );
  assert.equal(
    readFileSync(join(dir, "evidence/build.json"), "utf8"),
    JSON.stringify(buildOf({ sourceCommit: head })),
  );
  for (const args of [["--nonsense"], ["--comparison"], base.slice(0, 6), ["comparison", "x"]]) {
    const failed = run(args);
    assert.equal(failed.status, 1, args.join(" "));
    assert.ok(failed.stderr.length > 0);
  }
  assert.match(run(["--nonsense"]).stderr, /bad argument: --nonsense/);
  assert.match(run(["--comparison"]).stderr, /bad argument: --comparison/);
});

// ---- near misses the first mutation run found --------------------------------------------------------------

test("each part of the summary is checked on its own, a row without a condition is named, and only five stray rows are listed", () => {
  const good = comparisonOf();
  for (const [key, pattern] of [
    ["rows", /summary is not its rows' count/],
    ["match", /summary/],
    ["diff", /summary/],
    ["incomplete", /summary/],
  ])
    asRefusal(
      () =>
        checkComparison({ ...good, summary: { ...good.summary, [key]: good.summary[key] + 1 } }),
      pattern,
    );
  const withDiff = comparisonOf({
    over: { "functions-events/auth/create#admin-create#v1": { status: "DIFF", reasons: ["x"] } },
  });
  checkComparison(withDiff);
  asRefusal(
    () => checkComparison({ ...withDiff, summary: { ...withDiff.summary, diff: 0 } }),
    /summary/,
  );
  const noCondition = {
    ...good,
    rows: [{ ...good.rows[0], conditionId: undefined }, ...good.rows.slice(1)],
  };
  asRefusal(() => checkComparison(noCondition), /no row id or condition/);
  const strays = Array.from({ length: 7 }, (_, i) => ({
    row: `functions-events/other/thing#c${i}#v1`,
    conditionId: "X/y",
    case: `c${i}`,
    generation: 1,
    status: "MATCH",
    reasons: [],
    production: { status: "MATCH", reasons: [] },
    profiles: {
      emulator: { status: "MATCH", reasons: [] },
      strict: { status: "MATCH", reasons: [] },
    },
  }));
  const message = (() => {
    try {
      mapConditions(closure(), checkComparison(comparisonOf({ extra: strays })));
    } catch (error) {
      return error.message;
    }
    return "";
  })();
  assert.match(message, /thing#c4#v1/);
  assert.doesNotMatch(message, /thing#c5#v1/);
});

test("two passes at one time are refused even when the first pass is instantaneous; a build record with a renamed key is wrong", () => {
  const run = runOf();
  const instantaneous = {
    ...run,
    passes: [
      { ...run.passes[0], endedAt: run.passes[0].startedAt },
      { ...run.passes[1], startedAt: run.passes[0].startedAt },
    ],
  };
  asRefusal(() => recordingsFromRun(instantaneous), /start at the same time/);
  const { locked, ...rest } = buildOf();
  asRefusal(() => checkBuildRecord({ ...rest, lockedBy: locked }, comparisonOf()), /wrong fields/);
});

test("the final-artifact gate needs the build record; an INCOMPLETE row leaves its condition as it was, and the source commit is written into the evidence of a VERIFIED one", () => {
  const checked = checkComparison(
    comparisonOf({
      over: {
        "functions-events/storage/delete#live-object-delete#v2": {
          status: "INCOMPLETE",
          reasons: ["no frame"],
        },
      },
    }),
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
  const withBuild = applyClosure(base);
  const condition = withBuild.conditions.find((c) => c.conditionId.endsWith("/storage-deleted"));
  assert.deepEqual(
    condition,
    closure().conditions.find((c) => c.conditionId.endsWith("/storage-deleted")),
  );
  assert.equal(condition.evidence, undefined);
  assert.equal(
    withBuild.conditions.find((c) => c.conditionId.endsWith("/firestore-created")).evidence
      .sourceCommit,
    COMMIT,
  );
  const full = checkComparison(comparisonOf());
  const noBuild = applyClosure({
    ...base,
    mapping: mapConditions(closure(), full),
    comparison: { ...full, rows: [...full.rows, ...gateRows()] },
    finalArtifact: undefined,
  });
  assert.equal(status(noBuild, "/final-artifact-regression"), "PENDING_CORPUS");
  assert.equal(
    noBuild.conditions.find((c) => c.conditionId.endsWith("/firestore-created")).evidence
      .sourceCommit,
    undefined,
  );
});

test("the report says whether the comparison is preliminary, lists only conditions that are not VERIFIED, and a write without a receipt adds no gate rows", () => {
  const preliminary = comparisonOf({ execution: "preliminary (closure-base 774a9f24c)" });
  assert.equal(
    buildReport({
      comparison: preliminary,
      mapping: mapConditions(closure(), checkComparison(preliminary)),
    }).preliminary,
    true,
  );
  assert.equal(
    buildReport({
      comparison: comparisonOf(),
      mapping: mapConditions(closure(), checkComparison(comparisonOf())),
    }).preliminary,
    false,
  );
  const comparison = checkComparison(
    comparisonOf({
      over: { "functions-events/auth/create#admin-create#v1": { status: "DIFF", reasons: ["r"] } },
    }),
  );
  const text = reportText(
    buildReport({ comparison, mapping: mapConditions(closure(), comparison) }),
  );
  assert.doesNotMatch(text, /VERIFIED FUNCTIONS-EVENTS\/firestore-deleted/);
  assert.match(text, /^closure report of d{64}|^closure report of [0-9a-f]{64} \(/);
  const preText = reportText(
    buildReport({
      comparison: checkComparison(preliminary),
      mapping: mapConditions(closure(), checkComparison(preliminary)),
    }),
  );
  assert.match(preText, /\[preliminary\]/);
  const opts = writing();
  delete opts["workspace-regression"];
  const files = commandFiles();
  const { evidence } = closureEvidenceCommand(opts, files.io);
  assert.equal(
    evidence.rows.some((r) => r.row.startsWith("functions-events/gate#")),
    false,
  );
  assert.equal(
    JSON.parse(files.written.get("evidence.json")).rows.length,
    comparisonOf().rows.length,
  );
  assert.equal(gateRows().length, 3);
});

test("the command line names a word that is no flag", async () => {
  const { spawnSync } = await import("node:child_process");
  const script = fileURLToPath(
    new URL("./functions-events/compare/closure-evidence.mjs", import.meta.url),
  );
  const failed = spawnSync(process.execPath, [script, "comparison", "x"], { encoding: "utf8" });
  assert.equal(failed.status, 1);
  assert.match(failed.stderr, /bad argument: comparison/);
});

// ---- review 2026-10-05: strict-only (ledger 811), the per-profile status, M1, M2, S1 ----------------------------

const written = (over = {}, filesOf = {}) =>
  closureEvidenceCommand(writing(over), commandFiles(filesOf).io);
const refusedWrite = (filesOf, opts, pattern) =>
  asRefusal(() => closureEvidenceCommand(writing(opts), commandFiles(filesOf).io), pattern);

test("a comparison without the per-profile status of every row is refused, even with a good combined status", () => {
  const good = comparisonOf();
  const strip = (change) => ({ ...good, rows: [change(good.rows[0]), ...good.rows.slice(1)] });
  const missing = /no per-profile status: the comparison is from a comparator without/;
  asRefusal(() => checkComparison(strip(({ profiles: _profiles, ...row }) => row)), missing);
  asRefusal(
    () => checkComparison(strip((row) => ({ ...row, profiles: { strict: row.profiles.strict } }))),
    missing,
  );
  asRefusal(
    () =>
      checkComparison(strip((row) => ({ ...row, profiles: { emulator: row.profiles.emulator } }))),
    missing,
  );
  asRefusal(() => checkComparison(strip((row) => ({ ...row, profiles: "MATCH" }))), missing);
  asRefusal(
    () =>
      checkComparison(
        strip((row) => ({
          ...row,
          profiles: { ...row.profiles, strict: { status: "PASS", reasons: [] } },
        })),
      ),
    /bad strict status or reasons/,
  );
  asRefusal(
    () =>
      checkComparison(
        strip((row) => ({ ...row, profiles: { ...row.profiles, emulator: { status: "MATCH" } } })),
      ),
    /bad emulator status or reasons/,
  );
  // the combined status must be the worse of the two profiles: a MATCH combined over a strict DIFF is a forged row
  asRefusal(
    () =>
      checkComparison(
        strip((row) => ({
          ...row,
          profiles: { ...row.profiles, strict: { status: "DIFF", reasons: ["x"] } },
        })),
      ),
    /combined status is not the worse of its two profiles/,
  );
  asRefusal(
    () =>
      checkComparison(
        strip((row) => ({
          ...row,
          status: "DIFF",
          production: { status: "MATCH", reasons: [] },
          profiles: {
            emulator: { status: "MATCH", reasons: [] },
            strict: { status: "MATCH", reasons: [] },
          },
        })),
      ),
    /combined status is not the worse/,
  );
});

test("ledger 811: an emulator-profile DIFF does not block VERIFIED, a strict DIFF does, and a production-side fault blocks both", () => {
  const id = "functions-events/firestore/create#new-document#v1";
  const verifiedOf = (over) => {
    const next = written({}, { comparison: comparisonOf({ over }) }).closure;
    return next.conditions.find((c) => c.conditionId.endsWith("/firestore-created")).status;
  };
  assert.equal(verifiedOf({}), "VERIFIED");
  assert.equal(
    verifiedOf({ [id]: { only: { emulator: "DIFF" }, reasons: ["value $.x"] } }),
    "VERIFIED",
  );
  assert.equal(
    verifiedOf({ [id]: { only: { emulator: "INCOMPLETE" }, reasons: ["driver"] } }),
    "VERIFIED",
  );
  assert.notEqual(
    verifiedOf({ [id]: { only: { strict: "DIFF" }, reasons: ["value $.x"] } }),
    "VERIFIED",
  );
  assert.notEqual(
    verifiedOf({ [id]: { only: { strict: "INCOMPLETE" }, reasons: ["driver"] } }),
    "VERIFIED",
  );
  // a production pass fault is in both profiles' status: it blocks
  assert.notEqual(
    verifiedOf({ [id]: { status: "INCOMPLETE", reasons: ["production pass 1: no frame"] } }),
    "VERIFIED",
  );
  // the mapping keeps the two views apart
  const comparison = checkComparison(
    comparisonOf({ over: { [id]: { only: { emulator: "DIFF" }, reasons: ["value $.x"] } } }),
  );
  const entry = mapConditions(closure(), comparison).find((e) =>
    e.conditionId.endsWith("/firestore-created"),
  );
  assert.equal(entry.status, "VERIFIED");
  assert.equal(entry.match, entry.expected);
  assert.deepEqual(entry.emulatorProfile.diffRows, [{ row: id, reasons: ["emulator: value $.x"] }]);
  assert.equal(entry.emulatorProfile.match, entry.expected - 1);
  const strictEntry = mapConditions(
    closure(),
    checkComparison(
      comparisonOf({ over: { [id]: { only: { strict: "DIFF" }, reasons: ["value $.x"] } } }),
    ),
  ).find((e) => e.conditionId.endsWith("/firestore-created"));
  assert.equal(strictEntry.status, "MISMATCH");
  assert.deepEqual(strictEntry.diffRows, [{ row: id, reasons: ["strict: value $.x"] }]);
  assert.equal(strictEntry.emulatorProfile.diffRows.length, 0);
});

test("the final-artifact gate is judged on strict rows too, and the report has its own emulator-profile section", () => {
  const id = "functions-events/auth/create#admin-create#v1";
  const withEmulatorDiff = comparisonOf({
    over: { [id]: { only: { emulator: "DIFF" }, reasons: ["x"] } },
  });
  const { closure: next, evidence } = written({}, { comparison: withEmulatorDiff });
  assert.equal(status(next, "/final-artifact-regression"), "VERIFIED");
  assert.equal(evidence.rows.filter((r) => r.row.startsWith("functions-events/gate#")).length, 3);
  const strictDiff = comparisonOf({ over: { [id]: { only: { strict: "DIFF" }, reasons: ["x"] } } });
  const blocked = written({}, { comparison: strictDiff }).closure;
  assert.notEqual(status(blocked, "/final-artifact-regression"), "VERIFIED");
  // the report
  const report = buildReport({
    comparison: withEmulatorDiff,
    mapping: mapConditions(closure(), checkComparison(withEmulatorDiff)),
  });
  assert.equal(report.judgedOn, "strict profile against production (owner ledger 811)");
  assert.deepEqual(report.emulatorProfileVersusProduction, {
    match: report.comparison.rows - 1,
    diff: 1,
    incomplete: 0,
  });
  assert.equal(report.conditions.verified, 20);
  const text = reportText(report);
  assert.match(text, /judged on: strict profile against production/);
  assert.match(
    text,
    /emulator-profile versus production \(reported, not blocking\): \d+ MATCH, 1 DIFF, 0 INCOMPLETE rows/,
  );
  assert.match(text, /FUNCTIONS-EVENTS\/auth-created: 1 DIFF, 0 INCOMPLETE \(emulator profile\)/);
  assert.doesNotMatch(text, /official/i);
});

test("M1: the comparison must be of the production run and the corpus it is written with", () => {
  const other = "e".repeat(64);
  // another corpus: the comparison's own digest, then the run's digest it claims
  refusedWrite({ comparison: comparisonOf({ corpus: other }) }, {}, /another corpus than --corpus/);
  refusedWrite(
    {
      comparison: comparisonOf({
        productionRun: {
          project: "fireemu-oracle-events",
          recordedAt: RECORDED_AT,
          corpusDigest: other,
        },
      }),
    },
    {},
    /names another corpus than --production-run/,
  );
  // another run: recordedAt and project
  refusedWrite(
    {
      comparison: comparisonOf({
        productionRun: {
          project: "fireemu-oracle-events",
          recordedAt: "2026-10-04T10:00:00.000Z",
          corpusDigest: sha256(corpusText),
        },
      }),
    },
    {},
    /another production run than --production-run \(recordedAt differs\)/,
  );
  refusedWrite(
    {
      comparison: comparisonOf({
        productionRun: {
          project: "fireemu-other",
          recordedAt: RECORDED_AT,
          corpusDigest: sha256(corpusText),
        },
      }),
    },
    {},
    /another project than --production-run/,
  );
  refusedWrite(
    { comparison: { ...comparisonOf(), productionRun: undefined } },
    {},
    /names no production run/,
  );
  refusedWrite(
    { comparison: { ...comparisonOf(), corpusSha256: undefined } },
    {},
    /names no corpus digest/,
  );
  // the run itself recorded against another corpus than the comparison's
  refusedWrite({ run: runOf({ corpusDigest: other }) }, {}, /another corpus/);
  // --corpus is not the repository's corpus, even when run and comparison agree with it
  const foreign = `${corpusText} `;
  refusedWrite(
    {
      run: runOf({ corpusDigest: sha256(foreign) }),
      comparison: comparisonOf({
        corpus: sha256(foreign),
        productionRun: {
          project: "fireemu-oracle-events",
          recordedAt: RECORDED_AT,
          corpusDigest: sha256(foreign),
        },
      }),
      corpus: foreign,
      repoCorpus: corpusText,
    },
    {},
    /--corpus is not the repository's/,
  );
  // the good case still writes
  written();
});

test("M2: the local sessions must have run the artifact, from a clean tree of the build's commit, with that commit's runner", () => {
  const withLocal = (change) => ({
    comparison: comparisonOf({ localBinary: { ...LOCAL, ...change } }),
  });
  refusedWrite(
    { comparison: { ...comparisonOf(), localBinary: undefined } },
    {},
    /names no local binary/,
  );
  refusedWrite({ comparison: comparisonOf({ localBinary: null }) }, {}, /names no local binary/);
  refusedWrite(
    withLocal({ sha256: "e".repeat(64) }),
    {},
    /ran another binary than the artifact and the build record/,
  );
  refusedWrite(withLocal({ dirty: true }), {}, /uncommitted changes/);
  refusedWrite(withLocal({ dirty: undefined }), {}, /uncommitted changes/);
  refusedWrite(
    withLocal({ sourceCommit: "b".repeat(40) }),
    {},
    /another commit than the build record/,
  );
  refusedWrite(
    withLocal({ runnerTree: "6".repeat(40) }),
    {},
    /not the runner tree of the build's source commit/,
  );
  refusedWrite(
    withLocal({ runnerSha256: "8".repeat(64) }),
    {},
    /not index\.mjs of the build's source commit/,
  );
  // the artifact the sessions ran must also be the build record's, not only the comparison's
  refusedWrite({ build: buildOf({ binarySha256: "e".repeat(64) }) }, {}, /another binary/);
  // git is asked for the build's commit, not another
  const asked = [];
  closureEvidenceCommand(writing(), {
    ...commandFiles().io,
    git: (args) => {
      asked.push(args.join(" "));
      return gitFake(args);
    },
  });
  assert.deepEqual(asked, [
    `rev-parse ${COMMIT}:tools/runner-node`,
    `cat-file blob ${COMMIT}:tools/runner-node/index.mjs`,
  ]);
  // report mode needs none of it
  closureEvidenceCommand(options(), {
    ...commandFiles({ comparison: comparisonOf({ localBinary: null }) }).io,
    git: () => assert.fail("report mode does not ask git"),
  });
});

test("S1: --sandbox-ledger is required with --write, and the report mode does not need it", () => {
  refusedWrite({}, { "sandbox-ledger": undefined }, /--sandbox-ledger is required with --write/);
  closureEvidenceCommand(options(), commandFiles().io);
});

test("S2: a production-side fault counts against both profiles; one attributed to a single profile is refused", () => {
  const fault = { status: "INCOMPLETE", reasons: ["production pass 1: no frame in the window"] };
  const row = (change) => {
    const good = comparisonOf();
    return { ...good, rows: [change(good.rows[0]), ...good.rows.slice(1)] };
  };
  // the comparator's own shape: both profiles carry the production fault
  const id = "functions-events/firestore/create#new-document#v1";
  const both = comparisonOf({ over: { [id]: { production: fault } } });
  checkComparison(both);
  const faulty = both.rows.find((r) => r.row === id);
  assert.deepEqual(faulty.production, fault);
  for (const side of ["emulator", "strict"]) {
    assert.equal(faulty.profiles[side].status, "INCOMPLETE");
    assert.deepEqual(faulty.profiles[side].reasons, fault.reasons);
  }
  const verified = (comparison) =>
    mapConditions(closure(), checkComparison(comparison)).find((e) =>
      e.conditionId.endsWith("/firestore-created"),
    ).status;
  assert.equal(verified(both), "PRODUCTION_RECORDED");
  // attributed to the emulator profile only: strict MATCH would verify a condition with a faulty recording
  const emulatorOnly = (r) => ({
    ...r,
    status: "INCOMPLETE",
    reasons: fault.reasons,
    production: fault,
    profiles: {
      emulator: { status: "INCOMPLETE", reasons: fault.reasons },
      strict: { status: "MATCH", reasons: [] },
    },
  });
  const forged = row(emulatorOnly);
  asRefusal(
    () => checkComparison(forged),
    /strict status is better than the production-side status, which counts against both profiles/,
  );
  asRefusal(
    () => closureEvidenceCommand(writing(), commandFiles({ comparison: forged }).io),
    /strict status is better than the production-side status/,
  );
  // attributed to strict only: the emulator profile must carry it as well
  asRefusal(
    () =>
      checkComparison(
        row((r) => ({
          ...r,
          status: "INCOMPLETE",
          reasons: fault.reasons,
          production: fault,
          profiles: {
            emulator: { status: "MATCH", reasons: [] },
            strict: { status: "INCOMPLETE", reasons: fault.reasons },
          },
        })),
      ),
    /emulator status is better than the production-side status/,
  );
  // the status is right but the reasons were dropped from a profile
  asRefusal(
    () =>
      checkComparison(
        row((r) => ({
          ...r,
          status: "INCOMPLETE",
          reasons: fault.reasons,
          production: fault,
          profiles: {
            emulator: { status: "INCOMPLETE", reasons: fault.reasons },
            strict: { status: "INCOMPLETE", reasons: ["strict: something else"] },
          },
        })),
      ),
    /strict reasons lack the production-side reasons/,
  );
  // no production-side entry at all, or a bad one
  const noProduction = /has no production-side status/;
  asRefusal(() => checkComparison(row(({ production: _production, ...r }) => r)), noProduction);
  asRefusal(
    () => checkComparison(row((r) => ({ ...r, production: { status: "PASS", reasons: [] } }))),
    noProduction,
  );
  asRefusal(
    () => checkComparison(row((r) => ({ ...r, production: { status: "MATCH" } }))),
    noProduction,
  );
  // a worse profile than the production side is fine: a local DIFF with a MATCH production
  checkComparison(comparisonOf({ over: { [id]: { only: { strict: "DIFF" }, reasons: ["x"] } } }));
});

test("checkLocalBinary stands on its own: the sessions' binary must be the artifact and the build record's, each by itself", () => {
  const comparison = { artifactSha256: ART, localBinary: LOCAL };
  const build = buildOf();
  checkLocalBinary(comparison, build, { git: gitFake });
  const other = "e".repeat(64);
  // the artifact the comparison names is another binary than the sessions ran, although the build record agrees with the sessions
  asRefusal(
    () => checkLocalBinary({ ...comparison, artifactSha256: other }, build, { git: gitFake }),
    /ran another binary than the artifact and the build record/,
  );
  // the build record is of another binary than the sessions ran, although the comparison's artifact agrees with them
  asRefusal(
    () => checkLocalBinary(comparison, buildOf({ binarySha256: other }), { git: gitFake }),
    /ran another binary than the artifact and the build record/,
  );
});

test("the gate rows written into the evidence carry the production side and both profiles, all MATCH", () => {
  for (const row of gateRows()) {
    assert.deepEqual(row.production, { status: "MATCH", reasons: [] });
    assert.deepEqual(row.profiles, {
      emulator: { status: "MATCH", reasons: [] },
      strict: { status: "MATCH", reasons: [] },
    });
  }
  const { evidence } = written();
  const gate = evidence.rows.filter((r) => r.row.startsWith("functions-events/gate#"));
  assert.equal(gate.length, 3);
  for (const row of gate) assert.deepEqual(row.production, { status: "MATCH", reasons: [] });
});

// ---- the masks a comparison used must be declared by the closure record (review M-B2 (c)) -----------------------------------

const MASKS = [
  "authId-api_key-uid",
  "authId-unknown-present",
  "firestore-field-maps-unordered",
  "pubsub-subscription-numbers",
];

test("the closure record declares every mask a comparison can use: E10 the authId, E11 the subscription numbers, E12 the unordered field maps", () => {
  const declared = new Map();
  for (const decision of closure().scopeDecisions) {
    if (decision.status !== "APPROVED") continue;
    for (const mask of decision.masks ?? []) declared.set(mask, decision.id);
  }
  assert.deepEqual(Object.fromEntries([...declared].toSorted()), {
    "authId-api_key-uid": "E10",
    "authId-unknown-present": "E10",
    "firestore-field-maps-unordered": "E12",
    "pubsub-subscription-numbers": "E11",
  });
  // The accepted difference of the admin-write id is on its condition too, in STORAGE-OBJECT's form: a note that says what is
  // not judged, why and under which ruling.
  const note = closure().conditions.find((c) =>
    c.conditionId.endsWith("/firestore-auth-context"),
  ).note;
  assert.match(note, /admin write/i);
  assert.match(note, /operator/i);
  assert.match(note, /only its presence is compared/i);
  assert.match(note, /authType is compared exactly/i);
  assert.match(note, /E10/);
  for (const suffix of ["pubsub-published", "pubsub-topic-routing"])
    assert.match(
      closure().conditions.find((c) => c.conditionId.endsWith(`/${suffix}`)).note,
      /E11/,
    );
});

test("a comparison that used only declared masks passes, and one that does not record its masks, used an undeclared one, or cites the wrong decision is refused", () => {
  const ok = comparisonOf();
  assert.doesNotThrow(() => checkDeclaredMasks(ok, closure()));
  assert.doesNotThrow(() => checkDeclaredMasks(comparisonOf({ declaredMasks: [] }), closure()));
  // It must say which masks it used, even none.
  const silent = comparisonOf();
  delete silent.summary.declaredMasks;
  asRefusal(() => checkDeclaredMasks(silent, closure()), /does not record the masks it used/);
  // An undeclared mask, and a declared one under another decision.
  asRefusal(
    () =>
      checkDeclaredMasks(
        comparisonOf({ declaredMasks: [{ mask: "authId-any-string", reason: "E10", rows: 1 }] }),
        closure(),
      ),
    /undeclared mask authId-any-string/,
  );
  asRefusal(
    () =>
      checkDeclaredMasks(
        comparisonOf({
          declaredMasks: [{ mask: "authId-unknown-present", reason: "E11", rows: 1 }],
        }),
        closure(),
      ),
    /authId-unknown-present.*E10/,
  );
  // A mask of a row that the summary does not list.
  const rowOnly = comparisonOf();
  rowOnly.rows[0].declaredMasks = [{ mask: "authId-any-string", path: "$.x", reason: "E10" }];
  asRefusal(() => checkDeclaredMasks(rowOnly, closure()), /undeclared mask authId-any-string/);
  // A declared mask a row used that the summary leaves out is refused, and one the summary lists is fine.
  const unlisted = comparisonOf({ declaredMasks: [] });
  unlisted.rows[0].declaredMasks = [
    { mask: "authId-unknown-present", path: "$.frame.event.authId", reason: "E10" },
  ];
  asRefusal(() => checkDeclaredMasks(unlisted, closure()), /summary does not list/);
  const listed = comparisonOf();
  listed.rows[0].declaredMasks = unlisted.rows[0].declaredMasks;
  assert.doesNotThrow(() => checkDeclaredMasks(listed, closure()));
  // The record side: a decision that is not APPROVED, one that is missing, and one that lists no masks declare nothing.
  for (const edit of [
    (c) => (c.scopeDecisions.find((d) => d.id === "E10").status = "PENDING"),
    (c) => (c.scopeDecisions = c.scopeDecisions.filter((d) => d.id !== "E10")),
    (c) => delete c.scopeDecisions.find((d) => d.id === "E10").masks,
  ]) {
    const record = closure();
    edit(record);
    asRefusal(() => checkDeclaredMasks(comparisonOf(), record), /undeclared mask authId/);
  }
  for (const mask of MASKS)
    assert.doesNotThrow(() =>
      checkDeclaredMasks(
        comparisonOf({ declaredMasks: [{ mask, reason: DECLARED_REASON[mask], rows: 1 }] }),
        closure(),
      ),
    );
});

const DECLARED_REASON = {
  "authId-api_key-uid": "E10",
  "authId-unknown-present": "E10",
  "firestore-field-maps-unordered": "E12",
  "pubsub-subscription-numbers": "E11",
};

test("the report and the promotion both refuse a comparison that used an undeclared mask or records none", () => {
  const undeclared = comparisonOf({
    declaredMasks: [{ mask: "authId-any-string", reason: "E10", rows: 1 }],
  });
  asRefusal(
    () => closureEvidenceCommand(options(), commandFiles({ comparison: undeclared }).io),
    /undeclared mask authId-any-string/,
  );
  const silent = comparisonOf();
  delete silent.summary.declaredMasks;
  asRefusal(
    () => closureEvidenceCommand(writing(), commandFiles({ comparison: silent }).io),
    /does not record the masks it used/,
  );
  const files = commandFiles({ comparison: undeclared });
  asRefusal(() => closureEvidenceCommand(writing(), files.io), /undeclared mask/);
  assert.equal(files.written.size, 0, "nothing is written for a refused promotion");
});

// ---- the integrated regression block (promotion item 4, FS-DATA-WRITE / STORAGE-OBJECT form) ---------------------------------

const RELEASE = "v0.12.0";
const BUILD_PATH = "spec/compatibility/closure/evidence/FUNCTIONS-EVENTS-build.json";
const EVIDENCE_PATH = "spec/compatibility/closure/evidence/FUNCTIONS-EVENTS-comparison.json";

test("--integrated-release writes the integrated regression block of the closure: the release, the commit and binary, the build receipt and the comparison, identical to the lane's", () => {
  const { io, written } = commandFiles();
  closureEvidenceCommand(writing({ "integrated-release": RELEASE }), io);
  const closureFile = JSON.parse(written.get("closure.json"));
  const block = closureFile.integratedRegression;
  const evidenceText = written.get("evidence.json");
  const evidenceFile = JSON.parse(evidenceText);
  assert.deepEqual(Object.keys(block), [
    "release",
    "integrationCommit",
    "releaseBinarySha256",
    "buildReceiptPath",
    "buildReceiptSha256",
    "comparisons",
    "result",
    "productionRequests",
  ]);
  assert.equal(block.release, RELEASE);
  assert.equal(block.integrationCommit, COMMIT);
  assert.equal(block.releaseBinarySha256, ART);
  assert.equal(block.buildReceiptPath, BUILD_PATH);
  assert.equal(block.buildReceiptSha256, sha256(JSON.stringify(buildOf())));
  assert.equal(block.buildReceiptSha256, evidenceFile.buildRecordSha256);
  assert.deepEqual(block.comparisons, [
    {
      path: EVIDENCE_PATH,
      sha256: sha256(evidenceText),
      rows: evidenceFile.rows.length,
      summary: { MATCH: evidenceFile.rows.length },
      laneComparisonPath: EVIDENCE_PATH,
      laneComparisonSha256: sha256(evidenceText),
      identicalRows: evidenceFile.rows.length,
      changedRows: [],
    },
  ]);
  assert.equal(block.result, "IDENTICAL_TO_LANE");
  assert.equal(block.productionRequests, 0);
  // Only the integratedRegression key is new; the rest of the closure is what the command wrote without it.
  const without = commandFiles();
  closureEvidenceCommand(writing(), without.io);
  const { integratedRegression, ...rest } = closureFile;
  assert.deepEqual(rest, JSON.parse(without.written.get("closure.json")));
  assert.equal(JSON.parse(without.written.get("closure.json")).integratedRegression, undefined);
});

test("the integrated regression is written only for a closure whose 20 conditions and final-artifact gate are VERIFIED, and its release name is a plain name", () => {
  // A DIFF row: the conditions are not all VERIFIED.
  const diffId = "functions-events/firestore/update#changed-field#v1";
  const differing = commandFiles({
    comparison: comparisonOf({ over: { [diffId]: { status: "DIFF", reasons: ["a"] } } }),
  });
  asRefusal(
    () => closureEvidenceCommand(writing({ "integrated-release": RELEASE }), differing.io),
    /integrated regression.*VERIFIED/,
  );
  assert.equal(differing.written.size, 0, "nothing is written for a refused promotion");
  // No workspace receipt: the gate stays pending.
  const noReceipt = commandFiles();
  asRefusal(
    () =>
      closureEvidenceCommand(
        writing({ "integrated-release": RELEASE, "workspace-regression": undefined }),
        noReceipt.io,
      ),
    /integrated regression.*VERIFIED/,
  );
  assert.equal(noReceipt.written.size, 0);
  for (const bad of ["", "v0.12.0 ", "../x", "a/b", "v0.12.0\\n", ".", "x".repeat(65)]) {
    const files = commandFiles();
    asRefusal(
      () => closureEvidenceCommand(writing({ "integrated-release": bad }), files.io),
      /--integrated-release/,
    );
    assert.equal(files.written.size, 0, JSON.stringify(bad));
  }
  // Without --write the option is refused rather than ignored.
  asRefusal(
    () => closureEvidenceCommand(options({ "integrated-release": RELEASE }), commandFiles().io),
    /--integrated-release needs --write/,
  );
});

test("applyClosure writes the block only when it is given one, and refuses a block for a closure that is not fully verified", () => {
  const integrated = {
    release: RELEASE,
    buildReceiptPath: BUILD_PATH,
    buildReceiptSha256: "b".repeat(64),
    comparisonSha256: "c".repeat(64),
  };
  const { evidence, mapping } = applied();
  const call = (over) =>
    applyClosure({
      closure: closure(),
      mapping,
      comparison: evidence,
      recordings: recordingsFromRun(runOf()),
      comparisonPath: EVIDENCE_PATH,
      finalArtifact: checkBuildRecord(buildOf(), comparisonOf()),
      workspace: receiptOf(),
      ...over,
    });
  assert.equal(call({}).integratedRegression, undefined);
  const next = call({ integrated });
  assert.equal(next.integratedRegression.comparisons[0].sha256, "c".repeat(64));
  assert.equal(next.integratedRegression.buildReceiptSha256, "b".repeat(64));
  assert.equal(next.integratedRegression.comparisons[0].rows, evidence.rows.length);
  asRefusal(() => call({ integrated, workspace: undefined }), /integrated regression.*VERIFIED/);
  asRefusal(
    () =>
      call({
        integrated,
        mapping: mapping.map((entry, index) =>
          index === 0 ? { ...entry, status: "MISMATCH" } : entry,
        ),
      }),
    /integrated regression.*VERIFIED/,
  );
});
