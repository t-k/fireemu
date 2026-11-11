// The TASK-QUEUE-FUNCTIONS closure record at the IMPLEMENTING stage: its structure, its scope, the pin of the program, and
// that it claims only what the two recordings and the committed comparisons show.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { applyEvidence } from "./closure-evidence.mjs";
import { CONDITION_IDS, PROGRAM, corpusManifest } from "./corpus.mjs";
import { PROJECT, REGION } from "./plan.mjs";

const root = new URL("../../../", import.meta.url);
const path = "spec/compatibility/closure/TASK-QUEUE-FUNCTIONS.json";
const record = JSON.parse(await readFile(new URL(path, root), "utf8"));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const isText = (value) => typeof value === "string" && value.trim().length > 0;

test("the record is the implementing parent on the events sandbox, verified only where two recordings back it", () => {
  assert.equal(record.parent, "TASK-QUEUE-FUNCTIONS");
  assert.equal(record.parentStatus, "IMPLEMENTING");
  assert.equal(record.inventoryStatus, "PROPOSED");
  assert.equal(record.oracleTrack, "disposable-sandbox");
  assert.deepEqual(record.oracle, {
    project: PROJECT,
    region: REGION,
    generations: [2],
    runtime: "nodejs22",
  });
  assert.equal(record.closureReview, undefined, "no review has approved it");
  assert.equal(record.integratedRegression, undefined);
  assert.deepEqual(record.recordingPolicy, { observedPasses: 2, requiredPasses: 2, waiver: null });
  assert.deepEqual(
    record.recordings.map((r) => [
      r.alias,
      r.envelope,
      r.recorderRequests,
      r.observationComplete,
      r.findings,
    ]),
    [
      ["pass-1", "TASK-QUEUE-20261111-01", 230, true, 0],
      ["pass-2", "TASK-QUEUE-20261111-02", 230, true, 0],
    ],
  );
  for (const r of record.recordings) assert.equal(r.corpusSha256, record.corpusContentSha256);
  const notVerified = ["dedup-window-expiry", "queue-config-mapping", "max-dispatches-per-second"];
  for (const condition of record.conditions) {
    const name = condition.conditionId.split("/")[1];
    const expected = notVerified.includes(name)
      ? "NOT_COMPARED"
      : condition.evidenceType === "production-parity"
        ? "VERIFIED"
        : "PLANNED";
    assert.equal(condition.status, expected, condition.conditionId);
    if (expected === "VERIFIED") {
      assert.equal(condition.productionEvidence.length, 2, condition.conditionId);
      assert.equal(condition.observedPasses, 2, condition.conditionId);
      assert.ok(condition.knownDifferences.length > 0, condition.conditionId);
    }
    if (expected === "NOT_COMPARED") assert.ok(isText(condition.reason), condition.conditionId);
    if (expected === "PLANNED")
      assert.deepEqual(condition.productionEvidence, [], condition.conditionId);
  }
});

test("the record's evidence is what the committed recordings and comparisons derive", () => {
  assert.deepEqual(applyEvidence(record), record);
});

test("a condition with a mismatch in its cases would not be verified", () => {
  const broken = structuredClone(record);
  broken.conditions[0].corpusSteps = [...broken.conditions[0].corpusSteps, "no-such-case"];
  const derived = applyEvidence(broken);
  assert.equal(derived.conditions[0].status, "PLANNED");
});

test("the conditions are the conditions of the program, each with a reason and the steps that serve it", () => {
  assert.deepEqual(
    record.conditions.map((c) => c.conditionId),
    CONDITION_IDS,
  );
  const kinds = new Set(["production-parity", "fireemu-only", "closure-gate"]);
  for (const c of record.conditions) {
    assert.ok(isText(c.description), c.conditionId);
    assert.ok(kinds.has(c.evidenceType), c.conditionId);
    assert.deepEqual(c.recipeIds, ["task-queue/" + c.conditionId.split("/")[1]]);
    const served = PROGRAM.filter((s) => s.groups.includes(c.conditionId.split("/")[1])).map(
      (s) => s.key,
    );
    assert.deepEqual(c.corpusSteps ?? [], served, c.conditionId);
  }
  const expiry = record.conditions.find((c) => c.conditionId.endsWith("/dedup-window-expiry"));
  assert.equal(expiry.stage, 2);
  assert.deepEqual(
    record.conditions
      .filter((c) => c.evidenceType !== "production-parity")
      .map((c) => c.evidenceType),
    ["fireemu-only", "closure-gate", "closure-gate"],
  );
});

test("the program is pinned: its manifest bytes and its content digest", async () => {
  const bytes = await readFile(new URL(record.corpusPath, root));
  assert.equal(record.corpusSha256, sha(bytes));
  assert.equal(record.corpusContentSha256, corpusManifest().corpusSha256);
  assert.equal(JSON.parse(bytes).corpusSha256, record.corpusContentSha256);
  for (const file of [record.recorder, record.judge, record.fixture])
    assert.ok((await readFile(new URL(file, root))).length > 0, file);
});

test("the scope decisions, the exclusions and the budget are recorded", () => {
  assert.deepEqual(
    record.scopeDecisions.map((d) => d.id),
    ["TQ-SCOPE", "TQ-ORACLE", "TQ-BUDGET", "TQ-PROFILES", "TQ-TIMING"],
  );
  assert.match(record.scopeDecisions.find((d) => d.id === "TQ-BUDGET").decision, /US\$4/);
  assert.match(
    record.scopeDecisions.find((d) => d.id === "TQ-ORACLE").decision,
    /six hexadecimal digits/,
  );
  assert.deepEqual(
    record.excludedFromParent.map((e) => e.id),
    [
      "deployment",
      "queue-management-api",
      "gen1-tasks",
      "python",
      "task-uri",
      "oidc-values",
      "ordering-and-exact-timing",
      "scaling-and-quota",
    ],
  );
  for (const e of record.excludedFromParent) {
    assert.equal(e.status, "NOT_COMPARED");
    assert.ok(isText(e.reason));
  }
});

test("the record names no project number, no home-directory path and no key", async () => {
  const text = await readFile(new URL(path, root), "utf8");
  assert.equal(/\b\d{12,13}\b/.test(text), false);
  assert.equal(/\/Users\/|\/home\//.test(text), false);
  assert.equal(/AIza/.test(text), false);
});
