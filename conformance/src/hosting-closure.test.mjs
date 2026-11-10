// The Hosting closure record: structure, scope and the derived counts of the production corpus.
// While no recording is committed the record must stay IMPLEMENTING with every condition UNVERIFIED.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { CONDITIONS, buildCorpus, corpusManifest } from "./hosting-production/corpus.mjs";

const record = JSON.parse(
  await readFile(new URL("../../spec/compatibility/closure/HOSTING.json", import.meta.url), "utf8"),
);
const manifest = corpusManifest(buildCorpus());
const isText = (value) => typeof value === "string" && value.trim().length > 0;

test("the record is the pending Hosting parent with the corpus pinned", async () => {
  assert.equal(record.parent, "HOSTING");
  assert.equal(record.parentStatus, "IMPLEMENTING");
  assert.equal(record.closureReview, undefined, "no review yet");
  assert.deepEqual(record.recordingPolicy, { observedPasses: 0, requiredPasses: 2, waiver: null });
  assert.deepEqual(record.recordings, []);
  assert.equal(record.corpusPath, "conformance/src/hosting-production/corpus.manifest.json");
  assert.equal(record.corpusContentSha256, manifest.corpusSha256);
  const bytes = await readFile(
    new URL("./hosting-production/corpus.manifest.json", import.meta.url),
  );
  assert.equal(record.corpusSha256, createHash("sha256").update(bytes).digest("hex"));
});

test("every observed condition has its production corpus counts and no evidence yet", () => {
  const expected = {};
  for (const version of manifest.versions) {
    for (const request of version.requests) {
      if (request.infoOnly) continue;
      for (const condition of [request.condition, ...(request.also ?? [])]) {
        const entry = (expected[condition] ??= { versions: new Set(), requests: 0 });
        entry.versions.add(version.id);
        entry.requests += 1;
      }
    }
  }
  const ids = record.conditions.map((c) => c.conditionId);
  assert.equal(new Set(ids).size, ids.length);
  assert.deepEqual(
    ids.map((id) => id.replace("HOSTING/", "")).toSorted(),
    Object.keys(expected).toSorted(),
    "closure conditions and corpus conditions agree",
  );
  for (const condition of record.conditions) {
    const key = condition.conditionId.replace("HOSTING/", "");
    assert.ok(CONDITIONS.includes(key), key);
    assert.equal(condition.status, "UNVERIFIED", key);
    assert.deepEqual(condition.productionEvidence, [], key);
    assert.equal(condition.reviewRef, undefined);
    assert.deepEqual(condition.productionCorpus, {
      versions: [...expected[key].versions].toSorted(),
      requests: expected[key].requests,
    });
    assert.deepEqual(condition.recipeIds, [`hosting/${key}`]);
  }
});

test("the four excluded conditions are NOT_COMPARED with a reason and the ruling that excludes them", () => {
  assert.deepEqual(
    record.excludedFromParent.map((c) => c.conditionId),
    ["HOSTING/function-rewrites", "HOSTING/run-rewrites", "HOSTING/ignore", "HOSTING/local-safety"],
  );
  for (const condition of record.excludedFromParent) {
    assert.equal(condition.status, "NOT_COMPARED");
    assert.ok(isText(condition.reason) && condition.reason.length > 40);
    assert.match(condition.authority, /owner ledger 2435/);
    assert.equal(condition.reviewRef, undefined, "an excluded condition is never reviewed");
    assert.equal(
      record.conditions.some((c) => c.conditionId === condition.conditionId),
      false,
      "an excluded condition is not also in the claim",
    );
  }
  const reasons = record.excludedFromParent.slice(2).map((c) => c.reason);
  for (const reason of reasons)
    assert.match(reason, /not observable in production; official-emulator comparison only/);
});

test("scope decisions keep the preview-channel and no-live-release rules", () => {
  const ids = record.scopeDecisions.map((d) => d.id);
  assert.deepEqual(ids, ["HOSTING-LOCAL-ONLY", "HOSTING-ORACLE", "HOSTING-REST-SCOPE"]);
  const oracle = record.scopeDecisions.find((d) => d.id === "HOSTING-ORACLE").decision;
  assert.match(oracle, /preview channels/);
  assert.match(oracle, /never released to/);
  assert.match(oracle, /authorized domains/);
});
