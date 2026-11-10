// The Hosting closure record: structure, scope, the two production recordings and the evidence the
// conditions cite. The record carries no closure review yet: it is the candidate that review reads.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { CONDITIONS, buildCorpus, corpusManifest } from "./hosting-production/corpus.mjs";
import { loadKnownDifferences } from "./hosting-production/compare.mjs";

const root = new URL("../../", import.meta.url);
const record = JSON.parse(
  await readFile(new URL("spec/compatibility/closure/HOSTING.json", root), "utf8"),
);
const manifest = corpusManifest(buildCorpus());
const isText = (value) => typeof value === "string" && value.trim().length > 0;
const bytesOf = (path) => readFile(new URL(path, root));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const jsonOf = async (path) => JSON.parse(await bytesOf(path));

test("the record is the Hosting parent awaiting review, with the corpus pinned", async () => {
  assert.equal(record.parent, "HOSTING");
  assert.equal(record.parentStatus, "IMPLEMENTING", "promotion is the coordinator's after review");
  assert.equal(record.closureReview, undefined, "no review yet");
  assert.deepEqual(record.recordingPolicy, { observedPasses: 2, requiredPasses: 2, waiver: null });
  assert.equal(record.corpusPath, "conformance/src/hosting-production/corpus.manifest.json");
  assert.equal(record.corpusContentSha256, manifest.corpusSha256);
  assert.equal(record.corpusSha256, sha(await bytesOf(record.corpusPath)));
});

test("the two recordings are the rows of two runs of the pinned corpus, in corpus order, all answered", async () => {
  assert.deepEqual(
    record.recordings.map((r) => r.alias),
    ["pass-1", "pass-2"],
  );
  const ids = buildCorpus().versions.flatMap((v) => v.requests.map((r) => r.id));
  const runs = new Set();
  for (const recording of record.recordings) {
    const bytes = await bytesOf(recording.fixturePath);
    assert.equal(recording.fixtureSha256, sha(bytes), recording.alias);
    assert.equal(recording.corpusSha256, manifest.corpusSha256);
    const document = JSON.parse(bytes);
    assert.equal(document.corpusSha256, manifest.corpusSha256);
    assert.equal(document.run, recording.run);
    runs.add(document.run);
    assert.deepEqual(
      document.rows.map((row) => row.id),
      ids,
    );
    assert.ok(
      document.rows.every((row) => row.outcome === "answered"),
      recording.alias,
    );
    // nothing private: a Google API key, a project's numeric id in a name, a channel host
    const text = bytes.toString("utf8");
    assert.doesNotMatch(text, /AIza[0-9A-Za-z_-]{20,}/);
    assert.doesNotMatch(text, /web\.app|firebaseapp\.com|fireemu-oracle/);
  }
  assert.equal(runs.size, 2, "two different runs");
});

test("the committed comparisons are those of the recordings, with no mismatch and no unknown row", async () => {
  for (const [name, comparison] of Object.entries(record.comparisons)) {
    const bytes = await bytesOf(comparison.path);
    assert.equal(comparison.sha256, sha(bytes), name);
    const document = JSON.parse(bytes);
    assert.deepEqual(document.summary, comparison.summary, name);
    assert.equal(document.summary.MISMATCH, 0, name);
    assert.equal(document.summary.UNKNOWN, 0, name);
    assert.equal(document.corpusSha256, manifest.corpusSha256);
    assert.deepEqual(
      document.knownDifferences.map((entry) => entry.id).toSorted(),
      loadKnownDifferences()
        .filter((entry) => entry.appliesTo.includes(document.comparison))
        .map((entry) => entry.id)
        .toSorted(),
      name,
    );
  }
  assert.equal(
    record.comparisons.runVsRun.summary.MATCH + record.comparisons.runVsRun.summary.MATCH_LAYOUT,
    201,
  );
  const knownFile = await bytesOf(record.knownDifferences.path);
  assert.equal(record.knownDifferences.sha256, sha(knownFile));
  assert.deepEqual(
    record.knownDifferences.entries,
    JSON.parse(knownFile).entries.map((entry) => entry.id),
  );
});

test("every observed condition cites the recordings and comparisons its rows come from", async () => {
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
  const comparisons = {};
  for (const [name, comparison] of Object.entries(record.comparisons))
    comparisons[name] = await jsonOf(comparison.path);
  const knownIds = new Set(record.knownDifferences.entries);
  for (const condition of record.conditions) {
    const key = condition.conditionId.replace("HOSTING/", "");
    assert.ok(CONDITIONS.includes(key), key);
    assert.equal(condition.status, "VERIFIED", key);
    assert.equal(condition.observedPasses, 2, key);
    assert.equal(condition.passComparison, "MATCH", key);
    assert.equal(condition.reviewRef, undefined, "the review's reference is added at promotion");
    assert.deepEqual(
      condition.productionEvidence.map(({ alias, fixturePath, fixtureSha256 }) => ({
        alias,
        fixturePath,
        fixtureSha256,
      })),
      record.recordings.map(({ alias, fixturePath, fixtureSha256 }) => ({
        alias,
        fixturePath,
        fixtureSha256,
      })),
    );
    assert.deepEqual(condition.productionCorpus, {
      versions: [...expected[key].versions].toSorted(),
      requests: expected[key].requests,
    });
    assert.deepEqual(condition.recipeIds, [`hosting/${key}`]);
    assert.deepEqual(condition.profiles, {
      strict: "MATCHES_RECORDED_CASES",
      emulator: "NO_PRODUCTION_CLAIM",
    });
    for (const [name, document] of Object.entries(comparisons)) {
      const verdict = document.conditions[key];
      assert.ok(verdict.closable, `${key} ${name}`);
      assert.equal(verdict.rows, expected[key].requests);
      assert.deepEqual(condition.comparisons[name], {
        rows: verdict.rows,
        counts: verdict.counts,
        knownDifferenceRows: verdict.knownDifferenceRows,
      });
    }
    for (const id of condition.knownDifferences) assert.ok(knownIds.has(id), id);
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
