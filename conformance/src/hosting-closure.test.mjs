// The Hosting closure record: structure, scope, the production recordings (the parent corpus and the
// follow-up corpus, two runs of each) and the evidence the conditions cite.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { CONDITIONS, buildCorpus, corpusManifest } from "./hosting-production/corpus.mjs";
import { loadKnownDifferences } from "./hosting-production/compare.mjs";
import { followupComparisons, FOLLOWUP_FILES } from "./hosting-production/closure-evidence.mjs";
import { buildFollowupCorpus } from "./hosting-production/followup.mjs";

const root = new URL("../../", import.meta.url);
const record = JSON.parse(
  await readFile(new URL("spec/compatibility/closure/HOSTING.json", root), "utf8"),
);
const manifest = corpusManifest(buildCorpus());
const isText = (value) => typeof value === "string" && value.trim().length > 0;
const bytesOf = (path) => readFile(new URL(path, root));
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const jsonOf = async (path) => JSON.parse(await bytesOf(path));

test("the record is the verified Hosting parent with its review, and the corpus pinned", async () => {
  assert.equal(record.parent, "HOSTING");
  assert.equal(record.parentStatus, "COMPAT_VERIFIED");
  assert.equal(record.inventoryStatus, "PROPOSED");
  const review = record.closureReview;
  assert.equal(review.decision, "APPROVED");
  assert.equal(review.decider, "project coordinator");
  assert.match(review.decidedOn, /^\d{4}-\d{2}-\d{2}$/);
  assert.match(review.decisionRef, /owner ledger 2435, 2458; coordinator rulings 11-26/);
  assert.match(review.reviewedCommit, /^[0-9a-f]{40}$/);
  assert.equal(review.reviews.length, 4);
  for (const entry of review.reviews.slice(0, 2)) {
    assert.match(entry.reportPath, /^docs\.local\/reviews\/2026-11-11-hosting-parent-closure-/);
    assert.match(entry.reportSha256, /^[0-9a-f]{64}$/);
    assert.match(entry.reviewedCommit, /^[0-9a-f]{40}$/);
  }
  assert.equal(
    review.reviews[2].reportPath,
    undefined,
    "the coordinator's re-check has no report file",
  );
  assert.equal(review.reviews[2].reviewedCommit, review.reviewedCommit);
  assert.equal(review.reviews[2].outcome, "APPROVED");
  // the follow-up recordings settled the gzip, 404 page, dot-segment and digit-name To-Dos: what is
  // left is optional, and Brotli stays declared
  assert.equal(record.followUps.length, 2);
  assert.match(record.followUps[0], /11 to 99 bytes/);
  assert.match(record.followUps[1], /Brotli stays a declared difference/);
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
    assert.doesNotMatch(text, /Page Not Found|fireauth|oauthhelper|POST_BODY|bodyBase64/);
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
  const total = (summary) => Object.values(summary).reduce((sum, count) => sum + count, 0);
  for (const comparison of Object.values(record.comparisons))
    assert.equal(total(comparison.summary), 201);
  // a row with a known difference is KNOWN_DIFFERENCE, never MATCH: 18 rows of each strict comparison
  assert.equal(record.comparisons.strictVsPass1.summary.KNOWN_DIFFERENCE, 18);
  assert.equal(record.comparisons.strictVsPass2.summary.KNOWN_DIFFERENCE, 18);
  assert.equal(record.comparisons.runVsRun.summary.KNOWN_DIFFERENCE, 2);
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
    assert.equal(condition.reviewRef, record.closureReview.reviews[0].reportSha256, key);
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
      strict: "MATCHES_RECORDED_CASES_WITH_PRODUCTION_EXACT",
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

test("the release comparisons are the committed ones, and the limitations name what no recording settles", async () => {
  const regression = record.integratedRegression;
  assert.deepEqual(
    regression.comparisons.map((entry) => entry.path),
    [
      ...Object.values(record.comparisons).map((entry) => entry.path),
      ...Object.values(record.followUpComparisons).map((entry) => entry.path),
    ],
  );
  for (const entry of regression.comparisons) {
    const bytes = await bytesOf(entry.path);
    assert.equal(entry.sha256, sha(bytes), entry.path);
    assert.equal(entry.rows, entry.path.includes("followup") ? 78 : 201);
    assert.deepEqual(entry.summary, JSON.parse(bytes).summary);
  }
  assert.match(regression.releaseBindingNote, /R37/);
  const limits = record.limitations.join("\n");
  for (const text of [
    "KNOWN_DIFFERENCE",
    "KD-BROTLI",
    "KD-GZIP-LENGTH",
    "KD-SAFETY-ORIGIN-REDIRECT",
    "Observed (rows v12.*",
    "matches nothing in production",
    "416",
    "multi-range",
    "Range on HEAD",
    "productionExact",
    "init.js",
    "raw backslash",
    "reads a raw backslash as a slash",
    "/a/b/..",
  ]) {
    assert.ok(limits.includes(text), text);
  }
  // what the recordings settled is no longer called inferred; only the two 416 answers over a
  // compressed body that no recording asked for are (coordinator ruling 28, S2)
  assert.equal(limits.split("Inferred, not recorded").length, 2);
  assert.match(
    limits,
    /Inferred, not recorded: a range that starts past the gzip length but inside the file/,
  );
  assert.match(limits, /KD-GZIP-LENGTH, coordinator ruling 27/);
  assert.match(limits, /at most 8 bytes/);
  assert.match(record.followUps[0], /two inferred 416 answers/);
  for (const text of [
    "KD-DEFAULT-404-BODY",
    "KD-AUTH-HANDLER-PAGE",
    "owner decision of 2026-11-11",
  ]) {
    assert.ok(limits.includes(text), text);
  }
  const compression = record.conditions.find((c) => c.conditionId === "HOSTING/compression-vary");
  assert.match(compression.description, /precompressed files and Content-Encoding header rules/);
  assert.match(compression.description, /KD-COMPRESSION, KD-BROTLI: br only/);
});

test("KD-COMPRESSION is Brotli only: the gzip rows are compared, match in both strict comparisons and keep their decoded body compared", async () => {
  const entry = JSON.parse(await bytesOf(record.knownDifferences.path)).entries.find(
    (candidate) => candidate.id === "KD-COMPRESSION",
  );
  assert.deepEqual(entry.rows, [
    "v01.gz-br",
    "v01.gz-gzip-br",
    "v01.gz-br-refused",
    "v01.gz-json-br",
  ]);
  assert.deepEqual(entry.fields, ["header:content-encoding", "header:content-length"]);
  assert.equal(entry.etagSuffix, "-br");
  for (const name of ["strictVsPass1", "strictVsPass2"]) {
    const rows = JSON.parse(await bytesOf(record.comparisons[name].path)).rows;
    const status = Object.fromEntries(rows.map((row) => [row.id, row.status]));
    for (const id of ["v01.gz-gzip", "v01.gz-head-gzip", "v01.gz-json-gzip", "v01.gz-png-gzip"]) {
      assert.equal(status[id], "MATCH_LAYOUT", `${name} ${id}`);
    }
    for (const id of entry.rows) {
      assert.equal(status[id], "KNOWN_DIFFERENCE", `${name} ${id}`);
      const known = rows.find((row) => row.id === id).known.map((k) => k.field);
      assert.deepEqual(
        known.toSorted(),
        ["header:content-encoding", "header:content-length", "header:etag"],
        `${name} ${id}`,
      );
    }
  }
  const limits = record.limitations.join("\n");
  for (const text of [
    "Gzip (rows v01.gz-*, v14.*, v15.*)",
    "miniz_oxide",
    "32 MiB",
    "x-gzip",
    "A Content-Encoding header that a headers rule sets is not served",
    "every Accept-Encoding line counts",
    "the ten bytes production sent",
  ]) {
    assert.ok(limits.includes(text), text);
  }
});

test("every known-difference field is used by a committed comparison, and a wildcard says why", async () => {
  const entries = JSON.parse(await bytesOf(record.knownDifferences.path)).entries;
  const used = new Map();
  for (const comparison of Object.values(record.comparisons)) {
    for (const row of JSON.parse(await bytesOf(comparison.path)).rows) {
      for (const { field, entry } of row.known ?? []) {
        if (!used.has(entry)) used.set(entry, new Set());
        used.get(entry).add(field);
      }
    }
  }
  for (const entry of entries) {
    assert.ok(used.has(entry.id), `${entry.id} is used by no committed comparison`);
    if (entry.fields === "*") {
      assert.ok(isText(entry.wildcardReason), `${entry.id}: "*" needs a wildcardReason`);
      continue;
    }
    const listed = new Set(entry.fields);
    if (entry.etagSuffix) listed.add("header:etag");
    if (entry.locationHost) listed.add("header:location");
    for (const field of listed) {
      assert.ok(used.get(entry.id).has(field), `${entry.id} lists ${field}, which no row uses`);
    }
    for (const field of used.get(entry.id)) {
      assert.ok(listed.has(field), `${entry.id} covers ${field} without listing it`);
    }
  }
});

test("the two follow-up recordings are the rows of two runs of the follow-up corpus, answered, with no page body", async () => {
  const followup = JSON.parse(
    await bytesOf("conformance/src/hosting-production/followup.manifest.json"),
  );
  assert.equal(record.followUpCorpus.corpusSha256, followup.corpusSha256);
  assert.equal(
    record.followUpCorpus.sha256,
    sha(await bytesOf("conformance/src/hosting-production/followup.manifest.json")),
  );
  assert.equal(record.followUpCorpus.versions, 5);
  assert.equal(record.followUpCorpus.requests, 78);
  assert.deepEqual(
    record.followUpRecordings.map((r) => [r.alias, r.run, r.envelope]),
    [
      ["followup-1", "11ae6c", "HOSTING-FOLLOWUP-V1-20261111"],
      ["followup-2", "1c6a4c", "HOSTING-FOLLOWUP-V1-20261111"],
    ],
  );
  const ids = buildFollowupCorpus().versions.flatMap((v) => v.requests.map((r) => r.id));
  for (const recording of record.followUpRecordings) {
    const bytes = await bytesOf(recording.fixturePath);
    assert.equal(recording.fixtureSha256, sha(bytes), recording.alias);
    assert.equal(recording.corpusSha256, followup.corpusSha256);
    const document = JSON.parse(bytes);
    assert.equal(document.corpusSha256, followup.corpusSha256);
    assert.equal(document.run, recording.run);
    assert.deepEqual(
      document.rows.map((row) => row.id),
      ids,
    );
    assert.ok(document.rows.every((row) => row.outcome === "answered"));
    // no page body is published (owner decision, 2026-11-11): the default 404 page and the hosted
    // auth handler rows keep their length and digest only
    assert.equal(
      document.rows.filter((row) => row.bodyBase64 !== undefined || row.bodyWithheld).length,
      0,
    );
    for (const id of ["v11.default-404", "v11.auth-handler", "v11.auth-handler-query"]) {
      const row = document.rows.find((candidate) => candidate.id === id);
      assert.equal(row.bodyText, undefined, id);
      assert.ok(row.bodyBytes > 0 && /^[0-9a-f]{64}$/.test(row.bodySha256), id);
    }
    const text = bytes.toString("utf8");
    assert.doesNotMatch(text, /AIza[0-9A-Za-z_-]{20,}/);
    assert.doesNotMatch(text, /web\.app|firebaseapp\.com|fireemu-oracle/);
    assert.doesNotMatch(text, /Page Not Found|fireauth|oauthhelper|POST_BODY|bodyBase64/);
  }
  assert.notEqual(record.followUpRecordings[0].run, record.followUpRecordings[1].run);
});

test("the follow-up comparisons are those of the recordings, with no mismatch and no unknown row, and each condition cites them", async () => {
  const followup = JSON.parse(
    await bytesOf("conformance/src/hosting-production/followup.manifest.json"),
  );
  const knownFile = await bytesOf(record.followUpKnownDifferences.path);
  assert.equal(record.followUpKnownDifferences.sha256, sha(knownFile));
  const entries = JSON.parse(knownFile).entries;
  assert.deepEqual(
    record.followUpKnownDifferences.entries,
    entries.map((entry) => entry.id),
  );
  const documents = {};
  for (const [name, comparison] of Object.entries(record.followUpComparisons)) {
    const bytes = await bytesOf(comparison.path);
    assert.equal(comparison.sha256, sha(bytes), name);
    const document = JSON.parse(bytes);
    documents[name] = document;
    assert.deepEqual(document.summary, comparison.summary, name);
    assert.equal(document.summary.MISMATCH, 0, name);
    assert.equal(document.summary.UNKNOWN, 0, name);
    assert.equal(document.corpusSha256, followup.corpusSha256);
    assert.equal(
      Object.values(document.summary).reduce((a, b) => a + b, 0),
      78,
    );
  }
  // 15 rows of the run comparison and 42 of each strict comparison carry a known difference
  assert.equal(record.followUpComparisons.followUpRunVsRun.summary.KNOWN_DIFFERENCE, 15);
  assert.equal(record.followUpComparisons.followUpStrictVsRun1.summary.KNOWN_DIFFERENCE, 42);
  assert.equal(record.followUpComparisons.followUpStrictVsRun2.summary.KNOWN_DIFFERENCE, 42);
  // the three differences, and the rows each names (the other rows of the corpus match)
  assert.deepEqual(record.followUpKnownDifferences.entries, [
    "KD-SAFETY-ORIGIN-REDIRECT",
    "KD-DEFAULT-404-BODY",
    "KD-AUTH-HANDLER-PAGE",
    "KD-BROTLI",
    "KD-GZIP-LENGTH",
  ]);
  const known = Object.fromEntries(entries.map((entry) => [entry.id, entry]));
  assert.equal(known["KD-SAFETY-ORIGIN-REDIRECT"].rows.length, 15);
  assert.equal(known["KD-DEFAULT-404-BODY"].rows.length, 17);
  assert.deepEqual(known["KD-AUTH-HANDLER-PAGE"].rows, [
    "v11.auth-handler",
    "v11.auth-handler-query",
  ]);
  assert.deepEqual(known["KD-BROTLI"].rows, [
    "v14.identity-browser",
    "v14.free-browser",
    "v15.ae-browser",
  ]);
  assert.equal(known["KD-GZIP-LENGTH"].rows.length, 5);
  assert.equal(known["KD-GZIP-LENGTH"].gzipLengthBound, 8);
  assert.match(known["KD-GZIP-LENGTH"].authority, /coordinator ruling 27 \(2026-11-12\)/);
  for (const document of Object.values(documents)) {
    for (const row of document.rows.filter((r) => r.status === "KNOWN_DIFFERENCE")) {
      const named = entries.filter((entry) => entry.rows.includes(row.id)).map((entry) => entry.id);
      assert.deepEqual(
        row.known.map((k) => k.entry).filter((id) => named.includes(id)).length > 0,
        true,
        row.id,
      );
    }
  }
  // every condition the follow-up rows belong to cites the two recordings and the comparisons
  const cited = record.conditions.filter((condition) => condition.followUpEvidence);
  assert.deepEqual(
    cited.map((condition) => condition.conditionId),
    [
      "HOSTING/static-files",
      "HOSTING/redirects",
      "HOSTING/reserved-paths",
      "HOSTING/not-found",
      "HOSTING/compression-vary",
    ],
  );
  let requests = 0;
  for (const condition of cited) {
    const evidence = condition.followUpEvidence;
    assert.equal(evidence.corpus, followup.corpusId);
    assert.deepEqual(
      evidence.productionEvidence.map(({ alias, fixturePath, fixtureSha256 }) => ({
        alias,
        fixturePath,
        fixtureSha256,
      })),
      record.followUpRecordings.map(({ alias, fixturePath, fixtureSha256 }) => ({
        alias,
        fixturePath,
        fixtureSha256,
      })),
    );
    requests += evidence.requests;
    for (const [name, document] of Object.entries(documents)) {
      const verdicts = evidence.followUpConditions.map((key) => document.conditions[key]);
      assert.ok(
        verdicts.every((verdict) => verdict.closable),
        `${condition.conditionId} ${name}`,
      );
      assert.equal(
        evidence.comparisons[name].rows,
        verdicts.reduce((sum, verdict) => sum + verdict.rows, 0),
      );
      assert.equal(
        evidence.comparisons[name].knownDifferenceRows,
        verdicts.reduce((sum, verdict) => sum + verdict.knownDifferenceRows, 0),
      );
    }
    for (const id of evidence.knownDifferences) assert.ok(known[id], id);
  }
  assert.equal(requests, 78, "every follow-up row belongs to exactly one condition");
  const limits = record.limitations.join("\n");
  for (const text of [
    "KD-GZIP-LENGTH",
    "a case-sensitive substring",
    "11 to 99 bytes",
    "ten bytes production sent",
  ]) {
    assert.ok(limits.includes(text) || record.followUps.join("\n").includes(text), text);
  }
});

test("the follow-up comparisons are built from the right recordings: each strict document names its own run, and the known differences apply", async () => {
  // run 1's rows stand in for a local answer: the host of a Location differs from run 2's, a known difference
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const directory = mkdtempSync(join(tmpdir(), "followup-evidence-"));
  const local = join(directory, "local.json");
  writeFileSync(local, await bytesOf(record.followUpRecordings[0].fixturePath));
  const documents = await followupComparisons(local);
  assert.deepEqual(Object.keys(documents), [
    FOLLOWUP_FILES.runs,
    FOLLOWUP_FILES.strict1,
    FOLLOWUP_FILES.strict2,
  ]);
  const shaOf = async (path) => sha(await bytesOf(path));
  const run1 = await shaOf(record.followUpRecordings[0].fixturePath);
  const run2 = await shaOf(record.followUpRecordings[1].fixturePath);
  assert.equal(documents[FOLLOWUP_FILES.runs].inputs.a, run1);
  assert.equal(documents[FOLLOWUP_FILES.runs].inputs.b, run2);
  assert.equal(documents[FOLLOWUP_FILES.strict1].inputs.a, run1);
  assert.equal(documents[FOLLOWUP_FILES.strict2].inputs.a, run2);
  for (const name of [FOLLOWUP_FILES.strict1, FOLLOWUP_FILES.strict2]) {
    assert.equal(documents[name].inputs.b, null, "the local side names no digest");
    assert.equal(documents[name].comparison, "production-vs-local");
  }
  assert.equal(documents[FOLLOWUP_FILES.runs].comparison, "run-vs-run");
  // a row whose Location host or ETag suffix is replaced counts as known even when both sides agree:
  // run 1 against itself has the 15 Location rows and the 3 Brotli rows; run 2 differs in the hosts too
  assert.equal(documents[FOLLOWUP_FILES.strict1].summary.MISMATCH, 0);
  assert.equal(documents[FOLLOWUP_FILES.strict2].summary.MISMATCH, 0);
  assert.equal(documents[FOLLOWUP_FILES.strict2].summary.KNOWN_DIFFERENCE, 18);
  assert.equal(documents[FOLLOWUP_FILES.runs].summary.KNOWN_DIFFERENCE, 15);
  assert.equal(documents[FOLLOWUP_FILES.strict1].summary.KNOWN_DIFFERENCE, 18);
  assert.deepEqual(
    documents[FOLLOWUP_FILES.runs].knownDifferences.map((entry) => entry.id),
    ["KD-SAFETY-ORIGIN-REDIRECT"],
  );
});
