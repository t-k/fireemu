import assert from "node:assert/strict";
import { createHash } from "node:crypto";

export const families = [
  "firestore-events",
  "pubsub-events",
  "storage-events",
  "eventarc-custom-events",
  "scheduler-events",
  "tasks-events",
  "auth-blocking",
  "deployment",
];
const frameCounts = [3, 4, 2, 3, 2, 2, 1, 0];
const sdkCounts = [2, 2, 1, 1, 1, 1, 0, 0];
/** Fixed recorded inventory of each accepted recording, in alias order. */
const recordingKinds = [
  {
    alias: "pass-1",
    file: "observations.json",
    accounting: {
      recorderRequests: 160,
      cliWriteRows: 28,
      cliWriteAttempts: 44,
      accountedRequests: 204,
    },
    eventFrames: 16,
    functionFrameCategories: 13,
    conditions: families,
    unobserved: [],
  },
  {
    alias: "pass-2",
    file: "observations-pass2.json",
    accounting: {
      recorderRequests: 172,
      cliWriteRows: 26,
      cliWriteAttempts: 42,
      accountedRequests: 214,
    },
    eventFrames: 14,
    functionFrameCategories: 11,
    conditions: families.slice(0, 6),
    unobserved: ["tasks-events"],
  },
  {
    alias: "tasks-pass-2",
    profile: "tasks",
    file: "observations-tasks-pass2.json",
    accounting: {
      recorderRequests: 81,
      cliWriteRows: 10,
      cliWriteAttempts: 12,
      accountedRequests: 93,
    },
    eventFrames: 2,
    functionFrameCategories: 2,
    conditions: ["tasks-events"],
    unobserved: [],
  },
];
export const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

const COMPARISON_PATH = "spec/compatibility/closure/evidence/FUNCTIONS-PYTHON-comparison.json";
const isDigest = (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
const isCommit = (v) => typeof v === "string" && /^[0-9a-f]{40}$/.test(v);
const isText = (v) => typeof v === "string" && v.trim().length > 0;

/** A review that can back a promotion: approved, with every report pinned by digest and commit. */
function assertApprovedReview(review) {
  assert.equal(review.decision, "APPROVED", "a promotion needs an approved review");
  for (const key of ["decidedOn", "decider", "decisionRef"]) assert.ok(isText(review[key]), key);
  assert.ok(isCommit(review.reviewedCommit), "reviewed commit");
  assert.ok(Array.isArray(review.reviews) && review.reviews.length > 0, "recorded reviews");
  for (const r of review.reviews) {
    assert.ok(isText(r.reviewer), "reviewer");
    assert.ok(
      isText(r.reportPath) && !r.reportPath.startsWith("/") && !r.reportPath.includes(".."),
      "review report path",
    );
    assert.ok(isDigest(r.reportSha256), "review report digest");
    assert.ok(isCommit(r.reviewedCommit), "review commit");
    assert.equal(r.outcome, "APPROVED", "review outcome");
  }
}

/**
 * The recorded inventory of the parent. Without an approved review the parent stays
 * IMPLEMENTING and no leaf is VERIFIED; a leaf is VERIFIED only through a review reference
 * naming the digest of an approved review report recorded in the closure (fail closed).
 */
export function validate(record, corpus, fixtureBytes, secondBytes, tasksBytes) {
  assert.equal(record.parent, "FUNCTIONS-PYTHON");
  const promoted = record.parentStatus === "COMPAT_VERIFIED";
  assert.ok(promoted || record.parentStatus === "IMPLEMENTING", "parent status");
  if (promoted) assertApprovedReview(record.closureReview);
  else assert.equal(record.closureReview.decision, "PENDING", "no review, no promotion");
  const reviewRefs = new Set(
    promoted ? record.closureReview.reviews.map((r) => r.reportSha256) : [],
  );
  const entry = record.integratedRegression?.comparisons?.[0];
  assert.ok(
    record.integratedRegression?.comparisons?.length === 1 &&
      entry.path === COMPARISON_PATH &&
      isDigest(entry.sha256) &&
      record.integratedRegression.productionRequests === 0,
    "integrated regression",
  );
  const all = [...record.conditions, ...record.excludedFromParent];
  assert.deepEqual(
    record.scopeDecisions.map((d) => d.id),
    ["PY1", "PY2", "PY3"],
  );
  for (const d of record.scopeDecisions) {
    if (d.status === "PENDING") assert.equal(d.answer, null, d.id);
    else {
      assert.equal(d.status, "ANSWERED", d.id);
      assert.ok(typeof d.answer === "string" && d.answer.length > 0, d.id);
      assert.ok(typeof d.authority === "string" && d.authority.length > 0, d.id);
    }
    assert.ok(d.question && d.recommendation, d.id);
  }
  assert.deepEqual(
    all.map((c) => c.conditionId),
    families.map((f) => `FUNCTIONS-PYTHON/${f}`),
    "exact condition inventory",
  );
  assert.equal(record.conditions.length, 6, "the parent covers the six event families");
  assert.deepEqual(
    corpus.conditions.map((c) => c.id),
    all.map((c) => c.conditionId),
  );
  assert.equal(corpus.fixtureSha256, digest(fixtureBytes), "fixture digest");
  assert.deepEqual(record.recordings, corpus.recordings, "recording provenance inventory");
  assert.ok(
    [1, 2, 3].includes(corpus.recordings.length),
    "one or two independent events recordings and an optional Tasks pass",
  );
  const kinds = recordingKinds.slice(0, corpus.recordings.length);
  assert.deepEqual(
    corpus.recordings.map((r) => r.alias),
    kinds.map((k) => k.alias),
  );
  const allBytes = [fixtureBytes, secondBytes, tasksBytes].slice(0, kinds.length);
  for (const [index, item] of corpus.recordings.entries()) {
    const kind = kinds[index];
    assert.equal(item.fixturePath, `conformance/functions-python/fixtures/${kind.file}`);
    assert.ok(allBytes[index], "recording fixture required");
    assert.equal(item.fixtureSha256, digest(allBytes[index]), "recording fixture digest");
    const observed = JSON.parse(allBytes[index]);
    assert.deepEqual(
      observed.recording,
      {
        alias: item.alias,
        ...(kind.profile ? { profile: kind.profile } : {}),
        accounting: kind.accounting,
        eventFrames: kind.eventFrames,
        functionFrameCategories: kind.functionFrameCategories,
      },
      "recorded accounting and frame inventory",
    );
    assert.deepEqual(
      observed.observations.map((r) => r.condition),
      kind.conditions,
    );
    for (const row of observed.observations) {
      const i = families.indexOf(row.condition);
      if (i > 5) continue;
      const present = !kind.unobserved.includes(row.condition);
      assert.equal(row.coverage, present ? "RECORDED" : "UNOBSERVED");
      assert.equal(row.observedPasses, present ? 1 : 0);
      assert.equal(row.frames.length, present ? frameCounts[i] : 0);
      assert.equal(row.sdkCases.length, present ? sdkCounts[i] : 0);
      assert.equal(row.origin, "masked-production-projection");
      if (!present) assert.ok(row.reason);
      for (const frame of row.frames)
        if (frame.request) {
          assert.equal(frame.request.method, "POST");
          assert.equal(frame.request.path, "/");
          assert.ok(frame.request.headerNames.includes("authorization"));
          assert.equal(frame.request.headers.authorization, undefined);
        }
      for (const c of row.sdkCases) {
        assert.equal(c.origin, "observed-sdk-projection");
        assert.equal(c.inputIdentity, "synthetic");
        assert.ok(Object.keys(c.expected).length);
      }
      if (row.condition === "eventarc-custom-events") assert.equal(row.wholeSecondSdkFrames, 0);
    }
  }
  const familyPasses = [];
  for (let i = 0; i < 6; i += 1) {
    const aliases = kinds
      .filter((k) => k.conditions.includes(families[i]) && !k.unobserved.includes(families[i]))
      .map((k) => k.alias);
    assert.deepEqual(record.conditions[i].recordingAliases, aliases, "family recording provenance");
    assert.equal(record.conditions[i].observedPasses, aliases.length, "family recording count");
    // A two-pass family states its comparison; the closure test recomputes it from the fixtures.
    if (aliases.length === 2)
      assert.ok(
        ["MATCH", "MATCH_LAYOUT"].includes(record.conditions[i].passComparison),
        "pass comparison",
      );
    else assert.equal(record.conditions[i].passComparison, undefined, "pass comparison");
    familyPasses.push(aliases.length);
  }
  for (const condition of record.excludedFromParent)
    assert.equal(condition.passComparison, undefined, "pass comparison");
  assert.deepEqual(
    record.recordingPolicy,
    { observedPasses: Math.min(...familyPasses), requiredPasses: 2, waiver: null },
    "independent recordings are not a waiver",
  );
  const fixture = JSON.parse(fixtureBytes);
  assert.deepEqual(
    fixture.observations.map((r) => r.condition),
    families,
    "fixture condition inventory",
  );
  for (const [i, row] of fixture.observations.entries()) {
    const condition = all[i];
    if (i < 6) {
      assert.equal(
        condition.status,
        promoted ? "VERIFIED" : "PRODUCTION_RECORDED",
        "a leaf is VERIFIED only with the approved parent review",
      );
      if (promoted) {
        assert.ok(reviewRefs.has(condition.reviewRef), "verified leaf needs a review reference");
        assert.equal(condition.observedPasses, 2, "verified leaf has two passes");
        assert.ok(["MATCH", "MATCH_LAYOUT"].includes(condition.passComparison), "pass comparison");
      } else assert.equal(condition.reviewRef, undefined, "no review reference without a review");
    } else {
      assert.equal(condition.status, i === 6 ? "OPEN" : "NOT_COMPARED", "excluded condition");
      assert.ok(isText(condition.reason) && condition.reason.length > 40, "exclusion reason");
      assert.match(condition.authority ?? "", /owner ledger 2357/, "exclusion authority");
      assert.equal(condition.reviewRef, undefined, "excluded condition is never reviewed");
    }
    assert.deepEqual(condition.generations, [2]);
    assert.deepEqual(condition.profiles, {
      strict: "LIMITED_TO_RECORDED_CASES",
      emulator: "NO_PRODUCTION_CLAIM",
    });
    assert.deepEqual(condition.recipeIds, [`functions-python/${row.condition}`]);
    assert.equal(condition.fixturePath, corpus.fixturePath);
    assert.equal(condition.fixtureSha256, digest(fixtureBytes), "condition fixture digest");
    assert.equal(row.origin, "masked-production-projection");
    assert.equal(row.observedPasses, 1);
    assert.equal(row.frames.length, frameCounts[i], `${row.condition} recorded frame count`);
    assert.equal(row.sdkCases.length, sdkCounts[i], `${row.condition} SDK case count`);
    assert.equal(corpus.conditions[i].frames, frameCounts[i]);
    assert.equal(corpus.conditions[i].sdkCases, sdkCounts[i]);
    for (const frame of row.frames) {
      if (frame.request) {
        assert.equal(frame.request.method, "POST");
        assert.equal(frame.request.path, "/");
        assert.equal(
          frame.request.headerNames.includes("authorization"),
          i !== 6,
          "recorded authorization presence",
        );
        assert.equal(frame.request.headers.authorization, undefined, "no credential values");
      }
    }
    for (const c of row.sdkCases) {
      assert.equal(c.origin, "observed-sdk-projection");
      assert.equal(c.inputIdentity, "synthetic");
      assert.ok(Object.keys(c.expected).length > 0, "semantic SDK projection");
    }
  }
  assert.equal(fixture.observations[3].wholeSecondSdkFrames, 0, "recorded SDK absence");
  assert.equal(fixture.observations[6].clientStatus, 503, "recorded blocking failure");
  assert.equal(fixture.observations[6].sdkEventObserved, false, "blocking success unobserved");
  assert.equal(fixture.observations[7].localComparison, false, "deployment not compared");
  assert.equal(fixture.observations[7].observedFunctionCount, 13);
  assert.deepEqual(
    record.declaredDifferences.map(({ id, profiles, fields }) => ({ id, profiles, fields })),
    corpus.replayDifferences,
    "exact replay difference inventory",
  );
  for (const d of record.declaredDifferences) {
    assert.equal(d.status, "DECLARED_UNVERIFIED", "difference remains unverified");
    assert.ok(d.fields.length && d.profiles.length && d.reason);
    assert.ok(
      d.fields.every((p) => !p.includes("*")),
      "no wildcard masks",
    );
  }
  return fixture;
}

/** Compare the complete supplied projection; extra fields and presence changes are differences. */
export function compare(expected, actual, profile, declarations = []) {
  assert.ok(["strict", "emulator"].includes(profile), "known profile");
  const changes = [];
  function visit(a, b, path) {
    if (
      a !== null &&
      b !== null &&
      typeof a === "object" &&
      typeof b === "object" &&
      Array.isArray(a) === Array.isArray(b)
    ) {
      for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
        const next = path ? `${path}.${k}` : k;
        if (!Object.hasOwn(a, k) || !Object.hasOwn(b, k)) changes.push(next);
        else visit(a[k], b[k], next);
      }
    } else if (!Object.is(a, b)) changes.push(path);
  }
  visit(expected, actual, "");
  return changes.map((path) => ({
    path,
    status: declarations.some((d) => d.profiles.includes(profile) && d.fields.includes(path))
      ? "PENDING_DIFFERENCE"
      : "DIFF",
  }));
}
