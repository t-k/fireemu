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
export const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** A candidate inventory, never a promotion operation or an acceptance of differences. */
export function validate(record, corpus, fixtureBytes) {
  assert.equal(record.parent, "FUNCTIONS-PYTHON");
  assert.equal(record.parentStatus, "IMPLEMENTING", "parent must remain pending");
  assert.deepEqual(
    record.recordingPolicy,
    { observedPasses: 1, requiredPasses: 2, waiver: null },
    "one pass is not a waiver",
  );
  assert.equal(record.closureReview.decision, "PENDING");
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
    record.conditions.map((c) => c.conditionId),
    families.map((f) => `FUNCTIONS-PYTHON/${f}`),
    "exact condition inventory",
  );
  assert.deepEqual(
    corpus.conditions.map((c) => c.id),
    record.conditions.map((c) => c.conditionId),
  );
  assert.equal(corpus.fixtureSha256, digest(fixtureBytes), "fixture digest");
  const fixture = JSON.parse(fixtureBytes);
  assert.deepEqual(
    fixture.observations.map((r) => r.condition),
    families,
    "fixture condition inventory",
  );
  for (const [i, row] of fixture.observations.entries()) {
    const condition = record.conditions[i];
    assert.equal(
      condition.status,
      i === 6 ? "OPEN" : i === 7 ? "NOT_COMPARED" : "PRODUCTION_RECORDED",
      "no verified condition",
    );
    assert.deepEqual(condition.generations, [2]);
    assert.deepEqual(condition.profiles, { strict: "PENDING_SCOPE", emulator: "PENDING_SCOPE" });
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
    assert.equal(d.status, "PENDING", "difference not accepted");
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
