import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/FUNCTIONS-HTTP.json", import.meta.url),
);

// The frozen inventory changes only after a reviewed acceptance gap or a new production mismatch.
const requiredConditions = new Set([
  "FUNCTIONS-HTTP/http-method-path-query",
  "FUNCTIONS-HTTP/http-request-headers",
  "FUNCTIONS-HTTP/http-request-bodies",
  "FUNCTIONS-HTTP/http-response-status-headers",
  "FUNCTIONS-HTTP/http-large-response",
  "FUNCTIONS-HTTP/http-streaming",
  "FUNCTIONS-HTTP/http-cors-preflight",
  "FUNCTIONS-HTTP/http-throw",
  "FUNCTIONS-HTTP/http-timeout",
  "FUNCTIONS-HTTP/http-no-response",
  "FUNCTIONS-HTTP/callable-success-envelope",
  "FUNCTIONS-HTTP/callable-https-errors",
  "FUNCTIONS-HTTP/callable-malformed-requests",
  "FUNCTIONS-HTTP/callable-auth-context",
  "FUNCTIONS-HTTP/callable-auth-refusal",
  "FUNCTIONS-HTTP/callable-streaming",
  "FUNCTIONS-HTTP/public-invocation",
  "FUNCTIONS-HTTP/final-artifact-regression",
  "FUNCTIONS-HTTP/closure-review",
]);

const statuses = new Set([
  "PENDING_CORPUS",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
]);

const requiredCases = {
  "http-method-path-query": ["GET", "POST", "HEAD", "nested-path", "repeated-query-key"],
  "http-request-headers": [
    "x-forwarded-for",
    "x-forwarded-proto",
    "function-execution-id-presence",
  ],
  "http-request-bodies": ["json", "raw-text", "form-urlencoded", "malformed-json"],
  "http-response-status-headers": ["custom-status", "custom-header"],
  "http-large-response": ["one-mib-response-length-and-sha256"],
  "http-streaming": ["ordered-chunks-before-completion", "client-disconnect"],
  "http-throw": ["synchronous-throw", "rejected-promise"],
  "http-timeout": ["handler-exceeds-one-second-timeout"],
  "http-no-response": ["handler-returns-without-sending-response"],
  "callable-success-envelope": ["object-result", "scalar-result", "null-result"],
  "callable-malformed-requests": ["wrong-method", "wrong-content-type", "missing-data"],
  "callable-auth-context": ["no-authorization", "valid-project-id-token", "uid-and-claims"],
  "callable-auth-refusal": ["malformed-bearer", "invalid-signature", "expired-id-token"],
  "callable-streaming": ["send-chunk-order", "final-result", "client-disconnect"],
  "public-invocation": [
    "http-without-cloud-run-credentials",
    "callable-without-cloud-run-credentials",
  ],
};

const httpsErrorCodes = new Set([
  "ok",
  "cancelled",
  "unknown",
  "invalid-argument",
  "deadline-exceeded",
  "not-found",
  "already-exists",
  "permission-denied",
  "resource-exhausted",
  "failed-precondition",
  "aborted",
  "out-of-range",
  "unimplemented",
  "internal",
  "unavailable",
  "data-loss",
  "unauthenticated",
]);

const readRepo = (path) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`../../${path}`, import.meta.url)), "utf8"));

test("FUNCTIONS-HTTP closure keeps every declared condition and scope decision", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  assert.equal(closure.parent, "FUNCTIONS-HTTP");
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  assert.equal(closure.oracle.project, "fireemu-oracle-query");
  assert.equal(closure.oracle.region, "us-central1");
  assert.ok(["IMPLEMENTING", "COMPAT_VERIFIED"].includes(closure.parentStatus));
  assert.ok(["PENDING", "APPROVED"].includes(closure.closureReview.decision));

  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(ids.length, new Set(ids).size, "condition IDs must be unique");
  assert.deepEqual(new Set(ids), requiredConditions);
  for (const [suffix, cases] of Object.entries(requiredCases)) {
    const condition = closure.conditions.find(
      ({ conditionId }) => conditionId === `FUNCTIONS-HTTP/${suffix}`,
    );
    assert.ok(condition, suffix);
    for (const name of cases) assert.ok(condition.cases.includes(name), `${suffix}: ${name}`);
  }
  const errorCases = closure.conditions.find(
    ({ conditionId }) => conditionId === "FUNCTIONS-HTTP/callable-https-errors",
  ).cases;
  assert.ok(errorCases.includes("details"));
  assert.ok(errorCases.includes("unhandled-error"));
  assert.deepEqual(
    new Set(errorCases.filter((name) => httpsErrorCodes.has(name))),
    httpsErrorCodes,
  );
  assert.deepEqual(
    new Set(closure.scopeDecisions.map(({ id }) => id)),
    new Set(["H1", "H2", "H3", "H4", "H5", "H6"]),
  );
  for (const decision of closure.scopeDecisions) {
    assert.ok(decision.decision && decision.rationale, decision.id);
    assert.ok(["PROPOSED", "FROZEN"].includes(decision.status), decision.id);
  }

  for (const condition of closure.conditions) {
    const label = condition.conditionId;
    assert.ok(typeof condition.source === "string" && condition.source.length > 0, label);
    assert.ok(Array.isArray(condition.recipeIds) && condition.recipeIds.length > 0, label);
    assert.ok(
      condition.recipeIds.every((id) => id.startsWith("functions-http/")),
      label,
    );
    assert.ok(statuses.has(condition.status), `${label}: unknown status`);
    if (condition.status !== "VERIFIED") continue;

    const runs = condition.evidence?.productionRecordings ?? [];
    assert.equal(runs.length, 2, `${label}: exactly two production recordings`);
    assert.notEqual(runs[0].recordedAt, runs[1].recordedAt, `${label}: distinct recordings`);
    for (const run of runs) {
      assert.equal(run.project, "fireemu-oracle-query", label);
      assert.match(run.corpusDigest, /^[0-9a-f]{64}$/, label);
    }
    assert.equal(runs[0].corpusDigest, runs[1].corpusDigest, label);
    assert.match(condition.evidence.finalArtifactSha256, /^[0-9a-f]{64}$/, label);
    const comparison = readRepo(condition.evidence.comparisonPath);
    assert.equal(comparison.artifactSha256, condition.evidence.finalArtifactSha256, label);
    const rows = comparison.rows.filter(({ row }) =>
      condition.recipeIds.some((recipe) =>
        recipe.endsWith("/")
          ? row.startsWith(recipe)
          : row === recipe || row.startsWith(`${recipe}#`),
      ),
    );
    assert.ok(rows.length > 0, `${label}: has comparison rows`);
    assert.ok(
      rows.every(({ status }) => status === "MATCH"),
      `${label}: every row matches`,
    );
    if (label === "FUNCTIONS-HTTP/closure-review") {
      assert.equal(closure.closureReview.decision, "APPROVED", label);
      assert.equal(closure.closureReview.finalArtifactSha256, comparison.artifactSha256, label);
    }
  }
  if (closure.parentStatus === "COMPAT_VERIFIED") {
    assert.ok(closure.conditions.every(({ status }) => status === "VERIFIED"));
    assert.ok(closure.scopeDecisions.every(({ status }) => status === "FROZEN"));
    assert.equal(closure.closureReview.decision, "APPROVED");
  }
});
