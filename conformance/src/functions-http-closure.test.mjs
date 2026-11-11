import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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

test("FN-HTTP-001 reflects the approved Functions Origin policy in the generated inventory", () => {
  const requirement = readRepo("verification/requirements/requirements.json").requirements.find(
    ({ id }) => id === "FN-HTTP-001",
  );
  assert.ok(requirement);
  assert.doesNotMatch(requirement.statement, /refus\w*[^.]*non-loopback\s+Origin/i);
  assert.ok(
    requirement.artifacts.integration.includes(
      "crates/fireemu-adapter-functions/tests/app_check_callable.rs",
    ),
  );
  const inventory = readFileSync(
    fileURLToPath(new URL("../../docs/compatibility/requirements.md", import.meta.url)),
    "utf8",
  );
  assert.ok(inventory.includes(requirement.statement));
});

test("FUNCTIONS-HTTP closure keeps every declared condition and scope decision", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  assert.equal(closure.parent, "FUNCTIONS-HTTP");
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  assert.equal(closure.oracle.project, "fireemu-oracle-query");
  assert.equal(closure.oracle.region, "us-central1");
  assert.equal(closure.inventoryStatus, "FROZEN");
  assert.equal(closure.frozenOn, "2026-09-25");
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
    assert.equal(decision.status, "FROZEN", decision.id);
    assert.ok(decision.decidedBy && decision.decidedOn && decision.decisionRef, decision.id);
  }
  assert.match(
    closure.scopeDecisions.find(({ id }) => id === "H3").rationale,
    /candidate for a future parent/,
  );

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
    assert.deepEqual(
      runs.map(({ pass }) => pass),
      [1, 2],
      `${label}: distinct corpus passes`,
    );
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

// ---- closure amendment A1 (2026-11-12): the callable wrapper's envelope for a refused credential ------------

const sha256Path = (path) =>
  createHash("sha256")
    .update(readFileSync(fileURLToPath(new URL(`../../${path}`, import.meta.url))))
    .digest("hex");

test("amendment A1: the callable-auth-refusal rows are the two re-recordings, the September recording is history", () => {
  const closure = readRepo("spec/compatibility/closure/FUNCTIONS-HTTP.json");
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FUNCTIONS-HTTP/callable-auth-refusal",
  );
  const evidence = condition.evidence;
  const comparison = readRepo(evidence.comparisonPath);
  const production = readRepo(evidence.productionRecordingPath);
  assert.equal(evidence.comparisonSha256, sha256Path(evidence.comparisonPath));
  assert.equal(evidence.productionRecordingSha256, sha256Path(evidence.productionRecordingPath));
  assert.equal(comparison.productionRecording.sha256, evidence.productionRecordingSha256);
  assert.equal(comparison.artifactSha256, evidence.finalArtifactSha256);
  assert.equal(comparison.sourceCommit, evidence.sourceCommit);
  assert.equal(comparison.strictRecordingSha256, evidence.strictRecordingSha256);
  assert.equal(evidence.rows.MATCH, 3);
  assert.deepEqual(
    comparison.rows.map(({ row, status }) => [row, status]),
    condition.cases.map((name) => [`functions-http/callable/auth-refusal#${name}`, "MATCH"]),
  );
  // Both runs and both passes of the published recording are exactly the compared answers.
  const wrapper = {
    status: 401,
    headers: { "content-type": "application/json; charset=utf-8" },
    body: { error: { message: "Unauthenticated", status: "UNAUTHENTICATED" } },
  };
  for (const row of comparison.rows) {
    assert.deepEqual(row.answer, wrapper, row.row);
    assert.equal(row.productionObservations, 4, row.row);
    const name = row.row.split("#")[1];
    const observed = Object.values(production.runs).flatMap((run) =>
      run.captures.filter(
        (capture) => capture.program.endsWith("/auth-refusal") && capture.caseId === name,
      ),
    );
    assert.equal(observed.length, 4, row.row);
    for (const capture of observed) {
      assert.equal(capture.status, 401, row.row);
      assert.equal(capture.bodyBytes, 66, row.row);
      assert.deepEqual(JSON.parse(capture.bodyText), wrapper.body, row.row);
      assert.equal(capture.headers["content-type"], wrapper.headers["content-type"], row.row);
    }
  }
  assert.equal(evidence.productionRecordings.length, 2);
  assert.equal(evidence.confirmingProductionRecordings.length, 2);
  assert.deepEqual(
    evidence.productionRecordings.map(({ pass }) => pass),
    [1, 2],
  );
  // History: the September evidence is kept whole, and the amendment names what it supersedes.
  const history = evidence.supersededEvidence;
  assert.equal(history.productionRecordings[0].recordedAt, "2026-09-27T13:59:44Z");
  assert.equal(
    history.strictRecordingSha256,
    "92e9ea008073ae16897015e552ae7b58cb1560d2d55de14092c3ca71e8fea39f",
  );
  assert.equal(comparison.supersedes.comparisonPath, history.comparisonPath);
  assert.equal(comparison.supersedes.comparisonSha256, history.comparisonSha256);
  assert.equal(history.comparisonSha256, sha256Path(history.comparisonPath));
  assert.equal(comparison.supersedes.answer.bodyBytes, 294);
  assert.equal(closure.amendments.length, 1);
  assert.equal(closure.amendments[0].conditionId, condition.conditionId);
  assert.equal(closure.amendments[0].comparisonSha256, evidence.comparisonSha256);
  // Every other condition still cites the September comparison and recording.
  for (const other of closure.conditions) {
    if (other.conditionId === condition.conditionId || other.status !== "VERIFIED") continue;
    assert.equal(
      other.evidence.strictRecordingSha256 ??
        "92e9ea008073ae16897015e552ae7b58cb1560d2d55de14092c3ca71e8fea39f",
      "92e9ea008073ae16897015e552ae7b58cb1560d2d55de14092c3ca71e8fea39f",
      other.conditionId,
    );
  }
});
