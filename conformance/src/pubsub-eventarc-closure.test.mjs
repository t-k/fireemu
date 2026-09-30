import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

const root = new URL("../../", import.meta.url);
const readRepo = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
const sha256 = (path) =>
  createHash("sha256")
    .update(readFileSync(new URL(path, root)))
    .digest("hex");
const hash = /^[a-f0-9]{64}$/;
const statuses = new Set([
  "PENDING_CORPUS",
  "PRODUCTION_RECORDED",
  "MISMATCH",
  "VERIFIED",
  "PENDING_REVIEW",
  "OUT_OF_SCOPE_OBSERVED",
]);

const required = {
  PUBSUB: {
    "topic-lifecycle": [
      "create-get-list-delete",
      "duplicate-create",
      "delete-topic-with-subscription",
    ],
    "resource-names": ["valid-name", "invalid-name", "path-body-mismatch"],
    "list-pagination": ["page-traversal", "invalid-page-token"],
    "subscription-lifecycle": ["default-ack-deadline", "explicit-ack-deadline", "missing-topic"],
    "subscription-configuration": [
      "message-retention-duration",
      "retain-acked-messages",
      "atomic-field-mask-update",
    ],
    "push-configuration": [
      "create-push-config",
      "get-push-config",
      "modify-push-config",
      "invalid-push-config",
    ],
    "publish-wire": [
      "binary-data",
      "attributes-only",
      "ordering-key",
      "publish-pull-id-correlation",
    ],
    "publish-limits": ["request-bytes-boundary", "batch-count-boundary", "attribute-size-boundary"],
    "pull-ack": ["publish-pull-ack", "unknown-ack-id", "stale-ack-id"],
    "nack-deadline-redelivery": [
      "nack-zero",
      "deadline-extension",
      "deadline-expiry",
      "redelivery-id-correlation",
    ],
    "filter-evaluation": ["match", "nonmatch", "missing-attribute", "invalid-filter"],
    ordering: ["single-key-sequence", "nack-blocks-key", "ack-unblocks-key"],
    "retry-dead-letter": [
      "policy-round-trip",
      "delivery-attempt-without-policy",
      "eventual-forwarding",
    ],
    "streaming-pull": [
      "opening-frame",
      "in-stream-ack",
      "in-stream-nack",
      "flow-control",
      "client-cancel",
      "half-close",
    ],
    "snapshot-seek": [
      "snapshot-lifecycle",
      "post-snapshot-publication",
      "seek-time-retain-true",
      "seek-time-retain-false",
    ],
    "errors-authentication": ["missing-resource", "invalid-argument", "no-token", "invalid-token"],
    "final-artifact-regression": ["strict-production", "emulator-official", "complete-case-set"],
    "closure-review": ["independent-approval"],
  },
  EVENTARC: {
    "channel-lifecycle": ["providerless-create-capability", "get-channel", "delete-owned-channel"],
    "publish-envelope": [
      "single-event",
      "multiple-events",
      "required-attributes",
      "invalid-timestamp",
    ],
    "publish-content": [
      "json-object",
      "json-null",
      "text",
      "binary-data",
      "invalid-json",
      "oneof-collision",
    ],
    "admin-sdk-publish": [
      "full-channel",
      "relative-channel",
      "default-channel",
      "generated-metadata",
      "allowed-event-types",
    ],
    "publish-limits": ["request-bytes-boundary", "event-count-boundary", "event-bytes-boundary"],
    "custom-handler-envelope": [
      "required-attributes",
      "optional-attribute-absence",
      "extension-attributes",
      "binary-data",
    ],
    "trigger-filters": [
      "type",
      "source",
      "extension-attribute",
      "nonmatch",
      "channel-isolation",
      "unsupported-filter-refusal",
    ],
    "delivery-retry-identity": ["fail-then-succeed", "stable-id-and-data"],
    "errors-authentication": ["missing-channel", "invalid-event", "no-token", "invalid-token"],
    "final-artifact-regression": ["strict-production", "emulator-official", "complete-case-set"],
    "closure-review": ["independent-approval"],
  },
};

function assertRecordings(condition, parent) {
  const runs = condition.evidence?.productionRecordings;
  assert.equal(runs?.length, 2, `${condition.conditionId}: two production recordings`);
  assert.deepEqual(
    runs.map(({ pass }) => pass),
    [1, 2],
  );
  for (const run of runs) {
    assert.equal(run.project, "fireemu-oracle-idp");
    assert.match(run.corpusDigest, hash);
    assert.match(run.recordingSha256, hash);
    assert.ok(Number.isFinite(Date.parse(run.recordedAt)), "recording time");
    assert.equal(sha256(run.recordingPath), run.recordingSha256);
    const recording = readRepo(run.recordingPath);
    assert.equal(recording.parent, parent);
    assert.equal(recording.corpusDigest, run.corpusDigest);
    assert.equal(recording.pass, run.pass);
  }
  assert.equal(runs[0].corpusDigest, runs[1].corpusDigest);
  return runs;
}

function assertClosure(closure) {
  const { parent } = closure;
  assert.ok(Object.hasOwn(required, parent));
  assert.equal(closure.schemaVersion, 1);
  assert.equal(closure.inventoryStatus, "FROZEN");
  assert.equal(closure.frozenOn, "2026-09-30");
  assert.equal(closure.oracleTrack, "disposable-sandbox");
  assert.equal(closure.oracle.project, "fireemu-oracle-idp");
  assert.equal(closure.oracle.region, "us-central1");
  assert.ok(["IMPLEMENTING", "COMPAT_VERIFIED"].includes(closure.parentStatus));
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(new Set(ids).size, ids.length, "duplicate condition");
  assert.deepEqual(
    new Set(ids),
    new Set(Object.keys(required[parent]).map((id) => `${parent}/${id}`)),
  );
  const scopeIds =
    parent === "PUBSUB" ? ["P1", "P2", "P3", "P4", "P5", "P6"] : ["E1", "E2", "E3", "E4"];
  assert.deepEqual(
    closure.scopeDecisions.map(({ id }) => id),
    scopeIds,
  );
  for (const decision of closure.scopeDecisions) {
    assert.equal(decision.status, "FROZEN");
    assert.ok(decision.decision && decision.rationale && decision.decidedBy);
    assert.equal(decision.decidedOn, "2026-09-30");
    assert.match(decision.decisionRef, /PUBSUB and EVENTARC scope: coordinator rulings/);
  }
  if (parent === "PUBSUB") {
    assert.match(
      closure.scopeDecisions.find(({ id }) => id === "P4").decision,
      /configuration API/,
    );
    assert.match(closure.scopeDecisions.find(({ id }) => id === "P4").decision, /never publish/i);
    assert.match(
      closure.scopeDecisions.find(({ id }) => id === "P5").decision,
      /IAM permission refusal.*outside/i,
    );
  } else {
    assert.match(closure.scopeDecisions.find(({ id }) => id === "E1").decision, /provider-less/);
    assert.match(closure.scopeDecisions.find(({ id }) => id === "E1").decision, /record.*outside/i);
  }

  for (const condition of closure.conditions) {
    const suffix = condition.conditionId.slice(parent.length + 1);
    assert.ok(statuses.has(condition.status), condition.conditionId);
    assert.ok(condition.source);
    assert.equal(condition.recipeIds.length, 1);
    assert.ok(condition.recipeIds[0].startsWith(`${parent.toLowerCase()}/`));
    assert.equal(new Set(condition.cases).size, condition.cases.length, "duplicate case");
    for (const name of required[parent][suffix])
      assert.ok(condition.cases.includes(name), `${suffix}: ${name}`);
    const local = ["final-artifact-regression", "closure-review"].includes(suffix);
    const expectedTransports = local
      ? ["artifact"]
      : parent === "PUBSUB" && suffix !== "streaming-pull"
        ? ["rest", "grpc"]
        : parent === "PUBSUB"
          ? ["grpc"]
          : ["rest"];
    assert.deepEqual(condition.transports, expectedTransports, condition.conditionId);
    if (condition.status === "OUT_OF_SCOPE_OBSERVED") {
      assert.equal(
        condition.conditionId,
        "EVENTARC/channel-lifecycle",
        "only the approved conditional lifecycle exclusion",
      );
      const runs = assertRecordings(condition, parent);
      assert.ok(runs.every(({ operationSupported }) => operationSupported === false));
      assert.equal(condition.evidence.scopeReview.decision, "APPROVED");
      assert.ok(condition.evidence.scopeReview.decisionRef);
      continue;
    }
    if (condition.status !== "VERIFIED") {
      if (condition.status === "PENDING_CORPUS")
        assert.ok(!condition.evidence, "pending corpus must not claim evidence");
      if (condition.status === "PRODUCTION_RECORDED") assertRecordings(condition, parent);
      continue;
    }
    assertRecordings(condition, parent);
    const { evidence } = condition;
    assert.match(evidence.finalArtifactSha256, hash);
    assert.match(evidence.comparisonSha256, hash);
    assert.equal(sha256(evidence.comparisonPath), evidence.comparisonSha256);
    const comparison = readRepo(evidence.comparisonPath);
    assert.equal(comparison.parent, parent);
    assert.equal(comparison.artifactSha256, evidence.finalArtifactSha256);
    for (const name of condition.cases) {
      for (const transport of condition.transports) {
        const matches = comparison.rows.filter(
          ({ row, transport: actual }) =>
            row === `${condition.recipeIds[0]}#${name}` && actual === transport,
        );
        assert.equal(
          matches.length,
          1,
          `${condition.conditionId}: ${name}/${transport} must appear exactly once`,
        );
        assert.equal(matches[0].status, "MATCH");
      }
    }
    if (suffix === "closure-review") {
      assert.equal(closure.closureReview.decision, "APPROVED");
      assert.equal(closure.closureReview.finalArtifactSha256, evidence.finalArtifactSha256);
      assert.equal(closure.closureReview.comparisonSha256, evidence.comparisonSha256);
    }
  }
  if (closure.parentStatus === "COMPAT_VERIFIED") {
    assert.ok(
      closure.conditions.every(({ status }) =>
        ["VERIFIED", "OUT_OF_SCOPE_OBSERVED"].includes(status),
      ),
      "all required conditions must be verified",
    );
    assert.equal(closure.closureReview.decision, "APPROVED");
    const artifacts = closure.conditions
      .filter(({ status }) => status === "VERIFIED")
      .map(({ evidence }) => evidence.finalArtifactSha256);
    assert.equal(new Set(artifacts).size, 1, "same final artifact for every condition");
  }
}

for (const parent of Object.keys(required)) {
  const path = `spec/compatibility/closure/${parent}.json`;
  test(`${parent} has its approved frozen closure inventory`, () => {
    assert.ok(existsSync(new URL(path, root)), `${parent} closure inventory is missing`);
    assertClosure(readRepo(path));
  });
  test(`${parent} cannot promote incomplete evidence`, () => {
    assert.ok(existsSync(new URL(path, root)), `${parent} closure inventory is missing`);
    const closure = readRepo(path);
    closure.parentStatus = "COMPAT_VERIFIED";
    closure.conditions[0].status = "PENDING_CORPUS";
    delete closure.conditions[0].evidence;
    assert.throws(() => assertClosure(closure), /all required conditions/);
  });
}
