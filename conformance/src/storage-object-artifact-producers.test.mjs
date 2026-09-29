import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
import {
  createStage3RequestCounter,
  claimStage3RecipeContext,
} from "./storage-object/request-counter.mjs";
import { createStage3WireBudget } from "./storage-object/wire-budget.mjs";
import {
  createProductionArtifactProfile,
  sanitizeProductionArtifact,
} from "./storage-object/production-artifact-policy.mjs";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";

const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const resources = {
  projectNumber: "123456789012",
  apiKeyResource: "projects/123456789012/locations/global/keys/fixture-key",
  rulesetResource: "projects/example-project/rulesets/fixture-ruleset",
};
const hash = (value) => createHash("sha256").update(value).digest("hex");
function withProfile(action) {
  const registry = createProductionSecretRegistry({
    maxValues: 81,
    maxUtf8Bytes: 65536,
    maxIndexNodes: 200000,
    maxScanCodeUnits: 16777216,
  });
  const profile = createProductionArtifactProfile({ plan, resources, secretRegistry: registry });
  try {
    return action({ profile, registry });
  } finally {
    registry.close();
  }
}
function check(kind, value) {
  return withProfile(({ profile, registry }) => {
    const before = JSON.stringify(value),
      result = sanitizeProductionArtifact(profile, { kind, value });
    assert.equal(result?.taskSecretStatus, "AVAILABLE", before);
    assert.equal(result.mode, "TYPED_REDACTED_ARTIFACT");
    assert.equal(result.data.recording, value.recording);
    assert.equal(JSON.stringify(value), before);
    assert.equal(registry.snapshot().closed, false);
    return result;
  });
}

test("actual canonical request counter emits persistable start, reservation and lifecycle DTOs for both recordings", async () => {
  const rows = [];
  const ids = [
    ...buildCorpus({ bucket: plan.bucket, prefix: plan.recordings[0].prefix }).recipes,
    ...buildAuthCorpus({
      projectId: plan.projectId,
      bucket: plan.bucket,
      runId: plan.recordings[0].runId,
    }).recipes,
  ].map((row) => row.id);
  const counter = createStage3RequestCounter(plan, {
    onStart: (row) => rows.push({ kind: "ledger", value: row }),
    onReserve: (row) => rows.push({ kind: "intent", value: row }),
    recipeLifecycle: {
      recipeIds: ids,
      onBegin: (row) => rows.push({ kind: "journal", value: row }),
      onFinish: (row) => rows.push({ kind: "journal", value: row }),
      // This fixture inventories DTOs; it does not supply actual sender terminal evidence.
      verifyTerminal: () => true,
    },
  });
  await counter.start();
  for (const recording of [1, 2]) {
    if (recording === 2) await counter.startNextProductionRecording();
    for (const id of ids) {
      const token = await counter.beginRecipe(id),
        context = claimStage3RecipeContext(token, plan);
      await context.counter.start();
      await context.counter.send("fixture-operation", () => undefined);
      context.counter.beginCleanup();
      context.counter.close();
      await counter.finishRecipe(token);
    }
  }
  counter.close();
  assert.equal(rows.length, 158);
  assert.equal(rows.filter((row) => Object.hasOwn(row.value, "semanticOperationId")).length, 52);
  for (const row of rows) {
    const result = check(row.kind, row.value);
    for (const key of [
      "maxRequests",
      "recordings",
      "estimatedUsd",
      "maxUsdReservation",
      "taskMaxRequests",
      "subjectCapRequests",
      "cleanupReserveRequests",
      "sequence",
      "firstSequence",
      "lastSequence",
      "requests",
      "subject",
      "cleanup",
    ])
      if (Object.hasOwn(row.value, key)) assert.equal(result.data[key], row.value[key]);
  }
});

for (const recording of [1, 2]) {
  const operationId = "r" + recording + "/control/" + hash("fixture-producer");
  const shapes = [
    [
      "control-proof",
      {
        type: "production-control",
        recording,
        phase: "subject",
        slotId: "fixture-control",
        recipeId: "storage-object/auth/firebase-id-token",
        placement: "recipe",
        operationId,
        sequence: 1,
        status: 200,
        bodyByteLength: 2,
        bodySha256: hash("{}"),
      },
    ],
    [
      "owner-proof",
      {
        type: "production-owner",
        recording,
        stage: "initial",
        adcSha256: hash("fixture-adc"),
        adcType: "authorized_user",
        clientId: "fixture.apps.googleusercontent.com",
        principalSha256: hash("fixture-principal"),
        scopeSha256: hash("fixture-scope"),
        accessTokenSha256: hash("fixture-token"),
        accessTokenByteLength: 32,
        exchangeBodySha256: hash("fixture-exchange"),
        tokeninfoBodySha256: hash("fixture-tokeninfo"),
        deadlineMonotonicMs: 100000,
      },
    ],
    [
      "auth-proof",
      {
        type: "production-auth-account",
        recording,
        accountRef: Object.values(
          buildAuthCorpus({
            projectId: plan.projectId,
            bucket: plan.bucket,
            runId: plan.recordings[recording - 1].runId,
          }).recipes[0].accounts,
        )[0].ref,
        stage: "setup",
        ownedUidSha256: hash("fixture-uid"),
        emailSha256: hash("fixture-email"),
        tokenSha256: hash("fixture-id-token"),
        tokenByteLength: 64,
        responseBodySha256: hash("fixture-auth-response"),
        deadlineMonotonicMs: 100000,
      },
    ],
    [
      "auth-proof",
      {
        type: "production-auth-cleanup",
        recording,
        accountRef: Object.values(
          buildAuthCorpus({
            projectId: plan.projectId,
            bucket: plan.bucket,
            runId: plan.recordings[recording - 1].runId,
          }).recipes[0].accounts,
        )[0].ref,
        ownedUidSha256: hash("fixture-uid"),
        absent: true,
      },
    ],
    [
      "journal",
      {
        type: "production-auth-ownership",
        operationId,
        accountRef: Object.values(
          buildAuthCorpus({
            projectId: plan.projectId,
            bucket: plan.bucket,
            runId: plan.recordings[recording - 1].runId,
          }).recipes[0].accounts,
        )[0].ref,
        accountMutation: "receipt",
        ownedUid: "fixture-uid",
      },
    ],
    [
      "rules-proof",
      {
        type: "production-rules-checkpoint",
        recording,
        checkpoint: "rules-before-1",
        sourceSha256: hash("fixture-rules"),
        releaseBodySha256: hash("fixture-release"),
        rulesetBodySha256: hash("fixture-ruleset"),
        bucketlessBodySha256: hash("{}"),
        bucketlessAbsent: true,
      },
    ],
    [
      "rules-proof",
      {
        type: "production-rules-reference-list",
        recording,
        label: "before",
        pages: 1,
        releaseCount: 1,
        bodySha256: hash("fixture-list"),
        exhausted: true,
      },
    ],
    [
      "journal",
      {
        bucket: plan.bucket,
        prefix: plan.recordings[recording - 1].prefix,
        name: plan.recordings[recording - 1].prefix + "session",
        operationId,
        method: "PUT",
        continuationOf: "fixture-previous",
        sessionUriSha256: hash("fixture-session"),
      },
    ],
    [
      "journal",
      {
        type: "recipe-terminal",
        bucket: plan.bucket,
        prefix: plan.recordings[recording - 1].prefix,
        recording,
        recipeId: "storage-object/firebase/simple-upload",
        sequence: 1,
        namespaceEmpty: true,
      },
    ],
  ];
  if (recording === 2)
    shapes.push(
      [
        "rules-proof",
        {
          type: "production-rules-cleanup",
          recording,
          releaseAbsent: true,
          rulesetAbsent: true,
          bucketlessAbsent: true,
          sourceSha256: hash("fixture-rules"),
        },
      ],
      [
        "configuration-change",
        {
          type: "production-rules-config-change",
          recording,
          state: "ruleset-absent",
          releaseName: "projects/example-project/releases/firebase.storage/example.appspot.com",
          rulesetName: resources.rulesetResource,
          sourceSha256: hash("fixture-rules"),
        },
      ],
    );
  for (const [kind, value] of shapes)
    test(
      "recording " +
        recording +
        " retains the declared " +
        (value.type ?? "session-journal") +
        " callback schema",
      () => {
        // These records reproduce producer shapes, not their token or semantic proofs.
        const result = check(kind, value);
        if (value.type) assert.equal(result.data.type, value.type);
      },
    );
}

test("actual shared wire budget reservations and snapshot fit the artifact schema", async () => {
  const rows = [],
    meter = createStage3WireBudget(plan, { onReserve: (row) => rows.push(row) });
  for (const recording of [1, 2]) {
    const attempt = await meter.reserve("r" + recording + "/control/" + hash("wire-schema"), 64);
    attempt.receive(1);
    attempt.finish();
  }
  for (const row of rows) {
    const result = check("intent", row);
    assert.equal(result.data.requestReservedBytes, row.requestReservedBytes);
    assert.equal(result.data.responseReservedBytes, row.responseReservedBytes);
  }
  const result = check("manifest", meter.snapshot());
  assert.equal(result.data.attempts, 2);
  assert.equal(result.data.responseObservedBytes, 2);
  assert.equal(result.data.readAfterHaltBytes, 0);
  assert.equal(result.data.boundary, "HTTP_PLAINTEXT_DELIVERED_TO_ONREAD");
});

test("producer vocabulary keeps undeclared fields fail closed", () => {
  withProfile(({ profile, registry }) => {
    const result = sanitizeProductionArtifact(profile, {
      kind: "auth-proof",
      value: {
        type: "production-auth-account",
        recording: 1,
        emailSha256: hash("fixture"),
        undeclaredProducerField: true,
      },
    });
    assert.equal(result?.taskSecretStatus, "UNAVAILABLE");
    assert.equal(result.data, null);
    assert.equal(registry.snapshot().closed, true);
  });
});
