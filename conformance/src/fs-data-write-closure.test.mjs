import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { compareSandboxArtifact } from "./fs-data-write-sandbox.mjs";
import {
  prepareSandboxCorpus,
  selectComparableSandboxRecipes,
} from "./fs-data-write-sandbox-run.mjs";

const closurePath = fileURLToPath(
  new URL("../../spec/compatibility/closure/FS-DATA-WRITE.json", import.meta.url),
);
const fixturePath = fileURLToPath(
  new URL("../fs-data-write-production-matrix.json", import.meta.url),
);
const manifestPath = fileURLToPath(
  new URL("../fs-data-write-recipe-digests.json", import.meta.url),
);

const requiredConditions = new Set([
  "FS-WRITE-LIMITS-03/batch-malformed-middle",
  "FS-WRITE-LIMITS-03/batch-undecodable-value",
  "FS-DATA-WRITE/map-value-key-validation",
  "FS-WRITE-LIMITS-03/batch-duplicate-document",
  "FS-LIMIT-COLLECTION-ID",
  "FS-LIMIT-SUBCOLLECTION-DEPTH",
  "FS-LIMIT-DOCUMENT-NAME-BYTES",
  "FS-LIMIT-INDEX-ENTRIES-PER-DOCUMENT",
  "FS-LIMIT-INDEX-ENTRY-BYTES",
  "FS-LIMIT-INDEX-ENTRY-SUM-PER-DOCUMENT",
  "FS-DATA-WRITE/near-limit-delete-refusal",
  "FS-LIMIT-FIELD-PATH-BYTES",
  "FS-LIMIT-FIELD-VALUE-BYTES/scalar-refusal",
  "FS-LIMIT-FIELD-VALUE-BYTES/aggregate-string",
  "FS-LIMIT-FIELD-VALUE-BYTES/aggregate-map",
  "FS-LIMIT-INDEXED-FIELD-VALUE-BYTES",
  "FS-WRITE-LIMITS-03/implied-map",
  "FS-WRITE-LIMITS-03/implied-array",
  "FS-LIMIT-API-REQUEST-BYTES/rest-commit-json-accepted-samples",
  "FS-LIMIT-API-REQUEST-BYTES/raw-16mib-over",
  "FS-LIMIT-API-REQUEST-BYTES/non-commit-rest",
  "FS-LIMIT-API-REQUEST-BYTES/webchannel",
  "FS-LIMIT-API-REQUEST-BYTES/grpc",
  "FS-DATA-WRITE/stream-transaction-precedence",
  "FS-DATA-WRITE/write-stream-trailing-metadata",
  "FS-DATA-WRITE/write-stream-half-close",
  "FS-DATA-WRITE/write-stream-empty-write-response",
  "FS-DATA-WRITE/final-artifact-regression",
  "FS-DATA-WRITE/closure-review",
  "FS-DATA-WRITE-LIST/list-documents-rest",
  "FS-DATA-WRITE-LIST/list-collection-ids-rest",
  "FS-DATA-WRITE-LIST/list-grpc",
  "FS-DATA-WRITE-LIST/setup-writes",
]);

const requiredRecipes = new Map([
  [
    "FS-WRITE-LIMITS-03/batch-undecodable-value",
    new Set([
      "writes/batch-write-malformed/undecodable-value",
      "writes/batch-write-malformed/bad-integer",
      "writes/batch-write-malformed/two-fields-bad-integer",
      "writes/batch-write-malformed/unknown-value-kind",
      "writes/batch-write-malformed/bad-timestamp",
    ]),
  ],
  [
    "FS-DATA-WRITE/map-value-key-validation",
    new Set([
      "writes/map-key-validation/reserved/write",
      "writes/map-key-validation/reserved/query",
      "writes/map-key-validation/empty/write",
      "writes/map-key-validation/empty/query",
      "writes/map-key-validation/overlong/write",
      "writes/map-key-validation/overlong/query",
      "writes/map-key-validation/type-tag/query",
    ]),
  ],
  [
    "FS-LIMIT-COLLECTION-ID",
    new Set([
      "writes/limits/collection-id-boundary",
      "writes/limits/collection-id-slash",
      "writes/limits/collection-id-dot",
      "writes/limits/collection-id-dot-dot",
      "writes/limits/collection-id-reserved",
    ]),
  ],
  [
    "FS-LIMIT-FIELD-PATH-BYTES",
    new Set([
      "writes/limits/implied-map",
      "writes/limits/implied-array",
      "writes/limits/field-path-direct-mask",
      "writes/limits/field-path-mask/1499",
      "writes/limits/field-path-mask/1500",
    ]),
  ],
  [
    "FS-LIMIT-FIELD-VALUE-BYTES/aggregate-map",
    new Set(["writes/limits/aggregate-map", "writes/limits/aggregate-map/strict-only"]),
  ],
  [
    "FS-LIMIT-API-REQUEST-BYTES/rest-commit-json-accepted-samples",
    new Set([
      "writes/limits/decoded-request-bytes/under",
      "writes/limits/decoded-request-bytes/exact",
      "writes/limits/decoded-request-bytes/over",
      "writes/limits/decoded-11x1040000",
    ]),
  ],
  [
    "FS-LIMIT-API-REQUEST-BYTES/non-commit-rest",
    new Set(["writes/limits/non-commit-rest-request-bytes"]),
  ],
  ["FS-LIMIT-API-REQUEST-BYTES/webchannel", new Set(["writes/limits/webchannel-request-bytes"])],
  [
    "FS-LIMIT-API-REQUEST-BYTES/grpc",
    new Set(["writes/limits/grpc-unary-request-bytes", "writes/limits/grpc-stream-request-bytes"]),
  ],
  ["FS-DATA-WRITE/write-stream-half-close", new Set(["writes/write-stream-terminal/half-close"])],
  [
    "FS-DATA-WRITE/write-stream-empty-write-response",
    new Set(["writes/write-stream-terminal/response-before-half-close"]),
  ],
  [
    "FS-DATA-WRITE/final-artifact-regression",
    new Set([
      "firestore/historical-324",
      "writes/batch-write-malformed",
      "writes/limits",
      "writes/write-stream-transaction",
      "writes/write-stream-terminal",
    ]),
  ],
]);

function verifyAcceptedCondition(condition) {
  if (condition.status !== "VERIFIED") return;
  assert.ok(
    ["BRACKETED", "RULE_TRANSITION", "NOT_APPLICABLE"].includes(condition.boundaryStatus),
    `${condition.conditionId}: unresolved boundary cannot be VERIFIED`,
  );
  assert.equal(condition.evidence?.productionRecordings?.length, 2);
  assert.match(condition.evidence?.finalArtifactSha256 ?? "", /^[0-9a-f]{64}$/);
  assert.ok(condition.evidence?.comparisonPath);
}

test("VERIFIED requires a resolved production boundary classification", () => {
  const condition = {
    conditionId: "example",
    status: "VERIFIED",
    evidence: {
      productionRecordings: ["first", "second"],
      finalArtifactSha256: "a".repeat(64),
      comparisonPath: "example.json",
    },
  };
  for (const boundaryStatus of ["UNBRACKETED", "PENDING_RECORDING"]) {
    assert.throws(() => verifyAcceptedCondition({ ...condition, boundaryStatus }), /boundary/);
  }
  for (const boundaryStatus of ["BRACKETED", "RULE_TRANSITION", "NOT_APPLICABLE"]) {
    assert.doesNotThrow(() => verifyAcceptedCondition({ ...condition, boundaryStatus }));
  }
});

test("list condition proposal remains exact and pending integration", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const expected = new Map([
    [
      "FS-DATA-WRITE-LIST/list-documents-rest",
      [127, "1733f727d1ee927c7979be913f961f155ef1bb27f02dbf9e887e8550ef8f8f07"],
    ],
    [
      "FS-DATA-WRITE-LIST/list-collection-ids-rest",
      [35, "209eacb4c61e14a8fe58f1575e9689cab030e8855b37a00d7255d7cfb84e889c"],
    ],
    [
      "FS-DATA-WRITE-LIST/list-grpc",
      [36, "ee99ec519d91cefe373559b1766b986832b858133ddd8f16361e2f9cb8670229"],
    ],
    [
      "FS-DATA-WRITE-LIST/setup-writes",
      [3, "923390681e5cfaad43aba4c31f5066c0d334164284d29a3ca60745a4905dfac8"],
    ],
  ]);
  const listConditions = closure.conditions.filter(({ conditionId }) =>
    conditionId.startsWith("FS-DATA-WRITE-LIST/"),
  );

  assert.equal(closure.conditions.length, 33);
  assert.equal(listConditions.length, expected.size);
  const recipeIds = [];
  for (const condition of listConditions) {
    const [count, digest] = expected.get(condition.conditionId) ?? [];
    assert.ok(count, `unexpected list condition ${condition.conditionId}`);
    assert.equal(condition.status, "PENDING_INTEGRATION");
    assert.equal(condition.recipeIds.length, count, condition.conditionId);
    assert.equal(
      createHash("sha256")
        .update([...condition.recipeIds].sort().join("\n"))
        .digest("hex"),
      digest,
      condition.conditionId,
    );
    assert.deepEqual(condition.evidence.productionRecordings, [
      "e6bcc4b467e48d8a285d1cb754ce37bc3decf56dd5e822ef7f1e77abb089ed33",
      "5ef3ad1593391e2948f980cfde0b39747406c56d14597cbe7950158aafac3637",
    ]);
    assert.equal(condition.evidence.fixturePath, "conformance/fs-data-write-list-production.json");
    assert.equal(
      condition.evidence.comparisonPath,
      "spec/compatibility/closure/evidence/FS-DATA-WRITE-LIST-comparison.json",
    );
    assert.ok(condition.evidence.sourceCommit);
    assert.ok(condition.evidence.proposedArtifactSha256);
    assert.equal(condition.evidence.currentArtifact, undefined);
    recipeIds.push(...condition.recipeIds);
  }
  assert.equal(recipeIds.length, 201);
  assert.equal(new Set(recipeIds).size, 201, "each proposed recipe must belong to one condition");
  assert.equal(closure.parentStatus, "WAITING_ORACLE");
  assert.equal(closure.closureReview.decision, "PENDING");
});

test("verified conditions are bound to their saved comparisons", async () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const { corpus } = await prepareSandboxCorpus();
  const digestProgram = (program) => ({
    steps: Object.fromEntries(
      Object.entries(program.steps).map(([stepId, step]) => {
        const body = JSON.stringify(step.body);
        return [
          stepId,
          {
            status: step.status,
            code: step.code,
            bodyBytes: Buffer.byteLength(body),
            bodySha256: createHash("sha256").update(body).digest("hex"),
          },
        ];
      }),
    ),
  });
  const verified = closure.conditions.filter(({ status }) => status === "VERIFIED");
  for (const conditionId of [
    "FS-LIMIT-SUBCOLLECTION-DEPTH",
    "FS-LIMIT-DOCUMENT-NAME-BYTES",
    "FS-WRITE-LIMITS-03/batch-duplicate-document",
    "FS-WRITE-LIMITS-03/batch-malformed-middle",
    "FS-LIMIT-FIELD-VALUE-BYTES/scalar-refusal",
    "FS-LIMIT-FIELD-VALUE-BYTES/aggregate-string",
    "FS-WRITE-LIMITS-03/implied-map",
    "FS-WRITE-LIMITS-03/implied-array",
    "FS-LIMIT-API-REQUEST-BYTES/raw-16mib-over",
    "FS-LIMIT-API-REQUEST-BYTES/rest-commit-json-accepted-samples",
  ]) {
    assert.ok(verified.some((condition) => condition.conditionId === conditionId));
  }
  for (const condition of verified) {
    const comparisonPath = fileURLToPath(
      new URL(`../../${condition.evidence.comparisonPath}`, import.meta.url),
    );
    const comparison = JSON.parse(readFileSync(comparisonPath, "utf8"));
    assert.equal(comparison.conditionId, condition.conditionId);
    assert.deepEqual(new Set(comparison.recipeIds), new Set(condition.recipeIds));
    const streamComparison = comparison.comparisonMode === "sandbox-stream-comparator";
    assert.deepEqual(
      comparison.productionRecordingDigests,
      streamComparison
        ? fixture.evidence.streamRecordingDigests
        : fixture.evidence.recordingDigests,
    );
    assert.deepEqual(
      condition.evidence.productionRecordings,
      comparison.productionRecordingDigests,
    );
    assert.equal(
      condition.evidence.finalArtifactSha256,
      comparison.artifactSha256 ?? comparison.localExecutableSha256,
    );
    assert.equal(comparison.result.comparableRecipes, condition.recipeIds.length);
    assert.equal(comparison.result.mismatchedRecipes, 0);
    if (streamComparison) {
      assert.match(comparison.artifactSourceCommit, /^[0-9a-f]{40}$/);
      assert.ok(
        condition.evidence.comparisonPath.includes(comparison.artifactSourceCommit.slice(0, 9)),
      );
      assert.equal(
        comparison.localConfigSha256,
        createHash("sha256")
          .update(readFileSync(new URL("../fs-data-write-sandbox.fireemu.json", import.meta.url)))
          .digest("hex"),
      );
      assert.deepEqual(
        new Set(Object.keys(comparison.productionStreams)),
        new Set(condition.recipeIds),
      );
      assert.deepEqual(new Set(Object.keys(comparison.localStreams)), new Set(condition.recipeIds));
      for (const recipeId of condition.recipeIds) {
        assert.deepEqual(comparison.productionStreams[recipeId], fixture.streams[recipeId]);
        const recipe = corpus.streamRecipes.find(({ id }) => id === recipeId);
        assert.ok(recipe);
        const recipeDigest = createHash("sha256").update(JSON.stringify(recipe)).digest("hex");
        assert.equal(recipeDigest, manifest.streams[recipeId]);
        assert.equal(comparison.recipeSha256, recipeDigest);
      }
      assert.deepEqual(
        compareSandboxArtifact(
          { programs: {}, streams: comparison.productionStreams },
          {},
          comparison.localStreams,
          {
            restPrograms: [],
            streamRecipes: corpus.streamRecipes.filter(({ id }) =>
              condition.recipeIds.includes(id),
            ),
          },
        ),
        [],
      );
      continue;
    }
    assert.deepEqual(
      new Set(Object.keys(comparison.productionPrograms)),
      new Set(condition.recipeIds),
    );
    assert.deepEqual(new Set(Object.keys(comparison.localPrograms)), new Set(condition.recipeIds));
    for (const recipeId of condition.recipeIds) {
      const expected =
        comparison.comparisonMode === "digest-per-step"
          ? digestProgram(fixture.programs[recipeId])
          : fixture.programs[recipeId];
      assert.deepEqual(comparison.productionPrograms[recipeId], expected);
      if (
        comparison.comparisonMode !== "sandbox-comparator" &&
        !comparison.comparisonMode?.startsWith("existing-sandbox-comparator;")
      ) {
        assert.deepEqual(
          comparison.localPrograms[recipeId],
          comparison.productionPrograms[recipeId],
        );
      }
    }
    if (condition.conditionId === "FS-LIMIT-API-REQUEST-BYTES/rest-commit-json-accepted-samples") {
      const programs = condition.recipeIds.map((recipeId) =>
        corpus.restPrograms.find(({ id }) => id === recipeId),
      );
      assert.ok(programs.every(Boolean));
      assert.deepEqual(
        programs
          .slice(0, 3)
          .map((program) => Buffer.byteLength(JSON.stringify(program.steps[0].body))),
        comparison.measurement.firstThreeRawBytes,
      );
      assert.equal(Buffer.byteLength(JSON.stringify(programs[3].steps[0].body)), 11_441_443);
      for (const program of Object.values(comparison.localPrograms)) {
        assert.ok(
          Object.values(program.steps).every(({ status, code }) => status === 200 && code === "OK"),
        );
      }
    }
    if (comparison.comparisonMode === "sandbox-comparator") {
      assert.deepEqual(
        compareSandboxArtifact(
          { programs: comparison.productionPrograms, streams: {} },
          comparison.localPrograms,
          {},
          {
            restPrograms: corpus.restPrograms.filter(({ id }) => condition.recipeIds.includes(id)),
          },
        ),
        [],
      );
    }
    if (comparison.crossRecipeBoundary) {
      assert.equal(comparison.crossRecipeBoundary.classification, condition.boundaryStatus);
      assert.deepEqual(comparison.crossRecipeBoundary.evidence, condition.boundaryEvidence);
      const crossPath = fileURLToPath(
        new URL(`../../${comparison.crossRecipeBoundary.comparisonPath}`, import.meta.url),
      );
      const crossComparison = JSON.parse(readFileSync(crossPath, "utf8"));
      assert.ok(verified.some(({ conditionId }) => conditionId === crossComparison.conditionId));
      for (const reference of comparison.crossRecipeBoundary.evidence) {
        const [recipeId] = reference.split("#");
        assert.deepEqual(crossComparison.productionPrograms[recipeId], fixture.programs[recipeId]);
      }
    }
  }
});

test("10 MiB accepted samples and strict 11 MiB Commit probes keep separate recipe identities", async () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const { corpus } = await prepareSandboxCorpus();
  const accepted = closure.conditions.find(
    ({ conditionId }) =>
      conditionId === "FS-LIMIT-API-REQUEST-BYTES/rest-commit-json-accepted-samples",
  );
  const strict = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-LIMIT-API-REQUEST-BYTES/raw-16mib-over",
  );
  const acceptedIds = [
    "writes/limits/decoded-request-bytes/under",
    "writes/limits/decoded-request-bytes/exact",
    "writes/limits/decoded-request-bytes/over",
  ];
  const strictIds = ["writes/limits/raw-11mib/11534336", "writes/limits/raw-11mib/11534337"];
  assert.ok(accepted);
  assert.ok(strict);
  assert.deepEqual(accepted.recipeIds.slice(0, 3), acceptedIds);
  assert.ok(strictIds.every((recipeId) => strict.recipeIds.includes(recipeId)));
  assert.ok(acceptedIds.every((recipeId) => !strict.recipeIds.includes(recipeId)));

  for (const [index, recipeId] of acceptedIds.entries()) {
    const program = corpus.restPrograms.find(({ id }) => id === recipeId);
    assert.ok(program, recipeId);
    assert.equal(
      Buffer.byteLength(JSON.stringify(program.steps[0].body)),
      [10_485_759, 10_485_760, 10_485_761][index],
    );
    assert.equal(
      createHash("sha256").update(JSON.stringify(program)).digest("hex"),
      manifest.programs[recipeId],
    );
  }

  for (const [index, recipeId] of strictIds.entries()) {
    const program = corpus.restPrograms.find(({ id }) => id === recipeId);
    assert.ok(program, recipeId);
    assert.equal(Buffer.byteLength(program.steps[0].body), [11_534_336, 11_534_337][index]);
    assert.equal(
      createHash("sha256").update(JSON.stringify(program)).digest("hex"),
      manifest.programs[recipeId],
    );
  }
});

test("final artifact closure names both saved production regression commands", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/final-artifact-regression",
  );
  assert.deepEqual(condition.regressionCommands, [
    "pnpm -C conformance firestore:check-production",
    "pnpm -C conformance fs-data-write:check",
  ]);
  assert.notEqual(condition.status, "VERIFIED");
});

test("request-byte transports remain pending production recording after local corpus checks", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const nonCommitRest = closure.conditions.find(
    (row) => row.conditionId === "FS-LIMIT-API-REQUEST-BYTES/non-commit-rest",
  );
  assert.equal(nonCommitRest.status, "PENDING_RECORDING");
  assert.equal(nonCommitRest.boundaryStatus, "PENDING_RECORDING");
  const grpc = closure.conditions.find(
    (row) => row.conditionId === "FS-LIMIT-API-REQUEST-BYTES/grpc",
  );
  assert.equal(grpc.status, "PENDING_RECORDING");
  assert.equal(grpc.boundaryStatus, "PENDING_RECORDING");
  const webchannel = closure.conditions.find(
    (row) => row.conditionId === "FS-LIMIT-API-REQUEST-BYTES/webchannel",
  );
  assert.equal(webchannel.status, "PENDING_RECORDING");
  assert.equal(webchannel.boundaryStatus, "PENDING_RECORDING");
});

test("new strict-only map observation remains pending production recording", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-LIMIT-FIELD-VALUE-BYTES/aggregate-map",
  );
  assert.ok(condition.recipeIds.includes("writes/limits/aggregate-map/strict-only"));
  assert.equal(condition.status, "PENDING_RECORDING");
});

test("changed field-path and indexed-value recipes remain pending recording", async () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const { corpus } = await prepareSandboxCorpus();
  const selected = selectComparableSandboxRecipes(fixture, manifest, corpus, corpus);
  for (const [conditionId, recipeId] of [
    ["FS-LIMIT-FIELD-PATH-BYTES", "writes/limits/field-path-mask/1500"],
    ["FS-LIMIT-INDEXED-FIELD-VALUE-BYTES", "writes/limits/indexed-field-value-bytes"],
  ]) {
    const condition = closure.conditions.find((row) => row.conditionId === conditionId);
    assert.ok(condition.recipeIds.includes(recipeId));
    assert.ok(selected.pendingRestIds.includes(recipeId));
    assert.equal(condition.status, "PENDING_RECORDING", conditionId);
  }
});

test("an unrecorded empty-write response cannot inherit the known trailer mismatch", async () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const { corpus } = await prepareSandboxCorpus();
  const selected = selectComparableSandboxRecipes(fixture, manifest, corpus, corpus);
  const responseId = "writes/write-stream-terminal/response-before-half-close";
  const response = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/write-stream-empty-write-response",
  );
  const halfClose = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/write-stream-half-close",
  );
  assert.ok(selected.pendingStreamIds.includes(responseId));
  assert.equal(response.status, "PENDING_RECORDING");
  assert.deepEqual(response.recipeIds, [responseId]);
  assert.equal(halfClose.status, "VERIFIED");
  assert.match(
    halfClose.comparisonNormalizationApproval,
    /2026-09-24.*addendum 4.*content-disposition is stable/,
  );
  assert.ok(!halfClose.recipeIds.includes(responseId));
});

test("half-close accepts the source-bound current run without rewriting historical evidence", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/write-stream-half-close",
  );
  const comparisonPath = fileURLToPath(
    new URL(
      "../../spec/compatibility/broad-runs/fs-stream-half-close-1cb475837-current-comparison.json",
      import.meta.url,
    ),
  );
  const comparison = JSON.parse(readFileSync(comparisonPath, "utf8"));
  const historicalPath = fileURLToPath(
    new URL(`../../${condition.historicalComparison.comparisonPath}`, import.meta.url),
  );
  const historical = JSON.parse(readFileSync(historicalPath, "utf8"));

  assert.equal(condition.status, "VERIFIED");
  assert.deepEqual(condition.evidence.productionRecordings, [
    "ba880dc6feb56588256298deba48c9cbfd53de115e2f9381968867a28279d56f",
    "ba880dc6feb56588256298deba48c9cbfd53de115e2f9381968867a28279d56f",
  ]);
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  assert.deepEqual(comparison.productionRecordingDigests, fixture.evidence.streamRecordingDigests);
  assert.deepEqual(comparison.productionRecordingTimes, fixture.evidence.recordedAt);
  assert.equal(new Set(comparison.productionRecordingTimes).size, 2);
  assert.equal(
    comparison.productionFixturePath,
    "conformance/fs-data-write-production-matrix.json",
  );
  assert.equal(
    condition.evidence.comparisonPath,
    "spec/compatibility/broad-runs/fs-stream-half-close-1cb475837-current-comparison.json",
  );
  assert.deepEqual(condition.historicalComparison, {
    productionRecordings: historical.productionRecordingDigests,
    finalArtifactSha256: historical.artifactSha256,
    comparisonPath:
      "spec/compatibility/broad-runs/fs-stream-half-close-542b868b7-saved-comparison.json",
  });
  assert.deepEqual(comparison.sourceBinding, {
    sourceHead: "1cb4758372f21a467306a0a701994b7c1a02a8bb",
    executableSha256: "2af3f08c4d453459af86c9258f2283cb38fc7e74d83d388018cbdbb29e892a6a",
    executableSha256After: "2af3f08c4d453459af86c9258f2283cb38fc7e74d83d388018cbdbb29e892a6a",
    bindingFileSha256: "ea1c8bf15deb90fb70723e7a9a0ca3e1854779da79fb3473c6f8ab6451f7d37d",
    streamResultsSha256: "552b434a93f637be61d4d1ac5d8e22ecc682bad60958603bb29029b8e305fa80",
    corpusSha256: "407099fc6bb3137fdf2ca5294f0b8ef347e819bead6ab3085e804842bdb20450",
  });
  assert.deepEqual(comparison.result, {
    comparableRecipes: 1,
    mismatchedRecipes: 0,
    wholeRunComparableRestPrograms: 39,
    wholeRunComparableStreams: 2,
    wholeRunKnownMismatchRows: 9,
    wholeRunPendingRestPrograms: 39,
    wholeRunPendingStreams: 5,
  });
  assert.equal(
    comparison.localStreams[condition.recipeIds[0]].status.trailers[0].key,
    "content-disposition",
  );
  assert.deepEqual(comparison.differences, []);

  const trailingMetadata = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/write-stream-trailing-metadata",
  );
  const emptyResponse = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/write-stream-empty-write-response",
  );
  const finalRegression = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-DATA-WRITE/final-artifact-regression",
  );
  assert.equal(trailingMetadata.status, "MISMATCH");
  assert.equal(emptyResponse.status, "PENDING_RECORDING");
  assert.equal(finalRegression.status, "PENDING_REVIEW");
  assert.equal(comparison.result.wholeRunKnownMismatchRows, 9);
  assert.equal(comparison.result.wholeRunPendingStreams, 5);
  assert.notEqual(historical.artifactSha256, comparison.artifactSha256);
});

test("batch malformed-middle is rebound to the current source-bound comparison", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const condition = closure.conditions.find(
    ({ conditionId }) => conditionId === "FS-WRITE-LIMITS-03/batch-malformed-middle",
  );
  const comparisonPath = fileURLToPath(
    new URL(
      "../../spec/compatibility/broad-runs/fs-batch-malformed-middle-8a0f205-current-comparison.json",
      import.meta.url,
    ),
  );
  const comparison = JSON.parse(readFileSync(comparisonPath, "utf8"));

  assert.equal(condition.status, "VERIFIED");
  assert.equal(
    condition.evidence.comparisonPath,
    "spec/compatibility/broad-runs/fs-batch-malformed-middle-8a0f205-current-comparison.json",
  );
  assert.equal(condition.evidence.finalArtifactSha256, comparison.localExecutableSha256);
  assert.equal(condition.evidence.sourceCommit, comparison.sourceCommit);
  assert.equal(condition.evidence.sourceBindingSha256, comparison.localRunBindingSha256);
  assert.equal(
    condition.evidence.comparisonSha256,
    createHash("sha256").update(readFileSync(comparisonPath)).digest("hex"),
  );
  assert.deepEqual(condition.historicalEvidence, {
    productionRecordings: [
      "7c794af67119e745072ceae3d742bd463df28c0aa804998c2155b1333b1625d9",
      "7c794af67119e745072ceae3d742bd463df28c0aa804998c2155b1333b1625d9",
    ],
    finalArtifactSha256: "d6db62596e71c152883dc5b83bf8dc48b79b703777d49bab10874c1fae6dfc6d",
    comparisonPath:
      "spec/compatibility/broad-runs/fs-batch-malformed-middle-3d7ceabb8-saved-comparison.json",
  });
  assert.equal(comparison.result.comparableRecipes, condition.recipeIds.length);
  assert.equal(comparison.result.mismatchedRecipes, 0);
  assert.equal(comparison.closurePromotion, "none");
});

test("recorded conditions contain no changed or unrecorded runnable recipes", async () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const { corpus } = await prepareSandboxCorpus();
  const selected = selectComparableSandboxRecipes(fixture, manifest, corpus, corpus);
  const pending = new Set([...selected.pendingRestIds, ...selected.pendingStreamIds]);
  const failures = closure.conditions
    .filter(({ status }) => ["PRODUCTION_RECORDED", "VERIFIED"].includes(status))
    .flatMap(({ conditionId, recipeIds }) =>
      recipeIds
        .filter((recipeId) => pending.has(recipeId))
        .map((recipeId) => `${conditionId}: ${recipeId}`),
    );
  assert.deepEqual(failures, []);
});

test("FS-DATA-WRITE closure inventory cannot silently omit a declared condition", () => {
  const closure = JSON.parse(readFileSync(closurePath, "utf8"));
  const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
  assert.equal(closure.parent, "FS-DATA-WRITE");
  const ids = closure.conditions.map(({ conditionId }) => conditionId);
  assert.equal(ids.length, new Set(ids).size, "condition IDs must be unique");
  assert.deepEqual(new Set(ids), requiredConditions);
  for (const condition of closure.conditions) {
    assert.equal(typeof condition.source, "string");
    assert.ok(condition.source.length > 0);
    assert.ok(Array.isArray(condition.recipeIds) && condition.recipeIds.length > 0);
    assert.ok(
      [
        "BRACKETED",
        "RULE_TRANSITION",
        "UNBRACKETED",
        "NOT_APPLICABLE",
        "PENDING_RECORDING",
        "OBSERVED (page size 300)",
      ].includes(condition.boundaryStatus),
      `${condition.conditionId}: missing boundary classification`,
    );
    if (["BRACKETED", "RULE_TRANSITION"].includes(condition.boundaryStatus)) {
      assert.equal(condition.boundaryEvidence?.length, 2, condition.conditionId);
      const shape = (reference) => reference.split("#")[0].replace(/\/[^/]+$/, "");
      assert.equal(
        shape(condition.boundaryEvidence[0]),
        shape(condition.boundaryEvidence[1]),
        `${condition.conditionId}: evidence must keep the same recipe family`,
      );
      const pair = condition.boundaryEvidence.map((reference) => {
        const [programId, stepId] = reference.split("#");
        const step = fixture.programs[programId]?.steps[stepId];
        assert.ok(step, `${condition.conditionId}: missing fixture step ${reference}`);
        return step;
      });
      if (condition.boundaryStatus === "BRACKETED") {
        assert.ok(
          pair.some((step) => step.status < 300),
          condition.conditionId,
        );
        assert.ok(
          pair.some((step) => step.status >= 400),
          condition.conditionId,
        );
      } else {
        assert.ok(
          pair.every((step) => step.status >= 400),
          condition.conditionId,
        );
        assert.notEqual(pair[0].message, pair[1].message, condition.conditionId);
      }
    }
    if (condition.recipeIds.some((recipe) => fixture.programs[recipe])) {
      assert.notEqual(condition.status, "PENDING_CORPUS", condition.conditionId);
    }
    assert.ok(
      [
        "PENDING_CORPUS",
        "PENDING_RECORDING",
        "SAVED_REFERENCE_PENDING_FINAL",
        "PRODUCTION_RECORDED",
        "MISMATCH",
        "VERIFIED",
        "PENDING_REVIEW",
        "PENDING_INTEGRATION",
      ].includes(condition.status),
      `${condition.conditionId}: unknown status`,
    );
    verifyAcceptedCondition(condition);
  }
  for (const [conditionId, recipes] of requiredRecipes) {
    const condition = closure.conditions.find((row) => row.conditionId === conditionId);
    assert.deepEqual(
      new Set(condition.recipeIds),
      recipes,
      `${conditionId}: incomplete recipe mapping`,
    );
  }
  const allVerified = closure.conditions.every(({ status }) => status === "VERIFIED");
  assert.equal(
    closure.parentStatus === "COMPAT_VERIFIED",
    allVerified && closure.closureReview?.decision === "APPROVED",
    "parent promotion requires every condition and independent closure review",
  );
});
