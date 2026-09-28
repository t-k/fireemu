import assert from "node:assert/strict";
import { test } from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { resolveDeclaredQuery } from "./storage-object/reference-resolution.mjs";

const input = { bucket: "example.firebasestorage.app", prefix: "owned/run-012345/" };
const recipe = () =>
  buildCorpus(input).recipes.find((entry) => entry.id === "storage-object/gcs/copy-rewrite");
const findStep = (entry, id) => entry.steps.find((step) => step.id === id);

test("the first Firebase metadata read is observed before the later transfer prerequisite", () => {
  const entry = recipe();
  const ids = [
    "source-first-read-before-gcs-metadata",
    "source-first-read-firebase-metadata",
    "source-first-read-after-gcs-metadata",
  ];
  assert.deepEqual(entry.firstFirebaseMetadataRead.stepIds, ids);
  const rows = ids.map((id) => findStep(entry, id));
  assert.deepEqual(
    rows.map((step) => step.dialect),
    ["gcs", "firebase", "gcs"],
  );
  assert.ok(
    rows.every(
      (step) =>
        step.method === "GET" &&
        step.objectName === entry.objects[0] &&
        Object.keys(step.query).length === 0,
    ),
  );
  assert.ok(
    entry.steps.indexOf(rows[2]) <
      entry.steps.indexOf(findStep(entry, "source-before-firebase-metadata")),
  );
  assert.ok(
    entry.steps.indexOf(findStep(entry, "source-before-firebase-media")) <
      entry.steps.indexOf(findStep(entry, "source-before-gcs-metadata")),
  );
});

test("copy/rewrite owns distinct source, destinations and negative controls", () => {
  const entry = recipe();
  assert.deepEqual(
    entry.objects.map((name) => name.slice(input.prefix.length)),
    [
      "copy/source.bin",
      "copy/copied.bin",
      "copy/rewritten.bin",
      "copy/missing-source.bin",
      "copy/missing-destination.bin",
      "copy/rewrite-missing-source.bin",
      "copy/rewrite-missing-destination.bin",
      "copy/refused-copy.bin",
      "copy/refused-rewrite.bin",
    ],
  );
  assert.equal(entry.preflight.length, 18);
  assert.equal(entry.cleanup.length, 27);
  assert.ok(entry.objects.every((name) => name.startsWith(input.prefix)));
  assert.ok(entry.preflight.every((step) => step.method === "GET"));
  assert.ok(entry.cleanup.every((step) => step.objectName.startsWith(input.prefix)));
});

test("copy and rewrite use the production JSON API transfer route and destination creation guard", () => {
  const entry = recipe();
  const source = entry.objects[0];
  for (const [id, destination, operation] of [
    ["copy", entry.objects[1], "copyTo"],
    ["rewrite-0", entry.objects[2], "rewriteTo"],
    ["copy-missing-source", entry.objects[4], "copyTo"],
    ["rewrite-missing-source", entry.objects[6], "rewriteTo"],
    ["copy-refused-live-destination", entry.objects[7], "copyTo"],
    ["rewrite-refused-live-destination", entry.objects[8], "rewriteTo"],
  ]) {
    const step = findStep(entry, id);
    const expectedSource =
      id === "copy-missing-source"
        ? entry.objects[3]
        : id === "rewrite-missing-source"
          ? entry.objects[5]
          : source;
    assert.equal(step.method, "POST");
    assert.equal(step.dialect, "gcs");
    assert.equal(step.credential, "admin");
    assert.deepEqual(step.transfer, {
      operation,
      sourceName: expectedSource,
      destinationName: destination,
    });
    assert.equal(step.objectName, destination);
    assert.equal(
      step.path,
      `/storage/v1/b/${input.bucket}/o/${encodeURIComponent(expectedSource)}/${operation}/b/${input.bucket}/o/${encodeURIComponent(destination)}`,
    );
    assert.deepEqual(
      step.query,
      id.includes("missing-source")
        ? { ifGenerationMatch: "0" }
        : {
            ifGenerationMatch: "0",
            ifSourceGenerationMatch: {
              kind: "metadata-field",
              step: "source-before-gcs-metadata",
              field: "generation",
              format: "positive-decimal-string",
            },
            ifSourceMetagenerationMatch: {
              kind: "metadata-field",
              step: "source-before-gcs-metadata",
              field: "metageneration",
              format: "positive-decimal-string",
            },
          },
    );
    assert.deepEqual(step.headers, { "content-type": "application/json" });
    assert.equal(step.expectedStatus, undefined);
  }
  assert.deepEqual(findStep(entry, "copy").body, { json: {} });
  assert.deepEqual(findStep(entry, "rewrite-0").body, {
    json: { contentType: "text/plain", metadata: { marker: "rewrite-override" } },
  });
});

test("rewrite continuation is bounded and conditional on the preceding unfinished response", () => {
  const entry = recipe();
  const slots = entry.steps.filter((step) => /^rewrite-\d+$/.test(step.id));
  assert.equal(slots.length, 8);
  assert.deepEqual(entry.rewritePagination, {
    stepIds: slots.map((step) => step.id),
    maxCalls: 8,
    completeOnlyWhenDone: true,
  });
  assert.equal(slots[0].continuation, undefined);
  for (const [index, step] of slots.entries()) {
    assert.equal(step.query.rewriteToken, undefined);
    if (index === 0) continue;
    assert.deepEqual(step.query, {});
    assert.deepEqual(step.headers, {});
    assert.equal(step.body, undefined);
    assert.deepEqual(step.continuation, {
      kind: "rewrite-token",
      sourceStep: `rewrite-${index - 1}`,
      targetQuery: "rewriteToken",
      whenDone: false,
      maxTokenBytes: 4096,
    });
    assert.deepEqual(step.transfer, slots[0].transfer);
    assert.equal(step.path, slots[0].path);
  }
});

test("each transfer has both dialects' metadata and exact-media post-state declarations", () => {
  const entry = recipe();
  const groups = [
    ["copy", entry.objects[1]],
    ["rewrite-7", entry.objects[2]],
    ["copy-missing-source", entry.objects[4]],
    ["rewrite-missing-source", entry.objects[6]],
    ["copy-refused-live-destination", entry.objects[7]],
    ["rewrite-refused-live-destination", entry.objects[8]],
  ];
  for (const [id, destination] of groups) {
    const index = entry.steps.findIndex((step) => step.id === id);
    const offset = id.includes("missing-source") ? 5 : 1;
    assert.deepEqual(
      entry.steps
        .slice(index + offset, index + offset + 4)
        .map((step) => [step.dialect, step.method, step.objectName, step.query.alt ?? null]),
      [
        ["firebase", "GET", destination, null],
        ["firebase", "GET", destination, "media"],
        ["gcs", "GET", destination, null],
        ["gcs", "GET", destination, "media"],
      ],
    );
  }
});

test("live-destination refusal controls start with different known bytes", () => {
  const entry = recipe();
  const sourceBytes = Buffer.from(findStep(entry, "source-upload").body.base64, "base64");
  assert.deepEqual(sourceBytes, Buffer.from([0, 1, 127, 128, 255]));
  for (const [id, destination] of [
    ["copy-refusal-seed", entry.objects[7]],
    ["rewrite-refusal-seed", entry.objects[8]],
  ]) {
    const step = findStep(entry, id);
    assert.equal(step.objectName, destination);
    assert.notDeepEqual(Buffer.from(step.body.base64, "base64"), sourceBytes);
  }
  assert.equal(
    entry.steps.some((step) => step.method === "POST" && step.objectName === entry.objects[3]),
    false,
  );
});

test("source and live refusal destinations have readbacks before and after transfer attempts", () => {
  const entry = recipe();
  assert.deepEqual(findStep(entry, "source-marker").body.json, {
    metadata: { marker: "copy-source" },
  });
  const readback = (afterId, name) => {
    const index = entry.steps.findIndex((step) => step.id === afterId);
    assert.deepEqual(
      entry.steps
        .slice(index + 1, index + 5)
        .map((step) => [step.dialect, step.objectName, step.query.alt ?? null]),
      [
        ["firebase", name, null],
        ["firebase", name, "media"],
        ["gcs", name, null],
        ["gcs", name, "media"],
      ],
    );
  };
  readback("source-first-read-after-gcs-metadata", entry.objects[0]);
  readback("copy-refusal-seed", entry.objects[7]);
  readback("copy-refused-live-destination", entry.objects[7]);
  readback("rewrite-refusal-seed", entry.objects[8]);
  readback("rewrite-refused-live-destination", entry.objects[8]);
  assert.deepEqual(
    entry.steps.slice(-4).map((step) => step.objectName),
    Array(4).fill(entry.objects[0]),
  );
});

test("each missing-source control reads source and destination before and after transfer", () => {
  const entry = recipe();
  for (const [id, sourceName, destinationName] of [
    ["copy-missing-source", entry.objects[3], entry.objects[4]],
    ["rewrite-missing-source", entry.objects[5], entry.objects[6]],
  ]) {
    const index = entry.steps.findIndex((step) => step.id === id);
    assert.deepEqual(
      entry.steps.slice(index - 8, index).map((step) => step.objectName),
      [...Array(4).fill(sourceName), ...Array(4).fill(destinationName)],
    );
    assert.deepEqual(
      entry.steps.slice(index + 1, index + 9).map((step) => step.objectName),
      [...Array(4).fill(sourceName), ...Array(4).fill(destinationName)],
    );
    for (const step of [
      ...entry.steps.slice(index - 8, index),
      ...entry.steps.slice(index + 1, index + 9),
    ]) {
      assert.equal(step.method, "GET");
    }
  }
});

test("transfer source guards resolve from prior source metadata and reject false source identity", () => {
  const entry = recipe();
  const sourceName = entry.objects[0];
  const metadata = {
    kind: "storage#object",
    bucket: input.bucket,
    name: sourceName,
    generation: "9007199254740993",
    metageneration: "7",
  };
  const responses = new Map([
    [
      "source-before-gcs-metadata",
      { status: 200, bodyBase64: Buffer.from(JSON.stringify(metadata)).toString("base64") },
    ],
  ]);
  for (const id of [
    "copy",
    "rewrite-0",
    "copy-refused-live-destination",
    "rewrite-refused-live-destination",
  ]) {
    const stepIndex = entry.steps.findIndex((step) => step.id === id);
    assert.deepEqual(
      resolveDeclaredQuery({ recipe: entry, stepIndex, responses, bucket: input.bucket }),
      {
        ifGenerationMatch: "0",
        ifSourceGenerationMatch: "9007199254740993",
        ifSourceMetagenerationMatch: "7",
      },
    );
  }
  const copyIndex = entry.steps.findIndex((step) => step.id === "copy");
  const wrong = new Map([
    [
      "source-before-gcs-metadata",
      {
        status: 200,
        bodyBase64: Buffer.from(JSON.stringify({ ...metadata, name: entry.objects[1] })).toString(
          "base64",
        ),
      },
    ],
  ]);
  assert.throws(
    () =>
      resolveDeclaredQuery({
        recipe: entry,
        stepIndex: copyIndex,
        responses: wrong,
        bucket: input.bucket,
      }),
    { code: "EVIDENCE_IDENTITY_MISMATCH" },
  );
  assert.throws(
    () =>
      resolveDeclaredQuery({
        recipe: entry,
        stepIndex: copyIndex,
        responses: new Map(),
        bucket: input.bucket,
      }),
    { code: "MISSING_EVIDENCE" },
  );
  const altered = structuredClone(entry);
  altered.steps[copyIndex].transfer.sourceName = entry.objects[1];
  assert.throws(
    () =>
      resolveDeclaredQuery({
        recipe: altered,
        stepIndex: copyIndex,
        responses,
        bucket: input.bucket,
      }),
    { code: "INVALID_REFERENCE" },
  );
  const wrongRoute = structuredClone(entry);
  wrongRoute.steps[copyIndex].path = wrongRoute.steps[copyIndex].path.replace(
    "/copyTo/",
    "/rewriteTo/",
  );
  assert.throws(
    () =>
      resolveDeclaredQuery({
        recipe: wrongRoute,
        stepIndex: copyIndex,
        responses,
        bucket: input.bucket,
      }),
    { code: "INVALID_REFERENCE" },
  );
  const wrongSourceStep = structuredClone(entry);
  wrongSourceStep.steps[copyIndex].query.ifSourceGenerationMatch.step = "copy-gcs-metadata";
  assert.throws(
    () =>
      resolveDeclaredQuery({
        recipe: wrongSourceStep,
        stepIndex: copyIndex,
        responses,
        bucket: input.bucket,
      }),
    { code: "INVALID_REFERENCE" },
  );
  const unownedSource = structuredClone(entry);
  const externalName = "external/source.bin";
  const externalRead = structuredClone(findStep(entry, "source-before-gcs-metadata"));
  externalRead.id = "external-metadata";
  externalRead.objectName = externalName;
  externalRead.path = `/storage/v1/b/${input.bucket}/o/${encodeURIComponent(externalName)}`;
  unownedSource.preflight.push(externalRead);
  unownedSource.steps[copyIndex].transfer.sourceName = externalName;
  unownedSource.steps[copyIndex].path =
    `/storage/v1/b/${input.bucket}/o/${encodeURIComponent(externalName)}/copyTo/b/${input.bucket}/o/${encodeURIComponent(entry.objects[1])}`;
  for (const key of ["ifSourceGenerationMatch", "ifSourceMetagenerationMatch"])
    unownedSource.steps[copyIndex].query[key].step = externalRead.id;
  const externalResponses = new Map([
    [
      externalRead.id,
      {
        status: 200,
        bodyBase64: Buffer.from(JSON.stringify({ ...metadata, name: externalName })).toString(
          "base64",
        ),
      },
    ],
  ]);
  assert.throws(
    () =>
      resolveDeclaredQuery({
        recipe: unownedSource,
        stepIndex: copyIndex,
        responses: externalResponses,
        bucket: input.bucket,
      }),
    { code: "INVALID_REFERENCE" },
  );
  for (const id of ["copy-missing-source", "rewrite-missing-source"]) {
    const stepIndex = entry.steps.findIndex((step) => step.id === id);
    assert.deepEqual(
      resolveDeclaredQuery({
        recipe: entry,
        stepIndex,
        responses: new Map(),
        bucket: input.bucket,
      }),
      { ifGenerationMatch: "0" },
    );
  }
});
