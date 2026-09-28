import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
const module = await import("./storage-object/production-payload-authority.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const hash = (value) => createHash("sha256").update(value).digest("hex");
function fixture(recording, predicate) {
  assert.equal(typeof module.createProductionPayloadInventory, "function");
  const inventory = module.createProductionPayloadInventory({
    projectId: plan.projectId,
    bucket: plan.bucket,
    runIds: plan.recordings.map((row) => row.runId),
  });
  const corpus = buildCorpus({
    bucket: plan.bucket,
    prefix: plan.recordings[recording - 1].prefix,
  });
  for (const [index, recipe] of corpus.recipes.entries())
    for (const step of recipe.steps)
      if (predicate(step, recipe)) {
        const body = step.body?.base64
          ? Buffer.from(step.body.base64, "base64")
          : step.body?.json
            ? Buffer.from(JSON.stringify(step.body.json))
            : Buffer.alloc(0);
        const url = new URL(
          step.path,
          `https://${step.dialect === "gcs" ? "storage" : "firebasestorage"}.googleapis.com`,
        );
        for (const [key, value] of Object.entries(step.query ?? {}))
          url.searchParams.set(key, typeof value === "string" ? value : "123");
        const input = {
          recording,
          operationId: `r${recording}/p${index + 1}/${hash(step.id)}`,
          method: step.method,
          objectName: step.objectName ?? null,
          headers: Object.entries(step.headers ?? {}),
          body,
          url: url.href,
        };
        return {
          inventory,
          step,
          body,
          input,
          capability: module.bindProductionPayloadCapture(inventory, input),
        };
      }
  assert.fail("canonical fixture missing");
}
for (const recording of [1, 2])
  test(`canonical binary and multipart requests require their original operation and bytes (${recording})`, () => {
    for (const contentType of [
      "application/octet-stream",
      "multipart/related; boundary=fireemu-object-multipart-v1",
    ]) {
      const f = fixture(
        recording,
        (step) => step.headers?.["content-type"] === contentType && step.body?.base64,
      );
      assert.equal(module.isProductionPayloadAuthority(f.capability), true);
      assert.equal(module.productionPayloadCaptureIsCovered(f.capability, "request", f.body), true);
      assert.equal(
        module.productionPayloadCaptureIsCovered(
          f.capability,
          "request",
          Buffer.concat([f.body, Buffer.from([1])]),
        ),
        false,
      );
      for (const change of [
        { operationId: `r${recording}/p1/${hash("foreign")}` },
        { objectName: "foreign/object" },
        { recording: recording === 1 ? 2 : 1 },
        { headers: [["Content-Type", "unapproved/type"]] },
      ])
        assert.equal(
          module.bindProductionPayloadCapture(f.inventory, { ...f.input, ...change }),
          null,
        );
    }
  });
test("malformed multipart fixtures retain exact canonical authority without approving arbitrary malformed input", () => {
  for (const id of ["invalid-json", "missing-media"]) {
    const f = fixture(
      1,
      (step, recipe) => recipe.id.endsWith("/multipart-upload") && step.id === id,
    );
    assert.equal(module.productionPayloadCaptureIsCovered(f.capability, "request", f.body), true);
    assert.equal(
      module.productionPayloadCaptureIsCovered(
        f.capability,
        "request",
        Buffer.from("{arbitrary-invalid-json"),
      ),
      false,
    );
    const changed = Buffer.from(f.body);
    changed[0] ^= 1;
    assert.equal(module.productionPayloadCaptureIsCovered(f.capability, "request", changed), false);
    assert.equal(
      module.bindProductionPayloadCapture(f.inventory, { ...f.input, body: changed }),
      null,
    );
  }
});
test("payload authority is original, bounded to its object and unavailable to forged identities", () => {
  const f = fixture(
    1,
    (step) => step.body?.base64 && step.headers?.["content-type"] === "application/octet-stream",
  );
  assert.equal(module.isProductionPayloadAuthority(structuredClone(f.capability)), false);
  assert.equal(
    module.productionPayloadCaptureIsCovered(structuredClone(f.capability), "request", f.body),
    false,
  );
  assert.equal(module.bindProductionPayloadCapture(structuredClone(f.inventory), f.input), null);
  assert.equal(
    module.productionPayloadAuthorityMatches(f.capability, {
      method: f.input.method,
      objectName: f.input.objectName,
      url: f.input.url,
    }),
    true,
  );
  assert.equal(
    module.productionPayloadAuthorityMatches(f.capability, {
      method: f.input.method,
      objectName: "foreign/object",
      url: f.input.url,
    }),
    false,
  );
});
test("payload authority binds the canonical bucket, path, query and exact resolved URL", () => {
  const f = fixture(
    1,
    (step, recipe) =>
      recipe.id === "storage-object/gcs/resumable-upload" && step.query?.alt === "media",
  );
  const original = new URL(f.input.url);
  const changes = [
    new URL(original),
    new URL(original),
    new URL(original),
    new URL(original),
    new URL(original),
  ];
  changes[0].pathname = original.pathname.replace(plan.bucket, "foreign.appspot.com");
  changes[1].searchParams.set("alt", "metadata");
  changes[2].searchParams.set("generation", "1");
  changes[3].searchParams.append("alt", "media");
  changes[4].pathname = original.pathname.replace("/storage/v1/", "/upload/storage/v1/");
  for (const url of changes) {
    assert.equal(
      module.bindProductionPayloadCapture(f.inventory, { ...f.input, url: url.href }),
      null,
    );
    assert.equal(
      module.productionPayloadAuthorityMatches(f.capability, {
        method: f.input.method,
        objectName: f.input.objectName,
        url: url.href,
      }),
      false,
    );
  }
  const dynamic = fixture(1, (step) => typeof step.query?.generation === "object");
  assert.equal(module.isProductionPayloadAuthority(dynamic.capability), true);
  const changed = new URL(dynamic.input.url);
  changed.searchParams.set("generation", "124");
  assert.equal(
    module.productionPayloadAuthorityMatches(dynamic.capability, {
      method: dynamic.input.method,
      objectName: dynamic.input.objectName,
      url: changed.href,
    }),
    false,
  );
  changed.searchParams.set("generation", "invalid");
  assert.equal(
    module.bindProductionPayloadCapture(dynamic.inventory, { ...dynamic.input, url: changed.href }),
    null,
  );
});
test("Auth cleanup fresh media reads retain the canonical owned payload authority", () => {
  const inventory = module.createProductionPayloadInventory({
    projectId: plan.projectId,
    bucket: plan.bucket,
    runIds: plan.recordings.map((row) => row.runId),
  });
  for (const [recordingIndex, recording] of plan.recordings.entries())
    for (const [recipeIndex, recipe] of buildAuthCorpus({
      projectId: plan.projectId,
      bucket: plan.bucket,
      runId: recording.runId,
    }).recipes.entries())
      for (const probe of recipe.probes.filter((row) => row.seed)) {
        const step = probe.before.find((row) => row.query.alt === "media"),
          url = new URL(
            step.path,
            `https://${step.service === "gcs-json" ? "storage" : "firebasestorage"}.googleapis.com`,
          );
        for (const [key, value] of Object.entries(step.query)) url.searchParams.set(key, value);
        const capability = module.bindProductionPayloadCapture(inventory, {
          recording: recordingIndex + 1,
          operationId: `r${recordingIndex + 1}/p${25 + recipeIndex}/${hash(`${recipe.id}/${probe.id}/cleanup-fresh-${step.id}`)}`,
          method: step.method,
          objectName: probe.objectName,
          headers: [],
          body: Buffer.alloc(0),
          url: url.href,
        });
        assert.equal(module.isProductionPayloadAuthority(capability), true);
        assert.equal(
          module.productionPayloadCaptureIsCovered(
            capability,
            "response",
            Buffer.from(probe.seed.body.base64, "base64"),
          ),
          true,
        );
      }
});
test("Auth owner collection normalization uses the actual null object identity", () => {
  const inventory = module.createProductionPayloadInventory({
    projectId: plan.projectId,
    bucket: plan.bucket,
    runIds: plan.recordings.map((row) => row.runId),
  });
  const recipe = buildAuthCorpus({
      projectId: plan.projectId,
      bucket: plan.bucket,
      runId: plan.recordings[0].runId,
    }).recipes[0],
    probe = recipe.probes[0];
  const step = probe.initial.find((row) => row.path === `/storage/v1/b/${plan.bucket}/o`),
    url = new URL(step.path, "https://storage.googleapis.com");
  for (const [key, value] of Object.entries(step.query)) url.searchParams.set(key, value);
  const capability = module.bindProductionPayloadCapture(inventory, {
    recording: 1,
    operationId: `r1/p25/${hash(`${recipe.id}/${probe.id}/initial-${step.id}`)}`,
    method: step.method,
    objectName: null,
    headers: [],
    body: Buffer.alloc(0),
    url: url.href,
  });
  assert.equal(module.isProductionPayloadAuthority(capability), true);
});
test("canonical download payloads and session assembly are scoped to the owned read operation", () => {
  const f = fixture(
    1,
    (step, recipe) =>
      recipe.id === "storage-object/gcs/resumable-upload" && step.query?.alt === "media",
  );
  assert.equal(
    module.productionPayloadCaptureIsCovered(
      f.capability,
      "response",
      Buffer.concat([Buffer.alloc(262144, 90), Buffer.from([0, 1, 255])]),
    ),
    true,
  );
  assert.equal(
    module.productionPayloadCaptureIsCovered(
      f.capability,
      "response",
      Buffer.from("SYNTHETIC_UNAPPROVED_MEDIA"),
    ),
    false,
  );
});
test("both session dialects, declared ranges and transfer destinations retain known privacy bytes", () => {
  for (const dialect of ["firebase", "gcs"]) {
    const f = fixture(
      1,
      (step, recipe) =>
        recipe.id === `storage-object/${dialect}/resumable-upload` && step.query?.alt === "media",
    );
    assert.equal(
      module.productionPayloadCaptureIsCovered(
        f.capability,
        "response",
        Buffer.concat([Buffer.alloc(262144, 90), Buffer.from([0, 1, 255])]),
      ),
      true,
    );
  }
  for (const [range, bytes] of [
    ["bytes=0-2", [0, 1, 127]],
    ["bytes=3-", [128, 255]],
    ["bytes=-2", [128, 255]],
  ]) {
    const f = fixture(
      1,
      (step, recipe) =>
        recipe.id === "storage-object/gcs/download" && step.headers?.range === range,
    );
    assert.equal(
      module.productionPayloadCaptureIsCovered(f.capability, "response", Buffer.from(bytes)),
      true,
    );
  }
  for (const suffix of ["copy/copied.bin", "copy/rewritten.bin"]) {
    const f = fixture(
      1,
      (step, recipe) =>
        recipe.id === "storage-object/gcs/copy-rewrite" &&
        step.objectName.endsWith(suffix) &&
        step.query?.alt === "media",
    );
    assert.equal(
      module.productionPayloadCaptureIsCovered(
        f.capability,
        "response",
        Buffer.from([0, 1, 127, 128, 255]),
      ),
      true,
    );
  }
});
test("payload authority rejects nested hooks and Buffer coercion without executing them", () => {
  const f = fixture(
    1,
    (step) => step.body?.base64 && step.headers?.["content-type"] === "application/octet-stream",
  );
  let hooks = 0;
  const headers = Object.defineProperty([], "0", {
    enumerable: true,
    configurable: true,
    get() {
      hooks++;
      return ["Content-Type", "application/octet-stream"];
    },
  });
  assert.equal(module.bindProductionPayloadCapture(f.inventory, { ...f.input, headers }), null);
  assert.equal(
    module.bindProductionPayloadCapture(
      f.inventory,
      new Proxy(f.input, {
        ownKeys() {
          hooks++;
          throw new Error();
        },
      }),
    ),
    null,
  );
  const body = Buffer.from(f.body);
  Object.defineProperty(body, "length", {
    get() {
      hooks++;
      return 0;
    },
  });
  assert.equal(module.productionPayloadCaptureIsCovered(f.capability, "request", body), true);
  assert.equal(hooks, 0);
});
