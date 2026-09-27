import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";

const input = { bucket: "example.firebasestorage.app", prefix: "owned/run-012345/" };
const allRequests = (recipe) => [...recipe.preflight, ...recipe.steps, ...recipe.cleanup];

test("the partial corpus names the declared frozen recipes and its remaining obligations", () => {
  const corpus = buildCorpus(input);
  assert.equal(corpus.status, "LOCAL_DRAFT");
  assert.equal(corpus.evidenceHandling, "private-only-until-reviewed-normalization");
  assert.ok(corpus.remainingObligations.includes("step-preconditions-and-state-admission"));
  assert.deepEqual(
    corpus.recipes.map((r) => r.id),
    [
      "storage-object/firebase/simple-upload",
      "storage-object/cross-dialect/state",
      ...[
        "firebase/download",
        "firebase/metadata",
        "firebase/delete",
        "firebase/overwrite",
        "gcs/download",
        "gcs/metadata",
        "gcs/delete",
        "errors/missing",
        "errors/object-name",
        "errors/range",
        "firebase/multipart-upload",
        "gcs/simple-multipart-upload",
        "gcs/checksums",
        "gcs/generation-preconditions",
        "gcs/metageneration-preconditions",
        "firebase/list",
        "gcs/list",
        "gcs/copy-rewrite",
        "auth/admin",
        "firebase/download-tokens",
        "firebase/resumable-upload",
        "gcs/resumable-upload",
      ].map((id) => "storage-object/" + id),
    ],
  );
  const closure = JSON.parse(
    readFileSync(
      new URL("../../spec/compatibility/closure/STORAGE-OBJECT.json", import.meta.url),
      "utf8",
    ),
  );
  const frozenRecipes = new Set(
    closure.conditions
      .flatMap((c) => c.recipeIds)
      .filter(
        (id) => !["storage-object/final-artifact", "storage-object/closure-review"].includes(id),
      ),
  );
  assert.ok(corpus.recipes.every((r) => frozenRecipes.has(r.id)));
  assert.ok(corpus.remainingObligations.includes("refused-simple-upload-post-state"));
  assert.ok(corpus.remainingObligations.includes("production-two-recordings"));
  assert.equal(corpus.requestsPerRecording, 1888);
  assert.deepEqual(
    new Set([...corpus.recipes.map((r) => r.id), ...corpus.remainingRecipeIds]),
    frozenRecipes,
  );
  assert.equal(corpus.remainingRecipeIds.length, 2);
  assert.ok(corpus.remainingObligations.includes("typed-reference-resolution-and-preconditions"));
  assert.ok(corpus.remainingObligations.includes("list-token-resolution-and-exhaustion"));
  assert.ok(corpus.remainingObligations.includes("rewrite-token-resolution-and-completion"));
  assert.ok(corpus.remainingObligations.includes("owner-adc-credential-proof"));
  assert.ok(corpus.remainingObligations.includes("resumable-session-uri-resolution-and-progress"));
  assert.ok(corpus.remainingObligations.includes("download-token-provenance-and-authorization"));
  assert.ok(corpus.remainingObligations.includes("final-artifact-comparison"));
  assert.ok(corpus.remainingObligations.includes("independent-closure-review"));
  assert.equal(corpus.requestsPerRecording, corpus.recipes.flatMap(allRequests).length);
});

test("every operation is confined to declared names under the supplied prefix", () => {
  for (const recipe of buildCorpus(input).recipes) {
    assert.equal(recipe.initialState, "objects-absent");
    assert.ok(recipe.objects.length >= 1);
    assert.ok(recipe.objects.every((name) => name.startsWith(input.prefix)));
    for (const request of allRequests(recipe)) {
      const name = request.objectName;
      assert.equal(request.credential, request.query.token ? "none" : "admin");
      const endpoint = request.dialect === "firebase" ? "/v0" : "/storage/v1";
      const root = `${endpoint}/b/${input.bucket}/o`;
      if (request.collection) {
        assert.equal(name, undefined);
        assert.equal(request.method, "GET");
        assert.equal(request.path, root);
        assert.ok(recipe.objects.every((objectName) => objectName.startsWith(request.scopePrefix)));
        assert.ok(request.query.prefix.startsWith(request.scopePrefix));
      } else if (request.transfer) {
        assert.equal(request.method, "POST");
        assert.equal(request.dialect, "gcs");
        assert.ok(recipe.objects.includes(request.transfer.sourceName));
        assert.ok(recipe.objects.includes(request.transfer.destinationName));
        assert.equal(name, request.transfer.destinationName);
        assert.ok(["copyTo", "rewriteTo"].includes(request.transfer.operation));
        assert.equal(
          request.path,
          `/storage/v1/b/${input.bucket}/o/${encodeURIComponent(request.transfer.sourceName)}/${request.transfer.operation}/b/${input.bucket}/o/${encodeURIComponent(request.transfer.destinationName)}`,
        );
      } else if (request.malformedObjectName) {
        assert.equal(recipe.id, "storage-object/errors/object-name");
        assert.ok(recipe.objects.includes(name));
        assert.equal(request.malformedObjectName.attemptedName, name);
        assert.ok(name.startsWith(request.malformedObjectName.scopePrefix));
        assert.ok(["linefeed", "oversized"].includes(request.malformedObjectName.kind));
        if (request.method === "POST") {
          assert.equal(request.path, request.dialect === "gcs" ? `/upload${root}` : root);
          assert.equal(request.query.name, name);
        } else {
          assert.equal(request.method, "GET");
          assert.equal(request.path, `${root}/${encodeURIComponent(name)}`);
        }
      } else if (request.sessionUriReference) {
        assert.ok(recipe.objects.includes(name));
        assert.equal(
          request.method,
          request.dialect === "gcs"
            ? request.id === "cancel-unconfirmed-session"
              ? "DELETE"
              : "PUT"
            : "POST",
        );
        assert.equal(request.path, undefined);
        assert.equal(
          request.sessionUriReference.initiateStep,
          request.objectName.endsWith("/resumable-cancel.bin")
            ? "initiate-cancel"
            : request.objectName.endsWith("/resumable-wrong-offset.bin")
              ? "initiate-wrong"
              : "initiate",
        );
        assert.equal(
          request.sessionUriReference.expectedOrigin,
          request.dialect === "gcs"
            ? "https://storage.googleapis.com"
            : "https://firebasestorage.googleapis.com",
        );
        assert.equal(
          request.sessionUriReference.expectedPath,
          request.dialect === "gcs"
            ? `/upload/storage/v1/b/${input.bucket}/o`
            : `/v0/b/${input.bucket}/o`,
        );
        assert.equal(request.sessionUriReference.expectedName, name);
        assert.equal(request.sessionUriReference.secretHandling, "private-only");
      } else if (request.method === "POST") {
        assert.ok(recipe.objects.includes(name));
        if (request.query.create_token || request.query.delete_token) {
          assert.equal(recipe.id, "storage-object/firebase/download-tokens");
          assert.equal(request.path, `${root}/${encodeURIComponent(name)}`);
        } else {
          assert.equal(request.path, request.dialect === "gcs" ? `/upload${root}` : root);
          assert.equal(request.query.name, name);
        }
      } else {
        assert.ok(recipe.objects.includes(name));
        assert.equal(request.path, `${root}/${encodeURIComponent(name)}`);
        assert.equal(decodeURIComponent(request.path.slice(root.length + 1)), name);
      }
      assert.equal(request.headers.authorization, undefined);
      assert.equal(request.expectedStatus, undefined);
      assert.deepEqual(request.responseCapture, {
        status: true,
        headers: "all",
        body: "raw-bytes",
      });
    }
    assert.ok(recipe.preflight.every((r) => r.method === "GET"));
    assert.deepEqual(
      recipe.cleanup.map((r) => r.method),
      recipe.id === "storage-object/gcs/resumable-upload"
        ? ["DELETE", "PUT", "DELETE", "GET", "GET"]
        : recipe.id === "storage-object/firebase/resumable-upload"
          ? [
              "POST",
              "POST",
              "POST",
              "POST",
              "POST",
              "POST",
              ...recipe.objects.flatMap(() => ["DELETE", "GET", "GET"]),
            ]
          : recipe.objects.flatMap(() => ["DELETE", "GET", "GET"]),
    );
    assert.deepEqual(
      recipe.cleanup.filter((r) => r.method === "GET").map((r) => r.dialect),
      recipe.objects.flatMap(() => ["firebase", "gcs"]),
    );
  }
});

test("simple upload records metadata and exact bytes after writing", () => {
  const recipe = buildCorpus(input).recipes[0];
  assert.deepEqual(
    recipe.steps.map((s) => s.id),
    ["upload", "metadata", "media"],
  );
  assert.deepEqual(
    Buffer.from(recipe.steps[0].body.base64, "base64"),
    Buffer.from([0, 1, 127, 128, 255]),
  );
  assert.equal(recipe.steps[2].query.alt, "media");
});

test("cross dialect state records bytes, metadata changes and absence from both APIs", () => {
  const recipe = buildCorpus(input).recipes[1];
  assert.deepEqual(
    recipe.steps.map((s) => `${s.dialect}:${s.method}`),
    [
      "gcs:POST",
      "firebase:GET",
      "firebase:GET",
      "firebase:PATCH",
      "gcs:GET",
      "gcs:GET",
      "firebase:DELETE",
      "firebase:GET",
      "gcs:GET",
    ],
  );
  assert.equal(recipe.steps[0].query.uploadType, "media");
  assert.deepEqual(recipe.steps[3].body.json, { metadata: { marker: "cross-dialect-updated" } });
  assert.equal(recipe.steps[5].query.alt, "media");
  assert.match(recipe.steps[1].path, /%2F/);
  assert.match(recipe.steps[1].path, /%20/);
  assert.match(recipe.steps[1].path, /%25/);
  assert.match(recipe.steps[1].path, /%2B/);
});

test("invalid bucket or prefix input cannot expand the request scope", () => {
  for (const bucket of ["", "https://example.com", "a/b", "a?b", "A-bucket", "a..b", null, 7]) {
    assert.throws(() => buildCorpus({ ...input, bucket }), /bucket/);
  }
  for (const prefix of [
    "",
    "/",
    "run",
    "../run/",
    "run/../",
    "run//",
    "run/%2f/",
    "run/?/",
    "run/\\/",
    "run/\n/",
    "x".repeat(256) + "/",
    null,
    7,
  ]) {
    assert.throws(() => buildCorpus({ ...input, prefix }), /prefix/);
  }
});

test("corpus generation is deterministic and independent of prior output mutation", () => {
  const one = buildCorpus(input);
  const expected = JSON.stringify(one);
  assert.equal(JSON.stringify(buildCorpus(input)), expected);
  one.recipes[0].steps[0].query.name = "outside";
  one.recipes[1].steps[3].body.json.metadata.marker = "changed";
  assert.equal(JSON.stringify(buildCorpus(input)), expected);
});

const recipeNamed = (suffix) =>
  buildCorpus(input).recipes.find((r) => r.id === `storage-object/${suffix}`);
const bodyBytes = (step) =>
  step.body?.base64 === undefined
    ? Buffer.from(JSON.stringify(step.body?.json ?? ""))
    : Buffer.from(step.body.base64, "base64");

test("download declarations include all three range forms and unchanged-state readbacks", () => {
  for (const dialect of ["firebase", "gcs"]) {
    const recipe = recipeNamed(`${dialect}/download`);
    assert.deepEqual(
      recipe.steps
        .filter((s) => s.headers.range && !s.query.generation)
        .map((s) => s.headers.range),
      ["bytes=0-2", "bytes=3-", "bytes=-2"],
    );
    assert.ok(recipe.steps.every((s) => s.dialect === dialect));
    assert.deepEqual(
      recipe.steps.slice(-2).map((s) => [s.method, s.query.alt ?? null]),
      [
        ["GET", null],
        ["GET", "media"],
      ],
    );
  }
});

test("metadata declarations record preimage and read back bytes after every change", () => {
  for (const dialect of ["firebase", "gcs"]) {
    const recipe = recipeNamed(`${dialect}/metadata`);
    assert.deepEqual(
      recipe.steps.slice(0, 3).map((s) => s.method),
      ["POST", "GET", "GET"],
    );
    for (const [index, step] of recipe.steps.entries()) {
      if (!["PATCH", "PUT"].includes(step.method)) continue;
      assert.equal(step.headers["content-type"], "application/json");
      assert.ok(step.body.json);
      assert.deepEqual(
        recipe.steps.slice(index + 1, index + 3).map((s) => [s.method, s.query.alt ?? null]),
        [
          ["GET", null],
          ["GET", "media"],
        ],
      );
    }
    assert.deepEqual(
      recipe.steps.filter((s) => ["PATCH", "PUT"].includes(s.method)).map((s) => s.method),
      dialect === "gcs" ? ["PATCH", "PUT"] : ["PATCH", "PATCH"],
    );
  }
});

test("delete declarations include repeated deletion and metadata plus media absence", () => {
  for (const dialect of ["firebase", "gcs"]) {
    const recipe = recipeNamed(`${dialect}/delete`);
    const deletes = recipe.steps
      .map((s, i) => (s.method === "DELETE" ? i : -1))
      .filter((i) => i >= 0);
    assert.equal(deletes.length, 2);
    for (const index of deletes)
      assert.deepEqual(
        recipe.steps.slice(index + 1, index + 3).map((s) => [s.method, s.query.alt ?? null]),
        [
          ["GET", null],
          ["GET", "media"],
        ],
      );
  }
});

test("overwrite has distinct bytes and metadata baselines before and after", () => {
  const recipe = recipeNamed("firebase/overwrite");
  const uploads = recipe.steps.filter((s) => s.method === "POST");
  assert.equal(uploads.length, 2);
  assert.notDeepEqual(bodyBytes(uploads[0]), bodyBytes(uploads[1]));
  assert.ok(recipe.steps[1].body.json.metadata);
  assert.deepEqual(
    recipe.steps.map((s) => s.method),
    ["POST", "PATCH", "GET", "GET", "POST", "GET", "GET"],
  );
});

test("missing-object declarations never upload and retain readbacks after mutations", () => {
  const recipe = recipeNamed("errors/missing");
  assert.equal(
    recipe.steps.some((s) => s.method === "POST"),
    false,
  );
  for (const dialect of ["firebase", "gcs"]) {
    const steps = recipe.steps.filter((s) => s.dialect === dialect);
    assert.deepEqual(
      steps.map((s) => s.method),
      ["GET", "GET", "PATCH", "GET", "GET", "DELETE", "GET", "GET"],
    );
    assert.deepEqual(
      steps.filter((s) => s.method === "GET").map((s) => s.query.alt ?? null),
      [null, "media", null, "media", null, "media"],
    );
  }
});

test("invalid ranges cover both dialects and the empty-object boundary with full readbacks", () => {
  const recipe = recipeNamed("errors/range");
  const uploads = recipe.steps.filter((s) => s.method === "POST");
  assert.equal(uploads.length, 2);
  assert.equal(bodyBytes(uploads[0]).length, 5);
  assert.equal(bodyBytes(uploads[1]).length, 0);
  for (const dialect of ["firebase", "gcs"]) {
    const ranged = recipe.steps.filter((s) => s.dialect === dialect && s.headers.range);
    assert.deepEqual(
      ranged.map((s) => s.headers.range),
      ["invalid", "bytes=3-1", "bytes=99-", "bytes=-0", "bytes=0-0", "bytes=0-", "bytes=-1"],
    );
    for (const rangedStep of ranged) {
      const i = recipe.steps.indexOf(rangedStep);
      const after = recipe.steps.slice(i + 1, i + 3);
      assert.deepEqual(
        after.map((s) => [s.dialect, s.method, s.query.alt ?? null, s.headers.range ?? null]),
        [
          [dialect, "GET", null, null],
          [dialect, "GET", "media", null],
        ],
      );
    }
  }
});

test("request IDs and owned names are distinct and request bodies stay bounded", () => {
  const corpus = buildCorpus({ ...input, prefix: "x".repeat(255) + "/" });
  const names = corpus.recipes.flatMap((r) => r.objects);
  assert.equal(new Set(names).size, names.length);
  for (const recipe of corpus.recipes) {
    const requests = allRequests(recipe);
    assert.equal(new Set(requests.map((r) => r.id)).size, requests.length);
    for (const request of requests) {
      if (request.sessionUriReference) {
        assert.equal(request.path, undefined);
        assert.ok(bodyBytes(request).length <= 262144);
      } else {
        assert.ok(Buffer.byteLength(request.path) <= 2048);
        assert.ok(bodyBytes(request).length <= 2048);
      }
      assert.equal(request.expectedStatus, undefined);
      assert.deepEqual(request.responseCapture, {
        status: true,
        headers: "all",
        body: "raw-bytes",
      });
    }
  }
});
