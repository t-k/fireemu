// The answers production gave to probe-v3 (recorded/probe-v3.json), replayed through the recorder's
// own ownership, session, copy and rewrite, download-token and list judges: the five shapes whose
// clean-up depended on the answer (GCS multipart, GCS and Firebase resumable completion, copy and
// rewrite, delete_token) and GCS lists that hold objects, with paging. Nothing here sends a request.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { evaluateListPages } from "./storage-object/list-pages.mjs";
import { evaluateRewriteAttempts } from "./storage-object/rewrite-attempts.mjs";
import { resolveFirebaseDownloadToken } from "./storage-object/download-token-resolution.mjs";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const recorded = JSON.parse(
  readFileSync(new URL("./storage-object/recorded/probe-v3.json", import.meta.url), "utf8"),
);
const RUN = recorded.runId;
const BUCKET = "fireemu-oracle-query.firebasestorage.app";
const ORIGIN = "http://127.0.0.1:9199";
const plan = buildStage3DraftPlan({
  projectId: "fireemu-oracle-query",
  bucket: BUCKET,
  runIds: [RUN, "fedcba9876543210fedc"],
});
const prefix = plan.recordings[0].prefix;
const scope = `${prefix}probe3/`;

/** The recorded body with its object names moved from the probe's scope to the recorder's prefix. */
const moved = (text) => text.replaceAll(scope, prefix);
const answer = (id, { headers = {}, body } = {}) => {
  const row = recorded.answers[id];
  assert.ok(row, id);
  return new Response(row.status === 204 ? null : (body ?? moved(row.body)), {
    status: row.status,
    headers: { ...row.headers, ...headers },
  });
};
const bodyOf = (id) => moved(recorded.answers[id].body);

const gcsPath = (name) => `/storage/v1/b/${BUCKET}/o/${encodeURIComponent(name)}`;
const bytes262147 = Buffer.concat([Buffer.alloc(262144, 0x5a), Buffer.from([0, 1, 255])]);
const sha = (buffer) => createHash("sha256").update(buffer).digest("hex");

function makeSender(production) {
  const sent = [];
  const sender = createLocalStorageSender({
    plan,
    origin: ORIGIN,
    credentials: { admin: "Bearer owner" },
    onStart: async () => {},
    onReserve: async () => {},
    onJournal: async () => {},
    fetchImpl: async (href, init) => {
      const url = new URL(href);
      sent.push({
        method: init.method,
        path: url.pathname,
        query: Object.fromEntries(url.searchParams),
      });
      if (init.method === "GET" && url.pathname === `/storage/v1/b/${BUCKET}/o`)
        return answer("final-list");
      return production(init.method, url, init);
    },
  });
  return { sender, sent };
}

/**
 * Upload an object as the caller does, read it back through the GCS routes with the recorded
 * metadata, prove ownership, and remove it with the recorded delete and absence answers.
 */
async function ownAndRemove({ name, upload, uploadStep, metadata, media, session }) {
  let deleted = false;
  const { sender, sent } = makeSender((method, url, init) => {
    if (method === "DELETE") {
      deleted = true;
      return answer("cleanup-delete-0");
    }
    if (url.pathname === gcsPath(name)) {
      if (deleted)
        return url.searchParams.get("alt") === "media"
          ? new Response("No such object", {
              status: 404,
              headers: { "content-type": "text/html" },
            })
          : answer("cleanup-absent-0", { body: JSON.stringify({ error: { code: 404 } }) });
      if (url.searchParams.get("alt") === "media") return new Response(media);
      return answer(metadata.id, { body: metadata.body });
    }
    return upload(method, url, init);
  });
  await sender.start();
  await sender.admitNamespace();
  sender.admitObject(name);
  if (session) await session(sender);
  else await sender.sendStep({ ...uploadStep, objectName: name });
  for (const [id, query] of [
    ["metadata", {}],
    ["media", { alt: "media" }],
  ])
    await sender.sendStep({
      id,
      dialect: "gcs",
      method: "GET",
      objectName: name,
      path: gcsPath(name),
      query,
    });
  const generation = sender.confirmOwned({
    name,
    uploadOperationId: uploadStep.id,
    metadataOperationId: "metadata",
    mediaOperationId: "media",
    expectedBytesSha256: sha(media),
  });
  assert.match(generation, /^[1-9][0-9]{0,19}$/);
  sender.beginCleanup();
  const deletion = await sender.cleanupOwned({
    name,
    metadataOperationId: "metadata",
    mediaOperationId: "media",
    operationId: "cleanup",
  });
  assert.equal(deletion.status, 204);
  assert.deepEqual(sender.unresolved(), []);
  return { sender, sent, generation };
}

const corpus = buildCorpus({ bucket: BUCKET, prefix });
const recipe = (id) => corpus.recipes.find((row) => row.id === id);

// ---- GCS multipart ------------------------------------------------------------------------------------

test("GCS multipart: the upload answer is an owned upload once the readback agrees, and the object is removed", async () => {
  const step = recipe("storage-object/gcs/simple-multipart-upload").steps.find(
    (row) => row.id === "valid",
  );
  const name = `${prefix}multipart/gcs/valid.bin`;
  const { generation } = await ownAndRemove({
    name: step.objectName,
    upload: () => answer("multipart-create"),
    uploadStep: step,
    metadata: { id: "cleanup-metadata-0" },
    media: Buffer.from("test"),
  });
  assert.equal(step.objectName, name);
  assert.equal(generation, JSON.parse(bodyOf("multipart-create")).generation);
});

// ---- GCS resumable: chunk, status probe, completion ----------------------------------------------------------

test("GCS resumable: the recorded chunk (308 with Range), status probe and completion carry the upload to an owned object", async () => {
  const gcs = recipe("storage-object/gcs/resumable-upload");
  const name = gcs.objects[0];
  const location = `${ORIGIN}/upload/storage/v1/b/${BUCKET}/o?uploadType=resumable&name=${encodeURIComponent(name)}&ifGenerationMatch=0&upload_id=AbC-1_x`;
  const run = await ownAndRemove({
    name,
    uploadStep: gcs.steps.find((row) => row.id === "finish"),
    upload: (method, url, init) => {
      if (method === "POST") {
        const start = answer("gcs-resumable-start");
        const headers = new Headers(start.headers);
        headers.set("location", location);
        return new Response("", { status: 200, headers });
      }
      const range = new Headers(init.headers).get("content-range");
      if (range.startsWith("bytes 0-"))
        return answer("gcs-resumable-chunk", { headers: { range: "bytes=0-262143" } });
      if (range.startsWith("bytes */")) return answer("gcs-resumable-status");
      return answer("gcs-resumable-finish");
    },
    metadata: { id: "cleanup-metadata-1" },
    media: bytes262147,
    session: async (sender) => {
      await sender.sendStep(gcs.steps.find((row) => row.id === "initiate"));
      sender.bindSession({ recipe: gcs, initiateOperationId: "initiate" });
      const chunk = await sender.sendSessionStep({ recipe: gcs, stepIndex: 1 });
      assert.equal(chunk.status, 308);
      assert.equal(chunk.headers.range, "bytes=0-262143");
      const status = await sender.sendSessionStep({ recipe: gcs, stepIndex: 2 });
      assert.equal(status.status, 308);
      assert.equal(status.headers.range, "bytes=0-262143");
      const finish = await sender.sendSessionStep({ recipe: gcs, stepIndex: 3 });
      assert.equal(finish.status, 200);
    },
  });
  assert.equal(run.generation, JSON.parse(bodyOf("gcs-resumable-finish")).generation);
  // The three continuation requests went to the session URL production named.
  assert.equal(run.sent.filter((row) => row.method === "PUT").length, 3);
});

// ---- Firebase resumable in chunks --------------------------------------------------------------------------------

test("Firebase resumable: start, query, chunk, query after the chunk, and finalize are accepted, and the object is owned once read back", async () => {
  const firebase = recipe("storage-object/firebase/resumable-upload");
  const name = firebase.objects[0];
  const url = `${ORIGIN}/v0/b/${BUCKET}/o?name=${encodeURIComponent(name)}&upload_id=Qz-9_y&upload_protocol=resumable`;
  const finalize = JSON.parse(bodyOf("firebase-resumable-finish"));
  const run = await ownAndRemove({
    name,
    uploadStep: firebase.steps.find((row) => row.id === "finish"),
    upload: (method, _url, init) => {
      const command = new Headers(init.headers).get("x-goog-upload-command");
      if (command === "start") {
        const start = answer("firebase-resumable-start");
        const headers = new Headers(start.headers);
        headers.set("x-goog-upload-url", url);
        return new Response("", { status: 200, headers });
      }
      if (command === "query") {
        return init.body === undefined && chunked.done
          ? answer("firebase-resumable-query-after-chunk")
          : answer("firebase-resumable-query");
      }
      if (command === "upload") {
        chunked.done = true;
        return answer("firebase-resumable-chunk");
      }
      return answer("firebase-resumable-finish");
    },
    metadata: { id: "cleanup-metadata-2" },
    media: bytes262147,
    session: async (sender) => {
      const step = (id) => firebase.steps.findIndex((row) => row.id === id);
      await sender.sendStep(firebase.steps[step("initiate")]);
      sender.bindSession({ recipe: firebase, initiateOperationId: "initiate" });
      const initial = await sender.sendSessionStep({
        recipe: firebase,
        stepIndex: step("query-initial"),
      });
      assert.equal(initial.headers["x-goog-upload-size-received"], "0");
      const chunk = await sender.sendSessionStep({ recipe: firebase, stepIndex: step("chunk-0") });
      assert.equal(chunk.headers["x-goog-upload-status"], "active");
      const progress = await sender.sendSessionStep({
        recipe: firebase,
        stepIndex: step("query-progress"),
      });
      assert.equal(progress.headers["x-goog-upload-size-received"], "262144");
      const done = await sender.sendSessionStep({ recipe: firebase, stepIndex: step("finish") });
      assert.equal(done.headers["x-goog-upload-status"], "final");
    },
  });
  assert.equal(run.generation, finalize.generation);
  assert.equal(finalize.size, "262147");
});
const chunked = { done: false };

// ---- copy and rewrite ---------------------------------------------------------------------------------------

test("copyTo: the answer is an owned object once the destination reads back the same generation", async () => {
  const copy = recipe("storage-object/gcs/copy-rewrite");
  const step = copy.steps.find((row) => row.id === "copy");
  const resource = JSON.parse(bodyOf("copy-to"));
  assert.equal(resource.name, step.objectName);
  await ownAndRemove({
    name: step.objectName,
    upload: () => answer("copy-to"),
    uploadStep: {
      ...step,
      query: {
        ifGenerationMatch: "0",
        ifSourceGenerationMatch: "1",
        ifSourceMetagenerationMatch: "1",
      },
    },
    metadata: { id: "cleanup-metadata-4" },
    media: Buffer.from("copy!"),
  });
});

test("rewriteTo: the recorded one-call answer (done, no token, the resource) is a complete rewrite", () => {
  const copy = recipe("storage-object/gcs/copy-rewrite");
  const first = copy.steps.find((row) => row.id === "rewrite-0");
  const result = evaluateRewriteAttempts({
    recipe: copy,
    bucket: BUCKET,
    attempts: [
      {
        stepId: "rewrite-0",
        query: {
          ifGenerationMatch: "0",
          ifSourceGenerationMatch: "1790783220947288",
          ifSourceMetagenerationMatch: "1",
        },
        status: 200,
        bodyBase64: Buffer.from(bodyOf("rewrite-0")).toString("base64"),
      },
    ],
  });
  assert.equal(result.status, "MATCHED_SUPPLIED_REWRITE");
  assert.equal(result.attempts, 1);
  assert.equal(result.objectSize, "5");
  assert.equal(result.destinationName, first.transfer.destinationName);
  // The answer names no token: the recipe's later rewrite slots are not sent when done.
  assert.equal(JSON.parse(bodyOf("rewrite-0")).rewriteToken, undefined);
});

// ---- create_token and delete_token -----------------------------------------------------------------------------

test("delete_token: the token to delete is the one new token create_token added, in the recorded form", () => {
  const tokens = recipe("storage-object/firebase/download-tokens");
  const name = tokens.objects[0];
  const path = `/v0/b/${BUCKET}/o/${encodeURIComponent(name)}`;
  const reference = tokens.steps.find((row) => row.id === "delete-token").query.delete_token;
  const uploaded = JSON.parse(bodyOf("token-upload"));
  const created = JSON.parse(bodyOf("token-create"));
  assert.match(uploaded.downloadTokens, /^[0-9a-f-]{36}$/, "one UUID after the upload");
  assert.equal(
    created.downloadTokens.split(",").length,
    2,
    "the new one and the old one, comma-joined",
  );
  const evidence = (id, step, body) => ({
    step: { ...tokens.steps.find((row) => row.id === step), objectName: name, path },
    response: { status: 200, raw: Buffer.from(body) },
    id,
  });
  const token = resolveFirebaseDownloadToken({
    reference,
    prior: evidence(
      "prior",
      "after-upload-firebase-metadata",
      JSON.stringify({ ...uploaded, name, bucket: BUCKET }),
    ),
    created: evidence(
      "created",
      "create-token",
      JSON.stringify({ ...created, name, bucket: BUCKET }),
    ),
    bucket: BUCKET,
    name,
  });
  const before = new Set(uploaded.downloadTokens.split(","));
  assert.ok(!before.has(token), "the token is not the old one");
  assert.ok(created.downloadTokens.split(",").includes(token));
  // delete_token answers 200 with the object, the token removed and the metageneration bumped.
  const deleted = JSON.parse(bodyOf("token-delete"));
  assert.equal(deleted.downloadTokens, uploaded.downloadTokens);
  assert.equal(deleted.metageneration, "3");
});

// ---- GCS lists that hold objects, with paging ----------------------------------------------------------------------

test("GCS lists: real item resources, real next-page tokens and a real delimiter list satisfy the page judges", () => {
  const pages = ["list-page-1", "list-page-2", "list-page-3", "list-page-4"].map((id) =>
    JSON.parse(bodyOf(id)),
  );
  const [first, second, third, fourth] = pages;
  // Every page is a `storage#objects` with full `storage#object` items; all but the last carry a
  // token, and the tokens are the base64 (with padding) production gave.
  for (const page of pages) assert.equal(page.kind, "storage#objects");
  for (const page of [first, second, third]) assert.match(page.nextPageToken, /^[A-Za-z0-9+/]+=*$/);
  assert.equal(fourth.nextPageToken, undefined);
  assert.equal(pages.flatMap((page) => page.items).length, 7);
  const item = first.items[0];
  for (const key of [
    "kind",
    "id",
    "selfLink",
    "mediaLink",
    "name",
    "bucket",
    "generation",
    "metageneration",
    "size",
    "md5Hash",
    "crc32c",
    "etag",
  ])
    assert.ok(key in item, key);
  // The page judge takes them: the list recipe's declared pages, with real-shaped items and tokens.
  const list = recipe("storage-object/gcs/list");
  const scopeName = `${prefix}list/gcs/`;
  const real = (name) => ({ ...item, name: `${scopeName}${name}`, bucket: BUCKET });
  const parts = [
    { items: [real("a.txt"), real("b.txt")], prefixes: [`${scopeName}dir/`] },
    { items: [real("zz.txt")], prefixes: [`${scopeName}dir2/`] },
  ];
  const evaluated = evaluateListPages({
    recipe: list,
    bucket: BUCKET,
    pages: parts.map((part, index) => {
      const step = list.steps.find((row) => row.id === `page-${index}`);
      return {
        stepId: step.id,
        query: { ...step.query, ...(index ? { pageToken: first.nextPageToken } : {}) },
        status: 200,
        bodyBase64: Buffer.from(
          JSON.stringify({
            kind: "storage#objects",
            ...part,
            ...(index < parts.length - 1 ? { nextPageToken: first.nextPageToken } : {}),
          }),
        ).toString("base64"),
      };
    }),
  });
  assert.equal(evaluated.status, "MATCHED_SUPPLIED_PAGES");
  assert.equal(evaluated.itemCount, 3);
});

test("the delimiter list answers prefixes with no items key, and the empty prefix list has neither", () => {
  const delimited = JSON.parse(bodyOf("list-delimiter"));
  assert.equal(delimited.kind, "storage#objects");
  assert.equal(delimited.items, undefined);
  assert.equal(delimited.prefixes.length, 4);
  assert.deepEqual(JSON.parse(bodyOf("final-list")), { kind: "storage#objects" });
});
