// The answers production gave to probe-v4 (recorded/probe-v4.json): a write whose
// `ifGenerationNotMatch` or `ifMetagenerationNotMatch` names the object's current value is answered
// 304, with no body, on PATCH, PUT, upload and DELETE, and a PUT whose preconditions hold is
// accepted with the object resource. Both precondition recipes are replayed through the recorder's
// own adapter and sender against a stateful fake that answers in those shapes, and must finish with
// nothing left. Nothing here sends a request.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { isRefusedWriteStatus } from "./storage-object/ownership.mjs";
import { replayLocalPreconditions } from "./storage-object/precondition-replay.mjs";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const recorded = JSON.parse(
  readFileSync(new URL("./storage-object/recorded/probe-v4.json", import.meta.url), "utf8"),
);
const BUCKET = "fireemu-oracle-query.firebasestorage.app";
const GUARDS = [
  ["ifGenerationMatch", "generation", false],
  ["ifGenerationNotMatch", "generation", true],
  ["ifMetagenerationMatch", "metageneration", false],
  ["ifMetagenerationNotMatch", "metageneration", true],
];
const RECIPES = [
  "storage-object/gcs/generation-preconditions",
  "storage-object/gcs/metageneration-preconditions",
];
const resourceKeys = (id) => Object.keys(JSON.parse(recorded.answers[id].body));

/**
 * A production-shaped fake. `notMatch` is how a guard that names the current value is answered:
 * 304 with no body (recorded), 412 (what the judges assumed before), or accepted. A guard that does
 * not hold is 412, a malformed value 400, and a PUT or PATCH that is accepted answers with the
 * object resource whose keys are the recorded ones and whose metageneration is one more.
 */
function production({ notMatch = 304 } = {}) {
  const plan = buildStage3DraftPlan({
    projectId: "fireemu-oracle-query",
    bucket: BUCKET,
    runIds: ["recordone", "recordtwo"],
  });
  const objects = new Map();
  const seen = { PATCH: 0, PUT: 0, refused: 0 };
  let generation = 1_790_786_508_000_000n;
  const resource = (o) => ({
    kind: "storage#object",
    id: `${BUCKET}/${o.name}/${o.generation}`,
    selfLink: `https://www.googleapis.com/storage/v1/b/${BUCKET}/o/${encodeURIComponent(o.name)}`,
    mediaLink: `https://storage.googleapis.com/download/storage/v1/b/${BUCKET}/o/${encodeURIComponent(o.name)}?generation=${o.generation}&alt=media`,
    name: o.name,
    bucket: BUCKET,
    generation: o.generation,
    metageneration: `${o.metageneration}`,
    contentType: o.contentType,
    storageClass: "STANDARD",
    size: `${o.bytes.length}`,
    md5Hash: "6JnTKwgIrXzMisIUzQRzpw==",
    crc32c: "vjoVNQ==",
    etag: `etag-${o.metageneration}`,
    timeCreated: "2026-09-30T16:41:48.196Z",
    updated: "2026-09-30T16:41:48.196Z",
    timeStorageClassUpdated: "2026-09-30T16:41:48.196Z",
    timeFinalized: "2026-09-30T16:41:48.196Z",
    ...(Object.keys(o.metadata).length > 0 ? { metadata: o.metadata } : {}),
  });
  const judge = (query, o) => {
    for (const [key, field, negated] of GUARDS) {
      if (!query.has(key)) continue;
      const value = query.get(key);
      if (!/^[0-9]+$/.test(value)) return 400;
      const current =
        field === "generation" ? (o ? o.generation : "0") : (o?.metageneration ?? null);
      if (current === null) return 412;
      if (negated ? value === `${current}` : value !== `${current}`)
        return negated ? notMatch : 412;
    }
    return 0;
  };
  const refusal = (status) => {
    seen.refused++;
    return status === 304
      ? new Response(null, { status: 304, headers: { "content-type": "application/json" } })
      : Response.json(
          { error: { code: status, message: "Precondition Failed", errors: [] } },
          { status },
        );
  };
  const sender = createLocalStorageSender({
    plan,
    origin: "http://127.0.0.1:9199",
    credentials: { admin: "Bearer owner" },
    onStart: async () => {},
    onReserve: async () => {},
    onJournal: async () => {},
    fetchImpl: async (href, init) => {
      const url = new URL(href);
      const query = url.searchParams;
      const method = init.method;
      const v0 = url.pathname.startsWith("/v0/");
      if (method === "GET" && url.pathname === `/storage/v1/b/${BUCKET}/o`)
        return Response.json({
          kind: "storage#objects",
          ...(objects.size > 0
            ? {
                items: [...objects.values()]
                  .filter((o) => o.name.startsWith(query.get("prefix")))
                  .map(resource),
              }
            : {}),
        });
      const name = query.get("name") ?? decodeURIComponent(url.pathname.split("/o/")[1]);
      const o = objects.get(name);
      const verdict = judge(query, o);
      if (verdict === 400)
        return Response.json({ error: { code: 400, message: "Invalid value" } }, { status: 400 });
      if (method === "POST") {
        if (verdict) return refusal(verdict);
        generation += 1000n;
        const made = {
          name,
          generation: `${generation}`,
          metageneration: 1,
          contentType: "application/octet-stream",
          bytes: Buffer.from(init.body),
          metadata: {},
        };
        objects.set(name, made);
        return Response.json(resource(made));
      }
      if (!o)
        return Response.json({ error: { code: 404, message: "No such object" } }, { status: 404 });
      if (method === "DELETE") {
        if (verdict) return refusal(verdict);
        objects.delete(name);
        return new Response(null, { status: 204 });
      }
      if (method === "PATCH" || method === "PUT") {
        if (verdict) return refusal(verdict);
        seen[method]++;
        const body = JSON.parse(Buffer.from(init.body).toString());
        o.metadata = method === "PUT" ? (body.metadata ?? {}) : { ...o.metadata, ...body.metadata };
        if (body.contentType) o.contentType = body.contentType;
        o.metageneration += 1;
        return Response.json(resource(o));
      }
      if (verdict) return refusal(verdict);
      if (query.get("alt") === "media") return new Response(o.bytes);
      if (v0 && !o.token) {
        // A Firebase metadata read mints a download token, which raises the metageneration.
        o.token = `00000000-0000-4000-8000-${`${o.metageneration}`.padStart(12, "0")}`;
        o.metageneration += 1;
      }
      const out = resource(o);
      if (v0) {
        delete out.kind;
        out.downloadTokens = o.token;
      }
      return Response.json(out);
    },
  });
  return { sender, objects, seen, plan };
}

async function replay(recipeId, options) {
  const fake = production(options);
  const recipe = buildCorpus({
    bucket: BUCKET,
    prefix: fake.plan.recordings[0].prefix,
  }).recipes.find((row) => row.id === recipeId);
  const captures = [];
  const result = await replayLocalPreconditions({
    bucket: BUCKET,
    recipe,
    sender: fake.sender,
    onCapture: async (row) => captures.push(row),
  });
  return { ...fake, result, captures };
}

for (const recipeId of RECIPES)
  for (const notMatch of [304, 412]) {
    test(`${recipeId}, with the guard that names the current value answered ${notMatch}, finishes with nothing left`, async () => {
      const run = await replay(recipeId, { notMatch });
      assert.equal(run.result.failure ?? null, null);
      assert.equal(run.result.status, "LOCAL_COMPLETE");
      assert.deepEqual(run.result.unresolved, []);
      assert.deepEqual(run.result.cleanupFailures, []);
      assert.equal(run.objects.size, 0);
      const answers = run.captures.filter((row) => row.status === notMatch);
      assert.ok(answers.length > 0, `some write is answered ${notMatch}`);
      if (notMatch === 304)
        for (const row of answers) assert.equal(Buffer.from(row.bodyBase64, "base64").length, 0);
    });
  }

test("a guard that names the current value and is nevertheless accepted still finishes with nothing left", async () => {
  for (const recipeId of RECIPES) {
    const run = await replay(recipeId, { notMatch: 0 });
    assert.equal(run.result.status, "LOCAL_COMPLETE", recipeId);
    assert.equal(run.objects.size, 0, recipeId);
  }
});

test("the accepted PUT and PATCH of the metageneration recipe are judged against the recorded resource", async () => {
  const run = await replay(RECIPES[1]);
  assert.ok(run.seen.PUT >= 2, `${run.seen.PUT} PUTs accepted`);
  assert.ok(run.seen.PATCH >= 2, `${run.seen.PATCH} PATCHes accepted`);
  const accepted = run.captures.filter(
    (row) =>
      row.status === 200 && /^(put|patch)-ifMetagenerationMatch-current$/.test(row.operationId),
  );
  assert.equal(accepted.length, 2);
  // The fake answers with exactly the keys production answered the accepted PUT with.
  for (const row of accepted) {
    const keys = Object.keys(JSON.parse(Buffer.from(row.bodyBase64, "base64").toString()));
    assert.deepEqual(keys.toSorted(), resourceKeys("put-metageneration-match").toSorted());
  }
});

test("the recorded answers are what the fake assumes: 304 with no body, and an accepted PUT with the resource", () => {
  for (const id of [
    "patch-generation-not-match",
    "patch-metageneration-not-match",
    "put-generation-not-match",
    "put-metageneration-not-match",
    "upload-generation-not-match",
    "upload-metageneration-not-match",
    "delete-generation-not-match",
    "delete-metageneration-not-match",
  ]) {
    assert.equal(recorded.answers[id].status, 304, id);
    assert.equal(recorded.answers[id].body, "", id);
  }
  for (const id of ["put-metageneration-match", "put-metageneration-not-match-stale"]) {
    const body = JSON.parse(recorded.answers[id].body);
    assert.equal(recorded.answers[id].status, 200);
    assert.equal(body.kind, "storage#object");
    assert.equal(body.bucket, BUCKET);
    assert.match(body.generation, /^[1-9][0-9]*$/);
    assert.deepEqual(body.metadata, { preconditionMarker: "subject-update" });
  }
  // The metageneration moved 1, 2, 3 across the two accepted PUTs: each PUT raised it by one.
  assert.equal(JSON.parse(recorded.answers["target-create"].body).metageneration, "1");
  assert.equal(JSON.parse(recorded.answers["put-metageneration-match"].body).metageneration, "2");
  assert.equal(
    JSON.parse(recorded.answers["put-metageneration-not-match-stale"].body).metageneration,
    "3",
  );
  // The Firebase wrong-offset chunk: 400, the session alive, the cancel answered `cancelled`.
  assert.equal(recorded.answers["firebase-session-wrong-offset"].status, 400);
  assert.equal(
    recorded.answers["firebase-session-query-after"].headers["x-goog-upload-status"],
    "active",
  );
  assert.equal(
    recorded.answers["firebase-session-cancel"].headers["x-goog-upload-status"],
    "cancelled",
  );
  assert.equal(
    recorded.answers["firebase-session-query-after-cancel"].headers["x-goog-upload-status"],
    "cancelled",
  );
  assert.equal(
    "x-goog-upload-size-received" in
      recorded.answers["firebase-session-query-after-cancel"].headers,
    false,
  );
});

test("a write is refused by 304 or by any status from 400 to 599, and by nothing else", () => {
  for (const status of [304, 400, 404, 412, 499, 500, 501, 503, 599])
    assert.equal(isRefusedWriteStatus(status), true, String(status));
  for (const status of [
    0,
    200,
    201,
    204,
    206,
    300,
    301,
    302,
    303,
    305,
    307,
    308,
    399,
    600,
    700,
    -304,
    304.5,
    NaN,
    Infinity,
    "304",
    "412",
    null,
    undefined,
  ])
    assert.equal(isRefusedWriteStatus(status), false, String(status));
});

test("only the two precondition recipes carry a not-match guard, so only they can meet a 304 on a write", () => {
  const corpus = buildCorpus({ bucket: BUCKET, prefix: "storage-object/recordone/" });
  const withGuard = new Set();
  for (const recipe of corpus.recipes)
    for (const step of [...recipe.steps, ...(recipe.preflight ?? []), ...(recipe.cleanup ?? [])])
      if (Object.keys(step.query ?? {}).some((key) => /NotMatch$/i.test(key)))
        withGuard.add(recipe.id);
  assert.deepEqual([...withGuard].toSorted(), RECIPES.toSorted());
  // No step sends a conditional header either, which would be answered 304 as well.
  for (const recipe of corpus.recipes)
    for (const step of recipe.steps)
      for (const header of Object.keys(step.headers ?? {}))
        assert.doesNotMatch(header, /^if-(none-match|modified-since)$/i, `${recipe.id} ${step.id}`);
});
