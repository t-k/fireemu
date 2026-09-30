import assert from "node:assert/strict";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { replayLocalBasic } from "./storage-object/basic-replay.mjs";
import { replayLocalAdmin } from "./storage-object/admin-replay.mjs";
import { replayLocalList } from "./storage-object/list-replay.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { createLocalStorageSender } from "./storage-object/sender.mjs";
import { buildStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

function fixture({
  recipeId = "storage-object/firebase/simple-upload",
  driftBeforeCleanup = false,
  occupied = false,
  localListGapStatus = null,
  localListGapReason = "invalid",
  listAnswer = null,
} = {}) {
  const plan = buildStage3DraftPlan({
    projectId: "example-project",
    bucket: "example.appspot.com",
    runIds: ["recordone", "recordtwo"],
  });
  const recipe = buildCorpus({
    bucket: plan.bucket,
    prefix: plan.recordings[0].prefix,
  }).recipes.find((row) => row.id === recipeId);
  const objects = new Map(),
    reservations = [],
    deleted = [],
    events = [];
  let generation = 9007199254740993n;
  const listCalls = new Map();
  let sender;
  sender = createLocalStorageSender({
    plan,
    origin: "http://127.0.0.1:9199",
    credentials: { admin: "Bearer owner" },
    onStart: async () => events.push("started"),
    onReserve: async (row) => {
      reservations.push(row);
      events.push("reserved");
    },
    onJournal: async () => events.push("journal"),
    fetchImpl: async (href, init) => {
      events.push("wire");
      const url = new URL(href);
      if (
        [`/storage/v1/b/${plan.bucket}/o`, `/v0/b/${plan.bucket}/o`].includes(url.pathname) &&
        init.method === "GET"
      ) {
        const parameter = ["startOffset", "matchGlob"].find((key) => url.searchParams.has(key));
        if (parameter && localListGapStatus !== null) {
          const message = `unsupported JSON API list parameter: ${parameter}`;
          return Response.json(
            {
              error: {
                code: localListGapStatus,
                message,
                errors: [{ domain: "global", message, reason: localListGapReason }],
              },
            },
            { status: localListGapStatus },
          );
        }
        const nth = (listCalls.get(url.pathname) ?? 0) + 1;
        listCalls.set(url.pathname, nth);
        const scripted = listAnswer?.({ url, path: url.pathname, nth, query: url.searchParams });
        if (scripted) return scripted;
        const scope = url.searchParams.get("prefix");
        const delimiter = url.searchParams.get("delimiter");
        const entries = new Map();
        for (const row of objects.values()) {
          if (!row.metadata.name.startsWith(scope)) continue;
          const suffix = row.metadata.name.slice(scope.length);
          const boundary = delimiter ? suffix.indexOf(delimiter) : -1;
          if (boundary >= 0) {
            const name = `${scope}${suffix.slice(0, boundary + delimiter.length)}`;
            entries.set(name, { prefix: name });
          } else entries.set(row.metadata.name, { item: row.metadata });
        }
        const sorted = [...entries].toSorted(([a], [b]) => a.localeCompare(b));
        const offset = Number(url.searchParams.get("pageToken") ?? 0);
        const limit = Number(url.searchParams.get("maxResults")) || 1000;
        const page = sorted.slice(offset, offset + limit).map(([, value]) => value);
        return Response.json({
          items: occupied
            ? [{ bucket: plan.bucket, name: `${plan.recordings[0].prefix}foreign.bin` }]
            : page.flatMap((row) => (row.item ? [row.item] : [])),
          prefixes: page.flatMap((row) => (row.prefix ? [row.prefix] : [])),
          ...(offset + limit < sorted.length ? { nextPageToken: `${offset + limit}` } : {}),
        });
      }
      const name = url.searchParams.get("name") ?? decodeURIComponent(url.pathname.split("/o/")[1]);
      if (init.method === "POST") {
        const bytes = Buffer.from(init.body);
        const metadata = {
          kind: "storage#object",
          bucket: plan.bucket,
          name,
          generation: `${generation++}`,
          metageneration: "1",
          size: `${bytes.length}`,
        };
        objects.set(name, { bytes, metadata });
        return Response.json(metadata);
      }
      const object = objects.get(name);
      if (driftBeforeCleanup && sender.snapshot().mode === "cleanup" && object) {
        object.bytes = Buffer.from("changed-by-another-writer");
        object.metadata.generation = "9007199254740999";
      }
      if (init.method === "DELETE") {
        assert.ok(object);
        if (
          sender.snapshot().mode === "cleanup" &&
          url.searchParams.get("ifGenerationMatch") !== object.metadata.generation
        )
          return Response.json({ error: "precondition failed" }, { status: 412 });
        deleted.push(name);
        objects.delete(name);
        return new Response(null, { status: 204 });
      }
      if (!object) return Response.json({ error: "missing" }, { status: 404 });
      if (url.searchParams.get("alt") === "media") return new Response(object.bytes);
      return Response.json(object.metadata);
    },
  });
  return { sender, recipe, bucket: plan.bucket, objects, reservations, deleted, events };
}

test("the extracted basic replay retains counted admission, fresh ownership and final absence", async () => {
  const f = fixture();
  const result = await replayLocalBasic(f);
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.equal(result.requests, 12);
  assert.equal(f.objects.size, 0);
  assert.equal(f.deleted.length, 1);
  assert.equal(f.sender.snapshot().mode, "closed");
  assert.deepEqual(f.sender.unresolved(), []);
  assert.equal(f.events[0], "started");
  assert.deepEqual(
    f.reservations.map((row) => row.sequence),
    Array.from({ length: 12 }, (_, i) => i + 1),
  );
});

test("extraction preserves a conditional refusal after another writer replaces the owned generation", async () => {
  const f = fixture({ driftBeforeCleanup: true });
  await assert.rejects(replayLocalBasic(f), /conditional delete was not confirmed/);
  assert.equal(f.deleted.length, 0);
  assert.equal(f.objects.size, 1);
  assert.equal(f.sender.unresolved().length, 1);
});

test("an occupied namespace stops an extracted replay before any write or deletion", async () => {
  const f = fixture({ occupied: true });
  await assert.rejects(replayLocalBasic(f), /occupied run prefix/);
  assert.equal(f.reservations.length, 1);
  assert.equal(f.objects.size, 0);
  assert.equal(f.deleted.length, 0);
});

test("the extracted admin replay retains both dialects, subject deletion and final absence", async () => {
  const f = fixture({ recipeId: "storage-object/auth/admin" });
  const result = await replayLocalAdmin(f);
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.equal(result.credentialProof, "LOCAL_STUB_ONLY");
  assert.equal(result.requests, 32);
  assert.equal(f.objects.size, 0);
  assert.equal(f.deleted.length, 2);
  assert.deepEqual(f.sender.unresolved(), []);
});

test("all six replay modules import with no environment, output or transport side effects", () => {
  const modules = ["basic", "independent", "list", "admin", "object-name", "download-token"];
  const urls = modules.map(
    (name) => new URL(`./storage-object/${name}-replay.mjs`, import.meta.url).href,
  );
  const code = `globalThis.fetch = () => { throw new Error("unexpected transport"); }; process.stdout.write = () => { throw new Error("unexpected output"); }; for (const url of ${JSON.stringify(urls)}) await import(url);`;
  const result = spawnSync(process.execPath, ["--input-type=module", "--eval", code], {
    env: {},
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "");
});

test("explicit local list gap admission records both candidates and retains pagination and owned cleanup", async () => {
  const f = fixture({ recipeId: "storage-object/gcs/list", localListGapStatus: 400 });
  const captures = [];
  const result = await replayLocalList({
    ...f,
    allowKnownLocalListGaps: true,
    onCapture: async (row) => captures.push(row),
  });
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.deepEqual(
    result.localDifferenceCandidates.map(({ stepId, status, parameter }) => ({
      stepId,
      status,
      parameter,
    })),
    [
      { stepId: "offset-filter", status: 400, parameter: "startOffset" },
      { stepId: "glob-filter", status: 400, parameter: "matchGlob" },
    ],
  );
  assert.ok(
    result.localDifferenceCandidates.every((row) => row.compatibility === "UNOBSERVED_PRODUCTION"),
  );
  assert.equal(result.pageEvaluation.status, "MATCHED_SUPPLIED_PAGES");
  assert.equal(result.requests, 73);
  assert.equal(f.deleted.length, 6);
  assert.equal(f.objects.size, 0);
  assert.deepEqual(result.unresolved, []);
  assert.deepEqual(
    captures.filter((row) => row.status === 400).map((row) => row.stepId),
    ["offset-filter", "glob-filter"],
  );
});

test("known local list gaps require opt-in and never admit authorization errors", async () => {
  for (const [status, allowKnownLocalListGaps] of [
    [400, false],
    [401, true],
    [403, true],
    [500, true],
  ]) {
    const f = fixture({ recipeId: "storage-object/gcs/list", localListGapStatus: status });
    await assert.rejects(
      replayLocalList({ ...f, allowKnownLocalListGaps, onCapture: async () => {} }),
      /list response was not 200/,
    );
    assert.equal(f.deleted.length, 0);
    assert.equal(f.sender.unresolved().length, 6);
    assert.equal(f.reservations.at(-1).operationId, "offset-filter");
  }
});

test("local list gap admission cannot excuse another error body, altered query or undeclared step", async () => {
  for (const variation of ["error-body", "query", "step"]) {
    const f = fixture({
      recipeId: "storage-object/gcs/list",
      localListGapStatus: 400,
      ...(variation === "error-body" ? { localListGapReason: "permissionDenied" } : {}),
    });
    const step = f.recipe.steps.find((row) => row.id === "offset-filter");
    if (variation === "query") step.query.startOffset += "changed";
    if (variation === "step") step.id = "unregistered-filter";
    await assert.rejects(
      replayLocalList({ ...f, allowKnownLocalListGaps: true, onCapture: async () => {} }),
      /list response was not 200/,
    );
    assert.equal(f.deleted.length, 0);
    assert.equal(f.sender.unresolved().length, 6);
    assert.equal(f.reservations.at(-1).operationId, step.id);
  }
});

test("local list gap admission requires capture before start and stops if capture fails", async () => {
  const missing = fixture({ recipeId: "storage-object/gcs/list", localListGapStatus: 400 });
  await assert.rejects(
    replayLocalList({ ...missing, allowKnownLocalListGaps: true }),
    /capture writer is required/,
  );
  assert.equal(missing.reservations.length, 0);
  assert.equal(missing.sender.snapshot().mode, "not-started");
  const failed = fixture({ recipeId: "storage-object/gcs/list", localListGapStatus: 400 });
  await assert.rejects(
    replayLocalList({
      ...failed,
      allowKnownLocalListGaps: true,
      onCapture: async ({ stepId }) => {
        if (stepId === "offset-filter") throw new Error("capture fsync failed");
      },
    }),
    /capture fsync failed/,
  );
  assert.equal(failed.reservations.at(-1).operationId, "offset-filter");
  assert.equal(failed.deleted.length, 0);
  assert.equal(failed.sender.unresolved().length, 6);
});

async function seedConfirmed(f) {
  await f.sender.start();
  await f.sender.admitNamespace();
  const name = f.recipe.objects[0];
  f.sender.admitObject(name);
  const [upload, metadata, media] = f.recipe.steps;
  for (const step of [upload, metadata, media]) await f.sender.sendStep(step);
  f.sender.confirmOwned({
    name,
    uploadOperationId: upload.id,
    metadataOperationId: metadata.id,
    mediaOperationId: media.id,
    expectedBytesSha256: createHash("sha256")
      .update(Buffer.from(upload.body.base64, "base64"))
      .digest("hex"),
  });
  return name;
}

test("exception cleanup uses fresh metadata and full media before conditional deletion", async () => {
  const f = fixture();
  await seedConfirmed(f);
  f.sender.beginCleanup();
  const result = await f.sender.cleanupConfirmedOwned();
  assert.equal(result.cleanedNames.length, 1);
  assert.deepEqual(result.cleanupFailures, []);
  assert.deepEqual(result.unresolved, []);
  assert.deepEqual(
    f.reservations.slice(-5).map((row) => row.operationId),
    [
      "exception-cleanup-0-metadata",
      "exception-cleanup-0-media",
      "exception-cleanup-0-delete",
      "exception-cleanup-0-delete-metadata-absence",
      "exception-cleanup-0-delete-media-absence",
    ],
  );
  assert.ok(f.reservations.slice(-5).every((row) => row.phase === "cleanup"));
  await f.sender.verifyRunEmpty();
  f.sender.close();
});

test("exception cleanup retains changed ownership and never deletes the replacement", async () => {
  const f = fixture({ driftBeforeCleanup: true });
  const name = await seedConfirmed(f);
  f.sender.beginCleanup();
  const result = await f.sender.cleanupConfirmedOwned();
  assert.equal(f.deleted.length, 0);
  assert.equal(result.cleanupFailures.length, 1);
  assert.deepEqual(result.unresolved, [name]);
  assert.ok(!f.reservations.some((row) => row.operationId === "exception-cleanup-0-delete"));
});

test("an unconfirmed later mutation cannot borrow the previous cleanup proof", async () => {
  const f = fixture();
  const name = await seedConfirmed(f);
  await f.sender.sendStep({
    id: "unknown-later-write",
    dialect: "gcs",
    method: "PATCH",
    objectName: name,
    path: `/storage/v1/b/${f.bucket}/o/${encodeURIComponent(name)}`,
    query: {},
    credential: "admin",
    body: { json: { metadata: { changed: "yes" } } },
  });
  f.sender.beginCleanup();
  const requests = f.reservations.length;
  const result = await f.sender.cleanupConfirmedOwned();
  assert.equal(f.reservations.length, requests);
  assert.equal(f.deleted.length, 0);
  assert.deepEqual(result.unresolved, [name]);
});

test("a halted provider forbids every new exception cleanup request", async () => {
  const f = fixture();
  const name = await seedConfirmed(f);
  f.sender.beginCleanup();
  const requests = f.reservations.length;
  const result = await f.sender.cleanupConfirmedOwned({ canSend: () => false });
  assert.equal(f.reservations.length, requests);
  assert.equal(f.deleted.length, 0);
  assert.deepEqual(result.unresolved, [name]);
});

test("exhausting the subject cap still leaves exception cleanup and final absence available", async () => {
  const f = fixture();
  const name = await seedConfirmed(f);
  const read = {
    dialect: "gcs",
    method: "GET",
    objectName: name,
    path: `/storage/v1/b/${f.bucket}/o/${encodeURIComponent(name)}`,
    query: {},
    credential: "admin",
  };
  for (let i = f.reservations.length; i < 2000; i++)
    await f.sender.sendStep({ ...read, id: `bounded-read-${i}` });
  await assert.rejects(f.sender.sendStep({ ...read, id: "one-extra" }), /subject cap exhausted/);
  assert.equal(f.reservations.length, 2000);
  f.sender.beginCleanup();
  const result = await f.sender.cleanupConfirmedOwned();
  assert.deepEqual(result.unresolved, []);
  assert.deepEqual(result.cleanupFailures, []);
  await f.sender.verifyRunEmpty();
  f.sender.close();
  assert.deepEqual(f.sender.snapshot().recordings[0], { subject: 2000, cleanup: 6 });
});

// ---- the Firebase list steps production has not (all) answered ---------------------------------

const V0 = (path) => path.startsWith("/v0/");
const zeroLimit = ({ query }) => query.get("maxResults") === "0";
const productionZeroLimit = () =>
  Response.json(
    { error: { code: 400, message: "Expect maxResults to be a positive number." } },
    { status: 400 },
  );
const listOf = (recipeId, listAnswer) => fixture({ recipeId, listAnswer });
const replay = (f) =>
  replayLocalList({ ...f, allowKnownLocalListGaps: true, onCapture: async () => {} });

test("the zero-limit list, answered 400 with a JSON error envelope (production, Firebase), is recorded and the recipe completes", async () => {
  const f = listOf("storage-object/firebase/list", (ctx) =>
    V0(ctx.path) && zeroLimit(ctx) ? productionZeroLimit() : undefined,
  );
  const result = await replay(f);
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.deepEqual(result.zeroLimit, { stepId: "max-results-zero", status: 400 });
  assert.deepEqual(result.unobservedSteps, []);
  assert.equal(f.objects.size, 0);
  assert.deepEqual(f.sender.unresolved(), []);
  assert.ok(result.pageSummaries.length > 0, "the page steps after it still ran");
});

test("the zero-limit list answered 200 with a list (GCS, or a fireemu) is recorded too, and a body that is not a list fails", async () => {
  for (const recipeId of ["storage-object/firebase/list", "storage-object/gcs/list"]) {
    const ok = await replay(listOf(recipeId, () => undefined));
    assert.equal(ok.status, "LOCAL_COMPLETE", recipeId);
    assert.deepEqual(ok.zeroLimit, { stepId: "max-results-zero", status: 200 }, recipeId);
    const bad = listOf(recipeId, (ctx) =>
      zeroLimit(ctx) ? Response.json({ items: "not a list" }) : undefined,
    );
    await assert.rejects(replay(bad), /invalid collection data/, recipeId);
  }
});

test("the zero-limit list answered anything else is neither a list nor the recorded 400, and fails the recipe", async () => {
  const answers = {
    "400 text": () =>
      new Response("Expect maxResults", { status: 400, headers: { "content-type": "text/plain" } }),
    "400 not an object": () => Response.json(["x"], { status: 400 }),
    "400 no error": () => Response.json({ message: "x" }, { status: 400 }),
    "400 error is a string": () => Response.json({ error: "x" }, { status: 400 }),
    "400 wrong code": () => Response.json({ error: { code: 403, message: "x" } }, { status: 400 }),
    "400 no message": () => Response.json({ error: { code: 400 } }, { status: 400 }),
    "400 message number": () =>
      Response.json({ error: { code: 400, message: 7 } }, { status: 400 }),
    "400 empty": () => new Response(null, { status: 400 }),
    "400 error null": () => Response.json({ error: null }, { status: 400 }),
    "401 with a 400 envelope": () =>
      Response.json({ error: { code: 400, message: "x" } }, { status: 401 }),
    "500 with a 400 envelope": () =>
      Response.json({ error: { code: 400, message: "x" } }, { status: 500 }),
    403: () => Response.json({ error: { code: 403, message: "x" } }, { status: 403 }),
    404: () => Response.json({ error: { code: 404, message: "x" } }, { status: 404 }),
  };
  for (const [name, answer] of Object.entries(answers))
    for (const recipeId of ["storage-object/firebase/list", "storage-object/gcs/list"]) {
      const f = listOf(recipeId, (ctx) => (zeroLimit(ctx) ? answer() : undefined));
      await assert.rejects(replay(f), /zero-limit answer was neither/, `${name} ${recipeId}`);
    }
});

test("the other Firebase list steps are capture-only: an answer that is not a list is recorded and the recipe goes on", async () => {
  const bad = {
    "400 json": () => Response.json({ error: { code: 400, message: "x" } }, { status: 400 }),
    403: () =>
      Response.json({ error: { code: 403, message: "Permission denied." } }, { status: 403 }),
    "html 200": () => new Response("<html></html>", { status: 200 }),
    "text 404": () => new Response("Not Found", { status: 404 }),
    "items not a list": () => Response.json({ items: {} }),
    "prefixes not a list": () => Response.json({ prefixes: "x" }),
    null: () => Response.json(null),
  };
  for (const [name, answer] of Object.entries(bad)) {
    // Every Firebase list after the baseline, other than the zero-limit one, answers badly.
    const f = listOf("storage-object/firebase/list", (ctx) =>
      V0(ctx.path) && ctx.nth > 1 ? (zeroLimit(ctx) ? productionZeroLimit() : answer()) : undefined,
    );
    const result = await replay(f);
    assert.equal(result.status, "LOCAL_COMPLETE", name);
    assert.ok(result.unobservedSteps.length >= 4, name);
    assert.ok(
      result.unobservedSteps.every((row) => row.stepId !== "max-results-zero"),
      name,
    );
    assert.deepEqual(
      result.pageSummaries.map((row) => [row.stepId, row.unobserved]),
      [["page-0", true]],
      name,
    );
    assert.equal(f.objects.size, 0, name);
    assert.deepEqual(f.sender.unresolved(), [], name);
    assert.equal(f.sender.snapshot().mode, "closed", name);
  }
});

test("an unusable page answer ends the page walk, and later pages are not sent", async () => {
  let pages = 0;
  const f = listOf("storage-object/firebase/list", (ctx) => {
    if (!V0(ctx.path) || ctx.nth <= 1) return undefined;
    if (zeroLimit(ctx)) return productionZeroLimit();
    if (ctx.query.get("maxResults") === "2") {
      pages++;
      return pages < 3
        ? Response.json({ items: [], prefixes: [], nextPageToken: `t${pages}` })
        : Response.json({ error: { code: 400, message: "x" } }, { status: 400 });
    }
    return undefined;
  });
  const result = await replay(f);
  assert.equal(pages, 3);
  assert.equal(result.pageSummaries.length, 3);
  assert.deepEqual(
    result.pageSummaries.map((row) => row.unobserved ?? false),
    [false, false, true],
  );
  assert.equal(result.unobservedSteps.at(-1).status, 400);
});

test("a Firebase next-page token that is not a usable string is recorded, and the walk ends", async () => {
  for (const token of [7, "", "x".repeat(5000), "a\u0001b"]) {
    const f = listOf("storage-object/firebase/list", (ctx) => {
      if (!V0(ctx.path) || ctx.nth <= 1) return undefined;
      if (zeroLimit(ctx)) return productionZeroLimit();
      if (ctx.query.get("maxResults") === "2")
        return Response.json({ items: [], nextPageToken: token });
      return undefined;
    });
    const result = await replay(f);
    assert.equal(result.status, "LOCAL_COMPLETE", String(token));
    assert.equal(result.pageSummaries.length, 1);
    assert.equal(result.unobservedSteps.at(-1).reason, "next page token");
  }
});

test("a Firebase page walk that never ends is not a failure, where the same in GCS is", async () => {
  const endless = (ctx) =>
    ctx.query.get("maxResults") === "2" || ctx.query.get("maxResults") === "3"
      ? Response.json({ items: [], prefixes: [], nextPageToken: "more" })
      : undefined;
  const firebase = await replay(
    listOf("storage-object/firebase/list", (ctx) => (V0(ctx.path) ? endless(ctx) : undefined)),
  );
  assert.equal(firebase.status, "LOCAL_COMPLETE");
  assert.equal(firebase.pageSummaries.length, 12);
  await assert.rejects(
    replay(listOf("storage-object/gcs/list", (ctx) => (V0(ctx.path) ? undefined : endless(ctx)))),
    /seed or list traversal is incomplete/,
  );
});

test("the baseline list, and every GCS list step, are still judged: a bad answer fails the recipe", async () => {
  // The Firebase baseline is the first Firebase list of the recipe.
  await assert.rejects(
    replay(
      listOf("storage-object/firebase/list", (ctx) =>
        V0(ctx.path) && ctx.nth === 1
          ? Response.json({ error: { code: 403, message: "x" } }, { status: 403 })
          : undefined,
      ),
    ),
    /list response was not 200/,
  );
  await assert.rejects(
    replay(
      listOf("storage-object/firebase/list", (ctx) =>
        V0(ctx.path) && ctx.nth === 1 ? Response.json({ items: [{ name: "x" }] }) : undefined,
      ),
    ),
    /baseline list was not empty/,
  );
  for (const nthFrom of [2, 3, 5, 9]) {
    const f = listOf("storage-object/gcs/list", (ctx) =>
      !V0(ctx.path) && ctx.nth === nthFrom
        ? Response.json({ error: { code: 403, message: "x" } }, { status: 403 })
        : undefined,
    );
    await assert.rejects(replay(f), /list response was not 200/, `GCS list ${nthFrom}`);
  }
});

test("the answers production gave to the first Firebase list requests of recording 1 (recorded/recording1-firebase-list.json) go through the list judge, and the zero-limit 400 no longer stops the recipe", async () => {
  const recorded = JSON.parse(
    readFileSync(
      new URL("./storage-object/recorded/recording1-firebase-list.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(recorded.answers["max-results-zero"].status, 400);
  const order = [
    "baseline-list-firebase",
    "flat",
    "delimited",
    "subdirectory",
    "empty",
    "max-results-zero",
  ];
  const f = fixture({ recipeId: "storage-object/firebase/list" });
  const moved = (text) =>
    text.replaceAll(
      `storage-object/${recorded.runId}/`,
      `${f.recipe.objects[0].split("list/")[0]}`,
    );
  const served = [];
  const scripted = fixture({
    recipeId: "storage-object/firebase/list",
    listAnswer: ({ path, nth }) => {
      if (!V0(path) || nth > order.length) return undefined;
      const row = recorded.answers[order[nth - 1]];
      served.push(order[nth - 1]);
      return new Response(moved(row.body), { status: row.status, headers: row.headers });
    },
  });
  const result = await replay(scripted);
  assert.equal(result.status, "LOCAL_COMPLETE");
  assert.deepEqual(served, order);
  assert.deepEqual(result.zeroLimit, { stepId: "max-results-zero", status: 400 });
  assert.deepEqual(result.unobservedSteps, []);
  assert.equal(scripted.objects.size, 0);
  assert.deepEqual(scripted.sender.unresolved(), []);
  assert.ok(f.recipe);
});
