// The deployment's own objects in the two Gen2 source buckets: found by diffing a fresh list with the preflight's, adopted by
// name, deleted once each, read back, and left alone when they are not recognisably the deployment's.
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard } from "./guard.mjs";
import { isOwnSourceObject, sourceBuckets } from "./plan.mjs";
import { readbackRun, sourceObjectEntries } from "./readback.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const [UPLOADS, SOURCES] = sourceBuckets(NUMBER);
const error = (code, status) => reply(code, { error: { code, status, message: "x" } });
async function go(worldOptions = {}, wrapSend = (send) => send) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    send: wrapSend(world.send, world),
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  return { world, journal, result };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const path = (request) => new URL(request.url).pathname;
const url = (bucket, name) =>
  `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;

test("which new objects are the deployment's: any plain upload name, and a source name under the function of the run", () => {
  for (const name of ["a1b2.zip", "x/y.zip", "UP-1_2.zip"])
    assert.equal(isOwnSourceObject(NUMBER, UPLOADS, name), true, name);
  assert.equal(isOwnSourceObject(NUMBER, SOURCES, "pcblock/function-source.zip"), true);
  for (const name of [
    "",
    "/abs.zip",
    "a/../b.zip",
    "has space.zip",
    "a\nb",
    "x".repeat(1025),
    undefined,
    null,
    5,
    "é.zip",
  ])
    assert.equal(isOwnSourceObject(NUMBER, UPLOADS, name), false, String(name));
  for (const name of [
    "other/function-source.zip",
    "pcblockx/a",
    "",
    "../pcblock/x",
    "pcblock/../x",
    "PCBLOCK/x",
  ])
    assert.equal(isOwnSourceObject(NUMBER, SOURCES, name), false, name);
  assert.equal(isOwnSourceObject(NUMBER, SOURCES, "pcblock"), true);
  assert.equal(isOwnSourceObject(NUMBER, "someone-elses-bucket", "pcblock/x"), false);
  assert.equal(isOwnSourceObject("999999999999", UPLOADS, "a.zip"), false);
});

test("an object can be read or deleted only after the run adopted it by name, in its own bucket", () => {
  const g = createGuard(RUN, NUMBER);
  for (const method of ["GET", "DELETE"])
    assert.equal(g.allow({ method, url: url(UPLOADS, "a.zip") }), false);
  assert.equal(g.adoptObject(UPLOADS, "a.zip"), true);
  assert.equal(g.adoptObject(SOURCES, "pcblock/function-source.zip"), true);
  assert.equal(g.adoptObject(SOURCES, "other/x.zip"), false);
  assert.equal(g.adoptObject("another-bucket", "a.zip"), false);
  assert.deepEqual(g.adoptedObjects(), [
    `${UPLOADS}/a.zip`,
    `${SOURCES}/pcblock/function-source.zip`,
  ]);
  assert.equal(g.allow({ method: "GET", url: url(UPLOADS, "a.zip") }), true);
  assert.equal(g.isMutation({ method: "GET", url: url(UPLOADS, "a.zip") }), false);
  assert.equal(g.allow({ method: "DELETE", url: url(UPLOADS, "a.zip") }), true);
  assert.equal(g.isMutation({ method: "DELETE", url: url(UPLOADS, "a.zip") }), true);
  assert.equal(
    g.allow({ method: "DELETE", url: url(SOURCES, "pcblock/function-source.zip") }),
    true,
  );
  assert.equal(g.allow({ method: "DELETE", url: url(SOURCES, "a.zip") }), false);
  assert.equal(g.allow({ method: "DELETE", url: url(UPLOADS, "b.zip") }), false);
  assert.equal(g.allow({ method: "DELETE", url: url(UPLOADS, "a.zip") + "?generation=1" }), false);
  assert.equal(g.allow({ method: "DELETE", url: url(UPLOADS, "a.zip"), json: {} }), false);
  assert.equal(g.allow({ method: "PATCH", url: url(UPLOADS, "a.zip"), json: {} }), false);
  assert.equal(
    g.allow({
      method: "DELETE",
      url: `https://storage.googleapis.com/storage/v1/b/${UPLOADS}/o/a.zip%`,
    }),
    false,
  );
  assert.equal(
    g.allow({
      method: "DELETE",
      url: `https://storage.googleapis.com/storage/v1/b/${UPLOADS}/o/a/b.zip`,
    }),
    false,
  );
});

test("a clean run deletes exactly the objects the deploy added, once each, and reads each back", async () => {
  const { result, world, journal } = await go();
  assert.deepEqual(
    result.cleanup.sourceObjectsDeleted.map((d) => [d.bucket, d.name, d.class, d.status]),
    [
      [UPLOADS, result.cleanup.sourceObjectsDeleted[0].name, "2xx", 204],
      [SOURCES, "pcblock/function-source.zip", "2xx", 204],
    ],
  );
  assert.deepEqual(
    world.sourceBuckets.get(UPLOADS),
    ["old-upload.zip"],
    "the object that was there is still there",
  );
  assert.deepEqual(world.sourceBuckets.get(SOURCES), []);
  assert.deepEqual(
    ids(journal).filter((id) => id.startsWith("delete-source-object-")),
    ["delete-source-object-1", "delete-source-object-2"],
  );
  assert.equal(result.cleanup.readBack["source-object-1"], true);
  assert.equal(result.cleanup.readBack["source-object-2"], true);
  const order = ids(journal);
  assert.ok(
    order.indexOf("cleanup-source-objects-uploads") >
      order.indexOf("delete-package-fireemu--oracle--idp__us--central1__pcblock%2Fcache"),
  );
  assert.ok(
    order.indexOf("readback-gone-source-object-1") > order.indexOf("delete-source-object-2"),
  );
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.closureReady, true);
  assert.deepEqual(result.cleanup.sourceObjectsSkipped, []);
});

test("a pre-existing object under the function's name stays, because the preflight saw it; a new one under it is the deployment's", async () => {
  const world = createWorld({ runId: RUN });
  world.sourceBuckets.get(SOURCES).push("pcblock/previous-deploy.zip");
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.ok(world.sourceBuckets.get(SOURCES).includes("pcblock/previous-deploy.zip"));
  assert.equal(result.cleanup.sourceObjectsDeleted.length, 2);
  let injected = false;
  const other = await go({}, (send, w) => async (request) => {
    if (
      !injected &&
      request.method === "GET" &&
      path(request).endsWith("/o") &&
      request.url.includes("gcf-v2-sources") &&
      w.cliRuns.includes("delete")
    ) {
      injected = true;
      w.sourceBuckets.get(SOURCES).push("pcblock/older.zip");
    }
    return send(request);
  });
  assert.equal(other.result.cleanup.sourceObjectsDeleted.length, 3);
});

test("a new object that is not recognisably the deployment's is left, reported, and keeps the cleanup unverified", async () => {
  for (const [bucket, name] of [
    [SOURCES, "other/function-source.zip"],
    [UPLOADS, "has space.zip"],
  ]) {
    const { result, world } = await go({}, (send, w) => async (request) => {
      if (
        request.method === "GET" &&
        path(request).endsWith("/o") &&
        request.url.includes(bucket) &&
        w.cliRuns.includes("deploy") &&
        !w.sourceBuckets.get(bucket).includes(name)
      )
        w.sourceBuckets.get(bucket).push(name);
      return send(request);
    });
    assert.deepEqual(result.cleanup.sourceObjectsSkipped, [{ bucket, name }]);
    assert.ok(world.sourceBuckets.get(bucket).includes(name));
    assert.equal(result.cleanup.verified, false);
    assert.equal(result.outcome, "pcblock-needs-recovery");
    assert.equal(result.closureReady, false);
  }
});

test("a delete that did not take effect leaves the object to recover; an unknown delete is never re-sent and keeps the run open; a 403 is a stop", async () => {
  let hit = 0;
  const refused = await go(
    {},
    (send) => async (request) =>
      request.method === "DELETE" && request.url.includes("gcf-v2-uploads") && hit++ === 0
        ? error(500, "INTERNAL")
        : send(request),
  );
  assert.equal(refused.result.cleanup.readBack["source-object-1"], false);
  assert.equal(refused.result.cleanup.verified, false);
  assert.equal(refused.result.outcome, "pcblock-needs-recovery");
  assert.equal(refused.result.unknownMutations, 1);
  assert.equal(ids(refused.journal).filter((id) => id === "delete-source-object-1").length, 1);
  let sent = 0;
  const took = await go({}, (send) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("gcf-v2-sources") && sent++ === 0) {
      await send(request);
      return error(503, "UNAVAILABLE");
    }
    return send(request);
  });
  assert.equal(took.result.closureReady, false);
  assert.equal(took.result.readBackRequired, true);
  const forbidden = await go(
    {},
    (send) => async (request) =>
      request.method === "DELETE" && request.url.includes("gcf-v2-uploads")
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.equal(forbidden.result.outcome, "pcblock-auth-stop");
});

test("buckets that cannot be read before the run give nothing to delete; paging is followed to five pages; absent buckets are empty", async () => {
  let first = true;
  const before = await go({}, (send) => async (request) => {
    if (request.method === "GET" && request.url.includes("gcf-v2-uploads") && first) {
      first = false;
      return error(403, "PERMISSION_DENIED");
    }
    return send(request);
  });
  assert.equal(
    before.result.cleanup.sourceObjectsDeleted.filter((d) => d.bucket === UPLOADS).length,
    0,
  );
  assert.equal(
    before.result.cleanup.sourceObjectsDeleted.filter((d) => d.bucket === SOURCES).length,
    1,
  );
  assert.equal(before.result.closureReady, false);
  const world = createWorld({ runId: RUN, sourcePageSize: 1 });
  world.sourceBuckets.get(UPLOADS).push("older-1.zip", "older-2.zip");
  const journal = [];
  const paged = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.ok(ids(journal).includes("preflight-source-objects-uploads-page-3"));
  assert.ok(!ids(journal).includes("preflight-source-objects-uploads-page-4"));
  assert.equal(paged.cleanup.sourceObjectsDeleted.length, 2);
  const w2 = createWorld({ runId: RUN, sourcePageSize: 1 });
  for (let i = 0; i < 7; i++) w2.sourceBuckets.get(UPLOADS).push(`older-${i}.zip`);
  const endless = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: w2.send,
    runCli: w2.runCli,
    clock: () => w2.now,
    sleep: async (ms) => w2.advance(ms),
  });
  assert.ok(endless.incompleteReads.some((r) => r.class === "more-than-five-pages"));
  assert.equal(endless.closureReady, false);
  assert.equal(endless.cleanup.sourceObjectsDeleted.filter((d) => d.bucket === UPLOADS).length, 0);
  const none = await go({ withSourceBuckets: false });
  assert.deepEqual(none.result.cleanup.sourceObjectsDeleted, []);
  assert.deepEqual(none.result.incompleteReads, []);
});

test("the A2 read-back reads each deleted object by name with its own allowlist, and a leftover is not absent", async () => {
  const { world, result } = await go();
  const base = {
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    clock: () => world.now,
    localId: result.signUp.localId,
    accountsBefore: result.inventory.before.accounts,
    configBeforeDigest: result.configBefore.sha256,
    sourceObjects: result.cleanup.sourceObjectsDeleted,
  };
  const clean = await readbackRun({ ...base, send: world.send });
  assert.equal(clean.allAbsent, true);
  assert.deepEqual(
    Object.keys(clean.names).filter((n) => n.startsWith("source-object-")),
    ["source-object-1", "source-object-2"],
  );
  world.sourceBuckets.get(UPLOADS).push(result.cleanup.sourceObjectsDeleted[0].name);
  assert.equal((await readbackRun({ ...base, send: world.send })).allAbsent, false);
  assert.deepEqual(
    sourceObjectEntries([
      { bucket: "b", name: "n" },
      { bucket: UPLOADS },
      null,
      { name: "x" },
      "s",
      { bucket: 1, name: 2 },
    ]),
    [{ bucket: "b", name: "n" }],
  );
  assert.deepEqual(sourceObjectEntries(undefined), []);
});

test("boundaries: a one-character name and a 1024-character name are names, a 1025-character one is not; labels count from one", async () => {
  assert.equal(isOwnSourceObject(NUMBER, UPLOADS, "a"), true);
  assert.equal(isOwnSourceObject(NUMBER, UPLOADS, "a".repeat(1024)), true);
  assert.equal(isOwnSourceObject(NUMBER, UPLOADS, "a".repeat(1025)), false);
  const { world, result } = await go();
  const names = result.cleanup.sourceObjectsDeleted;
  const rb = await readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    clock: () => world.now,
    send: world.send,
    localId: result.signUp?.localId ?? null,
    accountsBefore: result.inventory.before.accounts ?? null,
    configBeforeDigest: result.configBefore?.sha256 ?? null,
    sourceObjects: names,
  });
  assert.deepEqual(
    Object.keys(rb.names).filter((n) => n.startsWith("source-object-")),
    names.map((_, i) => "source-object-" + (i + 1)),
  );
});

test("a bucket listing of exactly five pages is read to its end and is not flagged", async () => {
  const world = createWorld({ runId: RUN, sourcePageSize: 1 });
  for (let i = 0; i < 3; i++) world.sourceBuckets.get(UPLOADS).push(`older-${i}.zip`);
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (r) => journal.push(r),
    send: world.send,
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  assert.ok(ids(journal).includes("cleanup-source-objects-uploads-page-5"));
  assert.ok(!ids(journal).includes("cleanup-source-objects-uploads-page-6"));
  assert.ok(
    !result.incompleteReads.some((r) => r.class === "more-than-five-pages"),
    JSON.stringify(result.incompleteReads),
  );
  assert.equal(result.cleanup.sourceObjectsDeleted.filter((d) => d.bucket === UPLOADS).length, 1);
});
