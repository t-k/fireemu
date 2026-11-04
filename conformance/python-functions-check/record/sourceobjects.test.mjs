// The deployment's own objects in the two Gen2 source buckets: found by diffing a fresh list with the preflight's, adopted by
// name, deleted once each, read back, and left alone when they are not recognisably the deployment's.
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard } from "./guard.mjs";
import { ALL_FUNCTIONS, isOwnSourceObject, sourceBuckets } from "./plan.mjs";
import { readbackRun, sourceObjectEntries } from "./readback.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const [UPLOADS, SOURCES] = sourceBuckets(NUMBER);
const error = (code, status) => reply(code, { error: { code, status, message: "x" } });
async function go(worldOptions = {}, wrapSend = (send) => send, options = {}) {
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
    ...options,
  });
  return { world, journal, result };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);
const path = (request) => new URL(request.url).pathname;

test("which new objects are the deployment's: any plain upload name, and a source name under one of the run's functions", () => {
  for (const name of ["a1b2.zip", "x/y.zip", "UP-1_2.zip"])
    assert.equal(isOwnSourceObject(NUMBER, UPLOADS, name), true, name);
  for (const fn of ALL_FUNCTIONS)
    assert.equal(isOwnSourceObject(NUMBER, SOURCES, fn + "/function-source.zip"), true, fn);
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
  for (const name of ["other/function-source.zip", "pcps", "", "../pcps/x", "pcps/../x", "PCPS/x"])
    assert.equal(isOwnSourceObject(NUMBER, SOURCES, name), name === "pcps" ? true : false, name);
  assert.equal(isOwnSourceObject(NUMBER, "someone-elses-bucket", "pcps/x"), false);
  assert.equal(isOwnSourceObject("999999999999", UPLOADS, "a.zip"), false);
});

test("an object can be read or deleted only after the run adopted it by name, in its own bucket", () => {
  const g = createGuard(RUN, NUMBER);
  const url = (bucket, name) =>
    `https://storage.googleapis.com/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`;
  for (const method of ["GET", "DELETE"])
    assert.equal(g.allow({ method, url: url(UPLOADS, "a.zip") }), false);
  assert.equal(g.adoptObject(UPLOADS, "a.zip"), true);
  assert.equal(g.adoptObject(SOURCES, "pcps/function-source.zip"), true);
  assert.equal(g.adoptObject(SOURCES, "other/x.zip"), false);
  assert.equal(g.adoptObject("another-bucket", "a.zip"), false);
  assert.deepEqual(g.adoptedObjects(), [`${UPLOADS}/a.zip`, `${SOURCES}/pcps/function-source.zip`]);
  assert.equal(g.allow({ method: "GET", url: url(UPLOADS, "a.zip") }), true);
  assert.equal(g.isMutation({ method: "GET", url: url(UPLOADS, "a.zip") }), false);
  assert.equal(g.allow({ method: "DELETE", url: url(UPLOADS, "a.zip") }), true);
  assert.equal(g.isMutation({ method: "DELETE", url: url(UPLOADS, "a.zip") }), true);
  assert.equal(g.allow({ method: "DELETE", url: url(SOURCES, "pcps/function-source.zip") }), true);
  assert.equal(
    g.allow({ method: "DELETE", url: url(SOURCES, "a.zip") }),
    false,
    "the name is adopted for its own bucket only",
  );
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
    "an unencoded slash is another route",
  );
});

test("a clean run deletes exactly the objects the deploy added, once each, and reads each back", async () => {
  const { result, world, journal } = await go();
  const deleted = result.cleanup.sourceObjectsDeleted;
  assert.equal(deleted.length, 26);
  assert.deepEqual(deleted.filter((d) => d.bucket === UPLOADS).length, 13);
  assert.ok(deleted.every((d) => d.class === "2xx" && d.status === 204));
  assert.deepEqual(
    world.sourceBuckets.get(UPLOADS),
    ["old-upload.zip"],
    "the object that was there is still there",
  );
  assert.deepEqual(world.sourceBuckets.get(SOURCES), []);
  assert.equal(ids(journal).filter((id) => id.startsWith("delete-source-object-")).length, 26);
  assert.equal(new Set(ids(journal)).size, ids(journal).length);
  for (let i = 1; i <= 26; i++)
    assert.equal(result.cleanup.readBack["source-object-" + i], true, String(i));
  const order = ids(journal);
  assert.ok(
    order.indexOf("cleanup-source-objects-uploads") >
      order.indexOf("delete-package-fireemu--oracle--events__us--central1__pcea%2Fcache"),
  );
  assert.ok(
    order.indexOf("readback-gone-source-object-1") > order.indexOf("delete-source-object-26"),
  );
  assert.ok(
    order.indexOf("inventory-source-objects-uploads") >
      order.indexOf("readback-gone-source-object-26"),
  );
  assert.equal(result.cleanup.verified, true);
  assert.equal(result.closureReady, true);
  assert.deepEqual(result.cleanup.sourceObjectsSkipped, []);
});

test("a new object under a function of the run is the deployment's, whoever made it", async () => {
  let injected = false;
  const { world, result } = await go({}, (send, w) => async (request) => {
    if (
      !injected &&
      request.method === "GET" &&
      path(request).endsWith("/o") &&
      request.url.includes("gcf-v2-sources") &&
      w.cliRuns.includes("delete")
    ) {
      injected = true;
      w.sourceBuckets.get(SOURCES).push("pcps/older.zip");
    }
    return send(request);
  });
  assert.ok(!world.sourceBuckets.get(SOURCES).includes("pcps/older.zip"));
  assert.equal(result.cleanup.sourceObjectsDeleted.length, 27);
});

test("a pre-existing object under a function's name stays, because the preflight saw it", async () => {
  const world = createWorld({ runId: RUN });
  world.sourceBuckets.get(SOURCES).push("pcps/previous-deploy.zip");
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
  assert.ok(world.sourceBuckets.get(SOURCES).includes("pcps/previous-deploy.zip"));
  assert.equal(result.cleanup.sourceObjectsDeleted.length, 26);
  assert.equal(result.outcome, "pycheck-recorded");
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
    assert.equal(result.outcome, "pycheck-needs-recovery");
    assert.equal(result.closureReady, false);
  }
});

test("a delete that did not take effect leaves the object to recover; an unknown delete is never re-sent and keeps the run open", async () => {
  let hit = 0;
  const refused = await go({}, (send) => async (request) => {
    if (request.method === "DELETE" && request.url.includes("gcf-v2-uploads") && hit++ === 0)
      return error(500, "INTERNAL");
    return send(request);
  });
  assert.equal(refused.result.cleanup.readBack["source-object-1"], false);
  assert.equal(refused.result.cleanup.verified, false);
  assert.equal(refused.result.outcome, "pycheck-needs-recovery");
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
  assert.equal(
    took.result.vanishedAfterCreate.length,
    0,
    "the object was never confirmed as a create, so it is not 'vanished'",
  );
  const refused4xx = await go(
    {},
    (send) => async (request) =>
      request.method === "DELETE" && request.url.includes("gcf-v2-uploads")
        ? error(403, "PERMISSION_DENIED")
        : send(request),
  );
  assert.equal(refused4xx.result.outcome, "pycheck-auth-stop", "a 403 on a write is a stop");
});

test("buckets that cannot be read before the run give nothing to delete and an incomplete read; paging is followed to five pages", async () => {
  const before = await go({}, (send) => {
    let first = true;
    return async (request) => {
      if (request.method === "GET" && request.url.includes("gcf-v2-uploads") && first) {
        first = false;
        return error(403, "PERMISSION_DENIED");
      }
      return send(request);
    };
  });
  assert.equal(
    before.result.cleanup.sourceObjectsDeleted.filter((d) => d.bucket === UPLOADS).length,
    0,
  );
  assert.equal(
    before.result.cleanup.sourceObjectsDeleted.filter((d) => d.bucket === SOURCES).length,
    13,
  );
  assert.equal(before.result.closureReady, false);
  const paged = await go({ sourcePageSize: 5 });
  assert.equal(paged.result.cleanup.sourceObjectsDeleted.length, 26);
  assert.ok(ids(paged.journal).includes("cleanup-source-objects-uploads-page-3"));
  assert.ok(!ids(paged.journal).includes("cleanup-source-objects-uploads-page-4"));
  const endless = await go({ sourcePageSize: 2 });
  assert.equal(
    endless.result.cleanup.sourceObjectsDeleted.length,
    0,
    "a bucket that cannot be read to its end gives no diff",
  );
  assert.ok(endless.result.incompleteReads.some((r) => r.class === "more-than-five-pages"));
  assert.equal(endless.result.closureReady, false);
  assert.ok(!ids(endless.journal).some((id) => id.endsWith("-page-6")));
});

test("buckets that do not exist give nothing to delete and no incomplete read", async () => {
  const { result } = await go({ withSourceBuckets: false });
  assert.deepEqual(result.cleanup.sourceObjectsDeleted, []);
  assert.deepEqual(result.incompleteReads, []);
  assert.equal(result.outcome, "pycheck-recorded");
});

test("a failed deploy deletes the objects it did add, and a run with nothing added deletes nothing", async () => {
  const failed = await go({ failDeploy: true });
  assert.deepEqual(failed.result.cleanup.sourceObjectsDeleted, []);
  assert.equal(failed.result.cleanup.verified, true);
});

test("the A2 read-back reads each deleted object by name with its own allowlist, and a leftover is not absent", async () => {
  const { world, result } = await go();
  const baseline = { bucket: result.bucket, sourceObjects: result.cleanup.sourceObjectsDeleted };
  const base = {
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    clock: () => world.now,
    ...baseline,
  };
  const clean = await readbackRun({ ...base, send: world.send });
  assert.equal(clean.allAbsent, true);
  assert.equal(Object.keys(clean.names).filter((n) => n.startsWith("source-object-")).length, 26);
  world.sourceBuckets
    .get(UPLOADS)
    .push(result.cleanup.sourceObjectsDeleted.find((d) => d.bucket === UPLOADS).name);
  const left = await readbackRun({ ...base, send: world.send });
  assert.equal(left.allAbsent, false);
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
