// Events v1.1: the services the CLI would otherwise enable, the read-only inventory of the Gen2 source buckets, and the
// subscriptions that existed before the run.
import assert from "node:assert/strict";
import test from "node:test";
import { createGuard } from "./guard.mjs";
import { REQUIRED_SERVICES, sourceBuckets } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const P = "fireemu-oracle-events";
async function go(worldOptions = {}, wrapSend = (send) => send) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "tok-abcdefgh",
    save: async (row) => journal.push(row),
    send: wrapSend(world.send, world),
    runCli: world.runCli,
    clock: () => world.now,
    sleep: async (ms) => world.advance(ms),
  });
  return { world, journal, result };
}
const ids = (journal) => journal.filter((r) => r.state === "before-send").map((r) => r.id);

test("the services the CLI ensures are required, so the deploy enables nothing", async () => {
  for (const id of ["compute.googleapis.com", "firebaseextensions.googleapis.com"]) {
    assert.ok(REQUIRED_SERVICES.includes(id), id);
    const world = createWorld({ runId: RUN });
    world.services.delete(id);
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
    assert.deepEqual(result.servicesMissing, [id]);
    assert.equal(result.stoppedBecause, "services");
    assert.deepEqual(world.cliRuns, []);
  }
});

test("the two source buckets are the project's Gen2 upload and source buckets", () => {
  assert.deepEqual(sourceBuckets("1"), [
    "gcf-v2-uploads-1.us-central1.cloudfunctions.appspot.com",
    "gcf-v2-sources-1-us-central1",
  ]);
});

test("the objects the deploy left in the source buckets are reported, not deleted", async () => {
  const { result, world } = await go();
  assert.deepEqual(result.inventory.sourceObjects.uploads.removed, []);
  assert.equal(result.inventory.sourceObjects.uploads.added.length, 1);
  assert.match(result.inventory.sourceObjects.uploads.added[0], /^upload-\d+\.zip$/);
  assert.equal(result.inventory.sourceObjects.sources.added.length, 1);
  assert.ok(
    ![...world.sourceBuckets.values()].every((items) => items.length === 0),
    "nothing was deleted from the buckets",
  );
  assert.equal(
    world.calls.filter((c) => c.startsWith("DELETE storage") && !c.includes("pycheck")).length,
    0,
  );
  assert.equal(result.outcome, "pycheck-recorded");
  assert.equal(result.closureReady, true);
});

test("an object that was there before the run is not reported as added, and one that disappeared is reported as removed", async () => {
  const { result } = await go({}, (send, world) => async (request) => {
    if (
      request.method === "GET" &&
      request.url.includes("gcf-v2-uploads") &&
      world.cliRuns.includes("delete")
    )
      world.sourceBuckets.get(request.url.split("/b/")[1].split("/o")[0]).splice(0, 1);
    return send(request);
  });
  assert.deepEqual(result.inventory.sourceObjects.uploads.removed, ["old-upload.zip"]);
  assert.equal(result.inventory.sourceObjects.uploads.added.length, 1);
});

test("buckets that do not exist read as empty, and a bucket that cannot be read is incomplete but not a stop", async () => {
  const none = await go({ withSourceBuckets: false });
  assert.deepEqual(none.result.inventory.sourceObjects, {
    uploads: { added: [], removed: [] },
    sources: { added: [], removed: [] },
  });
  assert.deepEqual(none.result.incompleteReads, []);
  const forbidden = await go(
    {},
    (send) => async (request) =>
      request.url.includes("gcf-v2-sources")
        ? reply(403, { error: { code: 403, status: "PERMISSION_DENIED" } })
        : send(request),
  );
  assert.notEqual(forbidden.result.outcome, "pycheck-auth-stop");
  assert.equal(forbidden.result.inventory.sourceObjects.sources, null);
  assert.ok(forbidden.result.incompleteReads.some((r) => r.id === "preflight-source-objects"));
  assert.equal(forbidden.result.closureReady, false);
  const paged = await go(
    {},
    (send) => async (request) =>
      request.url.includes("gcf-v2-uploads")
        ? reply(200, { items: [{ name: "a" }], nextPageToken: "t" })
        : send(request),
  );
  assert.equal(paged.result.inventory.sourceObjects.uploads, null);
  assert.equal(paged.result.closureReady, false);
});

test("the source buckets are read before the deploy and after the cleanup, in that order", async () => {
  const { journal } = await go();
  const order = ids(journal);
  assert.ok(
    order.indexOf("preflight-source-objects-uploads") < order.indexOf("cli-deploy") ||
      !order.includes("cli-deploy"),
  );
  assert.ok(order.indexOf("preflight-source-objects-uploads") < order.indexOf("create-topic"));
  assert.ok(order.indexOf("inventory-source-objects-uploads") > order.indexOf("final-packages"));
});

test("subscriptions that existed before the run do not count against the final lists", async () => {
  const { result } = await go({ foreignSubscriptions: 2 });
  assert.equal(result.inventory.before.subscriptions, 2);
  assert.equal(result.cleanup.listsEmpty, true);
  assert.equal(result.outcome, "pycheck-recorded");
});

test("the allowlist reads the two source buckets' object lists and nothing else of them", () => {
  const guard = createGuard(RUN, NUMBER);
  const [uploads, sources] = sourceBuckets(NUMBER);
  for (const bucket of [uploads, sources]) {
    assert.equal(
      guard.allow({
        method: "GET",
        url: `https://storage.googleapis.com/storage/v1/b/${bucket}/o?maxResults=1000`,
      }),
      true,
    );
    assert.equal(
      guard.isMutation({
        method: "GET",
        url: `https://storage.googleapis.com/storage/v1/b/${bucket}/o?maxResults=1000`,
      }),
      false,
    );
    assert.equal(
      guard.allow({
        method: "GET",
        url: `https://storage.googleapis.com/storage/v1/b/${bucket}/o?maxResults=1001`,
      }),
      false,
    );
    assert.equal(
      guard.allow({
        method: "GET",
        url: `https://storage.googleapis.com/storage/v1/b/${bucket}/o?prefix=x`,
      }),
      false,
    );
    assert.equal(
      guard.allow({
        method: "GET",
        url: `https://storage.googleapis.com/storage/v1/b/${bucket}/o/some.zip`,
      }),
      false,
    );
    assert.equal(
      guard.allow({
        method: "DELETE",
        url: `https://storage.googleapis.com/storage/v1/b/${bucket}/o/some.zip`,
      }),
      false,
    );
  }
  assert.equal(
    guard.allow({
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/b/gcf-v2-uploads-999999999999.us-central1.cloudfunctions.appspot.com/o?maxResults=1000`,
    }),
    false,
  );
  assert.equal(
    guard.allow({
      method: "GET",
      url: `https://storage.googleapis.com/storage/v1/b/${P}.appspot.com.evil/o?maxResults=1000`,
    }),
    false,
  );
});

test("a source bucket that could not be read before the run, and can after it, gives no comparison and no cleanup error", async () => {
  let first = true;
  const { result } = await go({}, (send) => async (request) => {
    if (request.url.includes("gcf-v2-sources") && first) {
      first = false;
      return reply(403, { error: { code: 403, status: "PERMISSION_DENIED" } });
    }
    return send(request);
  });
  assert.equal(result.inventory.sourceObjects.sources, null);
  assert.equal(result.cleanup.errors, undefined);
  assert.ok(result.inventory.sourceObjects.uploads);
});
