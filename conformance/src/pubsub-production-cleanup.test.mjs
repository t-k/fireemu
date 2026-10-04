import assert from "node:assert/strict";
import test, { beforeEach } from "node:test";
import { cleanup } from "./pubsub-production/cleanup.mjs";
import { createClient, newPushState } from "./pubsub-production/client.mjs";
import { createOwnership } from "./pubsub-production/names.mjs";

const RUN = "0123456789ab";
// Every test has an ownership of its own: probes are registered for the life of one.
let own;
beforeEach(() => {
  own = createOwnership({ project: "demo-project", runId: RUN });
});
const mine = (kind, key) => own.resource(kind, key);
const foreign = (kind, key) => `projects/demo-project/${kind}/someone-else-${key}`;

/** An in-memory service that lists, gets and deletes, with pages and optional faults. */
function fakeService({
  resources,
  pageSize = 2,
  deleteFault,
  stayAfterDelete = new Set(),
  listFault,
}) {
  const live = new Set(resources);
  const calls = [];
  const kindOf = (path) => path.split("/")[3];
  const transport = {
    name: "rest",
    calls,
    async request({ method, path, op }) {
      calls.push({ method, path, op });
      const bare = decodeURIComponent(path.split("?")[0].replace(/^\/v1\//, ""));
      if (method === "GET" && /^projects\/[^/]+\/(topics|subscriptions|snapshots)$/.test(bare)) {
        if (listFault) return { status: 500, body: {}, unknown: true };
        const kind = bare.split("/")[2];
        const items = [...live].filter((name) => name.split("/")[2] === kind).toSorted();
        const offset = Number(new URL(`http://x${path}`).searchParams.get("pageToken") ?? 0);
        const slice = items.slice(offset, offset + pageSize);
        const next = offset + pageSize < items.length ? String(offset + pageSize) : undefined;
        return {
          status: 200,
          body: {
            [kind]: slice.map((name) => ({ name })),
            ...(next ? { nextPageToken: next } : {}),
          },
        };
      }
      if (method === "GET")
        return live.has(bare)
          ? { status: 200, body: { name: bare } }
          : { status: 404, body: { error: { status: "NOT_FOUND" } } };
      if (method === "DELETE") {
        const fault = deleteFault?.(bare);
        if (fault) return fault;
        if (!live.has(bare)) return { status: 404, body: { error: { status: "NOT_FOUND" } } };
        if (!stayAfterDelete.has(bare)) live.delete(bare);
        return { status: 200, body: {} };
      }
      throw new Error(`unexpected ${method} ${path} (${kindOf(path)})`);
    },
  };
  return {
    live,
    calls,
    client: createClient({
      transport,
      ownership: own,
      pushState: newPushState(),
      caseId: "cleanup",
    }),
  };
}
const sleep = async () => {};

test("only what carries the run's prefix is deleted, across pages, children before parents", async () => {
  const resources = [
    mine("topics", "a"),
    mine("topics", "b"),
    mine("topics", "c"),
    mine("subscriptions", "a"),
    mine("subscriptions", "b"),
    mine("snapshots", "a"),
    foreign("topics", "x"),
    foreign("subscriptions", "y"),
    "projects/demo-project/topics/fe999999999999-z",
  ];
  const service = fakeService({ resources });
  const report = await cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    sleep,
  });
  assert.deepEqual(report.leftover, []);
  assert.deepEqual(report.errors, []);
  assert.equal(report.deleted.length, 6);
  assert.deepEqual(
    [...service.live].toSorted(),
    [
      foreign("subscriptions", "y"),
      foreign("topics", "x"),
      "projects/demo-project/topics/fe999999999999-z",
    ].toSorted(),
  );
  const order = service.calls
    .filter((call) => call.method === "DELETE")
    .map((call) => call.path.split("/")[4]);
  assert.deepEqual(order, [
    "snapshots",
    "subscriptions",
    "subscriptions",
    "topics",
    "topics",
    "topics",
  ]);
  const reads = service.calls.filter(
    (call) => call.method === "GET" && /\/(topics|subscriptions|snapshots)\/fe/.test(call.path),
  );
  assert.equal(reads.length, 6, "every deletion is read back");
});

test("registered probes and known names are deleted even when no listing shows them", async () => {
  const probe = own.registerProbe("projects/demo-project/topics/goog-probe-cleanup");
  const knownName = mine("topics", "known");
  const service = fakeService({ resources: [probe, knownName], listFault: true });
  const report = await cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    known: [knownName],
    sleep,
  });
  assert.deepEqual(report.leftover, []);
  assert.equal(report.errors.length, 3, "each failed listing is reported");
  assert.deepEqual(report.deleted.toSorted(), [knownName, probe].toSorted());
});

test("the issued names are not tried while the listing can be read", async () => {
  const knownName = mine("topics", "issued-but-never-created");
  const service = fakeService({ resources: [] });
  const report = await cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    known: [knownName],
    sleep,
  });
  assert.deepEqual(report.deleted.concat(report.alreadyGone), []);
  assert.equal(service.calls.filter((call) => call.method === "DELETE").length, 0);
});

test("a probe the service refused to create is already gone, not an error", async () => {
  const probe = own.registerProbe("projects/demo-project/topics/never-created");
  const service = fakeService({ resources: [] });
  const report = await cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    sleep,
  });
  assert.deepEqual(report.alreadyGone, [probe]);
  assert.deepEqual(report.leftover, []);
});

test("a deletion with an unknown answer is repeated once; a resource that stays is reported as left over", async () => {
  const stubborn = mine("topics", "stubborn");
  const flaky = mine("subscriptions", "flaky");
  let flakyCalls = 0;
  const service = fakeService({
    resources: [stubborn, flaky],
    stayAfterDelete: new Set([stubborn]),
    deleteFault: (name) =>
      name === flaky && flakyCalls++ === 0 ? { status: 503, body: {}, unknown: true } : undefined,
  });
  const report = await cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    sleep,
    readBackAttempts: 2,
  });
  assert.deepEqual(report.leftover, [stubborn]);
  assert.ok(report.deleted.includes(flaky));
  assert.equal(flakyCalls, 2);
  const stubbornReads = service.calls.filter(
    (call) => call.method === "GET" && call.path.endsWith(stubborn.split("/").pop()),
  );
  assert.equal(stubbornReads.length, 2);
});

test("a deletion that fails with a code other than NOT_FOUND is an error and is not read back", async () => {
  const name = mine("topics", "denied");
  const service = fakeService({
    resources: [name],
    deleteFault: () => ({ status: 403, body: { error: { status: "PERMISSION_DENIED" } } }),
  });
  const report = await cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    sleep,
  });
  assert.deepEqual(report.errors, [`deleteTopic ${name}: PERMISSION_DENIED`]);
  assert.deepEqual(report.deleted, []);
  assert.deepEqual(report.leftover, []);
});
