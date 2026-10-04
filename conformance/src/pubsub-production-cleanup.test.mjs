import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test, { beforeEach } from "node:test";
import { BudgetExceeded, createBudget, createCapture } from "./pubsub-production/capture.mjs";
import { PAGE_LIMIT, cleanup } from "./pubsub-production/cleanup.mjs";
import { createClient, newPushState } from "./pubsub-production/client.mjs";
import { createLedger } from "./pubsub-production/ledger.mjs";
import { createOwnership } from "./pubsub-production/names.mjs";
import { createRest } from "./pubsub-production/rest.mjs";

const RUN = "0123456789ab";
let own;
let ledger;
beforeEach(() => {
  own = createOwnership({ project: "demo-project", runId: RUN });
  ledger = createLedger();
});
const mine = (kind, key) => own.resource(kind, key);
const foreign = (kind, key) => `projects/demo-project/${kind}/someone-else-${key}`;
const sleep = async () => {};
const NOT_FOUND = { status: 404, body: { error: { status: "NOT_FOUND" } }, unknown: false };
/** The ledger of a creation (or deletion) that was answered `kind`. */
const issue = (name, kind, action = "create") => {
  ledger.sent({ name, action, transport: "rest" });
  ledger.answered({ name, action, transport: "rest", kind });
};

/** An in-memory service that lists, gets and deletes, with pages and faults. */
function fakeService({
  resources,
  pageSize = 2,
  hidden = new Set(),
  deleteFault,
  listReply,
  stayAfterDelete = new Set(),
  endless = false,
}) {
  const live = new Set(resources);
  const calls = [];
  const transport = {
    name: "rest",
    async request({ method, path }) {
      calls.push(`${method} ${path}`);
      const bare = decodeURIComponent(path.split("?")[0].replace(/^\/v1\//, ""));
      if (method === "GET" && /^projects\/[^/]+\/(topics|subscriptions|snapshots)$/.test(bare)) {
        if (listReply) return listReply;
        if (endless) return { status: 200, body: { nextPageToken: "more" }, unknown: false };
        const kind = bare.split("/")[2];
        const items = [...live]
          .filter((name) => name.split("/")[2] === kind && !hidden.has(name))
          .toSorted();
        const offset = Number(new URL(`http://x${path}`).searchParams.get("pageToken") ?? 0);
        const next = offset + pageSize < items.length ? String(offset + pageSize) : undefined;
        return {
          status: 200,
          body: {
            [kind]: items.slice(offset, offset + pageSize).map((name) => ({ name })),
            ...(next ? { nextPageToken: next } : {}),
          },
          unknown: false,
        };
      }
      if (method === "GET")
        return live.has(bare) ? { status: 200, body: { name: bare }, unknown: false } : NOT_FOUND;
      if (method === "DELETE") {
        const fault = deleteFault?.(bare);
        if (fault) return fault;
        if (!live.has(bare)) return NOT_FOUND;
        if (!stayAfterDelete.has(bare)) live.delete(bare);
        return { status: 200, body: {}, unknown: false };
      }
      throw new Error(`unexpected ${method} ${path}`);
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
      ledger,
    }),
  };
}
const run = (service, extra = {}) =>
  cleanup({
    client: service.client,
    ownership: own,
    project: "demo-project",
    ledger,
    sleep,
    ...extra,
  });
const deletes = (service) => service.calls.filter((call) => call.startsWith("DELETE"));

test("what the listing shows under the run's prefix is deleted across pages, children first, and each deletion is read back", async () => {
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
  const report = await run(service);
  assert.deepEqual([report.leftover, report.errors, report.unsettled], [[], [], []]);
  assert.equal(report.deleted.length, 6);
  assert.equal(report.settled.length, 6);
  assert.deepEqual(
    deletes(service).map((call) => call.split("/")[4]),
    ["snapshots", "subscriptions", "subscriptions", "topics", "topics", "topics"],
  );
  assert.deepEqual(
    [...service.live].toSorted(),
    [
      foreign("subscriptions", "y"),
      foreign("topics", "x"),
      "projects/demo-project/topics/fe999999999999-z",
    ].toSorted(),
  );
});

test("a name the run created with a 2xx is deleted even when the listing omits it, after being read by name", async () => {
  const name = mine("topics", "hidden");
  issue(name, "ok");
  const service = fakeService({ resources: [name], hidden: new Set([name]) });
  const report = await run(service);
  assert.deepEqual(report.deleted, [name]);
  assert.deepEqual(report.settled, [{ name, how: "deleted" }]);
  const sequence = service.calls.filter((call) => call.includes(name.split("/").at(-1)));
  assert.deepEqual(
    sequence.map((call) => call.split(" ")[0]),
    ["GET", "DELETE", "GET"],
    "read first, then deleted, then read back",
  );
});

test("a probe is touched only when the run's own creation of it answered 2xx or unknown; a conflict or a refusal never makes it ours", async () => {
  const conflict = own.registerProbe("projects/demo-project/topics/x9e");
  const refused = own.registerProbe("projects/demo-project/topics/goog-probe-r");
  const created = own.registerProbe("projects/demo-project/topics/ab-created");
  const unknownPresent = own.registerProbe("projects/demo-project/topics/unk-present");
  const unknownAbsent = own.registerProbe("projects/demo-project/topics/unk-absent");
  const neverIssued = own.registerProbe("projects/demo-project/topics/never-issued");
  issue(conflict, "conflict");
  issue(refused, "error");
  issue(created, "ok");
  issue(unknownPresent, "unknown");
  issue(unknownAbsent, "unknown");
  const service = fakeService({
    resources: [conflict, refused, created, unknownPresent, neverIssued],
  });
  const report = await run(service);
  assert.deepEqual(report.deleted.toSorted(), [created, unknownPresent].toSorted());
  assert.deepEqual(report.alreadyGone, [unknownAbsent]);
  const touched = (name) =>
    service.calls.some((call) => call.endsWith(`/${name.split("/").at(-1)}`));
  assert.equal(touched(conflict), false, "a probe that answered 409 is not ours: not even read");
  assert.equal(touched(refused), false);
  assert.equal(touched(neverIssued), false);
  assert.equal(service.live.has(conflict), true);
  assert.deepEqual(report.unsettled, []);
  assert.equal(report.settled.length, 3);
});

test("a creation that was sent and never answered is unknown, and a probe name the service refuses as invalid is settled by INVALID_ARGUMENT", async () => {
  const probe = own.registerProbe("projects/demo-project/topics/goog-probe-g");
  ledger.sent({ name: probe, action: "create", transport: "grpc" });
  const invalid = { status: 400, body: { error: { status: "INVALID_ARGUMENT" } }, unknown: false };
  const calls = [];
  const transport = {
    name: "rest",
    request: async ({ method, path }) => {
      calls.push(`${method} ${path}`);
      return method === "GET" && path.endsWith("/topics?pageSize=100")
        ? { status: 200, body: {}, unknown: false }
        : method === "GET" && path.includes("?")
          ? { status: 200, body: {}, unknown: false }
          : invalid;
    },
  };
  const client = createClient({
    transport,
    ownership: own,
    pushState: newPushState(),
    caseId: "cleanup",
    ledger,
  });
  const report = await cleanup({ client, ownership: own, project: "demo-project", ledger, sleep });
  assert.deepEqual(
    [report.alreadyGone, report.settled, report.errors, report.unsettled],
    [[probe], [{ name: probe, how: "absent" }], [], []],
  );
});

test("an unknown deletion is not sent again, and it is settled only by the read-back", async () => {
  const name = mine("topics", "flaky");
  const service = fakeService({
    resources: [name],
    deleteFault: () => ({ status: 503, body: {}, unknown: true }),
    stayAfterDelete: new Set([name]),
  });
  const report = await run(service, { readBackAttempts: 2 });
  assert.equal(deletes(service).length, 1);
  assert.deepEqual(report.leftover, [name]);
  assert.deepEqual(report.unsettled, [name]);
  // The deletion was applied although its answer was lost.
  ledger = createLedger();
  let gone;
  gone = fakeService({
    resources: [mine("topics", "late")],
    deleteFault: (deleted) => {
      gone.live.delete(deleted);
      return { status: 503, body: {}, unknown: true };
    },
  });
  const settled = await run(gone);
  assert.equal(deletes(gone).length, 1);
  assert.deepEqual([settled.leftover, settled.errors, settled.unsettled], [[], [], []]);
  assert.deepEqual(
    settled.settled.map((item) => item.how),
    ["deleted"],
  );
});

test("a deletion that fails with a code other than NOT_FOUND is an error and is not read back; a name already gone is not an error", async () => {
  const denied = mine("topics", "denied");
  const service = fakeService({
    resources: [denied],
    deleteFault: () => ({
      status: 403,
      body: { error: { status: "PERMISSION_DENIED" } },
      unknown: false,
    }),
  });
  const report = await run(service);
  assert.deepEqual(report.errors, [`deleteTopic ${denied}: PERMISSION_DENIED`]);
  assert.deepEqual([report.deleted, report.leftover, report.unsettled], [[], [], [denied]]);
  ledger = createLedger();
  const gone = mine("topics", "gone");
  let other;
  other = fakeService({
    resources: [gone],
    deleteFault: (name) => {
      other.live.delete(name);
      return NOT_FOUND;
    },
  });
  const second = await run(other);
  assert.deepEqual([second.alreadyGone, second.errors], [[gone], []]);
});

test("a stuck read-back leaves the name over, with two seconds between the three reads", async () => {
  const name = mine("topics", "stubborn");
  const service = fakeService({ resources: [name], stayAfterDelete: new Set([name]) });
  const sleeps = [];
  const report = await run(service, { sleep: async (ms) => sleeps.push(ms) });
  assert.deepEqual(report.leftover, [name]);
  assert.deepEqual(sleeps, [2000, 2000]);
  assert.equal(service.calls.filter((call) => call === `GET /v1/${name}`).length, 3);
});

test("a list whose answer is unreadable, or that never ends, is an error and not an empty list", async () => {
  const name = mine("topics", "a");
  issue(name, "ok");
  const unreadable = fakeService({
    resources: [name],
    listReply: { status: 200, body: { raw: "<html>" }, unknown: true },
  });
  const report = await run(unreadable);
  assert.ok(report.errors.includes("listTopics: unknown answer"));
  assert.deepEqual(report.deleted, [name], "the ledger still finds what the run created");
  ledger = createLedger();
  const endless = fakeService({ resources: [], endless: true });
  const stuck = await run(endless);
  assert.equal(endless.calls.length, PAGE_LIMIT * 3, "the page cap for each of three kinds");
  assert.ok(
    endless.calls[0].includes("pageSize=100") && endless.calls[1].includes("pageToken=more"),
  );
  assert.deepEqual(
    stuck.errors,
    ["listSnapshots", "listSubscriptions", "listTopics"].map(
      (list) => `${list}: more than ${PAGE_LIMIT} pages`,
    ),
  );
});

test("running out of the cleanup budget is reported, not thrown, and leaves the rest unsettled", async () => {
  const names = [mine("topics", "a"), mine("topics", "b"), mine("topics", "c")];
  for (const name of names) issue(name, "ok");
  const service = fakeService({ resources: names });
  const budget = createBudget(5);
  const capture = createCapture({ journal: { write() {} } });
  const limited = createClient({
    transport: createRest({
      base: "http://127.0.0.1:1",
      budget,
      capture,
      fetchImpl: async () => {
        const call = service.calls.length;
        void call;
        return { status: 200, text: async () => "{}" };
      },
    }),
    ownership: own,
    pushState: newPushState(),
    caseId: "cleanup",
    ledger,
  });
  const report = await cleanup({
    client: limited,
    ownership: own,
    project: "demo-project",
    ledger,
    sleep,
  });
  assert.equal(report.budgetSpent, true);
  assert.match(report.errors.at(-1), /the cleanup budget is spent/);
  assert.equal(report.unsettled.length, 3);
  assert.ok(new BudgetExceeded(1) instanceof Error);
});

const fixtures = (dir, name) =>
  readFileSync(new URL(`./pubsub-production/fixtures/${dir}/${name}`, import.meta.url), "utf8");

test("replay on the recorded production answers: every body classifies as recorded, layouts match their byte length", async () => {
  const names = readFileSync(
    new URL("./pubsub-production/fixtures/lane7-shape-001/", import.meta.url).pathname
      ? new URL("./pubsub-production/fixtures/README.md", import.meta.url)
      : "",
    "utf8",
  );
  assert.match(names, /16 exchanges/);
  const { readdirSync } = await import("node:fs");
  const lane7 = readdirSync(
    new URL("./pubsub-production/fixtures/lane7-shape-001/", import.meta.url),
  ).toSorted();
  assert.equal(lane7.length, 16);
  for (const file of lane7) {
    const row = JSON.parse(fixtures("lane7-shape-001", file));
    assert.equal(
      Buffer.byteLength(row.body, "utf8"),
      row.bodyBytes,
      `${file}: the recorded layout is the recorded length`,
    );
    const capture = createCapture({ journal: { write() {} } });
    const rest = createRest({
      base: "https://pubsub.googleapis.com",
      budget: createBudget(1),
      capture,
      fetchImpl: async () => ({ status: row.status, text: async () => row.body }),
    });
    const reply = await rest.request({
      label: {},
      op: "x",
      method: row.method,
      path: new URL(row.url).pathname + new URL(row.url).search,
    });
    const client = createClient({
      transport: { name: "rest", request: async () => reply },
      ownership: own,
      pushState: newPushState(),
      caseId: "r",
    });
    const answer = await client.getTopic("projects/fireemu-oracle-idp/topics/t");
    assert.equal(reply.unknown, false, file);
    assert.equal(answer.status, row.status, file);
    assert.equal(answer.code, row.status === 200 ? "OK" : "NOT_FOUND", file);
    assert.equal(answer.ok, row.status === 200, file);
  }
  // The lane 8 bodies (raw bodies of the sbx project): a missing resource is the 404 shape, the rest are 200.
  const lane8 = {
    "before-list-subscriptions": 200,
    "before-list-topics": 200,
    "before-subscription": 404,
    "before-topic": 404,
    "create-subscription": 200,
    "create-topic": 200,
    "delete-subscription": 200,
    "delete-topic": 200,
    "final-list-subscriptions": 200,
    "final-list-topics": 200,
  };
  for (const [name, status] of Object.entries(lane8)) {
    const text = fixtures("lane8-recorded-shape", `${name}.json`);
    const reply = await createRest({
      base: "https://pubsub.googleapis.com",
      budget: createBudget(1),
      capture: createCapture({ journal: { write() {} } }),
      fetchImpl: async () => ({ status, text: async () => text }),
    }).request({ label: {}, op: "x", method: "GET", path: "/v1/x" });
    assert.equal(reply.unknown, false, name);
    assert.equal(reply.status, status, name);
  }
});

test("replay: the recorded empty lists and DELETE answers drive the cleanup to nothing to delete and a deleted-and-gone name", async () => {
  const list = fixtures("lane7-shape-001", "topics-list-before.json");
  const missing = JSON.parse(fixtures("lane7-shape-001", "topic-missing-get.json"));
  const deleted = JSON.parse(fixtures("lane7-shape-001", "topic-delete.json"));
  const reply = (row) => ({ status: row.status, body: JSON.parse(row.body), unknown: false });
  const empty = createClient({
    transport: { name: "rest", request: async () => reply(JSON.parse(list)) },
    ownership: own,
    pushState: newPushState(),
    caseId: "cleanup",
    ledger,
  });
  const nothing = await cleanup({
    client: empty,
    ownership: own,
    project: "demo-project",
    ledger,
    sleep,
  });
  assert.deepEqual([nothing.deleted, nothing.errors, nothing.unsettled], [[], [], []]);
  const name = mine("topics", "recorded");
  issue(name, "ok");
  let removed = false;
  const calls = [];
  const client = createClient({
    transport: {
      name: "rest",
      request: async ({ method, path }) => {
        calls.push(method);
        if (method === "DELETE") return ((removed = true), reply(deleted));
        if (path.includes("?")) return reply(JSON.parse(list));
        return removed ? reply(missing) : { status: 200, body: { name }, unknown: false };
      },
    },
    ownership: own,
    pushState: newPushState(),
    caseId: "cleanup",
    ledger,
  });
  const report = await cleanup({ client, ownership: own, project: "demo-project", ledger, sleep });
  assert.deepEqual(report.settled, [{ name, how: "deleted" }]);
});
