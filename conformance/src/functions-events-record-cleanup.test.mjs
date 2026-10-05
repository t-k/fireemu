import assert from "node:assert/strict";
import test from "node:test";

import { runCleanup } from "./functions-events/record/cleanup.mjs";
import { HANDLERS } from "./functions-events/record/logs.mjs";
import { createTransport } from "./functions-events/record/rest.mjs";
import { CONTROL_BUCKET, PRIMARY_BUCKET } from "./functions-events/record/script.mjs";
import { createWorld } from "./functions-events-record-world.mjs";
import { tempDir } from "./test-tmpdir.mjs";

function setup() {
  let t = Date.UTC(2026, 9, 4);
  const world = createWorld({ now: () => t });
  const directory = tempDir("fe-clean-");
  const transport = createTransport({
    directory,
    ceiling: 1000,
    token: async () => "t",
    apiKey: "k",
    fetch: world.fetch,
  });
  const slept = [];
  const cliCalls = [];
  const cli = async (action) => {
    cliCalls.push(action);
    world.undeploy();
    return { action, exitCode: 0 };
  };
  const sleep = async (seconds) => slept.push(seconds);
  return { world, transport, cli, cliCalls, sleep, slept };
}
const put = (world, key, versions) => world.objects.set(key, versions);

test("a clean world is verified, the CLI delete runs once, and the control bucket and topics are gone", async () => {
  const { world, transport, cli, cliCalls, sleep } = setup();
  world.deploy();
  world.topics.add("fe-events-primary").add("fe-events-control");
  world.buckets.set(CONTROL_BUCKET, { versioning: false });
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: true } });
  assert.deepEqual(result.problems, []);
  assert.equal(result.verified, true);
  assert.deepEqual(cliCalls, ["delete"]);
  assert.equal(world.buckets.has(CONTROL_BUCKET), false);
  assert.equal(world.topics.size, 0);
});

test("leftover objects (every generation), markers and versioning are removed and reported", async () => {
  const { world, transport, cli, sleep } = setup();
  world.deploy();
  world.buckets.get(PRIMARY_BUCKET).versioning = true;
  put(world, `${PRIMARY_BUCKET}/fe-events/e1.txt`, [
    { generation: "1", live: false },
    { generation: "2", live: true },
  ]);
  put(world, `${PRIMARY_BUCKET}/other/e2.txt`, [{ generation: "3", live: true }]);
  world.docs.set("fe_events_retry_markers/abc", { documentPath: { stringValue: "x" } });
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: true } });
  assert.equal(result.verified, true, JSON.stringify(result.problems));
  assert.equal(result.steps.markers.found, 1);
  assert.equal(result.steps["objects-primary"].removed, 3);
  assert.equal(result.steps.versioning.restored, true);
  assert.equal(world.buckets.get(PRIMARY_BUCKET).versioning, false);
});

test("a run that never started the deploy sends no CLI delete", async () => {
  const { transport, cli, cliCalls, sleep } = setup();
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: false } });
  assert.deepEqual(cliCalls, []);
  assert.equal(result.steps.functions.skipped.includes("never started"), true);
});

test("functions that stay listed after the CLI delete get one REST delete each and, if they still stay, make the run needs-recovery", async () => {
  const { world, transport, sleep, slept } = setup();
  world.deploy();
  const cliCalls = [];
  const cli = async (action) => {
    cliCalls.push(action);
    return { action, exitCode: 0 };
  };
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: true } });
  assert.equal(result.verified, false);
  assert.ok(result.problems.some((p) => p.startsWith("functions:")));
  assert.deepEqual(cliCalls, ["delete"], "no second CLI delete");
  assert.deepEqual(
    world.restDeletes.toSorted(),
    HANDLERS.filter((h) => h.generation === 2)
      .map((h) => h.name)
      .toSorted(),
    "one REST delete for each Gen2 function, none for Gen1",
  );
  assert.equal(
    slept.filter((s) => s === 30).length,
    5 + 3,
    "six polls before the REST deletes, four after",
  );
});

const gen2 = HANDLERS.filter((h) => h.generation === 2).map((h) => h.name);

test("the recorded storageArchivedV2 case: the CLI delete leaves it listed, one REST delete takes it, the lists then verify", async () => {
  const { world, transport, sleep } = setup();
  world.deploy();
  const cliCalls = [];
  const cli = async (action) => {
    cliCalls.push(action);
    world.undeploy({ stuck: ["storageArchivedV2"] });
    return { action, exitCode: 0, errored: 1 };
  };
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: true } });
  assert.equal(result.verified, true, JSON.stringify(result.problems));
  assert.deepEqual(cliCalls, ["delete"]);
  assert.deepEqual(world.restDeletes, ["storageArchivedV2"]);
  assert.deepEqual(
    result.steps.functions.rest.map((r) => [r.name, r.delete.status, r.error]),
    [["storageArchivedV2", 200, null]],
  );
  assert.equal(result.steps.functions.cli.errored, 1);
  assert.equal(result.steps.functions.summary.absent, true);
});

test("two functions left behind are deleted one at a time: the second delete is sent only after the first operation is done", async () => {
  const { world, transport, sleep } = setup();
  world.deploy();
  world.operationPolls = 2;
  const cli = async (action) => {
    world.undeploy({ stuck: ["storageArchivedV2", "fsCreatedV2"] });
    return { action, exitCode: 0 };
  };
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: true } });
  assert.equal(result.verified, true, JSON.stringify(result.problems));
  const order = world.requests
    .filter(
      (r) =>
        r.url.includes("/operations/") || (r.method === "DELETE" && r.url.includes("/functions/")),
    )
    .map((r) => `${r.method} ${r.url.split("/").slice(-2).join("/")}`);
  const firstOp = order.findLastIndex((entry) => entry.includes("operation-1"));
  const secondDelete = order.findIndex(
    (entry) => entry.startsWith("DELETE functions/") && order.indexOf(entry) > 0,
  );
  assert.ok(firstOp >= 0 && secondDelete > firstOp, order.join("\n"));
  assert.equal(world.restDeletes.length, 2);
});

test("a REST delete whose operation ends in an error is sent once and leaves the run needs-recovery", async () => {
  const { world, transport, sleep } = setup();
  world.deploy();
  world.restDeleteFails = true;
  const cli = async (action) => {
    world.undeploy({ stuck: ["storageArchivedV2"] });
    return { action, exitCode: 0 };
  };
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: true } });
  assert.equal(result.verified, false);
  assert.deepEqual(world.restDeletes, ["storageArchivedV2"]);
  assert.match(result.steps.functions.rest[0].error.message, /Deleting trigger failed/);
});

test("a REST delete with no usable answer is sent once and stops the other REST deletes", async () => {
  const { world, transport, sleep } = setup();
  world.deploy();
  world.failures.push({
    match: (m, u) => m === "DELETE" && u.endsWith("/functions/fsCreatedV2"),
    status: 503,
  });
  const cli = async (action) => {
    world.undeploy({ stuck: ["storageArchivedV2", "fsCreatedV2"] });
    return { action, exitCode: 0 };
  };
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: true } });
  assert.equal(result.verified, false);
  const sent = world.requests
    .filter((r) => r.method === "DELETE" && r.url.includes("/functions/"))
    .map((r) => r.url.split("/").at(-1));
  assert.deepEqual(sent.length, 1, "one delete, no retry, no other delete");
  assert.equal(result.steps.functions.rest[0].stopped, true);
});

test("a Gen1 function left behind and an unreadable list are not deleted by REST", async () => {
  const gen1 = setup();
  gen1.world.deploy();
  const first = await runCleanup({
    transport: gen1.transport,
    cli: async (action) => {
      gen1.world.undeploy({ stuck: ["fsCreatedV1"] });
      return { action, exitCode: 0 };
    },
    sleep: gen1.sleep,
    ran: { deployStarted: true },
  });
  assert.equal(first.verified, false);
  assert.deepEqual(gen1.world.restDeletes, []);
  assert.equal(
    gen1.slept.filter((x) => x === 30).length,
    5,
    "no REST delete, so no second round of list reads",
  );
  const unreadable = setup();
  unreadable.world.deploy();
  unreadable.world.failures.push({
    match: (m, u) => m === "GET" && u.includes("/v2/projects") && u.endsWith("/functions"),
    status: 503,
  });
  const second = await runCleanup({
    transport: unreadable.transport,
    cli: unreadable.cli,
    sleep: unreadable.sleep,
    ran: { deployStarted: true },
  });
  assert.equal(second.verified, false);
  assert.deepEqual(unreadable.world.restDeletes, []);
});

test("no REST delete is sent when the lists are already empty, or when the deploy never started", async () => {
  const { world, transport, cli, sleep } = setup();
  world.deploy();
  await runCleanup({ transport, cli, sleep, ran: { deployStarted: true } });
  assert.deepEqual(world.restDeletes, []);
  const never = setup();
  await runCleanup({
    transport: never.transport,
    cli: never.cli,
    sleep: never.sleep,
    ran: { deployStarted: false },
  });
  assert.deepEqual(never.world.restDeletes, []);
  void gen2;
});

test("an unreadable object list is a problem, never an empty bucket", async () => {
  const { world, transport, cli, sleep } = setup();
  world.failures.push({
    match: (m, u) => u.includes(`/b/${PRIMARY_BUCKET}/o?versions=true`),
    status: 503,
  });
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: false } });
  assert.equal(result.verified, false);
  assert.ok(result.problems.some((p) => p.startsWith("objects-primary")));
});

test("a delete that gets no answer is not counted as removed and is not retried", async () => {
  const { world, transport, cli, sleep } = setup();
  put(world, `${PRIMARY_BUCKET}/fe-events/e1.txt`, [{ generation: "1", live: true }]);
  world.failures.push({ match: (m) => m === "DELETE", error: "TimeoutError" });
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: false } });
  assert.equal(result.verified, false);
  assert.equal(
    world.requests.filter((r) => r.method === "DELETE" && r.url.includes("fe-events%2Fe1.txt"))
      .length,
    1,
  );
});

test("a control bucket that is still listed after its delete is a problem, however the delete answered", async () => {
  const { world, transport, cli, sleep } = setup();
  world.buckets.set(CONTROL_BUCKET, { versioning: false });
  world.failures.push({
    match: (m, u) => m === "DELETE" && u.endsWith(`/b/${CONTROL_BUCKET}`),
    status: 204,
    times: 1,
  });
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: false } });
  assert.equal(result.verified, false);
  assert.ok(result.problems.some((p) => p.startsWith("control-bucket")));
});

test("a topic list with a second page cannot show the topics gone", async () => {
  const { world, cli, sleep } = setup();
  const original = world.fetch;
  world.fetch = async (url, init) => {
    if (url.includes("/topics?pageSize")) {
      return {
        status: 200,
        arrayBuffer: async () => Buffer.from(JSON.stringify({ topics: [], nextPageToken: "more" })),
      };
    }
    return original(url, init);
  };
  const t2 = createTransport({
    directory: tempDir("fe-clean-"),
    ceiling: 1000,
    token: async () => "t",
    apiKey: "k",
    fetch: world.fetch,
  });
  const result = await runCleanup({ transport: t2, cli, sleep, ran: { deployStarted: false } });
  assert.ok(result.problems.some((p) => p.startsWith("topics")));
});

test("users the run may have made are looked up by uid and by email and removed", async () => {
  const { world, transport, cli, sleep } = setup();
  world.users.set("u1", { email: "u1@example.test" });
  world.users.set("u2", { email: "lost@example.test" });
  const owned = { uids: new Set(["u1"]), emails: new Set(["lost@example.test"]) };
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: false }, owned });
  assert.equal(result.verified, true, JSON.stringify(result.problems));
  assert.equal(world.users.size, 0);
  assert.equal(result.steps.users.removed, 2);
});

test("documents of the run in both collections are removed and read back", async () => {
  const { world, transport, cli, sleep } = setup();
  world.docs.set("fe_events_primary/a", { fixtureKind: { stringValue: "ordinary" } });
  world.docs.set("fe_events_control/b", { fixtureKind: { stringValue: "ordinary" } });
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: false } });
  assert.equal(result.verified, true);
  assert.equal(world.docs.size, 0);
  assert.equal(result.steps.documents.removed, 2);
});

test("two functions left behind: the second delete is sent only after the first operation is done, each wait is ten seconds", async () => {
  const { world, transport, sleep, slept } = setup();
  world.deploy();
  world.operationPolls = 2;
  const seen = [];
  world.hooks.push((method, url) => {
    if (method === "DELETE" && url.includes("/functions/"))
      seen.push([url.split("/").at(-1), [...world.removed]]);
  });
  const cli = async (action) => {
    world.undeploy({ stuck: ["storageArchivedV2", "fsCreatedV2"] });
    return { action, exitCode: 0 };
  };
  const result = await runCleanup({ transport, cli, sleep, ran: { deployStarted: true } });
  assert.equal(result.verified, true, JSON.stringify(result.problems));
  assert.equal(seen.length, 2);
  assert.deepEqual(seen[0][1], [], "the first delete finds nothing removed yet");
  assert.deepEqual(
    seen[1][1],
    [seen[0][0]],
    "the second delete is sent only after the first operation finished",
  );
  assert.equal(
    slept.filter((s) => s === 10).length,
    4,
    "two waits of ten seconds for each operation",
  );
  assert.equal(
    result.steps.functions.rest.every((r) => r.polls === 3),
    true,
  );
});

test("a REST delete is sent only from a complete list, and a delete answer that names no operation of this project is not polled", async () => {
  const { restDeleteLeftovers } = await import("./functions-events/record/cleanup.mjs");
  const sent = [];
  const request = async (spec) => {
    sent.push(spec.id);
    return {
      kind: "success",
      status: 200,
      json: { name: "projects/other/locations/us-central1/operations/x" },
    };
  };
  const item = {
    name: "projects/fireemu-oracle-events/locations/us-central1/functions/fsCreatedV2",
  };
  assert.deepEqual(
    await restDeleteLeftovers({
      request,
      sleep: async () => {},
      lists: { v2: { items: [item], complete: false } },
    }),
    [],
  );
  assert.deepEqual(
    await restDeleteLeftovers({ request, sleep: async () => {}, lists: undefined }),
    [],
  );
  assert.deepEqual(sent, []);
  const done = await restDeleteLeftovers({
    request,
    sleep: async () => {},
    lists: {
      v2: {
        items: [
          item,
          { name: "projects/p/locations/us-central1/functions/fsCreatedV1" },
          { name: "projects/p/locations/us-central1/functions/other" },
        ],
        complete: true,
      },
    },
  });
  assert.deepEqual(
    sent,
    ["cleanup.function-delete-fsCreatedV2"],
    "one delete, no poll of a foreign operation, Gen1 and unknown names ignored",
  );
  assert.equal(done[0].polls, undefined);
});
