import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { RECOVERY_RULES } from "./functions-events/record/guard.mjs";
import { OPERATION_MAX_POLLS, recover, residue } from "./functions-events/record/recover.mjs";
import { createTransport } from "./functions-events/record/rest.mjs";
import { createRecoverWorld } from "./functions-events-recover-world.mjs";

const setup = (options) => {
  const world = createRecoverWorld(options);
  const clock = { t: Date.UTC(2026, 9, 4, 16, 50) };
  const transport = createTransport({
    directory: mkdtempSync(join(tmpdir(), "fe-recover-")),
    ceiling: 90,
    token: async () => "t".repeat(24),
    fetch: world.fetch,
    now: () => clock.t,
    rules: RECOVERY_RULES,
  });
  const sleeps = [];
  const sleep = async (seconds) => {
    sleeps.push(seconds);
    clock.t += seconds * 1000;
  };
  return { world, transport, sleep, sleeps, clock };
};
const deletes = (world) =>
  world.state.requests
    .filter((r) => r.method === "DELETE")
    .map((r) => r.path.split("/").slice(-2).join("/"));
const writes = (world) =>
  world.state.requests.filter((r) => r.method !== "GET" && r.method !== "DELETE");

test("the recovery deletes the two functions one at a time, then what is left of Pub/Sub, and reads everything back", async () => {
  const { world, transport, sleep } = setup({ eventarcCleans: false });
  const { outcome, record } = await recover({ transport, sleep });
  assert.equal(outcome, "recovered", JSON.stringify(record.problems));
  assert.deepEqual(deletes(world), [
    "functions/storageArchivedV2",
    "functions/pubsubPublishedV2",
    "subscriptions/eventarc-us-east1-pubsubpublishedv2-974238-sub-583",
    "subscriptions/eventarc-us-central1-storagearchivedv2-494903-sub-488",
    "topics/eventarc-us-central1-storagearchivedv2-494903-679",
  ]);
  // one at a time: the first function's operation is polled to done before the second function is read
  const order = world.state.requests.map(
    (r) => `${r.method} ${r.path.split("/").slice(-2).join("/")}`,
  );
  const firstDone = order.findIndex(
    (entry, i) =>
      entry.startsWith("GET operations/") &&
      order[i + 1]?.startsWith("GET functions/pubsubPublishedV2"),
  );
  assert.ok(firstDone > 0, order.join("\n"));
  assert.equal(record.deletes, 5);
  assert.deepEqual(record.residue, { complete: true, remaining: [], settled: true });
  assert.deepEqual(record.readbacks.repositories["us-east1"].cleanupPolicies, [
    "firebase-functions-cleanup",
  ]);
  assert.equal(writes(world).length, 0, "nothing but GET and DELETE was sent");
  assert.ok(world.state.requests.length <= 90);
});

test("when the function delete takes Eventarc's Pub/Sub objects with it, only the functions are deleted and the rest read as absent", async () => {
  const { world, transport, sleep } = setup({ eventarcCleans: true });
  const { outcome, record } = await recover({ transport, sleep });
  assert.equal(outcome, "recovered");
  assert.deepEqual(deletes(world), ["functions/storageArchivedV2", "functions/pubsubPublishedV2"]);
  assert.equal(record.deletes, 2);
  assert.deepEqual(
    record.steps
      .filter((s) => s.resource.startsWith("subscription") || s.resource.startsWith("topic"))
      .map((s) => s.result),
    ["absent", "absent", "absent"],
  );
});

test("a resource a 404 shows absent is not deleted", async () => {
  const { world, transport, sleep } = setup();
  world.state.functions.delete("us-east1/pubsubPublishedV2");
  world.state.services.delete("us-east1/pubsubpublishedv2");
  world.state.triggers.delete("us-east1/pubsubpublishedv2-974238");
  const { outcome, record } = await recover({ transport, sleep });
  assert.equal(outcome, "recovered");
  assert.deepEqual(
    record.steps.find((s) => s.resource.includes("pubsubPublishedV2")).result,
    "absent",
  );
  assert.ok(!deletes(world).includes("functions/pubsubPublishedV2"));
});

test("a read that settles nothing deletes nothing and ends needs-review", async () => {
  for (const failure of [
    { match: (m, u) => m === "GET" && u.endsWith("/functions/storageArchivedV2"), status: 503 },
    { match: (m, u) => m === "GET" && u.endsWith("/functions/storageArchivedV2"), timeout: true },
    {
      match: (m, u) => m === "GET" && u.endsWith("/functions/storageArchivedV2"),
      status: 403,
      body: { error: { code: 403 } },
    },
  ]) {
    const { world, transport, sleep } = setup({ failures: [failure] });
    const { outcome, record } = await recover({ transport, sleep });
    assert.equal(outcome, "needs-review", JSON.stringify(failure));
    assert.ok(!deletes(world).includes("functions/storageArchivedV2"));
    assert.ok(record.problems.some((p) => p.startsWith("us-central1/storageArchivedV2")));
  }
});

test("a delete with no usable answer is sent once, stops the other deletes and still reads everything back", async () => {
  const { world, transport, sleep } = setup({
    failures: [
      {
        match: (m, u) => m === "DELETE" && u.endsWith("/functions/storageArchivedV2"),
        status: 503,
      },
    ],
  });
  const { outcome, record } = await recover({ transport, sleep });
  assert.equal(outcome, "needs-review");
  assert.deepEqual(
    deletes(world),
    ["functions/storageArchivedV2"],
    "no second delete, no other delete",
  );
  assert.ok(
    world.state.requests.some((r) => r.method === "GET" && r.path.endsWith("/subscriptions")),
    "the read-backs ran",
  );
  assert.ok(record.residue.remaining.includes("functions-v2 us-central1: storageArchivedV2"));
});

test("a refused delete (4xx) does not stop the next function", async () => {
  const { world, transport, sleep } = setup({
    failures: [
      {
        match: (m, u) => m === "DELETE" && u.endsWith("/functions/storageArchivedV2"),
        status: 400,
        body: { error: { code: 400 } },
      },
    ],
  });
  const { outcome } = await recover({ transport, sleep });
  assert.equal(outcome, "needs-review");
  assert.ok(deletes(world).includes("functions/pubsubPublishedV2"));
});

test("the recorded storageArchivedV2 case: a delete whose operation ends in the trigger error leaves the function and says so", async () => {
  const { world, transport, sleep } = setup({ failOperationFor: ["storageArchivedV2"] });
  const { outcome, record } = await recover({ transport, sleep });
  assert.equal(outcome, "needs-review");
  const step = record.steps[0];
  assert.equal(step.result, "operation-failed");
  assert.match(step.operationError.message, /Failed to update storage bucket metadata/);
  assert.ok(
    deletes(world).includes("functions/pubsubPublishedV2"),
    "the second function is still deleted, one at a time",
  );
  assert.ok(record.residue.remaining.includes("functions-v2 us-central1: storageArchivedV2"));
});

test("an operation that is never done is polled at most 30 times, 10 s apart, and not re-sent", async () => {
  const { world, transport, sleep, sleeps } = setup({ neverDone: ["storageArchivedV2"] });
  const { record } = await recover({ transport, sleep });
  const step = record.steps[0];
  assert.equal(step.result, "operation-pending");
  assert.equal(step.polls, OPERATION_MAX_POLLS);
  assert.equal(
    world.state.requests.filter(
      (r) => r.method === "DELETE" && r.path.endsWith("storageArchivedV2"),
    ).length,
    1,
  );
  assert.ok(sleeps.slice(0, 29).every((s) => s === 10));
});

test("a delete answer that names no operation of this project stops the deletes", async () => {
  const { world, transport, sleep } = setup({
    failures: [
      {
        match: (m, u) => m === "DELETE" && u.endsWith("/functions/storageArchivedV2"),
        status: 200,
        body: { name: "projects/other/locations/us-central1/operations/x" },
      },
    ],
  });
  const { outcome, record } = await recover({ transport, sleep });
  assert.equal(outcome, "needs-review");
  assert.equal(record.steps[0].result, "no-operation");
  assert.deepEqual(deletes(world), ["functions/storageArchivedV2"]);
});

test("a read that shows another name than the one asked for is not deleted", async () => {
  const { world, transport, sleep } = setup();
  world.state.functions.get("us-east1/pubsubPublishedV2").name =
    "projects/fireemu-oracle-events/locations/us-east1/functions/other";
  const { record } = await recover({ transport, sleep });
  assert.equal(record.steps.find((s) => s.resource.includes("us-east1")).result, "unsettled");
  assert.ok(!deletes(world).includes("functions/pubsubPublishedV2"));
});

// ---- the residue judge over the recorded bodies --------------------------------------------------

const rec = (name) =>
  JSON.parse(
    readFileSync(
      new URL(`./functions-events/record/recorded/v4-run/${name}.json`, import.meta.url),
      "utf8",
    ),
  ).body;
const list = (items, complete = true) => ({ items, complete });
const empty = () => list([]);
const emptyLists = () =>
  Object.fromEntries(
    ["us-central1", "us-east1"].flatMap((r) =>
      ["functions-v1", "functions-v2", "run-services", "eventarc-triggers"].map((k) => [
        `${k} ${r}`,
        empty(),
      ]),
    ),
  );

test("residue names what the v4 run left: the recorded us-central1 bodies", () => {
  const lists = {
    ...emptyLists(),
    "functions-v2 us-central1": list(rec("0140-lists.functions-v2").functions),
    "run-services us-central1": list(rec("0141-lists.run-services").services),
    "eventarc-triggers us-central1": list(rec("0142-lists.eventarc-triggers").triggers),
  };
  const left = residue({
    lists,
    subscriptions: list(rec("0147-cleanup.subscriptions").subscriptions),
    topics: list(rec("0146-cleanup.topics").topics),
  });
  assert.equal(left.settled, false);
  assert.deepEqual(left.remaining.toSorted(), [
    "eventarc-triggers us-central1: storagearchivedv2-494903",
    "functions-v2 us-central1: storageArchivedV2",
    "run-services us-central1: storagearchivedv2",
    "subscription: eventarc-us-central1-storagearchivedv2-494903-sub-488",
    "subscription: eventarc-us-east1-pubsubpublishedv2-974238-sub-583",
    "topic: eventarc-us-central1-storagearchivedv2-494903-679",
  ]);
});

test("residue is settled only by complete, empty lists; a foreign topic or subscription does not count, an incomplete read does not settle", () => {
  const clean = { lists: emptyLists(), subscriptions: empty(), topics: empty() };
  assert.deepEqual(residue(clean), { complete: true, remaining: [], settled: true });
  const foreign = {
    ...clean,
    topics: list([{ name: "projects/p/topics/someone-elses" }]),
    subscriptions: list([{ name: "projects/p/subscriptions/mine" }]),
  };
  assert.equal(residue(foreign).settled, true);
  const own = { ...clean, topics: list([{ name: "projects/p/topics/fe-events-primary" }]) };
  assert.deepEqual(residue(own).remaining, ["topic: fe-events-primary"]);
  const partial = { ...clean, lists: { ...clean.lists, "run-services us-east1": list([], false) } };
  assert.deepEqual([residue(partial).complete, residue(partial).settled], [false, false]);
  const east = {
    ...clean,
    lists: {
      ...clean.lists,
      "functions-v2 us-east1": list([
        { name: "projects/p/locations/us-east1/functions/pubsubPublishedV2" },
      ]),
    },
  };
  assert.deepEqual(residue(east).remaining, ["functions-v2 us-east1: pubsubPublishedV2"]);
});

test("the recovery sends only requests its own rules name: no POST, PUT or PATCH, no CLI", async () => {
  const { world, transport, sleep } = setup();
  await recover({ transport, sleep });
  assert.deepEqual([...new Set(world.state.requests.map((r) => r.method))].toSorted(), [
    "DELETE",
    "GET",
  ]);
  assert.ok(
    world.state.requests.every(
      (r) => !r.host.includes("storage.googleapis.com") || r.method === "GET",
    ),
  );
});
