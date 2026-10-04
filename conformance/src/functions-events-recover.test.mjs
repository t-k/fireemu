import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { RECOVERY_RULES } from "./functions-events/record/guard.mjs";
import { OPERATION_MAX_POLLS, recover, residue } from "./functions-events/record/recover.mjs";
import { RECOVERY_MAX_REQUESTS } from "./functions-events/record/sandbox.mjs";
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
  assert.equal(sleeps.filter((s) => s === 10).length, 29 + 2);
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

test("a 404 whose body cannot be read settles nothing: the resource is not taken for absent and not deleted", async () => {
  for (const url of [
    "/functions/storageArchivedV2",
    "/subscriptions/eventarc-us-east1-pubsubpublishedv2-974238-sub-583",
  ]) {
    const { world, transport, sleep } = setup({
      failures: [
        {
          match: (m, u) => m === "GET" && u.endsWith(url),
          status: 404,
          body: "<html>not found</html>",
        },
      ],
    });
    const { outcome, record } = await recover({ transport, sleep });
    assert.equal(outcome, "needs-review", url);
    assert.ok(
      record.steps.some((step) => step.result === "unsettled"),
      url,
    );
    assert.ok(!deletes(world).some((d) => url.endsWith(d)), url);
  }
});

test("a read-back that cannot be read is not complete, so nothing is settled by it", async () => {
  for (const tail of ["/locations/us-east1/services", "/subscriptions", "/topics"]) {
    const { transport, sleep } = setup({
      failures: [{ match: (m, u) => m === "GET" && u.endsWith(tail), status: 503 }],
    });
    const { outcome, record } = await recover({ transport, sleep });
    assert.equal(outcome, "needs-review", tail);
    assert.equal(record.residue.complete, false, tail);
  }
});

test("a list that comes in pages is read to the end, and a list of more than five pages is not complete", async () => {
  const { world, sleep } = setup();
  const original = world.fetch;
  const pages = new Map();
  world.fetch = async (url, init) => {
    const parsed = new URL(url);
    if (
      parsed.hostname === "pubsub.googleapis.com" &&
      parsed.pathname.endsWith("/subscriptions") &&
      init.method === "GET"
    ) {
      const page = Number(parsed.searchParams.get("pageToken") ?? "0");
      pages.set(page, true);
      const body =
        page < 2
          ? {
              subscriptions: [{ name: `projects/p/subscriptions/mine-${page}` }],
              nextPageToken: String(page + 1),
            }
          : { subscriptions: [{ name: "projects/p/subscriptions/eventarc-late" }] };
      return { status: 200, arrayBuffer: async () => Buffer.from(JSON.stringify(body)) };
    }
    return original(url, init);
  };
  const paged = createTransport({
    directory: mkdtempSync(join(tmpdir(), "fe-recover-")),
    ceiling: 90,
    token: async () => "t".repeat(24),
    fetch: world.fetch,
    rules: RECOVERY_RULES,
  });
  const { record } = await recover({ transport: paged, sleep });
  assert.deepEqual([...pages.keys()], [0, 1, 2]);
  assert.deepEqual(
    record.residue.remaining.filter((r) => r.startsWith("subscription")),
    ["subscription: eventarc-late"],
  );
  const endless = setup();
  const endlessFetch = endless.world.fetch;
  let served = 0;
  endless.world.fetch = async (url, init) => {
    const parsed = new URL(url);
    if (
      parsed.hostname === "pubsub.googleapis.com" &&
      parsed.pathname.endsWith("/topics") &&
      init.method === "GET"
    ) {
      served += 1;
      return {
        status: 200,
        arrayBuffer: async () => Buffer.from(JSON.stringify({ topics: [], nextPageToken: "more" })),
      };
    }
    return endlessFetch(url, init);
  };
  const transport2 = createTransport({
    directory: mkdtempSync(join(tmpdir(), "fe-recover-")),
    ceiling: 90,
    token: async () => "t".repeat(24),
    fetch: endless.world.fetch,
    rules: RECOVERY_RULES,
  });
  const result = await recover({ transport: transport2, sleep: endless.sleep });
  assert.equal(served, 5);
  assert.equal(result.record.residue.complete, false);
});

test("the worst case (both operations polled 30 times, nothing else helps) stays inside the 90 requests the envelope allows", async () => {
  const { world, transport, sleep } = setup({
    eventarcCleans: false,
    neverDone: ["storageArchivedV2", "pubsubPublishedV2"],
  });
  const { record } = await recover({ transport, sleep });
  assert.ok(world.state.requests.length <= 90, `${world.state.requests.length} requests`);
  assert.equal(transport.state.refused, 0);
  assert.equal(record.steps.filter((s) => s.result === "operation-pending").length, 2);
  assert.equal(RECOVERY_MAX_REQUESTS, 90);
  assert.ok(world.state.requests.length > 60, "the worst case is what the ceiling is for");
});

test("a pub/sub read that shows another name, or a 2xx that is not a 200, is not taken for the resource", async () => {
  const id = "eventarc-us-east1-pubsubpublishedv2-974238-sub-583";
  const wrongName = setup({ eventarcCleans: false });
  wrongName.world.state.subscriptions.get(id).name =
    "projects/fireemu-oracle-events/subscriptions/other";
  const first = await recover({ transport: wrongName.transport, sleep: wrongName.sleep });
  assert.equal(first.record.steps.find((s) => s.resource.includes(id)).result, "unsettled");
  assert.ok(!deletes(wrongName.world).includes(`subscriptions/${id}`));
  for (const url of ["/functions/storageArchivedV2", `/subscriptions/${id}`]) {
    const { world, transport, sleep } = setup({
      eventarcCleans: false,
      failures: [
        {
          match: (m, u) => m === "GET" && u.endsWith(url),
          status: 203,
          body: {
            name: url.includes("functions")
              ? "projects/fireemu-oracle-events/locations/us-central1/functions/storageArchivedV2"
              : `projects/fireemu-oracle-events/subscriptions/${id}`,
          },
        },
      ],
    });
    const { record } = await recover({ transport, sleep });
    assert.ok(
      record.steps.some((s) => s.result === "unsettled"),
      url,
    );
    assert.ok(!deletes(world).some((d) => url.endsWith(d)), url);
  }
});

test("an unknown pub/sub delete is sent once and stops the later pub/sub deletes", async () => {
  const id = "eventarc-us-east1-pubsubpublishedv2-974238-sub-583";
  const { world, transport, sleep } = setup({
    eventarcCleans: false,
    failures: [
      { match: (m, u) => m === "DELETE" && u.endsWith(`/subscriptions/${id}`), timeout: true },
    ],
  });
  const { outcome, record } = await recover({ transport, sleep });
  assert.equal(outcome, "needs-review");
  assert.deepEqual(
    deletes(world).filter((d) => d.startsWith("subscriptions") || d.startsWith("topics")),
    [`subscriptions/${id}`],
  );
  assert.equal(
    record.steps.filter(
      (s) => s.resource.startsWith("subscription") || s.resource.startsWith("topic"),
    ).length,
    1,
  );
});

test("a refusal that says done is not a finished operation; an error after the function is gone is still a problem", async () => {
  const stuck = setup({
    failures: [
      {
        match: (m, u) => m === "GET" && u.includes("/operations/"),
        status: 403,
        body: { done: true, error: { code: 403 } },
      },
    ],
  });
  const first = await recover({ transport: stuck.transport, sleep: stuck.sleep });
  assert.equal(first.record.steps[0].result, "operation-pending");
  const late = setup({ errorButRemoved: ["storageArchivedV2"] });
  const second = await recover({ transport: late.transport, sleep: late.sleep });
  assert.equal(second.record.steps[0].result, "operation-failed");
  assert.equal(
    second.outcome,
    "needs-review",
    "the residue is empty but the operation said it failed",
  );
  assert.deepEqual(second.record.residue.remaining, []);
});

test("the operation is polled every ten seconds, so a function that takes a minute to go is waited for", async () => {
  const { transport, sleep, sleeps } = setup({ neverDone: ["storageArchivedV2"] });
  await recover({ transport, sleep });
  assert.equal(
    sleeps.filter((s) => s === 10).length,
    29 + 2,
    "29 waits for the first operation, 2 for the second",
  );
  assert.ok(sleeps.every((s) => s === 10));
});

const PUBSUB = {
  sub583: "eventarc-us-east1-pubsubpublishedv2-974238-sub-583",
  sub488: "eventarc-us-central1-storagearchivedv2-494903-sub-488",
  topic679: "eventarc-us-central1-storagearchivedv2-494903-679",
};

test("the recorded failure again: while storageArchivedV2 is still there, its trigger's subscription and topic are kept; the other function's subscription goes", async () => {
  const { world, transport, sleep } = setup({
    eventarcCleans: false,
    failOperationFor: ["storageArchivedV2"],
  });
  const { outcome, record } = await recover({ transport, sleep });
  assert.equal(outcome, "needs-review");
  const deleted = deletes(world);
  assert.ok(
    !deleted.includes(`subscriptions/${PUBSUB.sub488}`),
    "the subscription of the live trigger stays",
  );
  assert.ok(!deleted.includes(`topics/${PUBSUB.topic679}`), "the topic of the live trigger stays");
  assert.ok(
    !world.state.requests.some(
      (r) => r.path.endsWith(PUBSUB.sub488) || r.path.endsWith(PUBSUB.topic679),
    ),
    "not even read: the owner step decides first",
  );
  assert.ok(
    world.state.subscriptions.has(PUBSUB.sub488) && world.state.topics.has(PUBSUB.topic679),
  );
  assert.ok(
    deleted.includes("functions/pubsubPublishedV2") &&
      deleted.includes(`subscriptions/${PUBSUB.sub583}`),
  );
  const kept = record.steps.filter((s) => s.result === "kept").map((s) => s.resource);
  assert.deepEqual(kept, [`subscription ${PUBSUB.sub488}`, `topic ${PUBSUB.topic679}`]);
  assert.ok(
    record.problems.some((p) => p.includes(PUBSUB.sub488) && p.includes("storageArchivedV2")),
  );
  assert.ok(
    record.residue.remaining.includes(`subscription: ${PUBSUB.sub488}`),
    "and the read-back still shows them",
  );
  assert.ok(record.residue.remaining.includes(`topic: ${PUBSUB.topic679}`));
});

test("each Pub/Sub object follows its own function: an owner that is deleted or already absent releases it, anything else keeps it", async () => {
  const gone = setup({ eventarcCleans: false });
  const first = await recover({ transport: gone.transport, sleep: gone.sleep });
  assert.deepEqual(
    deletes(gone.world)
      .filter((d) => !d.startsWith("functions"))
      .toSorted(),
    [
      `subscriptions/${PUBSUB.sub488}`,
      `subscriptions/${PUBSUB.sub583}`,
      `topics/${PUBSUB.topic679}`,
    ].toSorted(),
  );
  assert.equal(first.outcome, "recovered");
  const absent = setup({ eventarcCleans: false });
  absent.world.state.functions.delete("us-central1/storageArchivedV2");
  const second = await recover({ transport: absent.transport, sleep: absent.sleep });
  assert.ok(
    deletes(absent.world).includes(`topics/${PUBSUB.topic679}`),
    "an absent owner releases its objects",
  );
  assert.equal(
    second.record.steps.find((s) => s.resource === "function us-central1/storageArchivedV2").result,
    "absent",
  );
  // the Pub/Sub function stuck: only its own subscription is kept, the storage function's objects still go
  const stuck = setup({ eventarcCleans: false, failOperationFor: ["pubsubPublishedV2"] });
  const third = await recover({ transport: stuck.transport, sleep: stuck.sleep });
  assert.ok(!deletes(stuck.world).includes(`subscriptions/${PUBSUB.sub583}`));
  assert.ok(
    deletes(stuck.world).includes(`subscriptions/${PUBSUB.sub488}`) &&
      deletes(stuck.world).includes(`topics/${PUBSUB.topic679}`),
  );
  assert.deepEqual(
    third.record.steps.filter((s) => s.result === "kept").map((s) => s.resource),
    [`subscription ${PUBSUB.sub583}`],
  );
  // an owner whose read settled nothing, or whose operation never finished, keeps its objects too
  for (const options of [
    {
      eventarcCleans: false,
      failures: [
        { match: (m, u) => m === "GET" && u.endsWith("/functions/storageArchivedV2"), status: 503 },
      ],
    },
    { eventarcCleans: false, neverDone: ["storageArchivedV2"] },
  ]) {
    const { world, transport, sleep } = setup(options);
    await recover({ transport, sleep });
    assert.ok(
      !deletes(world).includes(`subscriptions/${PUBSUB.sub488}`) &&
        !deletes(world).includes(`topics/${PUBSUB.topic679}`),
      JSON.stringify(Object.keys(options)),
    );
  }
});

test("when a function delete has no usable answer, the later Pub/Sub objects are not even considered", async () => {
  const { world, transport, sleep } = setup({
    eventarcCleans: false,
    failures: [
      {
        match: (m, u) => m === "DELETE" && u.endsWith("/functions/storageArchivedV2"),
        status: 503,
      },
    ],
  });
  const { record } = await recover({ transport, sleep });
  assert.deepEqual(deletes(world), ["functions/storageArchivedV2"]);
  assert.equal(
    record.steps.filter(
      (s) => s.resource.startsWith("subscription") || s.resource.startsWith("topic"),
    ).length,
    0,
  );
});
