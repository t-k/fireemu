// The read-back: GETs only, absence judged only by a direct 404 NOT_FOUND, every list checked, and a leftover or an
// unreadable answer keeps it from saying everything is gone.
import assert from "node:assert/strict";
import test from "node:test";
import { ALL_FUNCTIONS, JOB_IDS, QUEUE_IDS, functionName, packageIds, TOPIC } from "./plan.mjs";
import { READBACK_MAX_REQUESTS, readbackAllow, readbackNames, readbackRun } from "./readback.mjs";
import { record } from "./run.mjs";
import { BUCKET, NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
async function afterRun(worldOptions = {}) {
  const world = createWorld({ runId: RUN, ...worldOptions });
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
  return { world, result };
}
const readback = (world, over = {}) =>
  readbackRun({
    baseline: world.baseline,
    runId: RUN,
    projectNumber: NUMBER,
    bucket: BUCKET,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: over.send ?? world.send,
    clock: () => world.now,
  });

test("after a clean run everything reads absent and nothing is sent but reads", async () => {
  const { world } = await afterRun();
  const before = world.calls.length;
  const result = await readback(world);
  assert.equal(result.allAbsent, true);
  const calls = world.calls.slice(before);
  assert.ok(
    calls.every((c) => c.startsWith("GET ") || c.endsWith(":getIamPolicy")),
    "only GETs and the project IAM read",
  );
  assert.equal(calls.filter((c) => !c.startsWith("GET ")).length, 1, "one POST, the IAM read");
  assert.ok(result.attempted <= READBACK_MAX_REQUESTS);
  assert.equal(Object.keys(result.names).length, readbackNames(RUN, BUCKET).length);
  assert.deepEqual(Object.keys(result.lists).toSorted(), [
    "documents",
    "functionsAndServices",
    "jobs",
    "objects",
    "packages",
    "queues",
    "topics",
    "triggers",
  ]);
});

test("the names it reads are every function, job, queue, the topic, the document, the object and both images of each", () => {
  const labels = readbackNames(RUN, BUCKET).map(([label]) => label);
  assert.equal(
    labels.length,
    ALL_FUNCTIONS.length + JOB_IDS.length + QUEUE_IDS.length + 1 + 1 + 1 + ALL_FUNCTIONS.length * 2,
  );
  assert.ok(
    !readbackNames(RUN, null).some(([label]) => label === "object"),
    "no bucket, no object name",
  );
  for (const fn of ALL_FUNCTIONS) assert.ok(labels.includes("function-" + fn));
  assert.ok(labels.includes("topic") && labels.includes("document") && labels.includes("object"));
});

const LEFTOVERS = [
  [
    "a function",
    (w) => w.functions.set(functionName("pcps"), { name: functionName("pcps"), state: "ACTIVE" }),
  ],
  ["a job", (w) => w.jobs.set(JOB_IDS[0], { name: "x" })],
  ["a queue", (w) => w.queues.set(QUEUE_IDS[0], { name: "x" })],
  ["the topic", (w) => w.topics.add(TOPIC)],
  ["an image", (w) => w.packages.add(packageIds("pcps")[1])],
  ["the document", (w) => w.documents.set("pcrun-" + RUN + "-a", { name: "x" })],
  ["the object", (w) => w.objects.set("pycheck/pcrun-" + RUN + "-a.json", { name: "x" })],
  ["a trigger", (w) => w.triggers.add("pcps-1")],
];
for (const [what, seed] of LEFTOVERS)
  test(`${what} that is still there is not absent`, async () => {
    const { world } = await afterRun();
    seed(world);
    const result = await readback(world);
    assert.equal(result.allAbsent, false);
  });

test("a 404 that is not NOT_FOUND, an unreadable answer, a 5xx and a transport error are not absence", async () => {
  const { world } = await afterRun();
  const url = "GET cloudfunctions.googleapis.com/v2/" + functionName("pcps");
  for (const answer of [
    () => reply(404, { error: { status: "PERMISSION_DENIED", code: 404 } }),
    () => new Response("not json", { status: 404 }),
    () => reply(500, { error: { status: "INTERNAL", code: 500 } }),
    () => "throw",
  ]) {
    const result = await readback(world, {
      send: (request) =>
        request.method + " " + new URL(request.url).hostname + new URL(request.url).pathname === url
          ? Promise.resolve(answer()).then((a) => {
              if (a === "throw") throw new Error("transport");
              return a;
            })
          : world.send(request),
    });
    assert.equal(result.allAbsent, false);
  }
});

test("a list that cannot be read, or runs past five pages, is incomplete and not allAbsent", async () => {
  const { world } = await afterRun();
  const broken = await readback(world, {
    send: (request) =>
      request.url.includes("/queues?")
        ? Promise.resolve(reply(500, { error: { status: "INTERNAL" } }))
        : world.send(request),
  });
  assert.equal(broken.allAbsent, false);
  assert.ok(broken.incompleteReads.length > 0);
});

test("a missing bucket cannot read the object and is incomplete", async () => {
  const { world } = await afterRun();
  const result = await readbackRun({
    baseline: world.baseline,
    runId: RUN,
    projectNumber: NUMBER,
    bucket: null,
    accessToken: "tok-abcdefgh",
    save: async () => {},
    send: world.send,
    clock: () => world.now,
  });
  assert.equal(result.allAbsent, false);
  assert.deepEqual(result.incompleteReads[0], { id: "bucket", status: "unknown" });
});

test("a 401 stops the read-back and is recorded", async () => {
  const { world } = await afterRun();
  const result = await readback(world, {
    send: async () => reply(401, { error: { status: "UNAUTHENTICATED" } }),
  });
  assert.equal(result.allAbsent, false);
  assert.ok(result.authStop);
});

test("the allowlist refuses every mutation and any read outside the run's names", () => {
  const allow = readbackAllow(RUN, NUMBER);
  assert.equal(
    allow({
      method: "DELETE",
      url: `https://pubsub.googleapis.com/v1/projects/fireemu-oracle-events/topics/${TOPIC}`,
    }),
    false,
  );
  assert.equal(
    allow({
      method: "PUT",
      url: `https://pubsub.googleapis.com/v1/projects/fireemu-oracle-events/topics/${TOPIC}`,
      json: {},
    }),
    false,
  );
  assert.equal(
    allow({
      method: "POST",
      url: `https://cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-events/locations/us-central1/jobs/${JOB_IDS[0]}:run`,
      json: {},
    }),
    false,
  );
  assert.equal(
    allow({
      method: "GET",
      url: `https://pubsub.googleapis.com/v1/projects/fireemu-oracle-events/topics/${TOPIC}`,
    }),
    true,
  );
  assert.equal(
    allow({
      method: "GET",
      url: "https://pubsub.googleapis.com/v1/projects/fireemu-oracle-events/topics/other",
    }),
    false,
  );
  assert.equal(
    allow({ method: "POST", url: "https://logging.googleapis.com/v2/entries:list", json: {} }),
    false,
    "a POST read is not in the read-back",
  );
});
