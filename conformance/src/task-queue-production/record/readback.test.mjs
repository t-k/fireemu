// The read-back: it sends only reads, it settles only absence, and it closes nothing the run left open.
import "./isolation.mjs";
import assert from "node:assert/strict";
import test from "node:test";
import { PROJECT, REGION, functionOfRole, functionsOf, queueName } from "../plan.mjs";
import { RUN, go } from "./harness.mjs";
import {
  READBACK_MAX_REQUESTS,
  readbackAllow,
  readbackNames,
  readbackRun,
  uploadObjectEntries,
} from "./readback.mjs";
import { NUMBER, createWorld } from "./world.mjs";

const run = async (world, extra = {}) => {
  const journal = [];
  const result = await readbackRun({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token-abcdefgh",
    save: async (row) => journal.push(row),
    send: world.send,
    clock: () => world.now,
    ...extra,
  });
  return { result, journal };
};

test("after a clean run every name reads absent, the lists are empty, the inventory is the baseline: allAbsent", async () => {
  const { world, result } = await go();
  const baseline = result.inventory.before;
  const back = await run(world, {
    baseline,
    uploadObjects: result.cleanup.uploadObjectsDeleted,
  });
  assert.equal(back.result.allAbsent, true);
  assert.equal(back.result.unknown, 0);
  assert.deepEqual(back.result.inventory.differences, []);
  assert.ok(back.result.attempted <= READBACK_MAX_REQUESTS);
  assert.equal(back.result.names["function-" + functionOfRole(RUN, "tqdef")].absent, true);
  for (const method of world.calls.map((c) => c.split(" ")[0]))
    assert.ok(["GET", "POST", "PUT", "DELETE"].includes(method));
});

test("a read-back sends nothing but GETs and the project policy read", async () => {
  const { world, result } = await go();
  const before = world.calls.length;
  await run(world, {
    baseline: result.inventory.before,
    uploadObjects: result.cleanup.uploadObjectsDeleted,
  });
  const sent = world.calls.slice(before);
  assert.ok(sent.length > 0);
  for (const call of sent)
    assert.ok(call.startsWith("GET ") || call.includes(":getIamPolicy"), call);
});

test("a name that is still there, a list that holds one, or a baseline that differs: not absent", async () => {
  const { world, result } = await go();
  const options = {
    baseline: result.inventory.before,
    uploadObjects: result.cleanup.uploadObjectsDeleted,
  };
  const fn = functionsOf(RUN)[0];
  const leftQueue = createWorld({ runId: RUN, seedQueues: [fn] });
  const q = await run(leftQueue, options);
  assert.equal(q.result.allAbsent, false);
  assert.equal(q.result.names["queue-" + fn].absent, false);
  assert.deepEqual(q.result.lists.queues, [fn]);
  const changed = structuredClone(options.baseline);
  changed.services = changed.services.slice(1);
  const d = await run(world, { ...options, baseline: changed });
  assert.equal(d.result.allAbsent, false);
  assert.ok(d.result.inventory.differences.some((x) => x.kind === "services"));
  const none = await run(world, { ...options, baseline: null });
  assert.equal(none.result.allAbsent, false);
  assert.deepEqual(none.result.inventory.missing, ["baseline"]);
});

test("an obligation the run carried keeps allAbsent false even when everything reads absent", async () => {
  const { world, result } = await go();
  const out = await run(world, {
    baseline: result.inventory.before,
    uploadObjects: result.cleanup.uploadObjectsDeleted,
    carried: ["upload:receipt-unconfirmed:x.zip"],
  });
  assert.equal(out.result.allAbsent, false);
});

test("an unknown read and a list that fails are incomplete reads, and a 401 stops it", async () => {
  const { result } = await go();
  const options = {
    baseline: result.inventory.before,
    uploadObjects: result.cleanup.uploadObjectsDeleted,
  };
  const url = `GET cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues`;
  const bad = createWorld({
    runId: RUN,
    hooks: { [url]: () => new Response("{}", { status: 500 }) },
  });
  const r = await run(bad, options);
  assert.equal(r.result.allAbsent, false);
  assert.ok(r.result.incompleteReads.length > 0);
  const stopped = createWorld({
    runId: RUN,
    hooks: { [url]: () => new Response("{}", { status: 401 }) },
  });
  const s = await run(stopped, options);
  assert.equal(s.result.allAbsent, false);
  assert.equal(s.result.authStop.status, 401);
});

test("the allowlist of a read-back refuses every mutation the recording's allowlist allows", async () => {
  const allow = readbackAllow(RUN, NUMBER, []);
  const q = `https://cloudtasks.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/queues/${functionOfRole(RUN, "tqdef")}`;
  assert.equal(allow({ method: "GET", url: q }), true);
  assert.equal(allow({ method: "DELETE", url: q }), false);
  assert.equal(allow({ method: "POST", url: q + "/tasks", json: {} }), false);
  assert.equal(
    allow({
      method: "POST",
      url: `https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:getIamPolicy`,
      json: {},
    }),
    true,
  );
  assert.equal(
    allow({
      method: "DELETE",
      url: `https://cloudfunctions.googleapis.com/v2/projects/${PROJECT}/locations/${REGION}/functions/${functionOfRole(RUN, "tqdef")}`,
    }),
    false,
  );
  assert.deepEqual(uploadObjectEntries([{ bucket: "b", name: "n" }, { bucket: 1 }, null]), [
    { bucket: "b", name: "n" },
  ]);
  assert.deepEqual(uploadObjectEntries("x"), []);
  assert.ok(
    readbackNames(RUN, []).some(
      ([label, url]) =>
        label === "queue-" + functionOfRole(RUN, "tqdef") &&
        url.endsWith(queueName(functionOfRole(RUN, "tqdef"))),
    ),
  );
  assert.ok(readbackNames(RUN, []).some(([label]) => label.startsWith("queue-tqnone")));
});
