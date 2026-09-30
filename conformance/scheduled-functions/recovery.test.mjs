import assert from "node:assert/strict";
import { test } from "node:test";
import { collectRecovery } from "./recovery.mjs";
import { ownedResources } from "./shape.mjs";

const originalRunId = "a1".repeat(8);
const runId = "b1".repeat(8);
const owned = ownedResources(originalRunId);
const absent = { error: { code: 404, status: "NOT_FOUND", message: "Job not found." } };
const paused = {
  name: owned.job,
  state: "PAUSED",
  pubsubTarget: { topicName: owned.topic, data: "c2hhcGUtb25seQ==" },
  schedule: "0 0 1 4 *",
  timeZone: "UTC",
  status: { code: -1 },
};
const conflict = {
  error: {
    code: 409,
    status: "ABORTED",
    message: "sync mutate calls cannot be queued",
    details: [{ "@type": "type.googleapis.com/google.rpc.ResourceInfo", resourceName: owned.job }],
  },
};

export function environment({
  initial = [200, paused],
  deletes = [[200, {}]],
  final = [404, absent],
  list = [200, {}],
} = {}) {
  let now = Date.parse("2026-09-30T11:10:00Z");
  const sends = [],
    rows = [],
    waits = [];
  const started = now;
  return {
    sends,
    rows,
    waits,
    started,
    deps: {
      originalRunId,
      runId,
      accessToken: "offline-recovery-bearer",
      clock: () => now,
      sleep: async (ms) => {
        waits.push(ms);
        now += ms;
      },
      save: async (row) => rows.push(row),
      send: async (request) => {
        sends.push({ ...request, sentAt: now });
        let response;
        if (request.id === "read-job-before") response = initial;
        else if (request.id === "read-job-after") response = final;
        else if (request.id === "list-jobs") response = list;
        else if (request.id.startsWith("delete-job-")) {
          const index = Number(request.id.slice("delete-job-".length)) - 1;
          response = deletes[Math.min(index, deletes.length - 1)];
        } else throw new Error("unexpected route");
        if (response === "unknown") throw new Error("offline-recovery-bearer timeout");
        return new Response(JSON.stringify(response[1]), { status: response[0] });
      },
    },
  };
}

test("recovery scopes all routes and waits before a captured unjudged DELETE ACK", async () => {
  const f = environment({ deletes: [[202, { unjudged: "accepted" }]] });
  const result = await collectRecovery(f.deps);
  assert.equal(result.attempted, 4);
  assert.equal(result.closureReady, true);
  assert.equal(result.cleanupVerified, false);
  assert.deepEqual(f.waits, [60000]);
  const deletion = f.sends.find(({ method }) => method === "DELETE");
  assert.ok(deletion.sentAt - f.started >= 60000);
  assert.equal(deletion.url, "https://cloudscheduler.googleapis.com/v1/" + owned.job);
  assert.ok(
    f.sends.every(({ url }) =>
      url.startsWith(
        "https://cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs",
      ),
    ),
  );
  assert.equal(
    f.sends.at(-1).url,
    "https://cloudscheduler.googleapis.com/v1/projects/fireemu-oracle-sbx/locations/us-central1/jobs?pageSize=500",
  );
  assert.ok(!JSON.stringify(f.rows).includes("offline-recovery-bearer"));
});

test("only the recorded conflict permits three additional spaced DELETE attempts", async () => {
  const f = environment({
    deletes: [
      [409, conflict],
      [409, conflict],
      [409, conflict],
      [200, {}],
    ],
  });
  const result = await collectRecovery(f.deps);
  assert.equal(result.attempted, 7);
  assert.equal(result.closureReady, true);
  assert.deepEqual(f.waits, [60000, 60000, 60000, 60000]);
  const deletes = f.sends.filter(({ method }) => method === "DELETE");
  assert.equal(deletes.length, 4);
  for (let i = 1; i < deletes.length; i++)
    assert.ok(deletes[i].sentAt - deletes[i - 1].sentAt >= 60000);
});

test("exhausted conflicts still record read-only postflight and cannot close recovery", async () => {
  const f = environment({ deletes: [[409, conflict]] });
  const result = await collectRecovery(f.deps);
  assert.equal(result.attempted, 7);
  assert.equal(result.closureReady, false);
  assert.equal(f.sends.filter(({ method }) => method === "DELETE").length, 4);
  assert.deepEqual(
    f.sends.slice(-2).map(({ id }) => id),
    ["read-job-after", "list-jobs"],
  );
});

test("already absent still needs the recorded exact GET and complete final list", async () => {
  const f = environment({ initial: [404, absent] });
  const result = await collectRecovery(f.deps);
  assert.equal(result.attempted, 3);
  assert.equal(result.closureReady, true);
  assert.deepEqual(f.waits, []);
  assert.ok(!f.sends.some(({ method }) => method === "DELETE"));
});

for (const [field, body] of [
  ["name", { ...paused, name: owned.job + "-foreign" }],
  ["state", { ...paused, state: "ENABLED" }],
  ["topic", { ...paused, pubsubTarget: { topicName: owned.topic + "-foreign" } }],
]) {
  test("a mismatched initial " + field + " blocks all deletion", async () => {
    const f = environment({ initial: [200, body] });
    const result = await collectRecovery(f.deps);
    assert.equal(result.attempted, 1);
    assert.equal(result.closureReady, false);
    assert.ok(!f.sends.some(({ method }) => method === "DELETE"));
  });
}

for (const [name, answer] of [
  ["unknown", "unknown"],
  ["server error", [500, { error: { code: 500 } }]],
  ["different conflict", [409, { error: { ...conflict.error, message: "other conflict" } }]],
  [
    "foreign resource",
    [
      409,
      {
        error: {
          ...conflict.error,
          details: [
            {
              "@type": "type.googleapis.com/google.rpc.ResourceInfo",
              resourceName: owned.job + "-foreign",
            },
          ],
        },
      },
    ],
  ],
]) {
  test(name + " DELETE stops writes but still records the read-only end state", async () => {
    const f = environment({ deletes: [answer] });
    const result = await collectRecovery(f.deps);
    assert.equal(result.attempted, 4);
    assert.equal(result.closureReady, false);
    assert.equal(f.sends.filter(({ method }) => method === "DELETE").length, 1);
    assert.deepEqual(
      f.sends.slice(-2).map(({ id }) => id),
      ["read-job-after", "list-jobs"],
    );
  });
}

for (const list of [
  { jobs: [paused] },
  { nextPageToken: "more" },
  { jobs: "invalid" },
  { jobs: [{}] },
  null,
]) {
  test(
    "an incomplete, malformed or residual list cannot close recovery: " + JSON.stringify(list),
    async () => {
      const f = environment({ list: [200, list] });
      const result = await collectRecovery(f.deps);
      assert.equal(result.closureReady, false);
    },
  );
}

test("a post-delete paused job is retained recovery debt", async () => {
  const f = environment({ final: [200, paused], list: [200, { jobs: [paused] }] });
  const result = await collectRecovery(f.deps);
  assert.equal(result.closureReady, false);
});
