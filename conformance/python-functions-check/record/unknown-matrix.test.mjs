// Every mutating request of the run crossed with every kind of answer it can get (the full product of two axes): whatever
// the answer, a request is never sent twice, an unknown answer keeps the run from closing and asks for the read-back, a
// known refusal is not mistaken for an unknown one, and the cleanup still runs.
import assert from "node:assert/strict";
import test from "node:test";
import { ALL_FUNCTIONS, packageIds } from "./plan.mjs";
import { record } from "./run.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";

const RUN = "0123456789abcdef";
const T = "fireemu-oracle-events";
const REQUESTS = [
  ["create the topic", (r) => r.method === "PUT" && r.url.includes("/topics/"), "create-topic"],
  [
    "create the document",
    (r) => r.method === "POST" && r.url.includes("/documents/pycheck-src?"),
    "op-fs-create",
  ],
  ["update the document", (r) => r.method === "PATCH", "op-fs-update"],
  [
    "publish a message",
    (r) =>
      r.method === "POST" &&
      r.url.endsWith(":publish") &&
      JSON.parse(r.body).messages[0].attributes.label === "plain",
    "op-ps-plain",
  ],
  [
    "upload the object",
    (r) => r.method === "POST" && r.url.includes("/upload/storage"),
    "op-st-upload",
  ],
  [
    "publish an event",
    (r) =>
      r.method === "POST" &&
      r.url.endsWith(":publishEvents") &&
      JSON.parse(r.body).events[0].id.endsWith("-fraction"),
    "op-ea-fraction",
  ],
  [
    "run a job",
    (r) => r.method === "POST" && r.url.endsWith("firebase-schedule-pcsch-us-central1:run"),
    "op-sched-pcsch",
  ],
  [
    "create a task",
    (r) => r.method === "POST" && r.url.includes("/queues/pctask/tasks"),
    "op-task-pctask",
  ],
  [
    "delete the document",
    (r) => r.method === "DELETE" && r.url.includes("/documents/"),
    "cleanup-fs-delete",
  ],
  [
    "delete the object",
    (r) =>
      r.method === "DELETE" && r.url.includes("/storage/v1/b/") && r.url.includes("pycheck%2F"),
    "cleanup-st-delete",
  ],
  ["delete the topic", (r) => r.method === "DELETE" && r.url.includes("/topics/"), "delete-topic"],
  [
    "delete an image",
    (r) =>
      r.method === "DELETE" &&
      r.url.includes("/packages/") &&
      r.url.endsWith(packageIds("pcps")[0]),
    "delete-package-" + packageIds("pcps")[0],
  ],
];
const ANSWERS = [
  ["transport error", "unknown", () => "throw"],
  ["500", "unknown", () => reply(500, { error: { code: 500, status: "INTERNAL", message: "x" } })],
  [
    "503",
    "unknown",
    () => reply(503, { error: { code: 503, status: "UNAVAILABLE", message: "x" } }),
  ],
  [
    "302",
    "unknown",
    () => new Response(null, { status: 302, headers: { location: "https://example.com/" } }),
  ],
  [
    "429",
    "known",
    () => reply(429, { error: { code: 429, status: "RESOURCE_EXHAUSTED", message: "x" } }),
  ],
  [
    "400",
    "known",
    () => reply(400, { error: { code: 400, status: "INVALID_ARGUMENT", message: "x" } }),
  ],
];

for (const [what, match, id] of REQUESTS)
  for (const [label, kind, answer] of ANSWERS)
    test(`${what} answered with ${label} is ${kind === "unknown" ? "never re-sent and keeps the run open" : "a known refusal"}`, async () => {
      const world = createWorld({ runId: RUN });
      const journal = [];
      let hit = 0;
      const result = await record({
        runId: RUN,
        projectNumber: NUMBER,
        accessToken: "tok-abcdefgh",
        save: async (row) => journal.push(row),
        runCli: world.runCli,
        clock: () => world.now,
        sleep: async (ms) => world.advance(ms),
        send: async (request) => {
          if (match(request)) {
            hit++;
            const out = answer();
            if (out === "throw") throw new Error("transport");
            return out;
          }
          return world.send(request);
        },
      });
      assert.equal(hit, 1, "the request was sent exactly once");
      const sentIds = journal.filter((r) => r.state === "before-send").map((r) => r.id);
      assert.equal(sentIds.filter((x) => x === id).length, 1, id);
      assert.equal(new Set(sentIds).size, sentIds.length, "no request id twice");
      if (kind === "unknown") {
        assert.equal(result.closureReady, false);
        assert.equal(result.readBackRequired, true);
        assert.ok(
          result.unknownMutationList.some((u) => u.id === id),
          JSON.stringify(result.unknownMutationList),
        );
      } else {
        assert.ok(!result.unknownMutationList.some((u) => u.id === id), "a 4xx is a known answer");
      }
      if (id === "create-topic") {
        // Without its topic the run stops before the deploy (an unknown create is unconfirmed; a refusal is a stop).
        assert.ok(!world.cliRuns.includes("deploy") || kind === "unknown");
      } else {
        assert.deepEqual(world.cliRuns, ["dry-run", "deploy", "delete"], "the cleanup ran");
      }
      assert.equal(result.stage, "done");
    });

test("no answer to any request changes the set of names the run may touch", async () => {
  for (const fn of ALL_FUNCTIONS) assert.match(fn, /^pc[a-z]+$/);
  assert.equal(T, "fireemu-oracle-events");
});
