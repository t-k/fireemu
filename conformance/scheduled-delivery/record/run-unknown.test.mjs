// A generated test of the orchestrator: over any mix of answer classes for the mutations and the lists, each
// CLI action runs at most once, nothing is re-sent after an unknown answer, a DELETE goes only to a name this
// run issued, nothing is sent after a refused credential, and a close means the project is as it was.
import assert from "node:assert/strict";
import test from "node:test";
import { ALL_FUNCTIONS, FUNCTIONS, extraJobId, scheduleId } from "./plan.mjs";
import { NUMBER, createWorld, reply } from "./world.mjs";
import { record } from "./run.mjs";

const RUN = "0123456789abcdef";

function seeded(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const CLASSES = ["3xx", "5xx", "199", "transport", "unreadable", "4xx", "401"];
function perturbed(kind) {
  switch (kind) {
    case "3xx":
      return new Response(null, { status: 302 });
    case "5xx":
      return reply(503, { error: { code: 503, message: "later", status: "UNAVAILABLE" } });
    case "199":
      return {
        status: 199,
        headers: { get: () => null },
        arrayBuffer: async () => new ArrayBuffer(0),
      };
    case "unreadable":
      return {
        status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => {
          throw new Error("lost");
        },
      };
    case "4xx":
      return reply(400, { error: { code: 400, message: "bad", status: "INVALID_ARGUMENT" } });
    case "401":
      return reply(401, { error: { code: 401, message: "expired", status: "UNAUTHENTICATED" } });
    default:
      return "throw";
  }
}

test("generated: the run keeps its safety rules over any mix of answer classes", async () => {
  let closed = 0;
  let stopped = 0;
  let unknownRuns = 0;
  for (let seed = 1; seed <= 150; seed++) {
    const rnd = seeded(seed);
    const noise = [0, 0, 0.02, 0.05, 0.15][Math.floor(rnd() * 5)];
    const noise401 = noise > 0 && rnd() < 0.3;
    const sentByKey = new Map();
    let refusedAt = null;
    const hooks = new Proxy(
      {},
      {
        has: () => true,
        get:
          (_target, key) =>
          async ({ w, method }) => {
            sentByKey.set(key, (sentByKey.get(key) ?? 0) + 1);
            if (refusedAt !== null)
              throw new Error("a request was sent after the credential was refused: " + key);
            const isWrite =
              method !== "GET" &&
              !String(key).includes("entries:list") &&
              !String(key).includes("getIamPolicy");
            if (rnd() >= noise * (isWrite ? 1 : 0.3)) return undefined;
            const kind = CLASSES[Math.floor(rnd() * CLASSES.length)];
            if (kind === "401" && !noise401) return undefined;
            if (kind === "401") refusedAt = w.calls.length;
            // The write takes effect half of the time, whatever the answer says.
            if (isWrite && rnd() < 0.5) return undefined;
            return perturbed(kind);
          },
      },
    );
    const world = createWorld({ hooks });
    const journal = [];
    let error = null;
    let result;
    try {
      result = await record({
        runId: RUN,
        projectNumber: NUMBER,
        accessToken: "test-token",
        save: async (row) => journal.push(row),
        send: world.send,
        runCli: async (o) => world.runCli(o),
        clock: () => world.now,
        sleep: async (ms) => world.advance(ms),
        passes: 1,
        naturalWindowMs: 120_000,
      });
    } catch (caught) {
      error = caught;
    }
    const label = "seed " + seed;
    if (error) {
      // The only exceptions allowed are the guard's refusal of a request the recorder must never build.
      assert.fail(label + ": " + error.message);
    }
    for (const action of ["dry-run", "deploy", "delete"])
      assert.ok(
        world.cliRuns.filter((a) => a === action).length <= 1,
        label + ": " + action + " at most once",
      );
    // Nothing is sent twice that is a mutation (no resend after any answer).
    const mutations = world.calls.filter(
      (c) =>
        !c.startsWith("GET ") &&
        !c.includes("entries:list") &&
        !c.includes("getIamPolicy") &&
        !c.includes(":pull") &&
        !c.includes(":acknowledge"),
    );
    const busyRetries = mutations.filter((c) => c.startsWith("DELETE cloudscheduler"));
    const counts = new Map();
    for (const c of mutations.filter(
      (m) => !m.startsWith("DELETE cloudscheduler") && !m.endsWith("/locations/us-central1/jobs"),
    ))
      counts.set(c, (counts.get(c) ?? 0) + 1);
    assert.equal(
      new Set(world.creates).size,
      world.creates.length,
      label + ": a job name is created once",
    );
    for (const [call, n] of counts)
      assert.equal(n, 1, label + ": " + call + " sent " + n + " times");
    assert.ok(busyRetries.length <= 8 * 4, label);
    // Only issued names are deleted.
    const allowed = new Set([
      ...ALL_FUNCTIONS.map(scheduleId),
      ...["zero", "duration", "count", "retry5"].map((k) => extraJobId(RUN, k)),
      ...FUNCTIONS.v1.map((f) => "fe-sd-" + RUN + "-pull-" + f.toLowerCase()),
      ...ALL_FUNCTIONS,
    ]);
    for (const call of world.calls.filter((c) => c.startsWith("DELETE")))
      assert.ok(allowed.has(call.split("/").at(-1)), label + ": " + call);
    if (result.authStop) {
      stopped++;
      assert.equal(result.closureReady, false, label);
      assert.equal(result.readBackRequired, true, label);
      assert.equal(world.calls.length, refusedAt, label + ": nothing after the refused request");
    }
    const unknownInjected = result.unknownMutations > 0;
    if (unknownInjected) unknownRuns++;
    if (unknownInjected) {
      assert.equal(result.closureReady, false, label + ": an unknown answer is never closed");
      assert.equal(result.readBackRequired, true, label);
    }
    if (result.closureReady) {
      closed++;
      assert.equal(result.cleanup.verified, true, label);
      assert.equal(
        world.jobs.size +
          world.topics.size +
          world.subs.size +
          world.functionsV1.size +
          world.functionsV2.size +
          world.runServices.size,
        0,
        label + ": the project is as it was",
      );
      assert.equal(result.unknownMutations, 0, label);
      assert.deepEqual(result.incompleteReads, [], label);
    }
    assert.ok(result.attempted <= 420, label);
  }
  assert.ok(closed >= 20, "many runs close: " + closed);
  assert.ok(unknownRuns >= 20, "many runs carry an unknown answer: " + unknownRuns);
  assert.ok(stopped >= 3, "some runs are stopped by a refused credential: " + stopped);
});
