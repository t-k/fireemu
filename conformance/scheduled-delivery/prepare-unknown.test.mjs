// A generated test of the preparation collector: over any mix of answer classes, the mutation is
// sent at most once, an unknown answer is never closed, and a close means the sandbox is as asked.
import assert from "node:assert/strict";
import test from "node:test";
import { TARGET_SERVICES } from "./prepare.mjs";
import { BASE_ENABLED, NUMBER, fakeServer, reply, run } from "./prepare-fake.mjs";

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

const CLASSES = ["3xx", "5xx", "199", "transport", "unreadable", "4xx", "other-2xx"];

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
          throw new Error("body lost");
        },
      };
    case "4xx":
      return reply(400, { error: { code: 400, message: "bad", status: "INVALID_ARGUMENT" } });
    case "other-2xx":
      return reply(200, { unrelated: true });
    default:
      return "throw";
  }
}

test("generated: the mutation is sent at most once, unknown is never closed, a close is a clean result", async () => {
  let closed = 0;
  let unknownRuns = 0;
  for (let seed = 1; seed <= 400; seed++) {
    const rnd = seeded(seed);
    const noise = [0, 0, 0.05, 0.2, 0.5][Math.floor(rnd() * 5)];
    const some = rnd() < 0.3 ? TARGET_SERVICES.slice(0, 1 + Math.floor(rnd() * 5)) : [];
    const all = rnd() < 0.1 ? [...TARGET_SERVICES] : some;
    const hooks = {};
    let injectedOnEnable = false;
    let dispatchedEnable = 0;
    const wrap = (name, onEnable) => {
      hooks[name] = async ({ state, body }) => {
        if (onEnable) dispatchedEnable++;
        if (rnd() >= noise) return undefined;
        const kind = CLASSES[Math.floor(rnd() * CLASSES.length)];
        if (onEnable) {
          injectedOnEnable = ["3xx", "5xx", "199", "transport", "unreadable"].includes(kind);
          if (rnd() < 0.5) for (const id of body.serviceIds) state.enabled.add(id);
        }
        return perturbed(kind);
      };
    };
    wrap("POST v1/projects/<number>/services:batchEnable", true);
    const server = fakeServer({
      enabled: [...BASE_ENABLED, ...all],
      hooks,
      pendingPolls: Math.floor(rnd() * 3),
    });
    // Read perturbations through the generic hook keys the fake honours by prefix.
    for (const read of [
      "GET v1/projects/<number>/services",
      "POST v1/projects/fireemu-oracle-sbx:getIamPolicy",
      "GET v1beta1/projects/fireemu-oracle-sbx/adminSdkConfig",
      "POST v2/entries:list",
      "GET v1/operations/acf.p2-<number>-e627f9a7-0f50-48e6-856c-93ad311e8f0e",
    ])
      hooks[read] = async () =>
        rnd() < noise / 2 ? perturbed(CLASSES[Math.floor(rnd() * CLASSES.length)]) : undefined;
    const { result } = await run(server);
    const label = "seed " + seed;
    const enables = server.state.calls.filter((c) => c.endsWith(":batchEnable")).length;
    assert.ok(enables <= 1, label + ": the mutation is sent at most once");
    assert.equal(dispatchedEnable, enables, label);
    if (result.requested.length === 0)
      assert.equal(enables, 0, label + ": nothing asked for, nothing sent");
    if (injectedOnEnable) {
      unknownRuns++;
      assert.ok(result.unknownMutations >= 1, label);
      assert.equal(result.closureReady, false, label + ": an unknown answer is never closed");
      assert.equal(result.readBackRequired, true, label);
    }
    if (result.closureReady) {
      closed++;
      assert.equal(result.unknownMutations, 0, label);
      assert.deepEqual(result.missingAfter, [], label);
      assert.ok(
        result.batchEnable === null || result.batchEnable.done === true,
        label + ": an enable closes only when its operation is done",
      );
      assert.deepEqual(result.incompleteReads, [], label);
      assert.deepEqual(result.iam.unexpected, [], label);
      assert.ok(!result.authStop, label);
      for (const id of TARGET_SERVICES) assert.ok(server.state.enabled.has(id), label + " " + id);
    }
    assert.ok(result.attempted <= 60, label);
  }
  assert.ok(closed > 50, "many generated runs close: " + closed);
  assert.ok(unknownRuns > 20, "many generated runs carry an unknown mutation: " + unknownRuns);
  assert.equal(typeof NUMBER, "string");
});
