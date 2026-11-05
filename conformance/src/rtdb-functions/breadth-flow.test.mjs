import test from "node:test";
import assert from "node:assert/strict";
import { runBreadth } from "./breadth-flow.mjs";
import { makeWorld } from "./breadth-flow.fake.mjs";

test("runs T1 writes and cleans owned resources in order", async () => {
  const world = makeWorld();
  const result = await runBreadth(world.deps);
  assert.equal(result.outcome, "stopped-needs-review");
  assert.ok(result.reasons.includes("no frames read"));
  assert.equal(world.events.filter((e) => e.startsWith("write ")).length, 12);
  assert.ok(world.events.indexOf("close sdk") < world.events.indexOf("cleanup user"));
  assert.deepEqual(
    world.events.filter((e) => e.startsWith("cleanup ")),
    [
      "cleanup g9WrittenV2Retry",
      "cleanup g9WrittenV1Retry",
      "cleanup g9WrittenV2",
      "cleanup user",
      "cleanup inventory",
      "cleanup rtdb",
    ],
  );
});

test("optional refusal continues but an unknown deploy stops", async () => {
  const optional = makeWorld({ failure: "g9WrittenV2", kind: "refused" });
  await runBreadth(optional.deps);
  assert.equal(optional.events.filter((e) => e.startsWith("write ")).length, 12);
  const unknown = makeWorld({ failure: "g9WrittenV2", kind: "unknown" });
  const result = await runBreadth(unknown.deps);
  assert.equal(unknown.events.filter((e) => e.startsWith("write ")).length, 0);
  assert.equal(result.residual, true);
});

test("preflight failure creates nothing", async () => {
  const world = makeWorld({ preflightFails: true });
  await runBreadth(world.deps);
  assert.deepEqual(world.events, ["preflight", "close sdk"]);
});

test("stops tail after all deployed handlers arrive and thirty seconds of quiet", async () => {
  const world = makeWorld({ allFrames: true });
  const result = await runBreadth(world.deps);
  assert.equal(result.logs.reads, 7);
  assert.equal(world.deps.clock.now(), 405000);
});

test("waits the full tail if retry success is missing", async () => {
  const world = makeWorld({ allFrames: true, missingRetrySuccess: true });
  const result = await runBreadth(world.deps);
  assert.equal(result.logs.reads, 14);
});

test("cleans resources when report evaluation fails", async () => {
  const world = makeWorld();
  Object.defineProperty(world.deps.auth, "uid", {
    get() {
      throw Error("report failure");
    },
  });
  const result = await runBreadth(world.deps);
  assert.ok(result.reasons.includes("report failure"));
  assert.ok(world.events.includes("cleanup rtdb"));
});

test("a refused required deployment stops observation", async () => {
  const world = makeWorld({ failure: "g9WrittenV2Retry", kind: "refused" });
  const result = await runBreadth(world.deps);
  assert.ok(result.reasons.includes("deploy failed"));
  assert.equal(world.events.filter((e) => e.startsWith("write ")).length, 0);
});

test("an incomplete log read remains incomplete after later successful reads", async () => {
  const world = makeWorld();
  let reads = 0;
  world.deps.logs.read = async () => ({
    frames: [],
    entries: 0,
    ignored: {},
    complete: ++reads > 1,
  });
  const result = await runBreadth(world.deps);
  assert.ok(reads > 1);
  assert.equal(result.logs.incomplete, true);
  assert.ok(result.reasons.includes("a Cloud Logging read was incomplete"));
});

test("total limit enters cleanup and cleanup exhaustion requires recovery", async () => {
  const { createBreadthBudget } = await import("./breadth-wiring.mjs");
  const world = makeWorld();
  const budget = createBreadthBudget();
  world.deps.budget = budget;
  world.deps.rtdb.setup = async () => {
    for (let i = 0; i < 130; i++) budget.take("rtdbAdmin");
    budget.take("control");
  };
  world.deps.rtdb.cleanup = async () => {
    for (let i = 0; i < 82; i++) budget.take("cleanup");
    budget.take("cleanup");
    return { closed: true };
  };
  const result = await runBreadth(world.deps);
  assert.equal(budget.snapshot().total, 212);
  assert.equal(result.residual, true);
  assert.ok(result.reasons.includes("request ceiling reached; recovery required"));
});

for (const failure of [
  "ownership",
  "cleanup phase",
  "target",
  "SDK",
  "user",
  "inventory",
  "upload report",
  "closed phase",
]) {
  test(`cleanup isolates ${failure} failure and preserves records`, async () => {
    const world = makeWorld();
    if (failure === "ownership")
      world.deps.ownedNames = () => {
        throw Error("bad ownership");
      };
    if (failure === "cleanup phase" || failure === "closed phase")
      world.deps.log = async (_action, phase) => {
        if (phase === (failure === "cleanup phase" ? "cleanup" : "closed"))
          throw Error("journal unavailable");
      };
    if (failure === "target")
      world.deps.ops.gcfv2.cleanup = async () => {
        throw Error("target unavailable");
      };
    if (failure === "SDK")
      world.deps.sdk.close = async () => {
        throw Error("SDK unavailable");
      };
    if (failure === "user")
      world.deps.auth.delete = async () => {
        throw Error("user unavailable");
      };
    if (failure === "inventory")
      world.deps.inventory.removeLeftovers = async () => {
        throw Error("inventory unavailable");
      };
    if (failure === "upload report")
      world.deps.uploads.report = () => {
        throw Error("uploads unavailable");
      };
    const result = await runBreadth(world.deps);
    assert.equal(Object.keys(result.records).length, 3);
    assert.ok(world.events.includes("cleanup rtdb"));
    if (failure !== "user") assert.equal(result.cleanup.user.gone, true);
    if (failure !== "inventory") assert.equal(result.cleanup.inventory.ok, true);
    if (["ownership", "target", "user", "inventory", "upload report"].includes(failure))
      assert.equal(result.residual, true);
  });
}

test("flow persists recovery identity and inventory before mutations and records before cleanup", async () => {
  const { mkdtemp, readFile, rm, stat } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "breadth-recovery-"));
  const world = makeWorld();
  Object.assign(world.deps, { runDir: dir, nonce: "test-nonce" });
  world.deps.rtdb.setup = async () => {
    assert.deepEqual(JSON.parse(await readFile(join(dir, "inventory-before.json"))), {
      complete: true,
    });
  };
  world.deps.auth.create = async () => {
    assert.deepEqual(JSON.parse(await readFile(join(dir, "run-identity.json"))), {
      nonce: "test-nonce",
      email: "breadth-test-nonce@example.com",
      uid: null,
    });
    return { outcome: "ok" };
  };
  world.deps.auth.signIn = async () => {
    assert.equal(JSON.parse(await readFile(join(dir, "run-identity.json"))).uid, "fake-uid");
    return { outcome: "ok" };
  };
  world.deps.ops.gcfv2.cleanup = async (spec, state) => {
    assert.deepEqual(JSON.parse(await readFile(join(dir, "records.json")))[spec.key], state.record);
    state.cleaned = true;
  };
  try {
    const result = await runBreadth(world.deps);
    assert.ok(!result.reasons.some((reason) => reason.includes("ENOENT")));
    assert.equal(result.nonce, "test-nonce");
    assert.equal(result.uid, "fake-uid");
    assert.equal(result.deployed, 3);
    for (const file of ["run-identity.json", "inventory-before.json", "records.json"])
      assert.equal((await stat(join(dir, file))).mode & 0o777, 0o600);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("optional refusal with complete production-shaped frames records successfully", async () => {
  const world = makeWorld({ failure: "g9WrittenV2", kind: "refused", allFrames: true });
  const read = world.deps.logs.read;
  world.deps.logs.read = async () => {
    const reply = await read();
    reply.frames = reply.frames.filter((frame) => frame.handler !== "g9WrittenV2");
    return reply;
  };
  assert.equal((await runBreadth(world.deps)).outcome, "recorded");
});

for (const signalPhase of ["deploy", "propagation-wait", "observe", "tail", "cleanup"]) {
  test(`signal in ${signalPhase} still deletes the real Auth user and restores RTDB`, async () => {
    const { createAuth } = await import("./breadth-auth.mjs");
    const world = makeWorld();
    const stop = {},
      calls = [];
    world.deps.auth = createAuth({
      projectId: "demo",
      apiKey: "test-key",
      email: "test@example.test",
      password: "test-password",
      stop,
      log: () => {},
      fetchImpl: async (url) => {
        calls.push(url);
        return {
          status: 200,
          text: async () =>
            JSON.stringify(
              url.endsWith("/accounts")
                ? { localId: "owned" }
                : url.includes("signInWithPassword")
                  ? { localId: "owned", idToken: "fake-id" }
                  : {},
            ),
        };
      },
    });
    world.deps.log = async (_action, phase) => {
      if (phase === signalPhase) {
        stop.requested = true;
        world.deps.abort.stopped = true;
      }
    };
    const result = await runBreadth(world.deps);
    assert.equal(result.cleanup.user.gone, true);
    assert.equal(result.cleanup.rtdb.closed, true);
    assert.equal(calls.filter((url) => url.endsWith("accounts:delete")).length, 1);
    assert.equal(calls.filter((url) => url.endsWith("accounts:lookup")).length, 1);
  });
}

test("a swallowed logging budget refusal stops observation and preserves cleanup allowance", async () => {
  const { createBreadthBudget } = await import("./breadth-wiring.mjs");
  const world = makeWorld();
  const budget = createBreadthBudget();
  world.deps.budget = budget;
  world.deps.rtdb.setup = async () => {
    for (let i = 0; i < 130; i++) budget.take("rtdbAdmin");
  };
  world.deps.logs.read = async () => {
    try {
      budget.take("logs");
    } catch {
      /* Log reader returns the pages already received. */
    }
    return { frames: [], complete: false };
  };
  world.deps.rtdb.cleanup = async () => {
    for (let i = 0; i < 82; i++) budget.take("cleanup");
    return { closed: true };
  };
  const result = await runBreadth(world.deps);
  assert.equal(world.events.filter((event) => event.startsWith("write ")).length, 3);
  assert.ok(result.reasons.includes("total request ceiling reached"));
  assert.equal(result.cleanup.rtdb.closed, true);
  assert.equal(budget.snapshot().total, 212);
  assert.equal(budget.cleanupExhausted, false);
});

for (const mode of ["validation", "cleanup discovery"]) {
  test(`early function records remain in final output after ${mode}`, async () => {
    const world = makeWorld(
      mode === "cleanup discovery" ? { failure: "g9WrittenV2Retry", kind: "unknown" } : {},
    );
    const records = {};
    world.deps.records = records;
    const first = world.deps.targets[0];
    const record = { name: first.functionName, eventTrigger: { trigger: "unreviewed" } };
    if (mode === "validation")
      world.deps.ops.gcfv2.read = async (spec) => {
        records[spec.key] = record;
        throw Error("shared validator rejected record");
      };
    else
      world.deps.ops.gcfv2.cleanup = async (spec, state) => {
        records[spec.key] = record;
        state.cleaned = true;
      };
    const result = await runBreadth(world.deps);
    assert.deepEqual(result.records[first.key], record);
    assert.equal(result.cleanup.user.gone, true);
    assert.equal(result.cleanup.rtdb.closed, true);
  });
}
