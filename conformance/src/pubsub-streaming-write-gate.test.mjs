import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { getEventListeners } from "node:events";
import { existsSync } from "node:fs";
import { mock, test } from "node:test";
import { promisify } from "node:util";

const target = new URL("../pubsub-corpus/streaming-write-gate.mjs", import.meta.url);
async function gate(extra = {}) {
  assert.ok(existsSync(target), "guarded streaming write admission is missing");
  const { createStreamingWriteGate } = await import(target.href);
  const events = [],
    issued = [];
  const instance = createStreamingWriteGate({
    maxFrames: 3,
    maxFrameBytes: 64,
    maxOutgoingBytes: 128,
    maxActions: 6,
    wallMs: 1000,
    guard: async (action) => events.push(`guard:${action.index}`),
    liveCheck: () => true,
    persist: async (row) => events.push(`${row.state}:${row.index}`),
    issue: (action, bytes) => {
      events.push(`issue:${action.index}`);
      issued.push([action.kind, bytes]);
    },
    contain: async () => events.push("contain"),
    ...extra,
  });
  return { g: instance, events, issued };
}
// A test-local real timer that loses the race to any module cutoff working as intended. If a cutoff
// never fires, the test fails this assertion instead of hanging until the per-test timeout.
const FALLBACK_MS = 3000;
async function settleOrFallback(work) {
  let fallback;
  const late = new Promise((resolve) => {
    fallback = setTimeout(resolve, FALLBACK_MS, { state: "still pending" });
  });
  try {
    return await Promise.race([
      work.then(
        (value) => ({ state: "fulfilled", value }),
        (error) => ({ state: "rejected", error }),
      ),
      late,
    ]);
  } finally {
    clearTimeout(fallback);
  }
}
test("a guard that never settles just short of the deadline is cut off by the gate and reported by done before a fallback timer", async () => {
  let now = 5000;
  const clock = mock.method(performance, "now", () => now);
  try {
    const origins = [];
    const { g, issued } = await gate({
      wallMs: 60000,
      guard: () => new Promise(() => {}),
      contain: async ({ origin }) => origins.push(origin),
    });
    now = 64999;
    const opened = await settleOrFallback(g.open());
    assert.equal(opened.state, "rejected", "open() must be settled by the gate's own cutoff");
    assert.match(opened.error.message, /streaming admission stopped/);
    assert.deepEqual(origins, ["deadline"]);
    const reported = await settleOrFallback(g.done());
    assert.equal(reported.state, "fulfilled", "done() must be settled by its own deadline wait");
    assert.equal(reported.value.stopOrigin, "deadline");
    assert.deepEqual(reported.value.pendingCallbacks, ["0:guard-before"]);
    assert.equal(reported.value.unknownActions, 1);
    assert.equal(reported.value.terminationRequired, true);
    assert.equal(issued.length, 0);
  } finally {
    clock.mock.restore();
  }
});
test("an abandoned gate never holds the process open", async () => {
  // The child opens a gate, completes one action and exits without stop() or done(); only an
  // unreferenced deadline timer lets it exit before the cutoff.
  const script = `const [target] = process.argv.slice(1);
    const { createStreamingWriteGate } = await import(target);
    let contained = 0, issued = 0;
    const g = createStreamingWriteGate({
      maxFrames: 1, maxFrameBytes: 8, maxOutgoingBytes: 64, maxActions: 2, wallMs: 60000,
      guard: () => {}, liveCheck: () => true, persist: () => {},
      issue: () => { issued++; }, contain: () => { contained++; },
    });
    await g.open();
    process.stdout.write(JSON.stringify({ issued, contained }));`;
  let outcome;
  try {
    const { stdout } = await promisify(execFile)(
      process.execPath,
      ["--input-type=module", "--eval", script, target.href],
      { timeout: 8000, killSignal: "SIGKILL" },
    );
    outcome = JSON.parse(stdout);
  } catch (error) {
    outcome = error.killed ? "the abandoned gate kept the process alive" : `${error.stderr}`;
  }
  assert.deepEqual(outcome, { issued: 1, contained: 0 });
});
test("opening frames half-close and explicit cancel have durable intents and finite distinct reservations", async () => {
  const { g, events, issued } = await gate();
  await g.open();
  await g.write(Buffer.from([10, 1, 65]));
  await g.halfClose();
  assert.throws(() => g.write(Buffer.alloc(0)), /direction/);
  await g.cancel();
  assert.deepEqual(
    issued.map(([kind]) => kind),
    ["open", "frame", "half-close", "client-cancel"],
  );
  assert.deepEqual(issued[1][1], Buffer.from([0, 0, 0, 0, 3, 10, 1, 65]));
  for (let i = 0; i < 4; i++) {
    assert.ok(events.indexOf(`before-send:${i}`) < events.indexOf(`issue:${i}`));
    assert.ok(events.indexOf(`issue:${i}`) < events.indexOf(`issued:${i}`));
  }
  const result = await g.done();
  assert.equal(result.attemptedActions, 4);
  assert.equal(result.completedActions, 4);
  assert.equal(result.unknownActions, 0);
  assert.equal(result.openingReservations, 1);
  assert.equal(result.frameReservations, 1);
  assert.equal(result.outgoingBytes, 8);
  assert.equal(result.stopOrigin, "client-cancel");
  assert.equal(result.terminationRequired, false);
  assert.equal(result.peerStatus, undefined);
});
test("a stalled WAL freezes input and rejects concurrent admission before buffers or slots accumulate", async () => {
  let release;
  const wait = new Promise((resolve) => {
    release = resolve;
  });
  let stall = false;
  const { g, issued } = await gate({
    persist: async (row) => {
      if (stall && row.state === "before-send") await wait;
    },
  });
  await g.open();
  stall = true;
  const payload = Buffer.from("original");
  const pending = g.write(payload);
  payload.fill(255);
  for (let i = 0; i < 20; i++) assert.throws(() => g.write(Buffer.alloc(64)), /concurrent/);
  release();
  await pending;
  assert.equal(issued[1][1].subarray(5).toString(), "original");
  g.stop("peer-terminal");
  const result = await g.done();
  assert.equal(result.attemptedActions, 2);
  assert.equal(result.frameReservations, 1);
});
test("revocation after WAL and synchronous stop inside the final live check prevent issue", async () => {
  for (const mode of ["revoked", "stop", "async-live"]) {
    let g;
    const setup = await gate({
      liveCheck: () => {
        if (mode === "stop") g.stop("revocation");
        return mode === "async-live" ? Promise.resolve(true) : mode !== "revoked";
      },
    });
    g = setup.g;
    await assert.rejects(g.open(), /stopped/);
    assert.equal(setup.issued.length, 0);
    const result = await g.done();
    assert.equal(result.unknownActions, 1);
    assert.equal(result.attemptedActions, 1);
  }
});
test("lost intent acknowledgement consumes its slot and cannot be retried", async () => {
  const { g, issued } = await gate({
    persist: async () => {
      throw new Error("synthetic secret-bearing storage failure");
    },
  });
  await assert.rejects(g.open(), /stopped/);
  assert.equal(issued.length, 0);
  assert.throws(() => g.open(), /stopped/);
  const result = await g.done();
  assert.equal(result.unknownActions, 1);
  assert.equal(JSON.stringify(result).includes("secret-bearing"), false);
});
test("each finite reservation cap is enforced before another action can reach authority or WAL", async () => {
  for (const bounds of [{ maxFrames: 1 }, { maxOutgoingBytes: 5 }, { maxActions: 2 }]) {
    const { g, issued } = await gate(bounds);
    await g.open();
    await g.write(Buffer.alloc(0));
    assert.throws(() => g.write(Buffer.alloc(0)), /bound/);
    assert.equal(issued.length, 2);
    g.stop("peer-terminal");
    assert.equal((await g.done()).attemptedActions, 2);
  }
  const { g } = await gate({ maxFrameBytes: 1 });
  await g.open();
  assert.throws(() => g.write(Buffer.alloc(2)), /bound/);
  g.stop("peer-terminal");
  await g.done();
});
test(
  "a callback surviving the hard deadline is accounted for and requires supervised termination",
  { timeout: 500 },
  async () => {
    let release;
    const hung = new Promise((resolve) => {
      release = resolve;
    });
    const { g, issued } = await gate({ wallMs: 30, persist: () => hung });
    await assert.rejects(g.open(), /stopped/);
    const result = await g.done();
    assert.equal(issued.length, 0);
    assert.equal(result.stopOrigin, "deadline");
    assert.equal(result.terminationRequired, true);
    assert.ok(result.pendingCallbacks.length > 0);
    release();
  },
);
test("failed or never-settling emergency containment cannot become clean completion", async () => {
  for (const kind of ["reject", "hang"]) {
    let release;
    const hung = new Promise((resolve) => {
      release = resolve;
    });
    const { g } = await gate({
      wallMs: 30,
      contain: () => (kind === "hang" ? hung : Promise.reject(new Error("secret"))),
    });
    g.stop("abort");
    const result = await g.done();
    assert.equal(result.terminationRequired, true);
    assert.equal(result.stopOrigin, "abort");
    release();
  }
});
test("local issue uncertainty and repeated opening never authorize a subsequent action", async () => {
  const { g } = await gate({
    issue: () => {
      throw new Error("unknown send");
    },
  });
  await assert.rejects(g.open(), /stopped/);
  assert.throws(() => g.open(), /stopped/);
  assert.equal((await g.done()).unknownActions, 1);
  const normal = await gate();
  await normal.g.open();
  assert.throws(() => normal.g.open(), /opening/);
  normal.g.stop("peer-terminal");
  await normal.g.done();
});
test("a supposedly synchronous issue or final check returning a promise always requires termination", async () => {
  for (const kind of ["issue", "liveCheck"]) {
    let release;
    const hung = new Promise((resolve) => {
      release = resolve;
    });
    const { g } = await gate({ wallMs: 30, [kind]: () => hung });
    await assert.rejects(g.open(), /stopped/);
    const result = await g.done();
    assert.equal(result.terminationRequired, true);
    assert.ok(result.pendingCallbacks.length > 0);
    release();
  }
});
test("a reflected credential cannot enter outbound durable payload receipts or consume frame admission", async () => {
  const credential = "SYNTHETIC-SECRET";
  const { g, issued } = await gate({ credential });
  await g.open();
  assert.throws(() => g.write(Buffer.from(credential)), /credential/);
  assert.equal(issued.length, 1);
  g.stop("uncertain");
  const result = await g.done();
  assert.equal(result.frameReservations, 0);
  assert.equal(JSON.stringify(result).includes(credential), false);
});
test("all125short action traces follow one opening and a terminal write direction without hidden attempts", async () => {
  const actions = ["open", "write", "halfClose", "cancel", "stop"];
  for (const first of actions)
    for (const second of actions)
      for (const third of actions) {
        const { g, issued } = await gate();
        let opened = false,
          half = false,
          stopped = false,
          attempted = 0,
          frames = 0;
        for (const name of [first, second, third]) {
          const allowed =
            !stopped &&
            (name === "stop" || name === "open"
              ? name === "stop" || !opened
              : opened && (name === "cancel" || !half));
          if (name === "stop") {
            g.stop("peer-terminal");
            stopped = true;
            continue;
          }
          const invoke = () => (name === "write" ? g.write(Buffer.alloc(0)) : g[name]());
          if (!allowed) {
            assert.throws(invoke);
            continue;
          }
          await invoke();
          attempted++;
          if (name === "open") opened = true;
          if (name === "write") frames++;
          if (name === "halfClose") half = true;
          if (name === "cancel") stopped = true;
        }
        g.stop("peer-terminal");
        const result = await g.done();
        assert.equal(result.attemptedActions, attempted);
        assert.equal(result.completedActions, attempted);
        assert.equal(result.frameReservations, frames);
        assert.equal(issued.length, attempted);
        assert.equal(result.terminationRequired, false);
      }
});
test("operator abort during awaited authority stops before WAL and preserves its local origin", async () => {
  const controller = new AbortController();
  const { g, events, issued } = await gate({
    signal: controller.signal,
    guard: async () => controller.abort(),
  });
  await assert.rejects(g.open(), /stopped/);
  assert.equal(issued.length, 0);
  assert.equal(
    events.some((row) => row.startsWith("before-send")),
    false,
  );
  assert.equal((await g.done()).stopOrigin, "abort");
});
test("lost issued receipt retains the known local issue and its uncertain acknowledgement", async () => {
  const { g, issued } = await gate({
    persist: async (row) => {
      if (row.state === "issued") throw new Error("lost ack");
    },
  });
  await assert.rejects(g.open(), /stopped/);
  assert.equal(issued.length, 1);
  const result = await g.done();
  assert.equal(result.issuedActions, 1);
  assert.equal(result.completedActions, 0);
  assert.equal(result.unknownActions, 1);
  assert.equal(result.stopOrigin, "uncertain");
});
test("awaited authority is checked again after the durable WAL before the synchronous check", async () => {
  let checks = 0;
  const { g, issued } = await gate({
    guard: async () => {
      if (++checks === 2) throw new Error("revoked");
    },
  });
  await assert.rejects(g.open(), /stopped/);
  assert.equal(checks, 2);
  assert.equal(issued.length, 0);
  assert.equal((await g.done()).unknownActions, 1);
});
test("durable frame descriptors are immutable and bind the exact issued envelope hash and length", async () => {
  const rows = [];
  const { g, issued } = await gate({
    persist: async (row) => {
      assert.equal(Reflect.set(row, "kind", "forged"), false);
      rows.push(row);
    },
  });
  await g.open();
  await g.write(Buffer.from([255, 0, 128]));
  const wire = issued[1][1];
  for (const row of rows.filter((r) => r.kind === "frame")) {
    assert.equal(row.frameBase64, wire.toString("base64"));
    assert.equal(row.frameBytes, wire.length);
    assert.equal(row.frameSha256, createHash("sha256").update(wire).digest("hex"));
  }
  g.stop("peer-terminal");
  await g.done();
});
test("invalid configuration and oversized native wire/timer ranges never allocate a gate", async () => {
  for (const key of ["maxFrames", "maxFrameBytes", "maxOutgoingBytes", "maxActions", "wallMs"])
    for (const value of [0, -1, Infinity, 1.1, Number.MAX_SAFE_INTEGER + 1])
      await assert.rejects(gate({ [key]: value }), /finite/);
  await assert.rejects(gate({ wallMs: 2147483648 }), /finite/);
  await assert.rejects(gate({ maxFrameBytes: 4294967296 }), /finite/);
  for (const key of ["guard", "liveCheck", "persist", "issue", "contain"])
    await assert.rejects(gate({ [key]: null }), /callbacks/);
});
test("an already-settled promise still violates either synchronous source contract", async () => {
  for (const kind of ["liveCheck", "issue"]) {
    const { g } = await gate({ [kind]: () => Promise.resolve(true) });
    await assert.rejects(g.open(), /stopped/);
    const result = await g.done();
    assert.equal(result.pendingCallbacks.length, 0);
    assert.equal(result.terminationRequired, true);
    assert.equal(result.stopOrigin, "uncertain");
  }
});
test("owned containment begins inline while authority is pending and remains single", async () => {
  let release,
    stopped = 0;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const { g, issued } = await gate({
    guard: () => held,
    contain: ({ origin }) => {
      assert.equal(origin, "abort");
      stopped++;
    },
  });
  const work = g.open();
  try {
    g.stop("abort");
    assert.equal(stopped, 1);
    g.stop("deadline");
    assert.equal(stopped, 1);
  } finally {
    release();
    await assert.rejects(work, /stopped/);
    await g.done();
  }
  assert.equal(issued.length, 0);
});
test(
  "an absolute shared monotonic deadline is retained and bounds hung authority",
  { timeout: 500 },
  async () => {
    const exact = performance.now() + 200;
    const { g } = await gate({ deadlineAt: exact });
    assert.equal((await g.done()).deadlineAt, exact);
    let release;
    const hung = new Promise((resolve) => {
      release = resolve;
    });
    const { g: bounded, issued } = await gate({
      deadlineAt: performance.now() + 30,
      guard: () => hung,
    });
    try {
      await assert.rejects(bounded.open(), /stopped/);
      assert.equal(issued.length, 0);
      assert.equal((await bounded.done()).terminationRequired, true);
    } finally {
      release();
    }
  },
);
test("expired malformed or extended absolute deadlines are refused before callbacks", async () => {
  for (const deadlineAt of [
    NaN,
    Infinity,
    -Infinity,
    -1,
    performance.now() - 1,
    performance.now() + 10000,
  ])
    await assert.rejects(gate({ deadlineAt }), /deadline/);
});
test(
  "idle containment timer uses the absolute deadline without waiting for an action",
  { timeout: 500 },
  async () => {
    let stops = 0;
    const { g } = await gate({
      deadlineAt: performance.now() + 30,
      contain: ({ origin }) => {
        assert.equal(origin, "deadline");
        stops++;
      },
    });
    try {
      await new Promise((resolve) => setTimeout(resolve, 60));
      assert.equal(stops, 1);
    } finally {
      await g.done();
    }
  },
);
test("late containment acknowledgment cannot beat an overdue absolute deadline timer", async () => {
  const deadlineAt = performance.now() + 30;
  const { g } = await gate({
    deadlineAt,
    contain: () =>
      Promise.resolve().then(() => {
        while (performance.now() < deadlineAt + 5) {
          /* Deliberately hold timer dispatch. */
        }
      }),
  });
  assert.equal((await g.done()).terminationRequired, true);
});
test("overridden outgoing byte-view properties cannot reenter finite frame admission", async () => {
  const { g, issued } = await gate({ maxFrames: 1 });
  await g.open();
  let getters = 0;
  const input = new Uint8Array([9]);
  Object.defineProperty(input, "length", {
    get() {
      getters++;
      g.write(Buffer.alloc(0)).catch(() => {});
      return 1;
    },
  });
  try {
    await g.write(input);
    assert.equal(getters, 0);
    assert.equal(issued.length, 2);
    assert.deepEqual(issued[1][1], Buffer.from([0, 0, 0, 0, 1, 9]));
  } finally {
    await g.done();
  }
});
test("timer and wire bounds are accepted at their exact native limits and refused one past them", async () => {
  const atLimit = await gate({ wallMs: 2147483647, maxFrameBytes: 4294967295 });
  // Released with stop(): if done() ever leaked its cutoff timer, a full-range timer would hold the
  // test process open instead of failing the timer-release test below.
  assert.equal(atLimit.g.stop("local-close"), undefined);
  await assert.rejects(gate({ wallMs: 2147483648 }), /timer\/wire/);
  await assert.rejects(gate({ maxFrameBytes: 4294967296 }), /timer\/wire/);
});
test("credential screening settings are validated and bounded before admission", async () => {
  for (const credential of ["", 5, null, Buffer.from("x"), "x".repeat(16385), "é".repeat(8193)])
    await assert.rejects(gate({ credential }), /bounded credential/);
  const longest = await gate({ credential: "y".repeat(16384) });
  await longest.g.open();
  await longest.g.write(Buffer.from("payload"));
  assert.equal(longest.issued.length, 2);
  await longest.g.done();
});
test("an absolute deadline equal to now is refused and one exactly wallMs ahead is accepted", async () => {
  const clock = mock.method(performance, "now", () => 5000);
  try {
    await assert.rejects(gate({ deadlineAt: 5000 }), /deadline/);
    await assert.rejects(gate({ deadlineAt: 6000.5 }), /deadline/);
    const edge = await gate({ deadlineAt: 6000 });
    assert.equal(edge.g.stop("local-close"), undefined);
  } finally {
    clock.mock.restore();
  }
});
test("listed stop labels are kept verbatim and unlisted or empty labels are recorded as uncertain", async () => {
  const listed = [
    "peer-terminal",
    "client-cancel",
    "revocation",
    "abort",
    "deadline",
    "local-close",
  ];
  for (const label of [...listed, "uncertain", "", "peer-ok", undefined]) {
    const origins = [];
    const { g } = await gate({ contain: async ({ origin }) => origins.push(origin) });
    g.stop(label);
    const expected = listed.includes(label) ? label : "uncertain";
    const result = await g.done();
    assert.equal(result.stopOrigin, expected, `label ${JSON.stringify(label)}`);
    assert.deepEqual(origins, [expected]);
  }
});
test("done without an earlier stop contains the gate as a local close", async () => {
  const origins = [];
  const { g } = await gate({ contain: async ({ origin }) => origins.push(origin) });
  const result = await g.done();
  assert.equal(result.stopOrigin, "local-close");
  assert.deepEqual(origins, ["local-close"]);
  assert.equal(result.terminationRequired, false);
});
test("an already-aborted caller signal stops admission before the first action", async () => {
  const controller = new AbortController();
  controller.abort();
  const origins = [];
  const { g, events, issued } = await gate({
    signal: controller.signal,
    contain: async ({ origin }) => origins.push(origin),
  });
  assert.deepEqual(origins, ["abort"]);
  assert.throws(() => g.open(), /stopped/);
  const result = await g.done();
  assert.equal(result.stopOrigin, "abort");
  assert.equal(result.attemptedActions, 0);
  assert.equal(issued.length, 0);
  assert.equal(events.length, 0);
});
test("every awaited callback and containment share one signal that aborts when the gate stops", async () => {
  const seen = [];
  const { g } = await gate({
    guard: async (intent, options) => seen.push(["guard", options?.signal]),
    persist: async (row, options) => seen.push([row.state, options?.signal]),
    contain: async ({ signal }) => seen.push(["contain", signal]),
  });
  await g.open();
  assert.deepEqual(
    seen.map(([name]) => name),
    ["guard", "before-send", "guard", "issued"],
  );
  for (const [name, signal] of seen) {
    assert.ok(signal instanceof AbortSignal, name);
    assert.equal(signal.aborted, false, name);
  }
  g.stop("peer-terminal");
  assert.equal(seen.length, 5);
  for (const [name, signal] of seen) {
    assert.equal(signal, seen[0][1], name);
    assert.equal(signal.aborted, true, name);
  }
  await g.done();
});
test("persisted receipts carry the frozen intent with exactly one before-send and one issued state", async () => {
  const rows = [];
  const { g, issued } = await gate({ persist: async (row) => rows.push(row) });
  await g.open();
  await g.write(Buffer.from([7, 8]));
  const wire = issued[1][1];
  const frame = {
    index: 1,
    kind: "frame",
    frameBase64: wire.toString("base64"),
    frameBytes: 7,
    frameSha256: createHash("sha256").update(wire).digest("hex"),
  };
  assert.deepEqual(rows, [
    { index: 0, kind: "open", state: "before-send" },
    { index: 0, kind: "open", state: "issued" },
    { ...frame, state: "before-send" },
    { ...frame, state: "issued" },
  ]);
  assert.ok(rows.every((row) => Object.isFrozen(row)));
  await g.done();
});
test("only a Uint8Array view is admitted as frame bytes; other inputs are refused without a reservation", async () => {
  const { g, issued } = await gate();
  await g.open();
  for (const input of [
    undefined,
    "text",
    [1, 2],
    new ArrayBuffer(2),
    new DataView(new ArrayBuffer(2)),
    new Uint16Array([1]),
    new Int8Array([1]),
    new Float32Array([1]),
  ])
    assert.throws(() => g.write(input), /raw frame bytes required/);
  await g.write(new Uint8Array([1]));
  const result = await g.done();
  assert.equal(result.attemptedActions, 2);
  assert.equal(result.frameReservations, 1);
  assert.equal(issued.length, 2);
});
test("synchronously throwing or rejecting callbacks settle as refusals without leaving pending work", async () => {
  // A frozen clock keeps the clean outcome independent of scheduling delays; the short wallMs still
  // bounds every real cutoff timer.
  const clock = mock.method(performance, "now", () => 5000);
  try {
    for (const guard of [
      () => {
        throw new Error("sync refusal");
      },
      async () => {
        throw new Error("async refusal");
      },
    ]) {
      const { g, issued } = await gate({ wallMs: 50, guard });
      await assert.rejects(g.open(), /stopped/);
      const result = await g.done();
      assert.equal(issued.length, 0);
      assert.equal(result.stopOrigin, "uncertain");
      assert.deepEqual(result.pendingCallbacks, []);
      assert.equal(result.terminationRequired, false);
    }
    const { g } = await gate({
      wallMs: 50,
      contain: () => {
        throw new Error("sync containment failure");
      },
    });
    assert.doesNotThrow(() => g.stop("abort"));
    const result = await g.done();
    assert.deepEqual(result.pendingCallbacks, []);
    assert.equal(result.terminationRequired, true);
    assert.equal(result.stopOrigin, "abort");
  } finally {
    clock.mock.restore();
  }
});
test("never-settling containment is reported by its own pending callback name", async () => {
  let release;
  const hung = new Promise((resolve) => {
    release = resolve;
  });
  const { g } = await gate({ wallMs: 30, contain: () => hung });
  try {
    g.stop("peer-terminal");
    const result = await g.done();
    assert.deepEqual(result.pendingCallbacks, ["containment"]);
    assert.equal(result.terminationRequired, true);
  } finally {
    release();
  }
});
test("a stop during the post-WAL authority check prevents the final live check and issue", async () => {
  let g,
    guards = 0,
    liveChecks = 0;
  const setup = await gate({
    guard: async () => {
      if (++guards === 2) g.stop("revocation");
    },
    liveCheck: () => {
      liveChecks++;
      return true;
    },
  });
  g = setup.g;
  await assert.rejects(g.open(), /stopped/);
  assert.equal(guards, 2);
  assert.equal(liveChecks, 0);
  assert.equal(setup.issued.length, 0);
  assert.equal((await g.done()).stopOrigin, "revocation");
});
test("a false final live check is recorded as a revocation stop", async () => {
  const { g, issued } = await gate({ liveCheck: () => false });
  await assert.rejects(g.open(), /stopped/);
  assert.equal(issued.length, 0);
  assert.equal((await g.done()).stopOrigin, "revocation");
});
test("a Promise-returning issue is not counted as a known local issue and opens no direction", async () => {
  const { g, issued } = await gate({
    issue: (action, bytes) => {
      issued.push([action.kind, bytes]);
      return Promise.resolve();
    },
  });
  await assert.rejects(g.open(), /stopped/);
  assert.equal(issued.length, 1);
  const result = await g.done();
  assert.equal(result.issuedActions, 0);
  assert.equal(result.completedActions, 0);
  assert.equal(result.direction, "NEW");
  assert.equal(result.stopOrigin, "uncertain");
  assert.equal(result.terminationRequired, true);
});
test("the reported write direction follows opening and half-close and is not reopened by cancel", async () => {
  for (const [steps, direction] of [
    [[], "NEW"],
    [["open"], "OPEN"],
    [["open", "cancel"], "OPEN"],
    [["open", "halfClose"], "HALF_CLOSED"],
    [["open", "halfClose", "cancel"], "HALF_CLOSED"],
  ]) {
    const { g } = await gate();
    for (const step of steps) await g[step]();
    assert.equal((await g.done()).direction, direction, steps.join(","));
  }
});
test("a clock reading exactly at the deadline stops admission before any callback", async () => {
  let now = 5000;
  const clock = mock.method(performance, "now", () => now);
  try {
    const origins = [];
    const { g, events } = await gate({ contain: async ({ origin }) => origins.push(origin) });
    now = 6000;
    assert.throws(() => g.open(), /stopped/);
    assert.deepEqual(origins, ["deadline"]);
    const result = await g.done();
    assert.equal(result.stopOrigin, "deadline");
    assert.equal(result.attemptedActions, 0);
    assert.deepEqual(events, []);
  } finally {
    clock.mock.restore();
  }
});
test("reaching the deadline exactly by the time done reports requires termination", async () => {
  let now = 5000;
  const clock = mock.method(performance, "now", () => now);
  try {
    const { g } = await gate({ wallMs: 100 });
    g.stop("peer-terminal");
    await new Promise((resolve) => setImmediate(resolve));
    now = 5100;
    const result = await g.done();
    assert.deepEqual(result.pendingCallbacks, []);
    assert.equal(result.terminationRequired, true);
  } finally {
    clock.mock.restore();
  }
});
test("a callback still pending when done reports requires termination even before the clock reaches the deadline", async () => {
  const clock = mock.method(performance, "now", () => 5000);
  let release;
  const hung = new Promise((resolve) => {
    release = resolve;
  });
  try {
    const { g } = await gate({ wallMs: 20, guard: () => hung });
    const work = g.open();
    g.stop("peer-terminal");
    await assert.rejects(work, /stopped/);
    const result = await g.done();
    assert.equal(result.stopOrigin, "peer-terminal");
    assert.deepEqual(result.pendingCallbacks, ["0:guard-before"]);
    assert.equal(result.terminationRequired, true);
  } finally {
    release();
    clock.mock.restore();
  }
});
test("an awaited callback outliving its share of the deadline stops the gate with a deadline origin", async () => {
  let now = 5000;
  const clock = mock.method(performance, "now", () => now);
  let release;
  const hung = new Promise((resolve) => {
    release = resolve;
  });
  try {
    const { g } = await gate({ guard: () => hung });
    now = 5980;
    await assert.rejects(g.open(), /stopped/);
    const result = await g.done();
    assert.equal(result.stopOrigin, "deadline");
    assert.deepEqual(result.pendingCallbacks, ["0:guard-before"]);
    assert.equal(result.terminationRequired, true);
  } finally {
    release();
    clock.mock.restore();
  }
});
test("no callback starts after a clock reading at or past the deadline", async () => {
  let now = 1000;
  const clock = mock.method(performance, "now", () => ++now);
  try {
    for (let wallMs = 1; wallMs <= 30; wallMs++) {
      const starts = [];
      const at = (name, value) => () => {
        starts.push([name, now]);
        return value;
      };
      const { g } = await gate({
        wallMs,
        guard: at("guard"),
        persist: at("persist"),
        liveCheck: at("liveCheck", true),
        issue: at("issue"),
      });
      try {
        await g.open();
      } catch {
        /* Refusal is expected once the deadline is reached. */
      }
      const { deadlineAt } = await g.done();
      for (const [name, reading] of starts)
        assert.ok(
          reading < deadlineAt,
          `${name} started at ${reading} with deadline ${deadlineAt}`,
        );
    }
  } finally {
    clock.mock.restore();
  }
});
test("an idle or finished gate holds no referenced timer and releases the caller's abort listener", async () => {
  const timeouts = () =>
    process.getActiveResourcesInfo().filter((resource) => resource === "Timeout").length;
  const controller = new AbortController();
  const baseline = timeouts();
  const { g } = await gate({ signal: controller.signal });
  assert.equal(timeouts(), baseline);
  await g.open();
  await g.write(Buffer.from([1]));
  assert.equal(timeouts(), baseline);
  await g.done();
  assert.equal(timeouts(), baseline);
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});
test("a synchronous throw from issue may follow sent bytes, so it requires termination", async () => {
  for (const kind of ["open", "frame", "half-close", "client-cancel"]) {
    let throwOn;
    const { g } = await gate({
      issue: (intent) => {
        if (intent.kind === throwOn) throw new Error("native write failed after a partial send");
      },
    });
    if (kind !== "open") await g.open();
    throwOn = kind;
    const action = {
      open: () => g.open(),
      frame: () => g.write(Buffer.from("x")),
      "half-close": () => g.halfClose(),
      "client-cancel": () => g.cancel(),
    }[kind];
    await assert.rejects(action(), /stopped/);
    const result = await g.done();
    assert.equal(result.stopOrigin, "uncertain", kind);
    assert.equal(result.unknownActions, 1, kind);
    assert.deepEqual(result.pendingCallbacks, [], kind);
    assert.equal(result.terminationRequired, true, kind);
  }
  // A failure before issue is reached (here the final live check) sent nothing and stays clean.
  const revoked = await gate({ liveCheck: () => false });
  await assert.rejects(revoked.g.open(), /stopped/);
  const result = await revoked.g.done();
  assert.equal(result.stopOrigin, "revocation");
  assert.equal(result.terminationRequired, false);
});
test("once issue is entered, any later unknown outcome requires termination, even after clean containment", async () => {
  for (const kind of ["open", "frame", "half-close", "client-cancel"]) {
    // The issue callback hands bytes to the transport and returns normally; only the acknowledgement
    // of the issued row is lost.
    let loseIssuedOf;
    const { g, issued } = await gate({
      persist: async (row) => {
        if (row.state === "issued" && row.kind === loseIssuedOf)
          throw new Error("issued acknowledgement lost");
      },
    });
    if (kind !== "open") await g.open();
    loseIssuedOf = kind;
    const action = {
      open: () => g.open(),
      frame: () => g.write(Buffer.from("x")),
      "half-close": () => g.halfClose(),
      "client-cancel": () => g.cancel(),
    }[kind];
    await assert.rejects(action(), /stopped/);
    const result = await g.done();
    assert.equal(issued.at(-1)[0], kind, kind);
    assert.equal(result.issuedActions, kind === "open" ? 1 : 2, kind);
    assert.equal(result.unknownActions, 1, kind);
    assert.equal(result.stopOrigin, "uncertain", kind);
    assert.deepEqual(result.pendingCallbacks, [], kind);
    assert.equal(result.terminationRequired, true, kind);
  }
  // The send-before-throw form: bytes were handed over, then the callback threw.
  const { g, issued } = await gate({
    issue: (intent, bytes) => {
      issued.push([intent.kind, bytes]);
      throw new Error("bookkeeping failed after the native write");
    },
  });
  await assert.rejects(g.open(), /stopped/);
  const result = await g.done();
  assert.equal(issued.length, 1);
  assert.equal(result.issuedActions, 0);
  assert.equal(result.unknownActions, 1);
  assert.equal(result.terminationRequired, true);
});
