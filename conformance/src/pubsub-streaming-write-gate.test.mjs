import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { test } from "node:test";

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
