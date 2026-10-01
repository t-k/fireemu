import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { mock, test } from "node:test";
import { promisify } from "node:util";

const target = new URL("../pubsub-corpus/streaming-receipts.mjs", import.meta.url);
const frame = (bytes) => {
  const head = Buffer.alloc(5);
  head.writeUInt32BE(bytes.length, 1);
  return Buffer.concat([head, bytes]);
};
const tick = () => new Promise((resolve) => setImmediate(resolve));
async function queue(extra = {}) {
  assert.ok(existsSync(target), "bounded durable streaming receipt queue is missing");
  const { createStreamingReceiptQueue } = await import(target.href);
  const saved = [],
    frames = [],
    order = [];
  const q = createStreamingReceiptQueue({
    maxFrameBytes: 64,
    maxTotalBytes: 512,
    maxFrames: 8,
    maxChunks: 16,
    maxHeaderBytes: 256,
    maxHeaderEvents: 4,
    maxHeaderPairs: 16,
    maxEvents: 24,
    wallMs: 1000,
    persist: async (row) => {
      saved.push(row);
      order.push(`persist:${row.index}`);
    },
    onFrame: async (row) => {
      frames.push(row);
      order.push(`frame:${row.index}`);
    },
    stopOwned: async () => order.push("stop"),
    ...extra,
  });
  return { q, saved, frames, order };
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
test("a persist that never settles just short of the deadline is bounded by the drain's own waits before a fallback timer", async () => {
  let now = 5000;
  const clock = mock.method(performance, "now", () => now);
  try {
    const { q, order } = await queue({ wallMs: 60000, persist: () => new Promise(() => {}) });
    now = 64999;
    assert.equal(q.data(frame(Buffer.from("m"))), true);
    const reported = await settleOrFallback(q.done());
    assert.equal(reported.state, "fulfilled", "done() must be settled by its own deadline waits");
    assert.deepEqual(reported.value.pendingCallbacks, ["receipt:0"]);
    assert.equal(reported.value.events, 1);
    assert.equal(reported.value.persistedEvents, 0);
    assert.equal(reported.value.unknownEvents, 1);
    assert.equal(reported.value.frameAttempts, 0);
    assert.equal(Object.hasOwn(reported.value, "reason"), false);
    assert.equal(reported.value.terminationRequired, true);
    assert.deepEqual(order, ["stop"]);
  } finally {
    clock.mock.restore();
  }
});
test("split frame candidates become visible only after every contributing raw chunk is durable", async () => {
  let release;
  const stall = new Promise((resolve) => {
    release = resolve;
  });
  const saved = [],
    visible = [];
  const { q } = await queue({
    persist: async (row) => {
      if (row.index === 1) await stall;
      saved.push(row);
    },
    onFrame: async (row) => visible.push(row),
  });
  const wire = frame(Buffer.from("payload"));
  q.data(wire.subarray(0, 3));
  q.data(wire.subarray(3));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(saved.length, 1);
  assert.equal(visible.length, 0);
  release();
  const result = await q.done();
  assert.equal(saved.length, 2);
  assert.equal(visible.length, 1);
  assert.equal(Buffer.from(visible[0].bodyBase64, "base64").toString(), "payload");
  assert.equal(result.terminationRequired, false);
  assert.equal(result.persistedEvents, 2);
  assert.equal(result.unknownEvents, 0);
  assert.equal(result.frameAttempts, 1);
  assert.equal(result.acknowledgedFrames, 1);
  assert.equal(result.framing.outcome, "complete-framing");
});
test("metadata pairs flags and lifecycle sequence remain raw ordered immutable receipts", async () => {
  const { q, saved } = await queue();
  const raw = [
    ":status",
    "200",
    "content-type",
    "application/grpc",
    "duplicate",
    "first",
    "duplicate",
    "second",
  ];
  q.headers("response", raw, 1);
  raw.fill("caller edit");
  q.lifecycle("end");
  const result = await q.done();
  assert.deepEqual(saved[0].rawHeaders, [
    ":status",
    "200",
    "content-type",
    "application/grpc",
    "duplicate",
    "first",
    "duplicate",
    "second",
  ]);
  assert.equal(saved[0].flags, 1);
  assert.equal(saved[1].kind, "end");
  assert.equal(result.events, 2);
  assert.equal(result.peerStatus, undefined);
});
test("stalled persistence cannot admit an unbounded flood of empty or oversized input", async () => {
  let release;
  const stall = new Promise((resolve) => {
    release = resolve;
  });
  let stopped = 0;
  const { q } = await queue({
    maxEvents: 2,
    persist: () => stall,
    stopOwned: () => {
      stopped++;
    },
  });
  q.data(Buffer.alloc(0));
  q.data(Buffer.alloc(0));
  assert.equal(q.data(Buffer.alloc(0)), false);
  for (let i = 0; i < 100; i++) assert.equal(q.data(Buffer.alloc(1024)), false);
  assert.equal(stopped, 1);
  release();
  const result = await q.done();
  assert.equal(result.events, 2);
  assert.equal(result.reason, "event-bound");
});
test("independent data metadata chunk and event caps halt with bounded evidence and explicit truncation", async () => {
  for (const [bounds, accept, reason] of [
    [{ maxTotalBytes: 3 }, (q) => q.data(frame(Buffer.alloc(0))), "total-bound"],
    [
      { maxChunks: 1 },
      (q) => {
        q.data(Buffer.alloc(0));
        q.data(Buffer.alloc(0));
      },
      "chunk-count",
    ],
    [{ maxHeaderBytes: 1 }, (q) => q.headers("response", [":status", "200"], 0), "header-bound"],
    [
      { maxHeaderEvents: 1 },
      (q) => {
        q.headers("response", [], 0);
        q.headers("trailers", [], 0);
      },
      "header-event-bound",
    ],
    [
      { maxHeaderPairs: 1 },
      (q) => q.headers("response", ["a", "b", "c", "d"], 0),
      "header-pair-bound",
    ],
  ]) {
    const { q, saved } = await queue(bounds);
    accept(q);
    const result = await q.done();
    assert.equal(result.reason, reason);
    assert.equal(result.peerStatus, undefined);
    if (reason === "total-bound") {
      assert.equal(saved[0].raw.truncated, true);
      assert.equal(saved[0].raw.bodyBytes, 3);
    }
  }
});
test("failed raw persistence never publishes candidate frames or admits further events", async () => {
  const { q, frames } = await queue({
    persist: async () => {
      throw new Error("secret-bearing store error");
    },
  });
  q.data(frame(Buffer.from("message")));
  const result = await q.done();
  assert.equal(frames.length, 0);
  assert.equal(result.reason, "persistence");
  assert.equal(result.persistedEvents, 0);
  assert.equal(result.unknownEvents, 1);
  assert.equal(q.data(Buffer.alloc(0)), false);
  assert.equal(JSON.stringify(result).includes("secret-bearing"), false);
});
test("credential reflection in split data and raw or binary metadata never reaches storage", async () => {
  const credential = "SYNTHETIC-SECRET";
  const wire = frame(Buffer.from(credential));
  for (const mode of ["split", "raw", "binary"]) {
    const { q, saved, frames } = await queue({ credential });
    if (mode === "split") {
      q.data(wire.subarray(0, 10));
      q.data(wire.subarray(10));
    } else
      q.headers(
        "trailers",
        [
          mode === "binary" ? "details-bin" : "details",
          mode === "binary" ? Buffer.from(credential).toString("base64") : credential,
        ],
        0,
      );
    const result = await q.done();
    assert.equal(result.reason, "credential-reflection");
    assert.equal(frames.length, 0);
    for (const row of saved) {
      if (row.raw)
        assert.equal(
          Buffer.from(row.raw.bodyBase64, "base64").includes(Buffer.from(credential)),
          false,
        );
      assert.equal(JSON.stringify(row).includes(credential), false);
    }
  }
});
test(
  "never-settling persistence or frame callbacks require parent termination within the shared wall budget",
  { timeout: 500 },
  async () => {
    for (const phase of ["persist", "onFrame"]) {
      let release;
      const hung = new Promise((resolve) => {
        release = resolve;
      });
      const { q } = await queue({ wallMs: 30, [phase]: () => hung });
      q.data(frame(Buffer.alloc(0)));
      const result = await q.done();
      assert.equal(result.terminationRequired, true);
      assert.ok(result.pendingCallbacks.length > 0);
      release();
    }
  },
);
test("truncated framing and teardown uncertainty cannot become complete durable capture", async () => {
  const { q } = await queue({
    stopOwned: async () => {
      throw new Error("cleanup");
    },
  });
  q.data(Buffer.from([0, 0]));
  const result = await q.done();
  assert.equal(result.framing.outcome, "inconclusive-framing");
  assert.equal(result.reason, "truncated-frame");
  assert.equal(result.terminationRequired, true);
});
test("all81bounded event traces charge empty data metadata and lifecycle events before queuing", async () => {
  const names = ["data", "headers", "lifecycle"];
  for (const a of names)
    for (const b of names)
      for (const c of names)
        for (const d of names) {
          const { q, saved } = await queue({ maxEvents: 3, maxHeaderEvents: 1, maxChunks: 2 });
          let count = 0,
            headers = 0,
            chunks = 0,
            stopped = false;
          for (const name of [a, b, c, d]) {
            const allowed =
              !stopped &&
              count < 3 &&
              (name !== "headers" || headers < 1) &&
              (name !== "data" || chunks < 2);
            const accepted =
              name === "data"
                ? q.data(Buffer.alloc(0))
                : name === "headers"
                  ? q.headers("response", [], 0)
                  : q.lifecycle("end");
            assert.equal(accepted, allowed);
            if (!allowed) {
              stopped = true;
              continue;
            }
            count++;
            if (name === "headers") headers++;
            if (name === "data") chunks++;
          }
          const result = await q.done();
          assert.equal(result.events, count);
          assert.equal(saved.length, count);
          assert.equal(result.terminationRequired, false);
          assert.equal(result.peerStatus, undefined);
        }
});
test("observer failure and operator abort halt without granting usable later frames", async () => {
  for (const mode of ["observer", "abort"]) {
    const controller = new AbortController();
    let visible = 0;
    const { q } = await queue({
      signal: controller.signal,
      onFrame: async () => {
        visible++;
        if (mode === "abort") controller.abort();
        else throw new Error("secret");
      },
    });
    q.data(Buffer.concat([frame(Buffer.alloc(0)), frame(Buffer.alloc(0))]));
    const result = await q.done();
    assert.equal(visible, 1);
    assert.equal(result.reason, mode);
    assert.equal(result.frameAttempts, 1);
    assert.equal(result.acknowledgedFrames, mode === "observer" ? 0 : 1);
    assert.equal(q.lifecycle("end"), false);
  }
});
test("metadata bytes are cumulative and malformed or unbounded receipt inputs are refused", async () => {
  const { q, saved } = await queue({ maxHeaderBytes: 5 });
  assert.equal(q.headers("response", ["ab", "cd"], 0), true);
  assert.equal(q.headers("trailers", ["ef", "gh"], 0), false);
  const result = await q.done();
  assert.equal(result.reason, "header-bound");
  assert.equal(saved.length, 1);
  assert.equal(result.headerBytes, 4);
  for (const key of ["maxHeaderBytes", "maxHeaderEvents", "maxHeaderPairs", "maxEvents", "wallMs"])
    for (const value of [0, -1, Infinity, 1.1, Number.MAX_SAFE_INTEGER + 1])
      await assert.rejects(queue({ [key]: value }), /finite/);
  await assert.rejects(queue({ wallMs: 2147483648 }), /finite timer/);
  for (const [kind, raw, flags] of [
    ["unknown", [], 0],
    ["response", ["odd"], 0],
    ["response", [], 256],
    ["response", [1, 2], 0],
  ]) {
    const { q: invalidQueue } = await queue();
    assert.equal(invalidQueue.headers(kind, raw, flags), false);
    assert.equal((await invalidQueue.done()).reason, "invalid-headers");
  }
});
test(
  "the same absolute monotonic deadline bounds receipt draining instead of restarting its window",
  { timeout: 500 },
  async () => {
    const exact = performance.now() + 200;
    const { q } = await queue({ deadlineAt: exact });
    assert.equal((await q.done()).deadlineAt, exact);
    let release;
    const hung = new Promise((resolve) => {
      release = resolve;
    });
    const { q: bounded } = await queue({ deadlineAt: performance.now() + 30, persist: () => hung });
    bounded.data(frame(Buffer.alloc(0)));
    try {
      const result = await bounded.done();
      assert.equal(result.terminationRequired, true);
      assert.ok(result.pendingCallbacks.length > 0);
    } finally {
      release();
    }
  },
);
test("invalid or extended receipt deadlines are refused without starting owned callbacks", async () => {
  for (const deadlineAt of [
    NaN,
    Infinity,
    -Infinity,
    -1,
    performance.now() - 1,
    performance.now() + 10000,
  ])
    await assert.rejects(queue({ deadlineAt }), /deadline/);
});
test(
  "idle receipt stop uses the shared deadline and supplies its bounded reason",
  { timeout: 500 },
  async () => {
    let stops = 0;
    const { q } = await queue({
      deadlineAt: performance.now() + 30,
      stopOwned: ({ reason }) => {
        assert.equal(reason, "deadline");
        stops++;
      },
    });
    try {
      await new Promise((resolve) => setTimeout(resolve, 60));
      assert.equal(stops, 1);
    } finally {
      await q.done();
    }
  },
);
test("late receipt stop acknowledgment cannot beat an overdue absolute deadline timer", async () => {
  const deadlineAt = performance.now() + 30;
  const { q } = await queue({
    deadlineAt,
    stopOwned: () =>
      Promise.resolve().then(() => {
        while (performance.now() < deadlineAt + 5) {
          /* Deliberately hold timer dispatch. */
        }
      }),
  });
  assert.equal((await q.done()).terminationRequired, true);
});
test("construction accepts the largest native timer bound and refuses missing callbacks or a zero-width deadline", async () => {
  // Fake timers keep a maximal deadline from holding the process if a cutoff is ever left behind.
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const { q } = await queue({ wallMs: 2147483647 });
    assert.equal((await q.done()).terminationRequired, false);
  } finally {
    mock.timers.reset();
  }
  for (const key of ["persist", "onFrame", "stopOwned"])
    await assert.rejects(queue({ [key]: undefined }), /owned receipt callbacks required/);
  const now = performance.now();
  const clock = mock.method(performance, "now", () => now);
  try {
    await assert.rejects(queue({ deadlineAt: now }), /live bounded monotonic deadline/);
  } finally {
    clock.mock.restore();
  }
});
test("throwing or rejecting owned callbacks settle as refusals instead of escaping or staying pending", async () => {
  const fail = () => {
    throw new Error("synthetic callback failure");
  };
  // A frozen clock keeps the clean outcomes independent of scheduling delays; the short wallMs still
  // bounds every real drain timer.
  const clock = mock.method(performance, "now", () => 5000);
  try {
    for (const failing of [fail, async () => fail()]) {
      const { q: stored, frames } = await queue({ wallMs: 100, persist: failing });
      stored.data(frame(Buffer.from("m")));
      const persisted = await stored.done();
      assert.equal(persisted.reason, "persistence");
      assert.equal(frames.length, 0);
      assert.deepEqual(persisted.pendingCallbacks, []);
      assert.equal(persisted.terminationRequired, false);
      const { q: observed } = await queue({ wallMs: 100, onFrame: failing });
      observed.data(frame(Buffer.from("m")));
      const delivered = await observed.done();
      assert.equal(delivered.reason, "observer");
      assert.equal(delivered.frameAttempts, 1);
      assert.equal(delivered.acknowledgedFrames, 0);
      assert.deepEqual(delivered.pendingCallbacks, []);
      assert.equal(delivered.terminationRequired, false);
      const { q: owned } = await queue({ wallMs: 100, stopOwned: failing });
      assert.equal(owned.lifecycle("unknown"), false);
      const stopped = await owned.done();
      assert.equal(stopped.reason, "invalid-lifecycle");
      assert.deepEqual(stopped.pendingCallbacks, []);
      assert.equal(stopped.terminationRequired, true);
    }
  } finally {
    clock.mock.restore();
  }
});
test("receipt and frame callbacks share the owned stop signal, which the first stop aborts and names", async () => {
  const callbackSignals = [];
  let stopSignal, stopReason, abortedAtStop;
  const { q } = await queue({
    persist: async (_row, { signal }) => {
      callbackSignals.push(signal);
    },
    onFrame: async (_row, { signal }) => {
      callbackSignals.push(signal);
    },
    stopOwned: ({ signal, reason }) => {
      stopSignal = signal;
      stopReason = reason;
      abortedAtStop = signal.aborted;
    },
  });
  q.data(frame(Buffer.from("m")));
  await tick();
  assert.equal(callbackSignals.length, 2);
  for (const signal of callbackSignals) {
    assert.ok(signal instanceof AbortSignal);
    assert.equal(signal.aborted, false);
  }
  q.data(Buffer.from([0, 0]));
  assert.equal(q.lifecycle("unknown"), false);
  assert.equal(stopReason, "invalid-lifecycle");
  assert.equal(abortedAtStop, true);
  for (const signal of callbackSignals) assert.equal(signal, stopSignal);
  const result = await q.done();
  assert.equal(result.framing.reason, "truncated-frame");
  assert.equal(result.reason, "invalid-lifecycle");
});
test("an operator signal that is already aborted stops the queue before any receipt is admitted", async () => {
  const reasons = [];
  const { q, saved } = await queue({
    signal: AbortSignal.abort(),
    stopOwned: async ({ reason }) => reasons.push(reason),
  });
  assert.deepEqual(reasons, ["abort"]);
  assert.equal(q.data(frame(Buffer.alloc(0))), false);
  assert.equal(q.lifecycle("end"), false);
  const result = await q.done();
  assert.equal(result.reason, "abort");
  assert.equal(result.events, 0);
  assert.equal(saved.length, 0);
});
test("non-byte data input stops the queue as invalid data without storing a receipt", async () => {
  const { q, saved } = await queue();
  assert.equal(q.data("not bytes"), false);
  assert.equal(q.lifecycle("end"), false);
  const result = await q.done();
  assert.equal(result.reason, "invalid-data");
  assert.equal(result.events, 0);
  assert.equal(saved.length, 0);
});
test("at the exact absolute deadline admission, queued persistence and frame delivery all stop", async () => {
  const start = performance.now();
  let now = start;
  const clock = mock.method(performance, "now", () => now);
  try {
    let release;
    const gate = new Promise((resolve) => {
      release = resolve;
    });
    const persisted = [],
      visible = [],
      reasons = [];
    const { q } = await queue({
      wallMs: 1000,
      persist: async (row) => {
        persisted.push(row.index);
        if (row.index === 0) await gate;
      },
      onFrame: async (row) => visible.push(row.index),
      stopOwned: async ({ reason }) => reasons.push(reason),
    });
    assert.equal(q.data(frame(Buffer.from("m"))), true);
    assert.equal(q.lifecycle("end"), true);
    await tick();
    assert.deepEqual(persisted, [0]);
    now = start + 1000;
    release();
    await tick();
    assert.deepEqual(persisted, [0]);
    assert.deepEqual(visible, []);
    assert.deepEqual(reasons, ["deadline"]);
    const result = await q.done();
    assert.equal(result.reason, "deadline");
    assert.equal(result.persistedEvents, 1);
    assert.equal(result.unknownEvents, 1);
    assert.equal(result.frameAttempts, 0);
    assert.equal(result.terminationRequired, true);

    now = start;
    const admitted = [];
    const { q: late, saved } = await queue({
      wallMs: 1000,
      stopOwned: async ({ reason }) => admitted.push(reason),
    });
    now = start + 1000;
    assert.equal(late.lifecycle("end"), false);
    assert.deepEqual(admitted, ["deadline"]);
    const lateResult = await late.done();
    assert.equal(lateResult.reason, "deadline");
    assert.equal(lateResult.events, 0);
    assert.equal(saved.length, 0);
  } finally {
    clock.mock.restore();
  }
});
test("a drain that completes exactly at the deadline requires termination even after an earlier stop acknowledgment", async () => {
  const start = performance.now();
  let now = start;
  const clock = mock.method(performance, "now", () => now);
  try {
    for (const [offset, terminationRequired] of [
      [999, false],
      [1000, true],
    ]) {
      now = start;
      const { q } = await queue({ wallMs: 1000 });
      assert.equal(q.lifecycle("unknown"), false);
      await tick();
      now = start + offset;
      const result = await q.done();
      assert.equal(result.reason, "invalid-lifecycle");
      assert.deepEqual(result.pendingCallbacks, []);
      assert.equal(result.terminationRequired, terminationRequired);
    }
  } finally {
    clock.mock.restore();
  }
});
test("a clean close drains admitted receipts before requesting owned stop, then refuses every later input", async () => {
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const order = [];
  const { q } = await queue({
    persist: async (row) => {
      order.push(`persist:${row.index}`);
      await gate;
    },
    stopOwned: async ({ signal, reason }) => order.push(`stop:${signal.aborted}:${reason}`),
  });
  q.data(frame(Buffer.from("m")));
  const closing = q.done();
  await tick();
  assert.deepEqual(order, ["persist:0"]);
  release();
  const result = await closing;
  assert.deepEqual(order, ["persist:0", "stop:false:undefined"]);
  assert.equal(Object.hasOwn(result, "reason"), false);
  assert.equal(result.acknowledgedFrames, 1);
  assert.equal(result.terminationRequired, false);
  assert.equal(q.lifecycle("end"), false);
  assert.equal(q.headers("trailers", [], 0), false);
  assert.equal(q.data(Buffer.alloc(0)), false);
});
test("a finished queue detaches its deadline timer and operator signal from callback signals", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const operator = new AbortController();
    let callbackSignal;
    const { q } = await queue({
      signal: operator.signal,
      persist: async (_row, { signal }) => {
        callbackSignal = signal;
      },
    });
    q.lifecycle("end");
    assert.equal((await q.done()).terminationRequired, false);
    operator.abort();
    mock.timers.tick(2000);
    assert.equal(callbackSignal.aborted, false);
  } finally {
    mock.timers.reset();
  }
});
test("receipt timers never keep the process alive beyond a finished drain", async () => {
  const { createStreamingReceiptQueue } = await import(target.href);
  const live = () => process.getActiveResourcesInfo().filter((name) => name === "Timeout").length;
  const before = live();
  const q = createStreamingReceiptQueue({
    maxFrameBytes: 64,
    maxTotalBytes: 512,
    maxFrames: 8,
    maxChunks: 16,
    maxHeaderBytes: 256,
    maxHeaderEvents: 4,
    maxHeaderPairs: 16,
    maxEvents: 24,
    wallMs: 1000,
    persist: async () => {},
    onFrame: async () => {},
    stopOwned: async () => {},
  });
  assert.equal(live(), before);
  q.lifecycle("end");
  await q.done();
  assert.ok(live() <= before);
});
test("metadata without a credential keeps default flags and binary values without decoding them", async () => {
  const { q, saved } = await queue();
  assert.equal(q.headers("response", ["x-note", "undefined", "details-bin", "AAAA"]), true);
  const result = await q.done();
  assert.equal(result.reason, undefined);
  assert.equal(saved[0].flags, 0);
});
// Screening runs in a child process so a screening loop that never returns fails an assertion
// instead of freezing the test process; a busy worker thread cannot be reliably terminated.
async function screenInChild(credential, cases) {
  const script = `const [target, input] = process.argv.slice(1);
    const { credential, cases } = JSON.parse(input);
    const { createStreamingReceiptQueue } = await import(target);
    const outcomes = [];
    for (const raw of cases) {
      const saved = [];
      const q = createStreamingReceiptQueue({
        maxFrameBytes: 64, maxTotalBytes: 512, maxFrames: 8, maxChunks: 16, maxHeaderBytes: 256,
        maxHeaderEvents: 4, maxHeaderPairs: 16, maxEvents: 24, wallMs: 1000, credential,
        persist: async (row) => { saved.push(row); },
        onFrame: async () => {},
        stopOwned: async () => {},
      });
      const accepted = q.headers("trailers", raw, 0);
      const result = await q.done();
      outcomes.push({ accepted, reason: result.reason ?? null, saved: saved.length });
    }
    process.stdout.write(JSON.stringify(outcomes));`;
  try {
    const { stdout } = await promisify(execFile)(
      process.execPath,
      ["--input-type=module", "--eval", script, target.href, JSON.stringify({ credential, cases })],
      { timeout: 8000, killSignal: "SIGKILL" },
    );
    return JSON.parse(stdout);
  } catch (error) {
    return error.killed ? "screening did not return" : `screening failed: ${error.stderr}`;
  }
}
test("credential screening visits each metadata pair once, decodes only binary values and refuses reflection", async () => {
  const credential = "SYNTHETIC-SECRET";
  const encoded = Buffer.from(credential).toString("base64");
  const accepted = { accepted: true, reason: null, saved: 1 };
  const refused = { accepted: false, reason: "credential-reflection", saved: 0 };
  assert.deepEqual(
    await screenInChild(credential, [
      [":status", "200"],
      ["details", encoded],
      ["other-bin", Buffer.from("harmless").toString("base64")],
      [":status", "200", "details-bin", encoded],
      ["details", credential],
    ]),
    [accepted, accepted, accepted, refused, refused],
  );
});
test("an owned stop that never acknowledges stays named among pending callbacks", async () => {
  const { q } = await queue({ wallMs: 30, stopOwned: () => new Promise(() => {}) });
  q.lifecycle("end");
  const result = await q.done();
  assert.deepEqual(result.pendingCallbacks, ["owned-stop"]);
  assert.equal(result.terminationRequired, true);
});
test("metadata flags and cumulative header bytes are accepted exactly at their limits", async () => {
  const { q, saved } = await queue({ maxHeaderBytes: 12, maxHeaderPairs: 1 });
  assert.equal(q.headers("response", [":status", "200"], 255), true);
  assert.equal(q.headers("trailers", ["a", "b"], 0), true);
  const result = await q.done();
  assert.equal(result.reason, undefined);
  assert.equal(result.headerBytes, 12);
  assert.deepEqual(
    saved.map((row) => [row.kind, row.flags]),
    [
      ["response", 255],
      ["trailers", 0],
    ],
  );
  const over = await queue({ maxHeaderBytes: 11 });
  assert.equal(over.q.headers("response", [":status", "200", "a", "bc"], 0), false);
  assert.equal((await over.q.done()).reason, "header-bound");
});
test("no stored row holds the credential's first eight bytes in data or metadata", async () => {
  const credential = "SYNTHETIC-SECRET";
  const prefix = Buffer.from(credential).subarray(0, 8);
  const wire = frame(Buffer.from(credential));
  const cases = {
    "three-chunk data": (q) => [
      q.data(wire.subarray(0, 9)),
      q.data(wire.subarray(9, 11)),
      q.data(wire.subarray(11)),
    ],
    "truncated text value": (q) => [q.headers("trailers", ["details", "token SYNTHETI..."], 0)],
    "truncated binary value": (q) => [
      q.headers("trailers", ["details-bin", Buffer.from("xSYNTHETIx").toString("base64")], 0),
    ],
  };
  for (const [name, feed] of Object.entries(cases)) {
    const { q, saved, frames } = await queue({ credential });
    assert.equal(feed(q).at(-1), false, name);
    const result = await q.done();
    assert.equal(result.reason, "credential-reflection", name);
    assert.equal(frames.length, 0, name);
    for (const row of saved) {
      const stored = row.raw
        ? Buffer.from(row.raw.bodyBase64, "base64")
        : Buffer.from(JSON.stringify(row));
      assert.equal(stored.includes(prefix), false, name);
    }
  }
  // Seven bytes of the prefix are ordinary data and metadata.
  const { q, saved } = await queue({ credential });
  assert.equal(q.data(frame(Buffer.from("SYNTHET"))), true);
  assert.equal(q.headers("trailers", ["details", "SYNTHET"], 0), true);
  assert.equal(
    q.headers("trailers", ["details-bin", Buffer.from("SYNTHET").toString("base64")], 0),
    true,
  );
  const result = await q.done();
  assert.equal(result.reason, undefined);
  assert.equal(saved.length, 3);
});
