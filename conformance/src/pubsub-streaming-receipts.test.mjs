import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";

const target = new URL("../pubsub-corpus/streaming-receipts.mjs", import.meta.url);
const frame = (bytes) => {
  const head = Buffer.alloc(5);
  head.writeUInt32BE(bytes.length, 1);
  return Buffer.concat([head, bytes]);
};
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
