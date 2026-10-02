import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mock, test } from "node:test";

const target = new URL("../pubsub-corpus/streaming-journal.mjs", import.meta.url);
async function journal(extra = {}) {
  assert.ok(existsSync(target), "observer-independent bounded journal is missing");
  const { createStreamingJournal } = await import(target.href);
  const rows = [],
    stopped = [];
  const j = createStreamingJournal({
    maxEntries: 8,
    maxEntryBytes: 64,
    maxTotalBytes: 256,
    deadlineAt: performance.now() + 1000,
    write: async (row) => rows.push(row),
    stopOwned: (row) => stopped.push(row.reason),
    ...extra,
  });
  return { j, rows, stopped };
}
// A test-local real timer that loses the race to any module cutoff or commit working as intended.
// If one never settles, the test fails this assertion instead of hanging until the per-test timeout.
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
test("a clean write's ticket commits its frozen receipt before a fallback timer", async () => {
  const { j, rows } = await journal({ deadlineAt: performance.now() + 60000 });
  const committed = await settleOrFallback(j.append(Buffer.from("kept")).committed);
  assert.equal(committed.state, "fulfilled", "a clean write must commit its ticket");
  assert.deepEqual(committed.value, {
    index: 0,
    sha256: createHash("sha256").update("kept").digest("hex"),
    bodyBytes: 4,
  });
  assert.ok(Object.isFrozen(committed.value));
  assert.equal(rows.length, 1);
  const result = await j.done();
  assert.equal(result.acknowledgedEntries, 1);
  assert.equal(result.unknownEntries, 0);
});
test("a write that never settles just short of the deadline is bounded by the drain's own wait before a fallback timer", async () => {
  let now = 5000;
  const clock = mock.method(performance, "now", () => now);
  const seen = [];
  try {
    const { j } = await journal({
      deadlineAt: 65000,
      write: () => new Promise(() => {}),
      stopOwned: ({ reason, signal }) => {
        seen.push([reason, signal.aborted]);
      },
    });
    now = 64999;
    const ticket = await settleOrFallback(j.append(Buffer.alloc(0)).committed);
    assert.equal(ticket.state, "rejected", "the write's own cutoff must reject its ticket");
    assert.deepEqual(seen, [["deadline", true]]);
    const reported = await settleOrFallback(j.done());
    assert.equal(reported.state, "fulfilled", "done() must be settled by its own deadline wait");
    assert.equal(reported.value.reason, "deadline");
    assert.deepEqual(reported.value.pendingCallbacks, ["write:0"]);
    assert.equal(reported.value.acknowledgedEntries, 0);
    assert.equal(reported.value.unknownEntries, 1);
    assert.equal(reported.value.terminationRequired, true);
  } finally {
    clock.mock.restore();
  }
});
test("journal sequence and acknowledgment bind immutable exact byte snapshots", async () => {
  let release;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const started = [];
  const { j, rows, stopped } = await journal({
    write: async (row) => {
      started.push(row.index);
      await held;
      rows.push(row);
    },
  });
  const input = Buffer.from("raw");
  const first = j.append(input),
    second = j.append(Buffer.alloc(0));
  input.fill(0);
  let visible = false;
  first.committed.then(() => {
    visible = true;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(visible, false);
  assert.deepEqual(started, [0]);
  assert.equal(first.index, 0);
  assert.equal(second.index, 1);
  release();
  await second.committed;
  assert.deepEqual(
    rows.map((row) => Buffer.from(row.bodyBase64, "base64")),
    [Buffer.from("raw"), Buffer.alloc(0)],
  );
  assert.equal(rows[0].sha256, createHash("sha256").update("raw").digest("hex"));
  assert.equal(Reflect.set(rows[0], "bodyBytes", 99), false);
  const result = await j.done();
  assert.equal(result.acknowledgedEntries, 2);
  assert.equal(result.unknownEntries, 0);
  assert.equal(result.terminationRequired, false);
  await j.done();
  assert.equal(stopped.length, 1);
});
test(
  "an observer awaiting a new outbound record never holds the journal commit chain",
  { timeout: 500 },
  async () => {
    const { j, rows } = await journal();
    const incoming = j.append(Buffer.from("incoming"));
    const observer = incoming.committed.then(async () => {
      const outgoing = j.append(Buffer.from("outgoing intent"));
      await outgoing.committed;
    });
    await observer;
    assert.equal(rows.length, 2);
    assert.equal((await j.done()).unknownEntries, 0);
  },
);
test("stalled storage charges entry and byte caps before copying including empty entries", async () => {
  for (const [bounds, first, reason] of [
    [{ maxEntries: 1 }, Buffer.alloc(0), "entry-bound"],
    [{ maxEntryBytes: 1 }, Buffer.from("a"), "entry-byte-bound"],
    [{ maxTotalBytes: 1 }, Buffer.from("a"), "total-byte-bound"],
  ]) {
    let release;
    const held = new Promise((resolve) => {
      release = resolve;
    });
    const { j, stopped } = await journal({ ...bounds, write: () => held });
    const admitted = j.append(first);
    assert.throws(() => j.append(Buffer.from("ab")), /stopped/);
    assert.deepEqual(stopped, [reason]);
    for (let i = 0; i < 10; i++) assert.throws(() => j.append(Buffer.alloc(0)), /stopped/);
    release();
    await admitted.committed;
    const result = await j.done();
    assert.equal(result.entries, 1);
    assert.equal(result.acknowledgedEntries, 1);
  }
});
test("failed storage acknowledges nothing and never retries or starts subsequent writes", async () => {
  let calls = 0;
  const { j } = await journal({
    write: () => {
      calls++;
      throw new Error("PRIVATE STORE DETAIL");
    },
  });
  const first = j.append(Buffer.from("first")),
    second = j.append(Buffer.from("second"));
  await assert.rejects(first.committed, /stopped/);
  await assert.rejects(second.committed, /stopped/);
  assert.throws(() => j.append(Buffer.alloc(0)), /stopped/);
  const result = await j.done();
  assert.equal(calls, 1);
  assert.equal(result.unknownEntries, 2);
  assert.equal(result.reason, "persistence");
  assert.equal(JSON.stringify(result).includes("PRIVATE STORE"), false);
});
test(
  "shared deadline accounts for hung write or owned stop and never returns clean containment",
  { timeout: 500 },
  async () => {
    for (const phase of ["write", "stopOwned"]) {
      let release;
      const held = new Promise((resolve) => {
        release = resolve;
      });
      const exact = performance.now() + 30;
      const { j } = await journal({ deadlineAt: exact, [phase]: () => held });
      const ticket = j.append(Buffer.alloc(0));
      const result = await j.done();
      assert.equal(result.deadlineAt, exact);
      assert.equal(result.terminationRequired, true);
      assert.ok(result.pendingCallbacks.length > 0);
      release();
      await ticket.committed.catch(() => {});
    }
  },
);
test("done initiates owned stop before waiting for admitted storage", async () => {
  let release;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  const { j, stopped } = await journal({ write: () => held });
  const ticket = j.append(Buffer.alloc(0));
  const done = j.done();
  assert.deepEqual(stopped, ["local-close"]);
  assert.throws(() => j.append(Buffer.alloc(0)), /stopped/);
  release();
  await ticket.committed;
  assert.equal((await done).terminationRequired, false);
});
test("invalid journal deadlines bounds callbacks and raw records are refused", async () => {
  for (const key of ["maxEntries", "maxEntryBytes", "maxTotalBytes"])
    for (const value of [0, -1, Infinity, 1.1])
      await assert.rejects(journal({ [key]: value }), /finite/);
  for (const deadlineAt of [
    NaN,
    Infinity,
    -1,
    performance.now() - 1,
    performance.now() + 2147493647,
  ])
    await assert.rejects(journal({ deadlineAt }), /deadline/);
  for (const key of ["write", "stopOwned"])
    await assert.rejects(journal({ [key]: null }), /callback/);
  const { j } = await journal();
  assert.throws(
    () =>
      j.append({
        toJSON() {
          throw new Error("must not run");
        },
      }),
    /stopped/,
  );
  assert.equal((await j.done()).entries, 0);
});
test("all16short append traces preserve bounded reservations and exact stored byte order", async () => {
  for (let mask = 0; mask < 16; mask++) {
    const { j, rows } = await journal({ maxEntries: 3, maxTotalBytes: 2 });
    const accepted = [];
    let size = 0,
      stopped = false;
    for (let i = 0; i < 4; i++) {
      const bytes = mask & (1 << i) ? Buffer.from([i]) : Buffer.alloc(0);
      if (stopped || accepted.length >= 3 || size + bytes.length > 2) {
        stopped = true;
        assert.throws(() => j.append(bytes), /stopped/);
      } else {
        accepted.push(bytes);
        size += bytes.length;
        j.append(bytes);
      }
    }
    const result = await j.done();
    assert.equal(result.entries, accepted.length);
    assert.equal(result.acknowledgedEntries, accepted.length);
    assert.deepEqual(
      rows.map((row) => Buffer.from(row.bodyBase64, "base64")),
      accepted,
    );
  }
});
test(
  "failed owned stop and late settlement cannot upgrade a returned uncertain report",
  { timeout: 500 },
  async () => {
    const { j: failed } = await journal({
      stopOwned: () => {
        throw new Error("private stop detail");
      },
    });
    assert.equal((await failed.done()).terminationRequired, true);
    let release;
    const held = new Promise((resolve) => {
      release = resolve;
    });
    const { j } = await journal({ deadlineAt: performance.now() + 30, stopOwned: () => held });
    const first = await j.done();
    assert.equal(first.terminationRequired, true);
    release();
    assert.equal((await j.done()).terminationRequired, true);
  },
);
test(
  "a hung write ticket rejects within the deadline before any explicit drain",
  { timeout: 500 },
  async () => {
    let release;
    const held = new Promise((resolve) => {
      release = resolve;
    });
    const { j } = await journal({ deadlineAt: performance.now() + 30, write: () => held });
    const ticket = j.append(Buffer.alloc(0));
    try {
      await assert.rejects(ticket.committed, /stopped/);
    } finally {
      release();
      await j.done();
    }
  },
);
test(
  "Uint8Array records preserve binary bytes and idle deadline begins owned stop",
  { timeout: 500 },
  async () => {
    const { j, rows } = await journal();
    const bytes = new Uint8Array([0, 255]);
    const ticket = j.append(bytes);
    bytes.fill(1);
    await ticket.committed;
    assert.deepEqual(Buffer.from(rows[0].bodyBase64, "base64"), Buffer.from([0, 255]));
    await j.done();
    const { j: idle, stopped } = await journal({ deadlineAt: performance.now() + 30 });
    try {
      await new Promise((resolve) => setTimeout(resolve, 60));
      assert.deepEqual(stopped, ["deadline"]);
    } finally {
      await idle.done();
    }
  },
);
test("overridden byte-view properties cannot reenter or bypass reservations", async () => {
  const { j, rows } = await journal({ maxEntries: 1 });
  let getters = 0;
  const bytes = new Uint8Array([7]);
  Object.defineProperty(bytes, "length", {
    get() {
      getters++;
      j.append(Buffer.alloc(0));
      return 1;
    },
  });
  await j.append(bytes).committed;
  const result = await j.done();
  assert.equal(getters, 0);
  assert.equal(result.entries, 1);
  assert.equal(result.totalBytes, 1);
  assert.equal(rows[0].bodyBase64, "Bw==");
});
test("late stop acknowledgment before overdue timers cannot claim clean deadline containment", async () => {
  const deadlineAt = performance.now() + 30;
  const { j } = await journal({
    deadlineAt,
    stopOwned: () =>
      Promise.resolve().then(() => {
        while (performance.now() < deadlineAt + 5) {
          /* Deliberately hold timer dispatch. */
        }
      }),
  });
  assert.equal((await j.done()).terminationRequired, true);
  assert.equal((await j.done()).terminationRequired, true);
});
test(
  "an early relative timer followed by a predeadline stop acknowledgment preserves observed uncertainty",
  { timeout: 500 },
  async () => {
    let now = 0,
      release;
    const clock = mock.method(performance, "now", () => now);
    const held = new Promise((resolve) => {
      release = resolve;
    });
    let acknowledgedAt;
    const advance = setTimeout(() => {
      now = 30.25;
    }, 5);
    let j;
    try {
      ({ j } = await journal({
        deadlineAt: 30.75,
        stopOwned: () =>
          held.then(() => {
            acknowledgedAt = now;
          }),
      }));
      const first = await j.done();
      assert.equal(first.terminationRequired, true);
      assert.ok(now < first.deadlineAt);
      release();
      await new Promise((resolve) => setImmediate(resolve));
      assert.equal(acknowledgedAt, 30.25);
      assert.equal((await j.done()).terminationRequired, true);
    } finally {
      clearTimeout(advance);
      release();
      await j?.done();
      clock.mock.restore();
    }
  },
);
test("a clean journal drained again after its absolute deadline cannot erase deadline uncertainty", async () => {
  let now = 0;
  const clock = mock.method(performance, "now", () => now);
  let j;
  try {
    ({ j } = await journal({ deadlineAt: 30 }));
    assert.equal((await j.done()).terminationRequired, false);
    now = 31;
    const later = await j.done();
    assert.deepEqual(later.pendingCallbacks, []);
    assert.equal(later.unknownEntries, 0);
    assert.equal(later.reason, "deadline");
    assert.equal(later.terminationRequired, true);
  } finally {
    await j?.done();
    clock.mock.restore();
  }
});
test("journal deadlines are refused at the construction instant and past the native timer bound", async () => {
  let now = 1000;
  const clock = mock.method(performance, "now", () => now);
  try {
    await assert.rejects(journal({ deadlineAt: 1000 }), /deadline/);
    await assert.rejects(journal({ deadlineAt: 1000 + 2147483648 }), /deadline/);
    const { j } = await journal({ deadlineAt: 1000 + 2147483647 });
    // Drain shortly before the far deadline so no drain wait can hold the process for days.
    now = 1000 + 2147483647 - 10;
    const result = await j.done();
    assert.equal(result.deadlineAt, 1000 + 2147483647);
    assert.equal(result.terminationRequired, false);
  } finally {
    clock.mock.restore();
  }
});
test("a refusal leaves admitted storage running until a stop acknowledgment at the deadline halts and aborts it", async () => {
  let now = 0,
    releaseStop,
    releaseWrite;
  const clock = mock.method(performance, "now", () => now);
  const stopHeld = new Promise((resolve) => {
      releaseStop = resolve;
    }),
    writeHeld = new Promise((resolve) => {
      releaseWrite = resolve;
    });
  const signals = [],
    stopped = [];
  let j;
  try {
    ({ j } = await journal({
      maxEntries: 1,
      deadlineAt: 1000,
      write: (row, { signal }) => {
        signals.push(signal);
        return writeHeld;
      },
      stopOwned: ({ reason }) => {
        stopped.push(reason);
        return stopHeld;
      },
    }));
    const admitted = j.append(Buffer.from("a"));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(signals.length, 1);
    assert.ok(signals[0] instanceof AbortSignal);
    assert.throws(() => j.append(Buffer.from("b")), /stopped/);
    assert.deepEqual(stopped, ["entry-bound"]);
    assert.equal(signals[0].aborted, false);
    now = 1000;
    releaseStop();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(signals[0].aborted, true);
    releaseWrite();
    await assert.rejects(admitted.committed, /stopped/);
    const result = await j.done();
    assert.equal(result.reason, "entry-bound");
    assert.equal(result.acknowledgedEntries, 0);
    assert.equal(result.terminationRequired, true);
  } finally {
    releaseStop();
    releaseWrite();
    await j?.done();
    clock.mock.restore();
  }
});
test("a drain whose owned stop is acknowledged at the deadline reports the deadline reason", async () => {
  let now = 0,
    release;
  const clock = mock.method(performance, "now", () => now);
  const held = new Promise((resolve) => {
    release = resolve;
  });
  let j;
  try {
    ({ j } = await journal({ deadlineAt: 1000, stopOwned: () => held }));
    const draining = j.done();
    now = 1000;
    release();
    const result = await draining;
    assert.equal(result.reason, "deadline");
    assert.equal(result.terminationRequired, true);
  } finally {
    release();
    await j?.done();
    clock.mock.restore();
  }
});
test(
  "an idle deadline timer halts and aborts before it requests owned stop",
  { timeout: 500 },
  async () => {
    const clock = mock.method(performance, "now", () => 0);
    let called;
    const requested = new Promise((resolve) => {
      called = resolve;
    });
    const seen = [];
    let j;
    try {
      ({ j } = await journal({
        deadlineAt: 20,
        stopOwned: ({ reason, signal }) => {
          seen.push([reason, signal.aborted]);
          called();
        },
      }));
      await requested;
      assert.deepEqual(seen, [["deadline", true]]);
      assert.throws(() => j.append(Buffer.alloc(0)), /stopped/);
    } finally {
      await j?.done();
      clock.mock.restore();
    }
  },
);
test("monotonic time at the deadline refuses appends and storage acknowledgments before overdue timers fire", async () => {
  let now = 0;
  const clock = mock.method(performance, "now", () => now);
  const seen = [];
  let j;
  try {
    ({ j } = await journal({
      deadlineAt: 1000,
      stopOwned: ({ reason, signal }) => {
        seen.push([reason, signal.aborted]);
      },
    }));
    now = 1000;
    assert.throws(() => j.append(Buffer.alloc(0)), /stopped/);
    assert.deepEqual(seen, [["deadline", true]]);
    const result = await j.done();
    assert.equal(result.entries, 0);
    assert.equal(result.reason, "deadline");
  } finally {
    await j?.done();
    clock.mock.restore();
  }
  now = 0;
  const lateClock = mock.method(performance, "now", () => now);
  let release, late;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  try {
    ({ j: late } = await journal({ deadlineAt: 1000, write: () => held }));
    const ticket = late.append(Buffer.from("late"));
    await new Promise((resolve) => setImmediate(resolve));
    now = 1000;
    release();
    await assert.rejects(ticket.committed, /stopped/);
    const result = await late.done();
    assert.equal(result.acknowledgedEntries, 0);
    assert.equal(result.unknownEntries, 1);
    assert.equal(result.reason, "deadline");
  } finally {
    release();
    await late?.done();
    lateClock.mock.restore();
  }
});
test(
  "a hung write's own cutoff rejects its ticket at the deadline and halts with the deadline reason",
  { timeout: 8000 },
  async () => {
    let now = 0,
      release;
    const clock = mock.method(performance, "now", () => now);
    const held = new Promise((resolve) => {
      release = resolve;
    });
    const seen = [];
    let j;
    try {
      ({ j } = await journal({
        deadlineAt: 65000,
        write: () => held,
        stopOwned: ({ reason, signal }) => {
          seen.push([reason, signal.aborted]);
        },
      }));
      const ticket = j.append(Buffer.alloc(0));
      // 10 ms of real time remain; any cutoff measured from the wrong origin is far past the fallback.
      now = 64990;
      const outcome = await settleOrFallback(ticket.committed);
      assert.equal(outcome.state, "rejected");
      assert.deepEqual(seen, [["deadline", true]]);
    } finally {
      release();
      await j?.done();
      clock.mock.restore();
    }
  },
);
test("pending callbacks name a hung write and a hung owned stop", { timeout: 500 }, async () => {
  const clock = mock.method(performance, "now", () => 0);
  let release;
  const held = new Promise((resolve) => {
    release = resolve;
  });
  let j;
  try {
    ({ j } = await journal({ deadlineAt: 20, write: () => held, stopOwned: () => held }));
    j.append(Buffer.alloc(0)).committed.catch(() => {});
    const result = await j.done();
    assert.deepEqual(result.pendingCallbacks.toSorted(), ["owned-stop", "write:0"]);
    assert.equal(result.terminationRequired, true);
  } finally {
    release();
    await j?.done();
    clock.mock.restore();
  }
});
test(
  "a drained journal leaves no timer that can later stop, abort or hold the process open",
  { timeout: 500 },
  async () => {
    const { createStreamingJournal } = await import(target.href);
    const nativeSetTimeout = globalThis.setTimeout;
    const timers = [];
    const clock = mock.method(performance, "now", () => 0);
    const nativeClearTimeout = globalThis.clearTimeout;
    const cleared = new Set();
    const spy = mock.method(globalThis, "setTimeout", (...args) => {
      const timer = nativeSetTimeout(...args);
      timers.push(timer);
      return timer;
    });
    const clearSpy = mock.method(globalThis, "clearTimeout", (timer) => {
      cleared.add(timer);
      return nativeClearTimeout(timer);
    });
    const holding = () => timers.filter((timer) => timer.hasRef() && !cleared.has(timer));
    const signals = [],
      stopped = [];
    let j;
    try {
      j = createStreamingJournal({
        maxEntries: 8,
        maxEntryBytes: 64,
        maxTotalBytes: 256,
        deadlineAt: 20,
        write: async (row, { signal }) => {
          signals.push(signal);
        },
        stopOwned: ({ reason }) => {
          stopped.push(reason);
        },
      });
      assert.equal(timers.length, 1);
      assert.equal(timers[0].hasRef(), false);
      await j.append(Buffer.from("kept")).committed;
      assert.ok(timers.length > 1);
      assert.deepEqual(holding(), []);
      const first = await j.done();
      assert.equal(Object.hasOwn(first, "reason"), false);
      assert.equal(first.terminationRequired, false);
      assert.deepEqual(holding(), []);
      spy.mock.restore();
      clearSpy.mock.restore();
      await new Promise((resolve) => setTimeout(resolve, 40));
      assert.equal(signals[0].aborted, false);
      assert.deepEqual(stopped, ["local-close"]);
      const second = await j.done();
      assert.equal(Object.hasOwn(second, "reason"), false);
      assert.equal(second.terminationRequired, false);
    } finally {
      spy.mock.restore();
      clearSpy.mock.restore();
      await j?.done();
      clock.mock.restore();
    }
  },
);
test("a drain at exactly the absolute deadline halts storage and reports deadline uncertainty", async () => {
  let now = 0;
  const clock = mock.method(performance, "now", () => now);
  const signals = [];
  let j;
  try {
    ({ j } = await journal({
      deadlineAt: 1000,
      stopOwned: ({ signal }) => {
        signals.push(signal);
      },
    }));
    const first = await j.done();
    assert.equal(first.terminationRequired, false);
    assert.equal(signals[0].aborted, false);
    now = 1000;
    const later = await j.done();
    assert.equal(later.reason, "deadline");
    assert.equal(later.terminationRequired, true);
    assert.equal(signals[0].aborted, true);
  } finally {
    await j?.done();
    clock.mock.restore();
  }
});
test("byte views other than live Uint8Array records are refused as invalid records", async () => {
  for (const view of [
    new Int16Array([1]),
    new Float64Array([1]),
    new DataView(new ArrayBuffer(2)),
  ]) {
    const { j, rows, stopped } = await journal();
    assert.throws(() => j.append(view), /stopped/);
    assert.deepEqual(stopped, ["invalid-record"]);
    const result = await j.done();
    assert.equal(result.entries, 0);
    assert.equal(rows.length, 0);
  }
  const buffer = new ArrayBuffer(4),
    detached = new Uint8Array(buffer);
  buffer.transfer();
  const seen = [];
  const { j, rows } = await journal({
    stopOwned: ({ reason, signal }) => {
      seen.push([reason, signal.aborted]);
    },
  });
  assert.throws(() => j.append(detached), /stopped/);
  assert.deepEqual(seen, [["invalid-record", true]]);
  assert.throws(() => j.append(Buffer.alloc(0)), /stopped/);
  const result = await j.done();
  assert.equal(result.reason, "invalid-record");
  assert.equal(result.acknowledgedEntries, 0);
  assert.equal(result.terminationRequired, true);
  assert.equal(rows.length, 0);
});
// The adapter contract: a sender may only use the journal through journalPersist, which resolves
// after the row's `.committed`; the injected write acknowledges only after the row is written and
// both the file and its parent directory are fsynced.
async function journalGate({ storage, issue = () => {} }) {
  const { createStreamingWriteGate } = await import(
    new URL("../pubsub-corpus/streaming-write-gate.mjs", import.meta.url).href
  );
  const { journalPersist } = await import(target.href);
  const deadlineAt = performance.now() + 1000,
    steps = [];
  const { j } = await journal({
    maxEntryBytes: 1024,
    maxTotalBytes: 4096,
    deadlineAt,
    write: async (row) => {
      for (const step of ["write", "fsync-file", "fsync-directory"]) {
        await storage(step, row);
        steps.push(`${step}:${row.index}`);
      }
    },
  });
  const g = createStreamingWriteGate({
    maxFrames: 2,
    maxFrameBytes: 64,
    maxOutgoingBytes: 256,
    maxActions: 4,
    wallMs: 1000,
    deadlineAt,
    guard: async () => {},
    liveCheck: () => true,
    persist: journalPersist(j, (record) => Buffer.from(JSON.stringify(record))),
    issue: (intent) => {
      steps.push(`issue:${intent.index}`);
      return issue(intent);
    },
    contain: async () => {},
  });
  return { g, j, steps };
}
test("a sender wired through journalPersist issues only after the intent row is written and fsynced with its directory", async () => {
  const released = [];
  const { g, j, steps } = await journalGate({
    storage: (step, row) =>
      new Promise((resolve) => released.push({ name: `${step}:${row.index}`, resolve })),
  });
  const opening = g.open();
  // Release one storage step at a time; issue must not run before the directory fsync of row 0.
  for (let turn = 0; turn < 6; turn++) {
    for (let wait = 0; !released.length; wait++) {
      assert.ok(wait < 100, `storage step ${turn} was never requested; steps: ${steps}`);
      await new Promise((resolve) => setImmediate(resolve));
    }
    const next = released.shift();
    if (next.name === "fsync-directory:0") assert.deepEqual(steps, ["write:0", "fsync-file:0"]);
    next.resolve();
  }
  await opening;
  assert.deepEqual(steps, [
    "write:0",
    "fsync-file:0",
    "fsync-directory:0",
    "issue:0",
    "write:1",
    "fsync-file:1",
    "fsync-directory:1",
  ]);
  const gate = await g.done();
  assert.equal(gate.completedActions, 1);
  assert.equal(gate.terminationRequired, false);
  assert.equal((await j.done()).acknowledgedEntries, 2);
});
test("a failed directory fsync of the intent row means issue is never entered and nothing is retried", async () => {
  const { g, j, steps } = await journalGate({
    storage: async (step) => {
      if (step === "fsync-directory") throw new Error("parent directory fsync failed");
    },
  });
  await assert.rejects(g.open(), /stopped/);
  assert.deepEqual(steps, ["write:0", "fsync-file:0"]);
  const gate = await g.done();
  assert.equal(gate.issuedActions, 0);
  assert.equal(gate.unknownActions, 1);
  assert.equal(gate.terminationRequired, false);
  const journalResult = await j.done();
  assert.equal(journalResult.reason, "persistence");
  assert.equal(journalResult.acknowledgedEntries, 0);
});
test("a lost acknowledgement of the issued row reaches the gate as an unknown outcome that requires termination", async () => {
  const { g, steps } = await journalGate({
    storage: async (step, row) => {
      if (row.index === 1 && step === "fsync-file") throw new Error("file fsync failed");
    },
  });
  await assert.rejects(g.open(), /stopped/);
  assert.deepEqual(steps, ["write:0", "fsync-file:0", "fsync-directory:0", "issue:0", "write:1"]);
  const gate = await g.done();
  assert.equal(gate.issuedActions, 1);
  assert.equal(gate.unknownActions, 1);
  assert.equal(gate.terminationRequired, true);
});
test("journalPersist refuses a non-journal and a missing encoder before any write", async () => {
  const { journalPersist } = await import(target.href);
  assert.throws(() => journalPersist({}, (record) => record), /journal/);
  const { j } = await journal();
  assert.throws(() => journalPersist(j), /encoder/);
});
test("a receipt queue wired through journalPersist stores nothing after a failed fsync and never shows a frame", async () => {
  const { createStreamingReceiptQueue } = await import(
    new URL("../pubsub-corpus/streaming-receipts.mjs", import.meta.url).href
  );
  const { journalPersist } = await import(target.href);
  const deadlineAt = performance.now() + 1000,
    writes = [];
  const { j } = await journal({
    maxEntryBytes: 1024,
    maxTotalBytes: 4096,
    deadlineAt,
    write: async (row) => {
      writes.push(row.index);
      if (row.index === 1) throw new Error("file fsync failed");
    },
  });
  const frames = [];
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
    deadlineAt,
    persist: journalPersist(j, (row) => Buffer.from(JSON.stringify(row))),
    onFrame: async (frame) => frames.push(frame),
    stopOwned: async () => {},
  });
  const message = Buffer.from([0, 0, 0, 0, 1, 120]);
  assert.equal(q.headers("response", [":status", "200"], 4), true);
  assert.equal(q.data(message), true);
  assert.equal(q.data(message), true);
  const result = await q.done();
  assert.deepEqual(writes, [0, 1]);
  assert.equal(result.reason, "persistence");
  assert.equal(result.persistedEvents, 1);
  assert.equal(result.unknownEvents, 2);
  assert.equal(frames.length, 0);
  const journalResult = await j.done();
  assert.equal(journalResult.reason, "persistence");
  assert.equal(journalResult.acknowledgedEntries, 1);
});
