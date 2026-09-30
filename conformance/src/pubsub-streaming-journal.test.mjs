import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { test } from "node:test";

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
