// Seeded property and model-based tests for the offline StreamingPull helpers. Each property
// replays a fixed seed sequence, so a failure names the seed and case that reproduce it.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

const corpus = new URL("../pubsub-corpus/", import.meta.url);
const load = async (name) => import(new URL(name, corpus).href);
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const CASES = 300;

function rng(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (min, max) => min + Math.floor(next() * (max - min + 1));
  return {
    int,
    chance: (p) => next() < p,
    pick: (list) => list[int(0, list.length - 1)],
    bytes: (length) => Buffer.from(Array.from({ length }, () => int(0, 255))),
  };
}
// A property returns the label of the case it exercised; every label in mustSee has to occur, so
// a generator that drifts away from a branch fails instead of passing vacuously.
function forAll(name, property, mustSee = []) {
  return async () => {
    const seen = new Set();
    for (let seed = 1; seed <= CASES; seed++) {
      try {
        seen.add(await property(rng(seed)));
      } catch (error) {
        error.message = `${name} seed ${seed}: ${error.message}`;
        throw error;
      }
    }
    assert.deepEqual(
      mustSee.filter((label) => !seen.has(label)),
      [],
      `${name} generator never reached these cases`,
    );
  };
}
function envelope(payload) {
  const head = Buffer.alloc(5);
  head.writeUInt32BE(payload.length, 1);
  return Buffer.concat([head, payload]);
}
function partition(r, stream, maxParts) {
  const parts = [];
  let at = 0;
  while (at < stream.length && parts.length < maxParts - 1) {
    const size = r.chance(0.1) ? 0 : r.int(1, Math.max(1, Math.ceil(stream.length / 3)));
    parts.push(stream.subarray(at, at + size));
    at += size;
  }
  if (at < stream.length || !parts.length) parts.push(stream.subarray(at));
  return parts;
}

// Reference decoder: works over the whole accepted byte string with a read cursor instead of the
// helper's retained buffer and rolling credential tail.
function modelFrames(chunks, { maxFrameBytes, maxTotalBytes, maxFrames, maxChunks }, secret) {
  let accepted = Buffer.alloc(0),
    cursor = 0,
    reason;
  const raws = [],
    frames = [];
  for (const chunk of chunks) {
    if (raws.length >= maxChunks) {
      reason = "chunk-count";
      break;
    }
    const take = chunk.subarray(0, maxTotalBytes - accepted.length);
    if (secret && Buffer.concat([accepted, take]).includes(secret)) {
      reason = "credential-reflection";
      break;
    }
    raws.push({ bytes: take, truncated: take.length !== chunk.length });
    accepted = Buffer.concat([accepted, take]);
    if (take.length !== chunk.length) {
      reason = "total-bound";
      cursor = accepted.length;
      break;
    }
    while (accepted.length - cursor >= 5) {
      const length = accepted.readUInt32BE(cursor + 1);
      if (accepted[cursor] !== 0) reason = "compression";
      else if (length > maxFrameBytes) reason = "frame-bound";
      else if (frames.length >= maxFrames) reason = "frame-count";
      if (reason || accepted.length - cursor < length + 5) break;
      frames.push(accepted.subarray(cursor + 5, cursor + 5 + length));
      cursor += length + 5;
    }
    if (reason) break;
  }
  if (!reason && cursor < accepted.length) reason = "truncated-frame";
  return { raws, frames, reason, bytes: accepted.length };
}
function randomStream(r, secret) {
  const messages = Array.from({ length: r.int(0, 6) }, () => r.bytes(r.int(0, 24)));
  let stream = Buffer.concat(messages.map(envelope));
  if (stream.length && r.chance(0.15)) {
    const at = r.int(0, stream.length - 1);
    stream = Buffer.from(stream);
    stream[at] = r.int(1, 255);
  }
  if (r.chance(0.15)) stream = Buffer.concat([stream, r.bytes(r.int(1, 7))]);
  if (secret && r.chance(0.5)) {
    const at = r.int(0, stream.length);
    stream = Buffer.concat([stream.subarray(0, at), secret, stream.subarray(at)]);
  }
  return stream;
}

test(
  "frame decoder matches the whole-stream reference model under random caps and partitions",
  forAll(
    "frames-model",
    async (r) => {
      const { createStreamingFrameDecoder } = await load("streaming-frames.mjs");
      const caps = {
        maxFrameBytes: r.int(1, 30),
        maxTotalBytes: r.int(1, 260),
        maxFrames: r.int(1, 8),
        maxChunks: r.int(1, 24),
      };
      const credential = r.chance(0.3) ? `secret-${r.int(0, 999)}` : undefined;
      const secret = credential && Buffer.from(credential);
      const chunks = partition(r, randomStream(r, secret), 30);
      const expected = modelFrames(chunks, caps, secret);
      const d = createStreamingFrameDecoder({ ...caps, credential });
      const raws = [],
        frames = [];
      for (const chunk of chunks) {
        const result = d.push(chunk);
        if (result.raw) raws.push(result.raw);
        frames.push(...result.frames);
        if (result.reason) {
          assert.throws(() => d.push(Buffer.alloc(0)), /stopped/);
          break;
        }
      }
      const summary = d.finish();
      assert.deepEqual(
        raws.map(({ bodyBase64, bodyBytes, bodySha256, truncated }) => [
          bodyBase64,
          bodyBytes,
          bodySha256,
          truncated ?? false,
        ]),
        expected.raws.map(({ bytes, truncated }) => [
          bytes.toString("base64"),
          bytes.length,
          sha(bytes),
          truncated,
        ]),
      );
      assert.deepEqual(
        frames.map((frame) => [frame.index, frame.bodyBase64, frame.bodyBytes, frame.bodySha256]),
        expected.frames.map((bytes, index) => [
          index,
          bytes.toString("base64"),
          bytes.length,
          sha(bytes),
        ]),
      );
      assert.equal(summary.reason, expected.reason);
      assert.equal(summary.outcome, expected.reason ? "inconclusive-framing" : "complete-framing");
      assert.equal(summary.frames, expected.frames.length);
      assert.equal(summary.bytes, expected.bytes);
      assert.equal(summary.chunks, expected.raws.length);
      if (secret)
        assert.ok(!Buffer.concat(expected.raws.map(({ bytes }) => bytes)).includes(secret));
      return expected.reason ?? "complete";
    },
    [
      "complete",
      "chunk-count",
      "credential-reflection",
      "total-bound",
      "compression",
      "frame-bound",
      "frame-count",
      "truncated-frame",
    ],
  ),
);

test(
  "well-formed streams round-trip through any partition with complete framing",
  forAll("frames-roundtrip", async (r) => {
    const { createStreamingFrameDecoder } = await load("streaming-frames.mjs");
    const messages = Array.from({ length: r.int(0, 8) }, () => r.bytes(r.int(0, 40)));
    const stream = Buffer.concat(messages.map(envelope));
    const chunks = partition(r, stream, 64);
    const d = createStreamingFrameDecoder({
      maxFrameBytes: 40,
      maxTotalBytes: stream.length || 1,
      maxFrames: 8,
      maxChunks: 64,
    });
    const raw = [],
      frames = [];
    for (const chunk of chunks) {
      const result = d.push(chunk);
      assert.equal(result.reason, undefined);
      raw.push(Buffer.from(result.raw.bodyBase64, "base64"));
      frames.push(...result.frames);
    }
    assert.deepEqual(Buffer.concat(raw), stream);
    assert.deepEqual(
      frames.map((frame) => Buffer.from(frame.bodyBase64, "base64")),
      messages,
    );
    assert.deepEqual(d.finish(), {
      outcome: "complete-framing",
      frames: messages.length,
      bytes: stream.length,
      chunks: chunks.length,
    });
  }),
);

test(
  "the write gate envelope decodes back to the exact payload from any byte view",
  forAll("gate-envelope", async (r) => {
    const { createStreamingWriteGate } = await load("streaming-write-gate.mjs");
    const { createStreamingFrameDecoder } = await load("streaming-frames.mjs");
    const payload = r.bytes(r.int(0, 48));
    const before = r.int(0, 9),
      backing = new Uint8Array(before + payload.length + r.int(0, 9));
    for (let i = 0; i < backing.length; i++) backing[i] = r.int(0, 255);
    backing.set(payload, before);
    const view = new Uint8Array(backing.buffer, before, payload.length);
    const issued = [],
      intents = [];
    const g = createStreamingWriteGate({
      maxFrames: 1,
      maxFrameBytes: 48,
      maxOutgoingBytes: 53,
      maxActions: 2,
      wallMs: 60000,
      guard: () => {},
      liveCheck: () => true,
      persist: (row) => intents.push(row),
      issue: (_, bytes) => issued.push(bytes),
      contain: () => {},
    });
    await g.open();
    await g.write(view);
    backing.fill(0);
    const wire = issued[1];
    const intent = intents.find((row) => row.kind === "frame" && row.state === "issued");
    assert.equal(intent.frameBytes, payload.length + 5);
    assert.equal(intent.frameBase64, wire.toString("base64"));
    assert.equal(intent.frameSha256, sha(wire));
    const d = createStreamingFrameDecoder({
      maxFrameBytes: 48,
      maxTotalBytes: 53,
      maxFrames: 1,
      maxChunks: 1,
    });
    const decoded = d.push(wire);
    assert.deepEqual(
      decoded.frames.map((frame) => Buffer.from(frame.bodyBase64, "base64")),
      [payload],
    );
    assert.equal(d.finish().outcome, "complete-framing");
    const result = await g.done();
    assert.equal(result.outgoingBytes, payload.length + 5);
    assert.equal(result.terminationRequired, false);
  }),
);

// Reference journal: sequential bookkeeping with the drain applied at explicit flush points.
function modelJournal({ maxEntries, maxEntryBytes, maxTotalBytes }) {
  const state = { entries: 0, totalBytes: 0, acknowledged: 0, reason: undefined, halted: false },
    queued = [],
    outcomes = [];
  return {
    state,
    outcomes,
    append({ valid, length, fail }) {
      if (state.reason) return "throws";
      let refusal;
      if (!valid) refusal = "invalid-record";
      else if (state.entries >= maxEntries) refusal = "entry-bound";
      else if (length > maxEntryBytes) refusal = "entry-byte-bound";
      else if (length > maxTotalBytes - state.totalBytes) refusal = "total-byte-bound";
      if (refusal) {
        state.reason = refusal;
        return "throws";
      }
      queued.push({ index: state.entries++, fail });
      state.totalBytes += length;
      return "admitted";
    },
    flush() {
      for (const { index, fail } of queued.splice(0)) {
        if (state.halted || fail) {
          state.reason ??= "persistence";
          state.halted = true;
          outcomes[index] = "rejected";
        } else {
          state.acknowledged++;
          outcomes[index] = "committed";
        }
      }
    },
  };
}

test(
  "journal counters, refusals and commit outcomes match the reference model for random operation sequences",
  forAll(
    "journal-model",
    async (r) => {
      const { createStreamingJournal } = await load("streaming-journal.mjs");
      const bounds = {
        maxEntries: r.int(1, 8),
        maxEntryBytes: r.int(1, 24),
        maxTotalBytes: r.int(1, 64),
      };
      const model = modelJournal(bounds);
      const failing = new Set(),
        written = [],
        tickets = [];
      let stops = 0;
      const j = createStreamingJournal({
        ...bounds,
        deadlineAt: performance.now() + 60000,
        write: async (row) => {
          if (failing.has(row.index)) throw new Error("lost acknowledgement");
          written.push(row);
        },
        stopOwned: () => stops++,
      });
      for (let step = r.int(0, 14); step > 0; step--) {
        if (r.chance(0.25)) {
          await new Promise((resolve) => setImmediate(resolve));
          model.flush();
          continue;
        }
        const op = { valid: !r.chance(0.08), length: r.int(0, 30), fail: r.chance(0.12) };
        const input = op.valid ? r.bytes(op.length) : "not bytes";
        const expected = model.append(op);
        if (expected === "throws") {
          assert.throws(() => j.append(input), /journal stopped/);
          continue;
        }
        if (op.fail) failing.add(model.state.entries - 1);
        const ticket = j.append(input);
        assert.equal(ticket.index, model.state.entries - 1);
        tickets.push({ ticket, bytes: input });
      }
      model.flush();
      const result = await j.done();
      assert.equal(result.entries, model.state.entries);
      assert.equal(result.totalBytes, model.state.totalBytes);
      assert.equal(result.acknowledgedEntries, model.state.acknowledged);
      assert.equal(result.unknownEntries, model.state.entries - model.state.acknowledged);
      assert.equal(result.reason, model.state.reason);
      assert.deepEqual(result.pendingCallbacks, []);
      assert.equal(result.terminationRequired, false);
      assert.equal(stops, 1);
      for (const { ticket, bytes } of tickets) {
        const settled = await ticket.committed.then(
          (receipt) => receipt,
          () => "rejected",
        );
        if (model.outcomes[ticket.index] === "rejected") assert.equal(settled, "rejected");
        else
          assert.deepEqual(settled, {
            index: ticket.index,
            sha256: sha(bytes),
            bodyBytes: bytes.length,
          });
      }
      assert.deepEqual(
        written.map((row) => row.index),
        tickets.map(({ ticket }) => ticket.index).filter((i) => model.outcomes[i] === "committed"),
      );
      return model.state.reason ?? "clean";
    },
    [
      "clean",
      "invalid-record",
      "entry-bound",
      "entry-byte-bound",
      "total-byte-bound",
      "persistence",
    ],
  ),
);

const LIFECYCLE = [
  "end",
  "close",
  "error",
  "goaway",
  "reset",
  "abort",
  "local-cancel",
  "half-close",
];
// Reference receipt queue admission: first refusal wins and every later event is refused. Raw
// receipts of admitted events are always persisted, but candidate frames still queued when a stop
// is recorded never reach the observer.
function modelReceipts({ maxHeaderBytes, maxHeaderEvents, maxHeaderPairs, maxEvents }) {
  const state = { reason: undefined, kinds: [], headerBytes: 0, headerEvents: 0, payloads: [] },
    queued = [];
  const refuse = (why) => {
    state.reason ??= why;
    return false;
  };
  const admit = () => !state.reason && (state.kinds.length < maxEvents || refuse("event-bound"));
  return {
    state,
    data(payload) {
      if (!admit()) return false;
      state.kinds.push("data");
      queued.push(payload);
      return true;
    },
    headers(kind, raw, flags) {
      if (!admit()) return false;
      const shapeOk =
        ["response", "trailers", "additional"].includes(kind) &&
        Number.isInteger(flags) &&
        flags >= 0 &&
        flags <= 255 &&
        raw.length % 2 === 0;
      if (!shapeOk) return refuse("invalid-headers");
      if (state.headerEvents >= maxHeaderEvents) return refuse("header-event-bound");
      if (raw.length > maxHeaderPairs * 2) return refuse("header-pair-bound");
      let size = 0;
      for (const value of raw) {
        size += Buffer.byteLength(value);
        if (state.headerBytes + size > maxHeaderBytes) return refuse("header-bound");
      }
      state.headerBytes += size;
      state.headerEvents++;
      state.kinds.push(kind);
      return true;
    },
    lifecycle(kind) {
      if (!admit()) return false;
      if (!LIFECYCLE.includes(kind)) return refuse("invalid-lifecycle");
      state.kinds.push(kind);
      return true;
    },
    flush() {
      if (!state.reason) state.payloads.push(...queued);
      queued.length = 0;
    },
  };
}

test(
  "receipt queue admission, bounds and durable-before-visible order match the reference model",
  forAll(
    "receipts-model",
    async (r) => {
      const { createStreamingReceiptQueue } = await load("streaming-receipts.mjs");
      const bounds = {
        maxHeaderBytes: r.int(1, 40),
        maxHeaderEvents: r.int(1, 4),
        maxHeaderPairs: r.int(1, 3),
        maxEvents: r.int(1, 10),
      };
      const model = modelReceipts(bounds);
      const order = [],
        persisted = [],
        observed = [];
      let stops = 0;
      const q = createStreamingReceiptQueue({
        maxFrameBytes: 16,
        maxTotalBytes: 4096,
        maxFrames: 64,
        maxChunks: 64,
        ...bounds,
        wallMs: 60000,
        persist: async (row) => {
          persisted.push(row);
          order.push(`persist:${row.index}`);
        },
        onFrame: async (frame) => {
          observed.push(frame);
          order.push(`frame:${persisted.length - 1}`);
        },
        stopOwned: () => stops++,
      });
      const text = () => "abcdefgh".slice(0, r.int(0, 8));
      for (let step = r.int(0, 14); step > 0; step--) {
        const choice = r.int(0, 3);
        if (choice === 3) {
          await new Promise((resolve) => setImmediate(resolve));
          model.flush();
        } else if (choice === 0) {
          const payload = r.bytes(r.int(0, 16));
          assert.equal(q.data(envelope(payload)), model.data(payload));
        } else if (choice === 1) {
          const kind = r.chance(0.9) ? r.pick(["response", "trailers", "additional"]) : "bogus";
          const flags = r.chance(0.9) ? r.int(0, 255) : r.pick([-1, 256, 1.5]);
          const raw = Array.from({ length: r.int(0, 7) }, text);
          assert.equal(q.headers(kind, raw, flags), model.headers(kind, raw, flags));
        } else {
          const kind = r.chance(0.9) ? r.pick(LIFECYCLE) : "bogus";
          assert.equal(q.lifecycle(kind), model.lifecycle(kind));
        }
      }
      const result = await q.done();
      model.flush();
      const kinds = model.state.kinds;
      assert.equal(result.events, kinds.length);
      assert.equal(result.persistedEvents, kinds.length);
      assert.equal(result.unknownEvents, 0);
      assert.equal(result.reason, model.state.reason);
      assert.equal(result.headerBytes, model.state.headerBytes);
      assert.equal(result.headerEvents, model.state.headerEvents);
      assert.equal(result.frameAttempts, model.state.payloads.length);
      assert.equal(result.acknowledgedFrames, model.state.payloads.length);
      assert.equal(result.terminationRequired, false);
      assert.equal(stops, 1);
      assert.deepEqual(
        persisted.map((row) => [row.index, row.kind]),
        kinds.map((kind, index) => [index, kind]),
      );
      assert.deepEqual(
        observed.map((frame) => [frame.index, Buffer.from(frame.bodyBase64, "base64")]),
        model.state.payloads.map((payload, index) => [index, payload]),
      );
      for (const entry of order.filter((item) => item.startsWith("frame:"))) {
        const row = Number(entry.slice(6));
        assert.equal(persisted[row].kind, "data");
        assert.ok(order.indexOf(`persist:${row}`) < order.indexOf(entry));
      }
      return model.state.reason ?? "clean";
    },
    [
      "clean",
      "event-bound",
      "invalid-headers",
      "header-event-bound",
      "header-pair-bound",
      "header-bound",
      "invalid-lifecycle",
    ],
  ),
);
