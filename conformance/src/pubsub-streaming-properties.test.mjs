// Seeded property and model-based tests for the offline StreamingPull helpers. Each property
// replays a fixed seed sequence, so a failure names the seed and case that reproduce it.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mock, test } from "node:test";

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
// A property returns the label (or labels) of the case it exercised; every label in mustSee has to
// occur, so a generator that drifts away from a branch fails instead of passing vacuously.
function forAll(name, property, mustSee = []) {
  return async () => {
    const seen = new Set();
    for (let seed = 1; seed <= CASES; seed++) {
      try {
        for (const label of [await property(rng(seed))].flat()) seen.add(label);
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

// Reference credential screen over the whole accepted byte string (the helper keeps a rolling tail
// and window sets): any 8-byte window of the credential, literally, as hex or %XX in either case,
// or as base64 (standard or URL alphabet) at any of the three alignments.
const ENCODINGS = ["literal", "hex", "HEX", "percent", "PERCENT", "base64", "base64url"];
function encodeFragment(bytes, encoding, lead = 0) {
  const pairs = bytes.toString("hex");
  const shifted = Buffer.concat([Buffer.alloc(lead, 0x41), bytes]);
  return Buffer.from(
    {
      literal: () => bytes.toString("latin1"),
      hex: () => pairs,
      HEX: () => pairs.toUpperCase(),
      percent: () => pairs.replace(/../g, "%$&"),
      PERCENT: () => pairs.replace(/../g, "%$&").toUpperCase(),
      base64: () => shifted.toString("base64"),
      base64url: () => shifted.toString("base64url"),
    }[encoding](),
    "latin1",
  );
}
function screenRefuses(bytes, secret) {
  const text = bytes.toString("latin1");
  const lower = text.toLowerCase();
  const standard = text.replaceAll("-", "+").replaceAll("_", "/");
  for (let at = 0; at + 8 <= secret.length; at++) {
    const window = secret.subarray(at, at + 8);
    const pairs = window.toString("hex");
    if (text.includes(window.toString("latin1"))) return true;
    if (lower.includes(pairs) || lower.includes(pairs.replace(/../g, "%$&"))) return true;
    for (const lead of [0, 1, 2]) {
      const encoded = Buffer.concat([Buffer.alloc(lead), window]).toString("base64");
      const from = [0, 2, 3][lead];
      if (standard.includes(encoded.slice(from, from + 10))) return true;
    }
  }
  return false;
}
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
    if (secret && screenRefuses(Buffer.concat([accepted, take]), secret)) {
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
// Inserts a random fragment of the credential (biased to seven and eight bytes) in a random
// encoding, so near misses below eight bytes are generated next to refusals.
function randomStream(r, secret, inserted) {
  const messages = Array.from({ length: r.int(0, 6) }, () => r.bytes(r.int(0, 24)));
  let stream = Buffer.concat(messages.map(envelope));
  if (stream.length && r.chance(0.15)) {
    const at = r.int(0, stream.length - 1);
    stream = Buffer.from(stream);
    stream[at] = r.int(1, 255);
  }
  if (r.chance(0.15)) stream = Buffer.concat([stream, r.bytes(r.int(1, 7))]);
  if (secret && r.chance(0.8)) {
    // Often near the start, so that the total cap rarely clips the longer encoded forms.
    const at = r.chance(0.5) ? r.int(0, Math.min(stream.length, 6)) : r.int(0, stream.length);
    const length = r.pick([7, 8, 8, r.int(1, secret.length)]);
    const start = r.int(0, secret.length - length);
    inserted.encoding = r.pick(ENCODINGS);
    inserted.length = length;
    const fragment = encodeFragment(
      secret.subarray(start, start + length),
      inserted.encoding,
      r.int(0, 2),
    );
    stream = Buffer.concat([stream.subarray(0, at), fragment, stream.subarray(at)]);
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
      const credential = r.chance(0.5)
        ? `secret-${r.int(0, 99)}${"x".repeat(r.int(0, 6))}`
        : undefined;
      const secret = credential && Buffer.from(credential);
      const inserted = {};
      const chunks = partition(r, randomStream(r, secret, inserted), 30);
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
      if (secret) {
        const kept = Buffer.concat(raws.map(({ bodyBase64 }) => Buffer.from(bodyBase64, "base64")));
        assert.equal(screenRefuses(kept, secret), false);
        // A kept literal fragment of seven bytes shows that near misses are not refused.
        if (
          inserted.encoding === "literal" &&
          inserted.length === 7 &&
          expected.reason !== "credential-reflection"
        )
          return [expected.reason ?? "complete", "near-miss-kept"];
        if (inserted.length >= 8 && expected.reason === "credential-reflection")
          return [expected.reason, `refused:${inserted.encoding}`];
      }
      return expected.reason ?? "complete";
    },
    [
      "complete",
      "chunk-count",
      "credential-reflection",
      "near-miss-kept",
      ...ENCODINGS.map((encoding) => `refused:${encoding}`),
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

const ORIGINS = [
  "peer-terminal",
  "client-cancel",
  "revocation",
  "abort",
  "deadline",
  "local-close",
  "uncertain",
];
const FAILURES = [
  "guard-before",
  "persist-before",
  "guard-after",
  "live-false",
  "live-promise",
  "issue-throws",
  "issue-promise",
  "persist-issued",
];
// Reference write gate for awaited, sequential actions: synchronous refusals change nothing,
// admitted actions reserve first and then either complete or stop the gate at their failure point.
function modelGate({ maxFrames, maxFrameBytes, maxOutgoingBytes, maxActions }) {
  const state = {
    attempted: 0,
    issued: 0,
    completed: 0,
    openings: 0,
    frames: 0,
    outgoing: 0,
    direction: "NEW",
    origin: undefined,
    contractBroken: false,
    issueEntered: false,
    seen: new Set(),
  };
  const stop = (origin) => {
    state.origin ??= ORIGINS.includes(origin) ? origin : "uncertain";
  };
  return {
    state,
    stop,
    action(kind, length, failure) {
      if (state.origin) return "throws";
      if (kind === "open" && state.openings) return "throws";
      if (kind !== "open" && state.direction === "NEW") return "throws";
      if ((kind === "frame" || kind === "half-close") && state.direction !== "OPEN")
        return "throws";
      const cap =
        state.attempted >= maxActions
          ? "actions"
          : kind !== "frame"
            ? undefined
            : length > maxFrameBytes
              ? "frame-bytes"
              : state.frames >= maxFrames
                ? "frames"
                : length + 5 > maxOutgoingBytes - state.outgoing
                  ? "outgoing"
                  : undefined;
      if (cap) {
        state.seen.add(`cap:${cap}`);
        return "throws";
      }
      if (failure) state.seen.add(`fail:${failure}`);
      state.attempted++;
      if (kind === "open") state.openings++;
      if (kind === "frame") {
        state.frames++;
        state.outgoing += length + 5;
      }
      if (["guard-before", "persist-before", "guard-after"].includes(failure)) {
        stop("uncertain");
        return "rejects";
      }
      // issue was invoked: a throw may follow sent bytes, so like a Promise return it leaves the
      // outcome to supervised termination.
      if (failure === "issue-throws") {
        state.issueEntered = true;
        stop("uncertain");
        return "rejects";
      }
      if (failure === "live-false") {
        stop("revocation");
        return "rejects";
      }
      // A Promise from a synchronous interface breaks the contract: the work may still run.
      if (failure === "live-promise" || failure === "issue-promise") {
        state.contractBroken = true;
        stop("uncertain");
        return "rejects";
      }
      state.issued++;
      if (kind === "open") state.direction = "OPEN";
      if (kind === "half-close") state.direction = "HALF_CLOSED";
      // The bytes were handed over; a lost issued acknowledgement leaves them to supervised
      // termination too.
      if (failure === "persist-issued") {
        state.issueEntered = true;
        stop("uncertain");
        return "rejects";
      }
      state.completed++;
      if (kind === "client-cancel") stop("client-cancel");
      return "resolves";
    },
  };
}

test(
  "write gate reservations, refusals, failure points, direction and stop origin match the reference model",
  forAll(
    "gate-model",
    async (r) => {
      const { createStreamingWriteGate } = await load("streaming-write-gate.mjs");
      const bounds = {
        maxFrames: r.int(1, 3),
        maxFrameBytes: r.int(1, 12),
        maxOutgoingBytes: r.int(5, 40),
        maxActions: r.int(1, 6),
      };
      const model = modelGate(bounds);
      const containmentFails = r.chance(0.1);
      let failure,
        guardCalls = 0,
        contained = 0;
      const issued = [];
      const g = createStreamingWriteGate({
        ...bounds,
        wallMs: 60000,
        guard: async () => {
          guardCalls++;
          if (failure === (guardCalls === 1 ? "guard-before" : "guard-after"))
            throw new Error("authority lost");
        },
        liveCheck: () =>
          failure === "live-promise" ? Promise.resolve(true) : failure !== "live-false",
        persist: async (row) => {
          if (failure === (row.state === "before-send" ? "persist-before" : "persist-issued"))
            throw new Error("lost acknowledgement");
        },
        issue: (intent, bytes) => {
          if (failure === "issue-throws") throw new Error("native write failed");
          if (failure === "issue-promise") return Promise.resolve();
          issued.push([intent.kind, bytes]);
        },
        contain: async () => {
          contained++;
          if (containmentFails) throw new Error("containment failed");
        },
      });
      const outcomes = new Set();
      for (let step = r.int(1, 10); step > 0; step--) {
        if (r.chance(0.08)) {
          const origin = r.chance(0.8) ? r.pick(ORIGINS) : "bogus";
          g.stop(origin);
          model.stop(origin);
          continue;
        }
        // Open most sequences early so frame caps and failure points are reached, not only the
        // refusals of an unopened gate.
        const kind =
          model.state.direction === "NEW" && r.chance(0.6)
            ? "open"
            : r.pick(["open", "frame", "frame", "frame", "half-close", "client-cancel"]);
        const length = r.int(0, 14);
        failure = r.chance(0.2) ? r.pick(FAILURES) : undefined;
        guardCalls = 0;
        const expected = model.action(kind, length, failure);
        const call = {
          open: () => g.open(),
          frame: () => g.write(r.bytes(length)),
          "half-close": () => g.halfClose(),
          "client-cancel": () => g.cancel(),
        }[kind];
        let actual;
        try {
          const pending = call();
          actual = await pending.then(
            () => "resolves",
            () => "rejects",
          );
        } catch {
          actual = "throws";
        }
        assert.equal(actual, expected, `${kind} with ${failure ?? "no failure"}`);
        outcomes.add(`${kind}:${actual}`);
      }
      const result = await g.done();
      model.stop("local-close");
      const state = model.state;
      assert.deepEqual(
        {
          attemptedActions: result.attemptedActions,
          issuedActions: result.issuedActions,
          completedActions: result.completedActions,
          unknownActions: result.unknownActions,
          openingReservations: result.openingReservations,
          frameReservations: result.frameReservations,
          outgoingBytes: result.outgoingBytes,
          direction: result.direction,
          stopOrigin: result.stopOrigin,
          pendingCallbacks: result.pendingCallbacks,
          terminationRequired: result.terminationRequired,
        },
        {
          attemptedActions: state.attempted,
          issuedActions: state.issued,
          completedActions: state.completed,
          unknownActions: state.attempted - state.completed,
          openingReservations: state.openings,
          frameReservations: state.frames,
          outgoingBytes: state.outgoing,
          direction: state.direction,
          stopOrigin: state.origin,
          pendingCallbacks: [],
          terminationRequired: state.contractBroken || state.issueEntered || containmentFails,
        },
      );
      assert.equal(contained, 1);
      assert.equal(issued.length, state.issued);
      return [state.origin, ...outcomes, ...state.seen];
    },
    [
      ...ORIGINS.filter((origin) => !["abort", "deadline"].includes(origin)),
      "cap:actions",
      "cap:frame-bytes",
      "cap:frames",
      "cap:outgoing",
      ...FAILURES.map((failure) => `fail:${failure}`),
      "open:throws",
      "frame:throws",
      "frame:resolves",
      "frame:rejects",
      "half-close:resolves",
      "client-cancel:resolves",
    ],
  ),
);

// Reference journal: sequential bookkeeping with the drain applied at explicit flush points. A
// hung write blocks the chain until the deadline; past it, the write's own cutoff rejects it and
// every entry queued behind it.
function modelJournal({ maxEntries, maxEntryBytes, maxTotalBytes }, hungAt) {
  const state = {
      entries: 0,
      totalBytes: 0,
      acknowledged: 0,
      reason: undefined,
      halted: false,
      blocked: false,
    },
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
    expire() {
      for (const { index } of queued.splice(0)) outcomes[index] = "rejected";
      state.blocked = false;
    },
    flush() {
      while (queued.length && !state.blocked) {
        const { index, fail } = queued.shift();
        if (!state.halted && index === hungAt) {
          state.blocked = true;
          queued.unshift({ index, fail });
        } else if (state.halted || fail) {
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
const tick = () => new Promise((resolve) => setImmediate(resolve));
// Drives a promise to settlement while setTimeout is mocked: every turn advances mocked timers by
// one millisecond, which fires the helper's overdue cutoffs without any real wait. A helper that
// never settles fails here by assertion instead of spinning.
async function settleWithMockedTimers(promise, maxTurns = 1000) {
  let finished = false;
  const settled = promise.finally(() => {
    finished = true;
  });
  for (let turn = 0; !finished && turn < maxTurns; turn++) {
    mock.timers.tick(1);
    await tick();
  }
  assert.ok(finished, `did not settle within ${maxTurns} mocked milliseconds`);
  return settled;
}
// Moves the mocked monotonic clock and the mocked timers past the deadline together, so every
// timer the helper armed for its deadline fires exactly as it would in real time.
async function passDeadline(setNow, deadlineAt, startedAt) {
  setNow(deadlineAt + 1);
  mock.timers.tick(deadlineAt + 1 - startedAt);
  await tick();
}
// End-of-case drain mode: done before the deadline, done after it, or (with a hung callback)
// done started before the deadline that then passes while done is waiting.
function drainMode(r, blocked) {
  if (blocked) return r.chance(0.5) ? "hung-late" : "hung-waiting";
  return r.chance(0.2) ? "late" : "clean";
}

test(
  "journal counters, refusals, hung writes, late drains and commit outcomes match the reference model",
  forAll(
    "journal-model",
    async (r) => {
      const { createStreamingJournal } = await load("streaming-journal.mjs");
      const bounds = {
        maxEntries: r.int(1, 8),
        maxEntryBytes: r.int(1, 24),
        maxTotalBytes: r.int(1, 64),
      };
      const hungAt = r.chance(0.25) ? r.int(0, 6) : -1;
      const model = modelJournal(bounds, hungAt);
      const failing = new Set(),
        written = [],
        tickets = [];
      let stops = 0,
        now = 1000;
      const clock = mock.method(performance, "now", () => now);
      mock.timers.enable({ apis: ["setTimeout"] });
      try {
        const deadlineAt = now + 60000;
        const j = createStreamingJournal({
          ...bounds,
          deadlineAt,
          write: async (row) => {
            if (row.index === hungAt) return new Promise(() => {});
            if (failing.has(row.index)) throw new Error("lost acknowledgement");
            written.push(row);
          },
          stopOwned: () => stops++,
        });
        for (let step = r.int(0, 14); step > 0; step--) {
          if (r.chance(0.25)) {
            await tick();
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
        await tick();
        model.flush();
        const blocked = model.state.blocked;
        const mode = drainMode(r, blocked);
        const late = mode !== "clean";
        let result;
        if (mode === "hung-waiting") {
          const draining = j.done();
          await tick();
          await passDeadline((value) => (now = value), deadlineAt, 1000);
          result = await settleWithMockedTimers(draining);
        } else {
          if (late) await passDeadline((value) => (now = value), deadlineAt, 1000);
          result = await settleWithMockedTimers(j.done());
        }
        // Past the deadline the hung write's own cutoff rejects it and the halted chain rejects
        // every entry queued behind it.
        if (late) model.expire();
        const reason = late ? (model.state.reason ?? "deadline") : model.state.reason;
        assert.equal(result.entries, model.state.entries);
        assert.equal(result.totalBytes, model.state.totalBytes);
        assert.equal(result.acknowledgedEntries, model.state.acknowledged);
        assert.equal(result.unknownEntries, model.state.entries - model.state.acknowledged);
        assert.equal(result.reason, reason);
        assert.deepEqual(result.pendingCallbacks, blocked ? [`write:${hungAt}`] : []);
        assert.equal(result.terminationRequired, late);
        assert.equal(stops, 1);
        for (const { ticket, bytes } of tickets) {
          const outcome = model.outcomes[ticket.index];
          const settled = await Promise.race([
            ticket.committed.then(
              (receipt) => receipt,
              () => "rejected",
            ),
            tick().then(() => "unsettled"),
          ]);
          if (outcome === "rejected") assert.equal(settled, "rejected");
          else
            assert.deepEqual(settled, {
              index: ticket.index,
              sha256: sha(bytes),
              bodyBytes: bytes.length,
            });
        }
        assert.deepEqual(
          written.map((row) => row.index),
          tickets
            .map(({ ticket }) => ticket.index)
            .filter((i) => model.outcomes[i] === "committed"),
        );
        return [model.state.reason ?? "clean", mode];
      } finally {
        mock.timers.reset();
        clock.mock.restore();
      }
    },
    [
      "clean",
      "late",
      "hung-late",
      "hung-waiting",
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
// receipts of admitted events are persisted in order at drain points; candidate frames are
// delivered only while no stop is recorded. A hung persist blocks the rest of the chain; a failed
// persist stops admission and no later queued row is persisted.
function modelReceipts(
  { maxHeaderBytes, maxHeaderEvents, maxHeaderPairs, maxEvents },
  hungAt,
  failAt,
) {
  const state = {
      reason: undefined,
      kinds: [],
      headerBytes: 0,
      headerEvents: 0,
      payloads: [],
      persisted: 0,
      blocked: false,
      halted: false,
    },
    queued = [];
  const refuse = (why) => {
    state.reason ??= why;
    return false;
  };
  const admit = () => !state.reason && (state.kinds.length < maxEvents || refuse("event-bound"));
  const enqueue = (kind, payloads = []) => {
    queued.push({ index: state.kinds.length, payloads });
    state.kinds.push(kind);
    return true;
  };
  return {
    state,
    data(payload) {
      return admit() && enqueue("data", [payload]);
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
      return enqueue(kind);
    },
    lifecycle(kind) {
      if (!admit()) return false;
      if (!LIFECYCLE.includes(kind)) return refuse("invalid-lifecycle");
      return enqueue(kind);
    },
    flush() {
      while (queued.length && !state.blocked) {
        // A halted chain never calls persist again, so a hung row behind the failure cannot hang.
        if (state.halted) {
          queued.shift();
          continue;
        }
        if (queued[0].index === hungAt) {
          state.blocked = true;
          break;
        }
        if (queued[0].index === failAt) {
          queued.shift();
          state.halted = true;
          state.reason ??= "persistence";
          continue;
        }
        const { payloads } = queued.shift();
        state.persisted++;
        if (!state.reason) state.payloads.push(...payloads);
      }
    },
  };
}

test(
  "receipt queue admission, bounds, hung persistence, late drains and durable-before-visible order match the reference model",
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
      const failAt = r.chance(0.3) ? r.int(0, 4) : -1;
      // Some hung rows are drawn right behind the failing row, where they must never be persisted.
      const hungAt =
        failAt >= 0 && r.chance(0.5) ? failAt + r.int(1, 2) : r.chance(0.25) ? r.int(0, 8) : -1;
      const model = modelReceipts(bounds, hungAt, failAt);
      const order = [],
        persisted = [],
        observed = [];
      let stops = 0,
        now = 1000;
      const clock = mock.method(performance, "now", () => now);
      mock.timers.enable({ apis: ["setTimeout"] });
      try {
        const q = createStreamingReceiptQueue({
          maxFrameBytes: 16,
          maxTotalBytes: 4096,
          maxFrames: 64,
          maxChunks: 64,
          ...bounds,
          wallMs: 60000,
          persist: async (row) => {
            if (row.index === hungAt) return new Promise(() => {});
            if (row.index === failAt) throw new Error("store refused");
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
            await tick();
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
        await tick();
        model.flush();
        const mode = drainMode(r, model.state.blocked);
        const late = mode !== "clean";
        let result;
        if (mode === "hung-waiting") {
          const draining = q.done();
          await tick();
          await passDeadline((value) => (now = value), 61000, 1000);
          result = await settleWithMockedTimers(draining);
        } else {
          if (late) await passDeadline((value) => (now = value), 61000, 1000);
          result = await settleWithMockedTimers(q.done());
        }
        const kinds = model.state.kinds;
        assert.equal(result.events, kinds.length);
        assert.equal(result.persistedEvents, model.state.persisted);
        assert.equal(result.unknownEvents, kinds.length - model.state.persisted);
        // The queue's own deadline timer records the deadline stop once the clock passes it.
        assert.equal(result.reason, late ? (model.state.reason ?? "deadline") : model.state.reason);
        assert.equal(result.headerBytes, model.state.headerBytes);
        assert.equal(result.headerEvents, model.state.headerEvents);
        assert.equal(result.frameAttempts, model.state.payloads.length);
        assert.equal(result.acknowledgedFrames, model.state.payloads.length);
        assert.deepEqual(result.pendingCallbacks, model.state.blocked ? [`receipt:${hungAt}`] : []);
        assert.equal(result.terminationRequired, late);
        assert.equal(stops, 1);
        assert.deepEqual(
          persisted.map((row) => [row.index, row.kind]),
          kinds.slice(0, model.state.persisted).map((kind, index) => [index, kind]),
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
        return [
          model.state.reason ?? "clean",
          mode,
          ...(observed.length ? ["frame-delivered"] : []),
          ...(model.state.halted && model.state.kinds.length > failAt + 1
            ? ["queued-after-failure"]
            : []),
          ...(model.state.halted && hungAt > failAt && model.state.kinds.length > hungAt
            ? ["hung-behind-failure"]
            : []),
        ];
      } finally {
        mock.timers.reset();
        clock.mock.restore();
      }
    },
    [
      "clean",
      "event-bound",
      "invalid-headers",
      "header-event-bound",
      "header-pair-bound",
      "header-bound",
      "invalid-lifecycle",
      "frame-delivered",
      "persistence",
      "queued-after-failure",
      "hung-behind-failure",
      "late",
      "hung-late",
      "hung-waiting",
    ],
  ),
);
