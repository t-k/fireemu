import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { test } from "node:test";

const target = new URL("../pubsub-corpus/streaming-frames.mjs", import.meta.url);
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
function frame(payload) {
  const header = Buffer.alloc(5);
  header.writeUInt32BE(payload.length, 1);
  return Buffer.concat([header, payload]);
}
async function decoder(extra = {}) {
  assert.ok(existsSync(target), "incremental streaming frame decoder is missing");
  const { createStreamingFrameDecoder } = await import(target.href);
  return createStreamingFrameDecoder({
    maxFrameBytes: 64,
    maxTotalBytes: 1024,
    maxFrames: 16,
    maxChunks: 64,
    ...extra,
  });
}
test("every two-part split preserves the exact raw bytes and candidate message order", async () => {
  const payloads = [Buffer.from([10, 3, 0, 255, 128]), Buffer.alloc(0), Buffer.from("tail")];
  const wire = Buffer.concat(payloads.map(frame));
  for (let split = 1; split < wire.length; split++) {
    const d = await decoder();
    const parts = [wire.subarray(0, split), wire.subarray(split)];
    const results = parts.map((part) => d.push(part));
    assert.deepEqual(
      Buffer.concat(results.map((r) => Buffer.from(r.raw.bodyBase64, "base64"))),
      wire,
    );
    assert.deepEqual(
      results.flatMap((r) => r.frames.map((f) => Buffer.from(f.bodyBase64, "base64"))),
      payloads,
    );
    assert.deepEqual(
      results.flatMap((r) => r.frames.map((f) => f.index)),
      [0, 1, 2],
    );
    assert.deepEqual(d.finish(), {
      outcome: "complete-framing",
      frames: 3,
      bytes: wire.length,
      chunks: 2,
    });
  }
});
test("single-byte chunks and coalesced frames preserve empty messages and hashes", async () => {
  const payloads = [Buffer.alloc(0), Buffer.from([255, 0, 127])];
  const wire = Buffer.concat(payloads.map(frame));
  for (const chunks of [[wire], [...wire].map((b) => Buffer.from([b]))]) {
    const d = await decoder();
    const rows = chunks.map((chunk) => d.push(chunk));
    for (let i = 0; i < rows.length; i++) {
      assert.equal(rows[i].raw.bodyBytes, chunks[i].length);
      assert.equal(rows[i].raw.bodySha256, sha(chunks[i]));
    }
    assert.deepEqual(
      rows.flatMap((r) => r.frames).map((r) => [r.bodyBytes, r.bodySha256]),
      payloads.map((p) => [p.length, sha(p)]),
    );
    assert.equal(d.finish().outcome, "complete-framing");
  }
});
test("mutable input and returned bytes cannot change an unfinished header or later message", async () => {
  const d = await decoder();
  const bytes = frame(Buffer.from("hello"));
  const prefix = Buffer.from(bytes.subarray(0, 3));
  const first = d.push(prefix);
  prefix.fill(255);
  first.raw.bodyBase64 = "invalid caller edit";
  const result = d.push(bytes.subarray(3));
  assert.equal(Buffer.from(result.frames[0].bodyBase64, "base64").toString(), "hello");
  assert.equal(d.finish().outcome, "complete-framing");
});
test("compressed and oversized advertised frames retain bounded raw bytes and halt", async () => {
  for (const wire of [Buffer.from([1, 0, 0, 0, 0]), Buffer.from([0, 255, 255, 255, 255])]) {
    const d = await decoder();
    const result = d.push(wire);
    assert.deepEqual(Buffer.from(result.raw.bodyBase64, "base64"), wire);
    assert.equal(result.frames.length, 0);
    assert.ok(["compression", "frame-bound"].includes(result.reason));
    assert.equal(d.finish().outcome, "inconclusive-framing");
    assert.throws(() => d.push(frame(Buffer.alloc(0))), /stopped/);
  }
});
test("frame chunk and total-byte caps are independent and cannot be bypassed by empty chunks", async () => {
  for (const [bounds, inputs, reason] of [
    [{ maxFrames: 1 }, [frame(Buffer.alloc(0)), frame(Buffer.alloc(0))], "frame-count"],
    [{ maxChunks: 1 }, [Buffer.alloc(0), Buffer.alloc(0)], "chunk-count"],
    [{ maxTotalBytes: 6 }, [frame(Buffer.from([1])), Buffer.from([1, 2])], "total-bound"],
  ]) {
    const d = await decoder(bounds);
    const results = inputs.map((input) => d.push(input));
    assert.equal(results.at(-1).reason, reason);
    const summary = d.finish();
    assert.equal(summary.outcome, "inconclusive-framing");
    assert.ok(summary.bytes <= (bounds.maxTotalBytes ?? 1024));
    assert.ok(summary.chunks <= (bounds.maxChunks ?? 64));
    assert.ok(summary.frames <= (bounds.maxFrames ?? 16));
    assert.throws(() => d.push(Buffer.alloc(0)), /stopped/);
  }
  const d = await decoder({ maxTotalBytes: 3 });
  const result = d.push(Buffer.from([0, 0, 0, 0, 0]));
  assert.equal(result.raw.truncated, true);
  assert.equal(result.raw.bodyBase64, "AAAA");
});
test("finish detects every incomplete frame prefix and makes clean closure final", async () => {
  const wire = frame(Buffer.from("payload"));
  for (let size = 1; size < wire.length; size++) {
    const d = await decoder();
    d.push(wire.subarray(0, size));
    const result = d.finish();
    assert.equal(result.outcome, "inconclusive-framing");
    assert.equal(result.reason, "truncated-frame");
    assert.deepEqual(d.finish(), result);
    assert.throws(() => d.push(wire.subarray(size)), /stopped/);
  }
  const d = await decoder();
  const result = d.finish();
  assert.equal(result.outcome, "complete-framing");
  result.outcome = "caller mutation";
  assert.equal(d.finish().outcome, "complete-framing");
  assert.throws(() => d.push(Buffer.alloc(0)), /stopped/);
});
test("a reflected credential completing across any chunk boundary never enters emitted receipts", async () => {
  const credential = "SYNTHETIC-SECRET";
  const wire = frame(Buffer.from(credential));
  for (let split = 0; split < wire.length; split++) {
    const d = await decoder({ credential });
    const first = d.push(wire.subarray(0, split));
    const second = d.push(wire.subarray(split));
    assert.equal(second.reason, "credential-reflection");
    assert.equal(second.raw, undefined);
    assert.equal(second.frames.length, 0);
    const recorded = Buffer.from(first.raw.bodyBase64, "base64");
    assert.equal(recorded.includes(Buffer.from(credential)), false);
    assert.equal(d.finish().outcome, "inconclusive-framing");
  }
});
test("invalid or unbounded decoder inputs are refused before framing", async () => {
  for (const bound of [0, -1, Infinity, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    for (const key of ["maxFrameBytes", "maxTotalBytes", "maxFrames", "maxChunks"]) {
      await assert.rejects(decoder({ [key]: bound }), /finite/);
    }
  }
  const d = await decoder();
  for (const bad of ["bytes", [0, 0], null, undefined]) assert.throws(() => d.push(bad), /bytes/);
});
test("all512partitions of two empty messages preserve frame count and exact concatenated raw bytes", async () => {
  const wire = Buffer.concat([frame(Buffer.alloc(0)), frame(Buffer.alloc(0))]);
  for (let mask = 0; mask < 512; mask++) {
    const d = await decoder({ maxFrames: 2, maxChunks: 10, maxTotalBytes: 10 });
    let start = 0;
    const rows = [];
    for (let end = 1; end <= wire.length; end++) {
      if (end === wire.length || mask & (1 << (end - 1))) {
        rows.push(d.push(wire.subarray(start, end)));
        start = end;
      }
    }
    assert.equal(rows.flatMap((row) => row.frames).length, 2);
    assert.deepEqual(
      Buffer.concat(rows.map((row) => Buffer.from(row.raw.bodyBase64, "base64"))),
      wire,
    );
    assert.deepEqual(d.finish(), {
      outcome: "complete-framing",
      frames: 2,
      bytes: 10,
      chunks: rows.length,
    });
  }
});
test("exact message-size and every other cap boundary is accepted while the next byte is refused", async () => {
  const d = await decoder({ maxFrameBytes: 64, maxFrames: 1, maxChunks: 1, maxTotalBytes: 69 });
  assert.equal(d.push(frame(Buffer.alloc(64, 255))).frames[0].bodyBytes, 64);
  assert.equal(d.finish().outcome, "complete-framing");
  const tooLarge = await decoder();
  assert.equal(tooLarge.push(frame(Buffer.alloc(65))).reason, "frame-bound");
});
