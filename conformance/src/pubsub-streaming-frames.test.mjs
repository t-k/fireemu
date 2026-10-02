import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { promisify } from "node:util";

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
// Decoding runs in a child process so a frame loop that never consumes its buffer fails an assertion
// instead of freezing the test process. The second child test also gives the test runner an event
// loop turn to report the first one before any later in-process test could spin.
// Keep both child-process tests first in this file: a later position lets a spinning in-process
// test freeze the runner before the child test's failure is reported.
async function decodeInChild(chunks) {
  const script = `const [target, input] = process.argv.slice(1);
    const { createStreamingFrameDecoder } = await import(target);
    const d = createStreamingFrameDecoder({ maxFrameBytes: 64, maxTotalBytes: 1024, maxFrames: 16, maxChunks: 64 });
    const pushed = JSON.parse(input).map((hex) => {
      const result = d.push(Buffer.from(hex, "hex"));
      return { frames: result.frames.map((f) => [f.index, f.bodyBytes]), reason: result.reason ?? null };
    });
    process.stdout.write(JSON.stringify({ pushed, finish: d.finish() }));`;
  try {
    const { stdout } = await promisify(execFile)(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        script,
        target.href,
        JSON.stringify(chunks.map((chunk) => chunk.toString("hex"))),
      ],
      { timeout: 8000, killSignal: "SIGKILL" },
    );
    return JSON.parse(stdout);
  } catch (error) {
    return error.killed ? "decoding did not return" : `decoding failed: ${error.stderr}`;
  }
}
test("pushing complete frames returns their candidates instead of spinning on the buffered bytes", async () => {
  const wire = Buffer.concat([
    frame(Buffer.from("a")),
    frame(Buffer.alloc(0)),
    Buffer.from([0, 0]),
  ]);
  assert.deepEqual(await decodeInChild([wire]), {
    pushed: [
      {
        frames: [
          [0, 1],
          [1, 0],
        ],
        reason: null,
      },
    ],
    finish: {
      outcome: "inconclusive-framing",
      frames: 2,
      bytes: 13,
      chunks: 1,
      reason: "truncated-frame",
    },
  });
});
test("a frame completed by a later push is returned once the buffered prefix is consumed", async () => {
  const wire = frame(Buffer.from("split"));
  assert.deepEqual(await decodeInChild([wire.subarray(0, 3), wire.subarray(3)]), {
    pushed: [
      { frames: [], reason: null },
      { frames: [[0, 5]], reason: null },
    ],
    finish: { outcome: "complete-framing", frames: 1, bytes: 10, chunks: 2 },
  });
});
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
test("no emitted receipt holds the credential's first eight bytes, across any two or three chunks", async () => {
  // Screening matches the first eight bytes of the credential, so a chunk that ends partway into a
  // reflected credential cannot persist more than seven of its bytes.
  const credential = "SYNTHETIC-SECRET";
  const prefix = Buffer.from(credential).subarray(0, 8);
  const wire = frame(Buffer.from(credential));
  const splits = [];
  for (let first = 0; first <= wire.length; first++)
    for (let second = first; second <= wire.length; second++) splits.push([first, second]);
  for (const [first, second] of splits) {
    const d = await decoder({ credential });
    const parts = [wire.subarray(0, first), wire.subarray(first, second), wire.subarray(second)];
    const emitted = [];
    let refused;
    for (const part of parts) {
      const result = d.push(part);
      if (result.raw) emitted.push(Buffer.from(result.raw.bodyBase64, "base64"));
      assert.equal(result.frames.length, 0, `${first}/${second}`);
      if (result.reason) {
        refused = result;
        break;
      }
    }
    assert.equal(refused?.reason, "credential-reflection", `${first}/${second}`);
    assert.equal(refused.raw, undefined, `${first}/${second}`);
    assert.equal(Buffer.concat(emitted).includes(prefix), false, `${first}/${second}`);
    assert.ok(Buffer.concat(emitted).length <= 5 + 7, `${first}/${second}`);
    assert.equal(d.finish().outcome, "inconclusive-framing");
  }
});
test("the credential's eight-byte prefix alone is refused, while seven bytes of it are kept as data", async () => {
  const credential = "SYNTHETIC-SECRET";
  const refused = await decoder({ credential });
  const truncated = refused.push(frame(Buffer.from("SYNTHETI")));
  assert.equal(truncated.reason, "credential-reflection");
  assert.equal(truncated.raw, undefined);
  const kept = await decoder({ credential });
  const nearMiss = kept.push(frame(Buffer.from("SYNTHETX-SYNTHET")));
  assert.equal(nearMiss.reason, undefined);
  assert.equal(nearMiss.frames.length, 1);
  assert.equal(kept.finish().outcome, "complete-framing");
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
test("credential screening settings are validated and bounded before framing", async () => {
  // A bare token of 8 to 16384 printable ASCII bytes: "Bearer <token>", whitespace, control and
  // non-ASCII characters and tokens shorter than one screening window are refused.
  for (const credential of [
    "",
    5,
    null,
    Buffer.from("x"),
    "x".repeat(16385),
    "Bearer abcdefgh",
    "tok en12345",
    "tökenabc",
    "a\tbcdefgh",
    "abcdefg",
    "abcdefg\u0000",
  ])
    await assert.rejects(decoder({ credential }), /bounded credential/);
  assert.equal(
    (await decoder({ credential: "abcdefgh" })).push(frame(Buffer.from("x"))).frames.length,
    1,
  );
  const longest = await decoder({ credential: "y".repeat(16384) });
  assert.equal(longest.push(frame(Buffer.from("payload"))).frames.length, 1);
  const multibyte = "é".repeat(8193);
  await assert.rejects(decoder({ credential: multibyte }), /bounded credential/);
});
test("credential screening never matches bytes that were not received", async () => {
  // Seven of eight bytes arrive; an eighth would have to be invented from the empty tail.
  const d = await decoder({ credential: "!!!!!!!!" });
  const result = d.push(frame(Buffer.from("!!!!!!!")));
  assert.equal(result.reason, undefined);
  assert.equal(result.frames.length, 1);
  assert.equal(d.finish().outcome, "complete-framing");
});
test("plain Uint8Array views are accepted as raw bytes", async () => {
  const d = await decoder();
  const wire = frame(Buffer.from("view"));
  const backing = new Uint8Array(wire.length + 4);
  backing.set(wire, 2);
  const result = d.push(new Uint8Array(backing.buffer, 2, wire.length));
  assert.equal(Buffer.from(result.frames[0].bodyBase64, "base64").toString(), "view");
  assert.equal(result.raw.bodyBytes, wire.length);
});
test("a push that is not stopped carries no reason field at all", async () => {
  const d = await decoder();
  const result = d.push(frame(Buffer.from("ok")));
  assert.equal("reason" in result, false);
  assert.equal("reason" in d.push(Buffer.alloc(0)), false);
});
const CREDENTIAL = "SYNTHETIC-SECRET";
// Every screened form of the whole credential, with base64 at all three alignments.
function encodedForms(value = CREDENTIAL) {
  const bytes = Buffer.from(value);
  const pairs = bytes.toString("hex");
  return {
    hex: pairs,
    HEX: pairs.toUpperCase(),
    percent: pairs.replace(/../g, "%$&"),
    PERCENT: pairs.replace(/../g, "%$&").toUpperCase(),
    base64: bytes.toString("base64"),
    "base64+1": Buffer.concat([Buffer.from("x"), bytes]).toString("base64"),
    "base64+2": Buffer.concat([Buffer.from("xy"), bytes]).toString("base64"),
    base64url: Buffer.concat([Buffer.from("~"), bytes]).toString("base64url"),
  };
}
test("encoded reflections of the credential are refused across any three-chunk split", async () => {
  for (const [name, text] of Object.entries(encodedForms())) {
    const wire = frame(Buffer.from(text));
    for (const [first, second] of [
      [0, 0],
      [5, 9],
      [7, wire.length - 3],
      [wire.length - 1, wire.length],
    ]) {
      const d = await decoder({ credential: CREDENTIAL });
      const emitted = [];
      let refused;
      for (const part of [
        wire.subarray(0, first),
        wire.subarray(first, second),
        wire.subarray(second),
      ]) {
        const result = d.push(part);
        if (result.raw) emitted.push(Buffer.from(result.raw.bodyBase64, "base64"));
        if (result.reason) {
          refused = result.reason;
          break;
        }
      }
      assert.equal(refused, "credential-reflection", `${name} ${first}/${second}`);
      assert.ok(Buffer.concat(emitted).length < wire.length, `${name} ${first}/${second}`);
    }
  }
});
test("any eight-byte window of the credential is refused, while seven-byte fragments are data", async () => {
  for (const window of ["IC-SECRET", "C-SECRET", "THETIC-S", "NTHETIC-"]) {
    const d = await decoder({ credential: CREDENTIAL });
    assert.equal(d.push(frame(Buffer.from(`x${window}x`))).reason, "credential-reflection", window);
  }
  // Fragments of seven bytes split by other bytes never form a window.
  const kept = await decoder({ credential: CREDENTIAL });
  const result = kept.push(frame(Buffer.from("SYNTHET IC-SECR ET")));
  assert.equal(result.reason, undefined);
  assert.equal(result.frames.length, 1);
});
test("a compressed frame is stored raw before the compression refusal, so the bridge must require identity encoding", async () => {
  // Documented limit: the screen sees only the bytes as received. gzip content is not inflated.
  const { gzipSync } = await import("node:zlib");
  const payload = gzipSync(Buffer.from(CREDENTIAL));
  const header = Buffer.alloc(5);
  header[0] = 1;
  header.writeUInt32BE(payload.length, 1);
  const d = await decoder({ credential: CREDENTIAL });
  const result = d.push(Buffer.concat([header, payload]));
  assert.equal(result.reason, "compression");
  assert.ok(result.raw);
  assert.equal(result.frames.length, 0);
});
test("every screened form of a window is refused when split at any offset across two chunks", async () => {
  const window = Buffer.from("SYNTHETI");
  const pairs = window.toString("hex");
  const forms = {
    literal: "SYNTHETI",
    hex: pairs,
    percent: pairs.replace(/../g, "%$&"),
    base64: window.toString("base64").slice(0, 10),
  };
  for (const [name, text] of Object.entries(forms)) {
    const wire = frame(Buffer.from(text));
    for (let cut = 6; cut < wire.length; cut++) {
      const d = await decoder({ credential: CREDENTIAL });
      assert.equal(d.push(wire.subarray(0, cut)).reason, undefined, `${name} ${cut}`);
      assert.equal(d.push(wire.subarray(cut)).reason, "credential-reflection", `${name} ${cut}`);
    }
  }
});
test("the URL-safe base64 alphabet is mapped before matching at every alignment", async () => {
  // Windows of this credential encode to "+" and "/" in standard base64, "-" and "_" in URL-safe.
  const credential = `${"~".repeat(12)}${"?".repeat(12)}`;
  const forms = [];
  for (let at = 0; at + 8 <= credential.length; at++)
    for (const lead of ["", "x", "xy"])
      forms.push(Buffer.from(lead + credential.slice(at, at + 8)).toString("base64url"));
  assert.ok(forms.some((form) => form.includes("-")));
  assert.ok(forms.some((form) => form.includes("_")));
  for (const form of forms) {
    const d = await decoder({ credential });
    assert.equal(d.push(frame(Buffer.from(form))).reason, "credential-reflection", form);
  }
});

test("the public credential validator preserves the optional credential", async () => {
  const { validateCredential } = await import(target.href);
  assert.equal(validateCredential(undefined), undefined);
  assert.equal(validateCredential("abcdefgh"), "abcdefgh");
});
test("encoded seven-byte suffixes remain data without a complete credential window", async () => {
  const credential = "abcdefgh";
  for (const lead of ["", "x", "xy"])
    for (let length = 1; length < 8; length++) {
      const encoded = Buffer.from(lead + credential.slice(-length)).toString("base64");
      const d = await decoder({ credential });
      const result = d.push(frame(Buffer.from(encoded)));
      assert.equal(result.reason, undefined, `${lead.length}/${length}: ${encoded}`);
      assert.equal(result.frames.length, 1);
    }
});
