// Pure framing candidates only. A guarded caller must persist raw bytes before using messages as evidence.
import { createHash } from "node:crypto";

function receipt(bytes) {
  return {
    bodyBase64: bytes.toString("base64"),
    bodyBytes: bytes.length,
    bodySha256: createHash("sha256").update(bytes).digest("hex"),
  };
}
export function createStreamingFrameDecoder({
  maxFrameBytes,
  maxTotalBytes,
  maxFrames,
  maxChunks,
  credential,
}) {
  for (const bound of [maxFrameBytes, maxTotalBytes, maxFrames, maxChunks])
    if (!Number.isSafeInteger(bound) || bound <= 0)
      throw new Error("finite positive framing bounds required");
  if (
    credential !== undefined &&
    (typeof credential !== "string" || !credential || Buffer.byteLength(credential) > 16384)
  )
    throw new Error("bounded credential required");
  const secret = credential === undefined ? undefined : Buffer.from(credential);
  let pending = Buffer.alloc(0),
    tail = Buffer.alloc(0),
    frames = 0,
    bytes = 0,
    chunks = 0,
    reason,
    closed = false;
  function push(input) {
    if (closed || reason) throw new Error("framing is stopped");
    if (!Buffer.isBuffer(input) && !(input instanceof Uint8Array))
      throw new Error("raw bytes required");
    if (chunks >= maxChunks) {
      reason = "chunk-count";
      return { frames: [], reason };
    }
    const chunk = Buffer.from(input.subarray(0, maxTotalBytes - bytes));
    if (secret) {
      const joined = Buffer.concat([tail, chunk]);
      if (joined.includes(secret)) {
        reason = "credential-reflection";
        return { frames: [], reason };
      }
      tail = Buffer.from(joined.subarray(Math.max(0, joined.length - secret.length + 1)));
    }
    bytes += chunk.length;
    chunks++;
    const raw = receipt(chunk);
    if (chunk.length !== input.length) {
      reason = "total-bound";
      return { raw: { ...raw, truncated: true }, frames: [], reason };
    }
    pending = Buffer.concat([pending, chunk]);
    const messages = [];
    while (pending.length >= 5) {
      if (pending[0] !== 0) {
        reason = "compression";
        break;
      }
      const length = pending.readUInt32BE(1);
      if (length > maxFrameBytes) {
        reason = "frame-bound";
        break;
      }
      if (frames >= maxFrames) {
        reason = "frame-count";
        break;
      }
      if (pending.length < length + 5) break;
      messages.push({ index: frames++, ...receipt(pending.subarray(5, length + 5)) });
      pending = Buffer.from(pending.subarray(length + 5));
    }
    return { raw, frames: messages, ...(reason ? { reason } : {}) };
  }
  function finish() {
    closed = true;
    if (!reason && pending.length) reason = "truncated-frame";
    return {
      outcome: reason ? "inconclusive-framing" : "complete-framing",
      frames,
      bytes,
      chunks,
      ...(reason ? { reason } : {}),
    };
  }
  return { push, finish };
}
