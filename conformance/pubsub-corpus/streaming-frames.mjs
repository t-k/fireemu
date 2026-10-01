// Pure framing candidates only. A guarded caller must persist raw bytes before using messages as evidence.
import { createHash } from "node:crypto";

// Credential screening. A credential is a bare token of 8 to 16384 printable ASCII bytes without
// whitespace ("Bearer <token>" is refused), so every screened form has a fixed length. A screen
// refuses any 8-byte window of the credential, literally, as hex (either case), as %XX escapes
// (either case) and as base64 (standard or URL alphabet, all three alignments), across every
// earlier byte it accepted: a refused stream never stores 8 contiguous credential bytes in any of
// these forms.
const WINDOW = 8;
export function validateCredential(credential) {
  if (credential === undefined) return undefined;
  if (
    typeof credential !== "string" ||
    credential.length < WINDOW ||
    credential.length > 16384 ||
    !/^[\x21-\x7e]+$/.test(credential)
  )
    throw new Error("bounded credential required");
  return credential;
}
export function createCredentialScreen(credential) {
  const secret = Buffer.from(validateCredential(credential), "latin1");
  const literal = new Set(),
    hex = new Set(),
    percent = new Set(),
    base64 = new Set();
  for (let at = 0; at + WINDOW <= secret.length; at++) {
    const window = secret.subarray(at, at + WINDOW);
    literal.add(window.toString("latin1"));
    const pairs = window.toString("hex");
    hex.add(pairs);
    percent.add(pairs.replace(/../g, "%$&"));
    // Only the characters that depend on the window's bytes alone: 10 at every alignment.
    for (const [lead, from] of [
      [0, 0],
      [1, 2],
      [2, 3],
    ])
      base64.add(
        Buffer.concat([Buffer.alloc(lead), window])
          .toString("base64")
          .slice(from, from + 10),
      );
  }
  const forms = [
    [literal, WINDOW, (text) => text],
    [hex, 16, (text) => text.toLowerCase()],
    [percent, 24, (text) => text.toLowerCase()],
    [base64, 10, (text) => text.replaceAll("-", "+").replaceAll("_", "/")],
  ];
  const keep = 24 - 1;
  let tail = "";
  // Scans the earlier tail followed by the given parts. On a match the tail is unchanged and the
  // caller must refuse the parts unstored; otherwise the parts are accepted into the tail.
  function refuses(parts) {
    const text = tail + parts.map((part) => Buffer.from(part).toString("latin1")).join("");
    for (const [needles, length, normalize] of forms) {
      const view = normalize(text);
      for (let at = 0; at + length <= view.length; at++)
        if (needles.has(view.slice(at, at + length))) return true;
    }
    tail = text.slice(Math.max(0, text.length - keep));
    return false;
  }
  return { refuses };
}
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
  const screen = credential === undefined ? undefined : createCredentialScreen(credential);
  let pending = Buffer.alloc(0),
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
    if (screen?.refuses([chunk])) {
      reason = "credential-reflection";
      return { frames: [], reason };
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
