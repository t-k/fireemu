import { openSync, closeSync, writeFileSync, fsyncSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { sanitize } from "../pubsub-production/capture.mjs";
import { sha256 } from "../pubsub-production/admission.mjs";
import { CAPS } from "./plan.mjs";
export function createJournal(out, runId) {
  mkdirSync(out, { recursive: true, mode: 0o700 });
  const fd = openSync(resolve(out, `capture-${runId}.jsonl`), "wx", 0o600);
  let n = 0,
    frame = 0,
    bytes = 0,
    closed = false;
  const journal = {
    write(value) {
      if (closed) throw new Error("closed journal");
      const line = `${JSON.stringify({ n: ++n, at: new Date().toISOString(), ...sanitize(value) })}\n`;
      bytes += Buffer.byteLength(line);
      if (bytes > 80 * 1024 * 1024 || n > 20000) throw new Error("journal bound exhausted");
      writeFileSync(fd, line);
      fsyncSync(fd);
    },
    frame(raw, value) {
      if (
        !Buffer.isBuffer(raw) ||
        raw.length > CAPS.frameBytes ||
        frame >= CAPS.framesOut + CAPS.framesIn
      )
        throw new Error("raw frame persistence bound");
      const path = `frame-${runId}-${String(++frame).padStart(4, "0")}.pb`;
      const handle = openSync(resolve(out, path), "wx", 0o600);
      try {
        writeFileSync(handle, raw);
        fsyncSync(handle);
      } finally {
        closeSync(handle);
      }
      journal.write({ ...value, blob: { path, bytes: raw.length, sha256: sha256(raw) } });
    },
    close() {
      if (!closed) {
        closed = true;
        closeSync(fd);
      }
    },
  };
  return journal;
}
export function writeExclusive(path, value) {
  const fd = openSync(path, "wx", 0o600);
  try {
    writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
