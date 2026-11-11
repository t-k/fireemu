import fs from "node:fs";
import path from "node:path";

export function writeExclusive(file, text) {
  fs.writeFileSync(file, text, { flag: "wx", mode: 0o600 });
}

export const MAX_ROWS = 20000;

export function createJournal(dir, runId, { limit = MAX_ROWS } = {}) {
  fs.mkdirSync(dir, { mode: 0o700 });
  const fd = fs.openSync(path.join(dir, `capture-${runId}.jsonl`), "wx", 0o600);
  let n = 0,
    closed = false;
  return {
    write(row) {
      if (closed) throw new Error("journal is closed");
      if (n >= limit) throw new Error("journal row limit");
      fs.writeFileSync(fd, JSON.stringify({ ...row, n: ++n, at: new Date().toISOString() }) + "\n");
      fs.fsyncSync(fd);
    },
    close() {
      if (!closed) {
        closed = true;
        fs.closeSync(fd);
      }
    },
  };
}
