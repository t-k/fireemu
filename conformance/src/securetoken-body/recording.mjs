// One recording against one target, with its own run id, ownership ledger and journal. Kept out of
// run.mjs (the command line) so the tests and the mutation harness load only what a recording needs.

import { appendFileSync } from "node:fs";
import { join } from "node:path";

import { SANDBOX_PROJECT, createContext } from "../auth-account/harness.mjs";
import { closeOwnership, openOwnership } from "../shared/ownership.mjs";
import { ROWS } from "./corpus.mjs";
import { createSession } from "./session.mjs";

/** Request ceilings per recording: the rows, and a separate budget for setup, polls and cleanup. */
export const ceilings = (rows = ROWS) => ({
  maxRequests: rows.length,
  maxHarnessRequests: 160,
});

/** Unique run ids, one per recording: seconds since the epoch, never reused within a process. */
let lastRun = 0;
export function nextRun(now = Date.now()) {
  lastRun = Math.max(Math.floor(now / 1000), lastRun + 1);
  return String(lastRun);
}

/** One recording against a target: its own run id, ownership ledger and journal. */
export async function recordWith(target, dir, n, options = {}) {
  const ctx = createContext({ run: nextRun(), project: SANDBOX_PROJECT, target });
  const ownership = openOwnership({
    path: join(dir, `issued-${n}.jsonl`),
    runId: `stb-${ctx.run}`,
  });
  const journalPath = join(dir, `journal-${n}.jsonl`);
  try {
    const session = createSession(ctx, {
      ...ceilings(),
      ownership,
      journal: (entry) => appendFileSync(journalPath, `${JSON.stringify(entry)}\n`),
      ...options,
    });
    return await session.runRecording();
  } finally {
    closeOwnership(ownership);
  }
}
