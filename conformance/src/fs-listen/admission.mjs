// The recorder's admission check, read-only: it never takes or releases a lock and never writes
// the sandbox ledger (the coordinator does both). A production recording starts only when the
// coordinator holds the project's lock, no legacy shared lock exists, and the project's last run
// ended at least 30 minutes ago (owner decision 2026-10-05, ledger 821: a run that only read and
// stopped is exempt, when its ledger row says `readOnlyStop: true`).

import { dirname, join } from "node:path";

export const MIN_SPACING_MS = 30 * 60_000;
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const ENDS = new Set(["finished", "cleanup-verified", "needs-recovery"]);

/** The lock file of `project` beside `ledger` (`<ledger dir>/sandbox-locks/<project>.lock`). */
export function lockPathOf(ledger, project) {
  if (!PROJECT_ID.test(project)) throw new Error(`${project} is not a project ID`);
  return join(dirname(ledger), "sandbox-locks", `${project}.lock`);
}

const timeOf = (row) => {
  const time = Date.parse(row.ts);
  if (!Number.isFinite(time))
    throw new Error(`a ledger row of ${row.project} has no readable time`);
  return time;
};

/** The latest run end of `project`, and the latest start that no end follows. */
export function lastRunEnd(text, project) {
  let end;
  let start;
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    let row;
    try {
      row = JSON.parse(line);
    } catch {
      if (line.includes(project)) throw new Error(`a ledger line for ${project} cannot be read`);
      continue;
    }
    if (row?.project !== project) continue;
    if (ENDS.has(row.event) && (!end || timeOf(row) >= timeOf(end))) end = row;
    if (row.event === "started" && (!start || timeOf(row) >= timeOf(start))) start = row;
  }
  const openStart = start && (!end || timeOf(start) > timeOf(end)) ? start : undefined;
  return { end, openStart };
}

/**
 * Refuses (throws) unless the recording may start. Returns the lock holder and the time the last
 * run ended. `readFile` and `now` are injected for tests.
 */
export async function checkAdmission({ ledger, project, now = () => Date.now(), readFile }) {
  const lockPath = lockPathOf(ledger, project);
  const present = async (path) => {
    try {
      return await readFile(path, "utf8");
    } catch (error) {
      if (error.code === "ENOENT") return undefined;
      throw error;
    }
  };
  if ((await present(`${ledger}.lock`)) !== undefined)
    throw new Error(`the legacy shared lock ${ledger}.lock exists`);
  const lockText = await present(lockPath);
  if (lockText === undefined) throw new Error(`the lock of ${project} is not held`);
  let holder;
  try {
    holder = JSON.parse(lockText);
  } catch {
    holder = undefined;
  }
  if (typeof holder?.taskId !== "string" || holder.taskId === "")
    throw new Error(`the lock of ${project} does not name a holder`);
  const text = await present(ledger);
  if (text === undefined) throw new Error(`the ledger ${ledger} cannot be read`);
  const { end, openStart } = lastRunEnd(text, project);
  if (openStart)
    throw new Error(`a run of ${project} started at ${openStart.ts} and has no end in the ledger`);
  if (end) {
    const exempt =
      end.event === "finished" && end.outcome === "stopped-clean" && end.readOnlyStop === true;
    const ago = now() - timeOf(end);
    if (!exempt && ago < MIN_SPACING_MS)
      throw new Error(
        `the last run of ${project} ended only ${Math.floor(ago / 60_000)} minutes ago (30 are needed)`,
      );
  }
  return { holder, lastRunEndAt: end?.ts };
}
