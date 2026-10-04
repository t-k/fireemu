// The recorder's admission check, read-only: it never takes or releases a lock and never writes
// the sandbox ledger (the coordinator does both). A production recording starts only when
//   - the coordinator holds the project's lock for this very envelope (task FS-LISTEN-SDK-SANDBOX
//     and the envelope id given with --envelope), and no legacy shared lock exists;
//   - no other run of the project is open in the ledger (the only open row allowed is the
//     coordinator's own `started` row of this envelope);
//   - the latest row of any kind that names the project is at least 30 minutes old (owner decision
//     2026-10-05, ledger 821: a run that only read and stopped is exempt, when its ledger row says
//     `readOnlyStop: true`).
//
// The ledger is heterogeneous. The rows this check reads come in these shapes (all seen in the live
// ledger): `event: started | finished | cleanup-verified | needs-recovery | reserved | note |
// change | progress | GO | ...` with `taskId` (or `task`); the FS-TRANSACTION runner's rows have no
// `event` and `outcome: "reserved"` (an open run) or any other `outcome` (its end); and `project`
// may be one id, a comma-joined list of ids, or an array of ids.

import { dirname, join } from "node:path";

export const MIN_SPACING_MS = 30 * 60_000;
export const TASK_ID = "FS-LISTEN-SDK-SANDBOX";
const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;
const OPENS = new Set(["started", "reserved", "needs-recovery", "GO"]);
const ENDS = new Set(["finished", "cleanup-verified"]);

/** The lock file of `project` beside `ledger` (`<ledger dir>/sandbox-locks/<project>.lock`). */
export function lockPathOf(ledger, project) {
  if (!PROJECT_ID.test(project)) throw new Error(`${project} is not a project ID`);
  return join(dirname(ledger), "sandbox-locks", `${project}.lock`);
}

/** Whether `row.project` names `project`: equal, one of a comma-joined list, or in an array. */
export function namesProject(row, project) {
  const value = row?.project;
  if (typeof value === "string") return value.split(",").some((part) => part.trim() === project);
  if (Array.isArray(value)) return value.includes(project);
  return false;
}

const timeOf = (row) => {
  const time = typeof row.ts === "string" ? Date.parse(row.ts) : row.issuedAt;
  if (!Number.isFinite(time))
    throw new Error(`a ledger row of ${row.project} has no readable time`);
  return time;
};

const taskOf = (row) => row.taskId ?? row.task ?? "";

/** `open`, `end` or `other`, by the row's `event` or, for rows without one, its `outcome`. */
function kindOf(row) {
  if (typeof row.event === "string") {
    if (OPENS.has(row.event)) return "open";
    return ENDS.has(row.event) ? "end" : "other";
  }
  if (typeof row.outcome !== "string") return "other";
  return row.outcome.startsWith("reserved") ? "open" : "end";
}

/** A read-only stop (ledger 821): a finished, stopped-clean row that says `readOnlyStop: true`. */
const isReadOnlyStop = (row) =>
  row.event === "finished" && row.outcome === "stopped-clean" && row.readOnlyStop === true;

/**
 * Reads the rows that name `project`. Returns every such row with its time, the runs still open
 * (an open row that no later end row of the same task followed) and, for the spacing, the rows
 * that count (everything except read-only stops and the rows they closed).
 */
export function projectRows(text, project) {
  const entries = [];
  const open = new Map();
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    let row;
    try {
      row = JSON.parse(line);
    } catch {
      if (line.includes(project)) throw new Error(`a ledger line for ${project} cannot be read`);
      continue;
    }
    if (!namesProject(row, project)) continue;
    const entry = { row, time: timeOf(row), counts: true };
    entries.push(entry);
    const task = taskOf(row);
    const kind = kindOf(row);
    if (kind === "open") open.set(task, [...(open.get(task) ?? []), entry]);
    if (kind === "end") {
      const exempt = isReadOnlyStop(row);
      if (exempt) {
        entry.counts = false;
        for (const closed of open.get(task) ?? []) closed.counts = false;
      }
      open.delete(task);
    }
  }
  return { entries, open: [...open.values()].flat() };
}

/** The latest time of a row that counts for the spacing. */
function latestCounting(entries, ignored) {
  let latest;
  for (const entry of entries)
    if (entry.counts && !ignored.has(entry) && (!latest || entry.time >= latest.time))
      latest = entry;
  return latest;
}

/**
 * Refuses (throws) unless the recording may start. Returns the lock holder and the time of the
 * latest row that counted. `readFile` and `now` are injected for tests.
 */
export async function checkAdmission({
  ledger,
  project,
  envelope,
  now = () => Date.now(),
  readFile,
}) {
  if (typeof envelope !== "string" || envelope === "")
    throw new Error("--envelope <envelope id> is required");
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
  if (holder.taskId !== TASK_ID)
    throw new Error(`the lock of ${project} is held by ${holder.taskId}, not by ${TASK_ID}`);
  if ((holder.envelopeId ?? holder.packetId) !== envelope)
    throw new Error(`the lock of ${project} is not held for envelope ${envelope}`);
  const text = await present(ledger);
  if (text === undefined) throw new Error(`the ledger ${ledger} cannot be read`);
  const { entries, open } = projectRows(text, project);
  // The coordinator's own `started` row of this envelope is the one open row that is allowed.
  const own = open
    .filter(
      ({ row }) =>
        row.event === "started" && taskOf(row) === TASK_ID && row.envelopeId === envelope,
    )
    .reduce((latest, entry) => (!latest || entry.time >= latest.time ? entry : latest), undefined);
  const others = open.filter((entry) => entry !== own);
  if (others.length > 0) {
    const { row } = others[0];
    throw new Error(
      `a run of ${project} (${taskOf(row) || "no task"}, ${row.event ?? row.outcome}) opened at ${row.ts ?? row.issuedAt} and has no end in the ledger`,
    );
  }
  const latest = latestCounting(entries, new Set(own ? [own] : []));
  if (latest) {
    const ago = now() - latest.time;
    if (ago < MIN_SPACING_MS)
      throw new Error(
        `the latest ledger row of ${project} is only ${Math.floor(ago / 60_000)} minutes old (30 are needed)`,
      );
  }
  return { holder, latestRowAt: latest?.row.ts };
}
