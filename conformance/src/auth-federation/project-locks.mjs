// Project-scoped sandbox locks (owner decision A, 2026-09-28): one lock file per project,
// `<ledger dir>/sandbox-locks/<project>.lock`, created exclusively, holding one line of JSON
// without secrets. A runner for several projects takes them in ascending order and releases
// what it took if one is held. While the legacy shared lock (`<ledger>.lock`) exists no runner
// starts, checked before and after taking. A lock is released only by its taker, after checking
// its inode and text, and it stays when the run fails after sending.

import { mkdir, open, readFile, rm, stat } from "node:fs/promises";
import { dirname, join } from "node:path";

import { checkRun } from "./guard.mjs";

const PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/;

/** The lock file of `project` beside `ledger`. */
export function projectLockPath(ledger, project) {
  if (!PROJECT_ID.test(project)) throw new Error(`${project} is not a project ID`);
  return join(dirname(ledger), "sandbox-locks", `${project}.lock`);
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

/**
 * Takes the locks of `projects` for `holder` (`{taskId, packetId, sourceCommit}`), or throws
 * before anything is sent: while the legacy lock exists, or when a project's lock is held (the
 * ones taken so far are released). Returns the handle `release` and `keep` use.
 */
export async function takeProjectLocks(
  ledger,
  projects,
  holder,
  { afterEach = async () => {}, adopt } = {},
) {
  const legacy = `${ledger}.lock`;
  if (await exists(legacy)) throw new Error(`the legacy shared lock ${legacy} exists`);
  checkRun(holder.run);
  await mkdir(join(dirname(ledger), "sandbox-locks"), { recursive: true, mode: 0o700 });
  const taken = [];
  const text = `${JSON.stringify({
    taskId: holder.taskId,
    packetId: holder.packetId,
    run: holder.run,
    sourceCommit: holder.sourceCommit,
    pid: process.pid,
    acquiredAt: new Date().toISOString(),
  })}\n`;
  try {
    for (const project of [...new Set(projects)].toSorted()) {
      const path = projectLockPath(ledger, project);
      let handle;
      try {
        handle = await open(path, "wx", 0o600);
      } catch (error) {
        if (error.code !== "EEXIST") throw error;
        const other = await readFile(path, "utf8").catch(() => "unreadable");
        if (!adoptable(other, adopt)) {
          throw new Error(`${project} is locked: ${other.trim()}`, { cause: error });
        }
        // A lock this task left for recovery, whose process is gone: taken over in place.
        handle = await open(path, "r+");
        await handle.truncate(0);
      }
      try {
        await handle.writeFile(text);
        taken.push({ path, ino: (await handle.stat()).ino });
      } finally {
        await handle.close();
      }
      await afterEach(project);
    }
    if (await exists(legacy)) throw new Error(`the legacy shared lock ${legacy} appeared`);
  } catch (error) {
    await releaseTaken(taken, text);
    throw error;
  }
  return { taken, text };
}

/**
 * Whether a held lock may be taken over: `adopt(body)` accepts its holder (this task's run
 * left it for recovery) and the process it names no longer runs.
 */
function adoptable(text, adopt) {
  if (!adopt) return false;
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return false;
  }
  if (!adopt(body)) return false;
  try {
    process.kill(Number(body.pid), 0);
    return false;
  } catch (error) {
    return error.code === "ESRCH";
  }
}

/** Removes only locks that are still the ones taken: the same inode and the same text. */
async function releaseTaken(taken, text) {
  for (const { path, ino } of taken.toReversed()) {
    try {
      const [current, body] = [await stat(path), await readFile(path, "utf8")];
      if (current.ino === ino && body === text) await rm(path);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
}

/** Releases the locks of `handle` (a run that ended with the sandboxes at their baseline). */
export async function releaseProjectLocks(handle) {
  await releaseTaken(handle.taken, handle.text);
}

/**
 * Runs `work(state)` holding the locks of `projects`. They are released when it returns and
 * `keep(result)` does not hold, or when it throws before `state.sent` was set; otherwise they
 * stay for recovery, as the shared lock did.
 */
export async function withProjectLocks(
  ledger,
  projects,
  holder,
  work,
  { keep = () => false, adopt } = {},
) {
  const handle = await takeProjectLocks(ledger, projects, holder, { adopt });
  const state = { sent: false };
  let result;
  try {
    result = await work(state);
  } catch (error) {
    if (!state.sent) await releaseProjectLocks(handle);
    throw error;
  }
  if (!keep(result)) await releaseProjectLocks(handle);
  return result;
}
