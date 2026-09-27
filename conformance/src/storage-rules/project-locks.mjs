import { constants } from "node:fs";
import { lstat, mkdir, open, readFile, unlink } from "node:fs/promises";
import { join } from "node:path";

async function pathExists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

async function acquire(lockDir, project, body) {
  const path = join(lockDir, `${project}.lock`);
  let handle;
  try {
    handle = await open(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600);
  } catch (error) {
    if (error.code === "EEXIST") throw new Error(`project lock exists: ${project}`);
    throw error;
  }
  try {
    await handle.writeFile(body);
    await handle.sync();
    const stat = await handle.stat();
    return { path, body, dev: stat.dev, ino: stat.ino };
  } finally {
    await handle.close();
  }
}

async function releaseOwned(records) {
  for (const record of records) {
    const stat = await lstat(record.path);
    if (!stat.isFile() || stat.dev !== record.dev || stat.ino !== record.ino) {
      throw new Error(`project lock ownership changed: ${record.path}`);
    }
    const body = await readFile(record.path, "utf8");
    if (body !== record.body) {
      throw new Error(`project lock ownership changed: ${record.path}`);
    }
  }
  for (const record of [...records].reverse()) await unlink(record.path);
}

export async function withProjectLocks(options, run, hooks = {}) {
  if (
    !Array.isArray(options?.projects) ||
    options.projects.length === 0 ||
    new Set(options.projects).size !== options.projects.length ||
    options.projects.some((project) => typeof project !== "string" || !/^[a-z][a-z0-9-]{2,61}$/.test(project))
  ) {
    throw new Error("invalid project ID set");
  }
  if (
    typeof options.taskId !== "string" || !/^[A-Z][A-Z0-9-]{1,63}$/.test(options.taskId) ||
    typeof options.packetId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(options.packetId) ||
    typeof options.sourceCommit !== "string" || !/^[a-f0-9]{40}$/.test(options.sourceCommit) ||
    !Number.isSafeInteger(options.pid) || options.pid <= 0 ||
    typeof options.acquiredAt !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(options.acquiredAt) ||
    Number.isNaN(Date.parse(options.acquiredAt))
  ) {
    throw new Error("invalid lock metadata");
  }
  if (await pathExists(options.legacyLockPath)) throw new Error("legacy shared lock exists");
  await mkdir(options.lockDir, { recursive: true, mode: 0o700 });
  const dir = await lstat(options.lockDir);
  if (!dir.isDirectory() || (dir.mode & 0o777) !== 0o700) throw new Error("project lock directory must be mode 700");
  const body = `${JSON.stringify({
    taskId: options.taskId,
    packetId: options.packetId,
    sourceCommit: options.sourceCommit,
    pid: options.pid,
    acquiredAt: options.acquiredAt,
  })}\n`;
  const records = [];
  try {
    for (const project of options.projects.toSorted()) {
      records.push(await acquire(options.lockDir, project, body));
      if (hooks.onLockCreated) await hooks.onLockCreated(project);
    }
    if (hooks.afterAcquire) await hooks.afterAcquire();
    if (await pathExists(options.legacyLockPath)) throw new Error("legacy shared lock exists");
  } catch (error) {
    await releaseOwned(records);
    throw error;
  }
  let sent = false;
  let failed = false;
  let closed = false;
  let inFlight = false;
  const lease = {
    async dispatch(transport) {
      if (typeof transport !== "function") throw new Error("outbound transport required");
      if (closed) throw new Error("project lock run already closed");
      if (inFlight) throw new Error("outbound dispatch already pending");
      sent = true;
      inFlight = true;
      try {
        return await transport();
      } catch (error) {
        failed = true;
        throw error;
      } finally {
        inFlight = false;
      }
    },
    confirmClosed() {
      if (!sent || failed) throw new Error("cannot confirm project lock closure");
      if (inFlight) throw new Error("outbound dispatch still pending");
      closed = true;
    },
  };
  let result;
  try {
    result = await run(lease);
    if (inFlight) throw new Error("outbound dispatch still pending; project locks retained");
    if (failed) throw new Error("outbound attempt failed; project locks retained");
    if (sent && !closed) throw new Error("closure not confirmed; project locks retained");
  } catch (error) {
    if (!sent) await releaseOwned(records);
    throw error;
  }
  await releaseOwned(records);
  return result;
}
