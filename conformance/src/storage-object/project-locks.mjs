import { constants, lstatSync, readFileSync, unlinkSync } from "node:fs";
import { lstat, mkdir, open, readFile } from "node:fs/promises";
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

async function acquire(lockDir, project, body, records) {
  const path = join(lockDir, `${project}.lock`);
  let handle;
  try {
    handle = await open(
      path,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
  } catch (error) {
    if (error.code === "EEXIST")
      throw new Error(`project lock exists: ${project}`, { cause: error });
    throw error;
  }
  try {
    const stat = await handle.stat();
    const record = { path, body, dev: stat.dev, ino: stat.ino };
    records.push(record);
    try {
      await handle.writeFile(body);
      await handle.sync();
    } catch (error) {
      const current = await lstat(path);
      if (current.isFile() && current.dev === record.dev && current.ino === record.ino) {
        const partial = await readFile(path, "utf8");
        if (body.startsWith(partial)) record.body = partial;
      }
      throw error;
    }
  } finally {
    await handle.close();
  }
}

async function releaseOwned(records) {
  for (const record of records) {
    const stat = await lstat(record.path);
    if (
      !stat.isFile() ||
      stat.dev !== record.dev ||
      stat.ino !== record.ino ||
      stat.size !== Buffer.byteLength(record.body)
    ) {
      throw new Error(`project lock ownership changed: ${record.path}`);
    }
    const body = await readFile(record.path, "utf8");
    if (body !== record.body) {
      throw new Error(`project lock ownership changed: ${record.path}`);
    }
  }
  // Check again at removal without yielding between the final checks and unlink.
  // Participants must obey O_EXCL and never overwrite an existing owner's lock.
  for (const record of records.toReversed()) {
    const stat = lstatSync(record.path);
    if (
      !stat.isFile() ||
      stat.dev !== record.dev ||
      stat.ino !== record.ino ||
      stat.size !== Buffer.byteLength(record.body) ||
      readFileSync(record.path, "utf8") !== record.body
    )
      throw new Error(`project lock ownership changed: ${record.path}`);
    const current = lstatSync(record.path);
    if (current.dev !== record.dev || current.ino !== record.ino)
      throw new Error(`project lock ownership changed: ${record.path}`);
    unlinkSync(record.path);
  }
}

/** Task-local lock lifecycle; the caller must verify cleanup and persist its terminal row before confirming closure. */
export async function withProjectLocks(options, run, hooks = {}) {
  if (
    !Array.isArray(options?.projects) ||
    options.projects.length === 0 ||
    new Set(options.projects).size !== options.projects.length ||
    options.projects.some(
      (project) => typeof project !== "string" || !/^[a-z][a-z0-9-]{2,61}$/.test(project),
    )
  ) {
    throw new Error("invalid project ID set");
  }
  if (
    options.taskId !== "STORAGE-OBJECT" ||
    typeof options.packetId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(options.packetId) ||
    typeof options.sourceCommit !== "string" ||
    !/^[a-f0-9]{40}$/.test(options.sourceCommit) ||
    !Number.isSafeInteger(options.pid) ||
    options.pid <= 0 ||
    typeof options.acquiredAt !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(options.acquiredAt) ||
    Number.isNaN(Date.parse(options.acquiredAt))
  ) {
    throw new Error("invalid lock metadata");
  }
  if (await pathExists(options.legacyLockPath)) throw new Error("legacy shared lock exists");
  await mkdir(options.lockDir, { recursive: true, mode: 0o700 });
  const dir = await lstat(options.lockDir);
  if (!dir.isDirectory() || (dir.mode & 0o777) !== 0o700)
    throw new Error("project lock directory must be mode 700");
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
      await acquire(options.lockDir, project, body, records);
      if (hooks.onLockCreated) await hooks.onLockCreated(project);
    }
    if (hooks.afterAcquire) await hooks.afterAcquire();
    if (await pathExists(options.legacyLockPath)) throw new Error("legacy shared lock exists");
  } catch (error) {
    await releaseOwned(records);
    throw error;
  }
  let sent = false;
  let started = false;
  let failed = false;
  let closed = false;
  let inFlight = false;
  let active = true;
  const lease = {
    // Call before attempting the started row: its durability can fail before any HTTP.
    markStarted() {
      if (!active) throw new Error("project lock lease is inactive");
      if (started || sent || closed || inFlight)
        throw new Error("project lock run already started");
      started = true;
    },
    async dispatch(transport) {
      if (!active) throw new Error("project lock lease is inactive");
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
      if (!active) throw new Error("project lock lease is inactive");
      if ((!sent && !started) || failed) throw new Error("cannot confirm project lock closure");
      if (inFlight) throw new Error("outbound dispatch still pending");
      closed = true;
    },
  };
  let result;
  try {
    try {
      result = await run(lease);
    } finally {
      active = false;
    }
    if (inFlight) throw new Error("outbound dispatch still pending; project locks retained");
    if (failed) throw new Error("outbound attempt failed; project locks retained");
    if ((sent || started) && !closed)
      throw new Error("closure not confirmed; project locks retained");
  } catch (error) {
    if (!sent && !started) await releaseOwned(records);
    throw error;
  }
  await releaseOwned(records);
  return result;
}
