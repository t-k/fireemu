import { constants, promises as fs } from "node:fs";
import { dirname, isAbsolute, join, relative } from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { requireThat, sha256 } from "./core.mjs";

export function cleanEnvironment(home) {
  // Never inherit NODE_OPTIONS, proxy/ADC/SDK variables, GIT_* overrides or credentials.
  return {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: home,
    TMPDIR: home,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_OPTIONAL_LOCKS: "0",
  };
}
export const inside = (root, target) => {
  const r = relative(root, target);
  return r === "" || (!r.startsWith(".." + "/") && r !== ".." && !isAbsolute(r));
};

// Bind the returned bytes to one observed regular-file version. This detects changes;
// it is not an atomic filesystem snapshot or protection against hostile directory renames.
const sameSourceVersion = (a, b) =>
  ["dev", "ino", "mode", "size", "mtimeNs", "ctimeNs"].every((key) => a[key] === b[key]);

export async function readSource(root, name, maxBytes = 16 * 1024 * 1024) {
  requireThat(Number.isSafeInteger(maxBytes) && maxBytes >= 0, "invalid-source-byte-limit");
  requireThat(
    typeof name === "string" &&
      !isAbsolute(name) &&
      !name.split("/").some((s) => !s || s === "." || s === "..") &&
      !name.includes("\\"),
    "unsafe-source-path",
  );
  root = await fs.realpath(root);
  let target = root;
  let checked;
  for (const part of name.split("/")) {
    target = join(target, part);
    checked = await fs.lstat(target, { bigint: true });
    requireThat(!checked.isSymbolicLink(), "source-symlink");
  }
  requireThat(checked.isFile() && checked.size <= BigInt(maxBytes), "source-size-or-type");
  // A FIFO substituted after lstat must not pin a worker before fstat can reject it.
  const handle = await fs.open(
    target,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const before = await handle.stat({ bigint: true });
    requireThat(before.isFile() && before.size <= BigInt(maxBytes), "source-size-or-type");
    requireThat(sameSourceVersion(checked, before), "source-changed");
    // Read no more than the observed size plus one growth probe, even if a writer
    // keeps appending. readFile() would consume an unbounded amount before the check.
    const budget = Number(before.size) + 1;
    const buffer = Buffer.alloc(Math.min(64 * 1024, budget));
    const chunks = [];
    let total = 0;
    while (total < budget) {
      const { bytesRead } = await handle.read(
        buffer, 0, Math.min(buffer.length, budget - total), total,
      );
      if (bytesRead === 0) break;
      total += bytesRead;
      requireThat(total <= maxBytes, "source-too-large");
      requireThat(BigInt(total) <= before.size, "source-changed");
      chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }
    requireThat(BigInt(total) === before.size, "source-changed");
    const after = await handle.stat({ bigint: true });
    requireThat(sameSourceVersion(before, after), "source-changed");
    requireThat(
      sameSourceVersion(after, await fs.lstat(target, { bigint: true })),
      "source-changed",
    );
    return Buffer.concat(chunks, total);
  } finally {
    await handle.close();
  }
}

export function git(root, args) {
  try {
    return execFileSync("git", ["--no-pager", "--literal-pathspecs", "-C", root, ...args], {
      env: cleanEnvironment("/nonexistent-fireemu-pilot-home"),
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 32 * 1024 * 1024,
      timeout: 15000,
    });
  } catch {
    throw new Error("required-git-object-unavailable");
  }
}
export function gitState(root) {
  return {
    head: git(root, ["rev-parse", "HEAD"]).toString().trim(),
    dirty: git(root, ["status", "--porcelain", "--untracked-files=normal"]).length > 0,
  };
}

export async function newPrivateDirectory(path, repo) {
  requireThat(isAbsolute(path), "absolute-output-directory-required");
  const parent = await fs.realpath(dirname(path));
  const target = join(parent, path.split("/").at(-1));
  const root = await fs.realpath(repo);
  requireThat(!inside(root, target) && !inside(target, root), "output-must-be-outside-repository");
  await fs.mkdir(target, { mode: 0o700 }); // EEXIST is an error; do not reuse receipts.
  return target;
}

export async function publish(path, bytes) {
  const temp = `${path}.tmp-${randomBytes(8).toString("hex")}`;
  let handle;
  try {
    handle = await fs.open(temp, "wx", 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
    await handle.close();
    handle = null;
    await fs.link(temp, path); // Atomic no-replace publication on the same filesystem.
  } finally {
    await handle?.close().catch(() => {});
    await fs.unlink(temp).catch((error) => {
      if (error.code !== "ENOENT") throw error;
    });
  }
}
export const publishJson = (path, value) => publish(path, JSON.stringify(value, null, 2) + "\n");

/**
 * Own one POSIX process group, not an arbitrary descendant tree. `exit` reaps the
 * leader; `close` also waits for inherited pipes, which a detached descendant may
 * keep open. TERM gets 2s, then KILL/drain gets 1s. If that final deadline expires,
 * close our pipe handles and return unconfirmed -- never claim an escaped writer
 * was stopped. All durations are event-loop deadlines, not hard real-time limits.
 */
export async function runProcess(
  command,
  args,
  { cwd, env, timeoutMs = 180000, maxLogBytes = 1024 * 1024, onSpawn = null } = {},
) {
  requireThat(process.platform !== "win32", "posix-supervision-required");
  requireThat(
    Number.isInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 2147483647,
    "invalid-process-timeout",
  );
  requireThat(Number.isSafeInteger(maxLogBytes) && maxLogBytes >= 0, "invalid-process-log-limit");
  return await new Promise((resolveResult) => {
    const child = spawn(command, args, {
      cwd,
      env,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let spawnReceiptError = null;
    try {
      onSpawn?.({ pid: child.pid ?? null, command, args: [...args] });
    } catch {
      spawnReceiptError = "spawn-receipt-failed";
    }
    let reason = null,
      bytes = 0,
      exitCode = null,
      exitSignal = null,
      exited = false,
      closed = false,
      groupGone = !child.pid,
      stopping = false,
      settled = false,
      killTimer,
      finalTimer,
      drainTimer,
      pollTimer;
    const chunks = [];
    const groupState = () => {
      if (groupGone) return "gone";
      try {
        process.kill(-child.pid, 0);
        return "present";
      } catch (error) {
        if (error.code !== "ESRCH") return "unknown";
        // Do not address a reused PGID after this owned group has disappeared.
        groupGone = true;
        return "gone";
      }
    };
    const kill = (signal) => {
      if (groupState() === "gone") return;
      try {
        process.kill(-child.pid, signal);
      } catch (error) {
        if (error.code === "ESRCH") groupGone = true;
        else reason ??= "group-kill-failed";
      }
    };
    const interrupt = () => stop("interrupted");
    const timer = setTimeout(() => stop("process-timeout"), timeoutMs);
    const finish = (forced = false) => {
      if (settled) return;
      const gone = groupState() === "gone";
      settled = true;
      for (const id of [timer, killTimer, finalTimer, drainTimer]) clearTimeout(id);
      clearInterval(pollTimer);
      process.off("SIGINT", interrupt);
      process.off("SIGTERM", interrupt);
      if (forced) {
        reason ??= "process-shutdown-unconfirmed";
        // Closing our ends does not prove the writer died. Do not wait for
        // another close event, nor leave an unconfirmed leader pinning Node.
        child.stdout.destroy();
        child.stderr.destroy();
        child.unref();
      }
      resolveResult({
        code: exitCode,
        signal: exitSignal,
        reason,
        pid: child.pid ?? null,
        state: !forced && exited && closed && gone ? "stopped" : "unconfirmed",
        log: Buffer.concat(chunks),
      });
    };
    const inspect = () => {
      if (settled) return;
      if (exited && closed && groupState() === "gone") finish();
    };
    const stop = (cause) => {
      if (settled) return;
      reason ??= cause;
      if (stopping) return;
      stopping = true;
      kill("SIGTERM");
      killTimer = setTimeout(() => kill("SIGKILL"), 2000);
      finalTimer = setTimeout(() => finish(true), 3000);
      pollTimer = setInterval(inspect, 25);
      inspect();
    };
    if (spawnReceiptError) stop(spawnReceiptError);
    process.once("SIGINT", interrupt);
    process.once("SIGTERM", interrupt);
    child.once("error", () => {
      if (settled) return;
      reason ??= "spawn-failed";
      if (!child.pid) {
        // A failed spawn has no owned process and must not await a timeout.
        exited = closed = true;
        finish();
      } else stop("process-error");
    });
    child.once("exit", (code, signal) => {
      if (settled) return;
      exited = true;
      exitCode = code;
      exitSignal = signal;
      // Ordinary pipe draining is allowed; inherited open descriptors are not
      // allowed to stall a finished leader until the full replay timeout.
      drainTimer = setTimeout(() => {
        if (!closed) stop("process-output-open");
      }, 250);
      inspect();
    });
    for (const stream of [child.stdout, child.stderr]) {
      stream.on("data", (bytesIn) => {
        if (settled) return;
        const remaining = Math.max(0, maxLogBytes - bytes);
        if (remaining) chunks.push(Buffer.from(bytesIn.subarray(0, remaining)));
        bytes = Math.min(Number.MAX_SAFE_INTEGER, bytes + bytesIn.length);
        if (bytes > maxLogBytes) stop("process-log-limit");
      });
      stream.on("error", () => stop("process-log-read-failed"));
    }
    child.once("close", (code, signal) => {
      if (settled) return;
      closed = true;
      clearTimeout(drainTimer);
      // Spawn failure is handled above. A real leader's exit is deliberately
      // required separately from pipe closure before publishing stopped.
      if (!exited) return stop("process-exit-unconfirmed");
      exitCode = code;
      exitSignal = signal;
      if (groupState() !== "gone") stop("remaining-process-group");
      inspect();
    });
  });
}

export async function snapshotBinary(path, destination) {
  const real = await fs.realpath(path);
  const h = await fs.open(real, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await h.stat();
    requireThat(info.isFile() && info.size > 4 && info.size < 1024 * 1024 * 1024, "invalid-binary");
    const data = await h.readFile();
    const magic = data.subarray(0, 4).toString("hex");
    requireThat(
      ["7f454c46", "cffaedfe", "cefaedfe", "feedfacf", "feedface", "cafebabe", "cafebabf"].includes(
        magic,
      ),
      "native-binary-required",
    );
    await publish(destination, data);
    await fs.chmod(destination, 0o700);
    return {
      sha256: sha256(data),
      bytes: data.length,
      platform: process.platform,
      sourceBinding: "not-attested-build-receipt-required-for-final-acceptance",
    };
  } finally {
    await h.close();
  }
}
