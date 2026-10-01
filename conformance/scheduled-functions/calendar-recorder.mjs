// The one module allowed to start child processes in the launch-accounting harness (design v4
// section 2). Every row is appended and fsynced as it happens, so a crash keeps the earlier rows.
import { spawn as spawnProcess } from "node:child_process";
import { closeSync, fsyncSync, openSync, writeSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const argvDigest = (file, args) =>
  createHash("sha256")
    .update(JSON.stringify([file, ...args]))
    .digest("hex");
const mono = () => String(process.hrtime.bigint());

/**
 * A recorder for one lane-owned process: `role` names its record file in the chain, and
 * `pid`/`started` are its own identity (checked against its parent's birth and identity rows).
 */
export function createRecorder({
  path,
  role,
  pid,
  started,
  harnessVersion,
  spawnImpl = spawnProcess,
  prelude = [],
}) {
  const fd = openSync(path, "a", 0o600);
  const append = (row) => {
    writeSync(fd, JSON.stringify(row) + "\n");
    fsyncSync(fd);
  };
  append({ type: "header", role, pid, started, harnessVersion });
  for (const row of prelude) append(row);
  const uid = process.getuid();
  let next = 0,
    closed = false;
  const recorder = {
    /** Starts a child; its exit row comes from this process's own wait (`exit`). */
    spawn(file, args, options = {}, purpose) {
      // Condition (C): only the measuring entry starts a new session, for the outer launcher.
      if (options.detached && !(role === "measure" && purpose === "outer"))
        throw new Error("only the measuring entry may start a session, for the outer launcher");
      const handle = `${role}:${++next}`;
      const spawnMonoNs = mono(),
        argvSha256 = argvDigest(file, args);
      const child = spawnImpl(file, args, options);
      let settle;
      child.recordHandle = handle;
      child.recordExit = new Promise((resolve) => {
        settle = resolve;
      });
      if (Number.isSafeInteger(child.pid)) {
        append({
          type: "birth",
          handle,
          pid: child.pid,
          uid,
          purpose,
          file,
          argvSha256,
          spawnMonoNs,
        });
        child.once("exit", (code, signal) => {
          append({ type: "exit", handle, code, signal, exitMonoNs: mono() });
          settle({ code, signal });
        });
      } else {
        child.once("error", (error) => {
          append({
            type: "spawn-failed",
            handle,
            pid: null,
            purpose,
            file,
            argvSha256,
            spawnMonoNs,
            error: error.code ?? "error",
          });
          settle({ code: null, signal: null, spawnFailed: true });
        });
      }
      return child;
    },
    /** Runs a child to completion and collects its output; a timeout is a recorded SIGKILL. */
    async execFile(file, args, { timeoutMs = 5000, env, cwd, maxBuffer = 16777216 } = {}, purpose) {
      const child = recorder.spawn(
        file,
        args,
        { env, cwd, stdio: ["ignore", "pipe", "pipe"] },
        purpose,
      );
      if (!Number.isSafeInteger(child.pid)) {
        await child.recordExit;
        return {
          code: null,
          signal: null,
          stdout: "",
          stderr: "",
          timedOut: false,
          spawnFailed: true,
        };
      }
      let stdout = "",
        stderr = "",
        timedOut = false;
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        if (stdout.length < maxBuffer) stdout += chunk;
      });
      child.stderr.on("data", (chunk) => {
        if (stderr.length < maxBuffer) stderr += chunk;
      });
      const closed = new Promise((resolve) => child.once("close", resolve));
      const timer = setTimeout(() => {
        timedOut = true;
        recorder.signal({ pid: child.pid, uid, started: "unknown" }, "SIGKILL", async () => {
          child.kill("SIGKILL");
        });
      }, timeoutMs);
      const { code, signal } = await child.recordExit;
      await closed;
      clearTimeout(timer);
      return { code, signal, stdout, stderr, timedOut, pid: child.pid, handle: child.recordHandle };
    },
    /** A process's start time, from a recorded `ps` (what a parent puts in an identity row). */
    async startedOf(target) {
      const answer = await recorder.execFile(
        "ps",
        ["-o", "lstart=", "-p", String(target)],
        { env: psEnv() },
        "start-time",
      );
      const value = normaliseStart(answer.stdout);
      if (answer.code !== 0 || !value) throw new Error(`start time of ${target} is unreadable`);
      return value;
    },
    /** The parent's record of a lane-owned child's start time (checked against its header). */
    identity(handle, childPid, childStarted) {
      append({ type: "identity", handle, pid: childPid, started: childStarted });
    },
    /** Every signal the harness sends is recorded, with the target identity, before it is sent. */
    async signal(target, kind, send) {
      append({ type: "signal", target, kind, monoNs: mono() });
      await send();
    },
    close() {
      if (closed) return;
      closed = true;
      closeSync(fd);
    },
  };
  return recorder;
}

export async function readRecords(path) {
  return (await readFile(path, "utf8"))
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line));
}

/** `ps -o lstart=` text, normalised the way inventories normalise it. */
const normaliseStart = (text) => text.trim().replace(/\s+/g, " ");
/** The environment of every `ps` the harness runs: C locale, and start times in UTC. */
export const psEnv = () => ({ PATH: process.env.PATH ?? "/usr/bin:/bin", LC_ALL: "C", TZ: "UTC" });

/**
 * A recorder for the calling lane-owned process. Its own start time comes from a `ps` of itself,
 * recorded after the header as an ordinary birth and exit (handle `<role>:0`).
 */
export async function createSelfRecorder({ path, role, harnessVersion, spawnImpl = spawnProcess }) {
  const args = ["-o", "lstart=", "-p", String(process.pid)];
  const spawnMonoNs = mono();
  const probe = spawnImpl("ps", args, { stdio: ["ignore", "pipe", "ignore"], env: psEnv() });
  let text = "";
  probe.stdout.setEncoding("utf8");
  probe.stdout.on("data", (chunk) => (text += chunk));
  const [code, signal] = await new Promise((resolve, reject) => {
    probe.once("error", reject);
    probe.once("close", (exitCode, exitSignal) => resolve([exitCode, exitSignal]));
  });
  const started = normaliseStart(text);
  if (code !== 0 || !started) throw new Error("own start time is unreadable");
  const handle = `${role}:0`;
  return createRecorder({
    path,
    role,
    pid: process.pid,
    started,
    harnessVersion,
    spawnImpl,
    prelude: [
      {
        type: "birth",
        handle,
        pid: probe.pid,
        uid: process.getuid(),
        purpose: "self-start",
        file: "ps",
        argvSha256: argvDigest("ps", args),
        spawnMonoNs,
      },
      { type: "exit", handle, code, signal, exitMonoNs: mono() },
    ],
  });
}
