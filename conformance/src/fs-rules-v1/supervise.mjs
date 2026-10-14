// Runs one child (fireemu or the official Firestore emulator wrapper) as a process-group leader
// and signals the whole group on a timeout, on a signal to this process and when the leader
// exits, so a run never leaves an emulator, a JVM or a runner behind.

import { spawn } from "node:child_process";

export const GRACE_MS = 8000;

/** Signals the group of `child` and resolves once the leader is gone (SIGKILL after a grace). */
export async function terminateGroup(child, graceMs = GRACE_MS) {
  const groupKill = (signal) => {
    try {
      process.kill(-child.pid, signal);
    } catch {
      // The group is already gone.
    }
  };
  if (child.exitCode === null && child.signalCode === null) {
    const exited = new Promise((resolve) => child.once("exit", resolve));
    groupKill("SIGTERM");
    const timer = setTimeout(() => groupKill("SIGKILL"), graceMs);
    await exited;
    clearTimeout(timer);
  }
  // The leader may have gone while members of its group live on.
  groupKill("SIGKILL");
}

/**
 * @param {{command: string, args: string[], env?: object, cwd?: string, timeoutMs: number,
 *          stdio?: any, graceMs?: number}} spec
 * @returns {Promise<{exitCode: number | null, timedOut: boolean, pid: number}>}
 */
export async function runSupervised(spec) {
  const child = spawn(spec.command, spec.args, {
    cwd: spec.cwd,
    env: spec.env ?? process.env,
    detached: true,
    stdio: spec.stdio ?? ["ignore", "inherit", "inherit"],
  });
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    void terminateGroup(child, spec.graceMs);
  }, spec.timeoutMs);
  const onSignal = () => {
    void terminateGroup(child, spec.graceMs);
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  const exitCode = await new Promise((resolve) => {
    child.once("exit", (code) => resolve(code));
    child.once("error", () => resolve(null));
  });
  clearTimeout(timer);
  process.off("SIGINT", onSignal);
  process.off("SIGTERM", onSignal);
  await terminateGroup(child, spec.graceMs);
  return { exitCode, timedOut, pid: child.pid };
}
