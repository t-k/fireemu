import type { ChildProcess } from "node:child_process";

/** Selects the owned process target supported by the current operating system. */
export const ownedProcessTarget = (pid: number, platform: NodeJS.Platform): number => {
  if (!Number.isSafeInteger(pid) || pid <= 1) throw new Error(`invalid owned PID: ${pid}`);
  return platform === "win32" ? pid : -pid;
};

/** Retain the spawned ChildProcess; never reconstruct signal authority from a state-file PID. */
export const stopOwnedProcess = async (child: ChildProcess): Promise<void> => {
  const pid = child.pid;
  if (pid === undefined) return;
  const target = ownedProcessTarget(pid, process.platform);
  const childAlive = () => child.exitCode === null && child.signalCode === null;
  if (!childAlive()) return;
  const alive = () => {
    if (process.platform === "win32") return childAlive();
    try {
      process.kill(target, 0);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
      throw error;
    }
  };
  const signal = (value: NodeJS.Signals) => {
    // A reaped leader's PID/group may have been reused. Do not signal it again.
    if (!childAlive()) return;
    if (process.platform === "win32") {
      child.kill(value);
      return;
    }
    try {
      process.kill(target, value);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
    }
  };
  const wait = async () => {
    for (let i = 0; i < 40 && (alive() || childAlive()); i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  };
  // Signal the retained child handle first, including failures before detached-group readiness.
  child.kill("SIGINT");
  await wait();
  if (alive() && childAlive()) {
    signal("SIGKILL");
    await wait();
  }
  if (alive() || childAlive()) {
    throw new Error(
      `daemon process target ${target} survived cleanup; ownership must be re-established before further signals`,
    );
  }
};
