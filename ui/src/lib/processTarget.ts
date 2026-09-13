import type { ChildProcess } from "node:child_process";

/** Selects the owned process target supported by the current operating system. */
export const ownedProcessTarget = (pid: number, platform: NodeJS.Platform): number => {
  if (!Number.isSafeInteger(pid) || pid <= 1) throw new Error(`invalid owned PID: ${pid}`);
  return platform === "win32" ? pid : -pid;
};

export type RetainedOwnedProcess = Readonly<{
  child: ChildProcess;
  pid: number | undefined;
  target: number | undefined;
  groupOwned: boolean;
}>;

/** Capture the spawned process group while the retained child is still alive. */
export const retainOwnedProcess = (child: ChildProcess): RetainedOwnedProcess => {
  const pid = child.pid;
  if (pid === undefined || child.exitCode !== null || child.signalCode !== null) {
    return { child, pid, target: undefined, groupOwned: false };
  }
  const target = ownedProcessTarget(pid, process.platform);
  if (process.platform === "win32") return { child, pid, target, groupOwned: false };
  try {
    process.kill(target, 0);
    return { child, pid, target, groupOwned: true };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EPERM") {
      return { child, pid, target, groupOwned: true };
    }
    if ((error as NodeJS.ErrnoException).code === "ESRCH") {
      // The detached group may not exist until the child has finished spawning.
      return { child, pid, target, groupOwned: false };
    }
    throw error;
  }
};

/** Stop a captured process group, while accepting ChildProcess for compatibility. */
export const stopOwnedProcess = async (
  retained: ChildProcess | RetainedOwnedProcess,
): Promise<void> => {
  const owned =
    "child" in retained && "target" in retained ? retained : retainOwnedProcess(retained);
  const { child, target } = owned;
  if (target === undefined) return;
  const childAlive = () => child.exitCode === null && child.signalCode === null;
  let groupOwned = owned.groupOwned;
  if (!childAlive() && !groupOwned) return;

  // Once a POSIX group is observed while its retained leader is alive, keep that
  // ownership proof until the group disappears. This prevents a later probe from
  // treating a reused PID/group as the daemon we started.
  let groupGone = false;
  const groupAlive = () => {
    if (process.platform === "win32" || groupGone) return false;
    try {
      process.kill(target, 0);
      if (childAlive()) groupOwned = true;
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") {
        if (groupOwned) groupGone = true;
        return false;
      }
      // EPERM still proves that a process/group exists; keep verifying instead of
      // treating an inaccessible target as safely gone.
      if ((error as NodeJS.ErrnoException).code === "EPERM") {
        if (childAlive() || groupOwned) groupOwned = true;
        return true;
      }
      throw error;
    }
  };
  const signal = (value: NodeJS.Signals) => {
    if (process.platform === "win32") {
      if (!childAlive()) return;
      child.kill(value);
      return;
    }
    // A reaped leader can leave descendants in the owned group. Signal that group
    // only while the ownership proof is still valid.
    if (!groupOwned || !groupAlive()) return;
    try {
      process.kill(target, value);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") {
        groupGone = true;
        return;
      }
      throw error;
    }
  };
  const waitForLeaderOrGroupExit = async () => {
    for (
      let i = 0;
      i < 40 && childAlive() && (process.platform === "win32" || groupAlive());
      i += 1
    ) {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  };
  const waitForTermination = async () => {
    for (
      let i = 0;
      i < 40 && (childAlive() || (process.platform !== "win32" && groupAlive()));
      i += 1
    ) {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  };

  // Establish group ownership before SIGINT can reap the leader.
  if (process.platform !== "win32") groupAlive();
  // Signal the retained child handle first, including failures before detached-group readiness.
  child.kill("SIGINT");
  await waitForLeaderOrGroupExit();
  if (process.platform === "win32" ? childAlive() : groupAlive()) {
    signal("SIGKILL");
    await waitForTermination();
  }
  if ((process.platform !== "win32" && groupAlive()) || childAlive()) {
    throw new Error(
      `daemon process target ${target} survived cleanup; ownership must be re-established before further signals`,
    );
  }
};
