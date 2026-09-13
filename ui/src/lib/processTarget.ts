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

  // Once a POSIX group is observed while its retained leader is alive, keep that
  // ownership proof until the group disappears. This prevents a later probe from
  // treating a reused PID/group as the daemon we started.
  let groupOwned = false;
  let groupGone = false;
  const groupAlive = () => {
    if (process.platform === "win32" || groupGone) return false;
    try {
      process.kill(target, 0);
      if (childAlive()) groupOwned = true;
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") {
        groupGone = true;
        return false;
      }
      // EPERM still proves that a process/group exists; keep verifying instead of
      // treating an inaccessible target as safely gone.
      if ((error as NodeJS.ErrnoException).code === "EPERM") return true;
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
