import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";

const SUPERVISOR_READY = "supervisor-ready\n";
const CLEANUP_ACK = "cleanup-ready\n";
const COMPLETE_CONTROL_OUTPUT = `${SUPERVISOR_READY}${CLEANUP_ACK}`;

export type OwnedProcessCommand = Readonly<{
  command: string;
  args: readonly string[];
  supervised: boolean;
}>;

export type OwnedProcess = Readonly<{
  child: ChildProcess;
  supervised: boolean;
  supervisorReady: () => boolean;
  supervisorReadyOrClosed: Promise<void>;
  cleanupAcknowledged: () => boolean;
  cleanupChannelClosed: Promise<void>;
}>;

/** Keep POSIX daemon descendants in a group led by the spawn-owning supervisor. */
export const ownedProcessCommand = (
  command: string,
  args: readonly string[],
  platform: NodeJS.Platform,
  posixSupervisor: string,
): OwnedProcessCommand =>
  platform === "win32"
    ? { command, args, supervised: false }
    : { command: posixSupervisor, args: [command, ...args], supervised: true };

/** Spawn the retained process and a private POSIX cleanup acknowledgement channel. */
export const spawnOwnedProcess = (
  command: string,
  args: readonly string[],
  platform: NodeJS.Platform,
  posixSupervisor: string,
  options: Omit<SpawnOptions, "detached" | "stdio"> = {},
): OwnedProcess => {
  const selected = ownedProcessCommand(command, args, platform, posixSupervisor);
  const child = spawn(selected.command, selected.args, {
    ...options,
    detached: true,
    stdio: selected.supervised ? ["ignore", "pipe", "pipe", "pipe"] : ["ignore", "pipe", "pipe"],
  });
  let cleanupOutput = "";
  let cleanupClosed = false;
  let supervisorReady = false;
  let markSupervisorReady = (): void => undefined;
  const supervisorReadyOrClosed = new Promise<void>((resolve) => {
    markSupervisorReady = resolve;
  });
  let closeCleanupChannel = (): void => undefined;
  const cleanupChannelClosed = new Promise<void>((resolve) => {
    closeCleanupChannel = resolve;
  });
  if (selected.supervised) {
    const cleanupChannel = child.stdio[3];
    cleanupChannel?.on("data", (data: Buffer) => {
      cleanupOutput += data.toString();
      if (cleanupOutput.startsWith(SUPERVISOR_READY) && !supervisorReady) {
        supervisorReady = true;
        markSupervisorReady();
      }
      if (cleanupOutput.length > COMPLETE_CONTROL_OUTPUT.length) cleanupOutput = "invalid";
    });
    cleanupChannel?.once("close", () => {
      cleanupClosed = true;
      markSupervisorReady();
      closeCleanupChannel();
    });
  } else {
    cleanupClosed = true;
    supervisorReady = true;
    markSupervisorReady();
    closeCleanupChannel();
  }
  return {
    child,
    supervised: selected.supervised,
    supervisorReady: () => supervisorReady,
    supervisorReadyOrClosed,
    cleanupAcknowledged: () => cleanupClosed && cleanupOutput === COMPLETE_CONTROL_OUTPUT,
    cleanupChannelClosed,
  };
};

const waitForExit = async (child: ChildProcess): Promise<void> => {
  for (let i = 0; i < 40 && child.exitCode === null && child.signalCode === null; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
};

const waitAtMost = async (waitFor: Promise<void>, timeoutMs: number): Promise<void> => {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      waitFor,
      new Promise<void>((resolve) => {
        timeout = setTimeout(resolve, timeoutMs);
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
};

/** Stop only the retained handle and require the POSIX supervisor's cleanup evidence. */
export const stopOwnedProcess = async (owned: OwnedProcess): Promise<void> => {
  const { child } = owned;
  const childAlive = () => child.exitCode === null && child.signalCode === null;
  if (owned.supervised && childAlive()) {
    await waitAtMost(owned.supervisorReadyOrClosed, 1_000);
    if (!owned.supervisorReady()) {
      if (childAlive() && child.pid !== undefined) {
        child.kill("SIGINT");
        await waitForExit(child);
      }
      if (childAlive()) {
        child.kill("SIGKILL");
        await waitForExit(child);
      }
      if (childAlive()) {
        throw new Error("unready daemon supervisor survived cleanup");
      }
      throw new Error("daemon supervisor did not establish cleanup ownership");
    }
  }
  if (childAlive() && child.pid !== undefined) {
    child.kill("SIGINT");
    await waitForExit(child);
  }
  if (childAlive() && !owned.supervised) {
    child.kill("SIGKILL");
    await waitForExit(child);
  }
  if (childAlive()) {
    throw new Error("daemon supervisor survived cleanup; its owned group remains reserved");
  }
  await waitAtMost(owned.cleanupChannelClosed, 1_000);
  if (owned.supervised && (!owned.cleanupAcknowledged() || child.signalCode !== "SIGKILL")) {
    throw new Error("daemon supervisor exited without completed group cleanup evidence");
  }
};
