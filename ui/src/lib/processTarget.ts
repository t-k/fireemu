import type { ChildProcess } from "node:child_process";

export type OwnedProcessCommand = Readonly<{
  command: string;
  args: readonly string[];
}>;

/** Keep POSIX daemon descendants under a spawn-owning supervisor. */
export const ownedProcessCommand = (
  command: string,
  args: readonly string[],
  platform: NodeJS.Platform,
  posixSupervisor: string,
): OwnedProcessCommand =>
  platform === "win32" ? { command, args } : { command: posixSupervisor, args: [command, ...args] };

/** Stop the retained supervisor handle without reconstructing signal authority from a numeric PID. */
export const stopOwnedProcess = async (child: ChildProcess): Promise<void> => {
  if (child.pid === undefined) return;
  const childAlive = () => child.exitCode === null && child.signalCode === null;
  if (!childAlive()) return;
  const wait = async () => {
    for (let i = 0; i < 40 && childAlive(); i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  };
  child.kill("SIGINT");
  await wait();
  if (childAlive()) {
    child.kill("SIGKILL");
    await wait();
  }
  if (childAlive()) {
    throw new Error("daemon supervisor survived cleanup");
  }
};
