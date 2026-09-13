/** Selects the owned process target supported by the current operating system. */
export const ownedProcessTarget = (pid: number, platform: NodeJS.Platform): number =>
  platform === "win32" ? pid : -pid;
