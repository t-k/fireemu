import { spawn } from "node:child_process";
import { once } from "node:events";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  type OwnedProcess,
  ownedProcessCommand,
  spawnOwnedProcess,
  stopOwnedProcess,
} from "./processTarget";

const supervisor = resolve(process.cwd(), "../ui/e2e/bin/process-supervisor");

const spawnOwnedNode = (script: string): OwnedProcess =>
  spawnOwnedProcess(process.execPath, ["-e", script], process.platform, supervisor);

const runningScript = "console.log('ready'); setInterval(() => {}, 1000)";

const expectRunning = (owned: OwnedProcess): void => {
  expect(owned.child.exitCode).toBeNull();
  expect(owned.child.signalCode).toBeNull();
  expect(owned.child.kill(0)).toBe(true);
};

const waitForProcessAbsence = async (pid: number): Promise<boolean> => {
  for (let i = 0; i < 40; i += 1) {
    try {
      process.kill(pid, 0);
    } catch {
      return true;
    }
    await new Promise((finish) => setTimeout(finish, 25));
  }
  return false;
};

const resistantDescendantScript = [
  "process.on('SIGINT', () => {});",
  "process.on('SIGTERM', () => {});",
  "process.stdout.write('ready');",
  "setInterval(() => {}, 1000);",
].join(" ");

const leaderWithResistantDescendant = (exitOnSignal: boolean): string =>
  [
    "const { spawn } = require('node:child_process');",
    `const descendant = spawn(process.execPath, ['-e', ${JSON.stringify(resistantDescendantScript)}], { stdio: ['ignore', 'pipe', 'ignore'] });`,
    "descendant.stdout.once('data', () => process.stdout.write(String(descendant.pid)));",
    ...(exitOnSignal ? ["process.on('SIGINT', () => process.exit(0));"] : []),
    "setInterval(() => {}, 1000);",
  ].join(" ");

describe("ownedProcessCommand", () => {
  it("runs the command directly on Windows", () => {
    expect(ownedProcessCommand("fireemu", ["up"], "win32", "process-supervisor")).toEqual({
      command: "fireemu",
      args: ["up"],
      supervised: false,
    });
  });

  it("runs the command through the POSIX supervisor", () => {
    expect(ownedProcessCommand("fireemu", ["up"], "darwin", "process-supervisor")).toEqual({
      command: "process-supervisor",
      args: ["fireemu", "up"],
      supervised: true,
    });
  });
});

describe("owned daemon lifecycle", () => {
  it("stops only its retained supervisor and preserves an unrelated process", async () => {
    const owned = spawnOwnedNode(runningScript);
    const unrelated = spawnOwnedNode(runningScript);
    await Promise.all([once(owned.child.stdout!, "data"), once(unrelated.child.stdout!, "data")]);
    try {
      await stopOwnedProcess(owned);
      expect(owned.cleanupAcknowledged()).toBe(process.platform !== "win32");
      expectRunning(unrelated);
    } finally {
      await stopOwnedProcess(owned);
      await stopOwnedProcess(unrelated);
    }
  });

  it("can stop a child before its application readiness event", async () => {
    const owned = spawnOwnedNode("setInterval(() => {}, 1000)");
    await once(owned.child, "spawn");
    await stopOwnedProcess(owned);
    expect(owned.child.exitCode !== null || owned.child.signalCode !== null).toBe(true);
  });

  it("does not signal a previously exited supervisor after its PID changes", async () => {
    const exited = spawnOwnedNode("process.exit(0)");
    await once(exited.child, "exit");
    const unrelated = spawnOwnedNode(runningScript);
    await once(unrelated.child.stdout!, "data");
    try {
      Object.defineProperty(exited.child, "pid", { value: unrelated.child.pid });
      await stopOwnedProcess(exited);
      expectRunning(unrelated);
    } finally {
      await stopOwnedProcess(unrelated);
    }
  });

  it.skipIf(process.platform === "win32")(
    "reaps a ready signal-resistant descendant when its daemon leader exits first",
    async () => {
      const owned = spawnOwnedNode(leaderWithResistantDescendant(true));
      const [descendantOutput] = await once(owned.child.stdout!, "data");
      const descendantPid = Number(descendantOutput.toString());
      expect(Number.isSafeInteger(descendantPid) && descendantPid > 1).toBe(true);
      await stopOwnedProcess(owned);
      expect(owned.cleanupAcknowledged()).toBe(true);
      expect(await waitForProcessAbsence(descendantPid)).toBe(true);
    },
  );

  it.skipIf(process.platform === "win32")(
    "reaps a ready descendant after a natural daemon-leader exit",
    async () => {
      const script = [
        "const { spawn } = require('node:child_process');",
        `const descendant = spawn(process.execPath, ['-e', ${JSON.stringify(resistantDescendantScript)}], { stdio: ['ignore', 'pipe', 'ignore'] });`,
        "descendant.stdout.once('data', () => { process.stdout.write(String(descendant.pid)); setTimeout(() => process.exit(23), 10); });",
        "setInterval(() => {}, 1000);",
      ].join(" ");
      const owned = spawnOwnedNode(script);
      const [descendantOutput] = await once(owned.child.stdout!, "data");
      const descendantPid = Number(descendantOutput.toString());
      expect(Number.isSafeInteger(descendantPid) && descendantPid > 1).toBe(true);
      await once(owned.child, "exit");
      await stopOwnedProcess(owned);
      expect(owned.cleanupAcknowledged()).toBe(true);
      expect(await waitForProcessAbsence(descendantPid)).toBe(true);
    },
  );

  it("rejects a supervised exit without cleanup acknowledgement", async () => {
    const child = spawn(process.execPath, ["-e", "process.exit(0)"]);
    await once(child, "exit");
    const incomplete: OwnedProcess = {
      child,
      supervised: true,
      supervisorReady: () => true,
      supervisorReadyOrClosed: Promise.resolve(),
      cleanupAcknowledged: () => false,
      cleanupChannelClosed: Promise.resolve(),
    };
    await expect(stopOwnedProcess(incomplete)).rejects.toThrow(
      "without completed group cleanup evidence",
    );
  });

  it.skipIf(process.platform === "win32")(
    "lets an unready retained supervisor reap its descendant before reporting failure",
    async () => {
      const script = [
        "const { spawn } = require('node:child_process');",
        "const descendant = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });",
        "process.on('SIGINT', () => { descendant.kill('SIGKILL'); descendant.once('exit', () => process.exit(0)); });",
        "process.stdout.write(String(descendant.pid));",
        "setInterval(() => {}, 1000);",
      ].join(" ");
      const child = spawn(process.execPath, ["-e", script]);
      const [descendantOutput] = await once(child.stdout!, "data");
      const descendantPid = Number(descendantOutput.toString());
      expect(Number.isSafeInteger(descendantPid) && descendantPid > 1).toBe(true);
      const never = new Promise<void>(() => undefined);
      const unready: OwnedProcess = {
        child,
        supervised: true,
        supervisorReady: () => false,
        supervisorReadyOrClosed: never,
        cleanupAcknowledged: () => false,
        cleanupChannelClosed: never,
      };
      try {
        await expect(stopOwnedProcess(unready)).rejects.toThrow(
          "did not establish cleanup ownership",
        );
        expect(child.exitCode !== null || child.signalCode !== null).toBe(true);
        expect(await waitForProcessAbsence(descendantPid)).toBe(true);
      } finally {
        if (child.exitCode === null && child.signalCode === null) {
          child.kill("SIGKILL");
          await once(child, "exit");
        }
      }
    },
  );

  it("rejects a cleanup marker when the supervisor did not finish by group SIGKILL", async () => {
    const child = spawn(process.execPath, ["-e", "process.exit(0)"]);
    await once(child, "exit");
    const incomplete: OwnedProcess = {
      child,
      supervised: true,
      supervisorReady: () => true,
      supervisorReadyOrClosed: Promise.resolve(),
      cleanupAcknowledged: () => true,
      cleanupChannelClosed: Promise.resolve(),
    };
    await expect(stopOwnedProcess(incomplete)).rejects.toThrow(
      "without completed group cleanup evidence",
    );
  });

  it.skipIf(process.platform === "win32")(
    "reports a closed cleanup channel after still terminating the owned group",
    async () => {
      const owned = spawnOwnedNode(runningScript);
      await once(owned.child.stdout!, "data");
      owned.child.stdio[3]?.destroy();
      await expect(stopOwnedProcess(owned)).rejects.toThrow(
        "without completed group cleanup evidence",
      );
      expect(owned.child.exitCode !== null || owned.child.signalCode !== null).toBe(true);
    },
  );
});
