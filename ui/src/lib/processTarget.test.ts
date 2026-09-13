import { spawn } from "node:child_process";
import { once } from "node:events";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { ownedProcessCommand, stopOwnedProcess } from "./processTarget";

describe("ownedProcessCommand", () => {
  it("runs the command directly on Windows", () => {
    expect(ownedProcessCommand("fireemu", ["up"], "win32", "process-group")).toEqual({
      command: "fireemu",
      args: ["up"],
    });
  });

  it("runs the command through the POSIX supervisor", () => {
    expect(ownedProcessCommand("fireemu", ["up"], "darwin", "process-group")).toEqual({
      command: "process-group",
      args: ["fireemu", "up"],
    });
  });
});

describe("owned daemon lifecycle", () => {
  it("stops only its retained child and preserves an unrelated process", async () => {
    const args = ["-e", "console.log('ready'); setInterval(() => {}, 1000)"];
    const owned = spawn(process.execPath, args, {
      detached: true,
      stdio: ["ignore", "pipe", "ignore"],
    });
    const unrelated = spawn(process.execPath, args, {
      detached: true,
      stdio: ["ignore", "pipe", "ignore"],
    });
    await Promise.all([once(owned.stdout!, "data"), once(unrelated.stdout!, "data")]);
    try {
      await stopOwnedProcess(owned);
      expect(owned.exitCode !== null || owned.signalCode !== null).toBe(true);
      expect(unrelated.exitCode).toBeNull();
      expect(unrelated.signalCode).toBeNull();
      expect(unrelated.kill(0)).toBe(true);
    } finally {
      await stopOwnedProcess(owned);
      await stopOwnedProcess(unrelated);
    }
  });

  it("can stop a child before its application readiness event", async () => {
    const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
      detached: true,
      stdio: "ignore",
    });
    await once(child, "spawn");
    try {
      await stopOwnedProcess(child);
      expect(child.exitCode !== null || child.signalCode !== null).toBe(true);
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGKILL");
        await once(child, "exit");
      }
    }
  });

  it("does not signal a previously exited daemon", async () => {
    const child = spawn(process.execPath, ["-e", "process.exit(0)"], { detached: true });
    await once(child, "exit");
    // Mutating a PID can model reuse; the exited ChildProcess must never be used to signal it.
    const unrelated = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
      detached: true,
      stdio: "ignore",
    });
    await once(unrelated, "spawn");
    try {
      Object.defineProperty(child, "pid", { value: unrelated.pid });
      await stopOwnedProcess(child);
      expect(unrelated.kill(0)).toBe(true);
      expect(unrelated.signalCode).toBeNull();
    } finally {
      await stopOwnedProcess(unrelated);
    }
  });

  it.skipIf(process.platform === "win32")(
    "the POSIX supervisor reaps descendants when the daemon leader exits first",
    async () => {
      const supervisor = resolve(process.cwd(), "../verification/quint/bin/process-group");
      const script = [
        "const { spawn } = require('node:child_process');",
        "const descendant = spawn(process.execPath, ['-e', `process.on('SIGINT', () => {}); process.on('SIGTERM', () => {}); setInterval(() => {}, 1000)`], { stdio: 'ignore' });",
        "process.on('SIGINT', () => process.exit(0));",
        "process.stdout.write(String(descendant.pid));",
        "setInterval(() => {}, 1000);",
      ].join(" ");
      const command = ownedProcessCommand(
        process.execPath,
        ["-e", script],
        process.platform,
        supervisor,
      );
      const child = spawn(command.command, command.args, {
        detached: true,
        stdio: ["ignore", "pipe", "ignore"],
      });
      const [descendantOutput] = await once(child.stdout!, "data");
      const descendantPid = Number(descendantOutput.toString());
      if (!Number.isSafeInteger(descendantPid) || descendantPid <= 1) {
        throw new Error(`invalid descendant PID: ${descendantOutput.toString()}`);
      }
      const unrelated = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
        detached: true,
        stdio: "ignore",
      });
      await once(unrelated, "spawn");
      try {
        await stopOwnedProcess(child);
        expect(child.exitCode !== null || child.signalCode !== null).toBe(true);
        expect(() => process.kill(descendantPid, 0)).toThrow();
        expect(unrelated.exitCode).toBeNull();
        expect(unrelated.signalCode).toBeNull();
        expect(unrelated.kill(0)).toBe(true);
      } finally {
        await stopOwnedProcess(child);
        await stopOwnedProcess(unrelated);
      }
    },
    10_000,
  );
});
