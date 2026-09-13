import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { ownedProcessTarget } from "../src/lib/processTarget";
import { STATE_FILE } from "./global-setup";

// Stops the daemon started by the setup (its whole process group: the runner too).
export default async function globalTeardown(): Promise<void> {
  if (!existsSync(STATE_FILE)) return;
  const { pid } = JSON.parse(readFileSync(STATE_FILE, "utf8")) as { pid: number };
  unlinkSync(STATE_FILE);
  const target = ownedProcessTarget(pid, process.platform);
  const alive = () => {
    try {
      process.kill(target, 0);
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
      throw error;
    }
  };
  const signal = (s: NodeJS.Signals) => {
    try {
      process.kill(target, s);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
    }
  };
  signal("SIGINT");
  for (let i = 0; i < 40 && alive(); i += 1) {
    await new Promise((r) => setTimeout(r, 250));
  }
  if (alive()) {
    signal("SIGKILL");
    for (let i = 0; i < 40 && alive(); i += 1) {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  if (alive()) throw new Error(`daemon process target ${target} survived cleanup`);
}
