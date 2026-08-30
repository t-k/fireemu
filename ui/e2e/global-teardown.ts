import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { STATE_FILE } from "./global-setup";

// Stops the daemon started by the setup (its whole process group: the runner too).
export default async function globalTeardown(): Promise<void> {
  if (!existsSync(STATE_FILE)) return;
  const { pid } = JSON.parse(readFileSync(STATE_FILE, "utf8")) as { pid: number };
  unlinkSync(STATE_FILE);
  const signal = (s: NodeJS.Signals) => {
    try {
      process.kill(-pid, s);
    } catch {
      try {
        process.kill(pid, s);
      } catch {
        // already gone
      }
    }
  };
  signal("SIGINT");
  for (let i = 0; i < 40; i += 1) {
    await new Promise((r) => setTimeout(r, 250));
    try {
      process.kill(pid, 0);
    } catch {
      return;
    }
  }
  signal("SIGKILL");
}
