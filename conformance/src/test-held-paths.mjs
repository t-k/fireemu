// The files this process holds open whose path contains `fragment`, for tests that prove a handle was
// closed. Linux lists them under /proc (no `lsof` is installed on every Linux machine); macOS asks `lsof`.
import { execFileSync } from "node:child_process";
import { readdirSync, readlinkSync } from "node:fs";

export function heldPaths(fragment) {
  if (process.platform === "linux") {
    const held = [];
    for (const fd of readdirSync("/proc/self/fd")) {
      try {
        const path = readlinkSync(`/proc/self/fd/${fd}`);
        if (path.includes(fragment)) held.push(path);
      } catch {
        // The descriptor of the directory listing itself, or one closed meanwhile.
      }
    }
    return held;
  }
  return execFileSync("lsof", ["-p", String(process.pid), "-Fn"], { encoding: "utf8" })
    .split("\n")
    .filter((line) => line.startsWith("n") && line.includes(fragment));
}
