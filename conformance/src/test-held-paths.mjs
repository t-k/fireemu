// The files this process holds open whose path contains `fragment`, for tests that prove a handle was
// closed. Linux lists them under /proc (no `lsof` is installed on every Linux machine); macOS asks `lsof`.
//
// A helper that proves an absence must not turn an error into one: only a descriptor that was closed
// between the listing and the read (ENOENT) is skipped; any other failure is thrown.
import { execFileSync } from "node:child_process";
import { readdirSync, readlinkSync } from "node:fs";

const system = {
  platform: process.platform,
  readdir: readdirSync,
  readlink: readlinkSync,
  lsof: execFileSync,
};

export function heldPaths(fragment, { platform, readdir, readlink, lsof } = system) {
  if (platform === "linux") {
    const held = [];
    for (const fd of readdir("/proc/self/fd")) {
      let path;
      try {
        path = readlink(`/proc/self/fd/${fd}`);
      } catch (error) {
        if (error?.code === "ENOENT") continue;
        throw error;
      }
      if (path.includes(fragment)) held.push(path);
    }
    return held;
  }
  return lsof("lsof", ["-p", String(process.pid), "-Fn"], { encoding: "utf8" })
    .split("\n")
    .filter((line) => line.startsWith("n") && line.includes(fragment));
}
