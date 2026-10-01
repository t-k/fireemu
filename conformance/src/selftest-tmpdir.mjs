// Runs a command (the selftest) with a private temp directory, removes it afterwards and fails a
// run that passed but left anything in it, naming what was left.
//
//   node src/selftest-tmpdir.mjs <command> [args...]
//
// Every test file and every process it starts inherits the private TMPDIR, so a temp directory a
// test forgets no longer accumulates in the shared one (the selftest alone left about 190 entries
// per run before its tests cleaned up).

import { spawn } from "node:child_process";
import { mkdtempSync, readdirSync } from "node:fs";
import { constants, tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { removeTree } from "./remove-tree.mjs";

/** Entries a tool creates on its own: Node's compile cache, enabled by package managers. */
export const TOOL_ENTRIES = new Set(["node-compile-cache"]);

/** The names a run left in its private temp directory, tool caches excluded, sorted. */
export function leftovers(names) {
  return names.filter((name) => !TOOL_ENTRIES.has(name)).toSorted();
}

/** The exit status of the run: the command's own, or 1 when it passed but left entries. */
export function runStatus(code, signal, left) {
  if (signal) return 128 + (constants.signals[signal] ?? 0);
  if (code !== 0) return code;
  return left.length > 0 ? 1 : 0;
}

const FORWARDED = ["SIGHUP", "SIGINT", "SIGTERM"];

async function main(command) {
  if (command.length === 0) {
    process.stderr.write("usage: node src/selftest-tmpdir.mjs <command> [args...]\n");
    return 2;
  }
  const directory = mkdtempSync(join(tmpdir(), "conformance-selftest-"));
  const env = { ...process.env, TMPDIR: directory, TMP: directory, TEMP: directory };
  const child = spawn(command[0], command.slice(1), { env, stdio: "inherit" });
  const forward = (signal) => child.kill(signal);
  for (const signal of FORWARDED) process.on(signal, forward);
  const [code, signal] = await new Promise((resolve) => {
    child.on("error", (error) => {
      process.stderr.write(`selftest-tmpdir: ${error.message}\n`);
      resolve([127, null]);
    });
    child.on("exit", (exitCode, exitSignal) => resolve([exitCode, exitSignal]));
  });
  const left = leftovers(readdirSync(directory));
  removeTree(directory);
  if (left.length > 0) {
    process.stderr.write(
      `selftest-tmpdir: the run left these entries in TMPDIR (removed now):\n${left.join("\n")}\n`,
    );
  }
  return runStatus(code, signal, left);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
