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
import { makeOwnerWritable, removeTree } from "./remove-tree.mjs";

/** Entries a tool creates on its own: Node's compile cache, enabled by package managers. */
export const TOOL_ENTRIES = new Set(["node-compile-cache"]);

/** The names a run left in its private temp directory, tool caches excluded, sorted. */
export function leftovers(names) {
  return names.filter((name) => !TOOL_ENTRIES.has(name)).toSorted();
}

/**
 * The exit status of the run: the command's own failure first (its signal or exit code), then
 * 128+n for a terminating signal the wrapper received and forwarded (a command may handle it
 * and exit 0), then 1 when it passed but left entries or the directory could not be inspected
 * or removed.
 */
export function runStatus(code, signal, left, received = null, cleanupFailed = false) {
  if (signal) return 128 + (constants.signals[signal] ?? 0);
  if (code !== 0) return code;
  if (received) return 128 + (constants.signals[received] ?? 0);
  return left.length > 0 || cleanupFailed ? 1 : 0;
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
  let received = null;
  const forward = (signal) => {
    received ??= signal;
    child.kill(signal);
  };
  for (const signal of FORWARDED) process.on(signal, forward);
  const [code, signal] = await new Promise((resolve) => {
    child.on("error", (error) => {
      process.stderr.write(`selftest-tmpdir: ${error.message}\n`);
      resolve([127, null]);
    });
    child.on("exit", (exitCode, exitSignal) => resolve([exitCode, exitSignal]));
  });
  // Restore permissions first, so a command cannot hide a leftover by removing them; an
  // inspection failure never stops the removal, and neither replaces the command's own status.
  const problems = [];
  let left = [];
  try {
    makeOwnerWritable(directory);
    left = leftovers(readdirSync(directory));
  } catch (error) {
    problems.push(`could not list ${directory}: ${error.message}`);
  }
  try {
    removeTree(directory);
  } catch (error) {
    problems.push(`could not remove ${directory}: ${error.message}`);
  }
  if (left.length > 0) {
    process.stderr.write(
      `selftest-tmpdir: the run left these entries in TMPDIR (removed now):\n${left.join("\n")}\n`,
    );
  }
  for (const problem of problems) process.stderr.write(`selftest-tmpdir: ${problem}\n`);
  return runStatus(code, signal, left, received, problems.length > 0);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exitCode = await main(process.argv.slice(2));
}
