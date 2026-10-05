// Runs one fixture under a local `fireemu exec` with a pinned virtual clock and returns what its handlers printed,
// placed on the logical timeline (the `STEP` line that follows a handler line is its logical instant). Loopback only:
// nothing here contacts a production service or reads a credential.
import { spawn } from "node:child_process";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const FRAME = /(SCHED_DELIVERY_FRAME|PROBE) (\{.*)$/;

/** Splits a daemon's output into handler lines placed on the logical timeline. Pure. */
export function parseTimeline(output) {
  const pending = [];
  const lines = [];
  const state = [];
  const manual = [];
  for (const line of String(output).split("\n")) {
    // `MANUAL <name> <instant> <answer>`: a run made by hand, at the logical instant the child printed
    const hand = /^MANUAL (\S+) (\S+) (\{.*)$/.exec(line);
    if (hand) {
      let status = null;
      try {
        status = JSON.parse(hand[3]).status ?? null;
      } catch {
        // an answer the child cut: the run is still recorded
      }
      manual.push({ name: hand[1], at: hand[2], status });
      continue;
    }
    const frame = FRAME.exec(line);
    if (frame) {
      try {
        pending.push({ kind: frame[1], value: JSON.parse(frame[2]) });
      } catch {
        // a handler line the daemon cut: not a frame
      }
      continue;
    }
    const step = /^STEP (\S+)/.exec(line);
    if (step) {
      for (const item of pending.splice(0)) lines.push({ at: step[1], ...item });
      continue;
    }
    if (line.startsWith("STATE ")) state.push(JSON.parse(line.slice(6)));
  }
  return { lines, unplaced: pending.length, state: state.at(-1) ?? null, manual };
}

const freePort = () =>
  new Promise((resolve) => {
    const server = net.createServer().listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });

/**
 * @param {object} options
 * @param {string} options.fireemu the daemon binary
 * @param {string} options.node a Node 22 binary
 * @param {string} options.depsDir a node_modules directory holding firebase-functions 7.3.2
 * @param {string} options.fixtureDir the functions source to run
 * @param {"strict"|"emulator"} options.profile
 * @param {string} options.start the logical start instant, RFC 3339 UTC
 * @param {number} options.seconds logical seconds to advance, one at a time
 * @param {string[]} [options.manual] functions to run by hand before the clock moves
 * @param {{name: string, afterSeconds: number}[]} [options.manualAt] functions to run by hand right after a step
 * @param {boolean} [options.clockFile] keep the logical epoch seconds in a file for a handler that lasts logical time
 * @param {boolean} [options.awaitIdle] wait for the runtime to be idle after each step
 * @param {number} [options.pauseMs] real milliseconds to wait after each step
 * @param {(source: string, context: {clockFile?: string}) => string} [options.patch] a rewrite of the copied `index.js`
 */
export async function runLocal({
  fireemu,
  node,
  depsDir,
  fixtureDir,
  profile,
  start,
  seconds,
  manual = [],
  manualAt = [],
  clockFile = false,
  awaitIdle = true,
  pauseMs = 40,
  patch = (source, _context) => source,
}) {
  const work = mkdtempSync(join(tmpdir(), "fireemu-local-delivery-"));
  try {
    cpSync(fixtureDir, join(work, "fixture"), { recursive: true });
    const index = join(work, "fixture", "index.js");
    const clockPath = clockFile ? join(work, "clock.txt") : undefined;
    writeFileSync(index, patch(readFileSync(index, "utf8"), { clockFile: clockPath }));
    symlinkSync(depsDir, join(work, "fixture", "node_modules"));
    writeFileSync(
      join(work, "fireemu.json"),
      JSON.stringify({ schemaVersion: 1, profile, daemon: { clockStart: start } }),
    );
    mkdirSync(join(work, "home"));
    const port = await freePort();
    const args = [
      "exec",
      "--project",
      "demo-sched",
      "--only",
      "functions",
      "--config",
      join(work, "fireemu.json"),
      "--functions",
      join(work, "fixture"),
      "--http-port",
      String(port),
      ...[
        "functions",
        "firestore",
        "storage",
        "eventarc",
        "tasks",
        "pubsub",
        "ui",
        "hub",
        "logging",
      ].flatMap((name) => ["--" + name + "-port", "0"]),
      "--",
      node,
      join(here, "local-child.mjs"),
    ];
    const env = {
      PATH: dirname(node) + ":/usr/bin:/bin",
      HOME: join(work, "home"),
      LOCAL_START: start,
      LOCAL_SECONDS: String(seconds),
      LOCAL_AWAIT_IDLE: awaitIdle ? "1" : "0",
      LOCAL_PAUSE_MS: String(pauseMs),
      LOCAL_MANUAL: manual.join(","),
      ...(manualAt.length
        ? { LOCAL_MANUAL_AT: manualAt.map((m) => `${m.name}@${m.afterSeconds}`).join(",") }
        : {}),
      ...(clockPath ? { LOCAL_CLOCK_FILE: clockPath } : {}),
    };
    const child = spawn(fireemu, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", (d) => (output += d));
    child.stderr.on("data", (d) => (output += d));
    const code = await new Promise((resolve) => child.on("exit", resolve));
    return { exitCode: code, output, ...parseTimeline(output) };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}
