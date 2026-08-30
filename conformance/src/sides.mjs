// Starting and, above all, stopping the two sides.
//
// Both supervisors are spawned as process-group leaders (`detached: true`). The official
// suite starts a Java child per downloadable emulator and a Node child per functions
// codebase, and fireemu starts a Node runner; killing the leader alone would orphan
// them. Every exit path here signals the whole group, waits, and escalates to SIGKILL, so a
// conformance run never leaves an emulator behind.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";

import { CONFORMANCE_DIR, OFFICIAL_PORTS, PROJECT, REPO_ROOT, TESTD_PORTS } from "./config.mjs";

const GRACE_MS = 8_000;

/** Signals a whole process group and resolves once the leader is gone. */
async function terminateGroup(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const groupKill = (signal) => {
    try {
      process.kill(-child.pid, signal);
    } catch {
      // The group is already gone.
    }
  };
  const exited = new Promise((resolve) => child.once("exit", resolve));
  groupKill("SIGTERM");
  const timer = setTimeout(() => groupKill("SIGKILL"), GRACE_MS);
  await exited;
  clearTimeout(timer);
}

/**
 * Runs one supervisor to completion, returning the parsed run it wrote.
 *
 * @param {{name: string, command: string, args: string[], env: Record<string,string>,
 *          outPath: string, timeoutMs: number}} spec
 */
async function runSupervisor(spec) {
  await rm(spec.outPath, { force: true });
  const child = spawn(spec.command, spec.args, {
    cwd: CONFORMANCE_DIR,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, ...spec.env },
  });

  const log = [];
  const capture = (stream) =>
    stream.on("data", (chunk) => {
      const text = chunk.toString();
      log.push(text);
      if (process.env.CONFORMANCE_VERBOSE) process.stderr.write(text);
    });
  capture(child.stdout);
  capture(child.stderr);

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    void terminateGroup(child);
  }, spec.timeoutMs);

  const onSignal = () => {
    void terminateGroup(child).then(() => process.exit(130));
  };
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);

  const code = await new Promise((resolve) => child.once("exit", resolve));
  clearTimeout(timer);
  process.off("SIGINT", onSignal);
  process.off("SIGTERM", onSignal);
  // The leader has exited; make sure nothing in its group outlived it.
  await terminateGroup(child);

  if (timedOut) {
    throw new Error(`${spec.name}: timed out after ${spec.timeoutMs} ms\n${log.join("")}`);
  }
  if (!existsSync(spec.outPath)) {
    throw new Error(`${spec.name}: exited ${code} without writing a run\n${log.join("")}`);
  }
  const run = JSON.parse(await readFile(spec.outPath, "utf8"));
  return { run, exitCode: code, log: log.join("") };
}

const shellQuote = (parts) => parts.map((p) => `'${p.replaceAll("'", `'\\''`)}'`).join(" ");

/** The official Local Emulator Suite, pinned by `conformance/package.json`. */
export function runOfficial({ variant, outPath, timeoutMs = 600_000 }) {
  const inner = shellQuote(["node", "src/run-corpus.mjs"]);
  return runSupervisor({
    name: `oracle/${variant}`,
    command: join(CONFORMANCE_DIR, "node_modules/.bin/firebase"),
    args: [
      "emulators:exec",
      "--project",
      PROJECT,
      "--config",
      "firebase.json",
      "--only",
      "firestore,auth,storage,functions",
      inner,
    ],
    env: {
      CONFORMANCE_SIDE: "oracle",
      CONFORMANCE_VARIANT: variant,
      CONFORMANCE_OUT: outPath,
      CONFORMANCE_FUNCTIONS_HOST: `127.0.0.1:${OFFICIAL_PORTS.functions}`,
      // The CLI must never look for credentials or phone home for a demo project.
      FIREBASE_CLI_EXPERIMENTS: "",
      GOOGLE_APPLICATION_CREDENTIALS: "",
    },
    outPath,
    timeoutMs,
  });
}

/** fireemu, built from this checkout. */
export function runTestd({ variant, outPath, config, timeoutMs = 600_000 }) {
  const binary =
    process.env.FIREEMU_BIN ??
    ["target/release/fireemu", "target/debug/fireemu"]
      .map((p) => join(REPO_ROOT, p))
      .find((p) => existsSync(p));
  if (!binary) {
    throw new Error(
      "fireemu is not built: run `cargo build -p fireemu` (or set FIREEMU_BIN)",
    );
  }
  return runSupervisor({
    name: `testd/${variant}`,
    command: binary,
    args: [
      "exec",
      "--config",
      config,
      "--project",
      PROJECT,
      "--only",
      "auth,firestore,storage,functions,appcheck",
      "--firestore-port",
      String(TESTD_PORTS.firestore),
      "--http-port",
      String(TESTD_PORTS.http),
      "--storage-port",
      String(TESTD_PORTS.storage),
      "--functions-port",
      String(TESTD_PORTS.functions),
      "--functions",
      join(CONFORMANCE_DIR, "functions"),
      "--",
      "node",
      "src/run-corpus.mjs",
    ],
    env: {
      CONFORMANCE_SIDE: "testd",
      CONFORMANCE_VARIANT: variant,
      CONFORMANCE_OUT: outPath,
      CONFORMANCE_FUNCTIONS_HOST: `127.0.0.1:${TESTD_PORTS.functions}`,
    },
    outPath,
    timeoutMs,
  });
}

/** The fireemu configuration a variant runs under. */
export const configFor = (variant) =>
  join(
    CONFORMANCE_DIR,
    variant === "appCheckEnforced"
      ? "fireemu.appcheck-enforced.json"
      : "fireemu.baseline.json",
  );
