#!/usr/bin/env node
// The `fireemu` launcher: find the binary for this platform and supervise it.
//
// `fireemu` itself carries no binary. Each platform's daemon ships in its own package
// (`@fireemu/darwin-arm64` and friends), declared here as an optional dependency with an `os`
// and `cpu` of its own, so npm installs exactly one of them and skips the rest. There is no
// postinstall step and nothing is downloaded at install time: an `npm install` that resolved
// from a cache or a private registry is a complete, offline-capable installation.
//
// The supported list this prints when nothing matched is read out of the installed
// `package.json` rather than hard-coded, so it always names the platforms that were actually
// published beside this launcher.

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolveBinary, ensureExecutable } from "../binary.mjs";
import { constants as osConstants } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** This launcher's own manifest: the version, and the platforms published with it. */
function manifest() {
  return JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8"));
}

/** `@fireemu/<os>-<arch>` for the platform this process runs on. */
function platformPackage() {
  return `@fireemu/${process.platform}-${process.arch}`;
}

/** The error a user can act on: what this host is, and what was published. */
function noBinaryMessage() {
  const supported = Object.keys(manifest().optionalDependencies ?? {})
    .toSorted()
    .map((name) => `  ${name}`)
    .join("\n");
  const pkg = platformPackage();
  return [
    `fireemu has no binary for ${process.platform}-${process.arch}.`,
    "",
    `It looked for the package ${pkg}, which is not installed. Supported platforms:`,
    supported,
    "",
    "If your platform is on that list, the install skipped the optional dependency. This is",
    "usually one of:",
    "  - an install run with --no-optional, --omit=optional or --ignore-optional;",
    "  - a lockfile created on another platform and installed with --frozen-lockfile;",
    "  - a private registry or offline cache that does not mirror the @fireemu scope.",
    "",
    `Reinstall with optional dependencies enabled, or install ${pkg} directly.`,
    "If your platform is not on that list, fireemu does not publish a binary for it yet;",
    "build one from source (https://github.com/t-k/fireemu) and point",
    "FIREEMU_BINARY_PATH at it.",
  ].join("\n");
}

function main() {
  const binary = resolveBinary();
  if (!binary) {
    process.stderr.write(`${noBinaryMessage()}\n`);
    process.exit(1);
  }
  ensureExecutable(binary.path);
  // Keep terminal I/O and the foreground process group intact. PID-directed signals only
  // reach this launcher, so forward them and wait for the daemon's own shutdown to finish.
  //
  // The handlers are registered before the daemon is spawned: a signal that reached the launcher
  // between spawn() and process.on() would kill it with the default action and orphan the daemon.
  // Node runs a handler on the event loop, after main() has returned, so `child` exists by then.
  let child;
  for (const signal of ["SIGTERM", "SIGINT"]) {
    process.on(signal, () => {
      // Windows delivers console Ctrl-C to the child directly; child.kill would forcefully
      // terminate it instead of requesting graceful shutdown. Only wait on that platform.
      if (process.platform === "win32") return;
      // Do not use child.killed here: it means a signal was sent, not that the child exited.
      if (child.exitCode === null && child.signalCode === null) child.kill(signal);
    });
  }
  child = spawn(binary.path, process.argv.slice(2), {
    stdio: "inherit",
    windowsHide: false,
  });
  child.on("error", (error) => {
    if (child.pid) {
      // A failed signal delivery must not orphan a daemon that is still running.
      process.stderr.write(`fireemu could not signal the daemon: ${error.message}\n`);
      return;
    }
    const reason =
      error.code === "ENOENT"
        ? `${binary.path} does not exist (from ${binary.from})`
        : `${binary.path}: ${error.message}`;
    process.stderr.write(`fireemu could not start the daemon: ${reason}\n`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      // Report the death the way a shell does, so `fireemu ... ; echo $?` matches running the
      // daemon directly.
      const number = osConstants.signals[signal] ?? 0;
      process.exit(128 + number);
    }
    process.exit(code ?? 1);
  });
}

main();
