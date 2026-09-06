#!/usr/bin/env node
// The `fireemu` launcher: find the binary for this platform and become it.
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

import { spawnSync } from "node:child_process";
import { chmodSync, accessSync, constants as fsConstants, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { constants as osConstants } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));

/** This launcher's own manifest: the version, and the platforms published with it. */
function manifest() {
  return JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8"));
}

/** `@fireemu/<os>-<arch>` for the platform this process runs on. */
function platformPackage() {
  return `@fireemu/${process.platform}-${process.arch}`;
}

/** The daemon's file name inside a platform package. */
function binaryName() {
  return process.platform === "win32" ? "fireemu.exe" : "fireemu";
}

/**
 * The daemon to run.
 *
 * `FIREEMU_BINARY_PATH` wins so a vendored, air-gapped or locally built binary can be used
 * without touching `node_modules`. Otherwise the platform package is resolved through Node's
 * own algorithm, which finds it wherever the package manager put it -- a flat `node_modules`,
 * a pnpm store, or a workspace root.
 */
function resolveBinary() {
  const override = process.env.FIREEMU_BINARY_PATH;
  if (override) {
    return { path: override, from: "FIREEMU_BINARY_PATH" };
  }
  const pkg = platformPackage();
  try {
    const root = dirname(require.resolve(`${pkg}/package.json`));
    return { path: join(root, "bin", binaryName()), from: pkg };
  } catch {
    return undefined;
  }
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

/**
 * Makes sure the binary is executable.
 *
 * npm preserves the executable bit through a tarball, but a registry proxy, a `pnpm` store on
 * a filesystem that drops modes, or an archive round-tripped through a zip can lose it. Fixing
 * it here keeps the package free of an install script; a read-only installation that is
 * already executable is left alone.
 */
function ensureExecutable(path) {
  if (process.platform === "win32") return;
  try {
    accessSync(path, fsConstants.X_OK);
    return;
  } catch {
    // Fall through and try to grant it.
  }
  try {
    chmodSync(path, 0o755);
  } catch {
    // A read-only install: let the spawn below report the real failure.
  }
}

function main() {
  const binary = resolveBinary();
  if (!binary) {
    process.stderr.write(`${noBinaryMessage()}\n`);
    process.exit(1);
  }
  ensureExecutable(binary.path);
  // stdio is inherited, so the daemon reads the real terminal and Ctrl-C reaches it directly:
  // the launcher is in the same process group and does not need to forward anything.
  const result = spawnSync(binary.path, process.argv.slice(2), {
    stdio: "inherit",
    windowsHide: false,
  });
  if (result.error) {
    const reason =
      result.error.code === "ENOENT"
        ? `${binary.path} does not exist (from ${binary.from})`
        : `${binary.path}: ${result.error.message}`;
    process.stderr.write(`fireemu could not start the daemon: ${reason}\n`);
    process.exit(1);
  }
  if (result.signal) {
    // Report the death the way a shell does, so `fireemu ... ; echo $?` matches running the
    // daemon directly.
    const number = osConstants.signals[result.signal] ?? 0;
    process.exit(128 + number);
  }
  process.exit(result.status ?? 1);
}

main();
