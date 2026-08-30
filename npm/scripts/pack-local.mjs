#!/usr/bin/env node
// The local proof that the published packages work: build this host's platform package from
// `target/release/fireemu` and pack both tarballs, exactly as the release workflow does.
//
//   cargo build --release -p fireemu        # after `pnpm -C ui build`, so the UI is embedded
//   node npm/scripts/pack-local.mjs
//
// Then install what it produced somewhere empty and run it:
//
//   mkdir /tmp/try && cd /tmp/try && npm init -y
//   npm install <the two tarballs it printed>
//   npx fireemu doctor
//
// The point of packing rather than linking is that `npm pack` applies the `files` allow-list
// and the executable bits, so what is exercised is the artifact a user would download and not
// the working tree it came from.

import { execFileSync } from "node:child_process";
import { mkdirSync, readdirSync, rmSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { buildPlatformPackage } from "../platforms/build-platform.mjs";
import { DEV_VERSION, hostPlatform, packageName } from "../platforms/platforms.mjs";
import { prepareLauncher } from "./prepare-launcher.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** `npm pack` into `outDir`, returning the tarball path it wrote. */
function pack(packageDir, outDir) {
  const before = new Set(readdirSync(outDir));
  execFileSync("npm", ["pack", "--pack-destination", outDir], {
    cwd: packageDir,
    stdio: ["ignore", "pipe", "inherit"],
  });
  const created = readdirSync(outDir).filter((f) => !before.has(f) && f.endsWith(".tgz"));
  if (created.length !== 1) {
    throw new Error(`npm pack in ${packageDir} produced ${created.length} tarballs, expected 1`);
  }
  return join(outDir, created[0]);
}

function main() {
  const platform = hostPlatform();
  if (!platform) {
    throw new Error(
      `fireemu publishes no package for ${process.platform}-${process.arch}; nothing to pack here`,
    );
  }
  const binary = join(repoRoot, "target", "release", `fireemu${platform.exe}`);
  if (!statSync(binary, { throwIfNoEntry: false })?.isFile()) {
    throw new Error(
      `no release binary at ${binary}. Run: pnpm -C ui install && pnpm -C ui build && ` +
        "cargo build --release -p fireemu",
    );
  }

  const dist = join(repoRoot, "npm", "dist");
  rmSync(dist, { recursive: true, force: true });
  mkdirSync(dist, { recursive: true });

  const platformDir = buildPlatformPackage({
    platformName: platform.name,
    binaryPath: binary,
    outDir: join(repoRoot, "npm", "platforms", "build", platform.name),
    version: DEV_VERSION,
  });
  prepareLauncher(repoRoot);

  const platformTarball = pack(platformDir, dist);
  const launcherTarball = pack(join(repoRoot, "npm", "fireemu"), dist);

  process.stdout.write(
    [
      `platform package: ${packageName(platform)} (${platform.target})`,
      `  ${platformTarball}`,
      "launcher package: fireemu",
      `  ${launcherTarball}`,
      "",
      "Try it:",
      "  mkdir -p /tmp/fireemu-try && cd /tmp/fireemu-try && npm init -y >/dev/null",
      `  npm install ${launcherTarball} ${platformTarball}`,
      "  npx fireemu doctor",
      "",
    ].join("\n"),
  );
}

main();
