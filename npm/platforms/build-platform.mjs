#!/usr/bin/env node
// Assembles one `@fireemu/<os>-<arch>` package from a built binary.
//
//   node npm/platforms/build-platform.mjs \
//     --platform darwin-arm64 \
//     --binary target/aarch64-apple-darwin/release/fireemu \
//     --out npm/platforms/build/darwin-arm64 \
//     [--version 1.2.3]
//
// The result is a complete, self-contained package -- there is no template to keep in sync
// and nothing is checked in per platform, so a new platform is one row in `platforms.mjs`.
//
// Layout, and why: the daemon locates its Node runner at `<directory of the executable>/
// runner-node/index.mjs`, so the runner sources are copied to `bin/runner-node/` next to
// `bin/fireemu`. Nothing else has to be resolved at run time -- the Emulator UI is compiled
// into the binary itself.

import {
  chmodSync,
  copyFileSync,
  cpSync,
  mkdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { DEV_VERSION, packageName, platformByName } from "./platforms.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** The runner sources every platform package ships. */
export const RUNNER_FILES = ["index.mjs", "callable-app-check.mjs"];

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (!flag.startsWith("--")) throw new Error(`unexpected argument ${flag}`);
    const value = argv[++i];
    if (value === undefined) throw new Error(`${flag} needs a value`);
    out[flag.slice(2)] = value;
  }
  return out;
}

/** The manifest of one platform package. */
export function platformManifest(platform, version) {
  return {
    name: packageName(platform),
    version,
    description: `The fireemu daemon for ${platform.name}`,
    homepage: "https://github.com/reckona/fireemu#readme",
    repository: {
      type: "git",
      url: "git+https://github.com/reckona/fireemu.git",
    },
    license: "Apache-2.0",
    // npm installs an optional dependency only when both match, so exactly one of these
    // packages lands on any given host and the others are skipped without an error.
    os: [platform.os],
    cpu: [platform.cpu],
    engines: { node: ">=20" },
    // No `bin`: the executable is launched by the `fireemu` package, and declaring it here
    // would put two entries in the same `node_modules/.bin/fireemu`.
    files: ["bin", "README.md", "LICENSE"],
    preferUnplugged: true,
  };
}

/** The package page for one platform: short, and honest about what it is. */
export function platformReadme(platform, version) {
  return `# ${packageName(platform)}

The [fireemu](https://www.npmjs.com/package/fireemu) daemon built for \`${platform.name}\`
(Rust target \`${platform.target}\`), version ${version}.

${platform.notes}

This package is installed automatically as an optional dependency of \`fireemu\` and is not
meant to be depended on directly. Install the launcher instead:

\`\`\`sh
npm install -D fireemu
\`\`\`

It contains the daemon (\`bin/fireemu${platform.exe}\`, with the Emulator UI compiled in) and the
Node runner that hosts a Functions codebase (\`bin/runner-node/\`). Nothing is downloaded at
install time and there is no install script.
`;
}

/**
 * Writes the package for `platformName` from `binaryPath` into `outDir`, replacing whatever
 * was there. Returns the directory it wrote.
 */
export function buildPlatformPackage({ platformName, binaryPath, outDir, version = DEV_VERSION }) {
  const platform = platformByName(platformName);
  const binary = resolve(binaryPath);
  if (!statSync(binary, { throwIfNoEntry: false })?.isFile()) {
    throw new Error(`no binary at ${binary}; build it first`);
  }
  const out = resolve(outDir);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(join(out, "bin"), { recursive: true });

  const installed = join(out, "bin", `fireemu${platform.exe}`);
  copyFileSync(binary, installed);
  if (platform.os !== "win32") chmodSync(installed, 0o755);

  const runnerOut = join(out, "bin", "runner-node");
  mkdirSync(runnerOut, { recursive: true });
  for (const file of RUNNER_FILES) {
    copyFileSync(join(repoRoot, "tools", "runner-node", file), join(runnerOut, file));
  }

  writeFileSync(
    join(out, "package.json"),
    `${JSON.stringify(platformManifest(platform, version), undefined, 2)}\n`,
  );
  writeFileSync(join(out, "README.md"), platformReadme(platform, version));
  cpSync(join(repoRoot, "LICENSE"), join(out, "LICENSE"));
  return out;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  for (const required of ["platform", "binary", "out"]) {
    if (!args[required]) throw new Error(`--${required} is required`);
  }
  const out = buildPlatformPackage({
    platformName: args.platform,
    binaryPath: args.binary,
    outDir: args.out,
    version: args.version ?? DEV_VERSION,
  });
  process.stdout.write(`${out}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (e) {
    process.stderr.write(`build-platform: ${e.message}\n`);
    process.exit(1);
  }
}
