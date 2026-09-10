#!/usr/bin/env node
// Proves that the packed packages install and run where installations actually live.
//
//   node npm/scripts/verify-install.mjs --dist npm/dist            # after pack-local.mjs
//   node npm/scripts/verify-install.mjs <launcher.tgz> <platform.tgz> [--keep]
//
// It installs the two tarballs exactly as a user would -- `npm install` with no network
// (`--offline`), no scripts and no audit -- into a project whose path carries a space and
// non-ASCII characters, then runs `doctor` and an `exec` round trip through `node_modules/.bin`,
// again through a symlink to the project, and from a read-only working directory. Every step
// is reported; the exit code is the number of failures. `--keep` leaves the project behind and
// prints its path as `install=<dir>`, so a caller can point other checks at the installed
// binary.

import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const keep = args.includes("--keep");
const distIndex = args.indexOf("--dist");
let tarballs;
if (distIndex >= 0) {
  const dist = resolve(args[distIndex + 1] ?? "npm/dist");
  let found;
  try {
    found = readdirSync(dist).filter((f) => f.endsWith(".tgz"));
  } catch (error) {
    const message = error instanceof Error ? error.message : error;
    console.error(`verify-install: ${escapeForLog(message)}`);
    process.exit(2);
  }
  const launcher = found.find((f) => /^fireemu-\d/.test(f));
  const platform = found.find((f) => f !== launcher);
  if (!launcher || !platform) {
    console.error(
      escapeForLog(
        `verify-install: expected a launcher and a platform tarball in ${dist}, found ${found}`,
      ),
    );
    process.exit(2);
  }
  tarballs = [join(dist, launcher), join(dist, platform)];
} else {
  tarballs = args.filter((a) => !a.startsWith("--")).map((p) => resolve(p));
}
if (tarballs.length !== 2) {
  console.error(
    "usage: verify-install.mjs (--dist <dir> | <launcher.tgz> <platform.tgz>) [--keep]",
  );
  process.exit(2);
}

const failures = [];
function escapeForLog(value) {
  return Array.from(String(value), (character) => {
    const code = character.codePointAt(0);
    const control = code <= 8 || (code >= 11 && code <= 31) || (code >= 127 && code <= 159);
    return control ? `\\u{${code.toString(16)}}` : character;
  }).join("");
}
function step(name, fn) {
  try {
    fn();
    console.log(`ok   ${name}`);
  } catch (e) {
    failures.push(name);
    console.log(`FAIL ${name}\n${escapeForLog(e.message).replace(/^/gm, "     ")}`);
  }
}
function run(cmd, cmdArgs, opts = {}) {
  const r = spawnSync(cmd, cmdArgs, { encoding: "utf8", ...opts });
  if (r.error) throw r.error;
  if (r.status !== 0) {
    throw new Error(
      escapeForLog(`${cmd} ${cmdArgs.join(" ")} exited ${r.status}\n${r.stdout}${r.stderr}`),
    );
  }
  return r;
}

// A path with a space and non-ASCII characters: the kind of directory a user's project sits in.
const base = mkdtempSync(join(tmpdir(), "fireemu-verify-"));
const project = join(base, "fireemu try ✓");
mkdirSync(project);
writeFileSync(
  join(project, "package.json"),
  JSON.stringify({ name: "fireemu-package-verification", version: "0.0.0", private: true }),
);
const exe = process.platform === "win32" ? "fireemu.cmd" : "fireemu";
const bin = join(project, "node_modules", ".bin", exe);
const launcher = join(project, "node_modules", "fireemu", "bin", "fireemu.mjs");
const nodeDirectory = dirname(process.execPath);
const npmCli = [
  process.env.npm_execpath,
  join(nodeDirectory, "node_modules", "npm", "bin", "npm-cli.js"),
  join(nodeDirectory, "..", "node_modules", "npm", "bin", "npm-cli.js"),
  join(nodeDirectory, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
].find((candidate) => candidate && existsSync(candidate));
const emptyPorts = [
  "--firestore-port",
  "0",
  "--http-port",
  "0",
  "--storage-port",
  "0",
  "--functions-port",
  "0",
  "--hub-port",
  "0",
  "--ui-port",
  "0",
];

step("installs offline, without scripts, from the two tarballs", () => {
  if (!npmCli) throw new Error("cannot locate npm-cli.js beside the current Node installation");
  run(
    process.execPath,
    [npmCli, "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", ...tarballs],
    { cwd: project },
  );
  if (!existsSync(bin)) throw new Error(`${bin} was not linked`);
});

step("doctor exits 0 through node_modules/.bin and found the bundled runner", () => {
  const r = run(process.execPath, [launcher, "doctor"], { cwd: project });
  if (!/runner/.test(r.stdout))
    throw new Error(`doctor said nothing about the runner:\n${r.stdout}`);
});

step("init creates a strict canonical configuration through the packaged launcher", () => {
  const initialized = join(base, "initialized project");
  mkdirSync(initialized);
  run(process.execPath, [launcher, "init", "--yes"], { cwd: initialized });
  const generated = JSON.parse(readFileSync(join(initialized, "fireemu.json"), "utf8"));
  if (generated.profile !== "strict") {
    throw new Error(`init selected ${JSON.stringify(generated.profile)} instead of strict`);
  }
  if (generated.firestore?.edition !== "standard" || generated.firestore?.apiMode !== "native") {
    throw new Error(`init generated an unexpected Firestore mode: ${JSON.stringify(generated)}`);
  }
});

step("exec serves on ephemeral ports, runs the command and exits with its status", () => {
  run(process.execPath, [launcher, "exec", ...emptyPorts, "--", "node", "-e", "process.exit(0)"], {
    cwd: project,
  });
  const r = spawnSync(
    process.execPath,
    [launcher, "exec", ...emptyPorts, "--", "node", "-e", "process.exit(3)"],
    { cwd: project, encoding: "utf8" },
  );
  if (r.status !== 3)
    throw new Error(`expected the command's exit code 3, got ${r.status}\n${r.stderr}`);
});

step("the packaged launcher forwards signals and waits for native shutdown", () => {
  const tests = fileURLToPath(new URL("launcher.test.mjs", import.meta.url));
  run(process.execPath, ["--test", tests], {
    cwd: project,
    env: { ...process.env, FIREEMU_TEST_LAUNCHER: launcher },
    timeout: 120_000,
  });
});

step("the same installation works through a symlink to the project", () => {
  const link = join(base, "link");
  symlinkSync(project, link, "dir");
  const linkedLauncher = join(link, "node_modules", "fireemu", "bin", "fireemu.mjs");
  run(process.execPath, [linkedLauncher, "doctor"], { cwd: link });
});

if (process.platform !== "win32" && userInfo().uid !== 0) {
  step("doctor and exec work from a read-only working directory", () => {
    const ro = join(base, "read-only");
    mkdirSync(ro);
    chmodSync(ro, 0o555);
    try {
      run(process.execPath, [launcher, "doctor"], { cwd: ro });
      run(
        process.execPath,
        [launcher, "exec", ...emptyPorts, "--", "node", "-e", "process.exit(0)"],
        { cwd: ro },
      );
    } finally {
      chmodSync(ro, 0o755);
    }
  });
  step("nothing is left running", () => {
    const ps = run("ps", ["-axo", "pid=,args="]);
    const stray = ps.stdout
      .split("\n")
      .filter((l) => l.includes(project) && /fireemu|runner-node/.test(l));
    if (stray.length > 0) throw new Error(`still running:\n${stray.join("\n")}`);
  });
}

if (keep) {
  console.log(`install=${escapeForLog(project)}`);
} else {
  rmSync(base, { recursive: true, force: true });
}
console.log(
  failures.length === 0 ? "verify-install: ok" : `verify-install: ${failures.length} failure(s)`,
);
process.exit(failures.length);
