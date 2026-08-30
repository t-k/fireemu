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
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
const keep = args.includes("--keep");
const distIndex = args.indexOf("--dist");
let tarballs;
if (distIndex >= 0) {
  const dist = resolve(args[distIndex + 1] ?? "npm/dist");
  const found = readdirSync(dist).filter((f) => f.endsWith(".tgz"));
  const launcher = found.find((f) => /^fireemu-\d/.test(f));
  const platform = found.find((f) => f !== launcher);
  if (!launcher || !platform) {
    console.error(`verify-install: expected a launcher and a platform tarball in ${dist}, found ${found}`);
    process.exit(2);
  }
  tarballs = [join(dist, launcher), join(dist, platform)];
} else {
  tarballs = args.filter((a) => !a.startsWith("--")).map((p) => resolve(p));
}
if (tarballs.length !== 2) {
  console.error("usage: verify-install.mjs (--dist <dir> | <launcher.tgz> <platform.tgz>) [--keep]");
  process.exit(2);
}

const failures = [];
function step(name, fn) {
  try {
    fn();
    console.log(`ok   ${name}`);
  } catch (e) {
    failures.push(name);
    console.log(`FAIL ${name}\n${String(e.message).replace(/^/gm, "     ")}`);
  }
}
function run(cmd, cmdArgs, opts = {}) {
  const r = spawnSync(cmd, cmdArgs, { encoding: "utf8", ...opts });
  if (r.error) throw r.error;
  if (r.status !== 0) {
    throw new Error(`${cmd} ${cmdArgs.join(" ")} exited ${r.status}\n${r.stdout}${r.stderr}`);
  }
  return r;
}

// A path with a space and non-ASCII characters: the kind of directory a user's project sits in.
const base = mkdtempSync(join(tmpdir(), "fireemu-verify-"));
const project = join(base, "fireemu try ✓");
mkdirSync(project);
writeFileSync(join(project, "package.json"), JSON.stringify({ name: "try", private: true }));
const exe = process.platform === "win32" ? "fireemu.cmd" : "fireemu";
const bin = join(project, "node_modules", ".bin", exe);
const shell = process.platform === "win32";
const emptyPorts = [
  "--firestore-port", "0", "--http-port", "0", "--storage-port", "0",
  "--functions-port", "0", "--hub-port", "0", "--ui-port", "0",
];

step("installs offline, without scripts, from the two tarballs", () => {
  run("npm", ["install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", ...tarballs], {
    cwd: project,
    shell,
  });
  if (!existsSync(bin)) throw new Error(`${bin} was not linked`);
});

step("doctor exits 0 through node_modules/.bin and found the bundled runner", () => {
  const r = run(bin, ["doctor"], { cwd: project, shell });
  if (!/runner/.test(r.stdout)) throw new Error(`doctor said nothing about the runner:\n${r.stdout}`);
});

step("exec serves on ephemeral ports, runs the command and exits with its status", () => {
  run(bin, ["exec", ...emptyPorts, "--", "node", "-e", "process.exit(0)"], { cwd: project, shell });
  const r = spawnSync(bin, ["exec", ...emptyPorts, "--", "node", "-e", "process.exit(3)"], {
    cwd: project,
    shell,
    encoding: "utf8",
  });
  if (r.status !== 3) throw new Error(`expected the command's exit code 3, got ${r.status}\n${r.stderr}`);
});

step("the same installation works through a symlink to the project", () => {
  const link = join(base, "link");
  symlinkSync(project, link, "dir");
  run(join(link, "node_modules", ".bin", exe), ["doctor"], { cwd: link, shell });
});

if (process.platform !== "win32" && userInfo().uid !== 0) {
  step("doctor and exec work from a read-only working directory", () => {
    const ro = join(base, "read-only");
    mkdirSync(ro);
    chmodSync(ro, 0o555);
    try {
      run(bin, ["doctor"], { cwd: ro, shell });
      run(bin, ["exec", ...emptyPorts, "--", "node", "-e", "process.exit(0)"], { cwd: ro, shell });
    } finally {
      chmodSync(ro, 0o755);
    }
  });
  step("nothing is left running", () => {
    const ps = run("ps", ["-axo", "pid=,args="]);
    const stray = ps.stdout.split("\n").filter((l) => l.includes(project) && /fireemu|runner-node/.test(l));
    if (stray.length > 0) throw new Error(`still running:\n${stray.join("\n")}`);
  });
}

if (keep) {
  console.log(`install=${project}`);
} else {
  rmSync(base, { recursive: true, force: true });
}
console.log(failures.length === 0 ? "verify-install: ok" : `verify-install: ${failures.length} failure(s)`);
process.exit(failures.length);
