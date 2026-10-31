// CI exercises the real PID namespace and an owned detached child retaining stderr.
import { spawn } from "node:child_process";
import {
  mkdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  writeFileSync,
  chmodSync,
  existsSync,
} from "node:fs";
import { resolve, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import {
  RUNS,
  runEntry,
  runUntilFatal,
  rtdbNamespaceError,
  writeReleaseSummary,
  observeUnlessFatal,
} from "./release-strict-regression.mjs";

const marker = "fireemu-rtdb-namespace-owned-probe";
const pidIdentity = (pid) => {
  try {
    const root = `/proc/${pid}`;
    const stat = readFileSync(`${root}/stat`, "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
    return {
      pid,
      birth: fields[19],
      comm: readFileSync(`${root}/comm`, "utf8").trim(),
      args: readFileSync(`${root}/cmdline`, "utf8").replaceAll("\0", " "),
      exe: readlinkSync(`${root}/exe`),
    };
  } catch {
    return undefined;
  }
};
export function sameOwnedIdentity(a, b) {
  return Boolean(
    a &&
    b &&
    ["pid", "birth", "comm", "args", "exe"].every(
      (key) => a[key] !== undefined && a[key] === b[key],
    ),
  );
}
export function sameInheritedPipe(a, b) {
  return typeof a === "string" && /^(?:pipe|socket):\[\d+\]$/.test(a) && a === b;
}
const directChildren = (pid) => {
  try {
    return readFileSync(`/proc/${pid}/task/${pid}/children`, "utf8")
      .trim()
      .split(/\s+/)
      .filter(Boolean)
      .map(Number);
  } catch {
    return [];
  }
};
function findOwned(root, rejections) {
  const rootIdentity = pidIdentity(root);
  if (!sameOwnedIdentity(rootIdentity, rootIdentity)) return undefined;
  const queue = [{ pid: root, ancestors: [rootIdentity] }],
    seen = new Set([root]);
  while (queue.length) {
    const { pid: parent, ancestors } = queue.shift();
    for (const pid of directChildren(parent)) {
      if (seen.has(pid)) continue;
      seen.add(pid);
      const identity = pidIdentity(pid);
      if (!identity) {
        try {
          const args = readFileSync(`/proc/${pid}/cmdline`, "utf8");
          if (args.includes(marker) && rejections.length < 8)
            rejections.push({ pid, reason: "marked process identity unavailable" });
        } catch {
          /* An exited or unreadable child is not a witness. */
        }
      }
      if (identity?.args.includes(marker)) {
        try {
          const childPipe = readlinkSync(`/proc/${pid}/fd/2`);
          const parentPipe = readlinkSync(`/proc/${parent}/fd/2`);
          const status = readFileSync(`/proc/${pid}/status`, "utf8");
          const nsPids = /^NSpid:\s+(.+)$/m.exec(status)?.[1].trim().split(/\s+/).map(Number);
          const parentIdentity = pidIdentity(parent);
          if (
            sameInheritedPipe(childPipe, parentPipe) &&
            nsPids?.length >= 2 &&
            nsPids[0] === pid &&
            sameOwnedIdentity(identity, identity) &&
            sameOwnedIdentity(parentIdentity, parentIdentity)
          )
            return {
              ...identity,
              parent: parentIdentity,
              ancestors,
              childPipe,
              parentPipe,
              nsPids,
            };
          if (rejections.length < 8)
            rejections.push({
              pid,
              birth: identity.birth,
              childPipe,
              parentPipe,
              nsPids,
              reason: "descriptor, namespace IDs, or process identity did not match",
            });
        } catch (error) {
          if (rejections.length < 8)
            rejections.push({
              pid,
              birth: identity.birth,
              reason: "proc read failed",
              code: error.code ?? "unknown",
            });
        }
      }
      if (identity) queue.push({ pid, ancestors: [...ancestors, identity] });
    }
  }
  return undefined;
}
export function createProbeExecutable(binary) {
  writeFileSync(
    binary,
    `#!${process.execPath}\nconst { spawn } = require('node:child_process');\nconst fs = require('node:fs');\nconst child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)', '${marker}'], { detached: true, stdio: ['ignore', 'ignore', 'inherit'] });\nfs.writeFileSync(process.env.PROBE_PID, String(child.pid));\nfs.writeFileSync(process.argv[process.argv.indexOf('--export') + 1], '{');\nsetInterval(() => {}, 1000);\n`,
  );
  chmodSync(binary, 0o755);
}
async function inner(out) {
  const namespace = {
    platform: process.platform,
    pid: process.pid,
    procSelf: realpathSync("/proc/self"),
  };
  const error = rtdbNamespaceError(namespace.platform, namespace.pid, namespace.procSelf);
  if (error) throw Error(error);
  mkdirSync(join(out, "logs"));
  const binary = join(out, "node");
  createProbeExecutable(binary);
  const run = structuredClone(RUNS.find((entry) => entry.id === "R22"));
  run.commands[0].timeoutMs = 10000;
  let result;
  const fatal = await runUntilFatal([run, { id: "later" }], async (item) => {
    if (item.id === "later") {
      writeFileSync(join(out, "later"), "unexpected");
      return { record: {} };
    }
    result = await runEntry(item, {
      binary: join(out, "installed"),
      functionsNode: process.execPath,
      out,
      env: { PATH: out, PROBE_PID: join(out, "inner-pid") },
    });
    return result;
  });
  let observed = false;
  await observeUnlessFatal(result, () => {
    observed = true;
    return JSON.parse(readFileSync(result.values.export, "utf8"));
  });
  const witnessAck = existsSync(join(out, "witness-ack"));
  await writeReleaseSummary(out, {
    result: "FAIL",
    fatal,
    observed,
    namespace,
    witnessAck,
    runs: [result.record],
  });
  if (!fatal || result.record.commands[0].exitCode !== "timeout")
    throw Error("timeout was not fatal");
  process.exit(1); // PID 1 exit causes the kernel to terminate the detached child.
}
async function outer(out) {
  if (process.platform !== "linux") throw Error("the namespace probe requires Linux");
  mkdirSync(out);
  const child = spawn(
    "/usr/bin/unshare",
    [
      "--net",
      "--pid",
      "--fork",
      "--mount-proc",
      "--kill-child",
      "--",
      process.execPath,
      fileURLToPath(import.meta.url),
      "--inside",
      out,
    ],
    { detached: true, stdio: ["ignore", "ignore", "pipe"] },
  );
  let stderr = "";
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const finished = new Promise((done) => {
    child.once("error", (error) => done({ error: error.message }));
    child.once("close", (code, signal) => done({ code, signal }));
  });
  let identity, launcherIdentity;
  const rejections = [];
  for (let i = 0; i < 320 && !identity; i++) {
    const launcher = pidIdentity(child.pid);
    if (
      launcher?.exe === "/usr/bin/unshare" &&
      launcher.args.includes(fileURLToPath(import.meta.url))
    )
      launcherIdentity ??= launcher;
    identity = findOwned(child.pid, rejections);
    if (!identity) await delay(25);
    else writeFileSync(join(out, "witness-ack"), String(identity.pid));
  }
  let timeoutId;
  const timeout = new Promise((done) => {
    timeoutId = setTimeout(() => done({ timeout: true }), 15000);
  });
  const outcome = await Promise.race([finished, timeout]);
  clearTimeout(timeoutId);
  let cleanupUnverified = false;
  if (outcome.timeout) {
    if (sameOwnedIdentity(launcherIdentity, pidIdentity(child.pid))) {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {}
      await finished;
    } else {
      cleanupUnverified = true;
      child.stderr.destroy();
      child.unref();
    }
  }
  const originalStillPresent = (original) => {
    try {
      const stat = readFileSync(`/proc/${original.pid}/stat`, "utf8");
      const fields = stat.slice(stat.lastIndexOf(")") + 2).split(" ");
      return fields[19] === original.birth
        ? { pid: original.pid, state: fields[0], birth: fields[19] }
        : undefined;
    } catch (error) {
      return error.code === "ENOENT"
        ? undefined
        : { pid: original.pid, error: error.code ?? "unknown" };
    }
  };
  let remaining;
  if (identity)
    for (let i = 0; i < 40; i++) {
      remaining = [...identity.ancestors, identity].map(originalStillPresent).filter(Boolean);
      if (remaining.length === 0) break;
      await delay(50);
    }
  let summary;
  try {
    summary = JSON.parse(readFileSync(join(out, "summary.json"), "utf8"));
  } catch {}
  const later = (() => {
    try {
      readFileSync(join(out, "later"));
      return true;
    } catch {
      return false;
    }
  })();
  let innerPid;
  try {
    innerPid = Number(readFileSync(join(out, "inner-pid"), "utf8"));
  } catch {}
  const ok =
    outcome.code === 1 &&
    !cleanupUnverified &&
    launcherIdentity &&
    identity?.nsPids?.at(-1) === innerPid &&
    sameInheritedPipe(identity?.childPipe, identity?.parentPipe) &&
    summary?.namespace?.platform === "linux" &&
    summary?.namespace?.pid === 1 &&
    summary?.namespace?.procSelf === "/proc/1" &&
    identity &&
    remaining?.length === 0 &&
    summary?.result === "FAIL" &&
    summary?.fatal === true &&
    summary?.witnessAck === true &&
    summary?.observed === false &&
    summary.runs?.[0]?.commands?.length === 1 &&
    summary.runs?.[0]?.commands?.[0]?.exitCode === "timeout" &&
    !later;
  writeFileSync(
    join(out, "receipt.json"),
    `${JSON.stringify({ ok: Boolean(ok), launcherIdentity, identity, rejections, innerPid, remaining, outcome, summary, later, cleanupUnverified, stderr }, null, 2)}\n`,
  );
  if (!ok) throw Error("PID namespace timeout probe failed; see receipt.json");
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [mode, output] = process.argv.slice(2);
  if (!output || !["--inside", "--out"].includes(mode)) throw Error("usage: --out <new directory>");
  await (mode === "--inside" ? inner(resolve(output)) : outer(resolve(output)));
}
