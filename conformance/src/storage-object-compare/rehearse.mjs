// Runs the recorder's local rehearsal (the same 26 recipes, through the lean wire, against a local
// fireemu in the strict profile) and writes a receipt that binds the comparison to the fireemu
// commit and binary digest, the recorder commit and the journal. The recorder is a checkout of the
// recorder branch; this tool does not change it.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const STANDIN = join(dirname(fileURLToPath(import.meta.url)), "rehearsal-standin.mjs");
const sha256File = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");

/** The SHA-256 of the stand-in a rehearsal runs with; a receipt must name the one in this tree. */
export const standinSha256 = () => sha256File(STANDIN);

/** Run git in `directory`; a failure (not a repository, no git) is an error, never empty output. */
function git(directory, ...args) {
  const result = spawnSync("git", ["-C", directory, ...args], { encoding: "utf8" });
  if (result.error || result.status !== 0)
    throw new Error(`git ${args[0]} failed in ${directory}: not a usable git checkout`);
  return result.stdout.trim();
}

/** The sandbox profile that allows loopback and nothing else outbound (macOS). */
export const LOOPBACK_PROFILE =
  '(version 1)\n(allow default)\n(deny network-outbound (remote ip))\n(allow network-outbound (remote ip "localhost:*"))\n';

export function rehearsalPlan({
  fireemuBinary,
  recorderDir,
  rulesFile,
  fixtureDir,
  outDir,
  sandbox,
}) {
  const conformance = join(recorderDir, "conformance");
  const config = join(outDir, "fireemu.config.json");
  const firebaseJson = join(outDir, "firebase.json");
  const profile = join(outDir, "loopback.sb");
  const inner = `STANDIN_STORAGE_ORIGIN="http://$FIREBASE_STORAGE_EMULATOR_HOST" exec node --import ${STANDIN} src/storage-object/local-aggregate.mjs`;
  const exec = [
    fireemuBinary,
    "exec",
    "--project",
    "example-project",
    "--config",
    config,
    "--firebase-json",
    firebaseJson,
    "--only",
    "storage,auth",
    "--",
    "sh",
    "-c",
    inner,
  ];
  return {
    cwd: conformance,
    files: {
      [config]: `${JSON.stringify({ schemaVersion: 1, profile: "strict", auth: { idTokenSigning: "session-rsa" } })}\n`,
      [firebaseJson]: `${JSON.stringify({ storage: { rules: rulesFile } })}\n`,
      ...(sandbox ? { [profile]: LOOPBACK_PROFILE } : {}),
    },
    command: sandbox ? ["sandbox-exec", "-f", profile, ...exec] : exec,
    env: {
      STORAGE_OBJECT_RULES_SOURCE: rulesFile,
      STORAGE_OBJECT_LOCAL_WIRE: "lean",
      STORAGE_OBJECT_LOCAL_RECORDINGS: "1",
      STANDIN_FIXTURE: fixtureDir,
    },
  };
}

// ps snapshots retain birth/command identity; zombies remain present until actually reaped.
function groupSnapshot(pgid) {
  const result = spawnSync("ps", ["-ww", "-axo", "pid=,pgid=,lstart=,comm=,args="], {
    encoding: "utf8",
    timeout: 1000,
    env: { ...process.env, LANG: "C", LC_ALL: "C", TZ: "UTC" },
  });
  if (result.error || result.status !== 0) throw new Error("rehearsal ownership inspection failed");
  return result.stdout.split("\n").flatMap((line) => {
    const match = line.trim().match(/^(\d+)\s+(\d+)\s+(.+)$/);
    return match && Number(match[2]) === pgid
      ? [{ pid: Number(match[1]), identity: match[3] }]
      : [];
  });
}

function run(command, { cwd, env, timeoutMs }) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command[0], command.slice(1), {
      cwd,
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
      detached: true,
    });
    let stdout = "",
      stderr = "",
      timedOut = false,
      closed = false;
    let originalLeader,
      ownershipError,
      leaderExited = false;
    child.on("spawn", () => {
      try {
        originalLeader = groupSnapshot(child.pid).find((row) => row.pid === child.pid);
        if (!originalLeader) throw new Error("rehearsal original leader identity unavailable");
      } catch (error) {
        ownershipError = error.message;
      }
    });
    child.on("exit", () => {
      leaderExited = true;
    });
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    const timer = setTimeout(async () => {
      timedOut = true;
      const cleanup = {
        pid: child.pid,
        confirmed: false,
        escalated: false,
        stage: "timeout-inspection",
        capturedLeader: originalLeader
          ? { pid: originalLeader.pid, identity: originalLeader.identity.slice(0, 1024) }
          : null,
      };
      try {
        const verifyLeader = (rows) => {
          const current = rows.find((row) => row.pid === child.pid);
          cleanup.currentLeader = current
            ? { pid: current.pid, identity: current.identity.slice(0, 1024) }
            : null;
          cleanup.currentPids = rows.slice(0, 16).map((row) => row.pid);
          if (ownershipError) throw new Error(ownershipError);
          if (
            !originalLeader ||
            leaderExited ||
            child.exitCode !== null ||
            child.signalCode !== null
          )
            throw new Error("rehearsal original leader is no longer owned");
          if (rows.find((row) => row.pid === child.pid)?.identity !== originalLeader.identity)
            throw new Error("rehearsal original leader identity changed");
        };
        const owned = groupSnapshot(child.pid);
        verifyLeader(owned);
        const signal = (name) => {
          cleanup.stage = `before-${name}`;
          const current = groupSnapshot(child.pid);
          verifyLeader(current);
          for (const row of current) {
            const original = owned.find((entry) => entry.pid === row.pid);
            if (!original || original.identity !== row.identity)
              throw new Error("rehearsal group identity changed");
          }
          if (current.length) {
            try {
              process.kill(-child.pid, name);
            } catch (error) {
              if (error.code !== "ESRCH") throw error;
            }
          }
        };
        const wait = async () => {
          cleanup.stage = "termination-observation";
          const deadline = Date.now() + 1000;
          do {
            if (closed && groupSnapshot(child.pid).length === 0) return true;
            await new Promise((resolve) => setTimeout(resolve, 20));
          } while (Date.now() < deadline);
          return false;
        };
        signal("SIGTERM");
        cleanup.confirmed = await wait();
        if (!cleanup.confirmed) {
          cleanup.escalated = true;
          signal("SIGKILL");
          cleanup.confirmed = await wait();
        }
      } catch (error) {
        cleanup.error = error.message;
        cleanup.failureStage = cleanup.stage;
      }
      Object.assign(cleanup, {
        leaderExited,
        closed,
        exitCode: child.exitCode,
        signalCode: child.signalCode,
      });
      const error = new Error(
        `the rehearsal timed out; cleanup ${cleanup.confirmed ? "confirmed" : "unresolved"}`,
      );
      error.cleanup = cleanup;
      if (!cleanup.confirmed) {
        child.stdout.destroy();
        child.stderr.destroy();
        child.unref();
      }
      reject(error);
    }, timeoutMs);
    child.on("close", (code) => {
      closed = true;
      if (!timedOut) {
        clearTimeout(timer);
        resolvePromise({ code, stdout, stderr });
      }
    });
    child.on("error", (error) => {
      if (!timedOut) {
        clearTimeout(timer);
        reject(error);
      }
    });
  });
}

/** Run the rehearsal and return the receipt (also written to `<outDir>/receipt.json`). */
export async function rehearse({
  fireemuBinary,
  fireemuCommit,
  recorderDir,
  rulesFile,
  fixtureDir,
  outDir,
  sandbox = process.platform === "darwin",
  timeoutMs = 1_800_000,
}) {
  if (!/^[0-9a-f]{40}$/.test(fireemuCommit ?? ""))
    throw new Error("--fireemu-commit must be a full commit SHA");
  for (const [name, path] of Object.entries({ fireemuBinary, recorderDir, rulesFile, fixtureDir }))
    if (!path || !existsSync(path)) throw new Error(`${name} does not exist`);
  const recorderCommit = git(recorderDir, "rev-parse", "HEAD");
  if (!/^[0-9a-f]{40}$/.test(recorderCommit))
    throw new Error("the recorder checkout has no commit");
  if (git(recorderDir, "status", "--porcelain") !== "")
    throw new Error("the recorder checkout is not clean");
  mkdirSync(outDir, { recursive: true });
  const plan = rehearsalPlan({
    fireemuBinary: resolve(fireemuBinary),
    recorderDir: resolve(recorderDir),
    rulesFile: resolve(rulesFile),
    fixtureDir: resolve(fixtureDir),
    outDir: resolve(outDir),
    sandbox,
  });
  for (const [path, text] of Object.entries(plan.files)) writeFileSync(path, text);
  const result = await run(plan.command, { cwd: plan.cwd, env: plan.env, timeoutMs });
  const summary = result.stdout
    .trim()
    .split("\n")
    .findLast((line) => line.startsWith("{"));
  const parsed = summary ? JSON.parse(summary) : null;
  if (!parsed?.eventDirectory)
    throw new Error(
      `the rehearsal did not report its journal (exit ${result.code}); stderr tail: ${JSON.stringify(result.stderr.slice(-300))}`,
    );
  const journal = join(resolve(outDir), "journal.jsonl");
  copyFileSync(join(parsed.eventDirectory, "aggregate-events.jsonl"), journal);
  const receipt = {
    fireemu: {
      binarySha256: sha256File(fireemuBinary),
      version: spawnSync(fireemuBinary, ["--version"], { encoding: "utf8" }).stdout.trim(),
      commit: fireemuCommit,
    },
    recorder: { commit: recorderCommit, clean: true },
    standinSha256: standinSha256(),
    fixtureIndexSha256: sha256File(join(resolve(fixtureDir), "index.json")),
    rulesSha256: sha256File(rulesFile),
    journalSha256: sha256File(journal),
    result: {
      status: parsed.status,
      completedRecipes: parsed.completedRecipes,
      requests: parsed.requests,
      exitCode: result.code,
    },
  };
  writeFileSync(join(resolve(outDir), "receipt.json"), `${JSON.stringify(receipt, null, 2)}\n`);
  return receipt;
}
