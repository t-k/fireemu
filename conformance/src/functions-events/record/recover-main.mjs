// The entry of the v4 recovery: `check` (local reads only: no network, no lock) and `recover` (admission, the
// REST recovery of recover.mjs, the ledger lines). It never takes, frees or replaces the project lock: the lock it
// works under is the origin run's, and the coordinator frees it after reading the result.

import { createHash, randomBytes } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { execFileSync } from "node:child_process";

import { envProblems, harnessDigest, nodeProblems } from "./main.mjs";
import { ORIGIN_RUN_DIR_NAME } from "./recover-targets.mjs";
import { RECOVERY_RULES } from "./guard.mjs";
import { recover } from "./recover.mjs";
import { createTransport } from "./rest.mjs";
import * as sandbox from "./sandbox.mjs";
import { createTokenSource } from "./token.mjs";

const sha256 = (data) => createHash("sha256").update(data).digest("hex");

export function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!["check", "recover"].includes(command))
    throw new Error("usage: recover-bin.mjs check|recover --packet <file> --source-commit <sha>");
  const options = {};
  for (let i = 0; i < rest.length; i += 2) {
    const key = rest[i];
    if (!key?.startsWith("--") || rest[i + 1] === undefined) throw new Error(`bad argument ${key}`);
    options[key.slice(2)] = rest[i + 1];
  }
  for (const required of ["packet", "source-commit"])
    if (!options[required]) throw new Error(`--${required} is required`);
  if (!/^[0-9a-f]{40}$/.test(options["source-commit"]))
    throw new Error("--source-commit must be a full SHA");
  return { command, options };
}

function sumsOf(dir, base = dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) out.push(...sumsOf(path, base));
    else out.push(`${sha256(readFileSync(path))}  ${relative(base, path)}`);
  }
  return out.toSorted();
}

/** All the local reads that must hold before anything is sent. */
export function localChecks({
  root,
  options,
  env,
  nodeVersion,
  readLedger,
  readOwner,
  readLock,
  legacyLockHeld,
  isAlive,
  now,
  git,
  originRunDir,
}) {
  const problems = [...envProblems(env), ...nodeProblems(nodeVersion)];
  const head = git(["rev-parse", "HEAD"]);
  if (head !== options["source-commit"])
    problems.push(`HEAD is ${head}, not the pinned source commit`);
  if (git(["status", "--porcelain", "--ignored=no"]) !== "")
    problems.push("the working tree is not clean");
  const packetSha256 = sha256(readFileSync(options.packet));
  const { digest: harnessSha256 } = harnessDigest(root, { git });
  const ledger = readLedger();
  problems.push(
    ...sandbox.recoveryProblems(ledger, {
      originRunDir,
      now: now(),
      lock: { text: readLock(), isAlive },
      legacyLockHeld: legacyLockHeld(),
    }),
    ...sandbox.budgetProblems(ledger, { reserve: sandbox.RECOVERY_RESERVE_USD }),
  );
  if (sandbox.packetUsed(ledger, packetSha256))
    problems.push("a run of this packet already started");
  const approved = sandbox.recoveryApproval(readOwner(), {
    packetSha256,
    harnessSha256,
    sourceCommit: options["source-commit"],
  });
  problems.push(...approved.problems);
  return { problems, packetSha256, harnessSha256, approval: approved.approval, head };
}

/** `main(argv, deps)`; `deps` carries what touches the world (see recover-bin.mjs). */
export async function main(argv, deps) {
  const { command, options } = parseArgs(argv);
  const { root, env, log = console.error } = deps;
  const git =
    deps.git ??
    ((args) =>
      execFileSync("git", ["-C", root, ...args])
        .toString()
        .trim());
  const originRunDir = join(deps.runsDir, ORIGIN_RUN_DIR_NAME);
  const lockPath = join(deps.lockDir, `${sandbox.PROJECT}.lock`);
  const readLock = () => {
    try {
      const stat = lstatSync(lockPath);
      return stat.isFile() ? readFileSync(lockPath, "utf8") : undefined;
    } catch {
      return undefined;
    }
  };
  const legacyLockHeld = () => {
    try {
      lstatSync(deps.legacyLock);
      return true;
    } catch {
      return false;
    }
  };
  const checks = localChecks({
    root,
    options,
    env,
    nodeVersion: deps.nodeVersion ?? process.versions.node,
    readLedger: () => readFileSync(deps.ledgerPath, "utf8"),
    readOwner: () => readFileSync(deps.ownerPath, "utf8"),
    readLock,
    legacyLockHeld,
    isAlive:
      deps.isAlive ??
      ((pid) => {
        try {
          process.kill(pid, 0);
          return true;
        } catch (error) {
          return error.code === "EPERM";
        }
      }),
    now: deps.now,
    git,
    originRunDir,
  });
  if (command === "check")
    return {
      ok: checks.problems.length === 0,
      problems: checks.problems,
      pins: {
        packetSha256: checks.packetSha256,
        harnessSha256: checks.harnessSha256,
        sourceCommit: options["source-commit"],
      },
    };
  if (checks.problems.length) return { ok: false, problems: checks.problems };

  const tokenSource = createTokenSource({ printToken: deps.printAccessToken, now: deps.now });
  try {
    await tokenSource();
  } catch (error) {
    return { ok: false, problems: [`no access token: ${error.message}`] };
  }
  const runDir = join(
    deps.runsDir,
    `functions-events-recovery-${new Date(deps.now()).toISOString().replace(/[-:.]/g, "").slice(0, 15)}Z-${randomBytes(8).toString("hex")}`,
  );
  mkdirSync(runDir, { recursive: true, mode: 0o700 });
  const nowIso = () => new Date(deps.now()).toISOString();
  const lockSha256 = sha256(readLock() ?? "");
  sandbox.appendLedger(
    deps.ledgerPath,
    sandbox.recoveryStartedLine({
      ts: nowIso(),
      runDir,
      originRunDir,
      packetSha256: checks.packetSha256,
      harnessSha256: checks.harnessSha256,
      gitSha: options["source-commit"],
      approval: checks.approval,
      lockSha256,
    }),
  );
  const transport = createTransport({
    fetch: deps.fetch,
    token: tokenSource,
    directory: join(runDir, "transport"),
    ceiling: sandbox.RECOVERY_MAX_REQUESTS,
    now: deps.now,
    rules: RECOVERY_RULES,
  });
  let result;
  try {
    result = await recover({ transport, sleep: deps.sleep, log });
  } catch (error) {
    // Anything unexpected: the lock stays and the ledger says so.
    result = {
      outcome: "needs-review",
      record: {
        problems: [`${error.constructor.name}: ${error.message}`],
        steps: [],
        deletes: null,
      },
    };
  }
  writeFileSync(
    join(runDir, "recovery.json"),
    `${JSON.stringify({ outcome: result.outcome, requestsSent: transport.state.sent, ...result.record }, null, 2)}\n`,
    { mode: 0o600 },
  );
  writeFileSync(join(runDir, "SHA256SUMS"), `${sumsOf(runDir).join("\n")}\n`, { mode: 0o600 });
  sandbox.appendLedger(
    deps.ledgerPath,
    sandbox.recoveryFinishedLine({
      ts: nowIso(),
      runDir,
      originRunDir,
      packetSha256: checks.packetSha256,
      gitSha: options["source-commit"],
      outcome: result.outcome,
      requests: transport.state.sent,
      deletes: result.record.deletes,
    }),
  );
  return {
    ok: result.outcome === "recovered",
    outcome: result.outcome,
    runDir,
    requests: transport.state.sent,
    problems: result.record.problems,
    residue: result.record.residue ?? null,
  };
}
