// The entry of the formal recording: `check` (local reads only, no network, no lock) and `record`
// (admission, the run, the ledger lines). Everything that touches the world is injected, so a test
// runs the whole entry against an in-memory world.

import { createHash, randomBytes } from "node:crypto";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { execFileSync } from "node:child_process";

import { cliPlan, dotenvSha256, prepareSource, sourceProblems } from "./deploy.mjs";
import { createTransport } from "./rest.mjs";
import { record as recordRun } from "./run.mjs";
import * as sandbox from "./sandbox.mjs";
import { createTokenSource } from "./token.mjs";

const sha256 = (data) => createHash("sha256").update(data).digest("hex");
export const FIREBASE_TOOLS_VERSION = "15.28.2";
export const NODE_MAJOR = 22;
const FORBIDDEN_ENV =
  /^(GOOGLE_APPLICATION_CREDENTIALS|FIREBASE_TOKEN|CLOUDSDK_.*|GCLOUD_PROJECT|GOOGLE_CLOUD_PROJECT|.*_EMULATOR_HOST)$/;

export function envProblems(env) {
  return Object.keys(env)
    .filter((name) => FORBIDDEN_ENV.test(name))
    .map((name) => `the environment sets ${name}`);
}
export const nodeProblems = (version) =>
  String(version).split(".")[0] === String(NODE_MAJOR)
    ? []
    : [`Node ${NODE_MAJOR} is required, this is ${version}`];
export const firebaseToolsProblems = (packageJson) =>
  packageJson?.version === FIREBASE_TOOLS_VERSION
    ? []
    : [`firebase-tools ${FIREBASE_TOOLS_VERSION} is required, found ${packageJson?.version}`];

/** The files whose bytes make up the recorder: the digest the approval pins. */
export function harnessFiles(root) {
  const record = join(root, "conformance/src/functions-events/record");
  return [
    ...readdirSync(record)
      .filter((n) => n.endsWith(".mjs"))
      .toSorted()
      .map((n) => `conformance/src/functions-events/record/${n}`),
    "conformance/src/functions-events/canary-cli.mjs",
    "conformance/functions-events/corpus.json",
    "conformance/functions-events/programs.json",
    "conformance/functions-events/firebase.json",
    ...["index.js", "local-host.js", "report.js", "package.json", "pnpm-lock.yaml"].map(
      (n) => `conformance/functions-events/fixtures/${n}`,
    ),
  ];
}
export function harnessDigest(root, { git } = {}) {
  const lines = harnessFiles(root).map(
    (path) => `${path} ${sha256(readFileSync(join(root, path)))}`,
  );
  // the whole deployed tree (pnpm-workspace.yaml and .gitignore ride along without being listed above)
  if (git) lines.push(`tree ${git(["rev-parse", "HEAD:conformance/functions-events"])}`);
  lines.push(`dotenv ${dotenvSha256()}`);
  return { digest: sha256(lines.join("\n")), lines };
}

export function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!["check", "record"].includes(command))
    throw new Error(
      "usage: main.mjs check|record --packet <file> --source-commit <sha> --api-key-file <file>",
    );
  const options = {};
  for (let i = 0; i < rest.length; i += 2) {
    const key = rest[i];
    if (!key?.startsWith("--") || rest[i + 1] === undefined) throw new Error(`bad argument ${key}`);
    options[key.slice(2)] = rest[i + 1];
  }
  for (const required of ["packet", "source-commit", "api-key-file"])
    if (!options[required]) throw new Error(`--${required} is required`);
  if (!/^[0-9a-f]{40}$/.test(options["source-commit"]))
    throw new Error("--source-commit must be a full SHA");
  return { command, options };
}

const readKey = (path) => {
  const text = readFileSync(path, "utf8").trim();
  try {
    const parsed = JSON.parse(text);
    return String(parsed.apiKey ?? parsed.api_key ?? "");
  } catch {
    return text;
  }
};

/** All the local reads that must hold before anything is sent; returns the pins and the problems. */
export function localChecks({
  root,
  options,
  env,
  nodeVersion,
  readLedger,
  readOwner,
  readTools,
  checkSource,
  now,
  git,
}) {
  const problems = [...envProblems(env), ...nodeProblems(nodeVersion)];
  const head = git(["rev-parse", "HEAD"]);
  if (head !== options["source-commit"])
    problems.push(`HEAD is ${head}, not the pinned source commit`);
  if (git(["status", "--porcelain", "--ignored=no"]) !== "")
    problems.push("the working tree is not clean");
  let tools;
  try {
    tools = readTools();
  } catch {
    tools = undefined;
  }
  problems.push(...firebaseToolsProblems(tools));
  problems.push(...checkSource());
  const packetSha256 = sha256(readFileSync(options.packet));
  const { digest: harnessSha256 } = harnessDigest(root, { git });
  const ledger = readLedger();
  const owner = readOwner();
  problems.push(...sandbox.ledgerProblems(ledger, now()), ...sandbox.budgetProblems(ledger));
  if (sandbox.packetUsed(ledger, packetSha256))
    problems.push("a run of this packet already started");
  const approved = sandbox.approval(owner, {
    packetSha256,
    harnessSha256,
    sourceCommit: options["source-commit"],
  });
  problems.push(...approved.problems);
  return { problems, packetSha256, harnessSha256, approval: approved.approval, head };
}

/**
 * `main(argv, deps)`. `deps` carries what touches the world: `env`, `root`, `fetch`, `readCredential`,
 * `runCli`, `sleep`, `now`, `ledgerPath`, `ownerPath`, `lockDir`, `legacyLock`, `runsDir`, `signals`, `log`.
 */
export async function main(argv, deps) {
  const { command, options } = parseArgs(argv);
  const { root, env, log = console.error } = deps;
  const git =
    deps.git ??
    ((args) =>
      execFileSync("git", ["-C", root, ...args])
        .toString()
        .trim());
  const depsDir = deps.depsDir ?? join(root, "conformance/functions-events/fixtures/node_modules");
  const readTools =
    deps.readTools ??
    (() =>
      JSON.parse(
        readFileSync(join(root, "conformance/node_modules/firebase-tools/package.json"), "utf8"),
      ));
  const checks = localChecks({
    root,
    options,
    env,
    nodeVersion: deps.nodeVersion ?? process.versions.node,
    readLedger: () => readFileSync(deps.ledgerPath, "utf8"),
    readOwner: () => readFileSync(deps.ownerPath, "utf8"),
    readTools,
    checkSource: () => {
      // The prepared copy must carry the dependencies and the SDK must discover the 22 handlers from it, offline.
      const scratch = mkdtempSync(join(tmpdir(), "fe-source-check-"));
      try {
        const copy = (deps.prepareSource ?? prepareSource)({
          repoRoot: root,
          commit: options["source-commit"],
          target: scratch,
          depsDir,
        });
        return (deps.sourceProblems ?? sourceProblems)({
          fixtureDir: copy.fixtureDir,
          node: process.execPath,
          directory: join(scratch, "discovery"),
        });
      } catch (error) {
        return [`the source copy could not be prepared: ${error.message}`];
      } finally {
        rmSync(scratch, { recursive: true, force: true });
      }
    },
    now: deps.now,
    git,
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

  // Local preparation first: nothing is locked or written to the ledger until the key, the credential
  // command and the source copy are all good, so a failure here leaves no lock and no `started` line.
  let apiKey;
  try {
    apiKey = readKey(options["api-key-file"]);
  } catch (error) {
    return { ok: false, problems: [`the API key file cannot be read: ${error.message}`] };
  }
  if (!apiKey) return { ok: false, problems: ["the API key file holds no key"] };
  const tokenSource = createTokenSource({ printToken: deps.printAccessToken, now: deps.now });
  try {
    await tokenSource();
  } catch (error) {
    return { ok: false, problems: [`no access token: ${error.message}`] };
  }
  const runDir = join(
    deps.runsDir,
    `functions-events-formal-${new Date(deps.now()).toISOString().replace(/[-:.]/g, "").slice(0, 15)}Z-${randomBytes(8).toString("hex")}`,
  );
  mkdirSync(runDir, { recursive: true, mode: 0o700 });
  let source;
  try {
    source = (deps.prepareSource ?? prepareSource)({
      repoRoot: root,
      commit: options["source-commit"],
      target: join(runDir, "source"),
      depsDir,
    });
    const found = (deps.sourceProblems ?? sourceProblems)({
      fixtureDir: source.fixtureDir,
      node: process.execPath,
      directory: join(runDir, "discovery"),
    });
    if (found.length) throw new Error(found.join("; "));
  } catch (error) {
    rmSync(runDir, { recursive: true, force: true });
    return { ok: false, problems: [`the source copy is not usable: ${error.message}`] };
  }
  const lock = sandbox.acquireLock({
    lockDir: deps.lockDir,
    legacyLock: deps.legacyLock,
    body: { pid: process.pid, runDir, packetSha256: checks.packetSha256 },
  });
  let lockHeld = true;
  const nowIso = () => new Date(deps.now()).toISOString();
  try {
    sandbox.appendLedger(
      deps.ledgerPath,
      sandbox.startedLine({
        ts: nowIso(),
        runDir,
        packetSha256: checks.packetSha256,
        harnessSha256: checks.harnessSha256,
        gitSha: options["source-commit"],
        approval: checks.approval,
        lock,
      }),
    );
    const transportDir = join(runDir, "transport");
    const transport = createTransport({
      fetch: deps.fetch,
      token: tokenSource,
      apiKey,
      directory: transportDir,
      ceiling: sandbox.MAX_REQUESTS,
      now: deps.now,
    });
    const cliAttempts = { deploy: 0, delete: 0 };
    const cli = async (action) => {
      if (cliAttempts[action] >= 1)
        throw new Error(`the CLI ${action} was already run once; never re-sent`);
      cliAttempts[action] += 1;
      const configHome = join(runDir, `config-${action}`);
      mkdirSync(configHome, { mode: 0o700 });
      const plan = cliPlan(action, {
        configHome,
        configPath: source.configPath,
        workDir: join(runDir, `work-${action}`),
        home: env.HOME,
        path: `${deps.nodeDir ?? dirname(process.execPath)}:${env.PATH ?? ""}`,
      });
      mkdirSync(plan.cwd, { recursive: true, mode: 0o700 });
      return deps.runCli({
        action,
        plan,
        firebaseJs: join(root, "conformance/node_modules/firebase-tools/lib/bin/firebase.js"),
        node: process.execPath,
        directory: join(runDir, "cli"),
      });
    };

    const signal = { aborted: false };
    deps.signals?.((name) => {
      if (signal.aborted) log(`a stop is already under way (${name}); wait for the cleanup`);
      else {
        signal.aborted = true;
        log(`${name}: stopping at the next step, then the cleanup runs`);
      }
    });
    const corpusDigest = sha256(
      readFileSync(join(root, "conformance/functions-events/corpus.json")),
    );
    let n = 0;
    const result = await recordRun({
      transport,
      cli,
      sleep: deps.sleep,
      now: deps.now,
      newId: (role) => `e${randomBytes(12).toString("hex")}${role.slice(0, 1)}${++n}`,
      corpusDigest,
      signal,
      log,
    });
    const file = join(runDir, "production-run.json");
    writeFileSync(file, `${JSON.stringify(result.run, null, 2)}\n`, { mode: 0o600 });
    const sums = readdirSyncRecursive(runDir)
      .toSorted()
      .map((path) => `${sha256(readFileSync(join(runDir, path)))}  ${path}`);
    writeFileSync(join(runDir, "SHA256SUMS"), `${sums.join("\n")}\n`, { mode: 0o600 });
    const keep = result.outcome === "needs-recovery";
    sandbox.appendLedger(
      deps.ledgerPath,
      sandbox.finishedLine({
        ts: nowIso(),
        runDir,
        packetSha256: checks.packetSha256,
        gitSha: options["source-commit"],
        outcome: result.outcome,
        requests: result.run.requestsSent,
        cliAttempts,
        lockRetained: keep,
      }),
    );
    if (!keep) {
      sandbox.releaseLock(lock);
      lockHeld = false;
    }
    return {
      ok: result.outcome === "recorded",
      outcome: result.outcome,
      runDir,
      requests: result.run.requestsSent,
      stops: result.run.stops,
      cleanup: result.run.cleanup?.problems ?? null,
    };
  } catch (error) {
    // Anything unexpected before the closing line: the lock stays, and the ledger says so.
    sandbox.appendLedger(
      deps.ledgerPath,
      sandbox.finishedLine({
        ts: nowIso(),
        runDir,
        packetSha256: checks.packetSha256,
        gitSha: options["source-commit"],
        outcome: "needs-recovery",
        requests: null,
        cliAttempts: null,
        lockRetained: true,
      }),
    );
    throw error;
  } finally {
    if (lockHeld) log("the project lock stays held until the coordinator releases it");
  }
}

function readdirSyncRecursive(dir, base = dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules") continue;
    const path = join(dir, entry);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) out.push(...readdirSyncRecursive(path, base));
    else out.push(relative(base, path));
  }
  return out;
}
