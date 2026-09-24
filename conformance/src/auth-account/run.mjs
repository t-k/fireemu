// AUTH-ACCOUNT sandbox runner.
//
//   node src/auth-account/run.mjs record-production   record the corpus twice against the
//                                                     Identity Platform sandbox and update
//                                                     auth-account-production.json
//   node src/auth-account/run.mjs check               run the corpus against fireemu and
//                                                     compare with the saved production rows
//
// `record-production` needs FIREEMU_AUTH_SANDBOX_WEB_CONFIG (the sandbox web app config JSON,
// kept outside the repository), owner ADC (`gcloud auth application-default`) and
// FIREEMU_SANDBOX_LEDGER (the private append-only run ledger). AUTH_ACCOUNT_PROGRAMS limits a
// run to programs whose id starts with one of its comma-separated prefixes; recorded programs
// replace their previous entries and the others are kept. `check` uses FIREEMU_BIN (or the
// workspace build) and writes .runs/auth-account/comparison.json.

import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { CONFORMANCE_DIR } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { BASELINE_CONFIG, CONFIG_DEFAULTS, PROGRAMS } from "./corpus.mjs";
import {
  RECORDED_PROJECT,
  SANDBOX_PROJECT,
  createContext,
  diffRecordings,
  isTransient,
  sameRecording,
  validateCorpus,
} from "./harness.mjs";
import { scanFixture } from "./fixture-scan.mjs";
import { runCorpus } from "./session.mjs";

const execFileAsync = promisify(execFile);
const FIXTURE = join(CONFORMANCE_DIR, "auth-account-production.json");
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-account");
const LOCAL_PORT = 32296;
/** The synthetic project number fireemu is configured with (auth-account.fireemu.json). */
const LOCAL_PROJECT_NUMBER = "123456789012";
const TASK_ID = "AUTH-ACCOUNT-SANDBOX";
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

function selectedPrograms() {
  const prefixes = (process.env.AUTH_ACCOUNT_PROGRAMS ?? "").split(",").filter(Boolean);
  // AUTH_ACCOUNT_PROGRAMS_EXACT=1 selects the listed ids only, so a re-record of one program
  // does not also pick up the programs its id prefixes.
  const exact = process.env.AUTH_ACCOUNT_PROGRAMS_EXACT === "1";
  const programs = prefixes.length
    ? PROGRAMS.filter((p) =>
        prefixes.some((prefix) => (exact ? p.id === prefix : p.id.startsWith(prefix))),
      )
    : PROGRAMS;
  if (programs.length === 0) throw new Error("no program matches AUTH_ACCOUNT_PROGRAMS");
  return programs;
}

const programDigest = (program) => sha256(JSON.stringify(program));

/** Normalization and request semantics a saved row depends on; a change makes it stale. */
async function harnessDigest() {
  const sources = await Promise.all(
    ["harness.mjs", "session.mjs"].map((file) =>
      readFile(join(CONFORMANCE_DIR, "src/auth-account", file), "utf8"),
    ),
  );
  return sha256(`${sources.join("\n")}\n${JSON.stringify(BASELINE_CONFIG)}`);
}

/** Per recording: every step once; the harness gets its own, generous cleanup budget. */
const ceilings = (programs) => ({
  maxRequests: programs.reduce((total, p) => total + p.steps.length, 0),
  maxHarnessRequests: programs.reduce((total, p) => total + 10 + (p.config ? 70 : 0), 20),
});

/** Private recordings must never be committable. */
async function assertIgnored(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  try {
    // Asked of the repository that contains the path (docs.local lives in the main checkout,
    // not in this worktree); a path in no repository cannot be committed at all.
    await execFileAsync("git", ["-C", path, "rev-parse", "--show-toplevel"]);
  } catch {
    return;
  }
  try {
    await execFileAsync("git", ["-C", path, "check-ignore", "-q", path]);
  } catch {
    throw new Error(`${path} is not ignored by git; private recordings must not be committable`);
  }
}

async function assertCleanTree() {
  const { stdout } = await execFileAsync(
    "git",
    [
      "status",
      "--porcelain",
      "--",
      "src/auth-account",
      "auth-account-production.json",
      "auth-account.fireemu.json",
    ],
    { cwd: CONFORMANCE_DIR },
  );
  if (stdout.trim()) throw new Error(`record-production needs a clean tree:\n${stdout}`);
}

async function gitSha() {
  const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: CONFORMANCE_DIR });
  return stdout.trim();
}

async function adminToken() {
  const { stdout } = await execFileAsync("gcloud", [
    "auth",
    "application-default",
    "print-access-token",
  ]);
  return stdout.trim();
}

async function sandboxWebConfig() {
  const configPath = process.env.FIREEMU_AUTH_SANDBOX_WEB_CONFIG;
  if (!configPath) throw new Error("FIREEMU_AUTH_SANDBOX_WEB_CONFIG is required");
  const web = JSON.parse(await readFile(configPath, "utf8"));
  if (web.projectId !== SANDBOX_PROJECT) throw new Error("web config is not the sandbox project");
  if (!/^\d+$/.test(web.projectNumber ?? "") || web.projectNumber !== web.messagingSenderId) {
    throw new Error("web config has no consistent project number");
  }
  return web;
}

async function recordOnce(programs, run, web, token) {
  const ctx = createContext({
    run,
    project: SANDBOX_PROJECT,
    target: {
      kind: "production",
      apiKey: web.apiKey,
      adminToken: token,
      quotaProject: SANDBOX_PROJECT,
      projectNumber: web.projectNumber,
    },
  });
  return runCorpus(programs, ctx, {
    // Production config changes were seen to take effect up to ~30 s after they read back.
    settleMs: 30_000,
    configDefaults: CONFIG_DEFAULTS,
    ...ceilings(programs),
    baselineConfig: BASELINE_CONFIG,
    log: (line) => console.log(line),
  });
}

/**
 * Writes the committed fixture from two recordings. Kept separate from recording so that a
 * refusal here (for example by the secret scan) never loses a production run: the recordings
 * are saved privately first and `rebuild-fixture` can retry from them.
 */
async function writeFixture({ programs, recordings, meta, secrets }) {
  const [first, second] = recordings;
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { version: 1, recordedAgainst: {}, programs: {} };
  fixture.recordedAgainst = {
    target: "production Identity Toolkit and Secure Token REST, Identity Platform sandbox",
    project: RECORDED_PROJECT,
    note: "Two recordings per program. Tokens, generated ids, hashes, salts, run-window times, the project id, its number and the API key are placeholders. `second` holds the other recording of rows that differed.",
    baselineConfig: BASELINE_CONFIG,
  };
  for (const program of programs) {
    const one = first.results[program.id];
    const two = second.results[program.id];
    if (!one || !two) continue;
    const differing = Object.fromEntries(
      Object.entries(two.steps).filter(([id, rec]) => !sameRecording(rec, one.steps[id])),
    );
    fixture.programs[program.id] = {
      corpusDigest: programDigest(program),
      harnessDigest: meta.harness,
      recordedAt: meta.startedAt,
      gitSha: meta.sha,
      ...(one.config ? { config: one.config } : {}),
      steps: one.steps,
      ...(Object.keys(differing).length ? { second: differing } : {}),
    };
  }
  fixture.programs = Object.fromEntries(
    Object.entries(fixture.programs).toSorted(([a], [b]) => a.localeCompare(b)),
  );
  const text = `${JSON.stringify(fixture, null, 2)}\n`;
  scanFixture(text, secrets);
  await writeFile(FIXTURE, text);
  return diffRecordings(first.results, second.results);
}

async function recordProduction() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  const privateRoot = process.env.FIREEMU_AUTH_ACCOUNT_PRIVATE_DIR;
  if (!ledger || !privateRoot) {
    throw new Error("FIREEMU_SANDBOX_LEDGER and FIREEMU_AUTH_ACCOUNT_PRIVATE_DIR are required");
  }
  await assertCleanTree();
  const programs = selectedPrograms();
  const corpusRequests = validateCorpus(programs);
  const meta = {
    sha: await gitSha(),
    harness: await harnessDigest(),
    startedAt: new Date().toISOString(),
    programs: programs.map((p) => p.id),
    corpusDigests: Object.fromEntries(programs.map((p) => [p.id, programDigest(p)])),
  };
  const web = await sandboxWebConfig();
  await assertIgnored(privateRoot);
  const runDir = join(privateRoot, `auth-account-production-${meta.startedAt.replaceAll(":", "")}`);
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const recordings = [];
  let outcome = "recorded";
  let error;
  let adminTokenValue;
  try {
    for (const offset of [0, 1]) {
      adminTokenValue = await adminToken();
      const recording = await recordOnce(
        programs,
        String(Date.now() + offset),
        web,
        adminTokenValue,
      );
      recordings.push(recording);
      await writeFile(join(runDir, `recording-${offset + 1}.json`), JSON.stringify(recording), {
        mode: 0o600,
      });
    }
  } catch (caught) {
    outcome = caught.fatal ? "aborted-fatal" : "aborted";
    error = String(caught.message ?? caught);
    if (caught.partial) recordings.push(caught.partial);
  }
  await writeFile(join(runDir, "meta.json"), JSON.stringify({ ...meta, outcome, error }, null, 2), {
    mode: 0o600,
  });
  const requests = recordings.reduce((n, r) => n + r.requests + r.harnessRequests, 0);
  const failures = recordings.flatMap((r) => r.failures);
  try {
    if (!error) {
      const nondeterministic = await writeFixture({
        programs,
        recordings,
        meta,
        secrets: [web.apiKey, adminTokenValue, SANDBOX_PROJECT, web.projectNumber],
      });
      if (failures.length) outcome = "recorded-with-program-failures";
      console.log(
        JSON.stringify(
          { programs: programs.length, corpusRequests, requests, nondeterministic, failures },
          null,
          2,
        ),
      );
    }
  } catch (caught) {
    outcome = "not-written";
    error = `${String(caught.message ?? caught)} (recordings kept in ${runDir})`;
  } finally {
    await appendFile(
      ledger,
      `${JSON.stringify({
        ts: new Date().toISOString(),
        project: SANDBOX_PROJECT,
        database: null,
        gitSha: meta.sha,
        corpusDigest: sha256(JSON.stringify(programs)),
        requests,
        estimatedUsd: 0,
        outcome,
        taskId: TASK_ID,
        programs: meta.programs,
        configAtEnd: recordings.map((r) => r.configAtEnd ?? "unknown"),
        ...(error ? { error } : {}),
      })}\n`,
    );
  }
  if (error) throw new Error(error);
  if (failures.length) process.exitCode = 1;
}

/** Retries the fixture from a saved run directory; sends nothing to production. */
async function rebuildFixture(runDir) {
  const meta = JSON.parse(await readFile(join(runDir, "meta.json"), "utf8"));
  if (meta.harness !== (await harnessDigest()))
    throw new Error("harness changed since the recording");
  const recordings = await Promise.all(
    [1, 2].map(async (n) =>
      JSON.parse(await readFile(join(runDir, `recording-${n}.json`), "utf8")),
    ),
  );
  const programs = PROGRAMS.filter((p) => meta.programs.includes(p.id));
  const changed = programs.filter((p) => meta.corpusDigests?.[p.id] !== programDigest(p));
  if (changed.length || programs.length !== meta.programs.length) {
    throw new Error(`corpus changed since the recording: ${changed.map((p) => p.id).join(", ")}`);
  }
  const web = await sandboxWebConfig();
  const nondeterministic = await writeFixture({
    programs,
    recordings,
    meta,
    secrets: [web.apiKey, SANDBOX_PROJECT, web.projectNumber],
  });
  console.log(JSON.stringify({ programs: programs.length, nondeterministic }, null, 2));
}

async function sessionLocal() {
  const programs = JSON.parse(await readFile(process.env.AUTH_ACCOUNT_IN, "utf8"));
  const ctx = createContext({
    run: process.env.AUTH_ACCOUNT_RUN,
    project: SANDBOX_PROJECT,
    target: {
      kind: "local",
      origin: process.env.AUTH_ACCOUNT_ORIGIN,
      projectNumber: LOCAL_PROJECT_NUMBER,
    },
  });
  // The sandbox baseline (providers and test phone numbers) is applied to fireemu through the
  // same Admin config surface production uses.
  const out = await runCorpus(programs, ctx, {
    baselineConfig: BASELINE_CONFIG,
    applyBaseline: true,
    configDefaults: CONFIG_DEFAULTS,
    ...ceilings(programs),
  });
  await writeFile(process.env.AUTH_ACCOUNT_OUT, JSON.stringify(out));
}

async function runLocal(programs) {
  await mkdir(RUN_DIR, { recursive: true });
  const inPath = join(RUN_DIR, "programs.json");
  const outPath = join(RUN_DIR, "fireemu.json");
  await writeFile(inPath, JSON.stringify(programs));
  const binary = resolveFireemuBinary();
  const child = spawn(
    binary,
    [
      "exec",
      "--config",
      join(CONFORMANCE_DIR, "auth-account.fireemu.json"),
      "--project",
      SANDBOX_PROJECT,
      "--only",
      "auth",
      "--http-port",
      String(LOCAL_PORT),
      "--firestore-port",
      "0",
      "--ui-port",
      "0",
      "--hub-port",
      "0",
      "--logging-port",
      "0",
      "--",
      process.execPath,
      "src/auth-account/run.mjs",
      "session-local",
    ],
    {
      cwd: CONFORMANCE_DIR,
      stdio: ["ignore", "inherit", "inherit"],
      env: {
        ...process.env,
        AUTH_ACCOUNT_IN: inPath,
        AUTH_ACCOUNT_OUT: outPath,
        AUTH_ACCOUNT_RUN: String(Date.now()),
        AUTH_ACCOUNT_ORIGIN: `http://127.0.0.1:${LOCAL_PORT}`,
      },
    },
  );
  const code = await new Promise((resolve) => child.once("exit", resolve));
  if (code !== 0) throw new Error(`fireemu session exited ${code}`);
  return { binary, ...JSON.parse(await readFile(outPath, "utf8")) };
}

function classify({ stale, production, alternative, fireemu }) {
  if (stale) return "STALE_FIXTURE";
  if (production === undefined) return "MISSING_FIXTURE";
  if (fireemu === undefined) return "MISSING";
  // A server error production returned identically in both recordings (no `second` row) is
  // behavior, not noise: compare it, and fireemu's own 5xx with it.
  const repeatedServerError = production.status >= 500 && alternative === undefined;
  const transient = (recorded) =>
    isTransient(recorded) && !(repeatedServerError && recorded?.status >= 500);
  if ([production, alternative, fireemu].some(transient)) return "INDETERMINATE";
  if (sameRecording(production, fireemu)) return alternative ? "MATCH_NONDETERMINISTIC" : "MATCH";
  if (alternative && sameRecording(alternative, fireemu)) return "MATCH_NONDETERMINISTIC";
  return "MISMATCH";
}

async function check() {
  const fixture = JSON.parse(await readFile(FIXTURE, "utf8"));
  const selected = selectedPrograms();
  const harness = await harnessDigest();
  const local = await runLocal(selected);
  const rows = [];
  for (const program of selected) {
    const saved = fixture.programs[program.id];
    const stale =
      saved !== undefined &&
      (saved.corpusDigest !== programDigest(program) || saved.harnessDigest !== harness);
    for (const step of program.steps) {
      const production = saved?.steps?.[step.id];
      const alternative = saved?.second?.[step.id];
      const fireemu = local.results[program.id]?.steps?.[step.id];
      rows.push({
        row: `${program.id}#${step.id}`,
        status: classify({ stale, production, alternative, fireemu }),
        production,
        ...(alternative ? { alternative } : {}),
        fireemu,
      });
    }
  }
  const known = new Set(PROGRAMS.map((p) => p.id));
  const orphans = Object.keys(fixture.programs).filter((id) => !known.has(id));
  const summary = {};
  for (const { status } of rows) summary[status] = (summary[status] ?? 0) + 1;
  const artifactSha256 = sha256(await readFile(local.binary));
  await writeFile(
    join(RUN_DIR, "comparison.json"),
    `${JSON.stringify({ artifact: local.binary, artifactSha256, summary, orphans, failures: local.failures, rows }, null, 2)}\n`,
  );
  const passing = new Set(["MATCH", "MATCH_NONDETERMINISTIC"]);
  for (const row of rows.filter((r) => !passing.has(r.status))) {
    console.log(`\n${row.status} ${row.row}`);
    console.log(`  production ${String(JSON.stringify(row.production)).slice(0, 400)}`);
    console.log(`  fireemu    ${String(JSON.stringify(row.fireemu)).slice(0, 400)}`);
  }
  console.log(JSON.stringify({ summary, orphans, failures: local.failures }, null, 2));
  if (!rows.every((r) => passing.has(r.status)) || orphans.length || local.failures.length) {
    process.exitCode = 1;
  }
}

/** The paths where two recordings differ, and whether their error messages share the code. */
function differenceSummary(production, fireemu) {
  const differences = [];
  const walk = (a, b, path) => {
    if (JSON.stringify(a) === JSON.stringify(b)) return;
    if (
      a &&
      b &&
      typeof a === "object" &&
      typeof b === "object" &&
      Array.isArray(a) === Array.isArray(b)
    ) {
      for (const key of new Set([...Object.keys(a), ...Object.keys(b)]))
        walk(a[key], b[key], `${path}.${key}`);
      return;
    }
    differences.push(path.slice(1));
  };
  walk(production, fireemu, "");
  const code = (recorded) => String(recorded?.body?.error?.message ?? "").split(" : ")[0];
  return {
    differences,
    sameErrorCode: code(production) !== "" && code(production) === code(fireemu),
  };
}

/**
 * Writes the committed closure evidence from the last `check`: the artifact, the fixture it
 * was compared with, and every row's classification (no response bodies).
 */
async function exportComparison(out) {
  if (!out) throw new Error("usage: export-comparison <output.json>");
  const comparison = JSON.parse(await readFile(join(RUN_DIR, "comparison.json"), "utf8"));
  const fixtureSha256 = sha256(await readFile(FIXTURE, "utf8"));
  const evidence = {
    kind: "auth-account-comparison-v1",
    artifactSha256: comparison.artifactSha256,
    fixtureSha256,
    summary: comparison.summary,
    rows: comparison.rows.map(({ row, status, production, fireemu }) =>
      status === "MISMATCH"
        ? Object.assign({ row, status }, differenceSummary(production, fireemu))
        : { row, status },
    ),
  };
  await writeFile(out, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(JSON.stringify({ out, summary: evidence.summary, fixtureSha256 }, null, 2));
}

const mode = process.argv[2];
if (mode === "record-production") await recordProduction();
else if (mode === "rebuild-fixture") await rebuildFixture(process.argv[3]);
else if (mode === "check") await check();
else if (mode === "export-comparison") await exportComparison(process.argv[3]);
else if (mode === "session-local") await sessionLocal();
else if (mode === "local") {
  const local = await runLocal(selectedPrograms());
  await writeFile(join(RUN_DIR, "fireemu-results.json"), `${JSON.stringify(local, null, 2)}\n`);
  console.log(JSON.stringify({ requests: local.requests, failures: local.failures }, null, 2));
} else {
  console.error("usage: run.mjs record-production|check");
  process.exitCode = 2;
}
