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
import { BASELINE_CONFIG, PROGRAMS } from "./corpus.mjs";
import {
  RECORDED_PROJECT,
  SANDBOX_PROJECT,
  createContext,
  diffRecordings,
  sameRecording,
  validateCorpus,
} from "./harness.mjs";
import { runCorpus } from "./session.mjs";

const execFileAsync = promisify(execFile);
const FIXTURE = join(CONFORMANCE_DIR, "auth-account-production.json");
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-account");
const LOCAL_PORT = 32296;
const TASK_ID = "AUTH-ACCOUNT-SANDBOX";
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

function selectedPrograms() {
  const prefixes = (process.env.AUTH_ACCOUNT_PROGRAMS ?? "").split(",").filter(Boolean);
  const programs = prefixes.length
    ? PROGRAMS.filter((p) => prefixes.some((prefix) => p.id.startsWith(prefix)))
    : PROGRAMS;
  if (programs.length === 0) throw new Error("no program matches AUTH_ACCOUNT_PROGRAMS");
  return programs;
}

const programDigest = (program) => sha256(JSON.stringify(program));

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

async function recordOnce(programs, run) {
  const configPath = process.env.FIREEMU_AUTH_SANDBOX_WEB_CONFIG;
  if (!configPath) throw new Error("FIREEMU_AUTH_SANDBOX_WEB_CONFIG is required");
  const web = JSON.parse(await readFile(configPath, "utf8"));
  if (web.projectId !== SANDBOX_PROJECT) throw new Error("web config is not the sandbox project");
  const ctx = createContext({
    run,
    project: SANDBOX_PROJECT,
    target: {
      kind: "production",
      apiKey: web.apiKey,
      adminToken: await adminToken(),
      quotaProject: SANDBOX_PROJECT,
    },
  });
  ctx.projectNumber = web.messagingSenderId;
  return runCorpus(programs, ctx, {
    settleMs: 10_000,
    baselineConfig: BASELINE_CONFIG,
    log: (l) => console.log(l),
  });
}

async function recordProduction() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  if (!ledger) throw new Error("FIREEMU_SANDBOX_LEDGER is required");
  const programs = selectedPrograms();
  const corpusRequests = validateCorpus(programs);
  const sha = await gitSha();
  const startedAt = new Date().toISOString();
  const first = await recordOnce(programs, String(Date.now()));
  const second = await recordOnce(programs, String(Date.now() + 1));
  const nondeterministic = diffRecordings(first.results, second.results);
  const failures = [...first.failures, ...second.failures];
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { version: 1, recordedAgainst: {}, programs: {} };
  fixture.recordedAgainst = {
    target: "production Identity Toolkit and Secure Token REST, Identity Platform sandbox",
    project: RECORDED_PROJECT,
    note: "Two recordings per program. Tokens, generated ids, hashes, salts, times, the project id, its number and the API key are placeholders. `second` holds the other recording of rows that differed.",
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
      recordedAt: startedAt,
      gitSha: sha,
      ...(one.config ? { config: one.config } : {}),
      steps: one.steps,
      ...(Object.keys(differing).length ? { second: differing } : {}),
    };
  }
  const ordered = Object.fromEntries(
    Object.entries(fixture.programs).toSorted(([a], [b]) => a.localeCompare(b)),
  );
  fixture.programs = ordered;
  await writeFile(FIXTURE, `${JSON.stringify(fixture, null, 2)}\n`);
  const requests =
    first.requests + second.requests + first.harnessRequests + second.harnessRequests;
  await appendFile(
    ledger,
    `${JSON.stringify({
      ts: new Date().toISOString(),
      project: SANDBOX_PROJECT,
      database: null,
      gitSha: sha,
      corpusDigest: sha256(JSON.stringify(programs)),
      requests,
      estimatedUsd: 0,
      outcome: failures.length ? "harness-failure" : "recorded",
      taskId: TASK_ID,
      programs: programs.map((p) => p.id),
    })}\n`,
  );
  console.log(
    JSON.stringify(
      { programs: programs.length, corpusRequests, requests, nondeterministic, failures },
      null,
      2,
    ),
  );
  if (failures.length) process.exitCode = 1;
}

async function sessionLocal() {
  const programs = JSON.parse(await readFile(process.env.AUTH_ACCOUNT_IN, "utf8"));
  const ctx = createContext({
    run: process.env.AUTH_ACCOUNT_RUN,
    project: SANDBOX_PROJECT,
    target: { kind: "local", origin: process.env.AUTH_ACCOUNT_ORIGIN },
  });
  // fireemu starts with every sign-in provider enabled; the admin config surface for the
  // provider fields is not implemented yet, so the baseline is only applied in production.
  const out = await runCorpus(programs, ctx, {
    baselineConfig: process.env.AUTH_ACCOUNT_LOCAL_BASELINE === "1" ? BASELINE_CONFIG : undefined,
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

async function check() {
  const fixture = JSON.parse(await readFile(FIXTURE, "utf8"));
  const programs = selectedPrograms().filter((p) => fixture.programs[p.id]);
  const local = await runLocal(programs);
  const rows = [];
  for (const program of programs) {
    const saved = fixture.programs[program.id];
    const stale = saved.corpusDigest !== programDigest(program);
    for (const step of program.steps) {
      const production = saved.steps[step.id];
      const alternative = saved.second?.[step.id];
      const fireemu = local.results[program.id]?.steps?.[step.id];
      let status;
      if (stale || production === undefined) status = "STALE_FIXTURE";
      else if (fireemu === undefined) status = "MISSING";
      else if (production.status === 429 || alternative?.status === 429) status = "INDETERMINATE";
      else if (
        sameRecording(production, fireemu) ||
        (alternative && sameRecording(alternative, fireemu))
      )
        status = alternative ? "MATCH_NONDETERMINISTIC" : "MATCH";
      else status = "MISMATCH";
      rows.push({
        row: `${program.id}#${step.id}`,
        status,
        production,
        ...(alternative ? { alternative } : {}),
        fireemu,
      });
    }
  }
  const summary = {};
  for (const { status } of rows) summary[status] = (summary[status] ?? 0) + 1;
  const artifactSha256 = sha256(await readFile(local.binary));
  await writeFile(
    join(RUN_DIR, "comparison.json"),
    `${JSON.stringify({ artifact: local.binary, artifactSha256, summary, failures: local.failures, rows }, null, 2)}\n`,
  );
  for (const row of rows.filter(
    (r) => r.status !== "MATCH" && r.status !== "MATCH_NONDETERMINISTIC",
  )) {
    console.log(`\n${row.status} ${row.row}`);
    console.log(`  production ${JSON.stringify(row.production).slice(0, 400)}`);
    console.log(`  fireemu    ${JSON.stringify(row.fireemu).slice(0, 400)}`);
  }
  console.log(JSON.stringify({ summary, failures: local.failures }, null, 2));
  const ok = rows.every((r) => r.status === "MATCH" || r.status === "MATCH_NONDETERMINISTIC");
  if (!ok || local.failures.length) process.exitCode = 1;
}

const mode = process.argv[2];
if (mode === "record-production") await recordProduction();
else if (mode === "check") await check();
else if (mode === "session-local") await sessionLocal();
else if (mode === "local") {
  const local = await runLocal(selectedPrograms());
  await writeFile(join(RUN_DIR, "fireemu-results.json"), `${JSON.stringify(local, null, 2)}\n`);
  console.log(JSON.stringify({ requests: local.requests, failures: local.failures }, null, 2));
} else {
  console.error("usage: run.mjs record-production|check");
  process.exitCode = 2;
}
