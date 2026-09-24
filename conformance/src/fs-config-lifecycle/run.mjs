// FS-CONFIG-LIFECYCLE sandbox runner.
//
//   node src/fs-config-lifecycle/run.mjs record-production   record the corpus twice against the
//                                                            query sandbox's named databases and
//                                                            update fs-config-lifecycle-production.json
//   node src/fs-config-lifecycle/run.mjs check               run the corpus against fireemu and
//                                                            compare with the saved production rows
//   node src/fs-config-lifecycle/run.mjs local               run the corpus against fireemu only
//   node src/fs-config-lifecycle/run.mjs export-comparison <out.json>
//   node src/fs-config-lifecycle/run.mjs rebuild-fixture <private run dir>
//
// `record-production` needs owner ADC (`gcloud auth application-default`),
// FIREEMU_SANDBOX_LEDGER (the private append-only run ledger) and FIREEMU_FS_CONFIG_PRIVATE_DIR
// (a git-ignored directory for the raw recordings). FS_CONFIG_PROGRAMS limits a run to programs
// whose id starts with one of its comma-separated prefixes; recorded programs replace their
// previous entries and the others are kept. `check` uses FIREEMU_BIN (or the workspace build).

import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { CONFORMANCE_DIR, REPO_ROOT } from "../config.mjs";
import { resolveFireemuBinary } from "../evidence.mjs";
import { PROGRAMS } from "./corpus.mjs";
import { scanFixture } from "./fixture-scan.mjs";
import {
  BISECT_PROJECT,
  RECORDED_PROJECT,
  SANDBOX_PROJECT,
  createContext,
  diffRecordings,
  isTransient,
  sameRecording,
  traceAgrees,
  validateCorpus,
} from "./harness.mjs";
import { runCorpus } from "./session.mjs";

const execFileAsync = promisify(execFile);
const FIXTURE = join(CONFORMANCE_DIR, "fs-config-lifecycle-production.json");
/** Normalized managed-export captures (production's and fireemu's) for the interop programs. */
const EXPORTS = join(CONFORMANCE_DIR, "fs-config-lifecycle-exports.json");
const LOCAL_CONFIG = join(CONFORMANCE_DIR, "fs-config-lifecycle.fireemu.json");
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "fs-config-lifecycle");
const TASK_ID = "FS-CONFIG-LIFECYCLE-SANDBOX";
const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** The project a program runs against: the query sandbox unless it names another (C9). */
const projectOf = (program) => program.project ?? SANDBOX_PROJECT;

/** Whether a program needs the run bucket. */
const usesBucket = (programs) =>
  programs.some((p) =>
    /\{prefix\}|\{objects\}|"capture"|"upload"|"reproduce"/.test(JSON.stringify(p)),
  );

async function loadExports() {
  return existsSync(EXPORTS) ? JSON.parse(await readFile(EXPORTS, "utf8")) : {};
}

function selectedPrograms() {
  const prefixes = (process.env.FS_CONFIG_PROGRAMS ?? "").split(",").filter(Boolean);
  const programs = prefixes.length
    ? PROGRAMS.filter((p) => prefixes.some((prefix) => p.id.startsWith(prefix)))
    : PROGRAMS;
  if (programs.length === 0) throw new Error("no program matches FS_CONFIG_PROGRAMS");
  return programs;
}

export const programDigest = (program) => sha256(JSON.stringify(program));

/** Normalization and request semantics a saved row depends on; a change makes it stale. */
export async function harnessDigest() {
  const sources = await Promise.all(
    ["harness.mjs", "session.mjs", "grpc.mjs"].map((file) =>
      readFile(join(CONFORMANCE_DIR, "src/fs-config-lifecycle", file), "utf8"),
    ),
  );
  return sha256(sources.join("\n"));
}

/** Per recording: every step once (every poll a poll step may make); a cleanup allowance. */
const ceilings = (programs) => ({
  maxRequests: validateCorpus(programs),
  maxHarnessRequests: programs.reduce((n, p) => n + 20 + 12 * (p.databases?.length ?? 0), 200),
});

async function assertIgnored(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  try {
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
      "src/fs-config-lifecycle",
      "fs-config-lifecycle-production.json",
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

async function projectNumber(token, project) {
  const response = await fetch(
    `https://cloudresourcemanager.googleapis.com/v1/projects/${project}`,
    {
      headers: { authorization: `Bearer ${token}`, "x-goog-user-project": project },
    },
  );
  const body = await response.json();
  if (!/^\d{6,}$/.test(String(body.projectNumber ?? "")))
    throw new Error(`cannot read the sandbox project number (${response.status})`);
  return String(body.projectNumber);
}

async function recordOnce(programs, project, token, number, captures) {
  const startedMs = Date.now();
  const run = String(Math.floor(startedMs / 1000));
  const ctx = createContext({
    run,
    startedMs,
    project,
    target: {
      kind: "production",
      token,
      quotaProject: project,
      projectNumber: number,
      bucket: `${project}-cfg-${run}`,
    },
  });
  return runCorpus(programs, ctx, {
    ...ceilings(programs),
    concurrency: 4,
    bucket: usesBucket(programs),
    captures,
    log: (line) => console.log(line),
  });
}

async function writeFixture({ programs, recordings, meta, secrets }) {
  const [first, second] = recordings;
  const fixture = existsSync(FIXTURE)
    ? JSON.parse(await readFile(FIXTURE, "utf8"))
    : { version: 1, recordedAgainst: {}, programs: {} };
  fixture.recordedAgainst = {
    target:
      "production Firestore Admin v1 and Cloud Storage JSON API, query sandbox named databases",
    project: RECORDED_PROJECT,
    note: "Two recordings per program. Database ids, uids, operation and index ids, etags, run-window times, the bucket, the project id and its number are placeholders. `second` holds the other recording of rows that differed. A poll row is the collapsed trace of the states it saw and the settled answer (scope decision C10).",
  };
  for (const program of programs) {
    const one = first.results[program.id];
    const two = second.results[program.id];
    if (!one || !two) continue;
    const differing = Object.fromEntries(
      Object.entries(two.steps).filter(([id, rec]) => {
        const other = one.steps[id];
        return rec?.trace
          ? !(traceAgrees(rec, other) && traceAgrees(other, rec))
          : !sameRecording(rec, other);
      }),
    );
    fixture.programs[program.id] = {
      corpusDigest: programDigest(program),
      harnessDigest: meta.harness,
      recordedAt: meta.startedAt,
      gitSha: meta.sha,
      steps: one.steps,
      ...(Object.keys(differing).length ? { second: differing } : {}),
    };
  }
  fixture.programs = Object.fromEntries(
    Object.entries(fixture.programs).toSorted(([a], [b]) => a.localeCompare(b)),
  );
  const text = `${JSON.stringify(fixture, null, 2)}\n`;
  scanFixture(text, secrets);
  await writeCaptures(first.results, (programId, as) => `${programId}:${as}`, secrets);
  await writeFile(FIXTURE, text);
  return diffRecordings(first.results, second.results);
}

/** Merges the normalized export captures of one recording into the committed exports file. */
async function writeCaptures(results, keyOf, secrets) {
  const exportsFile = await loadExports();
  let changed = false;
  for (const [programId, result] of Object.entries(results)) {
    for (const [as, capture] of Object.entries(result.captures ?? {})) {
      exportsFile[keyOf(programId, as)] = capture;
      changed = true;
    }
  }
  if (!changed) return;
  const text = `${JSON.stringify(Object.fromEntries(Object.entries(exportsFile).toSorted(([a], [b]) => a.localeCompare(b))), null, 2)}\n`;
  // The captures are base64 of binary files; scan their decoded bytes too.
  scanFixture(text, secrets);
  for (const capture of Object.values(exportsFile))
    for (const file of Object.values(capture.files))
      scanFixture(Buffer.from(file, "base64").toString("latin1"), secrets);
  await writeFile(EXPORTS, text);
}

async function recordProduction() {
  const ledger = process.env.FIREEMU_SANDBOX_LEDGER;
  const privateRoot = process.env.FIREEMU_FS_CONFIG_PRIVATE_DIR;
  if (!ledger || !privateRoot)
    throw new Error("FIREEMU_SANDBOX_LEDGER and FIREEMU_FS_CONFIG_PRIVATE_DIR are required");
  await assertCleanTree();
  // One project per run: the query sandbox, or the bisection project when FS_CONFIG_BISECT=1.
  const project = process.env.FS_CONFIG_BISECT === "1" ? BISECT_PROJECT : SANDBOX_PROJECT;
  const captures = await loadExports();
  // A program that uploads a capture not committed yet (fireemu's export before fireemu can
  // export) waits for a later run.
  const programs = selectedPrograms().filter(
    (p) =>
      !p.local &&
      projectOf(p) === project &&
      p.steps.every((s) => !s.upload || s.onlyOn === "local" || captures[s.upload.from]),
  );
  if (programs.length === 0) throw new Error(`no production program runs against ${project}`);
  const corpusRequests = validateCorpus(programs);
  const meta = {
    sha: await gitSha(),
    harness: await harnessDigest(),
    startedAt: new Date().toISOString(),
    programs: programs.map((p) => p.id),
    corpusDigests: Object.fromEntries(programs.map((p) => [p.id, programDigest(p)])),
  };
  await assertIgnored(privateRoot);
  const runDir = join(privateRoot, `fs-config-production-${meta.startedAt.replaceAll(":", "")}`);
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const recordings = [];
  let outcome = "recorded";
  let error;
  let token;
  let number;
  try {
    for (const n of [1, 2]) {
      token = await adminToken();
      number ??= await projectNumber(token, project);
      if (n === 2) await new Promise((r) => setTimeout(r, 1_000));
      const recording = await recordOnce(programs, project, token, number, captures);
      recordings.push(recording);
      await writeFile(join(runDir, `recording-${n}.json`), JSON.stringify(recording), {
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
  const failures = recordings.flatMap((r) => r.failures ?? []);
  try {
    if (!error) {
      const nondeterministic = await writeFixture({
        programs,
        recordings,
        meta,
        secrets: [token, project, number],
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
        project,
        database:
          project === BISECT_PROJECT
            ? "(default) (deleted and re-created, C9)"
            : "named cfg<run>-* (created and deleted per program)",
        gitSha: meta.sha,
        corpusDigest: sha256(JSON.stringify(programs)),
        requests,
        // Admin calls, index builds over a handful of documents, and bucket storage for
        // minutes: well under one cent. Index and export charges scale with documents.
        estimatedUsd: 0.01,
        outcome,
        taskId: TASK_ID,
        programs: meta.programs,
        buckets: usesBucket(programs)
          ? recordings.map((r) => `${project}-cfg-${r.context?.run ?? "?"}`)
          : [],
        ...(error ? { error } : {}),
      })}\n`,
    );
  }
  if (error) throw new Error(error);
  if (failures.length) process.exitCode = 1;
}

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
  if (changed.length || programs.length !== meta.programs.length)
    throw new Error(`corpus changed since the recording: ${changed.map((p) => p.id).join(", ")}`);
  const nondeterministic = await writeFixture({
    programs,
    recordings,
    meta,
    secrets: [SANDBOX_PROJECT],
  });
  console.log(JSON.stringify({ programs: programs.length, nondeterministic }, null, 2));
}

async function sessionLocal() {
  const programs = JSON.parse(await readFile(process.env.FS_CONFIG_IN, "utf8"));
  const host = process.env.FIRESTORE_EMULATOR_HOST;
  const storageHost = process.env.FIREBASE_STORAGE_EMULATOR_HOST;
  if (!host || !storageHost)
    throw new Error("the Firestore and Storage emulator hosts must be set");
  const url = new URL(`http://${host}`);
  const startedMs = Date.now();
  const run = String(Math.floor(startedMs / 1000));
  const ctx = createContext({
    run,
    startedMs,
    project: process.env.FS_CONFIG_PROJECT,
    target: {
      kind: "local",
      origin: url.origin,
      storageOrigin: new URL(`http://${storageHost}`).origin,
      grpcHost: url.hostname,
      grpcPort: Number(url.port),
    },
  });
  // fireemu's long-running work finishes in seconds, so polls and delays are scaled down.
  const out = await runCorpus(programs, ctx, {
    ...ceilings(programs),
    concurrency: 4,
    pollScale: 0.05,
    bucket: usesBucket(programs),
    captures: await loadExports(),
  });
  await writeFile(process.env.FS_CONFIG_OUT, JSON.stringify(out));
}

/** Runs programs against fireemu, one daemon per project, and merges what they answered. */
async function runLocal(programs) {
  const merged = { results: {}, failures: [], requests: 0, harnessRequests: 0 };
  let binary;
  for (const project of [SANDBOX_PROJECT, BISECT_PROJECT]) {
    const mine = programs.filter((p) => projectOf(p) === project);
    if (!mine.length) continue;
    const out = await runLocalProject(mine, project);
    binary = out.binary;
    Object.assign(merged.results, out.results);
    merged.failures.push(...out.failures);
    merged.requests += out.requests;
    merged.harnessRequests += out.harnessRequests;
  }
  return { binary, ...merged };
}

async function runLocalProject(programs, project) {
  await mkdir(RUN_DIR, { recursive: true });
  const inPath = join(RUN_DIR, `programs-${project}.json`);
  const outPath = join(RUN_DIR, `fireemu-${project}.json`);
  await writeFile(inPath, JSON.stringify(programs));
  const binary = resolveFireemuBinary();
  const child = spawn(
    binary,
    [
      "exec",
      "--config",
      LOCAL_CONFIG,
      "--project",
      project,
      "--only",
      "firestore,storage",
      "--firestore-port",
      "0",
      "--http-port",
      "0",
      "--storage-port",
      "0",
      "--ui-port",
      "0",
      "--hub-port",
      "0",
      "--logging-port",
      "0",
      "--",
      process.execPath,
      join(CONFORMANCE_DIR, "src/fs-config-lifecycle/run.mjs"),
      "session-local",
    ],
    {
      cwd: REPO_ROOT,
      stdio: ["ignore", "inherit", "inherit"],
      env: {
        ...process.env,
        FS_CONFIG_IN: inPath,
        FS_CONFIG_OUT: outPath,
        FS_CONFIG_PROJECT: project,
      },
    },
  );
  const code = await new Promise((resolve) => child.once("exit", resolve));
  if (code !== 0) throw new Error(`fireemu session exited ${code}`);
  return { binary, ...JSON.parse(await readFile(outPath, "utf8")) };
}

export function classify({ stale, production, alternative, fireemu }) {
  if (stale) return "STALE_FIXTURE";
  if (production === undefined) return "MISSING_FIXTURE";
  if (fireemu === undefined) return "MISSING";
  // A server error production returned identically in both recordings is behavior.
  const repeatedServerError = production.status >= 500 && alternative === undefined;
  const transient = (r) => isTransient(r) && !(repeatedServerError && r?.status >= 500);
  if ([production, alternative, fireemu].some(transient)) return "INDETERMINATE";
  const agrees = (saved) =>
    saved?.trace ? traceAgrees(saved, fireemu) : sameRecording(saved, fireemu);
  if (agrees(production)) return alternative ? "MATCH_NONDETERMINISTIC" : "MATCH";
  if (alternative && agrees(alternative)) return "MATCH_NONDETERMINISTIC";
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
      if (step.onlyOn === "production" || step.capture || step.upload) continue;
      if (program.local || step.reproduce) {
        // A local-only row: fireemu's export must reproduce the capture production accepted.
        if (!step.reproduce) continue;
        const fireemu = local.results[program.id]?.steps?.[step.id];
        rows.push({
          row: `${program.id}#${step.id}`,
          status: fireemu?.body?.identical === true ? "MATCH" : "MISMATCH",
          fireemu,
        });
        continue;
      }
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
  if (!rows.every((r) => passing.has(r.status)) || orphans.length || local.failures.length)
    process.exitCode = 1;
}

/** The paths where two recordings differ. */
function differencePaths(production, fireemu) {
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
  return differences;
}

async function exportComparison(out) {
  if (!out) throw new Error("usage: export-comparison <output.json>");
  const comparison = JSON.parse(await readFile(join(RUN_DIR, "comparison.json"), "utf8"));
  const evidence = {
    kind: "fs-config-lifecycle-comparison-v1",
    artifactSha256: comparison.artifactSha256,
    fixtureSha256: sha256(await readFile(FIXTURE, "utf8")),
    summary: comparison.summary,
    rows: comparison.rows.map(({ row, status, production, fireemu }) =>
      status === "MISMATCH"
        ? { row, status, differences: differencePaths(production, fireemu) }
        : { row, status },
    ),
  };
  await writeFile(out, `${JSON.stringify(evidence, null, 2)}\n`);
  console.log(
    JSON.stringify(
      { out, summary: evidence.summary, fixtureSha256: evidence.fixtureSha256 },
      null,
      2,
    ),
  );
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
} else if (mode === "capture-fireemu-export") {
  // Runs fireemu's export of the interop data and commits it (normalized) for production to
  // import. Every later artifact's check must reproduce it byte for byte.
  const programs = PROGRAMS.filter((p) => p.local);
  const local = await runLocal(programs);
  if (local.failures.length) throw new Error(JSON.stringify(local.failures));
  await writeCaptures(local.results, (_programId, as) => `fireemu:${as}`, [SANDBOX_PROJECT]);
  console.log(JSON.stringify({ captured: Object.keys(local.results) }));
} else if (mode === "validate") {
  console.log(JSON.stringify({ programs: PROGRAMS.length, requests: validateCorpus(PROGRAMS) }));
} else {
  console.error(
    "usage: run.mjs record-production|check|local|export-comparison|rebuild-fixture|validate",
  );
  process.exitCode = 2;
}
