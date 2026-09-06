// Supervisor for the Identity Toolkit black-box probe.
//
//   node src/auth-probe/run.mjs record             official Auth emulator -> auth-matrix.json
//   node src/auth-probe/run.mjs check              fireemu vs the recorded matrix
//   node src/auth-probe/run.mjs record-production  production Identity Toolkit, compared with
//                                                  the recorded emulator answer and fireemu
//
// `record` needs Java and the pinned firebase-tools; `check` needs a built fireemu;
// `record-production` needs FIREEMU_PRODUCTION_PROJECT and FIREEMU_PRODUCTION_API_KEY (the
// project's web API key; `firebase apps:sdkconfig web` prints it). Every account a program
// creates is deleted by the program; no production identifier is written to the matrices.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { CONFORMANCE_DIR, REPO_ROOT } from "../config.mjs";
import { PROGRAMS } from "./programs.mjs";

const PROJECT = "demo-auth-probe";
const TESTD_HTTP_PORT = 32295;
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "auth-probe");
const MATRIX_JSON = join(CONFORMANCE_DIR, "auth-matrix.json");
const PRODUCTION_JSON = join(CONFORMANCE_DIR, "auth-production-matrix.json");
const PRODUCTION_MD = join(CONFORMANCE_DIR, "AUTH-PRODUCTION-MATRIX.md");
const SESSION = "src/auth-probe/session.mjs";
const GRACE_MS = 8000;

async function terminateGroup(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const groupKill = (signal) => {
    try {
      process.kill(-child.pid, signal);
    } catch {
      /* already gone */
    }
  };
  const exited = new Promise((resolve) => child.once("exit", resolve));
  groupKill("SIGTERM");
  const timer = setTimeout(() => groupKill("SIGKILL"), GRACE_MS);
  await exited;
  clearTimeout(timer);
}

async function runSupervisor({ name, command, args, env, timeoutMs = 900_000 }) {
  const child = spawn(command, args, {
    cwd: CONFORMANCE_DIR,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, ...env },
  });
  const log = [];
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (chunk) => {
      log.push(chunk.toString());
      if (process.env.CONFORMANCE_VERBOSE) process.stderr.write(chunk);
    });
  }
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    void terminateGroup(child);
  }, timeoutMs);
  const onSignal = () => void terminateGroup(child).then(() => process.exit(130));
  process.once("SIGINT", onSignal);
  process.once("SIGTERM", onSignal);
  const code = await new Promise((resolve) => child.once("exit", resolve));
  clearTimeout(timer);
  process.off("SIGINT", onSignal);
  process.off("SIGTERM", onSignal);
  await terminateGroup(child);
  if (timedOut) throw new Error(`${name}: timed out\n${log.join("")}`);
  if (code !== 0) throw new Error(`${name}: exited ${code}\n${log.join("")}`);
  return log.join("");
}

async function writePrograms() {
  await mkdir(RUN_DIR, { recursive: true });
  const inPath = join(RUN_DIR, "programs.json");
  await writeFile(inPath, JSON.stringify(PROGRAMS));
  return inPath;
}

const run = String(Date.now());

async function probeOracle(inPath, outPath) {
  await runSupervisor({
    name: "oracle",
    command: join(CONFORMANCE_DIR, "node_modules/.bin/firebase"),
    args: [
      "emulators:exec",
      "--project",
      PROJECT,
      "--config",
      "auth-probe.firebase.json",
      "--only",
      "auth",
      `sh -c 'AUTH_PROBE_BASE=http://$FIREBASE_AUTH_EMULATOR_HOST/identitytoolkit.googleapis.com node ${SESSION}'`,
    ],
    env: {
      AUTH_PROBE_IN: inPath,
      AUTH_PROBE_OUT: outPath,
      AUTH_PROBE_RUN: run,
      FIREBASE_CLI_EXPERIMENTS: "",
      GOOGLE_APPLICATION_CREDENTIALS: "",
    },
  });
  return JSON.parse(await readFile(outPath, "utf8"));
}

/**
 * Runs the programs against fireemu. `record` and `check` compare fireemu with the official
 * Auth emulator, so they run it with `auth-probe.fireemu.json`, which switches off the
 * production default fireemu follows and the official emulator lacks (email enumeration
 * protection); `record-production` runs fireemu as shipped (`auth-probe.fireemu.production.json`).
 */
async function probeFireemu(inPath, outPath, config = "auth-probe.fireemu.json") {
  const binary =
    process.env.FIREEMU_BIN ??
    ["target/release/fireemu", "target/debug/fireemu"]
      .map((p) => join(REPO_ROOT, p))
      .find((p) => existsSync(p));
  if (!binary) throw new Error("fireemu is not built: run `cargo build -p fireemu`");
  await runSupervisor({
    name: "fireemu",
    command: binary,
    args: [
      "exec",
      "--config",
      join(CONFORMANCE_DIR, config),
      "--project",
      PROJECT,
      "--only",
      "auth",
      "--http-port",
      String(TESTD_HTTP_PORT),
      "--firestore-port",
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
      "node",
      SESSION,
    ],
    env: {
      AUTH_PROBE_BASE: `http://127.0.0.1:${TESTD_HTTP_PORT}/identitytoolkit.googleapis.com`,
      AUTH_PROBE_IN: inPath,
      AUTH_PROBE_OUT: outPath,
      AUTH_PROBE_RUN: run,
    },
  });
  return JSON.parse(await readFile(outPath, "utf8"));
}

function decision(step) {
  if (!step) return { missing: true };
  if (step.code === "OK") return { status: step.status, code: step.code, body: step.body };
  return { status: step.status, code: step.code };
}

function canonical(value) {
  const sort = (v) => {
    if (Array.isArray(v)) return v.map(sort);
    if (v && typeof v === "object") {
      return Object.fromEntries(
        Object.keys(v)
          .toSorted()
          .map((k) => [k, sort(v[k])]),
      );
    }
    return v;
  };
  return JSON.stringify(sort(value));
}

const rowKey = (programId, stepId) => `${programId}#${stepId}`;

async function record() {
  const inPath = await writePrograms();
  const oracle = await probeOracle(inPath, join(RUN_DIR, "oracle.json"));
  const provenance = JSON.parse(
    await readFile(join(CONFORMANCE_DIR, "package.json"), "utf8"),
  ).dependencies;
  const matrix = {
    version: 1,
    recordedAgainst: { firebaseTools: provenance["firebase-tools"] },
    programs: PROGRAMS.map((p) => ({
      id: p.id,
      area: p.area,
      steps: Object.fromEntries(
        p.steps.map((s) => [s.id, { oracle: oracle[p.id]?.steps?.[s.id] ?? { missing: true } }]),
      ),
    })),
  };
  await writeFile(MATRIX_JSON, `${JSON.stringify(matrix, null, 2)}\n`);
  console.log(
    `recorded ${PROGRAMS.length} programs, ${PROGRAMS.reduce((n, p) => n + p.steps.length, 0)} steps`,
  );
}

/**
 * The production answers recorded by `record-production`, keyed by row. A row where fireemu
 * disagrees with the official emulator but matches production is accepted: production is
 * the authority fireemu follows, and the official emulator's answer is the documented one.
 */
async function recordedProduction() {
  if (!existsSync(PRODUCTION_JSON)) return new Map();
  const production = JSON.parse(await readFile(PRODUCTION_JSON, "utf8"));
  return new Map(
    production.programs.flatMap((p) =>
      Object.entries(p.steps).map(([id, row]) => [rowKey(p.id, id), row.production]),
    ),
  );
}

async function check() {
  const matrix = JSON.parse(await readFile(MATRIX_JSON, "utf8"));
  const production = await recordedProduction();
  const inPath = await writePrograms();
  const got = await probeFireemu(inPath, join(RUN_DIR, "fireemu.json"));
  let rows = 0;
  let failures = 0;
  let followsProduction = 0;
  for (const program of matrix.programs) {
    for (const [stepId, recorded] of Object.entries(program.steps)) {
      rows += 1;
      const expected = recorded.oracle;
      const actual = got[program.id]?.steps?.[stepId] ?? { missing: true };
      if (canonical(decision(expected)) === canonical(decision(actual))) continue;
      const key = rowKey(program.id, stepId);
      const prod = production.get(key);
      if (prod && canonical(decision(prod)) === canonical(decision(actual))) {
        followsProduction += 1;
        console.log(`${key}: follows production where the official emulator differs`);
        continue;
      }
      failures += 1;
      console.error(`\n${key} disagrees`);
      console.error(`  expected ${JSON.stringify(decision(expected))}`);
      console.error(`  fireemu  ${JSON.stringify(decision(actual))}`);
    }
  }
  if (failures === 0) {
    console.log(
      `ok: ${rows} rows agree with the recorded oracle ` +
        `(${followsProduction} follow production where the official emulator differs)`,
    );
    return 0;
  }
  console.error(`\n${failures} of ${rows} rows disagree`);
  return 1;
}

async function recordProduction() {
  const project = process.env.FIREEMU_PRODUCTION_PROJECT;
  const key = process.env.FIREEMU_PRODUCTION_API_KEY;
  if (!project || !key) {
    throw new Error("FIREEMU_PRODUCTION_PROJECT and FIREEMU_PRODUCTION_API_KEY are required");
  }
  const inPath = await writePrograms();
  const productionOut = join(RUN_DIR, "production.json");
  const fireemuOut = join(RUN_DIR, "fireemu-for-production.json");
  await runSupervisor({
    name: "production",
    command: "node",
    args: [SESSION],
    env: {
      AUTH_PROBE_BASE: "https://identitytoolkit.googleapis.com",
      AUTH_PROBE_KEY: key,
      AUTH_PROBE_IN: inPath,
      AUTH_PROBE_OUT: productionOut,
      AUTH_PROBE_RUN: run,
      AUTH_PROBE_TIMEOUT_MS: "60000",
    },
    timeoutMs: 600_000,
  });
  const production = JSON.parse(await readFile(productionOut, "utf8"));
  const fireemu = await probeFireemu(inPath, fireemuOut, "auth-probe.fireemu.production.json");
  const matrix = JSON.parse(await readFile(MATRIX_JSON, "utf8"));
  const counts = {};
  const dropSecrets = (value) =>
    JSON.parse(
      JSON.stringify(value ?? null)
        .replaceAll(project, "<production project>")
        .replaceAll(key, "<api key>"),
    );
  const programs = PROGRAMS.map((p) => ({
    id: p.id,
    area: p.area,
    steps: Object.fromEntries(
      p.steps.map((s) => {
        const emulator = matrix.programs.find((m) => m.id === p.id)?.steps?.[s.id]?.oracle ?? {
          missing: true,
        };
        const mine = fireemu[p.id]?.steps?.[s.id] ?? { missing: true };
        const prod = dropSecrets(production[p.id]?.steps?.[s.id] ?? { missing: true });
        const same = (a, b) => canonical(decision(a)) === canonical(decision(b));
        let status;
        if (same(prod, emulator) && same(prod, mine)) status = "parity";
        else if (same(prod, mine)) status = "fireemu-matches-production";
        else if (same(prod, emulator)) status = "fireemu-divergence";
        else if (same(emulator, mine)) status = "emulators-diverge-from-production";
        else status = "three-way-difference";
        counts[status] = (counts[status] ?? 0) + 1;
        return [s.id, { production: prod, emulator, fireemu: mine, status }];
      }),
    ),
  }));
  const output = {
    version: 1,
    recordedAgainst: {
      target: "production Identity Toolkit (v1 and v2 REST) with the project's web API key",
      officialEmulatorMatrix: matrix.recordedAgainst,
      note: "The production project id and API key are never recorded. Rows compare HTTP status, the Identity Toolkit error code and the normalized success body; tokens, ids, expiry and timestamps are placeholders and the human sentence production appends to some error codes is not compared.",
    },
    summary: counts,
    programs,
  };
  await writeFile(PRODUCTION_JSON, `${JSON.stringify(output, null, 2)}\n`);
  const cell = (v) => JSON.stringify(decision(v)).slice(0, 90).replaceAll("|", "\\|");
  const lines = [
    "# Authentication production matrix",
    "",
    "Identity Toolkit REST programs (`src/auth-probe/programs.mjs`) run against production Authentication, the official Auth emulator (`auth-matrix.json`) and fireemu. Regenerate with `pnpm -C conformance auth-probe:production` (needs `FIREEMU_PRODUCTION_PROJECT` and `FIREEMU_PRODUCTION_API_KEY`).",
    "",
    "| status | rows | meaning |",
    "| --- | --- | --- |",
    `| parity | ${counts.parity ?? 0} | production, the official emulator and fireemu agree |`,
    `| fireemu-matches-production | ${counts["fireemu-matches-production"] ?? 0} | fireemu follows production where the official emulator differs |`,
    `| fireemu-divergence | ${counts["fireemu-divergence"] ?? 0} | production and the official emulator agree; fireemu differs |`,
    `| emulators-diverge-from-production | ${counts["emulators-diverge-from-production"] ?? 0} | both emulators agree with each other but not with production |`,
    `| three-way-difference | ${counts["three-way-difference"] ?? 0} | all three differ |`,
    "",
    "## Rows that are not parity",
    "",
    "| row | status | production | official emulator | fireemu |",
    "| --- | --- | --- | --- | --- |",
  ];
  for (const p of programs) {
    for (const [id, row] of Object.entries(p.steps)) {
      if (row.status === "parity") continue;
      lines.push(
        `| ${rowKey(p.id, id)} | ${row.status} | ${cell(row.production)} | ${cell(row.emulator)} | ${cell(row.fireemu)} |`,
      );
    }
  }
  await writeFile(PRODUCTION_MD, `${lines.join("\n")}\n`);
  console.log(`recorded ${programs.length} programs against production: ${JSON.stringify(counts)}`);
}

const mode = process.argv[2] ?? "record";
if (mode === "record") {
  await record();
} else if (mode === "check") {
  process.exitCode = await check();
} else if (mode === "record-production") {
  await recordProduction();
} else {
  console.error(`unknown mode ${mode}`);
  process.exitCode = 2;
}
