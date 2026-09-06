// Supervisor for the storage probe: raw-HTTP differential coverage of the Cloud Storage
// emulator surface (both dialects, the Rules request model and the Functions trigger
// payloads).
//
//   node src/storage-probe/run.mjs record   run oracle + fireemu, write storage-matrix.json
//   node src/storage-probe/run.mjs check    run fireemu, diff against the recorded matrix
//   node src/storage-probe/run.mjs both     record, then check
//
// `record` needs Java and the pinned firebase-tools; `check` needs a built fireemu.
// Both sides run the identical `session.mjs` against the identical program list
// (`programs.mjs`), the identical rules (`storage-probe.rules`) and the identical trigger
// codebase (`storage-probe-functions/`), so a difference is a difference in the emulator and
// nowhere else.
//
// Classification follows the conformance suite: a step both sides answered identically is
// `parity`; a step keyed `storage-probe/<program>#<step>` in `divergences.json` is a
// `documented-divergence` gated against the recorded fireemu value; anything else that
// differs is `debt` and gates nothing until someone rules on it.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import net from "node:net";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { CONFORMANCE_DIR, REPO_ROOT } from "../config.mjs";
import { deepEqual } from "../diff.mjs";
import { readValidatedDivergenceRegister } from "../divergence-authority.mjs";

const PROJECT = "demo-storage-probe";
// The official side's ports live in storage-probe.firebase.json (32380 / 32399 / 32301).
const TESTD = { firestore: 32385, http: 32386, storage: 32387, functions: 32388 };
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "storage-probe");
const MATRIX_JSON = join(CONFORMANCE_DIR, "storage-matrix.json");
const MATRIX_MD = join(CONFORMANCE_DIR, "STORAGE-MATRIX.md");
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

async function runSupervisor({ name, command, args, env, outPath, timeoutMs = 900_000 }) {
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
  // What matters is the session's run file: the official CLI can exit non-zero on shutdown
  // hiccups of emulators the probe already finished with (`sides.mjs` accepts runs the same
  // way).
  if (!existsSync(outPath)) {
    throw new Error(`${name}: exited ${code} without writing a run\n${log.join("")}`);
  }
  if (code !== 0) {
    console.error(`${name}: supervisor exited ${code} after the session wrote its run`);
  }
  return log.join("");
}

/**
 * Fails fast when one of a side's fixed ports is already held: a crashed earlier run can
 * leave an emulator behind, and the CLI's own message ("port taken") does not say which
 * process to kill.
 */
async function assertPortsFree(ports) {
  for (const port of ports) {
    const held = await new Promise((resolve) => {
      const socket = net.connect({ host: "127.0.0.1", port }, () => {
        socket.destroy();
        resolve(true);
      });
      socket.on("error", () => resolve(false));
    });
    if (held) {
      throw new Error(
        `port ${port} is already in use; a previous run left an emulator behind ` +
          `(lsof -nP -iTCP:${port} -sTCP:LISTEN names it)`,
      );
    }
  }
}

async function probeOracle(outPath) {
  await assertPortsFree([32380, 32399, 32301]);
  await rm(outPath, { force: true });
  await runSupervisor({
    name: "oracle",
    outPath,
    command: join(CONFORMANCE_DIR, "node_modules/.bin/firebase"),
    args: [
      "emulators:exec",
      "--project",
      PROJECT,
      "--config",
      "storage-probe.firebase.json",
      "--only",
      "firestore,storage,functions",
      `sh -c 'STORAGE_PROBE_STORAGE_HOST=$FIREBASE_STORAGE_EMULATOR_HOST STORAGE_PROBE_FIRESTORE_HOST=$FIRESTORE_EMULATOR_HOST node src/storage-probe/session.mjs'`,
    ],
    env: {
      STORAGE_PROBE_OUT: outPath,
      STORAGE_PROBE_PROJECT: PROJECT,
      FIREBASE_CLI_EXPERIMENTS: "",
      GOOGLE_APPLICATION_CREDENTIALS: "",
    },
  });
  return JSON.parse(await readFile(outPath, "utf8"));
}

async function probeFireemu(outPath) {
  const binary =
    process.env.FIREEMU_BIN ??
    ["target/release/fireemu", "target/debug/fireemu"]
      .map((p) => join(REPO_ROOT, p))
      .find((p) => existsSync(p));
  if (!binary) throw new Error("fireemu is not built: run `cargo build -p fireemu`");
  await assertPortsFree(Object.values(TESTD));
  await rm(outPath, { force: true });
  await runSupervisor({
    name: "fireemu",
    outPath,
    command: binary,
    args: [
      "exec",
      "--config",
      join(CONFORMANCE_DIR, "storage-probe.fireemu.json"),
      "--project",
      PROJECT,
      "--only",
      "firestore,storage,functions",
      "--firestore-port",
      String(TESTD.firestore),
      "--http-port",
      String(TESTD.http),
      "--storage-port",
      String(TESTD.storage),
      "--functions-port",
      String(TESTD.functions),
      "--functions",
      join(CONFORMANCE_DIR, "storage-probe-functions"),
      "--ui-port",
      "0",
      "--hub-port",
      "0",
      "--",
      "sh",
      "-c",
      "STORAGE_PROBE_STORAGE_HOST=$FIREBASE_STORAGE_EMULATOR_HOST STORAGE_PROBE_FIRESTORE_HOST=$FIRESTORE_EMULATOR_HOST node src/storage-probe/session.mjs",
    ],
    env: {
      STORAGE_PROBE_OUT: outPath,
      STORAGE_PROBE_PROJECT: PROJECT,
    },
  });
  return JSON.parse(await readFile(outPath, "utf8"));
}

async function annotations() {
  return readValidatedDivergenceRegister().divergences;
}

/** Folds the two runs into matrix rows, program by program, step by step. */
function classify(oracle, fireemu, notes) {
  const ABSENT = { absent: "this side recorded no such step" };
  const programs = [];
  const ids = Object.keys(oracle.programs);
  for (const id of Object.keys(fireemu.programs)) if (!ids.includes(id)) ids.push(id);
  for (const id of ids) {
    const o = oracle.programs[id];
    const t = fireemu.programs[id];
    const stepIds = [...(o?.order ?? [])];
    for (const s of t?.order ?? []) if (!stepIds.includes(s)) stepIds.push(s);
    const steps = [];
    for (const stepId of stepIds) {
      const oracleValue = o?.steps?.[stepId] ?? ABSENT;
      const fireemuValue = t?.steps?.[stepId] ?? ABSENT;
      if (deepEqual(oracleValue, fireemuValue)) {
        steps.push({ id: stepId, status: "parity", value: oracleValue });
        continue;
      }
      const note = notes[`storage-probe/${id}#${stepId}`];
      if (note) {
        steps.push({
          id: stepId,
          status: "documented-divergence",
          oracle: oracleValue,
          fireemu: fireemuValue,
          documents: note.documents,
          reason: note.reason,
        });
        continue;
      }
      steps.push({ id: stepId, status: "debt", oracle: oracleValue, fireemu: fireemuValue });
    }
    programs.push({
      id,
      area: o?.area ?? t?.area,
      faults: [o?.fault, t?.fault].filter(Boolean),
      steps,
    });
  }
  return programs;
}

function summarize(programs) {
  const totals = { parity: 0, "documented-divergence": 0, debt: 0 };
  for (const p of programs) for (const s of p.steps) totals[s.status] += 1;
  return totals;
}

function renderMarkdown(matrix) {
  const lines = [
    "# Cloud Storage emulator matrix",
    "",
    "Generated by `pnpm -C conformance run storage-probe`. Do not edit by hand.",
    "",
    `Recorded against \`firebase-tools ${matrix.recordedAgainst.firebaseTools}\`. Every row is`,
    "one raw HTTP exchange (or one batch of Functions trigger deliveries) run identically",
    "against the official Cloud Storage emulator and against fireemu:",
    "`parity` rows gate `pnpm -C conformance run storage-probe:check` against the recorded",
    "value, `documented-divergence` rows gate against the recorded fireemu value and name the",
    "text that publishes the difference, and `debt` rows are open mismatches that gate",
    "nothing until they are ruled on (they fail no claim while excluded by name).",
    "",
  ];
  const areas = new Map();
  for (const p of matrix.programs) {
    if (!areas.has(p.area)) areas.set(p.area, []);
    areas.get(p.area).push(p);
  }
  for (const [area, programs] of areas) {
    const totals = summarize(programs);
    lines.push(
      `## ${area}`,
      "",
      Object.entries(totals)
        .filter(([, n]) => n > 0)
        .map(([k, n]) => `${k}: ${n}`)
        .join(" &middot; "),
      "",
      "| program | step | status |",
      "| --- | --- | --- |",
    );
    for (const p of programs) {
      for (const s of p.steps) {
        lines.push(`| \`${p.id}\` | \`${s.id}\` | ${s.status} |`);
      }
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

async function record() {
  await mkdir(RUN_DIR, { recursive: true });
  console.log("oracle: firebase emulators:exec ...");
  const oracle = await probeOracle(join(RUN_DIR, "oracle.json"));
  console.log("fireemu: fireemu exec ...");
  const fireemu = await probeFireemu(join(RUN_DIR, "fireemu.json"));
  const notes = await annotations();
  const programs = classify(oracle, fireemu, notes);
  const provenance = JSON.parse(
    await readFile(join(CONFORMANCE_DIR, "package.json"), "utf8"),
  ).dependencies;
  const matrix = {
    version: 1,
    recordedAgainst: {
      firebaseTools: provenance["firebase-tools"],
      note: "the Cloud Storage emulator that firebase-tools pins; see ORACLE.md",
    },
    project: PROJECT,
    summary: summarize(programs),
    programs,
  };
  await writeFile(MATRIX_JSON, `${JSON.stringify(matrix, null, 2)}\n`);
  await writeFile(MATRIX_MD, renderMarkdown(matrix));
  const faults = matrix.programs.flatMap((p) => p.faults);
  console.log(
    `recorded ${matrix.programs.length} programs: ` +
      Object.entries(matrix.summary)
        .map(([k, n]) => `${k}=${n}`)
        .join(" ") +
      (faults.length ? `\nFAULTS:\n${faults.join("\n")}` : ""),
  );
  return faults.length === 0 ? 0 : 1;
}

async function check() {
  const matrix = JSON.parse(await readFile(MATRIX_JSON, "utf8"));
  const authorities = readValidatedDivergenceRegister().divergences;
  await mkdir(RUN_DIR, { recursive: true });
  const run = await probeFireemu(join(RUN_DIR, "check.json"));
  const failures = [];
  const warnings = [];
  let gated = 0;
  for (const program of matrix.programs) {
    const mine = run.programs[program.id];
    if (!mine) {
      failures.push(`${program.id}: the matrix has this program but the run does not`);
      continue;
    }
    if (mine.fault) failures.push(`${program.id}: faulted during the run: ${mine.fault}`);
    const seen = new Set();
    for (const step of program.steps) {
      seen.add(step.id);
      const value = mine.steps?.[step.id] ?? { absent: "this side recorded no such step" };
      if (step.status === "parity") {
        gated += 1;
        if (!deepEqual(step.value, value)) {
          failures.push(
            `${program.id}#${step.id}: parity drift\n  matrix: ${JSON.stringify(step.value)}\n  run:    ${JSON.stringify(value)}`,
          );
        }
      } else if (step.status === "documented-divergence") {
        if (!authorities[`storage-probe/${program.id}#${step.id}`]) {
          failures.push(`${program.id}#${step.id}: documented divergence has no authority`);
          continue;
        }
        gated += 1;
        if (!deepEqual(step.fireemu, value)) {
          failures.push(
            `${program.id}#${step.id}: documented divergence drifted from its recorded fireemu value\n` +
              `  documents: ${step.documents}\n  matrix: ${JSON.stringify(step.fireemu)}\n  run:    ${JSON.stringify(value)}`,
          );
        }
      } else if (!deepEqual(step.fireemu, value)) {
        warnings.push(`${program.id}#${step.id}: known debt row changed since it was recorded`);
      }
    }
    for (const stepId of mine.order ?? []) {
      if (!seen.has(stepId)) {
        failures.push(
          `${program.id}#${stepId}: the run produced a step the matrix does not describe`,
        );
      }
    }
  }
  if (warnings.length) {
    console.log(`${warnings.length} known-debt row(s) changed since they were recorded:`);
    for (const w of warnings) console.log(`  - ${w}`);
  }
  if (failures.length) {
    console.error(`\n${failures.length} storage-probe failure(s):\n`);
    for (const f of failures) console.error(`- ${f}\n`);
    return 1;
  }
  console.log(`storage-probe ok: ${matrix.programs.length} programs, ${gated} gated steps.`);
  return 0;
}

const mode = process.argv[2] ?? "record";
if (mode === "record") {
  process.exitCode = await record();
} else if (mode === "check") {
  process.exitCode = await check();
} else if (mode === "both") {
  const first = await record();
  process.exitCode = first === 0 ? await check() : first;
} else {
  console.error(`unknown mode ${mode}; expected record, check or both`);
  process.exitCode = 2;
}
