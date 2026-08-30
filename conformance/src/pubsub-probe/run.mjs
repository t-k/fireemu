// Supervisor for the Pub/Sub probe: differential coverage of the google.pubsub.v1 wire surface
// (topics, subscriptions, publish, pull, ack, filter, ordering, nack redelivery, seek) run
// through the real @google-cloud/pubsub client against both emulators.
//
//   node src/pubsub-probe/run.mjs record   run oracle + fireemu, write pubsub-matrix.json
//   node src/pubsub-probe/run.mjs check     run fireemu, diff against the recorded matrix
//   node src/pubsub-probe/run.mjs both      record, then check
//
// `record` needs Java and the pinned firebase-tools (it starts the official Pub/Sub emulator
// firebase-tools downloads); `check` needs a built fireemu. Both sides run the identical
// session.mjs against the identical programs.mjs, so a difference is a difference in the
// emulator and nowhere else. Classification follows the suite: identical -> `parity`; keyed in
// divergences.json under `pubsub-probe/<program>#<step>` -> `documented-divergence`; otherwise
// `debt`.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import net from "node:net";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { CONFORMANCE_DIR, REPO_ROOT } from "../config.mjs";
import { deepEqual } from "../diff.mjs";

const PROJECT = "demo-pubsub-probe";
// The official side binds the port in pubsub-probe.firebase.json (32460).
const ORACLE_PUBSUB_PORT = 32460;
const TESTD_PUBSUB_PORT = 32465;
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "pubsub-probe");
const MATRIX_JSON = join(CONFORMANCE_DIR, "pubsub-matrix.json");
const MATRIX_MD = join(CONFORMANCE_DIR, "PUBSUB-MATRIX.md");
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
  if (!existsSync(outPath)) {
    throw new Error(`${name}: exited ${code} without writing a run\n${log.join("")}`);
  }
  if (code !== 0) {
    console.error(`${name}: supervisor exited ${code} after the session wrote its run`);
  }
  return log.join("");
}

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
  await assertPortsFree([ORACLE_PUBSUB_PORT]);
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
      "pubsub-probe.firebase.json",
      "--only",
      "pubsub",
      "node src/pubsub-probe/session.mjs",
    ],
    env: {
      PUBSUB_PROBE_OUT: outPath,
      PUBSUB_PROBE_PROJECT: PROJECT,
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
  await assertPortsFree([TESTD_PUBSUB_PORT]);
  await rm(outPath, { force: true });
  await runSupervisor({
    name: "fireemu",
    outPath,
    command: binary,
    args: [
      "exec",
      "--config",
      join(CONFORMANCE_DIR, "pubsub-probe.fireemu.json"),
      "--project",
      PROJECT,
      "--only",
      "pubsub",
      "--pubsub-port",
      String(TESTD_PUBSUB_PORT),
      "--http-port",
      "0",
      "--ui-port",
      "0",
      "--hub-port",
      "0",
      "--",
      "node",
      "src/pubsub-probe/session.mjs",
    ],
    env: {
      PUBSUB_PROBE_OUT: outPath,
      PUBSUB_PROBE_PROJECT: PROJECT,
      // fireemu exec exports PUBSUB_EMULATOR_HOST; the session reads it.
    },
  });
  return JSON.parse(await readFile(outPath, "utf8"));
}

async function annotations() {
  const parsed = JSON.parse(await readFile(join(CONFORMANCE_DIR, "divergences.json"), "utf8"));
  return parsed.divergences;
}

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
      const note = notes[`pubsub-probe/${id}#${stepId}`];
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
    "# Cloud Pub/Sub emulator matrix",
    "",
    "Generated by `pnpm -C conformance run pubsub-probe`. Do not edit by hand.",
    "",
    `Recorded against \`firebase-tools ${matrix.recordedAgainst.firebaseTools}\` (the Cloud`,
    "Pub/Sub emulator it downloads). Every row is one observation run identically through the",
    "real `@google-cloud/pubsub` client against the official emulator and against fireemu:",
    "`parity` rows gate `pubsub-probe:check` against the recorded value, `documented-divergence`",
    "rows gate against the recorded fireemu value, and `debt` rows are open mismatches that gate",
    "nothing until they are ruled on.",
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
      for (const s of p.steps) lines.push(`| \`${p.id}\` | \`${s.id}\` | ${s.status} |`);
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

async function record() {
  await mkdir(RUN_DIR, { recursive: true });
  console.log("oracle: firebase emulators:exec --only pubsub ...");
  const oracle = await probeOracle(join(RUN_DIR, "oracle.json"));
  console.log("fireemu: fireemu exec --only pubsub ...");
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
      pubsubEmulator: "0.8.35",
      note: "the Cloud Pub/Sub emulator firebase-tools pins; see ORACLE.md",
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
    console.error(`\n${failures.length} pubsub-probe failure(s):\n`);
    for (const f of failures) console.error(`- ${f}\n`);
    return 1;
  }
  console.log(`pubsub-probe ok: ${matrix.programs.length} programs, ${gated} gated steps.`);
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
