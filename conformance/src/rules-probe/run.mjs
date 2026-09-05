// Supervisor for the Security Rules language matrix (RULES-PARITY-01).
//
//   node src/rules-probe/run.mjs record   run the oracle, write rules-matrix.json + .md
//   node src/rules-probe/run.mjs check    run fireemu, diff against the recorded matrix
//   node src/rules-probe/run.mjs both     record, then check
//
// `record` needs Java and the pinned firebase-tools; `check` needs a built fireemu.
// Both sides run the identical `session.mjs` against the identical claim list, so a
// difference is a difference in the runtime and nowhere else.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { CONFORMANCE_DIR, REPO_ROOT } from "../config.mjs";
import { readValidatedDivergenceRegister } from "../divergence-authority.mjs";
import { CLAIMS, AREA_NAMES } from "./matrix.mjs";
import { PROGRAMS } from "./programs.mjs";
import { generated, render, shrink } from "./generate.mjs";

const PROJECT = "demo-rules-matrix";
const TESTD_FIRESTORE_PORT = 32281;
const TESTD_HTTP_PORT = 32282;
const SEED = 20260831;
const GENERATED = Number(process.env.RULES_PROBE_GENERATED ?? 260);
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "rules-probe");
const MATRIX_JSON = join(CONFORMANCE_DIR, "rules-matrix.json");
const PROGRAMS_JSON = join(CONFORMANCE_DIR, "rules-programs.json");
const MATRIX_MD = join(CONFORMANCE_DIR, "RULES-MATRIX.md");
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

/** Runs one probe session against the official Firestore emulator. */
async function probeOracle(inPath, outPath, script = "src/rules-probe/session.mjs") {
  await runSupervisor({
    name: "oracle",
    command: join(CONFORMANCE_DIR, "node_modules/.bin/firebase"),
    args: [
      "emulators:exec",
      "--project",
      PROJECT,
      "--config",
      "rules-probe.firebase.json",
      "--only",
      "firestore",
      `sh -c 'RULES_PROBE_FIRESTORE_HOST=$FIRESTORE_EMULATOR_HOST node ${script}'`,
    ],
    env: {
      RULES_PROBE_IN: inPath,
      RULES_PROBE_OUT: outPath,
      RULES_PROBE_PROJECT: PROJECT,
      FIREBASE_CLI_EXPERIMENTS: "",
      GOOGLE_APPLICATION_CREDENTIALS: "",
    },
  });
  return JSON.parse(await readFile(outPath, "utf8"));
}

/** Runs one probe session against fireemu. */
async function probeFireemu(inPath, outPath, script = "src/rules-probe/session.mjs") {
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
      join(CONFORMANCE_DIR, "rules-probe.fireemu.json"),
      "--project",
      PROJECT,
      "--only",
      "firestore",
      "--firestore-port",
      String(TESTD_FIRESTORE_PORT),
      "--http-port",
      String(TESTD_HTTP_PORT),
      "--ui-port",
      "0",
      "--hub-port",
      "0",
      "--",
      "node",
      script,
    ],
    env: {
      RULES_PROBE_IN: inPath,
      RULES_PROBE_OUT: outPath,
      RULES_PROBE_PROJECT: PROJECT,
      RULES_PROBE_FIRESTORE_HOST: `127.0.0.1:${TESTD_FIRESTORE_PORT}`,
    },
  });
  return JSON.parse(await readFile(outPath, "utf8"));
}

const register = readValidatedDivergenceRegister();
const DIVERGENCES = Object.fromEntries(
  Object.entries(register.rulesMatrixDivergences).map(([key, entry]) => [
    key,
    { fireemu: entry.fireemu, reason: entry.reason },
  ]),
);

const claimList = () => [...CLAIMS, ...generated(SEED, GENERATED)];

async function writeClaims(claims, path) {
  await mkdir(RUN_DIR, { recursive: true });
  await writeFile(path, JSON.stringify(claims.map(({ id, claim }) => ({ id, claim }))));
  return path;
}

async function record() {
  const claims = claimList();
  const inPath = await writeClaims(claims, join(RUN_DIR, "claims.json"));
  const result = await probeOracle(inPath, join(RUN_DIR, "oracle.json"));
  const provenance = JSON.parse(
    await readFile(join(CONFORMANCE_DIR, "package.json"), "utf8"),
  ).dependencies;
  const matrix = {
    // Bumped by hand when the shape of this file changes.
    version: 1,
    recordedAgainst: {
      firebaseTools: provenance["firebase-tools"],
      note: "the Firestore emulator jar and its Rules runtime that firebase-tools pins; see ORACLE.md",
    },
    seed: SEED,
    generated: GENERATED,
    claims: claims.map((c) => ({
      id: c.id,
      area: c.area,
      claim: c.claim,
      oracle: result.claims[c.id] ?? "not-run",
      ...(DIVERGENCES[c.id] ? { divergence: DIVERGENCES[c.id] } : {}),
    })),
    diagnostics: result.diagnostics,
  };
  await writeFile(MATRIX_JSON, `${JSON.stringify(matrix, null, 2)}\n`);
  await writeFile(MATRIX_MD, renderMarkdown(matrix));
  summarise(matrix);
  return matrix;
}

function summarise(matrix) {
  const counts = new Map();
  for (const c of matrix.claims) counts.set(c.oracle, (counts.get(c.oracle) ?? 0) + 1);
  const parts = [...counts].toSorted().map(([k, v]) => `${k}=${v}`);
  console.log(`recorded ${matrix.claims.length} claims: ${parts.join(" ")}`);
}

function renderMarkdown(matrix) {
  const byArea = new Map();
  for (const c of matrix.claims) {
    if (!byArea.has(c.area)) byArea.set(c.area, []);
    byArea.get(c.area).push(c);
  }
  const order = [...AREA_NAMES, "generated"].filter((a) => byArea.has(a));
  const lines = [
    "# Security Rules language matrix",
    "",
    "Generated by `pnpm -C conformance run matrix`. Do not edit by hand.",
    "",
    `Recorded against \`firebase-tools ${matrix.recordedAgainst.firebaseTools}\`; ` +
      `${matrix.generated} of the claims are generated from seed \`${matrix.seed}\`.`,
    "",
    "Every row is one boolean Rules expression and the verdict the official runtime gave it:",
    "`true`, `false`, `error` (it raised or produced a non-boolean) or `compile-error`.",
    "`pnpm -C conformance run matrix:check` replays the same claims against fireemu and fails",
    "on any row that disagrees.",
    "",
  ];
  for (const area of order) {
    const rows = byArea.get(area);
    const counts = new Map();
    for (const r of rows) counts.set(r.oracle, (counts.get(r.oracle) ?? 0) + 1);
    lines.push(
      `## ${area} (${rows.length})`,
      "",
      [...counts]
        .toSorted()
        .map(([k, v]) => `${k}: ${v}`)
        .join(" &middot; "),
      "",
    );
    if (area === "generated") continue;
    lines.push("| claim | oracle |", "| --- | --- |");
    for (const r of rows) lines.push(`| \`${r.claim.replaceAll("|", "\\|")}\` | ${r.oracle} |`);
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

async function check() {
  const matrix = JSON.parse(await readFile(MATRIX_JSON, "utf8"));
  const claims = claimList();
  const inPath = await writeClaims(claims, join(RUN_DIR, "claims.json"));
  const result = await probeFireemu(inPath, join(RUN_DIR, "fireemu.json"));
  const byId = new Map(claims.map((c) => [c.id, c]));
  const mismatches = [];
  let diverged = 0;
  for (const row of matrix.claims) {
    const got = result.claims[row.id] ?? "not-run";
    const divergence = DIVERGENCES[row.id];
    if (row.divergence && !divergence) {
      mismatches.push({
        ...row,
        expected: "verified authority",
        fireemu: got,
        node: byId.get(row.id)?.node,
      });
      continue;
    }
    const expected = divergence ? divergence.fireemu : row.oracle;
    if (got === expected) {
      if (divergence) diverged += 1;
      continue;
    }
    mismatches.push({ ...row, expected, fireemu: got, node: byId.get(row.id)?.node });
  }
  if (mismatches.length === 0) {
    console.log(
      `ok: ${matrix.claims.length} claims agree with the recorded oracle ` +
        `(${diverged} documented divergence${diverged === 1 ? "" : "s"})`,
    );
    return 0;
  }
  const byArea = new Map();
  for (const m of mismatches) byArea.set(m.area, (byArea.get(m.area) ?? 0) + 1);
  console.error(`${mismatches.length} of ${matrix.claims.length} claims disagree:`);
  for (const [area, n] of [...byArea].toSorted()) console.error(`  ${area}: ${n}`);
  for (const m of mismatches) {
    console.error(`  ${m.id} [${m.area}] expected=${m.expected} fireemu=${m.fireemu}  ${m.claim}`);
  }
  await writeFile(join(RUN_DIR, "mismatches.json"), `${JSON.stringify(mismatches, null, 2)}\n`);
  await shrinkMismatches(mismatches);
  return 1;
}

/**
 * Reduces every generated mismatch to the smallest expression that still disagrees, by
 * replaying candidate shrinks through both sides in one pass each.
 */
async function shrinkMismatches(mismatches) {
  const targets = mismatches.filter((m) => m.node);
  if (targets.length === 0) return;
  const candidates = [];
  for (const m of targets) {
    for (const [i, node] of shrink(m.node).slice(0, 24).entries()) {
      candidates.push({ id: `${m.id}-s${i}`, of: m.id, claim: render(node) });
    }
  }
  if (candidates.length === 0) return;
  const inPath = await writeClaims(candidates, join(RUN_DIR, "shrink-claims.json"));
  const oracle = await probeOracle(inPath, join(RUN_DIR, "shrink-oracle.json"));
  const fireemu = await probeFireemu(inPath, join(RUN_DIR, "shrink-fireemu.json"));
  const smallest = new Map();
  for (const c of candidates) {
    const o = oracle.claims[c.id];
    const f = fireemu.claims[c.id];
    if (o === f) continue;
    const prev = smallest.get(c.of);
    if (!prev || c.claim.length < prev.claim.length) {
      smallest.set(c.of, { claim: c.claim, oracle: o, fireemu: f });
    }
  }
  console.error("\nshrunk:");
  for (const m of targets) {
    const s = smallest.get(m.id);
    console.error(
      s
        ? `  ${m.id}: ${s.claim}  oracle=${s.oracle} fireemu=${s.fireemu}`
        : `  ${m.id}: already minimal  ${m.claim}`,
    );
  }
  await writeFile(
    join(RUN_DIR, "shrunk.json"),
    `${JSON.stringify(
      [...smallest].map(([of, s]) => ({ of, ...s })),
      null,
      2,
    )}\n`,
  );
}

/** Programs are recorded and checked as one unit; `rules-programs.json` holds the oracle. */
async function recordPrograms() {
  await mkdir(RUN_DIR, { recursive: true });
  const inPath = join(RUN_DIR, "programs.json");
  await writeFile(inPath, JSON.stringify(PROGRAMS));
  const oracle = await probeOracle(
    inPath,
    join(RUN_DIR, "programs-oracle.json"),
    "src/rules-probe/session-programs.mjs",
  );
  const provenance = JSON.parse(
    await readFile(join(CONFORMANCE_DIR, "package.json"), "utf8"),
  ).dependencies;
  await writeFile(
    PROGRAMS_JSON,
    `${JSON.stringify(
      {
        version: 1,
        recordedAgainst: { firebaseTools: provenance["firebase-tools"] },
        programs: PROGRAMS.map((p) => ({
          id: p.id,
          area: p.area,
          oracle: oracle[p.id] ?? { missing: true },
          ...(PROGRAM_DIVERGENCES[p.id] ? { divergence: PROGRAM_DIVERGENCES[p.id] } : {}),
        })),
      },
      null,
      2,
    )}\n`,
  );
  console.log(`recorded ${PROGRAMS.length} programs`);
}

/**
 * Programs where fireemu deliberately answers something else. `fireemu` holds the answer it
 * is pinned to, exactly as the claim divergences are.
 */
const PROGRAM_DIVERGENCES = {};

async function checkPrograms() {
  const recorded = JSON.parse(await readFile(PROGRAMS_JSON, "utf8"));
  await mkdir(RUN_DIR, { recursive: true });
  const inPath = join(RUN_DIR, "programs.json");
  await writeFile(inPath, JSON.stringify(PROGRAMS));
  const got = await probeFireemu(
    inPath,
    join(RUN_DIR, "programs-fireemu.json"),
    "src/rules-probe/session-programs.mjs",
  );
  let failures = 0;
  let messageDrift = 0;
  for (const row of recorded.programs) {
    const expected = row.divergence ? row.divergence.fireemu : row.oracle;
    const actual = got[row.id] ?? { missing: true };
    if (JSON.stringify(decision(expected)) !== JSON.stringify(decision(actual))) {
      failures += 1;
      console.error(`\n${row.id} [${row.area}] disagrees`);
      console.error(`  expected ${JSON.stringify(decision(expected))}`);
      console.error(`  fireemu  ${JSON.stringify(decision(actual))}`);
      continue;
    }
    for (const [id, step] of Object.entries(expected.steps ?? {})) {
      const mine = actual.steps?.[id];
      if (step.message !== undefined && mine?.message !== step.message) messageDrift += 1;
    }
  }
  if (failures === 0) {
    console.log(
      `ok: ${recorded.programs.length} programs agree with the recorded oracle ` +
        `(${messageDrift} denial messages differ; see the divergence note in README)`,
    );
    return 0;
  }
  console.error(`\n${failures} of ${recorded.programs.length} programs disagree`);
  return 1;
}

/**
 * What a program probe gates on: the status, the canonical error code and the shape of a
 * success, for every step, plus whether the ruleset compiled at all.
 *
 * The *text* of a denial is deliberately not gated. The official emulator answers
 * `PERMISSION_DENIED` with a per-`allow` trace of its own evaluation
 * (`"\nevaluation error at L5:22 for 'get' @ L5, false for 'get' @ L5"`), which is an
 * internal diagnostic rather than an API contract; fireemu publishes the same information
 * through `GET /v1/sessions/{s}/rules/requests` on the control API instead, and names the
 * limit it hit in its own message. Drift in those messages is reported, never a failure.
 */
function decision(result) {
  if (result?.missing) return { missing: true };
  if (result?.compileError !== undefined) return { compileError: true };
  return {
    steps: Object.fromEntries(
      Object.entries(result?.steps ?? {}).map(([id, step]) => [
        id,
        { status: step.status, code: step.code, shape: step.shape },
      ]),
    ),
  };
}

const mode = process.argv[2] ?? "record";
if (mode === "record") {
  await record();
} else if (mode === "check") {
  process.exitCode = await check();
} else if (mode === "both") {
  await record();
  process.exitCode = await check();
} else if (mode === "record-programs") {
  await recordPrograms();
} else if (mode === "check-programs") {
  process.exitCode = await checkPrograms();
} else {
  console.error(
    `unknown mode ${mode}; expected record, check, both, record-programs or check-programs`,
  );
  process.exitCode = 2;
}
