// Supervisor for the Firestore semantics probe (FS-PARITY-01 / FS-PARITY-02 / FS-PARITY-03).
//
//   node src/firestore-probe/run.mjs record   run the oracle, write firestore-matrix.json + .md
//   node src/firestore-probe/run.mjs check    run fireemu, diff against the recorded matrix
//   node src/firestore-probe/run.mjs both     record, then check
//
// `record` needs Java and the pinned firebase-tools; `check` needs a built fireemu. Both
// sides run the identical `session.mjs` over the identical program list through the REST
// API, so a difference is a difference in the runtime and nowhere else.

import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { CONFORMANCE_DIR } from "../config.mjs";
import {
  classifyProductionCase,
  collectEvidence,
  digestFile,
  evidenceIdentity,
  resolveFireemuBinary,
  validateEvidenceJoin,
  validateLiveEvidence,
  validateRecordedExpectation,
} from "../evidence.mjs";
import { PROGRAMS } from "./programs.mjs";
import { DIVERGENCES } from "./divergences.mjs";

const PROJECT = "demo-firestore-probe";
const TESTD_FIRESTORE_PORT = 32291;
const TESTD_HTTP_PORT = 32292;
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "firestore-probe");
const MATRIX_JSON = join(CONFORMANCE_DIR, "firestore-matrix.json");
const MATRIX_MD = join(CONFORMANCE_DIR, "FIRESTORE-MATRIX.md");
const PRODUCTION_JSON = join(CONFORMANCE_DIR, "firestore-production-matrix.json");
const PRODUCTION_MD = join(CONFORMANCE_DIR, "FIRESTORE-PRODUCTION-MATRIX.md");
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

const SESSION = "src/firestore-probe/session.mjs";

/** Runs the programs against the official Firestore emulator. */
async function probeOracle(inPath, outPath) {
  await runSupervisor({
    name: "oracle",
    command: join(CONFORMANCE_DIR, "node_modules/.bin/firebase"),
    args: [
      "emulators:exec",
      "--project",
      PROJECT,
      "--config",
      "firestore-probe.firebase.json",
      "--only",
      "firestore",
      `sh -c 'FIRESTORE_PROBE_HOST=$FIRESTORE_EMULATOR_HOST node ${SESSION}'`,
    ],
    env: {
      FIRESTORE_PROBE_IN: inPath,
      FIRESTORE_PROBE_OUT: outPath,
      FIRESTORE_PROBE_PROJECT: PROJECT,
      FIREBASE_CLI_EXPERIMENTS: "",
      GOOGLE_APPLICATION_CREDENTIALS: "",
    },
  });
  return JSON.parse(await readFile(outPath, "utf8"));
}

/** Runs the programs against fireemu. */
async function probeFireemu(inPath, outPath) {
  const binary = resolveFireemuBinary();
  await runSupervisor({
    name: "fireemu",
    command: binary,
    args: [
      "exec",
      "--config",
      join(CONFORMANCE_DIR, "firestore-probe.fireemu.json"),
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
      SESSION,
    ],
    env: {
      FIRESTORE_PROBE_IN: inPath,
      FIRESTORE_PROBE_OUT: outPath,
      FIRESTORE_PROBE_PROJECT: PROJECT,
      FIRESTORE_PROBE_HOST: `127.0.0.1:${TESTD_FIRESTORE_PORT}`,
    },
  });
  return JSON.parse(await readFile(outPath, "utf8"));
}

async function writePrograms() {
  await mkdir(RUN_DIR, { recursive: true });
  const inPath = join(RUN_DIR, "programs.json");
  await writeFile(inPath, JSON.stringify(PROGRAMS));
  return inPath;
}

/**
 * What a row gates on. A success gates its status, code and normalized body: the documents,
 * their fields, the result order, the write results. An error gates its status and canonical
 * code; the message is recorded and reported when it drifts, never gated, the official
 * emulator's messages being diagnostics of its own implementation rather than an API
 * contract (the scenario corpus records the ones an SDK surfaces verbatim).
 */
function decision(step) {
  if (!step || step.missing === true) return { missing: true };
  if (step.code === "OK") return { status: step.status, code: step.code, body: step.body };
  return { status: step.status, code: step.code };
}

/** The first path at which two values differ, with both sides rendered, for the report. */
function firstDifference(a, b, path = "$") {
  const render = (v) => JSON.stringify(v)?.slice(0, 200) ?? "undefined";
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return [`${path}.length`, String(a.length), String(b.length)];
    for (const [i, item] of a.entries()) {
      const found = firstDifference(item, b[i], `${path}[${i}]`);
      if (found) return found;
    }
    return null;
  }
  if (
    a &&
    b &&
    typeof a === "object" &&
    typeof b === "object" &&
    !Array.isArray(a) &&
    !Array.isArray(b)
  ) {
    for (const key of new Set([...Object.keys(a), ...Object.keys(b)]).values()) {
      const found = firstDifference(a[key], b[key], `${path}.${key}`);
      if (found) return found;
    }
    return null;
  }
  return canonical(a) === canonical(b) ? null : [path, render(a), render(b)];
}

/** JSON with object keys sorted at every level: the two sides order fields differently. */
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

/**
 * Joins the production observation with the official matrix and the live fireemu observation.
 * A missing live step remains missing so an incomplete binary run cannot be promoted by a
 * stored divergence or emulator value.
 */
export function buildProductionPrograms({
  production,
  fireemu,
  matrix,
  programDefinitions = PROGRAMS,
  evidenceValid,
}) {
  const recordedRows = new Map(
    matrix.programs.flatMap((p) =>
      Object.entries(p.steps).map(([id, row]) => [rowKey(p.id, id), row]),
    ),
  );
  const counts = {};
  const programs = programDefinitions.map((p) => {
    const result = production[p.id] ?? {};
    const liveProgram = fireemu?.[p.id] ?? {};
    return {
      id: p.id,
      area: p.area,
      ...(result.seedError !== undefined ? { seedError: result.seedError } : {}),
      steps: Object.fromEntries(
        p.steps.map((s) => {
          const recorded = recordedRows.get(rowKey(p.id, s.id));
          const emulator = recorded?.oracle ?? { missing: true };
          const actual = liveProgram.steps?.[s.id] ?? { missing: true };
          const prod = result.steps?.[s.id] ?? { missing: true };
          const needsIndex =
            prod.code === "FAILED_PRECONDITION" &&
            /requires an? (\S+ )?index/.test(prod.message ?? "");
          const status = classifyProductionCase({
            production: decision(prod),
            emulator: decision(emulator),
            fireemu: decision(actual),
            evidenceValid,
            localOnly: p.area === "emulator",
            needsIndex,
          });
          counts[status] = (counts[status] ?? 0) + 1;
          return [s.id, { production: prod, emulator, fireemu: actual, status }];
        }),
      ),
    };
  });
  return { counts, programs };
}

async function record() {
  const inPath = await writePrograms();
  const oracle = await probeOracle(inPath, join(RUN_DIR, "oracle.json"));
  const provenance = JSON.parse(
    await readFile(join(CONFORMANCE_DIR, "package.json"), "utf8"),
  ).dependencies;
  const oracleEvidence = await collectEvidence({
    side: "official-emulator",
    mode: "live",
    profile: "official-emulator",
    configPath: join(CONFORMANCE_DIR, "firestore-probe.firebase.json"),
    rulesPath: join(CONFORMANCE_DIR, "firestore-probe.rules"),
    corpusPath: inPath,
    indexPaths: [join(CONFORMANCE_DIR, "firestore.indexes.json")],
    database: { target: "official Firestore emulator" },
  });
  const programs = PROGRAMS.map((p) => {
    const recorded = oracle[p.id] ?? { missing: true };
    return {
      id: p.id,
      area: p.area,
      ...(recorded.seedError !== undefined ? { seedError: recorded.seedError } : {}),
      steps: Object.fromEntries(
        p.steps.map((s) => {
          const key = rowKey(p.id, s.id);
          return [
            s.id,
            {
              oracle: recorded.steps?.[s.id] ?? { missing: true },
              ...(DIVERGENCES[key] ? { divergence: DIVERGENCES[key] } : {}),
            },
          ];
        }),
      ),
    };
  });
  const matrix = {
    // Bumped by hand when the shape of this file changes.
    version: 1,
    recordedAgainst: {
      firebaseTools: provenance["firebase-tools"],
      note: "the Firestore emulator jar that firebase-tools pins; see ORACLE.md",
      evidenceSchema: 1,
      evidence: { identity: evidenceIdentity(oracleEvidence) },
    },
    programs,
  };
  await writeFile(MATRIX_JSON, `${JSON.stringify(matrix, null, 2)}\n`);
  await writeFile(MATRIX_MD, renderMarkdown(matrix));
  const total = programs.reduce((n, p) => n + Object.keys(p.steps).length, 0);
  console.log(`recorded ${programs.length} programs, ${total} steps`);
  for (const key of Object.keys(DIVERGENCES)) {
    const [programId, stepId] = key.split("#");
    if (!programs.find((p) => p.id === programId)?.steps[stepId]) {
      console.error(`divergence ${key} names a row that does not exist`);
      process.exitCode = 1;
    }
  }
}

function renderMarkdown(matrix) {
  const lines = [
    "# Firestore semantics matrix",
    "",
    "Generated by `pnpm -C conformance run firestore`. Do not edit by hand.",
    "",
    `Recorded against \`firebase-tools ${matrix.recordedAgainst.firebaseTools}\`.`,
    "",
    "Every row is one REST request of `src/firestore-probe/programs.mjs` and what the official",
    "Firestore emulator answered: the status, the canonical code and, for a success, a digest",
    "of the body. `pnpm -C conformance run firestore:check` replays the same programs against",
    "fireemu and fails on any row that disagrees, except where a divergence pins fireemu's",
    "own answer (marked below).",
    "",
  ];
  for (const program of matrix.programs) {
    lines.push(`## ${program.id} (${Object.keys(program.steps).length})`, "");
    if (program.seedError) lines.push(`seed error: ${program.seedError}`, "");
    lines.push("| step | status | code | oracle |", "| --- | --- | --- | --- |");
    for (const [id, row] of Object.entries(program.steps)) {
      const o = row.oracle;
      const summary = o.missing
        ? "missing"
        : o.code === "OK"
          ? digest(o.body)
          : `\`${(o.message ?? "").replaceAll("|", "\\|").replaceAll("\n", " ").slice(0, 120)}\``;
      const mark = row.divergence ? " (divergence)" : "";
      lines.push(`| ${id}${mark} | ${o.status ?? ""} | ${o.code ?? ""} | ${summary} |`);
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

/** A one-line description of a success body for the Markdown rendering. */
function digest(body) {
  if (Array.isArray(body)) {
    const documents = body
      .filter((e) => e?.document?.name)
      .map((e) => e.document.name.split("/documents/")[1]);
    const results = body.filter((e) => e?.result).length;
    if (documents.length > 0) return `${documents.length} documents: ${documents.join(", ")}`;
    if (results > 0) return `${results} aggregation results`;
    const found = body.filter((e) => e?.found).length;
    const missing = body.filter((e) => e?.missing).length;
    if (found + missing > 0) return `found ${found}, missing ${missing}`;
    return `${body.length} entries`;
  }
  if (body && typeof body === "object") {
    if (body.name) return "document";
    if (body.writeResults) return `commit(${body.writeResults.length} results)`;
    if (body.documents) return `${body.documents.length} documents`;
    return `object(${Object.keys(body).toSorted().join(",")})`;
  }
  return String(body);
}

async function check() {
  const matrix = JSON.parse(await readFile(MATRIX_JSON, "utf8"));
  const inPath = await writePrograms();
  const got = await probeFireemu(inPath, join(RUN_DIR, "fireemu.json"));
  let rows = 0;
  let failures = 0;
  let diverged = 0;
  let messageDrift = 0;
  const drift = [];
  for (const program of matrix.programs) {
    const mine = got[program.id] ?? { missing: true };
    if (mine.seedError) {
      failures += 1;
      console.error(`\n${program.id}: fireemu could not seed: ${mine.seedError}`);
      continue;
    }
    for (const [stepId, recorded] of Object.entries(program.steps)) {
      rows += 1;
      // The register in `divergences.mjs` is the source of truth; the copy stamped into
      // the matrix at record time is for the reader of the JSON.
      const row = { ...recorded, divergence: DIVERGENCES[rowKey(program.id, stepId)] };
      const expected = row.divergence ? row.divergence.fireemu : row.oracle;
      const actual = mine.steps?.[stepId];
      // A divergence may pin a success by the digest of its body (the document names it
      // returns) rather than by the whole body, which keeps the register readable while
      // still pinning the result set.
      const pinnedByDigest = row.divergence && expected?.bodyDigest !== undefined;
      const want = pinnedByDigest
        ? canonical({
            status: expected.status,
            code: expected.code,
            bodyDigest: expected.bodyDigest,
          })
        : canonical(decision(expected));
      const have = pinnedByDigest
        ? canonical({
            status: actual?.status,
            code: actual?.code,
            bodyDigest: digest(actual?.body),
          })
        : canonical(decision(actual));
      if (want !== have) {
        failures += 1;
        console.error(
          `\n${rowKey(program.id, stepId)} disagrees${row.divergence ? " (with its pinned divergence)" : ""}`,
        );
        const [path, left, right] = firstDifference(decision(expected), decision(actual));
        console.error(`  at ${path}: expected ${left} / fireemu ${right}`);
        console.error(`  expected ${want.slice(0, 600)}`);
        console.error(`  fireemu  ${have.slice(0, 600)}`);
        if (actual?.message) console.error(`  fireemu message: ${actual.message}`);
        if (row.oracle?.message) console.error(`  oracle message:  ${row.oracle.message}`);
        continue;
      }
      if (row.divergence) diverged += 1;
      if (expected?.message !== undefined && actual?.message !== expected.message) {
        messageDrift += 1;
        drift.push({
          row: rowKey(program.id, stepId),
          oracle: expected.message,
          fireemu: actual?.message,
        });
      }
    }
  }
  await writeFile(join(RUN_DIR, "message-drift.json"), `${JSON.stringify(drift, null, 2)}\n`);
  if (failures === 0) {
    console.log(
      `ok: ${rows} rows agree with the recorded oracle ` +
        `(${diverged} documented divergence${diverged === 1 ? "" : "s"}, ` +
        `${messageDrift} error messages differ; see .runs/firestore-probe/message-drift.json)`,
    );
    return 0;
  }
  console.error(`\n${failures} of ${rows} rows disagree`);
  return 1;
}

/**
 * Runs the programs against production Firestore and compares every row with the recorded
 * official-emulator answer and with what fireemu is held to (the pinned divergence or the
 * oracle). Needs `FIREEMU_PRODUCTION_PROJECT` and an OAuth token (`FIREEMU_PRODUCTION_TOKEN`
 * or `gcloud auth application-default print-access-token`). Set FIREEMU_BIN to the artifact
 * under test and FIREEMU_PACKAGE_INTEGRITY (or FIREEMU_PACKAGE_TARBALL) for a verified release
 * claim. The production project id is normalized out of every recorded value and never written
 * to the matrix.
 */
async function recordProduction() {
  const project = process.env.FIREEMU_PRODUCTION_PROJECT;
  if (!project) throw new Error("FIREEMU_PRODUCTION_PROJECT is required");
  const token =
    process.env.FIREEMU_PRODUCTION_TOKEN ??
    (
      await runSupervisor({
        name: "gcloud",
        command: "gcloud",
        args: ["auth", "application-default", "print-access-token"],
        env: {},
        timeoutMs: 60_000,
      })
    ).trim();
  const metadata = await (
    await fetch(`https://firestore.googleapis.com/v1/projects/${project}/databases/(default)`, {
      headers: { authorization: `Bearer ${token}` },
    })
  ).json();
  const inPath = await writePrograms();
  const outPath = join(RUN_DIR, "production.json");
  const productionDatabase = {
    type: metadata.type,
    concurrencyMode: metadata.concurrencyMode,
    databaseEdition: metadata.databaseEdition,
    locationId: metadata.locationId,
    versionRetentionPeriod: metadata.versionRetentionPeriod,
  };
  const reuse = process.env.FIREEMU_PRODUCTION_REUSE === "1";
  let productionEvidence;
  // Reuse is allowed only when the previous matrix already carries a live production
  // observation. A raw result file alone cannot be promoted to verified evidence.
  if (reuse) {
    const previous = JSON.parse(await readFile(PRODUCTION_JSON, "utf8"));
    productionEvidence = previous.evidence?.observations?.production;
    if (!productionEvidence || productionEvidence.observation?.mode !== "live") {
      throw new Error(
        "FIREEMU_PRODUCTION_REUSE=1 requires a previous matrix with live production evidence",
      );
    }
  } else {
    const productionStartedAt = new Date().toISOString();
    await runSupervisor({
      name: "production",
      command: "node",
      args: [SESSION],
      env: {
        FIRESTORE_PROBE_TARGET: "production",
        FIRESTORE_PROBE_SCHEME: "https",
        FIRESTORE_PROBE_HOST: "firestore.googleapis.com",
        FIRESTORE_PROBE_TOKEN: token,
        FIRESTORE_PROBE_PROJECT: project,
        FIRESTORE_PROBE_RECORD_PROJECT: PROJECT,
        FIRESTORE_PROBE_IN: inPath,
        FIRESTORE_PROBE_OUT: outPath,
        FIRESTORE_PROBE_TIMEOUT_MS: "60000",
      },
      timeoutMs: 1_800_000,
    });
    productionEvidence = await collectEvidence({
      side: "production",
      mode: "live",
      profile: "production",
      corpusPath: inPath,
      indexPaths: [join(CONFORMANCE_DIR, "firestore.indexes.json")],
      database: productionDatabase,
      startedAt: productionStartedAt,
      finishedAt: new Date().toISOString(),
    });
  }
  const production = JSON.parse(await readFile(outPath, "utf8"));
  const artifact = resolveFireemuBinary();
  const fireemuStartedAt = new Date().toISOString();
  const fireemu = await probeFireemu(inPath, join(RUN_DIR, "fireemu-for-production.json"));
  const fireemuEvidence = await collectEvidence({
    side: "fireemu",
    mode: "live",
    profile: "firebase",
    configPath: join(CONFORMANCE_DIR, "firestore-probe.fireemu.json"),
    rulesPath: join(CONFORMANCE_DIR, "firestore-probe.rules"),
    corpusPath: inPath,
    indexPaths: [join(CONFORMANCE_DIR, "firestore.indexes.json")],
    database: { target: "fireemu local Firestore" },
    startedAt: fireemuStartedAt,
    finishedAt: new Date().toISOString(),
    artifactPath: artifact,
  });
  const fireemuValidation = validateLiveEvidence(fireemuEvidence, { requireIndex: true });
  const matrix = JSON.parse(await readFile(MATRIX_JSON, "utf8"));
  const officialMatrixDigest = await digestFile(MATRIX_JSON);
  const recordedValidation = validateRecordedExpectation(
    matrix.recordedAgainst.evidence,
    fireemuEvidence,
    { requireIndex: true },
  );
  const sharedValidation = validateEvidenceJoin(productionEvidence, fireemuEvidence, [
    "sourceSha",
    "packageVersion",
    "packageIntegrity",
    "sdkLockDigest",
    "corpusDigest",
    "indexDigest",
  ]);
  const evidenceErrors = [
    ...fireemuValidation.errors,
    ...recordedValidation.mismatches,
    ...sharedValidation.mismatches,
  ];
  const evidenceVerified =
    fireemuValidation.verified &&
    recordedValidation.verified &&
    sharedValidation.verified &&
    productionEvidence.observation.mode === "live";
  const { counts, programs } = buildProductionPrograms({
    production,
    fireemu,
    matrix,
    evidenceValid: evidenceVerified,
  });
  const dropId = (value) =>
    JSON.parse(JSON.stringify(value ?? null).replaceAll(project, "<production project>"));
  const output = {
    version: 1,
    recordedAgainst: {
      target: "production Firestore (Native mode) over the public REST surface",
      database: dropId({
        type: metadata.type,
        concurrencyMode: metadata.concurrencyMode,
        databaseEdition: metadata.databaseEdition,
        locationId: metadata.locationId,
        versionRetentionPeriod: metadata.versionRetentionPeriod,
      }),
      officialEmulatorMatrix: matrix.recordedAgainst,
      evidenceSchema: 1,
      note: "The production project id is normalized to the recording project id in every value; the project itself is not recorded. Rows compare status, canonical error code and normalized body; error message text is not compared.",
    },
    evidence: {
      schemaVersion: 1,
      verified: evidenceVerified,
      validation: evidenceErrors,
      observations: {
        production: productionEvidence,
        fireemu: fireemuEvidence,
        officialEmulator: {
          side: "official-emulator",
          mode: "stored",
          matrixDigest: officialMatrixDigest,
          source: "firestore-matrix.json",
        },
      },
    },
    summary: counts,
    programs,
  };
  await writeFile(PRODUCTION_JSON, `${JSON.stringify(output, null, 2)}\n`);
  const lines = [
    "# Firestore production matrix",
    "",
    "Every row of `firestore-matrix.json` run against production Firestore (Native mode, the concurrency mode and edition recorded in `firestore-production-matrix.json`), compared with the official emulator's recorded answer and with what fireemu is held to. Regenerate with `pnpm -C conformance firestore:production` (needs `FIREEMU_PRODUCTION_PROJECT` and Application Default Credentials).",
    "",
    "## Evidence",
    "",
    "Fireemu observation: live artifact " +
      fireemuEvidence.artifact.file +
      " (" +
      fireemuEvidence.artifact.sha256 +
      "), source " +
      fireemuEvidence.source.gitSha +
      ", profile " +
      fireemuEvidence.runtime.profile +
      ".",
    "Inputs: corpus " +
      fireemuEvidence.inputs.corpusDigest +
      ", SDK lock " +
      fireemuEvidence.inputs.sdkLockDigest +
      ", indexes " +
      fireemuEvidence.inputs.indexDigest +
      ".",
    "Official emulator values: stored expectation from firestore-matrix.json (" +
      officialMatrixDigest +
      ").",
    "Evidence status: " + (evidenceVerified ? "verified" : "unverified") + ".",
    ...(evidenceErrors.length > 0 ? ["Evidence validation: " + evidenceErrors.join("; ")] : []),
    "",
    "| status | rows | meaning |",
    "| --- | --- | --- |",
    `| parity | ${counts.parity ?? 0} | production, the official emulator and fireemu agree |`,
    `| fireemu-matches-production | ${counts["fireemu-matches-production"] ?? 0} | fireemu follows production where the official emulator differs |`,
    `| fireemu-divergence | ${counts["fireemu-divergence"] ?? 0} | production and the official emulator agree; fireemu differs |`,
    `| emulators-diverge-from-production | ${counts["emulators-diverge-from-production"] ?? 0} | the official emulator and fireemu agree with each other but not with production |`,
    `| three-way-difference | ${counts["three-way-difference"] ?? 0} | production, the official emulator and fireemu all differ |`,
    `| production-needs-index | ${counts["production-needs-index"] ?? 0} | production refused the query for want of a composite index in the oracle project; not a semantic comparison until the index exists |`,
    "",
    "## Rows that are not parity",
    "",
    "| row | status | production | official emulator | fireemu |",
    "| --- | --- | --- | --- | --- |",
  ];
  const cell = (v) => JSON.stringify(decision(v)).slice(0, 90).replaceAll("|", "\\|");
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

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2] ?? "record";
  if (mode === "record-production") {
    await recordProduction();
  } else if (mode === "record") {
    await record();
  } else if (mode === "check") {
    process.exitCode = await check();
  } else if (mode === "both") {
    await record();
    process.exitCode = await check();
  } else {
    console.error(`unknown mode ${mode}; expected record, check or both`);
    process.exitCode = 2;
  }
}
