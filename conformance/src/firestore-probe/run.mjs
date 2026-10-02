// Supervisor for the Firestore semantics probe (FS-PARITY-01 / FS-PARITY-02 / FS-PARITY-03).
//
//   node src/firestore-probe/run.mjs record   run the oracle, write firestore-matrix.json + .md
//   node src/firestore-probe/run.mjs check    run fireemu, diff against the recorded matrix
//   node src/firestore-probe/run.mjs both     record, then check
//
// `record` needs Java and the pinned firebase-tools; `check` needs a built fireemu. Both
// sides run the identical `session.mjs` over the identical program list through the REST
// API, so a difference is a difference in the runtime and nowhere else.

import { createHash, randomUUID } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
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
import * as historical from "./historical-production-check.mjs";

const PROJECT = "demo-firestore-probe";
const TESTD_FIRESTORE_PORT = 32291;
const TESTD_HTTP_PORT = 32292;
const RUN_DIR = join(CONFORMANCE_DIR, ".runs", "firestore-probe");
const MATRIX_JSON = join(CONFORMANCE_DIR, "firestore-matrix.json");
const MATRIX_MD = join(CONFORMANCE_DIR, "FIRESTORE-MATRIX.md");
const PRODUCTION_JSON = join(CONFORMANCE_DIR, "firestore-production-matrix.json");
const PRODUCTION_MD = join(CONFORMANCE_DIR, "FIRESTORE-PRODUCTION-MATRIX.md");
const GRACE_MS = 8000;
const HISTORICAL_PROGRAMS_DIGEST =
  "sha256-24f0c58a215406dffe211d236a39fbd322bc365bd510149bee7e53ac6ed072b2";
const HISTORICAL_MATRIX_DIGEST =
  "sha256-4bcb04ac9427e73bfe89aab5bc9916f318b2ea60efbf156d79cdf47632d58f56";
const HISTORICAL_CHANGED_STEPS = [
  "writes/transforms#maximum-and-minimum-invalid-field-path",
  "writes/transforms#read-after-invalid-max-min",
  "writes/transforms#maximum-and-minimum",
  "writes/transforms#read-after-max-min",
];

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

async function runSupervisor({
  name,
  command,
  args,
  env,
  cwd = CONFORMANCE_DIR,
  timeoutMs = 900_000,
}) {
  const child = spawn(command, args, {
    cwd,
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

const sha256Bytes = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** The profile option belongs to this Node harness, never to fireemu exec. */
export function parseProbeArguments(args) {
  const mode = args[0] ?? "record";
  if (!["record", "record-production", "check", "check-production", "both"].includes(mode))
    throw new Error(`unknown mode ${mode}`);
  if (args.length <= 1) return { mode };
  if (mode !== "check-production" || args.length !== 3 || args[1] !== "--profile")
    throw new Error("invalid, missing or duplicate profile option");
  if (!["strict", "emulator"].includes(args[2])) throw new Error("invalid profile");
  return { mode, profile: args[2] };
}

/** The pinned production observation is the authority for historical prerequisites. */
export function recordedProductionIndexAuthority(saved) {
  const observation = saved?.evidence?.observations?.production;
  const files = observation?.inputs?.indexFiles;
  const sourceGit = observation?.source?.gitSha;
  if (
    saved?.evidence?.verified !== true ||
    observation?.observation?.mode !== "live" ||
    !/^[a-f0-9]{40}$/.test(sourceGit ?? "") ||
    !Array.isArray(files) ||
    files.length !== 1
  )
    throw new Error("missing or ambiguous recorded production index authority");
  const entry = files[0];
  if (
    entry?.file !== "conformance/firestore.indexes.json" ||
    !Number.isSafeInteger(entry.bytes) ||
    entry.bytes <= 0 ||
    !/^sha256-[a-f0-9]{64}$/.test(entry.sha256 ?? "")
  )
    throw new Error("invalid recorded production index authority");
  return { sourceGit, file: entry.file, bytes: entry.bytes, sha256: entry.sha256 };
}

/** Validate the raw matrix pin before trusting its recorded index identity. */
export function pinnedProductionIndexAuthority(matrixBytes) {
  if (`sha256-${sha256Bytes(matrixBytes)}` !== HISTORICAL_MATRIX_DIGEST)
    throw new Error("recorded production matrix index authority changed");
  return recordedProductionIndexAuthority(JSON.parse(matrixBytes));
}

/** Only strict historical replay receives the exact portable recorded catalog. */
export async function createHistoricalProductionLaunch({
  productionMatrixPath = PRODUCTION_JSON,
  indexFixturePath = join(CONFORMANCE_DIR, "firestore-production.indexes.json"),
  ...options
}) {
  if (options.profile !== "strict") return createFireemuProbeLaunch(options);
  const matrixBytes = await readFile(productionMatrixPath);
  const authority = pinnedProductionIndexAuthority(matrixBytes);
  const sourceBytes = await readFile(indexFixturePath);
  if (
    sourceBytes.length !== authority.bytes ||
    `sha256-${sha256Bytes(sourceBytes)}` !== authority.sha256
  )
    throw new Error("recorded production index fixture bytes or digest mismatch");
  return createFireemuProbeLaunch({
    ...options,
    recordedIndexes: { authority, sourcePath: indexFixturePath, sourceBytes },
  });
}

/** Builds the exact launch argv and pins the bytes supplied through --config. */
export async function createFireemuProbeLaunch({
  binary,
  inPath,
  outPath,
  profile,
  recordedIndexes,
  configPath = join(CONFORMANCE_DIR, "firestore-probe.fireemu.json"),
  runDirectory = RUN_DIR,
  cwd = CONFORMANCE_DIR,
}) {
  if (profile !== undefined && !["strict", "emulator"].includes(profile))
    throw new Error("invalid profile");
  const sourceBytes = await readFile(configPath);
  const source = JSON.parse(sourceBytes);
  const requestedProfile = profile ?? source.profile;
  if (source.schemaVersion !== 1 || !["strict", "emulator"].includes(requestedProfile))
    throw new Error("invalid probe configuration profile");
  let path = configPath,
    bytes = sourceBytes,
    indexes;
  if (profile === "strict") {
    const config = structuredClone(source);
    config.profile = "strict";
    if (typeof config.firestore?.rules === "string")
      config.firestore.rules = resolve(cwd, config.firestore.rules);
    await mkdir(runDirectory, { recursive: true, mode: 0o700 });
    if (recordedIndexes) {
      const indexPath = resolve(runDirectory, `strict-indexes-${randomUUID()}.json`);
      await writeFile(indexPath, recordedIndexes.sourceBytes, { flag: "wx", mode: 0o600 });
      config.firestore.indexFile = indexPath;
      indexes = {
        authority: recordedIndexes.authority,
        sourcePath: recordedIndexes.sourcePath,
        sourceBytesBase64: recordedIndexes.sourceBytes.toString("base64"),
        sourceBytesBefore: recordedIndexes.sourceBytes.length,
        sourceSha256Before: sha256Bytes(recordedIndexes.sourceBytes),
        path: indexPath,
        bytesBase64: recordedIndexes.sourceBytes.toString("base64"),
        bytesBefore: recordedIndexes.sourceBytes.length,
        sha256Before: sha256Bytes(recordedIndexes.sourceBytes),
      };
    }
    path = join(runDirectory, `strict-config-${randomUUID()}.json`);
    bytes = Buffer.from(JSON.stringify(config, null, 2) + "\n");
    await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
  } else if (source.profile !== requestedProfile)
    throw new Error("probe configuration profile mismatch");
  return {
    command: binary,
    cwd,
    requestedProfile,
    ...(indexes ? { indexes } : {}),
    args: [
      "exec",
      "--config",
      path,
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
    config: {
      sourcePath: configPath,
      sourceBytesBase64: sourceBytes.toString("base64"),
      sourceSha256Before: sha256Bytes(sourceBytes),
      path,
      bytesBase64: bytes.toString("base64"),
      sha256Before: sha256Bytes(bytes),
    },
  };
}

/** Exactly one actual daemon banner is evidence; a requested marker is not. */
export function daemonProbeProfile(log) {
  const banners = [...String(log ?? "").matchAll(/^  profile: (strict|emulator) \([^\r\n]+\)$/gm)];
  if (banners.length !== 1) throw new Error("missing or ambiguous daemon profile banner");
  return banners[0][1];
}

/** Fail-closed validation shared by the collector and the strict release judge. */
export function probeProfileBindingProblems(
  binding,
  expectedProfile,
  binarySha256,
  sourceSha256,
  indexAuthority,
) {
  const problems = [];
  try {
    if (
      !binding ||
      binding.requestedProfile !== expectedProfile ||
      binding.effectiveProfile !== expectedProfile
    )
      throw new Error("missing or mismatched effective probe profile");
    if (
      daemonProbeProfile(binding.daemonLog) !== expectedProfile ||
      sha256Bytes(binding.daemonLog) !== binding.daemonLogSha256
    )
      throw new Error("daemon profile readback mismatch");
    for (const key of ["sha256Before", "sha256After"])
      if (binding.binary?.[key] !== binarySha256 || !/^[a-f0-9]{64}$/.test(binarySha256))
        throw new Error("profile receipt binary digest mismatch");
    const config = binding.config;
    const decode = (value) => {
      if (typeof value !== "string") throw new Error("missing config bytes");
      const bytes = Buffer.from(value, "base64");
      if (bytes.toString("base64") !== value) throw new Error("invalid config bytes");
      return bytes;
    };
    const bytes = decode(config?.bytesBase64),
      sourceBytes = decode(config.sourceBytesBase64);
    const configDigest = sha256Bytes(bytes),
      sourceDigest = sha256Bytes(sourceBytes);
    if (
      configDigest !== config.sha256Before ||
      configDigest !== config.sha256After ||
      sourceDigest !== config.sourceSha256Before ||
      sourceDigest !== config.sourceSha256After ||
      (sourceSha256 !== undefined && sourceDigest !== sourceSha256)
    )
      throw new Error("profile receipt configuration digest mismatch");
    const expected = JSON.parse(sourceBytes);
    if (expected.schemaVersion !== 1) throw new Error("noncanonical source config");
    if (expectedProfile === "strict") {
      expected.profile = "strict";
      if (typeof expected.firestore?.rules === "string")
        expected.firestore.rules = resolve(binding.cwd, expected.firestore.rules);
    }
    if (indexAuthority !== undefined) {
      const indexes = binding.indexes;
      if (
        expectedProfile !== "strict" ||
        !indexes ||
        !isDeepStrictEqual(indexes.authority, indexAuthority)
      )
        throw new Error("missing or mismatched recorded production index authority");
      const indexBytes = decode(indexes.bytesBase64),
        indexSourceBytes = decode(indexes.sourceBytesBase64);
      const indexDigest = sha256Bytes(indexBytes),
        indexSourceDigest = sha256Bytes(indexSourceBytes);
      if (
        indexBytes.length !== indexAuthority.bytes ||
        indexSourceBytes.length !== indexAuthority.bytes ||
        `sha256-${indexDigest}` !== indexAuthority.sha256 ||
        `sha256-${indexSourceDigest}` !== indexAuthority.sha256 ||
        !indexBytes.equals(indexSourceBytes)
      )
        throw new Error("recorded index receipt bytes or digest mismatch");
      for (const suffix of ["Before", "After"])
        if (
          indexes[`bytes${suffix}`] !== indexAuthority.bytes ||
          indexes[`sourceBytes${suffix}`] !== indexAuthority.bytes ||
          indexes[`sha256${suffix}`] !== indexDigest ||
          indexes[`sourceSha256${suffix}`] !== indexSourceDigest
        )
          throw new Error("recorded index receipt changed before or after launch");
      if (
        !isAbsolute(indexes.path) ||
        dirname(indexes.path) !== dirname(config.path) ||
        indexes.path === indexes.sourcePath
      )
        throw new Error("recorded index path is not a separate run-owned config prerequisite");
      expected.firestore.indexFile = indexes.path;
    } else if (binding.indexes) throw new Error("unbound recorded index receipt");
    const actual = JSON.parse(bytes);
    if (actual.profile !== expectedProfile || !isDeepStrictEqual(actual, expected))
      throw new Error("profile receipt configuration settings mismatch");
    if (
      !Array.isArray(binding.argv) ||
      binding.argv[0] !== "exec" ||
      binding.argv.filter((arg) => arg === "--config").length !== 1 ||
      binding.argv[binding.argv.indexOf("--config") + 1] !== config.path ||
      binding.argv.includes("--profile")
    )
      throw new Error("profile receipt launch config mismatch");
  } catch (error) {
    problems.push(error.message);
  }
  return problems;
}

/** Executes the tested plan and derives its receipt from the supervisor's actual output. */
export async function executeFireemuProbe(plan, supervisor = runSupervisor) {
  const before = sha256Bytes(await readFile(plan.command));
  const daemonLog = await supervisor({
    name: "fireemu",
    cwd: plan.cwd,
    command: plan.command,
    args: plan.args,
    env: plan.env,
  });
  const binding = {
    requestedProfile: plan.requestedProfile,
    effectiveProfile: daemonProbeProfile(daemonLog),
    daemonLog,
    daemonLogSha256: sha256Bytes(daemonLog),
    cwd: plan.cwd,
    argv: plan.args,
    binary: {
      path: plan.command,
      sha256Before: before,
      sha256After: sha256Bytes(await readFile(plan.command)),
    },
    config: {
      ...plan.config,
      sha256After: sha256Bytes(await readFile(plan.config.path)),
      sourceSha256After: sha256Bytes(await readFile(plan.config.sourcePath)),
    },
  };
  if (plan.indexes) {
    const indexBytes = await readFile(plan.indexes.path),
      indexSourceBytes = await readFile(plan.indexes.sourcePath);
    binding.indexes = {
      ...plan.indexes,
      bytesAfter: indexBytes.length,
      sha256After: sha256Bytes(indexBytes),
      sourceBytesAfter: indexSourceBytes.length,
      sourceSha256After: sha256Bytes(indexSourceBytes),
    };
  }
  const problems = probeProfileBindingProblems(
    binding,
    plan.requestedProfile,
    before,
    undefined,
    plan.indexes?.authority,
  );
  if (problems.length) throw new Error(problems.join("; "));
  const rawBytes = await readFile(plan.env.FIRESTORE_PROBE_OUT);
  return { fireemu: JSON.parse(rawBytes), binding, localRawSha256: sha256Bytes(rawBytes) };
}

/** Ordinary comparisons retain the original emulator configuration. */
async function probeFireemu(inPath, outPath, chosen) {
  const plan = await createFireemuProbeLaunch({
    binary: chosen ?? resolveFireemuBinary(),
    inPath,
    outPath,
  });
  return (await executeFireemuProbe(plan)).fireemu;
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

/** A transport result is not an observation that can establish an HTTP comparison. */
function isCompletedHttpObservation(step) {
  return (
    step &&
    step.missing !== true &&
    Number.isInteger(step.status) &&
    step.status >= 100 &&
    step.status <= 599 &&
    typeof step.code === "string" &&
    step.code.length > 0 &&
    (step.code !== "OK" || Object.hasOwn(step, "body"))
  );
}

/** Compare saved production decisions with a current normalized fireemu response. */
export function compareProductionToFireemu({ production, fireemu, programDefinitions = PROGRAMS }) {
  const savedPrograms = Array.isArray(production)
    ? Object.fromEntries(production.map((program) => [program.id, program]))
    : production.programs
      ? Object.fromEntries(production.programs.map((program) => [program.id, program]))
      : production;
  const rows = [];
  for (const program of programDefinitions) {
    for (const step of program.steps) {
      const saved = savedPrograms[program.id]?.steps?.[step.id]?.production ?? { missing: true };
      const actual = fireemu[program.id]?.steps?.[step.id] ?? { missing: true };
      const savedDecision = decision(saved);
      const localDecision = decision(actual);
      const comparison =
        isCompletedHttpObservation(saved) && isCompletedHttpObservation(actual)
          ? canonical(savedDecision) === canonical(localDecision)
            ? "match"
            : "mismatch"
          : "indeterminate";
      rows.push({
        id: step.id,
        comparison,
        production: savedDecision,
        local: localDecision,
      });
    }
  }
  const matches = rows.filter((row) => row.comparison === "match").length;
  return {
    rowCount: rows.length,
    matches,
    mismatches: rows.length - matches,
    rows,
  };
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
  let localOnlyRows = 0;
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
      const definition = PROGRAMS.find((candidate) => candidate.id === program.id)?.steps.find(
        (candidate) => candidate.id === stepId,
      );
      const actual = mine.steps?.[stepId];
      if (definition?.localOnly) {
        // Local-only extensions are not official-emulator compatibility claims. They still need
        // a complete HTTP observation so a failed local run cannot disappear as a skip.
        if (!isCompletedHttpObservation(actual)) {
          failures += 1;
          console.error(`\n${rowKey(program.id, stepId)} local-only observation is incomplete`);
        } else {
          localOnlyRows += 1;
        }
        continue;
      }
      // The register in `divergences.mjs` is the source of truth; the copy stamped into
      // the matrix at record time is for the reader of the JSON.
      const row = { ...recorded, divergence: DIVERGENCES[rowKey(program.id, stepId)] };
      const expected = row.divergence ? row.divergence.fireemu : row.oracle;
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
      `ok: ${rows - localOnlyRows} gated rows agree with the recorded oracle ` +
        `(${diverged} documented divergence${diverged === 1 ? "" : "s"}, ` +
        `${localOnlyRows} local-only rows observed, ` +
        `${messageDrift} error messages differ; see .runs/firestore-probe/message-drift.json)`,
    );
    return 0;
  }
  console.error(`\n${failures} of ${rows} rows disagree`);
  return 1;
}

/**
 * The status legend of the production matrix: one row per status `classifyProductionCase`
 * can return, with its count.
 */
export function productionStatusLegend(counts) {
  return [
    "| status | rows | meaning |",
    "| --- | --- | --- |",
    `| parity | ${counts.parity ?? 0} | production, the official emulator and fireemu agree |`,
    `| fireemu-matches-production | ${counts["fireemu-matches-production"] ?? 0} | fireemu follows production where the official emulator differs |`,
    `| fireemu-divergence | ${counts["fireemu-divergence"] ?? 0} | production and the official emulator agree; fireemu differs |`,
    `| emulators-diverge-from-production | ${counts["emulators-diverge-from-production"] ?? 0} | the official emulator and fireemu agree with each other but not with production |`,
    `| three-way-difference | ${counts["three-way-difference"] ?? 0} | production, the official emulator and fireemu all differ |`,
    `| production-needs-index | ${counts["production-needs-index"] ?? 0} | production refused the query for want of a composite index in the oracle project; not a semantic comparison until the index exists |`,
    `| excluded-local-only | ${counts["excluded-local-only"] ?? 0} | a local-only row (program area \`emulator\`): an explicit exclusion, not a production comparison |`,
    `| unverified | ${counts.unverified ?? 0} | no validated live identity, or a side has no answer: the row cannot become a compatibility match |`,
  ];
}

/** Replay the pinned historical production corpus without contacting production. */
export function historicalProductionSummary(live) {
  const matrixBytes = readFileSync(PRODUCTION_JSON);
  const programsBytes = readFileSync(join(CONFORMANCE_DIR, "src/firestore-probe/programs.mjs"));
  if (
    `sha256-${sha256Bytes(matrixBytes)}` !== HISTORICAL_MATRIX_DIGEST ||
    `sha256-${sha256Bytes(programsBytes)}` !== HISTORICAL_PROGRAMS_DIGEST
  )
    throw new Error("historical corpus pin mismatch");
  const saved = JSON.parse(matrixBytes);
  const ids = PROGRAMS.map((program) => program.id);
  if (!live || !isDeepStrictEqual(Object.keys(live).toSorted(), [...ids].toSorted()))
    throw new Error("historical program inventory mismatch");
  for (const program of PROGRAMS) {
    const actual = live[program.id];
    if (
      !actual ||
      !actual.steps ||
      !isDeepStrictEqual(
        Object.keys(actual.steps).toSorted(),
        program.steps.map((step) => step.id).toSorted(),
      )
    )
      throw new Error("historical step inventory mismatch");
  }
  return historical.checkHistoricalProduction({
    saved,
    live,
    definitions: PROGRAMS,
    excludedKeys: HISTORICAL_CHANGED_STEPS,
  });
}

export function historicalProductionBaseline() {
  const saved = JSON.parse(readFileSync(PRODUCTION_JSON));
  const live = Object.fromEntries(
    saved.programs.map((program) => [
      program.id,
      {
        steps: Object.fromEntries(
          Object.entries(program.steps).map(([id, row]) => [id, row.fireemu]),
        ),
      },
    ]),
  );
  return historical.checkHistoricalProduction({
    saved,
    live,
    definitions: PROGRAMS,
    excludedKeys: HISTORICAL_CHANGED_STEPS,
  });
}

async function checkProduction(profile) {
  const programsDigest = await digestFile(
    join(CONFORMANCE_DIR, "src/firestore-probe/programs.mjs"),
  );
  const matrixDigest = await digestFile(PRODUCTION_JSON);
  if (programsDigest !== HISTORICAL_PROGRAMS_DIGEST || matrixDigest !== HISTORICAL_MATRIX_DIGEST) {
    throw new Error(
      "historical production input changed; review recipe identity before updating digests",
    );
  }
  const saved = JSON.parse(await readFile(PRODUCTION_JSON, "utf8"));
  if (
    saved.evidence?.verified !== true ||
    saved.evidence?.observations?.production?.observation?.mode !== "live"
  ) {
    throw new Error("historical production matrix has no verified live production observation");
  }
  const inPath = await writePrograms();
  const binary = resolveFireemuBinary();
  const before = await historical.measureArtifact(binary);
  const plan = await createHistoricalProductionLaunch({
    binary,
    inPath,
    outPath: join(RUN_DIR, "fireemu-historical-production.json"),
    profile,
  });
  const { fireemu, binding, localRawSha256 } = await executeFireemuProbe(plan);
  const after = await historical.measureArtifact(binary);
  const result = {
    localRawSha256,
    profileBinding: binding,
    artifact: historical.historicalArtifactIdentity({
      binary,
      before: before.sha256,
      after: after.sha256,
      version: before.version,
    }),
    ...historical.checkHistoricalProduction({
      saved,
      live: fireemu,
      definitions: PROGRAMS,
      excludedKeys: HISTORICAL_CHANGED_STEPS,
    }),
  };
  await writeFile(
    join(RUN_DIR, "historical-production-comparison.json"),
    `${JSON.stringify(result, null, 2)}\n`,
  );
  console.log(
    `historical production: ${result.comparable} comparable rows, ` +
      `${result.currentMismatches.length} known mismatches, ` +
      `${result.indeterminate.length} indeterminate; ` +
      `${result.newMismatches.length} new mismatches, ` +
      `${result.newIndeterminate.length} new indeterminate`,
  );
  return result.newMismatches.length === 0 && result.newIndeterminate.length === 0 ? 0 : 1;
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
    profile: "emulator",
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
    ...productionStatusLegend(counts),
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
  const { mode, profile } = parseProbeArguments(process.argv.slice(2));
  if (mode === "record-production") {
    await recordProduction();
  } else if (mode === "record") {
    await record();
  } else if (mode === "check") {
    process.exitCode = await check();
  } else if (mode === "check-production") {
    process.exitCode = await checkProduction(profile);
  } else if (mode === "both") {
    await record();
    process.exitCode = await check();
  } else {
    console.error(`unknown mode ${mode}; expected record, check, check-production or both`);
    process.exitCode = 2;
  }
}
