// The release comparison of the strict profile with the committed production recordings.
//
//   FIREEMU_BIN=<installed fireemu> FIREEMU_NODE=<Node 22.22.1> \
//     node conformance/src/release-strict-regression.mjs --out <dir> [--dist <npm dist dir>]
//
// Every parent whose closure is COMPAT_VERIFIED names, in `integratedRegression`, the
// comparison files one release binary produced against its saved production recordings. This
// script reruns those local comparisons on the binary under test, from the repository root,
// and requires each result to equal the committed file: the same rows, each with the same
// status and the same row summary (differences, decisions, relabels), the same fixture and the
// same totals. Nothing is sent to production: the recording modes are not in the command table,
// production and sandbox credentials refuse the run, and the run refuses to start while a
// production endpoint answers (the release job runs it in a network namespace with loopback
// only). The comparisons that need private inputs are listed in EXCLUDED_PARTS with the issue
// that tracks them.
//
// The runs are sequential: several harnesses listen on fixed loopback ports (32291-32298,
// 32320-32322).
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { copyFile, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const CONFORMANCE = join(ROOT, "conformance");
const RUNS_DIR = join(CONFORMANCE, ".runs");
const CLOSURE_DIR = "spec/compatibility/closure";
const COMMAND_TIMEOUT_MS = 10 * 60 * 1000;
const MAX_ANNOTATIONS = 50;

/** The only harness modes this script may invoke: all of them local. */
export const ALLOWED_MODES = new Set([
  "check",
  "export-comparison",
  "local-child",
  "compare-local",
  "check-production",
  "check-local",
]);

/** Environment that belongs to production or sandbox recording; its presence refuses the run. */
const FORBIDDEN_ENV_NAMES = new Set([
  "FIREEMU_SANDBOX_LEDGER",
  "FIREEMU_AUTH_SANDBOX_WEB_CONFIG",
  "GOOGLE_APPLICATION_CREDENTIALS",
  "FIREEMU_PRODUCTION_TOKEN",
  "FIREEMU_PRODUCTION_PROJECT",
]);
const FORBIDDEN_ENV_PATTERNS = [/^FIREEMU_.*_PRIVATE_DIR$/, /^CLOUDSDK_/];

/** Production endpoints the harnesses' SDKs would reach if a local target were missed. */
export const PRODUCTION_ORIGINS = [
  "https://firestore.googleapis.com/",
  "https://identitytoolkit.googleapis.com/",
];

const laneRun = (id, kind, script, runDir, expectedCheckExit, env = {}) => ({
  id,
  kind,
  clear: [runDir],
  commands: [
    {
      mode: "check",
      argv: ["node", script, "check"],
      env,
      expectedExitCodes: [expectedCheckExit],
    },
    {
      mode: "export-comparison",
      argv: ["node", script, "export-comparison", "{export}"],
      env,
      expectedExitCodes: [0],
    },
  ],
});

/**
 * The comparisons the closures name, each rerun by one entry. `{bin}`, `{export}` and `{runDir}`
 * are filled in when the entry runs; `{functionsNode}` is FIREEMU_NODE.
 */
export const RUNS = [
  laneRun(
    "R1",
    "fs-query-index-comparison-v1",
    "conformance/src/fs-query-index/run.mjs",
    "fs-query-index",
    0,
  ),
  laneRun(
    "R2",
    "fs-data-write-list-comparison-v1",
    "conformance/src/fs-query-index/run.mjs",
    "fs-data-write-list",
    0,
    { FIREEMU_SANDBOX_LANE: "fs-data-write-list" },
  ),
  laneRun(
    "R3",
    "fs-config-lifecycle-comparison-v1",
    "conformance/src/fs-config-lifecycle/run.mjs",
    "fs-config-lifecycle",
    0,
  ),
  laneRun("R4", "fs-rules-comparison-v1", "conformance/src/fs-rules/run.mjs", "fs-rules", 0),
  laneRun(
    "R5",
    "auth-account-comparison-v1",
    "conformance/src/auth-account/run.mjs",
    "auth-account",
    0,
  ),
  laneRun(
    "R6",
    "auth-credential-comparison-v1",
    "conformance/src/auth-credential/run.mjs",
    "auth-credential",
    0,
  ),
  laneRun(
    "R7",
    "auth-action-comparison-v1",
    "conformance/src/auth-action/run.mjs",
    "auth-action",
    0,
  ),
  laneRun("R8", "auth-mfa-comparison-v1", "conformance/src/auth-mfa/run.mjs", "auth-mfa", 0),
  // The eight MISMATCH rows of AUTH-CONFIG-SDK are owner-approved, so its check exits 1.
  laneRun(
    "R9",
    "auth-config-sdk-comparison-v1",
    "conformance/src/auth-config-sdk/run.mjs",
    "auth-config-sdk",
    1,
  ),
  {
    // FS-DATA-WRITE's sandbox corpus against the binary under test, called directly: the lane's
    // local checker builds target/debug/fireemu, and the runner is bound to the lane evidence.
    id: "R10",
    kind: "fs-data-write-integrated-regression",
    part: "current",
    clear: ["fs-data-write-local-*"],
    commands: [
      {
        mode: "local-child",
        argv: [
          "{bin}",
          "exec",
          "--config",
          "conformance/fs-data-write-sandbox.fireemu.json",
          "--project",
          "fireemu-oracle-sbx",
          "--only",
          "firestore",
          "--firestore-port",
          "0",
          "--http-port",
          "0",
          "--storage-port",
          "0",
          "--hub-port",
          "0",
          "--logging-port",
          "0",
          "--",
          "node",
          "conformance/src/fs-data-write-sandbox-run.mjs",
          "local-child",
        ],
        env: {},
        expectedExitCodes: [0],
      },
      {
        mode: "compare-local",
        argv: [
          "node",
          "conformance/src/fs-data-write-sandbox-run.mjs",
          "compare-local",
          "{runDir}",
        ],
        env: {},
        expectedExitCodes: [0],
      },
    ],
  },
  {
    // The pinned historical production corpus of FS-DATA-WRITE, replayed without production.
    id: "R11",
    kind: "fs-data-write-integrated-regression",
    part: "historical",
    clear: ["firestore-probe"],
    commands: [
      {
        mode: "check-production",
        argv: ["node", "conformance/src/firestore-probe/run.mjs", "check-production"],
        env: {},
        expectedExitCodes: [0],
      },
    ],
  },
  {
    // FUNCTIONS-HTTP's production recordings are private; the local recording must be the same
    // bytes the lane compared with them, which fixes every row's result.
    id: "R12",
    kind: "functions-http-integrated-regression",
    clear: ["functions-http"],
    commands: [
      {
        mode: "check-local",
        argv: ["{functionsNode}", "conformance/functions-http/run.mjs", "check-local"],
        env: {},
        functionsNodeOnPath: true,
        expectedExitCodes: [0],
      },
    ],
  },
];

/** Composite comparison files: which part each run covers. Other keys are metadata. */
const COMPOSITE_KINDS = {
  "fs-data-write-integrated-regression": ["schemaVersion", "kind", "binarySha256"],
};

/** Parts of a comparison file the release does not rerun, with why and where it is tracked. */
export const EXCLUDED_PARTS = [
  {
    kind: "fs-data-write-integrated-regression",
    part: "savedStreamTransaction",
    condition: "FS-DATA-WRITE/stream-transaction-precedence",
    reason:
      "the saved 23-row stream transaction replay reads a production receipt that is not published; the condition stays on the lane evidence",
    issue: "fs-data-write-saved-stream-comparison-needs-private-receipt.md",
  },
  {
    kind: "fs-data-write-integrated-regression",
    part: "emulatorProfile",
    scope: "emulator-profile",
    reason:
      "the emulator profile rows are not a strict production comparison; the emulator profile is gated by verify-artifact",
  },
];

/** The environment variables that refuse the run. */
export function forbiddenEnvironment(env) {
  return Object.keys(env)
    .filter(
      (name) => FORBIDDEN_ENV_NAMES.has(name) || FORBIDDEN_ENV_PATTERNS.some((re) => re.test(name)),
    )
    .toSorted();
}

/** Fails when any production endpoint answers: the run needs a network with loopback only. */
export async function assertNoOutboundNetwork(fetchImpl, origins = PRODUCTION_ORIGINS) {
  const reached = [];
  for (const origin of origins) {
    try {
      await fetchImpl(origin, { signal: AbortSignal.timeout(5000), redirect: "manual" });
      reached.push(origin);
    } catch {
      // Refused, unresolvable or timed out: not reachable, as required.
    }
  }
  if (reached.length > 0) {
    throw new Error(
      `production reached (${reached.join(", ")}); run inside a loopback-only network namespace`,
    );
  }
}

/** Every harness mode the command table uses. */
export function commandModes(runs) {
  return [...new Set(runs.flatMap((run) => run.commands.map((command) => command.mode)))];
}

export function parseArguments(args) {
  const parsed = { out: undefined, dist: undefined };
  for (let index = 0; index < args.length; index += 1) {
    const name = args[index];
    const value = args[index + 1];
    if (name !== "--out" && name !== "--dist") throw new Error(`unknown argument ${name}`);
    if (!value || value.startsWith("--")) throw new Error(`${name} needs a value`);
    parsed[name.slice(2)] = value;
    index += 1;
  }
  if (!parsed.out)
    throw new Error("usage: release-strict-regression.mjs --out <dir> [--dist <dir>]");
  return parsed;
}

const parentName = ({ name, closure }) => closure.parent ?? name.replace(/\.json$/, "");

/**
 * The comparison files every COMPAT_VERIFIED closure names, each with the runs that reproduce
 * it. A closure without an integrated regression, a comparison of a kind no run produces, or a
 * part of a composite file that is neither run nor excluded is an error.
 */
export function planComparisons(closures, readJson) {
  const errors = [];
  const byPath = new Map();
  for (const entry of closures) {
    if (entry.closure.parentStatus !== "COMPAT_VERIFIED") continue;
    const parent = parentName(entry);
    const comparisons = entry.closure.integratedRegression?.comparisons;
    if (!Array.isArray(comparisons) || comparisons.length === 0) {
      errors.push(`${parent}: COMPAT_VERIFIED without integratedRegression comparisons`);
      continue;
    }
    for (const { path } of comparisons) {
      if (!byPath.has(path)) byPath.set(path, new Set());
      byPath.get(path).add(parent);
    }
  }
  const planned = [];
  for (const [path, parents] of byPath) {
    const document = readJson(path);
    const kind = document?.kind;
    const runs = RUNS.filter((run) => run.kind === kind);
    if (runs.length === 0) {
      errors.push(`${path}: no run produces comparisons of kind ${kind}`);
      continue;
    }
    if (COMPOSITE_KINDS[kind]) {
      const metadata = new Set(COMPOSITE_KINDS[kind]);
      for (const part of Object.keys(document)) {
        if (metadata.has(part)) continue;
        const covered = runs.some((run) => run.part === part);
        const excluded = EXCLUDED_PARTS.some((ex) => ex.kind === kind && ex.part === part);
        if (!covered && !excluded) errors.push(`${path}: part ${part} is neither run nor excluded`);
      }
    }
    planned.push({ path, kind, parents: [...parents].toSorted(), runIds: runs.map((r) => r.id) });
  }
  return { comparisons: planned, errors };
}

const brief = (value) => {
  const text = JSON.stringify(value);
  return text === undefined ? "undefined" : text.length > 300 ? `${text.slice(0, 300)}...` : text;
};

const rowKey = (row) => row?.row ?? row?.id;

/** Differences between a lane export and the committed comparison file. */
export function compareLaneExport(expected, actual, binarySha256) {
  if (!actual || typeof actual !== "object" || !Array.isArray(actual.rows)) {
    return ["no comparison was exported"];
  }
  const differences = [];
  for (const field of ["kind", "fixtureSha256", "summary"]) {
    if (!isDeepStrictEqual(expected[field], actual[field])) {
      differences.push(`${field}: expected ${brief(expected[field])} got ${brief(actual[field])}`);
    }
  }
  if ("rangeTotals" in expected && !isDeepStrictEqual(expected.rangeTotals, actual.rangeTotals)) {
    differences.push(
      `rangeTotals: expected ${brief(expected.rangeTotals)} got ${brief(actual.rangeTotals)}`,
    );
  }
  if (actual.artifactSha256 !== binarySha256) {
    differences.push(`artifactSha256 ${actual.artifactSha256} is not the binary under test`);
  }
  const committed = new Map(expected.rows.map((row) => [rowKey(row), row]));
  const seen = new Set();
  for (const row of actual.rows) {
    const key = rowKey(row);
    if (seen.has(key)) {
      differences.push(`${key}: exported twice`);
      continue;
    }
    seen.add(key);
    if (!committed.has(key)) differences.push(`${key}: not in the committed comparison`);
    else if (!isDeepStrictEqual(committed.get(key), row)) {
      differences.push(`${key}: expected ${brief(committed.get(key))} got ${brief(row)}`);
    }
  }
  for (const key of committed.keys()) {
    if (!seen.has(key)) differences.push(`${key}: missing from the export`);
  }
  return differences;
}

const sameSet = (a, b) =>
  Array.isArray(a) &&
  Array.isArray(b) &&
  a.length === b.length &&
  a.every((item) => b.includes(item));

const expectEqual = (differences, label, expected, actual) => {
  if (!isDeepStrictEqual(expected, actual)) {
    differences.push(`${label}: expected ${brief(expected)} got ${brief(actual)}`);
  }
};

const RUNNER_INPUTS = [
  "conformance/src/fs-data-write-sandbox-run.mjs",
  "conformance/src/firestore-probe/sandbox-session.mjs",
];

/** FS-DATA-WRITE's local sandbox comparison against `current` of the regression file. */
export function judgeFsDataWriteCurrent(expected, observed, laneRuntimeInputs) {
  const differences = [];
  expectEqual(differences, "compare-local exit code", 0, observed.exitCode);
  const result = observed.result;
  if (!result || typeof result !== "object") return [...differences, "no compare-local result"];
  expectEqual(differences, "corpusDigest", expected.corpusSha256, result.corpusDigest);
  expectEqual(
    differences,
    "recordedCorpusDigest",
    expected.recordedCorpusSha256,
    result.recordedCorpusDigest,
  );
  expectEqual(
    differences,
    "comparedPrograms",
    expected.comparedRestPrograms,
    result.comparedPrograms,
  );
  expectEqual(differences, "comparedStreams", expected.comparedGrpcStreams, result.comparedStreams);
  expectEqual(differences, "pendingRestIds", [], result.pendingRestIds);
  expectEqual(differences, "pendingStreamIds", [], result.pendingStreamIds);
  if (!sameSet(expected.retiredRestIds, result.retiredRestIds)) {
    differences.push(`retiredRestIds: got ${brief(result.retiredRestIds)}`);
  }
  expectEqual(
    differences,
    "retiredStreamIds",
    expected.retiredStreamIds ?? [],
    result.retiredStreamIds,
  );
  expectEqual(differences, "mismatches", 0, result.mismatches);
  for (const path of RUNNER_INPUTS) {
    expectEqual(
      differences,
      `runner input ${path}`,
      laneRuntimeInputs[path],
      observed.runtimeInputs?.[path],
    );
  }
  return differences;
}

/** FS-DATA-WRITE's historical production replay against `historical` of the regression file. */
export function judgeFsDataWriteHistorical(expected, observed, binarySha256) {
  const differences = [];
  expectEqual(differences, "check-production exit code", 0, observed.exitCode);
  const result = observed.result;
  if (!result || typeof result !== "object") return [...differences, "no historical comparison"];
  expectEqual(differences, "binary before", binarySha256, result.artifact?.sha256Before);
  expectEqual(differences, "binary after", binarySha256, result.artifact?.sha256After);
  expectEqual(differences, "comparable", expected.comparable, result.comparable);
  expectEqual(
    differences,
    "known mismatches",
    expected.knownMismatches,
    result.currentMismatches?.length,
  );
  expectEqual(differences, "indeterminate", expected.indeterminate, result.indeterminate?.length);
  expectEqual(differences, "newMismatches", [], result.newMismatches);
  expectEqual(differences, "newIndeterminate", [], result.newIndeterminate);
  const rows = [...(result.currentMismatches ?? []), ...(result.indeterminate ?? [])];
  if (!sameSet(expected.rows, rows)) differences.push(`known rows: got ${brief(rows)}`);
  return differences;
}

const caseCount = (recording) =>
  Object.values(recording ?? {}).reduce(
    (total, cases) => total + Object.keys(cases ?? {}).length,
    0,
  );

/** The FUNCTIONS-HTTP stand-in: the local strict recording is the lane's bytes. */
export function judgeFunctionsHttp(expected, observed) {
  const differences = [];
  expectEqual(differences, "check-local exit code", 0, observed.exitCode);
  const strict = expected.runs.find((run) => run.profile === "strict");
  expectEqual(
    differences,
    "strict recording sha256",
    strict?.recordingSha256,
    observed.outputSha256,
  );
  expectEqual(differences, "Functions runtime Node", expected.nodeVersion, observed.nodeVersion);
  expectEqual(
    differences,
    "fixture index.js",
    expected.fixtureIndexSha256,
    observed.fixtureIndexSha256,
  );
  expectEqual(
    differences,
    "fixture package-lock.json",
    expected.fixturePackageLockSha256,
    observed.fixturePackageLockSha256,
  );
  if (!/^\s*profile: strict\b/m.test(observed.log ?? "")) {
    differences.push("the daemon did not report the strict profile");
  }
  const recordings = observed.output?.recordings;
  if (!Array.isArray(recordings) || recordings.length !== 2) {
    return [...differences, "the local run did not record the corpus twice"];
  }
  if (!isDeepStrictEqual(recordings[0], recordings[1])) {
    differences.push("the two local recordings differ");
  }
  expectEqual(differences, "recorded cases", expected.totalCases, caseCount(recordings[0]));
  return differences;
}

// --- execution --------------------------------------------------------------------------------

const sha256Bytes = (bytes) => createHash("sha256").update(bytes).digest("hex");
const sha256File = async (path) => sha256Bytes(await readFile(path));

const fill = (argv, values) =>
  argv.map((arg) => arg.replace(/\{(\w+)\}/g, (match, name) => values[name] ?? match));

async function clearRunDirs(patterns) {
  let names = [];
  try {
    names = await readdir(RUNS_DIR);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  for (const pattern of patterns) {
    const matches = pattern.endsWith("*")
      ? names.filter((name) => name.startsWith(pattern.slice(0, -1)))
      : names.filter((name) => name === pattern);
    for (const name of matches) await rm(join(RUNS_DIR, name), { recursive: true, force: true });
  }
}

/** Processes still running the binary under test. */
function leftoverProcesses(binary) {
  const pids = [];
  if (process.platform === "linux") {
    for (const entry of readdirSync("/proc")) {
      if (!/^\d+$/.test(entry)) continue;
      try {
        if (realpathSync(`/proc/${entry}/exe`) === binary) pids.push(Number(entry));
      } catch {
        // Gone, or not ours to read.
      }
    }
  }
  return pids;
}

function killGroup(pid, signal) {
  try {
    process.kill(-pid, signal);
  } catch {
    // The group has already exited.
  }
}

/** Runs one command in its own process group, with a deadline, logging to `logPath`. */
async function runCommand(argv, env, cwd, logPath) {
  const started = Date.now();
  const child = spawn(argv[0], argv.slice(1), {
    cwd,
    env,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  const append = (chunk) => {
    output += chunk;
  };
  child.stdout.setEncoding("utf8").on("data", append);
  child.stderr.setEncoding("utf8").on("data", append);
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    killGroup(child.pid, "SIGKILL");
  }, COMMAND_TIMEOUT_MS);
  const exitCode = await new Promise((done) => {
    child.once("error", (error) => {
      append(`${error.stack}\n`);
      done(-1);
    });
    child.once("close", (code, signal) => done(code ?? (signal ? 128 : -1)));
  });
  clearTimeout(timer);
  killGroup(child.pid, "SIGKILL");
  await writeFile(logPath, output);
  return { exitCode: timedOut ? "timeout" : exitCode, ms: Date.now() - started, output };
}

const lastJsonLine = (text) => {
  const lines = text.trim().split("\n");
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try {
      return JSON.parse(lines[index]);
    } catch {
      // Not the result line.
    }
  }
  return undefined;
};

const readJsonFile = async (path) => JSON.parse(await readFile(path, "utf8"));

async function runEntry(run, context) {
  await clearRunDirs(run.clear);
  const record = { id: run.id, kind: run.kind, part: run.part, commands: [], errors: [] };
  const values = {
    bin: context.binary,
    functionsNode: context.functionsNode,
    export: join(context.out, `${run.id}-export.json`),
    runDir: "",
  };
  const outputs = [];
  for (const [index, command] of run.commands.entries()) {
    if (!ALLOWED_MODES.has(command.mode) || !command.argv.includes(command.mode)) {
      throw new Error(`${run.id}: mode ${command.mode} is not allowed`);
    }
    const argv = fill(command.argv, values);
    const env = { ...context.env, ...command.env };
    if (command.functionsNodeOnPath) {
      env.PATH = `${dirname(context.functionsNode)}:${env.PATH}`;
    }
    const logPath = join(context.out, "logs", `${run.id}-${index + 1}-${command.mode}.log`);
    const result = await runCommand(argv, env, ROOT, logPath);
    outputs.push(result.output);
    record.commands.push({ mode: command.mode, argv, exitCode: result.exitCode, ms: result.ms });
    if (!command.expectedExitCodes.includes(result.exitCode)) {
      record.errors.push(
        `${command.mode} exited ${result.exitCode}, expected ${command.expectedExitCodes.join(" or ")}`,
      );
    }
    if (command.mode === "local-child") {
      const runDir = lastJsonLine(result.output)?.runDir;
      if (
        typeof runDir !== "string" ||
        !resolve(runDir).startsWith(join(RUNS_DIR, "fs-data-write-local-"))
      ) {
        record.errors.push("local-child did not name a run directory under conformance/.runs");
        break;
      }
      values.runDir = resolve(runDir);
    }
  }
  const leftovers = leftoverProcesses(context.binary);
  for (const pid of leftovers) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Already gone.
    }
  }
  if (leftovers.length > 0) record.errors.push(`fireemu processes were left running: ${leftovers}`);
  return { record, outputs, values };
}

async function observe(run, entry, context) {
  const { record, outputs, values } = entry;
  const lastExit = record.commands.at(-1)?.exitCode;
  if (run.id === "R10") {
    const inputs = {};
    for (const path of RUNNER_INPUTS) inputs[path] = await sha256File(join(ROOT, path));
    const result = lastJsonLine(outputs.at(-1) ?? "");
    const raw = {};
    if (values.runDir) {
      for (const name of ["rest-results.json", "stream-results.json"]) {
        const path = join(values.runDir, name);
        if (existsSync(path)) raw[name] = await sha256File(path);
      }
    }
    if (result) {
      await writeFile(
        join(context.out, "R10-compare-local.json"),
        `${JSON.stringify(result, null, 2)}\n`,
      );
    }
    return {
      exitCode: record.commands.length === 2 ? lastExit : "not run",
      result,
      runtimeInputs: inputs,
      raw,
    };
  }
  if (run.id === "R11") {
    const path = join(RUNS_DIR, "firestore-probe", "historical-production-comparison.json");
    const result = existsSync(path) ? await readJsonFile(path) : undefined;
    if (result)
      await copyFile(path, join(context.out, "R11-historical-production-comparison.json"));
    return { exitCode: lastExit, result };
  }
  if (run.id === "R12") {
    const line = lastJsonLine(outputs.at(-1) ?? "");
    const outputPath = line?.output;
    const bytes = outputPath && existsSync(outputPath) ? await readFile(outputPath) : undefined;
    const fixture = join(CONFORMANCE, "functions-http", "fixtures");
    const version = await runCommand(
      [context.functionsNode, "--version"],
      context.env,
      ROOT,
      join(context.out, "logs", "R12-node-version.log"),
    );
    return {
      exitCode: lastExit,
      outputSha256: bytes ? sha256Bytes(bytes) : undefined,
      output: bytes ? JSON.parse(bytes.toString("utf8")) : undefined,
      nodeVersion: version.output.trim(),
      fixtureIndexSha256: await sha256File(join(fixture, "index.js")),
      fixturePackageLockSha256: await sha256File(join(fixture, "package-lock.json")),
      log: outputs.at(-1),
    };
  }
  const path = values.export;
  return existsSync(path) ? await readJsonFile(path) : undefined;
}

function judge(comparison, observations, context) {
  const expected = context.readJson(comparison.path);
  if (comparison.kind === "fs-data-write-integrated-regression") {
    const lane = context.readJson(expected.current.laneComparisonPath);
    return [
      ...judgeFsDataWriteCurrent(expected.current, observations.R10, lane.runtimeInputs).map(
        (d) => `current: ${d}`,
      ),
      ...judgeFsDataWriteHistorical(
        expected.historical,
        observations.R11,
        context.binarySha256,
      ).map((d) => `historical: ${d}`),
    ];
  }
  if (comparison.kind === "functions-http-integrated-regression") {
    return judgeFunctionsHttp(expected, observations.R12);
  }
  return compareLaneExport(expected, observations[comparison.runIds[0]], context.binarySha256);
}

const annotate = (title, message) => {
  const clean = (text) =>
    String(text).replaceAll("%", "%25").replaceAll("\r", "").replaceAll("\n", " ");
  console.log(`::error title=${clean(title)}::${clean(message)}`);
};

async function main() {
  const args = parseArguments(process.argv.slice(2));
  const forbidden = forbiddenEnvironment(process.env);
  if (forbidden.length > 0) throw new Error(`refusing to run with ${forbidden.join(", ")} set`);
  const binaryPath = process.env.FIREEMU_BIN;
  const functionsNode = process.env.FIREEMU_NODE;
  if (!binaryPath || !functionsNode) throw new Error("FIREEMU_BIN and FIREEMU_NODE are required");
  await assertNoOutboundNetwork(fetch);
  const binary = realpathSync(resolve(binaryPath));
  const out = resolve(args.out);
  await rm(out, { recursive: true, force: true });
  await mkdir(join(out, "logs"), { recursive: true });
  const readJson = (path) => JSON.parse(readFileSync(join(ROOT, path), "utf8"));
  const closures = readdirSync(join(ROOT, CLOSURE_DIR))
    .filter((name) => name.endsWith(".json") && name !== "record-digests.json")
    .map((name) => ({ name, closure: readJson(`${CLOSURE_DIR}/${name}`) }));
  const plan = planComparisons(closures, readJson);
  const binarySha256 = await sha256File(binary);
  const tarballs = {};
  if (args.dist) {
    for (const name of (await readdir(args.dist)).filter((n) => n.endsWith(".tgz")).toSorted()) {
      tarballs[name] = await sha256File(join(args.dist, name));
    }
  }
  const context = {
    binary,
    binarySha256,
    functionsNode,
    out,
    readJson,
    env: { ...process.env, FIREEMU_BIN: binary, FIREEMU_NODE: functionsNode },
  };
  const summary = {
    binary: { path: binary, sha256: binarySha256 },
    tarballs,
    node: process.version,
    exclusions: EXCLUDED_PARTS,
    planErrors: plan.errors,
    runs: [],
    comparisons: [],
  };
  const observations = {};
  if (plan.errors.length === 0) {
    for (const run of RUNS) {
      console.log(`== ${run.id} ${run.kind}${run.part ? ` (${run.part})` : ""}`);
      const entry = await runEntry(run, context);
      observations[run.id] = await observe(run, entry, context);
      if (run.id === "R10") entry.record.rawLocalResultDigests = observations.R10.raw;
      summary.runs.push(entry.record);
      console.log(
        `   ${entry.record.commands.map((c) => `${c.mode}=${c.exitCode} (${Math.round(c.ms / 1000)} s)`).join(", ")}`,
      );
    }
    for (const comparison of plan.comparisons) {
      const differences = judge(comparison, observations, context);
      summary.comparisons.push({ ...comparison, differences });
    }
    const exportsByRun = Object.fromEntries(
      plan.comparisons.map((c) => [c.runIds[0], c.path.split("/").at(-1)]),
    );
    for (const run of RUNS.slice(0, 9)) {
      const from = join(out, `${run.id}-export.json`);
      if (existsSync(from)) await copyFile(from, join(out, exportsByRun[run.id]));
    }
  }
  const expectedRaw = context.readJson(
    "spec/compatibility/closure/evidence/integration-v0.8.0/FS-DATA-WRITE-regression.json",
  ).current.rawLocalResultDigests.strict;
  summary.reportOnly = {
    fsDataWriteRawResultsEqualLane:
      observations.R10 && isDeepStrictEqual(observations.R10.raw, expectedRaw.lane ?? expectedRaw),
  };
  const failures = [
    ...plan.errors.map((error) => ["coverage", error]),
    ...summary.runs.flatMap((run) => run.errors.map((error) => [run.id, error])),
    ...summary.comparisons.flatMap((c) =>
      c.differences.map((d) => [c.parents.join(","), `${c.path.split("/").at(-1)}: ${d}`]),
    ),
  ];
  summary.result = failures.length === 0 ? "PASS" : "FAIL";
  await writeFile(join(out, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  for (const [title, message] of failures.slice(0, MAX_ANNOTATIONS)) annotate(title, message);
  for (const comparison of summary.comparisons) {
    console.log(
      `${comparison.differences.length === 0 ? "ok  " : "FAIL"} ${comparison.path.split("/").at(-1)} (${comparison.parents.join(", ")}; ${comparison.runIds.join(", ")})`,
    );
  }
  console.log(`strict production comparison: ${summary.result} (${failures.length} findings)`);
  return failures.length === 0 ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main();
}
