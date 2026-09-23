import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFile, mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { promisify } from "node:util";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { CONFORMANCE_DIR, RUNS_DIR } from "./config.mjs";
import {
  compareSandboxArtifact,
  freezeSandboxFixture,
  validateSandboxCorpus,
} from "./fs-data-write-sandbox.mjs";
import { validateStreamRecipes } from "./firestore-probe/stream-session.mjs";

const execFileAsync = promisify(execFile);
const require = createRequire(import.meta.url);
const ROOT = resolve(CONFORMANCE_DIR, "..");
const TASK_ID = "FS-DATA-WRITE-SANDBOX";
const TASK_LIMIT_USD = 10;
const SANDBOX_PROJECT = "fireemu-oracle-sbx";
const RECORDED_PROJECT = "demo-firestore-probe";
// 217 declared REST observation steps plus pre/final clears; the 100-level document chain adds about
// 200 recursive public-API reads, while the other bounded programs add smaller clears.
// Leave headroom, but reject attempt 1001 before the network send.
const REST_CAP = 1000;
const ATTEMPT_ESTIMATE_USD = 0.5;
export const MAX_STREAM_FRAMES = 7;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");

export function assertMatchingSandboxCorpus(fixture, currentCorpus, localCorpus) {
  const currentDigest = sha256(JSON.stringify(currentCorpus));
  if (fixture?.evidence?.corpusSha256 !== currentDigest) {
    throw new Error("fixture corpus differs from the current recipe");
  }
  if (sha256(JSON.stringify(localCorpus)) !== currentDigest) {
    throw new Error("local corpus differs from the current recipe");
  }
  return currentDigest;
}

/** Compare an older recording only where the serialized program recipe is unchanged. */
export function selectComparableSandboxRecipes(fixture, manifest, currentCorpus, localCorpus) {
  const currentDigest = sha256(JSON.stringify(currentCorpus));
  if (sha256(JSON.stringify(localCorpus)) !== currentDigest) {
    throw new Error("local corpus differs from the current recipe");
  }
  if (manifest?.schemaVersion !== 1 || manifest.corpusSha256 !== fixture?.evidence?.corpusSha256) {
    throw new Error("manifest corpus differs from the production fixture");
  }
  if (manifest.sourceCommit !== fixture.evidence.harnessRevision) {
    throw new Error("manifest source differs from the production fixture");
  }
  const recordedIds = Object.keys(fixture.programs ?? {}).toSorted();
  if (
    JSON.stringify(recordedIds) !== JSON.stringify(Object.keys(manifest.programs ?? {}).toSorted())
  ) {
    throw new Error("manifest programs differ from the production fixture");
  }
  if (Object.keys(fixture.streams ?? {}).some((id) => !manifest.streams?.[id])) {
    throw new Error("manifest streams differ from the production fixture");
  }
  const selectedPrograms = (currentCorpus.restPrograms ?? []).filter(
    (program) => manifest.programs[program.id] === sha256(JSON.stringify(program)),
  );
  const matchedRestIds = selectedPrograms.map((program) => program.id).toSorted();
  const pendingRestIds = [
    ...new Set([
      ...recordedIds,
      ...(currentCorpus.restPrograms ?? []).map((program) => program.id),
    ]),
  ]
    .filter((id) => !matchedRestIds.includes(id))
    .toSorted();
  const currentStreams = (currentCorpus.streamRecipes ?? []).filter(
    (recipe) => recipe.transport === "grpc",
  );
  const selectedStreams = currentStreams.filter(
    (recipe) => manifest.streams?.[recipe.id] === sha256(JSON.stringify(recipe)),
  );
  const matchedStreamIds = selectedStreams.map((recipe) => recipe.id).toSorted();
  const pendingStreamIds = [
    ...new Set([
      ...Object.keys(fixture.streams ?? {}),
      ...currentStreams.map((recipe) => recipe.id),
    ]),
  ]
    .filter((id) => !matchedStreamIds.includes(id))
    .toSorted();
  const keep = (entries, ids) => Object.fromEntries(ids.map((id) => [id, entries[id]]));
  return {
    fixture: {
      ...fixture,
      programs: keep(fixture.programs, matchedRestIds),
      streams: keep(fixture.streams ?? {}, matchedStreamIds),
    },
    corpus: {
      ...currentCorpus,
      restPrograms: selectedPrograms,
      streamRecipes: selectedStreams,
      restRequestCount: selectedPrograms.reduce(
        (total, program) => total + program.steps.length,
        0,
      ),
    },
    matchedRestIds,
    pendingRestIds,
    matchedStreamIds,
    pendingStreamIds,
  };
}

export function comparisonExitCode(differences, pendingRestIds, pendingStreamIds) {
  if (differences.length > 0) return 1;
  if (pendingRestIds.length > 0 || pendingStreamIds.length > 0) return 2;
  return 0;
}

export async function prepareSandboxCorpus() {
  const { stdout } = await execFileAsync(
    "uv",
    ["run", "python", join(CONFORMANCE_DIR, "src/firestore-probe/closure_export.py")],
    { cwd: ROOT, maxBuffer: 240 * 1024 * 1024 },
  );
  const corpus = JSON.parse(stdout);
  const { requestCount } = validateSandboxCorpus(corpus);
  const { live, saved } = validateStreamRecipes(corpus.streamRecipes);
  if (!(await stat(join(ROOT, saved.source))).isFile()) {
    throw new Error("saved stream production reference is missing");
  }
  return { corpus, restRequestCount: requestCount, liveStreamCount: live.length };
}

export function remainingSandboxBudget(rows, nextEstimateUsd = 0) {
  if (!Array.isArray(rows) || !Number.isFinite(nextEstimateUsd) || nextEstimateUsd < 0) {
    throw new Error("invalid sandbox budget input");
  }
  const spent = rows.reduce((total, row) => {
    if (row.taskId !== TASK_ID) return total;
    if (!Number.isFinite(row.estimatedUsd) || row.estimatedUsd < 0) {
      throw new Error("invalid sandbox ledger cost");
    }
    return total + row.estimatedUsd;
  }, 0);
  if (spent + nextEstimateUsd > TASK_LIMIT_USD + Number.EPSILON) {
    throw new Error("sandbox observation task budget exceeded");
  }
  return TASK_LIMIT_USD - spent;
}

export function sandboxLedgerEntry({ gitSha, corpusDigest, requests, outcome, runDir }) {
  if (
    requests !== null &&
    (!Number.isInteger(requests) || requests < 0 || requests > REST_CAP + MAX_STREAM_FRAMES)
  ) {
    throw new Error("invalid sandbox ledger request count");
  }
  return {
    ts: new Date().toISOString(),
    project: SANDBOX_PROJECT,
    database: "(default)",
    gitSha,
    corpusDigest,
    requests,
    estimatedUsd: ATTEMPT_ESTIMATE_USD,
    outcome,
    taskId: TASK_ID,
    runDir,
  };
}

export function sandboxLedgerPath(gitCommonDir) {
  if (typeof gitCommonDir !== "string" || !gitCommonDir.startsWith("/")) {
    throw new Error("absolute git common directory is required");
  }
  return resolve(gitCommonDir, "../docs.local/runs/sandbox-ledger.jsonl");
}

export function sessionRequestCount(meta) {
  if (
    !Number.isInteger(meta?.requestCount) ||
    meta.requestCount < 0 ||
    meta.requestCount > REST_CAP
  ) {
    throw new Error("session network attempt count escaped the bounded corpus");
  }
  return meta.requestCount;
}

export function localTarget(value) {
  const [host, portText, ...extra] = String(value ?? "").split(":");
  const port = Number(portText);
  if (extra.length > 0 || !new Set(["127.0.0.1", "localhost"]).has(host)) {
    throw new Error("local child requires a loopback target");
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("local child port is invalid");
  }
  return { host, port };
}

export function productionRestEnvironment({ input, output, meta, token }) {
  if (
    ![input, output, meta, token].every((value) => typeof value === "string" && value.length > 0)
  ) {
    throw new Error("production REST session inputs are required");
  }
  return {
    FIRESTORE_PROBE_TARGET: "production",
    FIRESTORE_PROBE_SCHEME: "https",
    FIRESTORE_PROBE_HOST: "firestore.googleapis.com",
    FIRESTORE_PROBE_TOKEN: token,
    FIRESTORE_PROBE_PROJECT: SANDBOX_PROJECT,
    FIRESTORE_PROBE_RECORD_PROJECT: RECORDED_PROJECT,
    FIRESTORE_PROBE_IN: input,
    FIRESTORE_PROBE_OUT: output,
    FIRESTORE_PROBE_META_OUT: meta,
    FIRESTORE_PROBE_MAX_REQUESTS: String(REST_CAP),
    FIRESTORE_PROBE_TIMEOUT_MS: "180000",
  };
}

async function runNode(name, script, env) {
  try {
    const childEnv = { ...process.env, ...env };
    for (const [key, value] of Object.entries(childEnv)) {
      if (value === undefined) delete childEnv[key];
    }
    await execFileAsync("node", [join(CONFORMANCE_DIR, "src", script)], {
      cwd: CONFORMANCE_DIR,
      env: childEnv,
      timeout: 1_200_000,
      maxBuffer: 1024 * 1024,
    });
  } catch (error) {
    throw new Error(`${name} failed: ${String(error.stderr ?? error.message).slice(0, 2000)}`, {
      cause: error,
    });
  }
}

async function readLedger(path) {
  try {
    const content = await readFile(path, "utf8");
    return content
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
}

async function productionRecording({
  corpusIn,
  restIn,
  privateDir,
  token,
  gitSha,
  corpusDigest,
  restRequestCount,
  liveStreamCount,
  rows,
}) {
  remainingSandboxBudget(rows, ATTEMPT_ESTIMATE_USD);
  const runDir = await mkdtemp(join(privateDir, "fs-data-write-production-"));
  const restOut = join(runDir, "rest-results.json");
  const metaOut = join(runDir, "rest-meta.json");
  const streamOut = join(runDir, "stream-results.json");
  const startedAt = new Date().toISOString();
  let requestCount = null;
  let outcome = "failed";
  try {
    await runNode(
      "production REST",
      "firestore-probe/session.mjs",
      productionRestEnvironment({
        input: restIn,
        output: restOut,
        meta: metaOut,
        token,
      }),
    );
    const meta = JSON.parse(await readFile(metaOut, "utf8"));
    requestCount = sessionRequestCount(meta);
    if (requestCount < restRequestCount) {
      throw new Error("production REST request count escaped the bounded corpus");
    }
    await runNode("production gRPC", "firestore-probe/stream-session.mjs", {
      FIRESTORE_STREAM_CORPUS: corpusIn,
      FIRESTORE_STREAM_OUT: streamOut,
      FIRESTORE_STREAM_TARGET: "production",
      FIRESTORE_STREAM_HOST: undefined,
      FIRESTORE_STREAM_PORT: undefined,
      FIRESTORE_STREAM_TOKEN: token,
    });
    const rest = JSON.parse(await readFile(restOut, "utf8"));
    const stream = JSON.parse(await readFile(streamOut, "utf8"));
    if (Object.keys(stream).length !== liveStreamCount)
      throw new Error("incomplete production stream set");
    const streamFrames = Object.values(stream).reduce((total, result) => {
      if (!Number.isInteger(result.sentFrames) || result.sentFrames < 1) {
        throw new Error("invalid production stream frame count");
      }
      return total + result.sentFrames;
    }, 0);
    if (streamFrames !== MAX_STREAM_FRAMES) {
      throw new Error("production stream messages escaped the bounded corpus");
    }
    requestCount += streamFrames;
    outcome = "recorded";
    return { rest, stream, startedAt, runDir, requestCount };
  } finally {
    if (requestCount === null) {
      try {
        requestCount = sessionRequestCount(JSON.parse(await readFile(metaOut, "utf8")));
      } catch {
        // An early transport failure may leave no metadata; the cost reservation still stands.
      }
    }
    const entry = sandboxLedgerEntry({
      gitSha,
      corpusDigest,
      requests: requestCount,
      outcome,
      runDir,
    });
    await appendFile(join(privateDir, "sandbox-ledger.jsonl"), `${JSON.stringify(entry)}\n`);
    rows.push(entry);
  }
}

async function recordProduction() {
  const gitCommonDir = (
    await execFileAsync("git", ["rev-parse", "--path-format=absolute", "--git-common-dir"], {
      cwd: ROOT,
    })
  ).stdout.trim();
  const ledgerPath = sandboxLedgerPath(gitCommonDir);
  const privateDir = dirname(ledgerPath);
  const { corpus, restRequestCount, liveStreamCount } = await prepareSandboxCorpus();
  const corpusDigest = sha256(JSON.stringify(corpus));
  const gitSha = (await execFileAsync("git", ["rev-parse", "HEAD"], { cwd: ROOT })).stdout.trim();
  const rows = await readLedger(ledgerPath);
  remainingSandboxBudget(rows, ATTEMPT_ESTIMATE_USD * 2);
  const token = (
    process.env.FIREEMU_PRODUCTION_TOKEN ??
    (
      await execFileAsync("gcloud", ["auth", "application-default", "print-access-token"], {
        maxBuffer: 4096,
      })
    ).stdout
  ).trim();
  if (!token) throw new Error("production OAuth bearer is missing");
  await mkdir(privateDir, { recursive: true });
  await mkdir(RUNS_DIR, { recursive: true });
  const generatedDir = await mkdtemp(join(RUNS_DIR, "fs-data-write-corpus-"));
  const corpusIn = join(generatedDir, "corpus.json");
  const restIn = join(generatedDir, "rest-programs.json");
  await writeFile(corpusIn, JSON.stringify(corpus));
  await writeFile(restIn, JSON.stringify(corpus.restPrograms));
  const first = await productionRecording({
    corpusIn,
    restIn,
    privateDir,
    token,
    gitSha,
    corpusDigest,
    restRequestCount,
    liveStreamCount,
    rows,
  });
  const second = await productionRecording({
    corpusIn,
    restIn,
    privateDir,
    token,
    gitSha,
    corpusDigest,
    restRequestCount,
    liveStreamCount,
    rows,
  });
  const sdkVersions = {
    firebase: require("firebase/package.json").version,
    firebaseAdmin: require("firebase-admin").SDK_VERSION,
    firestore: require("@google-cloud/firestore/package.json").version,
    grpc: require("@grpc/grpc-js/package.json").version,
  };
  const fixture = freezeSandboxFixture({
    corpus,
    first: first.rest,
    second: second.rest,
    firstStream: first.stream,
    secondStream: second.stream,
    recordedAt: [first.startedAt, second.startedAt],
    harnessRevision: gitSha,
    sdkVersions,
    credentialToken: token,
  });
  const output = join(CONFORMANCE_DIR, "fs-data-write-production-matrix.json");
  await writeFile(output, `${JSON.stringify(fixture, null, 2)}\n`);
  process.stdout.write(
    `${JSON.stringify({ output, firstRunDir: first.runDir, secondRunDir: second.runDir, requestCount: first.requestCount + second.requestCount, corpusDigest })}\n`,
  );
}

async function localChild() {
  const { host, port } = localTarget(process.env.FIRESTORE_EMULATOR_HOST);
  const { corpus, restRequestCount } = await prepareSandboxCorpus();
  await mkdir(RUNS_DIR, { recursive: true });
  const runDir = await mkdtemp(join(RUNS_DIR, "fs-data-write-local-"));
  const restIn = join(runDir, "rest-programs.json");
  const corpusIn = join(runDir, "corpus.json");
  const restOut = join(runDir, "rest-results.json");
  const metaOut = join(runDir, "rest-meta.json");
  const streamOut = join(runDir, "stream-results.json");
  await writeFile(restIn, JSON.stringify(corpus.restPrograms));
  await writeFile(corpusIn, JSON.stringify(corpus));
  await runNode("local REST", "firestore-probe/session.mjs", {
    FIRESTORE_PROBE_TARGET: "local",
    FIRESTORE_PROBE_HOST: `${host}:${port}`,
    FIRESTORE_PROBE_SCHEME: "http",
    FIRESTORE_PROBE_TOKEN: "owner",
    FIRESTORE_PROBE_PROJECT: SANDBOX_PROJECT,
    FIRESTORE_PROBE_RECORD_PROJECT: RECORDED_PROJECT,
    FIRESTORE_PROBE_IN: restIn,
    FIRESTORE_PROBE_OUT: restOut,
    FIRESTORE_PROBE_META_OUT: metaOut,
    FIRESTORE_PROBE_MAX_REQUESTS: String(REST_CAP),
  });
  const metadata = JSON.parse(await readFile(metaOut, "utf8"));
  if (metadata.requestCount < restRequestCount || metadata.requestCount > REST_CAP) {
    throw new Error("local REST request count escaped the bounded corpus");
  }
  await runNode("local gRPC", "firestore-probe/stream-session.mjs", {
    FIRESTORE_STREAM_CORPUS: corpusIn,
    FIRESTORE_STREAM_OUT: streamOut,
    FIRESTORE_STREAM_TARGET: "local",
    FIRESTORE_STREAM_HOST: host,
    FIRESTORE_STREAM_PORT: String(port),
    FIRESTORE_STREAM_TOKEN: "owner",
  });
  const rest = JSON.parse(await readFile(restOut, "utf8"));
  const stream = JSON.parse(await readFile(streamOut, "utf8"));
  process.stdout.write(
    `${JSON.stringify({ runDir, restPrograms: Object.keys(rest).length, restRequests: metadata.requestCount, streamRecipes: Object.keys(stream).length })}\n`,
  );
}

async function compareLocal(runDir) {
  if (typeof runDir !== "string" || !runDir) throw new Error("local run directory is required");
  const { corpus } = await prepareSandboxCorpus();
  const fixture = JSON.parse(
    await readFile(join(CONFORMANCE_DIR, "fs-data-write-production-matrix.json"), "utf8"),
  );
  const localCorpus = JSON.parse(await readFile(join(runDir, "corpus.json"), "utf8"));
  const corpusDigest = sha256(JSON.stringify(corpus));
  const rest = JSON.parse(await readFile(join(runDir, "rest-results.json"), "utf8"));
  const stream = JSON.parse(await readFile(join(runDir, "stream-results.json"), "utf8"));
  let comparison;
  if (fixture.evidence.corpusSha256 === corpusDigest) {
    assertMatchingSandboxCorpus(fixture, corpus, localCorpus);
    comparison = {
      fixture,
      corpus,
      matchedRestIds: corpus.restPrograms.map((program) => program.id),
      pendingRestIds: [],
      matchedStreamIds: corpus.streamRecipes
        .filter((recipe) => recipe.transport === "grpc")
        .map((recipe) => recipe.id),
      pendingStreamIds: [],
    };
  } else {
    const manifest = JSON.parse(
      await readFile(join(CONFORMANCE_DIR, "fs-data-write-recipe-digests.json"), "utf8"),
    );
    comparison = selectComparableSandboxRecipes(fixture, manifest, corpus, localCorpus);
  }
  const comparedRest = Object.fromEntries(comparison.matchedRestIds.map((id) => [id, rest[id]]));
  const comparedStreams = Object.fromEntries(
    comparison.matchedStreamIds.map((id) => [id, stream[id]]),
  );
  const differences = compareSandboxArtifact(
    comparison.fixture,
    comparedRest,
    comparedStreams,
    comparison.corpus,
  );
  process.stdout.write(
    `${JSON.stringify({ corpusDigest, recordedCorpusDigest: fixture.evidence.corpusSha256, comparedPrograms: comparison.matchedRestIds.length, comparedStreams: comparison.matchedStreamIds.length, pendingRestIds: comparison.pendingRestIds, pendingStreamIds: comparison.pendingStreamIds, mismatches: differences.length, differences })}\n`,
  );
  process.exitCode = comparisonExitCode(
    differences,
    comparison.pendingRestIds,
    comparison.pendingStreamIds,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv[2] === "local-child") {
    await localChild();
  } else if (process.argv[2] === "compare-local") {
    await compareLocal(process.argv[3]);
  } else if (process.argv[2] === "record-production") {
    await recordProduction();
  } else if (process.argv[2] === "prepare") {
    const prepared = await prepareSandboxCorpus();
    process.stdout.write(
      `${JSON.stringify({ programs: prepared.corpus.restPrograms.length, restRequests: prepared.restRequestCount, liveStreamRecipes: prepared.liveStreamCount })}\n`,
    );
  } else {
    throw new Error("expected prepare, local-child, compare-local or record-production");
  }
}
