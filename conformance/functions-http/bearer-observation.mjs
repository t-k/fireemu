// One bounded production observation: what a public Gen2 onRequest function (fixture fireemuHttpProbe)
// answers to `Authorization: Bearer malformed`, next to the same request without Authorization. Owner
// ledger 2408 approved one sandbox observation within US$10 per task.
//
//   node functions-http/bearer-observation.mjs local --profile strict|emulator --out <file>
//   node functions-http/bearer-observation.mjs record-production
//   node functions-http/bearer-observation.mjs judge <captures.json>
//
// `record-production` is run by the coordinator only, from the launch script that takes the
// fireemu-oracle-query project lock. It composes the stage 3 helpers of production.mjs (deploy, public
// invoker read-back, the two passes, cleanup with read-back, source upload ownership) and adds: its own
// admission, a capture of the raw answers, a regional Cloud Build read after cleanup, the judge, and two
// ledger lines (`started` and one terminal line). It never writes the private sandbox change log: the
// changes it makes are listed in the run directory's changes.jsonl for the coordinator's change-log row.

import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { REQUESTS_PER_DEPLOY, openSourceUploads } from "../src/shared/gen2-source-uploads.mjs";
import { CASE_IDS, judgeObservation } from "./bearer-judge.mjs";
import { FUNCTION_NAMES, PROJECT, REGION, createBudget, expectedFunctionName } from "./harness.mjs";
import {
  PRIVATE_ROOT,
  PROJECT_IDENTITY_FILE,
  PROJECT_IDENTITY_SHA,
  createControl,
  observeProgram,
  ownerAdc,
  preflightCliSideEffects,
  readPrivateProjectIdentity,
  readServiceAgentGrants,
  serviceAgentGrantChanges,
  storageSend,
  withUploadClosure,
} from "./production.mjs";
import { runCases } from "./session.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE = resolve(HERE, "..");
const execFileAsync = promisify(execFile);

export const TASK_ID = "FUNCTIONS-HTTP-BEARER";
export const PROGRAM_ID = "functions-http/http/malformed-bearer";
export const MAX_ATTEMPTS = 3;
const RESERVED_USD_PER_ATTEMPT = 1;
const WAIT_MS = 30 * 60 * 1000;
const MAX_CAPTURE_BYTES = 64 * 1024;
const CLOUDBUILD_HOST = "https://cloudbuild.googleapis.com";
const BUILDS_URL = `${CLOUDBUILD_HOST}/v1/projects/${PROJECT}/locations/${REGION}/builds?pageSize=10`;
const TERMINAL_BUILD = new Set([
  "SUCCESS",
  "FAILURE",
  "INTERNAL_ERROR",
  "TIMEOUT",
  "CANCELLED",
  "EXPIRED",
]);

// Ceilings of one attempt (createBudget can only lower the stage 3 bounds). One deploy: control 17 and
// cleanup 36 are the stage 3 per-deployment worst cases, plus 2 project IAM reads (control) and 1 Cloud
// Build read (cleanup).
export const CAPS = Object.freeze({
  invocation: 4,
  control: 19,
  cleanup: 37,
  auth: 0,
  cliDeploy: 1,
  cliDelete: 1,
  token: 3,
  upload: REQUESTS_PER_DEPLOY,
});

// The reviewed bytes the run depends on, relative to this directory.
export const SOURCE_PINS = Object.freeze({
  "bearer-observation.corpus.json":
    "ee831856d3b54a6d53d6f4081dd872d28023ac3803370661ce6e348a8d0e308f",
  "bearer-observation.baseline.json":
    "aff8b2cc9354df595900730de8e0517a17adff9630a971885bc8b4bbd4801ce0",
  "firebase.json": "0b76734c83f808f8842ee093177fc9ecc2fda2ec9f9d06e025436a0d7f9f7197",
  "fixtures/index.js": "0c481ec6b6ec87db71a2f90550238ce69ec2b923c7a92b7ea5171cb7909886a5",
  "fixtures/package.json": "5a2a9739e294a24104b837a940a65dd38746140dd64fd5744ac85f1d13c4043c",
  "fixtures/package-lock.json": "bcec0509ef824246fc0773859a02561ef178cfd59ede9aab5d39fbcfc178485d",
});

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

// ---- corpus ---------------------------------------------------------------------------------------

/** The one program of the frozen corpus; anything else in the file is refused. */
export function validateBearerCorpus(corpus) {
  const fail = (what) => {
    throw new Error(`bearer corpus: ${what}`);
  };
  if (corpus?.schemaVersion !== 1 || corpus.project !== PROJECT || corpus.region !== REGION)
    fail("project or region");
  if (JSON.stringify(corpus.functions) !== JSON.stringify(FUNCTION_NAMES)) fail("functions");
  if (!Array.isArray(corpus.programs) || corpus.programs.length !== 1) fail("one program");
  const [program] = corpus.programs;
  if (program.id !== PROGRAM_ID) fail("program id");
  if (!Array.isArray(program.cases) || program.cases.length !== CASE_IDS.length) fail("two cases");
  const expectedBody = JSON.stringify({ data: { op: "auth" } });
  program.cases.forEach((step, index) => {
    if (step.id !== CASE_IDS[index]) fail(`case ${index + 1} id`);
    if (step.target !== "http" || expectedFunctionName(step.target) !== "fireemuHttpProbe")
      fail(`${step.id} target`);
    if (step.capture !== "complete") fail(`${step.id} capture`);
    const { method, path, headers, body, ...rest } = step.request ?? {};
    if (Object.keys(rest).length || method !== "POST" || path !== "/") fail(`${step.id} request`);
    if (JSON.stringify(body) !== expectedBody) fail(`${step.id} body`);
    const expected =
      step.id === "malformed-bearer"
        ? { "content-type": "application/json", authorization: "Bearer malformed" }
        : { "content-type": "application/json" };
    if (JSON.stringify(headers) !== JSON.stringify(expected)) fail(`${step.id} headers`);
  });
  return program;
}

// ---- capture --------------------------------------------------------------------------------------

export const KEPT_HEADERS = [
  "content-type",
  "content-length",
  "www-authenticate",
  "cache-control",
  "x-content-type-options",
  "server",
];

async function readCapped(response) {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_CAPTURE_BYTES) {
      await reader.cancel("capture exceeded 64 KiB");
      throw new Error("response body exceeded 64 KiB");
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

/**
 * A fetch for runCases that records each answer as production sent it (status, selected headers, every
 * header name, the byte count and digest of the body, the body text when it is small) and hands the same
 * bytes on. Captures are numbered in send order: pass 1 control, pass 1 malformed, pass 2 control, pass 2
 * malformed (`caseIds` names the cases of one pass for another corpus; `slots` lists `{ pass, program,
 * caseId }` for every request of a run with several programs). Neither the host nor a credential value is
 * recorded unless `enrich` adds it: `enrich(record, source)` is called with the response (or, for a failed
 * request, the error) and may copy what the transport knows into the record; the Authorization values sent
 * are the corpus literals.
 */
export function captureFetch({
  fetchImpl = fetch,
  onCapture,
  now = Date.now,
  caseIds = CASE_IDS,
  keptHeaders = KEPT_HEADERS,
  slots,
  enrich,
  maskAuthorization = (value) => value,
}) {
  let index = 0;
  return async (url, init) => {
    const record = {
      seq: index + 1,
      ...(slots
        ? { pass: slots[index]?.pass ?? null, caseId: slots[index]?.caseId ?? null }
        : {
            pass: Math.floor(index / caseIds.length) + 1,
            caseId: caseIds[index % caseIds.length],
          }),
      ...(slots?.[index]?.program ? { program: slots[index].program } : {}),
      method: init.method,
      path: new URL(url).pathname.replace(/^.*\/fireemuHttpProbe(?=\/)/u, ""),
      authorization: maskAuthorization(init.headers?.authorization ?? null),
      latencyMs: null,
      status: null,
      headers: {},
      headerNames: [],
      bodyBytes: null,
      bodySha256: null,
      bodyText: null,
      error: null,
    };
    index += 1;
    const started = now();
    try {
      const response = await fetchImpl(url, init);
      record.status = response.status;
      record.headerNames = [...response.headers.keys()].toSorted();
      for (const name of keptHeaders) {
        const value = response.headers.get(name);
        if (value !== null) record.headers[name] = value;
      }
      const bytes = await readCapped(response);
      record.latencyMs = now() - started;
      record.bodyBytes = bytes.length;
      record.bodySha256 = sha256(bytes);
      if (bytes.length <= 4096) record.bodyText = bytes.toString("utf8");
      enrich?.(record, response);
      await onCapture(record);
      const nullBody = [101, 204, 205, 304].includes(response.status);
      return new Response(nullBody ? null : bytes, {
        status: response.status,
        headers: response.headers,
      });
    } catch (error) {
      if (record.latencyMs === null) record.latencyMs = now() - started;
      if (!record.error) record.error = `${error.name}: ${error.message}`;
      enrich?.(record, error);
      if (record.bodyBytes === null || record.status === null) await onCapture(record);
      throw error;
    }
  };
}

// ---- admission ------------------------------------------------------------------------------------

const CLOSING_EVENTS = new Set(["cleanup-verified", "observation-complete-cleanup-verified"]);
const CLOSING_OUTCOMES = new Set(["recorded", "cleanup-verified", "recovered-no-observation"]);

/** Whether a ledger row closes the run before it (explicit forms only; anything else is open). */
function closes(line) {
  if (CLOSING_EVENTS.has(line.event)) return true;
  return (
    (line.event === undefined || line.event === "finished") && CLOSING_OUTCOMES.has(line.outcome)
  );
}

const rowTime = (line) => Date.parse(line.ts ?? line.recordedAt ?? "");

/**
 * Plain admission on the sandbox ledger text: the last row for the project closes its run and is at
 * least 30 minutes old (unless the coordinator, as the only sender on the project with the previous run
 * closed, sets FIREEMU_BEARER_SOLE_SENDER=1: owner ledger 1299); every own `started` row has a later own
 * row; at most MAX_ATTEMPTS attempts (1 plus 2 retries). Own rows are those of `taskId`. Returns the
 * attempt number.
 */
export function admit({ ledgerText, now, env, taskId = TASK_ID }) {
  const lines = ledgerText
    .split("\n")
    .filter((text) => text.trim())
    .map((text) => JSON.parse(text))
    .filter((line) => line.project === PROJECT);
  if (!lines.length) throw new Error(`no ledger row for ${PROJECT}`);
  const last = lines.at(-1);
  if (!closes(last))
    throw new Error(
      `the last row for ${PROJECT} does not close its run (${last.event ?? "-"} / ${last.outcome ?? "-"}); the coordinator closes it first`,
    );
  const at = rowTime(last);
  if (!Number.isFinite(at)) throw new Error("the last row for the project has no time");
  if (now - at < WAIT_MS && env.FIREEMU_BEARER_SOLE_SENDER !== "1")
    throw new Error("30 minutes have not passed since the last row for the project");
  const own = lines.filter((line) => line.taskId === taskId);
  own.forEach((line, index) => {
    if (line.event === "started" && !own[index + 1])
      throw new Error("an own started row has no terminal row: recover that attempt first");
  });
  const attempt = own.filter((line) => line.event === "started").length + 1;
  if (attempt > MAX_ATTEMPTS)
    throw new Error(`attempt ${attempt} exceeds ${MAX_ATTEMPTS} attempts (1 plus 2 retries)`);
  return { attempt };
}

// The stage 3 estimate for one attempt (production.mjs estimatedUsd), conservative for one deploy.
export const estimatedUsd = (requests) =>
  Math.ceil((0.01 + requests.cliDeploy * 0.55 + requests.invocation * 0.001) * 100) / 100;

// ---- the recording ------------------------------------------------------------------------------

/** Builds of the run (created at or after its start): all must have ended. */
export async function readRunBuilds(control, startedAt) {
  const reply = await control("GET", BUILDS_URL, undefined, "cleanup");
  const builds = (reply.value.builds ?? [])
    .filter((build) => Date.parse(build.createTime) >= startedAt)
    .map(({ id, status, createTime, finishTime }) => ({ id, status, createTime, finishTime }));
  const open = builds.filter((build) => !TERMINAL_BUILD.has(build.status));
  return { builds, open };
}

/**
 * What differs between the observations that share this recorder: the ledger task, the run directory
 * name, the corpus check, the judge, the case names of one pass and the response headers kept, and the
 * fields the terminal ledger row and the first row add (`startFields`, `terminalFields`).
 */
export const BEARER_SPEC = Object.freeze({
  taskId: TASK_ID,
  runPrefix: "onrequest-bearer-obs",
  validateCorpus: validateBearerCorpus,
  judge: judgeObservation,
  caseIds: CASE_IDS,
  keptHeaders: KEPT_HEADERS,
  startFields: () => ({}),
  terminalFields: (judgement) => ({ differences: judgement.differences }),
});

export const recordBearer = (env, deps) => recordObservation(env, deps, BEARER_SPEC);

/**
 * @param {object} env FIREEMU_BEARER_SOLE_SENDER
 * @param {object} deps every effect: now, assertCleanTree, gitSha, readSources, readLedger, appendLedger,
 *   ownerAdc, projectNumber, makeRunDir, writeRunFile, createBudget, createControl, openUploads, run (the
 *   CLI; undefined for the real one), fetchImpl, installSignals, log, warn.
 * @param {object} spec see BEARER_SPEC
 */
export async function recordObservation(env, deps, spec) {
  await deps.assertCleanTree();
  const { corpus, baseline, digests } = await deps.readSources();
  const programs = [spec.validateCorpus(corpus)].flat();
  const { attempt } = admit({
    ledgerText: await deps.readLedger(),
    now: deps.now(),
    env,
    taskId: spec.taskId,
  });
  const adc = await deps.ownerAdc();
  const projectNumber = await deps.projectNumber();
  const gitSha = await deps.gitSha();
  const startedAt = deps.now();
  const runDir = await deps.makeRunDir(
    `${spec.runPrefix}-${new Date(startedAt).toISOString().replaceAll(":", "")}`,
  );
  const secrets = [projectNumber, adc.file.refresh_token, adc.file.client_secret].filter(Boolean);
  const write = async (name, value) => {
    const text = typeof value === "string" ? value : `${JSON.stringify(value, null, 2)}\n`;
    if (secrets.some((secret) => text.includes(secret)))
      throw new Error(`${name} would retain a private value`);
    await deps.writeRunFile(runDir, name, text);
  };
  const reservedUsd = spec.reservedUsd ?? RESERVED_USD_PER_ATTEMPT;
  const base = {
    project: PROJECT,
    database: null,
    taskId: spec.taskId,
    ...spec.startFields(),
    gitSha,
    corpusDigest: digests.corpus,
    runDir,
    attempt,
    reservedUsd,
    cumulativeReservedUsd: attempt * reservedUsd,
  };
  await deps.appendLedger(
    `${JSON.stringify({ ts: new Date(startedAt).toISOString(), ...base, event: "started" })}\n`,
  );

  const abort = { stopped: false };
  deps.installSignals(() => {
    abort.stopped = true;
  });
  const budget = deps.createBudget();
  const control = deps.createControl(adc.file, budget);
  const uploads = deps.openUploads({ runDir, projectNumber, control, budget });
  const changes = [];
  const log = async (action, detail) => {
    changes.push({ ts: new Date(deps.now()).toISOString(), action, detail });
  };
  const captures = [];
  const recordings = [{}, {}];
  const reasons = [];
  let residual = false;
  let grantsBefore;
  let builds;
  try {
    await preflightCliSideEffects(control);
    grantsBefore = await readServiceAgentGrants(control, projectNumber);
    const fetchImpl = captureFetch({
      fetchImpl: deps.fetchImpl,
      onCapture: (capture) => captures.push(capture),
      now: deps.now,
      caseIds: spec.caseIds,
      keptHeaders: spec.keptHeaders,
      slots: spec.slots,
      enrich:
        spec.enrichCapture &&
        ((record, source) => spec.enrichCapture(record, source, { projectNumber })),
      maskAuthorization: spec.maskAuthorization,
    });
    // The programs run one after the other, each with its own deployment; a program that fails stops the run.
    for (const program of programs) {
      await observeProgram(program, control, adc.path, budget, runDir, recordings, abort, uploads, {
        ...(deps.run ? { run: deps.run } : {}),
        ...(deps.auth ? { auth: deps.auth } : {}),
        log,
        fetchImpl,
      });
    }
  } catch (error) {
    reasons.push(error.message);
    residual = Boolean(error.residual);
  }
  const used = () => budget.snapshot();
  // A create (the deploy) is settled only by the run's own completed delete followed by absence; without
  // that delete, absence in the run settles nothing (checklist section 3) and A2 decides.
  if (
    used().cliDeploy > 0 &&
    changes.filter((change) => change.action === "function-deleted").length < used().cliDeploy
  ) {
    residual = true;
    reasons.push(
      "the deploy was not followed by the run's own delete: A2 read-back >= 10 min needed",
    );
  }
  const uploadReport = uploads.report();
  ({ residual } = withUploadClosure(uploadReport, { outcome: "", reason: "", residual }));
  if (!uploadReport.closureReady) reasons.push("source upload ledger is not closed");
  uploads.close?.();
  if (used().cliDeploy > 0) {
    try {
      builds = await readRunBuilds(control, startedAt);
      if (builds.open.length) {
        residual = true;
        reasons.push(
          `build ${builds.open.map((b) => `${b.id} ${b.status}`).join(", ")} has not ended`,
        );
      }
      if (builds.builds.length > used().cliDeploy) {
        residual = true;
        reasons.push(`more builds (${builds.builds.length}) than deploys since the run started`);
      }
    } catch (error) {
      residual = true;
      reasons.push(`Cloud Build read: ${error.message}`);
    }
    if (grantsBefore) {
      try {
        const after = await readServiceAgentGrants(control, projectNumber);
        for (const { kind, role } of serviceAgentGrantChanges(grantsBefore, after))
          await log(
            "service-agent-project-grant-observed",
            `${kind}: ${role}; project IAM readback`,
          );
        await log(
          "service-identity-generation-possible",
          "Firebase CLI 15.28.2 v2 deploy invokes Pub/Sub and Eventarc generateServiceIdentity; direct creation readback is unavailable",
        );
      } catch (error) {
        residual = true;
        reasons.push(`service-agent grant read-back: ${error.message}`);
      }
    }
  }
  const judgement = spec.judge(captures, baseline);
  const closureReady = !residual;
  const outcome = !closureReady
    ? "needs-recovery"
    : judgement.verdict === "unknown"
      ? "observed-unknown"
      : "recorded";
  let writeError;
  try {
    await write("captures.json", captures);
    await write("recordings.json", recordings);
    await write("judgement.json", judgement);
    await write("builds.json", builds ?? { builds: [], open: [] });
    await write("changes.jsonl", changes.map((change) => `${JSON.stringify(change)}\n`).join(""));
    for (const [name, value] of Object.entries(spec.extraFiles?.({ projectNumber }) ?? {}))
      await write(name, value);
  } catch (error) {
    writeError = error.message;
  }
  const requests = used();
  await deps.appendLedger(
    `${JSON.stringify({
      ts: new Date(deps.now()).toISOString(),
      ...base,
      event: closureReady ? "finished" : "needs-recovery",
      outcome,
      verdict: judgement.verdict,
      ...spec.terminalFields(judgement),
      needsReview: judgement.needsReview || !closureReady || Boolean(writeError),
      lockKept: judgement.lockKept || !closureReady || Boolean(writeError),
      closureReady,
      requests,
      estimatedUsd: estimatedUsd(requests),
      ...(reasons.length || writeError
        ? { reason: [...reasons, writeError].filter(Boolean).join("; ") }
        : {}),
    })}\n`,
  );
  const ok = outcome === "recorded" && !writeError;
  return { outcome, verdict: judgement.verdict, closureReady, runDir, exitCode: ok ? 0 : 1 };
}

// ---- production effects -------------------------------------------------------------------------

async function readSources() {
  const files = {};
  for (const [file, expected] of Object.entries(SOURCE_PINS)) {
    const bytes = await readFile(join(HERE, file));
    if (sha256(bytes) !== expected) throw new Error(`reviewed source changed: ${file}`);
    files[file] = bytes;
  }
  const cli = JSON.parse(
    await readFile(join(CONFORMANCE, "node_modules/firebase-tools/package.json"), "utf8"),
  );
  if (cli.version !== "15.28.2") throw new Error("pinned Firebase CLI 15.28.2 is required");
  return {
    corpus: JSON.parse(files["bearer-observation.corpus.json"]),
    baseline: JSON.parse(files["bearer-observation.baseline.json"]),
    digests: { corpus: SOURCE_PINS["bearer-observation.corpus.json"] },
  };
}

/** The real effects. `ledger` and `privateRoot` are the private sandbox ledger and directory (a test points them elsewhere). */
export function productionDeps({
  ledger = join(PRIVATE_ROOT, "runs/sandbox-ledger.jsonl"),
  privateRoot = PRIVATE_ROOT,
} = {}) {
  const git = (args) => execFileAsync("git", args, { cwd: CONFORMANCE });
  return {
    now: Date.now,
    async assertCleanTree() {
      const { stdout } = await git(["status", "--porcelain"]);
      if (stdout.trim()) throw new Error("the worktree is not clean");
    },
    gitSha: async () => (await git(["rev-parse", "HEAD"])).stdout.trim(),
    readSources,
    readLedger: () => readFile(ledger, "utf8"),
    appendLedger: (text) => appendFile(ledger, text),
    ownerAdc,
    projectNumber: () => readPrivateProjectIdentity(PROJECT_IDENTITY_FILE, PROJECT_IDENTITY_SHA),
    async makeRunDir(name) {
      const dir = join(privateRoot, "runs", name);
      await mkdir(dir, { recursive: false, mode: 0o700 });
      return dir;
    },
    writeRunFile: (dir, name, text) =>
      writeFile(join(dir, name), text, { mode: 0o600, flag: "wx" }),
    createBudget: () => createBudget(CAPS),
    createControl: (adcFile, budget) =>
      createControl(adcFile, budget, { extraHosts: [CLOUDBUILD_HOST] }),
    openUploads: ({ runDir, projectNumber, control, budget }) =>
      openSourceUploads({
        ledgerPath: join(runDir, "owned-uploads.jsonl"),
        runId: basename(runDir),
        projectNumber,
        region: REGION,
        send: storageSend(control),
        requestsLeft: () => CAPS.upload - budget.snapshot().upload,
      }),
    run: undefined,
    fetchImpl: fetch,
    installSignals(handler) {
      for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, handler);
    },
    log: (text) => console.log(text),
    warn: (text) => console.error(text),
  };
}

// ---- local dry run --------------------------------------------------------------------------------

const LOCAL_PROJECT = "demo-functions-http";

async function localChild() {
  const host = process.env.FIREEMU_FUNCTIONS_HOST;
  if (!/^127\.0\.0\.1:\d+$/.test(host ?? ""))
    throw new Error("local Functions host is not loopback");
  const { corpus, baseline } = await readSources();
  const program = validateBearerCorpus(corpus);
  const endpoint = `http://${host}/${LOCAL_PROJECT}/${REGION}/${FUNCTION_NAMES.http}`;
  const budget = createBudget(CAPS);
  const captures = [];
  const fetchImpl = captureFetch({ onCapture: (capture) => captures.push(capture) });
  const recordings = [];
  for (let pass = 0; pass < 2; pass += 1) {
    try {
      recordings.push(await runCases(program, { http: endpoint }, {}, budget, { fetchImpl }));
    } catch (error) {
      recordings.push({ error: error.message });
    }
  }
  const judgement = judgeObservation(captures, baseline);
  await writeFile(
    process.env.BEARER_LOCAL_OUTPUT,
    `${JSON.stringify({ profile: process.env.BEARER_LOCAL_PROFILE, captures, recordings, judgement }, null, 2)}\n`,
    { mode: 0o600, flag: "wx" },
  );
}

async function local(profile, out) {
  if (!["strict", "emulator"].includes(profile)) throw new Error("--profile strict|emulator");
  if (!out) throw new Error("--out <new file> is required");
  const binary = process.env.FIREEMU_BIN;
  if (!binary) throw new Error("FIREEMU_BIN is required");
  const config =
    profile === "emulator"
      ? ["--config", join(HERE, "bearer-observation.emulator.fireemu.json")]
      : ["--no-config-discovery"];
  const ports = [
    "http",
    "functions",
    "firestore",
    "storage",
    "eventarc",
    "tasks",
    "pubsub",
    "ui",
    "hub",
    "logging",
  ].flatMap((name) => [`--${name}-port`, "0"]);
  const args = [
    "exec",
    ...config,
    "--project",
    LOCAL_PROJECT,
    "--only",
    "functions",
    "--functions",
    join(HERE, "fixtures"),
    ...ports,
    "--",
    process.execPath,
    fileURLToPath(import.meta.url),
    "local-child",
  ];
  const child = spawn(binary, args, {
    cwd: CONFORMANCE,
    stdio: "inherit",
    env: { ...process.env, BEARER_LOCAL_OUTPUT: resolve(out), BEARER_LOCAL_PROFILE: profile },
  });
  const code = await new Promise((resolveChild, reject) => {
    child.once("error", reject);
    child.once("exit", resolveChild);
  });
  if (code !== 0) throw new Error(`local fireemu session exited ${code}`);
  const { judgement, captures } = JSON.parse(await readFile(out, "utf8"));
  console.log(
    JSON.stringify({
      profile,
      verdict: judgement.verdict,
      answers: captures.map((c) => [c.pass, c.caseId, c.status, c.bodyBytes]),
    }),
  );
}

// ---- entry ----------------------------------------------------------------------------------------

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [mode, ...rest] = process.argv.slice(2);
  const option = (name) => rest[rest.indexOf(name) + 1];
  if (mode === "local") await local(option("--profile"), option("--out"));
  else if (mode === "local-child") await localChild();
  else if (mode === "judge") {
    const { baseline } = await readSources();
    const captures = JSON.parse(await readFile(rest[0], "utf8"));
    console.log(JSON.stringify(judgeObservation(captures, baseline), null, 2));
  } else if (mode === "record-production") {
    const result = await recordBearer(process.env, productionDeps());
    console.log(JSON.stringify(result));
    process.exitCode = result.exitCode;
  } else throw new Error("usage: bearer-observation.mjs local|judge|record-production");
}
